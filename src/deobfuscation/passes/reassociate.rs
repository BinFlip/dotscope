//! Reassociation pass.
//!
//! This pass reorders operations to enable better constant folding. For example:
//!
//! ```text
//! (x + 5) + 3  →  x + (5 + 3)  →  x + 8
//! ```
//!
//! # Transformed Patterns
//!
//! ## Associative operations (`add`, `mul`, `and`, `or`, `xor`)
//!
//! For these operations, constants combine using the same operation:
//! - `(x + c1) + c2` → `x + (c1 + c2)`
//! - `(x * c1) * c2` → `x * (c1 * c2)`
//! - `(x ^ c1) ^ c2` → `x ^ (c1 ^ c2)` (common in obfuscation)
//!
//! ## Subtraction chains
//!
//! Subtraction is not associative, but constants combine with addition:
//! - `(x - c1) - c2` → `x - (c1 + c2)`
//!
//! ## Shift chains
//!
//! Shift amounts combine with addition:
//! - `(x << c1) << c2` → `x << (c1 + c2)`
//! - `(x >> c1) >> c2` → `x >> (c1 + c2)` (preserves signedness)
//!
//! # Implementation Strategy
//!
//! The pass works in three phases:
//! 1. Find constants and their defining instructions
//! 2. Identify operations where one operand is the result of another same-op with a constant
//! 3. Combine the constants and rewrite to `x op combined_const`
//!
//! The SCCP pass will then fold the combined constants in the next iteration.

use std::{collections::HashMap, sync::Arc};

use crate::{
    analysis::{ConstValue, DefUseIndex, SsaFunction, SsaOp, SsaVarId},
    deobfuscation::{
        changes::{EventKind, EventLog},
        context::AnalysisContext,
        pass::SsaPass,
    },
    metadata::token::Token,
    CilObject, Result,
};

/// Reassociation pass that reorders operations to enable constant folding.
pub struct ReassociationPass;

impl Default for ReassociationPass {
    fn default() -> Self {
        Self::new()
    }
}

/// A candidate for reassociation.
#[derive(Debug)]
struct ReassociationCandidate {
    /// Block containing the outer operation
    block_idx: usize,
    /// Instruction index of the outer operation
    instr_idx: usize,
    /// The destination variable
    dest: SsaVarId,
    /// The non-constant operand (x in `(x op c1) op c2`)
    base_var: SsaVarId,
    /// The first constant variable (c1)
    const1_var: SsaVarId,
    /// The second constant variable (c2)
    const2_var: SsaVarId,
    /// The first constant value
    const1_value: ConstValue,
    /// The second constant value
    const2_value: ConstValue,
    /// Block and instruction of the inner operation (to mark for removal)
    inner_block: usize,
    inner_instr: usize,
    inner_dest: SsaVarId,
    /// The type of operation
    op_kind: OpKind,
}

/// The kind of operation that can be reassociated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OpKind {
    /// Addition: constants combine with add
    Add,
    /// Subtraction: constants combine with add
    Sub,
    /// Multiplication: constants combine with mul
    Mul,
    /// Bitwise AND: constants combine with and
    And,
    /// Bitwise OR: constants combine with or
    Or,
    /// Bitwise XOR: constants combine with xor
    Xor,
    /// Shift left: shift amounts combine with add
    Shl,
    /// Shift right: shift amounts combine with add (preserves signedness)
    Shr { unsigned: bool },
}

impl OpKind {
    /// Combines two constants for reassociation.
    ///
    /// For associative operations (Add, Mul, And, Or, Xor), the combining
    /// operation is the same as the main operation.
    ///
    /// For non-associative operations that still benefit from reassociation:
    /// - Sub: `(x - c1) - c2` → `x - (c1 + c2)` (combine with add)
    /// - Shl/Shr: `(x << c1) << c2` → `x << (c1 + c2)` (combine with add)
    fn combine(&self, c1: &ConstValue, c2: &ConstValue) -> Option<ConstValue> {
        match self {
            // Associative: combine with same operation
            OpKind::Add => c1.add(c2),
            OpKind::Mul => c1.mul(c2),
            OpKind::And => c1.bitwise_and(c2),
            OpKind::Or => c1.bitwise_or(c2),
            OpKind::Xor => c1.bitwise_xor(c2),
            // Non-associative: combine with addition
            OpKind::Sub | OpKind::Shl | OpKind::Shr { .. } => c1.add(c2),
        }
    }

    /// Returns a description of the operation.
    fn name(&self) -> &'static str {
        match self {
            OpKind::Add => "add",
            OpKind::Sub => "sub",
            OpKind::Mul => "mul",
            OpKind::And => "and",
            OpKind::Or => "or",
            OpKind::Xor => "xor",
            OpKind::Shl => "shl",
            OpKind::Shr { unsigned: false } => "shr",
            OpKind::Shr { unsigned: true } => "shr.un",
        }
    }

    /// Returns the name of the combining operation for logging.
    fn combine_name(&self) -> &'static str {
        match self {
            // Associative: combine with same operation
            OpKind::Add | OpKind::Mul | OpKind::And | OpKind::Or | OpKind::Xor => self.name(),
            // Non-associative: combine with addition
            OpKind::Sub | OpKind::Shl | OpKind::Shr { .. } => "add",
        }
    }

    /// Returns true if this operation is commutative.
    ///
    /// For non-commutative operations, the constant must be on the right side.
    const fn is_commutative(&self) -> bool {
        match self {
            OpKind::Add | OpKind::Mul | OpKind::And | OpKind::Or | OpKind::Xor => true,
            OpKind::Sub | OpKind::Shl | OpKind::Shr { .. } => false,
        }
    }
}

impl ReassociationPass {
    /// Creates a new reassociation pass.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Gets the OpKind if the operation can be reassociated.
    ///
    /// Returns (kind, dest, left_operand, right_operand).
    /// For shift operations, left is the value being shifted, right is the amount.
    fn get_op_kind(op: &SsaOp) -> Option<(OpKind, SsaVarId, SsaVarId, SsaVarId)> {
        match op {
            SsaOp::Add { dest, left, right } => Some((OpKind::Add, *dest, *left, *right)),
            SsaOp::Sub { dest, left, right } => Some((OpKind::Sub, *dest, *left, *right)),
            SsaOp::Mul { dest, left, right } => Some((OpKind::Mul, *dest, *left, *right)),
            SsaOp::And { dest, left, right } => Some((OpKind::And, *dest, *left, *right)),
            SsaOp::Or { dest, left, right } => Some((OpKind::Or, *dest, *left, *right)),
            SsaOp::Xor { dest, left, right } => Some((OpKind::Xor, *dest, *left, *right)),
            SsaOp::Shl {
                dest,
                value,
                amount,
            } => Some((OpKind::Shl, *dest, *value, *amount)),
            SsaOp::Shr {
                dest,
                value,
                amount,
                unsigned,
            } => Some((
                OpKind::Shr {
                    unsigned: *unsigned,
                },
                *dest,
                *value,
                *amount,
            )),
            _ => None,
        }
    }

    /// Creates a new operation with the given operands.
    ///
    /// For shift operations, `left` is the value being shifted and `right` is the amount.
    fn make_op(kind: OpKind, dest: SsaVarId, left: SsaVarId, right: SsaVarId) -> SsaOp {
        match kind {
            OpKind::Add => SsaOp::Add { dest, left, right },
            OpKind::Sub => SsaOp::Sub { dest, left, right },
            OpKind::Mul => SsaOp::Mul { dest, left, right },
            OpKind::And => SsaOp::And { dest, left, right },
            OpKind::Or => SsaOp::Or { dest, left, right },
            OpKind::Xor => SsaOp::Xor { dest, left, right },
            OpKind::Shl => SsaOp::Shl {
                dest,
                value: left,
                amount: right,
            },
            OpKind::Shr { unsigned } => SsaOp::Shr {
                dest,
                value: left,
                amount: right,
                unsigned,
            },
        }
    }

    /// Finds reassociation candidates.
    fn find_candidates(
        ssa: &SsaFunction,
        constants: &HashMap<SsaVarId, ConstValue>,
        index: &DefUseIndex,
        uses: &HashMap<SsaVarId, usize>,
    ) -> Vec<ReassociationCandidate> {
        let mut candidates = Vec::new();

        for (block_idx, instr_idx, instr) in ssa.iter_instructions() {
            if let Some(candidate) =
                Self::check_reassociation(instr.op(), block_idx, instr_idx, constants, index, uses)
            {
                candidates.push(candidate);
            }
        }

        candidates
    }

    /// Checks if an operation can be reassociated.
    fn check_reassociation(
        op: &SsaOp,
        block_idx: usize,
        instr_idx: usize,
        constants: &HashMap<SsaVarId, ConstValue>,
        index: &DefUseIndex,
        uses: &HashMap<SsaVarId, usize>,
    ) -> Option<ReassociationCandidate> {
        // Get the outer operation's kind and operands
        let (outer_kind, dest, outer_left, outer_right) = Self::get_op_kind(op)?;

        // Try: (inner_result op c2) where inner_result = (x op c1)
        // Check right operand is a constant
        let c2_value = constants.get(&outer_right)?;

        // Check left operand is the result of a same-kind operation
        // Use DefUseIndex to get (block, instruction, operation) in one call
        let (inner_block, inner_instr, inner_op) = index.full_definition(outer_left)?;
        let (inner_kind, inner_dest, inner_left, inner_right) = Self::get_op_kind(inner_op)?;

        // Must be the same operation kind
        if inner_kind != outer_kind {
            return None;
        }

        // The inner result should only be used once (by this outer operation)
        // Otherwise we'd create extra computation
        let inner_uses = uses.get(&inner_dest).copied().unwrap_or(0);
        if inner_uses > 1 {
            return None;
        }

        // Try to find a constant in the inner operation
        // Case 1: inner_right is a constant (works for all operations)
        // Pattern: (x op c1) op c2 → x op (c1 combine c2)
        if let Some(c1_value) = constants.get(&inner_right) {
            return Some(ReassociationCandidate {
                block_idx,
                instr_idx,
                dest,
                base_var: inner_left,
                const1_var: inner_right,
                const2_var: outer_right,
                const1_value: c1_value.clone(),
                const2_value: c2_value.clone(),
                inner_block,
                inner_instr,
                inner_dest,
                op_kind: outer_kind,
            });
        }

        // Case 2: inner_left is a constant (only for commutative ops)
        // Pattern: (c1 op x) op c2 → x op (c1 combine c2)
        // This doesn't work for sub/shl/shr: (c1 - x) - c2 ≠ x - (c1 + c2)
        if outer_kind.is_commutative() {
            if let Some(c1_value) = constants.get(&inner_left) {
                return Some(ReassociationCandidate {
                    block_idx,
                    instr_idx,
                    dest,
                    base_var: inner_right,
                    const1_var: inner_left,
                    const2_var: outer_right,
                    const1_value: c1_value.clone(),
                    const2_value: c2_value.clone(),
                    inner_block,
                    inner_instr,
                    inner_dest,
                    op_kind: outer_kind,
                });
            }
        }

        None
    }

    /// Applies the reassociation transformations.
    fn apply_reassociations(
        ssa: &mut SsaFunction,
        candidates: Vec<ReassociationCandidate>,
        method_token: Token,
        changes: &mut EventLog,
    ) {
        for candidate in candidates {
            // Combine the constants
            let Some(combined) = candidate
                .op_kind
                .combine(&candidate.const1_value, &candidate.const2_value)
            else {
                continue;
            };

            // Update the first constant definition to the combined value
            if let Some(block) = ssa.block_mut(candidate.inner_block) {
                // Find and update the const1 definition
                for instr in block.instructions_mut() {
                    if let SsaOp::Const { dest, value: _ } = instr.op() {
                        if *dest == candidate.const1_var {
                            instr.set_op(SsaOp::Const {
                                dest: *dest,
                                value: combined.clone(),
                            });
                            break;
                        }
                    }
                }

                // Update the inner operation to just use base_var and the combined constant
                let inner_instr = &mut block.instructions_mut()[candidate.inner_instr];
                inner_instr.set_op(Self::make_op(
                    candidate.op_kind,
                    candidate.inner_dest,
                    candidate.base_var,
                    candidate.const1_var,
                ));
            }

            // Replace the outer operation with a Copy from the inner result
            if let Some(block) = ssa.block_mut(candidate.block_idx) {
                let outer_instr = &mut block.instructions_mut()[candidate.instr_idx];
                outer_instr.set_op(SsaOp::Copy {
                    dest: candidate.dest,
                    src: candidate.inner_dest,
                });
            }

            changes
                .record(EventKind::ConstantFolded)
                .at(method_token, candidate.instr_idx)
                .message(format!(
                    "reassociate: (x {} c1) {} c2 → x {} (c1 {} c2)",
                    candidate.op_kind.name(),
                    candidate.op_kind.name(),
                    candidate.op_kind.name(),
                    candidate.op_kind.combine_name()
                ));
        }
    }
}

impl SsaPass for ReassociationPass {
    fn name(&self) -> &'static str {
        "reassociation"
    }

    fn description(&self) -> &'static str {
        "Reorder operations to enable constant folding (add, sub, mul, and, or, xor, shl, shr)"
    }

    fn run_on_method(
        &self,
        ssa: &mut SsaFunction,
        method_token: Token,
        ctx: &AnalysisContext,
        _assembly: &Arc<CilObject>,
    ) -> Result<bool> {
        let mut changes = EventLog::new();

        // Gather information
        let constants = ssa.find_constants();
        let index = DefUseIndex::build_with_ops(ssa);
        let uses = ssa.count_uses();

        // Find and apply reassociations
        let candidates = Self::find_candidates(ssa, &constants, &index, &uses);
        Self::apply_reassociations(ssa, candidates, method_token, &mut changes);

        let changed = !changes.is_empty();
        if changed {
            ctx.events.merge(changes);
        }
        Ok(changed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_op_kind_combine_add() {
        let c1 = ConstValue::I32(5);
        let c2 = ConstValue::I32(3);
        let result = OpKind::Add.combine(&c1, &c2);
        assert_eq!(result, Some(ConstValue::I32(8)));
    }

    #[test]
    fn test_op_kind_combine_xor() {
        let c1 = ConstValue::I32(0xF0);
        let c2 = ConstValue::I32(0x0F);
        let result = OpKind::Xor.combine(&c1, &c2);
        assert_eq!(result, Some(ConstValue::I32(0xFF)));
    }

    #[test]
    fn test_op_kind_combine_mul() {
        let c1 = ConstValue::I32(7);
        let c2 = ConstValue::I32(11);
        let result = OpKind::Mul.combine(&c1, &c2);
        assert_eq!(result, Some(ConstValue::I32(77)));
    }

    #[test]
    fn test_op_kind_combine_and() {
        let c1 = ConstValue::I32(0xFF);
        let c2 = ConstValue::I32(0x0F);
        let result = OpKind::And.combine(&c1, &c2);
        assert_eq!(result, Some(ConstValue::I32(0x0F)));
    }

    #[test]
    fn test_op_kind_combine_or() {
        let c1 = ConstValue::I32(0xF0);
        let c2 = ConstValue::I32(0x0F);
        let result = OpKind::Or.combine(&c1, &c2);
        assert_eq!(result, Some(ConstValue::I32(0xFF)));
    }

    #[test]
    fn test_op_kind_combine_sub() {
        // (x - 5) - 3 → x - (5 + 3) → x - 8
        let c1 = ConstValue::I32(5);
        let c2 = ConstValue::I32(3);
        let result = OpKind::Sub.combine(&c1, &c2);
        assert_eq!(result, Some(ConstValue::I32(8)));
    }

    #[test]
    fn test_op_kind_combine_shl() {
        // (x << 2) << 3 → x << (2 + 3) → x << 5
        let c1 = ConstValue::I32(2);
        let c2 = ConstValue::I32(3);
        let result = OpKind::Shl.combine(&c1, &c2);
        assert_eq!(result, Some(ConstValue::I32(5)));
    }

    #[test]
    fn test_op_kind_combine_shr() {
        // (x >> 4) >> 2 → x >> (4 + 2) → x >> 6
        let c1 = ConstValue::I32(4);
        let c2 = ConstValue::I32(2);
        let result = OpKind::Shr { unsigned: false }.combine(&c1, &c2);
        assert_eq!(result, Some(ConstValue::I32(6)));
    }

    #[test]
    fn test_op_kind_combine_shr_unsigned() {
        // (x >>> 4) >>> 2 → x >>> (4 + 2) → x >>> 6
        let c1 = ConstValue::I32(4);
        let c2 = ConstValue::I32(2);
        let result = OpKind::Shr { unsigned: true }.combine(&c1, &c2);
        assert_eq!(result, Some(ConstValue::I32(6)));
    }

    #[test]
    fn test_op_kind_is_commutative() {
        assert!(OpKind::Add.is_commutative());
        assert!(OpKind::Mul.is_commutative());
        assert!(OpKind::And.is_commutative());
        assert!(OpKind::Or.is_commutative());
        assert!(OpKind::Xor.is_commutative());
        assert!(!OpKind::Sub.is_commutative());
        assert!(!OpKind::Shl.is_commutative());
        assert!(!OpKind::Shr { unsigned: false }.is_commutative());
        assert!(!OpKind::Shr { unsigned: true }.is_commutative());
    }

    #[test]
    fn test_op_kind_combine_name() {
        // Associative operations combine with themselves
        assert_eq!(OpKind::Add.combine_name(), "add");
        assert_eq!(OpKind::Mul.combine_name(), "mul");
        assert_eq!(OpKind::And.combine_name(), "and");
        assert_eq!(OpKind::Or.combine_name(), "or");
        assert_eq!(OpKind::Xor.combine_name(), "xor");
        // Non-associative operations combine with add
        assert_eq!(OpKind::Sub.combine_name(), "add");
        assert_eq!(OpKind::Shl.combine_name(), "add");
        assert_eq!(OpKind::Shr { unsigned: false }.combine_name(), "add");
        assert_eq!(OpKind::Shr { unsigned: true }.combine_name(), "add");
    }

    #[test]
    fn test_op_kind_name() {
        assert_eq!(OpKind::Add.name(), "add");
        assert_eq!(OpKind::Sub.name(), "sub");
        assert_eq!(OpKind::Mul.name(), "mul");
        assert_eq!(OpKind::And.name(), "and");
        assert_eq!(OpKind::Or.name(), "or");
        assert_eq!(OpKind::Xor.name(), "xor");
        assert_eq!(OpKind::Shl.name(), "shl");
        assert_eq!(OpKind::Shr { unsigned: false }.name(), "shr");
        assert_eq!(OpKind::Shr { unsigned: true }.name(), "shr.un");
    }
}
