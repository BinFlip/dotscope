//! Algebraic simplifications pass.
//!
//! This pass transforms algebraic identities into simpler forms:
//!
//! ## Self-canceling operations
//! - `x xor x` → `0`
//! - `x sub x` → `0`
//!
//! ## Idempotent operations
//! - `x or x` → `x`
//! - `x and x` → `x`
//!
//! ## Identity operations (with constant 0)
//! - `x add 0` / `0 add x` → `x`
//! - `x sub 0` → `x`
//! - `x xor 0` / `0 xor x` → `x`
//! - `x or 0` / `0 or x` → `x`
//!
//! ## Absorbing operations (with constant 0)
//! - `x mul 0` / `0 mul x` → `0`
//! - `x and 0` / `0 and x` → `0`
//!
//! ## Identity operations (with constant 1)
//! - `x mul 1` / `1 mul x` → `x`
//!
//! ## All-bits-set identity (with constant -1)
//! - `x and -1` / `-1 and x` → `x`
//! - `x or -1` / `-1 or x` → `-1`
//!
//! These simplifications are essential for deobfuscation because obfuscators
//! often insert redundant operations like `x xor x xor y` to compute `y`.

use std::{collections::HashMap, sync::Arc};

use crate::{
    analysis::{simplify_op, ConstValue, SimplifyResult, SsaFunction, SsaOp, SsaVarId},
    compiler::{pass::SsaPass, CompilerContext, EventKind, EventLog},
    metadata::token::Token,
    CilObject, Result,
};

/// Algebraic simplifications pass that transforms redundant operations.
///
/// This pass identifies patterns like `x xor x`, `x or x`, and operations
/// with identity elements (0 for add/xor/or, 1 for mul) and simplifies them.
pub struct AlgebraicSimplificationPass;

impl Default for AlgebraicSimplificationPass {
    fn default() -> Self {
        Self::new()
    }
}

/// The type of simplification applied.
#[derive(Debug, Clone)]
enum Simplification {
    /// Replace with a constant value
    Constant(ConstValue),
    /// Replace with a copy from another variable
    Copy(SsaVarId),
}

/// Information about a simplification candidate.
#[derive(Debug)]
struct SimplificationCandidate {
    /// Block index
    block_idx: usize,
    /// Instruction index within block
    instr_idx: usize,
    /// The destination variable
    dest: SsaVarId,
    /// The simplification to apply
    simplification: Simplification,
    /// Description for logging
    description: String,
}

impl AlgebraicSimplificationPass {
    /// Creates a new algebraic simplification pass.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Identifies simplification candidates in the SSA function.
    fn find_candidates(
        ssa: &SsaFunction,
        constants: &HashMap<SsaVarId, ConstValue>,
    ) -> Vec<SimplificationCandidate> {
        let mut candidates = Vec::new();

        for (block_idx, instr_idx, instr) in ssa.iter_instructions() {
            let op = instr.op();
            if let Some(candidate) = Self::check_simplification(op, block_idx, instr_idx, constants)
            {
                candidates.push(candidate);
            }
        }

        candidates
    }

    /// Checks if an operation can be algebraically simplified.
    fn check_simplification(
        op: &SsaOp,
        block_idx: usize,
        instr_idx: usize,
        constants: &HashMap<SsaVarId, ConstValue>,
    ) -> Option<SimplificationCandidate> {
        let dest = op.dest()?;
        match simplify_op(op, constants) {
            SimplifyResult::Constant(value) => Some(SimplificationCandidate {
                block_idx,
                instr_idx,
                dest,
                simplification: Simplification::Constant(value),
                description: "algebraic → const".to_string(),
            }),
            SimplifyResult::Copy(src) => Some(SimplificationCandidate {
                block_idx,
                instr_idx,
                dest,
                simplification: Simplification::Copy(src),
                description: "algebraic → copy".to_string(),
            }),
            SimplifyResult::None => None,
        }
    }

    /// Applies the simplifications to the SSA function.
    fn apply_simplifications(
        ssa: &mut SsaFunction,
        candidates: Vec<SimplificationCandidate>,
        method_token: Token,
        changes: &mut EventLog,
    ) {
        for candidate in candidates {
            if let Some(block) = ssa.block_mut(candidate.block_idx) {
                let instr = &mut block.instructions_mut()[candidate.instr_idx];
                let new_op = match candidate.simplification {
                    Simplification::Constant(value) => SsaOp::Const {
                        dest: candidate.dest,
                        value,
                    },
                    Simplification::Copy(src) => SsaOp::Copy {
                        dest: candidate.dest,
                        src,
                    },
                };
                instr.set_op(new_op);
                changes
                    .record(EventKind::ConstantFolded)
                    .at(method_token, candidate.instr_idx)
                    .message(&candidate.description);
            }
        }
    }
}

impl SsaPass for AlgebraicSimplificationPass {
    fn name(&self) -> &'static str {
        "algebraic-simplification"
    }

    fn description(&self) -> &'static str {
        "Simplify algebraic identities (x xor x = 0, x or x = x, etc.)"
    }

    fn run_on_method(
        &self,
        ssa: &mut SsaFunction,
        method_token: Token,
        ctx: &CompilerContext,
        _assembly: &Arc<CilObject>,
    ) -> Result<bool> {
        let mut changes = EventLog::new();

        // Find all constant definitions
        let constants = ssa.find_constants();

        // Find simplification candidates
        let candidates = Self::find_candidates(ssa, &constants);

        // Apply simplifications
        Self::apply_simplifications(ssa, candidates, method_token, &mut changes);

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
    fn test_div_by_one() {
        let left = SsaVarId::from_index(0);
        let right = SsaVarId::from_index(1);
        let dest = SsaVarId::from_index(2);
        let constants: HashMap<SsaVarId, ConstValue> = [(right, ConstValue::I32(1))].into();
        let op = SsaOp::Div {
            dest,
            left,
            right,
            unsigned: false,
        };
        let result = AlgebraicSimplificationPass::check_simplification(&op, 0, 0, &constants);
        assert!(result.is_some());
        let candidate = result.unwrap();
        assert!(matches!(candidate.simplification, Simplification::Copy(v) if v == left));
    }

    #[test]
    fn test_rem_by_one() {
        let left = SsaVarId::from_index(0);
        let right = SsaVarId::from_index(1);
        let dest = SsaVarId::from_index(2);
        let constants: HashMap<SsaVarId, ConstValue> = [(right, ConstValue::I32(1))].into();
        let op = SsaOp::Rem {
            dest,
            left,
            right,
            unsigned: false,
        };
        let result = AlgebraicSimplificationPass::check_simplification(&op, 0, 0, &constants);
        assert!(result.is_some());
        let candidate = result.unwrap();
        assert!(matches!(
            candidate.simplification,
            Simplification::Constant(ConstValue::I32(0))
        ));
    }

    #[test]
    fn test_ceq_same_var() {
        let x = SsaVarId::from_index(0);
        let dest = SsaVarId::from_index(1);
        let constants: HashMap<SsaVarId, ConstValue> = HashMap::new();
        let op = SsaOp::Ceq {
            dest,
            left: x,
            right: x,
        };
        let result = AlgebraicSimplificationPass::check_simplification(&op, 0, 0, &constants);
        assert!(result.is_some());
        let candidate = result.unwrap();
        assert!(matches!(
            candidate.simplification,
            Simplification::Constant(ConstValue::I32(1))
        ));
    }

    #[test]
    fn test_clt_same_var() {
        let x = SsaVarId::from_index(0);
        let dest = SsaVarId::from_index(1);
        let constants: HashMap<SsaVarId, ConstValue> = HashMap::new();
        let op = SsaOp::Clt {
            dest,
            left: x,
            right: x,
            unsigned: false,
        };
        let result = AlgebraicSimplificationPass::check_simplification(&op, 0, 0, &constants);
        assert!(result.is_some());
        let candidate = result.unwrap();
        assert!(matches!(
            candidate.simplification,
            Simplification::Constant(ConstValue::I32(0))
        ));
    }

    #[test]
    fn test_cgt_same_var() {
        let x = SsaVarId::from_index(0);
        let dest = SsaVarId::from_index(1);
        let constants: HashMap<SsaVarId, ConstValue> = HashMap::new();
        let op = SsaOp::Cgt {
            dest,
            left: x,
            right: x,
            unsigned: false,
        };
        let result = AlgebraicSimplificationPass::check_simplification(&op, 0, 0, &constants);
        assert!(result.is_some());
        let candidate = result.unwrap();
        assert!(matches!(
            candidate.simplification,
            Simplification::Constant(ConstValue::I32(0))
        ));
    }
}
