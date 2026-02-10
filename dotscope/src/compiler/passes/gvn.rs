//! Global Value Numbering (GVN) pass.
//!
//! This pass eliminates redundant computations by detecting when the same
//! expression is computed multiple times with the same operands, and replacing
//! later uses with the earlier result.
//!
//! # Example
//!
//! Before:
//! ```text
//! v1 = add v0, 5
//! v2 = add v0, 5    // Redundant - same operation
//! v3 = mul v1, v2
//! ```
//!
//! After:
//! ```text
//! v1 = add v0, 5
//! v2 = add v0, 5    // Now dead (DCE will remove)
//! v3 = mul v1, v1   // v2 replaced with v1
//! ```
//!
//! # Algorithm
//!
//! The pass uses hash-based value numbering:
//!
//! 1. For each pure operation, create a hashable key from its opcode and operands
//! 2. Normalize commutative operations (e.g., `add v1, v0` → `add v0, v1`)
//! 3. If the key was seen before, replace uses of the new result with the old one
//! 4. Otherwise, record the key with this operation's result
//!
//! # Limitations
//!
//! - Only handles pure operations (no side effects)
//! - Does not perform code motion (dominator-based GVN would be more powerful)
//! - Works within a single method

use std::{collections::HashMap, sync::Arc};

use crate::{
    analysis::{BinaryOpKind, SsaFunction, SsaOp, SsaVarId, UnaryOpKind},
    compiler::{pass::SsaPass, CompilerContext, EventKind, EventLog},
    metadata::token::Token,
    CilObject, Result,
};

/// A hashable key representing an operation for value numbering.
///
/// This captures the "value" of an expression - the operation type and operands,
/// but not the destination. Two operations with the same key compute the same value.
///
/// Uses the centralized `BinaryOpKind` and `UnaryOpKind` types from the SSA module.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum ValueKey {
    /// Binary operation: (kind, unsigned_flag, left, right)
    ///
    /// The unsigned flag is included for operations where signedness affects
    /// semantics (Div, Rem, Shr, Clt, Cgt). For other operations, it's normalized
    /// to `false` for consistent hashing.
    Binary(BinaryOpKind, bool, SsaVarId, SsaVarId),

    /// Unary operation: (kind, operand)
    Unary(UnaryOpKind, SsaVarId),
}

impl ValueKey {
    /// Creates a normalized value key from an SSA operation.
    ///
    /// Returns `None` for operations that shouldn't be value-numbered
    /// (impure operations, constants, control flow, etc.).
    ///
    /// Uses `as_binary_op()` and `as_unary_op()` for extraction, then applies
    /// normalization for commutative operations.
    fn from_op(op: &SsaOp) -> Option<(Self, SsaVarId)> {
        // Try binary operations first
        if let Some(info) = op.as_binary_op() {
            // Skip overflow-checked operations (they may throw)
            if matches!(
                info.kind,
                BinaryOpKind::AddOvf | BinaryOpKind::SubOvf | BinaryOpKind::MulOvf
            ) {
                return None;
            }

            // Normalize for consistent hashing
            let normalized = info.normalized();
            let (kind, unsigned, left, right) = normalized.value_key();
            return Some((Self::Binary(kind, unsigned, left, right), normalized.dest));
        }

        // Try unary operations
        if let Some(info) = op.as_unary_op() {
            // Skip Ckfinite (it may throw)
            if info.kind == UnaryOpKind::Ckfinite {
                return None;
            }
            return Some((Self::Unary(info.kind, info.operand), info.dest));
        }

        // Skip everything else (constants, loads, stores, calls, control flow, etc.)
        None
    }
}

/// Global Value Numbering pass.
///
/// Eliminates redundant computations by detecting equivalent expressions
/// and replacing later occurrences with references to earlier results.
pub struct GlobalValueNumberingPass;

impl Default for GlobalValueNumberingPass {
    fn default() -> Self {
        Self::new()
    }
}

impl GlobalValueNumberingPass {
    /// Creates a new GVN pass.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Runs GVN on a single SSA function.
    ///
    /// Returns the number of redundant expressions eliminated.
    fn run_gvn(ssa: &mut SsaFunction, method_token: Token, changes: &mut EventLog) -> usize {
        // Map from value key to the first variable that computed it
        let mut value_map: HashMap<ValueKey, SsaVarId> = HashMap::new();

        // Collect redundant definitions: (redundant_var, original_var)
        let mut redundant: Vec<(SsaVarId, SsaVarId)> = Vec::new();

        // First pass: identify redundant computations
        for block in ssa.blocks() {
            for instr in block.instructions() {
                if let Some((key, dest)) = ValueKey::from_op(instr.op()) {
                    if let Some(&original) = value_map.get(&key) {
                        // This computation is redundant
                        redundant.push((dest, original));
                    } else {
                        // First time seeing this value
                        value_map.insert(key, dest);
                    }
                }
            }
        }

        // Second pass: replace uses of redundant variables with originals
        let mut total_replaced = 0;
        for (redundant_var, original_var) in &redundant {
            let replaced = ssa.replace_uses(*redundant_var, *original_var);
            if replaced > 0 {
                changes
                    .record(EventKind::ConstantFolded) // Reuse existing kind for expression elimination
                    .method(method_token)
                    .message(format!(
                        "GVN: {redundant_var} → {original_var} ({replaced} uses)"
                    ));
                total_replaced += replaced;
            }
        }

        total_replaced
    }
}

impl SsaPass for GlobalValueNumberingPass {
    fn name(&self) -> &'static str {
        "global-value-numbering"
    }

    fn description(&self) -> &'static str {
        "Eliminates redundant computations using value numbering"
    }

    fn run_on_method(
        &self,
        ssa: &mut SsaFunction,
        method_token: Token,
        ctx: &CompilerContext,
        _assembly: &Arc<CilObject>,
    ) -> Result<bool> {
        let mut changes = EventLog::new();

        // GVN is a single-pass algorithm - no iteration needed
        // (unlike copy propagation which needs to resolve chains)
        Self::run_gvn(ssa, method_token, &mut changes);

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
    use crate::analysis::{ConstValue, SsaFunctionBuilder};

    #[test]
    fn test_value_key_binary_commutative() {
        // Test that commutative operations with swapped operands produce the same key
        let v0 = SsaVarId::new();
        let v1 = SsaVarId::new();
        let v2 = SsaVarId::new();
        let v3 = SsaVarId::new();

        // Add is commutative - should normalize to same key
        let add_op1 = SsaOp::Add {
            dest: v2,
            left: v0,
            right: v1,
        };
        let add_op2 = SsaOp::Add {
            dest: v3,
            left: v1,
            right: v0,
        }; // Swapped operands

        let (key1, _) = ValueKey::from_op(&add_op1).unwrap();
        let (key2, _) = ValueKey::from_op(&add_op2).unwrap();
        assert_eq!(key1, key2, "Add should be commutative");

        // Sub is not commutative - different keys
        let sub_op1 = SsaOp::Sub {
            dest: v2,
            left: v0,
            right: v1,
        };
        let sub_op2 = SsaOp::Sub {
            dest: v3,
            left: v1,
            right: v0,
        };

        let (key3, _) = ValueKey::from_op(&sub_op1).unwrap();
        let (key4, _) = ValueKey::from_op(&sub_op2).unwrap();
        assert_ne!(key3, key4, "Sub should NOT be commutative");
    }

    #[test]
    fn test_value_key_from_op() {
        let v0 = SsaVarId::new();
        let v1 = SsaVarId::new();
        let v2 = SsaVarId::new();

        // Add operation
        let add_op = SsaOp::Add {
            dest: v2,
            left: v0,
            right: v1,
        };
        let (key, dest) = ValueKey::from_op(&add_op).unwrap();
        assert_eq!(dest, v2);
        assert!(matches!(key, ValueKey::Binary(BinaryOpKind::Add, _, _, _)));

        // Neg operation
        let neg_op = SsaOp::Neg {
            dest: v1,
            operand: v0,
        };
        let (key, dest) = ValueKey::from_op(&neg_op).unwrap();
        assert_eq!(dest, v1);
        assert!(matches!(key, ValueKey::Unary(UnaryOpKind::Neg, _)));

        // Const should return None (not value-numbered)
        let const_op = SsaOp::Const {
            dest: v0,
            value: ConstValue::I32(42),
        };
        assert!(ValueKey::from_op(&const_op).is_none());
    }

    #[test]
    fn test_gvn_eliminates_redundant() {
        // Build SSA:
        // v2 = add v0, v1
        // v3 = add v0, v1  <- redundant
        // v4 = mul v2, v3
        let (mut ssa, v2) = {
            let mut v2_out = SsaVarId::new();
            let ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
                f.block(0, |b| {
                    let v0 = b.const_i32(10);
                    let v1 = b.const_i32(20);
                    let v2 = b.add(v0, v1);
                    v2_out = v2;
                    let v3 = b.add(v0, v1); // Redundant
                    let v4 = b.mul(v2, v3);
                    b.ret_val(v4);
                });
            });
            (ssa, v2_out)
        };

        let mut changes = EventLog::new();
        let replaced =
            GlobalValueNumberingPass::run_gvn(&mut ssa, Token::new(0x06000001), &mut changes);

        // Should have replaced uses of v3 with v2
        assert!(replaced > 0);
        assert!(!changes.is_empty());

        // The mul should now use v2 twice
        let block = ssa.block(0).unwrap();
        let mul_instr = &block.instructions()[4]; // After 2 consts and 2 adds
        if let SsaOp::Mul { left, right, .. } = mul_instr.op() {
            assert_eq!(*left, v2);
            assert_eq!(*right, v2);
        } else {
            panic!("Expected Mul instruction");
        }
    }

    #[test]
    fn test_gvn_commutative_order() {
        // Build SSA:
        // v2 = add v0, v1
        // v3 = add v1, v0  <- same as v2 (commutative)
        let (mut ssa, v2) = {
            let mut v2_out = SsaVarId::new();
            let ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
                f.block(0, |b| {
                    let v0 = b.const_i32(10);
                    let v1 = b.const_i32(20);
                    let v2 = b.add(v0, v1);
                    v2_out = v2;
                    let v3 = b.add(v1, v0); // Swapped
                    b.ret_val(v3);
                });
            });
            (ssa, v2_out)
        };

        let mut changes = EventLog::new();
        let replaced =
            GlobalValueNumberingPass::run_gvn(&mut ssa, Token::new(0x06000001), &mut changes);

        // Should detect that add v1, v0 == add v0, v1
        assert!(replaced > 0);

        // Return should now use v2
        let block = ssa.block(0).unwrap();
        let ret_instr = &block.instructions()[4]; // After 2 consts and 2 adds
        if let SsaOp::Return {
            value: Some(ret_val),
        } = ret_instr.op()
        {
            assert_eq!(*ret_val, v2);
        } else {
            panic!("Expected Return instruction");
        }
    }

    #[test]
    fn test_gvn_non_commutative_preserved() {
        // Build SSA:
        // v2 = sub v0, v1
        // v3 = sub v1, v0  <- NOT the same (sub is not commutative)
        let mut ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
            f.block(0, |b| {
                let v0 = b.const_i32(10);
                let v1 = b.const_i32(20);
                let _v2 = b.sub(v0, v1);
                let v3 = b.sub(v1, v0);
                b.ret_val(v3);
            });
        });

        let mut changes = EventLog::new();
        let replaced =
            GlobalValueNumberingPass::run_gvn(&mut ssa, Token::new(0x06000001), &mut changes);

        // Should NOT replace - these are different values
        assert_eq!(replaced, 0);
        assert!(changes.is_empty());
    }
}
