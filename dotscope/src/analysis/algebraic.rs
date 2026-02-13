//! Algebraic identity simplification.
//!
//! This module provides shared logic for detecting algebraic identities
//! in SSA operations. It checks for patterns like:
//!
//! - `x xor x = 0` (self-cancelling)
//! - `x xor 0 = x` (identity element)
//! - `x * 0 = 0` (absorbing element)
//! - `x * 1 = x` (identity element)
//! - etc.
//!
//! # Usage
//!
//! ```rust,ignore
//! use dotscope::analysis::{simplify_op, SimplifyResult};
//!
//! let constants = ssa.find_constants();
//! match simplify_op(op, &constants) {
//!     SimplifyResult::Constant(value) => { /* replace with constant */ }
//!     SimplifyResult::Copy(var) => { /* replace with copy of var */ }
//!     SimplifyResult::None => { /* no simplification */ }
//! }
//! ```

use std::{collections::HashMap, hash::BuildHasher};

use crate::analysis::{ConstValue, SsaOp, SsaVarId};

/// Result of checking an operation for algebraic simplification.
#[derive(Debug, Clone, PartialEq)]
pub enum SimplifyResult {
    /// The operation simplifies to a constant value.
    Constant(ConstValue),
    /// The operation simplifies to copying another variable.
    Copy(SsaVarId),
    /// No simplification possible.
    None,
}

impl SimplifyResult {
    /// Returns true if a simplification is possible.
    #[must_use]
    pub fn is_some(&self) -> bool {
        !matches!(self, Self::None)
    }

    /// Returns true if no simplification is possible.
    #[must_use]
    pub fn is_none(&self) -> bool {
        matches!(self, Self::None)
    }
}

/// Check if an SSA operation can be algebraically simplified.
///
/// This function checks for common algebraic identities that allow
/// an operation to be replaced with a simpler form (constant or copy).
#[must_use]
pub fn simplify_op<S: BuildHasher>(
    op: &SsaOp,
    constants: &HashMap<SsaVarId, ConstValue, S>,
) -> SimplifyResult {
    match op {
        // XOR: x ^ x = 0, x ^ 0 = x
        SsaOp::Xor { left, right, .. } => {
            if left == right {
                return SimplifyResult::Constant(ConstValue::I32(0));
            }
            if constants.get(right).is_some_and(ConstValue::is_zero) {
                return SimplifyResult::Copy(*left);
            }
            if constants.get(left).is_some_and(ConstValue::is_zero) {
                return SimplifyResult::Copy(*right);
            }
            SimplifyResult::None
        }

        // OR: x | x = x, x | 0 = x, x | -1 = -1
        SsaOp::Or { left, right, .. } => {
            if left == right {
                return SimplifyResult::Copy(*left);
            }
            if let Some(c) = constants.get(right) {
                if c.is_zero() {
                    return SimplifyResult::Copy(*left);
                }
                if c.is_all_ones() {
                    return SimplifyResult::Constant(c.clone());
                }
            }
            if let Some(c) = constants.get(left) {
                if c.is_zero() {
                    return SimplifyResult::Copy(*right);
                }
                if c.is_all_ones() {
                    return SimplifyResult::Constant(c.clone());
                }
            }
            SimplifyResult::None
        }

        // AND: x & x = x, x & 0 = 0, x & -1 = x
        SsaOp::And { left, right, .. } => {
            if left == right {
                return SimplifyResult::Copy(*left);
            }
            if let Some(c) = constants.get(right) {
                if c.is_zero() {
                    return SimplifyResult::Constant(c.zero_of_same_type());
                }
                if c.is_all_ones() {
                    return SimplifyResult::Copy(*left);
                }
            }
            if let Some(c) = constants.get(left) {
                if c.is_zero() {
                    return SimplifyResult::Constant(c.zero_of_same_type());
                }
                if c.is_all_ones() {
                    return SimplifyResult::Copy(*right);
                }
            }
            SimplifyResult::None
        }

        // ADD: x + 0 = x
        SsaOp::Add { left, right, .. } => {
            if constants.get(right).is_some_and(ConstValue::is_zero) {
                return SimplifyResult::Copy(*left);
            }
            if constants.get(left).is_some_and(ConstValue::is_zero) {
                return SimplifyResult::Copy(*right);
            }
            SimplifyResult::None
        }

        // SUB: x - 0 = x, x - x = 0
        SsaOp::Sub { left, right, .. } => {
            if left == right {
                return SimplifyResult::Constant(ConstValue::I32(0));
            }
            if constants.get(right).is_some_and(ConstValue::is_zero) {
                return SimplifyResult::Copy(*left);
            }
            SimplifyResult::None
        }

        // MUL: x * 0 = 0, x * 1 = x
        SsaOp::Mul { left, right, .. } => {
            if let Some(c) = constants.get(right) {
                if c.is_zero() {
                    return SimplifyResult::Constant(c.clone());
                }
                if c.is_one() {
                    return SimplifyResult::Copy(*left);
                }
            }
            if let Some(c) = constants.get(left) {
                if c.is_zero() {
                    return SimplifyResult::Constant(c.clone());
                }
                if c.is_one() {
                    return SimplifyResult::Copy(*right);
                }
            }
            SimplifyResult::None
        }

        // DIV: x / 1 = x, 0 / x = 0
        SsaOp::Div { left, right, .. } => {
            if constants.get(right).is_some_and(ConstValue::is_one) {
                return SimplifyResult::Copy(*left);
            }
            if let Some(c) = constants.get(left) {
                if c.is_zero() {
                    return SimplifyResult::Constant(c.clone());
                }
            }
            SimplifyResult::None
        }

        // REM: 0 % x = 0, x % 1 = 0
        SsaOp::Rem { left, right, .. } => {
            if let Some(c) = constants.get(left) {
                if c.is_zero() {
                    return SimplifyResult::Constant(c.clone());
                }
            }
            if let Some(c) = constants.get(right) {
                if c.is_one() {
                    return SimplifyResult::Constant(c.zero_of_same_type());
                }
            }
            SimplifyResult::None
        }

        // SHL/SHR: x << 0 = x, x >> 0 = x
        SsaOp::Shl { value, amount, .. } | SsaOp::Shr { value, amount, .. } => {
            if constants.get(amount).is_some_and(ConstValue::is_zero) {
                return SimplifyResult::Copy(*value);
            }
            SimplifyResult::None
        }

        // Comparisons: x == x → true, x < x → false, x > x → false
        SsaOp::Ceq { left, right, .. } => {
            if left == right {
                return SimplifyResult::Constant(ConstValue::I32(1));
            }
            SimplifyResult::None
        }

        SsaOp::Clt { left, right, .. } | SsaOp::Cgt { left, right, .. } => {
            if left == right {
                return SimplifyResult::Constant(ConstValue::I32(0));
            }
            SimplifyResult::None
        }

        _ => SimplifyResult::None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_constants(pairs: &[(SsaVarId, ConstValue)]) -> HashMap<SsaVarId, ConstValue> {
        pairs.iter().cloned().collect()
    }

    #[test]
    fn test_xor_self_cancels() {
        let v1 = SsaVarId::new();
        let dest = SsaVarId::new();
        let op = SsaOp::Xor {
            dest,
            left: v1,
            right: v1,
        };
        assert_eq!(
            simplify_op(&op, &HashMap::new()),
            SimplifyResult::Constant(ConstValue::I32(0))
        );
    }

    #[test]
    fn test_xor_zero_identity() {
        let v1 = SsaVarId::new();
        let v2 = SsaVarId::new();
        let dest = SsaVarId::new();
        let op = SsaOp::Xor {
            dest,
            left: v1,
            right: v2,
        };
        let constants = make_constants(&[(v2, ConstValue::I32(0))]);
        assert_eq!(simplify_op(&op, &constants), SimplifyResult::Copy(v1));
    }

    #[test]
    fn test_mul_zero_absorbs() {
        let v1 = SsaVarId::new();
        let v2 = SsaVarId::new();
        let dest = SsaVarId::new();
        let op = SsaOp::Mul {
            dest,
            left: v1,
            right: v2,
        };
        let constants = make_constants(&[(v2, ConstValue::I32(0))]);
        assert_eq!(
            simplify_op(&op, &constants),
            SimplifyResult::Constant(ConstValue::I32(0))
        );
    }

    #[test]
    fn test_mul_one_identity() {
        let v1 = SsaVarId::new();
        let v2 = SsaVarId::new();
        let dest = SsaVarId::new();
        let op = SsaOp::Mul {
            dest,
            left: v1,
            right: v2,
        };
        let constants = make_constants(&[(v2, ConstValue::I32(1))]);
        assert_eq!(simplify_op(&op, &constants), SimplifyResult::Copy(v1));
    }

    #[test]
    fn test_add_zero_identity() {
        let v1 = SsaVarId::new();
        let v2 = SsaVarId::new();
        let dest = SsaVarId::new();
        let op = SsaOp::Add {
            dest,
            left: v1,
            right: v2,
        };
        let constants = make_constants(&[(v2, ConstValue::I32(0))]);
        assert_eq!(simplify_op(&op, &constants), SimplifyResult::Copy(v1));
    }

    #[test]
    fn test_sub_self_cancels() {
        let v1 = SsaVarId::new();
        let dest = SsaVarId::new();
        let op = SsaOp::Sub {
            dest,
            left: v1,
            right: v1,
        };
        assert_eq!(
            simplify_op(&op, &HashMap::new()),
            SimplifyResult::Constant(ConstValue::I32(0))
        );
    }

    #[test]
    fn test_and_zero_absorbs() {
        let v1 = SsaVarId::new();
        let v2 = SsaVarId::new();
        let dest = SsaVarId::new();
        let op = SsaOp::And {
            dest,
            left: v1,
            right: v2,
        };
        let constants = make_constants(&[(v2, ConstValue::I32(0))]);
        assert_eq!(
            simplify_op(&op, &constants),
            SimplifyResult::Constant(ConstValue::I32(0))
        );
    }

    #[test]
    fn test_or_zero_identity() {
        let v1 = SsaVarId::new();
        let v2 = SsaVarId::new();
        let dest = SsaVarId::new();
        let op = SsaOp::Or {
            dest,
            left: v1,
            right: v2,
        };
        let constants = make_constants(&[(v2, ConstValue::I32(0))]);
        assert_eq!(simplify_op(&op, &constants), SimplifyResult::Copy(v1));
    }

    #[test]
    fn test_div_one_identity() {
        let v1 = SsaVarId::new();
        let v2 = SsaVarId::new();
        let dest = SsaVarId::new();
        let op = SsaOp::Div {
            dest,
            left: v1,
            right: v2,
            unsigned: false,
        };
        let constants = make_constants(&[(v2, ConstValue::I32(1))]);
        assert_eq!(simplify_op(&op, &constants), SimplifyResult::Copy(v1));
    }

    #[test]
    fn test_shl_zero_identity() {
        let v1 = SsaVarId::new();
        let v2 = SsaVarId::new();
        let dest = SsaVarId::new();
        let op = SsaOp::Shl {
            dest,
            value: v1,
            amount: v2,
        };
        let constants = make_constants(&[(v2, ConstValue::I32(0))]);
        assert_eq!(simplify_op(&op, &constants), SimplifyResult::Copy(v1));
    }

    #[test]
    fn test_no_simplification() {
        let v1 = SsaVarId::new();
        let v2 = SsaVarId::new();
        let dest = SsaVarId::new();
        let op = SsaOp::Add {
            dest,
            left: v1,
            right: v2,
        };
        // No constants - no simplification
        assert_eq!(simplify_op(&op, &HashMap::new()), SimplifyResult::None);
    }

    #[test]
    fn test_rem_one_zero() {
        let v1 = SsaVarId::new();
        let v2 = SsaVarId::new();
        let dest = SsaVarId::new();
        let op = SsaOp::Rem {
            dest,
            left: v1,
            right: v2,
            unsigned: false,
        };
        let constants = make_constants(&[(v2, ConstValue::I32(1))]);
        assert_eq!(
            simplify_op(&op, &constants),
            SimplifyResult::Constant(ConstValue::I32(0))
        );
    }

    #[test]
    fn test_ceq_self_true() {
        let v1 = SsaVarId::new();
        let dest = SsaVarId::new();
        let op = SsaOp::Ceq {
            dest,
            left: v1,
            right: v1,
        };
        assert_eq!(
            simplify_op(&op, &HashMap::new()),
            SimplifyResult::Constant(ConstValue::I32(1))
        );
    }

    #[test]
    fn test_clt_self_false() {
        let v1 = SsaVarId::new();
        let dest = SsaVarId::new();
        let op = SsaOp::Clt {
            dest,
            left: v1,
            right: v1,
            unsigned: false,
        };
        assert_eq!(
            simplify_op(&op, &HashMap::new()),
            SimplifyResult::Constant(ConstValue::I32(0))
        );
    }

    #[test]
    fn test_cgt_self_false() {
        let v1 = SsaVarId::new();
        let dest = SsaVarId::new();
        let op = SsaOp::Cgt {
            dest,
            left: v1,
            right: v1,
            unsigned: false,
        };
        assert_eq!(
            simplify_op(&op, &HashMap::new()),
            SimplifyResult::Constant(ConstValue::I32(0))
        );
    }
}
