//! x86 flags modeling for condition code tracking.
//!
//! This module provides infrastructure for tracking x86 flags across instructions
//! and fusing compare/test instructions with subsequent conditional jumps.
//!
//! # Overview
//!
//! x86 uses implicit flags (ZF, SF, OF, CF, PF) set by comparison and arithmetic
//! operations. Conditional jumps test these flags to determine the branch direction.
//!
//! In SSA form, we want to eliminate this implicit state by fusing:
//! - `CMP a, b` + `Jcc target` → `BranchCmp(cmp, a, b, true_target, false_target)`
//! - `TEST a, b` + `Jcc target` → `BranchCmp(eq/ne, a & b, 0, ...)`
//!
//! # Flag Dependencies
//!
//! | Condition | Flags | Meaning |
//! |-----------|-------|---------|
//! | E/NE | ZF | Equal / Not equal |
//! | L/GE | SF≠OF | Less / Greater-or-equal (signed) |
//! | LE/G | ZF or SF≠OF | Less-or-equal / Greater (signed) |
//! | B/AE | CF | Below / Above-or-equal (unsigned) |
//! | BE/A | CF or ZF | Below-or-equal / Above (unsigned) |
//! | S/NS | SF | Sign / Not sign |
//! | O/NO | OF | Overflow / Not overflow |
//!
//! # Example
//!
//! ```rust,ignore
//! use dotscope::analysis::x86::flags::{FlagState, FlagProducer};
//! use dotscope::analysis::{X86Condition, X86Operand, X86Register, SsaVarId, CmpKind};
//!
//! let mut flags = FlagState::new();
//!
//! // After CMP eax, 10
//! let v0 = SsaVarId::new();  // SSA var for eax
//! let v1 = SsaVarId::new();  // SSA var for constant 10
//! flags.set_compare(v0, v1);
//!
//! // Get SSA comparison for JL
//! let (cmp, left, right, unsigned) = flags.get_branch_operands(X86Condition::L).unwrap();
//! assert_eq!(cmp, CmpKind::Lt);
//! assert!(!unsigned);
//! ```

use crate::analysis::{
    ssa::{CmpKind, SsaVarId},
    x86::types::X86Condition,
};

/// Represents what instruction last set the flags.
///
/// This tracks the operands from the most recent flag-setting instruction
/// so they can be used when translating a subsequent conditional jump.
#[derive(Debug, Clone)]
pub enum FlagProducer {
    /// Flags set by a CMP instruction: `cmp left, right` (computes left - right).
    ///
    /// The operands are SSA variable IDs representing the compared values.
    Compare {
        /// Left operand of the comparison (minuend).
        left: SsaVarId,
        /// Right operand of the comparison (subtrahend).
        right: SsaVarId,
    },

    /// Flags set by a TEST instruction: `test left, right` (computes left & right).
    ///
    /// TEST sets ZF based on whether (left & right) == 0.
    Test {
        /// Left operand of the test.
        left: SsaVarId,
        /// Right operand of the test.
        right: SsaVarId,
    },

    /// Flags set by an arithmetic/bitwise operation.
    ///
    /// These instructions set flags as a side effect. The result variable
    /// can be used for simple zero/sign tests.
    Arithmetic {
        /// The result of the arithmetic operation.
        result: SsaVarId,
    },
}

/// Tracks the current state of x86 flags for SSA translation.
///
/// This state is maintained per basic block during translation and is used
/// to fuse compare/test instructions with subsequent conditional jumps.
#[derive(Debug, Clone, Default)]
pub struct FlagState {
    /// The instruction that last set the flags, if any.
    producer: Option<FlagProducer>,
}

impl FlagState {
    /// Creates a new flag state with no known flags.
    #[must_use]
    pub fn new() -> Self {
        Self { producer: None }
    }

    /// Records that a CMP instruction set the flags.
    ///
    /// # Arguments
    ///
    /// * `left` - SSA variable for the left operand
    /// * `right` - SSA variable for the right operand
    pub fn set_compare(&mut self, left: SsaVarId, right: SsaVarId) {
        self.producer = Some(FlagProducer::Compare { left, right });
    }

    /// Records that a TEST instruction set the flags.
    ///
    /// # Arguments
    ///
    /// * `left` - SSA variable for the left operand
    /// * `right` - SSA variable for the right operand
    pub fn set_test(&mut self, left: SsaVarId, right: SsaVarId) {
        self.producer = Some(FlagProducer::Test { left, right });
    }

    /// Records that an arithmetic operation set the flags.
    ///
    /// # Arguments
    ///
    /// * `result` - SSA variable for the operation result
    pub fn set_arithmetic(&mut self, result: SsaVarId) {
        self.producer = Some(FlagProducer::Arithmetic { result });
    }

    /// Clears the flag state (flags are now unknown).
    pub fn clear(&mut self) {
        self.producer = None;
    }

    /// Returns the current flag producer, if any.
    #[must_use]
    pub fn producer(&self) -> Option<&FlagProducer> {
        self.producer.as_ref()
    }

    /// Returns true if flags are currently known (set by a tracked instruction).
    #[must_use]
    pub fn is_known(&self) -> bool {
        self.producer.is_some()
    }

    /// Converts an x86 condition to SSA comparison operands.
    ///
    /// Returns the comparison kind, operands, and whether to use unsigned comparison.
    /// Returns `None` if the flags are unknown or the condition cannot be translated.
    ///
    /// # Arguments
    ///
    /// * `condition` - The x86 condition code to translate
    ///
    /// # Returns
    ///
    /// A tuple of `(CmpKind, left, right, unsigned)` for use in `SsaOp::BranchCmp`.
    #[must_use]
    pub fn get_branch_operands(
        &self,
        condition: X86Condition,
    ) -> Option<(CmpKind, SsaVarId, SsaVarId, bool)> {
        match &self.producer {
            Some(FlagProducer::Compare { left, right }) => {
                let (cmp, unsigned) = condition_to_cmp(condition)?;
                Some((cmp, *left, *right, unsigned))
            }
            Some(FlagProducer::Test { left, right }) => {
                // TEST sets ZF = ((left & right) == 0)
                // For E/NE conditions, we can translate directly
                // For other conditions, we need the AND result
                match condition {
                    X86Condition::E => {
                        // JE after TEST: branch if (left & right) == 0
                        // We need to compute the AND first, then compare to 0
                        // For now, return the test operands - the translator will handle this
                        Some((CmpKind::Eq, *left, *right, false))
                    }
                    X86Condition::Ne => {
                        // JNE after TEST: branch if (left & right) != 0
                        Some((CmpKind::Ne, *left, *right, false))
                    }
                    // Other conditions after TEST are rare and complex
                    // SF tests sign of (left & right), etc.
                    X86Condition::S | X86Condition::Ns => {
                        // Sign flag - need to check MSB of (left & right)
                        None
                    }
                    _ => None,
                }
            }
            Some(FlagProducer::Arithmetic { result }) => {
                // Arithmetic ops set ZF/SF based on result
                // Only E/NE (zero test) and S/NS (sign test) are straightforward
                match condition {
                    X86Condition::E => {
                        // Result == 0
                        Some((CmpKind::Eq, *result, *result, false))
                    }
                    X86Condition::Ne => {
                        // Result != 0
                        Some((CmpKind::Ne, *result, *result, false))
                    }
                    _ => None,
                }
            }
            None => None,
        }
    }

    /// Checks if the flags are from a TEST instruction with the same operand.
    ///
    /// Pattern: `TEST reg, reg` followed by `JE/JNE` is testing if reg == 0.
    #[must_use]
    pub fn is_zero_test(&self) -> Option<SsaVarId> {
        match &self.producer {
            Some(FlagProducer::Test { left, right }) if left == right => Some(*left),
            _ => None,
        }
    }
}

/// Converts an x86 condition code to an SSA comparison kind.
///
/// Returns the `CmpKind` and a boolean indicating whether the comparison
/// should be unsigned.
///
/// # Arguments
///
/// * `condition` - The x86 condition code
///
/// # Returns
///
/// `Some((CmpKind, unsigned))` for translatable conditions, `None` for
/// conditions that require special handling (parity, overflow-only, etc.).
#[must_use]
pub fn condition_to_cmp(condition: X86Condition) -> Option<(CmpKind, bool)> {
    match condition {
        // Equality (works for both signed and unsigned)
        X86Condition::E => Some((CmpKind::Eq, false)),
        X86Condition::Ne => Some((CmpKind::Ne, false)),

        // Signed comparisons
        X86Condition::L => Some((CmpKind::Lt, false)),
        X86Condition::Ge => Some((CmpKind::Ge, false)),
        X86Condition::Le => Some((CmpKind::Le, false)),
        X86Condition::G => Some((CmpKind::Gt, false)),

        // Unsigned comparisons
        X86Condition::B => Some((CmpKind::Lt, true)),
        X86Condition::Ae => Some((CmpKind::Ge, true)),
        X86Condition::Be => Some((CmpKind::Le, true)),
        X86Condition::A => Some((CmpKind::Gt, true)),

        // These conditions don't map directly to CmpKind
        // S (sign) would be Lt with 0, NS is Ge with 0
        // O/NO (overflow) require special handling
        // P/NP (parity) are rare and not supported
        X86Condition::S
        | X86Condition::Ns
        | X86Condition::O
        | X86Condition::No
        | X86Condition::P
        | X86Condition::Np => None,
    }
}

/// Returns true if the condition tests only the zero flag (ZF).
///
/// These conditions can be optimized when following certain instructions.
#[must_use]
pub const fn is_zero_flag_only(condition: X86Condition) -> bool {
    matches!(condition, X86Condition::E | X86Condition::Ne)
}

/// Returns true if the condition uses signed comparison semantics.
#[must_use]
pub const fn is_signed_condition(condition: X86Condition) -> bool {
    matches!(
        condition,
        X86Condition::L | X86Condition::Ge | X86Condition::Le | X86Condition::G
    )
}

/// Returns true if the condition uses unsigned comparison semantics.
#[must_use]
pub const fn is_unsigned_condition(condition: X86Condition) -> bool {
    matches!(
        condition,
        X86Condition::B | X86Condition::Ae | X86Condition::Be | X86Condition::A
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flag_state_compare() {
        let mut flags = FlagState::new();
        assert!(!flags.is_known());

        let v0 = SsaVarId::new();
        let v1 = SsaVarId::new();
        flags.set_compare(v0, v1);

        assert!(flags.is_known());

        // Test signed conditions
        let (cmp, left, right, unsigned) = flags.get_branch_operands(X86Condition::L).unwrap();
        assert_eq!(cmp, CmpKind::Lt);
        assert_eq!(left, v0);
        assert_eq!(right, v1);
        assert!(!unsigned);

        // Test unsigned conditions
        let (cmp, _, _, unsigned) = flags.get_branch_operands(X86Condition::B).unwrap();
        assert_eq!(cmp, CmpKind::Lt);
        assert!(unsigned);
    }

    #[test]
    fn test_flag_state_test() {
        let mut flags = FlagState::new();

        let v0 = SsaVarId::new();
        let v1 = SsaVarId::new();
        flags.set_test(v0, v1);

        // E/NE work with TEST
        let result = flags.get_branch_operands(X86Condition::E);
        assert!(result.is_some());

        let result = flags.get_branch_operands(X86Condition::Ne);
        assert!(result.is_some());

        // Signed comparisons don't work directly with TEST
        let result = flags.get_branch_operands(X86Condition::L);
        assert!(result.is_none());
    }

    #[test]
    fn test_zero_test_pattern() {
        let mut flags = FlagState::new();

        let v0 = SsaVarId::new();
        flags.set_test(v0, v0);

        assert_eq!(flags.is_zero_test(), Some(v0));

        // Different operands - not a zero test
        let v1 = SsaVarId::new();
        flags.set_test(v0, v1);
        assert!(flags.is_zero_test().is_none());
    }

    #[test]
    fn test_condition_to_cmp() {
        // Equality
        assert_eq!(
            condition_to_cmp(X86Condition::E),
            Some((CmpKind::Eq, false))
        );
        assert_eq!(
            condition_to_cmp(X86Condition::Ne),
            Some((CmpKind::Ne, false))
        );

        // Signed
        assert_eq!(
            condition_to_cmp(X86Condition::L),
            Some((CmpKind::Lt, false))
        );
        assert_eq!(
            condition_to_cmp(X86Condition::G),
            Some((CmpKind::Gt, false))
        );

        // Unsigned
        assert_eq!(condition_to_cmp(X86Condition::B), Some((CmpKind::Lt, true)));
        assert_eq!(condition_to_cmp(X86Condition::A), Some((CmpKind::Gt, true)));

        // Unsupported
        assert!(condition_to_cmp(X86Condition::P).is_none());
        assert!(condition_to_cmp(X86Condition::O).is_none());
    }

    #[test]
    fn test_flag_state_clear() {
        let mut flags = FlagState::new();
        flags.set_compare(SsaVarId::new(), SsaVarId::new());
        assert!(flags.is_known());

        flags.clear();
        assert!(!flags.is_known());
    }

    #[test]
    fn test_condition_classification() {
        assert!(is_zero_flag_only(X86Condition::E));
        assert!(is_zero_flag_only(X86Condition::Ne));
        assert!(!is_zero_flag_only(X86Condition::L));

        assert!(is_signed_condition(X86Condition::L));
        assert!(is_signed_condition(X86Condition::G));
        assert!(!is_signed_condition(X86Condition::B));

        assert!(is_unsigned_condition(X86Condition::B));
        assert!(is_unsigned_condition(X86Condition::A));
        assert!(!is_unsigned_condition(X86Condition::L));
    }
}
