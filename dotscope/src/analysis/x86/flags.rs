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
//! For Cmovcc and Setcc, we evaluate the condition into a 0/1 SSA variable.
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

/// Distinguishes arithmetic operations for overflow flag computation.
///
/// Different arithmetic operations compute the overflow flag (OF) differently:
/// - ADD: OF = sign mismatch between operands and result
/// - SUB/CMP: OF = sign mismatch in subtraction
/// - Logical ops: OF = 0 always
/// - NEG: OF = (operand == INT_MIN)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArithmeticKind {
    /// Addition (ADD, INC, ADC, XADD).
    Add,
    /// Subtraction (SUB, DEC, SBB, CMP).
    Sub,
    /// Logical operation (AND, OR, XOR, TEST) — OF always 0.
    LogicalOp,
    /// Negation (NEG) — OF = 1 only when operand is INT_MIN.
    Neg,
    /// Other operations (MUL, DIV, shifts) — OF undefined or complex.
    Other,
}

/// Source of a value for sign/parity flag testing.
///
/// This tells the SSA emitter how to obtain the value whose sign bit
/// or parity should be tested.
#[derive(Debug, Clone)]
pub enum FlagTestSource {
    /// Use an existing SSA variable directly (from arithmetic result).
    Direct(SsaVarId),
    /// Compute left - right (from CMP instruction).
    Subtract {
        /// Left operand of the subtraction.
        left: SsaVarId,
        /// Right operand of the subtraction.
        right: SsaVarId,
    },
    /// Compute left & right (from TEST instruction).
    BitwiseAnd {
        /// Left operand of the AND.
        left: SsaVarId,
        /// Right operand of the AND.
        right: SsaVarId,
    },
}

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
        /// The left operand of the operation (needed for signed overflow detection).
        left: SsaVarId,
        /// The right operand of the operation (needed for signed overflow detection).
        right: SsaVarId,
        /// What kind of arithmetic produced these flags (needed for OF computation).
        kind: ArithmeticKind,
    },
}

/// Tracks the current state of x86 flags for SSA translation.
///
/// This state is maintained per basic block during translation and is used
/// to fuse compare/test instructions with subsequent conditional jumps,
/// and to evaluate conditions for Cmovcc and Setcc.
///
/// # Flag Tracking Strategy
///
/// Rather than tracking each flag (ZF, SF, OF, CF) as individual SSA variables,
/// we use two complementary approaches:
///
/// 1. **FlagProducer**: Records the source instruction and its operands.
///    This allows on-demand condition evaluation for Jcc/Cmovcc/Setcc by
///    producing the right comparison (Clt/Cgt/Ceq) when needed.
///
/// 2. **Carry flag (CF)**: Tracked explicitly as an SSA variable because it
///    is consumed by ADC and SBB which need the actual 0/1 value.
///
/// This hybrid approach avoids emitting unused flag computations while still
/// providing correct flag semantics.
#[derive(Debug, Clone, Default)]
pub struct FlagState {
    /// The instruction that last set the flags, if any.
    producer: Option<FlagProducer>,
    /// The current carry flag (CF) as an SSA variable holding 0 or 1.
    ///
    /// Set by:
    /// - ADD/ADC: CF = (result < left) unsigned (unsigned overflow)
    /// - SUB/SBB/CMP: CF = (left < right) unsigned (borrow)
    /// - AND/OR/XOR/TEST: CF = 0
    /// - NEG: CF = (operand != 0)
    ///
    /// Consumed by:
    /// - ADC: dest = left + right + CF
    /// - SBB: dest = left - right - CF
    ///
    /// Preserved by:
    /// - INC/DEC (do NOT modify CF)
    carry: Option<SsaVarId>,
}

impl FlagState {
    /// Creates a new flag state with no known flags.
    #[must_use]
    pub fn new() -> Self {
        Self {
            producer: None,
            carry: None,
        }
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
    /// Stores the result, both operands, and the arithmetic kind so that
    /// all flag conditions (including S/NS/O/NO/P/NP) can be properly evaluated.
    pub fn set_arithmetic(
        &mut self,
        result: SsaVarId,
        left: SsaVarId,
        right: SsaVarId,
        kind: ArithmeticKind,
    ) {
        self.producer = Some(FlagProducer::Arithmetic {
            result,
            left,
            right,
            kind,
        });
    }

    /// Records that a NEG operation set the flags.
    ///
    /// For NEG, the result is the only meaningful value. OF is set only
    /// when the original operand was INT_MIN.
    pub fn set_arithmetic_unary(&mut self, result: SsaVarId) {
        self.producer = Some(FlagProducer::Arithmetic {
            result,
            left: result,
            right: result,
            kind: ArithmeticKind::Neg,
        });
    }

    /// Clears the flag state (flags are now unknown).
    /// Also clears the carry flag.
    pub fn clear(&mut self) {
        self.producer = None;
        self.carry = None;
    }

    /// Clears only the producer (for instructions like MOV that don't set flags)
    /// without affecting the carry flag.
    pub fn clear_producer(&mut self) {
        self.producer = None;
    }

    /// Sets the carry flag to a specific SSA variable (must hold 0 or 1).
    pub fn set_carry(&mut self, carry: SsaVarId) {
        self.carry = Some(carry);
    }

    /// Clears the carry flag to a specific SSA variable representing zero.
    /// Used after AND/OR/XOR/TEST which always clear CF.
    pub fn clear_carry(&mut self, zero: SsaVarId) {
        self.carry = Some(zero);
    }

    /// Returns the current carry flag SSA variable, if known.
    #[must_use]
    pub fn carry(&self) -> Option<SsaVarId> {
        self.carry
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

    /// Converts an x86 condition to SSA comparison operands for `BranchCmp`.
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
                match condition {
                    X86Condition::E => {
                        // JE after TEST: branch if (left & right) == 0
                        Some((CmpKind::Eq, *left, *right, false))
                    }
                    X86Condition::Ne => {
                        // JNE after TEST: branch if (left & right) != 0
                        Some((CmpKind::Ne, *left, *right, false))
                    }
                    // S/NS after TEST: test sign bit of (left & right)
                    // These are handled by the caller computing AND first
                    X86Condition::S | X86Condition::Ns => None,
                    _ => None,
                }
            }
            Some(FlagProducer::Arithmetic {
                result,
                left,
                right,
                ..
            }) => {
                // Arithmetic ops set ZF/SF based on result
                match condition {
                    // Zero flag: result == 0
                    X86Condition::E => Some((CmpKind::Eq, *result, *result, false)),
                    X86Condition::Ne => Some((CmpKind::Ne, *result, *result, false)),
                    // For signed comparisons after arithmetic, we use the original
                    // operands since CIL comparison handles the signed semantics.
                    // This works because ADD/SUB set flags based on (left op right).
                    X86Condition::L | X86Condition::Ge | X86Condition::Le | X86Condition::G => {
                        let (cmp, unsigned) = condition_to_cmp(condition)?;
                        Some((cmp, *left, *right, unsigned))
                    }
                    // Unsigned comparisons after arithmetic
                    X86Condition::B | X86Condition::Ae | X86Condition::Be | X86Condition::A => {
                        let (cmp, unsigned) = condition_to_cmp(condition)?;
                        Some((cmp, *left, *right, unsigned))
                    }
                    // S/NS/O/NO/P/NP handled via evaluate_condition fallback
                    _ => None,
                }
            }
            None => None,
        }
    }

    /// Returns the condition evaluation info for producing a 0/1 SSA value.
    ///
    /// Used by Cmovcc, Setcc, and the Jcc fallback to evaluate conditions into
    /// values rather than branches. Handles all 16 x86 condition codes including
    /// S/NS (sign), O/NO (overflow), and P/NP (parity).
    #[must_use]
    pub fn get_condition_operands(&self, condition: X86Condition) -> Option<ConditionEval> {
        match &self.producer {
            Some(FlagProducer::Compare { left, right }) => match condition {
                X86Condition::S => Some(ConditionEval::SignFlag {
                    source: FlagTestSource::Subtract {
                        left: *left,
                        right: *right,
                    },
                    negated: false,
                }),
                X86Condition::Ns => Some(ConditionEval::SignFlag {
                    source: FlagTestSource::Subtract {
                        left: *left,
                        right: *right,
                    },
                    negated: true,
                }),
                X86Condition::O => Some(ConditionEval::OverflowFlag {
                    left: *left,
                    right: *right,
                    result: None,
                    kind: ArithmeticKind::Sub,
                    negated: false,
                }),
                X86Condition::No => Some(ConditionEval::OverflowFlag {
                    left: *left,
                    right: *right,
                    result: None,
                    kind: ArithmeticKind::Sub,
                    negated: true,
                }),
                X86Condition::P => Some(ConditionEval::ParityFlag {
                    source: FlagTestSource::Subtract {
                        left: *left,
                        right: *right,
                    },
                    negated: false,
                }),
                X86Condition::Np => Some(ConditionEval::ParityFlag {
                    source: FlagTestSource::Subtract {
                        left: *left,
                        right: *right,
                    },
                    negated: true,
                }),
                _ => {
                    let (cmp, unsigned) = condition_to_cmp(condition)?;
                    Some(ConditionEval::Compare {
                        cmp,
                        left: *left,
                        right: *right,
                        unsigned,
                    })
                }
            },
            Some(FlagProducer::Test { left, right }) => match condition {
                X86Condition::E => Some(ConditionEval::Test {
                    cmp: CmpKind::Eq,
                    left: *left,
                    right: *right,
                }),
                X86Condition::Ne => Some(ConditionEval::Test {
                    cmp: CmpKind::Ne,
                    left: *left,
                    right: *right,
                }),
                X86Condition::S => Some(ConditionEval::SignFlag {
                    source: FlagTestSource::BitwiseAnd {
                        left: *left,
                        right: *right,
                    },
                    negated: false,
                }),
                X86Condition::Ns => Some(ConditionEval::SignFlag {
                    source: FlagTestSource::BitwiseAnd {
                        left: *left,
                        right: *right,
                    },
                    negated: true,
                }),
                X86Condition::O => Some(ConditionEval::OverflowFlag {
                    left: *left,
                    right: *right,
                    result: None,
                    kind: ArithmeticKind::LogicalOp,
                    negated: false,
                }),
                X86Condition::No => Some(ConditionEval::OverflowFlag {
                    left: *left,
                    right: *right,
                    result: None,
                    kind: ArithmeticKind::LogicalOp,
                    negated: true,
                }),
                X86Condition::P => Some(ConditionEval::ParityFlag {
                    source: FlagTestSource::BitwiseAnd {
                        left: *left,
                        right: *right,
                    },
                    negated: false,
                }),
                X86Condition::Np => Some(ConditionEval::ParityFlag {
                    source: FlagTestSource::BitwiseAnd {
                        left: *left,
                        right: *right,
                    },
                    negated: true,
                }),
                _ => None,
            },
            Some(FlagProducer::Arithmetic {
                result,
                left,
                right,
                kind,
            }) => match condition {
                X86Condition::E => Some(ConditionEval::ZeroTest {
                    cmp: CmpKind::Eq,
                    result: *result,
                }),
                X86Condition::Ne => Some(ConditionEval::ZeroTest {
                    cmp: CmpKind::Ne,
                    result: *result,
                }),
                X86Condition::S => Some(ConditionEval::SignFlag {
                    source: FlagTestSource::Direct(*result),
                    negated: false,
                }),
                X86Condition::Ns => Some(ConditionEval::SignFlag {
                    source: FlagTestSource::Direct(*result),
                    negated: true,
                }),
                X86Condition::O => Some(ConditionEval::OverflowFlag {
                    left: *left,
                    right: *right,
                    result: Some(*result),
                    kind: *kind,
                    negated: false,
                }),
                X86Condition::No => Some(ConditionEval::OverflowFlag {
                    left: *left,
                    right: *right,
                    result: Some(*result),
                    kind: *kind,
                    negated: true,
                }),
                X86Condition::P => Some(ConditionEval::ParityFlag {
                    source: FlagTestSource::Direct(*result),
                    negated: false,
                }),
                X86Condition::Np => Some(ConditionEval::ParityFlag {
                    source: FlagTestSource::Direct(*result),
                    negated: true,
                }),
                _ => {
                    let (cmp, unsigned) = condition_to_cmp(condition)?;
                    Some(ConditionEval::Compare {
                        cmp,
                        left: *left,
                        right: *right,
                        unsigned,
                    })
                }
            },
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

/// Describes how to evaluate an x86 condition into a 0/1 SSA value.
///
/// Used by the translator to emit the right SSA instructions for Jcc/Cmovcc/Setcc.
#[derive(Debug, Clone)]
pub enum ConditionEval {
    /// Direct comparison: emit Clt/Cgt/Ceq on left vs right.
    Compare {
        cmp: CmpKind,
        left: SsaVarId,
        right: SsaVarId,
        unsigned: bool,
    },
    /// TEST pattern: emit AND(left, right), then compare result to zero.
    Test {
        cmp: CmpKind,
        left: SsaVarId,
        right: SsaVarId,
    },
    /// Zero test on arithmetic result: compare result to zero.
    ZeroTest { cmp: CmpKind, result: SsaVarId },
    /// Sign flag test: extract MSB of value.
    ///
    /// S (negated=false): result is 1 when SF=1 (negative).
    /// NS (negated=true): result is 1 when SF=0 (non-negative).
    SignFlag {
        source: FlagTestSource,
        negated: bool,
    },
    /// Overflow flag test: signed overflow detection.
    ///
    /// O (negated=false): result is 1 when OF=1 (overflow occurred).
    /// NO (negated=true): result is 1 when OF=0 (no overflow).
    OverflowFlag {
        left: SsaVarId,
        right: SsaVarId,
        /// None for CMP (must emit Sub), Some for arithmetic operations.
        result: Option<SsaVarId>,
        kind: ArithmeticKind,
        negated: bool,
    },
    /// Parity flag test: even parity of low byte.
    ///
    /// P (negated=false): result is 1 when PF=1 (even parity).
    /// NP (negated=true): result is 1 when PF=0 (odd parity).
    ParityFlag {
        source: FlagTestSource,
        negated: bool,
    },
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

        // Sign/Overflow/Parity require special handling
        X86Condition::S
        | X86Condition::Ns
        | X86Condition::O
        | X86Condition::No
        | X86Condition::P
        | X86Condition::Np => None,
    }
}

/// Returns true if the condition tests only the zero flag (ZF).
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

    #[test]
    fn test_carry_flag_tracking() {
        let mut flags = FlagState::new();
        assert!(flags.carry().is_none());

        let cf = SsaVarId::new();
        flags.set_carry(cf);
        assert_eq!(flags.carry(), Some(cf));

        let zero = SsaVarId::new();
        flags.clear_carry(zero);
        assert_eq!(flags.carry(), Some(zero));

        flags.clear();
        assert!(flags.carry().is_none());
    }

    #[test]
    fn test_arithmetic_with_signed_conditions() {
        let mut flags = FlagState::new();

        let result = SsaVarId::new();
        let left = SsaVarId::new();
        let right = SsaVarId::new();
        flags.set_arithmetic(result, left, right, ArithmeticKind::Add);

        // Zero test should work
        let branch = flags.get_branch_operands(X86Condition::E);
        assert!(branch.is_some());

        // Signed conditions should also work (using original operands)
        let branch = flags.get_branch_operands(X86Condition::L);
        assert!(branch.is_some());
        let (cmp, l, r, unsigned) = branch.unwrap();
        assert_eq!(cmp, CmpKind::Lt);
        assert_eq!(l, left);
        assert_eq!(r, right);
        assert!(!unsigned);
    }

    #[test]
    fn test_condition_eval() {
        let mut flags = FlagState::new();

        let v0 = SsaVarId::new();
        let v1 = SsaVarId::new();
        flags.set_compare(v0, v1);

        let eval = flags.get_condition_operands(X86Condition::L);
        assert!(eval.is_some());
        assert!(matches!(eval.unwrap(), ConditionEval::Compare { .. }));

        // TEST pattern
        flags.set_test(v0, v1);
        let eval = flags.get_condition_operands(X86Condition::E);
        assert!(eval.is_some());
        assert!(matches!(eval.unwrap(), ConditionEval::Test { .. }));
    }

    #[test]
    fn test_sign_flag_from_compare() {
        let mut flags = FlagState::new();
        let v0 = SsaVarId::new();
        let v1 = SsaVarId::new();
        flags.set_compare(v0, v1);

        // S condition should produce SignFlag with Subtract source
        let eval = flags.get_condition_operands(X86Condition::S);
        assert!(eval.is_some());
        assert!(matches!(
            eval.unwrap(),
            ConditionEval::SignFlag {
                source: FlagTestSource::Subtract { .. },
                negated: false,
            }
        ));

        // NS should be negated
        let eval = flags.get_condition_operands(X86Condition::Ns);
        assert!(matches!(
            eval.unwrap(),
            ConditionEval::SignFlag { negated: true, .. }
        ));
    }

    #[test]
    fn test_sign_flag_from_test() {
        let mut flags = FlagState::new();
        let v0 = SsaVarId::new();
        let v1 = SsaVarId::new();
        flags.set_test(v0, v1);

        let eval = flags.get_condition_operands(X86Condition::S);
        assert!(matches!(
            eval.unwrap(),
            ConditionEval::SignFlag {
                source: FlagTestSource::BitwiseAnd { .. },
                negated: false,
            }
        ));
    }

    #[test]
    fn test_sign_flag_from_arithmetic() {
        let mut flags = FlagState::new();
        let result = SsaVarId::new();
        let left = SsaVarId::new();
        let right = SsaVarId::new();
        flags.set_arithmetic(result, left, right, ArithmeticKind::Add);

        let eval = flags.get_condition_operands(X86Condition::S);
        assert!(matches!(
            eval.unwrap(),
            ConditionEval::SignFlag {
                source: FlagTestSource::Direct(_),
                negated: false,
            }
        ));
    }

    #[test]
    fn test_overflow_flag_from_compare() {
        let mut flags = FlagState::new();
        let v0 = SsaVarId::new();
        let v1 = SsaVarId::new();
        flags.set_compare(v0, v1);

        let eval = flags.get_condition_operands(X86Condition::O);
        assert!(eval.is_some());
        match eval.unwrap() {
            ConditionEval::OverflowFlag {
                result,
                kind,
                negated,
                ..
            } => {
                assert!(result.is_none()); // CMP has no stored result
                assert_eq!(kind, ArithmeticKind::Sub);
                assert!(!negated);
            }
            other => panic!("Expected OverflowFlag, got {other:?}"),
        }

        // NO should be negated
        let eval = flags.get_condition_operands(X86Condition::No);
        assert!(matches!(
            eval.unwrap(),
            ConditionEval::OverflowFlag { negated: true, .. }
        ));
    }

    #[test]
    fn test_overflow_flag_from_test() {
        let mut flags = FlagState::new();
        let v0 = SsaVarId::new();
        let v1 = SsaVarId::new();
        flags.set_test(v0, v1);

        // TEST always clears OF, so OverflowFlag with LogicalOp kind
        let eval = flags.get_condition_operands(X86Condition::O);
        assert!(matches!(
            eval.unwrap(),
            ConditionEval::OverflowFlag {
                kind: ArithmeticKind::LogicalOp,
                negated: false,
                ..
            }
        ));
    }

    #[test]
    fn test_overflow_flag_from_arithmetic() {
        let mut flags = FlagState::new();
        let result = SsaVarId::new();
        let left = SsaVarId::new();
        let right = SsaVarId::new();
        flags.set_arithmetic(result, left, right, ArithmeticKind::Add);

        let eval = flags.get_condition_operands(X86Condition::O);
        match eval.unwrap() {
            ConditionEval::OverflowFlag {
                result: r,
                kind,
                negated,
                ..
            } => {
                assert!(r.is_some());
                assert_eq!(kind, ArithmeticKind::Add);
                assert!(!negated);
            }
            other => panic!("Expected OverflowFlag, got {other:?}"),
        }
    }

    #[test]
    fn test_parity_flag_from_compare() {
        let mut flags = FlagState::new();
        let v0 = SsaVarId::new();
        let v1 = SsaVarId::new();
        flags.set_compare(v0, v1);

        let eval = flags.get_condition_operands(X86Condition::P);
        assert!(matches!(
            eval.unwrap(),
            ConditionEval::ParityFlag {
                source: FlagTestSource::Subtract { .. },
                negated: false,
            }
        ));

        let eval = flags.get_condition_operands(X86Condition::Np);
        assert!(matches!(
            eval.unwrap(),
            ConditionEval::ParityFlag { negated: true, .. }
        ));
    }

    #[test]
    fn test_parity_flag_from_test() {
        let mut flags = FlagState::new();
        let v0 = SsaVarId::new();
        let v1 = SsaVarId::new();
        flags.set_test(v0, v1);

        let eval = flags.get_condition_operands(X86Condition::P);
        assert!(matches!(
            eval.unwrap(),
            ConditionEval::ParityFlag {
                source: FlagTestSource::BitwiseAnd { .. },
                negated: false,
            }
        ));
    }

    #[test]
    fn test_branch_operands_still_none_for_flag_conditions() {
        let mut flags = FlagState::new();
        flags.set_compare(SsaVarId::new(), SsaVarId::new());

        // S/NS/O/NO/P/NP should still return None from get_branch_operands
        // (these go through evaluate_condition fallback in Jcc handler)
        assert!(flags.get_branch_operands(X86Condition::S).is_none());
        assert!(flags.get_branch_operands(X86Condition::Ns).is_none());
        assert!(flags.get_branch_operands(X86Condition::O).is_none());
        assert!(flags.get_branch_operands(X86Condition::No).is_none());
        assert!(flags.get_branch_operands(X86Condition::P).is_none());
        assert!(flags.get_branch_operands(X86Condition::Np).is_none());

        // But the standard conditions should still work
        assert!(flags.get_branch_operands(X86Condition::E).is_some());
        assert!(flags.get_branch_operands(X86Condition::L).is_some());
    }

    #[test]
    fn test_arithmetic_kind_neg() {
        let mut flags = FlagState::new();
        let result = SsaVarId::new();
        flags.set_arithmetic_unary(result);

        // Should have Neg kind
        let eval = flags.get_condition_operands(X86Condition::O);
        match eval.unwrap() {
            ConditionEval::OverflowFlag { kind, .. } => {
                assert_eq!(kind, ArithmeticKind::Neg);
            }
            other => panic!("Expected OverflowFlag, got {other:?}"),
        }
    }
}
