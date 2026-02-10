//! Symbolic operation types.
//!
//! This module defines [`SymbolicOp`], the set of operations supported in
//! symbolic expressions. These operations map directly to CIL arithmetic
//! and logical operations, using 32-bit semantics.
//!
//! Operations are categorized as:
//! - **Arithmetic**: Add, Sub, Mul, Div, Rem, Neg
//! - **Bitwise**: And, Or, Xor, Not, Shl, Shr
//! - **Comparison**: Eq, Ne, Lt, Gt, Le, Ge (with signed/unsigned variants)

use std::fmt;

/// A symbolic operation in an expression tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SymbolicOp {
    // Arithmetic operations
    /// Addition.
    Add,
    /// Subtraction.
    Sub,
    /// Multiplication.
    Mul,
    /// Signed division.
    DivS,
    /// Unsigned division.
    DivU,
    /// Signed remainder (modulo).
    RemS,
    /// Unsigned remainder (modulo).
    RemU,
    /// Negation.
    Neg,

    // Bitwise operations
    /// Bitwise AND.
    And,
    /// Bitwise OR.
    Or,
    /// Bitwise XOR.
    Xor,
    /// Bitwise NOT.
    Not,
    /// Shift left.
    Shl,
    /// Arithmetic shift right (preserves sign).
    ShrS,
    /// Logical shift right (zero-fill).
    ShrU,

    // Comparison operations (return 0 or 1)
    /// Equal.
    Eq,
    /// Not equal.
    Ne,
    /// Signed less than.
    LtS,
    /// Unsigned less than.
    LtU,
    /// Signed greater than.
    GtS,
    /// Unsigned greater than.
    GtU,
    /// Signed less than or equal.
    LeS,
    /// Unsigned less than or equal.
    LeU,
    /// Signed greater than or equal.
    GeS,
    /// Unsigned greater than or equal.
    GeU,
}

impl SymbolicOp {
    /// Checks if this operation is commutative.
    ///
    /// Commutative operations produce the same result regardless of operand order:
    /// `a op b == b op a`. This property is useful for expression canonicalization.
    ///
    /// # Returns
    ///
    /// `true` if the operation is commutative (Add, Mul, And, Or, Xor, Eq, Ne).
    #[must_use]
    pub const fn is_commutative(self) -> bool {
        matches!(
            self,
            Self::Add | Self::Mul | Self::And | Self::Or | Self::Xor | Self::Eq | Self::Ne
        )
    }

    /// Checks if this operation is a comparison.
    ///
    /// Comparison operations return 0 or 1 based on the relationship between operands.
    ///
    /// # Returns
    ///
    /// `true` if this is a comparison operation (Eq, Ne, Lt*, Gt*, Le*, Ge*).
    #[must_use]
    pub const fn is_comparison(self) -> bool {
        matches!(
            self,
            Self::Eq
                | Self::Ne
                | Self::LtS
                | Self::LtU
                | Self::GtS
                | Self::GtU
                | Self::LeS
                | Self::LeU
                | Self::GeS
                | Self::GeU
        )
    }

    /// Checks if this is a unary operation.
    ///
    /// Unary operations take a single operand, unlike binary operations which take two.
    ///
    /// # Returns
    ///
    /// `true` if this is a unary operation (Neg, Not).
    #[must_use]
    pub const fn is_unary(self) -> bool {
        matches!(self, Self::Neg | Self::Not)
    }
}

impl fmt::Display for SymbolicOp {
    #[allow(clippy::match_same_arms)] // Sub and Neg are semantically different (binary vs unary)
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Add => write!(f, "+"),
            Self::Sub => write!(f, "-"),
            Self::Mul => write!(f, "*"),
            Self::DivS => write!(f, "/"),
            Self::DivU => write!(f, "/u"),
            Self::RemS => write!(f, "%"),
            Self::RemU => write!(f, "%u"),
            Self::Neg => write!(f, "-"),
            Self::And => write!(f, "&"),
            Self::Or => write!(f, "|"),
            Self::Xor => write!(f, "^"),
            Self::Not => write!(f, "~"),
            Self::Shl => write!(f, "<<"),
            Self::ShrS => write!(f, ">>"),
            Self::ShrU => write!(f, ">>>"),
            Self::Eq => write!(f, "=="),
            Self::Ne => write!(f, "!="),
            Self::LtS => write!(f, "<"),
            Self::LtU => write!(f, "<u"),
            Self::GtS => write!(f, ">"),
            Self::GtU => write!(f, ">u"),
            Self::LeS => write!(f, "<="),
            Self::LeU => write!(f, "<=u"),
            Self::GeS => write!(f, ">="),
            Self::GeU => write!(f, ">=u"),
        }
    }
}
