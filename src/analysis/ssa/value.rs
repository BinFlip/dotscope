//! Value tracking for SSA variables.
//!
//! This module provides abstract value representation for SSA variables,
//! enabling constant propagation, value numbering, and range analysis.
//!
//! # Lattice Structure
//!
//! The `AbstractValue` type forms a lattice for dataflow analysis:
//!
//! ```text
//!              Top (no information)
//!               |
//!     +---------+---------+
//!     |         |         |
//!   Const    Range     NonNull
//!     |         |         |
//!     +---------+---------+
//!               |
//!            Bottom (conflicting info)
//! ```
//!
//! - `Top`: No information known yet (initial state)
//! - `Constant`: Known compile-time constant
//! - `Range`: Value in a bounded range
//! - `NonNull`: Known to be non-null (for references)
//! - `Bottom`: Multiple conflicting values (cannot be constant)

use std::fmt;

use super::types::{FieldRef, MethodRef, TypeRef};
use super::SsaVarId;

/// Constant values that can appear in SSA form.
///
/// These represent compile-time constants that can be tracked through
/// the SSA graph for constant propagation and folding.
#[derive(Debug, Clone, PartialEq)]
pub enum ConstValue {
    /// 32-bit signed integer.
    I32(i32),

    /// 64-bit signed integer.
    I64(i64),

    /// 32-bit floating point.
    F32(f32),

    /// 64-bit floating point.
    F64(f64),

    /// String constant (index into #US heap).
    String(u32),

    /// Null reference.
    Null,

    /// Boolean true.
    True,

    /// Boolean false.
    False,

    /// Runtime type handle (typeof result).
    Type(TypeRef),

    /// Runtime method handle.
    MethodHandle(MethodRef),

    /// Runtime field handle.
    FieldHandle(FieldRef),
}

impl ConstValue {
    /// Returns `true` if this is the null constant.
    #[must_use]
    pub const fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }

    /// Returns `true` if this is a boolean constant.
    #[must_use]
    pub const fn is_bool(&self) -> bool {
        matches!(self, Self::True | Self::False)
    }

    /// Returns `true` if this is an integer constant.
    #[must_use]
    pub const fn is_integer(&self) -> bool {
        matches!(self, Self::I32(_) | Self::I64(_))
    }

    /// Returns `true` if this is a floating-point constant.
    #[must_use]
    pub const fn is_float(&self) -> bool {
        matches!(self, Self::F32(_) | Self::F64(_))
    }

    /// Returns the constant as an i32 if applicable.
    #[must_use]
    pub const fn as_i32(&self) -> Option<i32> {
        match self {
            Self::I32(v) => Some(*v),
            Self::True => Some(1),
            Self::False => Some(0),
            _ => None,
        }
    }

    /// Returns the constant as an i64 if applicable.
    #[must_use]
    pub const fn as_i64(&self) -> Option<i64> {
        match self {
            Self::I64(v) => Some(*v),
            Self::I32(v) => Some(*v as i64),
            Self::True => Some(1),
            Self::False => Some(0),
            _ => None,
        }
    }

    /// Returns the constant as a bool if applicable.
    #[must_use]
    pub const fn as_bool(&self) -> Option<bool> {
        match self {
            Self::True => Some(true),
            Self::False | Self::I32(0) | Self::Null => Some(false),
            Self::I32(_) => Some(true), // non-zero is truthy
            _ => None,
        }
    }

    /// Creates a boolean constant from a bool value.
    #[must_use]
    pub const fn from_bool(value: bool) -> Self {
        if value {
            Self::True
        } else {
            Self::False
        }
    }

    /// Attempts to negate this constant.
    #[must_use]
    pub fn negate(&self) -> Option<Self> {
        match self {
            Self::I32(v) => Some(Self::I32(-v)),
            Self::I64(v) => Some(Self::I64(-v)),
            Self::F32(v) => Some(Self::F32(-v)),
            Self::F64(v) => Some(Self::F64(-v)),
            _ => None,
        }
    }

    /// Attempts to perform bitwise NOT on this constant.
    #[must_use]
    pub fn bitwise_not(&self) -> Option<Self> {
        match self {
            Self::I32(v) => Some(Self::I32(!v)),
            Self::I64(v) => Some(Self::I64(!v)),
            _ => None,
        }
    }

    /// Attempts to add two constants.
    #[must_use]
    pub fn add(&self, other: &Self) -> Option<Self> {
        match (self, other) {
            (Self::I32(a), Self::I32(b)) => Some(Self::I32(a.wrapping_add(*b))),
            (Self::I64(a), Self::I64(b)) => Some(Self::I64(a.wrapping_add(*b))),
            (Self::F32(a), Self::F32(b)) => Some(Self::F32(a + b)),
            (Self::F64(a), Self::F64(b)) => Some(Self::F64(a + b)),
            _ => None,
        }
    }

    /// Attempts to subtract two constants.
    #[must_use]
    pub fn sub(&self, other: &Self) -> Option<Self> {
        match (self, other) {
            (Self::I32(a), Self::I32(b)) => Some(Self::I32(a.wrapping_sub(*b))),
            (Self::I64(a), Self::I64(b)) => Some(Self::I64(a.wrapping_sub(*b))),
            (Self::F32(a), Self::F32(b)) => Some(Self::F32(a - b)),
            (Self::F64(a), Self::F64(b)) => Some(Self::F64(a - b)),
            _ => None,
        }
    }

    /// Attempts to multiply two constants.
    #[must_use]
    pub fn mul(&self, other: &Self) -> Option<Self> {
        match (self, other) {
            (Self::I32(a), Self::I32(b)) => Some(Self::I32(a.wrapping_mul(*b))),
            (Self::I64(a), Self::I64(b)) => Some(Self::I64(a.wrapping_mul(*b))),
            (Self::F32(a), Self::F32(b)) => Some(Self::F32(a * b)),
            (Self::F64(a), Self::F64(b)) => Some(Self::F64(a * b)),
            _ => None,
        }
    }

    /// Attempts to compare two constants for equality.
    #[must_use]
    #[allow(clippy::float_cmp)] // Exact comparison is correct for constant propagation
    pub fn ceq(&self, other: &Self) -> Option<Self> {
        match (self, other) {
            (Self::I32(a), Self::I32(b)) => Some(Self::from_bool(a == b)),
            (Self::I64(a), Self::I64(b)) => Some(Self::from_bool(a == b)),
            (Self::F32(a), Self::F32(b)) => Some(Self::from_bool(a == b)),
            (Self::F64(a), Self::F64(b)) => Some(Self::from_bool(a == b)),
            (Self::Null, Self::Null)
            | (Self::True, Self::True)
            | (Self::False, Self::False) => Some(Self::True),
            (Self::True, Self::False) | (Self::False, Self::True) => Some(Self::False),
            _ => None,
        }
    }

    /// Attempts to compare two constants for less-than.
    #[must_use]
    pub fn clt(&self, other: &Self) -> Option<Self> {
        match (self, other) {
            (Self::I32(a), Self::I32(b)) => Some(Self::from_bool(a < b)),
            (Self::I64(a), Self::I64(b)) => Some(Self::from_bool(a < b)),
            (Self::F32(a), Self::F32(b)) => Some(Self::from_bool(a < b)),
            (Self::F64(a), Self::F64(b)) => Some(Self::from_bool(a < b)),
            _ => None,
        }
    }

    /// Attempts to compare two constants for greater-than.
    #[must_use]
    pub fn cgt(&self, other: &Self) -> Option<Self> {
        match (self, other) {
            (Self::I32(a), Self::I32(b)) => Some(Self::from_bool(a > b)),
            (Self::I64(a), Self::I64(b)) => Some(Self::from_bool(a > b)),
            (Self::F32(a), Self::F32(b)) => Some(Self::from_bool(a > b)),
            (Self::F64(a), Self::F64(b)) => Some(Self::from_bool(a > b)),
            _ => None,
        }
    }
}

impl fmt::Display for ConstValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::I32(v) => write!(f, "{v}"),
            Self::I64(v) => write!(f, "{v}L"),
            Self::F32(v) => write!(f, "{v}f"),
            Self::F64(v) => write!(f, "{v}"),
            Self::String(idx) => write!(f, "str@{idx}"),
            Self::Null => write!(f, "null"),
            Self::True => write!(f, "true"),
            Self::False => write!(f, "false"),
            Self::Type(t) => write!(f, "typeof({t})"),
            Self::MethodHandle(m) => write!(f, "methodof({m})"),
            Self::FieldHandle(fl) => write!(f, "fieldof({fl})"),
        }
    }
}

/// Abstract value for dataflow analysis.
///
/// This represents the abstract state of an SSA variable during analysis.
/// It forms a lattice where values can be refined as more information is gathered.
#[derive(Debug, Clone, PartialEq, Default)]
pub enum AbstractValue {
    /// No information yet (top of lattice).
    ///
    /// This is the initial state before any analysis.
    #[default]
    Top,

    /// Known constant value.
    Constant(ConstValue),

    /// Known to be non-null (for reference types).
    NonNull,

    /// Value in a bounded range [min, max].
    Range {
        /// Minimum value (inclusive).
        min: i64,
        /// Maximum value (inclusive).
        max: i64,
    },

    /// Same value as another SSA variable.
    ///
    /// Used for copy propagation.
    SameAs(SsaVarId),

    /// Result of a specific computation (for CSE).
    Computed(ComputedValue),

    /// Multiple possible values (bottom of lattice for constants).
    ///
    /// This means the value cannot be determined at compile time.
    Bottom,
}

impl AbstractValue {
    /// Returns `true` if this is the top element (no information).
    #[must_use]
    pub const fn is_top(&self) -> bool {
        matches!(self, Self::Top)
    }

    /// Returns `true` if this is the bottom element (conflicting info).
    #[must_use]
    pub const fn is_bottom(&self) -> bool {
        matches!(self, Self::Bottom)
    }

    /// Returns `true` if this is a known constant.
    #[must_use]
    pub const fn is_constant(&self) -> bool {
        matches!(self, Self::Constant(_))
    }

    /// Returns the constant value if this is a constant.
    #[must_use]
    pub const fn as_constant(&self) -> Option<&ConstValue> {
        match self {
            Self::Constant(c) => Some(c),
            _ => None,
        }
    }

    /// Returns `true` if this value is known to be non-null.
    #[must_use]
    pub const fn is_non_null(&self) -> bool {
        matches!(self, Self::NonNull | Self::Constant(_))
    }

    /// Meet operation for the lattice (used at control flow joins).
    ///
    /// Returns the greatest lower bound of `self` and `other`.
    #[must_use]
    #[allow(clippy::match_same_arms)] // Arms kept separate for lattice documentation clarity
    pub fn meet(&self, other: &Self) -> Self {
        match (self, other) {
            // Top meets anything yields the other
            (Self::Top, x) | (x, Self::Top) => x.clone(),

            // Bottom meets anything yields Bottom
            (Self::Bottom, _) | (_, Self::Bottom) => Self::Bottom,

            // Same constants stay constant
            (Self::Constant(a), Self::Constant(b)) if a == b => Self::Constant(a.clone()),

            // Different constants become Bottom
            (Self::Constant(_), Self::Constant(_)) => Self::Bottom,

            // NonNull meets NonNull stays NonNull
            (Self::NonNull, Self::NonNull) => Self::NonNull,

            // NonNull meets Constant stays Constant (constants are non-null if not null)
            (Self::NonNull, Self::Constant(c)) | (Self::Constant(c), Self::NonNull) => {
                if c.is_null() {
                    Self::Bottom // null is not non-null
                } else {
                    Self::Constant(c.clone())
                }
            }

            // Ranges can be merged
            (
                Self::Range {
                    min: a_min,
                    max: a_max,
                },
                Self::Range {
                    min: b_min,
                    max: b_max,
                },
            ) => {
                let new_min = (*a_min).min(*b_min);
                let new_max = (*a_max).max(*b_max);
                Self::Range {
                    min: new_min,
                    max: new_max,
                }
            }

            // SameAs values must match
            (Self::SameAs(a), Self::SameAs(b)) if a == b => Self::SameAs(*a),

            // Computed values must match exactly
            (Self::Computed(a), Self::Computed(b)) if a == b => Self::Computed(a.clone()),

            // Otherwise, Bottom
            _ => Self::Bottom,
        }
    }

    /// Join operation for the lattice.
    ///
    /// Returns the least upper bound of `self` and `other`.
    #[must_use]
    pub fn join(&self, other: &Self) -> Self {
        match (self, other) {
            // Bottom joins anything yields the other
            (Self::Bottom, x) | (x, Self::Bottom) => x.clone(),

            // Top joins anything yields Top
            (Self::Top, _) | (_, Self::Top) => Self::Top,

            // Same values stay the same
            (a, b) if a == b => a.clone(),

            // Otherwise, Top
            _ => Self::Top,
        }
    }
}

impl fmt::Display for AbstractValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Top => write!(f, "⊤"),
            Self::Constant(c) => write!(f, "{c}"),
            Self::NonNull => write!(f, "!null"),
            Self::Range { min, max } => write!(f, "[{min}..{max}]"),
            Self::SameAs(v) => write!(f, "={v}"),
            Self::Computed(c) => write!(f, "{c}"),
            Self::Bottom => write!(f, "⊥"),
        }
    }
}

/// Computed value for common subexpression elimination (CSE).
///
/// This represents the result of a computation, enabling recognition
/// of equivalent expressions that can be eliminated.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ComputedValue {
    /// The operation that produced this value.
    pub op: ComputedOp,
    /// The operands to the operation.
    pub operands: Vec<SsaVarId>,
}

impl ComputedValue {
    /// Creates a new computed value.
    #[must_use]
    pub fn new(op: ComputedOp, operands: Vec<SsaVarId>) -> Self {
        Self { op, operands }
    }

    /// Creates a unary computed value.
    #[must_use]
    pub fn unary(op: ComputedOp, operand: SsaVarId) -> Self {
        Self {
            op,
            operands: vec![operand],
        }
    }

    /// Creates a binary computed value.
    #[must_use]
    pub fn binary(op: ComputedOp, left: SsaVarId, right: SsaVarId) -> Self {
        Self {
            op,
            operands: vec![left, right],
        }
    }

    /// Normalizes commutative operations for better CSE.
    ///
    /// For commutative ops like add/mul, orders operands consistently
    /// so that `a + b` and `b + a` have the same computed value.
    #[must_use]
    pub fn normalized(self) -> Self {
        if self.op.is_commutative() && self.operands.len() == 2 {
            let mut ops = self.operands;
            if ops[0].index() > ops[1].index() {
                ops.swap(0, 1);
            }
            Self {
                op: self.op,
                operands: ops,
            }
        } else {
            self
        }
    }
}

impl fmt::Display for ComputedValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}(", self.op)?;
        for (i, op) in self.operands.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{op}")?;
        }
        write!(f, ")")
    }
}

/// Operations that can be tracked for CSE.
///
/// These represent the pure operations whose results can be reused
/// when the same operation is performed with the same operands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ComputedOp {
    // Arithmetic
    /// Addition
    Add,
    /// Subtraction
    Sub,
    /// Multiplication
    Mul,
    /// Division
    Div,
    /// Remainder (modulo)
    Rem,
    /// Negation
    Neg,

    // Bitwise
    /// Bitwise AND
    And,
    /// Bitwise OR
    Or,
    /// Bitwise XOR
    Xor,
    /// Bitwise NOT
    Not,
    /// Shift left
    Shl,
    /// Shift right
    Shr,

    // Comparison
    /// Compare equal
    Ceq,
    /// Compare not equal
    Cne,
    /// Compare less than
    Clt,
    /// Compare greater than
    Cgt,
    /// Compare less than or equal
    Cle,
    /// Compare greater than or equal
    Cge,

    // Conversion
    /// Convert to int8
    ConvI1,
    /// Convert to int16
    ConvI2,
    /// Convert to int32
    ConvI4,
    /// Convert to int64
    ConvI8,
    /// Convert to uint8
    ConvU1,
    /// Convert to uint16
    ConvU2,
    /// Convert to uint32
    ConvU4,
    /// Convert to uint64
    ConvU8,
    /// Convert to float32
    ConvR4,
    /// Convert to float64
    ConvR8,
}

impl ComputedOp {
    /// Returns `true` if this operation is commutative.
    #[must_use]
    pub const fn is_commutative(&self) -> bool {
        matches!(
            self,
            Self::Add | Self::Mul | Self::And | Self::Or | Self::Xor | Self::Ceq | Self::Cne
        )
    }

    /// Returns `true` if this is a comparison operation.
    #[must_use]
    pub const fn is_comparison(&self) -> bool {
        matches!(
            self,
            Self::Ceq | Self::Cne | Self::Clt | Self::Cgt | Self::Cle | Self::Cge
        )
    }
}

impl fmt::Display for ComputedOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Add => "add",
            Self::Sub => "sub",
            Self::Mul => "mul",
            Self::Div => "div",
            Self::Rem => "rem",
            Self::Neg => "neg",
            Self::And => "and",
            Self::Or => "or",
            Self::Xor => "xor",
            Self::Not => "not",
            Self::Shl => "shl",
            Self::Shr => "shr",
            Self::Ceq => "ceq",
            Self::Cne => "cne",
            Self::Clt => "clt",
            Self::Cgt => "cgt",
            Self::Cle => "cle",
            Self::Cge => "cge",
            Self::ConvI1 => "conv.i1",
            Self::ConvI2 => "conv.i2",
            Self::ConvI4 => "conv.i4",
            Self::ConvI8 => "conv.i8",
            Self::ConvU1 => "conv.u1",
            Self::ConvU2 => "conv.u2",
            Self::ConvU4 => "conv.u4",
            Self::ConvU8 => "conv.u8",
            Self::ConvR4 => "conv.r4",
            Self::ConvR8 => "conv.r8",
        };
        write!(f, "{s}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_const_arithmetic() {
        let a = ConstValue::I32(10);
        let b = ConstValue::I32(3);

        assert_eq!(a.add(&b), Some(ConstValue::I32(13)));
        assert_eq!(a.sub(&b), Some(ConstValue::I32(7)));
        assert_eq!(a.mul(&b), Some(ConstValue::I32(30)));
    }

    #[test]
    fn test_const_comparison() {
        let a = ConstValue::I32(10);
        let b = ConstValue::I32(3);
        let c = ConstValue::I32(10);

        assert_eq!(a.ceq(&b), Some(ConstValue::False));
        assert_eq!(a.ceq(&c), Some(ConstValue::True));
        assert_eq!(a.clt(&b), Some(ConstValue::False));
        assert_eq!(b.clt(&a), Some(ConstValue::True));
    }

    #[test]
    fn test_const_bool_conversion() {
        assert_eq!(ConstValue::True.as_bool(), Some(true));
        assert_eq!(ConstValue::False.as_bool(), Some(false));
        assert_eq!(ConstValue::I32(0).as_bool(), Some(false));
        assert_eq!(ConstValue::I32(42).as_bool(), Some(true));
        assert_eq!(ConstValue::Null.as_bool(), Some(false));
    }

    #[test]
    fn test_abstract_value_meet() {
        // Top meets anything yields the other
        assert_eq!(
            AbstractValue::Top.meet(&AbstractValue::Constant(ConstValue::I32(5))),
            AbstractValue::Constant(ConstValue::I32(5))
        );

        // Same constants stay constant
        assert_eq!(
            AbstractValue::Constant(ConstValue::I32(5))
                .meet(&AbstractValue::Constant(ConstValue::I32(5))),
            AbstractValue::Constant(ConstValue::I32(5))
        );

        // Different constants become Bottom
        assert_eq!(
            AbstractValue::Constant(ConstValue::I32(5))
                .meet(&AbstractValue::Constant(ConstValue::I32(10))),
            AbstractValue::Bottom
        );

        // Bottom meets anything yields Bottom
        assert_eq!(
            AbstractValue::Bottom.meet(&AbstractValue::Constant(ConstValue::I32(5))),
            AbstractValue::Bottom
        );
    }

    #[test]
    fn test_range_merge() {
        let r1 = AbstractValue::Range { min: 0, max: 10 };
        let r2 = AbstractValue::Range { min: 5, max: 15 };

        assert_eq!(r1.meet(&r2), AbstractValue::Range { min: 0, max: 15 });
    }

    #[test]
    fn test_computed_value_normalization() {
        let v0 = SsaVarId::new(0);
        let v1 = SsaVarId::new(1);

        // add(v1, v0) should normalize to add(v0, v1)
        let cv1 = ComputedValue::binary(ComputedOp::Add, v1, v0).normalized();
        let cv2 = ComputedValue::binary(ComputedOp::Add, v0, v1).normalized();

        assert_eq!(cv1, cv2);

        // sub is not commutative, should not normalize
        let cv3 = ComputedValue::binary(ComputedOp::Sub, v1, v0).normalized();
        let cv4 = ComputedValue::binary(ComputedOp::Sub, v0, v1).normalized();

        assert_ne!(cv3, cv4);
    }
}
