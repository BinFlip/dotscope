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

use crate::{
    analysis::ssa::{
        types::{FieldRef, MethodRef, TypeRef},
        SsaType, SsaVarId,
    },
    assembly::Immediate,
    metadata::typesystem::PointerSize,
    Error,
};

/// Constant values that can appear in SSA form.
///
/// These represent compile-time constants that can be tracked through
/// the SSA graph for constant propagation and folding.
#[derive(Debug, Clone, PartialEq)]
pub enum ConstValue {
    /// 8-bit signed integer.
    I8(i8),

    /// 16-bit signed integer.
    I16(i16),

    /// 32-bit signed integer.
    I32(i32),

    /// 64-bit signed integer.
    I64(i64),

    /// 8-bit unsigned integer.
    U8(u8),

    /// 16-bit unsigned integer.
    U16(u16),

    /// 32-bit unsigned integer.
    U32(u32),

    /// 64-bit unsigned integer.
    U64(u64),

    /// Native integer (pointer-sized).
    NativeInt(i64),

    /// Native unsigned integer (pointer-sized).
    NativeUInt(u64),

    /// 32-bit floating point.
    F32(f32),

    /// 64-bit floating point.
    F64(f64),

    /// String constant (index into #US heap).
    String(u32),

    /// Decrypted string value (actual string content, not a heap index).
    /// Used by deobfuscation passes to store strings that were decrypted at analysis time.
    DecryptedString(String),

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

    /// Returns `true` if this is an integer constant (signed or unsigned).
    #[must_use]
    pub const fn is_integer(&self) -> bool {
        matches!(
            self,
            Self::I8(_)
                | Self::I16(_)
                | Self::I32(_)
                | Self::I64(_)
                | Self::U8(_)
                | Self::U16(_)
                | Self::U32(_)
                | Self::U64(_)
                | Self::NativeInt(_)
                | Self::NativeUInt(_)
        )
    }

    /// Returns `true` if this is a signed integer constant.
    #[must_use]
    pub const fn is_signed(&self) -> bool {
        matches!(
            self,
            Self::I8(_) | Self::I16(_) | Self::I32(_) | Self::I64(_) | Self::NativeInt(_)
        )
    }

    /// Returns `true` if this is an unsigned integer constant.
    #[must_use]
    pub const fn is_unsigned(&self) -> bool {
        matches!(
            self,
            Self::U8(_) | Self::U16(_) | Self::U32(_) | Self::U64(_) | Self::NativeUInt(_)
        )
    }

    /// Returns `true` if this is a floating-point constant.
    #[must_use]
    pub const fn is_float(&self) -> bool {
        matches!(self, Self::F32(_) | Self::F64(_))
    }

    /// Returns the SSA type corresponding to this constant value.
    #[must_use]
    pub const fn ssa_type(&self) -> SsaType {
        match self {
            Self::I8(_) => SsaType::I8,
            Self::I16(_) => SsaType::I16,
            Self::I32(_) => SsaType::I32,
            Self::I64(_) => SsaType::I64,
            Self::U8(_) => SsaType::U8,
            Self::U16(_) => SsaType::U16,
            Self::U32(_) => SsaType::U32,
            Self::U64(_) => SsaType::U64,
            Self::F32(_) => SsaType::F32,
            Self::F64(_) => SsaType::F64,
            Self::NativeInt(_) => SsaType::NativeInt,
            Self::NativeUInt(_) => SsaType::NativeUInt,
            Self::True | Self::False => SsaType::Bool,
            Self::Null | Self::String(_) | Self::DecryptedString(_) => SsaType::Object,
            Self::Type(_) => SsaType::NativeInt, // RuntimeTypeHandle
            Self::MethodHandle(_) => SsaType::NativeInt, // RuntimeMethodHandle
            Self::FieldHandle(_) => SsaType::NativeInt, // RuntimeFieldHandle
        }
    }

    /// Returns the constant as an i32 if applicable.
    #[must_use]
    pub const fn as_i32(&self) -> Option<i32> {
        match self {
            Self::I8(v) => Some(*v as i32),
            Self::I16(v) => Some(*v as i32),
            Self::I32(v) => Some(*v),
            Self::U8(v) => Some(*v as i32),
            Self::U16(v) => Some(*v as i32),
            Self::True => Some(1),
            Self::False => Some(0),
            _ => None,
        }
    }

    /// Returns the constant as an i64 if applicable.
    #[must_use]
    #[allow(clippy::match_same_arms)] // NativeInt is semantically different from I64
    pub const fn as_i64(&self) -> Option<i64> {
        match self {
            Self::I8(v) => Some(*v as i64),
            Self::I16(v) => Some(*v as i64),
            Self::I32(v) => Some(*v as i64),
            Self::I64(v) => Some(*v),
            Self::U8(v) => Some(*v as i64),
            Self::U16(v) => Some(*v as i64),
            Self::U32(v) => Some(*v as i64),
            Self::NativeInt(v) => Some(*v),
            Self::True => Some(1),
            Self::False => Some(0),
            _ => None,
        }
    }

    /// Returns the constant as a u64 if applicable (for unsigned operations).
    #[must_use]
    #[allow(clippy::cast_sign_loss)] // Guarded by >= 0 checks
    #[allow(clippy::match_same_arms)] // NativeUInt is semantically different from U64
    pub const fn as_u64(&self) -> Option<u64> {
        match self {
            Self::U8(v) => Some(*v as u64),
            Self::U16(v) => Some(*v as u64),
            Self::U32(v) => Some(*v as u64),
            Self::U64(v) => Some(*v),
            Self::NativeUInt(v) => Some(*v),
            Self::I8(v) if *v >= 0 => Some(*v as u64),
            Self::I16(v) if *v >= 0 => Some(*v as u64),
            Self::I32(v) if *v >= 0 => Some(*v as u64),
            Self::I64(v) if *v >= 0 => Some(*v as u64),
            Self::True => Some(1),
            Self::False => Some(0),
            _ => None,
        }
    }

    /// Returns the constant as a u32 if applicable (for unsigned operations).
    #[must_use]
    #[allow(clippy::cast_sign_loss)] // Guarded by >= 0 checks
    pub const fn as_u32(&self) -> Option<u32> {
        match self {
            Self::U8(v) => Some(*v as u32),
            Self::U16(v) => Some(*v as u32),
            Self::U32(v) => Some(*v),
            Self::I8(v) if *v >= 0 => Some(*v as u32),
            Self::I16(v) if *v >= 0 => Some(*v as u32),
            Self::I32(v) if *v >= 0 => Some(*v as u32),
            Self::True => Some(1),
            Self::False => Some(0),
            _ => None,
        }
    }

    /// Returns the constant as an f32 if it's stored as F32.
    #[must_use]
    pub const fn as_f32(&self) -> Option<f32> {
        match self {
            Self::F32(v) => Some(*v),
            _ => None,
        }
    }

    /// Returns the constant as an f64 if it's stored as F64.
    #[must_use]
    pub const fn as_f64(&self) -> Option<f64> {
        match self {
            Self::F64(v) => Some(*v),
            _ => None,
        }
    }

    /// Returns the constant as a bool if applicable.
    #[must_use]
    pub const fn as_bool(&self) -> Option<bool> {
        match self {
            Self::False
            | Self::Null
            | Self::I8(0)
            | Self::I16(0)
            | Self::I32(0)
            | Self::I64(0)
            | Self::U8(0)
            | Self::U16(0)
            | Self::U32(0)
            | Self::U64(0) => Some(false),
            Self::True
            | Self::I8(_)
            | Self::I16(_)
            | Self::I32(_)
            | Self::I64(_)
            | Self::U8(_)
            | Self::U16(_)
            | Self::U32(_)
            | Self::U64(_) => Some(true),
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

    /// Returns `true` if this constant represents zero.
    ///
    /// This includes all numeric zero values and `False`.
    /// Useful for opaque predicate detection where `x ^ x`, `x - x`, `x * 0`, etc. produce zero.
    #[must_use]
    pub const fn is_zero(&self) -> bool {
        matches!(
            self,
            Self::I8(0)
                | Self::I16(0)
                | Self::I32(0)
                | Self::I64(0)
                | Self::U8(0)
                | Self::U16(0)
                | Self::U32(0)
                | Self::U64(0)
                | Self::NativeInt(0)
                | Self::NativeUInt(0)
                | Self::False
        )
    }

    /// Returns `true` if this constant represents one.
    ///
    /// This includes all numeric one values and `True`.
    /// Useful for identity operations and opaque predicate detection.
    #[must_use]
    pub const fn is_one(&self) -> bool {
        matches!(
            self,
            Self::I8(1)
                | Self::I16(1)
                | Self::I32(1)
                | Self::I64(1)
                | Self::U8(1)
                | Self::U16(1)
                | Self::U32(1)
                | Self::U64(1)
                | Self::NativeInt(1)
                | Self::NativeUInt(1)
                | Self::True
        )
    }

    /// Returns `true` if this constant represents negative one (-1).
    ///
    /// This is useful for detecting `x | -1 = -1` patterns in opaque predicates.
    #[must_use]
    pub const fn is_minus_one(&self) -> bool {
        matches!(
            self,
            Self::I8(-1) | Self::I16(-1) | Self::I32(-1) | Self::I64(-1) | Self::NativeInt(-1)
        )
    }

    /// Returns `true` if this constant has all bits set (e.g., -1 for signed, MAX for unsigned).
    ///
    /// This is useful for detecting `x & -1 = x` and `x | -1 = -1` patterns.
    #[must_use]
    pub const fn is_all_ones(&self) -> bool {
        matches!(
            self,
            Self::I8(-1)
                | Self::I16(-1)
                | Self::I32(-1)
                | Self::I64(-1)
                | Self::NativeInt(-1)
                | Self::U8(u8::MAX)
                | Self::U16(u16::MAX)
                | Self::U32(u32::MAX)
                | Self::U64(u64::MAX)
                | Self::NativeUInt(u64::MAX)
        )
    }

    /// Returns a zero constant of the same type as this constant.
    ///
    /// Useful for algebraic simplifications like `x * 0 = 0` where the result
    /// should preserve the type of the operands.
    #[must_use]
    pub const fn zero_of_same_type(&self) -> Self {
        match self {
            Self::I8(_) => Self::I8(0),
            Self::I16(_) => Self::I16(0),
            Self::I32(_) => Self::I32(0),
            Self::I64(_) => Self::I64(0),
            Self::U8(_) => Self::U8(0),
            Self::U16(_) => Self::U16(0),
            Self::U32(_) => Self::U32(0),
            Self::U64(_) => Self::U64(0),
            Self::NativeInt(_) => Self::NativeInt(0),
            Self::NativeUInt(_) => Self::NativeUInt(0),
            Self::F32(_) => Self::F32(0.0),
            Self::F64(_) => Self::F64(0.0),
            // For non-numeric types, default to i32
            _ => Self::I32(0),
        }
    }

    /// Attempts to negate this constant.
    #[must_use]
    pub fn negate(&self, ptr_size: PointerSize) -> Option<Self> {
        match self {
            Self::I8(v) => Some(Self::I8(v.wrapping_neg())),
            Self::I16(v) => Some(Self::I16(v.wrapping_neg())),
            Self::I32(v) => Some(Self::I32(v.wrapping_neg())),
            Self::I64(v) => Some(Self::I64(v.wrapping_neg())),
            Self::NativeInt(v) => Some(Self::NativeInt(v.wrapping_neg())),
            Self::F32(v) => Some(Self::F32(-v)),
            Self::F64(v) => Some(Self::F64(-v)),
            // Unsigned negation wraps
            Self::U8(v) => Some(Self::U8(v.wrapping_neg())),
            Self::U16(v) => Some(Self::U16(v.wrapping_neg())),
            Self::U32(v) => Some(Self::U32(v.wrapping_neg())),
            Self::U64(v) => Some(Self::U64(v.wrapping_neg())),
            Self::NativeUInt(v) => Some(Self::NativeUInt(v.wrapping_neg())),
            _ => None,
        }
        .map(|v| v.mask_native(ptr_size))
    }

    /// Attempts to perform bitwise NOT on this constant.
    #[must_use]
    pub fn bitwise_not(&self, ptr_size: PointerSize) -> Option<Self> {
        match self {
            Self::I8(v) => Some(Self::I8(!v)),
            Self::I16(v) => Some(Self::I16(!v)),
            Self::I32(v) => Some(Self::I32(!v)),
            Self::I64(v) => Some(Self::I64(!v)),
            Self::U8(v) => Some(Self::U8(!v)),
            Self::U16(v) => Some(Self::U16(!v)),
            Self::U32(v) => Some(Self::U32(!v)),
            Self::U64(v) => Some(Self::U64(!v)),
            Self::NativeInt(v) => Some(Self::NativeInt(!v)),
            Self::NativeUInt(v) => Some(Self::NativeUInt(!v)),
            _ => None,
        }
        .map(|v| v.mask_native(ptr_size))
    }

    /// Attempts to perform bitwise AND on two constants.
    #[must_use]
    pub fn bitwise_and(&self, other: &Self, ptr_size: PointerSize) -> Option<Self> {
        match (self, other) {
            (Self::I8(a), Self::I8(b)) => Some(Self::I8(a & b)),
            (Self::I16(a), Self::I16(b)) => Some(Self::I16(a & b)),
            (Self::I32(a), Self::I32(b)) => Some(Self::I32(a & b)),
            (Self::I64(a), Self::I64(b)) => Some(Self::I64(a & b)),
            (Self::U8(a), Self::U8(b)) => Some(Self::U8(a & b)),
            (Self::U16(a), Self::U16(b)) => Some(Self::U16(a & b)),
            (Self::U32(a), Self::U32(b)) => Some(Self::U32(a & b)),
            (Self::U64(a), Self::U64(b)) => Some(Self::U64(a & b)),
            (Self::NativeInt(a), Self::NativeInt(b)) => Some(Self::NativeInt(a & b)),
            (Self::NativeUInt(a), Self::NativeUInt(b)) => Some(Self::NativeUInt(a & b)),
            // Cross-type: promote to i64 for mixed signed operations
            (Self::I32(a), Self::I64(b)) | (Self::I64(b), Self::I32(a)) => {
                Some(Self::I64(i64::from(*a) & b))
            }
            (Self::U32(a), Self::U64(b)) | (Self::U64(b), Self::U32(a)) => {
                Some(Self::U64(u64::from(*a) & b))
            }
            _ => None,
        }
        .map(|v| v.mask_native(ptr_size))
    }

    /// Attempts to perform bitwise OR on two constants.
    #[must_use]
    pub fn bitwise_or(&self, other: &Self, ptr_size: PointerSize) -> Option<Self> {
        match (self, other) {
            (Self::I8(a), Self::I8(b)) => Some(Self::I8(a | b)),
            (Self::I16(a), Self::I16(b)) => Some(Self::I16(a | b)),
            (Self::I32(a), Self::I32(b)) => Some(Self::I32(a | b)),
            (Self::I64(a), Self::I64(b)) => Some(Self::I64(a | b)),
            (Self::U8(a), Self::U8(b)) => Some(Self::U8(a | b)),
            (Self::U16(a), Self::U16(b)) => Some(Self::U16(a | b)),
            (Self::U32(a), Self::U32(b)) => Some(Self::U32(a | b)),
            (Self::U64(a), Self::U64(b)) => Some(Self::U64(a | b)),
            (Self::NativeInt(a), Self::NativeInt(b)) => Some(Self::NativeInt(a | b)),
            (Self::NativeUInt(a), Self::NativeUInt(b)) => Some(Self::NativeUInt(a | b)),
            (Self::I32(a), Self::I64(b)) | (Self::I64(b), Self::I32(a)) => {
                Some(Self::I64(i64::from(*a) | b))
            }
            (Self::U32(a), Self::U64(b)) | (Self::U64(b), Self::U32(a)) => {
                Some(Self::U64(u64::from(*a) | b))
            }
            _ => None,
        }
        .map(|v| v.mask_native(ptr_size))
    }

    /// Attempts to perform bitwise XOR on two constants.
    #[must_use]
    pub fn bitwise_xor(&self, other: &Self, ptr_size: PointerSize) -> Option<Self> {
        match (self, other) {
            (Self::I8(a), Self::I8(b)) => Some(Self::I8(a ^ b)),
            (Self::I16(a), Self::I16(b)) => Some(Self::I16(a ^ b)),
            (Self::I32(a), Self::I32(b)) => Some(Self::I32(a ^ b)),
            (Self::I64(a), Self::I64(b)) => Some(Self::I64(a ^ b)),
            (Self::U8(a), Self::U8(b)) => Some(Self::U8(a ^ b)),
            (Self::U16(a), Self::U16(b)) => Some(Self::U16(a ^ b)),
            (Self::U32(a), Self::U32(b)) => Some(Self::U32(a ^ b)),
            (Self::U64(a), Self::U64(b)) => Some(Self::U64(a ^ b)),
            (Self::NativeInt(a), Self::NativeInt(b)) => Some(Self::NativeInt(a ^ b)),
            (Self::NativeUInt(a), Self::NativeUInt(b)) => Some(Self::NativeUInt(a ^ b)),
            (Self::I32(a), Self::I64(b)) | (Self::I64(b), Self::I32(a)) => {
                Some(Self::I64(i64::from(*a) ^ b))
            }
            (Self::U32(a), Self::U64(b)) | (Self::U64(b), Self::U32(a)) => {
                Some(Self::U64(u64::from(*a) ^ b))
            }
            _ => None,
        }
        .map(|v| v.mask_native(ptr_size))
    }

    /// Attempts to shift left.
    #[must_use]
    #[allow(clippy::cast_sign_loss)] // Shift amounts are non-negative by convention
    pub fn shl(&self, amount: &Self, ptr_size: PointerSize) -> Option<Self> {
        let shift = amount.as_i32()? as u32;
        match self {
            Self::I8(v) => Some(Self::I8(v.wrapping_shl(shift))),
            Self::I16(v) => Some(Self::I16(v.wrapping_shl(shift))),
            Self::I32(v) => Some(Self::I32(v.wrapping_shl(shift))),
            Self::I64(v) => Some(Self::I64(v.wrapping_shl(shift))),
            Self::U8(v) => Some(Self::U8(v.wrapping_shl(shift))),
            Self::U16(v) => Some(Self::U16(v.wrapping_shl(shift))),
            Self::U32(v) => Some(Self::U32(v.wrapping_shl(shift))),
            Self::U64(v) => Some(Self::U64(v.wrapping_shl(shift))),
            Self::NativeInt(v) => Some(Self::NativeInt(v.wrapping_shl(shift))),
            Self::NativeUInt(v) => Some(Self::NativeUInt(v.wrapping_shl(shift))),
            _ => None,
        }
        .map(|v| v.mask_native(ptr_size))
    }

    /// Attempts to shift right (arithmetic for signed, logical for unsigned).
    #[must_use]
    #[allow(clippy::cast_sign_loss)] // Shift amounts and unsigned shifts use intentional casts
    #[allow(clippy::cast_possible_wrap)] // Wrapping is expected for logical shift operations
    pub fn shr(&self, amount: &Self, unsigned: bool, ptr_size: PointerSize) -> Option<Self> {
        let shift = amount.as_i32()? as u32;
        match self {
            Self::I8(v) => {
                if unsigned {
                    Some(Self::I8((*v as u8).wrapping_shr(shift) as i8))
                } else {
                    Some(Self::I8(v.wrapping_shr(shift)))
                }
            }
            Self::I16(v) => {
                if unsigned {
                    Some(Self::I16((*v as u16).wrapping_shr(shift) as i16))
                } else {
                    Some(Self::I16(v.wrapping_shr(shift)))
                }
            }
            Self::I32(v) => {
                if unsigned {
                    Some(Self::I32((*v as u32).wrapping_shr(shift) as i32))
                } else {
                    Some(Self::I32(v.wrapping_shr(shift)))
                }
            }
            Self::I64(v) => {
                if unsigned {
                    Some(Self::I64((*v as u64).wrapping_shr(shift) as i64))
                } else {
                    Some(Self::I64(v.wrapping_shr(shift)))
                }
            }
            Self::U8(v) => Some(Self::U8(v.wrapping_shr(shift))),
            Self::U16(v) => Some(Self::U16(v.wrapping_shr(shift))),
            Self::U32(v) => Some(Self::U32(v.wrapping_shr(shift))),
            Self::U64(v) => Some(Self::U64(v.wrapping_shr(shift))),
            Self::NativeInt(v) => {
                if unsigned {
                    Some(Self::NativeInt((*v as u64).wrapping_shr(shift) as i64))
                } else {
                    Some(Self::NativeInt(v.wrapping_shr(shift)))
                }
            }
            Self::NativeUInt(v) => Some(Self::NativeUInt(v.wrapping_shr(shift))),
            _ => None,
        }
        .map(|v| v.mask_native(ptr_size))
    }

    /// Attempts to add two constants.
    #[must_use]
    pub fn add(&self, other: &Self, ptr_size: PointerSize) -> Option<Self> {
        match (self, other) {
            (Self::I8(a), Self::I8(b)) => Some(Self::I8(a.wrapping_add(*b))),
            (Self::I16(a), Self::I16(b)) => Some(Self::I16(a.wrapping_add(*b))),
            (Self::I32(a), Self::I32(b)) => Some(Self::I32(a.wrapping_add(*b))),
            (Self::I64(a), Self::I64(b)) => Some(Self::I64(a.wrapping_add(*b))),
            (Self::U8(a), Self::U8(b)) => Some(Self::U8(a.wrapping_add(*b))),
            (Self::U16(a), Self::U16(b)) => Some(Self::U16(a.wrapping_add(*b))),
            (Self::U32(a), Self::U32(b)) => Some(Self::U32(a.wrapping_add(*b))),
            (Self::U64(a), Self::U64(b)) => Some(Self::U64(a.wrapping_add(*b))),
            (Self::NativeInt(a), Self::NativeInt(b)) => Some(Self::NativeInt(a.wrapping_add(*b))),
            (Self::NativeUInt(a), Self::NativeUInt(b)) => {
                Some(Self::NativeUInt(a.wrapping_add(*b)))
            }
            (Self::F32(a), Self::F32(b)) => Some(Self::F32(a + b)),
            (Self::F64(a), Self::F64(b)) => Some(Self::F64(a + b)),
            // Cross-type promotions
            (Self::I32(a), Self::I64(b)) | (Self::I64(b), Self::I32(a)) => {
                Some(Self::I64(i64::from(*a).wrapping_add(*b)))
            }
            (Self::U32(a), Self::U64(b)) | (Self::U64(b), Self::U32(a)) => {
                Some(Self::U64(u64::from(*a).wrapping_add(*b)))
            }
            _ => None,
        }
        .map(|v| v.mask_native(ptr_size))
    }

    /// Attempts to subtract two constants.
    #[must_use]
    pub fn sub(&self, other: &Self, ptr_size: PointerSize) -> Option<Self> {
        match (self, other) {
            (Self::I8(a), Self::I8(b)) => Some(Self::I8(a.wrapping_sub(*b))),
            (Self::I16(a), Self::I16(b)) => Some(Self::I16(a.wrapping_sub(*b))),
            (Self::I32(a), Self::I32(b)) => Some(Self::I32(a.wrapping_sub(*b))),
            (Self::I64(a), Self::I64(b)) => Some(Self::I64(a.wrapping_sub(*b))),
            (Self::U8(a), Self::U8(b)) => Some(Self::U8(a.wrapping_sub(*b))),
            (Self::U16(a), Self::U16(b)) => Some(Self::U16(a.wrapping_sub(*b))),
            (Self::U32(a), Self::U32(b)) => Some(Self::U32(a.wrapping_sub(*b))),
            (Self::U64(a), Self::U64(b)) => Some(Self::U64(a.wrapping_sub(*b))),
            (Self::NativeInt(a), Self::NativeInt(b)) => Some(Self::NativeInt(a.wrapping_sub(*b))),
            (Self::NativeUInt(a), Self::NativeUInt(b)) => {
                Some(Self::NativeUInt(a.wrapping_sub(*b)))
            }
            (Self::F32(a), Self::F32(b)) => Some(Self::F32(a - b)),
            (Self::F64(a), Self::F64(b)) => Some(Self::F64(a - b)),
            (Self::I32(a), Self::I64(b)) => Some(Self::I64(i64::from(*a).wrapping_sub(*b))),
            (Self::I64(a), Self::I32(b)) => Some(Self::I64(a.wrapping_sub(i64::from(*b)))),
            (Self::U32(a), Self::U64(b)) => Some(Self::U64(u64::from(*a).wrapping_sub(*b))),
            (Self::U64(a), Self::U32(b)) => Some(Self::U64(a.wrapping_sub(u64::from(*b)))),
            _ => None,
        }
        .map(|v| v.mask_native(ptr_size))
    }

    /// Attempts to multiply two constants.
    #[must_use]
    pub fn mul(&self, other: &Self, ptr_size: PointerSize) -> Option<Self> {
        match (self, other) {
            (Self::I8(a), Self::I8(b)) => Some(Self::I8(a.wrapping_mul(*b))),
            (Self::I16(a), Self::I16(b)) => Some(Self::I16(a.wrapping_mul(*b))),
            (Self::I32(a), Self::I32(b)) => Some(Self::I32(a.wrapping_mul(*b))),
            (Self::I64(a), Self::I64(b)) => Some(Self::I64(a.wrapping_mul(*b))),
            (Self::U8(a), Self::U8(b)) => Some(Self::U8(a.wrapping_mul(*b))),
            (Self::U16(a), Self::U16(b)) => Some(Self::U16(a.wrapping_mul(*b))),
            (Self::U32(a), Self::U32(b)) => Some(Self::U32(a.wrapping_mul(*b))),
            (Self::U64(a), Self::U64(b)) => Some(Self::U64(a.wrapping_mul(*b))),
            (Self::NativeInt(a), Self::NativeInt(b)) => Some(Self::NativeInt(a.wrapping_mul(*b))),
            (Self::NativeUInt(a), Self::NativeUInt(b)) => {
                Some(Self::NativeUInt(a.wrapping_mul(*b)))
            }
            (Self::F32(a), Self::F32(b)) => Some(Self::F32(a * b)),
            (Self::F64(a), Self::F64(b)) => Some(Self::F64(a * b)),
            (Self::I32(a), Self::I64(b)) | (Self::I64(b), Self::I32(a)) => {
                Some(Self::I64(i64::from(*a).wrapping_mul(*b)))
            }
            (Self::U32(a), Self::U64(b)) | (Self::U64(b), Self::U32(a)) => {
                Some(Self::U64(u64::from(*a).wrapping_mul(*b)))
            }
            _ => None,
        }
        .map(|v| v.mask_native(ptr_size))
    }

    /// Attempts to add two constants with overflow checking.
    ///
    /// Returns `None` if the addition would overflow.
    /// When `unsigned` is true, operands are treated as unsigned for overflow detection.
    #[must_use]
    pub fn add_checked(&self, other: &Self, unsigned: bool, ptr_size: PointerSize) -> Option<Self> {
        if unsigned {
            // Unsigned overflow check
            match (self, other) {
                (Self::I32(a), Self::I32(b)) => (*a as u32)
                    .checked_add(*b as u32)
                    .map(|r| Self::I32(r as i32)),
                (Self::I64(a), Self::I64(b)) => (*a as u64)
                    .checked_add(*b as u64)
                    .map(|r| Self::I64(r as i64)),
                (Self::U8(a), Self::U8(b)) => a.checked_add(*b).map(Self::U8),
                (Self::U16(a), Self::U16(b)) => a.checked_add(*b).map(Self::U16),
                (Self::U32(a), Self::U32(b)) => a.checked_add(*b).map(Self::U32),
                (Self::U64(a), Self::U64(b)) => a.checked_add(*b).map(Self::U64),
                (Self::NativeUInt(a), Self::NativeUInt(b)) => {
                    a.checked_add(*b).map(Self::NativeUInt)
                }
                _ => None,
            }
        } else {
            // Signed overflow check
            match (self, other) {
                (Self::I8(a), Self::I8(b)) => a.checked_add(*b).map(Self::I8),
                (Self::I16(a), Self::I16(b)) => a.checked_add(*b).map(Self::I16),
                (Self::I32(a), Self::I32(b)) => a.checked_add(*b).map(Self::I32),
                (Self::I64(a), Self::I64(b)) => a.checked_add(*b).map(Self::I64),
                (Self::NativeInt(a), Self::NativeInt(b)) => a.checked_add(*b).map(Self::NativeInt),
                _ => None,
            }
        }
        .map(|v| v.mask_native(ptr_size))
    }

    /// Attempts to subtract two constants with overflow checking.
    ///
    /// Returns `None` if the subtraction would overflow.
    /// When `unsigned` is true, operands are treated as unsigned for overflow detection.
    #[must_use]
    pub fn sub_checked(&self, other: &Self, unsigned: bool, ptr_size: PointerSize) -> Option<Self> {
        if unsigned {
            // Unsigned overflow check
            match (self, other) {
                (Self::I32(a), Self::I32(b)) => (*a as u32)
                    .checked_sub(*b as u32)
                    .map(|r| Self::I32(r as i32)),
                (Self::I64(a), Self::I64(b)) => (*a as u64)
                    .checked_sub(*b as u64)
                    .map(|r| Self::I64(r as i64)),
                (Self::U8(a), Self::U8(b)) => a.checked_sub(*b).map(Self::U8),
                (Self::U16(a), Self::U16(b)) => a.checked_sub(*b).map(Self::U16),
                (Self::U32(a), Self::U32(b)) => a.checked_sub(*b).map(Self::U32),
                (Self::U64(a), Self::U64(b)) => a.checked_sub(*b).map(Self::U64),
                (Self::NativeUInt(a), Self::NativeUInt(b)) => {
                    a.checked_sub(*b).map(Self::NativeUInt)
                }
                _ => None,
            }
        } else {
            // Signed overflow check
            match (self, other) {
                (Self::I8(a), Self::I8(b)) => a.checked_sub(*b).map(Self::I8),
                (Self::I16(a), Self::I16(b)) => a.checked_sub(*b).map(Self::I16),
                (Self::I32(a), Self::I32(b)) => a.checked_sub(*b).map(Self::I32),
                (Self::I64(a), Self::I64(b)) => a.checked_sub(*b).map(Self::I64),
                (Self::NativeInt(a), Self::NativeInt(b)) => a.checked_sub(*b).map(Self::NativeInt),
                _ => None,
            }
        }
        .map(|v| v.mask_native(ptr_size))
    }

    /// Attempts to multiply two constants with overflow checking.
    ///
    /// Returns `None` if the multiplication would overflow.
    /// When `unsigned` is true, operands are treated as unsigned for overflow detection.
    #[must_use]
    pub fn mul_checked(&self, other: &Self, unsigned: bool, ptr_size: PointerSize) -> Option<Self> {
        if unsigned {
            // Unsigned overflow check
            match (self, other) {
                (Self::I32(a), Self::I32(b)) => (*a as u32)
                    .checked_mul(*b as u32)
                    .map(|r| Self::I32(r as i32)),
                (Self::I64(a), Self::I64(b)) => (*a as u64)
                    .checked_mul(*b as u64)
                    .map(|r| Self::I64(r as i64)),
                (Self::U8(a), Self::U8(b)) => a.checked_mul(*b).map(Self::U8),
                (Self::U16(a), Self::U16(b)) => a.checked_mul(*b).map(Self::U16),
                (Self::U32(a), Self::U32(b)) => a.checked_mul(*b).map(Self::U32),
                (Self::U64(a), Self::U64(b)) => a.checked_mul(*b).map(Self::U64),
                (Self::NativeUInt(a), Self::NativeUInt(b)) => {
                    a.checked_mul(*b).map(Self::NativeUInt)
                }
                _ => None,
            }
        } else {
            // Signed overflow check
            match (self, other) {
                (Self::I8(a), Self::I8(b)) => a.checked_mul(*b).map(Self::I8),
                (Self::I16(a), Self::I16(b)) => a.checked_mul(*b).map(Self::I16),
                (Self::I32(a), Self::I32(b)) => a.checked_mul(*b).map(Self::I32),
                (Self::I64(a), Self::I64(b)) => a.checked_mul(*b).map(Self::I64),
                (Self::NativeInt(a), Self::NativeInt(b)) => a.checked_mul(*b).map(Self::NativeInt),
                _ => None,
            }
        }
        .map(|v| v.mask_native(ptr_size))
    }

    /// Attempts to divide two constants.
    #[must_use]
    pub fn div(&self, other: &Self, ptr_size: PointerSize) -> Option<Self> {
        match (self, other) {
            (Self::I8(a), Self::I8(b)) if *b != 0 => Some(Self::I8(a.wrapping_div(*b))),
            (Self::I16(a), Self::I16(b)) if *b != 0 => Some(Self::I16(a.wrapping_div(*b))),
            (Self::I32(a), Self::I32(b)) if *b != 0 => Some(Self::I32(a.wrapping_div(*b))),
            (Self::I64(a), Self::I64(b)) if *b != 0 => Some(Self::I64(a.wrapping_div(*b))),
            (Self::U8(a), Self::U8(b)) if *b != 0 => Some(Self::U8(a / b)),
            (Self::U16(a), Self::U16(b)) if *b != 0 => Some(Self::U16(a / b)),
            (Self::U32(a), Self::U32(b)) if *b != 0 => Some(Self::U32(a / b)),
            (Self::U64(a), Self::U64(b)) if *b != 0 => Some(Self::U64(a / b)),
            (Self::NativeInt(a), Self::NativeInt(b)) if *b != 0 => {
                Some(Self::NativeInt(a.wrapping_div(*b)))
            }
            (Self::NativeUInt(a), Self::NativeUInt(b)) if *b != 0 => Some(Self::NativeUInt(a / b)),
            (Self::F32(a), Self::F32(b)) => Some(Self::F32(a / b)), // Float div by zero is inf
            (Self::F64(a), Self::F64(b)) => Some(Self::F64(a / b)),
            _ => None,
        }
        .map(|v| v.mask_native(ptr_size))
    }

    /// Attempts to compute remainder (modulo) of two constants.
    #[must_use]
    pub fn rem(&self, other: &Self, ptr_size: PointerSize) -> Option<Self> {
        match (self, other) {
            (Self::I8(a), Self::I8(b)) if *b != 0 => Some(Self::I8(a.wrapping_rem(*b))),
            (Self::I16(a), Self::I16(b)) if *b != 0 => Some(Self::I16(a.wrapping_rem(*b))),
            (Self::I32(a), Self::I32(b)) if *b != 0 => Some(Self::I32(a.wrapping_rem(*b))),
            (Self::I64(a), Self::I64(b)) if *b != 0 => Some(Self::I64(a.wrapping_rem(*b))),
            (Self::U8(a), Self::U8(b)) if *b != 0 => Some(Self::U8(a % b)),
            (Self::U16(a), Self::U16(b)) if *b != 0 => Some(Self::U16(a % b)),
            (Self::U32(a), Self::U32(b)) if *b != 0 => Some(Self::U32(a % b)),
            (Self::U64(a), Self::U64(b)) if *b != 0 => Some(Self::U64(a % b)),
            (Self::NativeInt(a), Self::NativeInt(b)) if *b != 0 => {
                Some(Self::NativeInt(a.wrapping_rem(*b)))
            }
            (Self::NativeUInt(a), Self::NativeUInt(b)) if *b != 0 => Some(Self::NativeUInt(a % b)),
            (Self::F32(a), Self::F32(b)) => Some(Self::F32(a % b)),
            (Self::F64(a), Self::F64(b)) => Some(Self::F64(a % b)),
            _ => None,
        }
        .map(|v| v.mask_native(ptr_size))
    }

    /// Attempts to compare two constants for equality.
    #[must_use]
    #[allow(clippy::float_cmp)] // Exact comparison is correct for constant propagation
    #[allow(clippy::match_same_arms)] // NativeInt/NativeUInt are semantically different
    pub fn ceq(&self, other: &Self) -> Option<Self> {
        match (self, other) {
            (Self::I8(a), Self::I8(b)) => Some(Self::from_bool(a == b)),
            (Self::I16(a), Self::I16(b)) => Some(Self::from_bool(a == b)),
            (Self::I32(a), Self::I32(b)) => Some(Self::from_bool(a == b)),
            (Self::I64(a), Self::I64(b)) => Some(Self::from_bool(a == b)),
            (Self::U8(a), Self::U8(b)) => Some(Self::from_bool(a == b)),
            (Self::U16(a), Self::U16(b)) => Some(Self::from_bool(a == b)),
            (Self::U32(a), Self::U32(b)) => Some(Self::from_bool(a == b)),
            (Self::U64(a), Self::U64(b)) => Some(Self::from_bool(a == b)),
            (Self::NativeInt(a), Self::NativeInt(b)) => Some(Self::from_bool(a == b)),
            (Self::NativeUInt(a), Self::NativeUInt(b)) => Some(Self::from_bool(a == b)),
            (Self::F32(a), Self::F32(b)) => Some(Self::from_bool(a == b)),
            (Self::F64(a), Self::F64(b)) => Some(Self::from_bool(a == b)),
            (Self::Null, Self::Null) | (Self::True, Self::True) | (Self::False, Self::False) => {
                Some(Self::True)
            }
            (Self::True, Self::False) | (Self::False, Self::True) => Some(Self::False),
            // Cross-type comparisons with promotion
            (Self::I32(a), Self::I64(b)) | (Self::I64(b), Self::I32(a)) => {
                Some(Self::from_bool(i64::from(*a) == *b))
            }
            (Self::U32(a), Self::U64(b)) | (Self::U64(b), Self::U32(a)) => {
                Some(Self::from_bool(u64::from(*a) == *b))
            }
            _ => None,
        }
    }

    /// Attempts to compare two constants for less-than (signed).
    #[must_use]
    #[allow(clippy::match_same_arms)] // NativeInt/NativeUInt are semantically different
    pub fn clt(&self, other: &Self) -> Option<Self> {
        match (self, other) {
            (Self::I8(a), Self::I8(b)) => Some(Self::from_bool(a < b)),
            (Self::I16(a), Self::I16(b)) => Some(Self::from_bool(a < b)),
            (Self::I32(a), Self::I32(b)) => Some(Self::from_bool(a < b)),
            (Self::I64(a), Self::I64(b)) => Some(Self::from_bool(a < b)),
            (Self::U8(a), Self::U8(b)) => Some(Self::from_bool(a < b)),
            (Self::U16(a), Self::U16(b)) => Some(Self::from_bool(a < b)),
            (Self::U32(a), Self::U32(b)) => Some(Self::from_bool(a < b)),
            (Self::U64(a), Self::U64(b)) => Some(Self::from_bool(a < b)),
            (Self::NativeInt(a), Self::NativeInt(b)) => Some(Self::from_bool(a < b)),
            (Self::NativeUInt(a), Self::NativeUInt(b)) => Some(Self::from_bool(a < b)),
            (Self::F32(a), Self::F32(b)) => Some(Self::from_bool(a < b)),
            (Self::F64(a), Self::F64(b)) => Some(Self::from_bool(a < b)),
            (Self::I32(a), Self::I64(b)) => Some(Self::from_bool(i64::from(*a) < *b)),
            (Self::I64(a), Self::I32(b)) => Some(Self::from_bool(*a < i64::from(*b))),
            (Self::U32(a), Self::U64(b)) => Some(Self::from_bool(u64::from(*a) < *b)),
            (Self::U64(a), Self::U32(b)) => Some(Self::from_bool(*a < u64::from(*b))),
            _ => None,
        }
    }

    /// Attempts to compare two constants for less-than (unsigned).
    #[must_use]
    #[allow(clippy::cast_sign_loss)] // Unsigned comparison requires interpreting bits as unsigned
    #[allow(clippy::match_same_arms)] // NativeInt/NativeUInt are semantically different
    pub fn clt_un(&self, other: &Self) -> Option<Self> {
        // Treat values as unsigned for comparison
        match (self, other) {
            (Self::I8(a), Self::I8(b)) => Some(Self::from_bool((*a as u8) < (*b as u8))),
            (Self::I16(a), Self::I16(b)) => Some(Self::from_bool((*a as u16) < (*b as u16))),
            (Self::I32(a), Self::I32(b)) => Some(Self::from_bool((*a as u32) < (*b as u32))),
            (Self::I64(a), Self::I64(b)) => Some(Self::from_bool((*a as u64) < (*b as u64))),
            (Self::U8(a), Self::U8(b)) => Some(Self::from_bool(a < b)),
            (Self::U16(a), Self::U16(b)) => Some(Self::from_bool(a < b)),
            (Self::U32(a), Self::U32(b)) => Some(Self::from_bool(a < b)),
            (Self::U64(a), Self::U64(b)) => Some(Self::from_bool(a < b)),
            (Self::NativeInt(a), Self::NativeInt(b)) => {
                Some(Self::from_bool((*a as u64) < (*b as u64)))
            }
            (Self::NativeUInt(a), Self::NativeUInt(b)) => Some(Self::from_bool(a < b)),
            // For floats, clt.un checks for unordered (NaN) or less than
            (Self::F32(a), Self::F32(b)) => {
                Some(Self::from_bool(a.is_nan() || b.is_nan() || a < b))
            }
            (Self::F64(a), Self::F64(b)) => {
                Some(Self::from_bool(a.is_nan() || b.is_nan() || a < b))
            }
            _ => None,
        }
    }

    /// Attempts to compare two constants for greater-than (signed).
    #[must_use]
    #[allow(clippy::match_same_arms)] // NativeInt/NativeUInt are semantically different
    pub fn cgt(&self, other: &Self) -> Option<Self> {
        match (self, other) {
            (Self::I8(a), Self::I8(b)) => Some(Self::from_bool(a > b)),
            (Self::I16(a), Self::I16(b)) => Some(Self::from_bool(a > b)),
            (Self::I32(a), Self::I32(b)) => Some(Self::from_bool(a > b)),
            (Self::I64(a), Self::I64(b)) => Some(Self::from_bool(a > b)),
            (Self::U8(a), Self::U8(b)) => Some(Self::from_bool(a > b)),
            (Self::U16(a), Self::U16(b)) => Some(Self::from_bool(a > b)),
            (Self::U32(a), Self::U32(b)) => Some(Self::from_bool(a > b)),
            (Self::U64(a), Self::U64(b)) => Some(Self::from_bool(a > b)),
            (Self::NativeInt(a), Self::NativeInt(b)) => Some(Self::from_bool(a > b)),
            (Self::NativeUInt(a), Self::NativeUInt(b)) => Some(Self::from_bool(a > b)),
            (Self::F32(a), Self::F32(b)) => Some(Self::from_bool(a > b)),
            (Self::F64(a), Self::F64(b)) => Some(Self::from_bool(a > b)),
            (Self::I32(a), Self::I64(b)) => Some(Self::from_bool(i64::from(*a) > *b)),
            (Self::I64(a), Self::I32(b)) => Some(Self::from_bool(*a > i64::from(*b))),
            (Self::U32(a), Self::U64(b)) => Some(Self::from_bool(u64::from(*a) > *b)),
            (Self::U64(a), Self::U32(b)) => Some(Self::from_bool(*a > u64::from(*b))),
            _ => None,
        }
    }

    /// Attempts to compare two constants for greater-than (unsigned).
    #[must_use]
    #[allow(clippy::cast_sign_loss)] // Unsigned comparison requires interpreting bits as unsigned
    #[allow(clippy::match_same_arms)] // NativeInt/NativeUInt are semantically different
    pub fn cgt_un(&self, other: &Self) -> Option<Self> {
        match (self, other) {
            (Self::I8(a), Self::I8(b)) => Some(Self::from_bool((*a as u8) > (*b as u8))),
            (Self::I16(a), Self::I16(b)) => Some(Self::from_bool((*a as u16) > (*b as u16))),
            (Self::I32(a), Self::I32(b)) => Some(Self::from_bool((*a as u32) > (*b as u32))),
            (Self::I64(a), Self::I64(b)) => Some(Self::from_bool((*a as u64) > (*b as u64))),
            (Self::U8(a), Self::U8(b)) => Some(Self::from_bool(a > b)),
            (Self::U16(a), Self::U16(b)) => Some(Self::from_bool(a > b)),
            (Self::U32(a), Self::U32(b)) => Some(Self::from_bool(a > b)),
            (Self::U64(a), Self::U64(b)) => Some(Self::from_bool(a > b)),
            (Self::NativeInt(a), Self::NativeInt(b)) => {
                Some(Self::from_bool((*a as u64) > (*b as u64)))
            }
            (Self::NativeUInt(a), Self::NativeUInt(b)) => Some(Self::from_bool(a > b)),
            // For floats, cgt.un checks for unordered (NaN) or greater than
            (Self::F32(a), Self::F32(b)) => {
                Some(Self::from_bool(a.is_nan() || b.is_nan() || a > b))
            }
            (Self::F64(a), Self::F64(b)) => {
                Some(Self::from_bool(a.is_nan() || b.is_nan() || a > b))
            }
            _ => None,
        }
    }

    /// Converts this constant to a different type.
    ///
    /// This implements CIL type conversion semantics (conv.* instructions).
    /// For overflow checking conversions, use `convert_to_checked`.
    ///
    /// # Arguments
    ///
    /// * `target` - The target SSA type to convert to.
    /// * `unsigned_source` - If true, treat the source value as unsigned for conversion.
    ///
    /// # Returns
    ///
    /// The converted constant, or `None` if conversion is not possible.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use dotscope::analysis::{ConstValue, SsaType};
    /// use dotscope::metadata::typesystem::PointerSize;
    ///
    /// let value = ConstValue::I32(42);
    /// let converted = value.convert_to(&SsaType::I64, false, PointerSize::Bit64);
    /// assert_eq!(converted, Some(ConstValue::I64(42)));
    /// ```
    #[must_use]
    pub fn convert_to(
        &self,
        target: &SsaType,
        unsigned_source: bool,
        ptr_size: PointerSize,
    ) -> Option<Self> {
        // For unsigned source interpretation, get the raw bits as u64
        // For signed source, get as i64
        let (signed_val, unsigned_val) = if unsigned_source {
            let u = self.as_u64()?;
            // Reinterpret as signed for operations that need it
            (i64::from_ne_bytes(u.to_ne_bytes()), u)
        } else {
            let s = self.as_i64()?;
            // Reinterpret as unsigned for operations that need it
            (s, u64::from_ne_bytes(s.to_ne_bytes()))
        };

        // These casts are intentional truncations for type conversion
        #[allow(clippy::cast_possible_truncation)]
        Some(match target {
            // Truncating conversions - use wrapping to get low bits
            SsaType::I8 => Self::I8(signed_val as i8),
            SsaType::U8 => Self::U8(unsigned_val as u8),
            SsaType::I16 => Self::I16(signed_val as i16),
            SsaType::U16 | SsaType::Char => Self::U16(unsigned_val as u16),
            SsaType::I32 => Self::I32(signed_val as i32),
            SsaType::U32 => Self::U32(unsigned_val as u32),
            // Non-truncating conversions
            SsaType::I64 => Self::I64(signed_val),
            SsaType::U64 => Self::U64(unsigned_val),
            SsaType::NativeInt => Self::NativeInt(signed_val),
            SsaType::NativeUInt => Self::NativeUInt(unsigned_val),
            // Float conversions - interpretation matters
            SsaType::F32 =>
            {
                #[allow(clippy::cast_precision_loss)]
                if unsigned_source {
                    Self::F32(unsigned_val as f32)
                } else {
                    Self::F32(signed_val as f32)
                }
            }
            SsaType::F64 =>
            {
                #[allow(clippy::cast_precision_loss)]
                if unsigned_source {
                    Self::F64(unsigned_val as f64)
                } else {
                    Self::F64(signed_val as f64)
                }
            }
            SsaType::Bool => Self::from_bool(signed_val != 0),
            _ => return None,
        })
        .map(|v| v.mask_native(ptr_size))
    }

    /// Converts this constant to a different type with overflow checking.
    ///
    /// This implements CIL overflow-checked conversion semantics (conv.ovf.* instructions).
    /// Returns `None` if the value would overflow the target type.
    ///
    /// # Arguments
    ///
    /// * `target` - The target SSA type to convert to.
    /// * `unsigned_source` - If true, treat the source value as unsigned for conversion.
    ///
    /// # Returns
    ///
    /// The converted constant if no overflow, or `None` if conversion would overflow
    /// or is not possible.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use dotscope::analysis::{ConstValue, SsaType};
    /// use dotscope::metadata::typesystem::PointerSize;
    ///
    /// let value = ConstValue::I32(1000);
    /// // 1000 doesn't fit in i8 (-128 to 127)
    /// assert_eq!(value.convert_to_checked(&SsaType::I8, false, PointerSize::Bit64), None);
    ///
    /// let small = ConstValue::I32(42);
    /// assert_eq!(small.convert_to_checked(&SsaType::I8, false, PointerSize::Bit64), Some(ConstValue::I8(42)));
    /// ```
    #[must_use]
    pub fn convert_to_checked(
        &self,
        target: &SsaType,
        unsigned_source: bool,
        ptr_size: PointerSize,
    ) -> Option<Self> {
        // Get both signed and unsigned interpretations
        let (signed_val, unsigned_val) = if unsigned_source {
            let u = self.as_u64()?;
            (i64::from_ne_bytes(u.to_ne_bytes()), u)
        } else {
            let s = self.as_i64()?;
            (s, u64::from_ne_bytes(s.to_ne_bytes()))
        };

        // Check if value fits in target type using try_into for range checking
        let fits = match target {
            SsaType::I8 => i8::try_from(signed_val).is_ok(),
            SsaType::U8 => u8::try_from(unsigned_val).is_ok() && signed_val >= 0,
            SsaType::I16 => i16::try_from(signed_val).is_ok(),
            SsaType::U16 => u16::try_from(unsigned_val).is_ok() && signed_val >= 0,
            SsaType::I32 => i32::try_from(signed_val).is_ok(),
            SsaType::U32 => u32::try_from(unsigned_val).is_ok() && signed_val >= 0,
            SsaType::I64
            | SsaType::NativeInt
            | SsaType::Bool
            | SsaType::Char
            | SsaType::F32
            | SsaType::F64 => true,
            SsaType::U64 | SsaType::NativeUInt => signed_val >= 0,
            _ => return None,
        };

        if !fits {
            return None; // Would overflow
        }

        // Perform the conversion (same as convert_to)
        self.convert_to(target, unsigned_source, ptr_size)
    }

    /// Masks a `ConstValue` to the target pointer width.
    ///
    /// For `NativeInt`, sign-extends from 32-bit on `Bit32`.
    /// For `NativeUInt`, zero-extends from 32-bit on `Bit32`.
    /// All other variants are returned unchanged.
    #[must_use]
    pub fn mask_native(self, ptr_size: PointerSize) -> Self {
        match self {
            Self::NativeInt(v) => Self::NativeInt(ptr_size.mask_signed(v)),
            Self::NativeUInt(v) => Self::NativeUInt(ptr_size.mask_unsigned(v)),
            other => other,
        }
    }
}

impl fmt::Display for ConstValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::I8(v) => write!(f, "{v}i8"),
            Self::I16(v) => write!(f, "{v}i16"),
            Self::I32(v) => write!(f, "{v}"),
            Self::I64(v) => write!(f, "{v}L"),
            Self::U8(v) => write!(f, "{v}u8"),
            Self::U16(v) => write!(f, "{v}u16"),
            Self::U32(v) => write!(f, "{v}u"),
            Self::U64(v) => write!(f, "{v}UL"),
            Self::NativeInt(v) => write!(f, "{v}n"),
            Self::NativeUInt(v) => write!(f, "{v}un"),
            Self::F32(v) => write!(f, "{v}f"),
            Self::F64(v) => write!(f, "{v}"),
            Self::String(idx) => write!(f, "str@{idx}"),
            Self::DecryptedString(s) => write!(f, "\"{}\"", s.escape_default()),
            Self::Null => write!(f, "null"),
            Self::True => write!(f, "true"),
            Self::False => write!(f, "false"),
            Self::Type(t) => write!(f, "typeof({t})"),
            Self::MethodHandle(m) => write!(f, "methodof({m})"),
            Self::FieldHandle(fl) => write!(f, "fieldof({fl})"),
        }
    }
}

/// Attempts to convert a `ConstValue` to an `Immediate` for CIL instruction encoding.
///
/// This conversion handles the numeric `ConstValue` variants, mapping them to
/// their corresponding `Immediate` representations. The conversion follows
/// CIL semantics where:
///
/// - Signed integers map directly to their signed `Immediate` variants
/// - Unsigned integers use bit-preserving casts to signed types (since CIL
///   doesn't distinguish unsigned at the instruction level for most operations)
/// - Floating-point values map directly
/// - Boolean values map to `Int32` (1 for true, 0 for false)
/// - Native integers use 64-bit representations
///
/// # Errors
///
/// Returns [`Error::SsaError`] for non-numeric `ConstValue` variants
/// (`String`, `DecryptedString`, `Null`, `Type`, `MethodHandle`, `FieldHandle`)
/// since these cannot be represented as immediate values. Handle these cases
/// with pattern matching before conversion.
///
/// # Example
///
/// ```rust,ignore
/// use dotscope::analysis::ConstValue;
/// use dotscope::assembly::Immediate;
/// use std::convert::TryFrom;
///
/// let const_val = ConstValue::I32(42);
/// let immediate = Immediate::try_from(&const_val)?;
/// assert!(matches!(immediate, Immediate::Int32(42)));
///
/// // Non-numeric values return an error
/// let null_val = ConstValue::Null;
/// assert!(Immediate::try_from(&null_val).is_err());
/// ```
impl TryFrom<&ConstValue> for Immediate {
    type Error = Error;

    #[allow(clippy::cast_possible_wrap)] // Intentional bit-preserving casts for CIL semantics
    fn try_from(value: &ConstValue) -> Result<Self, Self::Error> {
        match value {
            // Signed integers - direct mapping
            ConstValue::I8(v) => Ok(Immediate::Int8(*v)),
            ConstValue::I16(v) => Ok(Immediate::Int16(*v)),
            ConstValue::I32(v) => Ok(Immediate::Int32(*v)),

            // Unsigned integers - use signed Immediate variants with bit-preserving casts.
            // CIL instructions don't distinguish signed/unsigned for most operations;
            // the bit pattern is what matters.
            ConstValue::U8(v) => Ok(Immediate::Int8(*v as i8)),
            ConstValue::U16(v) => Ok(Immediate::Int16(*v as i16)),
            ConstValue::U32(v) => Ok(Immediate::Int32(*v as i32)),

            // 64-bit integers and native integers use Int64 representation
            // (NativeInt is semantically different but has identical representation)
            ConstValue::I64(v) | ConstValue::NativeInt(v) => Ok(Immediate::Int64(*v)),
            ConstValue::U64(v) | ConstValue::NativeUInt(v) => Ok(Immediate::Int64(*v as i64)),

            // Floating point - direct mapping
            ConstValue::F32(v) => Ok(Immediate::Float32(*v)),
            ConstValue::F64(v) => Ok(Immediate::Float64(*v)),

            // Boolean values - map to Int32 (CIL uses int32 for booleans on stack)
            ConstValue::True => Ok(Immediate::Int32(1)),
            ConstValue::False => Ok(Immediate::Int32(0)),

            // Non-numeric types cannot be converted to immediates
            ConstValue::String(_)
            | ConstValue::DecryptedString(_)
            | ConstValue::Null
            | ConstValue::Type(_)
            | ConstValue::MethodHandle(_)
            | ConstValue::FieldHandle(_) => Err(Error::SsaError(format!(
                "Cannot convert {value:?} to Immediate - use pattern matching to handle this case"
            ))),
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
    use crate::metadata::typesystem::PointerSize;

    #[test]
    fn test_const_arithmetic() {
        let a = ConstValue::I32(10);
        let b = ConstValue::I32(3);

        assert_eq!(a.add(&b, PointerSize::Bit64), Some(ConstValue::I32(13)));
        assert_eq!(a.sub(&b, PointerSize::Bit64), Some(ConstValue::I32(7)));
        assert_eq!(a.mul(&b, PointerSize::Bit64), Some(ConstValue::I32(30)));
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
        let v0 = SsaVarId::new();
        let v1 = SsaVarId::new();

        // add(v1, v0) should normalize to add(v0, v1)
        let cv1 = ComputedValue::binary(ComputedOp::Add, v1, v0).normalized();
        let cv2 = ComputedValue::binary(ComputedOp::Add, v0, v1).normalized();

        assert_eq!(cv1, cv2);

        // sub is not commutative, should not normalize
        let cv3 = ComputedValue::binary(ComputedOp::Sub, v1, v0).normalized();
        let cv4 = ComputedValue::binary(ComputedOp::Sub, v0, v1).normalized();

        assert_ne!(cv3, cv4);
    }

    #[test]
    fn test_is_zero() {
        // All integer zeros
        assert!(ConstValue::I8(0).is_zero());
        assert!(ConstValue::I16(0).is_zero());
        assert!(ConstValue::I32(0).is_zero());
        assert!(ConstValue::I64(0).is_zero());
        assert!(ConstValue::U8(0).is_zero());
        assert!(ConstValue::U16(0).is_zero());
        assert!(ConstValue::U32(0).is_zero());
        assert!(ConstValue::U64(0).is_zero());
        assert!(ConstValue::NativeInt(0).is_zero());
        assert!(ConstValue::NativeUInt(0).is_zero());
        assert!(ConstValue::False.is_zero());

        // Non-zeros
        assert!(!ConstValue::I32(1).is_zero());
        assert!(!ConstValue::I32(-1).is_zero());
        assert!(!ConstValue::True.is_zero());
        assert!(!ConstValue::Null.is_zero()); // Null is not zero
    }

    #[test]
    fn test_is_one() {
        // All integer ones
        assert!(ConstValue::I8(1).is_one());
        assert!(ConstValue::I16(1).is_one());
        assert!(ConstValue::I32(1).is_one());
        assert!(ConstValue::I64(1).is_one());
        assert!(ConstValue::U8(1).is_one());
        assert!(ConstValue::U16(1).is_one());
        assert!(ConstValue::U32(1).is_one());
        assert!(ConstValue::U64(1).is_one());
        assert!(ConstValue::NativeInt(1).is_one());
        assert!(ConstValue::NativeUInt(1).is_one());
        assert!(ConstValue::True.is_one());

        // Non-ones
        assert!(!ConstValue::I32(0).is_one());
        assert!(!ConstValue::I32(2).is_one());
        assert!(!ConstValue::False.is_one());
    }

    #[test]
    fn test_is_minus_one() {
        // Signed -1 values
        assert!(ConstValue::I8(-1).is_minus_one());
        assert!(ConstValue::I16(-1).is_minus_one());
        assert!(ConstValue::I32(-1).is_minus_one());
        assert!(ConstValue::I64(-1).is_minus_one());
        assert!(ConstValue::NativeInt(-1).is_minus_one());

        // Not -1
        assert!(!ConstValue::I32(0).is_minus_one());
        assert!(!ConstValue::I32(1).is_minus_one());
        // Unsigned types cannot represent -1
        assert!(!ConstValue::U32(u32::MAX).is_minus_one());
    }

    #[test]
    fn test_convert_to_widening() {
        // i32 -> i64 (sign extends)
        let v = ConstValue::I32(42);
        assert_eq!(
            v.convert_to(&SsaType::I64, false, PointerSize::Bit64),
            Some(ConstValue::I64(42))
        );

        // i32 -> i64 with negative
        let v = ConstValue::I32(-42);
        assert_eq!(
            v.convert_to(&SsaType::I64, false, PointerSize::Bit64),
            Some(ConstValue::I64(-42))
        );

        // u32 -> u64 (zero extends)
        let v = ConstValue::U32(42);
        assert_eq!(
            v.convert_to(&SsaType::U64, false, PointerSize::Bit64),
            Some(ConstValue::U64(42))
        );
    }

    #[test]
    fn test_convert_to_narrowing() {
        // i32 -> i8 (truncates)
        let v = ConstValue::I32(42);
        assert_eq!(
            v.convert_to(&SsaType::I8, false, PointerSize::Bit64),
            Some(ConstValue::I8(42))
        );

        // i32 -> i8 truncation with overflow
        let v = ConstValue::I32(1000);
        // 1000 = 0x3E8, truncated to i8 = 0xE8 = -24 (signed)
        assert_eq!(
            v.convert_to(&SsaType::I8, false, PointerSize::Bit64),
            Some(ConstValue::I8(-24))
        );

        // i64 -> i32 (truncates)
        let v = ConstValue::I64(0x1_0000_0042);
        assert_eq!(
            v.convert_to(&SsaType::I32, false, PointerSize::Bit64),
            Some(ConstValue::I32(0x42))
        );
    }

    #[test]
    fn test_convert_to_float() {
        // i32 -> f32
        let v = ConstValue::I32(42);
        assert_eq!(
            v.convert_to(&SsaType::F32, false, PointerSize::Bit64),
            Some(ConstValue::F32(42.0))
        );

        // i32 -> f64
        let v = ConstValue::I32(42);
        assert_eq!(
            v.convert_to(&SsaType::F64, false, PointerSize::Bit64),
            Some(ConstValue::F64(42.0))
        );

        // Unsigned source to float
        let v = ConstValue::U32(42);
        assert_eq!(
            v.convert_to(&SsaType::F32, true, PointerSize::Bit64),
            Some(ConstValue::F32(42.0))
        );
    }

    #[test]
    fn test_convert_to_bool() {
        // Non-zero -> true
        let v = ConstValue::I32(42);
        assert_eq!(
            v.convert_to(&SsaType::Bool, false, PointerSize::Bit64),
            Some(ConstValue::True)
        );

        // Zero -> false
        let v = ConstValue::I32(0);
        assert_eq!(
            v.convert_to(&SsaType::Bool, false, PointerSize::Bit64),
            Some(ConstValue::False)
        );
    }

    #[test]
    fn test_convert_to_checked_in_range() {
        // Value fits in target
        let v = ConstValue::I32(100);
        assert_eq!(
            v.convert_to_checked(&SsaType::I8, false, PointerSize::Bit64),
            Some(ConstValue::I8(100))
        );

        // Value at boundary
        let v = ConstValue::I32(127);
        assert_eq!(
            v.convert_to_checked(&SsaType::I8, false, PointerSize::Bit64),
            Some(ConstValue::I8(127))
        );

        let v = ConstValue::I32(-128);
        assert_eq!(
            v.convert_to_checked(&SsaType::I8, false, PointerSize::Bit64),
            Some(ConstValue::I8(-128))
        );
    }

    #[test]
    fn test_convert_to_checked_overflow() {
        // Value overflows target
        let v = ConstValue::I32(1000);
        assert_eq!(
            v.convert_to_checked(&SsaType::I8, false, PointerSize::Bit64),
            None
        );

        // Negative to unsigned
        let v = ConstValue::I32(-1);
        assert_eq!(
            v.convert_to_checked(&SsaType::U8, false, PointerSize::Bit64),
            None
        );
        assert_eq!(
            v.convert_to_checked(&SsaType::U32, false, PointerSize::Bit64),
            None
        );
        assert_eq!(
            v.convert_to_checked(&SsaType::U64, false, PointerSize::Bit64),
            None
        );
    }

    #[test]
    fn test_convert_to_char() {
        // i32 -> char (u16)
        let v = ConstValue::I32(65); // 'A'
        assert_eq!(
            v.convert_to(&SsaType::Char, false, PointerSize::Bit64),
            Some(ConstValue::U16(65))
        );
    }

    #[test]
    fn test_convert_to_native() {
        // i32 -> NativeInt
        let v = ConstValue::I32(42);
        assert_eq!(
            v.convert_to(&SsaType::NativeInt, false, PointerSize::Bit64),
            Some(ConstValue::NativeInt(42))
        );

        // i32 -> NativeUInt
        let v = ConstValue::I32(42);
        assert_eq!(
            v.convert_to(&SsaType::NativeUInt, false, PointerSize::Bit64),
            Some(ConstValue::NativeUInt(42))
        );
    }

    #[test]
    fn test_const_div() {
        let a = ConstValue::I32(100);
        let b = ConstValue::I32(7);
        assert_eq!(a.div(&b, PointerSize::Bit64), Some(ConstValue::I32(14)));

        // Unsigned division (uses U32 type)
        let a = ConstValue::U32(100);
        let b = ConstValue::U32(7);
        assert_eq!(a.div(&b, PointerSize::Bit64), Some(ConstValue::U32(14)));

        // i64 division
        let a = ConstValue::I64(1000);
        let b = ConstValue::I64(33);
        assert_eq!(a.div(&b, PointerSize::Bit64), Some(ConstValue::I64(30)));
    }

    #[test]
    fn test_const_div_by_zero() {
        let a = ConstValue::I32(100);
        let zero = ConstValue::I32(0);
        assert_eq!(a.div(&zero, PointerSize::Bit64), None);

        let a = ConstValue::U64(100);
        let zero = ConstValue::U64(0);
        assert_eq!(a.div(&zero, PointerSize::Bit64), None);
    }

    #[test]
    fn test_const_div_negative() {
        let a = ConstValue::I32(-100);
        let b = ConstValue::I32(7);
        assert_eq!(a.div(&b, PointerSize::Bit64), Some(ConstValue::I32(-14))); // -100 / 7 = -14
    }

    #[test]
    fn test_const_rem() {
        let a = ConstValue::I32(100);
        let b = ConstValue::I32(7);
        assert_eq!(a.rem(&b, PointerSize::Bit64), Some(ConstValue::I32(2))); // 100 % 7 = 2

        // Unsigned remainder
        let a = ConstValue::U32(100);
        let b = ConstValue::U32(7);
        assert_eq!(a.rem(&b, PointerSize::Bit64), Some(ConstValue::U32(2)));
    }

    #[test]
    fn test_const_rem_by_zero() {
        let a = ConstValue::I32(100);
        let zero = ConstValue::I32(0);
        assert_eq!(a.rem(&zero, PointerSize::Bit64), None);
    }

    #[test]
    fn test_const_rem_negative() {
        let a = ConstValue::I32(-100);
        let b = ConstValue::I32(7);
        assert_eq!(a.rem(&b, PointerSize::Bit64), Some(ConstValue::I32(-2)));
        // -100 % 7 = -2
    }

    #[test]
    fn test_const_shl() {
        let a = ConstValue::I32(1);
        let shift = ConstValue::I32(4);
        assert_eq!(a.shl(&shift, PointerSize::Bit64), Some(ConstValue::I32(16))); // 1 << 4 = 16

        // Larger shift
        let a = ConstValue::I32(1);
        let shift = ConstValue::I32(31);
        assert_eq!(
            a.shl(&shift, PointerSize::Bit64),
            Some(ConstValue::I32(i32::MIN))
        ); // 1 << 31 = MIN_VALUE
    }

    #[test]
    fn test_const_shr_signed() {
        let a = ConstValue::I32(-16);
        let shift = ConstValue::I32(2);
        assert_eq!(
            a.shr(&shift, false, PointerSize::Bit64),
            Some(ConstValue::I32(-4))
        ); // Sign preserved

        let b = ConstValue::I32(16);
        let shift = ConstValue::I32(2);
        assert_eq!(
            b.shr(&shift, false, PointerSize::Bit64),
            Some(ConstValue::I32(4))
        );
    }

    #[test]
    fn test_const_shr_unsigned() {
        let a = ConstValue::I32(-1); // All 1s in two's complement
        let shift = ConstValue::I32(1);
        // Unsigned right shift fills with 0
        let result = a.shr(&shift, true, PointerSize::Bit64);
        assert!(result.is_some());
        // -1 >> 1 (unsigned) = 0x7FFFFFFF
        if let Some(ConstValue::I32(v)) = result {
            assert_eq!(v, 0x7FFFFFFF);
        }
    }

    #[test]
    fn test_const_shr_i64() {
        let a = ConstValue::I64(256);
        let shift = ConstValue::I32(4);
        assert_eq!(
            a.shr(&shift, false, PointerSize::Bit64),
            Some(ConstValue::I64(16))
        );
    }

    #[test]
    fn test_const_cgt() {
        let a = ConstValue::I32(10);
        let b = ConstValue::I32(5);
        assert_eq!(a.cgt(&b), Some(ConstValue::True));
        assert_eq!(b.cgt(&a), Some(ConstValue::False));
        assert_eq!(a.cgt(&a), Some(ConstValue::False)); // Equal means not greater
    }

    #[test]
    fn test_const_cgt_i64() {
        let a = ConstValue::I64(1000);
        let b = ConstValue::I64(500);
        assert_eq!(a.cgt(&b), Some(ConstValue::True));
    }

    #[test]
    fn test_const_clt_negative() {
        let a = ConstValue::I32(-10);
        let b = ConstValue::I32(5);
        assert_eq!(a.clt(&b), Some(ConstValue::True)); // -10 < 5
    }

    #[test]
    fn test_const_float_arithmetic() {
        let a = ConstValue::F32(10.5);
        let b = ConstValue::F32(2.5);
        assert_eq!(a.add(&b, PointerSize::Bit64), Some(ConstValue::F32(13.0)));
        assert_eq!(a.sub(&b, PointerSize::Bit64), Some(ConstValue::F32(8.0)));
        assert_eq!(a.mul(&b, PointerSize::Bit64), Some(ConstValue::F32(26.25)));

        let a = ConstValue::F64(100.0);
        let b = ConstValue::F64(4.0);
        assert_eq!(a.div(&b, PointerSize::Bit64), Some(ConstValue::F64(25.0)));
    }

    #[test]
    fn test_const_float_comparison() {
        let a = ConstValue::F64(std::f64::consts::PI);
        let b = ConstValue::F64(std::f64::consts::E);
        assert_eq!(a.cgt(&b), Some(ConstValue::True));
        assert_eq!(a.clt(&b), Some(ConstValue::False));
        assert_eq!(a.ceq(&a), Some(ConstValue::True));
    }

    #[test]
    fn test_const_float_div_by_zero() {
        let a = ConstValue::F64(1.0);
        let b = ConstValue::F64(0.0);
        // Float div by zero returns inf, not None
        let result = a.div(&b, PointerSize::Bit64);
        assert!(result.is_some());
        if let Some(ConstValue::F64(v)) = result {
            assert!(v.is_infinite());
        }
    }

    #[test]
    fn test_is_zero_integer_types() {
        // Test is_zero for integer types (does not include floats)
        assert!(ConstValue::I8(0).is_zero());
        assert!(ConstValue::I16(0).is_zero());
        assert!(ConstValue::I32(0).is_zero());
        assert!(ConstValue::I64(0).is_zero());
        assert!(ConstValue::U8(0).is_zero());
        assert!(ConstValue::U16(0).is_zero());
        assert!(ConstValue::U32(0).is_zero());
        assert!(ConstValue::U64(0).is_zero());
        assert!(ConstValue::NativeInt(0).is_zero());
        assert!(ConstValue::NativeUInt(0).is_zero());
        assert!(ConstValue::False.is_zero());

        // Non-zero values
        assert!(!ConstValue::I32(1).is_zero());
        assert!(!ConstValue::True.is_zero());
    }

    #[test]
    fn test_is_one_integer_types() {
        // Test is_one for integer types (does not include floats)
        assert!(ConstValue::I8(1).is_one());
        assert!(ConstValue::I16(1).is_one());
        assert!(ConstValue::I32(1).is_one());
        assert!(ConstValue::I64(1).is_one());
        assert!(ConstValue::U8(1).is_one());
        assert!(ConstValue::U16(1).is_one());
        assert!(ConstValue::U32(1).is_one());
        assert!(ConstValue::U64(1).is_one());
        assert!(ConstValue::NativeInt(1).is_one());
        assert!(ConstValue::NativeUInt(1).is_one());
        assert!(ConstValue::True.is_one());

        // Non-one values
        assert!(!ConstValue::I32(0).is_one());
        assert!(!ConstValue::False.is_one());
    }

    #[test]
    fn test_is_minus_one_signed_types() {
        // Test is_minus_one for signed integer types only
        assert!(ConstValue::I8(-1).is_minus_one());
        assert!(ConstValue::I16(-1).is_minus_one());
        assert!(ConstValue::I32(-1).is_minus_one());
        assert!(ConstValue::I64(-1).is_minus_one());
        assert!(ConstValue::NativeInt(-1).is_minus_one());

        // Unsigned types cannot be -1
        assert!(!ConstValue::U8(255).is_minus_one());
        assert!(!ConstValue::U32(0xFFFFFFFF).is_minus_one());
    }

    #[test]
    fn test_zero_of_same_type_preserves_type() {
        // Integer types
        assert_eq!(ConstValue::I8(42).zero_of_same_type(), ConstValue::I8(0));
        assert_eq!(ConstValue::I16(42).zero_of_same_type(), ConstValue::I16(0));
        assert_eq!(ConstValue::I32(42).zero_of_same_type(), ConstValue::I32(0));
        assert_eq!(ConstValue::I64(42).zero_of_same_type(), ConstValue::I64(0));
        assert_eq!(ConstValue::U8(42).zero_of_same_type(), ConstValue::U8(0));
        assert_eq!(ConstValue::U16(42).zero_of_same_type(), ConstValue::U16(0));
        assert_eq!(ConstValue::U32(42).zero_of_same_type(), ConstValue::U32(0));
        assert_eq!(ConstValue::U64(42).zero_of_same_type(), ConstValue::U64(0));
        assert_eq!(
            ConstValue::NativeInt(42).zero_of_same_type(),
            ConstValue::NativeInt(0)
        );
        assert_eq!(
            ConstValue::NativeUInt(42).zero_of_same_type(),
            ConstValue::NativeUInt(0)
        );

        // Floating point types
        assert_eq!(
            ConstValue::F32(std::f32::consts::PI).zero_of_same_type(),
            ConstValue::F32(0.0)
        );
        assert_eq!(
            ConstValue::F64(std::f64::consts::PI).zero_of_same_type(),
            ConstValue::F64(0.0)
        );

        // Non-numeric types default to I32
        assert_eq!(ConstValue::Null.zero_of_same_type(), ConstValue::I32(0));
        assert_eq!(ConstValue::True.zero_of_same_type(), ConstValue::I32(0));
    }

    #[test]
    fn test_abstract_value_join() {
        let top = AbstractValue::Top;
        let bottom = AbstractValue::Bottom;
        let const_a = AbstractValue::Constant(ConstValue::I32(42));
        let const_b = AbstractValue::Constant(ConstValue::I32(42));
        let const_c = AbstractValue::Constant(ConstValue::I32(99));

        // Top joins with anything gives Top
        assert_eq!(top.join(&const_a), AbstractValue::Top);
        assert_eq!(const_a.join(&top), AbstractValue::Top);

        // Bottom joins with anything gives that thing
        assert_eq!(bottom.join(&const_a), const_a);
        assert_eq!(const_a.join(&bottom), const_a);

        // Same constants join to same constant
        assert_eq!(const_a.join(&const_b), const_a);

        // Different constants join to Top
        assert_eq!(const_a.join(&const_c), AbstractValue::Top);
    }

    #[test]
    fn test_abstract_value_is_constant() {
        let top = AbstractValue::Top;
        let bottom = AbstractValue::Bottom;
        let const_val = AbstractValue::Constant(ConstValue::I32(42));

        assert!(!top.is_constant());
        assert!(!bottom.is_constant());
        assert!(const_val.is_constant());
    }

    #[test]
    fn test_abstract_value_as_constant() {
        let const_val = AbstractValue::Constant(ConstValue::I32(42));
        assert_eq!(const_val.as_constant(), Some(&ConstValue::I32(42)));

        let top = AbstractValue::Top;
        assert_eq!(top.as_constant(), None);
    }

    #[test]
    fn test_as_i64() {
        // Signed types
        assert_eq!(ConstValue::I8(-100).as_i64(), Some(-100));
        assert_eq!(ConstValue::I16(-30000).as_i64(), Some(-30000));
        assert_eq!(
            ConstValue::I32(-2_000_000_000).as_i64(),
            Some(-2_000_000_000)
        );
        assert_eq!(
            ConstValue::I64(-9_000_000_000_000).as_i64(),
            Some(-9_000_000_000_000)
        );
        assert_eq!(ConstValue::NativeInt(42).as_i64(), Some(42));

        // Unsigned types up to U32 are included
        assert_eq!(ConstValue::U8(200).as_i64(), Some(200));
        assert_eq!(ConstValue::U16(60000).as_i64(), Some(60000));
        assert_eq!(ConstValue::U32(4_000_000_000).as_i64(), Some(4_000_000_000));

        // U64 is not included in as_i64
        assert_eq!(ConstValue::U64(1_000_000).as_i64(), None);

        // Bool values
        assert_eq!(ConstValue::True.as_i64(), Some(1));
        assert_eq!(ConstValue::False.as_i64(), Some(0));
    }

    #[test]
    fn test_as_u64() {
        assert_eq!(ConstValue::U8(200).as_u64(), Some(200));
        assert_eq!(ConstValue::U16(60000).as_u64(), Some(60000));
        assert_eq!(ConstValue::U32(4_000_000_000).as_u64(), Some(4_000_000_000));
        assert_eq!(ConstValue::U64(u64::MAX).as_u64(), Some(u64::MAX));
        // Positive signed values convert fine
        assert_eq!(ConstValue::I32(100).as_u64(), Some(100));
        // Negative signed values don't convert
        assert_eq!(ConstValue::I32(-1).as_u64(), None);
    }

    #[test]
    fn test_cross_type_arithmetic() {
        // I32 + I64 promotes to I64
        let i32_val = ConstValue::I32(10);
        let i64_val = ConstValue::I64(20);
        assert_eq!(
            i32_val.add(&i64_val, PointerSize::Bit64),
            Some(ConstValue::I64(30))
        );

        // U32 + U64 promotes to U64
        let u32_val = ConstValue::U32(100);
        let u64_val = ConstValue::U64(200);
        assert_eq!(
            u32_val.add(&u64_val, PointerSize::Bit64),
            Some(ConstValue::U64(300))
        );
    }

    #[test]
    fn test_incompatible_type_arithmetic() {
        // I32 + F32 returns None (incompatible)
        let i32_val = ConstValue::I32(10);
        let f32_val = ConstValue::F32(std::f32::consts::PI);
        assert!(i32_val.add(&f32_val, PointerSize::Bit64).is_none());

        // U64 + I64 returns None (signed vs unsigned)
        let u64_val = ConstValue::U64(100);
        let i64_val = ConstValue::I64(200);
        assert!(u64_val.add(&i64_val, PointerSize::Bit64).is_none());
    }

    #[test]
    fn test_null_const_value() {
        let null = ConstValue::Null;
        assert!(null.is_null());
        assert!(!null.is_one());
        assert!(!null.is_bool());
    }

    #[test]
    fn test_string_const_value() {
        let s = ConstValue::String(123);
        assert!(!s.is_zero());
        assert!(!s.is_one());
    }

    #[test]
    fn test_bool_const_values() {
        let t = ConstValue::True;
        let f = ConstValue::False;

        assert!(t.is_bool());
        assert!(f.is_bool());
        assert!(t.is_one());
        assert!(f.is_zero());
    }
}
