//! Operations for CIL emulation values.
//!
//! This module defines the operation types used during CIL bytecode emulation:
//!
//! - [`BinaryOp`] - Binary arithmetic and bitwise operations (`add`, `sub`, `mul`, `div`, etc.)
//! - [`UnaryOp`] - Unary operations (`neg`, `not`)
//! - [`CompareOp`] - Comparison operations (`ceq`, `clt`, `cgt`, etc.)
//! - [`ConversionType`] - Type conversion operations (`conv.i4`, `conv.r8`, etc.)
//!
//! # CIL Operation Semantics
//!
//! The operations follow ECMA-335 semantics for the CIL instruction set.
//! Operations are performed on stack types (I32, I64, F32, F64, NativeInt)
//! with appropriate widening and overflow behavior.
//!
//! # Operation Categories
//!
//! ## Arithmetic Operations
//!
//! Basic arithmetic (`Add`, `Sub`, `Mul`, `Div`, `Rem`) operates on numeric types
//! and wraps on overflow by default. Checked variants (`AddOvf`, `MulOvf`, etc.)
//! return errors on overflow.
//!
//! ## Bitwise Operations
//!
//! Bitwise operations (`And`, `Or`, `Xor`, `Shl`, `Shr`) are only valid for
//! integer types. Shift amounts are masked to the type width.
//!
//! ## Comparison Operations
//!
//! Comparisons return an I32 value (1 for true, 0 for false). Unsigned variants
//! (`GtUn`, `LtUn`) treat operands as unsigned integers.
//!
//! ## Conversions
//!
//! Conversions handle type changes between numeric types. Unchecked conversions
//! truncate silently, while checked variants (`I4Ovf`, `U1OvfUn`) return errors
//! when the value cannot be represented.
//!
//! # Examples
//!
//! ```rust
//! use dotscope::emulation::{EmValue, BinaryOp, CompareOp, ConversionType};
//! use dotscope::metadata::typesystem::PointerSize;
//!
//! // Arithmetic operations
//! let a = EmValue::I32(10);
//! let b = EmValue::I32(3);
//! let sum = a.binary_op(&b, BinaryOp::Add, PointerSize::Bit64).unwrap();
//! assert_eq!(sum, EmValue::I32(13));
//!
//! // Comparisons
//! let cmp = a.compare(&b, CompareOp::Gt).unwrap();
//! assert_eq!(cmp, EmValue::I32(1)); // 10 > 3
//!
//! // Conversions
//! let converted = EmValue::I32(42).convert(ConversionType::I8, PointerSize::Bit64).unwrap();
//! assert_eq!(converted, EmValue::I64(42));
//! ```

// CIL emulation requires intentional numeric casts to implement ECMA-335 type conversion
// semantics. These casts handle signed/unsigned reinterpretation, truncation, and widening
// as specified by the CIL instruction set.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss,
    clippy::cast_lossless
)]

use std::fmt;

use crate::{
    emulation::{
        engine::EmulationError,
        value::{EmValue, SymbolicValue, TaintSource},
    },
    metadata::typesystem::{CilFlavor, PointerSize},
    Result,
};

/// Binary operations for CIL arithmetic and bitwise instructions.
///
/// These operations correspond to CIL instructions like `add`, `sub`, `mul`,
/// `div`, `rem`, `and`, `or`, `xor`, `shl`, `shr`.
///
/// # Overflow Behavior
///
/// By default, arithmetic operations wrap on overflow (following Rust's
/// wrapping semantics). For checked operations, use [`BinaryOp::is_checked`]
/// variants and handle `EmulationError::Overflow`.
///
/// # Type Combinations
///
/// Not all type combinations are valid for all operations. For example,
/// bitwise operations are only valid on integer types. The `EmValue::binary_op`
/// method returns an error for invalid combinations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BinaryOp {
    /// Addition (`add`).
    ///
    /// Valid for: I32, I64, NativeInt, F32, F64
    Add,

    /// Addition with overflow check (`add.ovf`, `add.ovf.un`).
    ///
    /// Returns error on overflow.
    AddOvf,

    /// Unsigned addition with overflow check.
    AddOvfUn,

    /// Subtraction (`sub`).
    ///
    /// Valid for: I32, I64, NativeInt, F32, F64
    Sub,

    /// Subtraction with overflow check (`sub.ovf`, `sub.ovf.un`).
    SubOvf,

    /// Unsigned subtraction with overflow check.
    SubOvfUn,

    /// Multiplication (`mul`).
    ///
    /// Valid for: I32, I64, NativeInt, F32, F64
    Mul,

    /// Multiplication with overflow check (`mul.ovf`, `mul.ovf.un`).
    MulOvf,

    /// Unsigned multiplication with overflow check.
    MulOvfUn,

    /// Signed division (`div`).
    ///
    /// Valid for: I32, I64, NativeInt, F32, F64
    /// Returns error for division by zero.
    Div,

    /// Unsigned division (`div.un`).
    ///
    /// Valid for: I32, I64, NativeInt
    DivUn,

    /// Signed remainder (`rem`).
    ///
    /// Valid for: I32, I64, NativeInt, F32, F64
    Rem,

    /// Unsigned remainder (`rem.un`).
    ///
    /// Valid for: I32, I64, NativeInt
    RemUn,

    /// Bitwise AND (`and`).
    ///
    /// Valid for: I32, I64, NativeInt
    And,

    /// Bitwise OR (`or`).
    ///
    /// Valid for: I32, I64, NativeInt
    Or,

    /// Bitwise XOR (`xor`).
    ///
    /// Valid for: I32, I64, NativeInt
    Xor,

    /// Shift left (`shl`).
    ///
    /// The right operand is the shift amount (masked to type width).
    Shl,

    /// Shift right (`shr`).
    ///
    /// Arithmetic (signed) shift right - preserves sign bit.
    Shr,

    /// Unsigned shift right (`shr.un`).
    ///
    /// Logical shift right - fills with zeros.
    ShrUn,
}

impl BinaryOp {
    /// Returns `true` if this is a checked (overflow-detecting) operation.
    #[must_use]
    pub fn is_checked(&self) -> bool {
        matches!(
            self,
            BinaryOp::AddOvf
                | BinaryOp::AddOvfUn
                | BinaryOp::SubOvf
                | BinaryOp::SubOvfUn
                | BinaryOp::MulOvf
                | BinaryOp::MulOvfUn
        )
    }

    /// Returns `true` if this operation treats operands as unsigned.
    #[must_use]
    pub fn is_unsigned(&self) -> bool {
        matches!(
            self,
            BinaryOp::AddOvfUn
                | BinaryOp::SubOvfUn
                | BinaryOp::MulOvfUn
                | BinaryOp::DivUn
                | BinaryOp::RemUn
                | BinaryOp::ShrUn
        )
    }

    /// Returns `true` if this is an arithmetic operation.
    #[must_use]
    pub fn is_arithmetic(&self) -> bool {
        matches!(
            self,
            BinaryOp::Add
                | BinaryOp::AddOvf
                | BinaryOp::AddOvfUn
                | BinaryOp::Sub
                | BinaryOp::SubOvf
                | BinaryOp::SubOvfUn
                | BinaryOp::Mul
                | BinaryOp::MulOvf
                | BinaryOp::MulOvfUn
                | BinaryOp::Div
                | BinaryOp::DivUn
                | BinaryOp::Rem
                | BinaryOp::RemUn
        )
    }

    /// Returns `true` if this is a bitwise operation.
    #[must_use]
    pub fn is_bitwise(&self) -> bool {
        matches!(
            self,
            BinaryOp::And
                | BinaryOp::Or
                | BinaryOp::Xor
                | BinaryOp::Shl
                | BinaryOp::Shr
                | BinaryOp::ShrUn
        )
    }
}

impl fmt::Display for BinaryOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BinaryOp::Add => write!(f, "add"),
            BinaryOp::AddOvf => write!(f, "add.ovf"),
            BinaryOp::AddOvfUn => write!(f, "add.ovf.un"),
            BinaryOp::Sub => write!(f, "sub"),
            BinaryOp::SubOvf => write!(f, "sub.ovf"),
            BinaryOp::SubOvfUn => write!(f, "sub.ovf.un"),
            BinaryOp::Mul => write!(f, "mul"),
            BinaryOp::MulOvf => write!(f, "mul.ovf"),
            BinaryOp::MulOvfUn => write!(f, "mul.ovf.un"),
            BinaryOp::Div => write!(f, "div"),
            BinaryOp::DivUn => write!(f, "div.un"),
            BinaryOp::Rem => write!(f, "rem"),
            BinaryOp::RemUn => write!(f, "rem.un"),
            BinaryOp::And => write!(f, "and"),
            BinaryOp::Or => write!(f, "or"),
            BinaryOp::Xor => write!(f, "xor"),
            BinaryOp::Shl => write!(f, "shl"),
            BinaryOp::Shr => write!(f, "shr"),
            BinaryOp::ShrUn => write!(f, "shr.un"),
        }
    }
}

/// Unary operations for CIL instructions.
///
/// These operations correspond to CIL instructions like `neg` and `not`.
///
/// # Examples
///
/// ```rust
/// use dotscope::emulation::{EmValue, UnaryOp};
/// use dotscope::metadata::typesystem::PointerSize;
///
/// let value = EmValue::I32(42);
/// let negated = value.unary_op(UnaryOp::Neg, PointerSize::Bit64).unwrap();
/// assert_eq!(negated, EmValue::I32(-42));
///
/// let bits = EmValue::I32(0x0F);
/// let inverted = bits.unary_op(UnaryOp::Not, PointerSize::Bit64).unwrap();
/// assert_eq!(inverted, EmValue::I32(!0x0F));
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum UnaryOp {
    /// Negation (`neg`).
    ///
    /// Returns the two's complement negation for integers,
    /// or IEEE 754 negation for floats.
    Neg,

    /// Bitwise NOT (`not`).
    ///
    /// Returns the one's complement (all bits flipped).
    /// Only valid for integer types.
    Not,
}

impl fmt::Display for UnaryOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UnaryOp::Neg => write!(f, "neg"),
            UnaryOp::Not => write!(f, "not"),
        }
    }
}

/// Comparison operations for CIL instructions.
///
/// These operations correspond to CIL instructions like `ceq`, `cgt`, `clt`,
/// and the conditional branch instructions.
///
/// # Result Type
///
/// All comparisons produce an I32 result: 1 for true, 0 for false.
///
/// # Signed vs Unsigned
///
/// For integer comparisons, the unsigned variants (`GtUn`, `LtUn`, etc.) treat
/// the operands as unsigned integers. This is important for values like -1,
/// which is the largest unsigned value.
///
/// # Examples
///
/// ```rust
/// use dotscope::emulation::{EmValue, CompareOp};
///
/// let a = EmValue::I32(10);
/// let b = EmValue::I32(20);
///
/// // Signed comparison
/// assert_eq!(a.compare(&b, CompareOp::Lt).unwrap(), EmValue::I32(1));
///
/// // Unsigned comparison of -1 (largest unsigned) vs 1
/// let neg = EmValue::I32(-1);
/// let pos = EmValue::I32(1);
/// assert_eq!(neg.compare(&pos, CompareOp::Lt).unwrap(), EmValue::I32(1));   // signed: -1 < 1
/// assert_eq!(neg.compare(&pos, CompareOp::LtUn).unwrap(), EmValue::I32(0)); // unsigned: 0xFFFFFFFF > 1
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CompareOp {
    /// Equal (`ceq`).
    Eq,

    /// Not equal (for branch instructions).
    Ne,

    /// Greater than, signed (`cgt`).
    Gt,

    /// Greater than, unsigned (`cgt.un`).
    GtUn,

    /// Greater than or equal, signed (for branch instructions).
    Ge,

    /// Greater than or equal, unsigned.
    GeUn,

    /// Less than, signed (`clt`).
    Lt,

    /// Less than, unsigned (`clt.un`).
    LtUn,

    /// Less than or equal, signed (for branch instructions).
    Le,

    /// Less than or equal, unsigned.
    LeUn,
}

impl CompareOp {
    /// Returns `true` if this is an unsigned comparison.
    #[must_use]
    pub fn is_unsigned(&self) -> bool {
        matches!(
            self,
            CompareOp::GtUn | CompareOp::GeUn | CompareOp::LtUn | CompareOp::LeUn
        )
    }

    /// Returns the negated comparison operation.
    #[must_use]
    pub fn negate(&self) -> Self {
        match self {
            CompareOp::Eq => CompareOp::Ne,
            CompareOp::Ne => CompareOp::Eq,
            CompareOp::Gt => CompareOp::Le,
            CompareOp::GtUn => CompareOp::LeUn,
            CompareOp::Ge => CompareOp::Lt,
            CompareOp::GeUn => CompareOp::LtUn,
            CompareOp::Lt => CompareOp::Ge,
            CompareOp::LtUn => CompareOp::GeUn,
            CompareOp::Le => CompareOp::Gt,
            CompareOp::LeUn => CompareOp::GtUn,
        }
    }

    /// Returns the swapped comparison (as if operands were swapped).
    #[must_use]
    pub fn swap(&self) -> Self {
        match self {
            CompareOp::Eq => CompareOp::Eq,
            CompareOp::Ne => CompareOp::Ne,
            CompareOp::Gt => CompareOp::Lt,
            CompareOp::GtUn => CompareOp::LtUn,
            CompareOp::Ge => CompareOp::Le,
            CompareOp::GeUn => CompareOp::LeUn,
            CompareOp::Lt => CompareOp::Gt,
            CompareOp::LtUn => CompareOp::GtUn,
            CompareOp::Le => CompareOp::Ge,
            CompareOp::LeUn => CompareOp::GeUn,
        }
    }
}

impl fmt::Display for CompareOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CompareOp::Eq => write!(f, "ceq"),
            CompareOp::Ne => write!(f, "ne"),
            CompareOp::Gt => write!(f, "cgt"),
            CompareOp::GtUn => write!(f, "cgt.un"),
            CompareOp::Ge => write!(f, "ge"),
            CompareOp::GeUn => write!(f, "ge.un"),
            CompareOp::Lt => write!(f, "clt"),
            CompareOp::LtUn => write!(f, "clt.un"),
            CompareOp::Le => write!(f, "le"),
            CompareOp::LeUn => write!(f, "le.un"),
        }
    }
}

/// Type conversion operations for CIL instructions.
///
/// These correspond to the `conv.*` family of CIL instructions that convert
/// values between numeric types.
///
/// # Conversion Semantics
///
/// - Integer to integer: truncation or sign/zero extension
/// - Float to integer: truncation toward zero
/// - Integer to float: nearest representable value
/// - Float to float: nearest representable value or truncation
///
/// # Overflow Behavior
///
/// Unchecked conversions may lose data without error. Checked conversions
/// (the `*Ovf` variants) return an error if the value cannot be represented
/// in the target type.
///
/// # Examples
///
/// ```rust
/// use dotscope::emulation::{EmValue, ConversionType};
/// use dotscope::metadata::typesystem::PointerSize;
///
/// // Widening conversion (always succeeds)
/// let i32_val = EmValue::I32(42);
/// let i64_val = i32_val.convert(ConversionType::I8, PointerSize::Bit64).unwrap();
/// assert_eq!(i64_val, EmValue::I64(42));
///
/// // Truncating conversion
/// let large = EmValue::I32(300);
/// let truncated = large.convert(ConversionType::I1, PointerSize::Bit64).unwrap();
/// assert_eq!(truncated, EmValue::I32(44)); // 300 & 0xFF = 44, sign-extended
///
/// // Checked conversion that overflows
/// let value = EmValue::I32(200);
/// assert!(value.convert(ConversionType::I1Ovf, PointerSize::Bit64).is_err()); // 200 > 127
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ConversionType {
    /// Convert to int8 (`conv.i1`).
    ///
    /// Truncates to 8 bits, then sign-extends to int32.
    I1,

    /// Convert to int16 (`conv.i2`).
    ///
    /// Truncates to 16 bits, then sign-extends to int32.
    I2,

    /// Convert to int32 (`conv.i4`).
    I4,

    /// Convert to int64 (`conv.i8`).
    I8,

    /// Convert to uint8 (`conv.u1`).
    ///
    /// Truncates to 8 bits, then zero-extends to int32.
    U1,

    /// Convert to uint16 (`conv.u2`).
    ///
    /// Truncates to 16 bits, then zero-extends to int32.
    U2,

    /// Convert to uint32 (`conv.u4`).
    U4,

    /// Convert to uint64 (`conv.u8`).
    U8,

    /// Convert to float32 (`conv.r4`).
    R4,

    /// Convert to float64 (`conv.r8`).
    R8,

    /// Convert to native int (`conv.i`).
    I,

    /// Convert to native uint (`conv.u`).
    U,

    /// Convert float to unsigned (`conv.r.un`).
    ///
    /// Converts unsigned integer to float (the source is treated as unsigned).
    RUn,

    // Checked conversions (overflow-checking)
    /// Convert to int8 with overflow check (`conv.ovf.i1`).
    I1Ovf,

    /// Convert to int16 with overflow check (`conv.ovf.i2`).
    I2Ovf,

    /// Convert to int32 with overflow check (`conv.ovf.i4`).
    I4Ovf,

    /// Convert to int64 with overflow check (`conv.ovf.i8`).
    I8Ovf,

    /// Convert to uint8 with overflow check (`conv.ovf.u1`).
    U1Ovf,

    /// Convert to uint16 with overflow check (`conv.ovf.u2`).
    U2Ovf,

    /// Convert to uint32 with overflow check (`conv.ovf.u4`).
    U4Ovf,

    /// Convert to uint64 with overflow check (`conv.ovf.u8`).
    U8Ovf,

    /// Convert to native int with overflow check (`conv.ovf.i`).
    IOvf,

    /// Convert to native uint with overflow check (`conv.ovf.u`).
    UOvf,

    // Unsigned source checked conversions
    /// Convert unsigned to int8 with overflow check (`conv.ovf.i1.un`).
    I1OvfUn,

    /// Convert unsigned to int16 with overflow check (`conv.ovf.i2.un`).
    I2OvfUn,

    /// Convert unsigned to int32 with overflow check (`conv.ovf.i4.un`).
    I4OvfUn,

    /// Convert unsigned to int64 with overflow check (`conv.ovf.i8.un`).
    I8OvfUn,

    /// Convert unsigned to uint8 with overflow check (`conv.ovf.u1.un`).
    U1OvfUn,

    /// Convert unsigned to uint16 with overflow check (`conv.ovf.u2.un`).
    U2OvfUn,

    /// Convert unsigned to uint32 with overflow check (`conv.ovf.u4.un`).
    U4OvfUn,

    /// Convert unsigned to uint64 with overflow check (`conv.ovf.u8.un`).
    U8OvfUn,

    /// Convert unsigned to native int with overflow check (`conv.ovf.i.un`).
    IOvfUn,

    /// Convert unsigned to native uint with overflow check (`conv.ovf.u.un`).
    UOvfUn,
}

impl ConversionType {
    /// Returns `true` if this is a checked (overflow-detecting) conversion.
    #[must_use]
    pub fn is_checked(&self) -> bool {
        matches!(
            self,
            ConversionType::I1Ovf
                | ConversionType::I2Ovf
                | ConversionType::I4Ovf
                | ConversionType::I8Ovf
                | ConversionType::U1Ovf
                | ConversionType::U2Ovf
                | ConversionType::U4Ovf
                | ConversionType::U8Ovf
                | ConversionType::IOvf
                | ConversionType::UOvf
                | ConversionType::I1OvfUn
                | ConversionType::I2OvfUn
                | ConversionType::I4OvfUn
                | ConversionType::I8OvfUn
                | ConversionType::U1OvfUn
                | ConversionType::U2OvfUn
                | ConversionType::U4OvfUn
                | ConversionType::U8OvfUn
                | ConversionType::IOvfUn
                | ConversionType::UOvfUn
        )
    }

    /// Returns `true` if the source should be treated as unsigned.
    #[must_use]
    pub fn is_unsigned_source(&self) -> bool {
        matches!(
            self,
            ConversionType::RUn
                | ConversionType::I1OvfUn
                | ConversionType::I2OvfUn
                | ConversionType::I4OvfUn
                | ConversionType::I8OvfUn
                | ConversionType::U1OvfUn
                | ConversionType::U2OvfUn
                | ConversionType::U4OvfUn
                | ConversionType::U8OvfUn
                | ConversionType::IOvfUn
                | ConversionType::UOvfUn
        )
    }

    /// Returns the target CIL flavor for this conversion.
    #[must_use]
    pub fn target_cil_flavor(&self) -> CilFlavor {
        match self {
            ConversionType::I1
            | ConversionType::I2
            | ConversionType::I4
            | ConversionType::U1
            | ConversionType::U2
            | ConversionType::U4
            | ConversionType::I1Ovf
            | ConversionType::I2Ovf
            | ConversionType::I4Ovf
            | ConversionType::U1Ovf
            | ConversionType::U2Ovf
            | ConversionType::U4Ovf
            | ConversionType::I1OvfUn
            | ConversionType::I2OvfUn
            | ConversionType::I4OvfUn
            | ConversionType::U1OvfUn
            | ConversionType::U2OvfUn
            | ConversionType::U4OvfUn => CilFlavor::I4,

            ConversionType::I8
            | ConversionType::U8
            | ConversionType::I8Ovf
            | ConversionType::U8Ovf
            | ConversionType::I8OvfUn
            | ConversionType::U8OvfUn => CilFlavor::I8,

            ConversionType::R4 => CilFlavor::R4,
            ConversionType::R8 | ConversionType::RUn => CilFlavor::R8,

            ConversionType::I
            | ConversionType::U
            | ConversionType::IOvf
            | ConversionType::UOvf
            | ConversionType::IOvfUn
            | ConversionType::UOvfUn => CilFlavor::I,
        }
    }
}

impl fmt::Display for ConversionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConversionType::I1 => write!(f, "conv.i1"),
            ConversionType::I2 => write!(f, "conv.i2"),
            ConversionType::I4 => write!(f, "conv.i4"),
            ConversionType::I8 => write!(f, "conv.i8"),
            ConversionType::U1 => write!(f, "conv.u1"),
            ConversionType::U2 => write!(f, "conv.u2"),
            ConversionType::U4 => write!(f, "conv.u4"),
            ConversionType::U8 => write!(f, "conv.u8"),
            ConversionType::R4 => write!(f, "conv.r4"),
            ConversionType::R8 => write!(f, "conv.r8"),
            ConversionType::I => write!(f, "conv.i"),
            ConversionType::U => write!(f, "conv.u"),
            ConversionType::RUn => write!(f, "conv.r.un"),
            ConversionType::I1Ovf => write!(f, "conv.ovf.i1"),
            ConversionType::I2Ovf => write!(f, "conv.ovf.i2"),
            ConversionType::I4Ovf => write!(f, "conv.ovf.i4"),
            ConversionType::I8Ovf => write!(f, "conv.ovf.i8"),
            ConversionType::U1Ovf => write!(f, "conv.ovf.u1"),
            ConversionType::U2Ovf => write!(f, "conv.ovf.u2"),
            ConversionType::U4Ovf => write!(f, "conv.ovf.u4"),
            ConversionType::U8Ovf => write!(f, "conv.ovf.u8"),
            ConversionType::IOvf => write!(f, "conv.ovf.i"),
            ConversionType::UOvf => write!(f, "conv.ovf.u"),
            ConversionType::I1OvfUn => write!(f, "conv.ovf.i1.un"),
            ConversionType::I2OvfUn => write!(f, "conv.ovf.i2.un"),
            ConversionType::I4OvfUn => write!(f, "conv.ovf.i4.un"),
            ConversionType::I8OvfUn => write!(f, "conv.ovf.i8.un"),
            ConversionType::U1OvfUn => write!(f, "conv.ovf.u1.un"),
            ConversionType::U2OvfUn => write!(f, "conv.ovf.u2.un"),
            ConversionType::U4OvfUn => write!(f, "conv.ovf.u4.un"),
            ConversionType::U8OvfUn => write!(f, "conv.ovf.u8.un"),
            ConversionType::IOvfUn => write!(f, "conv.ovf.i.un"),
            ConversionType::UOvfUn => write!(f, "conv.ovf.u.un"),
        }
    }
}

impl EmValue {
    /// Performs a binary operation on two values.
    ///
    /// # Arguments
    ///
    /// * `other` - The right-hand operand
    /// * `op` - The binary operation to perform
    ///
    /// # Returns
    ///
    /// The result of the operation, or an error if the operation is invalid
    /// for the operand types or if an overflow/division-by-zero occurs.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::emulation::{EmValue, BinaryOp};
    /// use dotscope::metadata::typesystem::PointerSize;
    ///
    /// let a = EmValue::I32(10);
    /// let b = EmValue::I32(3);
    ///
    /// let sum = a.binary_op(&b, BinaryOp::Add, PointerSize::Bit64).unwrap();
    /// assert_eq!(sum, EmValue::I32(13));
    ///
    /// let product = a.binary_op(&b, BinaryOp::Mul, PointerSize::Bit64).unwrap();
    /// assert_eq!(product, EmValue::I32(30));
    /// ```
    ///
    /// # Errors
    ///
    /// Returns error if operation is invalid for the operand types or on overflow.
    pub fn binary_op(&self, other: &Self, op: BinaryOp, ptr_size: PointerSize) -> Result<Self> {
        if let EmValue::Symbolic(ref sym) = self {
            return Ok(EmValue::Symbolic(SymbolicValue::derived(
                sym.cil_flavor.clone(),
                TaintSource::Computation,
            )));
        }
        if let EmValue::Symbolic(ref sym) = other {
            return Ok(EmValue::Symbolic(SymbolicValue::derived(
                sym.cil_flavor.clone(),
                TaintSource::Computation,
            )));
        }

        let result = match op {
            BinaryOp::Add => self.add(other),
            BinaryOp::AddOvf => self.add_ovf(other, false),
            BinaryOp::AddOvfUn => self.add_ovf(other, true),
            BinaryOp::Sub => self.sub(other),
            BinaryOp::SubOvf => self.sub_ovf(other, false),
            BinaryOp::SubOvfUn => self.sub_ovf(other, true),
            BinaryOp::Mul => self.mul(other),
            BinaryOp::MulOvf => self.mul_ovf(other, false),
            BinaryOp::MulOvfUn => self.mul_ovf(other, true),
            BinaryOp::Div => self.div(other, false),
            BinaryOp::DivUn => self.div(other, true),
            BinaryOp::Rem => self.rem(other, false),
            BinaryOp::RemUn => self.rem(other, true),
            BinaryOp::And => self.bitand(other),
            BinaryOp::Or => self.bitor(other),
            BinaryOp::Xor => self.bitxor(other),
            BinaryOp::Shl => self.shl(other),
            BinaryOp::Shr => self.shr(other, false),
            BinaryOp::ShrUn => self.shr(other, true),
        }?;

        // Mask native int/uint results to the target pointer width
        Ok(match result {
            EmValue::NativeInt(v) => EmValue::NativeInt(ptr_size.mask_signed(v)),
            EmValue::NativeUInt(v) => EmValue::NativeUInt(ptr_size.mask_unsigned(v)),
            other => other,
        })
    }

    /// Performs a unary operation on this value.
    ///
    /// # Arguments
    ///
    /// * `op` - The unary operation to perform
    ///
    /// # Returns
    ///
    /// The result of the operation, or an error if invalid for the type.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::emulation::{EmValue, UnaryOp};
    /// use dotscope::metadata::typesystem::PointerSize;
    ///
    /// let a = EmValue::I32(42);
    /// let neg = a.unary_op(UnaryOp::Neg, PointerSize::Bit64).unwrap();
    /// assert_eq!(neg, EmValue::I32(-42));
    ///
    /// let b = EmValue::I32(0xFF);
    /// let not = b.unary_op(UnaryOp::Not, PointerSize::Bit64).unwrap();
    /// assert_eq!(not, EmValue::I32(!0xFF));
    /// ```
    ///
    /// # Errors
    ///
    /// Returns error if operation is invalid for the operand type.
    pub fn unary_op(&self, op: UnaryOp, ptr_size: PointerSize) -> Result<Self> {
        // Handle symbolic operands
        if let EmValue::Symbolic(ref sym) = self {
            return Ok(EmValue::Symbolic(SymbolicValue::derived(
                sym.cil_flavor.clone(),
                TaintSource::Computation,
            )));
        }

        let result = match op {
            UnaryOp::Neg => self.neg(),
            UnaryOp::Not => self.not(),
        }?;

        // Mask native int/uint results to the target pointer width
        Ok(match result {
            EmValue::NativeInt(v) => EmValue::NativeInt(ptr_size.mask_signed(v)),
            EmValue::NativeUInt(v) => EmValue::NativeUInt(ptr_size.mask_unsigned(v)),
            other => other,
        })
    }

    /// Performs a comparison operation on two values.
    ///
    /// # Arguments
    ///
    /// * `other` - The right-hand operand
    /// * `op` - The comparison operation to perform
    ///
    /// # Returns
    ///
    /// An I32 value: 1 if the comparison is true, 0 if false.
    /// Returns an error for invalid type combinations.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::emulation::{EmValue, CompareOp};
    ///
    /// let a = EmValue::I32(10);
    /// let b = EmValue::I32(20);
    ///
    /// let result = a.compare(&b, CompareOp::Lt).unwrap();
    /// assert_eq!(result, EmValue::I32(1)); // 10 < 20 is true
    /// ```
    ///
    /// # Errors
    ///
    /// Returns error for invalid type combinations.
    pub fn compare(&self, other: &Self, op: CompareOp) -> Result<Self> {
        // Handle symbolic operands - result is symbolic I32
        if matches!(self, EmValue::Symbolic(_)) || matches!(other, EmValue::Symbolic(_)) {
            return Ok(EmValue::Symbolic(SymbolicValue::derived(
                CilFlavor::I4,
                TaintSource::Computation,
            )));
        }

        let result = match op {
            CompareOp::Eq => self.cmp_eq(other)?,
            CompareOp::Ne => !self.cmp_eq(other)?,
            CompareOp::Lt => self.cmp_lt(other, false)?,
            CompareOp::LtUn => self.cmp_lt(other, true)?,
            CompareOp::Le => self.cmp_le(other, false)?,
            CompareOp::LeUn => self.cmp_le(other, true)?,
            CompareOp::Gt => self.cmp_gt(other, false)?,
            CompareOp::GtUn => self.cmp_gt(other, true)?,
            CompareOp::Ge => self.cmp_ge(other, false)?,
            CompareOp::GeUn => self.cmp_ge(other, true)?,
        };

        Ok(EmValue::I32(i32::from(result)))
    }

    /// Converts this value to a different type.
    ///
    /// # Arguments
    ///
    /// * `conv` - The conversion to perform
    ///
    /// # Returns
    ///
    /// The converted value, or an error if the conversion is invalid
    /// or would overflow (for checked conversions).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::emulation::{EmValue, ConversionType};
    /// use dotscope::metadata::typesystem::PointerSize;
    ///
    /// let i32_val = EmValue::I32(42);
    /// let i64_val = i32_val.convert(ConversionType::I8, PointerSize::Bit64).unwrap();
    /// assert_eq!(i64_val, EmValue::I64(42));
    /// ```
    ///
    /// # Errors
    ///
    /// Returns error if conversion is invalid or would overflow (for checked conversions).
    pub fn convert(&self, conv: ConversionType, ptr_size: PointerSize) -> Result<Self> {
        // Handle symbolic values
        if let EmValue::Symbolic(_) = self {
            return Ok(EmValue::Symbolic(SymbolicValue::derived(
                conv.target_cil_flavor(),
                TaintSource::Computation,
            )));
        }

        match conv {
            ConversionType::I1 => self.conv_i1(),
            ConversionType::I2 => self.conv_i2(),
            ConversionType::I4 => self.conv_i4(),
            ConversionType::I8 => self.conv_i8(),
            ConversionType::U1 => self.conv_u1(),
            ConversionType::U2 => self.conv_u2(),
            ConversionType::U4 => self.conv_u4(),
            ConversionType::U8 => self.conv_u8(),
            ConversionType::R4 => self.conv_r4(),
            ConversionType::R8 => self.conv_r8(),
            ConversionType::I => self.conv_i(ptr_size),
            ConversionType::U => self.conv_u(ptr_size),
            ConversionType::RUn => self.conv_r_un(),
            // Checked conversions
            ConversionType::I1Ovf => self.conv_i1_ovf(false),
            ConversionType::I2Ovf => self.conv_i2_ovf(false),
            ConversionType::I4Ovf => self.conv_i4_ovf(false),
            ConversionType::I8Ovf => self.conv_i8_ovf(false),
            ConversionType::U1Ovf => self.conv_u1_ovf(false),
            ConversionType::U2Ovf => self.conv_u2_ovf(false),
            ConversionType::U4Ovf => self.conv_u4_ovf(false),
            ConversionType::U8Ovf => self.conv_u8_ovf(false),
            ConversionType::IOvf => self.conv_i_ovf(false),
            ConversionType::UOvf => self.conv_u_ovf(false),
            // Unsigned source checked conversions
            ConversionType::I1OvfUn => self.conv_i1_ovf(true),
            ConversionType::I2OvfUn => self.conv_i2_ovf(true),
            ConversionType::I4OvfUn => self.conv_i4_ovf(true),
            ConversionType::I8OvfUn => self.conv_i8_ovf(true),
            ConversionType::U1OvfUn => self.conv_u1_ovf(true),
            ConversionType::U2OvfUn => self.conv_u2_ovf(true),
            ConversionType::U4OvfUn => self.conv_u4_ovf(true),
            ConversionType::U8OvfUn => self.conv_u8_ovf(true),
            ConversionType::IOvfUn => self.conv_i_ovf(true),
            ConversionType::UOvfUn => self.conv_u_ovf(true),
        }
    }

    fn add(&self, other: &Self) -> Result<Self> {
        match (self, other) {
            (EmValue::I32(a), EmValue::I32(b)) => Ok(EmValue::I32(a.wrapping_add(*b))),
            (EmValue::I64(a), EmValue::I64(b)) => Ok(EmValue::I64(a.wrapping_add(*b))),
            (EmValue::NativeInt(a), EmValue::NativeInt(b)) => {
                Ok(EmValue::NativeInt(a.wrapping_add(*b)))
            }
            (EmValue::NativeUInt(a), EmValue::NativeUInt(b)) => {
                Ok(EmValue::NativeUInt(a.wrapping_add(*b)))
            }
            (EmValue::F32(a), EmValue::F32(b)) => Ok(EmValue::F32(a + b)),
            (EmValue::F64(a), EmValue::F64(b)) => Ok(EmValue::F64(a + b)),
            // Mixed native int operations
            (EmValue::NativeInt(a), EmValue::I32(b)) => {
                Ok(EmValue::NativeInt(a.wrapping_add(i64::from(*b))))
            }
            (EmValue::I32(a), EmValue::NativeInt(b)) => {
                Ok(EmValue::NativeInt(i64::from(*a).wrapping_add(*b)))
            }
            // Mixed NativeUInt + NativeInt (treat as unsigned addition)
            (EmValue::NativeUInt(a), EmValue::NativeInt(b)) => {
                Ok(EmValue::NativeUInt(a.wrapping_add(*b as u64)))
            }
            (EmValue::NativeInt(a), EmValue::NativeUInt(b)) => {
                Ok(EmValue::NativeUInt((*a as u64).wrapping_add(*b)))
            }
            // NativeUInt + I32
            (EmValue::NativeUInt(a), EmValue::I32(b)) => {
                Ok(EmValue::NativeUInt(a.wrapping_add(*b as u64)))
            }
            (EmValue::I32(a), EmValue::NativeUInt(b)) => {
                Ok(EmValue::NativeUInt((*a as u64).wrapping_add(*b)))
            }
            // Pointer arithmetic: UnmanagedPtr + integer offsets
            (EmValue::UnmanagedPtr(a), EmValue::I32(b)) => {
                Ok(EmValue::UnmanagedPtr(a.wrapping_add(*b as u64)))
            }
            (EmValue::I32(a), EmValue::UnmanagedPtr(b)) => {
                Ok(EmValue::UnmanagedPtr((*a as u64).wrapping_add(*b)))
            }
            (EmValue::UnmanagedPtr(a), EmValue::NativeInt(b)) => {
                Ok(EmValue::UnmanagedPtr(a.wrapping_add(*b as u64)))
            }
            (EmValue::NativeInt(a), EmValue::UnmanagedPtr(b)) => {
                Ok(EmValue::UnmanagedPtr((*a as u64).wrapping_add(*b)))
            }
            (EmValue::UnmanagedPtr(a), EmValue::NativeUInt(b)) => {
                Ok(EmValue::UnmanagedPtr(a.wrapping_add(*b)))
            }
            (EmValue::NativeUInt(a), EmValue::UnmanagedPtr(b)) => {
                Ok(EmValue::UnmanagedPtr(a.wrapping_add(*b)))
            }
            (a, b) => Err(EmulationError::InvalidOperationTypes {
                operation: "add".to_string(),
                operand_types: format!("{}, {}", a.cil_flavor(), b.cil_flavor()),
            }
            .into()),
        }
    }

    fn add_ovf(&self, other: &Self, unsigned: bool) -> Result<Self> {
        match (self, other) {
            (EmValue::I32(a), EmValue::I32(b)) => {
                if unsigned {
                    let (result, overflow) = (*a as u32).overflowing_add(*b as u32);
                    if overflow {
                        Err(EmulationError::ArithmeticOverflow.into())
                    } else {
                        Ok(EmValue::I32(result as i32))
                    }
                } else {
                    a.checked_add(*b)
                        .map(EmValue::I32)
                        .ok_or_else(|| EmulationError::ArithmeticOverflow.into())
                }
            }
            (EmValue::I64(a), EmValue::I64(b)) => {
                if unsigned {
                    let (result, overflow) = (*a as u64).overflowing_add(*b as u64);
                    if overflow {
                        Err(EmulationError::ArithmeticOverflow.into())
                    } else {
                        Ok(EmValue::I64(result as i64))
                    }
                } else {
                    a.checked_add(*b)
                        .map(EmValue::I64)
                        .ok_or_else(|| EmulationError::ArithmeticOverflow.into())
                }
            }
            _ => Err(EmulationError::InvalidOperationTypes {
                operation: if unsigned { "add.ovf.un" } else { "add.ovf" }.to_string(),
                operand_types: format!("{}, {}", self.cil_flavor(), other.cil_flavor()),
            }
            .into()),
        }
    }

    fn sub(&self, other: &Self) -> Result<Self> {
        match (self, other) {
            (EmValue::I32(a), EmValue::I32(b)) => Ok(EmValue::I32(a.wrapping_sub(*b))),
            (EmValue::I64(a), EmValue::I64(b)) => Ok(EmValue::I64(a.wrapping_sub(*b))),
            (EmValue::NativeInt(a), EmValue::NativeInt(b)) => {
                Ok(EmValue::NativeInt(a.wrapping_sub(*b)))
            }
            (EmValue::NativeUInt(a), EmValue::NativeUInt(b)) => {
                Ok(EmValue::NativeUInt(a.wrapping_sub(*b)))
            }
            (EmValue::F32(a), EmValue::F32(b)) => Ok(EmValue::F32(a - b)),
            (EmValue::F64(a), EmValue::F64(b)) => Ok(EmValue::F64(a - b)),
            // Mixed native int operations
            (EmValue::NativeInt(a), EmValue::I32(b)) => {
                Ok(EmValue::NativeInt(a.wrapping_sub(i64::from(*b))))
            }
            (EmValue::I32(a), EmValue::NativeInt(b)) => {
                Ok(EmValue::NativeInt(i64::from(*a).wrapping_sub(*b)))
            }
            // Mixed NativeUInt - NativeInt (treat as unsigned subtraction)
            (EmValue::NativeUInt(a), EmValue::NativeInt(b)) => {
                Ok(EmValue::NativeUInt(a.wrapping_sub(*b as u64)))
            }
            (EmValue::NativeInt(a), EmValue::NativeUInt(b)) => {
                Ok(EmValue::NativeUInt((*a as u64).wrapping_sub(*b)))
            }
            // NativeUInt - I32
            (EmValue::NativeUInt(a), EmValue::I32(b)) => {
                Ok(EmValue::NativeUInt(a.wrapping_sub(*b as u64)))
            }
            (EmValue::I32(a), EmValue::NativeUInt(b)) => {
                Ok(EmValue::NativeUInt((*a as u64).wrapping_sub(*b)))
            }
            // Pointer arithmetic: UnmanagedPtr - integer offsets
            (EmValue::UnmanagedPtr(a), EmValue::I32(b)) => {
                Ok(EmValue::UnmanagedPtr(a.wrapping_sub(*b as u64)))
            }
            (EmValue::UnmanagedPtr(a), EmValue::NativeInt(b)) => {
                Ok(EmValue::UnmanagedPtr(a.wrapping_sub(*b as u64)))
            }
            (EmValue::UnmanagedPtr(a), EmValue::NativeUInt(b)) => {
                Ok(EmValue::UnmanagedPtr(a.wrapping_sub(*b)))
            }
            // Pointer difference (ptr - ptr = native int)
            (EmValue::UnmanagedPtr(a), EmValue::UnmanagedPtr(b)) => {
                Ok(EmValue::NativeInt(a.wrapping_sub(*b) as i64))
            }
            (a, b) => Err(EmulationError::InvalidOperationTypes {
                operation: "sub".to_string(),
                operand_types: format!("{}, {}", a.cil_flavor(), b.cil_flavor()),
            }
            .into()),
        }
    }

    fn sub_ovf(&self, other: &Self, unsigned: bool) -> Result<Self> {
        match (self, other) {
            (EmValue::I32(a), EmValue::I32(b)) => {
                if unsigned {
                    let (result, overflow) = (*a as u32).overflowing_sub(*b as u32);
                    if overflow {
                        Err(EmulationError::ArithmeticOverflow.into())
                    } else {
                        Ok(EmValue::I32(result as i32))
                    }
                } else {
                    a.checked_sub(*b)
                        .map(EmValue::I32)
                        .ok_or_else(|| EmulationError::ArithmeticOverflow.into())
                }
            }
            (EmValue::I64(a), EmValue::I64(b)) => {
                if unsigned {
                    let (result, overflow) = (*a as u64).overflowing_sub(*b as u64);
                    if overflow {
                        Err(EmulationError::ArithmeticOverflow.into())
                    } else {
                        Ok(EmValue::I64(result as i64))
                    }
                } else {
                    a.checked_sub(*b)
                        .map(EmValue::I64)
                        .ok_or_else(|| EmulationError::ArithmeticOverflow.into())
                }
            }
            _ => Err(EmulationError::InvalidOperationTypes {
                operation: if unsigned { "sub.ovf.un" } else { "sub.ovf" }.to_string(),
                operand_types: format!("{}, {}", self.cil_flavor(), other.cil_flavor()),
            }
            .into()),
        }
    }

    fn mul(&self, other: &Self) -> Result<Self> {
        match (self, other) {
            (EmValue::I32(a), EmValue::I32(b)) => Ok(EmValue::I32(a.wrapping_mul(*b))),
            (EmValue::I64(a), EmValue::I64(b)) => Ok(EmValue::I64(a.wrapping_mul(*b))),
            (EmValue::NativeInt(a), EmValue::NativeInt(b)) => {
                Ok(EmValue::NativeInt(a.wrapping_mul(*b)))
            }
            (EmValue::NativeUInt(a), EmValue::NativeUInt(b)) => {
                Ok(EmValue::NativeUInt(a.wrapping_mul(*b)))
            }
            (EmValue::F32(a), EmValue::F32(b)) => Ok(EmValue::F32(a * b)),
            (EmValue::F64(a), EmValue::F64(b)) => Ok(EmValue::F64(a * b)),
            // Mixed native int operations (per CIL spec, widen to NativeInt)
            (EmValue::NativeInt(a), EmValue::I32(b)) => {
                Ok(EmValue::NativeInt(a.wrapping_mul(i64::from(*b))))
            }
            (EmValue::I32(a), EmValue::NativeInt(b)) => {
                Ok(EmValue::NativeInt(i64::from(*a).wrapping_mul(*b)))
            }
            // Mixed NativeUInt operations
            (EmValue::NativeUInt(a), EmValue::NativeInt(b)) => {
                Ok(EmValue::NativeUInt(a.wrapping_mul(*b as u64)))
            }
            (EmValue::NativeInt(a), EmValue::NativeUInt(b)) => {
                Ok(EmValue::NativeUInt((*a as u64).wrapping_mul(*b)))
            }
            // NativeUInt + I32
            (EmValue::NativeUInt(a), EmValue::I32(b)) => {
                Ok(EmValue::NativeUInt(a.wrapping_mul(*b as u64)))
            }
            (EmValue::I32(a), EmValue::NativeUInt(b)) => {
                Ok(EmValue::NativeUInt((*a as u64).wrapping_mul(*b)))
            }
            (a, b) => Err(EmulationError::InvalidOperationTypes {
                operation: "mul".to_string(),
                operand_types: format!("{}, {}", a.cil_flavor(), b.cil_flavor()),
            }
            .into()),
        }
    }

    fn mul_ovf(&self, other: &Self, unsigned: bool) -> Result<Self> {
        match (self, other) {
            (EmValue::I32(a), EmValue::I32(b)) => {
                if unsigned {
                    let ua = *a as u32;
                    let ub = *b as u32;
                    ua.checked_mul(ub)
                        .map(|r| EmValue::I32(r as i32))
                        .ok_or_else(|| EmulationError::ArithmeticOverflow.into())
                } else {
                    a.checked_mul(*b)
                        .map(EmValue::I32)
                        .ok_or_else(|| EmulationError::ArithmeticOverflow.into())
                }
            }
            (EmValue::I64(a), EmValue::I64(b)) => {
                if unsigned {
                    let ua = *a as u64;
                    let ub = *b as u64;
                    ua.checked_mul(ub)
                        .map(|r| EmValue::I64(r as i64))
                        .ok_or_else(|| EmulationError::ArithmeticOverflow.into())
                } else {
                    a.checked_mul(*b)
                        .map(EmValue::I64)
                        .ok_or_else(|| EmulationError::ArithmeticOverflow.into())
                }
            }
            _ => Err(EmulationError::InvalidOperationTypes {
                operation: if unsigned { "mul.ovf.un" } else { "mul.ovf" }.to_string(),
                operand_types: format!("{}, {}", self.cil_flavor(), other.cil_flavor()),
            }
            .into()),
        }
    }

    fn div(&self, other: &Self, unsigned: bool) -> Result<Self> {
        // Check for division by zero first
        let is_zero = match other {
            EmValue::I32(v) => *v == 0,
            EmValue::I64(v) | EmValue::NativeInt(v) => *v == 0,
            EmValue::NativeUInt(v) => *v == 0,
            EmValue::F32(v) => *v == 0.0,
            EmValue::F64(v) => *v == 0.0,
            _ => false,
        };

        // Only check for integer division by zero (floats return infinity)
        if is_zero && !matches!(other, EmValue::F32(_) | EmValue::F64(_)) {
            return Err(EmulationError::DivisionByZero.into());
        }

        match (self, other) {
            (EmValue::I32(a), EmValue::I32(b)) => {
                if unsigned {
                    Ok(EmValue::I32(((*a as u32) / (*b as u32)) as i32))
                } else {
                    // Handle MIN / -1 overflow case
                    if *a == i32::MIN && *b == -1 {
                        Ok(EmValue::I32(i32::MIN)) // Wrapping behavior
                    } else {
                        Ok(EmValue::I32(a / b))
                    }
                }
            }
            (EmValue::I64(a), EmValue::I64(b)) => {
                if unsigned {
                    Ok(EmValue::I64(((*a as u64) / (*b as u64)) as i64))
                } else if *a == i64::MIN && *b == -1 {
                    Ok(EmValue::I64(i64::MIN))
                } else {
                    Ok(EmValue::I64(a / b))
                }
            }
            (EmValue::NativeInt(a), EmValue::NativeInt(b)) => {
                if unsigned {
                    Ok(EmValue::NativeInt(((*a as u64) / (*b as u64)) as i64))
                } else if *a == i64::MIN && *b == -1 {
                    Ok(EmValue::NativeInt(i64::MIN))
                } else {
                    Ok(EmValue::NativeInt(a / b))
                }
            }
            (EmValue::NativeUInt(a), EmValue::NativeUInt(b)) => Ok(EmValue::NativeUInt(a / b)),
            (EmValue::F32(a), EmValue::F32(b)) => Ok(EmValue::F32(a / b)),
            (EmValue::F64(a), EmValue::F64(b)) => Ok(EmValue::F64(a / b)),
            (a, b) => Err(EmulationError::InvalidOperationTypes {
                operation: if unsigned { "div.un" } else { "div" }.to_string(),
                operand_types: format!("{}, {}", a.cil_flavor(), b.cil_flavor()),
            }
            .into()),
        }
    }

    fn rem(&self, other: &Self, unsigned: bool) -> Result<Self> {
        // Check for division by zero
        let is_zero = match other {
            EmValue::I32(v) => *v == 0,
            EmValue::I64(v) | EmValue::NativeInt(v) => *v == 0,
            EmValue::NativeUInt(v) => *v == 0,
            _ => false,
        };

        if is_zero {
            return Err(EmulationError::DivisionByZero.into());
        }

        match (self, other) {
            (EmValue::I32(a), EmValue::I32(b)) => {
                if unsigned {
                    Ok(EmValue::I32(((*a as u32) % (*b as u32)) as i32))
                } else {
                    // Handle MIN % -1 case (result is 0)
                    if *a == i32::MIN && *b == -1 {
                        Ok(EmValue::I32(0))
                    } else {
                        Ok(EmValue::I32(a % b))
                    }
                }
            }
            (EmValue::I64(a), EmValue::I64(b)) => {
                if unsigned {
                    Ok(EmValue::I64(((*a as u64) % (*b as u64)) as i64))
                } else if *a == i64::MIN && *b == -1 {
                    Ok(EmValue::I64(0))
                } else {
                    Ok(EmValue::I64(a % b))
                }
            }
            (EmValue::NativeInt(a), EmValue::NativeInt(b)) => {
                if unsigned {
                    Ok(EmValue::NativeInt(((*a as u64) % (*b as u64)) as i64))
                } else if *a == i64::MIN && *b == -1 {
                    Ok(EmValue::NativeInt(0))
                } else {
                    Ok(EmValue::NativeInt(a % b))
                }
            }
            (EmValue::NativeUInt(a), EmValue::NativeUInt(b)) => Ok(EmValue::NativeUInt(a % b)),
            (EmValue::F32(a), EmValue::F32(b)) => Ok(EmValue::F32(a % b)),
            (EmValue::F64(a), EmValue::F64(b)) => Ok(EmValue::F64(a % b)),
            (a, b) => Err(EmulationError::InvalidOperationTypes {
                operation: if unsigned { "rem.un" } else { "rem" }.to_string(),
                operand_types: format!("{}, {}", a.cil_flavor(), b.cil_flavor()),
            }
            .into()),
        }
    }

    fn bitand(&self, other: &Self) -> Result<Self> {
        match (self, other) {
            (EmValue::I32(a), EmValue::I32(b)) => Ok(EmValue::I32(a & b)),
            (EmValue::I64(a), EmValue::I64(b)) => Ok(EmValue::I64(a & b)),
            (EmValue::NativeInt(a), EmValue::NativeInt(b)) => Ok(EmValue::NativeInt(a & b)),
            (EmValue::NativeUInt(a), EmValue::NativeUInt(b)) => Ok(EmValue::NativeUInt(a & b)),
            (a, b) => Err(EmulationError::InvalidOperationTypes {
                operation: "and".to_string(),
                operand_types: format!("{}, {}", a.cil_flavor(), b.cil_flavor()),
            }
            .into()),
        }
    }

    fn bitor(&self, other: &Self) -> Result<Self> {
        match (self, other) {
            (EmValue::I32(a), EmValue::I32(b)) => Ok(EmValue::I32(a | b)),
            (EmValue::I64(a), EmValue::I64(b)) => Ok(EmValue::I64(a | b)),
            (EmValue::NativeInt(a), EmValue::NativeInt(b)) => Ok(EmValue::NativeInt(a | b)),
            (EmValue::NativeUInt(a), EmValue::NativeUInt(b)) => Ok(EmValue::NativeUInt(a | b)),
            (a, b) => Err(EmulationError::InvalidOperationTypes {
                operation: "or".to_string(),
                operand_types: format!("{}, {}", a.cil_flavor(), b.cil_flavor()),
            }
            .into()),
        }
    }

    fn bitxor(&self, other: &Self) -> Result<Self> {
        match (self, other) {
            (EmValue::I32(a), EmValue::I32(b)) => Ok(EmValue::I32(a ^ b)),
            (EmValue::I64(a), EmValue::I64(b)) => Ok(EmValue::I64(a ^ b)),
            (EmValue::NativeInt(a), EmValue::NativeInt(b)) => Ok(EmValue::NativeInt(a ^ b)),
            (EmValue::NativeUInt(a), EmValue::NativeUInt(b)) => Ok(EmValue::NativeUInt(a ^ b)),
            (a, b) => Err(EmulationError::InvalidOperationTypes {
                operation: "xor".to_string(),
                operand_types: format!("{}, {}", a.cil_flavor(), b.cil_flavor()),
            }
            .into()),
        }
    }

    fn shl(&self, other: &Self) -> Result<Self> {
        // Shift amount is always taken from the low bits (masked by type width - 1)
        let shift = match *other {
            EmValue::I32(v) => v as u32,
            EmValue::I64(v) | EmValue::NativeInt(v) => v as u32,
            EmValue::NativeUInt(v) => v as u32,
            _ => {
                return Err(EmulationError::InvalidOperationTypes {
                    operation: "shl".to_string(),
                    operand_types: format!("_, {}", other.cil_flavor()),
                }
                .into());
            }
        };

        match *self {
            EmValue::I32(a) => Ok(EmValue::I32(a.wrapping_shl(shift & 31))),
            EmValue::I64(a) => Ok(EmValue::I64(a.wrapping_shl(shift & 63))),
            EmValue::NativeInt(a) => Ok(EmValue::NativeInt(a.wrapping_shl(shift & 63))),
            EmValue::NativeUInt(a) => Ok(EmValue::NativeUInt(a.wrapping_shl(shift & 63))),
            _ => Err(EmulationError::InvalidOperationTypes {
                operation: "shl".to_string(),
                operand_types: format!("{}, _", self.cil_flavor()),
            }
            .into()),
        }
    }

    fn shr(&self, other: &Self, unsigned: bool) -> Result<Self> {
        let shift = match *other {
            EmValue::I32(v) => v as u32,
            EmValue::I64(v) | EmValue::NativeInt(v) => v as u32,
            EmValue::NativeUInt(v) => v as u32,
            _ => {
                return Err(EmulationError::InvalidOperationTypes {
                    operation: if unsigned { "shr.un" } else { "shr" }.to_string(),
                    operand_types: format!("_, {}", other.cil_flavor()),
                }
                .into());
            }
        };

        match *self {
            EmValue::I32(a) => {
                if unsigned {
                    Ok(EmValue::I32((a as u32).wrapping_shr(shift & 31) as i32))
                } else {
                    Ok(EmValue::I32(a.wrapping_shr(shift & 31)))
                }
            }
            EmValue::I64(a) => {
                if unsigned {
                    Ok(EmValue::I64((a as u64).wrapping_shr(shift & 63) as i64))
                } else {
                    Ok(EmValue::I64(a.wrapping_shr(shift & 63)))
                }
            }
            EmValue::NativeInt(a) => {
                if unsigned {
                    Ok(EmValue::NativeInt(
                        (a as u64).wrapping_shr(shift & 63) as i64
                    ))
                } else {
                    Ok(EmValue::NativeInt(a.wrapping_shr(shift & 63)))
                }
            }
            EmValue::NativeUInt(a) => Ok(EmValue::NativeUInt(a.wrapping_shr(shift & 63))),
            _ => Err(EmulationError::InvalidOperationTypes {
                operation: if unsigned { "shr.un" } else { "shr" }.to_string(),
                operand_types: format!("{}, _", self.cil_flavor()),
            }
            .into()),
        }
    }

    fn neg(&self) -> Result<Self> {
        match *self {
            EmValue::I32(a) => Ok(EmValue::I32(a.wrapping_neg())),
            EmValue::I64(a) => Ok(EmValue::I64(a.wrapping_neg())),
            EmValue::NativeInt(a) => Ok(EmValue::NativeInt(a.wrapping_neg())),
            EmValue::F32(a) => Ok(EmValue::F32(-a)),
            EmValue::F64(a) => Ok(EmValue::F64(-a)),
            _ => Err(EmulationError::InvalidOperationTypes {
                operation: "neg".to_string(),
                operand_types: self.cil_flavor().to_string(),
            }
            .into()),
        }
    }

    fn not(&self) -> Result<Self> {
        match *self {
            EmValue::I32(a) => Ok(EmValue::I32(!a)),
            EmValue::I64(a) => Ok(EmValue::I64(!a)),
            EmValue::NativeInt(a) => Ok(EmValue::NativeInt(!a)),
            EmValue::NativeUInt(a) => Ok(EmValue::NativeUInt(!a)),
            _ => Err(EmulationError::InvalidOperationTypes {
                operation: "not".to_string(),
                operand_types: self.cil_flavor().to_string(),
            }
            .into()),
        }
    }

    fn cmp_eq(&self, other: &Self) -> Result<bool> {
        match (self, other) {
            (EmValue::I32(a), EmValue::I32(b)) => Ok(a == b),
            (EmValue::I64(a), EmValue::I64(b)) | (EmValue::NativeInt(a), EmValue::NativeInt(b)) => {
                Ok(a == b)
            }
            (EmValue::NativeUInt(a), EmValue::NativeUInt(b)) => Ok(a == b),
            (EmValue::F32(a), EmValue::F32(b)) => Ok(a == b),
            (EmValue::F64(a), EmValue::F64(b)) => Ok(a == b),
            (EmValue::ObjectRef(a), EmValue::ObjectRef(b)) => Ok(a == b),
            (EmValue::Null, EmValue::Null) => Ok(true),
            (EmValue::ObjectRef(_), EmValue::Null) | (EmValue::Null, EmValue::ObjectRef(_)) => {
                Ok(false)
            }
            (EmValue::Bool(a), EmValue::Bool(b)) => Ok(a == b),
            (EmValue::Char(a), EmValue::Char(b)) => Ok(a == b),
            // Cross-type comparisons for int32 stack types (I32, Bool, Char all use int32 on stack)
            (EmValue::I32(a), EmValue::Bool(b)) | (EmValue::Bool(b), EmValue::I32(a)) => {
                Ok(*a == i32::from(*b))
            }
            (EmValue::I32(a), EmValue::Char(b)) | (EmValue::Char(b), EmValue::I32(a)) => {
                Ok(*a == (*b as u32) as i32)
            }
            (EmValue::Bool(a), EmValue::Char(b)) | (EmValue::Char(b), EmValue::Bool(a)) => {
                Ok(i32::from(*a) == (*b as u32) as i32)
            }
            // Native int comparisons with I64
            (EmValue::NativeInt(a), EmValue::I64(b)) | (EmValue::I64(b), EmValue::NativeInt(a)) => {
                Ok(a == b)
            }
            // Pointer comparisons
            (EmValue::NativeInt(a), EmValue::UnmanagedPtr(b))
            | (EmValue::UnmanagedPtr(b), EmValue::NativeInt(a)) => Ok(*a as u64 == *b),
            (EmValue::UnmanagedPtr(a), EmValue::UnmanagedPtr(b)) => Ok(a == b),
            (a, b) => Err(EmulationError::InvalidOperationTypes {
                operation: "ceq".to_string(),
                operand_types: format!("{}, {}", a.cil_flavor(), b.cil_flavor()),
            }
            .into()),
        }
    }

    fn cmp_lt(&self, other: &Self, unsigned: bool) -> Result<bool> {
        match (self, other) {
            (EmValue::I32(a), EmValue::I32(b)) => {
                if unsigned {
                    Ok((*a as u32) < (*b as u32))
                } else {
                    Ok(a < b)
                }
            }
            (EmValue::I64(a), EmValue::I64(b)) | (EmValue::NativeInt(a), EmValue::NativeInt(b)) => {
                if unsigned {
                    Ok((*a as u64) < (*b as u64))
                } else {
                    Ok(a < b)
                }
            }
            (EmValue::NativeUInt(a), EmValue::NativeUInt(b)) => Ok(a < b),
            (EmValue::F32(a), EmValue::F32(b)) => {
                // For unordered comparison (clt.un), NaN < anything is false
                if unsigned {
                    Ok(a < b || a.is_nan() || b.is_nan())
                } else {
                    Ok(a < b)
                }
            }
            (EmValue::F64(a), EmValue::F64(b)) => {
                if unsigned {
                    Ok(a < b || a.is_nan() || b.is_nan())
                } else {
                    Ok(a < b)
                }
            }
            (a, b) => Err(EmulationError::InvalidOperationTypes {
                operation: if unsigned { "clt.un" } else { "clt" }.to_string(),
                operand_types: format!("{}, {}", a.cil_flavor(), b.cil_flavor()),
            }
            .into()),
        }
    }

    fn cmp_le(&self, other: &Self, unsigned: bool) -> Result<bool> {
        // a <= b is equivalent to !(a > b)
        self.cmp_gt(other, unsigned).map(|r| !r)
    }

    fn cmp_gt(&self, other: &Self, unsigned: bool) -> Result<bool> {
        match (self, other) {
            (EmValue::I32(a), EmValue::I32(b)) => {
                if unsigned {
                    Ok((*a as u32) > (*b as u32))
                } else {
                    Ok(a > b)
                }
            }
            (EmValue::I64(a), EmValue::I64(b)) | (EmValue::NativeInt(a), EmValue::NativeInt(b)) => {
                if unsigned {
                    Ok((*a as u64) > (*b as u64))
                } else {
                    Ok(a > b)
                }
            }
            (EmValue::NativeUInt(a), EmValue::NativeUInt(b)) => Ok(a > b),
            (EmValue::F32(a), EmValue::F32(b)) => {
                if unsigned {
                    Ok(a > b || a.is_nan() || b.is_nan())
                } else {
                    Ok(a > b)
                }
            }
            (EmValue::F64(a), EmValue::F64(b)) => {
                if unsigned {
                    Ok(a > b || a.is_nan() || b.is_nan())
                } else {
                    Ok(a > b)
                }
            }
            (a, b) => Err(EmulationError::InvalidOperationTypes {
                operation: if unsigned { "cgt.un" } else { "cgt" }.to_string(),
                operand_types: format!("{}, {}", a.cil_flavor(), b.cil_flavor()),
            }
            .into()),
        }
    }

    fn cmp_ge(&self, other: &Self, unsigned: bool) -> Result<bool> {
        // a >= b is equivalent to !(a < b)
        self.cmp_lt(other, unsigned).map(|r| !r)
    }

    fn conv_i1(&self) -> Result<Self> {
        let value = self.to_i64()?;
        // Truncate to 8 bits, then sign-extend to i32
        Ok(EmValue::I32(value as i8 as i32))
    }

    fn conv_i2(&self) -> Result<Self> {
        let value = self.to_i64()?;
        Ok(EmValue::I32(value as i16 as i32))
    }

    fn conv_i4(&self) -> Result<Self> {
        let value = self.to_i64()?;
        Ok(EmValue::I32(value as i32))
    }

    fn conv_i8(&self) -> Result<Self> {
        let value = self.to_i64()?;
        Ok(EmValue::I64(value))
    }

    fn conv_u1(&self) -> Result<Self> {
        let value = self.to_i64()?;
        // Truncate to 8 bits, then zero-extend to i32
        Ok(EmValue::I32((value as u8) as i32))
    }

    fn conv_u2(&self) -> Result<Self> {
        let value = self.to_i64()?;
        Ok(EmValue::I32((value as u16) as i32))
    }

    fn conv_u4(&self) -> Result<Self> {
        let value = self.to_i64()?;
        Ok(EmValue::I32(value as u32 as i32))
    }

    fn conv_u8(&self) -> Result<Self> {
        let value = self.to_u64()?;
        Ok(EmValue::I64(value as i64))
    }

    fn conv_r4(&self) -> Result<Self> {
        match *self {
            EmValue::I32(v) => Ok(EmValue::F32(v as f32)),
            EmValue::I64(v) | EmValue::NativeInt(v) => Ok(EmValue::F32(v as f32)),
            EmValue::NativeUInt(v) => Ok(EmValue::F32(v as f32)),
            EmValue::F32(v) => Ok(EmValue::F32(v)),
            EmValue::F64(v) => Ok(EmValue::F32(v as f32)),
            _ => Err(EmulationError::InvalidOperationTypes {
                operation: "conv.r4".to_string(),
                operand_types: self.cil_flavor().to_string(),
            }
            .into()),
        }
    }

    fn conv_r8(&self) -> Result<Self> {
        match *self {
            EmValue::I32(v) => Ok(EmValue::F64(f64::from(v))),
            EmValue::I64(v) | EmValue::NativeInt(v) => Ok(EmValue::F64(v as f64)),
            EmValue::NativeUInt(v) => Ok(EmValue::F64(v as f64)),
            EmValue::F32(v) => Ok(EmValue::F64(f64::from(v))),
            EmValue::F64(v) => Ok(EmValue::F64(v)),
            _ => Err(EmulationError::InvalidOperationTypes {
                operation: "conv.r8".to_string(),
                operand_types: self.cil_flavor().to_string(),
            }
            .into()),
        }
    }

    fn conv_i(&self, ptr_size: PointerSize) -> Result<Self> {
        let value = ptr_size.mask_signed(self.to_i64()?);
        Ok(EmValue::NativeInt(value))
    }

    fn conv_u(&self, ptr_size: PointerSize) -> Result<Self> {
        let value = ptr_size.mask_unsigned(self.to_u64()?);
        Ok(EmValue::NativeUInt(value))
    }

    fn conv_r_un(&self) -> Result<Self> {
        // Convert unsigned integer to float
        let value = self.to_u64()?;
        Ok(EmValue::F64(value as f64))
    }

    // Checked conversions

    fn conv_i1_ovf(&self, unsigned_source: bool) -> Result<Self> {
        let value = if unsigned_source {
            self.to_u64()? as i64
        } else {
            self.to_i64()?
        };

        if value < i8::MIN as i64 || value > i8::MAX as i64 {
            Err(EmulationError::ArithmeticOverflow.into())
        } else {
            Ok(EmValue::I32(value as i32))
        }
    }

    fn conv_i2_ovf(&self, unsigned_source: bool) -> Result<Self> {
        let value = if unsigned_source {
            self.to_u64()? as i64
        } else {
            self.to_i64()?
        };

        if value < i16::MIN as i64 || value > i16::MAX as i64 {
            Err(EmulationError::ArithmeticOverflow.into())
        } else {
            Ok(EmValue::I32(value as i32))
        }
    }

    fn conv_i4_ovf(&self, unsigned_source: bool) -> Result<Self> {
        let value = if unsigned_source {
            self.to_u64()? as i64
        } else {
            self.to_i64()?
        };

        if value < i32::MIN as i64 || value > i32::MAX as i64 {
            Err(EmulationError::ArithmeticOverflow.into())
        } else {
            Ok(EmValue::I32(value as i32))
        }
    }

    fn conv_i8_ovf(&self, unsigned_source: bool) -> Result<Self> {
        if unsigned_source {
            let value = self.to_u64()?;
            if value > i64::MAX as u64 {
                Err(EmulationError::ArithmeticOverflow.into())
            } else {
                Ok(EmValue::I64(value as i64))
            }
        } else {
            // No overflow possible for signed i64 -> i64
            let value = self.to_i64()?;
            Ok(EmValue::I64(value))
        }
    }

    fn conv_u1_ovf(&self, unsigned_source: bool) -> Result<Self> {
        let value = if unsigned_source {
            self.to_u64()?
        } else {
            let signed = self.to_i64()?;
            if signed < 0 {
                return Err(EmulationError::ArithmeticOverflow.into());
            }
            signed as u64
        };

        if value > u8::MAX as u64 {
            Err(EmulationError::ArithmeticOverflow.into())
        } else {
            Ok(EmValue::I32(value as i32))
        }
    }

    fn conv_u2_ovf(&self, unsigned_source: bool) -> Result<Self> {
        let value = if unsigned_source {
            self.to_u64()?
        } else {
            let signed = self.to_i64()?;
            if signed < 0 {
                return Err(EmulationError::ArithmeticOverflow.into());
            }
            signed as u64
        };

        if value > u16::MAX as u64 {
            Err(EmulationError::ArithmeticOverflow.into())
        } else {
            Ok(EmValue::I32(value as i32))
        }
    }

    fn conv_u4_ovf(&self, unsigned_source: bool) -> Result<Self> {
        let value = if unsigned_source {
            self.to_u64()?
        } else {
            let signed = self.to_i64()?;
            if signed < 0 {
                return Err(EmulationError::ArithmeticOverflow.into());
            }
            signed as u64
        };

        if value > u32::MAX as u64 {
            Err(EmulationError::ArithmeticOverflow.into())
        } else {
            Ok(EmValue::I32(value as u32 as i32))
        }
    }

    fn conv_u8_ovf(&self, unsigned_source: bool) -> Result<Self> {
        if unsigned_source {
            // No overflow possible for unsigned -> u64
            let value = self.to_u64()?;
            Ok(EmValue::I64(value as i64))
        } else {
            let value = self.to_i64()?;
            if value < 0 {
                Err(EmulationError::ArithmeticOverflow.into())
            } else {
                Ok(EmValue::I64(value))
            }
        }
    }

    fn conv_i_ovf(&self, unsigned_source: bool) -> Result<Self> {
        // Native int - for 64-bit emulation, same as i8
        self.conv_i8_ovf(unsigned_source).map(|v| match v {
            EmValue::I64(n) => EmValue::NativeInt(n),
            other => other,
        })
    }

    fn conv_u_ovf(&self, unsigned_source: bool) -> Result<Self> {
        if unsigned_source {
            let value = self.to_u64()?;
            Ok(EmValue::NativeUInt(value))
        } else {
            let value = self.to_i64()?;
            if value < 0 {
                Err(EmulationError::ArithmeticOverflow.into())
            } else {
                Ok(EmValue::NativeUInt(value as u64))
            }
        }
    }

    // Helper methods for conversion

    /// Extracts the value as `i64` for conversion operations.
    ///
    /// This is an internal helper that converts any numeric value type to `i64`.
    /// For floating point values, truncates toward zero.
    ///
    /// # Errors
    ///
    /// Returns an error if the value type cannot be converted to a numeric value.
    fn to_i64(&self) -> Result<i64> {
        match self {
            EmValue::I32(v) => Ok(i64::from(*v)),
            EmValue::I64(v) | EmValue::NativeInt(v) => Ok(*v),
            EmValue::NativeUInt(v) => Ok(*v as i64),
            EmValue::Bool(v) => Ok(i64::from(*v)),
            EmValue::Char(v) => Ok(*v as i64),
            EmValue::F32(v) => Ok(*v as i64),
            EmValue::F64(v) => Ok(*v as i64),
            _ => Err(EmulationError::InvalidOperationTypes {
                operation: "conversion".to_string(),
                operand_types: self.cil_flavor().to_string(),
            }
            .into()),
        }
    }

    /// Extracts the value as `u64` for unsigned conversion operations.
    ///
    /// This is an internal helper that converts any numeric value type to `u64`.
    /// For signed types, interprets the bit pattern as unsigned.
    /// For floating point values, truncates toward zero (negative values become 0).
    ///
    /// # Errors
    ///
    /// Returns an error if the value type cannot be converted to a numeric value.
    fn to_u64(&self) -> Result<u64> {
        match self {
            // For I32, we interpret the bit pattern as unsigned 32-bit then zero-extend
            EmValue::I32(v) => Ok(*v as u32 as u64),
            EmValue::I64(v) | EmValue::NativeInt(v) => Ok(*v as u64),
            EmValue::NativeUInt(v) => Ok(*v),
            EmValue::Bool(v) => Ok(u64::from(*v)),
            EmValue::Char(v) => Ok(*v as u64),
            EmValue::F32(v) => Ok(*v as u64),
            EmValue::F64(v) => Ok(*v as u64),
            _ => Err(EmulationError::InvalidOperationTypes {
                operation: "conversion".to_string(),
                operand_types: self.cil_flavor().to_string(),
            }
            .into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{super::HeapRef, *};
    use crate::{metadata::typesystem::PointerSize, Error};

    #[test]
    fn test_binary_op_add_i32() {
        let a = EmValue::I32(10);
        let b = EmValue::I32(20);
        assert_eq!(
            a.binary_op(&b, BinaryOp::Add, PointerSize::Bit64).unwrap(),
            EmValue::I32(30)
        );
    }

    #[test]
    fn test_binary_op_add_wrapping() {
        let a = EmValue::I32(i32::MAX);
        let b = EmValue::I32(1);
        assert_eq!(
            a.binary_op(&b, BinaryOp::Add, PointerSize::Bit64).unwrap(),
            EmValue::I32(i32::MIN)
        );
    }

    #[test]
    fn test_binary_op_add_i64() {
        let a = EmValue::I64(100);
        let b = EmValue::I64(200);
        assert_eq!(
            a.binary_op(&b, BinaryOp::Add, PointerSize::Bit64).unwrap(),
            EmValue::I64(300)
        );
    }

    #[test]
    fn test_binary_op_add_f64() {
        let a = EmValue::F64(1.5);
        let b = EmValue::F64(2.5);
        assert_eq!(
            a.binary_op(&b, BinaryOp::Add, PointerSize::Bit64).unwrap(),
            EmValue::F64(4.0)
        );
    }

    #[test]
    fn test_binary_op_add_ovf() {
        let a = EmValue::I32(i32::MAX);
        let b = EmValue::I32(1);
        assert!(matches!(
            a.binary_op(&b,BinaryOp::AddOvf, PointerSize::Bit64),
            Err(Error::Emulation(ref e)) if matches!(e.as_ref(), EmulationError::ArithmeticOverflow)
        ));
    }

    #[test]
    fn test_binary_op_sub() {
        let a = EmValue::I32(30);
        let b = EmValue::I32(20);
        assert_eq!(
            a.binary_op(&b, BinaryOp::Sub, PointerSize::Bit64).unwrap(),
            EmValue::I32(10)
        );
    }

    #[test]
    fn test_binary_op_mul() {
        let a = EmValue::I32(6);
        let b = EmValue::I32(7);
        assert_eq!(
            a.binary_op(&b, BinaryOp::Mul, PointerSize::Bit64).unwrap(),
            EmValue::I32(42)
        );
    }

    #[test]
    fn test_binary_op_div() {
        let a = EmValue::I32(42);
        let b = EmValue::I32(6);
        assert_eq!(
            a.binary_op(&b, BinaryOp::Div, PointerSize::Bit64).unwrap(),
            EmValue::I32(7)
        );
    }

    #[test]
    fn test_binary_op_div_by_zero() {
        let a = EmValue::I32(42);
        let b = EmValue::I32(0);
        assert!(matches!(
            a.binary_op(&b,BinaryOp::Div, PointerSize::Bit64),
            Err(Error::Emulation(ref e)) if matches!(e.as_ref(), EmulationError::DivisionByZero)
        ));
    }

    #[test]
    fn test_binary_op_div_unsigned() {
        let a = EmValue::I32(-1); // 0xFFFFFFFF as unsigned
        let b = EmValue::I32(2);
        let result = a
            .binary_op(&b, BinaryOp::DivUn, PointerSize::Bit64)
            .unwrap();
        // -1 as u32 is 0xFFFFFFFF = 4294967295, divided by 2 is 2147483647
        assert_eq!(result, EmValue::I32(0x7FFFFFFF));
    }

    #[test]
    fn test_binary_op_rem() {
        let a = EmValue::I32(17);
        let b = EmValue::I32(5);
        assert_eq!(
            a.binary_op(&b, BinaryOp::Rem, PointerSize::Bit64).unwrap(),
            EmValue::I32(2)
        );
    }

    #[test]
    fn test_binary_op_and() {
        let a = EmValue::I32(0xFF00);
        let b = EmValue::I32(0x0FF0);
        assert_eq!(
            a.binary_op(&b, BinaryOp::And, PointerSize::Bit64).unwrap(),
            EmValue::I32(0x0F00)
        );
    }

    #[test]
    fn test_binary_op_or() {
        let a = EmValue::I32(0xFF00);
        let b = EmValue::I32(0x00FF);
        assert_eq!(
            a.binary_op(&b, BinaryOp::Or, PointerSize::Bit64).unwrap(),
            EmValue::I32(0xFFFF)
        );
    }

    #[test]
    fn test_binary_op_xor() {
        let a = EmValue::I32(0xFFFF);
        let b = EmValue::I32(0x0F0F);
        assert_eq!(
            a.binary_op(&b, BinaryOp::Xor, PointerSize::Bit64).unwrap(),
            EmValue::I32(0xF0F0)
        );
    }

    #[test]
    fn test_binary_op_shl() {
        let a = EmValue::I32(1);
        let b = EmValue::I32(4);
        assert_eq!(
            a.binary_op(&b, BinaryOp::Shl, PointerSize::Bit64).unwrap(),
            EmValue::I32(16)
        );
    }

    #[test]
    fn test_binary_op_shr_signed() {
        let a = EmValue::I32(-8);
        let b = EmValue::I32(2);
        // Arithmetic shift right preserves sign
        assert_eq!(
            a.binary_op(&b, BinaryOp::Shr, PointerSize::Bit64).unwrap(),
            EmValue::I32(-2)
        );
    }

    #[test]
    fn test_binary_op_shr_unsigned() {
        let a = EmValue::I32(-8);
        let b = EmValue::I32(2);
        // Logical shift right fills with zeros
        let result = a
            .binary_op(&b, BinaryOp::ShrUn, PointerSize::Bit64)
            .unwrap();
        // -8 as u32 >> 2 = 0xFFFFFFF8 >> 2 = 0x3FFFFFFE
        assert_eq!(result, EmValue::I32(0x3FFFFFFE_u32 as i32));
    }

    #[test]
    fn test_binary_op_type_mismatch() {
        let a = EmValue::I32(1);
        let b = EmValue::I64(1);
        assert!(matches!(
            a.binary_op(&b,BinaryOp::Add, PointerSize::Bit64),
            Err(Error::Emulation(ref e)) if matches!(e.as_ref(), EmulationError::InvalidOperationTypes { .. })
        ));
    }

    #[test]
    fn test_unary_neg_i32() {
        let a = EmValue::I32(42);
        assert_eq!(
            a.unary_op(UnaryOp::Neg, PointerSize::Bit64).unwrap(),
            EmValue::I32(-42)
        );
    }

    #[test]
    fn test_unary_neg_f64() {
        let a = EmValue::F64(std::f64::consts::PI);
        assert_eq!(
            a.unary_op(UnaryOp::Neg, PointerSize::Bit64).unwrap(),
            EmValue::F64(-std::f64::consts::PI)
        );
    }

    #[test]
    fn test_unary_not_i32() {
        let a = EmValue::I32(0);
        assert_eq!(
            a.unary_op(UnaryOp::Not, PointerSize::Bit64).unwrap(),
            EmValue::I32(-1)
        );
    }

    #[test]
    fn test_unary_not_pattern() {
        let a = EmValue::I32(0x0F0F0F0F);
        assert_eq!(
            a.unary_op(UnaryOp::Not, PointerSize::Bit64).unwrap(),
            EmValue::I32(0xF0F0F0F0_u32 as i32)
        );
    }

    #[test]
    fn test_compare_eq() {
        let a = EmValue::I32(42);
        let b = EmValue::I32(42);
        assert_eq!(a.compare(&b, CompareOp::Eq).unwrap(), EmValue::I32(1));

        let c = EmValue::I32(43);
        assert_eq!(a.compare(&c, CompareOp::Eq).unwrap(), EmValue::I32(0));
    }

    #[test]
    fn test_compare_ne() {
        let a = EmValue::I32(42);
        let b = EmValue::I32(43);
        assert_eq!(a.compare(&b, CompareOp::Ne).unwrap(), EmValue::I32(1));
    }

    #[test]
    fn test_compare_lt() {
        let a = EmValue::I32(10);
        let b = EmValue::I32(20);
        assert_eq!(a.compare(&b, CompareOp::Lt).unwrap(), EmValue::I32(1));
        assert_eq!(b.compare(&a, CompareOp::Lt).unwrap(), EmValue::I32(0));
    }

    #[test]
    fn test_compare_lt_unsigned() {
        let a = EmValue::I32(-1); // Large unsigned value
        let b = EmValue::I32(1);
        // Signed: -1 < 1, Unsigned: 0xFFFFFFFF > 1
        assert_eq!(a.compare(&b, CompareOp::Lt).unwrap(), EmValue::I32(1));
        assert_eq!(a.compare(&b, CompareOp::LtUn).unwrap(), EmValue::I32(0));
    }

    #[test]
    fn test_compare_gt() {
        let a = EmValue::I32(20);
        let b = EmValue::I32(10);
        assert_eq!(a.compare(&b, CompareOp::Gt).unwrap(), EmValue::I32(1));
    }

    #[test]
    fn test_compare_le() {
        let a = EmValue::I32(10);
        let b = EmValue::I32(10);
        assert_eq!(a.compare(&b, CompareOp::Le).unwrap(), EmValue::I32(1));
    }

    #[test]
    fn test_compare_ge() {
        let a = EmValue::I32(10);
        let b = EmValue::I32(10);
        assert_eq!(a.compare(&b, CompareOp::Ge).unwrap(), EmValue::I32(1));
    }

    #[test]
    fn test_compare_null() {
        let a = EmValue::Null;
        let b = EmValue::Null;
        assert_eq!(a.compare(&b, CompareOp::Eq).unwrap(), EmValue::I32(1));
    }

    #[test]
    fn test_compare_object_ref() {
        let a = EmValue::ObjectRef(HeapRef::new(1));
        let b = EmValue::ObjectRef(HeapRef::new(1));
        let c = EmValue::ObjectRef(HeapRef::new(2));

        assert_eq!(a.compare(&b, CompareOp::Eq).unwrap(), EmValue::I32(1));
        assert_eq!(a.compare(&c, CompareOp::Eq).unwrap(), EmValue::I32(0));
    }

    #[test]
    fn test_conv_i1() {
        let a = EmValue::I32(300);
        // 300 truncated to 8 bits is 44, then sign-extended
        let result = a.convert(ConversionType::I1, PointerSize::Bit64).unwrap();
        assert_eq!(result, EmValue::I32(44));

        let b = EmValue::I32(-1);
        // -1 as i8 is -1, sign-extended to i32 is -1
        let result = b.convert(ConversionType::I1, PointerSize::Bit64).unwrap();
        assert_eq!(result, EmValue::I32(-1));
    }

    #[test]
    fn test_conv_u1() {
        let a = EmValue::I32(-1);
        // -1 truncated to u8 is 255, zero-extended to i32
        let result = a.convert(ConversionType::U1, PointerSize::Bit64).unwrap();
        assert_eq!(result, EmValue::I32(255));
    }

    #[test]
    fn test_conv_i8() {
        let a = EmValue::I32(42);
        let result = a.convert(ConversionType::I8, PointerSize::Bit64).unwrap();
        assert_eq!(result, EmValue::I64(42));
    }

    #[test]
    fn test_conv_u8() {
        let a = EmValue::I32(-1);
        let result = a.convert(ConversionType::U8, PointerSize::Bit64).unwrap();
        // -1 as u32 zero-extended to u64, stored as i64
        assert_eq!(result, EmValue::I64(0xFFFFFFFF));
    }

    #[test]
    fn test_conv_r4() {
        let a = EmValue::I32(42);
        let result = a.convert(ConversionType::R4, PointerSize::Bit64).unwrap();
        assert_eq!(result, EmValue::F32(42.0));
    }

    #[test]
    fn test_conv_r8() {
        let a = EmValue::I32(42);
        let result = a.convert(ConversionType::R8, PointerSize::Bit64).unwrap();
        assert_eq!(result, EmValue::F64(42.0));
    }

    #[test]
    fn test_conv_ovf_i1() {
        let a = EmValue::I32(200);
        // 200 > 127, overflow
        assert!(matches!(
            a.convert(ConversionType::I1Ovf, PointerSize::Bit64),
            Err(Error::Emulation(ref e)) if matches!(e.as_ref(), EmulationError::ArithmeticOverflow)
        ));
    }

    #[test]
    fn test_conv_ovf_u1() {
        let a = EmValue::I32(-1);
        // Negative value to unsigned, overflow
        assert!(matches!(
            a.convert(ConversionType::U1Ovf, PointerSize::Bit64),
            Err(Error::Emulation(ref e)) if matches!(e.as_ref(), EmulationError::ArithmeticOverflow)
        ));
    }

    #[test]
    fn test_conv_r_un() {
        let a = EmValue::I32(-1);
        // -1 as u32 is 4294967295, converted to float
        let result = a.convert(ConversionType::RUn, PointerSize::Bit64).unwrap();
        assert_eq!(result, EmValue::F64(4294967295.0));
    }

    #[test]
    fn test_binary_op_is_checked() {
        assert!(BinaryOp::AddOvf.is_checked());
        assert!(BinaryOp::MulOvfUn.is_checked());
        assert!(!BinaryOp::Add.is_checked());
        assert!(!BinaryOp::Div.is_checked());
    }

    #[test]
    fn test_binary_op_is_unsigned() {
        assert!(BinaryOp::DivUn.is_unsigned());
        assert!(BinaryOp::ShrUn.is_unsigned());
        assert!(!BinaryOp::Div.is_unsigned());
        assert!(!BinaryOp::Shr.is_unsigned());
    }

    #[test]
    fn test_compare_op_negate() {
        assert_eq!(CompareOp::Eq.negate(), CompareOp::Ne);
        assert_eq!(CompareOp::Lt.negate(), CompareOp::Ge);
        assert_eq!(CompareOp::Gt.negate(), CompareOp::Le);
    }

    #[test]
    fn test_compare_op_swap() {
        assert_eq!(CompareOp::Lt.swap(), CompareOp::Gt);
        assert_eq!(CompareOp::Ge.swap(), CompareOp::Le);
        assert_eq!(CompareOp::Eq.swap(), CompareOp::Eq);
    }

    #[test]
    fn test_conversion_type_target_cil_flavor() {
        assert_eq!(ConversionType::I1.target_cil_flavor(), CilFlavor::I4);
        assert_eq!(ConversionType::I8.target_cil_flavor(), CilFlavor::I8);
        assert_eq!(ConversionType::R4.target_cil_flavor(), CilFlavor::R4);
        assert_eq!(ConversionType::R8.target_cil_flavor(), CilFlavor::R8);
        assert_eq!(ConversionType::I.target_cil_flavor(), CilFlavor::I);
    }

    #[test]
    fn test_binary_op_display() {
        assert_eq!(format!("{}", BinaryOp::Add), "add");
        assert_eq!(format!("{}", BinaryOp::AddOvf), "add.ovf");
        assert_eq!(format!("{}", BinaryOp::DivUn), "div.un");
    }

    #[test]
    fn test_unary_op_display() {
        assert_eq!(format!("{}", UnaryOp::Neg), "neg");
        assert_eq!(format!("{}", UnaryOp::Not), "not");
    }

    #[test]
    fn test_compare_op_display() {
        assert_eq!(format!("{}", CompareOp::Eq), "ceq");
        assert_eq!(format!("{}", CompareOp::Lt), "clt");
        assert_eq!(format!("{}", CompareOp::GtUn), "cgt.un");
    }

    #[test]
    fn test_conversion_type_display() {
        assert_eq!(format!("{}", ConversionType::I4), "conv.i4");
        assert_eq!(format!("{}", ConversionType::I8Ovf), "conv.ovf.i8");
        assert_eq!(format!("{}", ConversionType::U4OvfUn), "conv.ovf.u4.un");
    }

    #[test]
    fn test_operation_error_display() {
        let err = EmulationError::DivisionByZero;
        assert_eq!(format!("{}", err), "division by zero");

        let err = EmulationError::ArithmeticOverflow;
        assert_eq!(format!("{}", err), "arithmetic overflow");
    }
}
