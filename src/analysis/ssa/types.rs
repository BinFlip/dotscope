//! SSA type system for .NET CIL types.
//!
//! This module provides a type representation for SSA variables that captures
//! the essential type information needed for analysis and optimization without
//! requiring full metadata resolution.
//!
//! # Design Rationale
//!
//! The `SsaType` enum is designed to be:
//! - **Fast to compare**: Enum variants are faster than token resolution
//! - **Self-contained**: No metadata context needed for basic operations
//! - **Analysis-friendly**: Includes special types like `Unknown` and `Null`
//!
//! # Type Categories
//!
//! - **Primitives**: Fixed-size numeric and boolean types
//! - **References**: Object references, arrays, and pointers
//! - **Special**: Generic parameters and analysis-only types

use std::fmt;

use crate::metadata::token::Token;

/// Reference to a type in metadata.
///
/// This is a lightweight handle that can be resolved to full type information
/// when needed. Used for class types, value types, and generic instantiations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TypeRef(pub Token);

impl TypeRef {
    /// Creates a new type reference from a metadata token.
    #[must_use]
    pub const fn new(token: Token) -> Self {
        Self(token)
    }

    /// Returns the underlying metadata token.
    #[must_use]
    pub const fn token(&self) -> Token {
        self.0
    }
}

impl fmt::Display for TypeRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TypeRef({})", self.0)
    }
}

/// Reference to a method in metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MethodRef(pub Token);

impl MethodRef {
    /// Creates a new method reference from a metadata token.
    #[must_use]
    pub const fn new(token: Token) -> Self {
        Self(token)
    }

    /// Returns the underlying metadata token.
    #[must_use]
    pub const fn token(&self) -> Token {
        self.0
    }
}

impl fmt::Display for MethodRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MethodRef({})", self.0)
    }
}

/// Reference to a field in metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FieldRef(pub Token);

impl FieldRef {
    /// Creates a new field reference from a metadata token.
    #[must_use]
    pub const fn new(token: Token) -> Self {
        Self(token)
    }

    /// Returns the underlying metadata token.
    #[must_use]
    pub const fn token(&self) -> Token {
        self.0
    }
}

impl fmt::Display for FieldRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FieldRef({})", self.0)
    }
}

/// Reference to a standalone signature in metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SigRef(pub Token);

impl SigRef {
    /// Creates a new signature reference from a metadata token.
    #[must_use]
    pub const fn new(token: Token) -> Self {
        Self(token)
    }

    /// Returns the underlying metadata token.
    #[must_use]
    pub const fn token(&self) -> Token {
        self.0
    }
}

impl fmt::Display for SigRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SigRef({})", self.0)
    }
}

/// SSA type representation for CIL types.
///
/// This enum provides a simplified view of .NET types suitable for SSA analysis.
/// It captures the essential type information without requiring full metadata
/// resolution for common operations.
///
/// # Examples
///
/// ```rust,ignore
/// use dotscope::analysis::ssa::SsaType;
///
/// let int_type = SsaType::I32;
/// let string_type = SsaType::String;
/// let array_type = SsaType::Array(Box::new(SsaType::I32), 1);
///
/// assert!(int_type.is_primitive());
/// assert!(string_type.is_reference());
/// assert!(array_type.is_array());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub enum SsaType {
    // ========== Primitives ==========
    /// No return value (void).
    Void,

    /// Boolean type (System.Boolean).
    Bool,

    /// Signed 8-bit integer (System.SByte).
    I8,

    /// Unsigned 8-bit integer (System.Byte).
    U8,

    /// Signed 16-bit integer (System.Int16).
    I16,

    /// Unsigned 16-bit integer (System.UInt16).
    U16,

    /// Signed 32-bit integer (System.Int32).
    I32,

    /// Unsigned 32-bit integer (System.UInt32).
    U32,

    /// Signed 64-bit integer (System.Int64).
    I64,

    /// Unsigned 64-bit integer (System.UInt64).
    U64,

    /// Native-sized signed integer (System.IntPtr).
    NativeInt,

    /// Native-sized unsigned integer (System.UIntPtr).
    NativeUInt,

    /// 32-bit floating point (System.Single).
    F32,

    /// 64-bit floating point (System.Double).
    F64,

    /// Unicode character (System.Char).
    Char,

    // ========== Reference Types ==========
    /// System.Object reference.
    Object,

    /// System.String reference.
    String,

    /// Reference to a specific class type.
    Class(TypeRef),

    /// Value type (struct) - stored inline, not by reference.
    ValueType(TypeRef),

    /// Single-dimensional or multi-dimensional array.
    ///
    /// The `u32` is the rank (number of dimensions). Rank 1 is a vector (SZ array).
    Array(Box<SsaType>, u32),

    /// Unmanaged pointer to a type.
    Pointer(Box<SsaType>),

    /// Managed reference (byref) to a type.
    ByRef(Box<SsaType>),

    // ========== Special Types ==========
    /// Typed reference (System.TypedReference).
    TypedReference,

    /// Generic type parameter (e.g., `!0`, `!1`).
    ///
    /// The `u32` is the parameter index.
    GenericParam(u32),

    /// Generic method parameter (e.g., `!!0`, `!!1`).
    ///
    /// The `u32` is the parameter index.
    MethodGenericParam(u32),

    /// Function pointer type.
    FnPtr(Box<FnPtrSig>),

    // ========== Analysis Types ==========
    /// Known null constant (more precise than Object).
    Null,

    /// Type not yet inferred or unknown.
    ///
    /// This is used during type inference before a type is determined.
    #[default]
    Unknown,

    /// Type that varies depending on control flow (for incomplete inference).
    Varying,
}

/// Function pointer signature.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FnPtrSig {
    /// Return type.
    pub ret: SsaType,
    /// Parameter types.
    pub params: Vec<SsaType>,
    /// Calling convention flags.
    pub call_conv: u8,
}

impl SsaType {
    /// Returns `true` if this is a primitive numeric or boolean type.
    #[must_use]
    pub const fn is_primitive(&self) -> bool {
        matches!(
            self,
            Self::Bool
                | Self::I8
                | Self::U8
                | Self::I16
                | Self::U16
                | Self::I32
                | Self::U32
                | Self::I64
                | Self::U64
                | Self::NativeInt
                | Self::NativeUInt
                | Self::F32
                | Self::F64
                | Self::Char
        )
    }

    /// Returns `true` if this is an integer type (signed or unsigned).
    #[must_use]
    pub const fn is_integer(&self) -> bool {
        matches!(
            self,
            Self::I8
                | Self::U8
                | Self::I16
                | Self::U16
                | Self::I32
                | Self::U32
                | Self::I64
                | Self::U64
                | Self::NativeInt
                | Self::NativeUInt
        )
    }

    /// Returns `true` if this is a floating-point type.
    #[must_use]
    pub const fn is_float(&self) -> bool {
        matches!(self, Self::F32 | Self::F64)
    }

    /// Returns `true` if this is a reference type (can be null).
    #[must_use]
    pub fn is_reference(&self) -> bool {
        matches!(
            self,
            Self::Object | Self::String | Self::Class(_) | Self::Array(_, _) | Self::Null
        )
    }

    /// Returns `true` if this is a value type (struct).
    #[must_use]
    pub const fn is_value_type(&self) -> bool {
        matches!(self, Self::ValueType(_)) || self.is_primitive()
    }

    /// Returns `true` if this is an array type.
    #[must_use]
    pub const fn is_array(&self) -> bool {
        matches!(self, Self::Array(_, _))
    }

    /// Returns `true` if this is a pointer type (managed or unmanaged).
    #[must_use]
    pub const fn is_pointer(&self) -> bool {
        matches!(self, Self::Pointer(_) | Self::ByRef(_))
    }

    /// Returns `true` if this is the void type.
    #[must_use]
    pub const fn is_void(&self) -> bool {
        matches!(self, Self::Void)
    }

    /// Returns `true` if this type is unknown or not yet inferred.
    #[must_use]
    pub const fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown | Self::Varying)
    }

    /// Returns `true` if this is the null type.
    #[must_use]
    pub const fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }

    /// Returns `true` if this is a generic parameter.
    #[must_use]
    pub const fn is_generic_param(&self) -> bool {
        matches!(self, Self::GenericParam(_) | Self::MethodGenericParam(_))
    }

    /// Returns the element type if this is an array.
    #[must_use]
    pub fn array_element_type(&self) -> Option<&SsaType> {
        match self {
            Self::Array(elem, _) => Some(elem),
            _ => None,
        }
    }

    /// Returns the array rank (number of dimensions) if this is an array.
    #[must_use]
    pub const fn array_rank(&self) -> Option<u32> {
        match self {
            Self::Array(_, rank) => Some(*rank),
            _ => None,
        }
    }

    /// Returns the pointed-to type if this is a pointer or byref.
    #[must_use]
    pub fn pointee_type(&self) -> Option<&SsaType> {
        match self {
            Self::Pointer(inner) | Self::ByRef(inner) => Some(inner),
            _ => None,
        }
    }

    /// Returns the size in bytes for primitive types, if known.
    ///
    /// Returns `None` for reference types and types with platform-dependent sizes.
    #[must_use]
    pub const fn size_bytes(&self) -> Option<u32> {
        match self {
            Self::Bool | Self::I8 | Self::U8 => Some(1),
            Self::I16 | Self::U16 | Self::Char => Some(2),
            Self::I32 | Self::U32 | Self::F32 => Some(4),
            Self::I64 | Self::U64 | Self::F64 => Some(8),
            // NativeInt/NativeUInt and pointers are platform-dependent
            _ => None,
        }
    }

    /// Returns the stack slot type for this SSA type.
    ///
    /// CIL uses a normalized set of types on the evaluation stack:
    /// - All integer types smaller than 32 bits become I32
    /// - Float types stay as-is (F32 becomes F64 in some contexts)
    /// - References stay as references
    #[must_use]
    pub fn stack_type(&self) -> SsaType {
        match self {
            // Small integers promote to I32 on the stack
            Self::Bool | Self::I8 | Self::U8 | Self::I16 | Self::U16 | Self::Char | Self::I32 => {
                Self::I32
            }
            Self::U32 => Self::I32, // Treated as I32 on stack
            Self::I64 | Self::U64 => Self::I64,
            Self::NativeInt | Self::NativeUInt => Self::NativeInt,
            Self::F32 | Self::F64 => Self::F64, // F is typically F64 on stack
            // Reference types stay as-is
            _ => self.clone(),
        }
    }

    /// Merges two types at a control flow join point.
    ///
    /// Returns the common type if compatible, or `Varying` if incompatible.
    #[must_use]
    pub fn merge(&self, other: &SsaType) -> SsaType {
        if self == other {
            return self.clone();
        }

        // Unknown can be refined
        if matches!(self, Self::Unknown) {
            return other.clone();
        }
        if matches!(other, Self::Unknown) {
            return self.clone();
        }

        // Null can merge with any reference type
        if matches!(self, Self::Null) && other.is_reference() {
            return other.clone();
        }
        if matches!(other, Self::Null) && self.is_reference() {
            return self.clone();
        }

        // If types are incompatible, return Varying
        Self::Varying
    }
}

impl fmt::Display for SsaType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Void => write!(f, "void"),
            Self::Bool => write!(f, "bool"),
            Self::I8 => write!(f, "i8"),
            Self::U8 => write!(f, "u8"),
            Self::I16 => write!(f, "i16"),
            Self::U16 => write!(f, "u16"),
            Self::I32 => write!(f, "i32"),
            Self::U32 => write!(f, "u32"),
            Self::I64 => write!(f, "i64"),
            Self::U64 => write!(f, "u64"),
            Self::NativeInt => write!(f, "nint"),
            Self::NativeUInt => write!(f, "nuint"),
            Self::F32 => write!(f, "f32"),
            Self::F64 => write!(f, "f64"),
            Self::Char => write!(f, "char"),
            Self::Object => write!(f, "object"),
            Self::String => write!(f, "string"),
            Self::Class(t) => write!(f, "class {t}"),
            Self::ValueType(t) => write!(f, "valuetype {t}"),
            Self::Array(elem, 1) => write!(f, "{elem}[]"),
            Self::Array(elem, rank) => write!(f, "{elem}[{rank}d]"),
            Self::Pointer(inner) => write!(f, "{inner}*"),
            Self::ByRef(inner) => write!(f, "{inner}&"),
            Self::TypedReference => write!(f, "typedref"),
            Self::GenericParam(idx) => write!(f, "!{idx}"),
            Self::MethodGenericParam(idx) => write!(f, "!!{idx}"),
            Self::FnPtr(_) => write!(f, "fnptr"),
            Self::Null => write!(f, "null"),
            Self::Unknown => write!(f, "?"),
            Self::Varying => write!(f, "varying"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_primitive_types() {
        assert!(SsaType::I32.is_primitive());
        assert!(SsaType::F64.is_primitive());
        assert!(SsaType::Bool.is_primitive());
        assert!(!SsaType::Object.is_primitive());
        assert!(!SsaType::String.is_primitive());
    }

    #[test]
    fn test_integer_types() {
        assert!(SsaType::I32.is_integer());
        assert!(SsaType::U64.is_integer());
        assert!(SsaType::NativeInt.is_integer());
        assert!(!SsaType::F32.is_integer());
        assert!(!SsaType::Bool.is_integer());
    }

    #[test]
    fn test_float_types() {
        assert!(SsaType::F32.is_float());
        assert!(SsaType::F64.is_float());
        assert!(!SsaType::I32.is_float());
    }

    #[test]
    fn test_reference_types() {
        assert!(SsaType::Object.is_reference());
        assert!(SsaType::String.is_reference());
        assert!(SsaType::Null.is_reference());
        let array_type = SsaType::Array(Box::new(SsaType::I32), 1);
        assert!(array_type.is_reference());
        assert!(!SsaType::I32.is_reference());
    }

    #[test]
    fn test_array_type() {
        let array = SsaType::Array(Box::new(SsaType::I32), 1);
        assert!(array.is_array());
        assert_eq!(array.array_element_type(), Some(&SsaType::I32));
        assert_eq!(array.array_rank(), Some(1));

        let multi_dim = SsaType::Array(Box::new(SsaType::F64), 3);
        assert_eq!(multi_dim.array_rank(), Some(3));
    }

    #[test]
    fn test_pointer_types() {
        let ptr = SsaType::Pointer(Box::new(SsaType::I32));
        assert!(ptr.is_pointer());
        assert_eq!(ptr.pointee_type(), Some(&SsaType::I32));

        let byref = SsaType::ByRef(Box::new(SsaType::Object));
        assert!(byref.is_pointer());
        assert_eq!(byref.pointee_type(), Some(&SsaType::Object));
    }

    #[test]
    fn test_size_bytes() {
        assert_eq!(SsaType::I8.size_bytes(), Some(1));
        assert_eq!(SsaType::I16.size_bytes(), Some(2));
        assert_eq!(SsaType::I32.size_bytes(), Some(4));
        assert_eq!(SsaType::I64.size_bytes(), Some(8));
        assert_eq!(SsaType::F32.size_bytes(), Some(4));
        assert_eq!(SsaType::F64.size_bytes(), Some(8));
        assert_eq!(SsaType::NativeInt.size_bytes(), None); // Platform-dependent
        assert_eq!(SsaType::Object.size_bytes(), None);
    }

    #[test]
    fn test_stack_type() {
        assert_eq!(SsaType::I8.stack_type(), SsaType::I32);
        assert_eq!(SsaType::I16.stack_type(), SsaType::I32);
        assert_eq!(SsaType::I32.stack_type(), SsaType::I32);
        assert_eq!(SsaType::I64.stack_type(), SsaType::I64);
        assert_eq!(SsaType::F32.stack_type(), SsaType::F64);
    }

    #[test]
    fn test_type_merge() {
        // Same types merge to themselves
        assert_eq!(SsaType::I32.merge(&SsaType::I32), SsaType::I32);

        // Unknown merges with anything
        assert_eq!(SsaType::Unknown.merge(&SsaType::I32), SsaType::I32);
        assert_eq!(SsaType::I32.merge(&SsaType::Unknown), SsaType::I32);

        // Null merges with reference types
        assert_eq!(SsaType::Null.merge(&SsaType::Object), SsaType::Object);
        assert_eq!(SsaType::Object.merge(&SsaType::Null), SsaType::Object);

        // Incompatible types become Varying
        assert_eq!(SsaType::I32.merge(&SsaType::I64), SsaType::Varying);
        assert_eq!(SsaType::Object.merge(&SsaType::I32), SsaType::Varying);
    }

    #[test]
    fn test_display() {
        assert_eq!(format!("{}", SsaType::I32), "i32");
        assert_eq!(format!("{}", SsaType::Object), "object");
        assert_eq!(
            format!("{}", SsaType::Array(Box::new(SsaType::I32), 1)),
            "i32[]"
        );
        assert_eq!(
            format!("{}", SsaType::Pointer(Box::new(SsaType::I32))),
            "i32*"
        );
        assert_eq!(
            format!("{}", SsaType::ByRef(Box::new(SsaType::I32))),
            "i32&"
        );
        assert_eq!(format!("{}", SsaType::GenericParam(0)), "!0");
        assert_eq!(format!("{}", SsaType::MethodGenericParam(1)), "!!1");
    }
}
