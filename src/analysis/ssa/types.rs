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

use crate::metadata::{
    cilobject::CilObject,
    method::Method,
    signatures::{
        CustomModifiers, SignatureArray, SignatureLocalVariable, SignatureMethod,
        SignatureParameter, SignaturePointer, SignatureSzArray, TypeSignature,
    },
    tables::{MemberRefSignature, StandAloneSigRaw, StandAloneSignature},
    token::Token,
    typesystem::{ArrayDimensions, CilFlavor},
};

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
/// ```rust,no_run
/// use dotscope::analysis::SsaType;
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

    // ========== Runtime Handle Types ==========
    /// Runtime type handle (System.RuntimeTypeHandle).
    ///
    /// Result of `ldtoken` on a type. Used with `Type.GetTypeFromHandle()`.
    RuntimeTypeHandle,

    /// Runtime method handle (System.RuntimeMethodHandle).
    ///
    /// Result of `ldtoken` on a method. Used with `MethodBase.GetMethodFromHandle()`.
    RuntimeMethodHandle,

    /// Runtime field handle (System.RuntimeFieldHandle).
    ///
    /// Result of `ldtoken` on a field. Used with `FieldInfo.GetFieldFromHandle()`.
    RuntimeFieldHandle,

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

/// Classification of types by their storage requirements.
///
/// Used for local variable coalescing to determine which types can share
/// the same storage slot. Types in the same class can be coalesced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum TypeClass {
    /// 32-bit integer types (I32, U32, Bool, Char, I16, U16, I8, U8).
    ///
    /// All these types are stored as 4 bytes on the CLR evaluation stack.
    Int32,
    /// 64-bit integer types (I64, U64).
    Int64,
    /// 32-bit floating point (F32).
    Float32,
    /// 64-bit floating point (F64).
    Float64,
    /// Reference types (Object, String, Class, Array, etc.).
    ///
    /// All reference types are pointer-sized.
    Reference,
    /// Native-sized integers (IntPtr, UIntPtr).
    ///
    /// Platform-dependent size (4 or 8 bytes).
    NativeInt,
    /// Other/unknown types that cannot be coalesced.
    Other,
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

    /// Returns the storage class of this type.
    ///
    /// Used for local variable coalescing to determine which types can share
    /// the same storage slot without requiring conversion.
    #[must_use]
    pub fn storage_class(&self) -> TypeClass {
        match self {
            // 32-bit integers (all stored as 4 bytes on the CLR stack)
            Self::I32
            | Self::U32
            | Self::Bool
            | Self::Char
            | Self::I16
            | Self::U16
            | Self::I8
            | Self::U8 => TypeClass::Int32,

            // 64-bit integers
            Self::I64 | Self::U64 => TypeClass::Int64,

            // Floating point
            Self::F32 => TypeClass::Float32,
            Self::F64 => TypeClass::Float64,

            // Native integers
            Self::NativeInt | Self::NativeUInt => TypeClass::NativeInt,

            // Reference types and value types (all pointer-sized on stack)
            Self::Object
            | Self::String
            | Self::Class(_)
            | Self::ValueType(_)
            | Self::Array(_, _)
            | Self::ByRef(_)
            | Self::Pointer(_)
            | Self::TypedReference
            | Self::RuntimeTypeHandle
            | Self::RuntimeMethodHandle
            | Self::RuntimeFieldHandle => TypeClass::Reference,

            // Other types
            Self::Void
            | Self::Unknown
            | Self::Varying
            | Self::Null
            | Self::GenericParam(_)
            | Self::MethodGenericParam(_)
            | Self::FnPtr(_) => TypeClass::Other,
        }
    }

    /// Checks if this type can share a local slot with another type.
    ///
    /// Two types are compatible for storage if they have the same size and
    /// alignment requirements, meaning they can be stored in the same local
    /// variable slot without data corruption.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::analysis::SsaType;
    ///
    /// // Same types are compatible
    /// assert!(SsaType::I32.is_compatible_for_storage(&SsaType::I32));
    ///
    /// // 32-bit integers can share slots
    /// assert!(SsaType::I32.is_compatible_for_storage(&SsaType::U32));
    /// assert!(SsaType::I32.is_compatible_for_storage(&SsaType::Bool));
    ///
    /// // Reference types can share slots
    /// assert!(SsaType::Object.is_compatible_for_storage(&SsaType::String));
    ///
    /// // Different sizes are incompatible
    /// assert!(!SsaType::I32.is_compatible_for_storage(&SsaType::I64));
    /// ```
    #[must_use]
    pub fn is_compatible_for_storage(&self, other: &SsaType) -> bool {
        if self == other {
            return true;
        }

        // Unknown types are conservatively compatible
        if matches!(self, Self::Unknown) || matches!(other, Self::Unknown) {
            return true;
        }

        // Same storage class means compatible
        matches!(
            (self.storage_class(), other.storage_class()),
            (TypeClass::Int32, TypeClass::Int32)
                | (TypeClass::Int64, TypeClass::Int64)
                | (TypeClass::Float32, TypeClass::Float32)
                | (TypeClass::Float64, TypeClass::Float64)
                | (TypeClass::Reference, TypeClass::Reference)
                | (TypeClass::NativeInt, TypeClass::NativeInt)
        )
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

    /// Converts this SSA type to a `TypeSignature` for signature encoding.
    ///
    /// This enables generating local variable signatures from SSA type information.
    /// Analysis-only types (`Unknown`, `Null`, `Varying`) are converted to `Object`
    /// as a safe fallback.
    ///
    /// # Returns
    ///
    /// The corresponding `TypeSignature` that can be used for signature encoding.
    #[must_use]
    pub fn to_type_signature(&self) -> TypeSignature {
        match self {
            Self::Void => TypeSignature::Void,
            Self::Bool => TypeSignature::Boolean,
            Self::I8 => TypeSignature::I1,
            Self::U8 => TypeSignature::U1,
            Self::I16 => TypeSignature::I2,
            Self::U16 => TypeSignature::U2,
            Self::I32 => TypeSignature::I4,
            Self::U32 => TypeSignature::U4,
            Self::I64 => TypeSignature::I8,
            Self::U64 => TypeSignature::U8,
            Self::NativeInt => TypeSignature::I,
            Self::NativeUInt => TypeSignature::U,
            Self::F32 => TypeSignature::R4,
            Self::F64 => TypeSignature::R8,
            Self::Char => TypeSignature::Char,
            Self::String => TypeSignature::String,
            Self::Class(type_ref) => TypeSignature::Class(type_ref.token()),
            Self::ValueType(type_ref) => TypeSignature::ValueType(type_ref.token()),
            Self::Array(elem, 1) => TypeSignature::SzArray(SignatureSzArray {
                modifiers: CustomModifiers::default(),
                base: Box::new(elem.to_type_signature()),
            }),
            Self::Array(elem, rank) => TypeSignature::Array(SignatureArray {
                base: Box::new(elem.to_type_signature()),
                rank: *rank,
                dimensions: (0..*rank)
                    .map(|_| ArrayDimensions {
                        size: None,
                        lower_bound: None,
                    })
                    .collect(),
            }),
            Self::Pointer(inner) => TypeSignature::Ptr(SignaturePointer {
                modifiers: CustomModifiers::default(),
                base: Box::new(inner.to_type_signature()),
            }),
            Self::ByRef(inner) => TypeSignature::ByRef(Box::new(inner.to_type_signature())),
            Self::TypedReference => TypeSignature::TypedByRef,
            Self::GenericParam(idx) => TypeSignature::GenericParamType(*idx),
            Self::MethodGenericParam(idx) => TypeSignature::GenericParamMethod(*idx),
            Self::FnPtr(sig) => TypeSignature::FnPtr(Box::new(SignatureMethod {
                has_this: false,
                explicit_this: false,
                default: true,
                vararg: false,
                cdecl: false,
                stdcall: false,
                thiscall: false,
                fastcall: false,
                param_count_generic: 0,
                param_count: sig.params.len() as u32,
                return_type: SignatureParameter {
                    modifiers: CustomModifiers::default(),
                    by_ref: false,
                    base: sig.ret.to_type_signature(),
                },
                params: sig
                    .params
                    .iter()
                    .map(|p| SignatureParameter {
                        modifiers: CustomModifiers::default(),
                        by_ref: false,
                        base: p.to_type_signature(),
                    })
                    .collect(),
                varargs: Vec::new(),
            })),
            // Object and analysis-only types (runtime handles would need BCL resolution)
            Self::Object
            | Self::Null
            | Self::Unknown
            | Self::Varying
            | Self::RuntimeTypeHandle
            | Self::RuntimeMethodHandle
            | Self::RuntimeFieldHandle => TypeSignature::Object,
        }
    }

    /// Creates an `SsaType` from a `CilFlavor`.
    ///
    /// This converts the metadata type flavor to the SSA type representation.
    /// For complex types (arrays, pointers, generic instances), a token is needed
    /// to create a proper type reference.
    ///
    /// # Arguments
    ///
    /// * `flavor` - The CIL type flavor to convert
    /// * `token` - The metadata token for creating type references
    #[must_use]
    pub fn from_cil_flavor(flavor: &CilFlavor, token: Token) -> Self {
        match flavor {
            // Primitive types
            CilFlavor::Void => Self::Void,
            CilFlavor::Boolean => Self::Bool,
            CilFlavor::Char => Self::Char,
            CilFlavor::I1 => Self::I8,
            CilFlavor::U1 => Self::U8,
            CilFlavor::I2 => Self::I16,
            CilFlavor::U2 => Self::U16,
            CilFlavor::I4 => Self::I32,
            CilFlavor::U4 => Self::U32,
            CilFlavor::I8 => Self::I64,
            CilFlavor::U8 => Self::U64,
            CilFlavor::R4 => Self::F32,
            CilFlavor::R8 => Self::F64,
            CilFlavor::I => Self::NativeInt,
            CilFlavor::U => Self::NativeUInt,
            CilFlavor::Object => Self::Object,
            CilFlavor::String => Self::String,

            // Complex types
            CilFlavor::Array { rank, .. } => Self::Array(Box::new(Self::Unknown), *rank),
            CilFlavor::Pointer => Self::Pointer(Box::new(Self::Unknown)),
            CilFlavor::ByRef => Self::ByRef(Box::new(Self::Unknown)),
            CilFlavor::GenericParameter { index, method } => {
                if *method {
                    Self::MethodGenericParam(*index)
                } else {
                    Self::GenericParam(*index)
                }
            }

            // Type categories
            CilFlavor::GenericInstance | CilFlavor::Class | CilFlavor::Interface => {
                Self::Class(TypeRef::new(token))
            }
            // ValueType and TypedReference (which is a value type)
            CilFlavor::ValueType | CilFlavor::TypedRef { .. } => {
                Self::ValueType(TypeRef::new(token))
            }

            CilFlavor::Pinned | CilFlavor::FnPtr { .. } | CilFlavor::Unknown => Self::Unknown,
        }
    }

    /// Creates an `SsaType` from a `TypeSignature`.
    ///
    /// This converts a metadata type signature to the SSA type representation.
    /// For class and value types, the assembly context is used to resolve
    /// type tokens to determine if they are primitives.
    ///
    /// # Arguments
    ///
    /// * `signature` - The type signature to convert
    /// * `assembly` - Assembly context for resolving type tokens
    #[must_use]
    pub fn from_type_signature(signature: &TypeSignature, assembly: &CilObject) -> Self {
        match signature {
            // Primitive types
            TypeSignature::Void => Self::Void,
            TypeSignature::Boolean => Self::Bool,
            TypeSignature::Char => Self::Char,
            TypeSignature::I1 => Self::I8,
            TypeSignature::U1 => Self::U8,
            TypeSignature::I2 => Self::I16,
            TypeSignature::U2 => Self::U16,
            TypeSignature::I4 => Self::I32,
            TypeSignature::U4 => Self::U32,
            TypeSignature::I8 => Self::I64,
            TypeSignature::U8 => Self::U64,
            TypeSignature::R4 => Self::F32,
            TypeSignature::R8 => Self::F64,
            TypeSignature::I => Self::NativeInt,
            TypeSignature::U => Self::NativeUInt,

            // Reference types
            TypeSignature::String => Self::String,
            TypeSignature::Object | TypeSignature::Type | TypeSignature::Boxed => Self::Object,
            TypeSignature::TypedByRef => Self::TypedReference,

            // Class/ValueType with token
            TypeSignature::Class(token) | TypeSignature::ValueType(token) => {
                Self::from_type_token(*token, assembly)
            }

            // Arrays
            TypeSignature::SzArray(sz_array) => {
                let elem_type = Self::from_type_signature(&sz_array.base, assembly);
                Self::Array(Box::new(elem_type), 1)
            }
            TypeSignature::Array(array) => {
                let elem_type = Self::from_type_signature(&array.base, assembly);
                Self::Array(Box::new(elem_type), array.rank)
            }

            // Pointers and references
            TypeSignature::Ptr(ptr) => {
                let inner = Self::from_type_signature(&ptr.base, assembly);
                Self::Pointer(Box::new(inner))
            }
            TypeSignature::ByRef(inner) => {
                let inner_type = Self::from_type_signature(inner, assembly);
                Self::ByRef(Box::new(inner_type))
            }

            // Generic parameters
            TypeSignature::GenericParamType(index) => Self::GenericParam(*index),
            TypeSignature::GenericParamMethod(index) => Self::MethodGenericParam(*index),

            // Generic instantiation
            TypeSignature::GenericInst(base_type, _type_args) => {
                Self::from_type_signature(base_type, assembly)
            }

            // Pinned - unwrap to inner type
            TypeSignature::Pinned(inner) => Self::from_type_signature(inner, assembly),

            // Function pointers, modifiers, and special types - not representable
            TypeSignature::FnPtr(_)
            | TypeSignature::ModifiedRequired(_)
            | TypeSignature::ModifiedOptional(_)
            | TypeSignature::Sentinel
            | TypeSignature::Unknown
            | TypeSignature::Internal
            | TypeSignature::Modifier
            | TypeSignature::Reserved
            | TypeSignature::Field => Self::Unknown,
        }
    }

    /// Creates an `SsaType` from a type token by resolving it in the assembly.
    ///
    /// Handles TypeDef (0x02), TypeRef (0x01), and TypeSpec (0x1B) tokens.
    #[must_use]
    pub fn from_type_token(token: Token, assembly: &CilObject) -> Self {
        let table_id = token.table();

        match table_id {
            // TypeDef or TypeRef - look up in type registry
            0x02 | 0x01 => {
                let Some(cil_type) = assembly.types().get(&token) else {
                    return Self::Unknown;
                };

                let name = &cil_type.name;
                let namespace = &cil_type.namespace;

                // Check for well-known primitive types in System namespace
                if namespace == "System" {
                    if let Some(primitive) = Self::match_system_type(name) {
                        return primitive;
                    }
                }

                // Return Class or ValueType based on flavor
                if cil_type.flavor().is_value_type() {
                    Self::ValueType(TypeRef::new(token))
                } else {
                    Self::Class(TypeRef::new(token))
                }
            }

            // TypeSpec - generic instantiation or complex type
            0x1B => {
                let Some(typespec) = assembly.types().get(&token) else {
                    return Self::Unknown;
                };
                Self::from_cil_flavor(typespec.flavor(), token)
            }

            // Unknown table
            _ => Self::Unknown,
        }
    }

    /// Matches a System namespace type name to its SSA primitive type.
    fn match_system_type(name: &str) -> Option<Self> {
        match name {
            "Void" => Some(Self::Void),
            "Boolean" => Some(Self::Bool),
            "Char" => Some(Self::Char),
            "SByte" => Some(Self::I8),
            "Byte" => Some(Self::U8),
            "Int16" => Some(Self::I16),
            "UInt16" => Some(Self::U16),
            "Int32" => Some(Self::I32),
            "UInt32" => Some(Self::U32),
            "Int64" => Some(Self::I64),
            "UInt64" => Some(Self::U64),
            "Single" => Some(Self::F32),
            "Double" => Some(Self::F64),
            "IntPtr" => Some(Self::NativeInt),
            "UIntPtr" => Some(Self::NativeUInt),
            "String" => Some(Self::String),
            "Object" => Some(Self::Object),
            "TypedReference" => Some(Self::TypedReference),
            _ => None,
        }
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
            Self::RuntimeTypeHandle => write!(f, "RuntimeTypeHandle"),
            Self::RuntimeMethodHandle => write!(f, "RuntimeMethodHandle"),
            Self::RuntimeFieldHandle => write!(f, "RuntimeFieldHandle"),
            Self::Null => write!(f, "null"),
            Self::Unknown => write!(f, "?"),
            Self::Varying => write!(f, "varying"),
        }
    }
}

/// Provides type information during SSA construction.
///
/// This struct holds references to the method being converted and the containing
/// assembly, allowing type lookups for arguments, locals, and call return types
/// without duplicating type information.
///
/// # Usage
///
/// ```rust,ignore
/// let ctx = TypeContext::new(&method, &assembly);
/// let arg0_type = ctx.arg_type(0);
/// let local2_type = ctx.local_type(2);
/// let ret_type = ctx.call_return_type(call_token);
/// ```
pub struct TypeContext<'a> {
    /// The method being converted to SSA form.
    method: &'a Method,
    /// The assembly containing the method.
    assembly: &'a CilObject,
}

impl<'a> TypeContext<'a> {
    /// Creates a new type context for SSA construction.
    #[must_use]
    pub fn new(method: &'a Method, assembly: &'a CilObject) -> Self {
        Self { method, assembly }
    }

    /// Returns the assembly reference.
    #[must_use]
    pub fn assembly(&self) -> &'a CilObject {
        self.assembly
    }

    /// Returns the type of a method argument by index.
    ///
    /// For instance methods, argument 0 is `this`. Parameter indices are offset
    /// by 1 for instance methods.
    #[must_use]
    pub fn arg_type(&self, idx: u16) -> SsaType {
        let idx = idx as usize;

        // For instance methods, arg 0 is 'this'
        if self.method.signature.has_this {
            if idx == 0 {
                // 'this' pointer - get type from declaring class
                return self
                    .method
                    .declaring_type
                    .get()
                    .and_then(|dt| dt.token())
                    .map(|token| SsaType::Class(TypeRef::new(token)))
                    .unwrap_or(SsaType::Object);
            }
            // Adjust for 'this' offset
            if let Some(param) = self.method.signature.params.get(idx - 1) {
                return SsaType::from_type_signature(&param.base, self.assembly);
            }
        } else if let Some(param) = self.method.signature.params.get(idx) {
            return SsaType::from_type_signature(&param.base, self.assembly);
        }

        SsaType::Unknown
    }

    /// Returns the type of a local variable by index.
    #[must_use]
    pub fn local_type(&self, idx: u16) -> SsaType {
        self.method
            .get_local_type_signatures()
            .and_then(|types| types.into_iter().nth(idx as usize))
            .map(|sig| SsaType::from_type_signature(&sig.base, self.assembly))
            .unwrap_or(SsaType::Unknown)
    }

    /// Returns the return type of a called method.
    ///
    /// Handles MethodDef (0x06), MemberRef (0x0A), and MethodSpec (0x2B) tokens.
    #[must_use]
    pub fn call_return_type(&self, token: Token) -> SsaType {
        let table_id = token.table();

        match table_id {
            // MethodDef - look up in methods
            0x06 => self
                .assembly
                .methods()
                .get(&token)
                .map(|entry| {
                    let method = entry.value();
                    SsaType::from_type_signature(&method.signature.return_type.base, self.assembly)
                })
                .unwrap_or(SsaType::Unknown),

            // MemberRef - look up and get signature
            0x0A => self
                .assembly
                .refs_members()
                .get(&token)
                .and_then(|entry| {
                    let member_ref = entry.value();
                    match &member_ref.signature {
                        MemberRefSignature::Method(sig) => Some(SsaType::from_type_signature(
                            &sig.return_type.base,
                            self.assembly,
                        )),
                        MemberRefSignature::Field(_) => None,
                    }
                })
                .unwrap_or(SsaType::Unknown),

            // MethodSpec - resolve to underlying method and get its return type
            0x2B => self
                .assembly
                .method_specs()
                .get(&token)
                .and_then(|entry| entry.value().method.token())
                .map(|method_token| self.call_return_type(method_token))
                .unwrap_or(SsaType::Unknown),

            _ => SsaType::Unknown,
        }
    }

    /// Returns the type of a newly constructed object (for newobj instruction).
    ///
    /// Extracts the declaring type from the constructor method token.
    #[must_use]
    pub fn newobj_type(&self, ctor_token: Token) -> SsaType {
        let table_id = ctor_token.table();

        match table_id {
            // MethodDef - get declaring type
            0x06 => self
                .assembly
                .methods()
                .get(&ctor_token)
                .and_then(|entry| {
                    entry
                        .value()
                        .declaring_type
                        .get()
                        .and_then(|cil_type| cil_type.token())
                })
                .map(|type_token| SsaType::Class(TypeRef::new(type_token)))
                .unwrap_or(SsaType::Object),

            // MemberRef - get declaring type from member ref
            0x0A => self
                .assembly
                .refs_members()
                .get(&ctor_token)
                .and_then(|entry| entry.value().declaredby.token())
                .map(|class_token| SsaType::from_type_token(class_token, self.assembly))
                .unwrap_or(SsaType::Object),

            // MethodSpec - resolve to underlying constructor
            0x2B => self
                .assembly
                .method_specs()
                .get(&ctor_token)
                .and_then(|entry| entry.value().method.token())
                .map(|method_token| self.newobj_type(method_token))
                .unwrap_or(SsaType::Object),

            _ => SsaType::Object,
        }
    }

    /// Returns the type of a field.
    ///
    /// Looks up the field's type signature from the assembly metadata.
    #[must_use]
    pub fn field_type(&self, field_token: Token) -> SsaType {
        let table_id = field_token.table();

        match table_id {
            // Field table (0x04) - look up through type registry
            0x04 => self
                .assembly
                .types()
                .get_field_signature(&field_token)
                .map(|sig| SsaType::from_type_signature(&sig, self.assembly))
                .unwrap_or(SsaType::Unknown),

            // MemberRef table (0x0A) - external field reference
            0x0A => self
                .assembly
                .refs_members()
                .get(&field_token)
                .and_then(|entry| {
                    if let MemberRefSignature::Field(field_sig) = &entry.value().signature {
                        Some(SsaType::from_type_signature(&field_sig.base, self.assembly))
                    } else {
                        None
                    }
                })
                .unwrap_or(SsaType::Unknown),

            _ => SsaType::Unknown,
        }
    }

    /// Returns the return type of a `calli` (indirect call) from its `StandAloneSig` token.
    ///
    /// Resolves the standalone method signature referenced by the token and extracts
    /// the return type. Returns `SsaType::Unknown` on any resolution failure.
    #[must_use]
    pub fn call_indirect_return_type(&self, sig_token: Token) -> SsaType {
        // StandAloneSig table is 0x11
        if sig_token.table() != 0x11 {
            return SsaType::Unknown;
        }
        let Some(tables) = self.assembly.tables() else {
            return SsaType::Unknown;
        };
        let Some(table) = tables.table::<StandAloneSigRaw>() else {
            return SsaType::Unknown;
        };
        let Some(raw) = table.get(sig_token.row()) else {
            return SsaType::Unknown;
        };
        let Some(blob) = self.assembly.blob() else {
            return SsaType::Unknown;
        };
        let Ok(owned) = raw.to_owned(blob) else {
            return SsaType::Unknown;
        };
        match &owned.parsed_signature {
            StandAloneSignature::Method(sig) => {
                SsaType::from_type_signature(&sig.return_type.base, self.assembly)
            }
            _ => SsaType::Unknown,
        }
    }

    /// Returns the original local variable type signatures for code generation.
    ///
    /// This provides the full `SignatureLocalVariable` information (including
    /// pinned and custom modifiers) needed when regenerating CIL code.
    #[must_use]
    pub fn local_type_signatures(&self) -> Option<Vec<SignatureLocalVariable>> {
        self.method.get_local_type_signatures()
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

    #[test]
    fn test_storage_class() {
        // 32-bit integers
        assert_eq!(SsaType::I32.storage_class(), TypeClass::Int32);
        assert_eq!(SsaType::U32.storage_class(), TypeClass::Int32);
        assert_eq!(SsaType::Bool.storage_class(), TypeClass::Int32);
        assert_eq!(SsaType::Char.storage_class(), TypeClass::Int32);
        assert_eq!(SsaType::I8.storage_class(), TypeClass::Int32);

        // 64-bit integers
        assert_eq!(SsaType::I64.storage_class(), TypeClass::Int64);
        assert_eq!(SsaType::U64.storage_class(), TypeClass::Int64);

        // Floats
        assert_eq!(SsaType::F32.storage_class(), TypeClass::Float32);
        assert_eq!(SsaType::F64.storage_class(), TypeClass::Float64);

        // Native integers
        assert_eq!(SsaType::NativeInt.storage_class(), TypeClass::NativeInt);
        assert_eq!(SsaType::NativeUInt.storage_class(), TypeClass::NativeInt);

        // Reference types
        assert_eq!(SsaType::Object.storage_class(), TypeClass::Reference);
        assert_eq!(SsaType::String.storage_class(), TypeClass::Reference);
        assert_eq!(
            SsaType::Array(Box::new(SsaType::I32), 1).storage_class(),
            TypeClass::Reference
        );

        // Other
        assert_eq!(SsaType::Void.storage_class(), TypeClass::Other);
        assert_eq!(SsaType::Unknown.storage_class(), TypeClass::Other);
    }

    #[test]
    fn test_is_compatible_for_storage() {
        // Same types are compatible
        assert!(SsaType::I32.is_compatible_for_storage(&SsaType::I32));

        // 32-bit integers are compatible with each other
        assert!(SsaType::I32.is_compatible_for_storage(&SsaType::U32));
        assert!(SsaType::I32.is_compatible_for_storage(&SsaType::Bool));
        assert!(SsaType::I32.is_compatible_for_storage(&SsaType::Char));

        // 64-bit integers are compatible
        assert!(SsaType::I64.is_compatible_for_storage(&SsaType::U64));

        // Reference types are compatible
        assert!(SsaType::Object.is_compatible_for_storage(&SsaType::String));

        // Unknown is compatible with anything
        assert!(SsaType::Unknown.is_compatible_for_storage(&SsaType::I32));
        assert!(SsaType::I32.is_compatible_for_storage(&SsaType::Unknown));

        // Different classes are not compatible
        assert!(!SsaType::I32.is_compatible_for_storage(&SsaType::I64));
        assert!(!SsaType::I32.is_compatible_for_storage(&SsaType::Object));
        assert!(!SsaType::F32.is_compatible_for_storage(&SsaType::F64));
    }
}
