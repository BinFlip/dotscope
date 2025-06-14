use crate::metadata::{token::Token, typesystem::ArrayDimensions};

/// Represents a parsed type in various signatures
#[derive(Debug, Clone, PartialEq, Default)]
pub enum TypeSignature {
    #[default]
    /// Not defined
    Unknown,
    /// void
    Void,
    /// bool
    Boolean,
    /// char
    Char,
    /// signed 8bit integer
    I1,
    /// unsigned 8bit integer
    U1,
    /// signed 16bit integer
    I2,
    /// unsigned 16bit integer
    U2,
    /// signed 32bit integer
    I4,
    /// unsigned 32bit integer
    U4,
    /// signed 64bit integer
    I8,
    /// unsigned 64bit integer
    U8,
    /// 32bit floating-point
    R4,
    /// 64bit floating-point
    R8,
    /// System.String
    String,
    /// A pointer to a type
    Ptr(SignaturePointer),
    /// Type by reference
    ByRef(Box<TypeSignature>),
    /// CIL value-type
    // TypeDefOrRefOrSpecEncoded
    ValueType(Token),
    /// CIL Class
    // TypeDefOrRefOrSpecEncoded
    Class(Token),
    /// Generic type parameter
    // Index into GenericParam table
    GenericParamType(u32),
    /// Array
    Array(SignatureArray),
    /// Generic type and its arguments
    GenericInst(Box<TypeSignature>, Vec<TypeSignature>),
    /// Type is referenced during runtime
    TypedByRef,
    /// signed integer, sized to executing platform
    I,
    /// unsigned integer, sized to executing platform
    U,
    /// Function pointer
    FnPtr(Box<SignatureMethod>),
    /// System.Object
    Object,
    /// Single dimension array
    SzArray(SignatureSzArray),
    /// Generic method parameter
    // Index into GenericParam table
    GenericParamMethod(u32),
    /// Required modifier
    // Token to TypeDef | TypeRef
    ModifiedRequired(Vec<Token>),
    /// Optional modifier
    // Token to TypeDef | TypeRef
    ModifiedOptional(Vec<Token>),
    /// Implemented within the CLI
    Internal,
    /// Or'd with following element types
    Modifier,
    /// Sentinel for vararg method signature
    Sentinel,
    /// A pinned type
    Pinned(Box<TypeSignature>),
    /// Indicates an argument of type
    Type,
    /// Used in custom attributes to specify a boxed object
    Boxed,
    /// Reserved
    Reserved,
    /// Used in custom attributes to indicate a field
    Field,
}

/// A pointer to a 'flat' Array
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SignatureArray {
    /// The type in the array
    pub base: Box<TypeSignature>,
    /// The number of dimensions
    pub rank: u32,
    /// The dimensions (can be less than 'rank', are in order from 0..count)
    pub dimensions: Vec<ArrayDimensions>,
}

/// A pointer to a 'flat' Array
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SignatureSzArray {
    /// Custom modifiers - `TypeDefOrRefOrSpecEncoded`
    pub modifiers: Vec<Token>,
    /// The type in the array
    pub base: Box<TypeSignature>,
}

/// A pointer to a type
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SignaturePointer {
    /// Custom modifiers - `TypeDefOrRefOrSpecEncoded`
    pub modifiers: Vec<Token>,
    /// The type pointed to
    pub base: Box<TypeSignature>,
}

/// Parameter with optional custom modifiers
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SignatureParameter {
    /// Custom modifiers of the parameter - `TypeDefOrRefOrSpecEncoded`
    pub modifiers: Vec<Token>,
    /// Parameter is passed by reference
    pub by_ref: bool,
    /// The type of the parameter
    pub base: TypeSignature,
}

/// Represents a method signature (II.23.2.1)
#[derive(Debug, Clone, PartialEq, Default)]
#[allow(clippy::struct_excessive_bools)]
pub struct SignatureMethod {
    /// Used to encode the keyword instance in the calling convention, see §II.15.3
    pub has_this: bool,
    /// Used to encode the keyword explicit in the calling convention, see §II.15.3
    pub explicit_this: bool,
    /// Used to encode the keyword default in the calling convention, see §II.15.3
    pub default: bool,
    /// Used to encode the keyword vararg in the calling convention, see §II.15.3
    pub vararg: bool,
    /// Uses native 'cdelc' calling convention
    pub cdecl: bool,
    /// Uses native 'stdcall' calling convention
    pub stdcall: bool,
    /// Uses native 'thiscall' calling convention
    pub thiscall: bool,
    /// Uses native 'fastcall' calling convention
    pub fastcall: bool,
    /// Used to indicate that the method has one or more generic parameters.
    pub param_count_generic: u32,
    /// Used to indicate the number of `Param` this `Method` has
    pub param_count: u32,
    /// The return type of this `Method`
    pub return_type: SignatureParameter,
    /// The parameters of this `Method`
    pub params: Vec<SignatureParameter>,
    /// The vararg parameters
    pub varargs: Vec<SignatureParameter>,
}

/// Field signature (II.23.2.4)
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SignatureField {
    /// The custom modifiers for this field - `TypeDefOrRefOrSpecEncoded`
    pub modifiers: Vec<Token>,
    /// The signature of this type
    pub base: TypeSignature,
}

/// Property signature (II.23.2.5)
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SignatureProperty {
    /// Indicates the passing of a 'this' pointer
    pub has_this: bool,
    /// The custom modifiers for this field - `TypeDefOrRefOrSpecEncoded`
    pub modifiers: Vec<Token>,
    /// The signature of this property
    pub base: TypeSignature,
    /// The parameters of this property
    pub params: Vec<SignatureParameter>,
}

/// Local variable signature (II.23.2.6)
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SignatureLocalVariables {
    /// The local variables
    pub locals: Vec<SignatureLocalVariable>,
}

/// Represents a local variable in a method body
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SignatureLocalVariable {
    /// Custom modifiers
    pub modifiers: Vec<Token>,
    /// Is passed by reference
    pub is_byref: bool,
    /// This variable is pinned
    pub is_pinned: bool,
    /// The signature of this variable
    pub base: TypeSignature,
}

/// Type specification signature (II.23.2.14)
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SignatureTypeSpec {
    /// Signature of this type
    pub base: TypeSignature,
}

/// Represents a method specification (II.23.2.15)
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SignatureMethodSpec {
    /// Types of the generic arguments
    pub generic_args: Vec<TypeSignature>,
}

impl TypeSignature {
    /// Check if a constant primitive value is compatible with this type signature
    ///
    /// This implements .NET type compatibility rules for constants including:
    /// - Exact type matching for primitives
    /// - Safe widening conversions (e.g., int32 constant to int64 type)
    /// - String constants to Object types
    ///
    /// # Arguments
    /// * `constant` - The constant primitive value to check
    ///
    /// # Returns
    /// `true` if the constant can be assigned to this type signature
    #[must_use]
    #[allow(clippy::unnested_or_patterns)] // Keep patterns separate for readability
    pub fn accepts_constant(&self, constant: &crate::metadata::typesystem::CilPrimitive) -> bool {
        use crate::metadata::typesystem::CilPrimitiveKind;

        match (constant.kind, self) {
            // Exact primitive matches and type conversions - all return true
            // Exact type matches
            (CilPrimitiveKind::Void, TypeSignature::Void)
            | (CilPrimitiveKind::Boolean, TypeSignature::Boolean)
            | (CilPrimitiveKind::Char, TypeSignature::Char)
            | (CilPrimitiveKind::I1, TypeSignature::I1)
            | (CilPrimitiveKind::U1, TypeSignature::U1)
            | (CilPrimitiveKind::I2, TypeSignature::I2)
            | (CilPrimitiveKind::U2, TypeSignature::U2)
            | (CilPrimitiveKind::I4, TypeSignature::I4)
            | (CilPrimitiveKind::U4, TypeSignature::U4)
            | (CilPrimitiveKind::I8, TypeSignature::I8)
            | (CilPrimitiveKind::U8, TypeSignature::U8)
            | (CilPrimitiveKind::R4, TypeSignature::R4)
            | (CilPrimitiveKind::R8, TypeSignature::R8)
            | (CilPrimitiveKind::I, TypeSignature::I)
            | (CilPrimitiveKind::U, TypeSignature::U)
            | (CilPrimitiveKind::String, TypeSignature::String)
            | (CilPrimitiveKind::Object, TypeSignature::Object)
            // Safe widening conversions for signed integers
            | (CilPrimitiveKind::I1, TypeSignature::I2 | TypeSignature::I4 | TypeSignature::I8)
            | (CilPrimitiveKind::I2, TypeSignature::I4 | TypeSignature::I8)
            | (CilPrimitiveKind::I4, TypeSignature::I8)
            // Safe widening conversions for unsigned integers
            | (CilPrimitiveKind::U1, TypeSignature::U2 | TypeSignature::U4 | TypeSignature::U8)
            | (CilPrimitiveKind::U2, TypeSignature::U4 | TypeSignature::U8)
            | (CilPrimitiveKind::U4, TypeSignature::U8)
            // Float widening
            | (CilPrimitiveKind::R4, TypeSignature::R8)
            // Integer to float (with potential precision loss, but allowed for constants)
            | (
                CilPrimitiveKind::I1
                | CilPrimitiveKind::U1
                | CilPrimitiveKind::I2
                | CilPrimitiveKind::U2
                | CilPrimitiveKind::I4,
                TypeSignature::R4 | TypeSignature::R8,
            )
            | (
                CilPrimitiveKind::I8 | CilPrimitiveKind::U4 | CilPrimitiveKind::U8,
                TypeSignature::R8,
            )
            // String constants to Object
            | (CilPrimitiveKind::String, TypeSignature::Object)
            // Null and Class constants can be assigned to any reference type
            | (
                CilPrimitiveKind::Null | CilPrimitiveKind::Class,
                TypeSignature::String | TypeSignature::Object,
            )
            // For complex types (Class, ValueType, etc.), we can't easily validate without
            // full type resolution, so we allow them (conservative approach)
            // Note: This also covers Null and Class constants to complex types
            | (_, TypeSignature::Class(_) | TypeSignature::ValueType(_)) => true,

            // All other combinations are incompatible
            _ => false,
        }
    }
}
