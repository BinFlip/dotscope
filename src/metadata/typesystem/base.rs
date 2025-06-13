use std::{sync::Arc, sync::Weak};

use crate::{
    metadata::{
        method::MethodRef,
        signatures::SignatureMethod,
        streams::{
            AssemblyRc, AssemblyRefRc, DeclSecurityRc, EventRc, ExportedTypeRc, FieldRc, FileRc,
            GenericParamConstraintRc, GenericParamRc, InterfaceImplRc, MemberRefRc, MethodSpecList,
            MethodSpecRc, ModuleRc, ModuleRefRc, ParamRc, PropertyRc, StandAloneSigRc,
        },
        typesystem::{CilPrimitive, CilPrimitiveKind, CilType, CilTypeRc},
    },
    prelude::{GenericParamList, Token},
};

/// A vector that holds `CilTypeRef` instances (weak references)
pub type CilTypeRefList = Arc<boxcar::Vec<CilTypeRef>>;

/// A smart reference to a `CilType` that automatically handles weak references
/// to prevent circular reference memory leaks while providing a clean API
#[derive(Clone, Debug)]
pub struct CilTypeRef {
    weak_ref: Weak<CilType>,
}

impl CilTypeRef {
    /// Create a new `CilTypeRef` from a strong reference
    pub fn new(strong_ref: &CilTypeRc) -> Self {
        Self {
            weak_ref: Arc::downgrade(strong_ref),
        }
    }

    /// Get a strong reference to the type, returning None if the type has been dropped
    #[must_use]
    pub fn upgrade(&self) -> Option<CilTypeRc> {
        self.weak_ref.upgrade()
    }

    /// Get a strong reference to the type, panicking if the type has been dropped
    /// Use this when you're certain the type should still exist
    ///
    /// # Panics
    /// Panics if the type has been dropped and the weak reference cannot be upgraded.
    #[must_use]
    pub fn expect(&self, msg: &str) -> CilTypeRc {
        self.weak_ref.upgrade().expect(msg)
    }

    /// Check if the referenced type is still alive
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.weak_ref.strong_count() > 0
    }

    // ToDo: These accessors are inefficient, creating copies in exchange for a clean API.
    /// Get the token of the referenced type (if still alive)
    #[must_use]
    pub fn token(&self) -> Option<Token> {
        self.upgrade().map(|t| t.token)
    }

    /// Get the name of the referenced type (if still alive)
    #[must_use]
    pub fn name(&self) -> Option<String> {
        self.upgrade().map(|t| t.name.clone())
    }

    /// Get the namespace of the referenced type (if still alive)
    #[must_use]
    pub fn namespace(&self) -> Option<String> {
        self.upgrade().map(|t| t.namespace.clone())
    }

    /// Get the `nested_types` collection of the referenced type (if still alive)
    #[must_use]
    pub fn nested_types(&self) -> Option<CilTypeRefList> {
        self.upgrade().map(|t| t.nested_types.clone())
    }

    /// Get the `generic_params` collection of the referenced type (if still alive)
    #[must_use]
    pub fn generic_params(&self) -> Option<GenericParamList> {
        self.upgrade().map(|t| t.generic_params.clone())
    }

    /// Get the `generic_args` collection of the referenced type (if still alive)
    #[must_use]
    pub fn generic_args(&self) -> Option<MethodSpecList> {
        self.upgrade().map(|t| t.generic_args.clone())
    }

    /// Check if this type reference is compatible with another type
    ///
    /// # Arguments
    /// * `other` - The other type to check compatibility against
    ///
    /// # Returns
    /// `true` if this type is compatible with the other type, `false` if incompatible or if the reference is invalid
    #[must_use]
    pub fn is_compatible_with(&self, other: &CilType) -> bool {
        if let Some(this_type) = self.upgrade() {
            this_type.is_compatible_with(other)
        } else {
            false
        }
    }

    /// Check if this type reference can accept a constant value
    ///
    /// # Arguments  
    /// * `constant` - The constant value to check
    ///
    /// # Returns
    /// `true` if this type can accept the constant, `false` if not or if the reference is invalid
    #[must_use]
    pub fn accepts_constant(&self, constant: &CilPrimitive) -> bool {
        if let Some(this_type) = self.upgrade() {
            this_type.accepts_constant(constant)
        } else {
            false
        }
    }
}

impl From<CilTypeRc> for CilTypeRef {
    fn from(strong_ref: CilTypeRc) -> Self {
        Self::new(&strong_ref)
    }
}

/// A single dimension of an array
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ArrayDimensions {
    /// The size of this dimension
    pub size: Option<u32>,
    /// The lower bound of this dimension (lowest index that can be used to access an element)
    pub lower_bound: Option<u32>,
}

#[allow(missing_docs)]
#[derive(Clone)]
/// Represents a reference to a table type item (which is fully resolved and owns the data)
/// Similar to `CodedIndex` but with resolved rerefences
pub enum CilTypeReference {
    TypeRef(CilTypeRef),
    TypeDef(CilTypeRef),
    TypeSpec(CilTypeRef),
    Field(FieldRc),
    Param(ParamRc),
    Property(PropertyRc),
    MethodDef(MethodRef),
    InterfaceImpl(InterfaceImplRc),
    MemberRef(MemberRefRc),
    Module(ModuleRc),
    DeclSecurity(DeclSecurityRc),
    Event(EventRc),
    StandAloneSig(StandAloneSigRc),
    ModuleRef(ModuleRefRc),
    Assembly(AssemblyRc),
    AssemblyRef(AssemblyRefRc),
    File(FileRc),
    ExportedType(ExportedTypeRc),
    //ManifestResource(ManifestResourceRc),
    GenericParam(GenericParamRc),
    GenericParamConstraint(GenericParamConstraintRc),
    MethodSpec(MethodSpecRc),
    None,
}

#[allow(non_snake_case, dead_code, missing_docs)]
/// Possible bytes that represent varioud 'Types' for a signature - from coreclr
pub mod ELEMENT_TYPE {
    //Marks end of a list
    pub const END: u8 = 0x00;
    pub const VOID: u8 = 0x01;
    pub const BOOLEAN: u8 = 0x02;
    pub const CHAR: u8 = 0x03;
    pub const I1: u8 = 0x04;
    pub const U1: u8 = 0x05;
    pub const I2: u8 = 0x06;
    pub const U2: u8 = 0x07;
    pub const I4: u8 = 0x08;
    pub const U4: u8 = 0x09;
    pub const I8: u8 = 0x0a;
    pub const U8: u8 = 0x0b;
    pub const R4: u8 = 0x0c;
    pub const R8: u8 = 0x0d;
    pub const STRING: u8 = 0x0e;
    // Followed by type
    pub const PTR: u8 = 0x0f;
    // Followed by type
    pub const BYREF: u8 = 0x10;
    // Followed by TypeDef or TypeRef token
    pub const VALUETYPE: u8 = 0x11;
    // Followed by TypeDef or TypeRef token
    pub const CLASS: u8 = 0x12;
    // Generic parameter in a generic type definition, represented as number
    pub const VAR: u8 = 0x13;
    // type rank boundsCount bound1 … loCount lo1 …
    pub const ARRAY: u8 = 0x14;
    // Generic type instantiation. Followed by type type-arg-count type-1 ... type-n
    pub const GENERICINST: u8 = 0x15;
    pub const TYPEDBYREF: u8 = 0x16;
    // System.IntPtr
    pub const I: u8 = 0x18;
    // System.UIntPtr
    pub const U: u8 = 0x19;
    // Followed by full method signature
    pub const FNPTR: u8 = 0x1b;
    // System.Object
    pub const OBJECT: u8 = 0x1c;
    // Single-dim array with 0 lower bound
    pub const SZARRAY: u8 = 0x1d;
    // Generic parameter in a generic method definition,represented as number
    pub const MVAR: u8 = 0x1e;
    // Required modifier : followed by a TypeDef or TypeRef token
    pub const CMOD_REQD: u8 = 0x1f;
    // Optional modifier : followed by a TypeDef or TypeRef token
    pub const CMOD_OPT: u8 = 0x20;
    // Implemented within the CLI
    pub const INTERNAL: u8 = 0x21;
    // Or’d with following element types
    pub const MODIFIER: u8 = 0x40;
    // Sentinel for vararg method signature
    pub const SENTINEL: u8 = 0x41;
    // Denotes a local variable that points at a pinned object
    pub const PINNED: u8 = 0x45;
}

/// CIL type modifier (required or optional)
pub struct CilModifier {
    /// Is this modifier required or optional?
    pub required: bool,
    /// The modifier to apply
    pub modifier: CilTypeRef,
}

#[allow(missing_docs)]
/// Represents complex type flavors in the type system
#[derive(Debug, Clone, PartialEq)]
pub enum CilFlavor {
    // Base primitive types
    Void,
    Boolean,
    Char,
    I1,
    U1,
    I2,
    U2,
    I4,
    U4,
    I8,
    U8,
    R4,
    R8,
    I,
    U,
    Object,
    String,

    // Complex types
    Array {
        /// The rank (number of dimensions)
        rank: u32,
        /// Details about each dimension
        dimensions: Vec<ArrayDimensions>,
    },
    Pointer,
    ByRef,
    GenericInstance,
    Pinned,
    FnPtr {
        /// The method signature
        signature: SignatureMethod,
    },
    GenericParameter {
        /// Index in the generic parameters list
        index: u32,
        /// Whether it's a method parameter (true) or type parameter (false)
        method: bool,
    },

    // Type categories
    Class,
    ValueType,
    Interface,

    // Fallback
    Unknown,
}

impl CilFlavor {
    /// Check if this is a primitive type
    #[must_use]
    pub fn is_primitive(&self) -> bool {
        matches!(
            self,
            CilFlavor::Void
                | CilFlavor::Boolean
                | CilFlavor::Char
                | CilFlavor::I1
                | CilFlavor::U1
                | CilFlavor::I2
                | CilFlavor::U2
                | CilFlavor::I4
                | CilFlavor::U4
                | CilFlavor::I8
                | CilFlavor::U8
                | CilFlavor::R4
                | CilFlavor::R8
                | CilFlavor::I
                | CilFlavor::U
                | CilFlavor::Object
                | CilFlavor::String
        )
    }

    /// Check if this is a value type
    #[must_use]
    pub fn is_value_type(&self) -> bool {
        matches!(
            self,
            CilFlavor::Boolean
                | CilFlavor::Char
                | CilFlavor::I1
                | CilFlavor::U1
                | CilFlavor::I2
                | CilFlavor::U2
                | CilFlavor::I4
                | CilFlavor::U4
                | CilFlavor::I8
                | CilFlavor::U8
                | CilFlavor::R4
                | CilFlavor::R8
                | CilFlavor::I
                | CilFlavor::U
                | CilFlavor::ValueType
        )
    }

    /// Check if this is a reference type
    #[must_use]
    pub fn is_reference_type(&self) -> bool {
        matches!(
            self,
            CilFlavor::Object | CilFlavor::String | CilFlavor::Class | CilFlavor::Array { .. }
        )
    }

    /// Try to convert to a `CilPrimitive` if this is a primitive type
    #[must_use]
    pub fn to_primitive_kind(&self) -> Option<CilPrimitiveKind> {
        match self {
            CilFlavor::Void => Some(CilPrimitiveKind::Void),
            CilFlavor::Boolean => Some(CilPrimitiveKind::Boolean),
            CilFlavor::Char => Some(CilPrimitiveKind::Char),
            CilFlavor::I1 => Some(CilPrimitiveKind::I1),
            CilFlavor::U1 => Some(CilPrimitiveKind::U1),
            CilFlavor::I2 => Some(CilPrimitiveKind::I2),
            CilFlavor::U2 => Some(CilPrimitiveKind::U2),
            CilFlavor::I4 => Some(CilPrimitiveKind::I4),
            CilFlavor::U4 => Some(CilPrimitiveKind::U4),
            CilFlavor::I8 => Some(CilPrimitiveKind::I8),
            CilFlavor::U8 => Some(CilPrimitiveKind::U8),
            CilFlavor::R4 => Some(CilPrimitiveKind::R4),
            CilFlavor::R8 => Some(CilPrimitiveKind::R8),
            CilFlavor::I => Some(CilPrimitiveKind::I),
            CilFlavor::U => Some(CilPrimitiveKind::U),
            CilFlavor::Object => Some(CilPrimitiveKind::Object),
            CilFlavor::String => Some(CilPrimitiveKind::String),
            CilFlavor::ValueType => Some(CilPrimitiveKind::ValueType),
            CilFlavor::GenericParameter { method, .. } => {
                if *method {
                    Some(CilPrimitiveKind::MVar)
                } else {
                    Some(CilPrimitiveKind::Var)
                }
            }
            _ => None,
        }
    }

    /// Check if this flavor is compatible with (assignable to) the target flavor
    ///
    /// Implements .NET primitive type compatibility rules including:
    /// - Exact type matching
    /// - Primitive widening conversions (byte -> int -> long, etc.)
    /// - Reference type compatibility
    ///
    /// # Arguments
    /// * `target` - The target flavor to check compatibility against
    ///
    /// # Returns
    /// `true` if this flavor can be assigned to the target flavor
    #[must_use]
    pub fn is_compatible_with(&self, target: &CilFlavor) -> bool {
        // Exact match
        if self == target {
            return true;
        }

        // Primitive widening rules
        #[allow(clippy::match_same_arms)]
        match (self, target) {
            // Integer widening: smaller -> larger
            (CilFlavor::I1 | CilFlavor::U1, CilFlavor::I2 | CilFlavor::I4 | CilFlavor::I8) => true,
            (CilFlavor::I2, CilFlavor::I4 | CilFlavor::I8) => true,
            (CilFlavor::I4, CilFlavor::I8) => true,

            // Unsigned integer widening
            (CilFlavor::U1, CilFlavor::U2 | CilFlavor::U4 | CilFlavor::U8) => true,
            (CilFlavor::U2, CilFlavor::U4 | CilFlavor::U8) => true,
            (CilFlavor::U4, CilFlavor::U8) => true,

            // Float widening: float -> double
            (CilFlavor::R4, CilFlavor::R8) => true,

            // Integer to float (with potential precision loss)
            (
                CilFlavor::I1 | CilFlavor::U1 | CilFlavor::I2 | CilFlavor::U2 | CilFlavor::I4,
                CilFlavor::R4 | CilFlavor::R8,
            ) => true,
            (CilFlavor::I8 | CilFlavor::U4 | CilFlavor::U8, CilFlavor::R8) => true,

            // Any reference type to Object
            (source, CilFlavor::Object) if source.is_reference_type() => true,

            // All value types are compatible with ValueType
            (source, CilFlavor::ValueType) if source.is_value_type() => true,

            _ => false,
        }
    }

    /// Check if this flavor can accept a constant of the given flavor
    ///
    /// This is more restrictive than general compatibility as constants
    /// require exact matches or safe widening conversions only.
    ///
    /// # Arguments
    /// * `constant_flavor` - The flavor of the constant value
    ///
    /// # Returns  
    /// `true` if a constant of the given flavor can be assigned to this type
    #[must_use]
    pub fn accepts_constant(&self, constant_flavor: &CilFlavor) -> bool {
        // Exact match is always allowed
        if self == constant_flavor {
            return true;
        }

        // For constants, we're more restrictive - only safe widening
        #[allow(clippy::match_same_arms)]
        match (constant_flavor, self) {
            // Integer literal widening (safe)
            (CilFlavor::I1, CilFlavor::I2 | CilFlavor::I4 | CilFlavor::I8) => true,
            (CilFlavor::I2, CilFlavor::I4 | CilFlavor::I8) => true,
            (CilFlavor::I4, CilFlavor::I8) => true,

            // Unsigned integer literal widening
            (CilFlavor::U1, CilFlavor::U2 | CilFlavor::U4 | CilFlavor::U8) => true,
            (CilFlavor::U2, CilFlavor::U4 | CilFlavor::U8) => true,
            (CilFlavor::U4, CilFlavor::U8) => true,

            // Float literal widening
            (CilFlavor::R4, CilFlavor::R8) => true,

            // String constants to Object
            (CilFlavor::String, CilFlavor::Object) => true,

            // Null constant to any reference type
            // Note: This would need special handling for null literals
            _ => false,
        }
    }
}
