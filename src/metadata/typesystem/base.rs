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
}

impl From<CilPrimitive> for CilFlavor {
    fn from(primitive: CilPrimitive) -> Self {
        primitive.to_flavor()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::metadata::{token::Token, typesystem::CilType};

    use super::*;

    #[test]
    fn test_cil_flavor_is_primitive() {
        assert!(CilFlavor::Void.is_primitive());
        assert!(CilFlavor::Boolean.is_primitive());
        assert!(CilFlavor::Char.is_primitive());
        assert!(CilFlavor::I1.is_primitive());
        assert!(CilFlavor::U1.is_primitive());
        assert!(CilFlavor::I2.is_primitive());
        assert!(CilFlavor::U2.is_primitive());
        assert!(CilFlavor::I4.is_primitive());
        assert!(CilFlavor::U4.is_primitive());
        assert!(CilFlavor::I8.is_primitive());
        assert!(CilFlavor::U8.is_primitive());
        assert!(CilFlavor::R4.is_primitive());
        assert!(CilFlavor::R8.is_primitive());
        assert!(CilFlavor::I.is_primitive());
        assert!(CilFlavor::U.is_primitive());
        assert!(CilFlavor::Object.is_primitive());
        assert!(CilFlavor::String.is_primitive());

        assert!(!CilFlavor::Array {
            rank: 1,
            dimensions: vec![]
        }
        .is_primitive());
        assert!(!CilFlavor::Pointer.is_primitive());
        assert!(!CilFlavor::ByRef.is_primitive());
        assert!(!CilFlavor::GenericInstance.is_primitive());
        assert!(!CilFlavor::Pinned.is_primitive());
        assert!(!CilFlavor::Class.is_primitive());
        assert!(!CilFlavor::ValueType.is_primitive());
        assert!(!CilFlavor::Interface.is_primitive());
        assert!(!CilFlavor::Unknown.is_primitive());
    }

    #[test]
    fn test_cil_flavor_is_value_type() {
        assert!(CilFlavor::Boolean.is_value_type());
        assert!(CilFlavor::Char.is_value_type());
        assert!(CilFlavor::I1.is_value_type());
        assert!(CilFlavor::U1.is_value_type());
        assert!(CilFlavor::I2.is_value_type());
        assert!(CilFlavor::U2.is_value_type());
        assert!(CilFlavor::I4.is_value_type());
        assert!(CilFlavor::U4.is_value_type());
        assert!(CilFlavor::I8.is_value_type());
        assert!(CilFlavor::U8.is_value_type());
        assert!(CilFlavor::R4.is_value_type());
        assert!(CilFlavor::R8.is_value_type());
        assert!(CilFlavor::I.is_value_type());
        assert!(CilFlavor::U.is_value_type());
        assert!(CilFlavor::ValueType.is_value_type());

        assert!(!CilFlavor::Void.is_value_type());
        assert!(!CilFlavor::Object.is_value_type());
        assert!(!CilFlavor::String.is_value_type());
        assert!(!CilFlavor::Array {
            rank: 1,
            dimensions: vec![]
        }
        .is_value_type());
        assert!(!CilFlavor::Pointer.is_value_type());
        assert!(!CilFlavor::Class.is_value_type());
    }

    #[test]
    fn test_cil_flavor_is_reference_type() {
        assert!(CilFlavor::Object.is_reference_type());
        assert!(CilFlavor::String.is_reference_type());
        assert!(CilFlavor::Class.is_reference_type());
        assert!(CilFlavor::Array {
            rank: 1,
            dimensions: vec![]
        }
        .is_reference_type());

        assert!(!CilFlavor::Boolean.is_reference_type());
        assert!(!CilFlavor::I4.is_reference_type());
        assert!(!CilFlavor::ValueType.is_reference_type());
        assert!(!CilFlavor::Pointer.is_reference_type());
        assert!(!CilFlavor::ByRef.is_reference_type());
    }

    #[test]
    fn test_cil_flavor_to_primitive_kind() {
        assert_eq!(
            CilFlavor::Void.to_primitive_kind(),
            Some(CilPrimitiveKind::Void)
        );
        assert_eq!(
            CilFlavor::Boolean.to_primitive_kind(),
            Some(CilPrimitiveKind::Boolean)
        );
        assert_eq!(
            CilFlavor::Char.to_primitive_kind(),
            Some(CilPrimitiveKind::Char)
        );
        assert_eq!(
            CilFlavor::I1.to_primitive_kind(),
            Some(CilPrimitiveKind::I1)
        );
        assert_eq!(
            CilFlavor::U1.to_primitive_kind(),
            Some(CilPrimitiveKind::U1)
        );
        assert_eq!(
            CilFlavor::I2.to_primitive_kind(),
            Some(CilPrimitiveKind::I2)
        );
        assert_eq!(
            CilFlavor::U2.to_primitive_kind(),
            Some(CilPrimitiveKind::U2)
        );
        assert_eq!(
            CilFlavor::I4.to_primitive_kind(),
            Some(CilPrimitiveKind::I4)
        );
        assert_eq!(
            CilFlavor::U4.to_primitive_kind(),
            Some(CilPrimitiveKind::U4)
        );
        assert_eq!(
            CilFlavor::I8.to_primitive_kind(),
            Some(CilPrimitiveKind::I8)
        );
        assert_eq!(
            CilFlavor::U8.to_primitive_kind(),
            Some(CilPrimitiveKind::U8)
        );
        assert_eq!(
            CilFlavor::R4.to_primitive_kind(),
            Some(CilPrimitiveKind::R4)
        );
        assert_eq!(
            CilFlavor::R8.to_primitive_kind(),
            Some(CilPrimitiveKind::R8)
        );
        assert_eq!(CilFlavor::I.to_primitive_kind(), Some(CilPrimitiveKind::I));
        assert_eq!(CilFlavor::U.to_primitive_kind(), Some(CilPrimitiveKind::U));
        assert_eq!(
            CilFlavor::Object.to_primitive_kind(),
            Some(CilPrimitiveKind::Object)
        );
        assert_eq!(
            CilFlavor::String.to_primitive_kind(),
            Some(CilPrimitiveKind::String)
        );
        assert_eq!(
            CilFlavor::ValueType.to_primitive_kind(),
            Some(CilPrimitiveKind::ValueType)
        );

        assert_eq!(
            CilFlavor::GenericParameter {
                index: 0,
                method: false
            }
            .to_primitive_kind(),
            Some(CilPrimitiveKind::Var)
        );
        assert_eq!(
            CilFlavor::GenericParameter {
                index: 0,
                method: true
            }
            .to_primitive_kind(),
            Some(CilPrimitiveKind::MVar)
        );

        assert_eq!(
            CilFlavor::Array {
                rank: 1,
                dimensions: vec![]
            }
            .to_primitive_kind(),
            None
        );
        assert_eq!(CilFlavor::Pointer.to_primitive_kind(), None);
        assert_eq!(CilFlavor::ByRef.to_primitive_kind(), None);
        assert_eq!(CilFlavor::GenericInstance.to_primitive_kind(), None);
        assert_eq!(CilFlavor::Pinned.to_primitive_kind(), None);
        assert_eq!(
            CilFlavor::FnPtr {
                signature: SignatureMethod::default()
            }
            .to_primitive_kind(),
            None
        );
    }

    #[test]
    fn test_from_cil_primitive_for_cil_flavor() {
        let primitive = CilPrimitive::new(CilPrimitiveKind::I4);
        let flavor = CilFlavor::from(primitive);

        assert!(matches!(flavor, CilFlavor::I4));

        assert!(matches!(
            CilFlavor::from(CilPrimitive::new(CilPrimitiveKind::Boolean)),
            CilFlavor::Boolean
        ));
        assert!(matches!(
            CilFlavor::from(CilPrimitive::new(CilPrimitiveKind::Object)),
            CilFlavor::Object
        ));
        assert!(matches!(
            CilFlavor::from(CilPrimitive::new(CilPrimitiveKind::Var)),
            CilFlavor::GenericParameter {
                index: 0,
                method: false
            }
        ));
    }

    #[test]
    fn test_cil_type_reference() {
        let type_ref = CilTypeReference::None;
        assert!(matches!(type_ref, CilTypeReference::None));

        let type_rc = Arc::new(CilType::new(
            Token::new(0x01000001),
            CilFlavor::I4,
            "System".to_string(),
            "Int32".to_string(),
            None,
            None,
            0,
            Arc::new(boxcar::Vec::new()),
            Arc::new(boxcar::Vec::new()),
        ));

        let type_ref = CilTypeReference::TypeDef(CilTypeRef::from(type_rc.clone()));
        match type_ref {
            CilTypeReference::TypeDef(ref t) => {
                assert_eq!(t.token(), Some(Token::new(0x01000001)));
                assert_eq!(t.name(), Some("Int32".to_string()));
            }
            _ => panic!("Expected TypeDef variant"),
        }

        let cloned_ref = type_ref.clone();
        match cloned_ref {
            CilTypeReference::TypeDef(ref t) => {
                assert_eq!(t.token(), Some(Token::new(0x01000001)));
            }
            _ => panic!("Expected TypeDef variant after cloning"),
        }
    }

    #[test]
    fn test_element_type_constants() {
        assert_eq!(ELEMENT_TYPE::END, 0x00);
        assert_eq!(ELEMENT_TYPE::VOID, 0x01);
        assert_eq!(ELEMENT_TYPE::BOOLEAN, 0x02);
        assert_eq!(ELEMENT_TYPE::CHAR, 0x03);
        assert_eq!(ELEMENT_TYPE::I1, 0x04);
        assert_eq!(ELEMENT_TYPE::U1, 0x05);
        assert_eq!(ELEMENT_TYPE::I2, 0x06);
        assert_eq!(ELEMENT_TYPE::U2, 0x07);
        assert_eq!(ELEMENT_TYPE::I4, 0x08);
        assert_eq!(ELEMENT_TYPE::U4, 0x09);
        assert_eq!(ELEMENT_TYPE::I8, 0x0a);
        assert_eq!(ELEMENT_TYPE::U8, 0x0b);
        assert_eq!(ELEMENT_TYPE::R4, 0x0c);
        assert_eq!(ELEMENT_TYPE::R8, 0x0d);
        assert_eq!(ELEMENT_TYPE::STRING, 0x0e);
        assert_eq!(ELEMENT_TYPE::PTR, 0x0f);
        assert_eq!(ELEMENT_TYPE::BYREF, 0x10);
        assert_eq!(ELEMENT_TYPE::VALUETYPE, 0x11);
        assert_eq!(ELEMENT_TYPE::CLASS, 0x12);
        assert_eq!(ELEMENT_TYPE::VAR, 0x13);
        assert_eq!(ELEMENT_TYPE::ARRAY, 0x14);
        assert_eq!(ELEMENT_TYPE::GENERICINST, 0x15);
        assert_eq!(ELEMENT_TYPE::TYPEDBYREF, 0x16);
        assert_eq!(ELEMENT_TYPE::I, 0x18);
        assert_eq!(ELEMENT_TYPE::U, 0x19);
        assert_eq!(ELEMENT_TYPE::FNPTR, 0x1b);
        assert_eq!(ELEMENT_TYPE::OBJECT, 0x1c);
        assert_eq!(ELEMENT_TYPE::SZARRAY, 0x1d);
        assert_eq!(ELEMENT_TYPE::MVAR, 0x1e);
        assert_eq!(ELEMENT_TYPE::CMOD_REQD, 0x1f);
        assert_eq!(ELEMENT_TYPE::CMOD_OPT, 0x20);
        assert_eq!(ELEMENT_TYPE::INTERNAL, 0x21);
        assert_eq!(ELEMENT_TYPE::MODIFIER, 0x40);
        assert_eq!(ELEMENT_TYPE::SENTINEL, 0x41);
        assert_eq!(ELEMENT_TYPE::PINNED, 0x45);
    }

    #[test]
    fn test_cil_modifier() {
        let type_rc = Arc::new(CilType::new(
            Token::new(0x01000001),
            CilFlavor::Class,
            "System.Runtime.InteropServices".to_string(),
            "InAttribute".to_string(),
            None,
            None,
            0,
            Arc::new(boxcar::Vec::new()),
            Arc::new(boxcar::Vec::new()),
        ));

        let required_modifier = CilModifier {
            required: true,
            modifier: CilTypeRef::from(type_rc.clone()),
        };
        assert!(required_modifier.required);
        assert_eq!(
            required_modifier.modifier.name(),
            Some("InAttribute".to_string())
        );

        let optional_modifier = CilModifier {
            required: false,
            modifier: CilTypeRef::from(type_rc.clone()),
        };
        assert!(!optional_modifier.required);
        assert_eq!(
            optional_modifier.modifier.name(),
            Some("InAttribute".to_string())
        );
    }
}
