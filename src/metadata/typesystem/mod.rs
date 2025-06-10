//! .NET type system implementation for CIL analysis.
//!
//! This module provides a complete representation of the .NET type system, including
//! type definitions, references, generics, arrays, and primitive types. It bridges
//! the gap between raw metadata tables and a usable type system for analysis.
//!
//! # Key Components
//!
//! - [`CilType`]: Core type representation combining TypeDef, TypeRef, and TypeSpec
//! - [`TypeRegistry`]: Central registry for all types in an assembly  
//! - [`TypeResolver`]: Resolves type references and builds complete type information
//! - [`TypeBuilder`]: Builder pattern for constructing complex types
//! - [`CilPrimitive`]: Built-in primitive types (int32, string, object, etc.)
//!
//! # Type System Features
//!
//! - **Unified representation**: Combines metadata from multiple tables
//! - **Generic support**: Full generic type and method parameter handling
//! - **Array types**: Multi-dimensional and jagged array support
//! - **Inheritance**: Type hierarchy and interface implementation tracking
//! - **Primitive mapping**: Automatic mapping to runtime primitive types
//! - **Reference resolution**: Resolves cross-assembly type references
//!
//! # Examples
//!
//! ```rust,no_run
//! use dotscope::{CilObject, metadata::typesystem::TypeRegistry};
//!
//! let assembly = CilObject::from_file("tests/samples/WindowsBase.dll".as_ref())?;
//! let type_registry = assembly.types();
//!
//! // Look up a specific type
//! for entry in type_registry.get_by_fullname("System.String") {
//!     println!("String type: {} (Token: 0x{:08X})",
//!         entry.name, entry.token.value());
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```

mod base;
mod builder;
mod primitives;
mod registry;
mod resolver;

use std::sync::{Arc, OnceLock, RwLock};

pub use base::{
    ArrayDimensions, CilFlavor, CilModifier, CilTypeRef, CilTypeRefList, CilTypeReference,
    GenericArgument, ELEMENT_TYPE,
};
pub use builder::TypeBuilder;
pub use primitives::{CilPrimitive, CilPrimitiveData, CilPrimitiveKind};
pub use registry::{TypeRegistry, TypeSource};
pub use resolver::TypeResolver;

use crate::metadata::{
    customattributes::CustomAttributeValueList,
    method::MethodRefList,
    security::Security,
    streams::{EventList, FieldList, GenericParamList, PropertyList},
    token::Token,
};

/// A vector that holds a list of `CilType`
pub type CilTypeList = Arc<boxcar::Vec<CilTypeRc>>;
/// Reference to a `CilType`
pub type CilTypeRc = Arc<CilType>;

/// Represents a 'Type', close to `TypeDef` and `TypeRef` but as a combined item, containing
/// more information. The `Token` will match either the `TypeDef` or `TypeRef` or `TypeSpec` or
/// `TypeBase` (artificial, for mapping to specific primitive types supported in the runtime).
pub struct CilType {
    /// Token
    pub token: Token,
    /// The `TypeFlavor`
    pub flavor: RwLock<CilFlavor>,
    /// `TypeNamespace` (can be empty, e.g. for artificial `<module>` (globals) )
    pub namespace: String,
    /// `TypeName`
    pub name: String,
    /// Type is imported (e.g. `AssemblyRef`, `File`, `ModuleRef`, ...)
    pub external: Option<CilTypeReference>,
    /// This types base aka 'extends' (from `TypeDef`, `TypeRef` or `TypeSpec`)
    base: OnceLock<CilTypeRef>,
    /// Flags (a 4-byte bitmask of type `TypeAttributes`, §II.23.1.15)
    pub flags: u32,
    /// All fields this type has
    pub fields: FieldList,
    /// All methods this type has
    pub methods: MethodRefList,
    /// All properties this type has
    pub properties: PropertyList,
    /// All events this type has
    pub events: EventList,
    /// All interfaces this class implements
    pub interfaces: CilTypeRefList,
    /// All method overwrites this type implements (e.g. Interfaces)
    pub overwrites: Arc<boxcar::Vec<CilTypeReference>>,
    /// All types that are 'contained' in this type
    pub nested_types: CilTypeRefList,
    /// All generic parameters this type has (type information, not the instantiated version)
    pub generic_params: GenericParamList,
    /// All generic arguments this type has (instantiated version)
    pub generic_args: Arc<boxcar::Vec<GenericArgument>>,
    /// All custom attributes this type has
    pub custom_attributes: CustomAttributeValueList,
    /// a 2-byte value, specifying the alignment of fields
    pub packing_size: OnceLock<u16>,
    /// a 4-byte value, specifying the size of the class
    pub class_size: OnceLock<u32>,
    /// `TypeSpec` specifiers for the type
    pub spec: OnceLock<CilFlavor>,
    /// Type modifiers from `TypeSpec` for this type
    pub modifiers: Arc<boxcar::Vec<CilModifier>>,
    /// The .NET CIL Security Information (if present)
    pub security: OnceLock<Security>,
    // vtable
    // security
    // default_constructor: Option<MethodRef>
    // type_initializer: Option<MethodRef>
    // enclosing_type (counter part of nested_types - who holds this instance, for reverse lookup)
    // module: ModuleRef
    // assembly: AssemblyRef
    // flags holds a lot of information, split up for better access?
}

impl CilType {
    /// Create a new instance of a `CilType`
    pub fn new(
        token: Token,
        flavor: CilFlavor,
        namespace: String,
        name: String,
        external: Option<CilTypeReference>,
        base: Option<CilTypeRc>,
        flags: u32,
        fields: FieldList,
        methods: MethodRefList,
    ) -> Self {
        let base_lock = OnceLock::new();
        if let Some(base_value) = base {
            base_lock.set(base_value.into()).ok();
        }

        CilType {
            token,
            flavor: RwLock::new(flavor),
            namespace,
            name,
            external,
            base: base_lock,
            flags,
            fields,
            methods,
            properties: Arc::new(boxcar::Vec::new()),
            events: Arc::new(boxcar::Vec::new()),
            interfaces: Arc::new(boxcar::Vec::new()),
            overwrites: Arc::new(boxcar::Vec::new()),
            nested_types: Arc::new(boxcar::Vec::new()),
            generic_params: Arc::new(boxcar::Vec::new()),
            generic_args: Arc::new(boxcar::Vec::new()),
            custom_attributes: Arc::new(boxcar::Vec::new()),
            packing_size: OnceLock::new(),
            class_size: OnceLock::new(),
            spec: OnceLock::new(),
            modifiers: Arc::new(boxcar::Vec::new()),
            security: OnceLock::new(),
        }
    }

    /// Access the base type of this type, if it exists
    pub fn base(&self) -> Option<CilTypeRc> {
        if let Some(base) = self.base.get() {
            base.upgrade()
        } else {
            None
        }
    }

    /// Returns the full name (Namespace.Name) of the entity
    pub fn fullname(&self) -> String {
        format!("{0}.{1}", self.namespace, self.name)
    }
}
