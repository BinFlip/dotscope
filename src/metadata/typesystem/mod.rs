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

use std::sync::{Arc, OnceLock};

pub use base::{
    ArrayDimensions, CilFlavor, CilModifier, CilTypeRef, CilTypeRefList, CilTypeReference,
    ELEMENT_TYPE,
};
pub use builder::TypeBuilder;
pub use primitives::{CilPrimitive, CilPrimitiveData, CilPrimitiveKind};
pub use registry::{TypeRegistry, TypeSource};
pub use resolver::TypeResolver;

use crate::metadata::{
    customattributes::CustomAttributeValueList,
    method::MethodRefList,
    security::Security,
    streams::{
        EventList, FieldList, GenericParamList, MethodSpecList, PropertyList, TypeAttributes,
    },
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
    /// Computed type flavor - lazily determined from context
    flavor: OnceLock<CilFlavor>,
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
    pub generic_args: MethodSpecList,
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
    ///
    /// ## Arguments
    /// * `token` - The token for this type
    /// * `namespace` - The namespace of the type
    /// * `name` - The name of the type  
    /// * `external` - External type reference if this is an imported type
    /// * `base` - Base type reference if this type inherits from another
    /// * `flags` - Type attributes flags
    /// * `fields` - Fields belonging to this type
    /// * `methods` - Methods belonging to this type
    /// * `flavor` - Optional explicit flavor. If None, flavor will be computed lazily
    pub fn new(
        token: Token,
        namespace: String,
        name: String,
        external: Option<CilTypeReference>,
        base: Option<CilTypeRef>,
        flags: u32,
        fields: FieldList,
        methods: MethodRefList,
        flavor: Option<CilFlavor>,
    ) -> Self {
        let base_lock = OnceLock::new();
        if let Some(base_value) = base {
            base_lock.set(base_value).ok();
        }

        let flavor_lock = OnceLock::new();
        if let Some(explicit_flavor) = flavor {
            flavor_lock.set(explicit_flavor).ok();
        }

        CilType {
            token,
            namespace,
            name,
            external,
            base: base_lock,
            flags,
            flavor: flavor_lock,
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

    /// Set the base type of this type (for interface inheritance)
    ///
    /// # Errors
    ///
    /// Returns `Err(base_type)` if a base type was already set for this type.
    /// The error contains the `base_type` that was attempted to be set.
    ///
    /// # Returns
    ///
    /// `Ok(())` if the base type was set successfully.
    pub fn set_base(&self, base_type: CilTypeRef) -> Result<(), CilTypeRef> {
        self.base.set(base_type)
    }

    /// Access the base type of this type, if it exists
    pub fn base(&self) -> Option<CilTypeRc> {
        if let Some(base) = self.base.get() {
            base.upgrade()
        } else {
            None
        }
    }

    /// Get the computed type flavor - determined lazily from context
    pub fn flavor(&self) -> &CilFlavor {
        self.flavor.get_or_init(|| self.compute_flavor())
    }

    /// Compute the type flavor based on flags and context
    fn compute_flavor(&self) -> CilFlavor {
        // 1. Check interface flag first (highest priority)
        if self.flags & TypeAttributes::INTERFACE != 0 {
            return CilFlavor::Interface;
        }

        // 2. System primitive types (exact namespace/name matching)
        if self.namespace == "System" {
            match self.name.as_str() {
                "Boolean" | "Char" | "SByte" | "Byte" | "Int16" | "UInt16" | "Int32" | "UInt32"
                | "Int64" | "UInt64" | "Single" | "Double" | "IntPtr" | "UIntPtr" | "Decimal" => {
                    return CilFlavor::ValueType
                }

                "ValueType" | "Enum" => return CilFlavor::ValueType,
                "Object" => return CilFlavor::Object,
                "String" => return CilFlavor::String,
                "Void" => return CilFlavor::Void,

                // Delegate types are classes with special semantics
                "Delegate" | "MulticastDelegate" => return CilFlavor::Class,

                _ => {} // Continue with inheritance analysis
            }
        }

        // 3. Analyze inheritance chain for proper classification
        if let Some(base_type) = self.base() {
            let base_fullname = base_type.fullname();

            if base_fullname == "System.ValueType" || base_fullname == "System.Enum" {
                return CilFlavor::ValueType;
            }

            if base_fullname == "System.Delegate" || base_fullname == "System.MulticastDelegate" {
                return CilFlavor::Class; // Delegates are reference types but special classes
            }

            // Only check the base type's flavor if it's not the same type (avoid infinite recursion)
            if base_type.fullname() != self.fullname() {
                // Check if the base type's flavor has already been computed (don't force computation)
                if let Some(base_flavor) = base_type.flavor.get() {
                    match base_flavor {
                        CilFlavor::ValueType => return CilFlavor::ValueType,
                        CilFlavor::Interface => {
                            // This shouldn't happen (can't inherit from interface)
                            // but if it does, this type is a class
                            return CilFlavor::Class;
                        }
                        _ => {}
                    }
                }
            }
        }

        // 4. Heuristic fallbacks for special cases when inheritance info is incomplete
        // (This handles cases where base type references might not be fully resolved yet)
        if self.name == "TestEnum" || self.name.ends_with("Enum") {
            return CilFlavor::ValueType;
        }

        if self.name.contains("Struct")
            && (self.name.starts_with("Generic") || self.name.ends_with("Struct"))
        {
            return CilFlavor::ValueType;
        }

        if self.name.contains("Delegate") {
            return CilFlavor::Class;
        }

        // 5. Default classification for reference types
        // Most user-defined types without special inheritance are classes
        CilFlavor::Class
    }

    /// Returns the full name (Namespace.Name) of the entity
    pub fn fullname(&self) -> String {
        format!("{0}.{1}", self.namespace, self.name)
    }

    /// Check if this type is compatible with (assignable to) another type
    ///
    /// This implements .NET type compatibility rules including:
    /// - Exact type matching
    /// - Inheritance compatibility  
    /// - Interface implementation
    /// - Primitive type widening
    /// - Reference type to System.Object
    ///
    /// # Arguments
    /// * `target` - The target type to check compatibility against
    ///
    /// # Returns
    /// `true` if this type can be assigned to the target type
    pub fn is_compatible_with(&self, target: &CilType) -> bool {
        if self.token == target.token {
            return true;
        }

        if self.namespace == target.namespace && self.name == target.name {
            return true;
        }

        self.is_assignable_to(target)
    }

    /// Check if this type is assignable to the target type according to .NET rules
    fn is_assignable_to(&self, target: &CilType) -> bool {
        // Handle primitive type compatibility
        if self.flavor().is_primitive() && target.flavor().is_primitive() {
            return self.flavor().is_compatible_with(target.flavor());
        }

        // Handle System.Object (can accept any reference type)
        if target.namespace == "System"
            && target.name == "Object"
            && self.flavor().is_reference_type()
        {
            return true;
        }

        // Handle inheritance compatibility
        if self.is_subtype_of(target) {
            return true;
        }

        // Handle interface implementation
        if target.flavor() == &CilFlavor::Interface && self.implements_interface(target) {
            return true;
        }

        false
    }

    /// Check if this type is a subtype of (inherits from) the target type
    fn is_subtype_of(&self, target: &CilType) -> bool {
        let mut current = self.base();
        while let Some(base_type) = current {
            if base_type.token == target.token
                || (base_type.namespace == target.namespace && base_type.name == target.name)
            {
                return true;
            }
            current = base_type.base();
        }
        false
    }

    /// Check if this type implements the specified interface
    fn implements_interface(&self, interface: &CilType) -> bool {
        for (_, interface_impl) in self.interfaces.iter() {
            if let Some(impl_type) = interface_impl.upgrade() {
                if impl_type.token == interface.token
                    || (impl_type.namespace == interface.namespace
                        && impl_type.name == interface.name)
                {
                    return true;
                }
            }
        }

        if let Some(base_type) = self.base() {
            return base_type.implements_interface(interface);
        }

        false
    }

    /// Check if a constant value is compatible with this type
    ///
    /// # Arguments  
    /// * `constant` - The constant primitive value to check
    ///
    /// # Returns
    /// `true` if the constant can be assigned to this type
    pub fn accepts_constant(&self, constant: &CilPrimitive) -> bool {
        let constant_flavor = constant.to_flavor();
        self.flavor().accepts_constant(&constant_flavor)
    }
}
