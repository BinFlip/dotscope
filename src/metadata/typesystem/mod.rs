//! .NET type system implementation for CIL analysis.
//!
//! This module provides a complete representation of the .NET type system, including
//! type definitions, references, generics, arrays, and primitive types. It bridges
//! the gap between raw metadata tables and a usable type system for analysis.
//!
//! # Key Components
//!
//! - [`crate::metadata::typesystem::CilType`]: Core type representation combining TypeDef, TypeRef, and TypeSpec
//! - [`crate::metadata::typesystem::TypeRegistry`]: Central registry for all types in an assembly  
//! - [`crate::metadata::typesystem::TypeResolver`]: Resolves type references and builds complete type information
//! - [`crate::metadata::typesystem::TypeBuilder`]: Builder pattern for constructing complex types
//! - [`crate::metadata::typesystem::CilPrimitive`]: Built-in primitive types (int32, string, object, etc.)
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
//! ```rust,ignore
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
mod encoder;
mod hash;
mod primitives;
mod registry;
mod resolver;

use std::sync::{Arc, OnceLock};

pub use base::{
    ArrayDimensions, CilFlavor, CilModifier, CilTypeRef, CilTypeRefList, CilTypeReference,
    ELEMENT_TYPE,
};
pub use builder::TypeBuilder;
pub use encoder::TypeSignatureEncoder;
pub use hash::TypeSignatureHash;
pub use primitives::{CilPrimitive, CilPrimitiveData, CilPrimitiveKind};
pub use registry::{CompleteTypeSpec, TypeRegistry, TypeSource};
pub use resolver::TypeResolver;

use crate::{
    metadata::{
        customattributes::CustomAttributeValueList,
        method::MethodRefList,
        security::Security,
        tables::{
            EventList, FieldList, GenericParamList, MethodSpecList, PropertyList, TypeAttributes,
        },
        token::Token,
    },
    Error, Result,
};

/// A vector that holds a list of `CilType` references.
///
/// This is a thread-safe, efficient collection optimized for append-only operations
/// during metadata loading and concurrent read access during analysis.
pub type CilTypeList = Arc<boxcar::Vec<CilTypeRc>>;

/// Reference-counted pointer to a `CilType`.
///
/// Enables efficient sharing of type information across the metadata system
/// while maintaining thread safety for concurrent access scenarios.
pub type CilTypeRc = Arc<CilType>;

/// Represents a unified type definition combining information from `TypeDef`, `TypeRef`, and `TypeSpec` tables.
///
/// `CilType` provides a complete representation of a .NET type, merging metadata from multiple
/// tables into a single coherent structure. This eliminates the need to navigate between
/// different metadata tables during type analysis and provides a more convenient API.
///
/// The `token` field indicates the source table:
/// - `TypeDef` tokens for types defined in the current assembly
/// - `TypeRef` tokens for types referenced from other assemblies  
/// - `TypeSpec` tokens for generic instantiations and complex type signatures
/// - Artificial tokens for runtime primitive types
///
/// # Thread Safety
///
/// `CilType` is designed for concurrent access with interior mutability using `OnceLock`
/// for lazily computed fields. Most fields are immutable after construction, while
/// computed properties like `flavor` and `base` are thread-safely cached.
///
/// # Examples
///
/// Basic type information access is available through the type registry.
/// Complex iteration patterns may require understanding the current iterator implementation.
pub struct CilType {
    /// Metadata token identifying this type (`TypeDef`, `TypeRef`, `TypeSpec`, or artificial)
    pub token: Token,
    /// Computed type flavor - lazily determined from context and inheritance chain
    flavor: OnceLock<CilFlavor>,
    /// Type namespace (empty for global types and some special cases like `<Module>`)
    pub namespace: String,
    /// Type name (class name, interface name, etc.)
    pub name: String,
    /// External type reference for imported types (from `AssemblyRef`, `File`, `ModuleRef`)
    external: OnceLock<CilTypeReference>,
    /// Base type reference - the type this type inherits from (for classes) or extends (for interfaces)
    base: OnceLock<CilTypeRef>,
    /// Type attributes flags - 4-byte bitmask from `TypeAttributes` (ECMA-335 §II.23.1.15)
    pub flags: u32,
    /// All fields defined in this type
    pub fields: FieldList,
    /// All methods defined in this type (constructors, instance methods, static methods)
    pub methods: MethodRefList,
    /// All properties defined in this type
    pub properties: PropertyList,
    /// All events defined in this type
    pub events: EventList,
    /// All interfaces this type implements (from `InterfaceImpl` table)
    pub interfaces: CilTypeRefList,
    /// All method overwrites this type implements (explicit interface implementations)
    pub overwrites: Arc<boxcar::Vec<CilTypeReference>>,
    /// Nested types contained within this type (inner classes, delegates, etc.)
    pub nested_types: CilTypeRefList,
    /// Generic parameters for this type definition (e.g., T, U in Class<T, U>)
    pub generic_params: GenericParamList,
    /// Generic arguments for instantiated generic types (actual types substituted for parameters)
    pub generic_args: MethodSpecList,
    /// Custom attributes applied to this type (annotations, decorators)
    pub custom_attributes: CustomAttributeValueList,
    /// Field layout packing size - alignment of fields in memory (from `ClassLayout` table)
    pub packing_size: OnceLock<u16>,
    /// Total size of the class in bytes (from `ClassLayout` table)
    pub class_size: OnceLock<u32>,
    /// `TypeSpec` specifiers providing additional type information for complex types
    pub spec: OnceLock<CilFlavor>,
    /// Type modifiers from `TypeSpec` (required/optional modifiers, pinned types, etc.)
    pub modifiers: Arc<boxcar::Vec<CilModifier>>,
    /// Security declarations and permissions associated with this type
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
    /// Create a new instance of a `CilType`.
    ///
    /// Creates a new type representation with the provided metadata. Some fields like
    /// `properties`, `events`, `interfaces`, etc. are initialized as empty collections
    /// and can be populated later during metadata loading.
    ///
    /// # Arguments
    /// * `token` - The metadata token for this type
    /// * `namespace` - The namespace of the type (can be empty for global types)
    /// * `name` - The name of the type  
    /// * `external` - External type reference if this is an imported type
    /// * `base` - Base type reference if this type inherits from another (optional)
    /// * `flags` - Type attributes flags from `TypeAttributes`
    /// * `fields` - Fields belonging to this type
    /// * `methods` - Methods belonging to this type
    /// * `flavor` - Optional explicit flavor. If None, flavor will be computed lazily
    ///
    /// # Thread Safety
    ///
    /// The returned `CilType` is safe for concurrent access. Lazily computed fields
    /// like `flavor` and `base` use `OnceLock` for thread-safe initialization.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::{
    ///     typesystem::{CilType, CilFlavor},
    ///     token::Token,
    /// };
    /// use std::sync::Arc;
    ///
    /// let cil_type = CilType::new(
    ///     Token::new(0x02000001), // TypeDef token
    ///     "MyNamespace".to_string(),
    ///     "MyClass".to_string(),
    ///     None, // Not an external type
    ///     None, // No base type specified yet
    ///     0x00100001, // TypeAttributes flags
    ///     Arc::new(boxcar::Vec::new()), // Empty fields list
    ///     Arc::new(boxcar::Vec::new()), // Empty methods list
    ///     Some(CilFlavor::Class), // Explicit class flavor
    /// );
    /// ```
    #[allow(clippy::too_many_arguments)]
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

        let external_lock = OnceLock::new();
        if let Some(external_value) = external {
            external_lock.set(external_value).ok();
        }

        let flavor_lock = OnceLock::new();
        if let Some(explicit_flavor) = flavor {
            flavor_lock.set(explicit_flavor).ok();
        }

        CilType {
            token,
            namespace,
            name,
            external: external_lock,
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

    /// Set the base type of this type for inheritance relationships.
    ///
    /// This method allows setting the base type after the `CilType` has been created,
    /// which is useful during metadata loading when type references may not be fully
    /// resolved at construction time.
    ///
    /// # Arguments
    /// * `base_type` - The base type this type inherits from
    ///
    /// # Returns
    /// * `Ok(())` if the base type was set successfully
    /// * `Err(base_type)` if a base type was already set for this type
    ///
    /// # Errors
    ///
    /// This function will return an error if a base type was already set for this type.
    /// The error contains the base type that was attempted to be set.
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently. Only the first
    /// call will succeed in setting the base type.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::typesystem::{CilType, CilTypeRef};
    /// use std::sync::{Arc, Weak};
    ///
    /// # fn example(cil_type: &CilType, base_type: Arc<CilType>) {
    /// let base_ref = CilTypeRef::new(&base_type);
    /// match cil_type.set_base(base_ref) {
    ///     Ok(()) => println!("Base type set successfully"),
    ///     Err(_) => println!("Base type was already set"),
    /// }
    /// # }
    /// ```
    pub fn set_base(&self, base_type: &CilTypeRef) -> Result<()> {
        match self.base.set(base_type.clone()) {
            Ok(()) => Ok(()),
            Err(_) => {
                if let Some(existing) = self.base.get() {
                    match (existing.upgrade(), base_type.upgrade()) {
                        (Some(existing_ref), Some(new_ref)) => {
                            if existing_ref.token == new_ref.token
                                || existing_ref.is_structurally_equivalent(&new_ref)
                            {
                                Ok(())
                            } else {
                                Err(Error::Error(
                                    format!("Base type was already set with different value: existing {} vs new {}", 
                                           existing_ref.fullname(), new_ref.fullname())
                                ))
                            }
                        }
                        (None, None) => {
                            // Both weak references are dropped - we can't compare
                            // This might be acceptable for deduplication
                            Ok(())
                        }
                        (Some(_existing_ref), None) => {
                            // Existing is valid but new is dropped
                            Ok(())
                        }
                        (None, Some(_new_ref)) => {
                            // This is suspicious - existing dropped but new is valid
                            Ok(())
                        }
                    }
                } else {
                    // This should be impossible with OnceLock - if set() failed, get() should return Some()
                    Err(Error::Error(
                        "Impossible OnceLock state detected".to_string(),
                    ))
                }
            }
        }
    }

    /// Access the base type of this type, if it exists.
    ///
    /// Returns the base type that this type inherits from, if one has been set.
    /// For classes, this is typically another class or `System.Object`. For value types,
    /// this is usually `System.ValueType` or `System.Enum`.
    ///
    /// # Returns
    /// * `Some(CilTypeRc)` - The base type if one is set and the reference is still valid
    /// * `None` - If no base type is set or the reference has been dropped
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// # use dotscope::metadata::typesystem::CilType;
    /// # fn example(cil_type: &CilType) {
    /// if let Some(base) = cil_type.base() {
    ///     println!("Base type: {}.{}", base.namespace, base.name);
    /// } else {
    ///     println!("No base type (likely System.Object or interface)");
    /// }
    /// # }
    /// ```
    pub fn base(&self) -> Option<CilTypeRc> {
        if let Some(base) = self.base.get() {
            base.upgrade()
        } else {
            None
        }
    }

    /// Sets the external type reference for this type.
    ///
    /// This method sets the external reference that indicates where this type is defined
    /// (e.g., which assembly, module, or file). This is primarily used for TypeRef entries
    /// that reference types defined outside the current assembly.
    ///
    /// ## Arguments
    /// * `external_ref` - The external type reference indicating where this type is defined
    ///
    /// ## Returns
    /// * `Ok(())` - External reference set successfully
    /// * `Err(_)` - External reference was already set or other error occurred
    ///
    /// # Errors
    ///
    /// Returns an error if the external reference was already set.
    ///
    /// ## Thread Safety
    /// This method is thread-safe and can be called concurrently. Only the first
    /// call will succeed in setting the external reference.
    pub fn set_external(&self, external_ref: &CilTypeReference) -> Result<()> {
        match self.external.set(external_ref.clone()) {
            Ok(()) => Ok(()),
            Err(_) => {
                if let Some(existing) = self.external.get() {
                    if Self::external_refs_compatible(existing, external_ref) {
                        Ok(())
                    } else {
                        Err(malformed_error!(
                            "External reference was already set with different value"
                        ))
                    }
                } else {
                    Err(malformed_error!("External reference was already set"))
                }
            }
        }
    }

    /// Check if two external references are compatible (for deduplication)
    fn external_refs_compatible(existing: &CilTypeReference, new: &CilTypeReference) -> bool {
        match (existing, new) {
            (CilTypeReference::AssemblyRef(ar1), CilTypeReference::AssemblyRef(ar2)) => {
                ar1.token == ar2.token
            }
            (CilTypeReference::ModuleRef(mr1), CilTypeReference::ModuleRef(mr2)) => {
                mr1.token == mr2.token
            }
            (CilTypeReference::File(f1), CilTypeReference::File(f2)) => f1.token == f2.token,
            // For deduplicated types, allow any external reference combination
            // since they should be structurally equivalent
            _ => true,
        }
    }

    /// Gets the external type reference for this type, if it exists.
    ///
    /// Returns the external reference that indicates where this type is defined,
    /// or `None` if this is a type defined in the current assembly or if no
    /// external reference has been set.
    ///
    /// ## Returns
    /// Returns the external reference if it has been set, or `None` if it's still pending resolution.
    pub fn get_external(&self) -> Option<&CilTypeReference> {
        self.external.get()
    }

    /// Get the computed type flavor - determined lazily from context.
    ///
    /// The flavor represents the fundamental nature of the type (class, interface,
    /// value type, etc.) and is computed from type attributes, inheritance relationships,
    /// and naming patterns. The result is cached for performance.
    ///
    /// # Returns
    /// A reference to the computed `CilFlavor` for this type
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe. The flavor is computed once and cached using
    /// `OnceLock` for subsequent calls.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::typesystem::{CilType, CilFlavor};
    ///
    /// # fn example(cil_type: &CilType) {
    /// match cil_type.flavor() {
    ///     CilFlavor::Class => println!("Reference type class"),
    ///     CilFlavor::ValueType => println!("Value type (struct/enum)"),
    ///     CilFlavor::Interface => println!("Interface definition"),
    ///     _ => println!("Other type flavor"),
    /// }
    /// # }
    /// ```
    pub fn flavor(&self) -> &CilFlavor {
        self.flavor.get_or_init(|| self.compute_flavor())
    }

    /// Compute the type flavor based on flags, inheritance chain, and intelligent heuristics
    fn compute_flavor(&self) -> CilFlavor {
        // 1. ECMA-335 definitive classification - Interface flag takes precedence
        if self.flags & TypeAttributes::INTERFACE != 0 {
            return CilFlavor::Interface;
        }

        // 2. System primitive types (exact namespace/name matching)
        // Keep these for performance - they're well-defined and unchanging
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

        // 3. Enhanced inheritance chain analysis
        if let Some(inherited_flavor) = self.classify_by_inheritance() {
            return inherited_flavor;
        }

        // 4. Intelligent attribute-based classification
        if let Some(attribute_flavor) = self.classify_by_attributes() {
            return attribute_flavor;
        }

        // 5. Default classification for reference types
        CilFlavor::Class
    }

    /// Classify type by analyzing inheritance chain with enhanced logic
    fn classify_by_inheritance(&self) -> Option<CilFlavor> {
        if let Some(base_type) = self.base() {
            let base_fullname = base_type.fullname();

            // Direct well-known base types
            if base_fullname == "System.ValueType" || base_fullname == "System.Enum" {
                return Some(CilFlavor::ValueType);
            }

            if base_fullname == "System.Delegate" || base_fullname == "System.MulticastDelegate" {
                return Some(CilFlavor::Class); // Delegates are reference types but special classes
            }

            // Traverse inheritance chain more intelligently
            if base_type.fullname() != self.fullname() {
                // Check if base type already has computed flavor
                if let Some(base_flavor) = base_type.flavor.get() {
                    match base_flavor {
                        CilFlavor::ValueType => return Some(CilFlavor::ValueType),
                        CilFlavor::Interface => {
                            // This shouldn't happen (can't inherit from interface)
                            // but if it does, this type is a class
                            return Some(CilFlavor::Class);
                        }
                        _ => {}
                    }
                } else {
                    // Base type flavor not computed yet - use transitive inheritance analysis
                    if let Some(transitive_flavor) = self.analyze_transitive_inheritance(&base_type)
                    {
                        return Some(transitive_flavor);
                    }
                }
            }
        }
        None
    }

    /// Analyze inheritance chain transitively without forcing computation
    fn analyze_transitive_inheritance(&self, base_type: &CilType) -> Option<CilFlavor> {
        // Look up the inheritance chain without computing flavors (avoid infinite recursion)
        let mut current = base_type.base();
        let mut depth = 0;
        const MAX_INHERITANCE_DEPTH: usize = 10; // Prevent infinite loops

        while let Some(ancestor) = current {
            depth += 1;
            if depth > MAX_INHERITANCE_DEPTH {
                break;
            }

            let ancestor_name = ancestor.fullname();

            // Check for well-known ancestor types
            if ancestor_name == "System.ValueType" || ancestor_name == "System.Enum" {
                return Some(CilFlavor::ValueType);
            }

            if ancestor_name == "System.Delegate" || ancestor_name == "System.MulticastDelegate" {
                return Some(CilFlavor::Class);
            }

            if ancestor_name == "System.Object" {
                // Reached the root - this is a reference type class
                return Some(CilFlavor::Class);
            }

            // Continue up the chain
            current = ancestor.base();
        }

        None
    }

    /// Classify type using TypeAttributes flags and intelligent heuristics
    fn classify_by_attributes(&self) -> Option<CilFlavor> {
        // ECMA-335 attribute-based classification

        // Sealed + Abstract is impossible, but if both are set, interface wins
        let is_sealed = self.flags & TypeAttributes::SEALED != 0;
        let is_abstract = self.flags & TypeAttributes::ABSTRACT != 0;

        // Value type indicators:
        // 1. Sealed with no methods often indicates value type (struct/enum)
        if is_sealed && !is_abstract && self.methods.is_empty() && !self.fields.is_empty() {
            return Some(CilFlavor::ValueType);
        }

        // 2. Types with sequential or explicit layout are often value types
        let layout = self.flags & TypeAttributes::LAYOUT_MASK;
        if (layout == TypeAttributes::SEQUENTIAL_LAYOUT
            || layout == TypeAttributes::EXPLICIT_LAYOUT)
            && is_sealed
            && !is_abstract
        {
            return Some(CilFlavor::ValueType);
        }

        // 3. Abstract classes that aren't sealed
        if is_abstract && !is_sealed {
            return Some(CilFlavor::Class);
        }

        // 4. Check for enum-like characteristics
        if self.has_enum_characteristics() {
            return Some(CilFlavor::ValueType);
        }

        // 5. Check for delegate-like characteristics
        if self.has_delegate_characteristics() {
            return Some(CilFlavor::Class);
        }

        None
    }

    /// Check if type has enum-like characteristics
    fn has_enum_characteristics(&self) -> bool {
        // Enums typically:
        // 1. Are sealed
        // 2. Have a single instance field named "value__"
        // 3. May have static fields for enum values

        if self.flags & TypeAttributes::SEALED == 0 {
            return false;
        }

        let instance_fields = self
            .fields
            .iter()
            .filter(|(_, field)| field.flags & 0x10 == 0) // Not static
            .count();

        let has_value_field = self
            .fields
            .iter()
            .any(|(_, field)| field.name == "value__" && field.flags & 0x10 == 0);

        // Classic enum pattern: single instance field named "value__"
        instance_fields == 1 && has_value_field
    }

    /// Check if type has delegate-like characteristics  
    fn has_delegate_characteristics(&self) -> bool {
        // Delegates typically:
        // 1. Are sealed classes
        // 2. Have Invoke, BeginInvoke, EndInvoke methods
        // 3. Have specific constructor signatures

        if self.flags & TypeAttributes::SEALED == 0 {
            return false;
        }

        let has_invoke = self.methods.iter().any(|(_, method)| {
            if let Some(name) = method.name() {
                name == "Invoke"
            } else {
                false
            }
        });

        let has_async_methods = self.methods.iter().any(|(_, method)| {
            if let Some(name) = method.name() {
                name == "BeginInvoke" || name == "EndInvoke"
            } else {
                false
            }
        });

        has_invoke && has_async_methods
    }

    /// Returns the full name (Namespace.Name) of the type.
    ///
    /// Combines the namespace and name to create a fully qualified type name,
    /// which is useful for type lookup and identification.
    ///
    /// # Returns
    /// A string containing the full name in the format "Namespace.Name"
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

    /// Performs deep structural comparison with another type for deduplication purposes
    ///
    /// This method compares all structural aspects of types to determine true equivalence,
    /// including generic arguments, base types, and source information. This is the
    /// authoritative method for determining if two types are semantically identical.
    ///
    /// ## Arguments
    /// * `other` - The other type to compare with
    ///
    /// ## Returns
    /// `true` if the types are structurally equivalent and can be deduplicated
    pub fn is_structurally_equivalent(&self, other: &CilType) -> bool {
        // Basic identity must match
        if self.namespace != other.namespace
            || self.name != other.name
            || *self.flavor() != *other.flavor()
        {
            return false;
        }

        // External source comparison
        if !self.external_sources_equivalent(other) {
            return false;
        }

        // Generic arguments comparison for generic instances
        if !self.generic_args_equivalent(other) {
            return false;
        }

        // Generic parameters comparison for generic definitions
        if !self.generic_params_equivalent(other) {
            return false;
        }

        // Base type comparison for derived types
        self.base_types_equivalent(other)
    }

    /// Compare external source references for equivalence
    fn external_sources_equivalent(&self, other: &CilType) -> bool {
        match (self.external.get(), other.external.get()) {
            (Some(ext1), Some(ext2)) => Self::type_sources_equivalent(ext1, ext2),
            (None, None) => true, // Both are current module types
            _ => false,           // One external, one local
        }
    }

    /// Compare type sources for equivalence
    fn type_sources_equivalent(source1: &CilTypeReference, source2: &CilTypeReference) -> bool {
        match (source1, source2) {
            (CilTypeReference::AssemblyRef(ar1), CilTypeReference::AssemblyRef(ar2)) => {
                ar1.token == ar2.token
            }
            (CilTypeReference::ModuleRef(mr1), CilTypeReference::ModuleRef(mr2)) => {
                mr1.token == mr2.token
            }
            (CilTypeReference::File(f1), CilTypeReference::File(f2)) => f1.token == f2.token,
            (CilTypeReference::None, CilTypeReference::None) => true,
            _ => false,
        }
    }

    /// Compare generic arguments for equivalence
    fn generic_args_equivalent(&self, other: &CilType) -> bool {
        // Must have same number of generic arguments
        if self.generic_args.count() != other.generic_args.count() {
            return false;
        }

        // Compare each generic argument
        for i in 0..self.generic_args.count() {
            let arg1 = self.generic_args.get(i);
            let arg2 = other.generic_args.get(i);

            match (arg1, arg2) {
                (Some(a1), Some(a2)) => {
                    if a1.generic_args.count() != a2.generic_args.count() {
                        return false;
                    }

                    // Compare inner generic argument types
                    for j in 0..a1.generic_args.count() {
                        let inner1 = a1.generic_args.get(j);
                        let inner2 = a2.generic_args.get(j);

                        match (inner1, inner2) {
                            (Some(i1), Some(i2)) => {
                                if i1.token() != i2.token() {
                                    return false;
                                }
                            }
                            (None, None) => {}
                            _ => return false,
                        }
                    }
                }
                (None, None) => {}
                _ => return false,
            }
        }

        true
    }

    /// Compare generic parameters for equivalence
    fn generic_params_equivalent(&self, other: &CilType) -> bool {
        // Must have same number of generic parameters
        if self.generic_params.count() != other.generic_params.count() {
            return false;
        }

        // Compare each generic parameter
        for i in 0..self.generic_params.count() {
            let param1 = self.generic_params.get(i);
            let param2 = other.generic_params.get(i);

            match (param1, param2) {
                (Some(p1), Some(p2)) => {
                    // Compare parameter names and numbers
                    if p1.name != p2.name || p1.number != p2.number {
                        return false;
                    }
                }
                (None, None) => {}
                _ => return false,
            }
        }

        true
    }

    /// Compare base types for equivalence
    fn base_types_equivalent(&self, other: &CilType) -> bool {
        match (self.base.get(), other.base.get()) {
            (Some(base1), Some(base2)) => {
                // Compare base type tokens
                match (base1.upgrade(), base2.upgrade()) {
                    (Some(b1), Some(b2)) => b1.token == b2.token,
                    (None, None) => true, // Both have weak refs that are dropped
                    _ => false,           // One valid, one dropped
                }
            }
            (None, None) => true, // Both have no base type
            _ => false,           // One has base, one doesn't
        }
    }
}
