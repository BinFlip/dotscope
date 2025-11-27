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
//! let assembly = CilObject::from_path("tests/samples/WindowsBase.dll")?;
//! let type_registry = assembly.types();
//!
//! // Look up a specific type
//! if let Some(string_type) = type_registry.get_by_fullname_first("System.String", true) {
//!     println!("String type: {} (Token: 0x{:08X})",
//!         string_type.name, string_type.token.value());
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

use std::{
    collections::HashSet,
    sync::{Arc, OnceLock},
};

pub use base::{
    ArrayDimensions, CilFlavor, CilModifier, CilTypeRef, CilTypeRefList, CilTypeRefListIter,
    CilTypeReference, ELEMENT_TYPE,
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
            EventList, FieldList, GenericParamList, MethodSpec, MethodSpecList, PropertyList,
            TableId, TypeAttributes,
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
    /// Enclosing type for nested types - used for reverse lookup to build hierarchical names
    pub enclosing_type: OnceLock<CilTypeRef>,
    /// Cached full name to avoid expensive recomputation
    fullname: OnceLock<String>,
    // vtable
    // security
    // default_constructor: Option<MethodRef>
    // type_initializer: Option<MethodRef>
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
            enclosing_type: OnceLock::new(),
            fullname: OnceLock::new(),
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
                                Err(Error::TypeError(
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
                            // The existing weak reference was dropped but the new one is valid.
                            // This is an edge case that could indicate:
                            // 1. The original base type was garbage collected
                            // 2. There's a race condition in type construction
                            //
                            // We accept this case since:
                            // - We can't compare against the dropped reference
                            // - The type system allows base types to be GC'd
                            // - Rejecting would cause false negatives in valid scenarios
                            //
                            // Future: Consider logging this case for debugging if needed
                            Ok(())
                        }
                    }
                } else {
                    // This should be impossible with OnceLock - if set() failed, get() should return Some()
                    Err(Error::TypeError(
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

    /// Set the enclosing type for nested types.
    ///
    /// This method allows setting the enclosing type for nested types, establishing the
    /// bidirectional relationship between nested and enclosing types. This is used to
    /// build proper hierarchical names with "/" separators like the .NET runtime.
    ///
    /// # Arguments
    /// * `enclosing_type` - The enclosing type that contains this nested type
    ///
    /// # Returns
    /// * `Ok(())` if the enclosing type was set successfully or an equivalent type was already set
    /// * `Err(_)` if a different enclosing type was already set for this type
    ///
    /// # Errors
    /// Returns an error if an enclosing type was already set with a different value.
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently. Only the first
    /// call will succeed in setting the enclosing type; subsequent calls with the
    /// same or equivalent enclosing type will succeed, while calls with a different
    /// enclosing type will return an error.
    pub fn set_enclosing_type(&self, enclosing_type: &CilTypeRef) -> Result<()> {
        match self.enclosing_type.set(enclosing_type.clone()) {
            Ok(()) => Ok(()),
            Err(_) => {
                // Check if the existing enclosing type is equivalent
                if let Some(existing) = self.enclosing_type.get() {
                    match (existing.upgrade(), enclosing_type.upgrade()) {
                        (Some(existing_ref), Some(new_ref)) => {
                            if existing_ref.token == new_ref.token
                                || existing_ref.is_structurally_equivalent(&new_ref)
                            {
                                Ok(())
                            } else {
                                Err(Error::TypeError(format!(
                                    "Enclosing type was already set with different value: existing {} vs new {}",
                                    existing_ref.fullname(),
                                    new_ref.fullname()
                                )))
                            }
                        }
                        // Any combination where at least one is dropped - accept
                        // since we can't compare or keep existing
                        (None | Some(_), None) | (None, Some(_)) => Ok(()),
                    }
                } else {
                    // This should be impossible with OnceLock
                    Err(Error::TypeError(
                        "Impossible OnceLock state detected in set_enclosing_type".to_string(),
                    ))
                }
            }
        }
    }

    /// Access the enclosing type for nested types, if it exists.
    ///
    /// Returns the enclosing type that contains this nested type, if one has been set.
    /// This is used to traverse up the type hierarchy for building hierarchical names.
    ///
    /// # Returns
    /// * `Some(CilTypeRc)` - The enclosing type if one is set and the reference is still valid
    /// * `None` - If this is not a nested type or the reference has been dropped
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently.
    pub fn enclosing_type(&self) -> Option<CilTypeRc> {
        if let Some(enclosing) = self.enclosing_type.get() {
            enclosing.upgrade()
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

    /// Compute the type flavor based on flags, inheritance chain, and intelligent heuristics.
    ///
    /// This method implements the core type classification logic, determining whether a type
    /// is a class, interface, value type, enum, delegate, etc. The classification follows
    /// these rules in priority order:
    ///
    /// 1. **ECMA-335 Interface flag** - Types with the Interface attribute are always interfaces
    /// 2. **System primitive types** - Well-known System namespace types get direct classification
    /// 3. **Inheritance chain analysis** - Types inheriting from ValueType, Enum, etc.
    /// 4. **Attribute-based heuristics** - Layout flags, sealed/abstract combinations
    /// 5. **Default** - Unclassified types default to Class
    ///
    /// # Returns
    /// The computed `CilFlavor` representing this type's classification.
    fn compute_flavor(&self) -> CilFlavor {
        // 1. ECMA-335 definitive classification - Interface flag takes precedence
        if self.flags & TypeAttributes::INTERFACE != 0 {
            return CilFlavor::Interface;
        }

        // 2. System primitive types (exact namespace/name matching)
        // Keep these for performance - they're well-defined and unchanging
        if self.namespace == "System" {
            // Check primitive value types and special value types
            match self.name.as_str() {
                // Primitive value types
                "Boolean" | "Char" | "SByte" | "Byte" | "Int16" | "UInt16" | "Int32" | "UInt32"
                | "Int64" | "UInt64" | "Single" | "Double" | "IntPtr" | "UIntPtr" | "Decimal" => {
                    return CilFlavor::ValueType;
                }
                // Special value types (base types themselves)
                "ValueType" | "Enum" => return CilFlavor::ValueType,
                // Well-known reference types
                "Object" => return CilFlavor::Object,
                "String" => return CilFlavor::String,
                "Void" => return CilFlavor::Void,
                // Delegate types are classes with special semantics
                "Delegate" | "MulticastDelegate" => return CilFlavor::Class,
                _ => {}
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

    /// Classify type by analyzing its immediate inheritance chain.
    ///
    /// Examines the direct base type and performs limited traversal to identify
    /// well-known .NET framework types that determine classification. Uses cached
    /// flavor values when available to avoid infinite recursion.
    ///
    /// # Returns
    /// * `Some(CilFlavor::ValueType)` - If the type inherits from System.ValueType or System.Enum
    /// * `Some(CilFlavor::Class)` - If the type inherits from System.Delegate or has an interface base
    /// * `None` - If classification cannot be determined from inheritance
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
                    if let Some(transitive_flavor) =
                        Self::analyze_transitive_inheritance(&base_type)
                    {
                        return Some(transitive_flavor);
                    }
                }
            }
        }
        None
    }

    /// Analyze inheritance chain transitively without forcing computation.
    ///
    /// Traverses up the inheritance hierarchy looking for well-known system types
    /// like `System.ValueType`, `System.Enum`, `System.Delegate`, etc. to determine
    /// the correct type flavor without recursively computing flavors (which could
    /// cause infinite recursion).
    ///
    /// # Arguments
    /// * `base_type` - The base type to start analysis from
    ///
    /// # Returns
    /// * `Some(CilFlavor)` - If a definitive classification is found in the inheritance chain
    /// * `None` - If no classification can be determined from the chain
    fn analyze_transitive_inheritance(base_type: &CilType) -> Option<CilFlavor> {
        /// Maximum depth to traverse in the inheritance chain.
        ///
        /// This limit prevents infinite loops in case of circular inheritance
        /// (which shouldn't occur in valid assemblies but could in malformed ones).
        /// The value of 10 is chosen because:
        /// - Most .NET type hierarchies are shallow (< 5 levels)
        /// - Deep hierarchies beyond 10 levels are extremely rare
        /// - The limit ensures bounded performance even with malformed input
        const MAX_INHERITANCE_DEPTH: usize = 10;

        // Look up the inheritance chain without computing flavors (avoid infinite recursion)
        let mut current = base_type.base();
        let mut depth = 0;

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

    /// Classify type using TypeAttributes flags and pattern-based heuristics.
    ///
    /// When inheritance analysis doesn't provide a definitive classification, this method
    /// uses type attributes and structural characteristics to infer the type category.
    /// This is particularly useful for types where base type information is unavailable.
    ///
    /// # Classification Heuristics
    /// - Sealed types with no methods but with fields → likely ValueType
    /// - Sequential/Explicit layout + sealed + not abstract → likely ValueType
    /// - Abstract + not sealed → Class
    /// - Has enum characteristics (single `value__` field) → ValueType
    /// - Has delegate characteristics (Invoke/BeginInvoke/EndInvoke) → Class
    ///
    /// # Returns
    /// * `Some(CilFlavor)` - If a heuristic matches
    /// * `None` - If no heuristic applies
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

    /// Check if this type exhibits characteristics typical of .NET enumerations.
    ///
    /// Enums in .NET have a specific structural pattern:
    /// - They are sealed (cannot be inherited)
    /// - They have exactly one instance field named `value__` (the underlying value)
    /// - They may have static fields representing the enum values
    ///
    /// This heuristic identifies enums even when base type information is unavailable.
    ///
    /// # Returns
    /// `true` if the type matches the enum pattern, `false` otherwise.
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

    /// Check if this type exhibits characteristics typical of .NET delegates.
    ///
    /// Delegates in .NET are sealed classes with a specific method signature pattern:
    /// - They have an `Invoke` method (synchronous invocation)
    /// - They have `BeginInvoke` and `EndInvoke` methods (asynchronous invocation)
    ///
    /// This heuristic identifies delegates even when base type information is unavailable.
    ///
    /// # Returns
    /// `true` if the type matches the delegate pattern, `false` otherwise.
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
    /// which is useful for type lookup and identification. For nested types,
    /// uses "/" separators as per .NET runtime convention.
    ///
    /// # Returns
    /// A string containing the full name in the format:
    /// - `"Namespace.Name"` for top-level types
    /// - `"Namespace.Outer/Inner"` for nested types
    ///
    /// # Caching
    /// The result is cached after first computation for performance.
    pub fn fullname(&self) -> String {
        if let Some(cached) = self.fullname.get() {
            return cached.clone();
        }

        let fullname = self.compute_fullname();
        let _ = self.fullname.set(fullname.clone());
        fullname
    }

    /// Computes the full name by traversing the enclosing type hierarchy.
    ///
    /// This is the core implementation separated from caching logic for clarity.
    fn compute_fullname(&self) -> String {
        let path_components = self.collect_type_path();

        if path_components.len() > 1 {
            // This is a nested type - use "/" separators like .NET runtime
            self.format_nested_fullname(&path_components)
        } else {
            // This is a top-level type - use traditional "." separator
            self.format_toplevel_fullname()
        }
    }

    /// Collects the type path from innermost (self) to outermost enclosing type.
    ///
    /// Returns components in outermost-to-innermost order (reversed during collection).
    fn collect_type_path(&self) -> Vec<String> {
        let mut path_components = Vec::new();

        path_components.push(self.safe_type_name());

        let mut visited_tokens = HashSet::new();
        visited_tokens.insert(self.token);

        let mut current_type = self.enclosing_type();
        while let Some(enclosing) = current_type {
            if visited_tokens.contains(&enclosing.token) {
                break; // Cycle detected
            }
            visited_tokens.insert(enclosing.token);

            path_components.push(Self::safe_name_for(&enclosing.name, enclosing.token));
            current_type = enclosing.enclosing_type();
        }

        // Reverse to get outermost-to-innermost order
        path_components.reverse();
        path_components
    }

    /// Returns a safe type name, using a placeholder for empty names.
    fn safe_type_name(&self) -> String {
        Self::safe_name_for(&self.name, self.token)
    }

    /// Returns a safe name string, using a token-based placeholder if empty.
    fn safe_name_for(name: &str, token: Token) -> String {
        if name.is_empty() {
            format!("<unnamed_{:08X}>", token.value())
        } else {
            name.to_string()
        }
    }

    /// Formats the full name for a nested type using "/" separators.
    fn format_nested_fullname(&self, path_components: &[String]) -> String {
        let nested_path = path_components.join("/");
        if self.namespace.is_empty() {
            nested_path
        } else {
            format!("{}.{}", self.namespace, nested_path)
        }
    }

    /// Formats the full name for a top-level type using "." separator.
    fn format_toplevel_fullname(&self) -> String {
        let type_name = self.safe_type_name();
        if self.namespace.is_empty() {
            type_name
        } else {
            format!("{}.{}", self.namespace, type_name)
        }
    }

    /// Checks if this type was created from a TypeRef table entry.
    ///
    /// Returns `true` if this type's token indicates it originated from a TypeRef table,
    /// meaning it references a type defined in an external assembly. This is essential
    /// for TypeRef to TypeDef resolution during multi-assembly loading.
    ///
    /// # Returns
    /// * `true` - If the type's token has table ID 0x01 (TypeRef)
    /// * `false` - If the type came from TypeDef (0x02), TypeSpec (0x1B), or other sources
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::typesystem::CilType;
    /// use dotscope::metadata::token::Token;
    ///
    /// # fn example(type_def: &CilType) {
    /// if type_def.is_typeref() {
    ///     println!("Type {} needs TypeRef resolution", type_def.fullname());
    /// }
    /// # }
    /// ```
    pub fn is_typeref(&self) -> bool {
        self.token.is_table(TableId::TypeRef)
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
        if self.namespace != other.namespace
            || self.name != other.name
            || *self.flavor() != *other.flavor()
        {
            return false;
        }

        if self.token != other.token {
            return false;
        }

        if !self.external_sources_equivalent(other) {
            return false;
        }

        if !self.generic_args_equivalent(other) {
            return false;
        }

        if !self.generic_params_equivalent(other) {
            return false;
        }

        self.base_types_equivalent(other)
    }

    /// Compare external source references for equivalence.
    ///
    /// Determines if two types originate from the same assembly by comparing their
    /// external source references (AssemblyRef, ModuleRef, File, etc.).
    ///
    /// # Returns
    ///
    /// - `true` if types are from the same assembly or indeterminate (conservative)
    /// - `false` if types are definitively from different assemblies
    ///
    /// # Examples
    ///
    /// Types from the same assembly will return `true`, while types from different
    /// assemblies (different AssemblyRef) will return `false`.
    pub fn external_sources_equivalent(&self, other: &CilType) -> bool {
        match (self.external.get(), other.external.get()) {
            (Some(ext1), Some(ext2)) => Self::type_sources_equivalent(ext1, ext2),
            // Both are current module types, or one external one local (TypeRef redirection case)
            _ => false,
        }
    }

    /// Compare type sources for equivalence
    fn type_sources_equivalent(source1: &CilTypeReference, source2: &CilTypeReference) -> bool {
        match (source1, source2) {
            (CilTypeReference::AssemblyRef(ar1), CilTypeReference::AssemblyRef(ar2)) => {
                if ar1.token == ar2.token {
                    return true;
                }

                // For cross-assembly type resolution, only consider assemblies equivalent
                // if they have identical name and strong name identity (be more conservative)
                // This prevents type conflicts while still allowing cross-assembly resolution
                ar1.name == ar2.name
                    && ar1.identifier == ar2.identifier
                    && ar1.major_version == ar2.major_version
                    && ar1.minor_version == ar2.minor_version
                    && ar1.build_number == ar2.build_number
                    && ar1.revision_number == ar2.revision_number
                    && ar1.culture == ar2.culture
            }
            (CilTypeReference::ModuleRef(mr1), CilTypeReference::ModuleRef(mr2)) => {
                mr1.token == mr2.token
            }
            (CilTypeReference::File(f1), CilTypeReference::File(f2)) => f1.token == f2.token,
            (CilTypeReference::None, CilTypeReference::None) => true,
            _ => false,
        }
    }

    /// Compare generic arguments for equivalence.
    ///
    /// Two types have equivalent generic arguments if they have the same number
    /// of arguments and each corresponding argument has the same token. This
    /// comparison is token-based for efficiency.
    fn generic_args_equivalent(&self, other: &CilType) -> bool {
        let count = self.generic_args.count();
        if count != other.generic_args.count() {
            return false;
        }

        (0..count).all(
            |i| match (self.generic_args.get(i), other.generic_args.get(i)) {
                (Some(a1), Some(a2)) => Self::method_specs_equivalent(a1, a2),
                (None, None) => true,
                _ => false,
            },
        )
    }

    /// Compare two MethodSpec entries for generic argument equivalence.
    ///
    /// MethodSpecs are equivalent if they have the same number of inner generic
    /// arguments and all corresponding inner arguments have matching tokens.
    fn method_specs_equivalent(spec1: &MethodSpec, spec2: &MethodSpec) -> bool {
        let inner_count = spec1.generic_args.count();
        if inner_count != spec2.generic_args.count() {
            return false;
        }

        (0..inner_count).all(
            |j| match (spec1.generic_args.get(j), spec2.generic_args.get(j)) {
                (Some(i1), Some(i2)) => i1.token() == i2.token(),
                (None, None) => true,
                _ => false,
            },
        )
    }

    /// Compare generic parameters for equivalence.
    ///
    /// Two types have equivalent generic parameters if they have the same number
    /// of parameters and each corresponding parameter has the same name and number.
    fn generic_params_equivalent(&self, other: &CilType) -> bool {
        let count = self.generic_params.count();
        if count != other.generic_params.count() {
            return false;
        }

        (0..count).all(
            |i| match (self.generic_params.get(i), other.generic_params.get(i)) {
                (Some(p1), Some(p2)) => p1.name == p2.name && p1.number == p2.number,
                (None, None) => true,
                _ => false,
            },
        )
    }

    /// Compare base types for equivalence
    fn base_types_equivalent(&self, other: &CilType) -> bool {
        match (self.base.get(), other.base.get()) {
            (Some(base1), Some(base2)) => {
                // Compare base types structurally, not just tokens
                match (base1.upgrade(), base2.upgrade()) {
                    (Some(b1), Some(b2)) => {
                        if b1.token == b2.token {
                            true
                        } else {
                            b1.is_structurally_equivalent(&b2)
                        }
                    }
                    (None, None) => true, // Both have weak refs that are dropped
                    _ => false,           // One valid, one dropped
                }
            }
            (None, None) => true, // Both have no base type
            _ => false,           // One has base, one doesn't
        }
    }

    /// Check if this type has an array relationship with the given base type.
    ///
    /// Returns true if this type is an array type (ends with "[]") and the base type
    /// matches the array's element type. This handles nested types correctly by
    /// checking both direct name matches and nested type patterns.
    ///
    /// # Arguments
    /// * `base_fullname` - The full name of the potential base type to check against.
    ///   Must be a non-empty, valid type name.
    ///
    /// # Returns
    /// * `true` - If this type is an array of the specified base type
    /// * `false` - If this is not an array type, the base name is empty, or there's no match
    ///
    /// # Examples
    /// - `MyClass[]` is an array of `MyClass`
    /// - `AdjustmentRule[]` is an array of `TimeZoneInfo/AdjustmentRule`
    pub fn is_array_of(&self, base_fullname: &str) -> bool {
        if base_fullname.is_empty() || base_fullname.trim().is_empty() {
            return false;
        }

        if let Some(element_name) = self.fullname().strip_suffix("[]") {
            base_fullname == element_name || base_fullname.ends_with(&format!("/{}", element_name))
        } else {
            false
        }
    }

    /// Check if this type has a pointer relationship with the given base type.
    ///
    /// Returns true if this type is a pointer type (ends with "*") and the base type
    /// matches the pointer's target type. This handles nested types correctly by
    /// checking both direct name matches and nested type patterns.
    ///
    /// # Arguments
    /// * `base_fullname` - The full name of the potential target type to check against.
    ///   Must be a non-empty, valid type name.
    ///
    /// # Returns
    /// * `true` - If this type is a pointer to the specified base type
    /// * `false` - If this is not a pointer type, the base name is empty, or there's no match
    ///
    /// # Examples
    /// - `EventData*` is a pointer to `EventData`
    /// - `MyStruct*` is a pointer to `OuterClass/MyStruct`
    pub fn is_pointer_to(&self, base_fullname: &str) -> bool {
        if base_fullname.is_empty() || base_fullname.trim().is_empty() {
            return false;
        }

        if let Some(element_name) = self.fullname().strip_suffix('*') {
            base_fullname == element_name || base_fullname.ends_with(&format!("/{}", element_name))
        } else {
            false
        }
    }

    /// Check if this type represents a generic relationship with the base type.
    ///
    /// Returns true if either type has generic parameters (contains '`') and they
    /// share a common base name, indicating a generic instantiation relationship.
    ///
    /// # Arguments
    /// * `base_fullname` - The full name of the potential generic base type to check against.
    ///   Must be a non-empty, valid type name.
    ///
    /// # Returns
    /// * `true` - If the types share a generic relationship
    /// * `false` - If there's no generic relationship, or the base name is empty
    ///
    /// # Examples
    /// - `List<int>` has a generic relationship with `List<T>`
    /// - `Dictionary<string, int>` has a generic relationship with `Dictionary<K, V>`
    pub fn is_generic_of(&self, base_fullname: &str) -> bool {
        if base_fullname.is_empty() || base_fullname.trim().is_empty() {
            return false;
        }

        let derived_fullname = self.fullname();
        (derived_fullname.contains('`') || base_fullname.contains('`'))
            && (derived_fullname.starts_with(base_fullname.split('`').next().unwrap_or(""))
                || base_fullname.starts_with(derived_fullname.split('`').next().unwrap_or("")))
    }
}
