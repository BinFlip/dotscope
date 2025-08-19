//! Centralized metadata loading context for .NET assembly processing.
//!
//! This module provides the [`LoaderContext`] structure that serves as the central hub
//! for all metadata table maps during the assembly loading process. It coordinates
//! parallel loading operations and provides unified access to metadata streams,
//! tables, and registries throughout the loading pipeline.
//!
//! # Loading Architecture
//!
//! The context follows a specific lifecycle:
//! 1. **Creation**: Built in internal data structures from file
//! 2. **Population**: Passed to parallel loaders via `execute_loaders_in_parallel`
//! 3. **Resolution**: Provides coded index resolution and cross-table lookups
//! 4. **Cleanup**: Automatically dropped after loading completes
//!
//! # Key Responsibilities
//!
//! - **Stream Access**: Provides unified access to metadata streams (strings, blobs, etc.)
//! - **Table Management**: Holds maps for all metadata tables during loading
//! - **Cross-References**: Resolves coded indices between different table types
//! - **Type Registry**: Coordinates with the central type system
//! - **Import/Export**: Manages assembly dependency relationships
//!
//! # Parallel Loading Support
//!
//! The context is designed for concurrent access during parallel loading:
//! - Reference-counted data structures for shared access
//! - Thread-safe maps and registries
//! - Immutable stream references
//! - Lock-based coordination for critical sections
//!
//! # Examples
//!
//! ```rust,ignore
//! # use dotscope::metadata::loader::context::LoaderContext;
//! # use dotscope::metadata::tables::CodedIndex;
//! # fn example_usage(context: &LoaderContext) {
//! // Resolve a coded index to a type reference
//! let coded_index = CodedIndex { /* ... */ };
//! let type_ref = context.get_ref(&coded_index);
//!
//! // Access metadata streams
//! if let Some(strings) = context.strings {
//!     // Use string heap for name resolution
//! }
//!
//! // Access specific table maps
//! let method_count = context.method_def.len();
//! println!("Assembly contains {} methods", method_count);
//! # }
//! ```
//!
//! # Memory Management
//!
//! The context uses careful memory management strategies:
//! - **Borrowed References**: Most data is borrowed from the parent CilObject
//! - **Reference Counting**: Shared data uses Arc for safe concurrent access
//! - **Lazy Initialization**: Some tables use OnceLock for deferred loading
//! - **Scoped Lifetime**: Context is dropped immediately after loading
//!
//! # Thread Safety
//!
//! All components in this module are designed for safe concurrent access during parallel loading.
//! The internal loader context contains thread-safe data structures and
//! is [`std::marker::Send`] and [`std::marker::Sync`], enabling efficient parallel processing
//! of metadata tables across multiple threads.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::loader::data`] - Assembly data loading and context creation
//! - [`crate::metadata::typesystem`] - Type registry and reference resolution
//! - [`crate::metadata::tables`] - All metadata table types and coded index resolution
//! - [`crate::metadata::streams`] - Metadata stream access and heap operations

use std::sync::{Arc, OnceLock};

use crate::{
    file::File,
    metadata::{
        cor20header::Cor20Header,
        exports::Exports,
        imports::Imports,
        method::MethodMap,
        resources::Resources,
        root::Root,
        streams::{Blob, Guid, Strings, TablesHeader, UserStrings},
        tables::{
            AssemblyOsRc, AssemblyProcessorRc, AssemblyRc, AssemblyRefMap, AssemblyRefOsMap,
            AssemblyRefProcessorMap, ClassLayoutMap, CodedIndex, ConstantMap, CustomAttributeMap,
            CustomDebugInformationMap, DeclSecurityMap, DocumentMap, EncLogMap, EncMapMap,
            EventMap, EventMapEntryMap, EventPtrMap, FieldLayoutMap, FieldMap, FieldMarshalMap,
            FieldPtrMap, FieldRVAMap, FileMap, GenericParamConstraintMap, GenericParamMap,
            ImportScopeMap, InterfaceImplMap, LocalConstantMap, LocalScopeMap, LocalVariableMap,
            MemberRefMap, MethodDebugInformationMap, MethodImplMap, MethodPtrMap,
            MethodSemanticsMap, MethodSpecMap, ModuleRc, ModuleRefMap, NestedClassMap, ParamMap,
            ParamPtrMap, PropertyMap, PropertyMapEntryMap, PropertyPtrMap, StandAloneSigMap,
            StateMachineMethodMap, TableId, TypeSpecMap,
        },
        typesystem::{CilTypeReference, TypeRegistry},
    },
};

/// Centralized context for metadata table maps during assembly loading.
///
/// This structure serves as the central coordination point for all metadata loading
/// operations in a .NET assembly. It provides unified access to metadata streams,
/// table maps, and cross-reference resolution capabilities required by parallel
/// loading operations.
///
/// # Lifecycle Management
///
/// The context follows a specific lifecycle pattern:
/// 1. **Initialization**: Created with references to parsed metadata streams
/// 2. **Population**: Parallel loaders populate table maps via `to_owned()` conversions
/// 3. **Resolution**: Cross-table references resolved via [`get_ref`](Self::get_ref) method
/// 4. **Application**: Loaders call `apply()` methods to build semantic relationships
/// 5. **Disposal**: Context automatically dropped after loading completes
///
/// # Data Organization
///
/// **Core Metadata**: Assembly header, streams, and basic structures
/// **Table Maps**: Concurrent containers for all metadata table types
/// **Registries**: Type system and import/export management
/// **References**: Cross-table relationship resolution
///
/// # Thread Safety
///
/// [`LoaderContext`] is [`std::marker::Send`] and [`std::marker::Sync`], designed for safe concurrent access:
/// - All maps use thread-safe data structures ([`crossbeam_skiplist::SkipMap`], [`dashmap::DashMap`])
/// - Metadata streams are immutable references
/// - Registries provide atomic operations
/// - Critical sections use [`std::sync::Arc`]<[`std::sync::OnceLock`]> for coordination
/// - Reference-counted data enables safe sharing across parallel loaders
///
/// # Examples
///
/// ```rust,ignore
/// # use dotscope::metadata::loader::context::LoaderContext;
/// # use dotscope::metadata::tables::{CodedIndex, TableId};
/// # use dotscope::metadata::token::Token;
/// # fn loader_example(context: &LoaderContext) -> dotscope::Result<()> {
/// // Resolve a coded index during loading
/// let coded_index = CodedIndex {
///     tag: TableId::TypeDef,
///     token: Token::new(0x02000001),
/// };
/// let type_reference = context.get_ref(&coded_index);
///
/// // Access metadata streams for name resolution
/// if let Some(strings) = context.strings {
///     let name = strings.get(123)?; // Get string at index 123
/// }
///
/// // Query loaded metadata
/// println!("Methods loaded: {}", context.method_def.len());
/// println!("Types registered: {}", context.types.len());
/// # Ok(())
/// # }
/// ```
pub(crate) struct LoaderContext<'a> {
    // === Core Assembly Data ===
    /// Input file reference for the assembly being loaded.
    pub input: Arc<File>,
    /// Raw binary data of the assembly file.
    pub data: &'a [u8],
    /// CLR 2.0 header containing metadata root and stream information.
    pub header: &'a Cor20Header,
    /// Metadata root header with stream definitions and signatures.
    pub header_root: &'a Root,

    // === Metadata Streams ===
    /// Tables stream containing all metadata table definitions.
    pub meta: Option<&'a TablesHeader<'a>>,
    /// String heap containing UTF-8 encoded names and identifiers.
    pub strings: Option<&'a Strings<'a>>,
    /// User string heap containing literal string constants.
    pub userstrings: Option<&'a UserStrings<'a>>,
    /// GUID heap containing unique identifiers for types and assemblies.
    pub guids: Option<&'a Guid<'a>>,
    /// Blob heap containing binary data (signatures, custom attributes, etc.).
    pub blobs: Option<&'a Blob<'a>>,

    // === Assembly and Module Tables ===
    /// Assembly definition (single entry per assembly).
    pub assembly: &'a Arc<OnceLock<AssemblyRc>>,
    /// Assembly operating system information.
    pub assembly_os: &'a Arc<OnceLock<AssemblyOsRc>>,
    /// Assembly processor architecture information.
    pub assembly_processor: &'a Arc<OnceLock<AssemblyProcessorRc>>,
    /// Assembly references to external assemblies.
    pub assembly_ref: &'a AssemblyRefMap,
    /// Operating system information for assembly references.
    pub assembly_ref_os: AssemblyRefOsMap,
    /// Processor information for assembly references.
    pub assembly_ref_processor: AssemblyRefProcessorMap,
    /// Module definition (primary module of the assembly).
    pub module: &'a Arc<OnceLock<ModuleRc>>,
    /// Module references to external modules.
    pub module_ref: &'a ModuleRefMap,

    // === Type System Tables ===
    /// Type specifications for instantiated generic types.
    pub type_spec: TypeSpecMap,

    // === Method and Field Tables ===
    /// Method definitions in the assembly.
    pub method_def: &'a MethodMap,
    /// Method implementations for interface/virtual methods.
    pub method_impl: MethodImplMap,
    /// Method semantics (property getters/setters, event handlers).
    pub method_semantics: MethodSemanticsMap,
    /// Method specifications for generic method instantiations.
    pub method_spec: &'a MethodSpecMap,
    /// Field definitions in types.
    pub field: FieldMap,
    /// Field pointer indirection table.
    pub field_ptr: FieldPtrMap,
    /// Method pointer indirection table.
    pub method_ptr: MethodPtrMap,
    /// Field layout information for explicit layout types.
    pub field_layout: FieldLayoutMap,
    /// Field marshalling information for interop.
    pub field_marshal: FieldMarshalMap,
    /// Field relative virtual addresses for initialized data.
    pub field_rva: FieldRVAMap,

    // === Edit-and-Continue Tables ===
    /// Edit-and-Continue log entries tracking debugging modifications.
    pub enc_log: EncLogMap,
    /// Edit-and-Continue token mapping for debugging scenarios.
    pub enc_map: EncMapMap,

    // === Portable PDB Debug Tables ===
    /// Document information for source file mapping in Portable PDB format.
    pub document: DocumentMap,
    /// Method debugging information including sequence points.
    pub method_debug_information: MethodDebugInformationMap,
    /// Local variable scope information for debugging.
    pub local_scope: LocalScopeMap,
    /// Local variable information for debugging.
    pub local_variable: LocalVariableMap,
    /// Local constant information for debugging.
    pub local_constant: LocalConstantMap,
    /// Import scope information for debugging.
    pub import_scope: ImportScopeMap,
    /// State machine method mapping for async/iterator debugging.
    pub state_machine_method: StateMachineMethodMap,
    /// Custom debug information for extensible debugging metadata.
    pub custom_debug_information: CustomDebugInformationMap,

    // === Parameter and Generic Tables ===
    /// Parameter definitions for methods.
    pub param: ParamMap,
    /// Parameter pointer indirection table.
    pub param_ptr: ParamPtrMap,
    /// Generic parameter definitions for generic types and methods.
    pub generic_param: GenericParamMap,
    /// Constraints on generic parameters.
    pub generic_param_constraint: GenericParamConstraintMap,

    // === Property and Event Tables ===
    /// Property definitions in types.
    pub property: PropertyMap,
    /// Property pointer indirection table.
    pub property_ptr: PropertyPtrMap,
    /// Property map linking types to their properties.
    pub property_map: PropertyMapEntryMap,
    /// Event definitions in types.
    pub event: EventMap,
    /// Event pointer indirection table.
    pub event_ptr: EventPtrMap,
    /// Event map linking types to their events.
    pub event_map: EventMapEntryMap,

    // === Reference and Relationship Tables ===
    /// Member references to external methods and fields.
    pub member_ref: &'a MemberRefMap,
    /// Class layout information for explicit layout types.
    pub class_layout: ClassLayoutMap,
    /// Nested class relationships.
    pub nested_class: NestedClassMap,
    /// Interface implementation relationships.
    pub interface_impl: InterfaceImplMap,

    // === Metadata and Security Tables ===
    /// Constant values for fields, parameters, and properties.
    pub constant: ConstantMap,
    /// Custom attribute definitions.
    pub custom_attribute: CustomAttributeMap,
    /// Declarative security attributes.
    pub decl_security: &'a DeclSecurityMap,
    /// File definitions for multi-file assemblies.
    pub file: &'a FileMap,
    /// Exported type definitions.
    pub exported_type: &'a Exports,
    /// Standalone signature definitions.
    pub standalone_sig: StandAloneSigMap,

    // === High-Level Registries ===
    /// Import tracking for external dependencies.
    pub imports: &'a Imports,
    /// Resource management for embedded resources.
    pub resources: &'a Resources,
    /// Central type registry for all loaded types.
    pub types: &'a Arc<TypeRegistry>,
}

impl LoaderContext<'_> {
    /// Resolve a coded index to a [`crate::metadata::typesystem::CilTypeReference`].
    ///
    /// This method provides unified coded index resolution across all metadata tables
    /// during the loading process. It uses the [`crate::metadata::tables::CodedIndex`]'s table identifier
    /// and token to look up the corresponding entity in the appropriate table map,
    /// then converts it to the correct [`crate::metadata::typesystem::CilTypeReference`] variant.
    ///
    /// # Supported Tables
    ///
    /// The method handles resolution for all major metadata table types:
    /// - **Type Tables**: `TypeDef`, `TypeRef`, `TypeSpec`
    /// - **Method Tables**: `MethodDef`, `MemberRef`, `MethodSpec`  
    /// - **Field/Property Tables**: `Field`, `Property`, `Param`, `Event`
    /// - **Assembly Tables**: `Assembly`, `AssemblyRef`, Module, `ModuleRef`
    /// - **Generic Tables**: `GenericParam`, `GenericParamConstraint`
    /// - **Other Tables**: `File`, `ExportedType`, `StandAloneSig`, `DeclSecurity`, `InterfaceImpl`
    ///
    /// # Resolution Strategy
    ///
    /// 1. **Table Identification**: Uses the coded index's `tag` field to determine target table
    /// 2. **Token Lookup**: Searches the appropriate table map using the `token` field
    /// 3. **Reference Creation**: Converts the found entity to the correct reference type
    /// 4. **Fallback Handling**: Returns [`crate::metadata::typesystem::CilTypeReference::None`] for unresolved references
    ///
    /// # Arguments
    /// * `coded_index` - The [`crate::metadata::tables::CodedIndex`] containing table ID and token to resolve
    ///
    /// # Returns
    /// The corresponding [`crate::metadata::typesystem::CilTypeReference`] variant, or
    /// [`crate::metadata::typesystem::CilTypeReference::None`] if the coded index cannot be resolved.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::loader::context::LoaderContext;
    /// use dotscope::metadata::tables::{CodedIndex, TableId};
    /// use dotscope::metadata::token::Token;
    /// use dotscope::metadata::typesystem::CilTypeReference;
    ///
    /// # fn resolve_example(context: &LoaderContext) {
    /// // Resolve a TypeDef coded index
    /// let coded_index = CodedIndex {
    ///     tag: TableId::TypeDef,
    ///     token: Token::new(0x02000001),
    /// };
    ///
    /// match context.get_ref(&coded_index) {
    ///     CilTypeReference::TypeDef(type_def) => {
    ///         println!("Resolved TypeDef: {}", type_def.name);
    ///     }
    ///     CilTypeReference::None => {
    ///         println!("Could not resolve coded index");
    ///     }
    ///     _ => {
    ///         println!("Unexpected reference type");
    ///     }
    /// }
    ///
    /// // The method automatically handles different table types
    /// let method_index = CodedIndex {
    ///     tag: TableId::MethodDef,
    ///     token: Token::new(0x06000001),
    /// };
    /// let method_ref = context.get_ref(&method_index);
    /// # }
    /// ```
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently from multiple threads during parallel loading.
    pub fn get_ref(&self, coded_index: &CodedIndex) -> CilTypeReference {
        match coded_index.tag {
            TableId::TypeDef => {
                if let Some(type_def) = self.types.get(&coded_index.token) {
                    CilTypeReference::TypeDef(type_def.into())
                } else {
                    CilTypeReference::None
                }
            }
            TableId::TypeRef => {
                if let Some(type_ref) = self.types.get(&coded_index.token) {
                    CilTypeReference::TypeRef(type_ref.into())
                } else {
                    CilTypeReference::None
                }
            }
            TableId::TypeSpec => {
                if let Some(type_spec) = self.types.get(&coded_index.token) {
                    CilTypeReference::TypeSpec(type_spec.into())
                } else {
                    CilTypeReference::None
                }
            }
            TableId::MethodDef => {
                if let Some(method_def) = self.method_def.get(&coded_index.token) {
                    CilTypeReference::MethodDef(method_def.value().clone().into())
                } else {
                    CilTypeReference::None
                }
            }
            TableId::MemberRef => {
                if let Some(member_ref) = self.member_ref.get(&coded_index.token) {
                    CilTypeReference::MemberRef(member_ref.value().clone())
                } else {
                    CilTypeReference::None
                }
            }
            TableId::Field => {
                if let Some(field) = self.field.get(&coded_index.token) {
                    CilTypeReference::Field(field.value().clone())
                } else {
                    CilTypeReference::None
                }
            }
            TableId::Param => {
                if let Some(param) = self.param.get(&coded_index.token) {
                    CilTypeReference::Param(param.value().clone())
                } else {
                    CilTypeReference::None
                }
            }
            TableId::Property => {
                if let Some(property) = self.property.get(&coded_index.token) {
                    CilTypeReference::Property(property.value().clone())
                } else {
                    CilTypeReference::None
                }
            }
            TableId::Event => {
                if let Some(event) = self.event.get(&coded_index.token) {
                    CilTypeReference::Event(event.value().clone())
                } else {
                    CilTypeReference::None
                }
            }
            TableId::InterfaceImpl => {
                if let Some(interface_impl) = self.interface_impl.get(&coded_index.token) {
                    CilTypeReference::InterfaceImpl(interface_impl.value().clone())
                } else {
                    CilTypeReference::None
                }
            }
            TableId::Module => {
                if let Some(module) = self.module.get() {
                    CilTypeReference::Module(module.clone())
                } else {
                    CilTypeReference::None
                }
            }
            TableId::ModuleRef => {
                if let Some(module_ref) = self.module_ref.get(&coded_index.token) {
                    CilTypeReference::ModuleRef(module_ref.value().clone())
                } else {
                    CilTypeReference::None
                }
            }
            TableId::Assembly => {
                if let Some(assembly) = self.assembly.get() {
                    CilTypeReference::Assembly(assembly.clone())
                } else {
                    CilTypeReference::None
                }
            }
            TableId::AssemblyRef => {
                if let Some(assembly_ref) = self.assembly_ref.get(&coded_index.token) {
                    CilTypeReference::AssemblyRef(assembly_ref.value().clone())
                } else {
                    CilTypeReference::None
                }
            }
            TableId::File => {
                if let Some(file) = self.file.get(&coded_index.token) {
                    CilTypeReference::File(file.value().clone())
                } else {
                    CilTypeReference::None
                }
            }
            TableId::ExportedType => {
                if let Some(exported_type) = self.exported_type.get(&coded_index.token) {
                    CilTypeReference::ExportedType(exported_type.value().clone())
                } else {
                    CilTypeReference::None
                }
            }
            TableId::GenericParam => {
                if let Some(generic_param) = self.generic_param.get(&coded_index.token) {
                    CilTypeReference::GenericParam(generic_param.value().clone())
                } else {
                    CilTypeReference::None
                }
            }
            TableId::GenericParamConstraint => {
                if let Some(constraint) = self.generic_param_constraint.get(&coded_index.token) {
                    CilTypeReference::GenericParamConstraint(constraint.value().clone())
                } else {
                    CilTypeReference::None
                }
            }
            TableId::MethodSpec => {
                if let Some(method_spec) = self.method_spec.get(&coded_index.token) {
                    CilTypeReference::MethodSpec(method_spec.value().clone())
                } else {
                    CilTypeReference::None
                }
            }
            TableId::DeclSecurity => {
                if let Some(decl_security) = self.decl_security.get(&coded_index.token) {
                    CilTypeReference::DeclSecurity(decl_security.value().clone())
                } else {
                    CilTypeReference::None
                }
            }
            TableId::StandAloneSig => {
                if let Some(standalone_sig) = self.standalone_sig.get(&coded_index.token) {
                    CilTypeReference::StandAloneSig(standalone_sig.value().clone())
                } else {
                    CilTypeReference::None
                }
            }
            _ => CilTypeReference::None,
        }
    }
}
