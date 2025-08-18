//! Core data structure for .NET assembly metadata storage and processing.
//!
//! This module contains [`CilObjectData`], the primary internal data holder for all parsed
//! metadata from a .NET assembly. It serves as the foundation for the metadata loading
//! pipeline and coordinates the parallel parsing of metadata tables, streams, and
//! cross-references.
//!
//! # Architecture Overview
//!
//! The [`CilObjectData`] structure follows a two-phase loading approach:
//! 1. **Stream Parsing**: Load metadata streams (#Strings, #Blob, #GUID, etc.)
//! 2. **Parallel Loading**: Execute specialized loaders for different table categories
//!
//! # Internal Use Only
//!
//! This module is designed for internal use by the loader system and should not be
//! exposed to external users. The public API is provided through [`crate::CilObject`]
//! which wraps and manages the underlying [`CilObjectData`].
//!
//! # Loading Pipeline
//!
//! ```text
//! File Input → Stream Parsing → Context Creation → Parallel Loaders → Final Object
//!     ↓              ↓               ↓                    ↓              ↓
//!   Raw PE      #Strings,etc.   LoaderContext      Table Population   CilObject
//!  Assembly       Streams        Creation          & Cross-refs      Ready for Use
//! ```
//!
//! # Key Components
//!
//! - **Metadata Streams**: String heap, blob heap, GUID heap, user strings
//! - **Table Maps**: Concurrent containers for all metadata table types
//! - **Type System**: Central registry for type definitions and references
//! - **Import/Export**: Dependency tracking and external reference management
//! - **Resources**: Embedded resource management and access
//!
//! # Memory Management
//!
//! The structure uses careful memory management:
//! - **Reference Counting**: Shared ownership of complex objects
//! - **Lazy Loading**: Some components use `OnceLock` for deferred initialization
//! - **Concurrent Access**: Thread-safe data structures for parallel loading
//!
//! # Error Handling
//!
//! Loading operations can fail due to:
//! - **Malformed Metadata**: Invalid stream layouts or table structures
//! - **Version Incompatibility**: Unsupported metadata format versions
//! - **Resource Constraints**: Memory allocation failures
//! - **File Corruption**: Inconsistent or damaged assembly files
//!
//! # Thread Safety
//!
//! All components in this module are designed for safe concurrent access during parallel loading.
//! The internal data structures are [`std::marker::Send`] and [`std::marker::Sync`],
//! enabling parallel metadata processing across multiple threads with lock-free data structures.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::loader::context`] - Loading context creation and parallel coordination
//! - [`crate::metadata::streams`] - Metadata stream parsing and validation
//! - [`crate::metadata::typesystem`] - Type registry initialization and management
//! - [`crate::metadata::tables`] - Metadata table loading and cross-reference resolution

use std::sync::{Arc, OnceLock};

use crossbeam_skiplist::SkipMap;

use crate::{
    metadata::{
        cilassemblyview::CilAssemblyView,
        exports::{NativeExports, UnifiedExportContainer},
        imports::{NativeImports, UnifiedImportContainer},
        loader::{execute_loaders_in_parallel, LoaderContext},
        method::MethodMap,
        resources::Resources,
        tables::{
            AssemblyOsRc, AssemblyProcessorRc, AssemblyRc, AssemblyRefMap, DeclSecurityMap,
            FileMap, MemberRefMap, MethodSpecMap, ModuleRc, ModuleRefMap,
        },
        typesystem::TypeRegistry,
    },
    Result,
};

/// Core data structure holding all parsed metadata for a .NET assembly.
///
/// This structure serves as the central repository for all metadata extracted from a
/// .NET assembly file. It coordinates the parsing of PE headers, metadata streams,
/// and table structures while providing the foundation for parallel metadata loading
/// operations.
///
/// # Structure Organization
///
/// **File Context**: Original file reference and raw binary data
/// **Headers**: CLR header and metadata root information\
/// **Streams**: Parsed metadata streams (strings, blobs, GUIDs, etc.)
/// **Tables**: Concurrent maps for all metadata table types
/// **Registries**: Type system, imports, exports, and resource management
///
/// # Loading Process
///
/// 1. **Initialization**: Parse PE headers and locate metadata
/// 2. **Stream Loading**: Extract and parse metadata streams via `load_streams`
/// 3. **Context Creation**: Build internal loader context for parallel loading
/// 4. **Parallel Execution**: Run specialized loaders for different table categories
/// 5. **Finalization**: Complete cross-references and semantic relationships
///
/// # Memory Layout
///
/// The structure maintains careful separation between:
/// - **Owned Data**: Parsed structures and computed relationships
/// - **Shared Data**: Reference-counted objects for concurrent access
/// - **Lazy Data**: Deferred initialization for optional components
///
/// # Thread Safety
///
/// [`CilObjectData`] is [`std::marker::Send`] and [`std::marker::Sync`], designed for safe concurrent access:
/// - Metadata streams are immutable after parsing
/// - Table maps use concurrent data structures ([`crossbeam_skiplist::SkipMap`])
/// - Reference counting enables safe sharing via [`std::sync::Arc`]
/// - Atomic operations coordinate loader synchronization using [`std::sync::OnceLock`]
/// - Lock-free access patterns minimize contention during parallel loading
///
/// # Internal Use
///
/// This structure is internal to the loader system. External code should use
/// [`crate::CilObject`] which provides a safe, ergonomic interface to the
/// underlying metadata.
pub(crate) struct CilObjectData {
    /// Assembly references to external .NET assemblies.
    pub refs_assembly: AssemblyRefMap,
    /// Module references to external modules and native libraries.
    pub refs_module: ModuleRefMap,
    /// Member references to external methods and fields.
    pub refs_member: MemberRefMap,
    /// File references for multi-file assemblies.
    pub refs_file: FileMap,
    /// Security declarations for permissions and security attributes.
    pub decl_security: DeclSecurityMap,

    /// Primary module definition for this assembly.
    pub module: Arc<OnceLock<ModuleRc>>,
    /// Assembly definition containing version and identity information.
    pub assembly: Arc<OnceLock<AssemblyRc>>,
    /// Operating system requirements for the assembly.
    pub assembly_os: Arc<OnceLock<AssemblyOsRc>>,
    /// Processor architecture requirements for the assembly.
    pub assembly_processor: Arc<OnceLock<AssemblyProcessorRc>>,

    /// Central type registry managing all type definitions and references.
    pub types: Arc<TypeRegistry>,
    /// Unified import container for both CIL and native imports.
    pub import_container: UnifiedImportContainer,
    /// Unified export container for both CIL and native exports.
    pub export_container: UnifiedExportContainer,
    /// Method definitions and implementation details.
    pub methods: MethodMap,
    /// Generic method instantiation specifications.
    pub method_specs: MethodSpecMap,
    /// Embedded resource management and access.
    pub resources: Resources,
}

impl CilObjectData {
    /// Parse and load .NET assembly metadata from a CilAssemblyView.
    ///
    /// This is the main entry point for loading metadata from a .NET assembly.
    /// It adapts the existing complex multi-threaded loader to work with CilAssemblyView
    /// instead of direct file access, preserving all the sophisticated parallel loading
    /// architecture while eliminating lifetime dependencies.
    ///
    /// # Loading Pipeline
    ///
    /// 1. **Initialize Concurrent Containers**: Create all SkipMap containers for parallel loading
    /// 2. **Native Table Loading**: Load PE import/export tables via CilAssemblyView
    /// 3. **Context Creation**: Build internal loader context using CilAssemblyView
    /// 4. **Parallel Loading**: Execute the same complex parallel loaders as before
    /// 5. **Cross-Reference Resolution**: Build semantic relationships between tables
    ///
    /// # Arguments
    /// * `view` - Reference to the CilAssemblyView containing parsed raw metadata
    ///
    /// # Returns
    /// A fully loaded [`CilObjectData`] instance ready for metadata queries and analysis.
    ///
    /// # Errors
    /// Returns [`crate::Error`] if:
    /// - **Metadata Format**: Malformed metadata streams or tables
    /// - **Version Support**: Unsupported metadata format version
    /// - **Memory**: Insufficient memory for loading large assemblies
    /// - **Corruption**: Inconsistent or damaged metadata structures
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::loader::data::CilObjectData;
    /// use dotscope::metadata::cilassemblyview::CilAssemblyView;
    ///
    /// # fn load_assembly_example() -> dotscope::Result<()> {
    /// // Create CilAssemblyView first
    /// let view = CilAssemblyView::from_file("example.dll")?;
    ///
    /// // Load resolved metadata using the view
    /// let cil_data = CilObjectData::from_assembly_view(&view)?;
    ///
    /// // Metadata is now ready for use
    /// println!("Loaded {} types", cil_data.types.len());
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe but should only be called once per CilAssemblyView.
    /// The resulting [`CilObjectData`] can be safely accessed from multiple threads.
    pub(crate) fn from_assembly_view(view: &CilAssemblyView) -> Result<Self> {
        let mut cil_object = CilObjectData {
            refs_assembly: SkipMap::default(),
            refs_module: SkipMap::default(),
            refs_member: SkipMap::default(),
            refs_file: SkipMap::default(),
            decl_security: SkipMap::default(),
            module: Arc::new(OnceLock::new()),
            assembly: Arc::new(OnceLock::new()),
            assembly_os: Arc::new(OnceLock::new()),
            assembly_processor: Arc::new(OnceLock::new()),
            types: Arc::new(TypeRegistry::new()?),
            import_container: UnifiedImportContainer::new(),
            export_container: UnifiedExportContainer::new(),
            methods: SkipMap::default(),
            method_specs: SkipMap::default(),
            resources: Resources::new(view.file().clone()),
        };

        cil_object.load_native_tables(view)?;

        {
            let context = LoaderContext {
                input: view.file().clone(),
                data: view.data(),
                header: view.cor20header(),
                header_root: view.metadata_root(),
                meta: view.tables(),
                strings: view.strings(),
                userstrings: view.userstrings(),
                guids: view.guids(),
                blobs: view.blobs(),
                assembly: &cil_object.assembly,
                assembly_os: &cil_object.assembly_os,
                assembly_processor: &cil_object.assembly_processor,
                assembly_ref: &cil_object.refs_assembly,
                assembly_ref_os: SkipMap::default(),
                assembly_ref_processor: SkipMap::default(),
                module: &cil_object.module,
                module_ref: &cil_object.refs_module,
                type_spec: SkipMap::default(),
                method_def: &cil_object.methods,
                method_impl: SkipMap::default(),
                method_semantics: SkipMap::default(),
                method_spec: &cil_object.method_specs,
                field: SkipMap::default(),
                field_ptr: SkipMap::default(),
                method_ptr: SkipMap::default(),
                field_layout: SkipMap::default(),
                field_marshal: SkipMap::default(),
                field_rva: SkipMap::default(),
                enc_log: SkipMap::default(),
                enc_map: SkipMap::default(),
                document: SkipMap::default(),
                method_debug_information: SkipMap::default(),
                local_scope: SkipMap::default(),
                local_variable: SkipMap::default(),
                local_constant: SkipMap::default(),
                import_scope: SkipMap::default(),
                state_machine_method: SkipMap::default(),
                custom_debug_information: SkipMap::default(),
                param: SkipMap::default(),
                param_ptr: SkipMap::default(),
                generic_param: SkipMap::default(),
                generic_param_constraint: SkipMap::default(),
                property: SkipMap::default(),
                property_ptr: SkipMap::default(),
                property_map: SkipMap::default(),
                event: SkipMap::default(),
                event_ptr: SkipMap::default(),
                event_map: SkipMap::default(),
                member_ref: &cil_object.refs_member,
                class_layout: SkipMap::default(),
                nested_class: SkipMap::default(),
                interface_impl: SkipMap::default(),
                constant: SkipMap::default(),
                custom_attribute: SkipMap::default(),
                decl_security: &cil_object.decl_security,
                file: &cil_object.refs_file,
                exported_type: cil_object.export_container.cil(),
                standalone_sig: SkipMap::default(),
                imports: cil_object.import_container.cil(),
                resources: &cil_object.resources,
                types: &cil_object.types,
            };

            execute_loaders_in_parallel(&context)?;
        }

        Ok(cil_object)
    }

    /// Load native PE import and export tables from CilAssemblyView.
    ///
    /// This method adapts the existing native table loading to work with CilAssemblyView
    /// instead of direct file access. It preserves the same functionality while using
    /// the new data access pattern.
    ///
    /// # Arguments
    /// * `view` - Reference to the CilAssemblyView containing the file
    ///
    /// # Returns
    /// Result indicating success or failure of the loading operation.
    ///
    /// # Errors
    /// Returns error if:
    /// - Import/export table parsing fails
    /// - Native container population fails
    fn load_native_tables(&mut self, view: &CilAssemblyView) -> Result<()> {
        if let Some(owned_imports) = view.file().imports() {
            if !owned_imports.is_empty() {
                let native_imports = NativeImports::from_pe_imports(owned_imports)?;
                *self.import_container.native_mut() = native_imports;
            }
        }

        if let Some(owned_exports) = view.file().exports() {
            if !owned_exports.is_empty() {
                let native_exports = NativeExports::from_pe_exports(owned_exports)?;
                *self.export_container.native_mut() = native_exports;
            }
        }

        Ok(())
    }
}
