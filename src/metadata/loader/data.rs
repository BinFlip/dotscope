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
//! - **Zero-Copy Streams**: Metadata streams reference original file data
//! - **Reference Counting**: Shared ownership of complex objects
//! - **Lazy Loading**: Some components use OnceLock for deferred initialization
//! - **Concurrent Access**: Thread-safe data structures for parallel loading
//!
//! # Error Handling
//!
//! Loading operations can fail due to:
//! - **Malformed Metadata**: Invalid stream layouts or table structures
//! - **Version Incompatibility**: Unsupported metadata format versions
//! - **Resource Constraints**: Memory allocation failures
//! - **File Corruption**: Inconsistent or damaged assembly files

use std::sync::{Arc, OnceLock};

use crossbeam_skiplist::SkipMap;

use crate::{
    file::File,
    metadata::{
        cor20header::Cor20Header,
        exports::Exports,
        imports::Imports,
        loader::{execute_loaders_in_parallel, LoaderContext},
        method::MethodMap,
        resources::Resources,
        root::Root,
        streams::{Blob, Guid, Strings, TablesHeader, UserStrings},
        tables::{
            AssemblyOsRc, AssemblyProcessorRc, AssemblyRc, AssemblyRefMap, FileMap, MemberRefMap,
            MethodSpecMap, ModuleRc, ModuleRefMap,
        },
        typesystem::TypeRegistry,
    },
    Error::NotSupported,
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
/// **Headers**: CLR header and metadata root information  
/// **Streams**: Parsed metadata streams (strings, blobs, GUIDs, etc.)
/// **Tables**: Concurrent maps for all metadata table types
/// **Registries**: Type system, imports, exports, and resource management
///
/// # Loading Process
///
/// 1. **Initialization**: Parse PE headers and locate metadata
/// 2. **Stream Loading**: Extract and parse metadata streams via [`load_streams`](Self::load_streams)
/// 3. **Context Creation**: Build [`crate::metadata::loader::context::LoaderContext`] for parallel loading
/// 4. **Parallel Execution**: Run specialized loaders for different table categories
/// 5. **Finalization**: Complete cross-references and semantic relationships
///
/// # Memory Layout
///
/// The structure maintains careful separation between:
/// - **Borrowed Data**: Zero-copy references to original file content
/// - **Owned Data**: Parsed structures and computed relationships
/// - **Shared Data**: Reference-counted objects for concurrent access
/// - **Lazy Data**: Deferred initialization for optional components
///
/// # Thread Safety
///
/// Designed for safe concurrent access during parallel loading:
/// - Metadata streams are immutable after parsing
/// - Table maps use concurrent data structures
/// - Reference counting enables safe sharing
/// - Atomic operations coordinate loader synchronization
///
/// # Internal Use
///
/// This structure is internal to the loader system. External code should use
/// [`crate::CilObject`] which provides a safe, ergonomic interface to the
/// underlying metadata.
pub(crate) struct CilObjectData<'a> {
    // === File Context ===
    /// Reference to the original assembly file for offset calculations and data access.
    pub file: Arc<File>,
    /// Raw binary data of the entire assembly file.
    pub data: &'a [u8],

    // === Headers ===
    /// CLR 2.0 header containing metadata directory information.
    pub header: Cor20Header,
    /// Metadata root header with stream definitions and layout.
    pub header_root: Root,

    // === Metadata Streams ===
    /// Tables stream containing all metadata table definitions and data.
    pub meta: Option<TablesHeader<'a>>,
    /// String heap containing UTF-8 encoded names and identifiers.
    pub strings: Option<Strings<'a>>,
    /// User string heap containing literal string constants from IL code.
    pub userstrings: Option<UserStrings<'a>>,
    /// GUID heap containing unique identifiers for types and assemblies.
    pub guids: Option<Guid<'a>>,
    /// Blob heap containing binary data (signatures, custom attributes, etc.).
    pub blobs: Option<Blob<'a>>,

    // === Reference Tables ===
    /// Assembly references to external .NET assemblies.
    pub refs_assembly: AssemblyRefMap,
    /// Module references to external modules and native libraries.
    pub refs_module: ModuleRefMap,
    /// Member references to external methods and fields.
    pub refs_member: MemberRefMap,
    /// File references for multi-file assemblies.
    pub refs_file: FileMap,

    // === Assembly Metadata ===
    /// Primary module definition for this assembly.
    pub module: Arc<OnceLock<ModuleRc>>,
    /// Assembly definition containing version and identity information.
    pub assembly: Arc<OnceLock<AssemblyRc>>,
    /// Operating system requirements for the assembly.
    pub assembly_os: Arc<OnceLock<AssemblyOsRc>>,
    /// Processor architecture requirements for the assembly.
    pub assembly_processor: Arc<OnceLock<AssemblyProcessorRc>>,

    // === Core Registries ===
    /// Central type registry managing all type definitions and references.
    pub types: Arc<TypeRegistry>,
    /// Import tracking for external dependencies and P/Invoke.
    pub imports: Imports,
    /// Export tracking for types visible to other assemblies.
    pub exports: Exports,
    /// Method definitions and implementation details.
    pub methods: MethodMap,
    /// Generic method instantiation specifications.
    pub method_specs: MethodSpecMap,
    /// Embedded resource management and access.
    pub resources: Resources,
}

impl<'a> CilObjectData<'a> {
    /// Parse and load .NET assembly metadata from a file.
    ///
    /// This is the main entry point for loading metadata from a .NET assembly file.
    /// It performs the complete loading pipeline: header parsing, stream extraction,
    /// parallel table loading, and cross-reference resolution.
    ///
    /// # Loading Pipeline
    ///
    /// 1. **Header Parsing**: Extract CLR header and metadata root from PE file
    /// 2. **Stream Loading**: Parse metadata streams (#Strings, #Blob, etc.)
    /// 3. **Context Creation**: Build [`crate::metadata::loader::context::LoaderContext`] for parallel operations
    /// 4. **Parallel Loading**: Execute specialized loaders for different table categories
    /// 5. **Cross-Reference Resolution**: Build semantic relationships between tables
    ///
    /// # Arguments
    /// * `file` - Reference to the parsed PE file containing the assembly
    /// * `data` - Raw binary data of the entire assembly file
    ///
    /// # Returns
    /// A fully loaded [`CilObjectData`] instance ready for metadata queries and analysis.
    ///
    /// # Errors
    /// Returns [`crate::Error`] if:
    /// - **File Format**: Invalid PE file or missing CLR header
    /// - **Metadata Format**: Malformed metadata streams or tables
    /// - **Version Support**: Unsupported metadata format version
    /// - **Memory**: Insufficient memory for loading large assemblies
    /// - **Corruption**: Inconsistent or damaged metadata structures
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::loader::data::CilObjectData;
    /// use dotscope::file::File;
    /// use std::sync::Arc;
    ///
    /// # fn load_assembly_example() -> dotscope::Result<()> {
    /// // Parse PE file
    /// let file_data = std::fs::read("example.dll")?;
    /// let file = Arc::new(File::from_data(&file_data)?);
    ///
    /// // Load metadata
    /// let cil_data = CilObjectData::from_file(file, &file_data)?;
    ///
    /// // Metadata is now ready for use
    /// println!("Loaded {} types", cil_data.types.len());
    /// # Ok(())
    /// # }
    /// ```
    pub(crate) fn from_file(file: Arc<File>, data: &'a [u8]) -> Result<Self> {
        let (clr_rva, clr_size) = file.clr();
        let clr_slice = file.data_slice(file.rva_to_offset(clr_rva)?, clr_size)?;

        let header = Cor20Header::read(clr_slice)?;

        let meta_root_offset = file.rva_to_offset(header.meta_data_rva as usize)?;
        let meta_root_slice = file.data_slice(meta_root_offset, header.meta_data_size as usize)?;

        let header_root = Root::read(meta_root_slice)?;

        let mut cil_object = CilObjectData {
            file: file.clone(),
            data,
            header,
            header_root,
            meta: None,
            strings: None,
            userstrings: None,
            guids: None,
            blobs: None,
            refs_assembly: SkipMap::default(),
            refs_module: SkipMap::default(),
            refs_member: SkipMap::default(),
            refs_file: SkipMap::default(),
            module: Arc::new(OnceLock::new()),
            assembly: Arc::new(OnceLock::new()),
            assembly_os: Arc::new(OnceLock::new()),
            assembly_processor: Arc::new(OnceLock::new()),
            types: Arc::new(TypeRegistry::new()?),
            imports: Imports::new(),
            exports: Exports::new(),
            methods: SkipMap::default(),
            method_specs: SkipMap::default(),
            resources: Resources::new(file),
        };

        cil_object.load_streams(meta_root_offset)?;

        {
            let context = LoaderContext {
                input: cil_object.file.clone(),
                data,
                header: &cil_object.header,
                header_root: &cil_object.header_root,
                meta: &cil_object.meta,
                strings: &cil_object.strings,
                userstrings: &cil_object.userstrings,
                guids: &cil_object.guids,
                blobs: &cil_object.blobs,
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
                decl_security: SkipMap::default(),
                file: &cil_object.refs_file,
                exported_type: &cil_object.exports,
                standalone_sig: SkipMap::default(),
                imports: &cil_object.imports,
                resources: &cil_object.resources,
                types: &cil_object.types,
            };

            execute_loaders_in_parallel(&context)?;
        };

        Ok(cil_object)
    }

    /// Parse and load metadata streams from the assembly file.
    ///
    /// This method extracts and parses the various metadata streams embedded in the
    /// .NET assembly according to the ECMA-335 specification. Each stream contains
    /// different types of metadata required for assembly processing.
    ///
    /// # Supported Streams
    ///
    /// - **`#~` or `#-`**: Tables stream containing metadata table definitions
    /// - **`#Strings`**: String heap with UTF-8 encoded names and identifiers
    /// - **`#US`**: User string heap with literal strings from IL code
    /// - **`#GUID`**: GUID heap containing unique identifiers
    /// - **`#Blob`**: Blob heap with binary data (signatures, custom attributes)
    ///
    /// # Stream Processing
    ///
    /// 1. **Offset Calculation**: Compute absolute file positions for each stream
    /// 2. **Bounds Checking**: Validate stream boundaries within file limits
    /// 3. **Stream Parsing**: Extract stream data using appropriate parsers
    /// 4. **Layout Validation**: Verify overall metadata layout consistency
    ///
    /// # Arguments
    /// * `meta_root_offset` - Absolute file offset of the metadata root header
    ///
    /// # Errors
    /// Returns [`crate::Error::Malformed`] if:
    /// - Stream offsets cause integer overflow
    /// - Stream boundaries exceed file size
    /// - Unknown or unsupported stream types encountered
    /// - Stream data is corrupted or invalid
    ///
    /// # Stream Layout
    ///
    /// ```text
    /// Metadata Root
    /// ├── Stream Header 1 → #Strings
    /// ├── Stream Header 2 → #US  
    /// ├── Stream Header 3 → #GUID
    /// ├── Stream Header 4 → #Blob
    /// └── Stream Header 5 → #~
    /// ```
    fn load_streams(&mut self, meta_root_offset: usize) -> Result<()> {
        for stream in &self.header_root.stream_headers {
            let Some(start) = usize::checked_add(meta_root_offset, stream.offset as usize) else {
                return Err(malformed_error!(
                    "Loading streams failed! 'start' - Integer overflow = {} + {}",
                    meta_root_offset,
                    stream.offset
                ));
            };

            let Some(end) = start.checked_add(stream.size as usize) else {
                return Err(malformed_error!(
                    "Loading streams failed! 'end' - Integer overflow = {} + {}",
                    start,
                    stream.offset
                ));
            };

            if start >= self.data.len() || end >= self.data.len() {
                return Err(malformed_error!(
                    "Loading streams failed! 'start' and/or 'end' are too large - {} + {}",
                    start,
                    end
                ));
            }

            match stream.name.as_str() {
                "#~" | "#-" => self.meta = Some(TablesHeader::from(&self.data[start..end])?),
                "#Strings" => self.strings = Some(Strings::from(&self.data[start..end])?),
                "#US" => self.userstrings = Some(UserStrings::from(&self.data[start..end])?),
                "#GUID" => self.guids = Some(Guid::from(&self.data[start..end])?),
                "#Blob" => self.blobs = Some(Blob::from(&self.data[start..end])?),
                _ => return Err(NotSupported),
            }
        }

        self.header_root
            .validate_stream_layout(meta_root_offset, self.header.meta_data_size)?;

        Ok(())
    }
}
