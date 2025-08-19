//! Raw assembly view for editing and modification operations.
//!
//! This module provides the [`crate::metadata::cilassemblyview::CilAssemblyView`] struct, which offers a read-only
//! representation of .NET assemblies that maintains a 1:1 mapping with the underlying
//! file structure. Unlike [`crate::CilObject`] which provides a fully processed and
//! resolved view optimized for analysis, [`crate::metadata::cilassemblyview::CilAssemblyView`] preserves the raw metadata
//! structure to enable future editing and modification operations.
//!
//! # Architecture
//!
//! The module is built around a self-referencing pattern that enables efficient access to
//! file data while maintaining memory safety. The architecture provides:
//!
//! - **Raw Structure Access**: Direct access to metadata tables and streams without resolution
//! - **Immutable View**: Read-only operations to ensure data integrity during analysis
//! - **Editing Foundation**: Structured to support future writable operations
//! - **Memory Efficient**: Self-referencing pattern avoids data duplication
//! - **No Validation**: Pure parsing without format validation or compliance checks
//!
//! # Key Components
//!
//! ## Core Types
//! - [`crate::metadata::cilassemblyview::CilAssemblyView`] - Main assembly view struct with file-mapped data
//! - [`crate::metadata::cilassemblyview::CilAssemblyViewData`] - Internal data structure holding raw metadata
//!
//! ## Access Methods
//! - [`crate::metadata::cilassemblyview::CilAssemblyView::tables`] - Raw metadata tables without semantic resolution
//! - [`crate::metadata::cilassemblyview::CilAssemblyView::strings`] - Direct access to strings heap (#Strings)
//! - [`crate::metadata::cilassemblyview::CilAssemblyView::userstrings`] - Direct access to user strings heap (#US)
//! - [`crate::metadata::cilassemblyview::CilAssemblyView::guids`] - Direct access to GUID heap (#GUID)
//! - [`crate::metadata::cilassemblyview::CilAssemblyView::blobs`] - Direct access to blob heap (#Blob)
//!
//! ## Conversion Methods
//! - [`crate::metadata::cilassemblyview::CilAssemblyView::to_owned`] - Convert to mutable [`crate::CilAssembly`] for editing
//!
//! # Usage Examples
//!
//! ## Basic Raw Metadata Access
//!
//! ```rust,ignore
//! use dotscope::CilAssemblyView;
//! use std::path::Path;
//!
//! // Load assembly for potential editing operations
//! let view = CilAssemblyView::from_file(Path::new("assembly.dll"))?;
//!
//! // Access raw metadata structures
//! if let Some(tables) = view.tables() {
//!     println!("Schema version: {}.{}", tables.major_version, tables.minor_version);
//! }
//!
//! // Access string heaps directly
//! if let Some(strings) = view.strings() {
//!     if let Ok(name) = strings.get(0x123) {
//!         println!("Raw string: {}", name);
//!     }
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Converting to Mutable Assembly
//!
//! ```rust,ignore
//! use dotscope::{CilAssemblyView, CilAssembly};
//! use std::path::Path;
//!
//! // Load raw view
//! let view = CilAssemblyView::from_file(Path::new("assembly.dll"))?;
//!
//! // Convert to mutable assembly for editing
//! let mut assembly = view.to_owned();
//!
//! // Now you can perform editing operations
//! let string_index = assembly.add_string("New String")?;
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Analyzing Raw Structures
//!
//! ```rust,ignore
//! use dotscope::CilAssemblyView;
//! use std::path::Path;
//!
//! let view = CilAssemblyView::from_file(Path::new("assembly.dll"))?;
//!
//! // Direct access to CLR header
//! let cor20 = view.with_data(|data| &data.cor20header);
//! println!("Runtime version: {}.{}", cor20.major_runtime_version, cor20.minor_runtime_version);
//!
//! // Raw metadata root access
//! let root = view.with_data(|data| &data.metadata_root);
//! println!("Metadata signature: {:?}", root.signature);
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Thread Safety
//!
//! [`crate::metadata::cilassemblyview::CilAssemblyView`] is [`std::marker::Send`] and [`std::marker::Sync`] as it provides read-only access
//! to immutable file data. Multiple threads can safely access the same view concurrently
//! without additional synchronization.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::CilAssembly`] - Provides conversion to mutable assembly for editing operations
//! - [`crate::metadata::streams`] - Uses stream types for direct heap access
//! - [`crate::metadata::cor20header`] - Provides CLR header information
//! - File I/O abstraction for memory-mapped or in-memory access

use ouroboros::self_referencing;
use std::{path::Path, sync::Arc};

use crate::{
    cilassembly::CilAssembly,
    file::File,
    metadata::{
        cor20header::Cor20Header,
        root::Root,
        streams::{Blob, Guid, StreamHeader, Strings, TablesHeader, UserStrings},
        validation::ValidationEngine,
    },
    Error, Result, ValidationConfig,
};

/// Raw assembly view data holding references to file structures.
///
/// `CilAssemblyViewData` manages the parsed metadata structures while maintaining
/// direct references to the underlying file data. This structure is designed to
/// preserve the raw layout of metadata streams and tables as they appear in the
/// PE file, enabling future editing operations.
///
/// # Layout Preservation
///
/// Unlike `CilObjectData` which creates resolved and cross-referenced structures,
/// `CilAssemblyViewData` maintains:
/// - Raw metadata table data without resolution
/// - Direct stream references without semantic processing
/// - Original file offsets and layout information
/// - Unprocessed blob and signature data
pub struct CilAssemblyViewData<'a> {
    /// Reference to the owning File structure
    pub file: Arc<File>,

    /// Raw file data slice
    pub data: &'a [u8],

    /// COR20 header containing .NET-specific PE information
    pub cor20header: Cor20Header,

    /// Metadata root header with stream directory
    pub metadata_root: Root,

    /// Raw metadata tables header from #~ or #- stream
    pub metadata_tables: Option<TablesHeader<'a>>,

    /// Strings heap from #Strings stream
    pub strings: Option<Strings<'a>>,

    /// User strings heap from #US stream  
    pub userstrings: Option<UserStrings<'a>>,

    /// GUID heap from #GUID stream
    pub guids: Option<Guid<'a>>,

    /// Blob heap from #Blob stream
    pub blobs: Option<Blob<'a>>,
}

impl<'a> CilAssemblyViewData<'a> {
    /// Creates a new `CilAssemblyViewData` from file data.
    ///
    /// This method parses the essential .NET metadata structures while preserving
    /// their raw form. Unlike `CilObjectData::from_file`, this method:
    /// - Does not resolve cross-references between tables
    /// - Does not create semantic object representations
    /// - Preserves original file layout information
    /// - Focuses on structural metadata access
    /// - Performs no validation or compliance checking
    ///
    /// # Arguments
    ///
    /// * `file` - The File containing PE data
    /// * `data` - Raw file data slice
    ///
    /// # Returns
    ///
    /// Returns the parsed `CilAssemblyViewData` structure or an error if
    /// essential structures cannot be located (e.g., missing CLR header).
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::NotSupported`] if the file is not a .NET assembly (missing CLR header).
    /// Returns [`crate::Error::OutOfBounds`] if the file data is truncated or corrupted.
    pub fn from_file(file: Arc<File>, data: &'a [u8]) -> Result<Self> {
        let (clr_rva, clr_size) = file.clr();
        if clr_rva == 0 || clr_size == 0 {
            return Err(Error::NotSupported);
        }

        let clr_offset = file.rva_to_offset(clr_rva)?;
        let clr_end = clr_offset
            .checked_add(clr_size)
            .ok_or(out_of_bounds_error!())?;

        if clr_size > data.len() || clr_offset > data.len() || clr_end > data.len() {
            return Err(out_of_bounds_error!());
        }

        let cor20_header = Cor20Header::read(&data[clr_offset..clr_end])?;

        let metadata_offset = file.rva_to_offset(cor20_header.meta_data_rva as usize)?;
        let metadata_end = metadata_offset
            .checked_add(cor20_header.meta_data_size as usize)
            .ok_or(out_of_bounds_error!())?;

        if metadata_end > data.len() {
            return Err(out_of_bounds_error!());
        }

        let metadata_slice = &data[metadata_offset..metadata_end];
        let metadata_root = Root::read(metadata_slice)?;

        let mut metadata_tables = None;
        let mut strings_heap = None;
        let mut userstrings_heap = None;
        let mut guid_heap = None;
        let mut blob_heap = None;

        for stream in &metadata_root.stream_headers {
            let stream_offset = stream.offset as usize;
            let stream_size = stream.size as usize;
            let stream_end = stream_offset
                .checked_add(stream_size)
                .ok_or(out_of_bounds_error!())?;

            if stream_end > metadata_slice.len() {
                return Err(out_of_bounds_error!());
            }

            let stream_data = &metadata_slice[stream_offset..stream_end];

            match stream.name.as_str() {
                "#~" | "#-" => {
                    metadata_tables = Some(TablesHeader::from(stream_data)?);
                }
                "#Strings" => {
                    strings_heap = Some(Strings::from(stream_data)?);
                }
                "#US" => {
                    userstrings_heap = Some(UserStrings::from(stream_data)?);
                }
                "#GUID" => {
                    guid_heap = Some(Guid::from(stream_data)?);
                }
                "#Blob" => {
                    blob_heap = Some(Blob::from(stream_data)?);
                }
                _ => {}
            }
        }

        Ok(CilAssemblyViewData {
            file,
            data,
            cor20header: cor20_header,
            metadata_root,
            metadata_tables,
            strings: strings_heap,
            userstrings: userstrings_heap,
            guids: guid_heap,
            blobs: blob_heap,
        })
    }
}

#[self_referencing]
/// A read-only view of a .NET assembly optimized for editing operations.
///
/// `CilAssemblyView` provides raw access to .NET assembly metadata structures
/// while maintaining a 1:1 mapping with the underlying file format. This design
/// preserves the original file layout and structure to enable future editing
/// and modification capabilities.
///
/// # Key Differences from CilObject
///
/// - **Raw Access**: Direct access to metadata tables without semantic resolution
/// - **Structure Preservation**: Maintains original file layout and offsets
/// - **Editing Foundation**: Designed as the base for modification operations
/// - **Minimal Processing**: No cross-reference resolution or object construction
/// - **No Validation**: Pure parsing without format validation or compliance checks
///
/// # Architecture
///
/// The view uses a self-referencing pattern to maintain efficient access to
/// file data while ensuring memory safety. The structure provides:
/// - Direct access to all metadata streams (#~, #Strings, #US, #GUID, #Blob)
/// - Raw metadata table data without semantic interpretation
/// - Original stream headers and layout information
/// - File-level operations for RVA resolution and section access
///
/// # Thread Safety
///
/// `CilAssemblyView` is designed for concurrent read access and implements
/// `Send` and `Sync` for safe use across threads. All operations are read-only
/// and do not modify the underlying file data.
pub struct CilAssemblyView {
    /// Holds the input data, either as memory buffer or memory-mapped file
    file: Arc<File>,

    #[borrows(file)]
    #[not_covariant]
    /// Holds direct references to metadata structures in the file
    data: CilAssemblyViewData<'this>,
}

impl CilAssemblyView {
    /// Creates a new `CilAssemblyView` by loading a .NET assembly from disk.
    ///
    /// This method loads the assembly and parses essential metadata structures
    /// while preserving their raw format. The file is memory-mapped for
    /// efficient access to large assemblies.
    ///
    /// # Arguments
    ///
    /// * `file` - Path to the .NET assembly file (.dll, .exe, or .netmodule)
    ///
    /// # Returns
    ///
    /// Returns a `CilAssemblyView` providing raw access to assembly metadata
    /// or an error if the file cannot be loaded or essential structures are missing.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::FileError`] if the file cannot be read.
    /// Returns [`crate::Error::NotSupported`] if the file is not a .NET assembly.
    /// Returns [`crate::Error::OutOfBounds`] if the file data is corrupted.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::CilAssemblyView;
    /// use std::path::Path;
    ///
    /// let view = CilAssemblyView::from_file(Path::new("assembly.dll"))?;
    ///
    /// // Access raw metadata
    /// let root = view.metadata_root();
    /// println!("Metadata root loaded");
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn from_file(file: &Path) -> Result<Self> {
        Self::from_file_with_validation(file, ValidationConfig::disabled())
    }

    /// Creates a new `CilAssemblyView` by loading a .NET assembly from disk with custom validation configuration.
    ///
    /// This method allows you to control which validation checks are performed during loading.
    /// Raw validation (stage 1) is performed if enabled in the configuration.
    ///
    /// # Arguments
    ///
    /// * `file` - Path to the .NET assembly file (.dll, .exe, or .netmodule)
    /// * `validation_config` - Configuration specifying which validation checks to perform
    ///
    /// # Returns
    ///
    /// Returns a `CilAssemblyView` providing raw access to assembly metadata
    /// or an error if the file cannot be loaded, essential structures are missing,
    /// or validation checks fail.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::FileError`] if the file cannot be read.
    /// Returns [`crate::Error::NotSupported`] if the file is not a .NET assembly.
    /// Returns [`crate::Error::OutOfBounds`] if the file data is corrupted.
    /// Returns validation errors if validation checks fail.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::{CilAssemblyView, ValidationConfig};
    /// use std::path::Path;
    ///
    /// // Load with minimal validation for maximum performance
    /// let view = CilAssemblyView::from_file_with_validation(
    ///     Path::new("assembly.dll"),
    ///     ValidationConfig::minimal()
    /// )?;
    ///
    /// // Load with comprehensive validation for maximum safety
    /// let view = CilAssemblyView::from_file_with_validation(
    ///     Path::new("assembly.dll"),
    ///     ValidationConfig::comprehensive()
    /// )?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn from_file_with_validation(
        file: &Path,
        validation_config: ValidationConfig,
    ) -> Result<Self> {
        let input = Arc::new(File::from_file(file)?);
        Self::load_with_validation(input, validation_config)
    }

    /// Creates a new `CilAssemblyView` by parsing a .NET assembly from a memory buffer.
    ///
    /// This method is useful for analyzing assemblies that are already loaded
    /// in memory or obtained from external sources. The data is managed
    /// internally to ensure proper lifetime handling.
    ///
    /// # Arguments
    ///
    /// * `data` - Raw bytes of the .NET assembly in PE format
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::NotSupported`] if the data is not a .NET assembly.
    /// Returns [`crate::Error::OutOfBounds`] if the data is corrupted or truncated.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::CilAssemblyView;
    ///
    /// let file_data = std::fs::read("assembly.dll")?;
    /// let view = CilAssemblyView::from_mem(file_data)?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn from_mem(data: Vec<u8>) -> Result<Self> {
        Self::from_mem_with_validation(data, ValidationConfig::disabled())
    }

    /// Creates a new `CilAssemblyView` by parsing a .NET assembly from a memory buffer with custom validation configuration.
    ///
    /// This method allows you to control which validation checks are performed during loading.
    /// Raw validation (stage 1) is performed if enabled in the configuration.
    ///
    /// # Arguments
    ///
    /// * `data` - Raw bytes of the .NET assembly in PE format
    /// * `validation_config` - Configuration specifying which validation checks to perform
    ///
    /// # Returns
    ///
    /// Returns a `CilAssemblyView` providing raw access to assembly metadata
    /// or an error if the data cannot be parsed or validation checks fail.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::NotSupported`] if the data is not a .NET assembly.
    /// Returns [`crate::Error::OutOfBounds`] if the data is corrupted or truncated.
    /// Returns validation errors if validation checks fail.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::{CilAssemblyView, ValidationConfig};
    ///
    /// let file_data = std::fs::read("assembly.dll")?;
    ///
    /// // Load with production validation settings
    /// let view = CilAssemblyView::from_mem_with_validation(
    ///     file_data,
    ///     ValidationConfig::production()
    /// )?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn from_mem_with_validation(
        data: Vec<u8>,
        validation_config: ValidationConfig,
    ) -> Result<Self> {
        let input = Arc::new(File::from_mem(data)?);
        Self::load_with_validation(input, validation_config)
    }

    /// Internal method for loading a CilAssemblyView from a File structure with validation.
    ///
    /// This method serves as the common implementation for validation-enabled loading operations.
    /// It first loads the assembly normally, then performs raw validation (stage 1) if enabled
    /// in the configuration.
    ///
    /// # Arguments
    ///
    /// * `file` - Arc-wrapped File containing the PE assembly data
    /// * `validation_config` - Configuration specifying which validation checks to perform
    ///
    /// # Returns
    ///
    /// Returns a fully constructed `CilAssemblyView` with parsed metadata structures
    /// or an error if parsing or validation fails.
    fn load_with_validation(file: Arc<File>, validation_config: ValidationConfig) -> Result<Self> {
        let view = CilAssemblyView::try_new(file, |file| {
            CilAssemblyViewData::from_file(file.clone(), file.data())
        })?;

        if validation_config.should_validate_raw() {
            view.validate(validation_config)?;
        }

        Ok(view)
    }

    /// Returns the COR20 header containing .NET-specific PE information.
    ///
    /// The COR20 header provides essential information about the .NET assembly
    /// including metadata location, entry point, and runtime flags.
    ///
    /// # Returns
    ///
    /// Reference to the [`Cor20Header`] structure.
    #[must_use]
    pub fn cor20header(&self) -> &Cor20Header {
        self.with_data(|data| &data.cor20header)
    }

    /// Returns the metadata root header containing stream directory information.
    ///
    /// The metadata root is the entry point to .NET metadata, containing
    /// version information and the directory of all metadata streams.
    ///
    /// # Returns
    ///
    /// Reference to the [`Root`] structure.
    #[must_use]
    pub fn metadata_root(&self) -> &Root {
        self.with_data(|data| &data.metadata_root)
    }

    /// Returns raw access to the metadata tables from the #~ or #- stream.
    ///
    /// Provides direct access to the metadata tables structure without
    /// semantic interpretation or cross-reference resolution.
    ///
    /// # Returns
    ///
    /// - `Some(&TablesHeader)` if metadata tables are present
    /// - `None` if no tables stream exists
    #[must_use]
    pub fn tables(&self) -> Option<&TablesHeader<'_>> {
        self.with_data(|data| data.metadata_tables.as_ref())
    }

    /// Returns direct access to the strings heap from the #Strings stream.
    ///
    /// # Returns
    ///
    /// - `Some(&Strings)` if the strings heap is present
    /// - `None` if no #Strings stream exists
    #[must_use]
    pub fn strings(&self) -> Option<&Strings<'_>> {
        self.with_data(|data| data.strings.as_ref())
    }

    /// Returns direct access to the user strings heap from the #US stream.
    ///
    /// # Returns
    ///
    /// - `Some(&UserStrings)` if the user strings heap is present
    /// - `None` if no #US stream exists
    #[must_use]
    pub fn userstrings(&self) -> Option<&UserStrings<'_>> {
        self.with_data(|data| data.userstrings.as_ref())
    }

    /// Returns direct access to the GUID heap from the #GUID stream.
    ///
    /// # Returns
    ///
    /// - `Some(&Guid)` if the GUID heap is present
    /// - `None` if no #GUID stream exists
    #[must_use]
    pub fn guids(&self) -> Option<&Guid<'_>> {
        self.with_data(|data| data.guids.as_ref())
    }

    /// Returns direct access to the blob heap from the #Blob stream.
    ///
    /// # Returns
    ///
    /// - `Some(&Blob)` if the blob heap is present
    /// - `None` if no #Blob stream exists
    #[must_use]
    pub fn blobs(&self) -> Option<&Blob<'_>> {
        self.with_data(|data| data.blobs.as_ref())
    }

    /// Returns all stream headers from the metadata root.
    ///
    /// Stream headers contain location and size information for all
    /// metadata streams in the assembly.
    ///
    /// # Returns
    ///
    /// Reference to the vector of [`StreamHeader`] structures.
    #[must_use]
    pub fn streams(&self) -> &[StreamHeader] {
        self.with_data(|data| &data.metadata_root.stream_headers)
    }

    /// Returns the underlying file representation of this assembly.
    ///
    /// Provides access to PE file operations, RVA resolution, and
    /// low-level file structure access.
    ///
    /// # Returns
    ///
    /// Reference to the `Arc<File>` containing the PE file representation.
    #[must_use]
    pub fn file(&self) -> &Arc<File> {
        self.borrow_file()
    }

    /// Returns the raw file data as a byte slice.
    ///
    /// # Returns
    ///
    /// Reference to the complete file data.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        self.with_data(|data| data.data)
    }

    /// Converts this read-only view into a mutable assembly.
    ///
    /// This method consumes the `CilAssemblyView` and creates a `CilAssembly`
    /// that can be modified. The original data remains unchanged until
    /// modifications are made.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::CilAssemblyView;
    /// use std::path::Path;
    ///
    /// let view = CilAssemblyView::from_file(Path::new("assembly.dll"))?;
    /// let mut assembly = view.to_owned();
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn to_owned(self) -> CilAssembly {
        CilAssembly::new(self)
    }

    /// Performs raw validation (stage 1) on the loaded assembly view.
    ///
    /// This method validates the raw assembly data using the unified validation engine
    /// without any modifications (changes = None). It performs basic structural
    /// validation and integrity checks on the raw metadata.
    ///
    /// # Arguments
    ///
    /// * `config` - Validation configuration specifying which validations to perform
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if validation passes, or an error describing validation failures.
    ///
    /// # Errors
    ///
    /// Returns validation errors if any validation checks fail, including schema violations,
    /// RID consistency issues, or referential integrity problems.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::{CilAssemblyView, ValidationConfig};
    /// use std::path::Path;
    ///
    /// let view = CilAssemblyView::from_file(Path::new("assembly.dll"))?;
    /// view.validate(ValidationConfig::production())?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn validate(&self, config: ValidationConfig) -> Result<()> {
        if config == ValidationConfig::disabled() {
            return Ok(());
        }

        let engine = ValidationEngine::new(self, config)?;
        let result = engine.execute_stage1_validation(self, None)?;
        result.into_result()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test::factories::metadata::cilassemblyview::verify_assembly_view_complete;
    use std::{fs, path::PathBuf};

    #[test]
    fn from_file() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        let view = CilAssemblyView::from_file(&path).unwrap();

        verify_assembly_view_complete(&view);
    }

    #[test]
    fn from_buffer() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        let data = fs::read(path).unwrap();
        let view = CilAssemblyView::from_mem(data.clone()).unwrap();

        assert_eq!(view.data(), data.as_slice());
        verify_assembly_view_complete(&view);
    }

    #[test]
    fn test_error_handling() {
        // Test with non-existent file
        let result = CilAssemblyView::from_file(Path::new("non_existent_file.dll"));
        assert!(result.is_err());

        // Test with invalid data
        let invalid_data = vec![0u8; 100];
        let result = CilAssemblyView::from_mem(invalid_data);
        assert!(result.is_err());

        // Test with empty data
        let empty_data = Vec::new();
        let result = CilAssemblyView::from_mem(empty_data);
        assert!(result.is_err());
    }
}
