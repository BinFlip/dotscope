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
    },
    Result,
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
    pub fn from_file(file: Arc<File>, data: &'a [u8]) -> Result<Self> {
        let (clr_rva, clr_size) = file.clr();
        let clr_offset = file.rva_to_offset(clr_rva)?;
        let cor20_header = Cor20Header::read(&data[clr_offset..clr_offset + clr_size])?;

        let metadata_offset = file.rva_to_offset(cor20_header.meta_data_rva as usize)?;
        let metadata_slice =
            &data[metadata_offset..metadata_offset + cor20_header.meta_data_size as usize];
        let metadata_root = Root::read(metadata_slice)?;

        let mut metadata_tables = None;
        let mut strings_heap = None;
        let mut userstrings_heap = None;
        let mut guid_heap = None;
        let mut blob_heap = None;

        for stream in &metadata_root.stream_headers {
            if stream.offset as usize + stream.size as usize > metadata_slice.len() {
                return Err(crate::Error::OutOfBounds);
            }

            let stream_data =
                &metadata_slice[stream.offset as usize..(stream.offset + stream.size) as usize];

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
        let input = Arc::new(File::from_file(file)?);
        Self::load(input)
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
        let input = Arc::new(File::from_mem(data)?);
        Self::load(input)
    }

    fn load(file: Arc<File>) -> Result<Self> {
        CilAssemblyView::try_new(file, |file| {
            CilAssemblyViewData::from_file(file.clone(), file.data())
        })
    }

    /// Returns the COR20 header containing .NET-specific PE information.
    ///
    /// The COR20 header provides essential information about the .NET assembly
    /// including metadata location, entry point, and runtime flags.
    ///
    /// # Returns
    ///
    /// Reference to the [`Cor20Header`] structure.
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
    pub fn tables(&self) -> Option<&TablesHeader> {
        self.with_data(|data| data.metadata_tables.as_ref())
    }

    /// Returns direct access to the strings heap from the #Strings stream.
    ///
    /// # Returns
    ///
    /// - `Some(&Strings)` if the strings heap is present
    /// - `None` if no #Strings stream exists
    pub fn strings(&self) -> Option<&Strings> {
        self.with_data(|data| data.strings.as_ref())
    }

    /// Returns direct access to the user strings heap from the #US stream.
    ///
    /// # Returns
    ///
    /// - `Some(&UserStrings)` if the user strings heap is present
    /// - `None` if no #US stream exists
    pub fn userstrings(&self) -> Option<&UserStrings> {
        self.with_data(|data| data.userstrings.as_ref())
    }

    /// Returns direct access to the GUID heap from the #GUID stream.
    ///
    /// # Returns
    ///
    /// - `Some(&Guid)` if the GUID heap is present
    /// - `None` if no #GUID stream exists
    pub fn guids(&self) -> Option<&Guid> {
        self.with_data(|data| data.guids.as_ref())
    }

    /// Returns direct access to the blob heap from the #Blob stream.
    ///
    /// # Returns
    ///
    /// - `Some(&Blob)` if the blob heap is present
    /// - `None` if no #Blob stream exists
    pub fn blobs(&self) -> Option<&Blob> {
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
    pub fn file(&self) -> &Arc<File> {
        self.borrow_file()
    }

    /// Returns the raw file data as a byte slice.
    ///
    /// # Returns
    ///
    /// Reference to the complete file data.
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
    pub fn to_owned(self) -> CilAssembly {
        CilAssembly::new(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, path::PathBuf};

    /// Verification of a CilAssemblyView instance.
    fn verify_assembly_view_complete(view: &CilAssemblyView) {
        let cor20_header = view.cor20header();
        assert!(cor20_header.meta_data_rva > 0);
        assert!(cor20_header.meta_data_size > 0);
        assert!(cor20_header.cb >= 72); // Minimum COR20 header size
        assert!(cor20_header.major_runtime_version > 0);

        let metadata_root = view.metadata_root();
        assert!(!metadata_root.stream_headers.is_empty());
        assert!(metadata_root.major_version > 0);

        let stream_names: Vec<&str> = metadata_root
            .stream_headers
            .iter()
            .map(|h| h.name.as_str())
            .collect();
        assert!(stream_names.contains(&"#~") || stream_names.contains(&"#-"));
        assert!(stream_names.contains(&"#Strings"));

        let tables = view.tables();
        assert!(tables.is_some());
        let tables = tables.unwrap();
        assert!(tables.major_version > 0 || tables.minor_version > 0);
        assert!(tables.valid > 0);

        let strings = view.strings();
        assert!(strings.is_some());
        let strings = strings.unwrap();
        assert_eq!(strings.get(0).unwrap(), "");

        for i in 1..10 {
            let _ = strings.get(i); // Just verify we can call get without panicking
        }

        if let Some(userstrings) = view.userstrings() {
            let _ = userstrings.get(0); // Should not panic
            let _ = userstrings.get(1); // Should not panic
        }

        if let Some(guids) = view.guids() {
            // If present, verify it's accessible
            // Index 0 is typically null GUID, index 1+ contain actual GUIDs
            for i in 1..5 {
                let _ = guids.get(i); // Should not panic
            }
        }

        let blobs = view.blobs().unwrap();
        assert_eq!(blobs.get(0).unwrap(), &[] as &[u8]);

        let streams = view.streams();
        assert!(!streams.is_empty());
        for stream in streams {
            assert!(!stream.name.is_empty());
            assert!(stream.size > 0);
            assert!(stream.offset < u32::MAX);
        }

        let stream_names: Vec<&str> = streams.iter().map(|s| s.name.as_str()).collect();
        assert!(stream_names.contains(&"#~") || stream_names.contains(&"#-"));
        assert!(stream_names.contains(&"#Strings"));

        for stream in streams {
            match stream.name.as_str() {
                "#~" | "#-" => {
                    assert!(stream.size >= 24); // Minimum tables header size
                }
                "#Strings" => {
                    assert!(stream.size > 1); // Should contain at least empty string
                }
                "#GUID" => {
                    assert!(stream.size % 16 == 0); // GUIDs are 16 bytes each
                }
                "#Blob" => {
                    assert!(stream.size > 1); // Should contain at least empty blob
                }
                _ => {}
            }
        }

        let file = view.file();
        assert!(!file.data().is_empty());

        let (clr_rva, clr_size) = file.clr();
        assert!(clr_rva > 0);
        assert!(clr_size > 0);
        assert!(clr_size >= 72); // Minimum COR20 header size

        let data = view.data();
        assert!(data.len() > 100);
        assert_eq!(&data[0..2], b"MZ"); // PE signature

        // Verify consistency between different access methods
        assert_eq!(
            view.streams().len(),
            view.metadata_root().stream_headers.len()
        );
        assert_eq!(view.data().len(), view.file().data().len());

        // Test that stream headers match between metadata_root and streams
        let root_streams = &view.metadata_root().stream_headers;
        let direct_streams = view.streams();

        for (i, stream) in direct_streams.iter().enumerate() {
            assert_eq!(stream.name, root_streams[i].name);
            assert_eq!(stream.size, root_streams[i].size);
            assert_eq!(stream.offset, root_streams[i].offset);
        }
    }

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
