//! PE file abstraction and .NET binary parsing.
//!
//! This module provides comprehensive support for parsing and analyzing Portable Executable (PE)
//! files containing .NET assemblies. It abstracts over different data sources (files, memory)
//! and provides ergonomic access to PE structures, .NET metadata, and binary data.
//!
//! # Architecture
//!
//! The module is built around several key components that work together to provide
//! comprehensive PE file analysis capabilities:
//!
//! - **File abstraction layer** - Unified interface for PE file access
//! - **Backend system** - Pluggable data sources (disk files, memory buffers)
//! - **PE format parsing** - Complete PE/COFF structure analysis
//! - **Address translation** - RVA to file offset conversion
//! - **Data directory access** - Direct access to PE data directories
//!
//! # Key Components
//!
//! ## Core Types
//! - [`crate::file::File`] - Main PE file abstraction with .NET-specific functionality
//! - [`crate::file::Backend`] - Trait for different data sources (disk files, memory buffers)
//!
//! ## Parsing Infrastructure  
//! - [`crate::file::parser::Parser`] - High-level parsing interface for metadata extraction
//! - [`crate::file::io`] - Low-level I/O utilities for reading PE structures
//!
//! ## Backend Implementations
//! - [`crate::file::physical::Physical`] - Memory-mapped file backend for disk access
//! - [`crate::file::memory::Memory`] - In-memory buffer backend for dynamic analysis
//!
//! # Data Sources
//!
//! The module supports multiple data sources through the [`crate::file::Backend`] trait:
//! - **Physical files** - Memory-mapped files for efficient disk access
//! - **Memory buffers** - In-memory PE data for dynamic analysis
//!
//! # PE Format Support
//!
//! Supports both PE32 and PE32+ formats with:
//! - DOS header and PE signature parsing
//! - COFF header and optional header extraction
//! - Section table parsing and virtual address resolution
//! - Data directory access (Import, Export, .NET metadata, etc.)
//! - RVA to file offset translation
//!
//! # Examples
//!
//! ## Loading from File
//!
//! ```rust,no_run
//! use dotscope::File;
//! use std::path::Path;
//!
//! // Load a .NET assembly from disk
//! let file = File::from_file(Path::new("tests/samples/WindowsBase.dll"))?;
//! println!("Loaded PE file with {} bytes", file.len());
//!
//! // Access PE headers
//! println!("Image base: 0x{:x}", file.imagebase());
//! println!("Number of sections: {}", file.sections().len());
//!
//! // Access .NET metadata location
//! let (clr_rva, clr_size) = file.clr();
//! println!("CLR header at RVA 0x{:x}, size: {} bytes", clr_rva, clr_size);
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Loading from Memory
//!
//! ```rust,no_run
//! use dotscope::File;
//! use std::fs;
//!
//! // Load assembly data into memory
//! let data = fs::read("tests/samples/WindowsBase.dll")?;
//! let file = File::from_mem(data)?;
//!
//! // Same API as file-based loading
//! println!("Assembly size: {} bytes", file.len());
//!
//! // Find specific sections
//! for section in file.sections() {
//!     let name = section.name.trim_end_matches('\0');
//!     if name == ".text" {
//!         println!("Code section at RVA 0x{:x}", section.virtual_address);
//!         break;
//!     }
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Address Translation
//!
//! ```rust,no_run
//! use dotscope::File;
//! use std::path::Path;
//!
//! let file = File::from_file(Path::new("tests/samples/WindowsBase.dll"))?;
//!
//! // Convert CLR header RVA to file offset
//! let (clr_rva, _) = file.clr();
//! let clr_offset = file.rva_to_offset(clr_rva)?;
//!
//! // Read CLR header data
//! let clr_data = file.data_slice(clr_offset, 72)?; // CLR header is 72 bytes
//! println!("CLR header starts with: {:02x?}", &clr_data[0..8]);
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//!
//! # Thread Safety
//!
//! All components are designed to be thread-safe and can be shared across threads
//! for concurrent analysis of the same PE file.
//!
//! # References
//!
//! - Microsoft PE/COFF Specification
//! - ECMA-335 6th Edition, Partition II - PE File Format

pub mod parser;
pub mod pe;

mod memory;
mod physical;

use std::path::Path;

use crate::{
    utils::align_to,
    Error::{Empty, GoblinErr, WriteLayoutFailed},
    Result,
};
use goblin::pe::PE;
use memory::Memory;
use pe::{DataDirectory, DataDirectoryType, Pe};
use physical::Physical;

/// Backend trait for file data sources.
///
/// This trait abstracts over the source of PE data, allowing for both in-memory and on-disk
/// representations. All implementations must be thread-safe.
///
/// The trait provides a common interface for accessing PE file data regardless of whether
/// it's loaded from a file on disk or from a memory buffer. This enables flexible handling
/// of different data sources while maintaining performance.
pub trait Backend: Send + Sync {
    /// Returns a slice of the data at the given offset and length.
    ///
    /// This method provides bounds-checked access to the underlying data.
    /// It's used internally by the `File` struct to safely read portions
    /// of the PE file data.
    ///
    /// # Arguments
    ///
    /// * `offset` - The starting offset within the data.
    /// * `len` - The length of the slice in bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the requested range is out of bounds.
    fn data_slice(&self, offset: usize, len: usize) -> Result<&[u8]>;

    /// Returns the entire data buffer.
    ///
    /// This provides access to the complete PE file data as a single slice.
    /// For file-based backends, this typically maps the entire file into memory.
    /// For memory-based backends, this returns the underlying buffer.
    fn data(&self) -> &[u8];

    /// Returns the total length of the data buffer.
    ///
    /// This is equivalent to `self.data().len()` but may be more efficient
    /// for some backend implementations.
    fn len(&self) -> usize;
}

/// Represents a loaded PE file with .NET metadata.
///
/// This struct contains the parsed PE information and provides methods for accessing headers,
/// sections, data directories, and for converting between address spaces. It supports loading
/// from both files and memory buffers.
///
/// The `File` struct is the main entry point for working with .NET PE files. It automatically
/// validates that the loaded file is a valid .NET assembly by checking for the presence of
/// the CLR runtime header.
///
/// # Examples
///
/// ## Loading from a file
///
/// ```rust,no_run
/// use dotscope::File;
/// use std::path::Path;
///
/// let file = File::from_file(Path::new("tests/samples/WindowsBase.dll"))?;
/// println!("Loaded PE with {} sections", file.sections().len());
///
/// // Access assembly metadata
/// let (clr_rva, clr_size) = file.clr();
/// println!("CLR runtime header: RVA=0x{:x}, size={}", clr_rva, clr_size);
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// ## Loading from memory
///
/// ```rust,no_run
/// use dotscope::File;
/// use std::fs;
///
/// let data = fs::read("tests/samples/WindowsBase.dll")?;
/// let file = File::from_mem(data)?;
///
/// // Access CLR metadata
/// let (clr_rva, clr_size) = file.clr();
/// println!("CLR header at RVA 0x{:x}, {} bytes", clr_rva, clr_size);
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// ## Working with addresses
///
/// ```rust,no_run
/// use dotscope::File;
/// use std::path::Path;
///
/// let file = File::from_file(Path::new("tests/samples/WindowsBase.dll"))?;
///
/// // Convert between address spaces
/// let entry_rva = file.header_optional().as_ref().unwrap()
///     .standard_fields.address_of_entry_point as usize;
/// let entry_offset = file.rva_to_offset(entry_rva)?;
///
/// // Read entry point code
/// let entry_code = file.data_slice(entry_offset, 16)?;
/// println!("Entry point bytes: {:02x?}", entry_code);
/// # Ok::<(), dotscope::Error>(())
/// ```
pub struct File {
    /// The underlying data source (memory or file).
    data: Box<dyn Backend>,
    /// The parsed PE structure as owned data.
    pe: Pe,
}

impl File {
    /// Loads a PE file from the given path.
    ///
    /// This method opens a file from disk and parses it as a .NET PE file.
    /// The file is memory-mapped for efficient access.
    ///
    /// # Arguments
    ///
    /// * `file` - Path to the PE file on disk.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The file cannot be read or opened
    /// - The file is not a valid PE format
    /// - The PE file does not contain .NET metadata (missing CLR runtime header)
    /// - The file is empty
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::File;
    /// use std::path::Path;
    ///
    /// let file = File::from_file(Path::new("tests/samples/WindowsBase.dll"))?;
    /// println!("Loaded {} bytes with {} sections",
    ///          file.len(), file.sections().len());
    ///
    /// // Access assembly metadata
    /// let (clr_rva, clr_size) = file.clr();
    /// println!("CLR runtime header: RVA=0x{:x}, size={}", clr_rva, clr_size);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn from_file(file: &Path) -> Result<File> {
        let input = Physical::new(file)?;

        Self::load(input)
    }

    /// Loads a PE file from a memory buffer.
    ///
    /// This method parses a PE file that's already loaded into memory.
    /// Useful when working with embedded resources or downloaded files.
    ///
    /// # Arguments
    ///
    /// * `data` - The bytes of the PE file.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The buffer is empty
    /// - The data is not a valid PE format
    /// - The PE file does not contain .NET metadata (missing CLR runtime header)
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::File;
    /// use std::fs;
    ///
    /// // Load from downloaded or embedded data
    /// let data = fs::read("tests/samples/WindowsBase.dll")?;
    /// let file = File::from_mem(data)?;
    ///
    /// // Inspect the assembly
    /// println!("Assembly size: {} bytes", file.len());
    /// println!("Image base: 0x{:x}", file.imagebase());
    ///
    /// // Find specific sections
    /// for section in file.sections() {
    ///     let name = section.name.trim_end_matches('\0');
    ///     if name == ".text" {
    ///         println!("Code section at RVA 0x{:x}", section.virtual_address);
    ///         break;
    ///     }
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn from_mem(data: Vec<u8>) -> Result<File> {
        let input = Memory::new(data);

        Self::load(input)
    }

    /// Internal loader for any backend.
    ///
    /// # Arguments
    ///
    /// * `data` - The backend providing the PE data.
    ///
    /// # Errors
    ///
    /// Returns an error if the data is empty, not a valid PE, or missing .NET metadata.
    fn load<T: Backend + 'static>(data: T) -> Result<File> {
        if data.len() == 0 {
            return Err(Empty);
        }

        // ToDo: For MONO, the .NET CIL part is embedded into an ELF as an actual valid PE file.
        //       To support MONO, we'll need to parse the ELF file here, and extract the PE structure that this `File`
        //       is then pointing to

        let goblin_pe = match PE::parse(data.data()) {
            Ok(pe) => pe,
            Err(error) => return Err(GoblinErr(error)),
        };

        let owned_pe = Pe::from_goblin_pe(&goblin_pe)?;

        Ok(File {
            data: Box::new(data),
            pe: owned_pe,
        })
    }

    /// Returns the total size of the loaded file in bytes.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::File;
    /// use std::path::Path;
    ///
    /// let file = File::from_file(Path::new("tests/samples/WindowsBase.dll"))?;
    /// println!("File size: {} bytes", file.len());
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns `true` if the file has a length of zero.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::File;
    /// use std::path::Path;
    ///
    /// let file = File::from_file(Path::new("tests/samples/WindowsBase.dll"))?;
    /// assert!(!file.is_empty()); // Valid PE files are never empty
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the image base address of the loaded PE file.
    ///
    /// The image base is the preferred virtual address where the PE file
    /// should be loaded in memory. This is used for calculating virtual addresses.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::File;
    /// use std::path::Path;
    ///
    /// let file = File::from_file(Path::new("tests/samples/WindowsBase.dll"))?;
    /// let base = file.imagebase();
    /// println!("Image base: 0x{:x}", base);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn imagebase(&self) -> u64 {
        self.pe.image_base
    }

    /// Returns a reference to the COFF header.
    ///
    /// The COFF header contains essential metadata about the executable,
    /// including the machine type, number of sections, and timestamp.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::File;
    /// use std::path::Path;
    ///
    /// let file = File::from_file(Path::new("tests/samples/WindowsBase.dll"))?;
    /// let header = file.header();
    /// println!("Machine type: 0x{:x}", header.machine);
    /// println!("Number of sections: {}", header.number_of_sections);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn header(&self) -> &pe::CoffHeader {
        &self.pe.coff_header
    }

    /// Returns a reference to the DOS header.
    ///
    /// The DOS header is the first part of a PE file and contains the DOS stub
    /// that displays the "This program cannot be run in DOS mode" message.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::File;
    /// use std::path::Path;
    ///
    /// let file = File::from_file(Path::new("tests/samples/WindowsBase.dll"))?;
    /// let dos_header = file.header_dos();
    /// println!("DOS signature: 0x{:x}", dos_header.signature);
    /// println!("Number of bytes on last page: {}", dos_header.bytes_on_last_page);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn header_dos(&self) -> &pe::DosHeader {
        &self.pe.dos_header
    }

    /// Returns a reference to the optional header, if present.
    ///
    /// This is always `Some` for valid .NET assemblies since they require
    /// an optional header to define data directories and other metadata.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::File;
    /// use std::path::Path;
    ///
    /// let file = File::from_file(Path::new("tests/samples/WindowsBase.dll"))?;
    /// let optional_header = file.header_optional().as_ref().unwrap();
    /// println!("Entry point: 0x{:x}", optional_header.standard_fields.address_of_entry_point);
    /// println!("Subsystem: {:?}", optional_header.windows_fields.subsystem);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn header_optional(&self) -> &Option<pe::OptionalHeader> {
        // We have verified the existence of the optional_header during the initial load.
        &self.pe.optional_header
    }

    /// Returns the RVA and size (in bytes) of the CLR runtime header.
    ///
    /// The CLR runtime header contains metadata about the .NET runtime,
    /// including pointers to metadata tables and other runtime structures.
    ///
    /// # Returns
    ///
    /// A tuple containing `(rva, size)` where:
    /// - `rva` is the relative virtual address of the CLR header
    /// - `size` is the size of the CLR header in bytes
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::File;
    /// use std::path::Path;
    ///
    /// let file = File::from_file(Path::new("tests/samples/WindowsBase.dll"))?;
    /// let (clr_rva, clr_size) = file.clr();
    /// println!("CLR header at RVA: 0x{:x}, size: {} bytes", clr_rva, clr_size);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Panics
    ///
    /// Panics if the CLR runtime header is missing (should not happen for valid .NET assemblies).
    #[must_use]
    pub fn clr(&self) -> (usize, usize) {
        let clr_dir = self
            .pe
            .get_clr_runtime_header()
            .expect("CLR runtime header should exist for .NET assemblies");

        (clr_dir.virtual_address as usize, clr_dir.size as usize)
    }

    /// Returns a slice of the section headers of the PE file.
    ///
    /// Sections contain the actual code and data of the PE file, such as
    /// `.text` (executable code), `.data` (initialized data), and `.rsrc` (resources).
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::File;
    /// use std::path::Path;
    ///
    /// let file = File::from_file(Path::new("tests/samples/WindowsBase.dll"))?;
    /// for section in file.sections() {
    ///     println!("Section: {} at RVA 0x{:x}, size: {} bytes",
    ///              section.name, section.virtual_address, section.virtual_size);
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn sections(&self) -> &[pe::SectionTable] {
        &self.pe.sections
    }

    /// Returns the data directories of the PE file.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::File;
    /// use std::path::Path;
    ///
    /// let file = File::from_file(Path::new("tests/samples/WindowsBase.dll"))?;
    /// for (dir_type, directory) in file.directories() {
    ///     println!("Directory: {:?}, RVA: 0x{:x}", dir_type, directory.virtual_address);
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Panics
    ///
    /// Panics if the optional header is missing (should not happen for valid .NET assemblies).
    #[must_use]
    pub fn directories(&self) -> Vec<(DataDirectoryType, DataDirectory)> {
        // We have verified the existence of the optional_header during the initial load.
        self.pe
            .data_directories
            .iter()
            .map(|(&dir_type, &dir)| (dir_type, dir))
            .collect()
    }

    /// Returns the RVA and size of a specific data directory entry.
    ///
    /// This method provides unified access to PE data directory entries by type.
    /// It returns the virtual address and size if the directory exists and is valid,
    /// or `None` if the directory doesn't exist or has zero address/size.
    ///
    /// # Arguments
    /// * `dir_type` - The type of data directory to retrieve
    ///
    /// # Returns
    /// - `Some((rva, size))` if the directory exists with non-zero address and size
    /// - `None` if the directory doesn't exist or has zero address/size
    ///
    /// # Panics
    ///
    /// Panics if the PE file has no optional header (which should not happen for valid PE files).
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::File;
    /// use dotscope::DataDirectoryType;
    /// use std::path::Path;
    ///
    /// let file = File::from_file(Path::new("example.dll"))?;
    ///
    /// // Check for import table
    /// if let Some((import_rva, import_size)) = file.get_data_directory(DataDirectoryType::ImportTable) {
    ///     println!("Import table at RVA 0x{:x}, size: {} bytes", import_rva, import_size);
    /// }
    ///
    /// // Check for export table
    /// if let Some((export_rva, export_size)) = file.get_data_directory(DataDirectoryType::ExportTable) {
    ///     println!("Export table at RVA 0x{:x}, size: {} bytes", export_rva, export_size);
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn get_data_directory(&self, dir_type: DataDirectoryType) -> Option<(u32, u32)> {
        self.pe
            .get_data_directory(dir_type)
            .filter(|directory| directory.virtual_address != 0 && directory.size != 0)
            .map(|directory| (directory.virtual_address, directory.size))
    }

    /// Returns the parsed import data from the PE file.
    ///
    /// Uses goblin's PE parsing to extract import table information including
    /// DLL dependencies and imported functions. Returns the parsed import data
    /// if an import directory exists.
    ///
    /// # Returns
    /// - `Some(imports)` if import directory exists and was successfully parsed
    /// - `None` if no import directory exists or parsing failed
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::File;
    /// use std::path::Path;
    ///
    /// let file = File::from_file(Path::new("example.dll"))?;
    /// if let Some(imports) = file.imports() {
    ///     for import in imports {
    ///         println!("DLL: {}", import.dll);
    ///         if let Some(ref name) = import.name {
    ///             if !name.is_empty() {
    ///                 println!("  Function: {}", name);
    ///             }
    ///         } else if let Some(ordinal) = import.ordinal {
    ///             println!("  Ordinal: {}", ordinal);
    ///         }
    ///     }
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn imports(&self) -> Option<&Vec<pe::Import>> {
        if self.pe.imports.is_empty() {
            None
        } else {
            Some(&self.pe.imports)
        }
    }

    /// Returns the parsed export data from the PE file.
    ///
    /// Uses goblin's PE parsing to extract export table information including
    /// exported functions and their addresses. Returns the parsed export data
    /// if an export directory exists.
    ///
    /// # Returns
    /// - `Some(exports)` if export directory exists and was successfully parsed
    /// - `None` if no export directory exists or parsing failed
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::File;
    /// use std::path::Path;
    ///
    /// let file = File::from_file(Path::new("example.dll"))?;
    /// if let Some(exports) = file.exports() {
    ///     for export in exports {
    ///         if let Some(name) = &export.name {
    ///             println!("Export: {} -> 0x{:X}", name, export.rva);
    ///         }
    ///     }
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn exports(&self) -> Option<&Vec<pe::Export>> {
        if self.pe.exports.is_empty() {
            None
        } else {
            Some(&self.pe.exports)
        }
    }

    /// Returns the raw data of the loaded file.
    ///
    /// This provides access to the entire PE file contents as a byte slice.
    /// Useful for reading specific offsets or when you need direct access
    /// to the binary data.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::File;
    /// use std::path::Path;
    ///
    /// let file = File::from_file(Path::new("tests/samples/WindowsBase.dll"))?;
    /// let data = file.data();
    ///
    /// // Check DOS signature (MZ)
    /// assert_eq!(&data[0..2], b"MZ");
    ///
    /// // Access PE signature offset
    /// let pe_offset = u32::from_le_bytes([data[60], data[61], data[62], data[63]]) as usize;
    /// assert_eq!(&data[pe_offset..pe_offset + 4], b"PE\0\0");
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn data(&self) -> &[u8] {
        self.data.data()
    }

    /// Returns a slice of the file data at the given offset and length.
    ///
    /// This is a safe way to access specific portions of the PE file data
    /// with bounds checking to prevent buffer overflows.
    ///
    /// # Arguments
    ///
    /// * `offset` - The offset to start the slice from.
    /// * `len` - The length of the slice.
    ///
    /// # Errors
    ///
    /// Returns an error if the requested range is out of bounds.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::File;
    /// use std::path::Path;
    ///
    /// let file = File::from_file(Path::new("tests/samples/WindowsBase.dll"))?;
    ///
    /// // Read the DOS header (first 64 bytes)
    /// let dos_header = file.data_slice(0, 64)?;
    /// assert_eq!(&dos_header[0..2], b"MZ");
    ///
    /// // Read PE signature
    /// let pe_offset = u32::from_le_bytes([dos_header[60], dos_header[61],
    ///                                     dos_header[62], dos_header[63]]) as usize;
    /// let pe_sig = file.data_slice(pe_offset, 4)?;
    /// assert_eq!(pe_sig, b"PE\0\0");
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn data_slice(&self, offset: usize, len: usize) -> Result<&[u8]> {
        self.data.data_slice(offset, len)
    }

    /// Converts a virtual address (VA) to a file offset.
    ///
    /// Virtual addresses are absolute addresses where the PE file would be
    /// loaded in memory. This method converts them to file offsets for
    /// reading data from the actual file.
    ///
    /// # Arguments
    ///
    /// * `va` - The virtual address to convert.
    ///
    /// # Errors
    ///
    /// Returns an error if the VA is out of bounds or cannot be mapped.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::File;
    /// use std::path::Path;
    ///
    /// let file = File::from_file(Path::new("tests/samples/WindowsBase.dll"))?;
    ///
    /// // Convert entry point VA to file offset
    /// let entry_point_va = file.header_optional().as_ref().unwrap().standard_fields.address_of_entry_point as usize;
    /// let image_base = file.imagebase() as usize;
    /// let full_va = image_base + entry_point_va;
    ///
    /// let offset = file.va_to_offset(full_va)?;
    /// println!("Entry point at file offset: 0x{:x}", offset);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn va_to_offset(&self, va: usize) -> Result<usize> {
        let ib = self.imagebase();
        if ib > va as u64 {
            return Err(out_of_bounds_error!());
        }

        let rva_u64 = va as u64 - ib;
        let rva = usize::try_from(rva_u64)
            .map_err(|_| malformed_error!("RVA too large to fit in usize: {}", rva_u64))?;
        self.rva_to_offset(rva)
    }

    /// Converts a relative virtual address (RVA) to a file offset.
    ///
    /// RVAs are addresses relative to the image base. This is the most common
    /// address format used within PE files for referencing data and code.
    ///
    /// # Arguments
    ///
    /// * `rva` - The RVA to convert.
    ///
    /// # Errors
    ///
    /// Returns an error if the RVA cannot be mapped to a file offset.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::File;
    /// use std::path::Path;
    ///
    /// let file = File::from_file(Path::new("tests/samples/WindowsBase.dll"))?;
    ///
    /// // Convert CLR header RVA to file offset
    /// let (clr_rva, _) = file.clr();
    /// let clr_offset = file.rva_to_offset(clr_rva)?;
    ///
    /// // Read CLR header data
    /// let clr_data = file.data_slice(clr_offset, 72)?; // CLR header is 72 bytes
    /// println!("CLR header starts with: {:02x?}", &clr_data[0..8]);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn rva_to_offset(&self, rva: usize) -> Result<usize> {
        for section in &self.pe.sections {
            let Some(section_max) = section.virtual_address.checked_add(section.virtual_size)
            else {
                return Err(malformed_error!(
                    "Section malformed, causing integer overflow - {} + {}",
                    section.virtual_address,
                    section.virtual_size
                ));
            };

            let rva_u32 = u32::try_from(rva)
                .map_err(|_| malformed_error!("RVA too large to fit in u32: {}", rva))?;
            if section.virtual_address <= rva_u32 && section_max > rva_u32 {
                return Ok(
                    (rva - section.virtual_address as usize) + section.pointer_to_raw_data as usize
                );
            }
        }

        Err(malformed_error!(
            "RVA could not be converted to offset - {}",
            rva
        ))
    }

    /// Converts a file offset to a relative virtual address (RVA).
    ///
    /// This is the inverse of `rva_to_offset()`. Given a file offset,
    /// it calculates what RVA that offset corresponds to when the
    /// PE file is loaded in memory.
    ///
    /// # Arguments
    ///
    /// * `offset` - The file offset to convert.
    ///
    /// # Errors
    ///
    /// Returns an error if the offset cannot be mapped to an RVA.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::File;
    /// use std::path::Path;
    ///
    /// let file = File::from_file(Path::new("tests/samples/WindowsBase.dll"))?;
    ///
    /// // Find what RVA corresponds to file offset 0x1000
    /// let rva = file.offset_to_rva(0x1000)?;
    /// println!("File offset 0x1000 maps to RVA 0x{:x}", rva);
    ///
    /// // Verify round-trip conversion
    /// let back_to_offset = file.rva_to_offset(rva)?;
    /// assert_eq!(back_to_offset, 0x1000);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn offset_to_rva(&self, offset: usize) -> Result<usize> {
        for section in &self.pe.sections {
            let Some(section_max) = section
                .pointer_to_raw_data
                .checked_add(section.size_of_raw_data)
            else {
                return Err(malformed_error!(
                    "Section malformed, causing integer overflow - {} + {}",
                    section.pointer_to_raw_data,
                    section.size_of_raw_data
                ));
            };

            let offset_u32 = u32::try_from(offset)
                .map_err(|_| malformed_error!("Offset too large to fit in u32: {}", offset))?;
            if section.pointer_to_raw_data < offset_u32 && section_max > offset_u32 {
                return Ok((offset - section.pointer_to_raw_data as usize)
                    + section.virtual_address as usize);
            }
        }

        Err(malformed_error!(
            "Offset could not be converted to RVA - {}",
            offset
        ))
    }

    /// Determines if a section contains .NET metadata by checking the actual metadata RVA.
    ///
    /// This method reads the CLR runtime header to get the metadata RVA and checks
    /// if it falls within the specified section's address range. This is more accurate
    /// than name-based heuristics since metadata can technically be located in any section.
    ///
    /// # Arguments
    /// * `section_name` - The name of the section to check (e.g., ".text")
    ///
    /// # Returns
    /// Returns `true` if the section contains .NET metadata, `false` otherwise.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::File;
    /// use std::path::Path;
    ///
    /// let file = File::from_file(Path::new("example.dll"))?;
    ///
    /// if file.section_contains_metadata(".text") {
    ///     println!("The .text section contains .NET metadata");
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn section_contains_metadata(&self, section_name: &str) -> bool {
        let (clr_rva, _clr_size) = match self.clr() {
            #[allow(clippy::cast_possible_truncation)]
            (rva, size) if rva > 0 && size >= 72 => (rva as u32, size),
            _ => return false, // No CLR header means no .NET metadata
        };

        let Ok(clr_offset) = self.rva_to_offset(clr_rva as usize) else {
            return false;
        };

        let Ok(clr_data) = self.data_slice(clr_offset, 72) else {
            return false;
        };

        if clr_data.len() < 12 {
            return false;
        }

        let meta_data_rva =
            u32::from_le_bytes([clr_data[8], clr_data[9], clr_data[10], clr_data[11]]);

        if meta_data_rva == 0 {
            return false; // No metadata
        }

        for section in self.sections() {
            let current_section_name = section.name.as_str();

            if current_section_name == section_name {
                let section_start = section.virtual_address;
                let section_end = section.virtual_address + section.virtual_size;
                return meta_data_rva >= section_start && meta_data_rva < section_end;
            }
        }

        false // Section not found
    }

    /// Gets the file alignment value from the PE header.
    ///
    /// This method extracts the file alignment value from the PE optional header.
    /// This is typically 512 bytes for most .NET assemblies.
    ///
    /// # Returns
    /// Returns the file alignment value in bytes.
    ///
    /// # Errors
    /// Returns [`crate::Error::WriteLayoutFailed`] if the PE header cannot be accessed.
    pub fn file_alignment(&self) -> Result<u32> {
        let optional_header = self
            .header_optional()
            .as_ref()
            .ok_or_else(|| WriteLayoutFailed {
                message: "Missing optional header for file alignment".to_string(),
            })?;

        Ok(optional_header.windows_fields.file_alignment)
    }

    /// Gets the section alignment value from the PE header.
    ///
    /// This method extracts the section alignment value from the PE optional header.
    /// This is typically 4096 bytes (page size) for most .NET assemblies.
    ///
    /// # Returns
    /// Returns the section alignment value in bytes.
    ///
    /// # Errors
    /// Returns [`crate::Error::WriteLayoutFailed`] if the PE header cannot be accessed.
    pub fn section_alignment(&self) -> Result<u32> {
        let optional_header = self
            .header_optional()
            .as_ref()
            .ok_or_else(|| WriteLayoutFailed {
                message: "Missing optional header for section alignment".to_string(),
            })?;

        Ok(optional_header.windows_fields.section_alignment)
    }

    /// Determines if this is a PE32+ format file.
    ///
    /// Returns `true` for PE32+ (64-bit) format, `false` for PE32 (32-bit) format.
    /// This affects the size of ILT/IAT entries and ordinal import bit positions.
    ///
    /// # Returns
    /// Returns `true` if PE32+ format, `false` if PE32 format.
    ///
    /// # Errors
    /// Returns [`crate::Error::WriteLayoutFailed`] if the PE format cannot be determined.
    pub fn is_pe32_plus_format(&self) -> Result<bool> {
        let optional_header = self
            .header_optional()
            .as_ref()
            .ok_or_else(|| WriteLayoutFailed {
                message: "Missing optional header for PE format detection".to_string(),
            })?;

        // PE32 magic is 0x10b, PE32+ magic is 0x20b
        Ok(optional_header.standard_fields.magic != 0x10b)
    }

    /// Gets the RVA of the .text section.
    ///
    /// Locates the .text section (or .text-prefixed section) which typically
    /// contains .NET metadata and executable code.
    ///
    /// # Returns
    /// Returns the RVA (Relative Virtual Address) of the .text section.
    ///
    /// # Errors
    /// Returns [`crate::Error::WriteLayoutFailed`] if no .text section is found.
    pub fn text_section_rva(&self) -> Result<u32> {
        for section in self.sections() {
            let section_name = section.name.as_str();
            if section_name == ".text" || section_name.starts_with(".text") {
                return Ok(section.virtual_address);
            }
        }

        Err(WriteLayoutFailed {
            message: "Could not find .text section".to_string(),
        })
    }

    /// Gets the file offset of the .text section.
    ///
    /// This method finds the .text section in the PE file and returns its file offset.
    /// This is needed for calculating absolute file offsets for metadata components.
    ///
    /// # Returns
    /// Returns the file offset of the .text section.
    ///
    /// # Errors
    /// Returns [`crate::Error::WriteLayoutFailed`] if no .text section is found.
    pub fn text_section_file_offset(&self) -> Result<u64> {
        for section in self.sections() {
            let section_name = section.name.as_str();
            if section_name == ".text" || section_name.starts_with(".text") {
                return Ok(u64::from(section.pointer_to_raw_data));
            }
        }

        Err(WriteLayoutFailed {
            message: "Could not find .text section for file offset".to_string(),
        })
    }

    /// Gets the raw size of the .text section.
    ///
    /// This method finds the .text section and returns its raw data size.
    /// This is needed for calculating metadata expansion requirements.
    ///
    /// # Returns
    /// Returns the raw size of the .text section in bytes.
    ///
    /// # Errors
    /// Returns [`crate::Error::WriteLayoutFailed`] if no .text section is found.
    pub fn text_section_raw_size(&self) -> Result<u32> {
        for section in self.sections() {
            let section_name = section.name.as_str();
            if section_name == ".text" || section_name.starts_with(".text") {
                return Ok(section.size_of_raw_data);
            }
        }

        Err(WriteLayoutFailed {
            message: "Could not find .text section for size calculation".to_string(),
        })
    }

    /// Gets the total size of the file.
    ///
    /// Returns the size of the underlying file data in bytes.
    ///
    /// # Returns
    /// Returns the file size in bytes.
    #[must_use]
    pub fn file_size(&self) -> u64 {
        u64::try_from(self.data().len()).unwrap_or(u64::MAX)
    }

    /// Gets the PE signature offset from the DOS header.
    ///
    /// Reads the PE offset from the DOS header at offset 0x3C to locate
    /// the PE signature ("PE\0\0") within the file.
    ///
    /// # Returns
    /// Returns the file offset where the PE signature is located.
    ///
    /// # Errors
    /// Returns [`crate::Error::WriteLayoutFailed`] if the file is too small to contain
    /// a valid DOS header.
    pub fn pe_signature_offset(&self) -> Result<u64> {
        let data = self.data();

        if data.len() < 64 {
            return Err(WriteLayoutFailed {
                message: "File too small to contain DOS header".to_string(),
            });
        }

        // PE offset is at offset 0x3C in DOS header
        let pe_offset = u32::from_le_bytes([data[60], data[61], data[62], data[63]]);
        Ok(u64::from(pe_offset))
    }

    /// Calculates the size of PE headers (including optional header).
    ///
    /// Computes the total size of PE signature, COFF header, and optional header
    /// by reading the optional header size from the COFF header.
    ///
    /// # Returns
    /// Returns the total size in bytes of all PE headers.
    ///
    /// # Errors
    /// Returns [`crate::Error::WriteLayoutFailed`] if the file is too small or
    /// headers are malformed.
    pub fn pe_headers_size(&self) -> Result<u64> {
        // PE signature (4) + COFF header (20) + Optional header size
        // We need to read the optional header size from the COFF header
        let pe_sig_offset = self.pe_signature_offset()?;
        let data = self.data();

        let coff_header_offset = pe_sig_offset + 4; // Skip PE signature

        #[allow(clippy::cast_possible_truncation)]
        if data.len() < (coff_header_offset + 20) as usize {
            return Err(WriteLayoutFailed {
                message: "File too small to contain COFF header".to_string(),
            });
        }

        // Optional header size is at offset 16 in COFF header
        let opt_header_size_offset = coff_header_offset + 16;
        #[allow(clippy::cast_possible_truncation)]
        let opt_header_size = u16::from_le_bytes([
            data[opt_header_size_offset as usize],
            data[opt_header_size_offset as usize + 1],
        ]);

        Ok(4 + 20 + u64::from(opt_header_size)) // PE sig + COFF + Optional header
    }

    /// Aligns an offset to this file's PE file alignment boundary.
    ///
    /// PE files require data to be aligned to specific boundaries for optimal loading.
    /// This method uses the actual file alignment value from the PE header rather than
    /// assuming a hardcoded value.
    ///
    /// # Arguments
    /// * `offset` - The offset to align
    ///
    /// # Returns
    /// Returns the offset rounded up to the next file alignment boundary.
    ///
    /// # Errors
    /// Returns [`crate::Error::WriteLayoutFailed`] if the PE header cannot be accessed.
    pub fn align_to_file_alignment(&self, offset: u64) -> Result<u64> {
        let file_alignment = u64::from(self.file_alignment()?);
        Ok(align_to(offset, file_alignment))
    }

    /// Returns a reference to the internal Pe structure.
    ///
    /// This provides access to the owned PE data structures for operations
    /// that need to work directly with PE components, such as size calculations
    /// and header updates during write operations.
    ///
    /// # Returns
    /// Reference to the internal Pe structure
    #[must_use]
    pub fn pe(&self) -> &Pe {
        &self.pe
    }

    /// Returns a mutable reference to the internal Pe structure.
    ///
    /// This provides mutable access to the owned PE data structures, enabling
    /// direct modifications to PE headers, sections, and data directories.
    /// Use this when you need to modify the PE structure in-place rather than
    /// creating copies.
    ///
    /// # Returns
    /// Mutable reference to the internal Pe structure
    ///
    /// # Examples
    /// ```rust,ignore
    /// // Add a new section to the PE file
    /// let mut file = File::from_file(path)?;
    /// let new_section = SectionTable::from_layout_info(
    ///     ".meta".to_string(),
    ///     0x4000,
    ///     0x1000,
    ///     0x2000,
    ///     0x1000,
    ///     0x40000040,
    /// )?;
    /// file.pe_mut().add_section(new_section);
    ///
    /// // Update CLR data directory
    /// file.pe_mut().update_clr_data_directory(0x4000, 72)?;
    /// ```
    pub fn pe_mut(&mut self) -> &mut Pe {
        &mut self.pe
    }
}

#[cfg(test)]
mod tests {
    use std::{env, fs, path::PathBuf};

    use super::*;
    use crate::test::factories::general::file::verify_file;

    /// Tests loading a PE file from disk.
    #[test]
    fn load_file() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        let file = File::from_file(&path).unwrap();

        verify_file(&file);
    }

    /// Tests loading a PE file from a memory buffer.
    #[test]
    fn load_buffer() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        let data = fs::read(&path).unwrap();
        let file = File::from_mem(data).unwrap();

        verify_file(&file);
    }

    /// Tests loading an invalid PE file.
    #[test]
    fn load_invalid() {
        let data = include_bytes!("../../tests/samples/WB_ROOT.bin");
        if File::from_mem(data.to_vec()).is_ok() {
            panic!("This should not load!")
        }
    }

    /// Tests the unified get_data_directory method.
    #[test]
    fn test_get_data_directory() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        let file = File::from_file(&path).unwrap();

        // Test CLR runtime header (should exist for .NET assemblies)
        let clr_dir = file.get_data_directory(DataDirectoryType::ClrRuntimeHeader);
        assert!(clr_dir.is_some(), "CLR runtime header should exist");
        let (clr_rva, clr_size) = clr_dir.unwrap();
        assert!(clr_rva > 0, "CLR RVA should be non-zero");
        assert!(clr_size > 0, "CLR size should be non-zero");

        // Verify it matches the existing clr() method
        let (expected_rva, expected_size) = file.clr();
        assert_eq!(
            clr_rva as usize, expected_rva,
            "CLR RVA should match clr() method"
        );
        assert_eq!(
            clr_size as usize, expected_size,
            "CLR size should match clr() method"
        );

        // Test non-existent directory (should return None)
        let _base_reloc_dir = file.get_data_directory(DataDirectoryType::BaseRelocationTable);
        // For a typical .NET assembly, base relocation table might not exist
        // We don't assert anything specific here as it depends on the assembly

        // The method should handle any directory type gracefully
        let tls_dir = file.get_data_directory(DataDirectoryType::TlsTable);
        // TLS table typically doesn't exist in .NET assemblies, but method should not panic
        if let Some((tls_rva, tls_size)) = tls_dir {
            assert!(
                tls_rva > 0 && tls_size > 0,
                "If TLS directory exists, it should have valid values"
            );
        }
    }

    /// Tests the pe_signature_offset method.
    #[test]
    fn test_pe_signature_offset() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/crafted_2.exe");
        let file = File::from_file(&path).expect("Failed to load test assembly");

        let pe_offset = file
            .pe_signature_offset()
            .expect("Should get PE signature offset");
        assert!(pe_offset > 0, "PE signature offset should be positive");
        assert!(pe_offset < 1024, "PE signature offset should be reasonable");
    }

    /// Tests the pe_headers_size method.
    #[test]
    fn test_pe_headers_size() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/crafted_2.exe");
        let file = File::from_file(&path).expect("Failed to load test assembly");

        let headers_size = file
            .pe_headers_size()
            .expect("Should calculate headers size");
        assert!(headers_size >= 24, "Headers should be at least 24 bytes");
        assert!(headers_size <= 1024, "Headers size should be reasonable");
    }

    /// Tests the align_to_file_alignment method.
    #[test]
    fn test_align_to_file_alignment() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/crafted_2.exe");
        let file = File::from_file(&path).expect("Failed to load test assembly");

        // Test alignment with actual file alignment from PE header
        let alignment = file.file_alignment().expect("Should get file alignment");

        // Test various offsets
        assert_eq!(file.align_to_file_alignment(0).unwrap(), 0);
        assert_eq!(file.align_to_file_alignment(1).unwrap(), alignment as u64);
        assert_eq!(
            file.align_to_file_alignment(alignment as u64).unwrap(),
            alignment as u64
        );
        assert_eq!(
            file.align_to_file_alignment(alignment as u64 + 1).unwrap(),
            (alignment * 2) as u64
        );
    }
}
