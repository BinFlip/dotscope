//! Owned PE file structures and serialization support.
//!
//! This module provides owned versions of PE (Portable Executable) structures that don't
//! require borrowing from the original file data. These structures support both parsing
//! from goblin PE objects and serialization back to binary format for the write pipeline.
//!
//! # Architecture
//!
//! The module provides owned alternatives to goblin's borrowed structures:
//! - [`Pe`] - Main PE file representation
//! - [`DosHeader`] - DOS header with signature and PE offset
//! - [`CoffHeader`] - COFF header with machine type and characteristics
//! - [`OptionalHeader`] - Optional header with data directories and Windows fields
//! - [`SectionTable`] - Section table entries with names and addresses
//! - [`DataDirectories`] - Data directory entries as owned map
//! - [`Import`]/[`Export`] - Owned import/export table entries
//!
//! Each structure implements:
//! - Conversion from corresponding goblin types
//! - Binary serialization methods for the write pipeline
//! - Accessor methods matching the original File API
//!
//! # Usage Examples
//!
//! ## Parsing from Goblin PE
//! ```rust,ignore
//! use goblin::pe::PE;
//! use dotscope::file::pe::Pe;
//!
//! let goblin_pe = PE::parse(data)?;
//! let owned_pe = Pe::from_goblin_pe(&goblin_pe)?;
//! ```
//!
//! ## Serialization for Write Pipeline
//! ```rust,ignore
//! let mut buffer = Vec::new();
//! owned_pe.write_headers(&mut buffer)?;
//! owned_pe.write_section_table(&mut buffer)?;
//! ```

use crate::{Error, Result};
use std::collections::HashMap;
use std::io::Write;

/// PE file format constants
pub mod constants {
    /// Size of the COR20 header in bytes (ECMA-335 specification)
    pub const COR20_HEADER_SIZE: u32 = 72;

    /// Section characteristic: IMAGE_SCN_MEM_EXECUTE
    pub const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;

    /// Section characteristic: IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ
    pub const IMAGE_SCN_METADATA: u32 = 0x4000_0040;

    /// Maximum reasonable RVA value for validation
    pub const MAX_REASONABLE_RVA: u32 = 0x1000_0000;
}

/// Owned PE file representation that doesn't require borrowing from source data.
///
/// This struct contains all the essential PE file information needed for both
/// analysis and generation operations. Unlike goblin's PE struct which borrows
/// from the source data, this structure owns all its data, eliminating lifetime
/// dependencies and enabling flexible usage patterns.
///
/// The structure is designed to support the write pipeline by providing binary
/// serialization methods for all PE components.
#[derive(Debug, Clone)]
pub struct Pe {
    /// DOS header information
    pub dos_header: DosHeader,

    /// COFF header with machine type and characteristics
    pub coff_header: CoffHeader,

    /// Optional header with Windows-specific fields and data directories
    pub optional_header: Option<OptionalHeader>,

    /// Section table entries
    pub sections: Vec<SectionTable>,

    /// Computed image base address
    pub image_base: u64,

    /// Whether this is a 64-bit PE file
    pub is_64bit: bool,

    /// Imported symbols and DLLs
    pub imports: Vec<Import>,

    /// Exported symbols
    pub exports: Vec<Export>,

    /// List of imported library names
    pub libraries: Vec<String>,

    /// Data directories as owned map for easy lookup
    pub data_directories: HashMap<DataDirectoryType, DataDirectory>,
}

/// Owned DOS header structure.
#[derive(Debug, Clone)]
pub struct DosHeader {
    /// DOS signature (usually "MZ")
    pub signature: u16,
    /// Number of bytes on last page of file
    pub bytes_on_last_page: u16,
    /// Number of pages in file
    pub pages_in_file: u16,
    /// Number of relocation entries
    pub relocations: u16,
    /// Size of header in paragraphs
    pub size_of_header_paragraphs: u16,
    /// Minimum extra paragraphs needed
    pub minimum_extra_paragraphs: u16,
    /// Maximum extra paragraphs needed
    pub maximum_extra_paragraphs: u16,
    /// Initial relative SS value
    pub initial_relative_ss: u16,
    /// Initial SP value
    pub initial_sp: u16,
    /// Checksum
    pub checksum: u16,
    /// Initial IP value
    pub initial_ip: u16,
    /// Initial relative CS value
    pub initial_relative_cs: u16,
    /// Address of relocation table
    pub address_of_relocation_table: u16,
    /// Overlay number
    pub overlay_number: u16,
    /// PE header offset
    pub pe_header_offset: u32,
}

/// Owned COFF header structure.
#[derive(Debug, Clone)]
pub struct CoffHeader {
    /// Machine type (e.g., IMAGE_FILE_MACHINE_I386, IMAGE_FILE_MACHINE_AMD64)
    pub machine: u16,
    /// Number of sections
    pub number_of_sections: u16,
    /// Time and date stamp
    pub time_date_stamp: u32,
    /// File pointer to symbol table
    pub pointer_to_symbol_table: u32,
    /// Number of symbols
    pub number_of_symbols: u32,
    /// Size of optional header
    pub size_of_optional_header: u16,
    /// Characteristics flags
    pub characteristics: u16,
}

/// Owned optional header structure.
#[derive(Debug, Clone)]
pub struct OptionalHeader {
    /// Standard fields (PE32/PE32+ common)
    pub standard_fields: StandardFields,
    /// Windows-specific fields
    pub windows_fields: WindowsFields,
    /// Data directories
    pub data_directories: DataDirectories,
}

/// Standard fields common to PE32 and PE32+.
#[derive(Debug, Clone)]
pub struct StandardFields {
    /// Magic number (0x10b for PE32, 0x20b for PE32+)
    pub magic: u16,
    /// Major linker version
    pub major_linker_version: u8,
    /// Minor linker version  
    pub minor_linker_version: u8,
    /// Size of code section
    pub size_of_code: u32,
    /// Size of initialized data
    pub size_of_initialized_data: u32,
    /// Size of uninitialized data
    pub size_of_uninitialized_data: u32,
    /// Address of entry point
    pub address_of_entry_point: u32,
    /// Base of code section
    pub base_of_code: u32,
    /// Base of data section (PE32 only)
    pub base_of_data: Option<u32>,
}

/// Windows-specific fields.
#[derive(Debug, Clone)]
pub struct WindowsFields {
    /// Image base address
    pub image_base: u64,
    /// Section alignment in memory
    pub section_alignment: u32,
    /// File alignment
    pub file_alignment: u32,
    /// Major OS version
    pub major_operating_system_version: u16,
    /// Minor OS version
    pub minor_operating_system_version: u16,
    /// Major image version
    pub major_image_version: u16,
    /// Minor image version
    pub minor_image_version: u16,
    /// Major subsystem version
    pub major_subsystem_version: u16,
    /// Minor subsystem version
    pub minor_subsystem_version: u16,
    /// Win32 version value
    pub win32_version_value: u32,
    /// Size of image
    pub size_of_image: u32,
    /// Size of headers
    pub size_of_headers: u32,
    /// Checksum
    pub checksum: u32,
    /// Subsystem
    pub subsystem: u16,
    /// DLL characteristics
    pub dll_characteristics: u16,
    /// Size of stack reserve
    pub size_of_stack_reserve: u64,
    /// Size of stack commit
    pub size_of_stack_commit: u64,
    /// Size of heap reserve
    pub size_of_heap_reserve: u64,
    /// Size of heap commit
    pub size_of_heap_commit: u64,
    /// Loader flags
    pub loader_flags: u32,
    /// Number of RVA and sizes
    pub number_of_rva_and_sizes: u32,
}

/// Data directories as an owned map for easy lookup.
#[derive(Debug, Clone)]
pub struct DataDirectories {
    directories: HashMap<DataDirectoryType, DataDirectory>,
}

/// Data directory entry.
#[derive(Debug, Clone, Copy)]
pub struct DataDirectory {
    /// Virtual address of the data
    pub virtual_address: u32,
    /// Size of the data
    pub size: u32,
}

/// Data directory types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DataDirectoryType {
    /// Export table directory.
    ExportTable = 0,
    /// Import table directory.
    ImportTable = 1,
    /// Resource table directory.
    ResourceTable = 2,
    /// Exception table directory.
    ExceptionTable = 3,
    /// Certificate table directory.
    CertificateTable = 4,
    /// Base relocation table directory.
    BaseRelocationTable = 5,
    /// Debug directory.
    Debug = 6,
    /// Architecture-specific data directory.
    Architecture = 7,
    /// Global pointer directory.
    GlobalPtr = 8,
    /// Thread local storage table directory.
    TlsTable = 9,
    /// Load configuration table directory.
    LoadConfigTable = 10,
    /// Bound import table directory.
    BoundImport = 11,
    /// Import address table directory.
    ImportAddressTable = 12,
    /// Delay import descriptor directory.
    DelayImportDescriptor = 13,
    /// CLR runtime header directory.
    ClrRuntimeHeader = 14,
    /// Reserved directory entry.
    Reserved = 15,
}

/// Owned section table entry.
#[derive(Debug, Clone)]
pub struct SectionTable {
    /// Section name (up to 8 bytes)
    pub name: String,
    /// Virtual size
    pub virtual_size: u32,
    /// Virtual address (RVA)
    pub virtual_address: u32,
    /// Size of raw data
    pub size_of_raw_data: u32,
    /// Pointer to raw data
    pub pointer_to_raw_data: u32,
    /// Pointer to relocations
    pub pointer_to_relocations: u32,
    /// Pointer to line numbers
    pub pointer_to_line_numbers: u32,
    /// Number of relocations
    pub number_of_relocations: u16,
    /// Number of line numbers
    pub number_of_line_numbers: u16,
    /// Section characteristics
    pub characteristics: u32,
}

/// Import entry representing a function imported from an external DLL.
///
/// This structure serves as the single source of truth for both PE parsing and metadata
/// processing, eliminating the need for type conversion between different layers of the
/// system. It captures all information needed to resolve and call imported functions
/// at runtime through the Windows PE loader.
///
/// # Import Resolution Mechanism
///
/// Windows PE imports use a two-table system:
/// - **Import Lookup Table (ILT)**: Template containing original import information
/// - **Import Address Table (IAT)**: Runtime-patched table with actual function addresses
///
/// The loader patches the IAT at runtime, replacing import descriptors with actual
/// function addresses from the target DLL.
///
/// # Import Types
///
/// Functions can be imported in two ways:
/// - **By Name**: Using function name and optional hint for optimization
/// - **By Ordinal**: Using only ordinal number (more efficient but less portable)
///
/// # Field Relationships
///
/// - `name` and `ordinal` are mutually exclusive (one will be None)
/// - `rva` points to the slot in the Import Address Table
/// - `hint` optimizes name lookups in the target DLL's export table
/// - `ilt_value` preserves the original Import Lookup Table entry value
#[derive(Debug, Clone)]
pub struct Import {
    /// Name of the DLL containing the imported function (e.g., "kernel32.dll")
    pub dll: String,
    /// Function name if imported by name (None for ordinal-only imports)
    pub name: Option<String>,
    /// Ordinal number if imported by ordinal (None for name-only imports)
    pub ordinal: Option<u16>,
    /// Relative Virtual Address of the Import Address Table slot for this import
    pub rva: u32,
    /// Hint value for optimizing name lookups in the target DLL's export table (0 if unavailable)
    pub hint: u16,
    /// Original Import Lookup Table entry value preserving import metadata (0 if unavailable)
    pub ilt_value: u64,
}

/// Owned export entry.
#[derive(Debug, Clone)]
pub struct Export {
    /// Function name (None for ordinal-only exports)
    pub name: Option<String>,
    /// Export RVA
    pub rva: u32,
    /// Ordinal offset for ordinal calculation
    pub offset: Option<u32>,
}

impl Pe {
    /// Create Pe from goblin PE structure.
    ///
    /// # Errors
    ///
    /// Returns an error if the PE structure contains invalid data or if conversion fails.
    pub fn from_goblin_pe(goblin_pe: &goblin::pe::PE) -> Result<Self> {
        let dos_header = DosHeader::from_goblin(&goblin_pe.header.dos_header);
        let coff_header = CoffHeader::from_goblin(&goblin_pe.header.coff_header);
        let optional_header = goblin_pe
            .header
            .optional_header
            .as_ref()
            .map(OptionalHeader::from_goblin)
            .transpose()?;

        match optional_header.as_ref() {
            Some(oh) => {
                if oh.data_directories.get_clr_runtime_header().is_none() {
                    return Err(malformed_error!(
                        "File does not have a CLR runtime header directory"
                    ));
                }
            }
            None => {
                return Err(malformed_error!("File does not have an OptionalHeader"));
            }
        }

        let sections = goblin_pe
            .sections
            .iter()
            .map(SectionTable::from_goblin)
            .collect::<Result<Vec<_>>>()?;

        let imports = goblin_pe
            .imports
            .iter()
            .map(Import::from_goblin)
            .collect::<Result<Vec<_>>>()?;

        let exports = goblin_pe
            .exports
            .iter()
            .map(Export::from_goblin)
            .collect::<Result<Vec<_>>>()?;

        let libraries = goblin_pe.libraries.iter().map(|&s| s.to_string()).collect();

        let data_directories = optional_header
            .as_ref()
            .map_or_else(DataDirectories::new, |oh| oh.data_directories.clone());

        Ok(Pe {
            dos_header,
            coff_header,
            optional_header,
            sections,
            image_base: goblin_pe.image_base,
            is_64bit: goblin_pe.is_64,
            imports,
            exports,
            libraries,
            data_directories: data_directories.directories,
        })
    }

    /// Write DOS header to buffer.
    ///
    /// # Errors
    ///
    /// Returns an error if writing to the buffer fails.
    pub fn write_dos_header<W: Write>(&self, writer: &mut W) -> Result<()> {
        self.dos_header.write_to(writer)
    }

    /// Write PE signature and COFF header to buffer.
    ///
    /// # Errors
    ///
    /// Returns an error if writing to the buffer fails.
    pub fn write_pe_headers<W: Write>(&self, writer: &mut W) -> Result<()> {
        // PE signature
        writer.write_all(b"PE\x00\x00")?;

        // COFF header
        self.coff_header.write_to(writer)?;

        // Optional header
        if let Some(ref oh) = self.optional_header {
            oh.write_to(writer)?;
        }

        Ok(())
    }

    /// Write section table to buffer.
    ///
    /// # Errors
    ///
    /// Returns an error if writing to the buffer fails.
    pub fn write_section_table<W: Write>(&self, writer: &mut W) -> Result<()> {
        for section in &self.sections {
            section.write_to(writer)?;
        }
        Ok(())
    }

    /// Get data directory by type.
    #[must_use]
    pub fn get_data_directory(&self, dir_type: DataDirectoryType) -> Option<DataDirectory> {
        self.data_directories.get(&dir_type).copied()
    }

    /// Get CLR runtime header directory.
    #[must_use]
    pub fn get_clr_runtime_header(&self) -> Option<DataDirectory> {
        self.get_data_directory(DataDirectoryType::ClrRuntimeHeader)
    }

    /// Calculates the total size of PE headers (PE signature + COFF header + Optional header).
    ///
    /// This method computes the complete size needed for all PE headers based on
    /// the actual header contents, which is useful for layout planning during write operations.
    ///
    /// # Returns
    /// Total size in bytes of all PE headers
    #[must_use]
    pub fn calculate_headers_size(&self) -> u64 {
        // PE signature (4 bytes) + COFF header (20 bytes) + optional header size
        let optional_header_size = self
            .optional_header
            .as_ref()
            .map_or(0, |_| u64::from(self.coff_header.size_of_optional_header));

        4 + CoffHeader::SIZE as u64 + optional_header_size
    }

    /// Calculates the total size of all file headers (DOS header + PE headers).
    ///
    /// This method computes the complete size needed for DOS header plus all PE headers,
    /// which is useful for file layout calculations where the total header space is needed.
    ///
    /// # Returns
    /// Total size in bytes of DOS header + PE headers
    #[must_use]
    pub fn calculate_total_file_headers_size(&self) -> u64 {
        DosHeader::size() + self.calculate_headers_size()
    }

    /// Calculates the total size of all current sections' raw data.
    ///
    /// This method sums the `size_of_raw_data` field from all sections, which represents
    /// the total space occupied by section content in the file.
    ///
    /// # Returns
    /// Total size in bytes of all section raw data
    #[must_use]
    pub fn get_sections_total_raw_data_size(&self) -> u64 {
        self.sections
            .iter()
            .map(|section| u64::from(section.size_of_raw_data))
            .sum()
    }

    /// Gets the PE headers offset from the DOS header.
    ///
    /// # Returns
    /// Offset where PE headers start in the file
    #[must_use]
    pub fn get_pe_headers_offset(&self) -> u64 {
        u64::from(self.dos_header.pe_header_offset)
    }

    /// Gets the file alignment from the original PE headers.
    ///
    /// # Returns
    /// File alignment in bytes from the original PE headers
    #[must_use]
    pub fn get_file_alignment(&self) -> u64 {
        self.optional_header
            .as_ref()
            .map_or(0x200, |oh| u64::from(oh.windows_fields.file_alignment)) // Fallback to common default
    }

    /// Gets the section alignment from the original PE headers.
    ///
    /// # Returns
    /// Section alignment in bytes from the original PE headers
    #[must_use]
    pub fn get_section_alignment(&self) -> u64 {
        self.optional_header
            .as_ref()
            .map_or(0x1000, |oh| u64::from(oh.windows_fields.section_alignment))
        // Fallback to common default
    }

    /// Adds a new section to the PE file.
    ///
    /// This method adds a new section entry and automatically updates the section count
    /// in the COFF header to maintain consistency.
    ///
    /// # Arguments
    /// * `section` - The section to add
    pub fn add_section(&mut self, section: SectionTable) {
        self.sections.push(section);
        if let Ok(section_count) = u16::try_from(self.sections.len()) {
            self.coff_header.update_section_count(section_count);
        }
    }

    /// Removes a section by name from the PE file.
    ///
    /// This method removes the first section with the given name and automatically
    /// updates the section count in the COFF header.
    ///
    /// # Arguments
    /// * `name` - The name of the section to remove
    ///
    /// # Returns
    /// Returns `true` if a section was removed, `false` if no section with the given name was found
    pub fn remove_section(&mut self, name: &str) -> bool {
        if let Some(index) = self.sections.iter().position(|s| s.name == name) {
            self.sections.remove(index);
            if let Ok(section_count) = u16::try_from(self.sections.len()) {
                self.coff_header.update_section_count(section_count);
            }
            true
        } else {
            false
        }
    }

    /// Finds a mutable reference to a section by name.
    ///
    /// This allows direct modification of section properties while maintaining
    /// the section within the PE structure.
    ///
    /// # Arguments
    /// * `name` - The name of the section to find
    ///
    /// # Returns
    /// Returns a mutable reference to the section if found, None otherwise
    pub fn get_section_mut(&mut self, name: &str) -> Option<&mut SectionTable> {
        self.sections.iter_mut().find(|s| s.name == name)
    }

    /// Finds a reference to a section by name.
    ///
    /// # Arguments
    /// * `name` - The name of the section to find
    ///
    /// # Returns
    /// Returns a reference to the section if found, None otherwise
    #[must_use]
    pub fn get_section(&self, name: &str) -> Option<&SectionTable> {
        self.sections.iter().find(|s| s.name == name)
    }

    /// Updates the CLR runtime header data directory.
    ///
    /// This method updates the CLR data directory entry to point to a new location,
    /// maintaining consistency between the optional header and main data directories map.
    ///
    /// # Arguments
    /// * `rva` - The new RVA for the CLR runtime header
    /// * `size` - The new size of the CLR runtime header
    ///
    /// # Errors
    /// Returns an error if the PE has no optional header
    pub fn update_clr_data_directory(&mut self, rva: u32, size: u32) -> Result<()> {
        if let Some(ref mut optional_header) = self.optional_header {
            optional_header.data_directories.update_clr_entry(rva, size);
            // Also update the main data_directories map
            self.data_directories.insert(
                DataDirectoryType::ClrRuntimeHeader,
                DataDirectory {
                    virtual_address: rva,
                    size,
                },
            );
            Ok(())
        } else {
            Err(malformed_error!(
                "Cannot update CLR data directory: PE has no optional header"
            ))
        }
    }

    /// Updates a specific data directory entry.
    ///
    /// This method updates any data directory entry while maintaining consistency
    /// between the optional header and main data directories map.
    ///
    /// # Arguments
    /// * `dir_type` - The type of data directory to update
    /// * `rva` - The new RVA for the directory
    /// * `size` - The new size of the directory
    ///
    /// # Errors
    /// Returns an error if the PE has no optional header
    pub fn update_data_directory(
        &mut self,
        dir_type: DataDirectoryType,
        rva: u32,
        size: u32,
    ) -> Result<()> {
        if let Some(ref mut optional_header) = self.optional_header {
            optional_header
                .data_directories
                .update_entry(dir_type, rva, size);
            // Also update the main data_directories map
            self.data_directories.insert(
                dir_type,
                DataDirectory {
                    virtual_address: rva,
                    size,
                },
            );
            Ok(())
        } else {
            Err(malformed_error!(
                "Cannot update data directory: PE has no optional header"
            ))
        }
    }

    /// Writes the complete PE headers in their current state.
    ///
    /// This method serializes the PE signature, COFF header, and optional header
    /// using their current values. No modifications are made during the write operation.
    ///
    /// # Arguments
    /// * `writer` - Writer to output the headers to
    ///
    /// # Errors
    /// Returns an error if writing fails
    pub fn write_headers<W: Write>(&self, writer: &mut W) -> Result<()> {
        // Write PE signature
        writer.write_all(b"PE\x00\x00")?;

        // Write COFF header in current state
        self.coff_header.write_to(writer)?;

        // Write optional header in current state
        if let Some(ref optional_header) = self.optional_header {
            optional_header.write_to(writer)?;
        }

        Ok(())
    }

    /// Writes all section headers in their current state.
    ///
    /// This method serializes all sections in the sections vector using their
    /// current values. The section count in the COFF header should already reflect
    /// the correct number of sections.
    ///
    /// # Arguments
    /// * `writer` - Writer to output the section table to
    ///
    /// # Errors
    /// Returns an error if writing fails
    pub fn write_section_headers<W: Write>(&self, writer: &mut W) -> Result<()> {
        for section in &self.sections {
            section.write_header_to(writer)?;
        }
        Ok(())
    }
}

impl DosHeader {
    /// Size of DOS header in bytes.
    pub const SIZE: usize = 64;

    /// Returns the size of the DOS header.
    #[must_use]
    pub fn size() -> u64 {
        Self::SIZE as u64
    }

    fn from_goblin(goblin_dos: &goblin::pe::header::DosHeader) -> Self {
        Self {
            signature: goblin_dos.signature,
            bytes_on_last_page: goblin_dos.bytes_on_last_page,
            pages_in_file: goblin_dos.pages_in_file,
            relocations: goblin_dos.relocations,
            size_of_header_paragraphs: goblin_dos.size_of_header_in_paragraphs,
            minimum_extra_paragraphs: goblin_dos.minimum_extra_paragraphs_needed,
            maximum_extra_paragraphs: goblin_dos.maximum_extra_paragraphs_needed,
            initial_relative_ss: goblin_dos.initial_relative_ss,
            initial_sp: goblin_dos.initial_sp,
            checksum: goblin_dos.checksum,
            initial_ip: goblin_dos.initial_ip,
            initial_relative_cs: goblin_dos.initial_relative_cs,
            address_of_relocation_table: goblin_dos.file_address_of_relocation_table,
            overlay_number: goblin_dos.overlay_number,
            pe_header_offset: goblin_dos.pe_pointer,
        }
    }

    fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&self.signature.to_le_bytes())?;
        writer.write_all(&self.bytes_on_last_page.to_le_bytes())?;
        writer.write_all(&self.pages_in_file.to_le_bytes())?;
        writer.write_all(&self.relocations.to_le_bytes())?;
        writer.write_all(&self.size_of_header_paragraphs.to_le_bytes())?;
        writer.write_all(&self.minimum_extra_paragraphs.to_le_bytes())?;
        writer.write_all(&self.maximum_extra_paragraphs.to_le_bytes())?;
        writer.write_all(&self.initial_relative_ss.to_le_bytes())?;
        writer.write_all(&self.initial_sp.to_le_bytes())?;
        writer.write_all(&self.checksum.to_le_bytes())?;
        writer.write_all(&self.initial_ip.to_le_bytes())?;
        writer.write_all(&self.initial_relative_cs.to_le_bytes())?;
        writer.write_all(&self.address_of_relocation_table.to_le_bytes())?;
        writer.write_all(&self.overlay_number.to_le_bytes())?;
        // Reserved fields (4 words)
        for _ in 0..4 {
            writer.write_all(&0u16.to_le_bytes())?;
        }
        // OEM fields
        writer.write_all(&0u16.to_le_bytes())?; // OEM identifier
        writer.write_all(&0u16.to_le_bytes())?; // OEM information
                                                // Reserved2 fields (10 words)
        for _ in 0..10 {
            writer.write_all(&0u16.to_le_bytes())?;
        }
        writer.write_all(&self.pe_header_offset.to_le_bytes())?;

        Ok(())
    }
}

impl CoffHeader {
    /// Size of COFF header in bytes.
    pub const SIZE: usize = 20;

    fn from_goblin(goblin_coff: &goblin::pe::header::CoffHeader) -> Self {
        Self {
            machine: goblin_coff.machine,
            number_of_sections: goblin_coff.number_of_sections,
            time_date_stamp: goblin_coff.time_date_stamp,
            pointer_to_symbol_table: goblin_coff.pointer_to_symbol_table,
            number_of_symbols: goblin_coff.number_of_symbol_table,
            size_of_optional_header: goblin_coff.size_of_optional_header,
            characteristics: goblin_coff.characteristics,
        }
    }

    /// Updates the number of sections in the COFF header.
    ///
    /// This method is used during write operations when adding new sections
    /// (like the .meta section) to ensure the COFF header reflects the
    /// correct section count.
    ///
    /// # Arguments
    /// * `new_count` - The new number of sections
    pub fn update_section_count(&mut self, new_count: u16) {
        self.number_of_sections = new_count;
    }

    /// Updates the size of optional header field in the COFF header.
    ///
    /// This method is used during write operations when the optional header
    /// size changes to ensure the COFF header reflects the correct size.
    ///
    /// # Arguments
    /// * `new_size` - The new size of the optional header in bytes
    pub fn update_optional_header_size(&mut self, new_size: u16) {
        self.size_of_optional_header = new_size;
    }

    fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&self.machine.to_le_bytes())?;
        writer.write_all(&self.number_of_sections.to_le_bytes())?;
        writer.write_all(&self.time_date_stamp.to_le_bytes())?;
        writer.write_all(&self.pointer_to_symbol_table.to_le_bytes())?;
        writer.write_all(&self.number_of_symbols.to_le_bytes())?;
        writer.write_all(&self.size_of_optional_header.to_le_bytes())?;
        writer.write_all(&self.characteristics.to_le_bytes())?;

        Ok(())
    }
}

impl OptionalHeader {
    fn from_goblin(goblin_oh: &goblin::pe::optional_header::OptionalHeader) -> Result<Self> {
        let standard_fields = StandardFields::from_goblin(&goblin_oh.standard_fields)?;
        let windows_fields = WindowsFields::from_goblin(&goblin_oh.windows_fields);
        let data_directories = DataDirectories::from_goblin(&goblin_oh.data_directories);

        Ok(Self {
            standard_fields,
            windows_fields,
            data_directories,
        })
    }

    fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        let is_pe32_plus = self.standard_fields.magic != 0x10b;
        self.standard_fields.write_to(writer)?;
        self.windows_fields.write_to(writer, is_pe32_plus)?;
        self.data_directories.write_to(writer)?;

        Ok(())
    }
}

impl StandardFields {
    fn from_goblin(goblin_sf: &goblin::pe::optional_header::StandardFields) -> Result<Self> {
        Ok(Self {
            magic: goblin_sf.magic,
            major_linker_version: goblin_sf.major_linker_version,
            minor_linker_version: goblin_sf.minor_linker_version,
            size_of_code: u32::try_from(goblin_sf.size_of_code)
                .map_err(|_| malformed_error!("PE size_of_code value too large"))?,
            size_of_initialized_data: u32::try_from(goblin_sf.size_of_initialized_data)
                .map_err(|_| malformed_error!("PE size_of_initialized_data value too large"))?,
            size_of_uninitialized_data: u32::try_from(goblin_sf.size_of_uninitialized_data)
                .map_err(|_| malformed_error!("PE size_of_uninitialized_data value too large"))?,
            address_of_entry_point: goblin_sf.address_of_entry_point,
            base_of_code: u32::try_from(goblin_sf.base_of_code)
                .map_err(|_| malformed_error!("PE base_of_code value too large"))?,
            base_of_data: if goblin_sf.magic == 0x10b {
                Some(goblin_sf.base_of_data)
            } else {
                None
            },
        })
    }

    fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&self.magic.to_le_bytes())?;
        writer.write_all(&self.major_linker_version.to_le_bytes())?;
        writer.write_all(&self.minor_linker_version.to_le_bytes())?;
        writer.write_all(&self.size_of_code.to_le_bytes())?;
        writer.write_all(&self.size_of_initialized_data.to_le_bytes())?;
        writer.write_all(&self.size_of_uninitialized_data.to_le_bytes())?;
        writer.write_all(&self.address_of_entry_point.to_le_bytes())?;
        writer.write_all(&self.base_of_code.to_le_bytes())?;

        // base_of_data only exists in PE32 (magic == 0x10b)
        if self.magic == 0x10b {
            if let Some(base_of_data) = self.base_of_data {
                writer.write_all(&base_of_data.to_le_bytes())?;
            } else {
                return Err(Error::Malformed {
                    message: "PE32 file missing base_of_data field".to_string(),
                    file: file!(),
                    line: line!(),
                });
            }
        }

        Ok(())
    }
}

impl WindowsFields {
    fn from_goblin(goblin_wf: &goblin::pe::optional_header::WindowsFields) -> Self {
        Self {
            image_base: goblin_wf.image_base,
            section_alignment: goblin_wf.section_alignment,
            file_alignment: goblin_wf.file_alignment,
            major_operating_system_version: goblin_wf.major_operating_system_version,
            minor_operating_system_version: goblin_wf.minor_operating_system_version,
            major_image_version: goblin_wf.major_image_version,
            minor_image_version: goblin_wf.minor_image_version,
            major_subsystem_version: goblin_wf.major_subsystem_version,
            minor_subsystem_version: goblin_wf.minor_subsystem_version,
            win32_version_value: goblin_wf.win32_version_value,
            size_of_image: goblin_wf.size_of_image,
            size_of_headers: goblin_wf.size_of_headers,
            checksum: goblin_wf.check_sum,
            subsystem: goblin_wf.subsystem,
            dll_characteristics: goblin_wf.dll_characteristics,
            size_of_stack_reserve: goblin_wf.size_of_stack_reserve,
            size_of_stack_commit: goblin_wf.size_of_stack_commit,
            size_of_heap_reserve: goblin_wf.size_of_heap_reserve,
            size_of_heap_commit: goblin_wf.size_of_heap_commit,
            loader_flags: goblin_wf.loader_flags,
            number_of_rva_and_sizes: goblin_wf.number_of_rva_and_sizes,
        }
    }

    fn write_to<W: Write>(&self, writer: &mut W, is_pe32_plus: bool) -> Result<()> {
        // Write image_base with appropriate size
        if is_pe32_plus {
            writer.write_all(&self.image_base.to_le_bytes())?;
        } else {
            writer.write_all(
                &u32::try_from(self.image_base)
                    .map_err(|_| Error::Error("Image base exceeds u32 range".to_string()))?
                    .to_le_bytes(),
            )?;
        }

        writer.write_all(&self.section_alignment.to_le_bytes())?;
        writer.write_all(&self.file_alignment.to_le_bytes())?;
        writer.write_all(&self.major_operating_system_version.to_le_bytes())?;
        writer.write_all(&self.minor_operating_system_version.to_le_bytes())?;
        writer.write_all(&self.major_image_version.to_le_bytes())?;
        writer.write_all(&self.minor_image_version.to_le_bytes())?;
        writer.write_all(&self.major_subsystem_version.to_le_bytes())?;
        writer.write_all(&self.minor_subsystem_version.to_le_bytes())?;
        writer.write_all(&self.win32_version_value.to_le_bytes())?;
        writer.write_all(&self.size_of_image.to_le_bytes())?;
        writer.write_all(&self.size_of_headers.to_le_bytes())?;
        writer.write_all(&self.checksum.to_le_bytes())?;
        writer.write_all(&self.subsystem.to_le_bytes())?;
        writer.write_all(&self.dll_characteristics.to_le_bytes())?;

        // Write stack/heap size fields with appropriate size based on PE format
        if is_pe32_plus {
            // PE32+: 8-byte fields
            writer.write_all(&self.size_of_stack_reserve.to_le_bytes())?;
            writer.write_all(&self.size_of_stack_commit.to_le_bytes())?;
            writer.write_all(&self.size_of_heap_reserve.to_le_bytes())?;
            writer.write_all(&self.size_of_heap_commit.to_le_bytes())?;
        } else {
            // PE32: 4-byte fields
            writer.write_all(
                &u32::try_from(self.size_of_stack_reserve)
                    .map_err(|_| Error::Error("Stack reserve size exceeds u32 range".to_string()))?
                    .to_le_bytes(),
            )?;
            writer.write_all(
                &u32::try_from(self.size_of_stack_commit)
                    .map_err(|_| Error::Error("Stack commit size exceeds u32 range".to_string()))?
                    .to_le_bytes(),
            )?;
            writer.write_all(
                &u32::try_from(self.size_of_heap_reserve)
                    .map_err(|_| Error::Error("Heap reserve size exceeds u32 range".to_string()))?
                    .to_le_bytes(),
            )?;
            writer.write_all(
                &u32::try_from(self.size_of_heap_commit)
                    .map_err(|_| Error::Error("Heap commit size exceeds u32 range".to_string()))?
                    .to_le_bytes(),
            )?;
        }

        writer.write_all(&self.loader_flags.to_le_bytes())?;

        writer.write_all(&self.number_of_rva_and_sizes.to_le_bytes())?;

        Ok(())
    }
}

impl DataDirectories {
    fn new() -> Self {
        Self {
            directories: HashMap::new(),
        }
    }

    /// Get CLR runtime header directory.
    #[must_use]
    pub fn get_clr_runtime_header(&self) -> Option<&DataDirectory> {
        self.directories.get(&DataDirectoryType::ClrRuntimeHeader)
    }

    /// Updates a data directory entry.
    ///
    /// This method allows updating specific data directory entries during write
    /// operations, such as updating the CLR runtime header when adding new metadata.
    ///
    /// # Arguments
    /// * `dir_type` - The type of data directory to update
    /// * `rva` - The new RVA (Relative Virtual Address) for the directory
    /// * `size` - The new size in bytes for the directory
    ///
    /// # Examples
    /// ```rust,ignore
    /// // Update CLR runtime header location
    /// data_directories.update_entry(
    ///     DataDirectoryType::ClrRuntimeHeader,
    ///     0x2000, // new RVA
    ///     72      // CLR header size
    /// )?;
    /// ```
    pub fn update_entry(&mut self, dir_type: DataDirectoryType, rva: u32, size: u32) {
        self.directories.insert(
            dir_type,
            DataDirectory {
                virtual_address: rva,
                size,
            },
        );
    }

    /// Updates the CLR runtime header data directory entry.
    ///
    /// This is a convenience method specifically for updating the CLR runtime header
    /// directory entry, which is commonly done during .NET assembly write operations.
    ///
    /// # Arguments
    /// * `rva` - The new RVA for the CLR runtime header
    /// * `size` - The new size of the CLR runtime header (typically 72 bytes)
    ///
    /// # Examples
    /// ```rust,ignore
    /// // Update CLR header to point to new location
    /// data_directories.update_clr_entry(0x2000, 72)?;
    /// ```
    pub fn update_clr_entry(&mut self, rva: u32, size: u32) {
        self.update_entry(DataDirectoryType::ClrRuntimeHeader, rva, size);
    }

    fn from_goblin(goblin_dd: &goblin::pe::data_directories::DataDirectories) -> Self {
        let mut directories = HashMap::new();

        // Convert goblin data directories to our owned format
        // Note: We avoid using goblin_dd.dirs() because it can panic on malformed files
        // with invalid data directory indices. Instead, we manually iterate through
        // the valid range and handle errors gracefully.
        for (i, opt_entry) in goblin_dd.data_directories.iter().enumerate() {
            if let Some((_, dir_entry)) = opt_entry {
                let dir_type = match i {
                    0 => DataDirectoryType::ExportTable,
                    1 => DataDirectoryType::ImportTable,
                    2 => DataDirectoryType::ResourceTable,
                    3 => DataDirectoryType::ExceptionTable,
                    4 => DataDirectoryType::CertificateTable,
                    5 => DataDirectoryType::BaseRelocationTable,
                    6 => DataDirectoryType::Debug,
                    7 => DataDirectoryType::Architecture,
                    8 => DataDirectoryType::GlobalPtr,
                    9 => DataDirectoryType::TlsTable,
                    10 => DataDirectoryType::LoadConfigTable,
                    11 => DataDirectoryType::BoundImport,
                    12 => DataDirectoryType::ImportAddressTable,
                    13 => DataDirectoryType::DelayImportDescriptor,
                    14 => DataDirectoryType::ClrRuntimeHeader,
                    15 => DataDirectoryType::Reserved,
                    _ => {
                        continue;
                    }
                };

                if dir_entry.virtual_address != 0 || dir_entry.size != 0 {
                    directories.insert(
                        dir_type,
                        DataDirectory {
                            virtual_address: dir_entry.virtual_address,
                            size: dir_entry.size,
                        },
                    );
                }
            }
        }

        Self { directories }
    }

    fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        // Write all 16 data directory entries in order
        for i in 0..16 {
            let dir_type = match i {
                0 => DataDirectoryType::ExportTable,
                1 => DataDirectoryType::ImportTable,
                2 => DataDirectoryType::ResourceTable,
                3 => DataDirectoryType::ExceptionTable,
                4 => DataDirectoryType::CertificateTable,
                5 => DataDirectoryType::BaseRelocationTable,
                6 => DataDirectoryType::Debug,
                7 => DataDirectoryType::Architecture,
                8 => DataDirectoryType::GlobalPtr,
                9 => DataDirectoryType::TlsTable,
                10 => DataDirectoryType::LoadConfigTable,
                11 => DataDirectoryType::BoundImport,
                12 => DataDirectoryType::ImportAddressTable,
                13 => DataDirectoryType::DelayImportDescriptor,
                14 => DataDirectoryType::ClrRuntimeHeader,
                15 => DataDirectoryType::Reserved,
                _ => unreachable!(),
            };

            if let Some(entry) = self.directories.get(&dir_type) {
                writer.write_all(&entry.virtual_address.to_le_bytes())?;
                writer.write_all(&entry.size.to_le_bytes())?;
            } else {
                // Empty entry
                writer.write_all(&0u32.to_le_bytes())?; // virtual_address
                writer.write_all(&0u32.to_le_bytes())?; // size
            }
        }

        Ok(())
    }
}

impl SectionTable {
    /// Size of a section table header in bytes.
    pub const HEADER_SIZE: usize = 40;

    fn from_goblin(goblin_section: &goblin::pe::section_table::SectionTable) -> Result<Self> {
        let name = std::str::from_utf8(&goblin_section.name)
            .map_err(|_| Error::Malformed {
                message: "Invalid section name".to_string(),
                file: file!(),
                line: line!(),
            })?
            .trim_end_matches('\0')
            .to_string();

        Ok(Self {
            name,
            virtual_size: goblin_section.virtual_size,
            virtual_address: goblin_section.virtual_address,
            size_of_raw_data: goblin_section.size_of_raw_data,
            pointer_to_raw_data: goblin_section.pointer_to_raw_data,
            pointer_to_relocations: goblin_section.pointer_to_relocations,
            pointer_to_line_numbers: goblin_section.pointer_to_linenumbers,
            number_of_relocations: goblin_section.number_of_relocations,
            number_of_line_numbers: goblin_section.number_of_linenumbers,
            characteristics: goblin_section.characteristics,
        })
    }

    /// Calculates the total size required for a section table with the given number of sections.
    ///
    /// # Arguments
    /// * `section_count` - Number of sections in the table
    ///
    /// # Returns
    /// Total size in bytes for the section table
    #[must_use]
    pub fn calculate_table_size(section_count: usize) -> u64 {
        (section_count * Self::HEADER_SIZE) as u64
    }

    /// Creates a SectionTable from layout information.
    ///
    /// This converts from the layout planning structures used during write operations
    /// back to the PE section table format.
    ///
    /// # Arguments
    /// * `name` - Section name
    /// * `virtual_address` - RVA where section is mapped
    /// * `virtual_size` - Virtual size of section in memory
    /// * `file_offset` - File offset where section data is stored
    /// * `file_size` - Size of section data in file
    /// * `characteristics` - Section characteristics flags
    ///
    /// # Returns
    /// A new SectionTable instance
    ///
    /// # Errors
    /// Returns an error if the file offset or size exceed u32 range
    pub fn from_layout_info(
        name: String,
        virtual_address: u32,
        virtual_size: u32,
        file_offset: u64,
        file_size: u64,
        characteristics: u32,
    ) -> Result<Self> {
        let size_of_raw_data = u32::try_from(file_size)
            .map_err(|_| malformed_error!("File size exceeds u32 range: {}", file_size))?;
        let pointer_to_raw_data = u32::try_from(file_offset)
            .map_err(|_| malformed_error!("File offset exceeds u32 range: {}", file_offset))?;

        Ok(Self {
            name,
            virtual_size,
            virtual_address,
            size_of_raw_data,
            pointer_to_raw_data,
            pointer_to_relocations: 0,  // 0 for .NET assemblies
            pointer_to_line_numbers: 0, // 0 for .NET assemblies
            number_of_relocations: 0,   // 0 for .NET assemblies
            number_of_line_numbers: 0,  // 0 for .NET assemblies
            characteristics,
        })
    }

    /// Updates the virtual address and size of this section.
    ///
    /// # Arguments
    /// * `virtual_address` - New RVA where section is mapped
    /// * `virtual_size` - New virtual size of section in memory
    pub fn update_virtual_location(&mut self, virtual_address: u32, virtual_size: u32) {
        self.virtual_address = virtual_address;
        self.virtual_size = virtual_size;
    }

    /// Updates the file location and size of this section.
    ///
    /// # Arguments
    /// * `file_offset` - New file offset where section data is stored
    /// * `file_size` - New size of section data in file
    ///
    /// # Errors
    /// Returns an error if the file offset or size exceed u32 range
    pub fn update_file_location(&mut self, file_offset: u64, file_size: u64) -> Result<()> {
        self.pointer_to_raw_data = u32::try_from(file_offset)
            .map_err(|_| malformed_error!("File offset exceeds u32 range: {}", file_offset))?;
        self.size_of_raw_data = u32::try_from(file_size)
            .map_err(|_| malformed_error!("File size exceeds u32 range: {}", file_size))?;
        Ok(())
    }

    /// Updates the section characteristics flags.
    ///
    /// # Arguments
    /// * `characteristics` - New section characteristics flags
    pub fn update_characteristics(&mut self, characteristics: u32) {
        self.characteristics = characteristics;
    }

    /// Sets the section name.
    ///
    /// # Arguments  
    /// * `name` - New section name (will be truncated to 8 bytes if longer)
    pub fn set_name(&mut self, name: String) {
        self.name = name;
    }

    /// Writes a section header as a standalone 40-byte header.
    ///
    /// This method encodes the section information into the PE section table format
    /// and writes it to the provided writer. This serializes the current state of
    /// the section without making any modifications.
    ///
    /// # Arguments
    /// * `writer` - Writer to output the header bytes to
    ///
    /// # Errors
    /// Returns an error if writing fails
    pub fn write_header_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        let mut header = vec![0u8; Self::HEADER_SIZE];
        let mut offset = 0;

        // Name (8 bytes, null-padded)
        let name_bytes = self.name.as_bytes();
        let copy_len = name_bytes.len().min(8);
        header[offset..offset + copy_len].copy_from_slice(&name_bytes[..copy_len]);
        offset += 8;

        // Virtual size (4 bytes, little-endian)
        header[offset..offset + 4].copy_from_slice(&self.virtual_size.to_le_bytes());
        offset += 4;

        // Virtual address (4 bytes, little-endian)
        header[offset..offset + 4].copy_from_slice(&self.virtual_address.to_le_bytes());
        offset += 4;

        // Size of raw data (4 bytes, little-endian)
        header[offset..offset + 4].copy_from_slice(&self.size_of_raw_data.to_le_bytes());
        offset += 4;

        // Pointer to raw data (4 bytes, little-endian)
        header[offset..offset + 4].copy_from_slice(&self.pointer_to_raw_data.to_le_bytes());
        offset += 4;

        // Pointer to relocations (4 bytes) - 0 for .NET assemblies
        header[offset..offset + 4].copy_from_slice(&self.pointer_to_relocations.to_le_bytes());
        offset += 4;

        // Pointer to line numbers (4 bytes) - 0 for .NET assemblies
        header[offset..offset + 4].copy_from_slice(&self.pointer_to_line_numbers.to_le_bytes());
        offset += 4;

        // Number of relocations (2 bytes) - 0 for .NET assemblies
        header[offset..offset + 2].copy_from_slice(&self.number_of_relocations.to_le_bytes());
        offset += 2;

        // Number of line numbers (2 bytes) - 0 for .NET assemblies
        header[offset..offset + 2].copy_from_slice(&self.number_of_line_numbers.to_le_bytes());
        offset += 2;

        // Characteristics (4 bytes, little-endian)
        header[offset..offset + 4].copy_from_slice(&self.characteristics.to_le_bytes());

        writer.write_all(&header)?;
        Ok(())
    }

    fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        // Write name (8 bytes, null-padded)
        let mut name_bytes = [0u8; 8];
        let name_str = self.name.as_bytes();
        let copy_len = std::cmp::min(name_str.len(), 8);
        name_bytes[..copy_len].copy_from_slice(&name_str[..copy_len]);
        writer.write_all(&name_bytes)?;

        writer.write_all(&self.virtual_size.to_le_bytes())?;
        writer.write_all(&self.virtual_address.to_le_bytes())?;
        writer.write_all(&self.size_of_raw_data.to_le_bytes())?;
        writer.write_all(&self.pointer_to_raw_data.to_le_bytes())?;
        writer.write_all(&self.pointer_to_relocations.to_le_bytes())?;
        writer.write_all(&self.pointer_to_line_numbers.to_le_bytes())?;
        writer.write_all(&self.number_of_relocations.to_le_bytes())?;
        writer.write_all(&self.number_of_line_numbers.to_le_bytes())?;
        writer.write_all(&self.characteristics.to_le_bytes())?;

        Ok(())
    }
}

impl Import {
    fn from_goblin(goblin_import: &goblin::pe::import::Import) -> Result<Self> {
        Ok(Self {
            dll: goblin_import.dll.to_string(),
            name: if goblin_import.name.is_empty() {
                None
            } else {
                Some(goblin_import.name.to_string())
            },
            ordinal: if goblin_import.ordinal != 0 {
                Some(goblin_import.ordinal)
            } else {
                None
            },
            rva: u32::try_from(goblin_import.rva)
                .map_err(|_| malformed_error!("PE import RVA value too large"))?,
            hint: 0, // Not available from goblin
            ilt_value: u64::try_from(goblin_import.offset)
                .map_err(|_| malformed_error!("PE import offset value too large"))?,
        })
    }

    /// Get the function identifier for this import (name or ordinal)
    #[must_use]
    pub fn function_identifier(&self) -> String {
        if let Some(ref name) = self.name {
            name.clone()
        } else if let Some(ordinal) = self.ordinal {
            format!("#{ordinal}")
        } else {
            "unknown".to_string()
        }
    }
}

impl Export {
    fn from_goblin(goblin_export: &goblin::pe::export::Export) -> Result<Self> {
        Ok(Self {
            name: goblin_export.name.map(ToString::to_string),
            rva: u32::try_from(goblin_export.rva)
                .map_err(|_| malformed_error!("PE export RVA value too large"))?,
            offset: goblin_export
                .offset
                .map(|o| {
                    u32::try_from(o)
                        .map_err(|_| malformed_error!("PE export offset value too large"))
                })
                .transpose()?,
        })
    }
}
