//! PE (Portable Executable) layout extraction and manipulation.
//!
//! This module provides comprehensive PE structure analysis and manipulation capabilities
//! for .NET assembly binary generation. It handles extracting PE layout information from
//! existing assemblies and calculating updates needed when sections are modified during
//! the layout planning process.
//!
//! # Key Components
//!
//! - [`crate::cilassembly::write::planner::pe::extract_pe_layout`] - Main PE structure extraction
//! - [`crate::cilassembly::write::planner::pe::PeLayout`] - Complete PE structure information
//! - [`crate::cilassembly::write::planner::pe::SectionLayout`] - Individual section layout details
//!
//! # Architecture
//!
//! The PE analysis system builds on the parsed goblin PE structures:
//!
//! ## PE Structure Analysis
//! Uses the already-parsed goblin PE structure to extract:
//! - DOS header, PE signature, and COFF header locations
//! - Optional header size and structure details
//! - Section table layout and individual section information
//! - File alignment and virtual address mappings
//!
//! ## Section Layout Extraction
//! Analyzes each PE section to determine:
//! - Virtual and file addresses with sizes
//! - Section characteristics and permissions
//! - Metadata-containing sections (typically .text)
//! - Alignment requirements and boundaries
//!
//! ## Layout Calculation
//! Provides utilities for:
//! - Calculating PE header sizes for different formats (PE32/PE32+)
//! - Determining file alignment boundaries (typically 512 bytes)
//! - Locating specific sections like .text for metadata
//! - Converting between RVAs and file offsets
//!
//! # Usage Examples
//!
//! ```rust,ignore
//! use crate::cilassembly::write::planner::pe::extract_pe_layout;
//! use crate::cilassembly::CilAssembly;
//!
//! # let assembly = CilAssembly::empty(); // placeholder
//! // Extract complete PE layout information
//! let pe_layout = extract_pe_layout(&assembly)?;
//!
//! println!("PE signature at offset: {}", pe_layout.pe_signature_offset);
//! println!("Number of sections: {}", pe_layout.section_count);
//!
//! // Check which sections contain metadata
//! for section in assembly.view().file().sections() {
//!     let name = std::str::from_utf8(&section.name).unwrap_or("<invalid>").trim_end_matches('\0');
//!     if assembly.view().file().section_contains_metadata(name) {
//!         println!("Metadata section: {} at RVA 0x{:08X}",
//!                  name, section.virtual_address);
//!     }
//! }
//! # Ok::<(), crate::Error>(())
//! ```
//!
//! # Thread Safety
//!
//! All functions in this module perform read-only analysis of PE structures and are
//! inherently thread-safe. However, they are designed for single-threaded use during
//! the layout planning phase.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::cilassembly::write::planner`] - Layout planning coordination
//! - [`crate::file`] - Underlying PE file parsing via goblin
//! - [`crate::cilassembly::write::output`] - Binary generation requirements
//! - [`crate::cilassembly::write::utils`] - Shared utility functions

use crate::{cilassembly::CilAssembly, file::File, Error, Result};

/// PE (Portable Executable) layout information for the binary file.
///
/// Contains the complete layout structure of a PE file including header locations,
/// section information, and structural details needed for binary generation and
/// modification planning.
///
/// # Usage
/// Created by [`crate::cilassembly::write::planner::pe::extract_pe_layout`] and used
/// throughout the layout planning process.
#[derive(Debug, Clone)]
pub struct PeLayout {
    /// Offset of DOS header (always 0 for valid PE files).
    pub dos_header_offset: u64,

    /// Offset of PE signature ("PE\0\0") as specified in DOS header.
    pub pe_signature_offset: u64,

    /// Offset of COFF header (immediately after PE signature).
    pub coff_header_offset: u64,

    /// Offset of optional header (after COFF header).
    pub optional_header_offset: u64,

    /// Offset of section table (after optional header).
    pub section_table_offset: u64,

    /// Number of sections in the PE file.
    pub section_count: u16,

    /// Layout information for all sections in the file.
    pub sections: Vec<SectionLayout>,
}

/// Layout information for a single PE section.
///
/// Contains all the layout details for an individual section within a PE file,
/// including both virtual (in-memory) and file (on-disk) address information.
#[derive(Debug, Clone)]
pub struct SectionLayout {
    /// Section name (e.g., ".text", ".rsrc", ".reloc").
    pub name: String,

    /// Virtual address (RVA) where section is loaded in memory.
    pub virtual_address: u32,

    /// Virtual size of section in memory (may differ from file size).
    pub virtual_size: u32,

    /// File offset where section data begins on disk.
    pub file_offset: u64,

    /// File size of section data on disk (aligned to file alignment).
    pub file_size: u32,

    /// Section characteristics flags from PE specification.
    /// Defines permissions and section behavior.
    pub characteristics: u32,
}

/// Extract PE layout information from the original assembly using goblin PE structure.
///
/// This function analyzes the parsed goblin PE structure to extract comprehensive
/// layout information needed for binary generation and modification planning.
///
/// # Arguments
/// * `assembly` - The [`crate::cilassembly::CilAssembly`] containing the PE file to analyze
///
/// # Returns
/// Returns [`crate::cilassembly::write::planner::pe::PeLayout`] with complete PE structure information.
///
/// # Errors
/// Returns [`crate::Error::WriteLayoutFailed`] if PE structure analysis fails or
/// required headers are missing.
pub fn extract_pe_layout(assembly: &CilAssembly) -> Result<PeLayout> {
    let file = assembly.file();

    // Use the already parsed goblin PE structure instead of manual parsing
    let dos_header = file.header_dos();
    let pe_signature_offset = u64::from(dos_header.pe_pointer);
    let coff_header_offset = pe_signature_offset + 4; // PE signature is 4 bytes

    // Get optional header size from the parsed structure
    let optional_header =
        file.header_optional()
            .as_ref()
            .ok_or_else(|| Error::WriteLayoutFailed {
                message: "Missing optional header in PE file".to_string(),
            })?;
    let optional_header_offset = coff_header_offset + 20; // COFF header is 20 bytes

    // Determine optional header size based on magic number
    let optional_header_size = if optional_header.standard_fields.magic == 0x10b {
        224u16 // PE32
    } else {
        240u16 // PE32+
    };

    // Calculate section table offset
    let section_table_offset = optional_header_offset + u64::from(optional_header_size);

    // Extract section layouts from goblin's parsed sections
    let sections = extract_section_layouts_from_goblin(file)?;
    let section_count = sections.len() as u16;

    Ok(PeLayout {
        dos_header_offset: 0,
        pe_signature_offset,
        coff_header_offset,
        optional_header_offset,
        section_table_offset,
        section_count,
        sections,
    })
}

/// Extract section layouts using goblin's parsed section information.
///
/// Converts goblin's internal section representation into our layout structures
/// with proper string conversion and field mapping.
///
/// # Arguments
/// * `file` - The parsed [`crate::file::File`] containing section information
///
/// # Returns
/// Returns a vector of [`crate::cilassembly::write::planner::pe::SectionLayout`] structures.
pub fn extract_section_layouts_from_goblin(file: &File) -> Result<Vec<SectionLayout>> {
    let mut sections = Vec::new();

    for section in file.sections() {
        // Convert section name from byte array to string
        let name = std::str::from_utf8(&section.name)
            .unwrap_or("<invalid>")
            .trim_end_matches('\0')
            .to_string();

        sections.push(SectionLayout {
            name,
            virtual_address: section.virtual_address,
            virtual_size: section.virtual_size,
            file_offset: u64::from(section.pointer_to_raw_data),
            file_size: section.size_of_raw_data,
            characteristics: section.characteristics,
        });
    }

    Ok(sections)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CilAssemblyView;
    use std::path::Path;

    #[test]
    fn test_extract_pe_layout() {
        let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))
            .expect("Failed to load test assembly");
        let assembly = view.to_owned();

        let pe_layout = extract_pe_layout(&assembly).expect("PE layout extraction should succeed");

        // Verify basic PE structure
        assert_eq!(
            pe_layout.dos_header_offset, 0,
            "DOS header should be at offset 0"
        );
        assert!(
            pe_layout.pe_signature_offset > 0,
            "PE signature should be after DOS header"
        );
        assert!(
            pe_layout.section_count > 0,
            "Should have at least one section"
        );
        assert!(
            !pe_layout.sections.is_empty(),
            "Sections vector should not be empty"
        );

        // Verify section names make sense for a .NET assembly
        let section_names: Vec<&str> = pe_layout.sections.iter().map(|s| s.name.as_str()).collect();
        assert!(
            section_names.contains(&".text") || section_names.contains(&".rdata"),
            "Should have typical PE sections, got: {section_names:?}"
        );
    }
}
