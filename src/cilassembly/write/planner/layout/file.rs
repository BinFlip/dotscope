//! File layout planning and management for binary generation.
//!
//! This module provides comprehensive file layout functionality including creation,
//! analysis, modification, and size calculation. It implements a type-driven approach
//! where FileLayout and related types encapsulate their behavior as methods.
//!
//! # Key Types
//!
//! - [`FileLayout`] - Complete file structure with sections and metadata
//! - [`SectionFileLayout`] - Individual section layout within the file
//! - [`StreamFileLayout`] - Metadata stream layout within sections
//!
//! # Architecture
//!
//! The file layout system provides rich methods for:
//! - **Creation**: Calculate complete file layouts from assemblies
//! - **Analysis**: Find sections, streams, and calculate sizes
//! - **Modification**: Update layouts for native tables and relocations
//! - **Query**: Search for specific components within layouts

use crate::{
    cilassembly::{
        write::{
            planner::{
                layout::{FileRegion, SectionFileLayout, StreamFileLayout},
                HeapExpansions, MetadataModifications, NativeTableRequirements,
            },
            utils::align_to_4_bytes,
        },
        CilAssembly,
    },
    Error, Result,
};

/// Complete file layout plan showing where everything goes in the new file.
///
/// This structure provides the detailed layout of the entire output file,
/// including PE headers, section table, and all sections with their
/// calculated positions and sizes. It offers rich methods for analysis
/// and modification of the file structure.
///
/// # Type-Driven API
/// Instead of passing FileLayout to external functions, it provides methods
/// that encapsulate file layout behavior and make the API more discoverable.
///
/// # Examples
/// ```rust,ignore
/// use crate::cilassembly::write::planner::layout::FileLayout;
/// use crate::cilassembly::CilAssembly;
///
/// # let assembly = CilAssembly::empty(); // placeholder
/// # let heap_expansions = HeapExpansions::calculate(&assembly)?;
/// # let mut metadata_modifications = MetadataModifications::identify(&assembly)?;
/// // Create a complete file layout
/// let file_layout = FileLayout::calculate(&assembly, &heap_expansions, &mut metadata_modifications)?;
///
/// // Use rich methods for analysis
/// let metadata_section = file_layout.find_metadata_section()?;
/// let total_size = file_layout.calculate_total_size(&assembly, &NativeTableRequirements::default());
///
/// // Work with sections in a type-driven way
/// for section in &file_layout.sections {
///     if section.contains_metadata {
///         let strings_stream = section.find_stream_layout("#Strings")?;
///         println!("Strings stream at offset: {}", strings_stream.file_region.offset);
///     }
/// }
/// # Ok::<(), crate::Error>(())
/// ```
#[derive(Debug, Clone)]
pub struct FileLayout {
    /// DOS header location in the output file.
    /// Typically at offset 0 with standard 64-byte size.
    pub dos_header: FileRegion,

    /// PE headers location including PE signature, COFF header, and optional header.
    /// Positioned after DOS header at the offset specified in DOS header.
    pub pe_headers: FileRegion,

    /// Section table location containing all section header entries.
    /// Positioned immediately after PE headers.
    pub section_table: FileRegion,

    /// All sections in their new calculated locations.
    /// Contains both relocated and non-relocated sections.
    pub sections: Vec<SectionFileLayout>,
}

impl FileLayout {
    /// Calculates the complete file layout with proper section placement.
    ///
    /// This function orchestrates the calculation of the complete file layout including
    /// PE headers, section table, and all sections with their calculated positions.
    ///
    /// # Arguments
    /// * `assembly` - The assembly to analyze
    /// * `heap_expansions` - Heap expansion requirements
    /// * `metadata_modifications` - Metadata stream modification requirements
    ///
    /// # Returns
    /// Returns a complete file layout with all components positioned.
    ///
    /// # Examples
    /// ```rust,ignore
    /// let layout = FileLayout::calculate(&assembly, &heap_expansions, &mut metadata_modifications)?;
    /// println!("File layout has {} sections", layout.sections.len());
    /// ```
    pub fn calculate(
        assembly: &CilAssembly,
        heap_expansions: &HeapExpansions,
        metadata_modifications: &mut MetadataModifications,
    ) -> Result<Self> {
        let view = assembly.view();

        // Start with PE headers layout (these don't move)
        let dos_header = FileRegion::new(0, 64); // Standard DOS header size

        // Find PE signature offset from DOS header
        let pe_sig_offset = assembly.file().pe_signature_offset()?;
        let pe_headers = FileRegion::new(pe_sig_offset, assembly.file().pe_headers_size()?);

        let section_table = FileRegion::new(
            pe_headers.end_offset(),
            (view.file().sections().count() * 40) as u64, // 40 bytes per section entry
        );

        // Calculate section layouts with potential relocations
        let sections =
            Self::calculate_section_layouts(assembly, heap_expansions, metadata_modifications)?;

        Ok(FileLayout {
            dos_header,
            pe_headers,
            section_table,
            sections,
        })
    }

    /// Finds the metadata section in this file layout.
    ///
    /// This is a commonly used operation that locates the section containing
    /// .NET metadata. Typically this is the .text section in most .NET assemblies.
    ///
    /// # Returns
    /// Returns a reference to the section containing metadata.
    ///
    /// # Errors
    /// Returns an error if no metadata section is found in the layout.
    ///
    /// # Examples
    /// ```rust,ignore
    /// let metadata_section = file_layout.find_metadata_section()?;
    /// println!("Metadata section: {}", metadata_section.name);
    /// ```
    pub fn find_metadata_section(&self) -> Result<&SectionFileLayout> {
        self.sections
            .iter()
            .find(|section| section.contains_metadata)
            .ok_or_else(|| Error::WriteLayoutFailed {
                message: "No metadata section found in file layout".to_string(),
            })
    }

    /// Calculates the total size needed for the output file.
    ///
    /// This method determines the complete file size by finding the maximum
    /// end offset of all file regions including native table requirements.
    ///
    /// # Arguments
    /// * `assembly` - The assembly for additional calculations
    /// * `native_requirements` - Native table space requirements
    ///
    /// # Returns
    /// Returns the total file size needed in bytes.
    ///
    /// # Examples
    /// ```rust,ignore
    /// let total_size = file_layout.calculate_total_size(&assembly, &native_requirements);
    /// println!("Output file will be {} bytes", total_size);
    /// ```
    pub fn calculate_total_size(
        &self,
        assembly: &CilAssembly,
        native_requirements: &NativeTableRequirements,
    ) -> u64 {
        // Find the maximum end offset of all regions
        let mut max_offset = 0u64;

        // Check DOS header
        max_offset = max_offset.max(self.dos_header.end_offset());

        // Check PE headers
        max_offset = max_offset.max(self.pe_headers.end_offset());

        // Check section table
        max_offset = max_offset.max(self.section_table.end_offset());

        // Check all sections
        for section in &self.sections {
            max_offset = max_offset.max(section.file_region.end_offset());
        }

        // Add space for native table requirements
        max_offset += native_requirements.import_table_size;
        max_offset += native_requirements.export_table_size;

        // Align to file alignment boundary
        assembly
            .file()
            .align_to_file_alignment(max_offset)
            .unwrap_or(max_offset)
    }

    /// Updates this layout to accommodate native table requirements.
    ///
    /// This method modifies the layout to allocate space for native PE tables
    /// like import and export tables, updating section sizes as needed.
    ///
    /// # Arguments
    /// * `native_requirements` - The native table space requirements
    ///
    /// # Returns
    /// Returns `Ok(())` if the layout was successfully updated.
    ///
    /// # Examples
    /// ```rust,ignore
    /// file_layout.update_for_native_tables(&native_requirements)?;
    /// ```
    pub fn update_for_native_tables(
        &mut self,
        native_requirements: &NativeTableRequirements,
    ) -> Result<()> {
        if !native_requirements.needs_import_tables && !native_requirements.needs_export_tables {
            return Ok(()); // No updates needed
        }

        // Find the last section to extend it for native table space
        if let Some(last_section) = self.sections.last_mut() {
            let additional_size =
                native_requirements.import_table_size + native_requirements.export_table_size;

            // Extend the virtual size to accommodate native tables
            last_section.virtual_size = (last_section.virtual_size as u64 + additional_size) as u32;

            // Update the file region size as well
            last_section.file_region.size += additional_size;
        }

        Ok(())
    }

    /// Calculates section layouts with proper positioning and size adjustments.
    ///
    /// This function analyzes each section in the assembly and calculates new layouts
    /// that accommodate metadata expansions and heap additions. It handles both
    /// metadata-containing sections (which may need expansion) and regular sections.
    fn calculate_section_layouts(
        assembly: &CilAssembly,
        _heap_expansions: &HeapExpansions,
        metadata_modifications: &mut MetadataModifications,
    ) -> Result<Vec<SectionFileLayout>> {
        let view = assembly.view();
        let original_sections: Vec<_> = view.file().sections().collect();
        let mut new_sections = Vec::new();

        // Always use full relocation path for reliability
        let section_table_end =
            assembly.file().pe_headers_size()? + (original_sections.len() * 40) as u64;
        let mut current_offset = assembly.file().align_to_file_alignment(section_table_end)?;

        for original_section in original_sections.iter() {
            // Convert section name from byte array to string
            let section_name = std::str::from_utf8(&original_section.name)
                .unwrap_or("<invalid>")
                .trim_end_matches('\0');
            let contains_metadata = view.file().section_contains_metadata(section_name);
            let section_name = section_name.to_string();

            let (new_size, metadata_streams) = if contains_metadata {
                // This section contains .NET metadata - calculate new size with expansions
                let metadata_streams = Self::calculate_metadata_stream_layouts(
                    assembly,
                    current_offset,
                    metadata_modifications,
                )?;

                let metadata_size: u64 = metadata_streams
                    .iter()
                    .map(|stream| stream.file_region.end_offset())
                    .max()
                    .unwrap_or(current_offset)
                    - current_offset;

                (metadata_size, metadata_streams)
            } else {
                // Non-metadata section - keep original size
                (original_section.size_of_raw_data as u64, Vec::new())
            };

            let file_region = FileRegion::new(current_offset, new_size);

            // Calculate new virtual size (should be at least as large as file size)
            let new_virtual_size = if new_size > original_section.virtual_size as u64 {
                new_size as u32
            } else {
                original_section.virtual_size
            };

            new_sections.push(SectionFileLayout {
                name: section_name,
                file_region,
                virtual_address: original_section.virtual_address,
                virtual_size: new_virtual_size,
                characteristics: original_section.characteristics,
                contains_metadata,
                metadata_streams,
            });

            // Move to next section (aligned)
            current_offset = assembly
                .file()
                .align_to_file_alignment(current_offset + new_size)?;
        }

        // Validate that sections don't overlap
        for (i, section1) in new_sections.iter().enumerate() {
            for section2 in new_sections.iter().skip(i + 1) {
                if section1.file_region.overlaps(&section2.file_region) {
                    return Err(Error::WriteLayoutFailed {
                        message: format!(
                            "Sections '{}' and '{}' overlap in file layout",
                            section1.name, section2.name
                        ),
                    });
                }
            }
        }

        Ok(new_sections)
    }

    /// Calculates metadata stream layouts within a section.
    ///
    /// This function determines the layout of metadata streams within a metadata-containing
    /// section, accounting for heap expansions and stream modifications.
    fn calculate_metadata_stream_layouts(
        assembly: &CilAssembly,
        section_start_offset: u64,
        metadata_modifications: &mut MetadataModifications,
    ) -> Result<Vec<StreamFileLayout>> {
        let view = assembly.view();
        let original_streams = view.streams();
        let mut stream_layouts = Vec::new();

        // Calculate the metadata root offset within the section
        let metadata_root_rva = view.cor20header().meta_data_rva as u64;
        let section_rva = assembly.file().text_section_rva()? as u64;
        let metadata_offset_in_section = metadata_root_rva - section_rva;
        let metadata_root_offset = section_start_offset + metadata_offset_in_section;

        // Start streams after metadata root header
        let metadata_root_size =
            crate::cilassembly::write::planner::metadata::calculate_metadata_root_header_size(
                assembly,
            )?;
        let mut current_stream_offset = metadata_root_offset + metadata_root_size;

        for original_stream in original_streams {
            let stream_name = &original_stream.name;
            let mut new_size = original_stream.size;
            let mut has_additions = false;

            // Check if this stream has additions
            for stream_mod in &metadata_modifications.stream_modifications {
                if stream_mod.name == *stream_name {
                    new_size = stream_mod.new_size as u32;
                    has_additions = stream_mod.additional_data_size > 0;
                    break;
                }
            }

            // Align stream size to 4-byte boundary
            let aligned_size = align_to_4_bytes(new_size as u64);

            stream_layouts.push(StreamFileLayout {
                name: stream_name.clone(),
                file_region: FileRegion::new(current_stream_offset, aligned_size),
                size: new_size,
                has_additions,
            });

            current_stream_offset += aligned_size;
        }

        // Validate that streams are properly adjacent
        for window in stream_layouts.windows(2) {
            if !window[0].file_region.is_adjacent_to(&window[1].file_region) {
                return Err(Error::WriteLayoutFailed {
                    message: format!(
                        "Streams '{}' and '{}' are not properly adjacent in metadata layout",
                        window[0].name, window[1].name
                    ),
                });
            }
        }

        Ok(stream_layouts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CilAssemblyView;
    use std::path::Path;

    #[test]
    fn test_file_layout_calculate() {
        let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))
            .expect("Failed to load test assembly");
        let assembly = view.to_owned();

        let heap_expansions =
            HeapExpansions::calculate(&assembly).expect("Should calculate heap expansions");
        let mut metadata_modifications =
            crate::cilassembly::write::planner::metadata::identify_metadata_modifications(
                &assembly,
            )
            .expect("Should identify modifications");

        let file_layout =
            FileLayout::calculate(&assembly, &heap_expansions, &mut metadata_modifications)
                .expect("Should calculate file layout");

        assert!(
            file_layout.dos_header.size > 0,
            "DOS header should have size"
        );
        assert!(
            file_layout.pe_headers.size > 0,
            "PE headers should have size"
        );
        assert!(
            file_layout.section_table.size > 0,
            "Section table should have size"
        );
        assert!(!file_layout.sections.is_empty(), "Should have sections");
    }

    #[test]
    fn test_find_metadata_section() {
        let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))
            .expect("Failed to load test assembly");
        let assembly = view.to_owned();

        let heap_expansions =
            HeapExpansions::calculate(&assembly).expect("Should calculate heap expansions");
        let mut metadata_modifications =
            crate::cilassembly::write::planner::metadata::identify_metadata_modifications(
                &assembly,
            )
            .expect("Should identify modifications");

        let file_layout =
            FileLayout::calculate(&assembly, &heap_expansions, &mut metadata_modifications)
                .expect("Should calculate file layout");

        let metadata_section = file_layout
            .find_metadata_section()
            .expect("Should find metadata section");

        assert!(
            metadata_section.contains_metadata,
            "Found section should contain metadata"
        );
        assert!(
            !metadata_section.metadata_streams.is_empty(),
            "Metadata section should have streams"
        );
    }

    #[test]
    fn test_section_find_stream_layout() {
        let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))
            .expect("Failed to load test assembly");
        let assembly = view.to_owned();

        let heap_expansions =
            HeapExpansions::calculate(&assembly).expect("Should calculate heap expansions");
        let mut metadata_modifications =
            crate::cilassembly::write::planner::metadata::identify_metadata_modifications(
                &assembly,
            )
            .expect("Should identify modifications");

        let file_layout =
            FileLayout::calculate(&assembly, &heap_expansions, &mut metadata_modifications)
                .expect("Should calculate file layout");

        let metadata_section = file_layout
            .find_metadata_section()
            .expect("Should find metadata section");

        // Try to find a common stream (most assemblies have #Strings)
        if metadata_section.has_stream("#Strings") {
            let strings_stream = metadata_section
                .find_stream_layout("#Strings")
                .expect("Should find strings stream");
            assert_eq!(strings_stream.name, "#Strings");
            assert!(strings_stream.size > 0, "Strings stream should have size");
        }
    }

    #[test]
    fn test_calculate_total_size() {
        let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))
            .expect("Failed to load test assembly");
        let assembly = view.to_owned();

        let heap_expansions =
            HeapExpansions::calculate(&assembly).expect("Should calculate heap expansions");
        let mut metadata_modifications =
            crate::cilassembly::write::planner::metadata::identify_metadata_modifications(
                &assembly,
            )
            .expect("Should identify modifications");

        let file_layout =
            FileLayout::calculate(&assembly, &heap_expansions, &mut metadata_modifications)
                .expect("Should calculate file layout");

        let native_requirements = NativeTableRequirements::default();
        let total_size = file_layout.calculate_total_size(&assembly, &native_requirements);

        assert!(total_size > 0, "Total size should be positive");
        // Note: Total size might be smaller than original if sections are better packed
        // Just ensure it's a reasonable size (at least half the original)
        assert!(
            total_size >= assembly.file().file_size() / 2,
            "Total size should be reasonable compared to original"
        );
    }

    #[test]
    fn test_stream_analysis_methods() {
        let stream = StreamFileLayout {
            name: "#Test".to_string(),
            file_region: FileRegion::new(0x1000, 0x500),
            size: 0x400,
            has_additions: true,
        };

        assert!(stream.has_additional_data());
        assert_eq!(stream.additional_data_size(), 0x100); // 0x500 - 0x400
        assert!(stream.is_aligned()); // Both offset and size are 4-byte aligned

        let aligned_stream = StreamFileLayout {
            name: "#Aligned".to_string(),
            file_region: FileRegion::new(0x1001, 0x509), // Not aligned - both offset and size have remainder
            size: 0x400,
            has_additions: false,
        };

        assert!(!aligned_stream.is_aligned());
        assert_eq!(aligned_stream.additional_data_size(), 0);
    }
}
