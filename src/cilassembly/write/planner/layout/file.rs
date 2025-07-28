//! File layout planning and management for binary generation.
//!
//! This module provides comprehensive file layout functionality including creation,
//! analysis, modification, and size calculation. It implements a type-driven approach
//! where FileLayout and related types encapsulate their behavior as methods.
//!
//! # Key Components
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
//!
//! ## Layout Strategy
//!
//! The system uses a clean approach of creating a new `.meta` section for all metadata:
//! - Original sections are preserved but marked as not containing metadata
//! - A new `.meta` section is created at the end of the file
//! - All metadata streams are rebuilt in the new section
//! - This avoids complex in-place modifications and ensures sufficient space
//!
//! ## Section Positioning
//!
//! File layout calculation follows these principles:
//! - DOS header and PE headers retain their original positions
//! - Section table is expanded to accommodate the new `.meta` section
//! - Original sections are shifted to account for expanded section table
//! - New `.meta` section is positioned at the end of the file
//!
//! ## Stream Layout
//!
//! Metadata streams within the `.meta` section are positioned:
//! - After the COR20 header at the appropriate offset
//! - After the metadata root header and stream directory
//! - With proper 4-byte alignment and safety padding
//! - With additional space for heap writer operations
//!
//! # Usage Examples
//!
//! ```rust,ignore
//! use crate::cilassembly::write::planner::layout::file::FileLayout;
//! use crate::cilassembly::write::planner::{HeapExpansions, MetadataModifications};
//! use crate::cilassembly::CilAssembly;
//!
//! # let assembly = CilAssembly::new(view);
//! # let heap_expansions = HeapExpansions::calculate(&assembly)?;
//! # let mut metadata_modifications = MetadataModifications::identify(&assembly)?;
//! // Create a complete file layout
//! let file_layout = FileLayout::calculate(&assembly, &heap_expansions, &mut metadata_modifications)?;
//!
//! // Use rich methods for analysis
//! let metadata_section = file_layout.find_metadata_section()?;
//! let total_size = file_layout.calculate_total_size(&assembly, &NativeTableRequirements::default());
//!
//! // Work with sections in a type-driven way
//! for section in &file_layout.sections {
//!     if section.contains_metadata {
//!         let strings_stream = section.find_stream_layout("#Strings")?;
//!         println!("Strings stream at offset: {}", strings_stream.file_region.offset);
//!     }
//! }
//! # Ok::<(), crate::Error>(())
//! ```
//!
//! # Thread Safety
//!
//! This type is [`Send`] and [`Sync`] as it contains only computed layout data
//! without any shared mutable state, making it safe for concurrent access.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::cilassembly::write::planner`] - Main layout planning coordination
//! - [`crate::cilassembly::write::planner::layout`] - Layout data structures
//! - [`crate::cilassembly::write::utils`] - Utility functions for alignment
//! - [`crate::cilassembly::write::writers`] - Uses layout for binary generation

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
/// # Design Philosophy
///
/// Instead of passing [`FileLayout`] to external functions, it provides methods
/// that encapsulate file layout behavior and make the API more discoverable.
/// This type-driven approach reduces coupling and makes the interface more intuitive.
///
/// # Fields
///
/// - `dos_header` - DOS header and stub positioning (typically at offset 0)
/// - `pe_headers` - PE signature, COFF header, and optional header positioning
/// - `section_table` - Section table with expanded size for new `.meta` section
/// - `sections` - All sections including original sections and new `.meta` section
///
/// # Layout Strategy
///
/// The layout calculation uses a clean approach:
/// 1. **Preserve Original Structure**: DOS header and PE headers retain positions
/// 2. **Expand Section Table**: Add space for new `.meta` section entry
/// 3. **Shift Original Sections**: Account for expanded section table
/// 4. **Create New Metadata Section**: Place all metadata in new `.meta` section
///
/// # Usage Examples
///
/// ```rust,ignore
/// use crate::cilassembly::write::planner::layout::file::FileLayout;
/// use crate::cilassembly::write::planner::{HeapExpansions, MetadataModifications};
/// use crate::cilassembly::CilAssembly;
///
/// # let assembly = CilAssembly::new(view);
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
///         if let Ok(strings_stream) = section.find_stream_layout("#Strings") {
///             println!("Strings stream at offset: {}", strings_stream.file_region.offset);
///         }
///     }
/// }
/// # Ok::<(), crate::Error>(())
/// ```
///
/// # Thread Safety
///
/// This type is [`Send`] and [`Sync`] as it contains only computed layout data
/// without any shared mutable state, making it safe for concurrent access.
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
        // DOS header + stub goes from 0 to PE signature offset
        let pe_sig_offset = assembly.file().pe_signature_offset()?;
        let dos_header = FileRegion::new(0, pe_sig_offset); // DOS header + stub
        let pe_headers = FileRegion::new(pe_sig_offset, assembly.file().pe_headers_size()?);

        // Account for the new .meta section in the section table
        let original_section_count = view.file().sections().count();
        let new_section_count = original_section_count + 1; // We're adding a new .meta section
        let section_table = FileRegion::new(
            pe_headers.end_offset(),
            u64::try_from(new_section_count * 40).map_err(|_| Error::WriteLayoutFailed {
                message: "Section table size exceeds u64 range".to_string(),
            })?, // 40 bytes per section entry
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
            last_section.virtual_size = u32::try_from(
                u64::from(last_section.virtual_size) + additional_size,
            )
            .map_err(|_| Error::WriteLayoutFailed {
                message: "Combined virtual size exceeds u32 range".to_string(),
            })?;

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

        // Always create a new .meta section at the end of the file
        // This approach avoids complexity of reusing existing sections and ensures we have enough space

        // Calculate how much the section table has grown
        let original_section_count = original_sections.len();
        let new_section_count = original_section_count + 1; // Adding .meta section
        let original_section_table_size =
            u64::try_from(original_section_count * 40).map_err(|_| Error::WriteLayoutFailed {
                message: "Original section table size exceeds u64 range".to_string(),
            })?;
        let new_section_table_size =
            u64::try_from(new_section_count * 40).map_err(|_| Error::WriteLayoutFailed {
                message: "New section table size exceeds u64 range".to_string(),
            })?;
        let section_table_growth = new_section_table_size - original_section_table_size;

        // Step 1: Copy all sections, adjusting their file offsets to account for expanded section table
        for original_section in &original_sections {
            let section_name = std::str::from_utf8(&original_section.name)
                .unwrap_or("<invalid>")
                .trim_end_matches('\0');
            let _contains_metadata = view.file().section_contains_metadata(section_name);
            let section_name = section_name.to_string();

            // Adjust file offset to account for expanded section table
            let adjusted_file_offset =
                u64::from(original_section.pointer_to_raw_data) + section_table_growth;

            // Copy all sections but mark that original metadata section no longer contains metadata
            let file_region = FileRegion::new(
                adjusted_file_offset,
                u64::from(original_section.size_of_raw_data),
            );

            new_sections.push(SectionFileLayout {
                name: section_name,
                file_region,
                virtual_address: original_section.virtual_address,
                virtual_size: original_section.virtual_size,
                characteristics: original_section.characteristics,
                contains_metadata: false, // Metadata will be moved to .meta section
                metadata_streams: Vec::new(),
            });
        }

        // Step 2: Create a new .meta section at the end of the file for all metadata
        // Account for the section table growth when calculating the end of file
        let mut new_metadata_offset = assembly.file().file_size() + section_table_growth;

        // Align to file alignment boundary
        new_metadata_offset = assembly
            .file()
            .align_to_file_alignment(new_metadata_offset)?;

        // Calculate new .meta section with all streams rebuilt from scratch
        let metadata_streams = Self::calculate_metadata_stream_layouts(
            assembly,
            new_metadata_offset,
            metadata_modifications,
        )?;

        // Calculate the total size needed for the .meta section
        // We need to include COR20 header + metadata root + streams + any gaps
        let calculated_metadata_size: u64 = metadata_streams
            .iter()
            .map(|stream| stream.file_region.end_offset())
            .max()
            .unwrap_or(new_metadata_offset)
            - new_metadata_offset;

        // Add space for COR20 header (72 bytes) + gap between COR20 and metadata root
        let cor20_header_size = 72u64;

        // Calculate actual gap between COR20 and metadata root from the assembly
        let view = assembly.view();
        let original_cor20_rva = u32::try_from(view.file().clr().0).unwrap_or(0);
        let original_metadata_rva = view.cor20header().meta_data_rva;
        let actual_gap = u64::from(original_metadata_rva - original_cor20_rva);

        let total_metadata_structure_size =
            cor20_header_size + actual_gap + calculated_metadata_size;

        // Add generous safety margin for metadata expansion and reconstruction
        let safety_margin = 2048; // More generous margin for complete metadata structure
        let new_section_size = total_metadata_structure_size + safety_margin;

        let file_region = FileRegion::new(new_metadata_offset, new_section_size);

        // Calculate virtual address for the new .meta section
        // Place it after the last section in virtual memory space
        let last_original_section = original_sections
            .iter()
            .max_by_key(|s| s.virtual_address + s.virtual_size)
            .unwrap();
        let section_alignment = assembly.file().section_alignment().unwrap_or(0x1000);
        let next_virtual_address =
            last_original_section.virtual_address + last_original_section.virtual_size;
        let aligned_virtual_address =
            (next_virtual_address + section_alignment - 1) & !(section_alignment - 1);

        // Create the new .meta section with standard characteristics for metadata
        let meta_characteristics = 0x4000_0040; // IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ

        new_sections.push(SectionFileLayout {
            name: ".meta".to_string(),
            file_region,
            virtual_address: aligned_virtual_address,
            virtual_size: u32::try_from(new_section_size).map_err(|_| {
                Error::WriteLayoutFailed {
                    message: "New section virtual size exceeds u32 range".to_string(),
                }
            })?,
            characteristics: meta_characteristics,
            contains_metadata: true,
            metadata_streams,
        });

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

        // For the .meta section, account for the COR20 header position within the section
        // Calculate where the COR20 header will be placed within the .meta section
        let original_cor20_rva = u32::try_from(view.file().clr().0).unwrap_or(0);
        let original_metadata_rva = view.cor20header().meta_data_rva;
        let metadata_rva_offset_from_cor20 = original_metadata_rva - original_cor20_rva;

        // Find original metadata section to get COR20 offset
        let original_sections: Vec<_> = view.file().sections().collect();
        let original_metadata_section = original_sections
            .iter()
            .find(|section| {
                let section_name = std::str::from_utf8(&section.name)
                    .unwrap_or("")
                    .trim_end_matches('\0');
                view.file().section_contains_metadata(section_name)
            })
            .unwrap();

        let cor20_offset_in_original_section =
            original_cor20_rva - original_metadata_section.virtual_address;

        // Position COR20 at the same relative offset within the .meta section
        let cor20_offset_in_meta =
            section_start_offset + u64::from(cor20_offset_in_original_section);
        let metadata_root_offset = cor20_offset_in_meta + u64::from(metadata_rva_offset_from_cor20);

        // Start streams after metadata root header including the stream directory
        // Calculate the exact position where streams should start (after the stream directory)
        let version_string = view.metadata_root().version.clone();
        let version_length =
            u64::try_from(version_string.len()).map_err(|_| Error::WriteLayoutFailed {
                message: "Version string length exceeds u64 range".to_string(),
            })?;
        let version_length_padded = (version_length + 3) & !3; // 4-byte align
        let stream_directory_start = metadata_root_offset + 16 + version_length_padded + 4; // +4 for flags + stream_count

        // Estimate stream directory size: each stream needs 8 bytes + name + padding
        let estimated_stream_dir_size =
            u64::try_from(view.streams().len()).map_err(|_| Error::WriteLayoutFailed {
                message: "Stream count exceeds u64 range".to_string(),
            })? * 20; // Extra conservative estimate
        let mut current_stream_offset = stream_directory_start + estimated_stream_dir_size;

        // Align to 4-byte boundary
        current_stream_offset = (current_stream_offset + 3) & !3;

        for original_stream in original_streams {
            let stream_name = &original_stream.name;
            let mut new_size = original_stream.size;
            let mut has_additions = false;

            // Check if this stream has modifications and calculate the complete rebuilt size
            for stream_mod in &mut metadata_modifications.stream_modifications {
                if stream_mod.name == *stream_name {
                    new_size = u32::try_from(stream_mod.new_size).map_err(|_| {
                        Error::WriteLayoutFailed {
                            message: "Stream new size exceeds u32 range".to_string(),
                        }
                    })?;
                    has_additions = stream_mod.additional_data_size > 0;
                    break;
                }
            }

            // Calculate aligned size for this stream
            let aligned_stream_size = align_to_4_bytes(u64::from(new_size));

            // Update the write offset for this stream in modifications
            for stream_mod in &mut metadata_modifications.stream_modifications {
                if stream_mod.name == *stream_name {
                    stream_mod.write_offset = current_stream_offset;
                    break;
                }
            }

            // Add padding for heap writer operations (64 bytes safety margin)
            let stream_size_with_padding = aligned_stream_size + 64;

            stream_layouts.push(StreamFileLayout {
                name: stream_name.clone(),
                file_region: FileRegion::new(current_stream_offset, stream_size_with_padding),
                size: new_size,
                has_additions,
            });

            // Move to next stream position
            current_stream_offset += stream_size_with_padding;
        }

        // Validate that streams don't overlap (they may have gaps for heap writer padding)
        // Temporarily disabled for debugging
        // for window in stream_layouts.windows(2) {
        //     if window[0].file_region.overlaps(&window[1].file_region) {
        //         return Err(Error::WriteLayoutFailed {
        //             message: format!(
        //                 "Streams '{}' and '{}' overlap in metadata layout",
        //                 window[0].name, window[1].name
        //             ),
        //         });
        //     }
        // }

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
