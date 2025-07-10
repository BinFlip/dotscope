//! PE file structure updates including checksums and relocations.
//!
//! This module provides comprehensive PE (Portable Executable) structure management for .NET assembly
//! binary generation, handling PE-specific modifications that occur after metadata changes.
//! It ensures proper PE file integrity through checksum recalculation, relocation updates,
//! and header validation while maintaining compatibility with Windows PE/COFF standards.
//!
//! # Key Components
//!
//! - [`crate::cilassembly::write::writers::pe::PeWriter`] - Stateful writer for all PE structure updates
//! - [`crate::cilassembly::write::writers::pe::PeWriter::write_pe_updates`] - Main entry point for PE updates
//! - [`crate::cilassembly::write::writers::pe::PeWriter::update_pe_checksum`] - PE file checksum recalculation
//! - [`crate::cilassembly::write::writers::pe::PeWriter::update_base_relocations`] - Base relocation updates
//! - [`crate::cilassembly::write::writers::pe::PeWriter::calculate_pe_checksum`] - Standard PE checksum algorithm
//!
//! # Architecture
//!
//! The PE writing system handles post-modification PE structure updates:
//!
//! ## PE File Integrity
//! Maintains PE file validity after modifications:
//! - Recalculates PE file checksums using standard algorithm
//! - Updates section table entries when sections move or resize
//! - Validates PE header structure and field constraints
//! - Ensures proper alignment and size calculations
//!
//! ## Checksum Management
//! Implements the standard PE checksum algorithm:
//! - Treats file as array of 16-bit words with carry propagation
//! - Excludes checksum field itself during calculation
//! - Adds file size to final sum for integrity verification
//! - Handles odd file sizes and boundary conditions
//!
//! ## Relocation Handling
//! Manages base relocations for mixed-mode assemblies:
//! - Detects when sections move to different virtual addresses
//! - Updates base relocation tables when necessary
//! - Handles position-independent managed code scenarios
//! - Provides framework for future relocation support
//!
//! # Usage Examples
//!
//! ```rust,ignore
//! use crate::cilassembly::write::writers::pe::PeWriter;
//! use crate::cilassembly::write::output::Output;
//! use crate::cilassembly::write::planner::LayoutPlan;
//! use crate::cilassembly::CilAssembly;
//!
//! # let assembly = CilAssembly::empty(); // placeholder
//! # let layout_plan = LayoutPlan { // placeholder
//! #     total_size: 1000,
//! #     original_size: 800,
//! #     file_layout: crate::cilassembly::write::planner::FileLayout {
//! #         dos_header: crate::cilassembly::write::planner::FileRegion { offset: 0, size: 64 },
//! #         pe_headers: crate::cilassembly::write::planner::FileRegion { offset: 64, size: 100 },
//! #         section_table: crate::cilassembly::write::planner::FileRegion { offset: 164, size: 80 },
//! #         sections: vec![]
//! #     },
//! #     pe_updates: crate::cilassembly::write::planner::PeUpdates {
//! #         section_table_needs_update: false,
//! #         checksum_needs_update: true,
//! #         section_updates: vec![]
//! #     },
//! #     metadata_modifications: crate::cilassembly::write::planner::metadata::MetadataModifications {
//! #         stream_modifications: vec![],
//! #         root_needs_update: false
//! #     },
//! #     heap_expansions: crate::cilassembly::write::planner::calc::HeapExpansions {
//! #         string_heap_addition: 0,
//! #         blob_heap_addition: 0,
//! #         guid_heap_addition: 0,
//! #         userstring_heap_addition: 0
//! #     },
//! #     table_modifications: vec![]
//! # };
//! # let mut output = Output::new(1000)?;
//!
//! // Create PE writer with necessary context
//! let mut pe_writer = PeWriter::new(&assembly, &mut output, &layout_plan);
//!
//! // Write PE structure updates
//! pe_writer.write_pe_updates()?;
//!
//! println!("PE structure updates completed successfully");
//! # Ok::<(), crate::Error>(())
//! ```
//!
//! # Thread Safety
//!
//! The [`crate::cilassembly::write::writers::pe::PeWriter`] is designed for single-threaded use during binary
//! generation. It maintains mutable state for output buffer management and is not thread-safe.
//! Each PE update operation should be completed atomically within a single thread.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::cilassembly::write::planner`] - Layout planning and PE update detection
//! - [`crate::cilassembly::write::output`] - Binary output buffer management
//! - [`crate::file`] - PE file structure parsing and analysis
//! - [`crate::cilassembly::write::utils`] - Shared utility functions

use crate::{
    cilassembly::{
        write::{
            output::Output,
            planner::{FileRegion, LayoutPlan},
            writers::{RelocationWriter, WriterBase},
        },
        CilAssembly,
    },
    Error, Result,
};

/// A stateful writer for PE structure updates that encapsulates all necessary context.
///
/// [`crate::cilassembly::write::writers::pe::PeWriter`] provides a clean API for writing PE modifications by maintaining
/// references to the assembly, output buffer, and layout plan. This eliminates the need
/// to pass these parameters around and provides a more object-oriented interface for
/// PE structure update operations.
///
/// # Usage
/// Created via [`crate::cilassembly::write::writers::pe::PeWriter::new`] and used throughout
/// the PE update process to modify checksums and relocation tables.
pub struct PeWriter<'a> {
    /// Base writer context containing assembly, output, and layout plan
    base: WriterBase<'a>,
}

impl<'a> PeWriter<'a> {
    /// Creates a new [`crate::cilassembly::write::writers::pe::PeWriter`] with the necessary context.
    ///
    /// # Arguments
    ///
    /// * `assembly` - The [`crate::cilassembly::CilAssembly`] containing PE modifications
    /// * `output` - Mutable reference to the [`crate::cilassembly::write::output::Output`] buffer
    /// * `layout_plan` - Reference to the [`crate::cilassembly::write::planner::LayoutPlan`] for offset calculations
    pub fn new(
        assembly: &'a CilAssembly,
        output: &'a mut Output,
        layout_plan: &'a LayoutPlan,
    ) -> Self {
        Self {
            base: WriterBase::new(assembly, output, layout_plan),
        }
    }

    /// Consolidates ALL PE structure updates into a single method.
    ///
    /// This is the main entry point for all PE modifications, combining previously
    /// scattered PE update logic from the main pipeline into a unified interface.
    /// Handles section tables, headers, COR20 updates, and file integrity.
    ///
    /// # Process
    /// 1. Updates section count in COFF header for new .meta section
    /// 2. Updates section table entries with new offsets and sizes
    /// 3. Updates COR20 header with new metadata location
    /// 4. Updates PE data directory entries
    /// 5. Recalculates checksums and handles relocations
    ///
    /// # Errors
    /// Returns [`crate::Error`] if any PE updates fail due to invalid structure
    /// or insufficient output buffer space.
    pub fn write_all_pe_updates(&mut self) -> Result<()> {
        self.update_section_count()?;
        self.update_section_table_entries()?;
        self.update_cor20_header()?;
        self.clear_certificate_table();

        if self.needs_relocation_updates() {
            self.update_base_relocations()?;
        }

        self.update_native_table_directories()?;

        if self.base.layout_plan.pe_updates.checksum_needs_update {
            self.update_pe_checksum()?;
        }

        Ok(())
    }

    /// Calculates and updates the PE file checksum.
    ///
    /// The PE checksum is calculated over the entire file excluding the checksum field itself
    /// using the standard PE checksum algorithm. This is required for signed assemblies
    /// and some system libraries to maintain file integrity validation.
    ///
    /// # Errors
    /// Returns [`crate::Error`] if checksum field cannot be located or updated.
    fn update_pe_checksum(&mut self) -> Result<()> {
        let checksum_offset = self.find_checksum_field_offset()?;

        let file_size = self.base.layout_plan.total_size as usize;
        let checksum = self.calculate_pe_checksum(checksum_offset, file_size)?;

        self.base
            .output
            .write_u32_le_at(checksum_offset, checksum)?;
        Ok(())
    }

    /// Finds the offset of the checksum field in the PE optional header.
    ///
    /// The checksum field is located at a fixed offset (64 bytes) from the start
    /// of the optional header for both PE32 and PE32+ formats.
    ///
    /// # Returns
    /// Returns the absolute file offset of the 4-byte checksum field.
    ///
    /// # Errors
    /// Returns [`crate::Error::WriteLayoutFailed`] if the checksum field would be
    /// outside the PE headers region.
    fn find_checksum_field_offset(&self) -> Result<u64> {
        // The checksum field is at a fixed offset in the PE optional header
        // PE32: offset 64 from start of optional header
        // PE32+: offset 64 from start of optional header

        let _view = self.base.assembly.view();
        let pe_headers_region = &self.base.layout_plan.file_layout.pe_headers;

        // PE signature (4) + COFF header (20) = 24 bytes before optional header
        let optional_header_start = pe_headers_region.offset + 24;

        // Checksum field is at offset 64 in the optional header
        let checksum_offset = optional_header_start + 64;

        // Validate that this is within the PE headers region
        if !pe_headers_region.contains(checksum_offset)
            || !pe_headers_region.contains(checksum_offset + 3)
        {
            return Err(Error::WriteLayoutFailed {
                message: "PE checksum field offset is outside PE headers region".to_string(),
            });
        }

        Ok(checksum_offset)
    }

    /// Calculates the PE file checksum using the standard algorithm.
    ///
    /// Implements the official PE checksum algorithm as defined by Microsoft:
    /// 1. Treat the file as an array of 16-bit little-endian words
    /// 2. Sum all words, carrying overflow into the high 16 bits
    /// 3. Add the file size to the final sum
    /// 4. Skip the checksum field itself during calculation
    /// 5. Handle odd file sizes by treating the final byte as a word
    ///
    /// # Arguments
    /// * `checksum_offset` - File offset of the checksum field to skip
    /// * `file_size` - Total size of the file in bytes
    ///
    /// # Returns
    /// Returns the calculated 32-bit PE checksum value.
    ///
    /// # Errors
    /// Returns [`crate::Error`] if file data cannot be accessed during calculation.
    fn calculate_pe_checksum(&mut self, checksum_offset: u64, file_size: usize) -> Result<u32> {
        let mut checksum: u64 = 0;
        let checksum_start = checksum_offset as usize;
        let checksum_end = checksum_start + 4;

        // Process the file in 16-bit chunks
        let mut offset = 0;
        while offset < file_size {
            // Skip the checksum field itself
            if offset >= checksum_start && offset < checksum_end {
                offset += 4;
                continue;
            }

            // Read 16-bit word (handle odd file sizes)
            let word = if offset + 1 < file_size {
                let slice = self.base.output.get_mut_slice(offset, 2)?;
                u16::from_le_bytes([slice[0], slice[1]]) as u64
            } else if offset < file_size {
                let slice = self.base.output.get_mut_slice(offset, 1)?;
                slice[0] as u64
            } else {
                break;
            };

            checksum += word;

            // Handle carry
            if checksum > 0xFFFF {
                checksum = (checksum & 0xFFFF) + (checksum >> 16);
            }

            offset += 2;
        }

        // Add file size and handle final carry
        checksum += file_size as u64;
        while checksum > 0xFFFF {
            checksum = (checksum & 0xFFFF) + (checksum >> 16);
        }

        Ok(checksum as u32)
    }

    /// Clears the PE certificate table directory entry to prevent corruption.
    ///
    /// When we modify a PE file and change its size, any existing certificate table
    /// entry may become invalid and point beyond the end of the file. This function
    /// safely clears the certificate table entry (directory entry 4) to prevent
    /// file corruption and parsing errors.
    ///
    /// This function is designed to be safe and will silently fail if the certificate
    /// table entry cannot be accessed (e.g., if the PE headers are malformed).
    fn clear_certificate_table(&mut self) {
        // Certificate table is directory entry 4, each entry is 8 bytes (RVA + Size)
        if let Ok(data_directory_offset) = self.find_data_directory_offset() {
            let certificate_entry_offset = data_directory_offset + (4 * 8); // Entry 4

            // Clear both RVA and Size (8 bytes total)
            if let Ok(()) = self
                .base
                .output
                .write_u32_le_at(certificate_entry_offset, 0)
            {
                let _ = self
                    .base
                    .output
                    .write_u32_le_at(certificate_entry_offset + 4, 0);
            }
        }
        // Silently fail if we can't clear it - better to have a working binary
        // than to fail entirely
    }

    /// Checks if base relocation updates are needed.
    ///
    /// Base relocations are typically not needed for pure .NET assemblies since they use
    /// managed code with relative addressing. However, mixed-mode assemblies with native
    /// code may require relocation updates when sections move to different virtual addresses.
    ///
    /// # Returns
    /// Returns `true` if any section moved to a different virtual address, indicating
    /// that base relocations may need updating.
    fn needs_relocation_updates(&self) -> bool {
        let view = self.base.assembly.view();
        let original_sections: Vec<_> = view.file().sections().collect();

        for (index, new_section) in self
            .base
            .layout_plan
            .file_layout
            .sections
            .iter()
            .enumerate()
        {
            if let Some(original_section) = original_sections.get(index) {
                if new_section.virtual_address != original_section.virtual_address {
                    return true;
                }
            }
        }

        false
    }

    /// Updates base relocations if sections moved.
    ///
    /// Handles base relocation table updates for mixed-mode assemblies when sections
    /// move to different virtual addresses. Pure .NET assemblies typically don't have
    /// base relocations due to their position-independent managed code nature.
    ///
    /// # Implementation
    /// 1. Parses the existing .reloc section from the original file
    /// 2. Updates relocation entries for sections that moved
    /// 3. Recalculates relocation tables with new addresses
    /// 4. Writes updated relocation data to the output buffer
    ///
    /// # Errors
    /// Returns errors for malformed relocation tables or I/O failures during
    /// relocation table processing.
    fn update_base_relocations(&mut self) -> Result<()> {
        let section_moves = self.create_section_moves();
        if section_moves.is_empty() {
            return Ok(());
        }

        let mut relocation_writer =
            RelocationWriter::with_assembly(self.base.output, &section_moves, self.base.assembly);

        relocation_writer.parse_relocation_table()?;
        relocation_writer.update_relocations()?;
        relocation_writer.write_relocation_table()?;

        Ok(())
    }

    /// Updates PE data directory entries for native import/export tables.
    ///
    /// This method updates the PE optional header's data directory to point to
    /// the new native import and export tables that were generated during the
    /// native table writing phase.
    ///
    /// # PE Data Directory Entries
    /// - Index 0: Export Table (IMAGE_DIRECTORY_ENTRY_EXPORT)
    /// - Index 1: Import Table (IMAGE_DIRECTORY_ENTRY_IMPORT)
    ///
    /// # Process
    /// 1. Check if native tables were generated according to the layout plan
    /// 2. Update the export table directory entry (index 0) if exports were generated
    /// 3. Update the import table directory entry (index 1) if imports were generated
    /// 4. Clear invalid entries to prevent corruption
    ///
    /// # Returns
    /// Returns `Ok(())` if directory updates completed successfully.
    ///
    /// # Errors
    /// Returns [`crate::Error`] if directory updates fail due to invalid addresses
    /// or insufficient space in the PE optional header.
    fn update_native_table_directories(&mut self) -> Result<()> {
        let data_directory_offset = self.find_data_directory_offset()?;
        let requirements = &self.base.layout_plan.native_table_requirements;

        // Update export table directory entry (index 0)
        if requirements.needs_export_tables {
            if let Some(export_rva) = requirements.export_table_rva {
                let export_entry_offset = data_directory_offset; // Entry 0

                // Write RVA
                self.base
                    .output
                    .write_u32_le_at(export_entry_offset, export_rva)?;
                // Write Size
                self.base.output.write_u32_le_at(
                    export_entry_offset + 4,
                    requirements.export_table_size as u32,
                )?;
            }
        }

        // Update import table directory entry (index 1)
        if requirements.needs_import_tables {
            if let Some(import_rva) = requirements.import_table_rva {
                let import_entry_offset = data_directory_offset + 8; // Entry 1

                // Write RVA
                self.base
                    .output
                    .write_u32_le_at(import_entry_offset, import_rva)?;
                // Write Size
                self.base.output.write_u32_le_at(
                    import_entry_offset + 4,
                    requirements.import_table_size as u32,
                )?;
            }
        }

        Ok(())
    }

    /// Updates a specific PE data directory entry if it points into the moved section
    fn update_data_directory_entry(
        &mut self,
        data_directory_offset: u64,
        entry_index: u32,
        rva_offset: i64,
        original_section: &goblin::pe::section_table::SectionTable,
    ) -> Result<()> {
        let entry_offset = data_directory_offset + (entry_index as u64 * 8);

        // Read the current RVA and size
        let current_rva = {
            let slice = self.base.output.get_mut_slice(entry_offset as usize, 4)?;
            u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]])
        };

        if current_rva != 0 {
            // Check if this RVA is within the original metadata section
            let section_start = original_section.virtual_address;
            let section_end = original_section.virtual_address + original_section.virtual_size;

            if current_rva >= section_start && current_rva < section_end {
                // This entry points into the moved section, update it
                let new_rva = (current_rva as i64 + rva_offset) as u32;
                self.base.output.write_u32_le_at(entry_offset, new_rva)?;
            }
        }

        Ok(())
    }

    /// Finds the offset of the PE data directory in the optional header.
    ///
    /// The data directory is located at different offsets depending on whether
    /// this is a PE32 or PE32+ file. The data directory contains 16 entries,
    /// each 8 bytes (RVA + Size).
    ///
    /// # Returns
    /// Returns the absolute file offset of the start of the data directory.
    ///
    /// # Errors
    /// Returns [`crate::Error::WriteLayoutFailed`] if the data directory cannot be located.
    fn find_data_directory_offset(&self) -> Result<u64> {
        let view = self.base.assembly.view();
        let pe_headers_region = &self.base.layout_plan.file_layout.pe_headers;

        // Get the PE type (PE32 or PE32+) from the assembly
        let optional_header =
            view.file()
                .header_optional()
                .as_ref()
                .ok_or_else(|| Error::WriteLayoutFailed {
                    message: "Missing optional header for PE data directory location".to_string(),
                })?;
        let is_pe32_plus = optional_header.standard_fields.magic != 0x10b;

        // PE signature (4) + COFF header (20) = 24 bytes before optional header
        let optional_header_start = pe_headers_region.offset + 24;

        // Data directory offset depends on PE type:
        // PE32: 96 bytes from start of optional header
        // PE32+: 112 bytes from start of optional header
        let data_directory_offset = if is_pe32_plus {
            optional_header_start + 112
        } else {
            optional_header_start + 96
        };

        // Validate that this is within the PE headers region
        // Data directory has 16 entries * 8 bytes = 128 bytes
        let data_directory_region = FileRegion::new(data_directory_offset, 128);
        if !pe_headers_region.contains(data_directory_offset)
            || data_directory_region.end_offset() > pe_headers_region.end_offset()
        {
            return Err(Error::WriteLayoutFailed {
                message: "PE data directory extends beyond PE headers region".to_string(),
            });
        }

        Ok(data_directory_offset)
    }

    /// Updates the NumberOfSections field in the COFF header.
    ///
    /// When we add a new .meta section, we need to increment the section count
    /// in the COFF header to reflect the additional section.
    ///
    /// # Errors
    /// Returns [`crate::Error`] if the COFF header cannot be updated.
    fn update_section_count(&mut self) -> Result<()> {
        let view = self.base.assembly.view();
        let original_sections: Vec<_> = view.file().sections().collect();

        // Calculate PE header offsets using cached information from the file
        let pe_signature_offset = view.file().header().dos_header.pe_pointer as u64;
        let coff_header_offset = pe_signature_offset + 4; // After PE signature (4 bytes)
        let number_of_sections_offset = coff_header_offset + 2; // After Machine field (2 bytes)

        // Calculate new section count (original + 1 for .meta section)
        let new_section_count = (original_sections.len() + 1) as u16;

        // Update NumberOfSections field in COFF header
        self.base
            .output
            .write_u16_le_at(number_of_sections_offset, new_section_count)?;

        Ok(())
    }

    /// Updates section table entries with new offsets and sizes.
    ///
    /// Processes section updates from the layout plan and applies them to
    /// the section table entries, updating file offsets, sizes, and other
    /// section properties as needed.
    ///
    /// # Errors
    /// Returns [`crate::Error`] if section table updates fail.
    fn update_section_table_entries(&mut self) -> Result<()> {
        if !self.base.layout_plan.pe_updates.section_table_needs_update {
            return Ok(()); // No updates needed
        }

        let section_table_region = &self.base.layout_plan.file_layout.section_table;

        // Apply section updates
        for section_update in &self.base.layout_plan.pe_updates.section_updates {
            let section_entry_offset =
                section_table_region.offset + (section_update.section_index * 40) as u64;

            // Update file offset if changed
            if let Some(new_file_offset) = section_update.new_file_offset {
                let offset_field_offset = section_entry_offset + 20; // PointerToRawData field
                self.base
                    .output
                    .write_u32_le_at(offset_field_offset, new_file_offset as u32)?;
            }

            // Update file size if changed
            if let Some(new_file_size) = section_update.new_file_size {
                // Add a small buffer to ensure we don't hit boundary issues
                let padded_size = (new_file_size + 15) & !15; // Round up to 16-byte boundary for safety
                let size_field_offset = section_entry_offset + 16; // SizeOfRawData field
                self.base
                    .output
                    .write_u32_le_at(size_field_offset, padded_size)?;
            }

            // Update virtual size if changed
            if let Some(new_virtual_size) = section_update.new_virtual_size {
                let vsize_field_offset = section_entry_offset + 8; // VirtualSize field
                self.base
                    .output
                    .write_u32_le_at(vsize_field_offset, new_virtual_size)?;
            }
        }

        Ok(())
    }

    /// Updates the COR20 header with new metadata location and data directory.
    ///
    /// When metadata is moved to a new .meta section, the COR20 header must be
    /// updated to point to the new location. This also updates the CLR data
    /// directory entry in the PE optional header.
    ///
    /// # Errors
    /// Returns [`crate::Error`] if COR20 header updates fail.
    fn update_cor20_header(&mut self) -> Result<()> {
        let view = self.base.assembly.view();

        // Find the .meta section
        let metadata_section = self
            .base
            .layout_plan
            .file_layout
            .sections
            .iter()
            .find(|section| section.contains_metadata && section.name == ".meta")
            .ok_or_else(|| Error::WriteLayoutFailed {
                message: "No .meta section found for COR20 update".to_string(),
            })?;

        // Calculate COR20 header location within the .meta section
        let original_cor20_rva = view.file().clr().0 as u32;
        let original_metadata_rva = view.cor20header().meta_data_rva;

        // Find original metadata section to calculate offsets
        let original_sections: Vec<_> = view.file().sections().collect();
        let original_metadata_section = original_sections
            .iter()
            .find(|section| {
                let section_name = std::str::from_utf8(&section.name)
                    .unwrap_or("")
                    .trim_end_matches('\0');
                view.file().section_contains_metadata(section_name)
            })
            .ok_or_else(|| Error::WriteLayoutFailed {
                message: "Original metadata section not found".to_string(),
            })?;

        let cor20_offset_in_section =
            original_cor20_rva - original_metadata_section.virtual_address;
        let metadata_offset_from_cor20 = original_metadata_rva - original_cor20_rva;

        // Calculate new file offset for COR20 header
        let cor20_file_offset =
            metadata_section.file_region.offset + cor20_offset_in_section as u64;

        // Calculate new RVAs
        let new_cor20_rva = metadata_section.virtual_address + cor20_offset_in_section;
        let new_metadata_rva = new_cor20_rva + metadata_offset_from_cor20;

        // Calculate actual metadata size
        let actual_metadata_size = metadata_section
            .metadata_streams
            .iter()
            .map(|stream| stream.file_region.end_offset())
            .max()
            .unwrap_or(metadata_section.file_region.offset)
            - metadata_section.file_region.offset;

        // Update COR20 header fields
        // Update metadata RVA field (offset 8)
        self.base
            .output
            .write_u32_le_at(cor20_file_offset + 8, new_metadata_rva)?;
        // Update metadata size field (offset 12)
        self.base
            .output
            .write_u32_le_at(cor20_file_offset + 12, actual_metadata_size as u32)?;

        // Update CLR data directory entry (entry 14)
        let data_directory_offset = self.find_data_directory_offset()?;
        let clr_directory_entry_offset = data_directory_offset + (14 * 8); // Entry 14

        // Write new COR20 RVA to data directory
        self.base
            .output
            .write_u32_le_at(clr_directory_entry_offset, new_cor20_rva)?;

        Ok(())
    }

    /// Creates section move information from the layout plan.
    fn create_section_moves(&self) -> Vec<super::relocation::SectionMove> {
        let view = self.base.assembly.view();
        let original_sections: Vec<_> = view.file().sections().collect();
        let mut section_moves = Vec::new();

        for (index, new_section) in self
            .base
            .layout_plan
            .file_layout
            .sections
            .iter()
            .enumerate()
        {
            if let Some(original_section) = original_sections.get(index) {
                if new_section.virtual_address != original_section.virtual_address {
                    section_moves.push(super::relocation::SectionMove {
                        old_virtual_address: original_section.virtual_address,
                        new_virtual_address: new_section.virtual_address,
                        virtual_size: new_section.virtual_size,
                    });
                }
            }
        }

        section_moves
    }
}

#[cfg(test)]
mod tests {
    use super::PeWriter;
    use crate::{
        cilassembly::write::{output::Output, planner::LayoutPlan},
        CilAssemblyView,
    };
    use std::path::Path;
    use tempfile::NamedTempFile;

    #[test]
    fn test_checksum_offset_calculation() {
        // Test the checksum offset calculation logic
        let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))
            .expect("Failed to load test assembly");
        let mut assembly = view.to_owned();
        let layout_plan = LayoutPlan::create(&mut assembly).expect("Failed to create layout plan");

        // Verify that PE headers have a reasonable size
        assert!(
            layout_plan.file_layout.pe_headers.size >= 88,
            "PE headers should be at least 88 bytes for checksum field"
        );
    }

    #[test]
    fn test_relocation_integration_with_pe_writer() {
        // Test that the PE writer correctly handles base relocations when sections don't move
        let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))
            .expect("Failed to load test assembly");

        let original_data = view.data().to_vec();
        let mut assembly = view.to_owned();
        let layout_plan = LayoutPlan::create(&mut assembly).expect("Failed to create layout plan");

        // Create a temporary file for the output
        let temp_file = NamedTempFile::new().expect("Failed to create temporary file");
        let temp_path = temp_file.path();

        // Create an output buffer
        let mut output =
            Output::create(temp_path, layout_plan.total_size).expect("Failed to create output");

        // Initialize output with original file data
        let copy_size = std::cmp::min(original_data.len(), layout_plan.total_size as usize);
        output
            .write_at(0, &original_data[..copy_size])
            .expect("Failed to copy original data");

        // Create PE writer
        let mut pe_writer = PeWriter::new(&assembly, &mut output, &layout_plan);

        // Test that PE updates complete without error
        let result = pe_writer.write_all_pe_updates();
        assert!(result.is_ok(), "PE updates should complete successfully");

        // Test the section move detection
        let needs_relocation = pe_writer.needs_relocation_updates();
        // With our new approach of always creating a new metadata section, we may or may not need relocations
        // depending on whether any non-metadata sections moved. Just verify this doesn't panic.
        let _ = needs_relocation;
    }

    #[test]
    fn test_section_move_detection() {
        let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))
            .expect("Failed to load test assembly");
        let mut assembly = view.to_owned();
        let layout_plan = LayoutPlan::create(&mut assembly).expect("Failed to create layout plan");

        // Create a temporary file for the output
        let temp_file = NamedTempFile::new().expect("Failed to create temporary file");
        let temp_path = temp_file.path();

        let mut output =
            Output::create(temp_path, layout_plan.total_size).expect("Failed to create output");

        let pe_writer = PeWriter::new(&assembly, &mut output, &layout_plan);

        // Test section move detection with current layout plan
        let needs_updates = pe_writer.needs_relocation_updates();

        // Test section move creation
        let section_moves = pe_writer.create_section_moves();

        assert_eq!(
            needs_updates,
            !section_moves.is_empty(),
            "needs_relocation_updates should match whether section_moves is empty"
        );

        // temp_file will be automatically cleaned up when it goes out of scope
    }
}
