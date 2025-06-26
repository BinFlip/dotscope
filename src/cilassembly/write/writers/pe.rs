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
        write::{output::Output, planner::LayoutPlan, writers::RelocationWriter},
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
/// # Design Benefits
///
/// - **Encapsulation**: All writing context is stored in one place
/// - **Clean API**: Methods don't require numerous parameters
/// - **Maintainability**: Easier to extend and modify functionality
/// - **Performance**: Avoids repeated parameter passing
/// - **Safety**: Centralized bounds checking and validation
///
/// # Usage
/// Created via [`crate::cilassembly::write::writers::pe::PeWriter::new`] and used throughout
/// the PE update process to modify checksums and relocation tables.
pub struct PeWriter<'a> {
    /// Reference to the [`crate::cilassembly::CilAssembly`] containing PE modifications
    assembly: &'a CilAssembly,
    /// Mutable reference to the [`crate::cilassembly::write::output::Output`] buffer for writing
    output: &'a mut Output,
    /// Reference to the [`crate::cilassembly::write::planner::LayoutPlan`] for offset calculations
    layout_plan: &'a LayoutPlan,
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
            assembly,
            output,
            layout_plan,
        }
    }

    /// Updates PE structure including checksums and relocations.
    ///
    /// This method handles all PE-specific updates required after metadata modifications.
    /// It operates based on the [`crate::cilassembly::write::planner::PeUpdates`] information in the layout plan
    /// to determine which updates are necessary.
    ///
    /// # Process
    /// 1. Recalculates PE file checksum if [`crate::cilassembly::write::planner::PeUpdates::checksum_needs_update`] is true
    /// 2. Updates base relocations if sections moved to different virtual addresses
    /// 3. Validates PE structure integrity throughout the process
    ///
    /// # Errors
    /// Returns [`crate::Error`] if PE updates fail due to invalid structure or
    /// insufficient output buffer space.
    pub fn write_pe_updates(&mut self) -> Result<()> {
        if self.layout_plan.pe_updates.checksum_needs_update {
            self.update_pe_checksum()?;
        }

        if self.needs_relocation_updates() {
            self.update_base_relocations()?;
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

        let file_size = self.layout_plan.total_size as usize;
        let checksum = self.calculate_pe_checksum(checksum_offset, file_size)?;

        self.output.write_u32_le_at(checksum_offset, checksum)?;
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

        let _view = self.assembly.view();
        let pe_headers_region = &self.layout_plan.file_layout.pe_headers;

        // PE signature (4) + COFF header (20) = 24 bytes before optional header
        let optional_header_start = pe_headers_region.offset + 24;

        // Checksum field is at offset 64 in the optional header
        let checksum_offset = optional_header_start + 64;

        // Validate that this is within the PE headers region
        if checksum_offset + 4 > pe_headers_region.offset + pe_headers_region.size {
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
                let slice = self.output.get_mut_slice(offset, 2)?;
                u16::from_le_bytes([slice[0], slice[1]]) as u64
            } else if offset < file_size {
                let slice = self.output.get_mut_slice(offset, 1)?;
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
        let view = self.assembly.view();
        let original_sections: Vec<_> = view.file().sections().collect();

        for (index, new_section) in self.layout_plan.file_layout.sections.iter().enumerate() {
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
            RelocationWriter::with_assembly(self.output, &section_moves, self.assembly);

        relocation_writer.parse_relocation_table()?;
        relocation_writer.update_relocations()?;
        relocation_writer.write_relocation_table()?;

        Ok(())
    }

    /// Creates section move information from the layout plan.
    fn create_section_moves(&self) -> Vec<super::relocation::SectionMove> {
        let view = self.assembly.view();
        let original_sections: Vec<_> = view.file().sections().collect();
        let mut section_moves = Vec::new();

        for (index, new_section) in self.layout_plan.file_layout.sections.iter().enumerate() {
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
        cilassembly::write::{output::Output, planner::create_layout_plan},
        CilAssemblyView,
    };
    use std::path::Path;
    use tempfile::NamedTempFile;

    #[test]
    fn test_checksum_offset_calculation() {
        // Test the checksum offset calculation logic
        let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))
            .expect("Failed to load test assembly");
        let assembly = view.to_owned();

        let layout_plan = create_layout_plan(&assembly).expect("Failed to create layout plan");

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
        let assembly = view.to_owned();

        let layout_plan = create_layout_plan(&assembly).expect("Failed to create layout plan");

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
        let result = pe_writer.write_pe_updates();
        assert!(result.is_ok(), "PE updates should complete successfully");

        // Test the section move detection
        let needs_relocation = pe_writer.needs_relocation_updates();
        println!("Assembly needs relocation updates: {}", needs_relocation);
        // For a typical layout plan without actual section moves, this should be false
    }

    #[test]
    fn test_section_move_detection() {
        let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))
            .expect("Failed to load test assembly");
        let assembly = view.to_owned();

        let layout_plan = create_layout_plan(&assembly).expect("Failed to create layout plan");

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
