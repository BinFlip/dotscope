//! Heap writing functionality for the copy-first binary generation approach.
//!
//! This module provides comprehensive heap writing capabilities for .NET assembly binary generation,
//! implementing efficient appending of new entries to existing metadata heap streams (#Strings, #Blob, #GUID, #US)
//! without requiring complete heap reconstruction. It maintains ECMA-335 compliance while minimizing
//! the complexity of binary generation through targeted modifications.
//!
//! # Key Components
//!
//! - [`crate::cilassembly::write::writers::heap::HeapWriter`] - Stateful writer for all heap modifications
//! - [`crate::cilassembly::write::writers::heap::HeapWriter::write_all_heaps`] - Main entry point for heap writing
//! - [`crate::cilassembly::write::writers::heap::strings`] - String heap writing with UTF-8 encoding
//! - [`crate::cilassembly::write::writers::heap::blobs`] - Blob heap writing with compression handling  
//! - [`crate::cilassembly::write::writers::heap::guids`] - GUID heap writing with 16-byte alignment
//! - [`crate::cilassembly::write::writers::heap::userstrings`] - User string heap writing with UTF-16 encoding
//! - [`crate::cilassembly::write::writers::heap::utilities`] - Shared heap utilities and helper functions
//!
//! # Architecture
//!
//! The heap writing system implements a copy-first strategy with targeted additions:
//!
//! ## Copy-First Approach
//! Instead of rebuilding entire heaps, this module:
//! - Preserves original heap content and structure
//! - Appends new entries only where modifications exist
//! - Maintains proper ECMA-335 alignment and encoding
//! - Minimizes binary generation complexity
//!
//! ## Heap-Specific Writing
//! Each heap type has specialized writing logic:
//! - **String Heap (#Strings)**: Null-terminated UTF-8 strings with 4-byte alignment
//! - **Blob Heap (#Blob)**: Length-prefixed binary data with compressed length encoding
//! - **GUID Heap (#GUID)**: Raw 16-byte GUID values with natural alignment
//! - **User String Heap (#US)**: UTF-16 strings with length prefix and terminator byte
//!
//! ## State Management
//! The [`crate::cilassembly::write::writers::heap::HeapWriter`] encapsulates:
//! - Assembly modification context and change tracking
//! - Output buffer management with bounds checking
//! - Layout plan integration for offset calculations
//! - Stream positioning and alignment requirements
//!
//! # Usage Examples
//!
//! ```rust,ignore
//! use crate::cilassembly::write::writers::heap::HeapWriter;
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
//! #         checksum_needs_update: false,
//! #         section_updates: vec![]
//! #     },
//! #     metadata_modifications: crate::cilassembly::write::planner::metadata::MetadataModifications {
//! #         stream_modifications: vec![]
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
//! // Create heap writer with necessary context
//! let mut heap_writer = HeapWriter::new(&assembly, &mut output, &layout_plan);
//!
//! // Write all heap modifications
//! heap_writer.write_all_heaps()?;
//!
//! println!("Heap modifications written successfully");
//! # Ok::<(), crate::Error>(())
//! ```
//!
//! # Thread Safety
//!
//! The [`crate::cilassembly::write::writers::heap::HeapWriter`] is designed for single-threaded use during binary
//! generation. It maintains mutable state for output buffer management and is not thread-safe.
//! Each heap writing operation should be completed atomically within a single thread.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::cilassembly::write::planner`] - Layout planning and offset calculations
//! - [`crate::cilassembly::write::output`] - Binary output buffer management
//! - [`crate::cilassembly::changes`] - Source of heap modification data
//! - [`crate::cilassembly::write::utils`] - Shared utility functions for layout searches

use crate::{
    cilassembly::{
        write::{
            output::Output,
            planner::{LayoutPlan, StreamFileLayout, StreamModification},
            writers::WriterBase,
        },
        CilAssembly,
    },
    Result,
};

mod blobs;
mod guids;
mod strings;
mod userstrings;
mod utilities;

/// A stateful writer for metadata heap modifications that encapsulates all necessary context.
///
/// [`crate::cilassembly::write::writers::heap::HeapWriter`] provides a clean API for writing heap modifications by maintaining
/// references to the assembly, output buffer, and layout plan. This eliminates the need
/// to pass these parameters around and provides a more object-oriented interface for
/// heap serialization operations.
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
/// Created via [`crate::cilassembly::write::writers::heap::HeapWriter::new`] and used throughout
/// the heap writing process to append new entries to existing metadata heaps.
pub struct HeapWriter<'a> {
    /// Base writer context containing assembly, output, and layout plan
    base: WriterBase<'a>,
}

impl<'a> HeapWriter<'a> {
    /// Creates a new [`crate::cilassembly::write::writers::heap::HeapWriter`] with the necessary context.
    ///
    /// # Arguments
    ///
    /// * `assembly` - The [`crate::cilassembly::CilAssembly`] containing heap modifications
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

    /// Common helper that finds stream layout and calculates write positions.
    ///
    /// Returns ([`crate::cilassembly::write::planner::StreamFileLayout`], write_start_position).
    ///
    /// # Arguments
    /// * `stream_mod` - The [`crate::cilassembly::write::planner::metadata::StreamModification`] to prepare for writing
    fn prepare_heap_write(
        &self,
        stream_mod: &StreamModification,
    ) -> Result<(&StreamFileLayout, usize)> {
        let stream_layout = self.base.find_stream_layout(&stream_mod.name)?;

        let write_start = if self.is_heap_rebuilding(&stream_mod.name) {
            stream_layout.file_region.offset as usize
        } else {
            self.find_actual_heap_data_end(stream_layout, stream_mod, &stream_mod.name)?
        };

        Ok((stream_layout, write_start))
    }

    /// Determines if a heap is being rebuilt (has any changes) or just appended to.
    fn is_heap_rebuilding(&self, stream_name: &str) -> bool {
        let changes = self.base.assembly.changes();
        match stream_name {
            "#Strings" => {
                changes.string_heap_changes.has_modifications()
                    || changes.string_heap_changes.has_removals()
            }
            "#Blob" => changes.blob_heap_changes.has_changes(),
            "#GUID" => {
                changes.guid_heap_changes.has_modifications()
                    || changes.guid_heap_changes.has_removals()
            }
            "#US" => {
                changes.userstring_heap_changes.has_modifications()
                    || changes.userstring_heap_changes.has_removals()
            }
            _ => false,
        }
    }

    /// Writes heap modifications based on the copy-first approach.
    ///
    /// Handles additions, modifications, and removals of heap entries. This method
    /// iterates through all [`crate::cilassembly::write::planner::metadata::StreamModification`] entries and
    /// writes the appropriate heap changes based on stream type.
    ///
    /// For modifications and removals, the original heap content is updated in place
    /// where possible, while additions are appended to the end.
    ///
    /// # Errors
    /// Returns [`crate::Error`] if any heap writing operation fails due to invalid data
    /// or insufficient output buffer space.
    pub fn write_all_heaps(&mut self) -> Result<()> {
        // Process each modified stream and append new data
        for stream_mod in self
            .base
            .layout_plan
            .metadata_modifications
            .stream_modifications
            .iter()
        {
            match stream_mod.name.as_str() {
                "#Strings" => {
                    self.write_string_heap_additions(stream_mod)?;
                }
                "#Blob" => {
                    self.write_blob_heap_additions(stream_mod)?;
                }
                "#GUID" => {
                    self.write_guid_heap_additions(stream_mod)?;
                }
                "#US" => {
                    self.write_userstring_heap_additions(stream_mod)?;
                }
                _ => {
                    // Skip unknown streams
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{cilassembly::write::planner::LayoutPlan, CilAssemblyView};
    use std::path::Path;

    #[test]
    fn test_heap_writer_no_modifications() {
        // Test with assembly that has no modifications
        let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))
            .expect("Failed to load test assembly");
        let assembly = view.to_owned();

        // Since there are no modifications, this should succeed without doing anything
        let layout_plan = LayoutPlan::create(&assembly).expect("Failed to create layout plan");

        // For testing, we'd need a mock Output, but for now just verify the layout plan
        assert_eq!(
            layout_plan
                .metadata_modifications
                .stream_modifications
                .len(),
            0
        );
    }
}
