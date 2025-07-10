//! Binary writers for different assembly components.
//!
//! This module provides specialized stateful writers for different parts of .NET assembly
//! binary generation, implementing the copy-first strategy with targeted modifications.
//! Each writer focuses on a specific aspect of the binary structure while maintaining
//! ECMA-335 compliance and proper cross-component coordination.
//!
//! # Key Components
//!
//! - [`crate::cilassembly::write::writers::heap::HeapWriter`] - Metadata heap writing (strings, blobs, GUIDs, user strings)
//! - [`crate::cilassembly::write::writers::table::TableWriter`] - Metadata table serialization and updates
//! - [`crate::cilassembly::write::writers::pe::PeWriter`] - PE structure updates including checksums and relocations
//! - [`crate::cilassembly::write::writers::native::NativeTablesWriter`] - Native PE import/export table generation
//!
//! # Architecture
//!
//! The binary writing system is organized around specialized, stateful writers:
//!
//! ## Writer Specialization
//! Each writer handles a specific aspect of binary generation:
//! - **Heap Writers**: Append new entries to metadata heaps without rebuilding
//! - **Table Writers**: Update specific metadata table rows or perform complete replacement
//! - **Metadata Writers**: Update metadata root structures when streams change
//! - **PE Writers**: Modify PE headers, section tables, and checksums
//!
//! ## Stateful Design
//! All writers follow a consistent stateful pattern:
//! - Encapsulate assembly context, output buffer, and layout plan
//! - Provide clean APIs without excessive parameter passing
//! - Maintain writing state and bounds checking
//! - Enable easy extension and modification
//!
//! ## Coordination Strategy
//! Writers coordinate through the shared layout plan:
//! - Layout plan provides unified offset calculations
//! - Writers operate on different file regions without conflicts
//! - Cross-writer dependencies handled through plan coordination
//! - Proper ordering ensures consistent binary generation
//!
//! # Usage Examples
//!
//! ```rust,ignore
//! use crate::cilassembly::write::writers::{
//!     heap::HeapWriter,
//!     metadata::MetadataWriter,
//!     table::TableWriter,
//!     pe::PeWriter
//! };
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
//! // Coordinate multiple writers for complete binary generation
//! let mut heap_writer = HeapWriter::new(&assembly, &mut output, &layout_plan);
//! let mut table_writer = TableWriter::new(&assembly, &mut output, &layout_plan);
//! let mut pe_writer = PeWriter::new(&assembly, &mut output, &layout_plan);
//!
//! // Write in proper order for dependencies
//! heap_writer.write_all_heaps()?;
//! table_writer.write_all_tables()?;
//! pe_writer.write_pe_updates()?;
//!
//! println!("Complete binary generation successful");
//! # Ok::<(), crate::Error>(())
//! ```
//!
//! # Thread Safety
//!
//! All writers in this module are designed for single-threaded use during binary
//! generation. They maintain mutable state for output buffer management and are
//! not thread-safe. Each writing operation should be completed atomically within
//! a single thread.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::cilassembly::write::planner`] - Layout planning and coordination
//! - [`crate::cilassembly::write::output`] - Binary output buffer management
//! - [`crate::cilassembly::changes`] - Source of modification data
//! - [`crate::cilassembly::write::utils`] - Shared utility functions

use crate::{
    cilassembly::{
        write::{
            output::Output,
            planner::{LayoutPlan, SectionFileLayout, StreamFileLayout, StreamModification},
            utils::{find_metadata_section, find_stream_layout},
        },
        CilAssembly,
    },
    Result,
};

mod heap;
mod native;
mod pe;
mod relocation;
mod table;

pub use heap::*;
pub use native::*;
pub use pe::*;
pub use relocation::*;
pub use table::*;

/// Base context and utilities shared by all assembly writers.
///
/// This structure encapsulates the common context needed by most writers in the binary
/// generation pipeline, reducing boilerplate code and providing shared utility methods
/// for common operations like layout searches and error handling.
///
/// # Philosophy
/// Instead of repeating the same context fields and constructor patterns across multiple
/// writers, `WriterBase` provides a foundation that can be embedded or inherited by
/// specific writers, following the DRY principle and improving maintainability.
///
/// # Usage
/// Writers can embed this base or use it as a foundation:
/// ```rust,ignore
/// struct MyWriter<'a> {
///     base: WriterBase<'a>,
///     // additional fields specific to MyWriter
/// }
///
/// impl<'a> MyWriter<'a> {
///     pub fn new(assembly: &'a CilAssembly, output: &'a mut Output, layout_plan: &'a LayoutPlan) -> Self {
///         Self {
///             base: WriterBase::new(assembly, output, layout_plan),
///             // initialize additional fields
///         }
///     }
/// }
/// ```
pub struct WriterBase<'a> {
    /// Reference to the [`crate::cilassembly::CilAssembly`] containing modification data
    pub assembly: &'a CilAssembly,
    /// Mutable reference to the [`crate::cilassembly::write::output::Output`] buffer for writing
    pub output: &'a mut Output,
    /// Reference to the [`crate::cilassembly::write::planner::LayoutPlan`] for offset calculations
    pub layout_plan: &'a LayoutPlan,
}

impl<'a> WriterBase<'a> {
    /// Creates a new [`WriterBase`] with the necessary context.
    ///
    /// This constructor encapsulates the standard initialization pattern used by most
    /// writers in the pipeline, reducing code duplication.
    ///
    /// # Arguments
    /// * `assembly` - Reference to the [`crate::cilassembly::CilAssembly`] containing modification data
    /// * `output` - Mutable reference to the [`crate::cilassembly::write::output::Output`] buffer for writing
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

    /// Finds the metadata section within the file layout.
    ///
    /// This is a common operation used by most writers that need to locate metadata
    /// streams within the PE file structure.
    ///
    /// # Returns
    /// Returns a reference to the [`crate::cilassembly::write::planner::SectionFileLayout`] containing metadata.
    ///
    /// # Errors
    /// Returns [`crate::Error`] if no metadata section is found in the layout.
    pub fn find_metadata_section(&self) -> Result<&SectionFileLayout> {
        find_metadata_section(&self.layout_plan.file_layout)
    }

    /// Finds a specific stream layout within the metadata section.
    ///
    /// This combines the common pattern of finding the metadata section and then
    /// locating a specific stream within that section.
    ///
    /// # Arguments
    /// * `stream_name` - Name of the stream to locate (e.g., "#Strings", "#Blob", "#GUID", "#US")
    ///
    /// # Returns
    /// Returns a reference to the [`crate::cilassembly::write::planner::StreamFileLayout`] for the specified stream.
    ///
    /// # Errors
    /// Returns [`crate::Error`] if the metadata section or the specified stream is not found.
    pub fn find_stream_layout(&self, stream_name: &str) -> Result<&StreamFileLayout> {
        let metadata_section = self.find_metadata_section()?;
        find_stream_layout(metadata_section, stream_name)
    }

    /// Convenient access to the total file size from the layout plan.
    ///
    /// This is frequently accessed by writers for bounds checking and validation.
    pub fn total_file_size(&self) -> u64 {
        self.layout_plan.total_size
    }

    /// Convenient access to the original file size from the layout plan.
    ///
    /// Useful for writers that need to understand the expansion amount.
    pub fn original_file_size(&self) -> u64 {
        self.layout_plan.original_size
    }

    /// Gets the stream layout and write position for writing operations.
    ///
    /// In the .meta section approach, streams are always written from the beginning
    /// of their allocated stream region. This method encapsulates the common pattern
    /// of finding the stream layout and calculating the write start position.
    ///
    /// Returns ([`crate::cilassembly::write::planner::StreamFileLayout`], write_start_position).
    ///
    /// # Arguments
    /// * `stream_mod` - The [`crate::cilassembly::write::planner::StreamModification`] to prepare for writing
    ///
    /// # Returns
    /// Returns a tuple containing the stream layout and the write start position (as usize).
    ///
    /// # Errors
    /// Returns [`crate::Error`] if the stream layout cannot be found.
    pub fn get_stream_write_position(
        &self,
        stream_mod: &StreamModification,
    ) -> Result<(&StreamFileLayout, usize)> {
        let stream_layout = self.find_stream_layout(&stream_mod.name)?;
        let write_start = stream_layout.file_region.offset as usize;
        Ok((stream_layout, write_start))
    }
}
