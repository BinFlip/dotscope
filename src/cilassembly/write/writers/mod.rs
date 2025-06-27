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
