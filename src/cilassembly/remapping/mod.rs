//! Index and RID remapping for binary generation.
//!
//! This module provides comprehensive remapping infrastructure for maintaining referential
//! integrity during assembly modification and binary generation. It coordinates the complex
//! task of updating all cross-references when metadata structures are modified, ensuring
//! that the final binary maintains proper relationships between tables, heaps, and indices.
//!
//! # Key Components
//!
//! - [`crate::cilassembly::remapping::index::IndexRemapper`] - Central coordinator for all index remapping operations
//! - [`crate::cilassembly::remapping::rid::RidRemapper`] - Per-table RID (Row ID) remapping management
//!
//! # Architecture
//!
//! The remapping system operates in a two-tier architecture to handle the different scales
//! and requirements of index management:
//!
//! ## Index Remapping Level
//! The [`crate::cilassembly::remapping::index::IndexRemapper`] serves as the central coordinator,
//! managing remapping for all metadata heaps and coordinating table-level operations:
//! - **Heap Index Management**: String, Blob, GUID, and UserString heap indices
//! - **Cross-Reference Coordination**: Ensures all references are updated consistently
//! - **Global State Management**: Maintains complete mapping state across all structures
//!
//! ## Table RID Level  
//! Individual [`crate::cilassembly::remapping::rid::RidRemapper`] instances handle per-table
//! RID management with specialized logic for different modification patterns:
//! - **Sparse Modifications**: Handle individual insert/update/delete operations
//! - **Bulk Replacements**: Optimize for complete table replacement scenarios
//! - **Conflict Resolution**: Apply timestamp-based ordering for overlapping operations
//!
//! # Remapping Process
//!
//! The remapping system follows a well-defined process to ensure correctness:
//!
//! ## Phase 1: Analysis
//! 1. **Change Detection**: Identify all modified heaps and tables
//! 2. **Dependency Analysis**: Determine cross-reference relationships
//! 3. **Strategy Selection**: Choose optimal remapping approach per structure
//!
//! ## Phase 2: Mapping Construction
//! 1. **Heap Mapping**: Build index mappings for modified heaps
//! 2. **Table Mapping**: Create RID remappers for modified tables
//! 3. **Validation**: Ensure mapping completeness and consistency
//!
//! ## Phase 3: Application
//! 1. **Cross-Reference Updates**: Apply mappings to all table data
//! 2. **Heap Consolidation**: Merge original and new heap content
//! 3. **Binary Generation**: Output final binary with updated references
//!
//! # Usage Examples
//!
//! ```rust,ignore
//! use crate::cilassembly::remapping::{IndexRemapper, RidRemapper};
//! use crate::cilassembly::changes::AssemblyChanges;
//! use crate::metadata::cilassemblyview::CilAssemblyView;
//! use crate::metadata::tables::TableId;
//! use std::path::Path;
//!
//! # let view = CilAssemblyView::from_file(Path::new("test.dll"))?;
//! # let mut changes = AssemblyChanges::new(&view);
//!
//! // Build comprehensive remapping
//! let remapper = IndexRemapper::build_from_changes(&changes, &view);
//!
//! // Access table-specific remapping
//! if let Some(table_remapper) = remapper.get_table_remapper(TableId::TypeDef) {
//!     let final_rid = table_remapper.map_rid(42);
//!     let total_rows = table_remapper.final_row_count();
//! }
//!
//! // Apply all remappings
//! remapper.apply_to_assembly(&mut changes)?;
//! # Ok::<(), crate::Error>(())
//! ```
//!
//! # Thread Safety
//!
//! Both remapper types are designed for single-threaded batch processing during
//! binary generation and are not [`Send`] or [`Sync`]. They contain large hash maps
//! optimized for sequential access patterns.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::cilassembly::changes`] - Change tracking and storage
//! - [`crate::cilassembly::write`] - Binary output generation
//! - Assembly validation - Validation and conflict resolution
//! - [`crate::metadata::tables`] - Table data structures and cross-references

pub use self::{index::IndexRemapper, rid::RidRemapper};

mod index;
mod rid;
