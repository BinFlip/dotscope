//! Layout planning for 1:1 copy with targeted modifications.
//!
//! This module provides comprehensive layout planning for .NET assembly binary generation
//! using a copy-first strategy. It creates a 1:1 copy of the original assembly file
//! and then applies targeted modifications only where needed, ensuring proper ECMA-335
//! compliance while minimizing the complexity of binary generation.
//!
//! # Key Components
//!
//! - [`crate::cilassembly::write::planner::create_layout_plan`] - Main entry point for layout planning
//! - [`crate::cilassembly::write::planner::LayoutPlan`] - Complete layout plan with all file structure information
//! - [`crate::cilassembly::write::planner::FileLayout`] - Detailed file structure with section placements
//! - [`crate::cilassembly::write::planner::SectionFileLayout`] - Individual section layout with metadata stream details
//! - [`crate::cilassembly::write::planner::PeUpdates`] - PE header modification requirements
//! - [`crate::cilassembly::write::planner::calc`] - Comprehensive size and alignment calculation module
//! - [`crate::cilassembly::write::planner::calc::heaps`] - Heap expansion calculations
//! - [`crate::cilassembly::write::planner::calc::tables`] - Table size and modification calculations
//! - [`crate::cilassembly::write::planner::calc::alignment`] - ECMA-335 alignment utilities
//! - [`crate::cilassembly::write::planner::metadata`] - Metadata layout planning module
//! - [`crate::cilassembly::write::planner::pe`] - PE structure analysis module
//!
//! # Architecture
//!
//! The layout planning system implements a sophisticated copy-first strategy:
//!
//! ## Copy-First Strategy
//! Instead of building assembly files from scratch, this approach:
//! - Preserves the original file structure and layout
//! - Identifies only the sections that need modification
//! - Calculates minimal changes required for compliance
//! - Reduces complexity and maintains compatibility
//!
//! ## Section-by-Section Analysis
//! The planner analyzes each PE section to determine:
//! - Whether the section contains metadata that needs modification
//! - Required size expansions due to heap additions
//! - Potential relocations if metadata sections grow
//! - Cross-section dependencies and alignment requirements
//!
//! ## Metadata Stream Planning
//! For sections containing .NET metadata:
//! - Calculates new stream sizes after heap additions
//! - Plans stream relocations within metadata sections
//! - Updates metadata root directory structures
//! - Maintains proper ECMA-335 stream alignment
//!
//! ## PE Structure Updates
//! Plans all necessary PE header updates:
//! - Section table entries for relocated/resized sections
//! - Virtual address mappings and size adjustments
//! - Checksum recalculation requirements
//! - Directory entry updates for metadata changes
//!
//! # Usage Examples
//!
//! ```rust,ignore
//! use crate::cilassembly::write::planner::create_layout_plan;
//! use crate::cilassembly::CilAssembly;
//!
//! # let assembly = CilAssembly::empty(); // placeholder
//! // Create comprehensive layout plan
//! let layout_plan = create_layout_plan(&assembly)?;
//!
//! println!("Original size: {} bytes", layout_plan.original_size);
//! println!("New size: {} bytes", layout_plan.total_size);
//! println!("Sections: {}", layout_plan.file_layout.sections.len());
//!
//! // Check if PE updates are needed
//! if layout_plan.pe_updates.section_table_needs_update {
//!     println!("PE section table requires updates");
//! }
//!
//! // Access heap expansion information
//! let expansions = &layout_plan.heap_expansions;
//! println!("String heap addition: {} bytes", expansions.string_heap_addition);
//! # Ok::<(), crate::Error>(())
//! ```
//!
//! # Thread Safety
//!
//! The layout planning process is designed for single-threaded use during binary
//! generation. The analysis involves complex state tracking and file structure
//! calculations that are not thread-safe by design.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::cilassembly::write`] - Main binary generation pipeline
//! - [`crate::cilassembly::changes`] - Source of modification data
//! - [`crate::cilassembly::write::output`] - Binary output coordination
//! - [`crate::cilassembly::write::writers`] - Specialized binary writers

use crate::metadata::tables::TableId;

mod calc;
mod heap_expansions;
mod layout;
mod memory;
mod metadata;
mod pe;
mod tables;
mod updates;
mod validation;

pub use heap_expansions::HeapExpansions;
pub use layout::{FileLayout, FileRegion, LayoutPlan, SectionFileLayout, StreamFileLayout};
pub use metadata::{MetadataModifications, StreamModification};

/// PE header updates needed after section relocations.
///
/// Contains information about all PE header modifications required
/// when sections are relocated or resized during layout planning.
#[derive(Debug, Clone)]
pub struct PeUpdates {
    /// Whether PE section table needs updating due to section changes.
    pub section_table_needs_update: bool,

    /// Whether PE checksum needs recalculation due to structural changes.
    pub checksum_needs_update: bool,

    /// Individual section updates needed in the section table.
    /// Contains specific changes for each modified section.
    pub section_updates: Vec<SectionUpdate>,
}

/// Update needed for a PE section header.
///
/// Specifies the changes required for an individual section header
/// in the PE section table.
#[derive(Debug, Clone)]
pub struct SectionUpdate {
    /// Index of the section in the section table (0-based).
    pub section_index: usize,

    /// New file offset if the section was relocated.
    /// None if section remains at original offset.
    pub new_file_offset: Option<u64>,

    /// New file size if the section grew due to modifications.
    /// None if section size unchanged.
    pub new_file_size: Option<u32>,

    /// New virtual size if the section grew in memory.
    /// None if virtual size unchanged.
    pub new_virtual_size: Option<u32>,
}

/// Requirements for native PE import/export table generation.
///
/// Contains information needed to allocate space and position native PE tables
/// in the output file. This includes import tables (IAT/ILT) and export tables (EAT)
/// when the assembly contains native dependencies or exports.
#[derive(Debug, Clone, Default)]
pub struct NativeTableRequirements {
    /// Space needed for import tables (Import Directory, IAT, ILT, names).
    /// Zero if no native imports are present.
    pub import_table_size: u64,

    /// Space needed for export tables (Export Directory, EAT, names, ordinals).
    /// Zero if no native exports are present.
    pub export_table_size: u64,

    /// Preferred RVA for import table placement.
    /// Calculated based on available address space and alignment requirements.
    pub import_table_rva: Option<u32>,

    /// Preferred RVA for export table placement.
    /// Calculated based on available address space and alignment requirements.
    pub export_table_rva: Option<u32>,

    /// Whether import tables are needed for this assembly.
    pub needs_import_tables: bool,

    /// Whether export tables are needed for this assembly.
    pub needs_export_tables: bool,
}

/// Information about a table modification region.
///
/// Contains details about modifications needed for a specific metadata table,
/// including size changes and replacement requirements.
#[derive(Debug, Clone)]
pub struct TableModificationRegion {
    /// The metadata table being modified.
    pub table_id: TableId,

    /// Original offset of this table in the file.
    /// Calculated during layout planning.
    pub original_offset: u64,

    /// Original size of this table in bytes.
    /// Based on original row count and row size.
    pub original_size: u64,

    /// New size needed for this table after modifications.
    /// Accounts for added, modified, or deleted rows.
    pub new_size: u64,

    /// Whether the table content needs to be completely replaced.
    /// True for replaced tables, false for sparse modifications.
    pub needs_replacement: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CilAssemblyView;
    use std::path::Path;

    #[test]
    fn test_create_layout_plan() {
        let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))
            .expect("Failed to load test assembly");
        let assembly = view.to_owned();

        let result = LayoutPlan::create(&assembly);
        assert!(result.is_ok(), "Layout plan creation should succeed");

        let plan = result.unwrap();
        assert!(plan.original_size > 0, "Original size should be positive");
        assert!(
            plan.total_size > 0,
            "Total size should be positive. Got: total={}, original={}",
            plan.total_size,
            plan.original_size
        );
    }

    #[test]
    fn test_layout_plan_basic_properties() {
        let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))
            .expect("Failed to load test assembly");
        let assembly = view.to_owned();

        let layout_plan = LayoutPlan::create(&assembly).expect("Failed to create layout plan");

        // Basic sanity checks
        assert!(
            layout_plan.total_size > 0,
            "Total size should be positive. Got: total={}, original={}",
            layout_plan.total_size,
            layout_plan.original_size
        );
        assert!(
            layout_plan.original_size > 0,
            "Original size should be positive"
        );
        assert!(
            !layout_plan.file_layout.sections.is_empty(),
            "Should have sections in file layout"
        );
    }
}
