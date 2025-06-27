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
//! - [`crate::cilassembly::write::planner::calc`] - Size calculation utilities module
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

use crate::{
    cilassembly::{
        write::utils::{calculate_table_row_size, find_metadata_section},
        CilAssembly, TableModifications,
    },
    metadata::tables::TableId,
    Error, Result,
};
use goblin::pe::data_directories::DataDirectoryType;

mod calc;
mod metadata;
mod pe;

pub use calc::HeapExpansions;
pub use metadata::{MetadataModifications, StreamModification};

/// Layout plan for section-by-section copy with proper relocations.
///
/// This comprehensive plan contains all information needed for binary generation,
/// including file structure calculations, PE header updates, and metadata modifications.
/// It serves as the complete blueprint for transforming a modified assembly into
/// a valid binary file.
///
/// # Structure
/// The plan calculates the complete new file structure including:
/// - PE section relocations when metadata grows
/// - New stream offsets after section relocation
/// - Updated metadata root structure
/// - Complete file layout from start to finish
/// - All required PE header modifications
///
/// # Usage
/// Created by [`crate::cilassembly::write::planner::create_layout_plan`] and used
/// throughout the binary generation pipeline to coordinate all writing operations.
#[derive(Debug, Clone)]
pub struct LayoutPlan {
    /// Total size needed for the output file in bytes.
    /// Calculated from the complete file layout including all expansions.
    pub total_size: u64,

    /// Size of the original file in bytes.
    /// Used for comparison and validation purposes.
    pub original_size: u64,

    /// Complete file layout plan with section placements.
    /// Contains detailed structure of the entire output file.
    pub file_layout: FileLayout,

    /// PE structure updates needed for header modifications.
    /// Specifies what changes are required in PE headers and section table.
    pub pe_updates: PeUpdates,

    /// Metadata modifications that need to be applied.
    /// Contains detailed information about metadata root and stream changes.
    pub metadata_modifications: MetadataModifications,

    /// Heap expansion information with calculated sizes.
    /// Provides size calculations for all metadata heap additions.
    pub heap_expansions: HeapExpansions,

    /// Table modification regions requiring updates.
    /// Contains information about modified metadata tables.
    pub table_modifications: Vec<TableModificationRegion>,

    /// Native PE table requirements for import/export table generation.
    /// Contains space allocation and placement information for native PE tables.
    pub native_table_requirements: NativeTableRequirements,
}

/// Complete file layout plan showing where everything goes in the new file.
///
/// This structure provides the detailed layout of the entire output file,
/// including PE headers, section table, and all sections with their
/// calculated positions and sizes.
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

/// Layout of a single section in the new file.
///
/// Contains the complete layout information for an individual PE section,
/// including its position, size, and metadata stream details if applicable.
#[derive(Debug, Clone)]
pub struct SectionFileLayout {
    /// Section name (e.g., ".text", ".rsrc", ".reloc").
    pub name: String,

    /// Location in the new file with offset and size.
    /// May differ from original if section was relocated or resized.
    pub file_region: FileRegion,

    /// Virtual address where section is loaded in memory.
    /// May be updated if section was moved during layout planning.
    pub virtual_address: u32,

    /// Virtual size of section in memory.
    /// May be updated if section grew due to metadata additions.
    pub virtual_size: u32,

    /// Section characteristics flags from PE specification.
    /// Preserved from original section headers.
    pub characteristics: u32,

    /// Whether this section contains .NET metadata that needs updating.
    /// True for sections containing metadata streams.
    pub contains_metadata: bool,

    /// If this section contains metadata, the layout of metadata streams.
    /// Empty for non-metadata sections.
    pub metadata_streams: Vec<StreamFileLayout>,
}

/// Layout of a metadata stream in the new file.
///
/// Contains the layout information for an individual metadata stream
/// within a metadata-containing section.
#[derive(Debug, Clone)]
pub struct StreamFileLayout {
    /// Stream name (e.g., "#Strings", "#Blob", "#GUID", "#US", "#~").
    pub name: String,

    /// Location in the new file with absolute offset and aligned size.
    pub file_region: FileRegion,

    /// Actual stream size in bytes (may be larger than original).
    /// Does not include alignment padding.
    pub size: u32,

    /// Whether this stream has additional data appended beyond original content.
    /// True for modified heaps with new entries.
    pub has_additions: bool,
}

/// A region within the file with start and size.
///
/// Represents a contiguous region of bytes within the output file,
/// used for positioning various file components.
#[derive(Debug, Clone)]
pub struct FileRegion {
    /// Start offset in the file in bytes from beginning.
    pub offset: u64,

    /// Size of the region in bytes.
    pub size: u64,
}

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

/// Creates a layout plan for copy-with-modifications approach.
///
/// This function performs comprehensive analysis of assembly changes and creates
/// a complete layout plan for binary generation. It calculates all required
/// modifications, expansions, and relocations needed to produce a valid output file.
///
/// # Arguments
/// * `assembly` - The [`crate::cilassembly::CilAssembly`] containing modifications to analyze
///
/// # Returns
/// Returns a complete [`crate::cilassembly::write::planner::LayoutPlan`] with all layout information.
///
/// # Errors
/// Returns [`crate::Error`] if layout planning fails due to invalid assembly structure
/// or calculation errors.
///
/// # Process
/// 1. Analyzes heap expansions and metadata modifications
/// 2. Calculates section relocations and size changes
/// 3. Determines PE header updates required
/// 4. Creates complete file layout with proper alignment
pub fn create_layout_plan(assembly: &CilAssembly) -> Result<LayoutPlan> {
    let mut planner = LayoutPlanner::new(assembly);
    planner.create_plan()
}

/// Internal state for copy-first layout planning.
///
/// Maintains the state and calculations needed during the layout planning process.
struct LayoutPlanner<'a> {
    assembly: &'a CilAssembly,
}

impl<'a> LayoutPlanner<'a> {
    fn new(assembly: &'a CilAssembly) -> Self {
        Self { assembly }
    }

    fn create_plan(&mut self) -> Result<LayoutPlan> {
        // Get the original file size from the assembly view
        let original_size = self.get_original_file_size()?;

        // Calculate heap expansions needed
        let heap_expansions = calc::calculate_heap_expansions(self.assembly)?;

        // Identify metadata modifications needed
        let metadata_modifications = metadata::identify_metadata_modifications(self.assembly)?;

        // Identify table modification regions
        let table_modifications = self.identify_table_modifications()?;

        // Calculate native PE table requirements
        let native_table_requirements = self.calculate_native_table_requirements()?;

        // Calculate complete file layout with proper section placement
        let mut file_layout =
            self.calculate_file_layout(&heap_expansions, &metadata_modifications)?;

        // Update file layout to accommodate native table requirements
        self.update_layout_for_native_tables(&mut file_layout, &native_table_requirements)?;

        // Determine PE updates needed
        let pe_updates = self.calculate_pe_updates(&file_layout)?;

        // Recalculate total size based on file layout and native table requirements
        let total_size =
            self.calculate_total_size_from_layout(&file_layout, &native_table_requirements);

        Ok(LayoutPlan {
            total_size,
            original_size,
            file_layout,
            pe_updates,
            metadata_modifications,
            heap_expansions,
            table_modifications,
            native_table_requirements,
        })
    }

    fn get_original_file_size(&self) -> Result<u64> {
        let file_data = self.assembly.view().data();
        Ok(file_data.len() as u64)
    }

    fn identify_table_modifications(&self) -> Result<Vec<TableModificationRegion>> {
        let changes = self.assembly.changes();
        let mut table_modifications = Vec::new();

        for table_id in changes.modified_tables() {
            if let Some(table_mod) = changes.get_table_modifications(table_id) {
                let modification_region =
                    self.create_table_modification_region(table_id, table_mod)?;
                table_modifications.push(modification_region);
            }
        }

        Ok(table_modifications)
    }

    fn create_table_modification_region(
        &self,
        table_id: TableId,
        table_mod: &TableModifications,
    ) -> Result<TableModificationRegion> {
        let view = self.assembly.view();
        let tables = view.tables().ok_or_else(|| Error::WriteLayoutFailed {
            message: "No tables found in assembly".to_string(),
        })?;

        let original_row_count = tables.table_row_count(table_id);
        let row_size = calculate_table_row_size(table_id, &tables.info);
        let original_size = original_row_count as u64 * row_size as u64;

        let new_row_count = calc::calculate_new_row_count(self.assembly, table_id, table_mod)?;
        let new_size = new_row_count as u64 * row_size as u64;

        let needs_replacement = matches!(table_mod, TableModifications::Replaced(_));
        Ok(TableModificationRegion {
            table_id,
            original_offset: 0, // Will be calculated during actual writing
            original_size,
            new_size,
            needs_replacement,
        })
    }

    /// Calculates native PE table requirements for import/export tables.
    fn calculate_native_table_requirements(&self) -> Result<NativeTableRequirements> {
        let mut requirements = NativeTableRequirements::default();

        if let Some(imports) = self.assembly.native_imports() {
            if !imports.native().is_empty() {
                requirements.needs_import_tables = true;

                let is_pe32_plus = self.is_pe32_plus_format()?;
                match imports.native().get_import_table_data(is_pe32_plus) {
                    Ok(import_data) => {
                        requirements.import_table_size = import_data.len() as u64;
                    }
                    Err(_) => {
                        // If table generation fails, estimate conservatively
                        // Each DLL needs ~64 bytes + function names + descriptors
                        let dll_count = imports.native().dll_count();
                        let function_count = imports.native().total_function_count();
                        requirements.import_table_size =
                            (dll_count * 64 + function_count * 32 + 1024) as u64;
                    }
                }
            }
        }

        if let Some(exports) = self.assembly.native_exports() {
            if !exports.native().is_empty() {
                requirements.needs_export_tables = true;

                match exports.native().get_export_table_data() {
                    Ok(export_data) => {
                        requirements.export_table_size = export_data.len() as u64;
                    }
                    Err(_) => {
                        // If table generation fails, estimate conservatively
                        // Export directory + function addresses + names + ordinals
                        let function_count = exports.native().function_count();
                        requirements.export_table_size = (40 + function_count * 16 + 512) as u64;
                        // 40 = sizeof(IMAGE_EXPORT_DIRECTORY)
                    }
                }
            }
        }

        self.calculate_native_table_rvas(&mut requirements)?;

        Ok(requirements)
    }

    /// Calculates optimal RVAs for native PE tables.
    ///
    /// This method implements the following allocation strategy:
    /// 1. Try to reuse existing import/export table locations if space allows
    /// 2. Find available space within existing sections
    /// 3. Allocate new space at the end of the file if needed
    ///
    /// The method ensures that import and export table RVAs don't overlap
    /// by tracking allocated regions and adjusting subsequent allocations.
    ///
    /// # Arguments
    /// * `requirements` - Mutable reference to native table requirements
    ///
    /// # Returns
    /// Returns `Ok(())` if RVA allocation succeeded.
    ///
    /// # Errors
    /// Returns [`crate::Error::WriteLayoutFailed`] if no suitable RVA can be found.
    fn calculate_native_table_rvas(
        &self,
        requirements: &mut NativeTableRequirements,
    ) -> Result<()> {
        let view = self.assembly.view();

        let (existing_import_rva, existing_import_size) = view
            .file()
            .get_data_directory(DataDirectoryType::ImportTable)
            .map_or((None, 0), |(rva, size)| (Some(rva), size));
        let (existing_export_rva, existing_export_size) = view
            .file()
            .get_data_directory(DataDirectoryType::ExportTable)
            .map_or((None, 0), |(rva, size)| (Some(rva), size));

        // Track allocated regions to prevent overlaps
        let mut allocated_regions: Vec<(u32, u32)> = Vec::new();

        if requirements.needs_import_tables {
            requirements.import_table_rva = self.calculate_table_rva(
                existing_import_rva,
                existing_import_size,
                requirements.import_table_size,
                &allocated_regions,
            )?;

            // Add the import table region to exclusions
            if let Some(import_rva) = requirements.import_table_rva {
                allocated_regions.push((import_rva, requirements.import_table_size as u32));
            }
        }

        if requirements.needs_export_tables {
            requirements.export_table_rva = self.calculate_table_rva(
                existing_export_rva,
                existing_export_size,
                requirements.export_table_size,
                &allocated_regions,
            )?;
        }

        Ok(())
    }

    /// Calculates RVA for a specific table (import or export) with collision avoidance.
    ///
    /// Implements the allocation strategy while avoiding conflicts with already allocated regions:
    /// 1. If existing location has sufficient space and no conflicts, reuse it
    /// 2. If no existing location, find space within a suitable section that doesn't conflict
    /// 3. As last resort, allocate at end of last section with proper spacing
    fn calculate_table_rva(
        &self,
        existing_rva: Option<u32>,
        existing_size: u32,
        required_size: u64,
        allocated_regions: &[(u32, u32)],
    ) -> Result<Option<u32>> {
        let required_size_u32 = required_size as u32;

        // Strategy 1: Try to reuse existing location if space allows and no conflicts
        if let Some(rva) = existing_rva {
            if existing_size >= required_size_u32
                && !self.conflicts_with_regions(rva, required_size_u32, allocated_regions)
            {
                return Ok(Some(rva));
            }

            if let Ok(available_space) = self.get_available_space_after_rva(rva, existing_size) {
                let total_available = existing_size + available_space;
                if total_available >= required_size_u32
                    && !self.conflicts_with_regions(rva, required_size_u32, allocated_regions)
                {
                    return Ok(Some(rva));
                }
            }
        }

        // Strategy 2: Find space within existing sections that doesn't conflict
        if let Some(rva) = self.find_space_in_sections(required_size_u32, allocated_regions)? {
            return Ok(Some(rva));
        }

        // Strategy 3: Allocate at end of sections within boundaries, avoiding conflicts
        if let Ok(rva) = self.allocate_at_end_of_sections(required_size_u32, allocated_regions) {
            return Ok(Some(rva));
        }

        // Strategy 4: Extend a suitable section to make space, avoiding conflicts
        let rva = self.extend_section_for_allocation(required_size_u32, allocated_regions)?;
        Ok(Some(rva))
    }

    /// Checks if a region conflicts with any allocated regions.
    fn conflicts_with_regions(
        &self,
        rva: u32,
        size: u32,
        allocated_regions: &[(u32, u32)],
    ) -> bool {
        let end_rva = rva + size;
        for &(allocated_rva, allocated_size) in allocated_regions {
            let allocated_end = allocated_rva + allocated_size;
            if rva < allocated_end && end_rva > allocated_rva {
                return true;
            }
        }
        false
    }

    /// Gets genuinely available space after a specific RVA within the same section.
    ///
    /// This method now properly checks for actual padding bytes (0x00 or 0xCC)
    /// after the specified RVA to determine how much space is genuinely available
    /// for reuse.
    fn get_available_space_after_rva(&self, rva: u32, used_size: u32) -> Result<u32> {
        let view = self.assembly.view();
        let file = view.file();

        for section in file.sections() {
            let section_start = section.virtual_address;
            let section_end = section.virtual_address + section.virtual_size;

            if rva >= section_start && rva < section_end {
                let table_end = rva + used_size;

                if table_end > section_end {
                    return Ok(0);
                }

                return self.get_padding_space_after_rva(section, table_end, section_end);
            }
        }

        Err(Error::WriteLayoutFailed {
            message: format!("Could not find section containing RVA 0x{rva:x}"),
        })
    }

    /// Gets contiguous padding space after a specific RVA within a section.
    ///
    /// This method analyzes the section content starting from the given RVA
    /// to find how many contiguous padding bytes (0x00 or 0xCC) are available.
    fn get_padding_space_after_rva(
        &self,
        section: &goblin::pe::section_table::SectionTable,
        start_rva: u32,
        section_end_rva: u32,
    ) -> Result<u32> {
        let view = self.assembly.view();
        let file = view.file();

        if section.size_of_raw_data == 0 {
            return Ok(0);
        }

        let start_file_offset = match file.rva_to_offset(start_rva as usize) {
            Ok(offset) => offset,
            Err(_) => return Ok(0),
        };

        let section_file_offset = match file.rva_to_offset(section.virtual_address as usize) {
            Ok(offset) => offset,
            Err(_) => return Ok(0),
        };

        let offset_in_section = start_file_offset.saturating_sub(section_file_offset);
        if offset_in_section >= section.size_of_raw_data as usize {
            return Ok(0);
        }

        let remaining_raw_size =
            (section.size_of_raw_data as usize).saturating_sub(offset_in_section);
        if remaining_raw_size == 0 {
            return Ok(0);
        }

        let section_data = match file.data_slice(start_file_offset, remaining_raw_size) {
            Ok(data) => data,
            Err(_) => return Ok(0),
        };

        let mut padding_count = 0;
        for &byte in section_data {
            if byte == 0x00 || byte == 0xCC {
                padding_count += 1;
            } else {
                break;
            }
        }

        let max_rva_space = section_end_rva.saturating_sub(start_rva);
        let padding_rva_space = std::cmp::min(padding_count as u32, max_rva_space);

        Ok(padding_rva_space)
    }

    /// Finds available space within existing sections for a table.
    ///
    /// This method now properly checks for actual padding bytes (0x00 or 0xCC)
    /// to ensure the space is genuinely available, not just theoretically unused.
    fn find_space_in_sections(
        &self,
        required_size: u32,
        allocated_regions: &[(u32, u32)],
    ) -> Result<Option<u32>> {
        let view = self.assembly.view();
        let file = view.file();
        let preferred_sections = [".text", ".rdata", ".data"];

        for section in file.sections() {
            let section_name = std::str::from_utf8(&section.name)
                .unwrap_or("")
                .trim_end_matches('\0');

            let is_preferred = preferred_sections.contains(&section_name);
            if is_preferred {
                if let Some(allocation_rva) =
                    self.find_padding_space_in_section(section, required_size)?
                {
                    if !self.conflicts_with_regions(
                        allocation_rva,
                        required_size,
                        allocated_regions,
                    ) {
                        return Ok(Some(allocation_rva));
                    }
                }
            }
        }

        Ok(None)
    }

    /// Allocates space at the end of sections, but only within section boundaries.
    ///
    /// This method attempts to find space at the end of sections without creating
    /// overlay data outside proper PE section boundaries. It fails if no suitable
    /// space is found within section limits.
    fn allocate_at_end_of_sections(
        &self,
        required_size: u32,
        allocated_regions: &[(u32, u32)],
    ) -> Result<u32> {
        let view = self.assembly.view();
        let file = view.file();

        let mut sections: Vec<_> = file.sections().collect();
        sections.sort_by_key(|s| std::cmp::Reverse(s.virtual_address));

        for section in sections {
            let raw_data_end = section.virtual_address + section.size_of_raw_data;
            let virtual_end = section.virtual_address + section.virtual_size;

            let available_space = virtual_end.saturating_sub(raw_data_end);
            if available_space >= required_size {
                // Align to 8-byte boundary for PE tables
                let aligned_rva = (raw_data_end + 7) & !7;
                if aligned_rva + required_size <= virtual_end
                    && !self.conflicts_with_regions(aligned_rva, required_size, allocated_regions)
                {
                    return Ok(aligned_rva);
                }
            }
        }

        Err(Error::WriteLayoutFailed {
            message: format!(
                "No space available within section boundaries for {required_size} bytes allocation. \
                 Consider expanding section virtual sizes or using a different allocation strategy."
            ),
        })
    }

    /// Allocates space by extending the last section.
    ///
    /// This method allocates space at the end of the last section, expanding
    /// the file size as needed. The new file size will be calculated to accommodate
    /// this allocation.
    fn extend_section_for_allocation(
        &self,
        _required_size: u32,
        allocated_regions: &[(u32, u32)],
    ) -> Result<u32> {
        let view = self.assembly.view();
        let file = view.file();

        // Find the last section (highest virtual address + virtual size)
        let mut last_section = None;
        let mut highest_end = 0;

        for section in file.sections() {
            let section_end = section.virtual_address + section.virtual_size;
            if section_end >= highest_end {
                highest_end = section_end;
                last_section = Some(section);
            }
        }

        if let Some(_section) = last_section {
            let mut actual_end = highest_end;
            for &(allocated_rva, allocated_size) in allocated_regions {
                let allocated_end = allocated_rva + allocated_size;
                if allocated_end > actual_end {
                    actual_end = allocated_end;
                }
            }

            let allocation_rva = actual_end;
            let aligned_rva = (allocation_rva + 7) & !7;

            // This allocation will be handled by extending the total file size
            // and updating the section virtual size in update_layout_for_native_tables
            Ok(aligned_rva)
        } else {
            Err(Error::WriteLayoutFailed {
                message: "No sections found for native table allocation".to_string(),
            })
        }
    }

    /// Finds contiguous padding space within a section.
    ///
    /// This method analyzes the actual section content byte-by-byte to find
    /// contiguous areas of padding bytes (0x00 or 0xCC) that are large enough
    /// for the required allocation. This ensures we only allocate in genuinely
    /// available space, not just theoretically unused space.
    fn find_padding_space_in_section(
        &self,
        section: &goblin::pe::section_table::SectionTable,
        required_size: u32,
    ) -> Result<Option<u32>> {
        let view = self.assembly.view();
        let file = view.file();

        if section.size_of_raw_data == 0 {
            return Ok(None);
        }

        let section_file_offset = match file.rva_to_offset(section.virtual_address as usize) {
            Ok(offset) => offset,
            Err(_) => {
                return Ok(None);
            }
        };

        let section_data =
            match file.data_slice(section_file_offset, section.size_of_raw_data as usize) {
                Ok(data) => data,
                Err(_) => {
                    return Ok(None);
                }
            };

        let aligned_required_size = ((required_size + 7) & !7) as usize;

        let mut current_padding_start = None;
        let mut current_padding_length = 0;
        for (i, &byte) in section_data.iter().enumerate() {
            if byte == 0x00 || byte == 0xCC {
                if current_padding_start.is_none() {
                    current_padding_start = Some(i);
                    current_padding_length = 1;
                } else {
                    current_padding_length += 1;
                }

                if current_padding_length >= aligned_required_size {
                    let padding_start_offset = current_padding_start.unwrap();
                    let aligned_start = (padding_start_offset + 7) & !7;
                    if aligned_start + aligned_required_size
                        <= padding_start_offset + current_padding_length
                    {
                        let allocation_rva = section.virtual_address + aligned_start as u32;

                        if allocation_rva + required_size
                            <= section.virtual_address + section.virtual_size
                        {
                            return Ok(Some(allocation_rva));
                        }
                    }
                }
            } else {
                current_padding_start = None;
                current_padding_length = 0;
            }
        }

        Ok(None)
    }

    /// Calculates the complete file layout with proper section placement.
    fn calculate_file_layout(
        &self,
        heap_expansions: &HeapExpansions,
        metadata_modifications: &MetadataModifications,
    ) -> Result<FileLayout> {
        let view = self.assembly.view();

        // Start with PE headers layout (these don't move)
        let dos_header = FileRegion {
            offset: 0,
            size: 64,
        }; // Standard DOS header size

        // Find PE signature offset from DOS header
        let pe_sig_offset = pe::get_pe_signature_offset(self.assembly)?;
        let pe_headers = FileRegion {
            offset: pe_sig_offset,
            size: pe::calculate_pe_headers_size(self.assembly)?,
        };

        let section_table = FileRegion {
            offset: pe_headers.offset + pe_headers.size,
            size: (view.file().sections().count() * 40) as u64, // 40 bytes per section entry
        };

        // Calculate section layouts with potential relocations
        let sections = self.calculate_section_layouts(heap_expansions, metadata_modifications)?;

        Ok(FileLayout {
            dos_header,
            pe_headers,
            section_table,
            sections,
        })
    }

    /// Calculates PE updates needed after section relocations.
    fn calculate_pe_updates(&self, file_layout: &FileLayout) -> Result<PeUpdates> {
        let view = self.assembly.view();
        let original_sections: Vec<_> = view.file().sections().collect();

        let mut section_updates = Vec::new();
        let mut section_table_needs_update = false;

        for (index, new_section) in file_layout.sections.iter().enumerate() {
            if let Some(original_section) = original_sections.get(index) {
                let mut update = SectionUpdate {
                    section_index: index,
                    new_file_offset: None,
                    new_file_size: None,
                    new_virtual_size: None,
                };

                // Check if file offset changed
                if new_section.file_region.offset != original_section.pointer_to_raw_data as u64 {
                    update.new_file_offset = Some(new_section.file_region.offset);
                    section_table_needs_update = true;
                }

                // Check if file size changed
                if new_section.file_region.size != original_section.size_of_raw_data as u64 {
                    update.new_file_size = Some(new_section.file_region.size as u32);
                    section_table_needs_update = true;
                }

                // Check if virtual size changed
                if new_section.virtual_size != original_section.virtual_size {
                    update.new_virtual_size = Some(new_section.virtual_size);
                    section_table_needs_update = true;
                }

                // Only add update if something changed
                if update.new_file_offset.is_some()
                    || update.new_file_size.is_some()
                    || update.new_virtual_size.is_some()
                {
                    section_updates.push(update);
                }
            }
        }

        Ok(PeUpdates {
            section_table_needs_update,
            checksum_needs_update: section_table_needs_update, // Update checksum if sections changed
            section_updates,
        })
    }

    /// Calculates total file size from the complete file layout and native table requirements.
    fn calculate_total_size_from_layout(
        &self,
        file_layout: &FileLayout,
        native_requirements: &NativeTableRequirements,
    ) -> u64 {
        // Find the maximum end offset of all regions
        let mut max_end = 0u64;

        max_end = max_end.max(file_layout.dos_header.offset + file_layout.dos_header.size);
        max_end = max_end.max(file_layout.pe_headers.offset + file_layout.pe_headers.size);
        max_end = max_end.max(file_layout.section_table.offset + file_layout.section_table.size);

        for section in &file_layout.sections {
            max_end = max_end.max(section.file_region.offset + section.file_region.size);
        }

        // Account for native table space requirements
        if let Some(import_rva) = native_requirements.import_table_rva {
            if let Ok(import_offset) = self.rva_to_file_offset_for_planning(import_rva) {
                let import_end = import_offset + native_requirements.import_table_size;
                max_end = max_end.max(import_end);
            }
        }

        if let Some(export_rva) = native_requirements.export_table_rva {
            if let Ok(export_offset) = self.rva_to_file_offset_for_planning(export_rva) {
                let export_end = export_offset + native_requirements.export_table_size;
                max_end = max_end.max(export_end);
            }
        }

        max_end
    }

    /// Converts RVA to file offset for planning purposes.
    ///
    /// This is a simplified version that assumes a 1:1 mapping for new allocations
    /// beyond existing sections. For existing sections, it uses the section mapping.
    fn rva_to_file_offset_for_planning(&self, rva: u32) -> Result<u64> {
        let view = self.assembly.view();
        let file = view.file();

        for section in file.sections() {
            let section_start = section.virtual_address;
            let section_end = section.virtual_address + section.virtual_size;

            if rva >= section_start && rva < section_end {
                let offset_in_section = rva - section_start;
                let file_offset = section.pointer_to_raw_data as u64 + offset_in_section as u64;
                return Ok(file_offset);
            }
        }

        // RVA is beyond existing sections - assume 1:1 mapping for simplicity
        // This is a conservative approach for newly allocated space
        Ok(rva as u64)
    }

    /// Calculates section layouts, potentially relocating sections if metadata grows.
    fn calculate_section_layouts(
        &self,
        heap_expansions: &HeapExpansions,
        metadata_modifications: &MetadataModifications,
    ) -> Result<Vec<SectionFileLayout>> {
        let view = self.assembly.view();
        let original_sections: Vec<_> = view.file().sections().collect();
        let mut new_sections = Vec::new();

        // Start sections after section table
        let section_table_end =
            pe::calculate_pe_headers_size(self.assembly)? + (original_sections.len() * 40) as u64;
        let mut current_offset = pe::align_to_file_alignment(section_table_end);

        for original_section in original_sections.iter() {
            // Convert section name from byte array to string
            let section_name = std::str::from_utf8(&original_section.name)
                .unwrap_or("<invalid>")
                .trim_end_matches('\0');
            let contains_metadata = view.file().section_contains_metadata(section_name);
            let section_name = section_name.to_string();

            let (new_size, metadata_streams) = if contains_metadata {
                // This section contains .NET metadata - calculate new size with expansions
                let metadata_streams = self.calculate_metadata_stream_layouts(
                    current_offset,
                    heap_expansions,
                    metadata_modifications,
                )?;

                let metadata_size: u64 = metadata_streams
                    .iter()
                    .map(|stream| stream.file_region.offset + stream.file_region.size)
                    .max()
                    .unwrap_or(current_offset)
                    - current_offset;

                (metadata_size, metadata_streams)
            } else {
                // Non-metadata section - keep original size
                (original_section.size_of_raw_data as u64, Vec::new())
            };

            let file_region = FileRegion {
                offset: current_offset,
                size: new_size,
            };

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
            current_offset = pe::align_to_file_alignment(current_offset + new_size);
        }

        Ok(new_sections)
    }

    /// Updates the file layout to accommodate native table allocations.
    ///
    /// This method extends section virtual sizes when native tables are allocated
    /// beyond the current section boundaries.
    fn update_layout_for_native_tables(
        &self,
        file_layout: &mut FileLayout,
        native_requirements: &NativeTableRequirements,
    ) -> Result<()> {
        for section in &mut file_layout.sections {
            let section_start = section.virtual_address;
            let mut section_end = section_start + section.virtual_size;
            let mut needs_extension = false;

            if let Some(import_rva) = native_requirements.import_table_rva {
                if import_rva >= section_start && (import_rva <= section_end) {
                    let required_end = import_rva + native_requirements.import_table_size as u32;
                    if required_end > section_end {
                        section_end = std::cmp::max(section_end, required_end);
                        needs_extension = true;
                    }
                }
            }

            if let Some(export_rva) = native_requirements.export_table_rva {
                if export_rva >= section_start && (export_rva <= section_end) {
                    let required_end = export_rva + native_requirements.export_table_size as u32;
                    if required_end > section_end {
                        section_end = std::cmp::max(section_end, required_end);
                        needs_extension = true;
                    }
                }
            }

            if needs_extension {
                let new_virtual_size = section_end - section_start;
                let size_increase = new_virtual_size - section.virtual_size;

                section.virtual_size = new_virtual_size;
                section.file_region.size += size_increase as u64;
            }
        }

        Ok(())
    }

    /// Calculates metadata stream layouts within a section.
    fn calculate_metadata_stream_layouts(
        &self,
        section_start_offset: u64,
        _heap_expansions: &HeapExpansions,
        metadata_modifications: &MetadataModifications,
    ) -> Result<Vec<StreamFileLayout>> {
        let view = self.assembly.view();
        let original_streams = view.streams();
        let mut stream_layouts = Vec::new();

        // Calculate the metadata root offset within the section
        let metadata_root_rva = view.cor20header().meta_data_rva as u64;
        let section_rva = pe::get_text_section_rva(self.assembly)? as u64;
        let metadata_offset_in_section = metadata_root_rva - section_rva;
        let metadata_root_offset = section_start_offset + metadata_offset_in_section;

        // Start streams after metadata root header
        let metadata_root_size = metadata::calculate_metadata_root_header_size(self.assembly)?;
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
            let aligned_size = ((new_size + 3) & !3) as u64;

            stream_layouts.push(StreamFileLayout {
                name: stream_name.clone(),
                file_region: FileRegion {
                    offset: current_stream_offset,
                    size: aligned_size,
                },
                size: new_size,
                has_additions,
            });

            current_stream_offset += aligned_size;
        }

        Ok(stream_layouts)
    }

    /// Determines if this is a PE32+ format file.
    ///
    /// Returns `true` for PE32+ (64-bit) format, `false` for PE32 (32-bit) format.
    /// This affects the size of ILT/IAT entries and ordinal import bit positions.
    ///
    /// # Returns
    /// Returns `true` if PE32+ format, `false` if PE32 format.
    ///
    /// # Errors
    /// Returns [`crate::Error`] if the PE format cannot be determined.
    fn is_pe32_plus_format(&self) -> Result<bool> {
        let view = self.assembly.view();
        let optional_header =
            view.file()
                .header_optional()
                .as_ref()
                .ok_or_else(|| Error::WriteLayoutFailed {
                    message: "Missing optional header for PE format detection in planner"
                        .to_string(),
                })?;

        // PE32 magic is 0x10b, PE32+ magic is 0x20b
        Ok(optional_header.standard_fields.magic != 0x10b)
    }
}

impl LayoutPlan {
    /// Returns the absolute file offset where the tables stream (#~ or #-) begins.
    ///
    /// This method calculates the offset by:
    /// 1. Finding the section containing metadata in the layout plan
    /// 2. Locating the tables stream within the metadata streams
    /// 3. Returning the calculated file offset for the tables stream
    ///
    /// # Arguments
    /// * `_assembly` - The [`crate::cilassembly::CilAssembly`] (currently unused)
    ///
    /// # Returns
    /// Returns the absolute file offset of the tables stream.
    ///
    /// # Errors
    /// Returns [`crate::Error::WriteLayoutFailed`] if the tables stream cannot be located.
    pub fn tables_stream_offset(&self, _assembly: &CilAssembly) -> Result<u64> {
        // Find the section containing metadata
        let metadata_section = find_metadata_section(&self.file_layout)?;

        // Find the tables stream within the metadata section
        let tables_stream = metadata_section
            .metadata_streams
            .iter()
            .find(|stream| stream.name == "#~" || stream.name == "#-")
            .ok_or_else(|| Error::WriteLayoutFailed {
                message: "Tables stream (#~ or #-) not found in metadata section".to_string(),
            })?;

        Ok(tables_stream.file_region.offset)
    }
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

        let result = create_layout_plan(&assembly);
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

        let layout_plan = create_layout_plan(&assembly).expect("Failed to create layout plan");

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
