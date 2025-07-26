//! Table modification planning and calculation utilities.
//!
//! This module provides comprehensive functionality for analyzing table modifications and calculating
//! the space requirements for native PE tables during layout planning. It handles both metadata table
//! modifications and native PE table requirements (import/export tables) for complete layout analysis.
//!
//! # Key Components
//!
//! - [`identify_table_modifications`] - Identifies all table modifications that need planning
//! - [`create_table_modification_region`] - Creates modification regions for specific tables
//! - [`calculate_native_table_requirements`] - Calculates native PE table space requirements
//! - [`allocate_native_table_rvas_with_layout`] - Allocates RVAs for native tables
//!
//! # Architecture
//!
//! The table modification planning system handles two distinct types of tables:
//!
//! ## Metadata Table Modifications
//! For .NET metadata tables:
//! - Analyzes table changes to determine size requirements
//! - Calculates original and new sizes for modified tables
//! - Identifies whether tables need complete replacement or sparse updates
//! - Creates modification regions for layout planning
//!
//! ## Native PE Table Requirements
//! For native PE tables (import/export):
//! - Analyzes assembly changes to determine if native tables are needed
//! - Calculates space requirements for import tables (IAT/ILT)
//! - Calculates space requirements for export tables (EAT)
//! - Allocates RVAs within available address space
//! - Handles proper alignment and section placement
//!
//! ## RVA Allocation Strategy
//! The system uses a multi-stage allocation approach:
//! 1. **Padding Space**: Look for padding bytes within existing sections
//! 2. **Section Boundaries**: Utilize space between raw data and virtual size
//! 3. **Section Extension**: Extend sections if no suitable space is found
//!
//! # Usage Examples
//!
//! ```rust,ignore
//! use crate::cilassembly::write::planner::tables::{
//!     identify_table_modifications, calculate_native_table_requirements
//! };
//! use crate::cilassembly::CilAssembly;
//!
//! # let mut assembly = CilAssembly::new(view);
//! // Identify table modifications
//! let table_modifications = identify_table_modifications(&assembly)?;
//! for modification in &table_modifications {
//!     println!("Table {:?}: {} -> {} bytes",
//!              modification.table_id,
//!              modification.original_size,
//!              modification.new_size);
//! }
//!
//! // Calculate native table requirements
//! let native_requirements = calculate_native_table_requirements(&mut assembly)?;
//! if native_requirements.needs_import_tables {
//!     println!("Import tables need {} bytes", native_requirements.import_table_size);
//! }
//! # Ok::<(), crate::Error>(())
//! ```
//!
//! # Thread Safety
//!
//! All functions in this module are [`Send`] and [`Sync`] as they perform analysis
//! and calculations on assembly data without maintaining mutable state.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::cilassembly::write::planner::calc`] - Size calculation utilities
//! - [`crate::cilassembly::write::planner::memory`] - Memory allocation strategies
//! - [`crate::cilassembly::write::planner::validation`] - Allocation validation
//! - [`crate::cilassembly::write::utils`] - Table row size calculations
//! - [`crate::cilassembly::changes`] - Source of modification data

use crate::{
    cilassembly::{
        write::{
            planner::{calc, memory, validation, NativeTableRequirements, TableModificationRegion},
            utils::calculate_table_row_size,
        },
        CilAssembly, TableModifications,
    },
    metadata::tables::TableId,
    Error, Result,
};
use goblin::pe::data_directories::DataDirectoryType;

/// Identifies all table modifications that need to be planned.
///
/// This function examines the assembly changes to identify which tables have been
/// modified and creates modification regions for layout planning. It analyzes both
/// sparse operations and complete table replacements to determine space requirements.
///
/// # Arguments
///
/// * `assembly` - The [`crate::cilassembly::CilAssembly`] to analyze for table modifications
///
/// # Returns
///
/// Returns a [`Vec`] of [`crate::cilassembly::write::planner::TableModificationRegion`] instances
/// representing all tables that require layout planning.
///
/// # Errors
///
/// Returns [`crate::Error`] if there are issues accessing table information or
/// calculating modification requirements.
///
/// # Examples
///
/// ```rust,ignore
/// use crate::cilassembly::write::planner::tables::identify_table_modifications;
/// use crate::cilassembly::CilAssembly;
///
/// # let assembly = CilAssembly::new(view);
/// // Identify all table modifications
/// let table_modifications = identify_table_modifications(&assembly)?;
///
/// for modification in &table_modifications {
///     println!("Table {:?}: {} -> {} bytes",
///              modification.table_id,
///              modification.original_size,
///              modification.new_size);
/// }
/// # Ok::<(), crate::Error>(())
/// ```
pub fn identify_table_modifications(
    assembly: &CilAssembly,
) -> Result<Vec<TableModificationRegion>> {
    let changes = assembly.changes();
    let mut table_modifications = Vec::new();

    for table_id in changes.modified_tables() {
        if let Some(table_mod) = changes.get_table_modifications(table_id) {
            let modification_region =
                create_table_modification_region(assembly, table_id, table_mod)?;
            table_modifications.push(modification_region);
        }
    }

    Ok(table_modifications)
}

/// Creates a table modification region for a specific table.
///
/// This function calculates the original and new sizes for a modified table
/// to determine the space requirements during layout planning.
///
/// # Arguments
/// * `assembly` - The assembly containing the table
/// * `table_id` - The ID of the table being modified
/// * `table_mod` - The modifications being applied to the table
///
/// # Returns
/// Returns a table modification region with size calculations.
pub fn create_table_modification_region(
    assembly: &CilAssembly,
    table_id: TableId,
    table_mod: &TableModifications,
) -> Result<TableModificationRegion> {
    let view = assembly.view();
    let tables = view.tables().ok_or_else(|| Error::WriteLayoutFailed {
        message: "No tables found in assembly".to_string(),
    })?;

    let original_row_count = tables.table_row_count(table_id);
    let row_size = calculate_table_row_size(table_id, &tables.info);
    let original_size = u64::from(original_row_count) * u64::from(row_size);

    let new_row_count = calc::calculate_new_row_count(assembly, table_id, table_mod)?;
    let new_size = u64::from(new_row_count) * u64::from(row_size);

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
///
/// This function analyzes the assembly's changes to determine if native tables
/// are needed and calculates their sizes. RVA allocation is done separately
/// after the file layout is calculated.
///
/// # Arguments
/// * `assembly` - The assembly to analyze for native table requirements
///
/// # Returns
/// Returns native table requirements with size calculations only (no RVA allocations).
pub fn calculate_native_table_requirements(
    assembly: &mut CilAssembly,
) -> Result<NativeTableRequirements> {
    let mut requirements = NativeTableRequirements::default();
    let has_changes = assembly.changes().has_changes();
    if !has_changes {
        return Ok(requirements);
    }

    let has_import_changes = !assembly.changes().native_imports.native().is_empty();
    if has_import_changes {
        requirements.needs_import_tables = true;

        let file_ref = assembly.view.file().clone();
        if let Some(goblin_imports) = file_ref.imports() {
            if !goblin_imports.is_empty() {
                assembly
                    .changes
                    .native_imports
                    .native_mut()
                    .populate_from_goblin(goblin_imports)?;
            }
        }

        let imports = &assembly.changes().native_imports;
        let is_pe32_plus = assembly.file().is_pe32_plus_format()?;

        match imports.native().get_import_table_data(is_pe32_plus) {
            Ok(import_data) => {
                requirements.import_table_size = import_data.len() as u64;
            }
            Err(_) => {
                // If table generation fails, estimate conservatively using unified data
                let dll_count = imports.native().dll_count();
                let function_count = imports.native().total_function_count();
                requirements.import_table_size =
                    (dll_count * 64 + function_count * 32 + 1024) as u64;
            }
        }
    }

    let has_export_changes = !assembly.changes().native_exports.native().is_empty();
    if has_export_changes {
        requirements.needs_export_tables = true;

        let file_ref = assembly.view.file().clone();
        if let Some(goblin_exports) = file_ref.exports() {
            if !goblin_exports.is_empty() {
                assembly
                    .changes
                    .native_exports
                    .native_mut()
                    .populate_from_goblin(goblin_exports)?;
            }
        }

        let exports = &assembly.changes().native_exports;
        match exports.native().get_export_table_data() {
            Ok(export_data) => {
                requirements.export_table_size = export_data.len() as u64;
            }
            Err(_) => {
                // Conservative estimation using unified data
                let function_count = exports.native().function_count();
                requirements.export_table_size = (40 + function_count * 16 + 512) as u64;
            }
        }
    }

    // Note: RVA allocation is done separately after file layout calculation
    Ok(requirements)
}

/// Allocates RVAs for native PE tables using the complete file layout.
///
/// This function allocates RVAs for native tables after the file layout
/// has been calculated, ensuring that the allocation considers the new
/// sections (like .meta) that are created during layout planning.
///
/// # Arguments
/// * `assembly` - The assembly to analyze (for original PE data)
/// * `file_layout` - The complete file layout with all sections
/// * `requirements` - Mutable reference to native table requirements
///
/// # Returns
/// Returns `Ok(())` if RVA allocation succeeded.
pub fn allocate_native_table_rvas_with_layout(
    assembly: &CilAssembly,
    file_layout: &super::FileLayout,
    requirements: &mut NativeTableRequirements,
) -> Result<()> {
    let view = assembly.view();

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
        requirements.import_table_rva = calculate_table_rva_with_layout(
            assembly,
            file_layout,
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
        requirements.export_table_rva = calculate_table_rva_with_layout(
            assembly,
            file_layout,
            existing_export_rva,
            existing_export_size,
            requirements.export_table_size,
            &allocated_regions,
        )?;
    }

    Ok(())
}

/// Calculates optimal RVAs for native PE tables (legacy function).
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
/// * `assembly` - The assembly to analyze
/// * `requirements` - Mutable reference to native table requirements
///
/// # Returns
/// Returns `Ok(())` if RVA allocation succeeded.
///
/// # Errors
/// Returns [`crate::Error::WriteLayoutFailed`] if no suitable RVA can be found.
pub fn calculate_native_table_rvas(
    assembly: &CilAssembly,
    requirements: &mut NativeTableRequirements,
) -> Result<()> {
    let view = assembly.view();

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
        requirements.import_table_rva = calculate_table_rva(
            assembly,
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
        requirements.export_table_rva = calculate_table_rva(
            assembly,
            existing_export_rva,
            existing_export_size,
            requirements.export_table_size,
            &allocated_regions,
        )?;
    }

    Ok(())
}

/// Calculates RVA for a specific table using the complete file layout.
///
/// This version uses the complete file layout (including new sections like .meta)
/// to allocate RVAs for native tables, ensuring they are placed within proper section boundaries.
///
/// # Arguments
/// * `assembly` - The assembly to analyze (for original PE data)
/// * `file_layout` - The complete file layout with all sections
/// * `existing_rva` - The existing RVA of the table (if any)
/// * `existing_size` - The existing size of the table
/// * `required_size` - The required size for the new table
/// * `allocated_regions` - Already allocated regions to avoid conflicts
///
/// # Returns
/// Returns the allocated RVA for the table, or None if no suitable location found.
pub fn calculate_table_rva_with_layout(
    assembly: &CilAssembly,
    file_layout: &super::FileLayout,
    existing_rva: Option<u32>,
    existing_size: u32,
    required_size: u64,
    allocated_regions: &[(u32, u32)],
) -> Result<Option<u32>> {
    let required_size_u32 = required_size as u32;

    // Strategy 1: Try to reuse existing location if space allows and no conflicts
    if let Some(rva) = existing_rva {
        if existing_size >= required_size_u32
            && !validation::conflicts_with_regions(rva, required_size_u32, allocated_regions)
        {
            return Ok(Some(rva));
        }

        if let Ok(available_space) =
            memory::get_available_space_after_rva(assembly, rva, existing_size)
        {
            let total_available = existing_size + available_space;
            if total_available >= required_size_u32
                && !validation::conflicts_with_regions(rva, required_size_u32, allocated_regions)
            {
                return Ok(Some(rva));
            }
        }
    }

    // Strategy 2: Find the last section in the file layout and allocate at its end
    if let Some(last_section) = file_layout.sections.last() {
        let section_end = last_section.virtual_address + last_section.virtual_size;

        // Check for conflicts with allocated regions
        let mut actual_end = section_end;
        for &(allocated_rva, allocated_size) in allocated_regions {
            let allocated_end = allocated_rva + allocated_size;
            if allocated_end > actual_end {
                actual_end = allocated_end;
            }
        }

        let allocation_rva = actual_end;
        let aligned_rva = (allocation_rva + 7) & !7;

        if !validation::conflicts_with_regions(aligned_rva, required_size_u32, allocated_regions) {
            return Ok(Some(aligned_rva));
        }
    }

    // Strategy 3: Fall back to original allocation strategy (using original sections)
    if let Some(rva) =
        memory::find_space_in_sections(assembly, required_size_u32, allocated_regions)?
    {
        return Ok(Some(rva));
    }

    if let Ok(rva) =
        memory::allocate_at_end_of_sections(assembly, required_size_u32, allocated_regions)
    {
        return Ok(Some(rva));
    }

    let rva =
        memory::extend_section_for_allocation(assembly, required_size_u32, allocated_regions)?;
    Ok(Some(rva))
}

/// Calculates RVA for a specific table (import or export) with collision avoidance.
///
/// Implements the allocation strategy while avoiding conflicts with already allocated regions:
/// 1. If existing location has sufficient space and no conflicts, reuse it
/// 2. If no existing location, find space within a suitable section that doesn't conflict
/// 3. As last resort, allocate at end of last section with proper spacing
///
/// # Arguments
/// * `assembly` - The assembly to analyze
/// * `existing_rva` - The existing RVA of the table (if any)
/// * `existing_size` - The existing size of the table
/// * `required_size` - The required size for the new table
/// * `allocated_regions` - Already allocated regions to avoid conflicts
///
/// # Returns
/// Returns the allocated RVA for the table, or None if no suitable location found.
pub fn calculate_table_rva(
    assembly: &CilAssembly,
    existing_rva: Option<u32>,
    existing_size: u32,
    required_size: u64,
    allocated_regions: &[(u32, u32)],
) -> Result<Option<u32>> {
    let required_size_u32 = required_size as u32;

    // Strategy 1: Try to reuse existing location if space allows and no conflicts
    if let Some(rva) = existing_rva {
        if existing_size >= required_size_u32
            && !validation::conflicts_with_regions(rva, required_size_u32, allocated_regions)
        {
            return Ok(Some(rva));
        }

        if let Ok(available_space) =
            memory::get_available_space_after_rva(assembly, rva, existing_size)
        {
            let total_available = existing_size + available_space;
            if total_available >= required_size_u32
                && !validation::conflicts_with_regions(rva, required_size_u32, allocated_regions)
            {
                return Ok(Some(rva));
            }
        }
    }

    // Strategy 2: Find space within existing sections that doesn't conflict
    if let Some(rva) =
        memory::find_space_in_sections(assembly, required_size_u32, allocated_regions)?
    {
        return Ok(Some(rva));
    }

    // Strategy 3: Allocate at end of sections within boundaries, avoiding conflicts
    if let Ok(rva) =
        memory::allocate_at_end_of_sections(assembly, required_size_u32, allocated_regions)
    {
        return Ok(Some(rva));
    }

    // Strategy 4: Extend a suitable section to make space, avoiding conflicts
    let rva =
        memory::extend_section_for_allocation(assembly, required_size_u32, allocated_regions)?;
    Ok(Some(rva))
}
