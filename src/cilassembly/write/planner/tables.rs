//! Table modification planning and calculation utilities.
//!
//! This module provides functionality for analyzing table modifications and calculating
//! the space requirements for native PE tables during layout planning.

use crate::{
    cilassembly::{write::utils::calculate_table_row_size, CilAssembly, TableModifications},
    metadata::tables::TableId,
    Error, Result,
};
use goblin::pe::data_directories::DataDirectoryType;

use super::{calc, memory, validation, NativeTableRequirements, TableModificationRegion};

/// Identifies all table modifications that need to be planned.
///
/// This function examines the assembly changes to identify which tables have been
/// modified and creates modification regions for layout planning.
///
/// # Arguments
/// * `assembly` - The assembly to analyze for table modifications
///
/// # Returns
/// Returns a vector of table modification regions requiring layout planning.
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
    let original_size = original_row_count as u64 * row_size as u64;

    let new_row_count = calc::calculate_new_row_count(assembly, table_id, table_mod)?;
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
///
/// This function analyzes the assembly's native imports and exports to determine
/// the space requirements for PE import and export tables during layout planning.
///
/// # Arguments
/// * `assembly` - The assembly to analyze for native table requirements
///
/// # Returns
/// Returns native table requirements with size calculations and RVA allocations.
pub fn calculate_native_table_requirements(
    assembly: &CilAssembly,
) -> Result<NativeTableRequirements> {
    let mut requirements = NativeTableRequirements::default();

    if let Some(imports) = assembly.native_imports() {
        if !imports.native().is_empty() {
            requirements.needs_import_tables = true;

            let is_pe32_plus = assembly.file().is_pe32_plus_format()?;
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

    if let Some(exports) = assembly.native_exports() {
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

    calculate_native_table_rvas(assembly, &mut requirements)?;

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
