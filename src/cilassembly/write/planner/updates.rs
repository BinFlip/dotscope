//! Layout and PE update calculation utilities.
//!
//! This module provides functionality for calculating PE header updates and modifying
//! file layouts to accommodate changes during binary generation.

use crate::{cilassembly::CilAssembly, Result};

use super::{FileLayout, NativeTableRequirements, PeUpdates, SectionUpdate};

/// Calculates PE updates needed after section relocations.
///
/// This function analyzes the changes between original and new section layouts
/// to determine what PE header updates are required during binary generation.
///
/// # Arguments
/// * `assembly` - The assembly to analyze
/// * `file_layout` - The new file layout with section changes
///
/// # Returns
/// Returns PE update requirements including section table and checksum updates.
pub fn calculate_pe_updates(assembly: &CilAssembly, file_layout: &FileLayout) -> Result<PeUpdates> {
    let view = assembly.view();
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

/// Updates the file layout to accommodate native table allocations.
///
/// This function extends section virtual sizes when native tables are allocated
/// beyond the current section boundaries.
///
/// # Arguments
/// * `file_layout` - Mutable reference to the file layout to update
/// * `native_requirements` - Native table requirements with RVA allocations
///
/// # Returns
/// Returns `Ok(())` if the layout was successfully updated.
pub fn update_layout_for_native_tables(
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
