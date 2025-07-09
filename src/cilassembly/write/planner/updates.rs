//! Layout and PE update calculation utilities.
//!
//! This module provides comprehensive functionality for calculating PE header updates and modifying
//! file layouts to accommodate changes during binary generation. It handles the complex task of
//! determining what PE structural changes are needed when sections are relocated, resized, or
//! when native tables are allocated within the file.
//!
//! # Key Components
//!
//! - [`calculate_pe_updates`] - Calculates PE header updates needed after section relocations
//! - [`update_layout_for_native_tables`] - Updates file layout to accommodate native table allocations
//!
//! # Architecture
//!
//! The PE update calculation system handles two main scenarios:
//!
//! ## Section Layout Changes
//! When sections are relocated or resized:
//! - Compares original section properties with new layout
//! - Identifies changes in file offset, file size, and virtual size
//! - Determines if PE section table needs updating
//! - Calculates checksum update requirements
//!
//! ## Native Table Accommodation
//! When native tables (import/export) are allocated:
//! - Extends section virtual sizes to encompass allocated tables
//! - Handles special cases for last section extension
//! - Updates file region sizes to match virtual size changes
//! - Maintains proper section boundaries and alignment
//!
//! ## Update Tracking
//! The system tracks all necessary updates:
//! - Section table entry modifications
//! - Checksum recalculation requirements
//! - File and virtual size adjustments
//! - Section boundary extensions
//!
//! # Usage Examples
//!
//! ```rust,ignore
//! use crate::cilassembly::write::planner::updates::{
//!     calculate_pe_updates, update_layout_for_native_tables
//! };
//! use crate::cilassembly::CilAssembly;
//! use crate::cilassembly::write::planner::{FileLayout, NativeTableRequirements};
//!
//! # let assembly = CilAssembly::new(view);
//! # let mut file_layout = FileLayout::calculate(&assembly, &heap_expansions, &mut metadata_modifications)?;
//! # let native_requirements = NativeTableRequirements::default();
//! // Calculate PE updates needed
//! let pe_updates = calculate_pe_updates(&assembly, &file_layout)?;
//! if pe_updates.section_table_needs_update {
//!     println!("PE section table needs updating");
//! }
//!
//! // Update layout for native tables
//! update_layout_for_native_tables(&mut file_layout, &native_requirements)?;
//! # Ok::<(), crate::Error>(())
//! ```
//!
//! # Thread Safety
//!
//! All functions in this module are [`Send`] and [`Sync`] as they perform analysis
//! and calculations on file layout data without maintaining mutable state.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::cilassembly::write::planner::FileLayout`] - File layout structures
//! - [`crate::cilassembly::write::planner::NativeTableRequirements`] - Native table requirements
//! - [`crate::cilassembly::write::planner::PeUpdates`] - PE update tracking
//! - [`crate::cilassembly::write::writers::pe`] - PE header writing

use crate::{
    cilassembly::{
        write::planner::{FileLayout, NativeTableRequirements, PeUpdates, SectionUpdate},
        CilAssembly,
    },
    Result,
};

/// Calculates PE updates needed after section relocations.
///
/// This function analyzes the changes between original and new section layouts
/// to determine what PE header updates are required during binary generation.
/// It performs a comprehensive comparison of section properties to identify
/// all necessary modifications.
///
/// # Arguments
///
/// * `assembly` - The [`crate::cilassembly::CilAssembly`] to analyze for original section layout
/// * `file_layout` - The new [`crate::cilassembly::write::planner::FileLayout`] with section changes
///
/// # Returns
///
/// Returns [`crate::cilassembly::write::planner::PeUpdates`] containing all PE header
/// update requirements including section table and checksum updates.
///
/// # Errors
///
/// This function is designed to always succeed with valid input, but returns
/// [`crate::Result`] for consistency with the module interface.
///
/// # Algorithm
///
/// 1. **Section Comparison**: Compare each section in the new layout with the original
/// 2. **Change Detection**: Identify changes in file offset, file size, and virtual size
/// 3. **Update Tracking**: Create section update records for all changes
/// 4. **Checksum Requirements**: Determine if PE checksum needs recalculation
///
/// # Examples
///
/// ```rust,ignore
/// use crate::cilassembly::write::planner::updates::calculate_pe_updates;
/// use crate::cilassembly::CilAssembly;
/// use crate::cilassembly::write::planner::FileLayout;
///
/// # let assembly = CilAssembly::new(view);
/// # let file_layout = FileLayout::calculate(&assembly, &heap_expansions, &mut metadata_modifications)?;
/// // Calculate PE updates needed
/// let pe_updates = calculate_pe_updates(&assembly, &file_layout)?;
///
/// if pe_updates.section_table_needs_update {
///     println!("PE section table needs updating");
///     for update in &pe_updates.section_updates {
///         println!("Section {} needs updates", update.section_index);
///     }
/// }
/// # Ok::<(), crate::Error>(())
/// ```
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
/// beyond the current section boundaries. It handles cases where native tables
/// are allocated just beyond the end of the last section.
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
    // Find the last section (highest virtual address + virtual size)
    let mut last_section_index = None;
    let mut highest_end = 0;

    for (index, section) in file_layout.sections.iter().enumerate() {
        let section_end = section.virtual_address + section.virtual_size;
        if section_end >= highest_end {
            highest_end = section_end;
            last_section_index = Some(index);
        }
    }

    for (section_index, section) in file_layout.sections.iter_mut().enumerate() {
        let section_start = section.virtual_address;
        let mut section_end = section_start + section.virtual_size;
        let mut needs_extension = false;
        let is_last_section = Some(section_index) == last_section_index;

        if let Some(import_rva) = native_requirements.import_table_rva {
            // ToDo: This is a dirty hack and should not be necessary
            // Check if RVA is within section or just beyond the last section
            let rva_in_range = if is_last_section {
                // For the last section, include RVAs that are close to the section end
                import_rva >= section_start && import_rva <= (section_end + 0x1000)
            } else {
                // For other sections, only include RVAs strictly within the section
                import_rva >= section_start && import_rva < section_end
            };

            if rva_in_range {
                let required_end = import_rva + native_requirements.import_table_size as u32;
                if required_end > section_end {
                    section_end = std::cmp::max(section_end, required_end);
                    needs_extension = true;
                }
            }
        }

        if let Some(export_rva) = native_requirements.export_table_rva {
            // ToDo: This is a dirty hack and should not be necessary
            // Check if RVA is within section or just beyond the last section
            let rva_in_range = if is_last_section {
                // For the last section, include RVAs that are close to the section end
                export_rva >= section_start && export_rva <= (section_end + 0x1000)
            } else {
                // For other sections, only include RVAs strictly within the section
                export_rva >= section_start && export_rva < section_end
            };

            if rva_in_range {
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
