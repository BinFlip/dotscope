//! Memory and size calculation utilities for layout planning.
//!
//! This module provides comprehensive memory-related calculations for assembly binary generation,
//! focusing on file size determinations, memory layout utilities, and space allocation strategies.
//! It handles the complex task of finding and allocating space within PE sections while respecting
//! section boundaries and maintaining proper alignment.
//!
//! # Key Components
//!
//! - [`rva_to_file_offset_for_planning`] - RVA to file offset conversion for planning
//! - [`calculate_total_size_from_layout`] - Total file size calculation from layout
//! - [`get_available_space_after_rva`] - Available space analysis after specific RVA
//! - [`find_space_in_sections`] - Space allocation within existing sections
//! - [`allocate_at_end_of_sections`] - Allocation at section boundaries
//! - [`extend_section_for_allocation`] - Section extension for additional space
//!
//! # Architecture
//!
//! The memory management system provides several allocation strategies:
//!
//! ## Padding Space Allocation
//! The system can find and utilize padding bytes (0x00 or 0xCC) within existing sections:
//! - Scans section content for contiguous padding regions
//! - Ensures proper 8-byte alignment for PE tables
//! - Validates that space is genuinely available, not just theoretically unused
//!
//! ## Section Boundary Allocation
//! For larger allocations, the system can utilize space at section boundaries:
//! - Allocates space between raw data end and virtual section end
//! - Maintains proper PE structure without creating overlays
//! - Respects section virtual size limits
//!
//! ## Section Extension
//! When existing space is insufficient, the system can extend sections:
//! - Extends the last section to accommodate new allocations
//! - Updates virtual sizes to maintain PE structure integrity
//! - Calculates new file sizes to accommodate extensions
//!
//! # Usage Examples
//!
//! ```rust,ignore
//! use crate::cilassembly::write::planner::memory::{
//!     calculate_total_size_from_layout, find_space_in_sections
//! };
//! use crate::cilassembly::CilAssembly;
//! use crate::cilassembly::write::planner::{FileLayout, NativeTableRequirements};
//!
//! # let assembly = CilAssembly::new(view);
//! # let file_layout = FileLayout::calculate(&assembly, &heap_expansions, &mut metadata_modifications)?;
//! # let native_requirements = NativeTableRequirements::default();
//! // Calculate total file size from layout
//! let total_size = calculate_total_size_from_layout(&assembly, &file_layout, &native_requirements);
//! println!("Total file size: {} bytes", total_size);
//!
//! // Find space for a table within existing sections
//! let allocated_regions = vec![(0x2000, 0x100)]; // Example allocated regions
//! if let Some(rva) = find_space_in_sections(&assembly, 0x200, &allocated_regions) {
//!     println!("Found space at RVA: 0x{:X}", rva);
//! }
//! # Ok::<(), crate::Error>(())
//! ```
//!
//! # Thread Safety
//!
//! All functions in this module are [`Send`] and [`Sync`] as they perform pure calculations
//! and analysis on immutable data without maintaining any mutable state.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::cilassembly::write::planner::validation`] - Space allocation validation
//! - [`crate::cilassembly::write::planner::FileLayout`] - File layout planning
//! - [`crate::cilassembly::write::planner::NativeTableRequirements`] - Native table space requirements
//! - [`crate::file::File`] - PE file structure analysis

use crate::{
    cilassembly::{
        write::planner::{validation, FileLayout, NativeTableRequirements},
        CilAssembly,
    },
    Error, Result,
};

/// Converts RVA to file offset for planning purposes.
///
/// This is a simplified version that assumes a 1:1 mapping for new allocations
/// beyond existing sections. For existing sections, it uses the section mapping
/// to provide accurate file offset calculations.
///
/// # Arguments
///
/// * `assembly` - The [`crate::cilassembly::CilAssembly`] to analyze
/// * `rva` - The RVA (Relative Virtual Address) to convert
///
/// # Returns
///
/// Returns the corresponding file offset as a [`u64`].
///
/// # Algorithm
///
/// 1. **Section Scan**: Iterate through all sections to find the one containing the RVA
/// 2. **Offset Calculation**: For RVAs within sections, calculate file offset using section mapping
/// 3. **Fallback**: For RVAs beyond existing sections, assume 1:1 mapping for new allocations
///
/// # Examples
///
/// ```rust,ignore
/// use crate::cilassembly::write::planner::memory::rva_to_file_offset_for_planning;
/// use crate::cilassembly::CilAssembly;
///
/// # let assembly = CilAssembly::new(view);
/// // Convert RVA to file offset
/// let file_offset = rva_to_file_offset_for_planning(&assembly, 0x2000);
/// println!("RVA 0x2000 maps to file offset: 0x{:X}", file_offset);
/// ```
pub fn rva_to_file_offset_for_planning(assembly: &CilAssembly, rva: u32) -> u64 {
    let file = assembly.file();

    for section in file.sections() {
        let section_start = section.virtual_address;
        let section_end = section.virtual_address + section.virtual_size;

        if rva >= section_start && rva < section_end {
            let offset_in_section = rva - section_start;
            let file_offset = u64::from(section.pointer_to_raw_data) + u64::from(offset_in_section);
            return file_offset;
        }
    }

    // RVA is beyond existing sections - assume 1:1 mapping for simplicity
    // This is a conservative approach for newly allocated space
    u64::from(rva)
}

/// Calculates total file size from complete layout and native table requirements.
///
/// This function determines the final file size by finding the maximum end offset
/// of all file regions including headers, sections, and native tables. It also
/// preserves any trailing data from the original file to ensure certificate
/// tables and other trailing structures are not truncated.
///
/// # Arguments
///
/// * `assembly` - The [`crate::cilassembly::CilAssembly`] for context
/// * `file_layout` - The complete [`crate::cilassembly::write::planner::FileLayout`] with all regions
/// * `native_requirements` - Native table space requirements
///
/// # Returns
///
/// Returns the total file size needed in bytes as a [`u64`].
///
/// # Algorithm
///
/// 1. **Region Analysis**: Find maximum end offset of all file regions (headers, sections)
/// 2. **Native Table Space**: Account for import and export table space requirements
/// 3. **Trailing Data**: Preserve original file size if it extends beyond calculated layout
/// 4. **Size Determination**: Return maximum of calculated size and original file size
///
/// # Examples
///
/// ```rust,ignore
/// use crate::cilassembly::write::planner::memory::calculate_total_size_from_layout;
/// use crate::cilassembly::CilAssembly;
/// use crate::cilassembly::write::planner::{FileLayout, NativeTableRequirements};
///
/// # let assembly = CilAssembly::new(view);
/// # let file_layout = FileLayout::calculate(&assembly, &heap_expansions, &mut metadata_modifications)?;
/// # let native_requirements = NativeTableRequirements::default();
/// // Calculate total file size
/// let total_size = calculate_total_size_from_layout(&assembly, &file_layout, &native_requirements);
/// println!("Total file size: {} bytes", total_size);
/// # Ok::<(), crate::Error>(())
/// ```
pub fn calculate_total_size_from_layout(
    assembly: &CilAssembly,
    file_layout: &FileLayout,
    native_requirements: &NativeTableRequirements,
) -> u64 {
    // Find the maximum end offset of all regions
    let mut max_end = 0u64;

    max_end = max_end.max(file_layout.dos_header.offset + file_layout.dos_header.size);
    max_end = max_end.max(file_layout.pe_headers.offset + file_layout.pe_headers.size);
    max_end = max_end.max(file_layout.section_table.offset + file_layout.section_table.size);

    for section in &file_layout.sections {
        let section_end = section.file_region.offset + section.file_region.size;
        max_end = max_end.max(section_end);
    }

    // Account for native table space requirements
    if let Some(import_rva) = native_requirements.import_table_rva {
        let import_offset = rva_to_file_offset_for_planning(assembly, import_rva);
        let import_end = import_offset + native_requirements.import_table_size;
        max_end = max_end.max(import_end);
    }

    if let Some(export_rva) = native_requirements.export_table_rva {
        let export_offset = rva_to_file_offset_for_planning(assembly, export_rva);
        let export_end = export_offset + native_requirements.export_table_size;
        max_end = max_end.max(export_end);
    }

    // Account for trailing data like certificate tables that exist beyond normal sections
    // Get the original file size to ensure we don't truncate important trailing data
    let original_file_size = assembly.file().file_size();

    // Only use the original file size if it's larger than our calculated layout
    // This preserves trailing data while allowing files to shrink if modifications reduce size
    max_end.max(original_file_size)
}

/// Gets genuinely available space after a specific RVA within the same section.
///
/// This function properly checks for actual padding bytes (0x00 or 0xCC)
/// after the specified RVA to determine how much space is genuinely available
/// for reuse.
///
/// # Arguments
/// * `assembly` - The assembly to analyze
/// * `rva` - The RVA to check space after
/// * `used_size` - The size currently used at the RVA
///
/// # Returns
/// Returns the number of bytes available after the RVA.
pub fn get_available_space_after_rva(
    assembly: &CilAssembly,
    rva: u32,
    used_size: u32,
) -> Result<u32> {
    let file = assembly.file();

    for section in file.sections() {
        let section_start = section.virtual_address;
        let section_end = section.virtual_address + section.virtual_size;

        if rva >= section_start && rva < section_end {
            let table_end = rva + used_size;

            if table_end > section_end {
                return Ok(0);
            }

            return Ok(get_padding_space_after_rva(
                assembly,
                section,
                table_end,
                section_end,
            ));
        }
    }

    Err(Error::WriteLayoutFailed {
        message: format!("Could not find section containing RVA 0x{rva:x}"),
    })
}

/// Gets contiguous padding space after a specific RVA within a section.
///
/// This function analyzes the section content starting from the given RVA
/// to find how many contiguous padding bytes (0x00 or 0xCC) are available.
///
/// # Arguments
/// * `assembly` - The assembly to analyze
/// * `section` - The section to check
/// * `start_rva` - The RVA to start checking from
/// * `section_end_rva` - The end RVA of the section
///
/// # Returns
/// Returns the number of contiguous padding bytes available.
pub fn get_padding_space_after_rva(
    assembly: &CilAssembly,
    section: &goblin::pe::section_table::SectionTable,
    start_rva: u32,
    section_end_rva: u32,
) -> u32 {
    let file = assembly.file();

    if section.size_of_raw_data == 0 {
        return 0;
    }

    let Ok(start_file_offset) = file.rva_to_offset(start_rva as usize) else {
        return 0;
    };

    let Ok(section_file_offset) = file.rva_to_offset(section.virtual_address as usize) else {
        return 0;
    };

    let offset_in_section = start_file_offset.saturating_sub(section_file_offset);
    if offset_in_section >= section.size_of_raw_data as usize {
        return 0;
    }

    let remaining_raw_size = (section.size_of_raw_data as usize).saturating_sub(offset_in_section);
    if remaining_raw_size == 0 {
        return 0;
    }

    let Ok(section_data) = file.data_slice(start_file_offset, remaining_raw_size) else {
        return 0;
    };

    let mut padding_count = 0u32;
    for &byte in section_data {
        if byte == 0x00 || byte == 0xCC {
            padding_count += 1;
        } else {
            break;
        }
    }

    let max_rva_space = section_end_rva.saturating_sub(start_rva);
    std::cmp::min(padding_count, max_rva_space)
}

/// Finds available space within existing sections for a table.
///
/// This function properly checks for actual padding bytes (0x00 or 0xCC)
/// to ensure the space is genuinely available, not just theoretically unused.
///
/// # Arguments
/// * `assembly` - The assembly to analyze
/// * `required_size` - The size needed for allocation
/// * `allocated_regions` - Slice of (RVA, size) tuples representing allocated regions
///
/// # Returns
/// Returns the RVA where space was found, or None if no suitable space exists.
pub fn find_space_in_sections(
    assembly: &CilAssembly,
    required_size: u32,
    allocated_regions: &[(u32, u32)],
) -> Option<u32> {
    let file = assembly.file();
    let preferred_sections = [".text", ".rdata", ".data"];

    for section in file.sections() {
        let section_name = std::str::from_utf8(&section.name)
            .unwrap_or("")
            .trim_end_matches('\0');

        let is_preferred = preferred_sections.contains(&section_name);
        if is_preferred {
            if let Some(allocation_rva) =
                find_padding_space_in_section(assembly, section, required_size)
            {
                if !validation::conflicts_with_regions(
                    allocation_rva,
                    required_size,
                    allocated_regions,
                ) {
                    return Some(allocation_rva);
                }
            }
        }
    }

    None
}

/// Finds contiguous padding space within a specific section.
///
/// This function analyzes the section content to find contiguous padding bytes
/// (0x00 or 0xCC) that are large enough for the required allocation size.
///
/// # Arguments
/// * `assembly` - The assembly to analyze
/// * `section` - The section to search within
/// * `required_size` - The size needed for allocation
///
/// # Returns
/// Returns the RVA where padding space was found, or None if insufficient space.
pub fn find_padding_space_in_section(
    assembly: &CilAssembly,
    section: &goblin::pe::section_table::SectionTable,
    required_size: u32,
) -> Option<u32> {
    let file = assembly.file();

    if section.size_of_raw_data == 0 {
        return None;
    }

    let Ok(section_file_offset) = file.rva_to_offset(section.virtual_address as usize) else {
        return None;
    };

    let Ok(section_data) = file.data_slice(section_file_offset, section.size_of_raw_data as usize)
    else {
        return None;
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
                    let allocation_rva =
                        section.virtual_address + u32::try_from(aligned_start).unwrap_or(0);

                    if allocation_rva + required_size
                        <= section.virtual_address + section.virtual_size
                    {
                        return Some(allocation_rva);
                    }
                }
            }
        } else {
            current_padding_start = None;
            current_padding_length = 0;
        }
    }

    None
}

/// Allocates space at the end of sections, but only within section boundaries.
///
/// This function attempts to find space at the end of sections without creating
/// overlay data outside proper PE section boundaries. It fails if no suitable
/// space is found within section limits.
///
/// # Arguments
/// * `assembly` - The assembly to analyze
/// * `required_size` - The size needed for allocation
/// * `allocated_regions` - Slice of (RVA, size) tuples representing allocated regions
///
/// # Returns
/// Returns the RVA where space was allocated.
///
/// # Errors
/// Returns error if no space is available within section boundaries.
pub fn allocate_at_end_of_sections(
    assembly: &CilAssembly,
    required_size: u32,
    allocated_regions: &[(u32, u32)],
) -> Result<u32> {
    let file = assembly.file();

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
                && !validation::conflicts_with_regions(
                    aligned_rva,
                    required_size,
                    allocated_regions,
                )
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
/// This function allocates space at the end of the last section, expanding
/// the file size as needed. The new file size will be calculated to accommodate
/// this allocation.
///
/// # Arguments
/// * `assembly` - The assembly to analyze
/// * `_required_size` - The size needed for allocation (currently unused)
/// * `allocated_regions` - Slice of (RVA, size) tuples representing allocated regions
///
/// # Returns
/// Returns the RVA where space was allocated.
///
/// # Errors
/// Returns error if no sections are found.
pub fn extend_section_for_allocation(
    assembly: &CilAssembly,
    _required_size: u32,
    allocated_regions: &[(u32, u32)],
) -> Result<u32> {
    let file = assembly.file();

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
