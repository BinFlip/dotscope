//! Validation utilities for layout planning.
//!
//! This module provides validation functions for layout planning operations,
//! including region conflict detection and space allocation validation.

/// Checks if a region conflicts with any allocated regions.
///
/// This function performs collision detection to determine if a proposed
/// region overlaps with any existing allocated regions.
///
/// # Arguments
/// * `rva` - Starting RVA of the proposed region
/// * `size` - Size of the proposed region
/// * `allocated_regions` - Slice of (RVA, size) tuples representing allocated regions
///
/// # Returns
/// Returns `true` if there is a conflict, `false` otherwise.
pub fn conflicts_with_regions(rva: u32, size: u32, allocated_regions: &[(u32, u32)]) -> bool {
    let end_rva = rva + size;
    for &(allocated_rva, allocated_size) in allocated_regions {
        let allocated_end = allocated_rva + allocated_size;
        if rva < allocated_end && end_rva > allocated_rva {
            return true;
        }
    }
    false
}
