//! Validation utilities for layout planning.
//!
//! This module provides comprehensive validation functions for layout planning operations,
//! including region conflict detection and space allocation validation. It ensures that
//! memory allocations and layout modifications maintain proper boundaries and do not
//! create overlapping regions that could cause binary corruption.
//!
//! # Key Components
//!
//! - [`conflicts_with_regions`] - Checks for region conflicts during space allocation
//!
//! # Architecture
//!
//! The validation system provides essential safety checks for layout planning:
//!
//! ## Region Conflict Detection
//! The system validates that new allocations do not overlap with existing regions:
//! - Performs collision detection using RVA ranges
//! - Checks for overlapping boundaries between regions
//! - Prevents double-allocation of memory space
//! - Ensures allocation integrity throughout the layout process
//!
//! ## Allocation Validation
//! Each proposed allocation is validated to ensure:
//! - No conflicts with previously allocated regions
//! - Proper alignment and size requirements
//! - Maintenance of PE structure integrity
//!
//! # Usage Examples
//!
//! ```rust,ignore
//! use crate::cilassembly::write::planner::validation::conflicts_with_regions;
//!
//! // Define existing allocated regions
//! let allocated_regions = vec![
//!     (0x1000, 0x500),  // Region 1: RVA 0x1000, size 0x500
//!     (0x2000, 0x300),  // Region 2: RVA 0x2000, size 0x300
//! ];
//!
//! // Check if a new allocation would conflict
//! let new_rva = 0x1200;
//! let new_size = 0x100;
//!
//! if conflicts_with_regions(new_rva, new_size, &allocated_regions) {
//!     println!("Allocation conflicts with existing regions");
//! } else {
//!     println!("Allocation is safe");
//! }
//! ```
//!
//! # Thread Safety
//!
//! All functions in this module are [`Send`] and [`Sync`] as they perform pure
//! calculations on immutable data without maintaining any mutable state.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::cilassembly::write::planner::memory`] - Memory allocation strategies
//! - [`crate::cilassembly::write::planner::tables`] - Table allocation planning
//! - [`crate::cilassembly::write::planner::layout`] - File layout planning

/// Checks if a region conflicts with any allocated regions.
///
/// This function performs collision detection to determine if a proposed
/// region overlaps with any existing allocated regions. It uses interval
/// overlap detection to ensure no double-allocation of memory space.
///
/// # Arguments
///
/// * `rva` - Starting RVA (Relative Virtual Address) of the proposed region
/// * `size` - Size in bytes of the proposed region
/// * `allocated_regions` - Slice of (RVA, size) tuples representing existing allocated regions
///
/// # Returns
///
/// Returns `true` if there is a conflict with any existing region, `false` if the
/// proposed region is safe to allocate.
///
/// # Algorithm
///
/// The function uses interval overlap detection:
/// - For each existing region, calculates its end RVA
/// - Checks if the proposed region overlaps using: `start1 < end2 && start2 < end1`
/// - Returns true immediately upon finding any overlap
///
/// # Examples
///
/// ```rust,ignore
/// use crate::cilassembly::write::planner::validation::conflicts_with_regions;
///
/// // Define existing allocated regions
/// let allocated_regions = vec![
///     (0x1000, 0x500),  // Region at 0x1000-0x1500
///     (0x2000, 0x300),  // Region at 0x2000-0x2300
/// ];
///
/// // Check for conflicts
/// assert!(conflicts_with_regions(0x1200, 0x100, &allocated_regions)); // Conflicts with first region
/// assert!(conflicts_with_regions(0x1F00, 0x200, &allocated_regions)); // Conflicts with second region
/// assert!(!conflicts_with_regions(0x1600, 0x200, &allocated_regions)); // No conflict
/// ```
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
