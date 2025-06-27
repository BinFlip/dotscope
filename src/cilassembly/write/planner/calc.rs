//! Size calculation utilities for layout planning.
//!
//! This module provides comprehensive size calculation logic for all components of .NET
//! assemblies during the binary generation process. It handles the complex task of determining
//! exact byte sizes for metadata heaps, table expansions, and structural alignments required
//! for ECMA-335 compliance.
//!
//! # Key Components
//!
//! - [`crate::cilassembly::write::planner::calc::calculate_heap_expansions`] - Main entry point for heap size calculations
//! - [`crate::cilassembly::write::planner::calc::HeapExpansions`] - Structure containing all heap expansion information
//! - [`crate::cilassembly::write::planner::calc::calculate_string_heap_size`] - String heap size calculation with null termination
//! - [`crate::cilassembly::write::planner::calc::calculate_blob_heap_size`] - Blob heap size with compressed length prefixes
//! - [`crate::cilassembly::write::planner::calc::calculate_guid_heap_size`] - GUID heap size (16 bytes per GUID)
//! - [`crate::cilassembly::write::planner::calc::calculate_userstring_heap_size`] - UserString heap with UTF-16 encoding
//! - [`crate::cilassembly::write::planner::calc::calculate_table_stream_expansion`] - Table modifications size calculation
//! - [`crate::cilassembly::write::planner::calc::calculate_new_row_count`] - Row count after table modifications
//!
//! # Architecture
//!
//! The size calculation system implements the exact ECMA-335 specification requirements:
//!
//! ## Heap Size Calculations
//! Each metadata heap type has specific encoding and alignment requirements:
//! - **String Heap**: UTF-8 encoded with null terminators, 4-byte aligned
//! - **Blob Heap**: Binary data with compressed length prefixes, 4-byte aligned
//! - **GUID Heap**: Fixed 16-byte GUIDs, naturally aligned
//! - **UserString Heap**: UTF-16 encoded with compressed length prefixes, 4-byte aligned
//!
//! ## Table Size Calculations
//! Table expansions are calculated based on:
//! - Row size determined by table schema and index sizes
//! - Number of additional rows from modifications
//! - Sparse vs replacement modification patterns
//!
//! ## Alignment Requirements
//! All calculations respect ECMA-335 alignment requirements:
//! - Heap data aligned to 4-byte boundaries
//! - Compressed integers for length prefixes
//! - UTF-16 encoding for user strings
//!
//! # Usage Examples
//!
//! ```rust,ignore
//! use crate::cilassembly::write::planner::calc::calculate_heap_expansions;
//! use crate::cilassembly::CilAssembly;
//!
//! # let assembly = CilAssembly::empty(); // placeholder
//! // Calculate all heap expansions for layout planning
//! let expansions = calculate_heap_expansions(&assembly)?;
//!
//! println!("String heap needs {} additional bytes", expansions.string_heap_addition);
//! println!("Total expansion: {} bytes", expansions.total_heap_addition);
//! # Ok::<(), crate::Error>(())
//! ```
//!
//! # Thread Safety
//!
//! All functions in this module are pure calculations that do not modify shared state,
//! making them inherently thread-safe. However, they are designed for single-threaded
//! use during the layout planning phase.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::cilassembly::write::planner`] - Layout planning coordination
//! - [`crate::cilassembly::changes`] - Source of modification data
//! - [`crate::cilassembly::write::utils`] - Utility functions for table calculations
//! - [`crate::metadata::tables`] - Table schema and size information

use crate::{
    cilassembly::{
        write::utils::calculate_table_row_size, CilAssembly, HeapChanges, Operation,
        TableModifications,
    },
    metadata::tables::TableId,
    Error, Result,
};

/// Calculates heap expansions needed for all heap types.
///
/// This function analyzes all modifications to metadata heaps and calculates the exact
/// byte sizes needed for each heap type. It ensures proper alignment and encoding
/// according to ECMA-335 requirements.
///
/// # Arguments
/// * `assembly` - The [`crate::cilassembly::CilAssembly`] containing heap modifications
///
/// # Returns
/// Returns [`crate::cilassembly::write::planner::calc::HeapExpansions`] with calculated sizes for all heaps.
///
/// # Errors
/// Returns [`crate::Error`] if heap size calculations fail due to invalid data or encoding issues.
pub fn calculate_heap_expansions(assembly: &CilAssembly) -> Result<HeapExpansions> {
    let changes = assembly.changes();

    // Use the aligned heap size calculations to ensure consistency
    let string_size = if changes.string_heap_changes.has_additions() {
        calculate_string_heap_size(&changes.string_heap_changes)?
    } else {
        0
    };

    let blob_size = if changes.blob_heap_changes.has_additions() {
        calculate_blob_heap_size(&changes.blob_heap_changes)?
    } else {
        0
    };

    let guid_size = if changes.guid_heap_changes.has_additions() {
        calculate_guid_heap_size(&changes.guid_heap_changes)?
    } else {
        0
    };

    let userstring_size = if changes.userstring_heap_changes.has_additions() {
        calculate_userstring_heap_size(&changes.userstring_heap_changes)?
    } else {
        0
    };

    // Calculate table stream expansion
    let table_expansion = calculate_table_stream_expansion(assembly)?;

    let total_heap_addition =
        string_size + blob_size + guid_size + userstring_size + table_expansion;

    Ok(HeapExpansions {
        string_heap_addition: string_size,
        blob_heap_addition: blob_size,
        guid_heap_addition: guid_size,
        userstring_heap_addition: userstring_size,
        total_heap_addition,
    })
}

/// Information about heap expansions needed for layout planning.
///
/// This structure contains the calculated additional bytes needed for each metadata heap
/// type after applying all modifications. All sizes are properly aligned according to
/// ECMA-335 requirements and ready for use in layout planning.
///
/// # Usage
/// This structure is returned by [`crate::cilassembly::write::planner::calc::calculate_heap_expansions`]
/// and used by the layout planner to determine new file structure.
#[derive(Debug, Clone)]
pub struct HeapExpansions {
    /// Additional bytes needed for string heap.
    /// Includes null terminators and 4-byte alignment padding.
    pub string_heap_addition: u64,

    /// Additional bytes needed for blob heap.
    /// Includes compressed length prefixes and 4-byte alignment padding.
    pub blob_heap_addition: u64,

    /// Additional bytes needed for GUID heap.
    /// Each GUID is exactly 16 bytes with natural alignment.
    pub guid_heap_addition: u64,

    /// Additional bytes needed for user string heap.
    /// Includes UTF-16 encoding, compressed length prefixes, and 4-byte alignment padding.
    pub userstring_heap_addition: u64,

    /// Total additional space needed for all heaps and table modifications.
    /// Sum of all individual heap additions plus table stream expansion.
    pub total_heap_addition: u64,
}

/// Calculates the actual byte size needed for string heap additions.
///
/// String heap entries are UTF-8 encoded with null terminators and aligned to 4-byte
/// boundaries as required by ECMA-335 specification.
///
/// # Arguments
/// * `heap_changes` - The [`crate::cilassembly::HeapChanges<String>`] containing string additions
///
/// # Returns
/// Returns the total aligned byte size needed for all string additions.
///
/// # Format
/// Each string is stored as: UTF-8 bytes + null terminator, with the entire heap
/// section padded to 4-byte alignment.
pub fn calculate_string_heap_size(heap_changes: &HeapChanges<String>) -> Result<u64> {
    // Calculate the actual byte size of the string additions
    let mut total_size = 0u64;

    for string in &heap_changes.appended_items {
        // Each string is null-terminated in the heap
        total_size += string.len() as u64 + 1; // +1 for null terminator
    }

    // Align to 4-byte boundary (ECMA-335 II.24.2.2)
    let aligned_size = align_to(total_size, 4);
    Ok(aligned_size)
}

/// Calculates the actual byte size needed for blob heap additions.
///
/// Blob heap entries use compressed integer length prefixes followed by the binary data,
/// with the entire section aligned to 4-byte boundaries per ECMA-335.
///
/// # Arguments
/// * `heap_changes` - The [`crate::cilassembly::HeapChanges<Vec<u8>>`] containing blob additions
///
/// # Returns
/// Returns the total aligned byte size needed for all blob additions.
///
/// # Format
/// Each blob is stored as: compressed_length + binary_data, where compressed_length
/// is 1, 2, or 4 bytes depending on the data size.
pub fn calculate_blob_heap_size(heap_changes: &HeapChanges<Vec<u8>>) -> Result<u64> {
    // Calculate the actual byte size of the blob additions
    let mut total_size = 0u64;

    for blob in &heap_changes.appended_items {
        // Blobs are prefixed with their length (compressed integer)
        let length_prefix_size = if blob.len() < 128 {
            1 // Single byte length
        } else if blob.len() < 16384 {
            2 // Two byte length
        } else {
            4 // Four byte length
        };

        total_size += length_prefix_size + blob.len() as u64;
    }

    // Align to 4-byte boundary (ECMA-335 II.24.2.2)
    let aligned_size = align_to(total_size, 4);
    Ok(aligned_size)
}

/// Calculates the actual byte size needed for GUID heap additions.
///
/// GUID heap entries are exactly 16 bytes each with no prefixes or padding needed
/// since 16 bytes is naturally aligned to 4-byte boundaries.
///
/// # Arguments
/// * `heap_changes` - The [`crate::cilassembly::HeapChanges<[u8; 16]>`] containing GUID additions
///
/// # Returns
/// Returns the total byte size needed for all GUID additions (count * 16).
///
/// # Format
/// Each GUID is stored as 16 consecutive bytes in the heap.
pub fn calculate_guid_heap_size(heap_changes: &HeapChanges<[u8; 16]>) -> Result<u64> {
    // GUIDs are always 16 bytes each, no prefix
    let total_size = heap_changes.appended_items.len() as u64 * 16;
    // GUIDs are always 16 bytes each, so already aligned to 4-byte boundary
    Ok(total_size)
}

/// Calculates the actual byte size needed for userstring heap additions.
///
/// UserString heap entries are UTF-16 encoded with compressed integer length prefixes,
/// aligned to 4-byte boundaries as required by ECMA-335.
///
/// # Arguments
/// * `heap_changes` - The [`crate::cilassembly::HeapChanges<String>`] containing user string additions
///
/// # Returns
/// Returns the total aligned byte size needed for all user string additions.
///
/// # Format
/// Each user string is stored as: compressed_length + UTF-16_bytes, where the length
/// indicates the number of UTF-16 bytes (not characters).
pub fn calculate_userstring_heap_size(heap_changes: &HeapChanges<String>) -> Result<u64> {
    // Calculate the actual byte size of the userstring additions
    let mut total_size = 0u64;

    for string in &heap_changes.appended_items {
        // User strings are UTF-16 encoded with length prefix
        let utf16_length = string.encode_utf16().count() * 2; // 2 bytes per UTF-16 code unit

        // Length prefix (compressed integer)
        let length_prefix_size = if utf16_length < 128 {
            1
        } else if utf16_length < 16384 {
            2
        } else {
            4
        };

        total_size += length_prefix_size as u64 + utf16_length as u64;
    }

    // Align to 4-byte boundary (ECMA-335 II.24.2.2)
    let aligned_size = align_to(total_size, 4);
    Ok(aligned_size)
}

/// Calculates the additional bytes needed for the tables stream due to table modifications.
///
/// This function analyzes all table modifications to determine how much additional space
/// is needed in the tables stream. It accounts for both sparse operations and complete
/// table replacements.
///
/// # Arguments
/// * `assembly` - The [`crate::cilassembly::CilAssembly`] containing table modifications
///
/// # Returns
/// Returns the total additional bytes needed for the tables stream.
///
/// # Errors
/// Returns [`crate::Error::WriteLayoutFailed`] if table information is unavailable.
pub fn calculate_table_stream_expansion(assembly: &CilAssembly) -> Result<u64> {
    let changes = assembly.changes();
    let view = assembly.view();

    let tables = view.tables().ok_or_else(|| Error::WriteLayoutFailed {
        message: "No tables found in assembly for expansion calculation".to_string(),
    })?;

    let mut total_expansion = 0u64;

    // Calculate expansion for each modified table
    for table_id in changes.modified_tables() {
        if let Some(table_mod) = changes.get_table_modifications(table_id) {
            let row_size = calculate_table_row_size(table_id, &tables.info);

            let additional_rows = match table_mod {
                TableModifications::Replaced(new_rows) => {
                    let original_count = tables.table_row_count(table_id);
                    if new_rows.len() as u32 > original_count {
                        new_rows.len() as u32 - original_count
                    } else {
                        0 // Table shrunk or stayed same size
                    }
                }
                TableModifications::Sparse { operations, .. } => {
                    // Count insert operations
                    operations
                        .iter()
                        .filter(|op| matches!(op.operation, Operation::Insert(_, _)))
                        .count() as u32
                }
            };

            let expansion_bytes = additional_rows as u64 * row_size as u64;
            total_expansion += expansion_bytes;
        }
    }

    Ok(total_expansion)
}

/// Calculates the new row count for a table after modifications.
///
/// This function determines the final number of rows in a table after applying
/// all modifications, handling both replacement and sparse modification patterns.
///
/// # Arguments
/// * `assembly` - The [`crate::cilassembly::CilAssembly`] for context
/// * `table_id` - The [`crate::metadata::tables::TableId`] to calculate for
/// * `table_mod` - The [`crate::cilassembly::TableModifications`] to apply
///
/// # Returns
/// Returns the final row count after all modifications are applied.
///
/// # Errors
/// Returns [`crate::Error::WriteLayoutFailed`] if table information is unavailable.
///
/// # Note
/// For sparse modifications, this uses a simplified calculation that may not account
/// for complex operation interactions. Production code should use proper operation
/// sequence processing.
pub fn calculate_new_row_count(
    assembly: &CilAssembly,
    table_id: TableId,
    table_mod: &TableModifications,
) -> Result<u32> {
    match table_mod {
        TableModifications::Replaced(rows) => Ok(rows.len() as u32),
        TableModifications::Sparse { operations, .. } => {
            // Calculate final row count after all operations
            let view = assembly.view();
            let tables = view.tables().ok_or_else(|| Error::WriteLayoutFailed {
                message: "No tables found".to_string(),
            })?;
            let original_count = tables.table_row_count(table_id);

            // This is a simplified calculation - in a real implementation,
            // we'd need to process all operations to get the final count
            let added_count = operations
                .iter()
                .filter(|op| matches!(op.operation, Operation::Insert(_, _)))
                .count();

            let deleted_count = operations
                .iter()
                .filter(|op| matches!(op.operation, Operation::Delete(_)))
                .count();

            Ok(original_count + added_count as u32 - deleted_count as u32)
        }
    }
}

/// Aligns a value to the next multiple of the given alignment.
///
/// This utility function implements the standard alignment calculation used throughout
/// the ECMA-335 specification for heap and structure alignment.
///
/// # Arguments
/// * `value` - The value to align
/// * `alignment` - The alignment boundary (must be a power of 2)
///
/// # Returns
/// The smallest value >= input that is a multiple of the alignment.
fn align_to(value: u64, alignment: u64) -> u64 {
    (value + alignment - 1) & !(alignment - 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CilAssemblyView;
    use std::path::Path;

    #[test]
    fn test_heap_expansion_calculation() {
        let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))
            .expect("Failed to load test assembly");
        let assembly = view.to_owned();

        let heap_expansions = calculate_heap_expansions(&assembly)
            .expect("Heap expansion calculation should succeed");

        // For an unmodified assembly, all expansions should be 0
        assert_eq!(
            heap_expansions.string_heap_addition, 0,
            "String heap addition should be 0 for unmodified assembly"
        );
        assert_eq!(
            heap_expansions.blob_heap_addition, 0,
            "Blob heap addition should be 0 for unmodified assembly"
        );
        assert_eq!(
            heap_expansions.guid_heap_addition, 0,
            "GUID heap addition should be 0 for unmodified assembly"
        );
        assert_eq!(
            heap_expansions.userstring_heap_addition, 0,
            "UserString heap addition should be 0 for unmodified assembly"
        );
        assert_eq!(
            heap_expansions.total_heap_addition, 0,
            "Total heap addition should be 0 for unmodified assembly"
        );
    }

    #[test]
    fn test_string_heap_size_calculation() {
        let mut heap_changes = HeapChanges::new(0);
        heap_changes.appended_items.push("test".to_string());
        heap_changes.appended_items.push("hello world".to_string());

        let size = calculate_string_heap_size(&heap_changes).unwrap();

        // "test" (4) + null (1) + "hello world" (11) + null (1) = 17 bytes
        // Aligned to 4 bytes = 20 bytes
        assert_eq!(size, 20);
    }

    #[test]
    fn test_blob_heap_size_calculation() {
        let mut heap_changes = HeapChanges::new(0);
        heap_changes.appended_items.push(vec![1, 2, 3]); // length 3, prefix 1 byte
        heap_changes.appended_items.push(vec![4, 5]); // length 2, prefix 1 byte

        let size = calculate_blob_heap_size(&heap_changes).unwrap();

        // blob1: 1 (prefix) + 3 (data) = 4 bytes
        // blob2: 1 (prefix) + 2 (data) = 3 bytes
        // total: 7 bytes, aligned to 4 = 8 bytes
        assert_eq!(size, 8);
    }

    #[test]
    fn test_guid_heap_size_calculation() {
        let mut heap_changes = HeapChanges::new(0);
        heap_changes.appended_items.push([0u8; 16]);
        heap_changes.appended_items.push([1u8; 16]);

        let size = calculate_guid_heap_size(&heap_changes).unwrap();

        // 2 GUIDs * 16 bytes each = 32 bytes (already aligned)
        assert_eq!(size, 32);
    }

    #[test]
    fn test_userstring_heap_size_calculation() {
        let mut heap_changes = HeapChanges::new(0);
        heap_changes.appended_items.push("A".to_string()); // 1 char = 2 UTF-16 bytes

        let size = calculate_userstring_heap_size(&heap_changes).unwrap();

        // 1 (prefix) + 2 (UTF-16 data) = 3 bytes, aligned to 4 = 4 bytes
        assert_eq!(size, 4);
    }
}
