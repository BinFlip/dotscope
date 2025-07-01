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
    let string_size = if changes.string_heap_changes.has_additions()
        || changes.string_heap_changes.has_modifications()
        || changes.string_heap_changes.has_removals()
    {
        assembly.calculate_string_heap_size()?
    } else {
        0
    };

    let blob_size = if changes.blob_heap_changes.has_additions()
        || changes.blob_heap_changes.has_modifications()
        || changes.blob_heap_changes.has_removals()
    {
        assembly.calculate_blob_heap_size()?
    } else {
        0
    };

    let guid_size = if changes.guid_heap_changes.has_additions()
        || changes.guid_heap_changes.has_modifications()
        || changes.guid_heap_changes.has_removals()
    {
        assembly.calculate_guid_heap_size()?
    } else {
        0
    };

    let userstring_size = if changes.userstring_heap_changes.has_additions()
        || changes.userstring_heap_changes.has_modifications()
        || changes.userstring_heap_changes.has_removals()
    {
        assembly.calculate_userstring_heap_size()?
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

/// Calculates the actual byte size needed for string heap modifications.
///
/// This function handles both addition-only scenarios and heap rebuilding scenarios.
/// When modifications or removals are present, it calculates the total size of the
/// rebuilt heap rather than just additions.
///
/// # Arguments
/// * `heap_changes` - The [`crate::cilassembly::HeapChanges<String>`] containing string changes
/// * `assembly` - The [`crate::cilassembly::CilAssembly`] for accessing original heap data
///
/// # Returns
/// Returns the total aligned byte size needed for the string heap after all changes.
///
/// # Format
/// Each string is stored as: UTF-8 bytes + null terminator, with the entire heap
/// section padded to 4-byte alignment.
pub fn calculate_string_heap_size(
    heap_changes: &HeapChanges<String>,
    assembly: &CilAssembly,
) -> Result<u64> {
    let mut total_size = 0u64;

    if heap_changes.has_modifications() || heap_changes.has_removals() {
        // NEW APPROACH: Offset-preserving heap rebuild
        // 1. Preserve original heap size (with all modifications in-place)
        // 2. Add size of appended strings that aren't removed

        if let Some(strings_heap) = assembly.view().strings() {
            // Step 1: Start with original heap size (preserve layout)
            let mut original_heap_end = 0;
            for (offset, string) in strings_heap.iter() {
                let string_end = offset + string.to_string().len() + 1; // +1 for null terminator
                if string_end > original_heap_end {
                    original_heap_end = string_end;
                }
            }
            total_size += original_heap_end as u64;

            // Step 2: Add size of modified original strings that need to be appended
            // (when they're too big for in-place replacement)
            for (offset, string) in strings_heap.iter() {
                let heap_index = offset as u32;
                if let Some(modified_string) = heap_changes.get_modification(heap_index) {
                    let original_size = string.to_string().len() + 1; // include null terminator
                    let new_size = modified_string.len() + 1; // include null terminator

                    if new_size > original_size {
                        // Too big for in-place - will be appended at end
                        total_size += new_size as u64;
                    }
                }
            }

            // Step 3: Add size of appended strings that aren't removed
            for (heap_index, appended_string) in heap_changes.string_items_with_indices() {
                if !heap_changes.is_removed(heap_index) {
                    // Apply modification if present, otherwise use original appended string
                    let final_string = heap_changes
                        .get_modification(heap_index)
                        .cloned()
                        .unwrap_or_else(|| appended_string.clone());
                    let string_size = final_string.len() as u64 + 1; // +1 for null terminator
                    total_size += string_size;
                }
            }
        } else {
            // No original heap - just count appended strings
            total_size += 1; // mandatory null byte
            for (heap_index, appended_string) in heap_changes.string_items_with_indices() {
                if !heap_changes.is_removed(heap_index) {
                    let final_string = heap_changes
                        .get_modification(heap_index)
                        .cloned()
                        .unwrap_or_else(|| appended_string.clone());
                    let string_size = final_string.len() as u64 + 1;
                    total_size += string_size;
                }
            }
        }
    } else {
        // Addition-only scenario - calculate size of additions only
        for string in &heap_changes.appended_items {
            // Each string is null-terminated in the heap
            total_size += string.len() as u64 + 1; // +1 for null terminator
        }
    }

    // Align to 4-byte boundary (ECMA-335 II.24.2.2)
    // Note: String heap padding uses 0xFF bytes to avoid creating empty string entries
    let aligned_size = align_to(total_size, 4);
    Ok(aligned_size)
}

/// Helper function to calculate the size of a compressed uint according to ECMA-335.
fn compressed_uint_size(value: usize) -> u64 {
    if value < 0x80 {
        1
    } else if value < 0x4000 {
        2
    } else {
        4
    }
}

/// Calculates the actual byte size needed for blob heap modifications.
///
/// This function handles both addition-only scenarios and heap rebuilding scenarios.
/// When modifications or removals are present, it calculates the total size of the
/// rebuilt heap rather than just additions.
///
/// # Arguments
/// * `heap_changes` - The [`crate::cilassembly::HeapChanges<Vec<u8>>`] containing blob changes
/// * `assembly` - The [`crate::cilassembly::CilAssembly`] for accessing original heap data
///
/// # Returns
/// Returns the total aligned byte size needed for the blob heap after all changes.
///
/// # Format
/// Each blob is stored as: compressed_length + binary_data, where compressed_length
/// is 1, 2, or 4 bytes depending on the data size.
pub fn calculate_blob_heap_size(
    heap_changes: &HeapChanges<Vec<u8>>,
    assembly: &CilAssembly,
) -> Result<u64> {
    let mut total_size = 0u64;

    if heap_changes.has_changes() {
        // ECMA-335 requirement: include the mandatory null byte at offset 0
        total_size += 1;

        // Build sets for efficient lookup of removed and modified indices
        let removed_indices = &heap_changes.removed_indices;
        let modified_indices: std::collections::HashSet<u32> =
            heap_changes.modified_items.keys().cloned().collect();

        // Calculate size of original blobs that are neither removed nor modified
        if let Some(blob_heap) = assembly.view().blobs() {
            for (offset, original_blob) in blob_heap.iter() {
                if offset == 0 {
                    continue;
                } // Skip the mandatory null byte at offset 0

                // The heap changes system uses byte offsets as indices
                let offset_u32 = offset as u32;
                if !removed_indices.contains(&offset_u32) && !modified_indices.contains(&offset_u32)
                {
                    let length_prefix_size = compressed_uint_size(original_blob.len());
                    total_size += length_prefix_size + original_blob.len() as u64;
                }
            }
        }

        // Add size of modified blobs (use the new values)
        for new_blob in heap_changes.modified_items.values() {
            let length_prefix_size = compressed_uint_size(new_blob.len());
            total_size += length_prefix_size + new_blob.len() as u64;
        }

        // Add size of appended blobs that haven't been modified
        // (modified appended blobs are already counted in the modified_items section above)
        let original_heap_size = if let Some(blob_heap) = assembly.view().blobs() {
            blob_heap.data().len() as u32
        } else {
            0
        };

        let mut current_index = original_heap_size;
        for blob in &heap_changes.appended_items {
            // Only count this appended blob if it hasn't been modified
            if !heap_changes.modified_items.contains_key(&current_index) {
                let length_prefix_size = compressed_uint_size(blob.len());
                total_size += length_prefix_size + blob.len() as u64;
            }

            // Calculate the index for the next blob (prefix + data)
            let length = blob.len();
            let prefix_size = if length < 128 {
                1
            } else if length < 16384 {
                2
            } else {
                4
            };
            current_index += prefix_size + length as u32;
        }
    } else {
        // Addition-only scenario - calculate size of additions only
        for blob in &heap_changes.appended_items {
            // Blobs are prefixed with their length (compressed integer)
            let length_prefix_size = compressed_uint_size(blob.len());
            total_size += length_prefix_size + blob.len() as u64;
        }
    }

    // Align to 4-byte boundary (ECMA-335 II.24.2.2)
    // Padding is handled carefully in the writer to avoid phantom blob entries
    let aligned_size = align_to(total_size, 4);
    Ok(aligned_size)
}

/// Calculates the actual byte size needed for GUID heap modifications.
///
/// This function handles both addition-only scenarios and heap rebuilding scenarios.
/// When modifications or removals are present, it calculates the total size of the
/// rebuilt heap rather than just additions.
///
/// # Arguments
/// * `heap_changes` - The [`crate::cilassembly::HeapChanges<[u8; 16]>`] containing GUID changes
/// * `assembly` - The [`crate::cilassembly::CilAssembly`] for accessing original heap data
///
/// # Returns
/// Returns the total byte size needed for the GUID heap after all changes.
///
/// # Format
/// Each GUID is stored as 16 consecutive bytes in the heap.
pub fn calculate_guid_heap_size(
    heap_changes: &HeapChanges<[u8; 16]>,
    assembly: &CilAssembly,
) -> Result<u64> {
    let mut total_size = 0u64;

    if heap_changes.has_modifications() || heap_changes.has_removals() {
        // Heap rebuilding scenario - calculate total size of rebuilt heap

        // Build sets for efficient lookup of removed and modified indices
        let removed_indices = &heap_changes.removed_indices;
        let modified_indices: std::collections::HashSet<u32> =
            heap_changes.modified_items.keys().cloned().collect();

        // Calculate size of original GUIDs that are neither removed nor modified
        if let Some(guid_heap) = assembly.view().guids() {
            for (offset, _) in guid_heap.iter() {
                // The heap changes system uses byte offsets as indices
                let offset_u32 = offset as u32;
                if !removed_indices.contains(&offset_u32) && !modified_indices.contains(&offset_u32)
                {
                    total_size += 16; // Each GUID is exactly 16 bytes
                }
            }
        }

        // Add size of modified GUIDs (but only those that modify original GUIDs, not appended ones)
        let original_guid_count = if let Some(guid_heap) = assembly.view().guids() {
            guid_heap.iter().count() as u32
        } else {
            0
        };

        let modified_original_count = heap_changes
            .modified_items
            .keys()
            .filter(|&&index| index <= original_guid_count)
            .count();
        total_size += modified_original_count as u64 * 16;

        // Add size of all appended GUIDs (modifications to appended GUIDs are counted here, not above)
        let appended_count = heap_changes.appended_items.len();
        total_size += appended_count as u64 * 16;
    } else {
        // Addition-only scenario - calculate size of additions only
        total_size = heap_changes.appended_items.len() as u64 * 16;
    }

    // GUIDs are always 16 bytes each, so already aligned to 4-byte boundary
    Ok(total_size)
}

/// Calculates the actual byte size needed for userstring heap modifications.
///
/// This function handles both addition-only scenarios and heap rebuilding scenarios.
/// When modifications or removals are present, it calculates the total size of the
/// rebuilt heap rather than just additions.
///
/// # Arguments
/// * `heap_changes` - The [`crate::cilassembly::HeapChanges<String>`] containing user string changes
/// * `assembly` - The [`crate::cilassembly::CilAssembly`] for accessing original heap data
///
/// # Returns
/// Returns the total aligned byte size needed for the userstring heap after all changes.
///
/// # Format
/// Each user string is stored as: compressed_length + UTF-16_bytes + terminator, where the length
/// indicates the total size including the terminator byte.
pub fn calculate_userstring_heap_size(
    heap_changes: &HeapChanges<String>,
    assembly: &CilAssembly,
) -> Result<u64> {
    let mut total_size = 0u64;

    if heap_changes.has_modifications() || heap_changes.has_removals() {
        total_size += 1;

        // Build sets for efficient lookup of removed and modified indices
        let removed_indices = &heap_changes.removed_indices;
        let modified_indices: std::collections::HashSet<u32> =
            heap_changes.modified_items.keys().cloned().collect();

        // Calculate size of original user strings that are neither removed nor modified
        if let Some(userstring_heap) = assembly.view().userstrings() {
            for (offset, original_userstring) in userstring_heap.iter() {
                if offset == 0 {
                    continue;
                } // Skip the mandatory null byte at offset 0

                // The heap changes system uses byte offsets as indices
                let offset_u32 = offset as u32;
                if !removed_indices.contains(&offset_u32) && !modified_indices.contains(&offset_u32)
                {
                    // Convert to string and calculate UTF-16 length
                    if let Ok(string_value) = original_userstring.to_string() {
                        let utf16_length = string_value.encode_utf16().count() * 2; // 2 bytes per UTF-16 code unit
                        let total_entry_length = utf16_length + 1; // UTF-16 data + terminator byte

                        // Length prefix (compressed integer)
                        let length_prefix_size = if total_entry_length < 128 {
                            1
                        } else if total_entry_length < 16384 {
                            2
                        } else {
                            4
                        };

                        total_size += length_prefix_size as u64 + total_entry_length as u64;
                    }
                }
            }
        }

        // Calculate total size by rebuilding exactly what the writer will write
        // The writer creates a sorted list of all final userstrings and writes continuously

        // Reset total_size since we'll calculate from scratch
        total_size = 1; // Start with mandatory null byte

        // Calculate the starting index for appended items (same logic as add_userstring)
        let starting_next_index = if let Some(_userstring_heap) = assembly.view().userstrings() {
            // Use the actual heap size, not max offset (same as HeapChanges::new)
            let heap_stream = assembly.view().streams().iter().find(|s| s.name == "#US");
            heap_stream.map(|s| s.size).unwrap_or(0)
        } else {
            0
        };

        // Build the complete final userstring list (matching the writer's logic exactly)
        let mut all_userstrings: Vec<(u32, String)> = Vec::new();
        if let Some(userstring_heap) = assembly.view().userstrings() {
            for (offset, original_userstring) in userstring_heap.iter() {
                let heap_index = offset as u32;
                if !removed_indices.contains(&heap_index) {
                    let final_string = if let Some(modified_string) =
                        heap_changes.modified_items.get(&heap_index)
                    {
                        modified_string.clone()
                    } else {
                        original_userstring.to_string_lossy().to_string()
                    };
                    all_userstrings.push((heap_index, final_string));
                }
            }
        }

        // Add appended userstrings with their final content (accounting for modifications)
        let mut current_api_index = starting_next_index;
        for original_appended_string in &heap_changes.appended_items {
            if !removed_indices.contains(&current_api_index) {
                // Check if this appended string is modified
                let final_string = if let Some(modified_string) =
                    heap_changes.modified_items.get(&current_api_index)
                {
                    modified_string.clone()
                } else {
                    original_appended_string.clone()
                };
                all_userstrings.push((current_api_index, final_string));
            }

            // Advance API index by original string size (maintains API index stability)
            let orig_utf16_len = original_appended_string.encode_utf16().count() * 2;
            let orig_total_len = orig_utf16_len + 1;
            let orig_compressed_len_size = if orig_total_len < 128 {
                1
            } else if orig_total_len < 16384 {
                2
            } else {
                4
            };
            current_api_index += (orig_compressed_len_size + orig_total_len) as u32;
        }

        // Sort by API index (same as writer)
        all_userstrings.sort_by_key(|(index, _)| *index);

        // Calculate total size from final strings (exactly what the writer will write)
        for (_, final_string) in &all_userstrings {
            let utf16_length = final_string.encode_utf16().count() * 2;
            let total_entry_length = utf16_length + 1;
            let length_prefix_size = if total_entry_length < 128 {
                1
            } else if total_entry_length < 16384 {
                2
            } else {
                4
            };
            total_size += length_prefix_size as u64 + total_entry_length as u64;
        }
    } else {
        // Addition-only scenario - calculate size of additions only
        for string in &heap_changes.appended_items {
            // User strings are UTF-16 encoded with length prefix
            let utf16_length = string.encode_utf16().count() * 2; // 2 bytes per UTF-16 code unit
            let total_entry_length = utf16_length + 1; // UTF-16 data + terminator byte

            // Length prefix (compressed integer)
            let length_prefix_size = if total_entry_length < 128 {
                1
            } else if total_entry_length < 16384 {
                2
            } else {
                4
            };

            total_size += length_prefix_size as u64 + total_entry_length as u64;
        }
    }

    // Stream size must be 4-byte aligned for ECMA-335 compliance
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
        let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))
            .expect("Failed to load test assembly");
        let assembly = view.to_owned();

        let mut heap_changes = HeapChanges::new(0);
        heap_changes.appended_items.push("test".to_string());
        heap_changes.appended_items.push("hello world".to_string());

        let size = calculate_string_heap_size(&heap_changes, &assembly).unwrap();

        // "test" (4) + null (1) + "hello world" (11) + null (1) = 17 bytes
        // Aligned to 4 bytes = 20 bytes
        assert_eq!(size, 20);
    }

    #[test]
    fn test_blob_heap_size_calculation() {
        let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))
            .expect("Failed to load test assembly");
        let assembly = view.to_owned();

        // Test 1: Rebuild scenario (with changes)
        let mut heap_changes = HeapChanges::new(0);
        heap_changes.appended_items.push(vec![1, 2, 3]); // length 3, prefix 1 byte
        heap_changes.appended_items.push(vec![4, 5]); // length 2, prefix 1 byte

        let rebuilt_size = calculate_blob_heap_size(&heap_changes, &assembly).unwrap();

        // In rebuild scenario, should include original heap + new additions
        let original_heap_size = if let Some(blob_heap) = assembly.view().blobs() {
            blob_heap.data().len()
        } else {
            0
        };

        // blob1: 1 (prefix) + 3 (data) = 4 bytes
        // blob2: 1 (prefix) + 2 (data) = 3 bytes
        // total additions: 7 bytes, aligned to 4 = 8 bytes
        // But since has_changes()=true, we get original + additions
        assert!(rebuilt_size > original_heap_size as u64);
        assert!(rebuilt_size <= (original_heap_size + 8) as u64);
    }

    #[test]
    fn test_guid_heap_size_calculation() {
        let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))
            .expect("Failed to load test assembly");
        let assembly = view.to_owned();

        let mut heap_changes = HeapChanges::new(0);
        heap_changes.appended_items.push([0u8; 16]);
        heap_changes.appended_items.push([1u8; 16]);

        let size = calculate_guid_heap_size(&heap_changes, &assembly).unwrap();

        // 2 GUIDs * 16 bytes each = 32 bytes (already aligned)
        assert_eq!(size, 32);
    }

    #[test]
    fn test_userstring_heap_size_calculation() {
        let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))
            .expect("Failed to load test assembly");
        let assembly = view.to_owned();

        let mut heap_changes = HeapChanges::new(0);
        heap_changes.appended_items.push("A".to_string()); // 1 char = 2 UTF-16 bytes

        let size = calculate_userstring_heap_size(&heap_changes, &assembly).unwrap();

        // 1 (prefix) + 2 (UTF-16 data) + 1 (terminator) = 4 bytes, aligned to 4 = 4 bytes
        assert_eq!(size, 4);
    }

    #[test]
    fn test_empty_heap_changes() {
        let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))
            .expect("Failed to load test assembly");
        let assembly = view.to_owned();

        let empty_string_changes = HeapChanges::<String>::new(0);
        let empty_blob_changes = HeapChanges::<Vec<u8>>::new(0);
        let empty_guid_changes = HeapChanges::<[u8; 16]>::new(0);

        assert_eq!(
            calculate_string_heap_size(&empty_string_changes, &assembly).unwrap(),
            0
        );
        assert_eq!(
            calculate_blob_heap_size(&empty_blob_changes, &assembly).unwrap(),
            0
        );
        assert_eq!(
            calculate_guid_heap_size(&empty_guid_changes, &assembly).unwrap(),
            0
        );
        assert_eq!(
            calculate_userstring_heap_size(&empty_string_changes, &assembly).unwrap(),
            0
        );
    }

    #[test]
    fn test_empty_string_addition() {
        let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))
            .expect("Failed to load test assembly");
        let assembly = view.to_owned();

        let mut heap_changes = HeapChanges::new(0);
        heap_changes.appended_items.push("".to_string());

        let size = calculate_string_heap_size(&heap_changes, &assembly).unwrap();

        // Empty string = 0 bytes + 1 null terminator = 1 byte, aligned to 4 = 4 bytes
        assert_eq!(size, 4);
    }

    #[test]
    fn test_unicode_string_calculation() {
        let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))
            .expect("Failed to load test assembly");
        let assembly = view.to_owned();

        let mut heap_changes = HeapChanges::new(0);
        heap_changes.appended_items.push("Test🦀Rust".to_string());

        let size = calculate_string_heap_size(&heap_changes, &assembly).unwrap();

        // String is stored as UTF-8 bytes in string heap
        let utf8_len = "Test🦀Rust".len(); // 12 bytes (🦀 is 4 bytes in UTF-8)
        let expected_size = (utf8_len + 1).div_ceil(4) * 4; // +1 for null, align to 4

        assert_eq!(size, expected_size as u64);
    }

    #[test]
    fn test_large_blob_compressed_length() {
        let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))
            .expect("Failed to load test assembly");
        let assembly = view.to_owned();

        let mut heap_changes = HeapChanges::new(0);
        let large_blob = vec![0u8; 200]; // 200 bytes requires 2-byte compressed length
        heap_changes.appended_items.push(large_blob);

        let rebuilt_size = calculate_blob_heap_size(&heap_changes, &assembly).unwrap();

        // In rebuild scenario, should include original heap + new additions
        let original_heap_size = if let Some(blob_heap) = assembly.view().blobs() {
            blob_heap.data().len()
        } else {
            0
        };

        // 200-byte blob: 2 bytes length prefix + 200 bytes data = 202 bytes, aligned to 4 = 204 bytes
        // But since has_changes()=true, we get original + additions
        assert!(rebuilt_size > original_heap_size as u64);
        assert!(rebuilt_size <= (original_heap_size + 204) as u64);
    }

    #[test]
    fn test_align_to_function() {
        assert_eq!(align_to(0, 4), 0);
        assert_eq!(align_to(1, 4), 4);
        assert_eq!(align_to(4, 4), 4);
        assert_eq!(align_to(5, 4), 8);
        assert_eq!(align_to(7, 8), 8);
        assert_eq!(align_to(15, 16), 16);
        assert_eq!(align_to(33, 32), 64);
    }
}
