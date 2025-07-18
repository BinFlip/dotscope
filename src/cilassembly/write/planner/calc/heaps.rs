//! Heap size calculation functions for metadata heaps.
//!
//! This module provides specialized size calculation logic for all .NET metadata heap types,
//! implementing exact ECMA-335 specification requirements for heap encoding and alignment.
//! These calculations are essential for determining the exact binary size requirements
//! during the assembly write pipeline.
//!
//! # Key Components
//!
//! - [`calculate_string_heap_size`] - Calculates size for #Strings heap modifications
//! - [`calculate_string_heap_total_size`] - Calculates complete reconstructed string heap size
//! - [`calculate_blob_heap_size`] - Calculates size for #Blob heap modifications
//! - [`calculate_guid_heap_size`] - Calculates size for #GUID heap modifications
//! - [`calculate_userstring_heap_size`] - Calculates size for #US heap modifications
//!
//! # Architecture
//!
//! The size calculation system handles two distinct scenarios:
//!
//! ## Addition-Only Scenario
//! When only new items are added to heaps, calculations are straightforward:
//! - Calculate size of new items only
//! - Apply appropriate encoding (null terminators, compressed lengths, etc.)
//! - Apply 4-byte alignment requirements
//!
//! ## Heap Rebuilding Scenario
//! When modifications or removals are present, the entire heap must be rebuilt:
//! - Calculate size of original items (excluding removed ones)
//! - Apply modifications to existing items
//! - Add new items
//! - Maintain proper offset relationships for reference stability
//!
//! ## ECMA-335 Compliance
//! All calculations implement exact ECMA-335 specification requirements:
//! - **String Heap**: UTF-8 null-terminated strings with 4-byte alignment
//! - **Blob Heap**: Length-prefixed binary data with compressed length headers
//! - **GUID Heap**: 16-byte raw GUID values (naturally aligned)
//! - **UserString Heap**: UTF-16 strings with compressed length headers and termination
//!
//! # Usage Examples
//!
//! ```rust,ignore
//! use crate::cilassembly::write::planner::calc::calculate_string_heap_size;
//! use crate::cilassembly::{CilAssembly, HeapChanges};
//!
//! # let assembly = CilAssembly::new(view);
//! # let heap_changes = HeapChanges::<String>::new(100);
//! // Calculate additional space needed for string modifications
//! let additional_size = calculate_string_heap_size(&heap_changes, &assembly)?;
//! println!("Need {} additional bytes for string heap", additional_size);
//! # Ok::<(), crate::Error>(())
//! ```
//!
//! # Thread Safety
//!
//! All functions in this module are [`Send`] and [`Sync`] as they operate on immutable
//! references to heap changes and assembly data without maintaining any mutable state.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::cilassembly::write::planner`] - Uses calculations for layout planning
//! - Validates size calculations against actual heap writing
//! - [`crate::cilassembly::write::utils`] - Uses utility functions for alignment and compression

use crate::{
    cilassembly::{
        write::utils::{align_to, compressed_uint_size},
        CilAssembly, HeapChanges,
    },
    Result,
};

/// Calculates the actual byte size needed for string heap modifications.
///
/// This function handles both addition-only scenarios and heap rebuilding scenarios.
/// When modifications or removals are present, it preserves the original heap layout
/// for offset consistency and appends changed strings at the end.
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
pub(crate) fn calculate_string_heap_size(
    heap_changes: &HeapChanges<String>,
    assembly: &CilAssembly,
) -> Result<u64> {
    let mut total_size = 0u64;

    if heap_changes.has_modifications() || heap_changes.has_removals() {
        // When there are modifications or removals, we need to calculate the total size
        // using the same logic as calculate_string_heap_total_size to ensure consistency
        let total_size = calculate_string_heap_total_size(heap_changes, assembly)?;

        // But we need to subtract the existing heap size since calculate_string_heap_size
        // is supposed to return only the ADDITIONAL size needed
        let existing_heap_size = if let Some(_strings_heap) = assembly.view().strings() {
            assembly
                .view()
                .streams()
                .iter()
                .find(|stream| stream.name == "#Strings")
                .map(|stream| stream.size as u64)
                .unwrap_or(1)
        } else {
            1u64
        };

        return Ok(total_size - existing_heap_size);
    }
    // Addition-only scenario - calculate size of additions only
    for string in &heap_changes.appended_items {
        // Each string is null-terminated in the heap
        total_size += string.len() as u64 + 1; // +1 for null terminator
    }

    // Align to 4-byte boundary (ECMA-335 II.24.2.2)
    // Note: String heap padding uses 0xFF bytes to avoid creating empty string entries
    let aligned_size = align_to(total_size, 4);

    Ok(aligned_size)
}

/// Calculates the complete reconstructed string heap size.
///
/// This function calculates the total size of the reconstructed string heap,
/// including all original strings (excluding removed ones), modified strings,
/// and new strings. This is used for metadata layout planning when heap
/// reconstruction is required.
///
/// # Arguments
/// * `heap_changes` - The [`crate::cilassembly::HeapChanges<String>`] containing string changes
/// * `assembly` - The [`crate::cilassembly::CilAssembly`] for accessing original heap data
///
/// # Returns
/// Returns the total aligned byte size of the complete reconstructed heap.
pub(crate) fn calculate_string_heap_total_size(
    heap_changes: &HeapChanges<String>,
    assembly: &CilAssembly,
) -> Result<u64> {
    // If there's a heap replacement, use its size plus any appended items
    if let Some(replacement_heap) = heap_changes.replacement_heap() {
        let replacement_size = replacement_heap.len() as u64;
        let appended_size = heap_changes.binary_string_heap_size() as u64;
        // Add padding to align to 4-byte boundary
        let total_size = replacement_size + appended_size;
        let aligned_size = (total_size + 3) & !3; // Round up to next 4-byte boundary
        return Ok(aligned_size);
    }

    // This function must match EXACTLY what reconstruct_string_heap_in_memory does
    // to ensure stream directory size matches actual written heap size

    // Start with the actual end of existing content (where new strings will be added)
    let existing_content_end = if let Some(strings_heap) = assembly.view().strings() {
        let mut actual_end = 1u64; // Start after mandatory null byte at index 0
        for (offset, string) in strings_heap.iter() {
            if !heap_changes.is_removed(offset as u32) {
                let string_len =
                    if let Some(modified_string) = heap_changes.get_modification(offset as u32) {
                        modified_string.len() as u64
                    } else {
                        string.len() as u64
                    };
                let string_end = offset as u64 + string_len + 1; // +1 for null terminator
                actual_end = actual_end.max(string_end);
            }
        }
        actual_end
    } else {
        1u64
    };

    // Account for the original heap size and padding logic (matching reconstruction exactly)
    let original_heap_size = if let Some(_strings_heap) = assembly.view().strings() {
        assembly
            .view()
            .streams()
            .iter()
            .find(|stream| stream.name == "#Strings")
            .map(|stream| stream.size as u64)
            .unwrap_or(1)
    } else {
        1u64
    };

    // Apply the same padding logic as the reconstruction function
    let mut final_index_position = existing_content_end;
    if final_index_position < original_heap_size {
        let padding_needed = original_heap_size - final_index_position;
        final_index_position += padding_needed;
    } else if final_index_position == original_heap_size {
        // Don't add padding when we're exactly at the boundary
        // This matches the reconstruction logic
    }

    // Add space for new appended strings
    // We need to calculate the final size of each appended string accounting for modifications
    let mut additional_size = 0u64;
    for appended_string in heap_changes.appended_items.iter() {
        // Calculate the API index for this appended string by working backwards from next_index
        let mut api_index = heap_changes.next_index;
        for item in heap_changes.appended_items.iter().rev() {
            api_index -= (item.len() + 1) as u32;
            if std::ptr::eq(item, appended_string) {
                break;
            }
        }

        // Check if this appended string has been modified and use the final size
        let final_string_len =
            if let Some(modified_string) = heap_changes.get_modification(api_index) {
                modified_string.len()
            } else {
                appended_string.len()
            };
        additional_size += final_string_len as u64 + 1; // +1 for null terminator
    }

    let total_size = final_index_position + additional_size;

    // Apply 4-byte alignment (same as reconstruction)
    let aligned_size = align_to(total_size, 4);

    Ok(aligned_size)
}

/// Calculates the actual byte size needed for blob heap modifications.
///
/// This function handles both addition-only scenarios and heap rebuilding scenarios.
/// When modifications or removals are present, it calculates the total size of the
/// rebuilt heap rather than just additions.
///
/// # Arguments
///
/// * `heap_changes` - The [`crate::cilassembly::HeapChanges<Vec<u8>>`] containing blob changes
/// * `assembly` - The [`crate::cilassembly::CilAssembly`] for accessing original heap data
///
/// # Returns
///
/// Returns the total aligned byte size needed for the blob heap after all changes.
///
/// # Errors
///
/// Returns [`crate::Error`] if there are issues accessing the original blob heap data.
///
/// # Format
///
/// Each blob is stored as: compressed_length + binary_data, where compressed_length
/// is 1, 2, or 4 bytes depending on the data size according to ECMA-335 specification.
///
/// # Examples
///
/// ```rust,ignore
/// use crate::cilassembly::write::planner::calc::calculate_blob_heap_size;
/// use crate::cilassembly::{CilAssembly, HeapChanges};
///
/// # let assembly = CilAssembly::new(view);
/// # let heap_changes = HeapChanges::<Vec<u8>>::new(100);
/// // Calculate size for blob heap modifications
/// let size = calculate_blob_heap_size(&heap_changes, &assembly)?;
/// println!("Blob heap needs {} bytes", size);
/// # Ok::<(), crate::Error>(())
/// ```
pub(crate) fn calculate_blob_heap_size(
    heap_changes: &HeapChanges<Vec<u8>>,
    assembly: &CilAssembly,
) -> Result<u64> {
    // If there's a heap replacement, use its size plus any appended items
    if let Some(replacement_heap) = heap_changes.replacement_heap() {
        let replacement_size = replacement_heap.len() as u64;
        let appended_size = heap_changes.binary_blob_heap_size() as u64;
        // Add padding to align to 4-byte boundary
        let total_size = replacement_size + appended_size;
        let aligned_size = (total_size + 3) & !3; // Round up to next 4-byte boundary
        return Ok(aligned_size);
    }

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
            let prefix_size = compressed_uint_size(length);
            current_index += prefix_size as u32 + length as u32;
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
///
/// * `heap_changes` - The [`crate::cilassembly::HeapChanges<[u8; 16]>`] containing GUID changes
/// * `assembly` - The [`crate::cilassembly::CilAssembly`] for accessing original heap data
///
/// # Returns
///
/// Returns the total byte size needed for the GUID heap after all changes.
///
/// # Errors
///
/// Returns [`crate::Error`] if there are issues accessing the original GUID heap data.
///
/// # Format
///
/// Each GUID is stored as 16 consecutive bytes in the heap according to ECMA-335 specification.
/// GUIDs are naturally aligned to 4-byte boundaries.
///
/// # Examples
///
/// ```rust,ignore
/// use crate::cilassembly::write::planner::calc::calculate_guid_heap_size;
/// use crate::cilassembly::{CilAssembly, HeapChanges};
///
/// # let assembly = CilAssembly::new(view);
/// # let heap_changes = HeapChanges::<[u8; 16]>::new(100);
/// // Calculate size for GUID heap modifications
/// let size = calculate_guid_heap_size(&heap_changes, &assembly)?;
/// println!("GUID heap needs {} bytes", size);
/// # Ok::<(), crate::Error>(())
/// ```
pub(crate) fn calculate_guid_heap_size(
    heap_changes: &HeapChanges<[u8; 16]>,
    assembly: &CilAssembly,
) -> Result<u64> {
    // If there's a heap replacement, use its size plus any appended items
    if let Some(replacement_heap) = heap_changes.replacement_heap() {
        let replacement_size = replacement_heap.len() as u64;
        let appended_size = heap_changes.appended_items.len() as u64 * 16;
        // GUIDs are naturally aligned to 4-byte boundary (16 bytes each)
        return Ok(replacement_size + appended_size);
    }

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
        // Addition-only scenario - calculate total size (original + additions)

        if let Some(guid_heap) = assembly.view().guids() {
            total_size += guid_heap.iter().count() as u64 * 16;
        }
        total_size += heap_changes.appended_items.len() as u64 * 16;
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
///
/// * `heap_changes` - The [`crate::cilassembly::HeapChanges<String>`] containing user string changes
/// * `assembly` - The [`crate::cilassembly::CilAssembly`] for accessing original heap data
///
/// # Returns
///
/// Returns the total aligned byte size needed for the userstring heap after all changes.
///
/// # Errors
///
/// Returns [`crate::Error`] if there are issues accessing the original userstring heap data.
///
/// # Format
///
/// Each user string is stored as: compressed_length + UTF-16_bytes + terminator, where the length
/// indicates the total size including the terminator byte according to ECMA-335 specification.
///
/// # Examples
///
/// ```rust,ignore
/// use crate::cilassembly::write::planner::calc::calculate_userstring_heap_size;
/// use crate::cilassembly::{CilAssembly, HeapChanges};
///
/// # let assembly = CilAssembly::new(view);
/// # let heap_changes = HeapChanges::<String>::new(100);
/// // Calculate size for userstring heap modifications
/// let size = calculate_userstring_heap_size(&heap_changes, &assembly)?;
/// println!("Userstring heap needs {} bytes", size);
/// # Ok::<(), crate::Error>(())
/// ```
pub(crate) fn calculate_userstring_heap_size(
    heap_changes: &HeapChanges<String>,
    assembly: &CilAssembly,
) -> Result<u64> {
    // If there's a heap replacement, use its size plus any appended items
    if let Some(replacement_heap) = heap_changes.replacement_heap() {
        let replacement_size = replacement_heap.len() as u64;
        let appended_size = heap_changes.binary_userstring_heap_size() as u64;
        // Add padding to align to 4-byte boundary
        let total_size = replacement_size + appended_size;
        let aligned_size = (total_size + 3) & !3; // Round up to next 4-byte boundary
        return Ok(aligned_size);
    }

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
                        let length_prefix_size = compressed_uint_size(total_entry_length);

                        total_size += length_prefix_size + total_entry_length as u64;
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
            let orig_compressed_len_size = compressed_uint_size(orig_total_len);
            current_api_index += (orig_compressed_len_size as usize + orig_total_len) as u32;
        }

        // Sort by API index (same as writer)
        all_userstrings.sort_by_key(|(index, _)| *index);

        // Calculate total size from final strings (exactly what the writer will write)
        for (_, final_string) in &all_userstrings {
            let utf16_length = final_string.encode_utf16().count() * 2;
            let total_entry_length = utf16_length + 1;
            let length_prefix_size = compressed_uint_size(total_entry_length);
            total_size += length_prefix_size + total_entry_length as u64;
        }
    } else {
        // Addition-only scenario - calculate size of additions only
        for string in &heap_changes.appended_items {
            // User strings are UTF-16 encoded with length prefix
            let utf16_length = string.encode_utf16().count() * 2; // 2 bytes per UTF-16 code unit
            let total_entry_length = utf16_length + 1; // UTF-16 data + terminator byte

            // Length prefix (compressed integer)
            let length_prefix_size = compressed_uint_size(total_entry_length);

            total_size += length_prefix_size + total_entry_length as u64;
        }
    }

    // Stream size must be 4-byte aligned for ECMA-335 compliance
    let aligned_size = align_to(total_size, 4);
    Ok(aligned_size)
}

/// Calculates the complete reconstructed userstring heap size.
///
/// This function calculates the total size of the reconstructed userstring heap,
/// including all original userstrings (excluding removed ones), modified userstrings,
/// and new userstrings. This is used for metadata layout planning when heap
/// reconstruction is required.
///
/// # Arguments
/// * `heap_changes` - The [`crate::cilassembly::HeapChanges<String>`] containing userstring changes
/// * `assembly` - The [`crate::cilassembly::CilAssembly`] for accessing original heap data
///
/// # Returns
/// Returns the total aligned byte size of the complete reconstructed heap.
pub(crate) fn calculate_userstring_heap_total_size(
    heap_changes: &HeapChanges<String>,
    assembly: &CilAssembly,
) -> Result<u64> {
    // If there's a heap replacement, use its size plus any appended items
    if let Some(replacement_heap) = heap_changes.replacement_heap() {
        let replacement_size = replacement_heap.len() as u64;
        let appended_size = heap_changes.binary_userstring_heap_size() as u64;
        // Add padding to align to 4-byte boundary
        let total_size = replacement_size + appended_size;
        let aligned_size = (total_size + 3) & !3; // Round up to next 4-byte boundary
        return Ok(aligned_size);
    }

    let mut total_size = 1u64; // Start with mandatory null byte at index 0

    if heap_changes.has_modifications() || heap_changes.has_removals() {
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
                        let length_prefix_size = compressed_uint_size(total_entry_length);

                        total_size += length_prefix_size + total_entry_length as u64;
                    }
                }
            }
        }

        // Add size of modified userstrings (use the new values)
        for new_userstring in heap_changes.modified_items.values() {
            let utf16_length = new_userstring.encode_utf16().count() * 2;
            let total_entry_length = utf16_length + 1;
            let length_prefix_size = compressed_uint_size(total_entry_length);
            total_size += length_prefix_size + total_entry_length as u64;
        }

        // Add size of appended userstrings that haven't been modified
        let original_heap_size = if let Some(userstring_heap) = assembly.view().userstrings() {
            userstring_heap.data().len() as u32
        } else {
            0
        };

        let mut current_index = original_heap_size;
        for userstring in &heap_changes.appended_items {
            // Only count this appended userstring if it hasn't been modified
            if !heap_changes.modified_items.contains_key(&current_index) {
                let utf16_length = userstring.encode_utf16().count() * 2;
                let total_entry_length = utf16_length + 1;
                let length_prefix_size = compressed_uint_size(total_entry_length);
                total_size += length_prefix_size + total_entry_length as u64;
            }

            // Calculate the index for the next userstring (prefix + data)
            let length = userstring.encode_utf16().count() * 2;
            let total_length = length + 1;
            let prefix_size = compressed_uint_size(total_length);
            current_index += prefix_size as u32 + total_length as u32;
        }
    } else {
        // Addition-only scenario - calculate total size including original heap
        if let Some(userstring_heap) = assembly.view().userstrings() {
            // Calculate actual end of original content
            let mut actual_end = 1u64; // Start after mandatory null byte at index 0
            for (offset, userstring) in userstring_heap.iter() {
                let string_val = userstring.to_string_lossy();
                let utf16_bytes = string_val.encode_utf16().count() * 2;
                let total_length = utf16_bytes + 1; // +1 for terminator
                let compressed_length_size = compressed_uint_size(total_length);
                let entry_end = offset as u64 + compressed_length_size + total_length as u64;
                actual_end = actual_end.max(entry_end);
            }
            total_size = actual_end;
        }

        // Add size of new userstrings
        for string in &heap_changes.appended_items {
            let utf16_length = string.encode_utf16().count() * 2;
            let total_entry_length = utf16_length + 1;
            let length_prefix_size = compressed_uint_size(total_entry_length);
            total_size += length_prefix_size + total_entry_length as u64;
        }
    }

    // Stream size must be 4-byte aligned for ECMA-335 compliance
    let aligned_size = align_to(total_size, 4);
    Ok(aligned_size)
}
