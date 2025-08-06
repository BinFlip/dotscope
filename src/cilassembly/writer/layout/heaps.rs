//! Heap size calculation functions for the simplified assembly writer.
//!
//! This module provides specialized size calculation logic for all .NET metadata heap types,
//! implementing exact ECMA-335 specification requirements for heap encoding and alignment.
//! These battle-tested algorithms are essential for determining precise binary size requirements
//! during the revolutionary 3-stage assembly write pipeline.
//!
//! # Architecture
//!
//! The heap calculation system supports the **"Complete Planning, Zero Decisions"** philosophy
//! by pre-calculating exact heap sizes during the layout planning phase:
//!
//! ```text
//! ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
//! │  Heap Changes   │───▶│ Size Calculator │───▶│  Exact Sizes    │
//! │   Analysis      │    │   Functions     │    │  for Layout     │
//! └─────────────────┘    └─────────────────┘    └─────────────────┘
//!          │                       │                       │
//!          ▼                       ▼                       ▼
//! ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
//! │ • Additions     │    │ • String Heap   │    │ • Planning      │
//! │ • Modifications │    │ • Blob Heap     │    │ • Allocation    │
//! │ • Removals      │    │ • GUID Heap     │    │ • Validation    │
//! │ • Replacements  │    │ • UserStr Heap  │    │ • Operations    │
//! └─────────────────┘    └─────────────────┘    └─────────────────┘
//! ```
//!
//! # Key Components
//!
//! - [`crate::cilassembly::writer::layout::heaps::calculate_string_heap_size`] - String heap size with ECMA-335 null termination
//! - [`crate::cilassembly::writer::layout::heaps::calculate_blob_heap_size`] - Blob heap size with compressed length prefixes
//! - [`crate::cilassembly::writer::layout::heaps::calculate_guid_heap_size`] - GUID heap size with 16-byte alignment
//! - [`crate::cilassembly::writer::layout::heaps::calculate_userstring_heap_size`] - User string heap size with UTF-16 encoding
//!
//! # Calculation Strategy
//!
//! ## Battle-Tested Algorithms
//! These functions are derived from the proven algorithms in the legacy pipeline,
//! ensuring 100% compatibility and accuracy while being adapted for the simplified
//! architecture.
//!
//! ## Scenario Handling
//! Each heap calculator handles multiple scenarios:
//! - **Addition-Only**: When only new entries are added (most efficient)
//! - **Modification/Removal**: When existing entries are changed or removed (requires rebuilding)
//! - **Replacement**: When entire heaps are replaced with new content
//!
//! ## ECMA-335 Compliance
//! All calculations strictly follow ECMA-335 specification requirements:
//! - **String Heap**: UTF-8 encoding with null termination, 4-byte aligned
//! - **Blob Heap**: Compressed length prefix + binary data, 4-byte aligned
//! - **GUID Heap**: 16 consecutive bytes per GUID, naturally 4-byte aligned
//! - **User String Heap**: Compressed length + UTF-16 + terminator, 4-byte aligned
//!
//! # Heap Format Specifications
//!
//! ## String Heap Format (#Strings)
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │ Null │ String1\\0 │ String2\\0 │ ... │ StringN\\0 │ Padding(0xFF) │
//! │  0x00 │   UTF-8    │   UTF-8    │     │   UTF-8    │  to 4-byte    │
//! └─────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Blob Heap Format (#Blob)
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │ Null │ Len1│Data1 │ Len2│Data2 │ ... │ LenN│DataN │ Padding(0xFF) │
//! │  0x00 │CompInt│Bytes│CompInt│Bytes│     │CompInt│Bytes│ to 4-byte     │
//! └─────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## GUID Heap Format (#GUID)
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │           GUID1           │           GUID2           │ ... │ GUIDN  │
//! │      16 bytes each        │      16 bytes each        │     │16 bytes│
//! └─────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## User String Heap Format (#US)
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │ Null │ Len1│UTF16₁│T│ Len2│UTF16₂│T│ ... │ LenN│UTF16ₙ│T│ Padding │
//! │  0x00 │CompInt│Data │1││CompInt│Data │1││     │CompInt│Data │1││0xFF │
//! └─────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Performance Characteristics
//!
//! - **Constant Time Complexity**: Most calculations are O(1) or O(n) where n is the number of changes
//! - **Memory Efficient**: No heap reconstruction during calculation, only size analysis
//! - **Cache-Friendly**: Sequential access patterns for optimal performance
//! - **Minimal Allocations**: Uses iterators and references where possible
//!
//! # Thread Safety
//!
//! All calculation functions are thread-safe:
//! - **Pure Functions**: No mutable global state
//! - **Immutable Inputs**: Only read from assembly and heap changes
//! - **No Side Effects**: Only perform calculations and return results
//! - **Safe Concurrency**: Can be called concurrently for different assemblies
//!
//! # Integration
//!
//! This module integrates with:
//!
//! - [`crate::cilassembly::writer::layout::planner`] - Layout planning using calculated sizes
//! - [`crate::cilassembly::writer::heap_builders`] - Heap reconstruction with size validation
//! - [`crate::cilassembly::HeapChanges`] - Change tracking for heap modifications
//! - [`crate::cilassembly::CilAssembly`] - Source assembly analysis
//! - [`crate::utils`] - Shared utilities for alignment and compression
//!
//! # Examples
//!
//! ## Basic String Heap Size Calculation
//!
//! ```text
//! use dotscope::cilassembly::writer::layout::heaps::calculate_string_heap_size;
//! use dotscope::prelude::*;
//! use std::path::Path;
//!
//! # let view = CilAssemblyView::from_file(Path::new(\"tests/samples/crafted_2.exe\"))?;
//! # let mut assembly = view.to_owned();
//! // Add some strings and calculate size
//! assembly.changes_mut().strings.add_string(\"Hello, World!\".to_string());
//! assembly.changes_mut().strings.add_string(\"Another string\".to_string());
//!
//! let string_heap_size = calculate_string_heap_size(
//!     &assembly.changes().strings,
//!     &assembly
//! )?;
//!
//! println!(\"String heap size: {} bytes\", string_heap_size);
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Comprehensive Heap Size Analysis
//!
//! ```text
//! use dotscope::cilassembly::writer::layout::heaps::*;
//! use dotscope::prelude::*;
//! use std::path::Path;
//!
//! # let view = CilAssemblyView::from_file(Path::new(\"tests/samples/crafted_2.exe\"))?;
//! # let mut assembly = view.to_owned();
//! // Calculate sizes for all heap types
//! let string_size = calculate_string_heap_size(&assembly.changes().strings, &assembly)?;
//! let blob_size = calculate_blob_heap_size(&assembly.changes().blobs, &assembly)?;
//! let guid_size = calculate_guid_heap_size(&assembly.changes().guids, &assembly)?;
//! let userstr_size = calculate_userstring_heap_size(&assembly.changes().userstrings, &assembly)?;
//!
//! let total_heap_size = string_size + blob_size + guid_size + userstr_size;
//! println!(\"Total heap size: {} bytes\", total_heap_size);
//! println!(\"  Strings: {} bytes\", string_size);
//! println!(\"  Blobs: {} bytes\", blob_size);
//! println!(\"  GUIDs: {} bytes\", guid_size);
//! println!(\"  User Strings: {} bytes\", userstr_size);
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # References
//!
//! - [ECMA-335 II.24.2.2 - #Strings heap](https://www.ecma-international.org/publications/standards/Ecma-335.htm)
//! - [ECMA-335 II.24.2.3 - #US and #Blob heaps](https://www.ecma-international.org/publications/standards/Ecma-335.htm)
//! - [ECMA-335 II.24.2.4 - #GUID heap](https://www.ecma-international.org/publications/standards/Ecma-335.htm)

use crate::{
    cilassembly::{CilAssembly, HeapChanges},
    utils::{align_to, compressed_uint_size},
    Error, Result,
};

/// Calculates the actual byte size needed for string heap modifications with ECMA-335 compliance.
///
/// This function performs precise size calculation for the #Strings heap, handling both
/// simple addition-only scenarios and complex heap rebuilding scenarios. It implements
/// exact ECMA-335 specification requirements for string storage and alignment.
///
/// # Calculation Strategy
///
/// ## Addition-Only Scenario
/// When only new strings are added (most common and efficient case):
/// - Calculates size of new strings only
/// - Each string: UTF-8 bytes + null terminator (0x00)
/// - Applies 4-byte alignment with 0xFF padding
///
/// ## Modification/Removal Scenario
/// When existing strings are modified or removed (requires heap rebuilding):
/// - Calculates total size after reconstruction
/// - Preserves original layout where possible for offset consistency
/// - Appends oversized modifications at the end
/// - Accounts for remapping of large modifications
///
/// # ECMA-335 String Heap Format
///
/// ```text
/// Offset  Content
/// ------  -------
/// 0x00    Null byte (mandatory empty string at index 0)
/// 0x01    "Hello\\0"     (UTF-8 + null terminator)
/// 0x07    "World\\0"     (UTF-8 + null terminator)
/// 0x0D    "Test\\0"      (UTF-8 + null terminator)
/// 0x12    0xFF 0xFF      (Padding to 4-byte boundary)
/// ```
///
/// # Arguments
///
/// * `heap_changes` - The [`crate::cilassembly::HeapChanges<String>`] containing all string
///   modifications, additions, and removals to be applied
/// * `assembly` - The [`crate::cilassembly::CilAssembly`] for accessing original heap data
///   and determining the current state
///
/// # Returns
///
/// Returns the total aligned byte size needed for the string heap after all changes
/// are applied. This size includes:
/// - Original strings (excluding removed ones)
/// - Modified strings (using their new sizes)
/// - Newly added strings
/// - Required alignment padding to 4-byte boundary
///
/// # Errors
///
/// Returns [`crate::Error::WriteLayoutFailed`] if:
/// - String heap offset calculations exceed u32 range
/// - String size calculations result in overflow
/// - Original heap data is corrupted or inaccessible
///
/// # Examples
///
/// ## Addition-Only Calculation
///
/// ```rust,ignore
/// use dotscope::cilassembly::writer::layout::heaps::calculate_string_heap_size;
/// use dotscope::prelude::*;
/// use std::path::Path;
///
/// # let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))?;
/// # let mut assembly = view.to_owned();
/// // Add new strings
/// assembly.changes_mut().strings.add_string("Hello".to_string());
/// assembly.changes_mut().strings.add_string("World".to_string());
///
/// let size = calculate_string_heap_size(&assembly.changes().strings, &assembly)?;
/// // Size includes: "Hello\0" (6) + "World\0" (6) + padding = 12 bytes aligned to 4
/// assert_eq!(size, 12);
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// ## Modification Scenario
///
/// ```rust,ignore
/// use dotscope::cilassembly::writer::layout::heaps::calculate_string_heap_size;
/// use dotscope::prelude::*;
/// use std::path::Path;
///
/// # let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))?;
/// # let mut assembly = view.to_owned();
/// // Modify existing string at index 1
/// assembly.changes_mut().strings.modify_string(1, "Modified String".to_string());
///
/// let total_size = calculate_string_heap_size(&assembly.changes().strings, &assembly)?;
/// // Calculates total reconstructed heap size with modifications
/// println!("Total string heap size: {} bytes", total_size);
/// # Ok::<(), dotscope::Error>(())
/// ```
pub fn calculate_string_heap_size(
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
                .map_or(1, |stream| u64::from(stream.size))
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
pub fn calculate_string_heap_total_size(
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
            if !heap_changes.is_removed(u32::try_from(offset).map_err(|_| {
                Error::WriteLayoutFailed {
                    message: "String heap offset exceeds u32 range".to_string(),
                }
            })?) {
                let string_len = if let Some(modified_string) =
                    heap_changes.get_modification(u32::try_from(offset).map_err(|_| {
                        Error::WriteLayoutFailed {
                            message: "String heap offset exceeds u32 range (modification)"
                                .to_string(),
                        }
                    })?) {
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
            .map_or(1, |stream| u64::from(stream.size))
    } else {
        1u64
    };

    // Apply the same padding logic as the reconstruction function
    let mut final_index_position = existing_content_end;
    match final_index_position.cmp(&original_heap_size) {
        std::cmp::Ordering::Less => {
            let padding_needed = original_heap_size - final_index_position;
            final_index_position += padding_needed;
        }
        std::cmp::Ordering::Equal | std::cmp::Ordering::Greater => {
            // Don't add padding when we're exactly at the boundary or beyond
            // This matches the reconstruction logic
        }
    }

    // Add space for new appended strings
    // We need to calculate the final size of each appended string accounting for modifications
    let mut additional_size = 0u64;
    for appended_string in &heap_changes.appended_items {
        // Calculate the API index for this appended string by working backwards from next_index
        let mut api_index = heap_changes.next_index;
        for item in heap_changes.appended_items.iter().rev() {
            api_index -= u32::try_from(item.len() + 1).map_err(|_| Error::WriteLayoutFailed {
                message: "String item size exceeds u32 range".to_string(),
            })?;
            if std::ptr::eq(item, appended_string) {
                break;
            }
        }

        // Check if this appended string has been removed
        if !heap_changes.is_removed(api_index) {
            // Check if this appended string has been modified and use the final size
            let final_string_len =
                if let Some(modified_string) = heap_changes.get_modification(api_index) {
                    modified_string.len()
                } else {
                    appended_string.len()
                };
            additional_size += final_string_len as u64 + 1; // +1 for null terminator
        }
    }

    // CRITICAL FIX: Add space for remapped modifications
    // When a modified string is too large for its original space, it gets remapped to the end
    if let Some(strings_heap) = assembly.view().strings() {
        for (&modified_index, new_string) in &heap_changes.modified_items {
            // Find the original string to determine if remapping is needed
            if let Some((_offset, original_string)) = strings_heap
                .iter()
                .find(|(offset, _)| *offset == modified_index as usize)
            {
                let original_space = original_string.len(); // Available space (excluding null terminator)
                let new_size = new_string.len();

                if new_size > original_space {
                    // This modification will be remapped to the end - add its size
                    additional_size += new_size as u64 + 1; // +1 for null terminator
                }
            }
        }
    }

    let total_size = final_index_position + additional_size;

    // Apply 4-byte alignment (same as reconstruction)
    let aligned_size = align_to(total_size, 4);

    Ok(aligned_size)
}

/// Calculates the actual byte size needed for blob heap modifications with ECMA-335 compliance.
///
/// This function performs precise size calculation for the #Blob heap, handling both
/// simple addition-only scenarios and complex heap rebuilding scenarios. It implements
/// exact ECMA-335 specification requirements for blob storage with compressed length prefixes.
///
/// # Calculation Strategy
///
/// ## Addition-Only Scenario
/// When only new blobs are added (most efficient case):
/// - Calculates size of new blobs only
/// - Each blob: compressed length prefix + binary data
/// - Applies 4-byte alignment with 0xFF padding
///
/// ## Modification/Removal Scenario
/// When existing blobs are modified or removed (requires heap rebuilding):
/// - Uses append-only strategy with zero-padding for in-place modifications
/// - Oversized modifications are remapped to the end
/// - Maintains original heap structure for consistency
/// - Accounts for all size changes precisely
///
/// # ECMA-335 Blob Heap Format
///
/// ```text
/// Offset  Content
/// ------  -------
/// 0x00    0x00              (Null blob at index 0)
/// 0x01    0x05 0x48 0x65... (Length=5, then 5 bytes of data)
/// 0x07    0x8F 0x02 0x12... (Length=271, compressed as 0x8F 0x02)
/// 0x??    0xFF 0xFF         (Padding to 4-byte boundary)
/// ```
///
/// ## Compressed Length Encoding
/// Per ECMA-335 II.24.2.4:
/// - 0x00-0x7F: 1 byte (length ≤ 127)
/// - 0x8000-0xBFFF: 2 bytes (length ≤ 16383)
/// - 0xC0000000-0xDFFFFFFF: 4 bytes (length ≤ 536870911)
///
/// # Arguments
///
/// * `heap_changes` - The [`crate::cilassembly::HeapChanges<Vec<u8>>`] containing all blob
///   modifications, additions, and removals to be applied
/// * `assembly` - The [`crate::cilassembly::CilAssembly`] for accessing original heap data
///   and determining the current state
///
/// # Returns
///
/// Returns the total aligned byte size needed for the blob heap after all changes
/// are applied. This size includes:
/// - Original blobs (with zero-padding for in-place modifications)
/// - Remapped blobs that don't fit in their original space
/// - Newly added blobs with proper length prefixes
/// - Required alignment padding to 4-byte boundary
///
/// # Errors
///
/// Returns [`crate::Error::WriteLayoutFailed`] if:
/// - Blob heap offset calculations exceed u32 range
/// - Blob size calculations result in overflow
/// - Original heap data is corrupted or inaccessible
/// - Compressed length calculations fail
///
/// # Examples
///
/// ## Addition-Only Calculation
///
/// ```rust,ignore
/// use dotscope::cilassembly::writer::layout::heaps::calculate_blob_heap_size;
/// use dotscope::prelude::*;
/// use std::path::Path;
///
/// # let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))?;
/// # let mut assembly = view.to_owned();
/// // Add new blobs
/// assembly.changes_mut().blobs.add_blob(vec![0x01, 0x02, 0x03]);
/// assembly.changes_mut().blobs.add_blob(vec![0x04, 0x05]);
///
/// let size = calculate_blob_heap_size(&assembly.changes().blobs, &assembly)?;
/// // Size includes: length_prefix + data for each blob + alignment
/// println!("Blob heap size: {} bytes", size);
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// ## Modification with Remapping
///
/// ```rust,ignore
/// use dotscope::cilassembly::writer::layout::heaps::calculate_blob_heap_size;
/// use dotscope::prelude::*;
/// use std::path::Path;
///
/// # let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))?;
/// # let mut assembly = view.to_owned();
/// // Modify existing blob with larger data (will be remapped)
/// let large_blob = vec![0; 1000]; // Much larger than original
/// assembly.changes_mut().blobs.modify_blob(5, large_blob);
///
/// let total_size = calculate_blob_heap_size(&assembly.changes().blobs, &assembly)?;
/// // Includes original heap + remapped modifications
/// println!("Total blob heap size: {} bytes", total_size);
/// # Ok::<(), dotscope::Error>(())
/// ```
pub fn calculate_blob_heap_size(
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
        // NEW APPROACH: Match the append-only strategy used by BlobHeapBuilder
        // The builder uses zero-padding with remapping to the end, so we need to calculate
        // the size exactly as the builder constructs it

        // Start with the original heap size (this is preserved with zero-padding)
        let original_heap_size = if let Some(blob_heap) = assembly.view().blobs() {
            blob_heap.data().len() as u64
        } else {
            1u64 // Just the null byte if no original heap
        };

        total_size = original_heap_size;

        // Add remapped modifications that don't fit in place
        // These are appended at the end as new blobs
        if let Some(blob_heap) = assembly.view().blobs() {
            for (&modified_index, new_blob) in &heap_changes.modified_items {
                if let Some((_, original_blob)) = blob_heap
                    .iter()
                    .find(|(offset, _)| *offset == modified_index as usize)
                {
                    let original_data_size = original_blob.len();
                    let new_blob_size = new_blob.len();

                    // Check if this blob needs remapping (doesn't fit in place)
                    if new_blob_size > original_data_size {
                        // This will be remapped to the end - add its full size
                        let length_prefix_size = compressed_uint_size(new_blob.len());
                        total_size += length_prefix_size + new_blob.len() as u64;
                    }
                    // If it fits in place, no additional size needed (just zero-padding)
                }
            }
        }

        // Add appended blobs (matching the builder's logic exactly)
        let original_heap_size = if let Some(blob_heap) = assembly.view().blobs() {
            blob_heap.data().len() as u32
        } else {
            0u32
        };

        let mut current_index = original_heap_size;
        for original_blob in &heap_changes.appended_items {
            // Check if this appended blob has been removed
            if heap_changes.removed_indices.contains(&current_index) {
                // Skip removed appended blob - no size added
            } else if let Some(modified_blob) = heap_changes.modified_items.get(&current_index) {
                // Use modified version
                let length_prefix_size = compressed_uint_size(modified_blob.len());
                total_size += length_prefix_size + modified_blob.len() as u64;
            } else {
                // Use original appended blob
                let length_prefix_size = compressed_uint_size(original_blob.len());
                total_size += length_prefix_size + original_blob.len() as u64;
            }

            // Update current index by original blob size (maintains API index stability)
            let prefix_size = compressed_uint_size(original_blob.len());
            current_index += prefix_size as u32 + original_blob.len() as u32;
        }
    } else {
        // Addition-only scenario - calculate size of additions only
        for blob in &heap_changes.appended_items {
            // Blobs are prefixed with their length (compressed integer)
            let length_prefix_size = compressed_uint_size(blob.len());
            total_size += length_prefix_size + blob.len() as u64;
        }

        // CRITICAL FIX: If there are no changes AND no additions, we still need to preserve
        // the original blob heap size for zero-modification roundtrips
        if heap_changes.appended_items.is_empty() {
            if let Some(_blob_heap) = assembly.view().blobs() {
                // Get the original blob heap size from the stream directory
                let original_size = assembly
                    .view()
                    .streams()
                    .iter()
                    .find(|stream| stream.name == "#Blob")
                    .map_or(0, |stream| u64::from(stream.size));
                total_size = original_size;
            }
        }
    }

    // Align to 4-byte boundary (ECMA-335 II.24.2.2)
    // Padding is handled carefully in the writer to avoid phantom blob entries
    let aligned_size = align_to(total_size, 4);
    Ok(aligned_size)
}

/// Calculates the actual byte size needed for GUID heap modifications with ECMA-335 compliance.
///
/// This function performs precise size calculation for the #GUID heap, handling both
/// simple addition-only scenarios and complex heap rebuilding scenarios. GUID heap
/// calculations are the simplest among all heap types due to their fixed 16-byte size.
///
/// # Calculation Strategy
///
/// ## Addition-Only Scenario
/// When only new GUIDs are added (most efficient case):
/// - Each GUID contributes exactly 16 bytes
/// - No alignment padding needed (16 is naturally 4-byte aligned)
/// - Total size = original_count × 16 + new_count × 16
///
/// ## Modification/Removal Scenario
/// When existing GUIDs are modified or removed:
/// - Counts original GUIDs that remain (not removed, not modified)
/// - Adds all modified GUIDs (16 bytes each)
/// - Adds all appended GUIDs that weren't removed
/// - No length prefixes or padding needed
///
/// # ECMA-335 GUID Heap Format
///
/// ```text
/// Offset  Content
/// ------  -------
/// 0x00    GUID1 (16 bytes: 00112233-4455-6677-8899-AABBCCDDEEFF)
/// 0x10    GUID2 (16 bytes: 11223344-5566-7788-99AA-BBCCDDEEFF00)
/// 0x20    GUID3 (16 bytes: 22334455-6677-8899-AABB-CCDDEEFF0011)
/// ```
///
/// ## Fixed Size Benefits
/// - **No compression**: GUIDs are stored as raw 16-byte values
/// - **No length prefixes**: Fixed size eliminates the need for length encoding
/// - **Natural alignment**: 16 bytes is always 4-byte aligned
/// - **Simple calculation**: Size = count × 16
///
/// # Arguments
///
/// * `heap_changes` - The [`crate::cilassembly::HeapChanges<[u8; 16]>`] containing all GUID
///   modifications, additions, and removals to be applied
/// * `assembly` - The [`crate::cilassembly::CilAssembly`] for accessing original heap data
///   and determining the current state
///
/// # Returns
///
/// Returns the total byte size needed for the GUID heap after all changes are applied.
/// This size is always a multiple of 16 bytes and includes:
/// - Original GUIDs (excluding removed ones)
/// - Modified GUIDs (16 bytes each)
/// - Newly added GUIDs (16 bytes each)
///
/// # Errors
///
/// Returns [`crate::Error::WriteLayoutFailed`] if:
/// - GUID heap offset calculations exceed u32 range
/// - GUID count calculations result in overflow
/// - Original heap data is corrupted or inaccessible
///
/// # Examples
///
/// ## Addition-Only Calculation
///
/// ```rust,ignore
/// use dotscope::cilassembly::writer::layout::heaps::calculate_guid_heap_size;
/// use dotscope::prelude::*;
/// use std::path::Path;
///
/// # let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))?;
/// # let mut assembly = view.to_owned();
/// // Add new GUIDs
/// let guid1 = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
///              0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
/// let guid2 = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
///              0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00];
///
/// assembly.changes_mut().guids.add_guid(guid1);
/// assembly.changes_mut().guids.add_guid(guid2);
///
/// let size = calculate_guid_heap_size(&assembly.changes().guids, &assembly)?;
/// // Size = 2 GUIDs × 16 bytes = 32 bytes (no padding needed)
/// assert_eq!(size, 32);
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// ## Modification Scenario
///
/// ```rust,ignore
/// use dotscope::cilassembly::writer::layout::heaps::calculate_guid_heap_size;
/// use dotscope::prelude::*;
/// use std::path::Path;
///
/// # let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))?;
/// # let mut assembly = view.to_owned();
/// // Modify existing GUID at offset 16 (second GUID)
/// let new_guid = [0xFF; 16]; // All 0xFF bytes
/// assembly.changes_mut().guids.modify_guid(16, new_guid);
///
/// let total_size = calculate_guid_heap_size(&assembly.changes().guids, &assembly)?;
/// // Includes all original GUIDs + modified GUID (16 bytes each)
/// println!("Total GUID heap size: {} bytes", total_size);
/// # Ok::<(), dotscope::Error>(())
/// ```
pub fn calculate_guid_heap_size(
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
            heap_changes.modified_items.keys().copied().collect();

        // Calculate size of original GUIDs that are neither removed nor modified
        if let Some(guid_heap) = assembly.view().guids() {
            for (offset, _) in guid_heap.iter() {
                // The heap changes system uses byte offsets as indices
                let offset_u32 = u32::try_from(offset).map_err(|_| Error::WriteLayoutFailed {
                    message: "Blob heap offset exceeds u32 range".to_string(),
                })?;
                if !removed_indices.contains(&offset_u32) && !modified_indices.contains(&offset_u32)
                {
                    total_size += 16; // Each GUID is exactly 16 bytes
                }
            }
        }

        // Add size of modified GUIDs (but only those that modify original GUIDs, not appended ones)
        let original_guid_count = if let Some(guid_heap) = assembly.view().guids() {
            u32::try_from(guid_heap.iter().count()).map_err(|_| Error::WriteLayoutFailed {
                message: "GUID heap count exceeds u32 range".to_string(),
            })?
        } else {
            0
        };

        let modified_original_count = heap_changes
            .modified_items
            .keys()
            .filter(|&&index| index <= original_guid_count)
            .count();
        total_size += modified_original_count as u64 * 16;

        // Add size of appended GUIDs that haven't been removed
        let original_heap_size = if let Some(guid_heap) = assembly.view().guids() {
            u32::try_from(guid_heap.data().len()).map_err(|_| Error::WriteLayoutFailed {
                message: "GUID heap data length exceeds u32 range".to_string(),
            })?
        } else {
            0
        };

        let mut current_index = original_heap_size;
        for _guid in &heap_changes.appended_items {
            // Only count this appended GUID if it hasn't been removed
            if !heap_changes.removed_indices.contains(&current_index) {
                total_size += 16; // Each GUID is exactly 16 bytes
            }
            current_index += 16; // Each GUID takes 16 bytes
        }
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
pub fn calculate_userstring_heap_size(
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
            heap_changes.modified_items.keys().copied().collect();

        // Calculate size of original user strings that are neither removed nor modified
        if let Some(userstring_heap) = assembly.view().userstrings() {
            for (offset, original_userstring) in userstring_heap.iter() {
                if offset == 0 {
                    continue;
                } // Skip the mandatory null byte at offset 0

                // The heap changes system uses byte offsets as indices
                let offset_u32 = u32::try_from(offset).map_err(|_| Error::WriteLayoutFailed {
                    message: "Blob heap offset exceeds u32 range".to_string(),
                })?;
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
            heap_stream.map_or(0, |s| s.size)
        } else {
            0
        };

        // Build the complete final userstring list (matching the writer's logic exactly)
        let mut all_userstrings: Vec<(u32, String)> = Vec::new();
        if let Some(userstring_heap) = assembly.view().userstrings() {
            for (offset, original_userstring) in userstring_heap.iter() {
                let heap_index = u32::try_from(offset).map_err(|_| Error::WriteLayoutFailed {
                    message: "Userstring heap offset exceeds u32 range".to_string(),
                })?;
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
            current_api_index += u32::try_from(
                usize::try_from(orig_compressed_len_size).map_err(|_| {
                    Error::WriteLayoutFailed {
                        message: "Compressed length size exceeds usize range".to_string(),
                    }
                })? + orig_total_len,
            )
            .map_err(|_| Error::WriteLayoutFailed {
                message: "Combined userstring size exceeds u32 range".to_string(),
            })?;
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

        // CRITICAL FIX: If there are no changes AND no additions, we still need to preserve
        // the original user string heap size for zero-modification roundtrips
        if heap_changes.appended_items.is_empty() {
            if let Some(_userstring_heap) = assembly.view().userstrings() {
                // Get the original user string heap size from the stream directory
                let original_size = assembly
                    .view()
                    .streams()
                    .iter()
                    .find(|stream| stream.name == "#US")
                    .map_or(0, |stream| u64::from(stream.size));
                total_size = original_size;
            }
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
pub fn calculate_userstring_heap_total_size(
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
            heap_changes.modified_items.keys().copied().collect();

        // Calculate size of original user strings that are neither removed nor modified
        if let Some(userstring_heap) = assembly.view().userstrings() {
            for (offset, original_userstring) in userstring_heap.iter() {
                if offset == 0 {
                    continue;
                } // Skip the mandatory null byte at offset 0

                // The heap changes system uses byte offsets as indices
                let offset_u32 = u32::try_from(offset).map_err(|_| Error::WriteLayoutFailed {
                    message: "Blob heap offset exceeds u32 range".to_string(),
                })?;
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
            u32::try_from(userstring_heap.data().len()).map_err(|_| Error::WriteLayoutFailed {
                message: "Userstring heap data length exceeds u32 range".to_string(),
            })?
        } else {
            0
        };

        let mut current_index = original_heap_size;
        for userstring in &heap_changes.appended_items {
            // Only count this appended userstring if it hasn't been modified or removed
            if !heap_changes.modified_items.contains_key(&current_index)
                && !heap_changes.removed_indices.contains(&current_index)
            {
                let utf16_length = userstring.encode_utf16().count() * 2;
                let total_entry_length = utf16_length + 1;
                let length_prefix_size = compressed_uint_size(total_entry_length);
                total_size += length_prefix_size + total_entry_length as u64;
            }

            // Calculate the index for the next userstring (prefix + data)
            let length = userstring.encode_utf16().count() * 2;
            let total_length = length + 1;
            let prefix_size = compressed_uint_size(total_length);
            current_index +=
                u32::try_from(prefix_size).map_err(|_| Error::WriteLayoutFailed {
                    message: "Prefix size exceeds u32 range (userstring rebuild)".to_string(),
                })? + u32::try_from(total_length).map_err(|_| Error::WriteLayoutFailed {
                    message: "Total length exceeds u32 range (userstring rebuild)".to_string(),
                })?;
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
