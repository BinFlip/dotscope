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
    utils::{align_to, align_to_4_bytes, compressed_uint_size},
    Error, Result,
};

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
pub fn calculate_string_heap_size(
    heap_changes: &HeapChanges<String>,
    assembly: &CilAssembly,
) -> Result<u64> {
    // If there's a heap replacement, use its size plus any appended items
    if let Some(replacement_heap) = heap_changes.replacement_heap() {
        let replacement_size = replacement_heap.len() as u64;
        let appended_size = heap_changes.binary_string_heap_size() as u64;
        // Add padding to align to 4-byte boundary
        let total_size = replacement_size + appended_size;
        let aligned_size = align_to_4_bytes(total_size);
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
        let aligned_size = align_to_4_bytes(total_size);
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
            u32::try_from(blob_heap.data().len())
                .map_err(|_| malformed_error!("Blob heap size exceeds u32 range"))?
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
            let prefix_size_u32 = u32::try_from(prefix_size)
                .map_err(|_| malformed_error!("Compressed uint size exceeds u32 range"))?;
            let blob_len_u32 = u32::try_from(original_blob.len())
                .map_err(|_| malformed_error!("Blob length exceeds u32 range"))?;
            current_index += prefix_size_u32 + blob_len_u32;
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
pub fn calculate_userstring_heap_size(
    heap_changes: &HeapChanges<String>,
    assembly: &CilAssembly,
) -> u64 {
    // For append-only strategy: start with original heap size, then add appended items contiguously
    let mut total_size = if let Some(replacement_heap) = heap_changes.replacement_heap() {
        u64::try_from(replacement_heap.len()).unwrap_or(0)
    } else if assembly.view().userstrings().is_some() {
        // Copy original heap size - need to get the actual stream size
        let view = assembly.view();
        let metadata_root = view.metadata_root();

        // Find the userstrings stream in the original metadata
        let mut original_size = 0u64;
        for stream_header in &metadata_root.stream_headers {
            if stream_header.name == "#US" {
                original_size = u64::from(stream_header.size);
                break;
            }
        }
        original_size
    } else {
        1u64 // Just null byte for empty heap
    };

    // Add size of appended items (they are placed contiguously at the end)
    for original_string in &heap_changes.appended_items {
        let original_heap_index = {
            let mut calculated_index = heap_changes.next_index;
            for item in heap_changes.appended_items.iter().rev() {
                let utf16_len = item.encode_utf16().count() * 2;
                let total_len = utf16_len + 1; // +1 for terminator
                let prefix_size = compressed_uint_size(total_len);
                calculated_index -=
                    u32::try_from(prefix_size).unwrap_or(0) + u32::try_from(total_len).unwrap_or(0);
                if std::ptr::eq(item, original_string) {
                    break;
                }
            }
            calculated_index
        };

        if !heap_changes.removed_indices.contains(&original_heap_index) {
            let final_string = heap_changes
                .modified_items
                .get(&original_heap_index)
                .cloned()
                .unwrap_or_else(|| original_string.clone());

            let utf16_len = final_string.encode_utf16().count() * 2;
            let total_len = utf16_len + 1; // +1 for terminator
            let prefix_size = compressed_uint_size(total_len);
            total_size += prefix_size + total_len as u64;
        }
    }

    if let Some(userstrings_heap) = assembly.view().userstrings() {
        for (&modified_index, new_string) in &heap_changes.modified_items {
            // Find the original userstring to determine if remapping is needed
            if let Some((_offset, original_string)) = userstrings_heap
                .iter()
                .find(|(offset, _)| *offset == modified_index as usize)
            {
                let original_utf16_len = original_string.len() * 2; // U16Str len() gives UTF-16 code units
                let original_total_len = original_utf16_len + 1; // +1 for terminator
                let original_prefix_size = compressed_uint_size(original_total_len);
                let original_entry_size =
                    original_prefix_size + u64::try_from(original_total_len).unwrap_or(0);

                let new_utf16_len = new_string.encode_utf16().count() * 2;
                let new_total_len = new_utf16_len + 1; // +1 for terminator
                let new_prefix_size = compressed_uint_size(new_total_len);
                let new_entry_size = new_prefix_size + u64::try_from(new_total_len).unwrap_or(0);

                if new_entry_size > original_entry_size {
                    // This modification will be remapped to the end - add its size
                    total_size += new_entry_size;
                }
            }
        }
    }

    // Align to 4-byte boundary
    (total_size + 3) & !3
}
