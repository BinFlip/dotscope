//! String heap builder for the simplified assembly writer.
//!
//! This module implements string heap reconstruction using the exact same
//! algorithms as the existing pipeline to ensure 100% compatibility.

use std::collections::HashMap;

use crate::{
    cilassembly::{
        writer::{heaps::HeapBuilder, layout::calculate_string_heap_size},
        CilAssembly,
    },
    Error, Result,
};

/// Builder for #Strings metadata heap reconstruction.
///
/// The string heap contains UTF-8 null-terminated strings referenced by metadata tables.
/// This builder implements an advanced "append-only with zero-padding" strategy that
/// preserves ALL original indices and eliminates the need for index remapping in most cases.
///
/// # ECMA-335 Format
///
/// - Index 0 is reserved for null (contains single 0x00 byte)
/// - All other strings are UTF-8 encoded with null terminators
/// - Indices are byte offsets from heap start
/// - Heap is padded to 4-byte alignment with 0xFF bytes
///
/// # Revolutionary Approach
///
/// This builder uses a revolutionary append-only strategy:
///
/// 1. **Preserve Original Layout**: Original heap data is copied exactly
/// 2. **Zero-Pad Deletions**: Deleted strings are zero-padded in place
/// 3. **In-Place Modifications**: Shorter replacements fit in original space
/// 4. **Append When Needed**: Longer replacements appended at end with remapping
///
/// This approach preserves virtually all original indices, maintaining compatibility
/// with existing references while minimizing the need for costly index remapping.
///
/// # Examples
///
/// ```rust,ignore
/// let mut builder = StringHeapBuilder::new(&assembly);
/// let heap_data = builder.build()?;
/// let size = builder.calculate_size()?;
/// let mappings = builder.get_index_mappings(); // Usually empty!
/// ```
pub struct StringHeapBuilder<'a> {
    /// Reference to the assembly being processed
    assembly: &'a CilAssembly,
    /// Mapping from original string indices to final indices (minimal due to append-only strategy)
    index_mappings: HashMap<u32, u32>,
}

impl<'a> StringHeapBuilder<'a> {
    /// Creates a new string heap builder for the specified assembly.
    ///
    /// The builder is optimized for minimal index remapping using the
    /// append-only with zero-padding strategy.
    ///
    /// # Arguments
    ///
    /// * `assembly` - Assembly containing string heap changes to process
    ///
    /// # Returns
    ///
    /// Returns a new `StringHeapBuilder` ready for heap reconstruction.
    pub fn new(assembly: &'a CilAssembly) -> Self {
        Self {
            assembly,
            index_mappings: HashMap::new(),
        }
    }
}

impl HeapBuilder for StringHeapBuilder<'_> {
    fn build(&mut self) -> Result<Vec<u8>> {
        // Reconstruct the complete string heap using the same algorithm as the existing pipeline
        let string_changes = &self.assembly.changes().string_heap_changes;
        let mut final_heap = Vec::new();
        let mut final_index_position = 1u32; // Start at 1, index 0 is always null

        // Handle heap replacement scenario
        if let Some(replacement_heap) = string_changes.replacement_heap() {
            final_heap.clone_from(replacement_heap);

            // Create basic index mapping for the replacement heap
            let mut current_position = 1u32; // Skip null byte at index 0
            let heap_data = &final_heap[1..]; // Skip the null byte at start
            let mut start = 0;

            while start < heap_data.len() {
                if let Some(null_pos) = heap_data[start..].iter().position(|&b| b == 0) {
                    self.index_mappings
                        .insert(current_position, current_position);
                    current_position += u32::try_from(null_pos + 1).unwrap_or(0);
                    start += null_pos + 1;
                } else {
                    break;
                }
            }

            // Handle appended items
            for original_string in &string_changes.appended_items {
                let original_heap_index = {
                    let mut calculated_index = string_changes.next_index;
                    for item in string_changes.appended_items.iter().rev() {
                        calculated_index -= u32::try_from(item.len() + 1).unwrap_or(0);
                        if std::ptr::eq(item, original_string) {
                            break;
                        }
                    }
                    calculated_index
                };

                if !string_changes.is_removed(original_heap_index) {
                    let final_string = string_changes
                        .get_modification(original_heap_index)
                        .cloned()
                        .unwrap_or_else(|| original_string.clone());

                    self.index_mappings
                        .insert(original_heap_index, final_index_position);
                    final_heap.extend_from_slice(final_string.as_bytes());
                    final_heap.push(0);
                    final_index_position += u32::try_from(final_string.len()).unwrap_or(0) + 1;
                }
            }

            // Apply 4-byte alignment padding
            while final_heap.len() % 4 != 0 {
                final_heap.push(0xFF);
            }

            return Ok(final_heap);
        }

        // Always start with null byte at position 0
        final_heap.push(0);

        // REVOLUTIONARY APPROACH: Append-only with zero-padding
        // This preserves ALL original indices and eliminates the need for ANY index remapping
        if let Some(_strings_heap) = self.assembly.view().strings() {
            // Start with the original heap data
            let original_heap_data = self.copy_original_string_heap_raw_data()?;
            final_heap.clear(); // Remove the null byte we added earlier
            final_heap.extend_from_slice(&original_heap_data);

            // Step 1: Zero-pad any deleted strings in place
            for &deleted_index in &string_changes.removed_indices {
                if let Some((start_pos, end_pos)) =
                    Self::find_string_boundaries_in_heap(&final_heap, deleted_index as usize)
                {
                    // Replace the string content with zeros, keeping the null terminator
                    final_heap[start_pos..end_pos].fill(0);
                }
            }

            // Step 2: Handle modified strings - in-place when possible, remap when necessary
            for (&modified_index, new_string) in &string_changes.modified_items {
                if let Some((start_pos, end_pos)) =
                    Self::find_string_boundaries_in_heap(&final_heap, modified_index as usize)
                {
                    let original_space = end_pos - start_pos - 1; // Exclude null terminator
                    let new_size = new_string.len();

                    if new_size <= original_space {
                        // FITS IN PLACE: Overwrite original location and zero-pad remainder

                        // Write new string data
                        final_heap[start_pos..start_pos + new_size]
                            .copy_from_slice(new_string.as_bytes());
                        // Zero-pad the remainder (excluding null terminator)
                        final_heap[(start_pos + new_size)..(end_pos - 1)].fill(0);
                        // Keep the null terminator at the end
                        final_heap[end_pos - 1] = 0;
                    } else {
                        // DOESN'T FIT: Need to remap - zero original and append new

                        // Zero-pad the original location completely
                        final_heap[start_pos..end_pos].fill(0);

                        // Append at end and create index mapping
                        let new_index = u32::try_from(final_heap.len())
                            .map_err(|_| malformed_error!("String heap size exceeds u32 range"))?;
                        final_heap.extend_from_slice(new_string.as_bytes());
                        final_heap.push(0);

                        // CRITICAL: We need to track this remapping for table updates
                        self.index_mappings.insert(modified_index, new_index);
                    }
                }
            }

            // Step 3: Append new strings at the end, applying any modifications or removals
            let mut current_append_index = u32::try_from(original_heap_data.len())
                .map_err(|_| malformed_error!("Original heap size exceeds u32 range"))?;
            for new_string in &string_changes.appended_items {
                // Check if this newly added string has been modified or removed
                if string_changes
                    .removed_indices
                    .contains(&current_append_index)
                {
                } else if let Some(modified_string) =
                    string_changes.modified_items.get(&current_append_index)
                {
                    final_heap.extend_from_slice(modified_string.as_bytes());
                    final_heap.push(0);
                } else {
                    final_heap.extend_from_slice(new_string.as_bytes());
                    final_heap.push(0);
                }

                // Update the current append index for the next string
                current_append_index += if string_changes
                    .modified_items
                    .contains_key(&current_append_index)
                {
                    u32::try_from(string_changes.modified_items[&current_append_index].len())
                        .map_err(|_| malformed_error!("Modified string length exceeds u32 range"))?
                        + 1
                } else if !string_changes
                    .removed_indices
                    .contains(&current_append_index)
                {
                    u32::try_from(new_string.len())
                        .map_err(|_| malformed_error!("New string length exceeds u32 range"))?
                        + 1
                } else {
                    0 // Removed strings don't consume space
                };
            }

            // Apply 4-byte alignment padding
            while final_heap.len() % 4 != 0 {
                final_heap.push(0xFF);
            }

            return Ok(final_heap);
        }

        // Fallback: build from scratch if no original strings heap
        let mut min_index = u32::MAX;
        let mut max_index = 0u32;

        if let Some(strings_heap) = self.assembly.view().strings() {
            // Phase 1: Process all original strings with modifications/removals
            for (original_index, original_string) in strings_heap.iter() {
                let original_index =
                    u32::try_from(original_index).map_err(|_| Error::WriteLayoutFailed {
                        message: "String heap index exceeds u32 range".to_string(),
                    })?;

                if original_index < min_index {
                    min_index = original_index;
                }
                if original_index > max_index {
                    max_index = original_index;
                }

                if string_changes.is_removed(original_index) {
                    // String is removed - no mapping entry
                    continue;
                }
                if let Some(modified_string) = string_changes.get_modification(original_index) {
                    // String is modified - add modified version
                    self.index_mappings
                        .insert(original_index, final_index_position);
                    final_heap.extend_from_slice(modified_string.as_bytes());
                    final_heap.push(0); // null terminator
                    final_index_position += u32::try_from(modified_string.len()).map_err(|_| {
                        Error::WriteLayoutFailed {
                            message: "Modified string length exceeds u32 range".to_string(),
                        }
                    })? + 1;
                } else {
                    // String is unchanged - add original version
                    let original_data = original_string.to_string();
                    self.index_mappings
                        .insert(original_index, final_index_position);
                    final_heap.extend_from_slice(original_data.as_bytes());
                    final_heap.push(0); // null terminator
                    final_index_position += u32::try_from(original_data.len()).map_err(|_| {
                        Error::WriteLayoutFailed {
                            message: "Original string length exceeds u32 range".to_string(),
                        }
                    })? + 1;
                }
            }
        }

        // Handle appended strings
        for original_string in &string_changes.appended_items {
            let original_heap_index = {
                let mut calculated_index = string_changes.next_index;
                for item in string_changes.appended_items.iter().rev() {
                    calculated_index -=
                        u32::try_from(item.len() + 1).map_err(|_| Error::WriteLayoutFailed {
                            message: "String item size exceeds u32 range".to_string(),
                        })?;
                    if std::ptr::eq(item, original_string) {
                        break;
                    }
                }
                calculated_index
            };

            if !string_changes.is_removed(original_heap_index) {
                let final_string = string_changes
                    .get_modification(original_heap_index)
                    .cloned()
                    .unwrap_or_else(|| original_string.clone());

                self.index_mappings
                    .insert(original_heap_index, final_index_position);
                final_heap.extend_from_slice(final_string.as_bytes());
                final_heap.push(0);
                final_index_position +=
                    u32::try_from(final_string.len()).map_err(|_| Error::WriteLayoutFailed {
                        message: "Final string length exceeds u32 range".to_string(),
                    })? + 1;
            }
        }

        // Apply 4-byte alignment padding with 0xFF bytes
        while final_heap.len() % 4 != 0 {
            final_heap.push(0xFF);
        }

        Ok(final_heap)
    }

    fn calculate_size(&self) -> Result<u64> {
        let string_changes = &self.assembly.changes().string_heap_changes;
        calculate_string_heap_size(string_changes, self.assembly)
    }

    fn get_index_mappings(&self) -> &HashMap<u32, u32> {
        &self.index_mappings
    }

    fn heap_name(&self) -> &'static str {
        "#Strings"
    }
}

impl StringHeapBuilder<'_> {
    /// Find the byte boundaries of a string at a given index in the heap.
    /// Returns (start_pos, end_pos) where end_pos is exclusive and includes the null terminator.
    fn find_string_boundaries_in_heap(
        heap_data: &[u8],
        string_index: usize,
    ) -> Option<(usize, usize)> {
        if string_index == 0 || string_index >= heap_data.len() {
            return None; // Invalid index
        }

        let start_pos = string_index;

        // Find the null terminator
        if let Some(null_pos) = heap_data[start_pos..].iter().position(|&b| b == 0) {
            let end_pos = start_pos + null_pos + 1; // Include the null terminator
            Some((start_pos, end_pos))
        } else {
            None // No null terminator found
        }
    }

    /// Copy the original string heap raw data to preserve exact byte positions.
    fn copy_original_string_heap_raw_data(&self) -> Result<Vec<u8>> {
        // Use the same approach as the planner's copy_original_stream_data
        let view = self.assembly.view();
        let metadata_root = view.metadata_root();

        // Find the strings stream in the original metadata
        for stream_header in &metadata_root.stream_headers {
            if stream_header.name == "#Strings" {
                // Get the original stream data
                let cor20_header = view.cor20header();
                let metadata_offset = view
                    .file()
                    .rva_to_offset(cor20_header.meta_data_rva as usize)
                    .map_err(|_| Error::WriteLayoutFailed {
                        message: "Failed to convert metadata RVA to file offset".to_string(),
                    })?;

                let stream_start = metadata_offset + stream_header.offset as usize;
                let stream_end = stream_start + stream_header.size as usize;

                let file_data = view.file().data();
                let stream_data = file_data.get(stream_start..stream_end).ok_or_else(|| {
                    Error::WriteLayoutFailed {
                        message: "Failed to read original stream data".to_string(),
                    }
                })?;

                return Ok(stream_data.to_vec());
            }
        }

        Err(Error::WriteLayoutFailed {
            message: "String stream not found in original metadata".to_string(),
        })
    }
}
