//! String heap writing functionality.
//!
//! This module handles writing modifications to the #Strings heap, including simple additions
//! and complex operations involving modifications and removals that require heap rebuilding.

use crate::{cilassembly::write::planner::StreamModification, Result};
use std::collections::HashMap;

/// Result of string heap reconstruction containing the new heap data and index mapping.
#[derive(Debug)]
pub struct StringHeapReconstruction {
    /// The reconstructed heap data ready to be written to the .meta section
    pub heap_data: Vec<u8>,
    /// Mapping from original heap indices to new heap indices (None = removed)
    pub index_mapping: HashMap<u32, Option<u32>>,
    /// The final size of the reconstructed heap
    pub final_size: usize,
}

impl<'a> super::HeapWriter<'a> {
    /// Reconstructs the complete string heap in memory with all modifications applied.
    ///
    /// This is the correct architectural approach that:
    /// 1. Reads the original heap into memory
    /// 2. Applies ALL modifications/additions/deletions in memory
    /// 3. Generates a complete index mapping for reference updates
    /// 4. Returns reconstructed heap data ready for writing
    ///
    /// This replaces the flawed copy-then-modify approach.
    fn reconstruct_string_heap_in_memory(&self) -> Result<StringHeapReconstruction> {
        let string_changes = &self.base.assembly.changes().string_heap_changes;
        let mut final_heap = Vec::new();
        let mut index_mapping = HashMap::new();
        let mut final_index_position = 1u32; // Start at 1, index 0 is always null

        if let Some(replacement_heap) = string_changes.replacement_heap() {
            final_heap = replacement_heap.clone();

            // Create basic index mapping for the replacement heap
            // Note: This is a simplified mapping that assumes the replacement heap
            // is well-formed. In a more sophisticated implementation, we would
            // parse the replacement heap to create proper mappings.
            let mut current_position = 1u32; // Skip null byte at index 0
            let heap_data = &final_heap[1..]; // Skip the null byte at start
            let mut start = 0;

            while start < heap_data.len() {
                if let Some(null_pos) = heap_data[start..].iter().position(|&b| b == 0) {
                    index_mapping.insert(current_position, Some(current_position));
                    current_position += (null_pos + 1) as u32;
                    start += null_pos + 1;
                } else {
                    break;
                }
            }

            for original_string in string_changes.appended_items.iter() {
                let original_heap_index = {
                    let mut calculated_index = string_changes.next_index;
                    for item in string_changes.appended_items.iter().rev() {
                        calculated_index -= (item.len() + 1) as u32;
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

                    index_mapping.insert(original_heap_index, Some(final_index_position));
                    final_heap.extend_from_slice(final_string.as_bytes());
                    final_heap.push(0);
                    final_index_position += final_string.len() as u32 + 1;
                }
            }

            while final_heap.len() % 4 != 0 {
                final_heap.push(0xFF);
            }

            let final_size = final_heap.len();
            return Ok(StringHeapReconstruction {
                heap_data: final_heap,
                index_mapping,
                final_size,
            });
        }

        // Always start with null byte at position 0
        final_heap.push(0);

        // String changes state is ready for processing

        if let Some(strings_heap) = self.base.assembly.view().strings() {
            // Phase 1: Process all original strings with modifications/removals
            for (original_index, original_string) in strings_heap.iter() {
                let original_index = original_index as u32;

                if string_changes.is_removed(original_index) {
                    // String is removed - no mapping entry (means removed)
                    index_mapping.insert(original_index, None);
                } else if let Some(modified_string) =
                    string_changes.get_modification(original_index)
                {
                    // String is modified - add modified version
                    index_mapping.insert(original_index, Some(final_index_position));
                    final_heap.extend_from_slice(modified_string.as_bytes());
                    final_heap.push(0); // null terminator
                    final_index_position += modified_string.len() as u32 + 1;
                } else {
                    // String is unchanged - add original version
                    let original_data = original_string.to_string();
                    index_mapping.insert(original_index, Some(final_index_position));
                    final_heap.extend_from_slice(original_data.as_bytes());
                    final_heap.push(0); // null terminator
                    final_index_position += original_data.len() as u32 + 1;
                }
            }

            // Ensure we account for the full original heap size, including any trailing padding
            // The new strings were assigned indices based on the original heap's raw byte size
            let original_heap_size = self
                .base
                .assembly
                .view()
                .streams()
                .iter()
                .find(|stream| stream.name == "#Strings")
                .map(|stream| stream.size)
                .unwrap_or(1);

            // Only add padding if we haven't reached the original heap boundary yet
            // If we've exactly reached it, new strings can start immediately
            if final_index_position < original_heap_size {
                let padding_needed = original_heap_size - final_index_position;
                final_heap.extend(vec![0xFFu8; padding_needed as usize]);
                final_index_position += padding_needed;
            } else if final_index_position == original_heap_size {
                // Don't add padding when we're exactly at the boundary
                // This matches the calculation logic
            }
        }

        // Phase 2: Add all new strings
        // Process in order of appended items to ensure proper sequential placement
        for original_string in string_changes.appended_items.iter() {
            // Calculate the original heap index for this item
            let original_heap_index = {
                let mut calculated_index = string_changes.next_index;
                for item in string_changes.appended_items.iter().rev() {
                    calculated_index -= (item.len() + 1) as u32;
                    if std::ptr::eq(item, original_string) {
                        break;
                    }
                }
                calculated_index
            };

            if !string_changes.is_removed(original_heap_index) {
                // Apply modification if present, otherwise use original appended string
                let final_string = string_changes
                    .get_modification(original_heap_index)
                    .cloned()
                    .unwrap_or_else(|| original_string.clone());

                // Map the original heap index to the current position in the reconstructed heap
                // This ensures the string is accessible at the position where it's actually placed
                index_mapping.insert(original_heap_index, Some(final_index_position));
                final_heap.extend_from_slice(final_string.as_bytes());
                final_heap.push(0); // null terminator

                final_index_position += final_string.len() as u32 + 1;
            }
        }

        // Phase 3: Apply alignment padding (ECMA-335 II.24.2.2)
        while final_heap.len() % 4 != 0 {
            final_heap.push(0xFF); // Use 0xFF to avoid creating empty string entries
        }

        // Heap reconstruction complete

        let reconstruction = StringHeapReconstruction {
            final_size: final_heap.len(),
            heap_data: final_heap,
            index_mapping,
        };

        Ok(reconstruction)
    }
    /// Writes string heap with complete reconstruction approach.
    ///
    /// This method implements the correct architectural approach:
    /// 1. Reconstructs the entire string heap in memory with all modifications
    /// 2. Writes the reconstructed heap to the .meta section  
    /// 3. Returns index mapping for updating metadata table references at pipeline level
    ///
    /// This replaces the flawed copy-then-modify approach.
    ///
    /// # Arguments
    ///
    /// * `stream_mod` - The [`crate::cilassembly::write::planner::StreamModification`] for the #Strings heap
    ///
    /// # Returns
    /// Returns Some((index_mapping, actual_size)) if reconstruction was performed, None if no changes needed.
    pub(super) fn write_string_heap_with_reconstruction(
        &mut self,
        stream_mod: &StreamModification,
    ) -> Result<Option<std::collections::HashMap<u32, u32>>> {
        // Starting string heap reconstruction
        let string_changes = &self.base.assembly.changes().string_heap_changes;

        // If no changes, we don't need reconstruction
        if !string_changes.has_additions()
            && !string_changes.has_modifications()
            && !string_changes.has_removals()
            && !string_changes.has_replacement()
        {
            return Ok(None);
        }

        // Phase 1: Reconstruct the complete heap in memory
        let reconstruction = self.reconstruct_string_heap_in_memory()?;

        // Phase 2: Write the reconstructed heap to the .meta section
        let stream_layout = self.base.find_stream_layout(&stream_mod.name)?;
        let write_start = stream_layout.file_region.offset as usize;
        self.base
            .output
            .write_at(write_start as u64, &reconstruction.heap_data)?;

        // Phase 3: Convert index mapping to the format expected by IndexRemapper
        let mut final_index_mapping = std::collections::HashMap::new();
        for (original_index, final_index_opt) in &reconstruction.index_mapping {
            if let Some(final_index) = final_index_opt {
                final_index_mapping.insert(*original_index, *final_index);
            }
            // Removed items (None) are not included in the final mapping
        }
        Ok(Some(final_index_mapping))
    }

    /// Writes the string heap with modifications or removals applied.
    ///
    /// This method provides comprehensive string heap rebuilding that:
    /// - Preserves all original string offsets for compatibility
    /// - Applies in-place modifications where possible
    /// - Handles string removals by zero-filling
    /// - Appends new strings at the end
    /// - Maintains proper ECMA-335 alignment
    ///
    /// # Strategy
    ///
    /// 1. **Reconstruct Original**: Rebuild the original heap layout to preserve offsets
    /// 2. **Apply Changes**: Modify/remove strings in-place where size permits
    /// 3. **Append New**: Add new strings at the end of the heap
    /// 4. **Alignment**: Apply proper 4-byte alignment padding
    ///
    /// # Arguments
    ///
    /// * `stream_mod` - The [`crate::cilassembly::write::planner::StreamModification`] for the #Strings heap
    pub(super) fn write_string_heap_with_changes(
        &mut self,
        stream_mod: &StreamModification,
    ) -> Result<()> {
        let (stream_layout, write_start) = self.base.get_stream_write_position(stream_mod)?;
        let mut write_pos = write_start;
        let stream_end = stream_layout.file_region.end_offset() as usize;
        let string_changes = &self.base.assembly.changes().string_heap_changes;

        // Step 1: Reconstruct the original heap to preserve all original offsets
        if let Some(strings_heap) = self.base.assembly.view().strings() {
            // Use the original stream size instead of calculating it
            let original_heap_size = self
                .base
                .assembly
                .view()
                .streams()
                .iter()
                .find(|stream| stream.name == "#Strings")
                .map(|stream| stream.size as usize)
                .unwrap_or(1);

            // Initialize the heap area with zeros
            let heap_slice = self
                .base
                .output
                .get_mut_slice(write_pos, original_heap_size)?;
            for byte in heap_slice.iter_mut() {
                *byte = 0;
            }

            // Ensure the null byte at position 0 (required by string heap format)
            heap_slice[0] = 0;

            // Second pass: Write each string to its original offset
            for (offset, string) in strings_heap.iter() {
                let string_data = string.to_string();
                let string_bytes = string_data.as_bytes();
                let string_slice = &mut heap_slice[offset..offset + string_bytes.len()];
                string_slice.copy_from_slice(string_bytes);
                // Null terminator is already zero from initialization
            }

            write_pos += original_heap_size;

            // Step 2: Apply modifications in-place where possible
            for (offset, string) in strings_heap.iter() {
                let heap_index = offset as u32;

                if string_changes.is_removed(heap_index) {
                    // Zero-fill removed strings instead of removing them
                    let original_string = string.to_string();
                    let string_size = original_string.len() + 1; // include null terminator
                    let zero_slice = self
                        .base
                        .output
                        .get_mut_slice(write_start + offset, string_size)?;
                    for byte in zero_slice.iter_mut() {
                        *byte = 0;
                    }
                } else if let Some(modified_string) = string_changes.get_modification(heap_index) {
                    // Try to modify in-place
                    let original_string = string.to_string();
                    let original_size = original_string.len() + 1; // include null terminator
                    let new_size = modified_string.len() + 1; // include null terminator

                    if new_size <= original_size {
                        // Fits in place - modify directly
                        let mod_slice = self
                            .base
                            .output
                            .get_mut_slice(write_start + offset, original_size)?;
                        let mod_bytes = modified_string.as_bytes();
                        mod_slice[..mod_bytes.len()].copy_from_slice(mod_bytes);
                        mod_slice[mod_bytes.len()] = 0; // null terminator
                                                        // Zero-fill any remaining space
                        for byte in mod_slice
                            .iter_mut()
                            .skip(new_size)
                            .take(original_size - new_size)
                        {
                            *byte = 0;
                        }
                    } else {
                        // Too big for in-place - zero original and append at end
                        let zero_slice = self
                            .base
                            .output
                            .get_mut_slice(write_start + offset, original_size)?;
                        for byte in zero_slice.iter_mut() {
                            *byte = 0;
                        }

                        // Append at end
                        let mod_bytes = modified_string.as_bytes();
                        let append_slice = self.base.output.get_mut_slice(write_pos, new_size)?;
                        append_slice[..mod_bytes.len()].copy_from_slice(mod_bytes);
                        append_slice[mod_bytes.len()] = 0; // null terminator
                        write_pos += new_size;
                    }
                }
            }
        } else {
            // No original heap - just write the mandatory null byte
            self.base.output.write_and_advance(&mut write_pos, &[0])?;
        }

        // Step 3: Append new strings at the end (but skip removed ones)
        for (heap_index, appended_string) in string_changes.string_items_with_indices() {
            if !string_changes.is_removed(heap_index) {
                // Apply modification if present, otherwise use original appended string
                let final_string = string_changes
                    .get_modification(heap_index)
                    .cloned()
                    .unwrap_or_else(|| appended_string.clone());

                let string_bytes = final_string.as_bytes();
                let string_size = string_bytes.len() + 1; // include null terminator

                // Ensure we won't exceed stream boundary
                if write_pos + string_size > stream_end {
                    return Err(crate::Error::WriteLayoutFailed {
                        message: format!(
                            "String heap overflow: write would exceed allocated space by {} bytes",
                            (write_pos + string_size) - stream_end
                        ),
                    });
                }

                let append_slice = self.base.output.get_mut_slice(write_pos, string_size)?;
                append_slice[..string_bytes.len()].copy_from_slice(string_bytes);
                append_slice[string_bytes.len()] = 0; // null terminator

                write_pos += string_size;
            }
        }

        // Add special padding to align to 4-byte boundary (ECMA-335 II.24.2.2)
        // Use 0xFF bytes instead of 0x00 to avoid creating empty string entries
        self.base.output.add_heap_padding(write_pos, write_start)?;

        Ok(())
    }
}
