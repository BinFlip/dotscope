//! String heap writing functionality.
//!
//! This module handles writing modifications to the #Strings heap, including simple additions
//! and complex operations involving modifications and removals that require heap rebuilding.

use crate::{
    cilassembly::write::planner::{FileRegion, StreamModification},
    Result,
};

impl<'a> super::HeapWriter<'a> {
    /// Writes string heap modifications including additions, modifications, and removals.
    ///
    /// Handles all types of string heap changes:
    /// - Additions only: Appends new strings to the end of the heap
    /// - Modifications/Removals: Triggers complete heap rebuilding for consistency
    ///
    /// Writes null-terminated UTF-8 strings as specified by ECMA-335 II.24.2.2.
    /// Each string is followed by a null terminator byte.
    ///
    /// # Arguments
    ///
    /// * `stream_mod` - The [`crate::cilassembly::write::planner::metadata::StreamModification`] for the #Strings heap
    pub(super) fn write_string_heap_additions(
        &mut self,
        stream_mod: &StreamModification,
    ) -> Result<()> {
        let string_changes = &self.base.assembly.changes().string_heap_changes;

        if string_changes.has_modifications() || string_changes.has_removals() {
            return self.rebuild_string_heap(stream_mod);
        }

        let (_stream_layout, write_start) = self.prepare_heap_write(stream_mod)?;
        let mut write_pos = write_start;

        // Write each new string to the heap
        for string in &self
            .base
            .assembly
            .changes()
            .string_heap_changes
            .appended_items
        {
            // Strings in the heap are null-terminated UTF-8
            let string_bytes = string.as_bytes();

            // Create region for the complete string entry (string + null terminator)
            let string_region = FileRegion::new(write_pos as u64, string_bytes.len() as u64 + 1);

            // Write the string bytes
            let output_slice = self
                .base
                .output
                .get_mut_slice(string_region.offset as usize, string_bytes.len())?;
            output_slice.copy_from_slice(string_bytes);

            // Write null terminator
            let null_slice = self
                .base
                .output
                .get_mut_slice(string_region.offset as usize + string_bytes.len(), 1)?;
            null_slice[0] = 0;

            // Move to next position using the region's end
            write_pos = string_region.end_offset() as usize;
        }

        // Note: Padding is handled at the file layout level, not individual heap level
        Ok(())
    }

    /// Rebuilds the entire string heap when modifications or removals are present.
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
    /// * `stream_mod` - The [`crate::cilassembly::write::planner::metadata::StreamModification`] for the #Strings heap
    pub(super) fn rebuild_string_heap(&mut self, stream_mod: &StreamModification) -> Result<()> {
        let (_stream_layout, write_start) = self.prepare_heap_write(stream_mod)?;
        let mut write_pos = write_start;

        let string_changes = &self.base.assembly.changes().string_heap_changes;

        // Step 1: Reconstruct the original heap to preserve all original offsets
        let mut original_heap_end = 1; // Start with 1 to ensure null byte at position 0
        if let Some(strings_heap) = self.base.assembly.view().strings() {
            // First pass: find the size of the original heap by finding the highest offset + string size
            for (offset, string) in strings_heap.iter() {
                let string_end = offset + string.to_string().len() + 1; // +1 for null terminator
                if string_end > original_heap_end {
                    original_heap_end = string_end;
                }
            }

            // Initialize the heap area with zeros
            let heap_slice = self
                .base
                .output
                .get_mut_slice(write_pos, original_heap_end)?;
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

            write_pos += original_heap_end;

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
            let null_slice = self.base.output.get_mut_slice(write_pos, 1)?;
            null_slice[0] = 0;
            write_pos += 1;
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

                let append_slice = self.base.output.get_mut_slice(write_pos, string_size)?;
                append_slice[..string_bytes.len()].copy_from_slice(string_bytes);
                append_slice[string_bytes.len()] = 0; // null terminator
                write_pos += string_size;
            }
        }

        // Add special padding to align to 4-byte boundary (ECMA-335 II.24.2.2)
        // Use 0xFF bytes instead of 0x00 to avoid creating empty string entries
        self.add_heap_padding_to_4_bytes(write_pos, write_start)?;

        Ok(())
    }
}
