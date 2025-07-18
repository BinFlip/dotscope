//! UserString heap writing functionality.
//!
//! This module handles writing modifications to the #US (UserString) heap, including simple additions
//! and complex operations involving modifications and removals that require heap rebuilding.

use crate::{
    cilassembly::write::{planner::StreamModification, utils::compressed_uint_size},
    Error, Result,
};

impl<'a> super::HeapWriter<'a> {
    /// Writes user string heap modifications including additions, modifications, and removals.
    ///
    /// Handles all types of user string heap changes:
    /// - Additions: Appends new user strings to the end of the heap
    /// - Modifications: Updates existing user strings in place (if possible)
    /// - Removals: Marks user strings as removed (handled during parsing/indexing)
    ///
    /// Writes UTF-16 encoded strings with compressed integer length prefixes and
    /// terminator bytes as specified by ECMA-335 II.24.2.4. The format includes:
    /// - Compressed integer length (total size including terminator)
    /// - UTF-16 string data (little-endian)
    /// - Terminator byte (high-character flag: 0 = no chars >= 0x80, 1 = has chars >= 0x80)
    ///
    /// # Arguments
    ///
    /// * `stream_mod` - The [`crate::cilassembly::write::planner::StreamModification`] for the #US heap
    pub(super) fn write_userstring_heap(&mut self, stream_mod: &StreamModification) -> Result<()> {
        let userstring_changes = &self.base.assembly.changes().userstring_heap_changes;
        if userstring_changes.has_changes() {
            return self.write_userstring_heap_with_changes(stream_mod);
        }

        let (stream_layout, write_start) = self.base.get_stream_write_position(stream_mod)?;
        let mut write_pos = write_start;
        let stream_end = stream_layout.file_region.end_offset() as usize;

        for user_string in &self
            .base
            .assembly
            .changes()
            .userstring_heap_changes
            .appended_items
        {
            // User strings are UTF-16 encoded with length prefix (ECMA-335 II.24.2.4)
            let utf16_bytes: Vec<u8> = user_string
                .encode_utf16()
                .flat_map(|c| c.to_le_bytes())
                .collect();

            // Length includes: UTF-16 data + terminator byte (1 byte)
            // No null terminator in the actual data according to .NET runtime implementation
            let utf16_data_length = utf16_bytes.len();
            let total_length = utf16_data_length + 1; // UTF-16 data + terminator byte

            // Write compressed integer length prefix (ECMA-335 II.24.2.4)
            write_pos = self
                .base
                .output
                .write_compressed_uint_at(write_pos as u64, total_length as u32)?
                as usize;

            // Write the UTF-16 string data
            let string_slice = self
                .base
                .output
                .get_mut_slice(write_pos, utf16_bytes.len())?;
            string_slice.copy_from_slice(&utf16_bytes);
            write_pos += utf16_bytes.len();

            // Write the terminator byte (contains high-character flag)
            // According to .NET runtime: 0 = no chars >= 0x80, 1 = has chars >= 0x80
            let has_high_chars = user_string.chars().any(|c| c as u32 >= 0x80);
            let terminator_byte = if has_high_chars { 1 } else { 0 };

            // Ensure we won't exceed stream boundary
            if write_pos + 1 > stream_end {
                return Err(Error::WriteLayoutFailed {
                    message: format!(
                        "UserString heap overflow: write would exceed allocated space by {} bytes",
                        (write_pos + 1) - stream_end
                    ),
                });
            }

            let terminal_slice = self.base.output.get_mut_slice(write_pos, 1)?;
            terminal_slice[0] = terminator_byte;
            write_pos += 1;
        }

        // Note: Padding is handled at the file layout level, not individual heap level

        Ok(())
    }

    /// Writes the user string heap when modifications or removals are present.
    ///
    /// This method provides comprehensive userstring heap writing that handles
    /// complex scenarios involving modifications to original heap data and appended
    /// userstrings that require maintaining API index contracts.
    ///
    /// # Strategy
    ///
    /// 1. **Analyze Changes**: Determine if original heap modifications or appended modifications exist
    /// 2. **Conditional Rebuild**: Only rebuild if necessary to maintain index integrity
    /// 3. **Preserve Structure**: For simple appends, preserve original heap byte structure
    /// 4. **Complete Rebuild**: For complex changes, rebuild entire heap maintaining API indices
    /// 5. **Alignment**: Apply proper 4-byte alignment padding
    ///
    /// # API Index Semantics
    ///
    /// UserString heap uses byte offset indexing (unlike GUID's sequential indexing):
    /// - Indices represent actual byte positions within the heap
    /// - Modifications can change string sizes, affecting subsequent indices
    /// - Appended strings must maintain stable API indices for existing code
    ///
    /// # Arguments
    ///
    /// * `stream_mod` - The [`crate::cilassembly::write::planner::StreamModification`] for the #US heap
    pub(super) fn write_userstring_heap_with_changes(
        &mut self,
        stream_mod: &StreamModification,
    ) -> Result<()> {
        let (stream_layout, write_start) = self.base.get_stream_write_position(stream_mod)?;
        let mut write_pos = write_start;

        let userstring_changes = &self.base.assembly.changes().userstring_heap_changes;
        let stream_end = stream_layout.file_region.end_offset() as usize;

        // Check if heap is being completely replaced
        if let Some(replacement_heap) = userstring_changes.replacement_heap() {
            // Use replacement heap directly
            self.base
                .output
                .write_and_advance(&mut write_pos, replacement_heap)?;

            // Process appended items (additions after replacement)
            for user_string in userstring_changes.appended_items.iter() {
                let utf16_bytes: Vec<u8> = user_string
                    .encode_utf16()
                    .flat_map(|c| c.to_le_bytes())
                    .collect();

                let total_length = utf16_bytes.len() + 1; // +1 for terminator byte
                let has_high_chars = user_string.chars().any(|c| c as u32 >= 0x80);
                let terminator_byte = if has_high_chars { 1u8 } else { 0u8 };

                write_pos = self
                    .base
                    .output
                    .write_compressed_uint_at(write_pos as u64, total_length as u32)?
                    as usize;

                let total_size = utf16_bytes.len() + 1;
                if write_pos + total_size > stream_end {
                    return Err(Error::Error(
                        "UserString heap overflow: write would exceed allocated space".to_string(),
                    ));
                }

                let string_slice = self
                    .base
                    .output
                    .get_mut_slice(write_pos, utf16_bytes.len())?;
                string_slice.copy_from_slice(&utf16_bytes);
                write_pos += utf16_bytes.len();

                let terminator_slice = self.base.output.get_mut_slice(write_pos, 1)?;
                terminator_slice[0] = terminator_byte;
                write_pos += 1;
            }

            return Ok(());
        }

        // For userstrings, any modifications or additions require a complete heap rebuild
        // to ensure proper API index positioning. Unlike other heap types, userstrings
        // use byte offset indexing and need precise positioning.
        if let Some(us_heap) = self.base.assembly.view().userstrings() {
            // Always rebuild when we have changes to maintain index integrity
            self.write_complete_userstring_heap(
                &mut write_pos,
                us_heap,
                userstring_changes,
                stream_end,
            )?;
        } else {
            // No original heap, start with null byte
            let null_slice = self.base.output.get_mut_slice(write_pos, 1)?;
            null_slice[0] = 0;
            write_pos += 1;
        }

        self.base.output.add_heap_padding(write_pos, write_start)?;

        Ok(())
    }

    /// Writes the complete userstring heap (original + appended) maintaining API index contract.
    ///
    /// This method implements the most comprehensive userstring heap rebuilding strategy,
    /// ensuring that all API indices remain stable even when string sizes change due to
    /// modifications. It rebuilds the entire heap from scratch while preserving the
    /// logical index structure.
    ///
    /// # API Index Stability
    ///
    /// The key challenge is maintaining API index stability:
    /// - Original userstrings use their original byte offsets as indices
    /// - Appended userstrings use calculated API indices based on original string sizes
    /// - When modifications change string sizes, we must maintain the original API indices
    /// - The rebuilt heap writes strings continuously but preserves logical index ordering
    ///
    /// # Strategy
    ///
    /// 1. **Collect All**: Gather original + appended userstrings with their API indices
    /// 2. **Apply Changes**: Apply modifications and filter out removed strings
    /// 3. **Sort by Index**: Maintain heap order by sorting by API index
    /// 4. **Write Continuously**: Write all strings sequentially (not at specific positions)
    /// 5. **Preserve Indices**: API indices remain stable for external references
    ///
    /// # Arguments
    ///
    /// * `write_pos` - Mutable reference to current write position
    /// * `original_heap` - Reference to the original UserStrings heap
    /// * `userstring_changes` - Reference to the heap changes to apply
    pub(super) fn write_complete_userstring_heap(
        &mut self,
        write_pos: &mut usize,
        original_heap: &crate::metadata::streams::UserStrings,
        userstring_changes: &crate::cilassembly::changes::HeapChanges<String>,
        stream_end: usize,
    ) -> Result<()> {
        // Start with null byte
        let heap_start = *write_pos;
        let null_slice = self.base.output.get_mut_slice(*write_pos, 1)?;
        null_slice[0] = 0;
        *write_pos += 1;

        // Step 1: Build complete list of all userstrings (original + appended) with their storage indices
        let mut all_userstrings: Vec<(u32, String)> = Vec::new();

        // Add original userstrings
        for (offset, original_userstring) in original_heap.iter() {
            let heap_index = offset as u32;
            if !userstring_changes.is_removed(heap_index) {
                let final_string = userstring_changes
                    .get_modification(heap_index)
                    .cloned()
                    .unwrap_or_else(|| original_userstring.to_string_lossy().to_string());
                all_userstrings.push((heap_index, final_string));
            }
        }

        // Add appended userstrings with their API indices
        let original_heap_size = userstring_changes.next_index
            - userstring_changes
                .appended_items
                .iter()
                .map(|s| {
                    let utf16_bytes: usize = s.encode_utf16().map(|_| 2).sum();
                    let total_length = utf16_bytes + 1;
                    let compressed_length_size = if total_length < 0x80 {
                        1
                    } else if total_length < 0x4000 {
                        2
                    } else {
                        4
                    };
                    (compressed_length_size + total_length) as u32
                })
                .sum::<u32>();

        let mut current_api_index = original_heap_size;
        for original_string in &userstring_changes.appended_items {
            let api_index = current_api_index;

            if !userstring_changes.is_removed(api_index) {
                let final_string = userstring_changes
                    .get_modification(api_index)
                    .cloned()
                    .unwrap_or_else(|| original_string.clone());
                all_userstrings.push((api_index, final_string));
            }

            // Advance API index by original string size (maintains API index stability)
            let utf16_bytes: usize = original_string.encode_utf16().map(|_| 2).sum();
            let total_length = utf16_bytes + 1;
            let compressed_length_size = if total_length < 0x80 {
                1
            } else if total_length < 0x4000 {
                2
            } else {
                4
            };
            current_api_index += (compressed_length_size + total_length) as u32;
        }

        // Step 2: Sort by API index to maintain heap order
        all_userstrings.sort_by_key(|(index, _)| *index);

        // Step 3: Write all userstrings continuously, maintaining the logical index structure

        let mut final_position = heap_start + 1; // Start after null byte

        for (_api_index, userstring) in all_userstrings {
            // Ensure we won't exceed stream boundary (account for potential padding)
            let entry_size = self.calculate_userstring_entry_size(&userstring) as usize;
            if final_position + entry_size > stream_end {
                return Err(crate::Error::WriteLayoutFailed {
                    message: format!("UserString heap overflow during writing: write would exceed allocated space by {} bytes", 
                        (final_position + entry_size) - stream_end)
                });
            }

            // Write userstring continuously, not at specific API index positions
            // API indices are logical indices, not byte offsets in userstring heaps
            self.write_single_userstring_at(&userstring, final_position)?;

            // Calculate where this userstring ends to advance write position
            let utf16_len = userstring.encode_utf16().count() * 2;
            let total_len = utf16_len + 1; // UTF-16 + terminator
            let compressed_len_size = if total_len < 0x80 {
                1
            } else if total_len < 0x4000 {
                2
            } else {
                4
            };

            final_position += compressed_len_size + total_len;
        }

        *write_pos = final_position;

        Ok(())
    }

    /// Helper method to write a single user string with proper encoding.
    ///
    /// Writes a userstring entry with compressed length prefix, UTF-16 data, and terminator byte.
    /// The length prefix uses ECMA-335 compressed integer format, and the terminator byte
    /// indicates whether the string contains high Unicode characters (>= 0x80).
    ///
    /// # Arguments
    ///
    /// * `user_string` - The string to write
    /// * `write_pos` - Mutable reference to the current write position, updated after writing
    pub(super) fn write_single_userstring(
        &mut self,
        user_string: &str,
        write_pos: &mut usize,
    ) -> Result<()> {
        let utf16_bytes: Vec<u8> = user_string
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();

        let utf16_data_length = utf16_bytes.len();
        let total_length = utf16_data_length + 1; // UTF-16 data + terminator byte

        // Write compressed integer length prefix
        *write_pos = self
            .base
            .output
            .write_compressed_uint_at(*write_pos as u64, total_length as u32)?
            as usize;

        // Write the UTF-16 string data
        self.base
            .output
            .write_and_advance(write_pos, &utf16_bytes)?;

        // Write the terminator byte
        let has_high_chars = user_string.chars().any(|c| c as u32 >= 0x80);
        let terminator_byte = if has_high_chars { 1 } else { 0 };
        self.base
            .output
            .write_and_advance(write_pos, &[terminator_byte])?;

        Ok(())
    }

    /// Helper method to write a single userstring at a specific position with proper UTF-16 encoding.
    ///
    /// Similar to `write_single_userstring` but writes at a specific target position rather than
    /// using a mutable write position reference. Used when precise positioning is required
    /// during heap rebuilding operations.
    ///
    /// # Arguments
    ///
    /// * `user_string` - The string to write
    /// * `target_pos` - The specific position in the output buffer to write to
    pub(super) fn write_single_userstring_at(
        &mut self,
        user_string: &str,
        target_pos: usize,
    ) -> Result<()> {
        let utf16_bytes: Vec<u8> = user_string
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();

        let utf16_data_length = utf16_bytes.len();
        let total_length = utf16_data_length + 1; // UTF-16 data + terminator byte

        let mut write_pos = target_pos;

        // Write compressed integer length prefix
        write_pos = self
            .base
            .output
            .write_compressed_uint_at(write_pos as u64, total_length as u32)?
            as usize;

        // Write the UTF-16 string data
        let string_slice = self
            .base
            .output
            .get_mut_slice(write_pos, utf16_bytes.len())?;
        string_slice.copy_from_slice(&utf16_bytes);
        write_pos += utf16_bytes.len();

        // Write the terminator byte
        let has_high_chars = user_string.chars().any(|c| c as u32 >= 0x80);
        let terminator_byte = if has_high_chars { 1 } else { 0 };
        let terminator_slice = self.base.output.get_mut_slice(write_pos, 1)?;
        terminator_slice[0] = terminator_byte;

        Ok(())
    }

    /// Retrieves all original userstrings from the assembly's userstring heap.
    ///
    /// Returns a vector containing all userstring data from the original heap,
    /// converted to UTF-8 strings. Used for heap rebuilding operations that
    /// need to process original content.
    ///
    /// # Returns
    ///
    /// A `Result<Vec<String>>` containing all original userstring data,
    /// or an empty vector if no userstring heap exists in the original assembly.
    /// Returns an error if any userstring cannot be converted to valid UTF-8.
    pub(super) fn get_original_userstrings(&self) -> Result<Vec<String>> {
        let mut userstrings = Vec::new();
        if let Some(us_heap) = self.base.assembly.view().userstrings() {
            for (_, userstring) in us_heap.iter() {
                match userstring.to_string() {
                    Ok(s) => userstrings.push(s),
                    Err(_) => {
                        return Err(crate::Error::WriteLayoutFailed {
                            message: "Failed to convert userstring to UTF-8".to_string(),
                        })
                    }
                }
            }
        }
        Ok(userstrings)
    }

    /// Retrieves all original userstrings with their heap offsets.
    ///
    /// Returns a vector containing all userstring data from the original heap
    /// along with their byte offsets within the heap. This is useful for
    /// operations that need to understand the original heap structure and
    /// maintain offset relationships.
    ///
    /// # Returns
    ///
    /// A `Result<Vec<(u32, String)>>` containing (offset, string) pairs for all
    /// original userstrings, or an empty vector if no userstring heap exists.
    /// Returns an error if any userstring cannot be converted to valid UTF-8.
    pub(super) fn get_original_userstrings_with_offsets(&self) -> Result<Vec<(u32, String)>> {
        let mut userstrings = Vec::new();
        if let Some(us_heap) = self.base.assembly.view().userstrings() {
            for (offset, userstring) in us_heap.iter() {
                match userstring.to_string() {
                    Ok(s) => userstrings.push((offset as u32, s)),
                    Err(_) => {
                        return Err(crate::Error::WriteLayoutFailed {
                            message: "Failed to convert userstring to UTF-8".to_string(),
                        })
                    }
                }
            }
        }
        Ok(userstrings)
    }

    /// Calculates the total size of a userstring entry including its length prefix.
    ///
    /// Determines the compressed length prefix size and adds it to the userstring data size.
    /// This matches the ECMA-335 compressed integer encoding used in userstring heaps.
    ///
    /// # Arguments
    ///
    /// * `userstring` - The userstring to calculate the entry size for
    ///
    /// # Returns
    ///
    /// The total size in bytes (prefix + UTF-16 data + terminator) that this userstring entry will occupy
    pub(super) fn calculate_userstring_entry_size(&self, userstring: &str) -> u32 {
        let utf16_bytes: Vec<u8> = userstring
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        let utf16_data_length = utf16_bytes.len();
        let total_length = utf16_data_length + 1;

        let prefix_size = compressed_uint_size(total_length);
        prefix_size as u32 + total_length as u32
    }
}
