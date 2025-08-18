//! User string heap builder for the simplified assembly writer.
//!
//! This module implements user string heap reconstruction using the exact same
//! algorithms as the existing pipeline to ensure 100% compatibility.

use std::collections::HashMap;

use crate::{
    cilassembly::{
        writer::{heaps::HeapBuilder, layout::calculate_userstring_heap_size},
        CilAssembly,
    },
    utils::{compressed_uint_size, write_compressed_uint},
    Error, Result,
};

/// Builder for #US (User String) metadata heap reconstruction.
///
/// The user string heap (#US) contains UTF-16 strings used by IL string literals.
/// Each string is prefixed with a compressed length and includes a trailing byte
/// indicating whether the string contains special characters.
///
/// # ECMA-335 Format
///
/// Each user string entry has the format:
/// - Compressed length (1-4 bytes)
/// - UTF-16 string data (length bytes)
/// - Trailing byte (0x00 for ASCII-only, 0x01 for special chars)
///
/// # Index Management
///
/// - Index 0 is reserved for null (contains single 0x00 byte)
/// - All other indices point to the start of compressed length prefix
/// - Indices are byte offsets from heap start
///
/// # Examples
///
/// ```rust,ignore
/// let mut builder = UserStringHeapBuilder::new(&assembly);
/// let heap_data = builder.build()?;
/// let size = builder.calculate_size()?;
/// ```
pub struct UserStringHeapBuilder<'a> {
    /// Reference to the assembly being processed
    assembly: &'a CilAssembly,
    /// Mapping from original user string indices to final indices after reconstruction
    index_mappings: HashMap<u32, u32>,
}

impl<'a> UserStringHeapBuilder<'a> {
    /// Creates a new user string heap builder for the specified assembly.
    ///
    /// # Arguments
    ///
    /// * `assembly` - Assembly containing user string heap changes to process
    ///
    /// # Returns
    ///
    /// Returns a new `UserStringHeapBuilder` ready for heap reconstruction.
    pub fn new(assembly: &'a CilAssembly) -> Self {
        Self {
            assembly,
            index_mappings: HashMap::new(),
        }
    }
}

impl HeapBuilder for UserStringHeapBuilder<'_> {
    fn build(&mut self) -> Result<Vec<u8>> {
        let userstring_changes = &self.assembly.changes().userstring_heap_changes;
        let mut final_heap = Vec::new();
        let mut final_index_position = 1u32; // Start at 1, index 0 is always null

        // Handle heap replacement scenario
        if let Some(replacement_heap) = userstring_changes.replacement_heap() {
            final_heap.clone_from(replacement_heap);

            // Create basic index mapping for the replacement heap
            let mut current_position = 1u32; // Skip null byte at index 0
            let heap_data = &final_heap[1..]; // Skip the null byte at start
            let mut start = 0;

            while start < heap_data.len() {
                // Read compressed length
                let mut len_bytes = 1;
                if start < heap_data.len() && heap_data[start] >= 0x80 {
                    if start + 1 < heap_data.len() && heap_data[start + 1] >= 0x80 {
                        len_bytes = 4;
                    } else {
                        len_bytes = 2;
                    }
                }

                if start + len_bytes <= heap_data.len() {
                    let length = match len_bytes {
                        1 => u32::from(heap_data[start]),
                        2 => {
                            (u32::from(heap_data[start] & 0x7F) << 8)
                                | u32::from(heap_data[start + 1])
                        }
                        4 => {
                            (u32::from(heap_data[start] & 0x1F) << 24)
                                | (u32::from(heap_data[start + 1]) << 16)
                                | (u32::from(heap_data[start + 2]) << 8)
                                | u32::from(heap_data[start + 3])
                        }
                        _ => break,
                    };

                    self.index_mappings
                        .insert(current_position, current_position);
                    let entry_size = len_bytes + length as usize;
                    current_position += u32::try_from(entry_size).unwrap_or(0);
                    start += entry_size;
                } else {
                    break;
                }
            }

            // Handle appended items
            for original_string in &userstring_changes.appended_items {
                let original_heap_index = {
                    let mut calculated_index = userstring_changes.next_index;
                    for item in userstring_changes.appended_items.iter().rev() {
                        let utf16_bytes: usize = item.encode_utf16().map(|_| 2).sum();
                        let total_length = utf16_bytes + 1;
                        let compressed_length_size = compressed_uint_size(total_length);
                        calculated_index -= u32::try_from(
                            compressed_length_size + u64::try_from(total_length).unwrap_or(0),
                        )
                        .unwrap_or(0);
                        if std::ptr::eq(item, original_string) {
                            break;
                        }
                    }
                    calculated_index
                };

                if !userstring_changes.is_removed(original_heap_index) {
                    let final_string = userstring_changes
                        .get_modification(original_heap_index)
                        .cloned()
                        .unwrap_or_else(|| original_string.clone());

                    self.index_mappings
                        .insert(original_heap_index, final_index_position);

                    // Write user string entry
                    let utf16_bytes: Vec<u8> = final_string
                        .encode_utf16()
                        .flat_map(u16::to_le_bytes)
                        .collect();
                    let total_length = utf16_bytes.len() + 1; // UTF-16 data + terminator byte

                    // Write compressed length prefix
                    let total_length_u32 = u32::try_from(total_length)
                        .map_err(|_| malformed_error!("String length exceeds u32 range"))?;
                    write_compressed_uint(total_length_u32, &mut final_heap);
                    // Write UTF-16 data
                    final_heap.extend_from_slice(&utf16_bytes);
                    // Write terminator byte
                    let has_high_chars = final_string.chars().any(|c| c as u32 >= 0x80);
                    final_heap.push(u8::from(has_high_chars));

                    final_index_position += u32::try_from(
                        compressed_uint_size(total_length)
                            + u64::try_from(total_length).unwrap_or(0),
                    )
                    .unwrap_or(0);
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

        // Process original user strings if available
        if let Some(userstrings_heap) = self.assembly.view().userstrings() {
            for (original_index, original_userstring) in userstrings_heap.iter() {
                let original_index =
                    u32::try_from(original_index).map_err(|_| Error::WriteLayoutFailed {
                        message: "UserString heap index exceeds u32 range".to_string(),
                    })?;

                if userstring_changes.is_removed(original_index) {
                    // UserString is removed - no mapping entry
                    continue;
                }
                if let Some(modified_string) = userstring_changes.get_modification(original_index) {
                    // UserString is modified - add modified version
                    self.index_mappings
                        .insert(original_index, final_index_position);

                    let utf16_bytes: Vec<u8> = modified_string
                        .encode_utf16()
                        .flat_map(u16::to_le_bytes)
                        .collect();
                    let total_length = utf16_bytes.len() + 1; // UTF-16 data + terminator byte

                    // Write compressed length prefix
                    let total_length_u32 = u32::try_from(total_length)
                        .map_err(|_| malformed_error!("String length exceeds u32 range"))?;
                    write_compressed_uint(total_length_u32, &mut final_heap);
                    // Write UTF-16 data
                    final_heap.extend_from_slice(&utf16_bytes);
                    // Write terminator byte
                    let has_high_chars = modified_string.chars().any(|c| c as u32 >= 0x80);
                    final_heap.push(u8::from(has_high_chars));

                    final_index_position += u32::try_from(
                        compressed_uint_size(total_length)
                            + u64::try_from(total_length).unwrap_or(0),
                    )
                    .map_err(|_| Error::WriteLayoutFailed {
                        message: "Modified userstring size calculation exceeds u32 range"
                            .to_string(),
                    })?;
                } else {
                    // UserString is unchanged - add original version
                    let original_data = original_userstring.to_string_lossy().to_string();
                    self.index_mappings
                        .insert(original_index, final_index_position);

                    let utf16_bytes: Vec<u8> = original_data
                        .encode_utf16()
                        .flat_map(u16::to_le_bytes)
                        .collect();
                    let total_length = utf16_bytes.len() + 1; // UTF-16 data + terminator byte

                    // Write compressed length prefix
                    let total_length_u32 = u32::try_from(total_length)
                        .map_err(|_| malformed_error!("String length exceeds u32 range"))?;
                    write_compressed_uint(total_length_u32, &mut final_heap);
                    // Write UTF-16 data
                    final_heap.extend_from_slice(&utf16_bytes);
                    // Write terminator byte
                    let has_high_chars = original_data.chars().any(|c| c as u32 >= 0x80);
                    final_heap.push(u8::from(has_high_chars));

                    final_index_position += u32::try_from(
                        compressed_uint_size(total_length)
                            + u64::try_from(total_length).unwrap_or(0),
                    )
                    .map_err(|_| Error::WriteLayoutFailed {
                        message: "Original userstring size calculation exceeds u32 range"
                            .to_string(),
                    })?;
                }
            }
        }

        // Handle appended user strings, applying any modifications or removals
        for original_string in &userstring_changes.appended_items {
            let original_heap_index = {
                let mut calculated_index = userstring_changes.next_index;
                for item in userstring_changes.appended_items.iter().rev() {
                    let utf16_bytes: usize = item.encode_utf16().map(|_| 2).sum();
                    let total_length = utf16_bytes + 1;
                    let compressed_length_size = compressed_uint_size(total_length);
                    calculated_index -= u32::try_from(
                        compressed_length_size + u64::try_from(total_length).unwrap_or(0),
                    )
                    .map_err(|_| Error::WriteLayoutFailed {
                        message: "UserString item size exceeds u32 range".to_string(),
                    })?;
                    if std::ptr::eq(item, original_string) {
                        break;
                    }
                }
                calculated_index
            };

            if userstring_changes
                .removed_indices
                .contains(&original_heap_index)
            {
            } else if let Some(modified_string) =
                userstring_changes.modified_items.get(&original_heap_index)
            {
                self.index_mappings
                    .insert(original_heap_index, final_index_position);

                let utf16_bytes: Vec<u8> = modified_string
                    .encode_utf16()
                    .flat_map(u16::to_le_bytes)
                    .collect();
                let total_length = utf16_bytes.len() + 1; // UTF-16 data + terminator byte

                // Write compressed length prefix
                let total_length_u32 = u32::try_from(total_length)
                    .map_err(|_| malformed_error!("String length exceeds u32 range"))?;
                write_compressed_uint(total_length_u32, &mut final_heap);
                // Write UTF-16 data
                final_heap.extend_from_slice(&utf16_bytes);
                // Write terminator byte
                final_heap.push(0);

                final_index_position += u32::try_from(
                    compressed_uint_size(total_length) + u64::try_from(total_length).unwrap_or(0),
                )
                .map_err(|_| Error::WriteLayoutFailed {
                    message: "UserString final index exceeds u32 range".to_string(),
                })?;
            } else {
                self.index_mappings
                    .insert(original_heap_index, final_index_position);

                let utf16_bytes: Vec<u8> = original_string
                    .encode_utf16()
                    .flat_map(u16::to_le_bytes)
                    .collect();
                let total_length = utf16_bytes.len() + 1; // UTF-16 data + terminator byte

                // Write compressed length prefix
                let total_length_u32 = u32::try_from(total_length)
                    .map_err(|_| malformed_error!("String length exceeds u32 range"))?;
                write_compressed_uint(total_length_u32, &mut final_heap);
                // Write UTF-16 data
                final_heap.extend_from_slice(&utf16_bytes);
                // Write terminator byte
                let has_high_chars = original_string.chars().any(|c| c as u32 >= 0x80);
                final_heap.push(u8::from(has_high_chars));

                final_index_position += u32::try_from(
                    compressed_uint_size(total_length) + u64::try_from(total_length).unwrap_or(0),
                )
                .map_err(|_| Error::WriteLayoutFailed {
                    message: "Final userstring size calculation exceeds u32 range".to_string(),
                })?;
            }
        }

        // Apply 4-byte alignment padding with 0xFF bytes
        while final_heap.len() % 4 != 0 {
            final_heap.push(0xFF);
        }

        Ok(final_heap)
    }

    fn calculate_size(&self) -> Result<u64> {
        let userstring_changes = &self.assembly.changes().userstring_heap_changes;
        calculate_userstring_heap_size(userstring_changes, self.assembly)
    }

    fn get_index_mappings(&self) -> &HashMap<u32, u32> {
        &self.index_mappings
    }

    fn heap_name(&self) -> &'static str {
        "#US"
    }
}
