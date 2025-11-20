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
/// # Building Strategy: Append-Only with Zero-Padding
///
/// This builder uses a append-only strategy that minimizes index remapping:
///
/// **In-Place Modification**: When a modified string fits in the original space,
/// it overwrites the original location with zero-padding for unused space.
/// *No index remapping needed!*
///
/// **Append When Necessary**: When a modified string is too large, the original
/// location is zero-padded and the new string is appended at the heap end.
/// *Only this string needs index remapping.*
///
/// **New Strings**: Always appended at the heap end with appropriate index mappings.
///
/// This approach preserves most original indices (critical for `ldstr` instructions)
/// while eliminating buffer overlaps and corruption risks.
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

    /// Calculate the total size of a userstring entry including prefix and terminator.
    fn calculate_userstring_entry_size(string: &str) -> u32 {
        let utf16_len = string.encode_utf16().count() * 2;
        let total_len = utf16_len + 1; // +1 for terminator
        let prefix_size = compressed_uint_size(total_len);
        u32::try_from(prefix_size).unwrap_or(0) + u32::try_from(total_len).unwrap_or(0)
    }

    /// Create a complete userstring entry with length prefix, UTF-16 data, and terminator.
    fn create_userstring_entry(string: &str) -> Result<Vec<u8>> {
        let utf16_bytes: Vec<u8> = string.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let total_length = utf16_bytes.len() + 1; // UTF-16 data + terminator byte

        let mut entry_bytes = Vec::new();
        let total_length_u32 = u32::try_from(total_length)
            .map_err(|_| malformed_error!("String length exceeds u32 range"))?;
        write_compressed_uint(total_length_u32, &mut entry_bytes);
        entry_bytes.extend_from_slice(&utf16_bytes);
        let has_high_chars = string.chars().any(|c| c as u32 >= 0x80);
        entry_bytes.push(u8::from(has_high_chars));

        Ok(entry_bytes)
    }

    /// Copy the original userstring heap raw data to preserve exact byte positions.
    fn copy_original_userstring_heap_raw_data(&self) -> Result<Vec<u8>> {
        let view = self.assembly.view();
        let metadata_root = view.metadata_root();

        // Find the userstrings stream in the original metadata
        for stream_header in &metadata_root.stream_headers {
            if stream_header.name == "#US" {
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
                        message: "Failed to read original userstring stream data".to_string(),
                    }
                })?;

                return Ok(stream_data.to_vec());
            }
        }

        Err(Error::WriteLayoutFailed {
            message: "UserString stream not found in original metadata".to_string(),
        })
    }
}

impl HeapBuilder for UserStringHeapBuilder<'_> {
    fn build(&mut self) -> Result<Vec<u8>> {
        let userstring_changes = &self.assembly.changes().userstring_heap_changes;

        // STEP 1: Copy the whole original heap (or start with null byte if none exists)
        let mut final_heap = if let Some(replacement_heap) = userstring_changes.replacement_heap() {
            replacement_heap.clone()
        } else if let Some(_userstrings_heap) = self.assembly.view().userstrings() {
            self.copy_original_userstring_heap_raw_data()?
        } else {
            vec![0] // Just null byte for empty heap
        };

        // STEP 2: Apply deletions and modifications using existing iterator for boundaries
        if let Some(userstrings_heap) = self.assembly.view().userstrings() {
            for (offset, _userstring) in userstrings_heap.iter() {
                let index = u32::try_from(offset).unwrap_or(0);

                // Handle deletions - zero out the string
                if userstring_changes.removed_indices.contains(&index) {
                    // Use existing compressed int parsing to get entry size
                    let mut pos = offset;
                    if let Ok((length, length_bytes)) =
                        crate::utils::read_compressed_int(&final_heap, &mut pos)
                    {
                        let end_pos = offset + length_bytes + length;
                        if end_pos <= final_heap.len() {
                            final_heap[offset..end_pos].fill(0);
                        }
                    }
                    continue;
                }

                // Handle modifications
                if let Some(new_string) = userstring_changes.modified_items.get(&index) {
                    // Use existing compressed int parsing to get original entry size
                    let mut pos = offset;
                    if let Ok((original_length, length_bytes)) =
                        crate::utils::read_compressed_int(&final_heap, &mut pos)
                    {
                        let original_end_pos = offset + length_bytes + original_length;
                        let original_space = original_end_pos - offset;

                        let new_entry = Self::create_userstring_entry(new_string)?;
                        let new_size = new_entry.len();

                        if new_size <= original_space {
                            // FITS IN PLACE: Overwrite and zero-pad remainder
                            final_heap[offset..offset + new_size].copy_from_slice(&new_entry);
                            if new_size < original_space {
                                final_heap[(offset + new_size)..original_end_pos].fill(0);
                            }
                            // NO remapping needed!
                        } else {
                            // DOESN'T FIT: Zero original and append at end
                            final_heap[offset..original_end_pos].fill(0);

                            let new_index = u32::try_from(final_heap.len()).map_err(|_| {
                                malformed_error!("UserString heap size exceeds u32 range")
                            })?;
                            final_heap.extend_from_slice(&new_entry);

                            // Track remapping
                            self.index_mappings.insert(index, new_index);
                        }
                    }
                }
            }
        }

        // STEP 3: Append new strings at the end
        for (vec_index, original_string) in userstring_changes.appended_items.iter().enumerate() {
            let original_heap_index = userstring_changes
                .get_appended_item_index(vec_index)
                .ok_or_else(|| Error::WriteLayoutFailed {
                    message: "Missing index for appended userstring item".to_string(),
                })?;

            // Skip if removed
            if userstring_changes
                .removed_indices
                .contains(&original_heap_index)
            {
                continue;
            }

            // Get final string (check for modifications)
            let final_string = userstring_changes
                .modified_items
                .get(&original_heap_index)
                .cloned()
                .unwrap_or_else(|| original_string.clone());

            // For append-only strategy: append at heap end and track the mapping
            let new_index = u32::try_from(final_heap.len())
                .map_err(|_| malformed_error!("UserString heap size exceeds u32 range"))?;

            let entry_bytes = Self::create_userstring_entry(&final_string)?;
            final_heap.extend_from_slice(&entry_bytes);

            // Map the original promised offset to the actual placement
            self.index_mappings.insert(original_heap_index, new_index);
        }

        // Apply 4-byte alignment padding
        while final_heap.len() % 4 != 0 {
            final_heap.push(0xFF);
        }

        Ok(final_heap)
    }

    fn calculate_size(&self) -> Result<u64> {
        let userstring_changes = &self.assembly.changes().userstring_heap_changes;
        Ok(calculate_userstring_heap_size(
            userstring_changes,
            self.assembly,
        ))
    }

    fn get_index_mappings(&self) -> &HashMap<u32, u32> {
        &self.index_mappings
    }

    fn heap_name(&self) -> &'static str {
        "#US"
    }
}
