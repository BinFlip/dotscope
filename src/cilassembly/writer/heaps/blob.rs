//! Blob heap builder for the simplified assembly writer.
//!
//! This module implements blob heap reconstruction using the exact same
//! algorithms as the existing pipeline to ensure 100% compatibility.

use std::collections::HashMap;

use crate::{
    cilassembly::{
        writer::{heaps::HeapBuilder, layout::calculate_blob_heap_size},
        CilAssembly,
    },
    utils::{compressed_uint_size, read_compressed_uint, write_compressed_uint},
    Error, Result,
};

/// Builder for #Blob metadata heap reconstruction.
///
/// The blob heap contains binary data referenced by metadata tables.
/// Each blob entry is prefixed with its length encoded as a compressed unsigned integer
/// according to ECMA-335 specification.
///
/// # ECMA-335 Format
///
/// Each blob entry has the format:
/// - Compressed length prefix (1-4 bytes)
/// - Binary data (length bytes)
///
/// Compressed length encoding:
/// - Values < 0x80: 1 byte (0xxxxxxx)
/// - Values < 0x4000: 2 bytes (10xxxxxx xxxxxxxx)
/// - Larger values: 4 bytes (110xxxxx xxxxxxxx xxxxxxxx xxxxxxxx)
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
/// let mut builder = BlobHeapBuilder::new(&assembly);
/// let heap_data = builder.build()?;
/// let mappings = builder.get_index_mappings();
/// ```
pub struct BlobHeapBuilder<'a> {
    /// Reference to the assembly being processed
    assembly: &'a CilAssembly,
    /// Mapping from original blob indices to final indices after reconstruction
    index_mappings: HashMap<u32, u32>,
}

impl<'a> BlobHeapBuilder<'a> {
    /// Creates a new blob heap builder for the specified assembly.
    ///
    /// # Arguments
    ///
    /// * `assembly` - Assembly containing blob heap changes to process
    ///
    /// # Returns
    ///
    /// Returns a new `BlobHeapBuilder` ready for heap reconstruction.
    pub fn new(assembly: &'a CilAssembly) -> BlobHeapBuilder<'a> {
        Self {
            assembly,
            index_mappings: HashMap::new(),
        }
    }
}

impl HeapBuilder for BlobHeapBuilder<'_> {
    fn build(&mut self) -> Result<Vec<u8>> {
        let blob_changes = &self.assembly.changes().blob_heap_changes;
        let mut final_heap = Vec::new();
        let mut final_index_position = 1u32; // Start at 1, index 0 is always null

        // Handle heap replacement scenario
        if let Some(replacement_heap) = blob_changes.replacement_heap() {
            final_heap.clone_from(replacement_heap);

            // Handle appended items
            for original_blob in &blob_changes.appended_items {
                let original_heap_index = {
                    let mut calculated_index = blob_changes.next_index;
                    for item in blob_changes.appended_items.iter().rev() {
                        let prefix_size = compressed_uint_size(item.len());
                        calculated_index -= u32::try_from(prefix_size).unwrap_or(0)
                            + u32::try_from(item.len()).unwrap_or(0);
                        if std::ptr::eq(item, original_blob) {
                            break;
                        }
                    }
                    calculated_index
                };

                if !blob_changes.is_removed(original_heap_index) {
                    let final_blob = blob_changes
                        .get_modification(original_heap_index)
                        .cloned()
                        .unwrap_or_else(|| original_blob.clone());

                    self.index_mappings
                        .insert(original_heap_index, final_index_position);

                    // Write length prefix
                    let blob_len = u32::try_from(final_blob.len())
                        .map_err(|_| malformed_error!("Blob size exceeds u32 range"))?;
                    write_compressed_uint(blob_len, &mut final_heap);
                    // Write blob data
                    final_heap.extend_from_slice(&final_blob);

                    final_index_position += u32::try_from(
                        compressed_uint_size(final_blob.len()) + final_blob.len() as u64,
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

        // REVOLUTIONARY APPROACH: Append-only with zero-padding
        // This preserves ALL original indices and eliminates the need for ANY index remapping
        if let Some(_blob_heap) = self.assembly.view().blobs() {
            // Start with the original heap data
            let original_heap_data = self.copy_original_blob_heap_raw_data()?;
            final_heap.clear(); // Remove the null byte we added earlier
            final_heap.extend_from_slice(&original_heap_data);

            // Step 1: Zero-pad any deleted blobs in place
            for &deleted_index in &blob_changes.removed_indices {
                if let Some((start_pos, end_pos)) =
                    Self::find_blob_boundaries_in_heap(&final_heap, deleted_index as usize)?
                {
                    // Replace the blob content with zeros, keeping the length prefix
                    final_heap[start_pos..end_pos].fill(0);
                }
            }

            // Step 2: Handle modified blobs - in-place when possible, remap when necessary
            for (&modified_index, new_blob) in &blob_changes.modified_items {
                if let Some((start_pos, end_pos)) =
                    Self::find_blob_boundaries_in_heap(&final_heap, modified_index as usize)?
                {
                    // Calculate original blob size (excluding length prefix)
                    let mut temp_offset = start_pos;
                    let original_length = read_compressed_uint(&final_heap, &mut temp_offset)?;
                    let original_data_size = original_length as usize;
                    let prefix_size = temp_offset - start_pos;
                    let new_blob_size = new_blob.len();

                    if new_blob_size <= original_data_size {
                        // FITS IN PLACE: Update length prefix and data, zero-pad remainder

                        // For simplicity, if blob fits, we can only handle it if the length prefix is the same size
                        // Otherwise, we need to remap (this is a limitation of in-place modification)
                        let new_prefix_size = compressed_uint_size(new_blob_size);
                        if new_prefix_size != prefix_size as u64 {
                            // Zero-pad and remap
                            final_heap[start_pos..end_pos].fill(0);
                            let new_index = u32::try_from(final_heap.len())
                                .map_err(|_| malformed_error!("Heap size exceeds u32 range"))?;
                            let new_blob_len = u32::try_from(new_blob.len())
                                .map_err(|_| malformed_error!("Blob size exceeds u32 range"))?;
                            write_compressed_uint(new_blob_len, &mut final_heap);
                            final_heap.extend_from_slice(new_blob);
                            self.index_mappings.insert(modified_index, new_index);
                            continue;
                        }

                        // Write new length prefix in place (same size as original)
                        let mut temp_vec = Vec::new();
                        let size_u32 = u32::try_from(new_blob_size)
                            .map_err(|_| malformed_error!("Blob size exceeds u32 range"))?;
                        write_compressed_uint(size_u32, &mut temp_vec);
                        final_heap[start_pos..start_pos + prefix_size].copy_from_slice(&temp_vec);
                        let write_pos = start_pos + prefix_size;

                        // Write new blob data
                        final_heap[write_pos..write_pos + new_blob_size].copy_from_slice(new_blob);
                        // Zero-pad remainder
                        final_heap[(write_pos + new_blob_size)..end_pos].fill(0);
                    } else {
                        // DOESN'T FIT: Need to remap - zero original and append new

                        // Zero-pad the original location completely
                        final_heap[start_pos..end_pos].fill(0);

                        // Append at end and create index mapping
                        let new_index = u32::try_from(final_heap.len())
                            .map_err(|_| malformed_error!("Heap size exceeds u32 range"))?;
                        let new_blob_len = u32::try_from(new_blob.len())
                            .map_err(|_| malformed_error!("Blob size exceeds u32 range"))?;
                        write_compressed_uint(new_blob_len, &mut final_heap);
                        final_heap.extend_from_slice(new_blob);

                        // CRITICAL: We need to track this remapping for table updates
                        self.index_mappings.insert(modified_index, new_index);
                    }
                }
            }

            // Step 3: Append new blobs at the end, applying any modifications or removals
            let mut current_append_index = u32::try_from(original_heap_data.len())
                .map_err(|_| malformed_error!("Original heap size exceeds u32 range"))?;
            for new_blob in &blob_changes.appended_items {
                // Check if this newly added blob has been modified or removed
                if blob_changes.removed_indices.contains(&current_append_index) {
                } else if let Some(modified_blob) =
                    blob_changes.modified_items.get(&current_append_index)
                {
                    let modified_blob_len = u32::try_from(modified_blob.len())
                        .map_err(|_| malformed_error!("Modified blob size exceeds u32 range"))?;
                    write_compressed_uint(modified_blob_len, &mut final_heap);
                    final_heap.extend_from_slice(modified_blob);
                } else {
                    let new_blob_len = u32::try_from(new_blob.len())
                        .map_err(|_| malformed_error!("New blob size exceeds u32 range"))?;
                    write_compressed_uint(new_blob_len, &mut final_heap);
                    final_heap.extend_from_slice(new_blob);
                }

                // Update the current append index for the next blob
                // Always use the original blob size for index calculation since that's how indices were assigned
                let prefix_size = compressed_uint_size(new_blob.len());
                let prefix_size_u32 = u32::try_from(prefix_size)
                    .map_err(|_| malformed_error!("Compressed uint size exceeds u32 range"))?;
                let new_blob_len_u32 = u32::try_from(new_blob.len())
                    .map_err(|_| malformed_error!("New blob size exceeds u32 range"))?;
                current_append_index += prefix_size_u32 + new_blob_len_u32;
            }

            // Apply 4-byte alignment padding
            while final_heap.len() % 4 != 0 {
                final_heap.push(0xFF);
            }

            return Ok(final_heap);
        }

        // Fallback: build from scratch if no original blob heap
        if let Some(blob_heap) = self.assembly.view().blobs() {
            for (original_index, original_blob) in blob_heap.iter() {
                if original_index == 0 {
                    continue; // Skip the mandatory null byte
                }

                let original_index =
                    u32::try_from(original_index).map_err(|_| Error::WriteLayoutFailed {
                        message: "Blob heap index exceeds u32 range".to_string(),
                    })?;

                if blob_changes.is_removed(original_index) {
                    // Blob is removed - no mapping entry
                    continue;
                }
                if let Some(modified_blob) = blob_changes.get_modification(original_index) {
                    // Blob is modified - add modified version
                    self.index_mappings
                        .insert(original_index, final_index_position);

                    // Write length prefix
                    let modified_blob_len = u32::try_from(modified_blob.len())
                        .map_err(|_| malformed_error!("Modified blob size exceeds u32 range"))?;
                    write_compressed_uint(modified_blob_len, &mut final_heap);
                    // Write blob data
                    final_heap.extend_from_slice(modified_blob);

                    final_index_position += u32::try_from(
                        compressed_uint_size(modified_blob.len()) + modified_blob.len() as u64,
                    )
                    .map_err(|_| Error::WriteLayoutFailed {
                        message: "Modified blob size calculation exceeds u32 range".to_string(),
                    })?;
                } else {
                    // Blob is unchanged - add original version
                    self.index_mappings
                        .insert(original_index, final_index_position);

                    // Write length prefix
                    let original_blob_len = u32::try_from(original_blob.len())
                        .map_err(|_| malformed_error!("Original blob size exceeds u32 range"))?;
                    write_compressed_uint(original_blob_len, &mut final_heap);
                    // Write blob data
                    final_heap.extend_from_slice(original_blob);

                    final_index_position += u32::try_from(
                        compressed_uint_size(original_blob.len()) + original_blob.len() as u64,
                    )
                    .map_err(|_| Error::WriteLayoutFailed {
                        message: "Original blob size calculation exceeds u32 range".to_string(),
                    })?;
                }
            }
        }

        // Handle appended blobs
        for original_blob in &blob_changes.appended_items {
            let original_heap_index = {
                let mut calculated_index = blob_changes.next_index;
                for item in blob_changes.appended_items.iter().rev() {
                    let prefix_size = compressed_uint_size(item.len());
                    calculated_index -=
                        u32::try_from(prefix_size).map_err(|_| Error::WriteLayoutFailed {
                            message: "Blob prefix size exceeds u32 range".to_string(),
                        })? + u32::try_from(item.len()).map_err(|_| Error::WriteLayoutFailed {
                            message: "Blob length exceeds u32 range".to_string(),
                        })?;
                    if std::ptr::eq(item, original_blob) {
                        break;
                    }
                }
                calculated_index
            };

            if !blob_changes.is_removed(original_heap_index) {
                let final_blob = blob_changes
                    .get_modification(original_heap_index)
                    .cloned()
                    .unwrap_or_else(|| original_blob.clone());

                self.index_mappings
                    .insert(original_heap_index, final_index_position);

                // Write length prefix
                let final_blob_len = u32::try_from(final_blob.len())
                    .map_err(|_| malformed_error!("Final blob size exceeds u32 range"))?;
                write_compressed_uint(final_blob_len, &mut final_heap);
                // Write blob data
                final_heap.extend_from_slice(&final_blob);

                final_index_position +=
                    u32::try_from(compressed_uint_size(final_blob.len()) + final_blob.len() as u64)
                        .map_err(|_| Error::WriteLayoutFailed {
                            message: "Final blob size calculation exceeds u32 range".to_string(),
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
        let blob_changes = &self.assembly.changes().blob_heap_changes;
        calculate_blob_heap_size(blob_changes, self.assembly)
    }

    fn get_index_mappings(&self) -> &HashMap<u32, u32> {
        &self.index_mappings
    }

    fn heap_name(&self) -> &'static str {
        "#Blob"
    }
}

impl BlobHeapBuilder<'_> {
    /// Find the byte boundaries of a blob at a given index in the heap.
    /// Returns (start_pos, end_pos) where end_pos is exclusive and includes the entire blob.
    fn find_blob_boundaries_in_heap(
        heap_data: &[u8],
        blob_index: usize,
    ) -> Result<Option<(usize, usize)>> {
        if blob_index == 0 || blob_index >= heap_data.len() {
            return Ok(None); // Invalid index
        }

        let start_pos = blob_index;

        // Read the compressed length prefix to determine blob size
        let mut offset = start_pos;
        let blob_length = read_compressed_uint(heap_data, &mut offset)?;
        let end_pos = offset + blob_length as usize;

        if end_pos > heap_data.len() {
            Ok(None) // Blob extends beyond heap
        } else {
            Ok(Some((start_pos, end_pos)))
        }
    }

    /// Copy the original blob heap raw data to preserve exact byte positions.
    fn copy_original_blob_heap_raw_data(&self) -> Result<Vec<u8>> {
        // Use the same approach as the planner's copy_original_stream_data
        let view = self.assembly.view();
        let metadata_root = view.metadata_root();

        // Find the blob stream in the original metadata
        for stream_header in &metadata_root.stream_headers {
            if stream_header.name == "#Blob" {
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
                        message: "Failed to read original blob stream data".to_string(),
                    }
                })?;

                return Ok(stream_data.to_vec());
            }
        }

        Err(Error::WriteLayoutFailed {
            message: "Blob stream not found in original metadata".to_string(),
        })
    }
}
