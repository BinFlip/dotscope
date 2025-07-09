//! Blob heap writing functionality.
//!
//! This module handles writing modifications to the #Blob heap, including simple additions
//! and complex operations involving modifications and removals that require heap rebuilding.

use crate::{cilassembly::write::planner::StreamModification, Error, Result};

impl<'a> super::HeapWriter<'a> {
    /// Writes blob heap modifications including additions, modifications, and removals.
    ///
    /// Handles all types of blob heap changes:
    /// - Additions: Appends new blobs to the end of the heap
    /// - Modifications: Updates existing blobs in place (if possible)
    /// - Removals: Marks blobs as removed (handled during parsing/indexing)
    ///
    /// Writes binary data with compressed integer length prefixes as specified by
    /// ECMA-335 II.24.2.4. Each blob is prefixed with its length using compressed
    /// integer encoding (1, 2, or 4 bytes) followed by the raw blob data.
    ///
    /// # Arguments
    ///
    /// * `stream_mod` - The [`crate::cilassembly::write::planner::metadata::StreamModification`] for the #Blob heap
    pub(super) fn write_blob_heap(&mut self, stream_mod: &StreamModification) -> Result<()> {
        let blob_changes = &self.base.assembly.changes().blob_heap_changes;

        // Always write blob heap with changes to preserve byte offsets
        // The append-only approach corrupts original blob offsets during sequential copying
        if blob_changes.has_changes() {
            return self.write_blob_heap_with_changes(stream_mod);
        }

        let (stream_layout, write_start) = self.base.get_stream_write_position(stream_mod)?;
        let mut write_pos = write_start;
        let stream_end = stream_layout.file_region.end_offset() as usize;

        // Copy original blob heap data first to preserve existing blobs
        if let Some(blob_heap) = self.base.assembly.view().blobs() {
            // Start with null byte
            self.base.output.write_and_advance(&mut write_pos, &[0])?;

            // Copy all original blobs sequentially
            for (_, blob) in blob_heap.iter() {
                // Write length prefix
                write_pos = self
                    .base
                    .output
                    .write_compressed_uint_at(write_pos as u64, blob.len() as u32)?
                    as usize;

                // Write blob data
                self.base.output.write_and_advance(&mut write_pos, blob)?;
            }
        } else {
            // No original heap, start with null byte
            self.base.output.write_and_advance(&mut write_pos, &[0])?;
        }

        // Append new blobs, applying modifications if present

        // Calculate correct API indices for appended blobs (replicating add_blob logic)
        let start_index = if let Some(_blob_heap) = self.base.assembly.view().blobs() {
            // Use the actual heap size (same as HeapChanges::new)
            let heap_stream = self
                .base
                .assembly
                .view()
                .streams()
                .iter()
                .find(|s| s.name == "#Blob");
            heap_stream.map(|s| s.size).unwrap_or(0)
        } else {
            1 // Start after null byte if no original heap
        };

        let mut current_api_index = start_index;

        for appended_blob in &blob_changes.appended_items {
            let heap_index = current_api_index;

            if blob_changes.is_removed(heap_index) {
                continue;
            }

            // Apply modification if present, otherwise use original appended blob
            let final_blob = blob_changes
                .get_modification(heap_index)
                .cloned()
                .unwrap_or_else(|| appended_blob.clone());

            let length = final_blob.len();

            // Ensure we won't exceed stream boundary
            if write_pos + final_blob.len() > stream_end {
                return Err(Error::WriteLayoutFailed {
                    message: format!(
                        "Blob heap overflow: write would exceed allocated space by {} bytes",
                        (write_pos + final_blob.len()) - stream_end
                    ),
                });
            }

            // Write length prefix
            write_pos = self
                .base
                .output
                .write_compressed_uint_at(write_pos as u64, length as u32)?
                as usize;

            // Write blob data
            self.base
                .output
                .write_and_advance(&mut write_pos, &final_blob)?;

            // Advance API index by actual blob size (same as add_blob logic)
            let prefix_size = if length < 128 {
                1
            } else if length < 16384 {
                2
            } else {
                4
            };
            current_api_index += prefix_size + length as u32;
        }

        // Add special blob padding to avoid creating extra blob entries during parsing
        self.base.output.add_heap_padding(write_pos, write_start)?;

        Ok(())
    }

    /// Writes the blob heap when modifications or removals are present.
    ///
    /// This method provides comprehensive blob heap writing that:
    /// - Preserves all valid blob entries and their byte offsets
    /// - Applies in-place modifications where possible
    /// - Handles blob removals by skipping entries
    /// - Appends new blobs at the end
    /// - Maintains proper ECMA-335 alignment and encoding
    ///
    /// # Strategy
    ///
    /// 1. **Rebuild Original**: Process original blobs applying modifications/removals
    /// 2. **Calculate Indices**: Determine correct indices for appended blobs
    /// 3. **Apply Changes**: Process appended blobs with modifications/removals
    /// 4. **Alignment**: Apply proper 4-byte alignment padding
    ///
    /// # Arguments
    ///
    /// * `stream_mod` - The [`crate::cilassembly::write::planner::metadata::StreamModification`] for the #Blob heap
    pub(super) fn write_blob_heap_with_changes(
        &mut self,
        stream_mod: &StreamModification,
    ) -> Result<()> {
        let (stream_layout, write_start) = self.base.get_stream_write_position(stream_mod)?;
        let mut write_pos = write_start;

        let blob_changes = &self.base.assembly.changes().blob_heap_changes;
        let stream_end = stream_layout.file_region.end_offset() as usize;

        // Step 1: Rebuild blob heap entry by entry, applying modifications
        let mut rebuilt_original_count = 0;
        if let Some(blob_heap) = self.base.assembly.view().blobs() {
            // Start with null byte
            self.base.output.write_and_advance(&mut write_pos, &[0])?;

            // Rebuild each blob, applying modifications
            for (offset, blob) in blob_heap.iter() {
                let blob_index = offset as u32;

                // Check if this blob should be removed
                if blob_changes.is_removed(blob_index) {
                    continue;
                }

                // Get the blob data (original or modified)
                let blob_data =
                    if let Some(modified_blob) = blob_changes.get_modification(blob_index) {
                        modified_blob.clone()
                    } else {
                        blob.to_vec()
                    };

                // Write the blob
                self.write_single_blob(&blob_data, &mut write_pos)?;
                rebuilt_original_count += 1;
            }
        } else {
            // No original heap, start with null byte only
            let null_slice = self.base.output.get_mut_slice(write_pos, 1)?;
            null_slice[0] = 0;
            write_pos += 1;
        }

        // Step 2: Write appended blobs, applying modifications to newly added blobs
        let mut appended_count = 0;

        // Calculate the original heap size to distinguish original vs newly added blobs
        let original_heap_size = stream_mod.original_size as u32;

        // Build mappings for modifications and removals of appended items
        let mut appended_modifications: std::collections::HashMap<usize, Vec<u8>> =
            std::collections::HashMap::new();
        let mut appended_removals: std::collections::HashSet<usize> =
            std::collections::HashSet::new();

        // Calculate which appended items have modifications or removals
        let mut current_index = original_heap_size;
        for (pos, appended_blob) in blob_changes.appended_items.iter().enumerate() {
            // Check if there's a modification at the current calculated index
            if let Some(modified_blob) = blob_changes.get_modification(current_index) {
                appended_modifications.insert(pos, modified_blob.clone());
            }

            // Check if this appended item has been removed
            if blob_changes.is_removed(current_index) {
                appended_removals.insert(pos);
            }

            // Calculate the index for the next blob (prefix + data)
            let length = appended_blob.len();
            let prefix_size = if length < 128 {
                1
            } else if length < 16384 {
                2
            } else {
                4
            };
            current_index += prefix_size + length as u32;
        }

        // Write each appended blob, applying modifications if found and skipping removed ones
        for (i, appended_blob) in blob_changes.appended_items.iter().enumerate() {
            // Skip removed appended items
            if appended_removals.contains(&i) {
                continue;
            }

            // Check if this appended item has been modified
            let blob_data = if let Some(modified_blob) = appended_modifications.get(&i) {
                modified_blob.clone()
            } else {
                appended_blob.clone()
            };

            // Ensure we won't exceed stream boundary
            let entry_size = self.calculate_blob_entry_size(&blob_data) as usize;
            if write_pos + entry_size > stream_end {
                return Err(Error::WriteLayoutFailed {
                    message: format!("Blob heap overflow during writing: write would exceed allocated space by {} bytes", 
                        (write_pos + entry_size) - stream_end)
                });
            }

            self.write_single_blob(&blob_data, &mut write_pos)?;
            appended_count += 1;
        }

        let _total_blobs_count = rebuilt_original_count + appended_count;

        // Add padding to align to 4-byte boundary (ECMA-335 II.24.2.2)
        // Use a pattern that won't create valid blob entries
        self.base.output.add_heap_padding(write_pos, write_start)?;
        Ok(())
    }

    /// Helper method to write a single blob with proper encoding.
    ///
    /// Writes a blob entry with compressed length prefix followed by the blob data.
    /// The length is encoded using ECMA-335 compressed integer format:
    /// - 1 byte for lengths < 128
    /// - 2 bytes for lengths < 16,384  
    /// - 4 bytes for larger lengths
    ///
    /// # Arguments
    ///
    /// * `blob` - The blob data to write
    /// * `write_pos` - Mutable reference to the current write position, updated after writing
    pub(super) fn write_single_blob(&mut self, blob: &[u8], write_pos: &mut usize) -> Result<()> {
        // Write compressed length using
        *write_pos = self
            .base
            .output
            .write_compressed_uint_at(*write_pos as u64, blob.len() as u32)?
            as usize;

        // Write blob data
        self.base.output.write_and_advance(write_pos, blob)?;

        Ok(())
    }

    /// Retrieves all original blobs from the assembly's blob heap.
    ///
    /// Returns a vector containing all blob data from the original heap,
    /// preserving the order but not the indices. Used for heap rebuilding
    /// operations that need to process original content.
    ///
    /// # Returns
    ///
    /// A `Result<Vec<Vec<u8>>>` containing all original blob data, or an empty
    /// vector if no blob heap exists in the original assembly.
    pub(super) fn get_original_blobs(&self) -> Result<Vec<Vec<u8>>> {
        let mut blobs = Vec::new();
        if let Some(blob_heap) = self.base.assembly.view().blobs() {
            for (_, blob) in blob_heap.iter() {
                blobs.push(blob.to_vec());
            }
        }
        Ok(blobs)
    }

    /// Calculates the total size of a blob entry including its length prefix.
    ///
    /// Determines the compressed length prefix size and adds it to the blob data size.
    /// This matches the ECMA-335 compressed integer encoding used in blob heaps.
    ///
    /// # Arguments
    ///
    /// * `blob` - The blob data to calculate the entry size for
    ///
    /// # Returns
    ///
    /// The total size in bytes (prefix + data) that this blob entry will occupy
    pub(super) fn calculate_blob_entry_size(&self, blob: &[u8]) -> u32 {
        let length = blob.len();
        let prefix_size = if length < 128 {
            1
        } else if length < 16384 {
            2
        } else {
            4
        };
        prefix_size + length as u32
    }
}
