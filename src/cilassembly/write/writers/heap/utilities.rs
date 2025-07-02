//! Utility functions for heap writing operations.
//!
//! This module contains shared utility functions used across different heap writing operations,
//! including padding utilities and data access functions that ensure proper ECMA-335 compliance.

use crate::{
    cilassembly::write::planner::{StreamFileLayout, StreamModification},
    Result,
};

impl<'a> super::HeapWriter<'a> {
    /// Finds the actual end of heap data, accounting for the true size of the heap content.
    ///
    /// This is necessary because the stream size in the metadata might include padding
    /// or might not reflect the actual data end position accurately.
    pub(super) fn find_actual_heap_data_end(
        &self,
        stream_layout: &StreamFileLayout,
        stream_mod: &StreamModification,
        stream_name: &str,
    ) -> Result<usize> {
        let stream_start = stream_layout.file_region.offset as usize;

        match stream_name {
            "#Strings" => {
                let mut actual_end = stream_start + 1; // Start after null byte

                if let Some(strings_heap) = self.base.assembly.view().strings() {
                    // Find the highest offset + string length to get actual end
                    for (offset, string) in strings_heap.iter() {
                        let string_end = stream_start + offset + string.to_string().len() + 1;
                        if string_end > actual_end {
                            actual_end = string_end;
                        }
                    }
                }

                Ok(actual_end)
            }
            "#Blob" => {
                let mut actual_end = stream_start + 1; // Start after null byte

                if let Some(blob_heap) = self.base.assembly.view().blobs() {
                    // For blob heap, we need to reconstruct the actual layout
                    for (_, blob) in blob_heap.iter() {
                        let length = blob.len();
                        let prefix_size = if length < 128 {
                            1
                        } else if length < 16384 {
                            2
                        } else {
                            4
                        };
                        actual_end += prefix_size + length;
                    }
                }

                Ok(actual_end)
            }
            "#GUID" => {
                let mut actual_end = stream_start;

                if let Some(guid_heap) = self.base.assembly.view().guids() {
                    actual_end += guid_heap.iter().count() * 16; // Each GUID is 16 bytes
                }

                Ok(actual_end)
            }
            "#US" => {
                let mut actual_end = stream_start + 1; // Start after null byte

                if let Some(us_heap) = self.base.assembly.view().userstrings() {
                    // For userstrings, use the raw data size as it preserves the actual layout
                    actual_end = stream_start + us_heap.raw_data().len();
                }

                Ok(actual_end)
            }
            _ => {
                // For unknown streams, use the original size
                Ok(stream_start + stream_mod.original_size as usize)
            }
        }
    }

    /// Adds safe heap padding to align to 4-byte boundary.
    ///
    /// Uses 0xFF bytes to prevent the padding from being interpreted as valid entries
    /// when the heap is parsed. This works for all heap types:
    /// - String heap: 0xFF bytes won't create empty string entries  
    /// - Blob heap: 0xFF bytes create invalid compressed length prefixes
    /// - UserString heap: 0xFF bytes create invalid compressed length prefixes
    /// - GUID heap: Padding handled at file layout level due to fixed 16-byte entries
    ///
    /// # Arguments
    /// * `write_pos` - Current position after writing heap data
    /// * `heap_start` - Starting position of the heap being written
    pub(super) fn add_heap_padding_to_4_bytes(
        &mut self,
        write_pos: usize,
        heap_start: usize,
    ) -> Result<()> {
        let bytes_written = write_pos - heap_start;
        let padding_needed = (4 - (bytes_written % 4)) % 4;

        if padding_needed > 0 {
            // Use 0xFF bytes which create invalid entries for all heap types
            let padding_slice = self.base.output.get_mut_slice(write_pos, padding_needed)?;
            padding_slice.fill(0xFF);
        }

        Ok(())
    }
}
