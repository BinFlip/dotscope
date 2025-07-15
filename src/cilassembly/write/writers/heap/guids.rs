//! GUID heap writing functionality.
//!
//! This module handles writing modifications to the #GUID heap, including simple additions
//! and complex operations involving modifications and removals that require heap rebuilding.

use crate::{cilassembly::write::planner::StreamModification, Result};

impl<'a> super::HeapWriter<'a> {
    /// Writes GUID heap modifications including additions, modifications, and removals.
    ///
    /// Handles all types of GUID heap changes:
    /// - Additions: Appends new GUIDs to the end of the heap
    /// - Modifications: Updates existing GUIDs in place (supported for fixed-size entries)
    /// - Removals: Marks GUIDs as removed (handled during parsing/indexing)
    ///
    /// Writes raw 16-byte GUID values without length prefixes. GUIDs are naturally
    /// aligned to 4-byte boundaries due to their 16-byte size.
    ///
    /// # Arguments
    ///
    /// * `stream_mod` - The [`crate::cilassembly::write::planner::StreamModification`] for the #GUID heap
    pub(super) fn write_guid_heap(&mut self, stream_mod: &StreamModification) -> Result<()> {
        let guid_changes = &self.base.assembly.changes().guid_heap_changes;

        if guid_changes.has_changes() {
            return self.write_guid_heap_with_changes(stream_mod);
        }

        let (stream_layout, write_start) = self.base.get_stream_write_position(stream_mod)?;
        let mut write_pos = write_start;

        let stream_end = stream_layout.file_region.end_offset() as usize;

        for guid in guid_changes.appended_items.iter() {
            // Ensure we won't exceed stream boundary
            if write_pos + 16 > stream_end {
                return Err(crate::Error::WriteLayoutFailed {
                    message: format!(
                        "GUID heap overflow: write would exceed allocated space by {} bytes",
                        (write_pos + 16) - stream_end
                    ),
                });
            }

            let guid_slice = self.base.output.get_mut_slice(write_pos, 16)?;
            guid_slice.copy_from_slice(guid);
            write_pos += 16;
        }

        Ok(())
    }

    /// Writes the GUID heap when modifications or removals are present.
    ///
    /// This method provides comprehensive GUID heap writing that:
    /// - Preserves valid GUID entries in sequential order (1-based indexing)
    /// - Applies in-place modifications for existing GUIDs
    /// - Handles GUID removals by skipping entries
    /// - Appends new GUIDs maintaining sequential indices
    /// - Clears any remaining allocated space to prevent garbage data
    ///
    /// # Strategy
    ///
    /// 1. **Process Original**: Include original GUIDs that aren't removed, applying modifications
    /// 2. **Add Appended**: Include appended GUIDs that aren't removed, applying modifications
    /// 3. **Sequential Write**: Write all final GUIDs continuously in 16-byte blocks
    /// 4. **Clear Remainder**: Zero-fill any remaining allocated space
    ///
    /// # GUID Index Semantics
    ///
    /// GUID heap uses 1-based sequential indexing (not byte offsets like other heaps):
    /// - Index 1 = first GUID, Index 2 = second GUID, etc.
    /// - Each GUID occupies exactly 16 bytes
    /// - No length prefixes or variable-size entries
    ///
    /// # Arguments
    ///
    /// * `stream_mod` - The [`crate::cilassembly::write::planner::StreamModification`] for the #GUID heap
    pub(super) fn write_guid_heap_with_changes(
        &mut self,
        stream_mod: &StreamModification,
    ) -> Result<()> {
        let (stream_layout, write_start) = self.base.get_stream_write_position(stream_mod)?;
        let mut write_pos = write_start;
        let allocated_total_bytes = stream_layout.file_region.size as usize;

        let guid_changes = &self.base.assembly.changes().guid_heap_changes;
        let stream_end = stream_layout.file_region.end_offset() as usize;

        if let Some(replacement_heap) = guid_changes.replacement_heap() {
            self.base
                .output
                .write_and_advance(&mut write_pos, replacement_heap)?;

            for appended_guid in guid_changes.appended_items.iter() {
                if write_pos + 16 > stream_end {
                    return Err(crate::Error::WriteLayoutFailed {
                        message: format!(
                            "GUID heap overflow: write would exceed allocated space by {} bytes",
                            (write_pos + 16) - stream_end
                        ),
                    });
                }

                let guid_slice = self.base.output.get_mut_slice(write_pos, 16)?;
                guid_slice.copy_from_slice(appended_guid);
                write_pos += 16;
            }

            return Ok(());
        }

        // Step 1: Start with original GUIDs that aren't removed
        let mut guids_to_write: Vec<[u8; 16]> = Vec::new();
        if let Some(guid_heap) = self.base.assembly.view().guids() {
            for (i, (_offset, guid)) in guid_heap.iter().enumerate() {
                let sequential_index = (i + 1) as u32; // GUID indices are 1-based sequential

                if !guid_changes.is_removed(sequential_index) {
                    // Apply modification if present, otherwise use original
                    let final_guid = guid_changes
                        .get_modification(sequential_index)
                        .copied()
                        .unwrap_or_else(|| guid.to_bytes());
                    guids_to_write.push(final_guid);
                }
            }
        }

        // Step 2: Add appended GUIDs that aren't removed
        let original_guid_count = if let Some(guid_heap) = self.base.assembly.view().guids() {
            guid_heap.iter().count() as u32
        } else {
            0
        };

        for (i, appended_guid) in guid_changes.appended_items.iter().enumerate() {
            let sequential_index = original_guid_count + (i + 1) as u32;

            if !guid_changes.is_removed(sequential_index) {
                // Apply modification if present, otherwise use original appended GUID
                let final_guid = guid_changes
                    .get_modification(sequential_index)
                    .copied()
                    .unwrap_or(*appended_guid);
                guids_to_write.push(final_guid);
            }
        }

        // Step 3: Write all final GUIDs continuously

        let start_write_pos = write_pos;
        for guid_to_write in guids_to_write {
            // Ensure we won't exceed stream boundary
            if write_pos + 16 > stream_end {
                return Err(crate::Error::WriteLayoutFailed {
                    message: format!("GUID heap overflow during writing: write would exceed allocated space by {} bytes", 
                        (write_pos + 16) - stream_end)
                });
            }

            let guid_slice = self.base.output.get_mut_slice(write_pos, 16)?;
            guid_slice.copy_from_slice(&guid_to_write);
            write_pos += 16;
        }

        let total_bytes_written = write_pos - start_write_pos;

        // Clear any remaining bytes to prevent garbage data from being interpreted as GUIDs
        // This is crucial when writing the heap because we might write fewer bytes than the allocated space
        if total_bytes_written < allocated_total_bytes {
            let remaining_bytes = allocated_total_bytes - total_bytes_written;
            let clear_slice = self.base.output.get_mut_slice(write_pos, remaining_bytes)?;
            clear_slice.fill(0);
        }

        Ok(())
    }

    /// Retrieves all original GUIDs from the assembly's GUID heap.
    ///
    /// Returns a vector containing all GUID data from the original heap,
    /// preserving the order but returning raw 16-byte arrays. Used for heap
    /// rebuilding operations that need to process original content.
    ///
    /// # Returns
    ///
    /// A `Result<Vec<[u8; 16]>>` containing all original GUID data as 16-byte arrays,
    /// or an empty vector if no GUID heap exists in the original assembly.
    pub(super) fn get_original_guids(&self) -> Result<Vec<[u8; 16]>> {
        let mut guids = Vec::new();
        if let Some(guid_heap) = self.base.assembly.view().guids() {
            for (_, guid) in guid_heap.iter() {
                guids.push(guid.to_bytes());
            }
        }
        Ok(guids)
    }
}
