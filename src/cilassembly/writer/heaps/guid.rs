//! GUID heap builder for the simplified assembly writer.
//!
//! This module implements GUID heap reconstruction using the exact same
//! algorithms as the existing pipeline to ensure 100% compatibility.

use std::collections::HashMap;

use crate::{
    cilassembly::{
        writer::{heaps::HeapBuilder, layout::calculate_guid_heap_size},
        CilAssembly,
    },
    Error, Result,
};

/// Builder for #GUID metadata heap reconstruction.
///
/// The GUID heap contains 16-byte GUID values stored sequentially without separators.
/// Unlike other heaps, the GUID heap has no null entry at index 0 - all valid indices
/// point directly to 16-byte GUID values.
///
/// # ECMA-335 Compliance
///
/// - GUIDs are stored as 16-byte values in little-endian format
/// - No null termination or separation between entries
/// - Index 0 is not reserved (unlike string heaps)
/// - Heap is padded to 4-byte alignment
///
/// # Index Management
///
/// GUID indices are **logical indices** (GUID number) not byte offsets:
/// - Index 0 = first GUID at byte 0
/// - Index 1 = second GUID at byte 16  
/// - Index N = GUID at byte (N * 16)
///
/// # Examples
///
/// ```rust,ignore
/// let mut builder = GuidHeapBuilder::new(&assembly);
/// let heap_data = builder.build()?;
/// let mappings = builder.get_index_mappings();
/// ```
pub struct GuidHeapBuilder<'a> {
    /// Reference to the assembly being processed
    assembly: &'a CilAssembly,
    /// Mapping from original GUID indices to final indices after reconstruction
    index_mappings: HashMap<u32, u32>,
}

impl<'a> GuidHeapBuilder<'a> {
    /// Creates a new GUID heap builder for the specified assembly.
    ///
    /// The builder starts with empty index mappings that will be populated
    /// during the build process to track how GUID indices change.
    ///
    /// # Arguments
    ///
    /// * `assembly` - Assembly containing GUID heap changes to process
    ///
    /// # Returns
    ///
    /// Returns a new `GuidHeapBuilder` ready for heap reconstruction.
    pub fn new(assembly: &'a CilAssembly) -> Self {
        Self {
            assembly,
            index_mappings: HashMap::new(),
        }
    }
}

impl HeapBuilder for GuidHeapBuilder<'_> {
    fn build(&mut self) -> Result<Vec<u8>> {
        let guid_changes = &self.assembly.changes().guid_heap_changes;
        let mut final_heap = Vec::new();
        let mut final_index_position = 0u32; // GUID heap starts at 0 (no null entry)

        // Handle heap replacement scenario
        if let Some(replacement_heap) = guid_changes.replacement_heap() {
            final_heap.clone_from(replacement_heap);

            // Create basic index mapping for the replacement heap
            let mut current_position = 0u32;
            let final_heap_len = u32::try_from(final_heap.len())
                .map_err(|_| malformed_error!("GUID heap size exceeds u32 range"))?;
            while current_position < final_heap_len {
                self.index_mappings
                    .insert(current_position, current_position);
                current_position += 16; // Each GUID is 16 bytes
            }

            // Handle appended items
            for original_guid in &guid_changes.appended_items {
                let original_heap_index = {
                    let mut calculated_index = guid_changes.next_index;
                    for item in guid_changes.appended_items.iter().rev() {
                        calculated_index -= 16; // Each GUID is 16 bytes
                        if std::ptr::eq(item, original_guid) {
                            break;
                        }
                    }
                    calculated_index
                };

                if !guid_changes.is_removed(original_heap_index) {
                    let final_guid = guid_changes
                        .get_modification(original_heap_index)
                        .copied()
                        .unwrap_or(*original_guid);

                    self.index_mappings
                        .insert(original_heap_index, final_index_position);
                    final_heap.extend_from_slice(&final_guid);
                    final_index_position += 16;
                }
            }

            return Ok(final_heap);
        }

        // Process original GUIDs if available
        if let Some(guid_heap) = self.assembly.view().guids() {
            for (original_index, original_guid) in guid_heap.iter() {
                let original_index =
                    u32::try_from(original_index).map_err(|_| Error::WriteLayoutFailed {
                        message: "GUID heap index exceeds u32 range".to_string(),
                    })?;

                if guid_changes.is_removed(original_index) {
                    // GUID is removed - no mapping entry
                    continue;
                }
                if let Some(modified_guid) = guid_changes.get_modification(original_index) {
                    // GUID is modified - add modified version
                    self.index_mappings
                        .insert(original_index, final_index_position);
                    final_heap.extend_from_slice(modified_guid);
                    final_index_position += 16;
                } else {
                    // GUID is unchanged - add original version
                    self.index_mappings
                        .insert(original_index, final_index_position);
                    final_heap.extend_from_slice(&original_guid.to_bytes());
                    final_index_position += 16;
                }
            }
        }

        // Handle appended GUIDs, applying any modifications or removals

        // First, calculate the logical index for each appended GUID
        // GUID heap uses 1-based logical indices, not byte offsets
        let original_heap_size = guid_changes.next_index
            - (u32::try_from(guid_changes.appended_items.len())
                .map_err(|_| malformed_error!("Appended GUIDs count exceeds u32 range"))?
                * 16);
        let existing_guid_count = original_heap_size / 16;

        for (appended_index, original_guid) in guid_changes.appended_items.iter().enumerate() {
            // Calculate the logical GUID index (1-based sequential)
            let logical_guid_index = existing_guid_count
                + u32::try_from(appended_index)
                    .map_err(|_| malformed_error!("Appended GUID index exceeds u32 range"))?
                + 1;

            if guid_changes.removed_indices.contains(&logical_guid_index) {
            } else if let Some(modified_guid) = guid_changes.modified_items.get(&logical_guid_index)
            {
                // Convert logical index to byte offset for index mapping
                let byte_offset = (logical_guid_index - 1) * 16;
                self.index_mappings
                    .insert(byte_offset, final_index_position);
                final_heap.extend_from_slice(modified_guid);
                final_index_position += 16;
            } else {
                // Convert logical index to byte offset for index mapping
                let byte_offset = (logical_guid_index - 1) * 16;
                self.index_mappings
                    .insert(byte_offset, final_index_position);
                final_heap.extend_from_slice(original_guid);
                final_index_position += 16;
            }
        }

        // GUIDs are naturally aligned to 4-byte boundary (16 bytes each)
        Ok(final_heap)
    }

    fn calculate_size(&self) -> Result<u64> {
        let guid_changes = &self.assembly.changes().guid_heap_changes;
        calculate_guid_heap_size(guid_changes, self.assembly)
    }

    fn get_index_mappings(&self) -> &HashMap<u32, u32> {
        &self.index_mappings
    }

    fn heap_name(&self) -> &'static str {
        "#GUID"
    }
}
