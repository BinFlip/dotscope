//! Heap writing functionality for the copy-first binary generation approach.
//!
//! This module provides comprehensive heap writing capabilities for .NET assembly binary generation,
//! implementing efficient appending of new entries to existing metadata heap streams (#Strings, #Blob, #GUID, #US)
//! without requiring complete heap reconstruction. It maintains ECMA-335 compliance while minimizing
//! the complexity of binary generation through targeted modifications.
//!
//! # Key Components
//!
//! - [`crate::cilassembly::write::writers::heap::HeapWriter`] - Stateful writer for all heap modifications
//! - [`crate::cilassembly::write::writers::heap::HeapWriter::write_all_heaps`] - Main entry point for heap writing
//! - [`crate::cilassembly::write::writers::heap::HeapWriter::write_string_heap_additions`] - String heap appending
//! - [`crate::cilassembly::write::writers::heap::HeapWriter::write_blob_heap_additions`] - Blob heap appending
//! - [`crate::cilassembly::write::writers::heap::HeapWriter::write_guid_heap_additions`] - GUID heap appending
//! - [`crate::cilassembly::write::writers::heap::HeapWriter::write_userstring_heap_additions`] - User string heap appending
//!
//! # Architecture
//!
//! The heap writing system implements a copy-first strategy with targeted additions:
//!
//! ## Copy-First Approach
//! Instead of rebuilding entire heaps, this module:
//! - Preserves original heap content and structure
//! - Appends new entries only where modifications exist
//! - Maintains proper ECMA-335 alignment and encoding
//! - Minimizes binary generation complexity
//!
//! ## Heap-Specific Writing
//! Each heap type has specialized writing logic:
//! - **String Heap (#Strings)**: Null-terminated UTF-8 strings with 4-byte alignment
//! - **Blob Heap (#Blob)**: Length-prefixed binary data with compressed length encoding
//! - **GUID Heap (#GUID)**: Raw 16-byte GUID values with natural alignment
//! - **User String Heap (#US)**: UTF-16 strings with length prefix and terminator byte
//!
//! ## State Management
//! The [`crate::cilassembly::write::writers::heap::HeapWriter`] encapsulates:
//! - Assembly modification context and change tracking
//! - Output buffer management with bounds checking
//! - Layout plan integration for offset calculations
//! - Stream positioning and alignment requirements
//!
//! # Usage Examples
//!
//! ```rust,ignore
//! use crate::cilassembly::write::writers::heap::HeapWriter;
//! use crate::cilassembly::write::output::Output;
//! use crate::cilassembly::write::planner::LayoutPlan;
//! use crate::cilassembly::CilAssembly;
//!
//! # let assembly = CilAssembly::empty(); // placeholder
//! # let layout_plan = LayoutPlan { // placeholder
//! #     total_size: 1000,
//! #     original_size: 800,
//! #     file_layout: crate::cilassembly::write::planner::FileLayout {
//! #         dos_header: crate::cilassembly::write::planner::FileRegion { offset: 0, size: 64 },
//! #         pe_headers: crate::cilassembly::write::planner::FileRegion { offset: 64, size: 100 },
//! #         section_table: crate::cilassembly::write::planner::FileRegion { offset: 164, size: 80 },
//! #         sections: vec![]
//! #     },
//! #     pe_updates: crate::cilassembly::write::planner::PeUpdates {
//! #         section_table_needs_update: false,
//! #         checksum_needs_update: false,
//! #         section_updates: vec![]
//! #     },
//! #     metadata_modifications: crate::cilassembly::write::planner::metadata::MetadataModifications {
//! #         stream_modifications: vec![]
//! #     },
//! #     heap_expansions: crate::cilassembly::write::planner::calc::HeapExpansions {
//! #         string_heap_addition: 0,
//! #         blob_heap_addition: 0,
//! #         guid_heap_addition: 0,
//! #         userstring_heap_addition: 0
//! #     },
//! #     table_modifications: vec![]
//! # };
//! # let mut output = Output::new(1000)?;
//!
//! // Create heap writer with necessary context
//! let mut heap_writer = HeapWriter::new(&assembly, &mut output, &layout_plan);
//!
//! // Write all heap modifications
//! heap_writer.write_all_heaps()?;
//!
//! println!("Heap modifications written successfully");
//! # Ok::<(), crate::Error>(())
//! ```
//!
//! # Thread Safety
//!
//! The [`crate::cilassembly::write::writers::heap::HeapWriter`] is designed for single-threaded use during binary
//! generation. It maintains mutable state for output buffer management and is not thread-safe.
//! Each heap writing operation should be completed atomically within a single thread.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::cilassembly::write::planner`] - Layout planning and offset calculations
//! - [`crate::cilassembly::write::output`] - Binary output buffer management
//! - [`crate::cilassembly::changes`] - Source of heap modification data
//! - [`crate::cilassembly::write::utils`] - Shared utility functions for layout searches

use crate::{
    cilassembly::{
        write::{
            output::Output,
            planner::{LayoutPlan, StreamFileLayout, StreamModification},
        },
        CilAssembly,
    },
    file::io::write_compressed_uint,
    Result,
};

/// A stateful writer for metadata heap modifications that encapsulates all necessary context.
///
/// [`crate::cilassembly::write::writers::heap::HeapWriter`] provides a clean API for writing heap modifications by maintaining
/// references to the assembly, output buffer, and layout plan. This eliminates the need
/// to pass these parameters around and provides a more object-oriented interface for
/// heap serialization operations.
///
/// # Design Benefits
///
/// - **Encapsulation**: All writing context is stored in one place
/// - **Clean API**: Methods don't require numerous parameters
/// - **Maintainability**: Easier to extend and modify functionality
/// - **Performance**: Avoids repeated parameter passing
/// - **Safety**: Centralized bounds checking and validation
///
/// # Usage
/// Created via [`crate::cilassembly::write::writers::heap::HeapWriter::new`] and used throughout
/// the heap writing process to append new entries to existing metadata heaps.
pub struct HeapWriter<'a> {
    /// Reference to the [`crate::cilassembly::CilAssembly`] containing heap changes
    assembly: &'a CilAssembly,
    /// Mutable reference to the [`crate::cilassembly::write::output::Output`] buffer for writing
    output: &'a mut Output,
    /// Reference to the [`crate::cilassembly::write::planner::LayoutPlan`] for offset calculations
    layout_plan: &'a LayoutPlan,
}

impl<'a> HeapWriter<'a> {
    /// Creates a new [`crate::cilassembly::write::writers::heap::HeapWriter`] with the necessary context.
    ///
    /// # Arguments
    ///
    /// * `assembly` - The [`crate::cilassembly::CilAssembly`] containing heap modifications
    /// * `output` - Mutable reference to the [`crate::cilassembly::write::output::Output`] buffer
    /// * `layout_plan` - Reference to the [`crate::cilassembly::write::planner::LayoutPlan`] for offset calculations
    pub fn new(
        assembly: &'a CilAssembly,
        output: &'a mut Output,
        layout_plan: &'a LayoutPlan,
    ) -> Self {
        Self {
            assembly,
            output,
            layout_plan,
        }
    }

    /// Common helper that finds stream layout and calculates write positions.
    ///
    /// Returns ([`crate::cilassembly::write::planner::StreamFileLayout`], write_start_position).
    ///
    /// # Arguments
    /// * `stream_mod` - The [`crate::cilassembly::write::planner::metadata::StreamModification`] to prepare for writing
    fn prepare_heap_write(
        &self,
        stream_mod: &StreamModification,
    ) -> Result<(&StreamFileLayout, usize)> {
        let metadata_section =
            crate::cilassembly::write::utils::find_metadata_section(&self.layout_plan.file_layout)?;
        let stream_layout = crate::cilassembly::write::utils::find_stream_layout(
            metadata_section,
            &stream_mod.name,
        )?;

        let write_start = if self.is_heap_rebuilding(&stream_mod.name) {
            stream_layout.file_region.offset as usize
        } else {
            self.find_actual_heap_data_end(stream_layout, stream_mod, &stream_mod.name)?
        };

        Ok((stream_layout, write_start))
    }

    /// Determines if a heap is being rebuilt (has any changes) or just appended to.
    fn is_heap_rebuilding(&self, stream_name: &str) -> bool {
        let changes = self.assembly.changes();
        match stream_name {
            "#Strings" => {
                changes.string_heap_changes.has_modifications()
                    || changes.string_heap_changes.has_removals()
            }
            "#Blob" => changes.blob_heap_changes.has_changes(),
            "#GUID" => {
                changes.guid_heap_changes.has_modifications()
                    || changes.guid_heap_changes.has_removals()
            }
            "#US" => {
                changes.userstring_heap_changes.has_modifications()
                    || changes.userstring_heap_changes.has_removals()
            }
            _ => false,
        }
    }

    /// Writes heap modifications based on the copy-first approach.
    ///
    /// Handles additions, modifications, and removals of heap entries. This method
    /// iterates through all [`crate::cilassembly::write::planner::metadata::StreamModification`] entries and
    /// writes the appropriate heap changes based on stream type.
    ///
    /// For modifications and removals, the original heap content is updated in place
    /// where possible, while additions are appended to the end.
    ///
    /// # Errors
    /// Returns [`crate::Error`] if any heap writing operation fails due to invalid data
    /// or insufficient output buffer space.
    pub fn write_all_heaps(&mut self) -> Result<()> {
        // Process each modified stream and append new data
        for stream_mod in self
            .layout_plan
            .metadata_modifications
            .stream_modifications
            .iter()
        {
            match stream_mod.name.as_str() {
                "#Strings" => {
                    self.write_string_heap_additions(stream_mod)?;
                }
                "#Blob" => {
                    self.write_blob_heap_additions(stream_mod)?;
                }
                "#GUID" => {
                    self.write_guid_heap_additions(stream_mod)?;
                }
                "#US" => {
                    self.write_userstring_heap_additions(stream_mod)?;
                }
                _ => {
                    // Skip unknown streams
                }
            }
        }

        Ok(())
    }

    /// Writes string heap modifications including additions, modifications, and removals.
    ///
    /// Handles all types of string heap changes:
    /// - Additions: Appends new strings to the end of the heap
    /// - Modifications: Updates existing strings in place (if possible)
    /// - Removals: Marks strings as removed (handled during parsing/indexing)
    ///
    /// Writes null-terminated UTF-8 strings with proper 4-byte alignment as required
    /// by ECMA-335 II.24.2.2. Each string is followed by a null terminator byte.
    ///
    /// # Arguments
    /// * `stream_mod` - The [`crate::cilassembly::write::planner::metadata::StreamModification`] for the #Strings heap
    fn write_string_heap_additions(&mut self, stream_mod: &StreamModification) -> Result<()> {
        let string_changes = &self.assembly.changes().string_heap_changes;

        if string_changes.has_modifications() || string_changes.has_removals() {
            return self.rebuild_string_heap(stream_mod);
        }

        let (_stream_layout, write_start) = self.prepare_heap_write(stream_mod)?;
        let mut write_pos = write_start;

        // Write each new string to the heap
        for string in &self.assembly.changes().string_heap_changes.appended_items {
            // Strings in the heap are null-terminated UTF-8
            let string_bytes = string.as_bytes();

            // Write the string bytes
            let output_slice = self.output.get_mut_slice(write_pos, string_bytes.len())?;
            output_slice.copy_from_slice(string_bytes);
            write_pos += string_bytes.len();

            // Write null terminator
            let null_slice = self.output.get_mut_slice(write_pos, 1)?;
            null_slice[0] = 0;
            write_pos += 1;
        }

        // Note: Padding is handled at the file layout level, not individual heap level
        Ok(())
    }

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
    /// * `stream_mod` - The [`crate::cilassembly::write::planner::metadata::StreamModification`] for the #Blob heap
    fn write_blob_heap_additions(&mut self, stream_mod: &StreamModification) -> Result<()> {
        let blob_changes = &self.assembly.changes().blob_heap_changes;

        // Always rebuild blob heap to preserve byte offsets (similar to userstring fix)
        // The append-only approach corrupts original blob offsets during sequential copying
        if blob_changes.has_changes() {
            return self.rebuild_blob_heap(stream_mod);
        }

        let (_stream_layout, write_start) = self.prepare_heap_write(stream_mod)?;
        let mut write_pos = write_start;

        // Copy original blob heap data first to preserve existing blobs
        if let Some(blob_heap) = self.assembly.view().blobs() {
            // Start with null byte
            let null_slice = self.output.get_mut_slice(write_pos, 1)?;
            null_slice[0] = 0;
            write_pos += 1;

            // Copy all original blobs sequentially
            for (_, blob) in blob_heap.iter() {
                let length = blob.len();

                // Write length prefix
                let mut length_buffer = Vec::new();
                write_compressed_uint(length as u32, &mut length_buffer);
                let length_slice = self.output.get_mut_slice(write_pos, length_buffer.len())?;
                length_slice.copy_from_slice(&length_buffer);
                write_pos += length_buffer.len();

                // Write blob data
                let blob_slice = self.output.get_mut_slice(write_pos, blob.len())?;
                blob_slice.copy_from_slice(blob);
                write_pos += blob.len();
            }
        } else {
            // No original heap, start with null byte
            let null_slice = self.output.get_mut_slice(write_pos, 1)?;
            null_slice[0] = 0;
            write_pos += 1;
        }

        // Append new blobs, applying modifications if present

        // Calculate correct API indices for appended blobs (replicating add_blob logic)
        let start_index = if let Some(_blob_heap) = self.assembly.view().blobs() {
            // Use the actual heap size (same as HeapChanges::new)
            let heap_stream = self
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

            // Write length prefix using standard ECMA-335 compressed integer format
            let mut length_buffer = Vec::new();
            write_compressed_uint(length as u32, &mut length_buffer);

            let length_slice = self.output.get_mut_slice(write_pos, length_buffer.len())?;
            length_slice.copy_from_slice(&length_buffer);
            write_pos += length_buffer.len();

            let blob_slice = self.output.get_mut_slice(write_pos, final_blob.len())?;
            blob_slice.copy_from_slice(&final_blob);
            write_pos += final_blob.len();

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
        self.add_safe_blob_padding(write_pos, write_start)?;

        Ok(())
    }

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
    /// * `stream_mod` - The [`crate::cilassembly::write::planner::metadata::StreamModification`] for the #GUID heap
    fn write_guid_heap_additions(&mut self, stream_mod: &StreamModification) -> Result<()> {
        let guid_changes = &self.assembly.changes().guid_heap_changes;

        if guid_changes.has_modifications() || guid_changes.has_removals() {
            return self.rebuild_guid_heap(stream_mod);
        }

        let (_, write_start) = self.prepare_heap_write(stream_mod)?;
        let mut write_pos = write_start;

        for guid in guid_changes.appended_items.iter() {
            let guid_slice = self.output.get_mut_slice(write_pos, 16)?;
            guid_slice.copy_from_slice(guid);
            write_pos += 16;
        }

        Ok(())
    }

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
    /// - Terminator byte (indicates presence of high characters)
    ///
    /// # Arguments
    /// * `stream_mod` - The [`crate::cilassembly::write::planner::metadata::StreamModification`] for the #US heap
    fn write_userstring_heap_additions(&mut self, stream_mod: &StreamModification) -> Result<()> {
        let userstring_changes = &self.assembly.changes().userstring_heap_changes;
        if userstring_changes.has_modifications() || userstring_changes.has_removals() {
            return self.rebuild_userstring_heap(stream_mod);
        }

        let (_stream_layout, write_start) = self.prepare_heap_write(stream_mod)?;
        let mut write_pos = write_start;

        for user_string in &self
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
            let mut length_buffer = Vec::new();
            let start_len = length_buffer.len();
            crate::file::io::write_compressed_uint(total_length as u32, &mut length_buffer);
            let bytes_written = length_buffer.len() - start_len;

            let length_slice = self.output.get_mut_slice(write_pos, bytes_written)?;
            length_slice.copy_from_slice(&length_buffer);
            write_pos += bytes_written;

            // Write the UTF-16 string data
            let string_slice = self.output.get_mut_slice(write_pos, utf16_bytes.len())?;
            string_slice.copy_from_slice(&utf16_bytes);
            write_pos += utf16_bytes.len();

            // Write the terminator byte (contains high-character flag)
            // According to .NET runtime: 0 = no chars >= 0x80, 1 = has chars >= 0x80
            let has_high_chars = user_string.chars().any(|c| c as u32 >= 0x80);
            let terminator_byte = if has_high_chars { 1 } else { 0 };

            let terminal_slice = self.output.get_mut_slice(write_pos, 1)?;
            terminal_slice[0] = terminator_byte;
            write_pos += 1;
        }

        // Note: Padding is handled at the file layout level, not individual heap level

        Ok(())
    }

    /// Writes userstring heap with modifications by copying original data and appending changes.
    fn write_userstring_heap_with_modifications(
        &mut self,
        stream_mod: &StreamModification,
    ) -> Result<()> {
        let (_stream_layout, write_start) = self.prepare_heap_write(stream_mod)?;
        let mut write_pos = write_start;

        let userstring_changes = &self.assembly.changes().userstring_heap_changes;

        // Get the original userstring heap data and copy it exactly
        if let Some(us_heap) = self.assembly.view().userstrings() {
            let original_data = us_heap.raw_data();
            let original_slice = self.output.get_mut_slice(write_pos, original_data.len())?;
            original_slice.copy_from_slice(original_data);
            write_pos += original_data.len();
        } else {
            // If no original heap, start with null byte
            let null_slice = self.output.get_mut_slice(write_pos, 1)?;
            null_slice[0] = 0;
            write_pos += 1;
        }

        // Append all modified userstrings as new entries
        for modified_string in userstring_changes.modified_items.values() {
            self.write_single_userstring(modified_string, &mut write_pos)?;
        }

        // Append all new userstrings
        for appended_string in &userstring_changes.appended_items {
            self.write_single_userstring(appended_string, &mut write_pos)?;
        }

        self.add_userstring_padding_to_4_bytes(write_pos, write_start)?;
        Ok(())
    }

    /// Adds padding bytes to align the heap to a 4-byte boundary.
    ///
    /// Ensures ECMA-335 II.24.2.2 compliance by padding heaps to 4-byte alignment.
    /// Calculates the padding needed and fills with zero bytes.
    ///
    /// # Arguments
    /// * `current_pos` - Current write position in the output buffer
    /// * `start_pos` - Starting position of the heap data
    fn add_padding_to_4_bytes(&mut self, current_pos: usize, start_pos: usize) -> Result<()> {
        let heap_size = current_pos - start_pos;
        let remainder = heap_size % 4;

        if remainder != 0 {
            let padding_needed = 4 - remainder;
            let padding_slice = self.output.get_mut_slice(current_pos, padding_needed)?;
            for byte in padding_slice.iter_mut() {
                *byte = 0;
            }
        }

        Ok(())
    }

    fn add_string_padding_to_4_bytes(
        &mut self,
        current_pos: usize,
        start_pos: usize,
    ) -> Result<()> {
        let heap_size = current_pos - start_pos;
        let remainder = heap_size % 4;

        if remainder != 0 {
            let padding_needed = 4 - remainder;
            let padding_slice = self.output.get_mut_slice(current_pos, padding_needed)?;
            // Use 0xFF bytes for string heap padding to avoid creating empty string entries
            for byte in padding_slice.iter_mut() {
                *byte = 0xFF;
            }
        }

        Ok(())
    }

    fn add_userstring_padding_to_4_bytes(
        &mut self,
        current_pos: usize,
        start_pos: usize,
    ) -> Result<()> {
        let heap_size = current_pos - start_pos;
        let remainder = heap_size % 4;

        if remainder != 0 {
            let padding_needed = 4 - remainder;
            let padding_slice = self.output.get_mut_slice(current_pos, padding_needed)?;
            // Use 0x7F bytes for userstring heap padding
            // 0x7F = 01111111 binary, interpreted as single-byte compressed integer with value 127
            // Since there won't be 127 bytes of valid data following, parsing will fail gracefully
            for byte in padding_slice.iter_mut() {
                *byte = 0x7F;
            }
        }

        Ok(())
    }

    fn add_safe_blob_padding(&mut self, current_pos: usize, start_pos: usize) -> Result<()> {
        let heap_size = current_pos - start_pos;
        let remainder = heap_size % 4;

        if remainder != 0 {
            let padding_needed = 4 - remainder;
            let padding_slice = self.output.get_mut_slice(current_pos, padding_needed)?;

            // Use a pattern that won't create phantom blob entries:
            // Write bytes that form an invalid compressed integer sequence
            // that would require reading beyond the heap boundary
            match padding_needed {
                1 => {
                    // 0xFF indicates a 4-byte compressed integer follows, but we only have 1 byte
                    // This makes the entry unparseable without creating multiple blob entries
                    padding_slice[0] = 0xFF;
                }
                2 => {
                    // Start a 4-byte compressed integer but don't complete it
                    padding_slice[0] = 0xFF;
                    padding_slice[1] = 0xFF;
                }
                3 => {
                    // Start a 4-byte compressed integer but don't complete it
                    padding_slice[0] = 0xFF;
                    padding_slice[1] = 0xFF;
                    padding_slice[2] = 0xFF;
                }
                _ => unreachable!("Padding should be 1-3 bytes for 4-byte alignment"),
            }
        }

        Ok(())
    }

    /// Finds the actual end of heap data by scanning through the original heap
    /// to skip heap-level alignment padding that may exist at the end.
    ///
    /// This handles all heap types (#Strings, #Blob, #GUID, #US) generically by
    /// analyzing the underlying heap structure to determine where actual data ends.
    ///
    /// # Arguments
    /// * `stream_layout` - The [`crate::cilassembly::write::planner::StreamFileLayout`] for the heap
    /// * `stream_mod` - The [`crate::cilassembly::write::planner::metadata::StreamModification`] being processed
    /// * `heap_name` - The name of the heap being analyzed (e.g., "#US", "#Strings")
    fn find_actual_heap_data_end(
        &self,
        stream_layout: &StreamFileLayout,
        stream_mod: &StreamModification,
        heap_name: &str,
    ) -> Result<usize> {
        let view = self.assembly.view();

        match heap_name {
            "#US" => {
                let userstrings =
                    view.userstrings()
                        .ok_or_else(|| crate::Error::WriteLayoutFailed {
                            message: "No userstring heap found in original assembly".to_string(),
                        })?;

                // Find the last valid userstring entry by iterating through all entries
                let mut last_entry_end = 1; // Start after the initial null byte at position 0

                for (offset, _) in userstrings.iter() {
                    // Get the entry at this offset to determine its end position
                    if let Ok(entry_str) = userstrings.get(offset) {
                        // Calculate the size of this entry
                        // Format: [compressed_length][utf16_data][terminator_byte]
                        let utf16_bytes = entry_str.len() * 2; // 2 bytes per UTF-16 char
                        let total_length = utf16_bytes + 1; // UTF-16 data + terminator byte

                        // Determine compressed length size (1, 2, or 4 bytes)
                        let length_prefix_size = if total_length < 128 {
                            1
                        } else if total_length < 16384 {
                            2
                        } else {
                            4
                        };

                        let entry_end = offset + length_prefix_size + total_length;
                        last_entry_end = last_entry_end.max(entry_end);
                    }
                }

                // Convert to absolute file offset
                let base_offset = stream_layout.file_region.offset as usize;
                Ok(base_offset + last_entry_end)
            }
            "#Strings" | "#Blob" | "#GUID" => {
                // For strings, blobs, and GUIDs, we use the original size for simplicity.
                // While these heaps have iterators available (strings.iter(), blobs.iter(), guids.iter()),
                // scanning to find the actual data end is less critical than for userstrings since
                // alignment padding is less common in these heaps.
                let write_start =
                    (stream_layout.file_region.offset + stream_mod.original_size) as usize;
                Ok(write_start)
            }
            _ => Err(crate::Error::WriteLayoutFailed {
                message: format!("Unknown heap type: {heap_name}"),
            }),
        }
    }

    /// Rebuilds the entire string heap when modifications or removals are present.
    fn rebuild_string_heap(&mut self, stream_mod: &StreamModification) -> Result<()> {
        let (_stream_layout, write_start) = self.prepare_heap_write(stream_mod)?;
        let mut write_pos = write_start;

        let string_changes = &self.assembly.changes().string_heap_changes;

        // Step 1: Reconstruct the original heap to preserve all original offsets
        let mut original_heap_end = 1; // Start with 1 to ensure null byte at position 0
        if let Some(strings_heap) = self.assembly.view().strings() {
            // First pass: find the size of the original heap by finding the highest offset + string size
            for (offset, string) in strings_heap.iter() {
                let string_end = offset + string.to_string().len() + 1; // +1 for null terminator
                if string_end > original_heap_end {
                    original_heap_end = string_end;
                }
            }

            // Initialize the heap area with zeros
            let heap_slice = self.output.get_mut_slice(write_pos, original_heap_end)?;
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
                            .output
                            .get_mut_slice(write_start + offset, original_size)?;
                        for byte in zero_slice.iter_mut() {
                            *byte = 0;
                        }

                        // Append at end
                        let mod_bytes = modified_string.as_bytes();
                        let append_slice = self.output.get_mut_slice(write_pos, new_size)?;
                        append_slice[..mod_bytes.len()].copy_from_slice(mod_bytes);
                        append_slice[mod_bytes.len()] = 0; // null terminator
                        write_pos += new_size;
                    }
                }
            }
        } else {
            // No original heap - just write the mandatory null byte
            let null_slice = self.output.get_mut_slice(write_pos, 1)?;
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

                let append_slice = self.output.get_mut_slice(write_pos, string_size)?;
                append_slice[..string_bytes.len()].copy_from_slice(string_bytes);
                append_slice[string_bytes.len()] = 0; // null terminator
                write_pos += string_size;
            }
        }

        // Add special padding to align to 4-byte boundary (ECMA-335 II.24.2.2)
        // Use 0xFF bytes instead of 0x00 to avoid creating empty string entries
        self.add_string_padding_to_4_bytes(write_pos, write_start)?;
        Ok(())
    }

    /// Rebuilds the entire blob heap when modifications or removals are present.
    fn rebuild_blob_heap(&mut self, stream_mod: &StreamModification) -> Result<()> {
        let (_stream_layout, write_start) = self.prepare_heap_write(stream_mod)?;
        let mut write_pos = write_start;

        let blob_changes = &self.assembly.changes().blob_heap_changes;

        // Step 1: Rebuild blob heap entry by entry, applying modifications
        let mut rebuilt_original_count = 0;
        if let Some(blob_heap) = self.assembly.view().blobs() {
            // Start with null byte
            let null_slice = self.output.get_mut_slice(write_pos, 1)?;
            null_slice[0] = 0;
            write_pos += 1;

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
            let null_slice = self.output.get_mut_slice(write_pos, 1)?;
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

            self.write_single_blob(&blob_data, &mut write_pos)?;
            appended_count += 1;
        }

        let _total_blobs_count = rebuilt_original_count + appended_count;

        // Add padding to align to 4-byte boundary (ECMA-335 II.24.2.2)
        // Use a pattern that won't create valid blob entries
        self.add_safe_blob_padding(write_pos, write_start)?;
        Ok(())
    }

    /// Rebuilds the entire user string heap when modifications or removals are present.
    fn rebuild_userstring_heap(&mut self, stream_mod: &StreamModification) -> Result<()> {
        let (_stream_layout, write_start) = self.prepare_heap_write(stream_mod)?;
        let mut write_pos = write_start;

        let userstring_changes = &self.assembly.changes().userstring_heap_changes;

        // Check if we have modifications to the ORIGINAL userstring heap (not appended ones)
        let original_data_len = if let Some(us_heap) = self.assembly.view().userstrings() {
            us_heap.raw_data().len() as u32
        } else {
            0
        };

        let has_original_modifications = userstring_changes
            .modified_items_iter()
            .any(|(index, _)| *index < original_data_len)
            || userstring_changes
                .removed_indices_iter()
                .any(|index| *index < original_data_len);

        // Also check if any appended userstrings have been modified - this requires rebuild
        // to maintain API index contract and ensure indices remain valid
        let has_appended_modifications = userstring_changes
            .modified_items_iter()
            .any(|(index, _)| *index >= original_data_len);

        let needs_rebuild = has_original_modifications || has_appended_modifications;

        if let Some(us_heap) = self.assembly.view().userstrings() {
            if needs_rebuild {
                // We have modifications, need to rebuild the entire heap
                self.rebuild_complete_userstring_heap(&mut write_pos, us_heap, userstring_changes)?;
            } else {
                // No modifications to original heap, copy it exactly to preserve byte structure
                let original_data = us_heap.raw_data();
                let output_slice = self.output.get_mut_slice(write_pos, original_data.len())?;
                output_slice.copy_from_slice(original_data);
                write_pos += original_data.len();
            }
        } else {
            // No original heap, start with null byte
            let null_slice = self.output.get_mut_slice(write_pos, 1)?;
            null_slice[0] = 0;
            write_pos += 1;
        }

        // Only append new userstrings if we didn't do a full rebuild
        if !needs_rebuild {
            // Debug info for userstring heap

            // Append new userstrings (simple append-only case)
            for (heap_index, appended_userstring) in
                userstring_changes.userstring_items_with_indices()
            {
                if userstring_changes.is_removed(heap_index) {
                    continue;
                }

                // Apply modification if present, otherwise use original appended string
                let final_userstring = userstring_changes
                    .get_modification(heap_index)
                    .cloned()
                    .unwrap_or_else(|| appended_userstring.clone());

                self.write_single_userstring(&final_userstring, &mut write_pos)?;
            }
        }

        self.add_userstring_padding_to_4_bytes(write_pos, write_start)?;

        Ok(())
    }

    /// Rebuilds the entire GUID heap when modifications or removals are present.
    fn rebuild_guid_heap(&mut self, stream_mod: &StreamModification) -> Result<()> {
        let (_stream_layout, write_start) = self.prepare_heap_write(stream_mod)?;
        let mut write_pos = write_start;

        let guid_changes = &self.assembly.changes().guid_heap_changes;

        // Step 1: Start with original GUIDs that aren't removed
        let mut guids_to_write: Vec<[u8; 16]> = Vec::new();
        if let Some(guid_heap) = self.assembly.view().guids() {
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
        let original_guid_count = if let Some(guid_heap) = self.assembly.view().guids() {
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
            let guid_slice = self.output.get_mut_slice(write_pos, 16)?;
            guid_slice.copy_from_slice(&guid_to_write);
            write_pos += 16;
        }

        let total_bytes_written = write_pos - start_write_pos;

        // Clear any remaining bytes to prevent garbage data from being interpreted as GUIDs
        // This is crucial when rebuilding the heap because we might write fewer bytes than the allocated space
        let expected_total_bytes = stream_mod.additional_data_size as usize;
        if total_bytes_written < expected_total_bytes {
            let remaining_bytes = expected_total_bytes - total_bytes_written;
            let clear_slice = self.output.get_mut_slice(write_pos, remaining_bytes)?;
            clear_slice.fill(0);
        }

        Ok(())
    }

    /// Rebuilds the complete userstring heap (original + appended) maintaining API index contract.
    /// This is needed when appended userstrings are modified, as size changes would break the indices.
    fn rebuild_complete_userstring_heap(
        &mut self,
        write_pos: &mut usize,
        original_heap: &crate::metadata::streams::UserStrings,
        userstring_changes: &crate::cilassembly::changes::HeapChanges<String>,
    ) -> Result<()> {
        // Start with null byte
        let heap_start = *write_pos;
        let null_slice = self.output.get_mut_slice(*write_pos, 1)?;
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

    /// Helper method to write a single blob with proper encoding.
    fn write_single_blob(&mut self, blob: &[u8], write_pos: &mut usize) -> Result<()> {
        let length = blob.len();

        // Write compressed length using standard ECMA-335 format
        let mut length_buffer = Vec::new();
        write_compressed_uint(length as u32, &mut length_buffer);

        let length_slice = self.output.get_mut_slice(*write_pos, length_buffer.len())?;
        length_slice.copy_from_slice(&length_buffer);
        *write_pos += length_buffer.len();

        // Write blob data
        let blob_slice = self.output.get_mut_slice(*write_pos, blob.len())?;
        blob_slice.copy_from_slice(blob);
        *write_pos += blob.len();

        Ok(())
    }

    /// Helper method to write a single user string with proper encoding.
    fn write_single_userstring(&mut self, user_string: &str, write_pos: &mut usize) -> Result<()> {
        let utf16_bytes: Vec<u8> = user_string
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();

        let utf16_data_length = utf16_bytes.len();
        let total_length = utf16_data_length + 1; // UTF-16 data + terminator byte

        // Write compressed integer length prefix
        let mut length_buffer = Vec::new();
        let start_len = length_buffer.len();
        write_compressed_uint(total_length as u32, &mut length_buffer);
        let bytes_written = length_buffer.len() - start_len;

        let length_slice = self.output.get_mut_slice(*write_pos, bytes_written)?;
        length_slice.copy_from_slice(&length_buffer);
        *write_pos += bytes_written;

        // Write the UTF-16 string data
        let string_slice = self.output.get_mut_slice(*write_pos, utf16_bytes.len())?;
        string_slice.copy_from_slice(&utf16_bytes);
        *write_pos += utf16_bytes.len();

        // Write the terminator byte
        let terminator_slice = self.output.get_mut_slice(*write_pos, 1)?;
        let has_high_chars = user_string.chars().any(|c| c as u32 >= 0x80);
        terminator_slice[0] = if has_high_chars { 1 } else { 0 };
        *write_pos += 1;

        Ok(())
    }

    /// Helper method to write a single userstring at a specific position with proper UTF-16 encoding.
    fn write_single_userstring_at(&mut self, user_string: &str, target_pos: usize) -> Result<()> {
        let utf16_bytes: Vec<u8> = user_string
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();

        let utf16_data_length = utf16_bytes.len();
        let total_length = utf16_data_length + 1; // UTF-16 data + terminator byte

        let mut write_pos = target_pos;

        // Write compressed integer length prefix
        let mut length_buffer = Vec::new();
        let start_len = length_buffer.len();
        write_compressed_uint(total_length as u32, &mut length_buffer);
        let bytes_written = length_buffer.len() - start_len;

        let length_slice = self.output.get_mut_slice(write_pos, bytes_written)?;
        length_slice.copy_from_slice(&length_buffer);
        write_pos += bytes_written;

        // Write the UTF-16 string data
        let string_slice = self.output.get_mut_slice(write_pos, utf16_bytes.len())?;
        string_slice.copy_from_slice(&utf16_bytes);
        write_pos += utf16_bytes.len();

        // Write the terminator byte
        let terminator_slice = self.output.get_mut_slice(write_pos, 1)?;
        let has_high_chars = user_string.chars().any(|c| c as u32 >= 0x80);
        terminator_slice[0] = if has_high_chars { 1 } else { 0 };

        Ok(())
    }

    /// Helper methods to get original heap data from the assembly view
    fn get_original_strings(&self) -> Result<Vec<String>> {
        let mut strings = Vec::new();
        if let Some(strings_heap) = self.assembly.view().strings() {
            for (_, string) in strings_heap.iter() {
                strings.push(string.to_string());
            }
        }
        Ok(strings)
    }

    fn get_original_blobs(&self) -> Result<Vec<Vec<u8>>> {
        let mut blobs = Vec::new();
        if let Some(blob_heap) = self.assembly.view().blobs() {
            for (_, blob) in blob_heap.iter() {
                blobs.push(blob.to_vec());
            }
        }
        Ok(blobs)
    }

    fn get_original_userstrings(&self) -> Result<Vec<String>> {
        let mut userstrings = Vec::new();
        if let Some(us_heap) = self.assembly.view().userstrings() {
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

    fn get_original_userstrings_with_offsets(&self) -> Result<Vec<(u32, String)>> {
        let mut userstrings = Vec::new();
        if let Some(us_heap) = self.assembly.view().userstrings() {
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

    fn get_original_guids(&self) -> Result<Vec<[u8; 16]>> {
        let mut guids = Vec::new();
        if let Some(guid_heap) = self.assembly.view().guids() {
            for (_, guid) in guid_heap.iter() {
                guids.push(guid.to_bytes());
            }
        }
        Ok(guids)
    }

    fn calculate_blob_entry_size(&self, blob: &[u8]) -> u32 {
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

    fn calculate_userstring_entry_size(&self, userstring: &str) -> u32 {
        let utf16_bytes: Vec<u8> = userstring
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        let utf16_data_length = utf16_bytes.len();
        let total_length = utf16_data_length + 1;

        let prefix_size = if total_length < 128 {
            1
        } else if total_length < 16384 {
            2
        } else {
            4
        };
        prefix_size + total_length as u32
    }
}

#[cfg(test)]
mod tests {
    use crate::CilAssemblyView;
    use std::path::Path;

    #[test]
    fn test_heap_writer_no_modifications() {
        // Test with assembly that has no modifications
        let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))
            .expect("Failed to load test assembly");
        let assembly = view.to_owned();

        // Since there are no modifications, this should succeed without doing anything
        let layout_plan = crate::cilassembly::write::planner::create_layout_plan(&assembly)
            .expect("Failed to create layout plan");

        // For testing, we'd need a mock Output, but for now just verify the layout plan
        assert_eq!(
            layout_plan
                .metadata_modifications
                .stream_modifications
                .len(),
            0
        );
    }
}
