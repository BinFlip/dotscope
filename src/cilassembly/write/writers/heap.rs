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

        // Calculate the actual end of heap data (excluding heap-level alignment padding)
        let actual_data_end =
            self.find_actual_heap_data_end(stream_layout, stream_mod, &stream_mod.name)?;

        Ok((stream_layout, actual_data_end))
    }

    /// Writes heap modifications based on the copy-first approach.
    ///
    /// Only appends new heap entries; existing entries remain unchanged. This method
    /// iterates through all [`crate::cilassembly::write::planner::metadata::StreamModification`] entries and
    /// writes the appropriate heap additions based on stream type.
    ///
    /// # Errors
    /// Returns [`crate::Error`] if any heap writing operation fails due to invalid data
    /// or insufficient output buffer space.
    pub fn write_all_heaps(&mut self) -> Result<()> {
        // Process each modified stream and append new data
        for stream_mod in &self.layout_plan.metadata_modifications.stream_modifications {
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

    /// Appends new strings to the String heap (#Strings).
    ///
    /// Writes null-terminated UTF-8 strings with proper 4-byte alignment as required
    /// by ECMA-335 II.24.2.2. Each string is followed by a null terminator byte.
    ///
    /// # Arguments
    /// * `stream_mod` - The [`crate::cilassembly::write::planner::metadata::StreamModification`] for the #Strings heap
    fn write_string_heap_additions(&mut self, stream_mod: &StreamModification) -> Result<()> {
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

        // Add padding to align to 4-byte boundary (ECMA-335 II.24.2.2)
        self.add_padding_to_4_bytes(write_pos, write_start)?;

        Ok(())
    }

    /// Appends new blobs to the Blob heap (#Blob).
    ///
    /// Writes binary data with compressed integer length prefixes as specified by
    /// ECMA-335 II.24.2.4. Each blob is prefixed with its length using compressed
    /// integer encoding (1, 2, or 4 bytes) followed by the raw blob data.
    ///
    /// # Arguments
    /// * `stream_mod` - The [`crate::cilassembly::write::planner::metadata::StreamModification`] for the #Blob heap
    fn write_blob_heap_additions(&mut self, stream_mod: &StreamModification) -> Result<()> {
        let (_stream_layout, write_start) = self.prepare_heap_write(stream_mod)?;
        let mut write_pos = write_start;

        // Write each new blob to the heap
        for blob in &self.assembly.changes().blob_heap_changes.appended_items {
            // Blobs are prefixed with their length (compressed integer)
            let length = blob.len();

            // Write length prefix (compressed integer encoding)
            if length < 128 {
                // Single byte length
                let length_slice = self.output.get_mut_slice(write_pos, 1)?;
                length_slice[0] = length as u8;
                write_pos += 1;
            } else if length < 16384 {
                // Two byte length
                let encoded = 0x8000 | (length as u16);
                let length_slice = self.output.get_mut_slice(write_pos, 2)?;
                length_slice.copy_from_slice(&encoded.to_be_bytes());
                write_pos += 2;
            } else {
                // Four byte length
                let encoded = 0xC0000000 | (length as u32);
                let length_slice = self.output.get_mut_slice(write_pos, 4)?;
                length_slice.copy_from_slice(&encoded.to_be_bytes());
                write_pos += 4;
            }

            // Write the blob data
            let blob_slice = self.output.get_mut_slice(write_pos, blob.len())?;
            blob_slice.copy_from_slice(blob);
            write_pos += blob.len();
        }

        // Add padding to align to 4-byte boundary (ECMA-335 II.24.2.2)
        self.add_padding_to_4_bytes(write_pos, write_start)?;

        Ok(())
    }

    /// Appends new GUIDs to the GUID heap (#GUID).
    ///
    /// Writes raw 16-byte GUID values without length prefixes. GUIDs are naturally
    /// aligned to 4-byte boundaries due to their 16-byte size.
    ///
    /// # Arguments
    /// * `stream_mod` - The [`crate::cilassembly::write::planner::metadata::StreamModification`] for the #GUID heap
    fn write_guid_heap_additions(&mut self, stream_mod: &StreamModification) -> Result<()> {
        let (_stream_layout, write_start) = self.prepare_heap_write(stream_mod)?;
        let mut write_pos = write_start;

        // Write each new GUID to the heap
        for guid in &self.assembly.changes().guid_heap_changes.appended_items {
            // GUIDs are stored as raw 16-byte values, no length prefix
            let guid_slice = self.output.get_mut_slice(write_pos, 16)?;
            guid_slice.copy_from_slice(guid);
            write_pos += 16;
        }

        // GUIDs are always 16 bytes each, so already aligned to 4-byte boundary
        // No additional padding needed

        Ok(())
    }

    /// Appends new user strings to the User String heap (#US).
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
        let (_stream_layout, write_start) = self.prepare_heap_write(stream_mod)?;
        let mut write_pos = write_start;

        // Write each new user string to the heap
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

        // Add padding to align to 4-byte boundary (ECMA-335 II.24.2.2)
        self.add_padding_to_4_bytes(write_pos, write_start)?;

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
            // Fill with zeros
            for byte in padding_slice.iter_mut() {
                *byte = 0;
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
                // For other heaps, we don't have iterators to scan actual data,
                // so we'll use the original size for now. In practice, these heaps
                // may also have alignment padding, but it's less common than userstrings.
                // TODO: Implement proper scanning for these heaps if needed.
                let write_start =
                    (stream_layout.file_region.offset + stream_mod.original_size) as usize;
                Ok(write_start)
            }
            _ => Err(crate::Error::WriteLayoutFailed {
                message: format!("Unknown heap type: {}", heap_name),
            }),
        }
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
