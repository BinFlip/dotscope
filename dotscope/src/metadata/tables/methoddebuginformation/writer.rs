//! Writer implementation for `MethodDebugInformation` metadata table.
//!
//! This module provides the [`RowWritable`] trait implementation for the
//! [`MethodDebugInformationRaw`] struct, enabling serialization of method debug
//! information rows back to binary format. This supports Portable PDB generation
//! and assembly modification scenarios where debug information needs to be preserved.
//!
//! # Binary Format
//!
//! Each `MethodDebugInformation` row consists of two fields:
//! - `document` (2/4 bytes): Simple index into Document table (0 = no document)
//! - `sequence_points` (2/4 bytes): Blob heap index for sequence point data (0 = no data)
//!
//! # Row Layout
//!
//! `MethodDebugInformation` table rows are serialized with this binary structure:
//! - Document table index (2 or 4 bytes, depending on Document table size)
//! - Blob heap index (2 or 4 bytes, depending on blob heap size)
//! - Total row size varies based on table and heap sizes
//!
//! # Architecture
//!
//! This implementation provides efficient serialization by writing data directly to the
//! target buffer without intermediate allocations. Index sizes are determined dynamically
//! based on the actual table and heap sizes, matching the compression scheme used in .NET metadata.
//!
//! The writer maintains strict compatibility with the [`crate::metadata::tables::methoddebuginformation::reader`]
//! module, ensuring that data serialized by this writer can be correctly deserialized.

use crate::{
    metadata::tables::{
        methoddebuginformation::MethodDebugInformationRaw,
        types::{RowWritable, TableInfoRef},
        TableId,
    },
    utils::write_le_at_dyn,
    Result,
};

impl RowWritable for MethodDebugInformationRaw {
    /// Write a `MethodDebugInformation` table row to binary data
    ///
    /// Serializes one `MethodDebugInformation` table entry to the metadata tables stream format, handling
    /// variable-width table and heap indexes based on the table and heap size information.
    ///
    /// # Arguments
    /// * `data` - Target binary buffer for metadata tables stream
    /// * `offset` - Current write position (updated after writing)
    /// * `_rid` - Row identifier for this method debug information entry (unused for `MethodDebugInformation`)
    /// * `sizes` - Table sizing information for writing table and heap indexes
    ///
    /// # Returns
    /// * `Ok(())` - Successfully serialized method debug information row
    /// * `Err(`[`crate::Error`]`)` - If buffer is too small or write fails
    ///
    /// # Binary Format
    /// Fields are written in the exact order specified by the Portable PDB specification:
    /// 1. Document table index (2/4 bytes, little-endian, 0 = no document)
    /// 2. Sequence points blob index (2/4 bytes, little-endian, 0 = no sequence points)
    fn row_write(
        &self,
        data: &mut [u8],
        offset: &mut usize,
        _rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<()> {
        // Write document table index
        write_le_at_dyn(
            data,
            offset,
            self.document,
            sizes.is_large(TableId::Document),
        )?;

        // Write sequence points blob index
        write_le_at_dyn(data, offset, self.sequence_points, sizes.is_large_blob())?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        metadata::tables::types::{RowReadable, TableInfo, TableRow},
        metadata::token::Token,
    };

    #[test]
    fn test_round_trip_serialization_small_indices() {
        // Create test data with small table and heap indices
        let original_row = MethodDebugInformationRaw {
            rid: 1,
            token: Token::new(0x3100_0001),
            offset: 0,
            document: 5,
            sequence_points: 42,
        };

        let table_info = std::sync::Arc::new(TableInfo::new_test(
            &[(crate::metadata::tables::TableId::Document, 100)], // Small Document table
            false,                                                // small string heap
            false,                                                // small guid heap
            false,                                                // small blob heap
        ));

        // Calculate buffer size and serialize
        let row_size = <MethodDebugInformationRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        original_row
            .row_write(&mut buffer, &mut offset, 1, &table_info)
            .expect("Serialization should succeed");

        // Deserialize and verify round-trip
        let mut read_offset = 0;
        let deserialized_row =
            MethodDebugInformationRaw::row_read(&buffer, &mut read_offset, 1, &table_info)
                .expect("Deserialization should succeed");

        // Compare all fields
        assert_eq!(original_row.document, deserialized_row.document);
        assert_eq!(
            original_row.sequence_points,
            deserialized_row.sequence_points
        );
        assert_eq!(offset, row_size, "Offset should match expected row size");
        assert_eq!(
            read_offset, row_size,
            "Read offset should match expected row size"
        );
    }

    #[test]
    fn test_round_trip_serialization_large_indices() {
        // Create test data with large table and heap indices
        let original_row = MethodDebugInformationRaw {
            rid: 2,
            token: Token::new(0x3100_0002),
            offset: 0,
            document: 0x1BEEF,
            sequence_points: 0x2CAFE,
        };

        let table_info = std::sync::Arc::new(TableInfo::new_test(
            &[(crate::metadata::tables::TableId::Document, 100000)], // Large Document table
            true,                                                    // large string heap
            true,                                                    // large guid heap
            true,                                                    // large blob heap
        ));

        // Calculate buffer size and serialize
        let row_size = <MethodDebugInformationRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        original_row
            .row_write(&mut buffer, &mut offset, 2, &table_info)
            .expect("Serialization should succeed");

        // Deserialize and verify round-trip
        let mut read_offset = 0;
        let deserialized_row =
            MethodDebugInformationRaw::row_read(&buffer, &mut read_offset, 2, &table_info)
                .expect("Deserialization should succeed");

        // Compare all fields
        assert_eq!(original_row.document, deserialized_row.document);
        assert_eq!(
            original_row.sequence_points,
            deserialized_row.sequence_points
        );
        assert_eq!(offset, row_size, "Offset should match expected row size");
        assert_eq!(
            read_offset, row_size,
            "Read offset should match expected row size"
        );
    }

    #[test]
    fn test_known_binary_format_small_indices() {
        // Test with specific binary layout for small indices
        let method_debug_info = MethodDebugInformationRaw {
            rid: 1,
            token: Token::new(0x3100_0001),
            offset: 0,
            document: 0x1234,
            sequence_points: 0x5678,
        };

        let table_info = std::sync::Arc::new(TableInfo::new_test(
            &[(crate::metadata::tables::TableId::Document, 100)],
            false,
            false,
            false,
        ));

        let row_size = <MethodDebugInformationRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        method_debug_info
            .row_write(&mut buffer, &mut offset, 1, &table_info)
            .expect("Serialization should succeed");

        // Verify the binary format matches expected layout
        assert_eq!(row_size, 4, "Row size should be 4 bytes for small indices");

        // Document table index (0x1234) as little-endian
        assert_eq!(buffer[0], 0x34);
        assert_eq!(buffer[1], 0x12);

        // Sequence points blob index (0x5678) as little-endian
        assert_eq!(buffer[2], 0x78);
        assert_eq!(buffer[3], 0x56);
    }

    #[test]
    fn test_known_binary_format_large_indices() {
        // Test with specific binary layout for large indices
        let method_debug_info = MethodDebugInformationRaw {
            rid: 1,
            token: Token::new(0x3100_0001),
            offset: 0,
            document: 0x12345678,
            sequence_points: 0x9ABCDEF0,
        };

        let table_info = std::sync::Arc::new(TableInfo::new_test(
            &[(crate::metadata::tables::TableId::Document, 100000)],
            true,
            true,
            true,
        ));

        let row_size = <MethodDebugInformationRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        method_debug_info
            .row_write(&mut buffer, &mut offset, 1, &table_info)
            .expect("Serialization should succeed");

        // Verify the binary format matches expected layout
        assert_eq!(row_size, 8, "Row size should be 8 bytes for large indices");

        // Document table index (0x12345678) as little-endian
        assert_eq!(buffer[0], 0x78);
        assert_eq!(buffer[1], 0x56);
        assert_eq!(buffer[2], 0x34);
        assert_eq!(buffer[3], 0x12);

        // Sequence points blob index (0x9ABCDEF0) as little-endian
        assert_eq!(buffer[4], 0xF0);
        assert_eq!(buffer[5], 0xDE);
        assert_eq!(buffer[6], 0xBC);
        assert_eq!(buffer[7], 0x9A);
    }

    #[test]
    fn test_null_values() {
        // Test with null/zero values (no document, no sequence points)
        let method_debug_info = MethodDebugInformationRaw {
            rid: 1,
            token: Token::new(0x3100_0001),
            offset: 0,
            document: 0,        // no document
            sequence_points: 0, // no sequence points
        };

        let table_info = std::sync::Arc::new(TableInfo::new_test(
            &[(crate::metadata::tables::TableId::Document, 100)],
            false,
            false,
            false,
        ));

        let row_size = <MethodDebugInformationRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        method_debug_info
            .row_write(&mut buffer, &mut offset, 1, &table_info)
            .expect("Serialization should succeed");

        // Verify that zero values are preserved
        let mut read_offset = 0;
        let deserialized_row =
            MethodDebugInformationRaw::row_read(&buffer, &mut read_offset, 1, &table_info)
                .expect("Deserialization should succeed");

        assert_eq!(deserialized_row.document, 0);
        assert_eq!(deserialized_row.sequence_points, 0);
    }
}
