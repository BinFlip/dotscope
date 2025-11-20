//! Writer implementation for `Document` metadata table.
//!
//! This module provides the [`RowWritable`] trait implementation for the
//! [`DocumentRaw`] struct, enabling serialization of source document metadata
//! rows back to binary format. This supports assembly modification scenarios
//! where debug information needs to be regenerated.
//!
//! # Binary Format
//!
//! Each `Document` row consists of four heap index fields:
//! - `name` (2/4 bytes): Blob heap index for document name/path
//! - `hash_algorithm` (2/4 bytes): GUID heap index for hash algorithm
//! - `hash` (2/4 bytes): Blob heap index for document content hash
//! - `language` (2/4 bytes): GUID heap index for source language
//!
//! # Row Layout
//!
//! `Document` table rows are serialized with this binary structure:
//! - All fields are variable-size heap indices (2 or 4 bytes each)
//! - Total row size varies based on heap sizes
//!
//! # Architecture
//!
//! This implementation provides efficient serialization by writing data directly to the
//! target buffer without intermediate allocations. Index sizes are determined dynamically
//! based on the actual heap sizes, matching the compression scheme used in .NET metadata.
//!
//! The writer maintains strict compatibility with the [`crate::metadata::tables::document::reader`]
//! module, ensuring that data serialized by this writer can be correctly deserialized.

use crate::{
    metadata::tables::{
        document::DocumentRaw,
        types::{RowWritable, TableInfoRef},
    },
    utils::write_le_at_dyn,
    Result,
};

impl RowWritable for DocumentRaw {
    /// Write a `Document` table row to binary data
    ///
    /// Serializes one `Document` table entry to the metadata tables stream format, handling
    /// variable-width heap indexes based on the heap size information.
    ///
    /// # Arguments
    /// * `data` - Target binary buffer for metadata tables stream
    /// * `offset` - Current write position (updated after writing)
    /// * `_rid` - Row identifier for this document entry (unused for `Document`)
    /// * `sizes` - Table sizing information for writing heap indexes
    ///
    /// # Returns
    /// * `Ok(())` - Successfully serialized document row
    /// * `Err(`[`crate::Error`]`)` - If buffer is too small or write fails
    ///
    /// # Binary Format
    /// Fields are written in the exact order specified by the Portable PDB specification:
    /// 1. Name blob index (2/4 bytes, little-endian)
    /// 2. Hash algorithm GUID index (2/4 bytes, little-endian)
    /// 3. Hash blob index (2/4 bytes, little-endian)
    /// 4. Language GUID index (2/4 bytes, little-endian)
    fn row_write(
        &self,
        data: &mut [u8],
        offset: &mut usize,
        _rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<()> {
        // Write all heap indices
        write_le_at_dyn(data, offset, self.name, sizes.is_large_blob())?;
        write_le_at_dyn(data, offset, self.hash_algorithm, sizes.is_large_guid())?;
        write_le_at_dyn(data, offset, self.hash, sizes.is_large_blob())?;
        write_le_at_dyn(data, offset, self.language, sizes.is_large_guid())?;

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
    fn test_round_trip_serialization_small_heaps() {
        // Create test data with small heap indices
        let original_row = DocumentRaw {
            rid: 1,
            token: Token::new(0x3000_0001),
            offset: 0,
            name: 42,
            hash_algorithm: 15,
            hash: 123,
            language: 7,
        };

        let table_info = std::sync::Arc::new(TableInfo::new_test(&[], false, false, false));

        // Calculate buffer size and serialize
        let row_size = <DocumentRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        original_row
            .row_write(&mut buffer, &mut offset, 1, &table_info)
            .expect("Serialization should succeed");

        // Deserialize and verify round-trip
        let mut read_offset = 0;
        let deserialized_row = DocumentRaw::row_read(&buffer, &mut read_offset, 1, &table_info)
            .expect("Deserialization should succeed");

        // Compare all fields
        assert_eq!(original_row.name, deserialized_row.name);
        assert_eq!(original_row.hash_algorithm, deserialized_row.hash_algorithm);
        assert_eq!(original_row.hash, deserialized_row.hash);
        assert_eq!(original_row.language, deserialized_row.language);
        assert_eq!(offset, row_size, "Offset should match expected row size");
        assert_eq!(
            read_offset, row_size,
            "Read offset should match expected row size"
        );
    }

    #[test]
    fn test_round_trip_serialization_large_heaps() {
        // Create test data with large heap indices
        let original_row = DocumentRaw {
            rid: 2,
            token: Token::new(0x3000_0002),
            offset: 0,
            name: 0x1ABCD,
            hash_algorithm: 0x2BEEF,
            hash: 0x3CAFE,
            language: 0x4DEAD,
        };

        let table_info = std::sync::Arc::new(TableInfo::new_test(&[], false, true, true));

        // Calculate buffer size and serialize
        let row_size = <DocumentRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        original_row
            .row_write(&mut buffer, &mut offset, 2, &table_info)
            .expect("Serialization should succeed");

        // Deserialize and verify round-trip
        let mut read_offset = 0;
        let deserialized_row = DocumentRaw::row_read(&buffer, &mut read_offset, 2, &table_info)
            .expect("Deserialization should succeed");

        // Compare all fields
        assert_eq!(original_row.name, deserialized_row.name);
        assert_eq!(original_row.hash_algorithm, deserialized_row.hash_algorithm);
        assert_eq!(original_row.hash, deserialized_row.hash);
        assert_eq!(original_row.language, deserialized_row.language);
        assert_eq!(offset, row_size, "Offset should match expected row size");
        assert_eq!(
            read_offset, row_size,
            "Read offset should match expected row size"
        );
    }

    #[test]
    fn test_known_binary_format_small_heaps() {
        // Test with specific binary layout for small heaps
        let document = DocumentRaw {
            rid: 1,
            token: Token::new(0x3000_0001),
            offset: 0,
            name: 0x1234,
            hash_algorithm: 0x5678,
            hash: 0x9ABC,
            language: 0xDEF0,
        };

        let table_info = std::sync::Arc::new(TableInfo::new_test(&[], false, false, false));

        let row_size = <DocumentRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        document
            .row_write(&mut buffer, &mut offset, 1, &table_info)
            .expect("Serialization should succeed");

        // Verify the binary format matches expected layout
        assert_eq!(row_size, 8, "Row size should be 8 bytes for small heaps");

        // Name blob index (0x1234) as little-endian
        assert_eq!(buffer[0], 0x34);
        assert_eq!(buffer[1], 0x12);

        // Hash algorithm GUID index (0x5678) as little-endian
        assert_eq!(buffer[2], 0x78);
        assert_eq!(buffer[3], 0x56);

        // Hash blob index (0x9ABC) as little-endian
        assert_eq!(buffer[4], 0xBC);
        assert_eq!(buffer[5], 0x9A);

        // Language GUID index (0xDEF0) as little-endian
        assert_eq!(buffer[6], 0xF0);
        assert_eq!(buffer[7], 0xDE);
    }

    #[test]
    fn test_known_binary_format_large_heaps() {
        // Test with specific binary layout for large heaps
        let document = DocumentRaw {
            rid: 1,
            token: Token::new(0x3000_0001),
            offset: 0,
            name: 0x12345678,
            hash_algorithm: 0x9ABCDEF0,
            hash: 0x11223344,
            language: 0x55667788,
        };

        let table_info = std::sync::Arc::new(TableInfo::new_test(&[], false, true, true));

        let row_size = <DocumentRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        document
            .row_write(&mut buffer, &mut offset, 1, &table_info)
            .expect("Serialization should succeed");

        // Verify the binary format matches expected layout
        assert_eq!(row_size, 16, "Row size should be 16 bytes for large heaps");

        // Name blob index (0x12345678) as little-endian
        assert_eq!(buffer[0], 0x78);
        assert_eq!(buffer[1], 0x56);
        assert_eq!(buffer[2], 0x34);
        assert_eq!(buffer[3], 0x12);

        // Hash algorithm GUID index (0x9ABCDEF0) as little-endian
        assert_eq!(buffer[4], 0xF0);
        assert_eq!(buffer[5], 0xDE);
        assert_eq!(buffer[6], 0xBC);
        assert_eq!(buffer[7], 0x9A);

        // Hash blob index (0x11223344) as little-endian
        assert_eq!(buffer[8], 0x44);
        assert_eq!(buffer[9], 0x33);
        assert_eq!(buffer[10], 0x22);
        assert_eq!(buffer[11], 0x11);

        // Language GUID index (0x55667788) as little-endian
        assert_eq!(buffer[12], 0x88);
        assert_eq!(buffer[13], 0x77);
        assert_eq!(buffer[14], 0x66);
        assert_eq!(buffer[15], 0x55);
    }
}
