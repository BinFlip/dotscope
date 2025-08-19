//! Writer implementation for `LocalConstant` metadata table.
//!
//! This module provides the [`RowWritable`] trait implementation for the
//! [`LocalConstantRaw`] struct, enabling serialization of local constant information
//! rows back to binary format. This supports Portable PDB generation and
//! assembly modification scenarios where debug information needs to be preserved.
//!
//! # Binary Format
//!
//! Each `LocalConstant` row consists of two fields:
//! - `name` (2/4 bytes): String heap index for constant name (0 = anonymous)
//! - `signature` (2/4 bytes): Blob heap index for constant signature
//!
//! # Row Layout
//!
//! `LocalConstant` table rows are serialized with this binary structure:
//! - Name string index (2 or 4 bytes, depending on string heap size)
//! - Signature blob index (2 or 4 bytes, depending on blob heap size)
//! - Total row size varies based on heap sizes
//!
//! # Architecture
//!
//! This implementation provides efficient serialization by writing data directly to the
//! target buffer without intermediate allocations. Index sizes are determined dynamically
//! based on the actual heap sizes, matching the compression scheme used in .NET metadata.
//!
//! The writer maintains strict compatibility with the [`crate::metadata::tables::localconstant::reader`]
//! module, ensuring that data serialized by this writer can be correctly deserialized.

use crate::{
    metadata::tables::{
        localconstant::LocalConstantRaw,
        types::{RowWritable, TableInfoRef},
    },
    utils::write_le_at_dyn,
    Result,
};

impl RowWritable for LocalConstantRaw {
    /// Write a `LocalConstant` table row to binary data
    ///
    /// Serializes one `LocalConstant` table entry to the metadata tables stream format, handling
    /// variable-width string and blob heap indexes based on the heap size information.
    ///
    /// # Arguments
    /// * `data` - Target binary buffer for metadata tables stream
    /// * `offset` - Current write position (updated after writing)
    /// * `_rid` - Row identifier for this local constant entry (unused for `LocalConstant`)
    /// * `sizes` - Table sizing information for writing heap indexes
    ///
    /// # Returns
    /// * `Ok(())` - Successfully serialized local constant row
    /// * `Err(`[`crate::Error`]`)` - If buffer is too small or write fails
    ///
    /// # Binary Format
    /// Fields are written in the exact order specified by the Portable PDB specification:
    /// 1. Name string index (2/4 bytes, little-endian, 0 = anonymous)
    /// 2. Signature blob index (2/4 bytes, little-endian)
    fn row_write(
        &self,
        data: &mut [u8],
        offset: &mut usize,
        _rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<()> {
        // Write string and blob heap indices
        write_le_at_dyn(data, offset, self.name, sizes.is_large_str())?;
        write_le_at_dyn(data, offset, self.signature, sizes.is_large_blob())?;

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
        // Create test data with small string and blob heaps
        let original_row = LocalConstantRaw {
            rid: 1,
            token: Token::new(0x3400_0001),
            offset: 0,
            name: 42,
            signature: 123,
        };

        let table_info = std::sync::Arc::new(TableInfo::new_test(&[], false, false, false));

        // Calculate buffer size and serialize
        let row_size = <LocalConstantRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        original_row
            .row_write(&mut buffer, &mut offset, 1, &table_info)
            .expect("Serialization should succeed");

        // Deserialize and verify round-trip
        let mut read_offset = 0;
        let deserialized_row =
            LocalConstantRaw::row_read(&buffer, &mut read_offset, 1, &table_info)
                .expect("Deserialization should succeed");

        // Compare all fields
        assert_eq!(original_row.name, deserialized_row.name);
        assert_eq!(original_row.signature, deserialized_row.signature);
        assert_eq!(offset, row_size, "Offset should match expected row size");
        assert_eq!(
            read_offset, row_size,
            "Read offset should match expected row size"
        );
    }

    #[test]
    fn test_round_trip_serialization_large_heaps() {
        // Create test data with large string and blob heaps
        let original_row = LocalConstantRaw {
            rid: 2,
            token: Token::new(0x3400_0002),
            offset: 0,
            name: 0x1BEEF,
            signature: 0x2CA, // Smaller value for 2-byte blob heap
        };

        let table_info = std::sync::Arc::new(TableInfo::new_test(&[], true, false, false));

        // Calculate buffer size and serialize
        let row_size = <LocalConstantRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        original_row
            .row_write(&mut buffer, &mut offset, 2, &table_info)
            .expect("Serialization should succeed");

        // Deserialize and verify round-trip
        let mut read_offset = 0;
        let deserialized_row =
            LocalConstantRaw::row_read(&buffer, &mut read_offset, 2, &table_info)
                .expect("Deserialization should succeed");

        // Compare all fields
        assert_eq!(original_row.name, deserialized_row.name);
        assert_eq!(original_row.signature, deserialized_row.signature);
        assert_eq!(offset, row_size, "Offset should match expected row size");
        assert_eq!(
            read_offset, row_size,
            "Read offset should match expected row size"
        );
    }

    #[test]
    fn test_known_binary_format_small_heaps() {
        // Test with specific binary layout for small heaps
        let local_constant = LocalConstantRaw {
            rid: 1,
            token: Token::new(0x3400_0001),
            offset: 0,
            name: 0x1234,
            signature: 0x5678,
        };

        let table_info = std::sync::Arc::new(TableInfo::new_test(&[], false, false, false));

        let row_size = <LocalConstantRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        local_constant
            .row_write(&mut buffer, &mut offset, 1, &table_info)
            .expect("Serialization should succeed");

        // Verify the binary format matches expected layout
        assert_eq!(row_size, 4, "Row size should be 4 bytes for small heaps");

        // Name string index (0x1234) as little-endian
        assert_eq!(buffer[0], 0x34);
        assert_eq!(buffer[1], 0x12);

        // Signature blob index (0x5678) as little-endian
        assert_eq!(buffer[2], 0x78);
        assert_eq!(buffer[3], 0x56);
    }

    #[test]
    fn test_known_binary_format_large_heaps() {
        // Test with specific binary layout for large heaps
        let local_constant = LocalConstantRaw {
            rid: 1,
            token: Token::new(0x3400_0001),
            offset: 0,
            name: 0x12345678,
            signature: 0x9ABC, // Smaller value for 2-byte blob heap
        };

        let table_info = std::sync::Arc::new(TableInfo::new_test(&[], true, false, false));

        let row_size = <LocalConstantRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        local_constant
            .row_write(&mut buffer, &mut offset, 1, &table_info)
            .expect("Serialization should succeed");

        // Verify the binary format matches expected layout
        assert_eq!(
            row_size, 6,
            "Row size should be 6 bytes for large string, small blob"
        );

        // Name string index (0x12345678) as little-endian
        assert_eq!(buffer[0], 0x78);
        assert_eq!(buffer[1], 0x56);
        assert_eq!(buffer[2], 0x34);
        assert_eq!(buffer[3], 0x12);

        // Signature blob index (0x9ABC) as little-endian
        assert_eq!(buffer[4], 0xBC);
        assert_eq!(buffer[5], 0x9A);
    }

    #[test]
    fn test_anonymous_constant() {
        // Test with anonymous constant (name = 0)
        let local_constant = LocalConstantRaw {
            rid: 1,
            token: Token::new(0x3400_0001),
            offset: 0,
            name: 0, // Anonymous constant
            signature: 100,
        };

        let table_info = std::sync::Arc::new(TableInfo::new_test(&[], false, false, false));

        let row_size = <LocalConstantRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        local_constant
            .row_write(&mut buffer, &mut offset, 1, &table_info)
            .expect("Serialization should succeed");

        // Verify that zero name is preserved
        let mut read_offset = 0;
        let deserialized_row =
            LocalConstantRaw::row_read(&buffer, &mut read_offset, 1, &table_info)
                .expect("Deserialization should succeed");

        assert_eq!(deserialized_row.name, 0);
        assert_eq!(deserialized_row.signature, 100);
    }

    #[test]
    fn test_mixed_heap_sizes() {
        // Test with mixed heap sizes (large string, small blob)
        let local_constant = LocalConstantRaw {
            rid: 1,
            token: Token::new(0x3400_0001),
            offset: 0,
            name: 0x12345678,  // Large string index
            signature: 0x1234, // Small blob index
        };

        let table_info = std::sync::Arc::new(TableInfo::new_test(&[], true, false, false));

        let row_size = <LocalConstantRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        local_constant
            .row_write(&mut buffer, &mut offset, 1, &table_info)
            .expect("Serialization should succeed");

        // Verify the binary format matches expected layout
        assert_eq!(
            row_size, 6,
            "Row size should be 6 bytes for mixed heap sizes"
        );

        // Verify round-trip
        let mut read_offset = 0;
        let deserialized_row =
            LocalConstantRaw::row_read(&buffer, &mut read_offset, 1, &table_info)
                .expect("Deserialization should succeed");

        assert_eq!(deserialized_row.name, 0x12345678);
        assert_eq!(deserialized_row.signature, 0x1234);
    }

    #[test]
    fn test_edge_case_values() {
        // Test with edge case values
        let test_cases = vec![
            (0, 0),           // Both zero
            (1, 1),           // Minimum valid values
            (0xFFFF, 0xFFFF), // Max for small heap
        ];

        for (name, signature) in test_cases {
            let local_constant = LocalConstantRaw {
                rid: 1,
                token: Token::new(0x3400_0001),
                offset: 0,
                name,
                signature,
            };

            let table_info = std::sync::Arc::new(TableInfo::new_test(&[], false, false, false));

            let row_size = <LocalConstantRaw as TableRow>::row_size(&table_info) as usize;
            let mut buffer = vec![0u8; row_size];
            let mut offset = 0;

            local_constant
                .row_write(&mut buffer, &mut offset, 1, &table_info)
                .expect("Serialization should succeed");

            // Verify round-trip
            let mut read_offset = 0;
            let deserialized_row =
                LocalConstantRaw::row_read(&buffer, &mut read_offset, 1, &table_info)
                    .expect("Deserialization should succeed");

            assert_eq!(deserialized_row.name, name);
            assert_eq!(deserialized_row.signature, signature);
        }
    }
}
