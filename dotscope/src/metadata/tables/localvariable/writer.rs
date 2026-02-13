//! Writer implementation for `LocalVariable` metadata table.
//!
//! This module provides the [`RowWritable`] trait implementation for the
//! [`LocalVariableRaw`] struct, enabling serialization of local variable information
//! rows back to binary format. This supports Portable PDB generation and
//! assembly modification scenarios where debug information needs to be preserved.
//!
//! # Binary Format
//!
//! Each `LocalVariable` row consists of three fields:
//! - `attributes` (2 bytes): Variable attribute flags
//! - `index` (2 bytes): Variable index within the method
//! - `name` (2/4 bytes): String heap index for variable name (0 = anonymous)
//!
//! # Row Layout
//!
//! `LocalVariable` table rows are serialized with this binary structure:
//! - Attributes (2 bytes, little-endian)
//! - Index (2 bytes, little-endian)
//! - Name string index (2 or 4 bytes, depending on string heap size)
//! - Total row size varies based on heap sizes
//!
//! # Architecture
//!
//! This implementation provides efficient serialization by writing data directly to the
//! target buffer without intermediate allocations. Index sizes are determined dynamically
//! based on the actual heap sizes, matching the compression scheme used in .NET metadata.
//!
//! The writer maintains strict compatibility with the [`crate::metadata::tables::localvariable::reader`]
//! module, ensuring that data serialized by this writer can be correctly deserialized.

use crate::{
    metadata::tables::{
        localvariable::LocalVariableRaw,
        types::{RowWritable, TableInfoRef},
    },
    utils::{write_le_at, write_le_at_dyn},
    Result,
};

impl RowWritable for LocalVariableRaw {
    /// Write a `LocalVariable` table row to binary data
    ///
    /// Serializes one `LocalVariable` table entry to the metadata tables stream format, handling
    /// variable-width string heap indexes based on the heap size information.
    ///
    /// # Arguments
    /// * `data` - Target binary buffer for metadata tables stream
    /// * `offset` - Current write position (updated after writing)
    /// * `_rid` - Row identifier for this local variable entry (unused for `LocalVariable`)
    /// * `sizes` - Table sizing information for writing heap indexes
    ///
    /// # Returns
    /// * `Ok(())` - Successfully serialized local variable row
    /// * `Err(`[`crate::Error`]`)` - If buffer is too small or write fails
    ///
    /// # Binary Format
    /// Fields are written in the exact order specified by the Portable PDB specification:
    /// 1. Attributes (2 bytes, little-endian)
    /// 2. Index (2 bytes, little-endian)
    /// 3. Name string index (2/4 bytes, little-endian, 0 = anonymous)
    fn row_write(
        &self,
        data: &mut [u8],
        offset: &mut usize,
        _rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<()> {
        // Write fixed-size fields
        write_le_at::<u16>(data, offset, self.attributes)?;
        write_le_at::<u16>(data, offset, self.index)?;

        // Write variable-size string heap index
        write_le_at_dyn(data, offset, self.name, sizes.is_large_str())?;

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
    fn test_round_trip_serialization_small_heap() {
        // Create test data with small string heap
        let original_row = LocalVariableRaw {
            rid: 1,
            token: Token::new(0x3300_0001),
            offset: 0,
            attributes: 0x1234,
            index: 0x5678,
            name: 42,
        };

        let table_info = std::sync::Arc::new(TableInfo::new_test(&[], false, false, false));

        // Calculate buffer size and serialize
        let row_size = <LocalVariableRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        original_row
            .row_write(&mut buffer, &mut offset, 1, &table_info)
            .expect("Serialization should succeed");

        // Deserialize and verify round-trip
        let mut read_offset = 0;
        let deserialized_row =
            LocalVariableRaw::row_read(&buffer, &mut read_offset, 1, &table_info)
                .expect("Deserialization should succeed");

        // Compare all fields
        assert_eq!(original_row.attributes, deserialized_row.attributes);
        assert_eq!(original_row.index, deserialized_row.index);
        assert_eq!(original_row.name, deserialized_row.name);
        assert_eq!(offset, row_size, "Offset should match expected row size");
        assert_eq!(
            read_offset, row_size,
            "Read offset should match expected row size"
        );
    }

    #[test]
    fn test_round_trip_serialization_large_heap() {
        // Create test data with large string heap
        let original_row = LocalVariableRaw {
            rid: 2,
            token: Token::new(0x3300_0002),
            offset: 0,
            attributes: 0x9ABC,
            index: 0xDEF0,
            name: 0x1BEEF,
        };

        let table_info = std::sync::Arc::new(TableInfo::new_test(&[], true, false, false));

        // Calculate buffer size and serialize
        let row_size = <LocalVariableRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        original_row
            .row_write(&mut buffer, &mut offset, 2, &table_info)
            .expect("Serialization should succeed");

        // Deserialize and verify round-trip
        let mut read_offset = 0;
        let deserialized_row =
            LocalVariableRaw::row_read(&buffer, &mut read_offset, 2, &table_info)
                .expect("Deserialization should succeed");

        // Compare all fields
        assert_eq!(original_row.attributes, deserialized_row.attributes);
        assert_eq!(original_row.index, deserialized_row.index);
        assert_eq!(original_row.name, deserialized_row.name);
        assert_eq!(offset, row_size, "Offset should match expected row size");
        assert_eq!(
            read_offset, row_size,
            "Read offset should match expected row size"
        );
    }

    #[test]
    fn test_known_binary_format_small_heap() {
        // Test with specific binary layout for small heap
        let local_variable = LocalVariableRaw {
            rid: 1,
            token: Token::new(0x3300_0001),
            offset: 0,
            attributes: 0x1234,
            index: 0x5678,
            name: 0x9ABC,
        };

        let table_info = std::sync::Arc::new(TableInfo::new_test(&[], false, false, false));

        let row_size = <LocalVariableRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        local_variable
            .row_write(&mut buffer, &mut offset, 1, &table_info)
            .expect("Serialization should succeed");

        // Verify the binary format matches expected layout
        assert_eq!(row_size, 6, "Row size should be 6 bytes for small heap");

        // Attributes (0x1234) as little-endian
        assert_eq!(buffer[0], 0x34);
        assert_eq!(buffer[1], 0x12);

        // Index (0x5678) as little-endian
        assert_eq!(buffer[2], 0x78);
        assert_eq!(buffer[3], 0x56);

        // Name string index (0x9ABC) as little-endian
        assert_eq!(buffer[4], 0xBC);
        assert_eq!(buffer[5], 0x9A);
    }

    #[test]
    fn test_known_binary_format_large_heap() {
        // Test with specific binary layout for large heap
        let local_variable = LocalVariableRaw {
            rid: 1,
            token: Token::new(0x3300_0001),
            offset: 0,
            attributes: 0x1234,
            index: 0x5678,
            name: 0x9ABCDEF0,
        };

        let table_info = std::sync::Arc::new(TableInfo::new_test(&[], true, false, false));

        let row_size = <LocalVariableRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        local_variable
            .row_write(&mut buffer, &mut offset, 1, &table_info)
            .expect("Serialization should succeed");

        // Verify the binary format matches expected layout
        assert_eq!(row_size, 8, "Row size should be 8 bytes for large heap");

        // Attributes (0x1234) as little-endian
        assert_eq!(buffer[0], 0x34);
        assert_eq!(buffer[1], 0x12);

        // Index (0x5678) as little-endian
        assert_eq!(buffer[2], 0x78);
        assert_eq!(buffer[3], 0x56);

        // Name string index (0x9ABCDEF0) as little-endian
        assert_eq!(buffer[4], 0xF0);
        assert_eq!(buffer[5], 0xDE);
        assert_eq!(buffer[6], 0xBC);
        assert_eq!(buffer[7], 0x9A);
    }

    #[test]
    fn test_anonymous_variable() {
        // Test with anonymous variable (name = 0)
        let local_variable = LocalVariableRaw {
            rid: 1,
            token: Token::new(0x3300_0001),
            offset: 0,
            attributes: 0x0001, // Some attribute flag
            index: 0,           // First variable
            name: 0,            // Anonymous variable
        };

        let table_info = std::sync::Arc::new(TableInfo::new_test(&[], false, false, false));

        let row_size = <LocalVariableRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        local_variable
            .row_write(&mut buffer, &mut offset, 1, &table_info)
            .expect("Serialization should succeed");

        // Verify that zero name is preserved
        let mut read_offset = 0;
        let deserialized_row =
            LocalVariableRaw::row_read(&buffer, &mut read_offset, 1, &table_info)
                .expect("Deserialization should succeed");

        assert_eq!(deserialized_row.attributes, 0x0001);
        assert_eq!(deserialized_row.index, 0);
        assert_eq!(deserialized_row.name, 0);
    }

    #[test]
    fn test_various_attributes_and_indices() {
        // Test with different attribute and index combinations
        let test_cases = vec![
            (0x0000, 0),     // No attributes, first variable
            (0x0001, 1),     // Some attribute, second variable
            (0xFFFF, 65535), // All attributes, last possible index
        ];

        for (attributes, index) in test_cases {
            let local_variable = LocalVariableRaw {
                rid: 1,
                token: Token::new(0x3300_0001),
                offset: 0,
                attributes,
                index,
                name: 100, // Some name index
            };

            let table_info = std::sync::Arc::new(TableInfo::new_test(&[], false, false, false));

            let row_size = <LocalVariableRaw as TableRow>::row_size(&table_info) as usize;
            let mut buffer = vec![0u8; row_size];
            let mut offset = 0;

            local_variable
                .row_write(&mut buffer, &mut offset, 1, &table_info)
                .expect("Serialization should succeed");

            // Verify round-trip
            let mut read_offset = 0;
            let deserialized_row =
                LocalVariableRaw::row_read(&buffer, &mut read_offset, 1, &table_info)
                    .expect("Deserialization should succeed");

            assert_eq!(deserialized_row.attributes, attributes);
            assert_eq!(deserialized_row.index, index);
            assert_eq!(deserialized_row.name, 100);
        }
    }
}
