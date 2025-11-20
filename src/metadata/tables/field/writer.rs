//! Implementation of `RowWritable` for `FieldRaw` metadata table entries.
//!
//! This module provides binary serialization support for the `Field` table (ID 0x04),
//! enabling writing of field definition metadata back to .NET PE files. The Field table
//! defines data members for types, including instance fields, static fields, and literals.
//!
//! ## Table Structure (ECMA-335 §II.22.15)
//!
//! | Field | Type | Description |
//! |-------|------|-------------|
//! | `Flags` | `u16` | Field attributes bitmask (`FieldAttributes`) |
//! | `Name` | String heap index | Field identifier name |
//! | `Signature` | Blob heap index | Field type signature |
//!
//! ## Field Attributes
//!
//! The `Flags` field contains a `FieldAttributes` bitmask with common values:
//! - `0x0001` - `CompilerControlled`
//! - `0x0002` - `Private`
//! - `0x0007` - `Public`
//! - `0x0010` - `Static`
//! - `0x0020` - `Literal`
//! - `0x1000` - `HasDefault`

use crate::{
    metadata::tables::{
        field::FieldRaw,
        types::{RowWritable, TableInfoRef},
    },
    utils::{write_le_at, write_le_at_dyn},
    Result,
};

impl RowWritable for FieldRaw {
    /// Write a Field table row to binary data
    ///
    /// Serializes one Field table entry to the metadata tables stream format, handling
    /// variable-width heap indexes based on the table size information.
    ///
    /// # Field Serialization Order (ECMA-335)
    /// 1. `flags` - Field attributes as 2-byte little-endian value
    /// 2. `name` - String heap index (2 or 4 bytes)
    /// 3. `signature` - Blob heap index (2 or 4 bytes)
    ///
    /// # Arguments
    /// * `data` - Target binary buffer for metadata tables stream
    /// * `offset` - Current write position (updated after writing)
    /// * `rid` - Row identifier (unused for Field serialization)
    /// * `sizes` - Table size information for determining index widths
    ///
    /// # Returns
    /// `Ok(())` on successful serialization, error if buffer is too small
    ///
    /// # Errors
    /// Returns an error if:
    /// - The target buffer is too small for the row data
    fn row_write(
        &self,
        data: &mut [u8],
        offset: &mut usize,
        _rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<()> {
        // Write flags (2 bytes) - convert from u32 to u16 with range check
        let flags_u16 = u16::try_from(self.flags).map_err(|_| crate::Error::WriteLayoutFailed {
            message: "Field flags value exceeds u16 range".to_string(),
        })?;
        write_le_at(data, offset, flags_u16)?;

        // Write name string heap index (2 or 4 bytes)
        write_le_at_dyn(data, offset, self.name, sizes.is_large_str())?;

        // Write signature blob heap index (2 or 4 bytes)
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
    use std::sync::Arc;

    #[test]
    fn test_row_size() {
        // Test with small heaps
        let table_info = Arc::new(TableInfo::new_test(&[], false, false, false));

        let size = <FieldRaw as TableRow>::row_size(&table_info);
        // flags(2) + name(2) + signature(2) = 6
        assert_eq!(size, 6);

        // Test with large heaps
        let table_info_large = Arc::new(TableInfo::new_test(&[], true, true, false));

        let size_large = <FieldRaw as TableRow>::row_size(&table_info_large);
        // flags(2) + name(4) + signature(4) = 10
        assert_eq!(size_large, 10);
    }

    #[test]
    fn test_round_trip_serialization() {
        // Create test data using same values as reader tests
        let original_row = FieldRaw {
            rid: 1,
            token: Token::new(0x04000001),
            offset: 0,
            flags: 0x0006, // Public
            name: 0x1234,
            signature: 0x5678,
        };

        // Create minimal table info for testing
        let table_info = Arc::new(TableInfo::new_test(&[], false, false, false));

        // Calculate buffer size and serialize
        let row_size = <FieldRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        original_row
            .row_write(&mut buffer, &mut offset, 1, &table_info)
            .expect("Serialization should succeed");

        // Deserialize and verify round-trip
        let mut read_offset = 0;
        let deserialized_row = FieldRaw::row_read(&buffer, &mut read_offset, 1, &table_info)
            .expect("Deserialization should succeed");

        assert_eq!(deserialized_row.rid, original_row.rid);
        assert_eq!(deserialized_row.flags, original_row.flags);
        assert_eq!(deserialized_row.name, original_row.name);
        assert_eq!(deserialized_row.signature, original_row.signature);
    }

    #[test]
    fn test_known_binary_format() {
        // Test with known binary data from reader tests
        let data = vec![
            0x06, 0x00, // flags (0x0006 = Public)
            0x34, 0x12, // name (0x1234)
            0x78, 0x56, // signature (0x5678)
        ];

        let table_info = Arc::new(TableInfo::new_test(&[], false, false, false));

        // First read the original data to get a reference row
        let mut read_offset = 0;
        let reference_row = FieldRaw::row_read(&data, &mut read_offset, 1, &table_info)
            .expect("Reading reference data should succeed");

        // Now serialize and verify we get the same binary data
        let mut buffer = vec![0u8; data.len()];
        let mut write_offset = 0;
        reference_row
            .row_write(&mut buffer, &mut write_offset, 1, &table_info)
            .expect("Serialization should succeed");

        assert_eq!(
            buffer, data,
            "Serialized data should match original binary format"
        );
    }

    #[test]
    fn test_field_attributes() {
        // Test various field attribute combinations
        let test_cases = vec![
            (0x0001, "CompilerControlled"),
            (0x0002, "Private"),
            (0x0006, "Public"),
            (0x0010, "Static"),
            (0x0020, "Literal"),
            (0x0040, "InitOnly"),
            (0x1000, "HasDefault"),
            (0x2000, "HasFieldMarshal"),
            (0x0016, "Public|Static"), // 0x0006 | 0x0010
        ];

        let table_info = Arc::new(TableInfo::new_test(&[], false, false, false));

        for (flags, description) in test_cases {
            let field_row = FieldRaw {
                rid: 1,
                token: Token::new(0x04000001),
                offset: 0,
                flags,
                name: 0x100,
                signature: 0x200,
            };

            let row_size = <FieldRaw as TableRow>::row_size(&table_info) as usize;
            let mut buffer = vec![0u8; row_size];
            let mut offset = 0;

            field_row
                .row_write(&mut buffer, &mut offset, 1, &table_info)
                .unwrap_or_else(|_| panic!("Serialization should succeed for {description}"));

            // Verify round-trip
            let mut read_offset = 0;
            let deserialized_row = FieldRaw::row_read(&buffer, &mut read_offset, 1, &table_info)
                .unwrap_or_else(|_| panic!("Deserialization should succeed for {description}"));

            assert_eq!(
                deserialized_row.flags, field_row.flags,
                "Flags should match for {description}"
            );
        }
    }

    #[test]
    fn test_large_heap_serialization() {
        // Test with large heaps to ensure 4-byte indexes are handled correctly
        let original_row = FieldRaw {
            rid: 1,
            token: Token::new(0x04000001),
            offset: 0,
            flags: 0x0026, // Public | Literal
            name: 0x123456,
            signature: 0x789ABC,
        };

        let table_info = Arc::new(TableInfo::new_test(&[], true, true, false));

        let row_size = <FieldRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        original_row
            .row_write(&mut buffer, &mut offset, 1, &table_info)
            .expect("Large heap serialization should succeed");

        // Verify round-trip
        let mut read_offset = 0;
        let deserialized_row = FieldRaw::row_read(&buffer, &mut read_offset, 1, &table_info)
            .expect("Large heap deserialization should succeed");

        assert_eq!(deserialized_row.flags, original_row.flags);
        assert_eq!(deserialized_row.name, original_row.name);
        assert_eq!(deserialized_row.signature, original_row.signature);
    }

    #[test]
    fn test_edge_cases() {
        // Test with zero values
        let zero_row = FieldRaw {
            rid: 1,
            token: Token::new(0x04000001),
            offset: 0,
            flags: 0,
            name: 0,
            signature: 0,
        };

        let table_info = Arc::new(TableInfo::new_test(&[], false, false, false));

        let row_size = <FieldRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        zero_row
            .row_write(&mut buffer, &mut offset, 1, &table_info)
            .expect("Zero value serialization should succeed");

        // Verify round-trip with zero values
        let mut read_offset = 0;
        let deserialized_row = FieldRaw::row_read(&buffer, &mut read_offset, 1, &table_info)
            .expect("Zero value deserialization should succeed");

        assert_eq!(deserialized_row.flags, zero_row.flags);
        assert_eq!(deserialized_row.name, zero_row.name);
        assert_eq!(deserialized_row.signature, zero_row.signature);
    }

    #[test]
    fn test_flags_range_validation() {
        // Test that large flag values are properly rejected
        let large_flags_row = FieldRaw {
            rid: 1,
            token: Token::new(0x04000001),
            offset: 0,
            flags: 0x12345678, // Large value that exceeds u16 range
            name: 0x100,
            signature: 0x200,
        };

        let table_info = Arc::new(TableInfo::new_test(&[], false, false, false));
        let row_size = <FieldRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        // Should fail with range error
        let result = large_flags_row.row_write(&mut buffer, &mut offset, 1, &table_info);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Field flags value exceeds u16 range"));
    }
}
