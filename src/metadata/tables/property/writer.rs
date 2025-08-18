//! Implementation of `RowWritable` for `PropertyRaw` metadata table entries.
//!
//! This module provides binary serialization support for the `Property` table (ID 0x17),
//! enabling writing of property definition metadata back to .NET PE files. The Property table
//! defines properties exposed by types, including their names, signatures, and attributes.
//!
//! ## Table Structure (ECMA-335 §II.22.34)
//!
//! | Field | Type | Description |
//! |-------|------|-------------|
//! | `Flags` | `u16` | Property attributes bitmask |
//! | `Name` | String heap index | Property name identifier |
//! | `Type` | Blob heap index | Property signature (type, parameters for indexers) |
//!
//! ## Property Attributes
//!
//! The `Flags` field contains property attributes with common values:
//! - `0x0200` - `SpecialName` (property has special naming conventions)
//! - `0x0400` - `RTSpecialName` (runtime should verify name encoding)
//! - `0x1000` - `HasDefault` (property has a default value defined)

use crate::{
    metadata::tables::{
        property::PropertyRaw,
        types::{RowWritable, TableInfoRef},
    },
    utils::{write_le_at, write_le_at_dyn},
    Result,
};

impl RowWritable for PropertyRaw {
    /// Write a Property table row to binary data
    ///
    /// Serializes one Property table entry to the metadata tables stream format, handling
    /// variable-width heap indexes based on the table size information.
    ///
    /// # Field Serialization Order (ECMA-335)
    /// 1. `flags` - Property attributes as 2-byte little-endian value
    /// 2. `name` - String heap index (2 or 4 bytes)
    /// 3. `signature` - Blob heap index (2 or 4 bytes)
    ///
    /// # Arguments
    /// * `data` - Target binary buffer for metadata tables stream
    /// * `offset` - Current write position (updated after writing)
    /// * `rid` - Row identifier (unused for Property serialization)
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
            message: "Property flags value exceeds u16 range".to_string(),
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

        let size = <PropertyRaw as TableRow>::row_size(&table_info);
        // flags(2) + name(2) + signature(2) = 6
        assert_eq!(size, 6);

        // Test with large heaps
        let table_info_large = Arc::new(TableInfo::new_test(&[], true, true, false));

        let size_large = <PropertyRaw as TableRow>::row_size(&table_info_large);
        // flags(2) + name(4) + signature(4) = 10
        assert_eq!(size_large, 10);
    }

    #[test]
    fn test_round_trip_serialization() {
        // Create test data using same values as reader tests
        let original_row = PropertyRaw {
            rid: 1,
            token: Token::new(0x17000001),
            offset: 0,
            flags: 0x0101,
            name: 0x0202,
            signature: 0x0303,
        };

        // Create minimal table info for testing
        let table_info = Arc::new(TableInfo::new_test(&[], false, false, false));

        // Calculate buffer size and serialize
        let row_size = <PropertyRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        original_row
            .row_write(&mut buffer, &mut offset, 1, &table_info)
            .expect("Serialization should succeed");

        // Deserialize and verify round-trip
        let mut read_offset = 0;
        let deserialized_row = PropertyRaw::row_read(&buffer, &mut read_offset, 1, &table_info)
            .expect("Deserialization should succeed");

        assert_eq!(deserialized_row.rid, original_row.rid);
        assert_eq!(deserialized_row.flags, original_row.flags);
        assert_eq!(deserialized_row.name, original_row.name);
        assert_eq!(deserialized_row.signature, original_row.signature);
        assert_eq!(offset, row_size, "Offset should match expected row size");
    }

    #[test]
    fn test_known_binary_format_small_heap() {
        // Test with known binary data from reader tests
        let data = vec![
            0x01, 0x01, // flags (0x0101)
            0x02, 0x02, // name (0x0202)
            0x03, 0x03, // signature (0x0303)
        ];

        let table_info = Arc::new(TableInfo::new_test(&[], false, false, false));

        // First read the original data to get a reference row
        let mut read_offset = 0;
        let reference_row = PropertyRaw::row_read(&data, &mut read_offset, 1, &table_info)
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
    fn test_known_binary_format_large_heap() {
        // Test with known binary data from reader tests (large heap variant)
        let data = vec![
            0x01, 0x01, // flags (0x0101)
            0x02, 0x02, 0x02, 0x02, // name (0x02020202)
            0x03, 0x03, 0x03, 0x03, // signature (0x03030303)
        ];

        let table_info = Arc::new(TableInfo::new_test(&[], true, true, false));

        // First read the original data to get a reference row
        let mut read_offset = 0;
        let reference_row = PropertyRaw::row_read(&data, &mut read_offset, 1, &table_info)
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
    fn test_property_attributes() {
        // Test various property attribute combinations
        let test_cases = vec![
            (0x0000, "None"),
            (0x0200, "SpecialName"),
            (0x0400, "RTSpecialName"),
            (0x0600, "SpecialName|RTSpecialName"),
            (0x1000, "HasDefault"),
            (0x1200, "SpecialName|HasDefault"),
            (0x1400, "RTSpecialName|HasDefault"),
            (0x1600, "SpecialName|RTSpecialName|HasDefault"),
        ];

        let table_info = Arc::new(TableInfo::new_test(&[], false, false, false));

        for (flags, description) in test_cases {
            let property_row = PropertyRaw {
                rid: 1,
                token: Token::new(0x17000001),
                offset: 0,
                flags,
                name: 0x100,
                signature: 0x200,
            };

            let row_size = <PropertyRaw as TableRow>::row_size(&table_info) as usize;
            let mut buffer = vec![0u8; row_size];
            let mut offset = 0;

            property_row
                .row_write(&mut buffer, &mut offset, 1, &table_info)
                .unwrap_or_else(|_| panic!("Serialization should succeed for {description}"));

            // Verify round-trip
            let mut read_offset = 0;
            let deserialized_row = PropertyRaw::row_read(&buffer, &mut read_offset, 1, &table_info)
                .unwrap_or_else(|_| panic!("Deserialization should succeed for {description}"));

            assert_eq!(
                deserialized_row.flags, property_row.flags,
                "Flags should match for {description}"
            );
        }
    }

    #[test]
    fn test_large_heap_serialization() {
        // Test with large heaps to ensure 4-byte indexes are handled correctly
        let original_row = PropertyRaw {
            rid: 1,
            token: Token::new(0x17000001),
            offset: 0,
            flags: 0x1600, // Complex flags combination
            name: 0x123456,
            signature: 0x789ABC,
        };

        let table_info = Arc::new(TableInfo::new_test(&[], true, true, false));

        let row_size = <PropertyRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        original_row
            .row_write(&mut buffer, &mut offset, 1, &table_info)
            .expect("Large heap serialization should succeed");

        // Verify round-trip
        let mut read_offset = 0;
        let deserialized_row = PropertyRaw::row_read(&buffer, &mut read_offset, 1, &table_info)
            .expect("Large heap deserialization should succeed");

        assert_eq!(deserialized_row.flags, original_row.flags);
        assert_eq!(deserialized_row.name, original_row.name);
        assert_eq!(deserialized_row.signature, original_row.signature);
    }

    #[test]
    fn test_edge_cases() {
        // Test with zero values (unnamed property)
        let minimal_property = PropertyRaw {
            rid: 1,
            token: Token::new(0x17000001),
            offset: 0,
            flags: 0,     // No attributes
            name: 0,      // Unnamed (null string reference)
            signature: 0, // No signature (null blob reference)
        };

        let table_info = Arc::new(TableInfo::new_test(&[], false, false, false));

        let row_size = <PropertyRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        minimal_property
            .row_write(&mut buffer, &mut offset, 1, &table_info)
            .expect("Minimal property serialization should succeed");

        // Verify round-trip with zero values
        let mut read_offset = 0;
        let deserialized_row = PropertyRaw::row_read(&buffer, &mut read_offset, 1, &table_info)
            .expect("Minimal property deserialization should succeed");

        assert_eq!(deserialized_row.flags, minimal_property.flags);
        assert_eq!(deserialized_row.name, minimal_property.name);
        assert_eq!(deserialized_row.signature, minimal_property.signature);
    }

    #[test]
    fn test_flags_range_validation() {
        // Test that large flag values are properly rejected
        let large_flags_row = PropertyRaw {
            rid: 1,
            token: Token::new(0x17000001),
            offset: 0,
            flags: 0x12345678, // Large value that exceeds u16 range
            name: 0x100,
            signature: 0x200,
        };

        let table_info = Arc::new(TableInfo::new_test(&[], false, false, false));

        let row_size = <PropertyRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        // Should fail with range error
        let result = large_flags_row.row_write(&mut buffer, &mut offset, 1, &table_info);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Property flags value exceeds u16 range"));
    }

    #[test]
    fn test_different_heap_combinations() {
        // Test with different combinations of heap sizes
        let property_row = PropertyRaw {
            rid: 1,
            token: Token::new(0x17000001),
            offset: 0,
            flags: 0x1200, // SpecialName|HasDefault
            name: 0x8000,
            signature: 0x9000,
        };

        // Test combinations: (large_str, large_blob)
        let test_cases = vec![
            (false, false, 6), // small string, small blob: 2+2+2 = 6
            (true, false, 8),  // large string, small blob: 2+4+2 = 8
            (false, true, 8),  // small string, large blob: 2+2+4 = 8
            (true, true, 10),  // large string, large blob: 2+4+4 = 10
        ];

        for (large_str, large_blob, expected_size) in test_cases {
            let table_info = Arc::new(TableInfo::new_test(
                &[],
                large_str,
                large_blob,
                false, // guid heap size doesn't matter for property
            ));

            let size = <PropertyRaw as TableRow>::row_size(&table_info) as usize;
            assert_eq!(
                size, expected_size,
                "Row size should be {expected_size} for large_str={large_str}, large_blob={large_blob}"
            );

            let mut buffer = vec![0u8; size];
            let mut offset = 0;

            property_row
                .row_write(&mut buffer, &mut offset, 1, &table_info)
                .expect("Serialization should succeed");

            // Verify round-trip
            let mut read_offset = 0;
            let deserialized_row = PropertyRaw::row_read(&buffer, &mut read_offset, 1, &table_info)
                .expect("Deserialization should succeed");

            assert_eq!(deserialized_row.flags, property_row.flags);
            assert_eq!(deserialized_row.name, property_row.name);
            assert_eq!(deserialized_row.signature, property_row.signature);
        }
    }
}
