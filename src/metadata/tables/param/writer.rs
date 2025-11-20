//! Implementation of `RowWritable` for `ParamRaw` metadata table entries.
//!
//! This module provides binary serialization support for the `Param` table (ID 0x08),
//! enabling writing of method parameter metadata back to .NET PE files. The Param table
//! contains information about method parameters including their names, attributes,
//! sequence numbers, and marshalling details.
//!
//! ## Table Structure (ECMA-335 §II.22.33)
//!
//! | Field | Type | Description |
//! |-------|------|-------------|
//! | `Flags` | `u16` | Parameter attributes bitmask |
//! | `Sequence` | `u16` | Parameter sequence number (0 = return type, 1+ = parameters) |
//! | `Name` | String heap index | Parameter name identifier |
//!
//! ## Parameter Attributes
//!
//! The `Flags` field contains parameter attributes with common values:
//! - `0x0001` - `In` (input parameter)
//! - `0x0002` - `Out` (output parameter)
//! - `0x0010` - `Optional` (optional parameter with default value)
//! - `0x1000` - `HasDefault` (parameter has default value)
//! - `0x2000` - `HasFieldMarshal` (parameter has marshalling information)

use crate::{
    metadata::tables::{
        param::ParamRaw,
        types::{RowWritable, TableInfoRef},
    },
    utils::{write_le_at, write_le_at_dyn},
    Result,
};

impl RowWritable for ParamRaw {
    /// Write a Param table row to binary data
    ///
    /// Serializes one Param table entry to the metadata tables stream format, handling
    /// variable-width string heap indexes based on the table size information.
    ///
    /// # Field Serialization Order (ECMA-335)
    /// 1. `flags` - Parameter attributes as 2-byte little-endian value
    /// 2. `sequence` - Parameter sequence number as 2-byte little-endian value
    /// 3. `name` - String heap index (2 or 4 bytes)
    ///
    /// # Arguments
    /// * `data` - Target binary buffer for metadata tables stream
    /// * `offset` - Current write position (updated after writing)
    /// * `rid` - Row identifier (unused for Param serialization)
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
            message: "Parameter flags value exceeds u16 range".to_string(),
        })?;
        write_le_at(data, offset, flags_u16)?;

        // Write sequence (2 bytes) - convert from u32 to u16 with range check
        let sequence_u16 =
            u16::try_from(self.sequence).map_err(|_| crate::Error::WriteLayoutFailed {
                message: "Parameter sequence value exceeds u16 range".to_string(),
            })?;
        write_le_at(data, offset, sequence_u16)?;

        // Write name string heap index (2 or 4 bytes)
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
    use std::sync::Arc;

    #[test]
    fn test_row_size() {
        // Test with small string heap
        let table_info = Arc::new(TableInfo::new_test(&[], false, false, false));

        let size = <ParamRaw as TableRow>::row_size(&table_info);
        // flags(2) + sequence(2) + name(2) = 6
        assert_eq!(size, 6);

        // Test with large string heap
        let table_info_large = Arc::new(TableInfo::new_test(&[], true, false, false));

        let size_large = <ParamRaw as TableRow>::row_size(&table_info_large);
        // flags(2) + sequence(2) + name(4) = 8
        assert_eq!(size_large, 8);
    }

    #[test]
    fn test_round_trip_serialization() {
        // Create test data using same values as reader tests
        let original_row = ParamRaw {
            rid: 1,
            token: Token::new(0x08000001),
            offset: 0,
            flags: 0x0101,
            sequence: 0x0202,
            name: 0x0303,
        };

        // Create minimal table info for testing
        let table_info = Arc::new(TableInfo::new_test(&[], false, false, false));

        // Calculate buffer size and serialize
        let row_size = <ParamRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        original_row
            .row_write(&mut buffer, &mut offset, 1, &table_info)
            .expect("Serialization should succeed");

        // Deserialize and verify round-trip
        let mut read_offset = 0;
        let deserialized_row = ParamRaw::row_read(&buffer, &mut read_offset, 1, &table_info)
            .expect("Deserialization should succeed");

        assert_eq!(deserialized_row.rid, original_row.rid);
        assert_eq!(deserialized_row.flags, original_row.flags);
        assert_eq!(deserialized_row.sequence, original_row.sequence);
        assert_eq!(deserialized_row.name, original_row.name);
        assert_eq!(offset, row_size, "Offset should match expected row size");
    }

    #[test]
    fn test_known_binary_format_small_heap() {
        // Test with known binary data from reader tests
        let data = vec![
            0x01, 0x01, // flags (0x0101)
            0x02, 0x02, // sequence (0x0202)
            0x03, 0x03, // name (0x0303)
        ];

        let table_info = Arc::new(TableInfo::new_test(&[], false, false, false));

        // First read the original data to get a reference row
        let mut read_offset = 0;
        let reference_row = ParamRaw::row_read(&data, &mut read_offset, 1, &table_info)
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
            0x02, 0x02, // sequence (0x0202)
            0x03, 0x03, 0x03, 0x03, // name (0x03030303)
        ];

        let table_info = Arc::new(TableInfo::new_test(&[], true, false, false));

        // First read the original data to get a reference row
        let mut read_offset = 0;
        let reference_row = ParamRaw::row_read(&data, &mut read_offset, 1, &table_info)
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
    fn test_parameter_attributes() {
        // Test various parameter attribute combinations
        let test_cases = vec![
            (0x0000, "None"),
            (0x0001, "In"),
            (0x0002, "Out"),
            (0x0003, "In|Out"),
            (0x0010, "Optional"),
            (0x1000, "HasDefault"),
            (0x2000, "HasFieldMarshal"),
            (0x3011, "In|Optional|HasDefault|HasFieldMarshal"), // Combined flags
        ];

        let table_info = Arc::new(TableInfo::new_test(&[], false, false, false));

        for (flags, description) in test_cases {
            let param_row = ParamRaw {
                rid: 1,
                token: Token::new(0x08000001),
                offset: 0,
                flags,
                sequence: 1,
                name: 0x100,
            };

            let row_size = <ParamRaw as TableRow>::row_size(&table_info) as usize;
            let mut buffer = vec![0u8; row_size];
            let mut offset = 0;

            param_row
                .row_write(&mut buffer, &mut offset, 1, &table_info)
                .unwrap_or_else(|_| panic!("Serialization should succeed for {description}"));

            // Verify round-trip
            let mut read_offset = 0;
            let deserialized_row = ParamRaw::row_read(&buffer, &mut read_offset, 1, &table_info)
                .unwrap_or_else(|_| panic!("Deserialization should succeed for {description}"));

            assert_eq!(
                deserialized_row.flags, param_row.flags,
                "Flags should match for {description}"
            );
        }
    }

    #[test]
    fn test_sequence_numbers() {
        // Test various sequence number scenarios
        let test_cases = vec![
            (0, "Return type parameter"),
            (1, "First parameter"),
            (2, "Second parameter"),
            (10, "Tenth parameter"),
            (255, "Max 8-bit parameter"),
            (65535, "Max 16-bit parameter"),
        ];

        let table_info = Arc::new(TableInfo::new_test(&[], false, false, false));

        for (sequence, description) in test_cases {
            let param_row = ParamRaw {
                rid: 1,
                token: Token::new(0x08000001),
                offset: 0,
                flags: 0x0001, // In parameter
                sequence,
                name: 0x100,
            };

            let row_size = <ParamRaw as TableRow>::row_size(&table_info) as usize;
            let mut buffer = vec![0u8; row_size];
            let mut offset = 0;

            param_row
                .row_write(&mut buffer, &mut offset, 1, &table_info)
                .unwrap_or_else(|_| panic!("Serialization should succeed for {description}"));

            // Verify round-trip
            let mut read_offset = 0;
            let deserialized_row = ParamRaw::row_read(&buffer, &mut read_offset, 1, &table_info)
                .unwrap_or_else(|_| panic!("Deserialization should succeed for {description}"));

            assert_eq!(
                deserialized_row.sequence, param_row.sequence,
                "Sequence should match for {description}"
            );
        }
    }

    #[test]
    fn test_large_heap_serialization() {
        // Test with large string heap to ensure 4-byte indexes are handled correctly
        let original_row = ParamRaw {
            rid: 1,
            token: Token::new(0x08000001),
            offset: 0,
            flags: 0x3011, // Complex flags combination
            sequence: 255,
            name: 0x123456,
        };

        let table_info = Arc::new(TableInfo::new_test(&[], true, false, false));

        let row_size = <ParamRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        original_row
            .row_write(&mut buffer, &mut offset, 1, &table_info)
            .expect("Large heap serialization should succeed");

        // Verify round-trip
        let mut read_offset = 0;
        let deserialized_row = ParamRaw::row_read(&buffer, &mut read_offset, 1, &table_info)
            .expect("Large heap deserialization should succeed");

        assert_eq!(deserialized_row.flags, original_row.flags);
        assert_eq!(deserialized_row.sequence, original_row.sequence);
        assert_eq!(deserialized_row.name, original_row.name);
    }

    #[test]
    fn test_edge_cases() {
        // Test with zero values (unnamed parameter)
        let unnamed_param = ParamRaw {
            rid: 1,
            token: Token::new(0x08000001),
            offset: 0,
            flags: 0,    // No attributes
            sequence: 0, // Return type
            name: 0,     // Unnamed (null string reference)
        };

        let table_info = Arc::new(TableInfo::new_test(&[], false, false, false));

        let row_size = <ParamRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        unnamed_param
            .row_write(&mut buffer, &mut offset, 1, &table_info)
            .expect("Unnamed parameter serialization should succeed");

        // Verify round-trip with zero values
        let mut read_offset = 0;
        let deserialized_row = ParamRaw::row_read(&buffer, &mut read_offset, 1, &table_info)
            .expect("Unnamed parameter deserialization should succeed");

        assert_eq!(deserialized_row.flags, unnamed_param.flags);
        assert_eq!(deserialized_row.sequence, unnamed_param.sequence);
        assert_eq!(deserialized_row.name, unnamed_param.name);
    }

    #[test]
    fn test_flags_range_validation() {
        // Test that large flag values are properly rejected
        let large_flags_row = ParamRaw {
            rid: 1,
            token: Token::new(0x08000001),
            offset: 0,
            flags: 0x12345678,    // Large value that exceeds u16 range
            sequence: 0x87654321, // Large value that exceeds u16 range
            name: 0x100,
        };

        let table_info = Arc::new(TableInfo::new_test(&[], false, false, false));

        let row_size = <ParamRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        // Should fail with range error
        let result = large_flags_row.row_write(&mut buffer, &mut offset, 1, &table_info);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Parameter flags value exceeds u16 range"));
    }
}
