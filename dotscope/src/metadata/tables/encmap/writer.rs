//! Writer implementation for `EncMap` metadata table.
//!
//! This module provides the [`RowWritable`] trait implementation for the
//! [`EncMapRaw`] struct, enabling serialization of Edit-and-Continue token
//! mapping entries back to binary format. This supports debugging scenario
//! reconstruction and token correlation for assemblies that have been modified
//! during debugging sessions.
//!
//! # Binary Format
//!
//! Each `EncMap` row consists of a single fixed-size field:
//! - `original_token` (4 bytes): Original metadata token before editing
//!
//! # Row Layout
//!
//! `EncMap` table rows are serialized with this binary structure:
//! - Original token value (4 bytes, little-endian)
//! - Total row size is always 4 bytes (fixed size table)
//!
//! # Edit-and-Continue Context
//!
//! The `EncMap` table provides token mapping during Edit-and-Continue operations.
//! Each entry preserves the original token value before code modifications,
//! enabling debuggers to correlate pre-edit and post-edit metadata elements
//! through table position indexing.
//!
//! # Architecture
//!
//! This implementation provides efficient serialization by writing data directly to the
//! target buffer without intermediate allocations. Since the only field is a fixed-size
//! token value, no heap index calculations are required.
//!
//! The writer maintains strict compatibility with the [`crate::metadata::tables::encmap::reader`]
//! module, ensuring that data serialized by this writer can be correctly deserialized.

use crate::{
    metadata::tables::{
        encmap::EncMapRaw,
        types::{RowWritable, TableInfoRef},
    },
    utils::write_le_at,
    Result,
};

impl RowWritable for EncMapRaw {
    /// Write an `EncMap` table row to binary data
    ///
    /// Serializes one `EncMap` table entry to the metadata tables stream format.
    /// The single field is a fixed-size 4-byte token written in little-endian format.
    ///
    /// # Arguments
    /// * `data` - Target binary buffer for metadata tables stream
    /// * `offset` - Current write position (updated after writing)
    /// * `_rid` - Row identifier for this mapping entry (unused for `EncMap`)
    /// * `_sizes` - Table sizing information (unused for `EncMap`)
    ///
    /// # Returns
    /// * `Ok(())` - Successfully serialized Edit-and-Continue mapping entry
    /// * `Err(`[`crate::Error`]`)` - If buffer is too small or write fails
    ///
    /// # Binary Format
    /// Fields are written in the exact order specified by the ECMA-335 specification:
    /// 1. Original token value (4 bytes, little-endian)
    fn row_write(
        &self,
        data: &mut [u8],
        offset: &mut usize,
        _rid: u32,
        _sizes: &TableInfoRef,
    ) -> Result<()> {
        // Write original metadata token value
        write_le_at(data, offset, self.original_token.value())?;

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
    fn test_round_trip_serialization() {
        // Create test data for Edit-and-Continue mapping entry
        let original_row = EncMapRaw {
            rid: 1,
            token: Token::new(0x1F00_0001),
            offset: 0,
            original_token: Token::new(0x0602_0001), // MethodDef table, row 1
        };

        let table_info = std::sync::Arc::new(TableInfo::new_test(
            &[(crate::metadata::tables::TableId::EncMap, 100)],
            false,
            false,
            false,
        ));

        // Calculate buffer size and serialize
        let row_size = <EncMapRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        original_row
            .row_write(&mut buffer, &mut offset, 1, &table_info)
            .expect("Serialization should succeed");

        // Deserialize and verify round-trip
        let mut read_offset = 0;
        let deserialized_row = EncMapRaw::row_read(&buffer, &mut read_offset, 1, &table_info)
            .expect("Deserialization should succeed");

        // Compare all fields
        assert_eq!(
            original_row.original_token.value(),
            deserialized_row.original_token.value()
        );
        assert_eq!(offset, row_size, "Offset should match expected row size");
        assert_eq!(
            read_offset, row_size,
            "Read offset should match expected row size"
        );
    }

    #[test]
    fn test_known_binary_format() {
        // Test with specific binary layout matching reader test
        let encmap_entry = EncMapRaw {
            rid: 1,
            token: Token::new(0x1F00_0001),
            offset: 0,
            original_token: Token::new(0x0602_0001), // MethodDef table, row 1
        };

        let table_info = std::sync::Arc::new(TableInfo::new_test(
            &[(crate::metadata::tables::TableId::EncMap, 100)],
            false,
            false,
            false,
        ));

        let row_size = <EncMapRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        encmap_entry
            .row_write(&mut buffer, &mut offset, 1, &table_info)
            .expect("Serialization should succeed");

        // Verify the binary format matches expected layout
        assert_eq!(row_size, 4, "Row size should be 4 bytes");

        // Original token (0x06020001) as little-endian
        assert_eq!(buffer[0], 0x01);
        assert_eq!(buffer[1], 0x00);
        assert_eq!(buffer[2], 0x02);
        assert_eq!(buffer[3], 0x06);
    }

    #[test]
    fn test_various_token_types() {
        // Test with different metadata token types
        let test_cases = vec![
            ("TypeDef", 0x0200_0001),   // TypeDef table
            ("MethodDef", 0x0600_0010), // MethodDef table
            ("Field", 0x0400_0025),     // Field table
            ("Property", 0x1700_0003),  // Property table
            ("Event", 0x1400_0007),     // Event table
            ("Assembly", 0x2000_0001),  // Assembly table
            ("Module", 0x0000_0001),    // Module table
        ];

        for (token_type, token_value) in test_cases {
            let encmap_entry = EncMapRaw {
                rid: 1,
                token: Token::new(0x1F00_0001),
                offset: 0,
                original_token: Token::new(token_value),
            };

            let table_info = std::sync::Arc::new(TableInfo::new_test(
                &[(crate::metadata::tables::TableId::EncMap, 100)],
                false,
                false,
                false,
            ));

            let row_size = <EncMapRaw as TableRow>::row_size(&table_info) as usize;
            let mut buffer = vec![0u8; row_size];
            let mut offset = 0;

            encmap_entry
                .row_write(&mut buffer, &mut offset, 1, &table_info)
                .unwrap_or_else(|_| panic!("Serialization should succeed for {token_type}"));

            // Verify round-trip
            let mut read_offset = 0;
            let deserialized_row = EncMapRaw::row_read(&buffer, &mut read_offset, 1, &table_info)
                .unwrap_or_else(|_| panic!("Deserialization should succeed for {token_type}"));

            assert_eq!(
                encmap_entry.original_token.value(),
                deserialized_row.original_token.value(),
                "Token value mismatch for {token_type}"
            );
        }
    }

    #[test]
    fn test_multiple_token_mappings() {
        // Test multiple token mapping entries
        let entries = [
            EncMapRaw {
                rid: 1,
                token: Token::new(0x1F00_0001),
                offset: 0,
                original_token: Token::new(0x0600_0001), // MethodDef, row 1
            },
            EncMapRaw {
                rid: 2,
                token: Token::new(0x1F00_0002),
                offset: 4,
                original_token: Token::new(0x0200_0005), // TypeDef, row 5
            },
            EncMapRaw {
                rid: 3,
                token: Token::new(0x1F00_0003),
                offset: 8,
                original_token: Token::new(0x0400_0010), // Field, row 16
            },
        ];

        let table_info = std::sync::Arc::new(TableInfo::new_test(
            &[(crate::metadata::tables::TableId::EncMap, 100)],
            false,
            false,
            false,
        ));

        let row_size = <EncMapRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size * entries.len()];
        let mut offset = 0;

        // Serialize all entries
        for (i, entry) in entries.iter().enumerate() {
            entry
                .row_write(&mut buffer, &mut offset, (i + 1) as u32, &table_info)
                .expect("Serialization should succeed");
        }

        // Verify all entries can be read back
        let mut read_offset = 0;
        for (i, original_entry) in entries.iter().enumerate() {
            let deserialized_row =
                EncMapRaw::row_read(&buffer, &mut read_offset, (i + 1) as u32, &table_info)
                    .expect("Deserialization should succeed");

            assert_eq!(
                original_entry.original_token.value(),
                deserialized_row.original_token.value()
            );
        }
    }

    #[test]
    fn test_edge_case_tokens() {
        // Test edge case token values
        let test_cases = vec![
            ("Minimum token", 0x0000_0001), // Smallest valid token
            ("Maximum row", 0x00FF_FFFF),   // Maximum row value
            ("High table ID", 0xFF00_0001), // High table ID value
        ];

        for (description, token_value) in test_cases {
            let encmap_entry = EncMapRaw {
                rid: 1,
                token: Token::new(0x1F00_0001),
                offset: 0,
                original_token: Token::new(token_value),
            };

            let table_info = std::sync::Arc::new(TableInfo::new_test(
                &[(crate::metadata::tables::TableId::EncMap, 100)],
                false,
                false,
                false,
            ));

            let row_size = <EncMapRaw as TableRow>::row_size(&table_info) as usize;
            let mut buffer = vec![0u8; row_size];
            let mut offset = 0;

            encmap_entry
                .row_write(&mut buffer, &mut offset, 1, &table_info)
                .unwrap_or_else(|_| panic!("Serialization should succeed for {description}"));

            // Verify round-trip
            let mut read_offset = 0;
            let deserialized_row = EncMapRaw::row_read(&buffer, &mut read_offset, 1, &table_info)
                .unwrap_or_else(|_| panic!("Deserialization should succeed for {description}"));

            assert_eq!(
                encmap_entry.original_token.value(),
                deserialized_row.original_token.value(),
                "Token value mismatch for {description}"
            );
        }
    }

    #[test]
    fn test_sequential_mappings() {
        // Test sequential token mappings as would occur in real Edit-and-Continue scenarios
        let base_tokens = [
            0x0600_0001, // MethodDef 1
            0x0600_0002, // MethodDef 2
            0x0600_0003, // MethodDef 3
            0x0200_0001, // TypeDef 1
            0x0400_0001, // Field 1
        ];

        for (i, &token_value) in base_tokens.iter().enumerate() {
            let encmap_entry = EncMapRaw {
                rid: (i + 1) as u32,
                token: Token::new(0x1F00_0000 | ((i + 1) as u32)),
                offset: i * 4,
                original_token: Token::new(token_value),
            };

            let table_info = std::sync::Arc::new(TableInfo::new_test(
                &[(crate::metadata::tables::TableId::EncMap, 100)],
                false,
                false,
                false,
            ));

            let row_size = <EncMapRaw as TableRow>::row_size(&table_info) as usize;
            let mut buffer = vec![0u8; row_size];
            let mut offset = 0;

            encmap_entry
                .row_write(&mut buffer, &mut offset, (i + 1) as u32, &table_info)
                .expect("Serialization should succeed");

            // Verify round-trip
            let mut read_offset = 0;
            let deserialized_row =
                EncMapRaw::row_read(&buffer, &mut read_offset, (i + 1) as u32, &table_info)
                    .expect("Deserialization should succeed");

            assert_eq!(
                encmap_entry.original_token.value(),
                deserialized_row.original_token.value()
            );
        }
    }
}
