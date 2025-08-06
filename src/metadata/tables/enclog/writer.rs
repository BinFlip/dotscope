//! Writer implementation for `EncLog` metadata table.
//!
//! This module provides the [`RowWritable`] trait implementation for the
//! [`EncLogRaw`] struct, enabling serialization of Edit-and-Continue log
//! entries back to binary format. This supports debugging scenario reconstruction
//! and metadata modification tracking for assemblies that have been edited
//! during debugging sessions.
//!
//! # Binary Format
//!
//! Each `EncLog` row consists of two fixed-size fields:
//! - `token_value` (4 bytes): Metadata token identifying the affected element
//! - `func_code` (4 bytes): Operation code (0=Create, 1=Update, 2=Delete)
//!
//! # Row Layout
//!
//! `EncLog` table rows are serialized with this binary structure:
//! - Token value (4 bytes, little-endian)
//! - Function code (4 bytes, little-endian)
//! - Total row size is always 8 bytes (fixed size table)
//!
//! # Edit-and-Continue Context
//!
//! The `EncLog` table tracks metadata modifications made during debugging sessions.
//! Each entry represents an operation (create/update/delete) performed on a specific
//! metadata element, enabling debuggers to understand what has changed since the
//! original assembly was compiled.
//!
//! # Architecture
//!
//! This implementation provides efficient serialization by writing data directly to the
//! target buffer without intermediate allocations. Since all fields are fixed-size
//! integers, no heap index calculations are required.
//!
//! The writer maintains strict compatibility with the [`crate::metadata::tables::enclog::reader`]
//! module, ensuring that data serialized by this writer can be correctly deserialized.

use crate::{
    metadata::tables::{
        enclog::EncLogRaw,
        types::{RowWritable, TableInfoRef},
    },
    utils::write_le_at,
    Result,
};

impl RowWritable for EncLogRaw {
    /// Write an `EncLog` table row to binary data
    ///
    /// Serializes one `EncLog` table entry to the metadata tables stream format.
    /// All fields are fixed-size 4-byte integers written in little-endian format.
    ///
    /// # Arguments
    /// * `data` - Target binary buffer for metadata tables stream
    /// * `offset` - Current write position (updated after writing)
    /// * `_rid` - Row identifier for this log entry (unused for `EncLog`)
    /// * `_sizes` - Table sizing information (unused for `EncLog`)
    ///
    /// # Returns
    /// * `Ok(())` - Successfully serialized Edit-and-Continue log entry
    /// * `Err(`[`crate::Error`]`)` - If buffer is too small or write fails
    ///
    /// # Binary Format
    /// Fields are written in the exact order specified by the ECMA-335 specification:
    /// 1. Token value (4 bytes, little-endian)
    /// 2. Function code (4 bytes, little-endian)
    fn row_write(
        &self,
        data: &mut [u8],
        offset: &mut usize,
        _rid: u32,
        _sizes: &TableInfoRef,
    ) -> Result<()> {
        // Write metadata token value
        write_le_at(data, offset, self.token_value)?;

        // Write operation function code
        write_le_at(data, offset, self.func_code)?;

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
        // Create test data for Edit-and-Continue log entry
        let original_row = EncLogRaw {
            rid: 1,
            token: Token::new(0x1E00_0001),
            offset: 0,
            token_value: 0x0602_0001, // MethodDef table, row 1
            func_code: 0,             // Create operation
        };

        let table_info = std::sync::Arc::new(TableInfo::new_test(
            &[(crate::metadata::tables::TableId::EncLog, 100)],
            false,
            false,
            false,
        ));

        // Calculate buffer size and serialize
        let row_size = <EncLogRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        original_row
            .row_write(&mut buffer, &mut offset, 1, &table_info)
            .expect("Serialization should succeed");

        // Deserialize and verify round-trip
        let mut read_offset = 0;
        let deserialized_row = EncLogRaw::row_read(&buffer, &mut read_offset, 1, &table_info)
            .expect("Deserialization should succeed");

        // Compare all fields
        assert_eq!(original_row.token_value, deserialized_row.token_value);
        assert_eq!(original_row.func_code, deserialized_row.func_code);
        assert_eq!(offset, row_size, "Offset should match expected row size");
        assert_eq!(
            read_offset, row_size,
            "Read offset should match expected row size"
        );
    }

    #[test]
    fn test_known_binary_format() {
        // Test with specific binary layout matching reader test
        let enclog_entry = EncLogRaw {
            rid: 1,
            token: Token::new(0x1E00_0001),
            offset: 0,
            token_value: 0x0602_0001, // MethodDef table, row 1
            func_code: 0,             // Create operation
        };

        let table_info = std::sync::Arc::new(TableInfo::new_test(
            &[(crate::metadata::tables::TableId::EncLog, 100)],
            false,
            false,
            false,
        ));

        let row_size = <EncLogRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        enclog_entry
            .row_write(&mut buffer, &mut offset, 1, &table_info)
            .expect("Serialization should succeed");

        // Verify the binary format matches expected layout
        assert_eq!(row_size, 8, "Row size should be 8 bytes");

        // Token value (0x06020001) as little-endian
        assert_eq!(buffer[0], 0x01);
        assert_eq!(buffer[1], 0x00);
        assert_eq!(buffer[2], 0x02);
        assert_eq!(buffer[3], 0x06);

        // Function code (0x00000000) as little-endian
        assert_eq!(buffer[4], 0x00);
        assert_eq!(buffer[5], 0x00);
        assert_eq!(buffer[6], 0x00);
        assert_eq!(buffer[7], 0x00);
    }

    #[test]
    fn test_different_operation_codes() {
        // Test all Edit-and-Continue operation types
        let test_cases = vec![("Create", 0), ("Update", 1), ("Delete", 2)];

        for (operation_name, func_code) in test_cases {
            let enclog_entry = EncLogRaw {
                rid: 1,
                token: Token::new(0x1E00_0001),
                offset: 0,
                token_value: 0x0200_0005, // TypeDef table, row 5
                func_code,
            };

            let table_info = std::sync::Arc::new(TableInfo::new_test(
                &[(crate::metadata::tables::TableId::EncLog, 100)],
                false,
                false,
                false,
            ));

            let row_size = <EncLogRaw as TableRow>::row_size(&table_info) as usize;
            let mut buffer = vec![0u8; row_size];
            let mut offset = 0;

            enclog_entry
                .row_write(&mut buffer, &mut offset, 1, &table_info)
                .unwrap_or_else(|_| panic!("Serialization should succeed for {operation_name}"));

            // Verify round-trip
            let mut read_offset = 0;
            let deserialized_row = EncLogRaw::row_read(&buffer, &mut read_offset, 1, &table_info)
                .unwrap_or_else(|_| panic!("Deserialization should succeed for {operation_name}"));

            assert_eq!(enclog_entry.token_value, deserialized_row.token_value);
            assert_eq!(
                enclog_entry.func_code, deserialized_row.func_code,
                "Function code mismatch for {operation_name}"
            );
        }
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
        ];

        for (token_type, token_value) in test_cases {
            let enclog_entry = EncLogRaw {
                rid: 1,
                token: Token::new(0x1E00_0001),
                offset: 0,
                token_value,
                func_code: 1, // Update operation
            };

            let table_info = std::sync::Arc::new(TableInfo::new_test(
                &[(crate::metadata::tables::TableId::EncLog, 100)],
                false,
                false,
                false,
            ));

            let row_size = <EncLogRaw as TableRow>::row_size(&table_info) as usize;
            let mut buffer = vec![0u8; row_size];
            let mut offset = 0;

            enclog_entry
                .row_write(&mut buffer, &mut offset, 1, &table_info)
                .unwrap_or_else(|_| panic!("Serialization should succeed for {token_type}"));

            // Verify round-trip
            let mut read_offset = 0;
            let deserialized_row = EncLogRaw::row_read(&buffer, &mut read_offset, 1, &table_info)
                .unwrap_or_else(|_| panic!("Deserialization should succeed for {token_type}"));

            assert_eq!(
                enclog_entry.token_value, deserialized_row.token_value,
                "Token value mismatch for {token_type}"
            );
            assert_eq!(enclog_entry.func_code, deserialized_row.func_code);
        }
    }

    #[test]
    fn test_multiple_entries() {
        // Test multiple Edit-and-Continue entries
        let entries = [
            EncLogRaw {
                rid: 1,
                token: Token::new(0x1E00_0001),
                offset: 0,
                token_value: 0x0600_0001, // MethodDef, row 1
                func_code: 0,             // Create
            },
            EncLogRaw {
                rid: 2,
                token: Token::new(0x1E00_0002),
                offset: 8,
                token_value: 0x0600_0001, // Same method
                func_code: 1,             // Update
            },
            EncLogRaw {
                rid: 3,
                token: Token::new(0x1E00_0003),
                offset: 16,
                token_value: 0x0400_0005, // Field, row 5
                func_code: 2,             // Delete
            },
        ];

        let table_info = std::sync::Arc::new(TableInfo::new_test(
            &[(crate::metadata::tables::TableId::EncLog, 100)],
            false,
            false,
            false,
        ));

        let row_size = <EncLogRaw as TableRow>::row_size(&table_info) as usize;
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
                EncLogRaw::row_read(&buffer, &mut read_offset, (i + 1) as u32, &table_info)
                    .expect("Deserialization should succeed");

            assert_eq!(original_entry.token_value, deserialized_row.token_value);
            assert_eq!(original_entry.func_code, deserialized_row.func_code);
        }
    }
}
