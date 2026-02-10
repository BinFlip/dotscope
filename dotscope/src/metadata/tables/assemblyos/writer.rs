//! Writer implementation for `AssemblyOS` metadata table.
//!
//! This module provides the [`RowWritable`] trait implementation for the
//! [`AssemblyOsRaw`] struct, enabling serialization of assembly OS targeting metadata
//! rows back to binary format. This supports assembly modification scenarios
//! where OS targeting information needs to be regenerated.
//!
//! # Binary Format
//!
//! Each `AssemblyOS` row consists of three 4-byte fields:
//! - `os_platform_id` (4 bytes): Operating system platform identifier
//! - `os_major_version` (4 bytes): Major version number of the target OS
//! - `os_minor_version` (4 bytes): Minor version number of the target OS
//!
//! # Row Layout
//!
//! `AssemblyOS` table rows are serialized with this binary structure:
//! - All fields are fixed-size 4-byte little-endian integers
//! - Total row size is always 12 bytes
//!
//! # Architecture
//!
//! This implementation provides efficient serialization by writing data directly to the
//! target buffer without intermediate allocations. Since all fields are fixed-size integers,
//! no dynamic sizing is required.
//!
//! The writer maintains strict compatibility with the [`crate::metadata::tables::assemblyos::reader`]
//! module, ensuring that data serialized by this writer can be correctly deserialized.

use crate::{
    metadata::tables::{
        assemblyos::AssemblyOsRaw,
        types::{RowWritable, TableInfoRef},
    },
    utils::write_le_at,
    Result,
};

impl RowWritable for AssemblyOsRaw {
    /// Write a `AssemblyOS` table row to binary data
    ///
    /// Serializes one `AssemblyOS` table entry to the metadata tables stream format.
    /// All fields are written as 4-byte little-endian integers.
    ///
    /// # Arguments
    /// * `data` - Target binary buffer for metadata tables stream
    /// * `offset` - Current write position (updated after writing)
    /// * `_rid` - Row identifier for this assembly OS entry (unused for `AssemblyOS`)
    /// * `_sizes` - Table sizing information (unused for fixed-size table)
    ///
    /// # Returns
    /// * `Ok(())` - Successfully serialized assembly OS row
    /// * `Err(`[`crate::Error`]`)` - If buffer is too small or write fails
    ///
    /// # Binary Format
    /// Fields are written in the exact order specified by ECMA-335:
    /// 1. OS Platform ID (4 bytes, little-endian)
    /// 2. OS Major Version (4 bytes, little-endian)
    /// 3. OS Minor Version (4 bytes, little-endian)
    fn row_write(
        &self,
        data: &mut [u8],
        offset: &mut usize,
        _rid: u32,
        _sizes: &TableInfoRef,
    ) -> Result<()> {
        // Write all three fields as 4-byte little-endian integers
        write_le_at(data, offset, self.os_platform_id)?;
        write_le_at(data, offset, self.os_major_version)?;
        write_le_at(data, offset, self.os_minor_version)?;

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
        // Create test data
        let original_row = AssemblyOsRaw {
            rid: 1,
            token: Token::new(0x2200_0001),
            offset: 0,
            os_platform_id: 0x12345678,
            os_major_version: 10,
            os_minor_version: 5,
        };

        let table_info = std::sync::Arc::new(TableInfo::new_test(&[], false, false, false));

        // Calculate buffer size and serialize
        let row_size = AssemblyOsRaw::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        original_row
            .row_write(&mut buffer, &mut offset, 1, &table_info)
            .expect("Serialization should succeed");

        // Deserialize and verify round-trip
        let mut read_offset = 0;
        let deserialized_row = AssemblyOsRaw::row_read(&buffer, &mut read_offset, 1, &table_info)
            .expect("Deserialization should succeed");

        // Compare all fields
        assert_eq!(original_row.os_platform_id, deserialized_row.os_platform_id);
        assert_eq!(
            original_row.os_major_version,
            deserialized_row.os_major_version
        );
        assert_eq!(
            original_row.os_minor_version,
            deserialized_row.os_minor_version
        );
        assert_eq!(offset, row_size, "Offset should match expected row size");
        assert_eq!(
            read_offset, row_size,
            "Read offset should match expected row size"
        );
    }

    #[test]
    fn test_known_binary_format() {
        // Test with specific binary layout
        let assembly_os = AssemblyOsRaw {
            rid: 1,
            token: Token::new(0x2200_0001),
            offset: 0,
            os_platform_id: 0x12345678,
            os_major_version: 0xABCDEF01,
            os_minor_version: 0x87654321,
        };

        let table_info = std::sync::Arc::new(TableInfo::new_test(
            &[], // No table references
            false,
            false,
            false,
        ));

        let row_size = AssemblyOsRaw::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        assembly_os
            .row_write(&mut buffer, &mut offset, 1, &table_info)
            .expect("Serialization should succeed");

        // Verify the binary format matches expected layout
        assert_eq!(row_size, 12, "Row size should be 12 bytes");

        // OS Platform ID (0x12345678) as little-endian
        assert_eq!(buffer[0], 0x78);
        assert_eq!(buffer[1], 0x56);
        assert_eq!(buffer[2], 0x34);
        assert_eq!(buffer[3], 0x12);

        // OS Major Version (0xABCDEF01) as little-endian
        assert_eq!(buffer[4], 0x01);
        assert_eq!(buffer[5], 0xEF);
        assert_eq!(buffer[6], 0xCD);
        assert_eq!(buffer[7], 0xAB);

        // OS Minor Version (0x87654321) as little-endian
        assert_eq!(buffer[8], 0x21);
        assert_eq!(buffer[9], 0x43);
        assert_eq!(buffer[10], 0x65);
        assert_eq!(buffer[11], 0x87);
    }

    #[test]
    fn test_zero_values() {
        // Test with zero values
        let assembly_os = AssemblyOsRaw {
            rid: 1,
            token: Token::new(0x2200_0001),
            offset: 0,
            os_platform_id: 0,
            os_major_version: 0,
            os_minor_version: 0,
        };

        let table_info = std::sync::Arc::new(TableInfo::new_test(
            &[], // No table references
            false,
            false,
            false,
        ));

        let row_size = AssemblyOsRaw::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        assembly_os
            .row_write(&mut buffer, &mut offset, 1, &table_info)
            .expect("Serialization should succeed");

        // Verify all bytes are zero
        assert_eq!(row_size, 12, "Row size should be 12 bytes");
        for &byte in &buffer {
            assert_eq!(byte, 0, "All bytes should be zero");
        }
    }
}
