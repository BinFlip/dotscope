//! Writer implementation for `AssemblyRefOS` metadata table.
//!
//! This module provides the [`RowWritable`] trait implementation for the
//! [`AssemblyRefOsRaw`] struct, enabling serialization of assembly reference OS targeting metadata
//! rows back to binary format. This supports assembly modification scenarios
//! where OS targeting information for external assembly references needs to be regenerated.
//!
//! # Binary Format
//!
//! Each `AssemblyRefOS` row consists of four fields:
//! - `os_platform_id` (4 bytes): Operating system platform identifier
//! - `os_major_version` (4 bytes): Major version number of the target OS
//! - `os_minor_version` (4 bytes): Minor version number of the target OS
//! - `assembly_ref` (2/4 bytes): AssemblyRef table index
//!
//! # Row Layout
//!
//! `AssemblyRefOS` table rows are serialized with this binary structure:
//! - First three fields are fixed-size 4-byte little-endian integers
//! - Last field is a variable-size table index (2 or 4 bytes)
//! - Total row size varies based on AssemblyRef table size
//!
//! # Architecture
//!
//! This implementation provides efficient serialization by writing data directly to the
//! target buffer without intermediate allocations. Index sizes are determined dynamically
//! based on the actual table sizes, matching the compression scheme used in .NET metadata.
//!
//! The writer maintains strict compatibility with the [`crate::metadata::tables::assemblyrefos::reader`]
//! module, ensuring that data serialized by this writer can be correctly deserialized.

use crate::{
    metadata::tables::{
        assemblyrefos::AssemblyRefOsRaw,
        types::{RowWritable, TableId, TableInfoRef},
    },
    utils::{write_le_at, write_le_at_dyn},
    Result,
};

impl RowWritable for AssemblyRefOsRaw {
    /// Write a `AssemblyRefOS` table row to binary data
    ///
    /// Serializes one `AssemblyRefOS` table entry to the metadata tables stream format, handling
    /// variable-width table indexes based on the table size information.
    ///
    /// # Arguments
    /// * `data` - Target binary buffer for metadata tables stream
    /// * `offset` - Current write position (updated after writing)
    /// * `_rid` - Row identifier for this assembly ref OS entry (unused for `AssemblyRefOS`)
    /// * `sizes` - Table sizing information for writing table indexes
    ///
    /// # Returns
    /// * `Ok(())` - Successfully serialized assembly ref OS row
    /// * `Err(`[`crate::Error`]`)` - If buffer is too small or write fails
    ///
    /// # Binary Format
    /// Fields are written in the exact order specified by ECMA-335:
    /// 1. OS Platform ID (4 bytes, little-endian)
    /// 2. OS Major Version (4 bytes, little-endian)
    /// 3. OS Minor Version (4 bytes, little-endian)
    /// 4. AssemblyRef table index (2/4 bytes, little-endian)
    fn row_write(
        &self,
        data: &mut [u8],
        offset: &mut usize,
        _rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<()> {
        // Write the three fixed-size fields
        write_le_at(data, offset, self.os_platform_id)?;
        write_le_at(data, offset, self.os_major_version)?;
        write_le_at(data, offset, self.os_minor_version)?;

        // Write the variable-size table index
        write_le_at_dyn(
            data,
            offset,
            self.assembly_ref,
            sizes.is_large(TableId::AssemblyRef),
        )?;

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
    fn test_round_trip_serialization_short() {
        // Create test data with small table indices
        let original_row = AssemblyRefOsRaw {
            rid: 1,
            token: Token::new(0x2500_0001),
            offset: 0,
            os_platform_id: 1,
            os_major_version: 10,
            os_minor_version: 5,
            assembly_ref: 42,
        };

        let table_info = std::sync::Arc::new(TableInfo::new_test(
            &[(TableId::AssemblyRef, 1)],
            false,
            false,
            false,
        ));

        // Calculate buffer size and serialize
        let row_size = <AssemblyRefOsRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        original_row
            .row_write(&mut buffer, &mut offset, 1, &table_info)
            .expect("Serialization should succeed");

        // Deserialize and verify round-trip
        let mut read_offset = 0;
        let deserialized_row =
            AssemblyRefOsRaw::row_read(&buffer, &mut read_offset, 1, &table_info)
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
        assert_eq!(original_row.assembly_ref, deserialized_row.assembly_ref);
        assert_eq!(offset, row_size, "Offset should match expected row size");
        assert_eq!(
            read_offset, row_size,
            "Read offset should match expected row size"
        );
    }

    #[test]
    fn test_round_trip_serialization_long() {
        // Create test data with large table indices
        let original_row = AssemblyRefOsRaw {
            rid: 2,
            token: Token::new(0x2500_0002),
            offset: 0,
            os_platform_id: 2,
            os_major_version: 6,
            os_minor_version: 3,
            assembly_ref: 0x1ABCD,
        };

        let table_info = std::sync::Arc::new(TableInfo::new_test(
            &[(TableId::AssemblyRef, u16::MAX as u32 + 3)],
            false,
            false,
            false,
        ));

        // Calculate buffer size and serialize
        let row_size = AssemblyRefOsRaw::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        original_row
            .row_write(&mut buffer, &mut offset, 2, &table_info)
            .expect("Serialization should succeed");

        // Deserialize and verify round-trip
        let mut read_offset = 0;
        let deserialized_row =
            AssemblyRefOsRaw::row_read(&buffer, &mut read_offset, 2, &table_info)
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
        assert_eq!(original_row.assembly_ref, deserialized_row.assembly_ref);
        assert_eq!(offset, row_size, "Offset should match expected row size");
        assert_eq!(
            read_offset, row_size,
            "Read offset should match expected row size"
        );
    }

    #[test]
    fn test_known_binary_format_short() {
        // Test with specific binary layout for small indices
        let assembly_ref_os = AssemblyRefOsRaw {
            rid: 1,
            token: Token::new(0x2500_0001),
            offset: 0,
            os_platform_id: 0x12345678,
            os_major_version: 0xABCDEF01,
            os_minor_version: 0x87654321,
            assembly_ref: 0x1234,
        };

        let table_info = std::sync::Arc::new(TableInfo::new_test(
            &[(TableId::AssemblyRef, 1)], // Small AssemblyRef table (2 byte indices)
            false,
            false,
            false,
        ));

        let row_size = AssemblyRefOsRaw::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        assembly_ref_os
            .row_write(&mut buffer, &mut offset, 1, &table_info)
            .expect("Serialization should succeed");

        // Verify the binary format matches expected layout
        assert_eq!(
            row_size, 14,
            "Row size should be 14 bytes for small indices"
        );

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

        // AssemblyRef index (0x1234) as little-endian (2 bytes)
        assert_eq!(buffer[12], 0x34);
        assert_eq!(buffer[13], 0x12);
    }

    #[test]
    fn test_known_binary_format_long() {
        // Test with specific binary layout for large indices
        let assembly_ref_os = AssemblyRefOsRaw {
            rid: 1,
            token: Token::new(0x2500_0001),
            offset: 0,
            os_platform_id: 0x12345678,
            os_major_version: 0xABCDEF01,
            os_minor_version: 0x87654321,
            assembly_ref: 0x9ABCDEF0,
        };

        let table_info = std::sync::Arc::new(TableInfo::new_test(
            &[(TableId::AssemblyRef, u16::MAX as u32 + 3)], // Large AssemblyRef table (4 byte indices)
            false,
            false,
            false,
        ));

        let row_size = AssemblyRefOsRaw::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        assembly_ref_os
            .row_write(&mut buffer, &mut offset, 1, &table_info)
            .expect("Serialization should succeed");

        // Verify the binary format matches expected layout
        assert_eq!(
            row_size, 16,
            "Row size should be 16 bytes for large indices"
        );

        // Fixed fields same as above...
        // OS Platform ID (0x12345678) as little-endian
        assert_eq!(buffer[0], 0x78);
        assert_eq!(buffer[1], 0x56);
        assert_eq!(buffer[2], 0x34);
        assert_eq!(buffer[3], 0x12);

        // AssemblyRef index (0x9ABCDEF0) as little-endian (4 bytes)
        assert_eq!(buffer[12], 0xF0);
        assert_eq!(buffer[13], 0xDE);
        assert_eq!(buffer[14], 0xBC);
        assert_eq!(buffer[15], 0x9A);
    }
}
