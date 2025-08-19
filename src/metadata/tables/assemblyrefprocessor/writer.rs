//! Writer implementation for `AssemblyRefProcessor` metadata table.
//!
//! This module provides the [`RowWritable`] trait implementation for the
//! [`AssemblyRefProcessorRaw`] struct, enabling serialization of assembly reference processor targeting metadata
//! rows back to binary format. This supports assembly modification scenarios
//! where processor targeting information for external assembly references needs to be regenerated.
//!
//! # Binary Format
//!
//! Each `AssemblyRefProcessor` row consists of two fields:
//! - `processor` (4 bytes): Processor architecture identifier
//! - `assembly_ref` (2/4 bytes): AssemblyRef table index
//!
//! # Row Layout
//!
//! `AssemblyRefProcessor` table rows are serialized with this binary structure:
//! - First field is a fixed-size 4-byte little-endian integer
//! - Second field is a variable-size table index (2 or 4 bytes)
//! - Total row size varies based on AssemblyRef table size
//!
//! # Architecture
//!
//! This implementation provides efficient serialization by writing data directly to the
//! target buffer without intermediate allocations. Index sizes are determined dynamically
//! based on the actual table sizes, matching the compression scheme used in .NET metadata.
//!
//! The writer maintains strict compatibility with the [`crate::metadata::tables::assemblyrefprocessor::reader`]
//! module, ensuring that data serialized by this writer can be correctly deserialized.

use crate::{
    metadata::tables::{
        assemblyrefprocessor::AssemblyRefProcessorRaw,
        types::{RowWritable, TableId, TableInfoRef},
    },
    utils::{write_le_at, write_le_at_dyn},
    Result,
};

impl RowWritable for AssemblyRefProcessorRaw {
    /// Write a `AssemblyRefProcessor` table row to binary data
    ///
    /// Serializes one `AssemblyRefProcessor` table entry to the metadata tables stream format, handling
    /// variable-width table indexes based on the table size information.
    ///
    /// # Arguments
    /// * `data` - Target binary buffer for metadata tables stream
    /// * `offset` - Current write position (updated after writing)
    /// * `_rid` - Row identifier for this assembly ref processor entry (unused for `AssemblyRefProcessor`)
    /// * `sizes` - Table sizing information for writing table indexes
    ///
    /// # Returns
    /// * `Ok(())` - Successfully serialized assembly ref processor row
    /// * `Err(`[`crate::Error`]`)` - If buffer is too small or write fails
    ///
    /// # Binary Format
    /// Fields are written in the exact order specified by ECMA-335:
    /// 1. Processor ID (4 bytes, little-endian)
    /// 2. AssemblyRef table index (2/4 bytes, little-endian)
    fn row_write(
        &self,
        data: &mut [u8],
        offset: &mut usize,
        _rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<()> {
        // Write the fixed-size field
        write_le_at(data, offset, self.processor)?;

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
        metadata::tables::types::{RowReadable, TableInfo},
        metadata::tables::TableRow,
        metadata::token::Token,
    };

    #[test]
    fn test_round_trip_serialization_short() {
        // Create test data with small table indices
        let original_row = AssemblyRefProcessorRaw {
            rid: 1,
            token: Token::new(0x2400_0001),
            offset: 0,
            processor: 0x014C, // Intel 386 (x86)
            assembly_ref: 42,
        };

        let table_info = std::sync::Arc::new(TableInfo::new_test(
            &[(TableId::AssemblyRef, 1)],
            false,
            false,
            false,
        ));

        // Calculate buffer size and serialize
        let row_size = <AssemblyRefProcessorRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        original_row
            .row_write(&mut buffer, &mut offset, 1, &table_info)
            .expect("Serialization should succeed");

        // Deserialize and verify round-trip
        let mut read_offset = 0;
        let deserialized_row =
            AssemblyRefProcessorRaw::row_read(&buffer, &mut read_offset, 1, &table_info)
                .expect("Deserialization should succeed");

        // Compare all fields
        assert_eq!(original_row.processor, deserialized_row.processor);
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
        let original_row = AssemblyRefProcessorRaw {
            rid: 2,
            token: Token::new(0x2400_0002),
            offset: 0,
            processor: 0x8664, // AMD64 (x64)
            assembly_ref: 0x1ABCD,
        };

        let table_info = std::sync::Arc::new(TableInfo::new_test(
            &[(TableId::AssemblyRef, u16::MAX as u32 + 3)],
            false,
            false,
            false,
        ));

        // Calculate buffer size and serialize
        let row_size = <AssemblyRefProcessorRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        original_row
            .row_write(&mut buffer, &mut offset, 2, &table_info)
            .expect("Serialization should succeed");

        // Deserialize and verify round-trip
        let mut read_offset = 0;
        let deserialized_row =
            AssemblyRefProcessorRaw::row_read(&buffer, &mut read_offset, 2, &table_info)
                .expect("Deserialization should succeed");

        // Compare all fields
        assert_eq!(original_row.processor, deserialized_row.processor);
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
        let assembly_ref_processor = AssemblyRefProcessorRaw {
            rid: 1,
            token: Token::new(0x2400_0001),
            offset: 0,
            processor: 0x12345678,
            assembly_ref: 0x1234,
        };

        let table_info = std::sync::Arc::new(TableInfo::new_test(
            &[(TableId::AssemblyRef, 1)], // Small AssemblyRef table (2 byte indices)
            false,
            false,
            false,
        ));

        let row_size = <AssemblyRefProcessorRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        assembly_ref_processor
            .row_write(&mut buffer, &mut offset, 1, &table_info)
            .expect("Serialization should succeed");

        // Verify the binary format matches expected layout
        assert_eq!(row_size, 6, "Row size should be 6 bytes for small indices");

        // Processor ID (0x12345678) as little-endian
        assert_eq!(buffer[0], 0x78);
        assert_eq!(buffer[1], 0x56);
        assert_eq!(buffer[2], 0x34);
        assert_eq!(buffer[3], 0x12);

        // AssemblyRef index (0x1234) as little-endian (2 bytes)
        assert_eq!(buffer[4], 0x34);
        assert_eq!(buffer[5], 0x12);
    }

    #[test]
    fn test_known_binary_format_long() {
        // Test with specific binary layout for large indices
        let assembly_ref_processor = AssemblyRefProcessorRaw {
            rid: 1,
            token: Token::new(0x2400_0001),
            offset: 0,
            processor: 0x12345678,
            assembly_ref: 0x9ABCDEF0,
        };

        let table_info = std::sync::Arc::new(TableInfo::new_test(
            &[(TableId::AssemblyRef, u16::MAX as u32 + 3)], // Large AssemblyRef table (4 byte indices)
            false,
            false,
            false,
        ));

        let row_size = <AssemblyRefProcessorRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        assembly_ref_processor
            .row_write(&mut buffer, &mut offset, 1, &table_info)
            .expect("Serialization should succeed");

        // Verify the binary format matches expected layout
        assert_eq!(row_size, 8, "Row size should be 8 bytes for large indices");

        // Processor ID (0x12345678) as little-endian
        assert_eq!(buffer[0], 0x78);
        assert_eq!(buffer[1], 0x56);
        assert_eq!(buffer[2], 0x34);
        assert_eq!(buffer[3], 0x12);

        // AssemblyRef index (0x9ABCDEF0) as little-endian (4 bytes)
        assert_eq!(buffer[4], 0xF0);
        assert_eq!(buffer[5], 0xDE);
        assert_eq!(buffer[6], 0xBC);
        assert_eq!(buffer[7], 0x9A);
    }
}
