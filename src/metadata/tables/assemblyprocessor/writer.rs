//! Writer implementation for `AssemblyProcessor` metadata table.
//!
//! This module provides the [`RowWritable`] trait implementation for the
//! [`AssemblyProcessorRaw`] struct, enabling serialization of assembly processor targeting metadata
//! rows back to binary format. This supports assembly modification scenarios
//! where processor targeting information needs to be regenerated.
//!
//! # Binary Format
//!
//! Each `AssemblyProcessor` row consists of a single 4-byte field:
//! - `processor` (4 bytes): Processor architecture identifier
//!
//! # Row Layout
//!
//! `AssemblyProcessor` table rows are serialized with this binary structure:
//! - Single field is a fixed-size 4-byte little-endian integer
//! - Total row size is always 4 bytes
//!
//! # Architecture
//!
//! This implementation provides efficient serialization by writing data directly to the
//! target buffer without intermediate allocations. Since the field is a fixed-size integer,
//! no dynamic sizing is required.
//!
//! The writer maintains strict compatibility with the [`crate::metadata::tables::assemblyprocessor::reader`]
//! module, ensuring that data serialized by this writer can be correctly deserialized.

use crate::{
    metadata::tables::{
        assemblyprocessor::AssemblyProcessorRaw,
        types::{RowWritable, TableInfoRef},
    },
    utils::write_le_at,
    Result,
};

impl RowWritable for AssemblyProcessorRaw {
    /// Write a `AssemblyProcessor` table row to binary data
    ///
    /// Serializes one `AssemblyProcessor` table entry to the metadata tables stream format.
    /// The field is written as a 4-byte little-endian integer.
    ///
    /// # Arguments
    /// * `data` - Target binary buffer for metadata tables stream
    /// * `offset` - Current write position (updated after writing)
    /// * `_rid` - Row identifier for this assembly processor entry (unused for `AssemblyProcessor`)
    /// * `_sizes` - Table sizing information (unused for fixed-size table)
    ///
    /// # Returns
    /// * `Ok(())` - Successfully serialized assembly processor row
    /// * `Err(`[`crate::Error`]`)` - If buffer is too small or write fails
    ///
    /// # Binary Format
    /// Fields are written in the exact order specified by ECMA-335:
    /// 1. Processor ID (4 bytes, little-endian)
    fn row_write(
        &self,
        data: &mut [u8],
        offset: &mut usize,
        _rid: u32,
        _sizes: &TableInfoRef,
    ) -> Result<()> {
        // Write the single field as a 4-byte little-endian integer
        write_le_at(data, offset, self.processor)?;

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
        let original_row = AssemblyProcessorRaw {
            rid: 1,
            token: Token::new(0x2100_0001),
            offset: 0,
            processor: 0x12345678,
        };

        let table_info = std::sync::Arc::new(TableInfo::new_test(&[], false, false, false));

        // Calculate buffer size and serialize
        let row_size = <AssemblyProcessorRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        original_row
            .row_write(&mut buffer, &mut offset, 1, &table_info)
            .expect("Serialization should succeed");

        // Deserialize and verify round-trip
        let mut read_offset = 0;
        let deserialized_row =
            AssemblyProcessorRaw::row_read(&buffer, &mut read_offset, 1, &table_info)
                .expect("Deserialization should succeed");

        // Compare all fields
        assert_eq!(original_row.processor, deserialized_row.processor);
        assert_eq!(offset, row_size, "Offset should match expected row size");
        assert_eq!(
            read_offset, row_size,
            "Read offset should match expected row size"
        );
    }

    #[test]
    fn test_known_binary_format() {
        // Test with specific binary layout
        let assembly_processor = AssemblyProcessorRaw {
            rid: 1,
            token: Token::new(0x2100_0001),
            offset: 0,
            processor: 0xABCDEF01,
        };

        let table_info = std::sync::Arc::new(TableInfo::new_test(
            &[], // No table references
            false,
            false,
            false,
        ));

        let row_size = <AssemblyProcessorRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        assembly_processor
            .row_write(&mut buffer, &mut offset, 1, &table_info)
            .expect("Serialization should succeed");

        // Verify the binary format matches expected layout
        assert_eq!(row_size, 4, "Row size should be 4 bytes");

        // Processor ID (0xABCDEF01) as little-endian
        assert_eq!(buffer[0], 0x01);
        assert_eq!(buffer[1], 0xEF);
        assert_eq!(buffer[2], 0xCD);
        assert_eq!(buffer[3], 0xAB);
    }

    #[test]
    fn test_zero_value() {
        // Test with zero value
        let assembly_processor = AssemblyProcessorRaw {
            rid: 1,
            token: Token::new(0x2100_0001),
            offset: 0,
            processor: 0,
        };

        let table_info = std::sync::Arc::new(TableInfo::new_test(
            &[], // No table references
            false,
            false,
            false,
        ));

        let row_size = <AssemblyProcessorRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        assembly_processor
            .row_write(&mut buffer, &mut offset, 1, &table_info)
            .expect("Serialization should succeed");

        // Verify all bytes are zero
        assert_eq!(row_size, 4, "Row size should be 4 bytes");
        for &byte in &buffer {
            assert_eq!(byte, 0, "All bytes should be zero");
        }
    }
}
