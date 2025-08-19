//! Writer implementation for `PropertyPtr` metadata table.
//!
//! This module provides the [`RowWritable`] trait implementation for the
//! [`PropertyPtrRaw`] struct, enabling serialization of property pointer metadata
//! rows back to binary format. This supports assembly modification scenarios
//! where property indirection tables need to be regenerated.
//!
//! # Binary Format
//!
//! Each `PropertyPtr` row consists of a single field:
//! - **Small indexes**: 2-byte table references (for tables with < 64K entries)  
//! - **Large indexes**: 4-byte table references (for larger tables)
//!
//! # Row Layout
//!
//! `PropertyPtr` table rows are serialized with this binary structure:
//! - `property` (2/4 bytes): Property table index for indirection
//!
//! # Architecture
//!
//! This implementation provides efficient serialization by writing data directly to the
//! target buffer without intermediate allocations. Index sizes are determined dynamically
//! based on the actual table sizes, matching the compression scheme used in .NET metadata.
//!
//! The writer maintains strict compatibility with the [`crate::metadata::tables::propertyptr::reader`]
//! module, ensuring that data serialized by this writer can be correctly deserialized.

use crate::{
    metadata::tables::{
        propertyptr::PropertyPtrRaw,
        types::{RowWritable, TableId, TableInfoRef},
    },
    utils::write_le_at_dyn,
    Result,
};

impl RowWritable for PropertyPtrRaw {
    /// Write a `PropertyPtr` table row to binary data
    ///
    /// Serializes one `PropertyPtr` table entry to the metadata tables stream format, handling
    /// variable-width table indexes based on the table size information.
    ///
    /// # Arguments
    /// * `data` - Target binary buffer for metadata tables stream
    /// * `offset` - Current write position (updated after writing)
    /// * `rid` - Row identifier for this property pointer entry (unused for `PropertyPtr`)
    /// * `sizes` - Table sizing information for writing table indexes
    ///
    /// # Returns
    /// * `Ok(())` - Successfully serialized property pointer row
    /// * `Err(`[`crate::Error`]`)` - If buffer is too small or write fails
    ///
    /// # Binary Format
    /// Fields are written in the exact order specified by ECMA-335:
    /// 1. Property table index (2/4 bytes, little-endian)
    fn row_write(
        &self,
        data: &mut [u8],
        offset: &mut usize,
        _rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<()> {
        // Write the single field
        write_le_at_dyn(
            data,
            offset,
            self.property,
            sizes.is_large(TableId::Property),
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
        let original_row = PropertyPtrRaw {
            rid: 1,
            token: Token::new(0x1600_0001),
            offset: 0,
            property: 42,
        };

        let table_info = std::sync::Arc::new(TableInfo::new_test(
            &[(TableId::Property, 1)],
            false,
            false,
            false,
        ));

        // Calculate buffer size and serialize
        let row_size = <PropertyPtrRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        original_row
            .row_write(&mut buffer, &mut offset, 1, &table_info)
            .expect("Serialization should succeed");

        // Deserialize and verify round-trip
        let mut read_offset = 0;
        let deserialized_row = PropertyPtrRaw::row_read(&buffer, &mut read_offset, 1, &table_info)
            .expect("Deserialization should succeed");

        // Compare all fields
        assert_eq!(original_row.property, deserialized_row.property);
        assert_eq!(offset, row_size, "Offset should match expected row size");
        assert_eq!(
            read_offset, row_size,
            "Read offset should match expected row size"
        );
    }

    #[test]
    fn test_round_trip_serialization_long() {
        // Create test data with large table indices
        let original_row = PropertyPtrRaw {
            rid: 2,
            token: Token::new(0x1600_0002),
            offset: 0,
            property: 0x1ABCD,
        };

        let table_info = std::sync::Arc::new(TableInfo::new_test(
            &[(TableId::Property, u16::MAX as u32 + 3)],
            false,
            false,
            false,
        ));

        // Calculate buffer size and serialize
        let row_size = <PropertyPtrRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        original_row
            .row_write(&mut buffer, &mut offset, 2, &table_info)
            .expect("Serialization should succeed");

        // Deserialize and verify round-trip
        let mut read_offset = 0;
        let deserialized_row = PropertyPtrRaw::row_read(&buffer, &mut read_offset, 2, &table_info)
            .expect("Deserialization should succeed");

        // Compare all fields
        assert_eq!(original_row.property, deserialized_row.property);
        assert_eq!(offset, row_size, "Offset should match expected row size");
        assert_eq!(
            read_offset, row_size,
            "Read offset should match expected row size"
        );
    }

    #[test]
    fn test_known_binary_format_short() {
        // Test with same data structure as reader tests for small indices
        let property_ptr = PropertyPtrRaw {
            rid: 1,
            token: Token::new(0x1600_0001),
            offset: 0,
            property: 42,
        };

        let table_info = std::sync::Arc::new(TableInfo::new_test(
            &[(TableId::Property, 1)], // Small Property table (2 byte indices)
            false,
            false,
            false,
        ));

        let row_size = <PropertyPtrRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        property_ptr
            .row_write(&mut buffer, &mut offset, 1, &table_info)
            .expect("Serialization should succeed");

        // Verify the binary format matches expected layout
        assert_eq!(row_size, 2, "Row size should be 2 bytes for small indices");
        assert_eq!(
            buffer[0], 42,
            "First byte should be property index (low byte)"
        );
        assert_eq!(
            buffer[1], 0,
            "Second byte should be property index (high byte)"
        );
    }

    #[test]
    fn test_known_binary_format_long() {
        // Test with same data structure as reader tests for large indices
        let property_ptr = PropertyPtrRaw {
            rid: 1,
            token: Token::new(0x1600_0001),
            offset: 0,
            property: 0x1ABCD,
        };

        let table_info = std::sync::Arc::new(TableInfo::new_test(
            &[(TableId::Property, u16::MAX as u32 + 3)], // Large Property table (4 byte indices)
            false,
            false,
            false,
        ));

        let row_size = <PropertyPtrRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        property_ptr
            .row_write(&mut buffer, &mut offset, 1, &table_info)
            .expect("Serialization should succeed");

        // Verify the binary format matches expected layout
        assert_eq!(row_size, 4, "Row size should be 4 bytes for large indices");
        assert_eq!(
            buffer[0], 0xCD,
            "First byte should be property index (byte 0)"
        );
        assert_eq!(
            buffer[1], 0xAB,
            "Second byte should be property index (byte 1)"
        );
        assert_eq!(
            buffer[2], 0x01,
            "Third byte should be property index (byte 2)"
        );
        assert_eq!(
            buffer[3], 0x00,
            "Fourth byte should be property index (byte 3)"
        );
    }
}
