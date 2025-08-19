//! Implementation of `RowWritable` for `PropertyMapRaw` metadata table entries.
//!
//! This module provides binary serialization support for the `PropertyMap` table (ID 0x15),
//! enabling writing of property ownership mapping back to .NET PE files. The PropertyMap table
//! establishes ownership relationships between types and their properties by defining contiguous
//! ranges in the Property table, enabling efficient enumeration of all properties declared by
//! a particular type.
//!
//! ## Table Structure (ECMA-335 §II.22.35)
//!
//! | Field | Type | Description |
//! |-------|------|-------------|
//! | `Parent` | TypeDef table index | Type that owns the properties |
//! | `PropertyList` | Property table index | First property owned by the parent type |
//!
//! ## Range Resolution
//!
//! PropertyMap entries define property ranges implicitly:
//! - Properties from `PropertyList\[i\]` to `PropertyList\[i+1\]`-1 belong to Parent\[i\]
//! - The final entry's range extends to the end of the Property table
//! - Empty ranges are valid and indicate types with no properties

use crate::{
    metadata::tables::{
        propertymap::PropertyMapRaw,
        types::{RowWritable, TableId, TableInfoRef},
    },
    utils::write_le_at_dyn,
    Result,
};

impl RowWritable for PropertyMapRaw {
    /// Serialize a PropertyMap table row to binary format
    ///
    /// Writes the row data according to ECMA-335 §II.22.35 specification:
    /// - `parent`: TypeDef table index (type that owns the properties)
    /// - `property_list`: Property table index (first property owned by the parent type)
    ///
    /// # Arguments
    /// * `data` - Target buffer for writing binary data
    /// * `offset` - Current write position (updated after write)
    /// * `rid` - Row identifier (unused in this implementation)
    /// * `sizes` - Table sizing information for index widths
    ///
    /// # Returns
    /// `Ok(())` on successful write, error on buffer overflow or encoding failure
    fn row_write(
        &self,
        data: &mut [u8],
        offset: &mut usize,
        _rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<()> {
        // Write TypeDef table index for parent
        write_le_at_dyn(data, offset, self.parent, sizes.is_large(TableId::TypeDef))?;

        // Write Property table index for property_list
        write_le_at_dyn(
            data,
            offset,
            self.property_list,
            sizes.is_large(TableId::Property),
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::metadata::tables::{
        propertymap::PropertyMapRaw,
        types::{RowReadable, RowWritable, TableId, TableInfo, TableRow},
    };
    use crate::metadata::token::Token;

    #[test]
    fn test_propertymap_row_size() {
        // Test with small tables
        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::TypeDef, 100), (TableId::Property, 50)],
            false,
            false,
            false,
        ));

        let expected_size = 2 + 2; // parent(2) + property_list(2)
        assert_eq!(
            <PropertyMapRaw as TableRow>::row_size(&sizes),
            expected_size
        );

        // Test with large tables
        let sizes_large = Arc::new(TableInfo::new_test(
            &[(TableId::TypeDef, 0x10000), (TableId::Property, 0x10000)],
            false,
            false,
            false,
        ));

        let expected_size_large = 4 + 4; // parent(4) + property_list(4)
        assert_eq!(
            <PropertyMapRaw as TableRow>::row_size(&sizes_large),
            expected_size_large
        );
    }

    #[test]
    fn test_propertymap_row_write_small() {
        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::TypeDef, 100), (TableId::Property, 50)],
            false,
            false,
            false,
        ));

        let property_map = PropertyMapRaw {
            rid: 1,
            token: Token::new(0x15000001),
            offset: 0,
            parent: 0x0101,
            property_list: 0x0202,
        };

        let mut buffer = vec![0u8; <PropertyMapRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;

        property_map
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        // Verify the written data
        let expected = vec![
            0x01, 0x01, // parent: 0x0101, little-endian
            0x02, 0x02, // property_list: 0x0202, little-endian
        ];

        assert_eq!(buffer, expected);
        assert_eq!(offset, expected.len());
    }

    #[test]
    fn test_propertymap_row_write_large() {
        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::TypeDef, 0x10000), (TableId::Property, 0x10000)],
            false,
            false,
            false,
        ));

        let property_map = PropertyMapRaw {
            rid: 1,
            token: Token::new(0x15000001),
            offset: 0,
            parent: 0x01010101,
            property_list: 0x02020202,
        };

        let mut buffer = vec![0u8; <PropertyMapRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;

        property_map
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        // Verify the written data
        let expected = vec![
            0x01, 0x01, 0x01, 0x01, // parent: 0x01010101, little-endian
            0x02, 0x02, 0x02, 0x02, // property_list: 0x02020202, little-endian
        ];

        assert_eq!(buffer, expected);
        assert_eq!(offset, expected.len());
    }

    #[test]
    fn test_propertymap_round_trip() {
        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::TypeDef, 100), (TableId::Property, 50)],
            false,
            false,
            false,
        ));

        let original = PropertyMapRaw {
            rid: 42,
            token: Token::new(0x1500002A),
            offset: 0,
            parent: 25,        // TypeDef index 25
            property_list: 10, // Property index 10
        };

        // Write to buffer
        let mut buffer = vec![0u8; <PropertyMapRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;
        original
            .row_write(&mut buffer, &mut offset, 42, &sizes)
            .unwrap();

        // Read back
        let mut read_offset = 0;
        let read_back = PropertyMapRaw::row_read(&buffer, &mut read_offset, 42, &sizes).unwrap();

        // Verify round-trip
        assert_eq!(original.rid, read_back.rid);
        assert_eq!(original.token, read_back.token);
        assert_eq!(original.parent, read_back.parent);
        assert_eq!(original.property_list, read_back.property_list);
    }

    #[test]
    fn test_propertymap_different_ranges() {
        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::TypeDef, 100), (TableId::Property, 50)],
            false,
            false,
            false,
        ));

        // Test different property range configurations
        let test_cases = vec![
            (1, 1),   // First type, first property
            (2, 5),   // Second type, starting at property 5
            (10, 15), // Mid-range type and properties
            (50, 30), // High type index, mid property range
            (1, 0),   // Type with no properties (property_list = 0)
        ];

        for (parent_index, property_start) in test_cases {
            let property_map = PropertyMapRaw {
                rid: 1,
                token: Token::new(0x15000001),
                offset: 0,
                parent: parent_index,
                property_list: property_start,
            };

            let mut buffer = vec![0u8; <PropertyMapRaw as TableRow>::row_size(&sizes) as usize];
            let mut offset = 0;
            property_map
                .row_write(&mut buffer, &mut offset, 1, &sizes)
                .unwrap();

            // Round-trip test
            let mut read_offset = 0;
            let read_back = PropertyMapRaw::row_read(&buffer, &mut read_offset, 1, &sizes).unwrap();

            assert_eq!(property_map.parent, read_back.parent);
            assert_eq!(property_map.property_list, read_back.property_list);
        }
    }

    #[test]
    fn test_propertymap_edge_cases() {
        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::TypeDef, 100), (TableId::Property, 50)],
            false,
            false,
            false,
        ));

        // Test with zero values
        let zero_map = PropertyMapRaw {
            rid: 1,
            token: Token::new(0x15000001),
            offset: 0,
            parent: 0,
            property_list: 0,
        };

        let mut buffer = vec![0u8; <PropertyMapRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;
        zero_map
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        let expected = vec![
            0x00, 0x00, // parent: 0
            0x00, 0x00, // property_list: 0
        ];

        assert_eq!(buffer, expected);

        // Test with maximum values for 2-byte indexes
        let max_map = PropertyMapRaw {
            rid: 1,
            token: Token::new(0x15000001),
            offset: 0,
            parent: 0xFFFF,
            property_list: 0xFFFF,
        };

        let mut buffer = vec![0u8; <PropertyMapRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;
        max_map
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        assert_eq!(buffer.len(), 4); // Both 2-byte fields
    }

    #[test]
    fn test_propertymap_sorted_order() {
        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::TypeDef, 100), (TableId::Property, 50)],
            false,
            false,
            false,
        ));

        // Test that PropertyMap entries can be written in sorted order by parent
        let entries = [
            (1, 1),  // Type 1, properties starting at 1
            (2, 5),  // Type 2, properties starting at 5
            (3, 10), // Type 3, properties starting at 10
            (5, 15), // Type 5, properties starting at 15 (Type 4 has no properties)
        ];

        for (i, (parent, property_start)) in entries.iter().enumerate() {
            let property_map = PropertyMapRaw {
                rid: i as u32 + 1,
                token: Token::new(0x15000001 + i as u32),
                offset: 0,
                parent: *parent,
                property_list: *property_start,
            };

            let mut buffer = vec![0u8; <PropertyMapRaw as TableRow>::row_size(&sizes) as usize];
            let mut offset = 0;
            property_map
                .row_write(&mut buffer, &mut offset, i as u32 + 1, &sizes)
                .unwrap();

            // Verify the parent is written correctly (should be in ascending order)
            let written_parent = u16::from_le_bytes([buffer[0], buffer[1]]);
            assert_eq!(written_parent as u32, *parent);

            let written_property_list = u16::from_le_bytes([buffer[2], buffer[3]]);
            assert_eq!(written_property_list as u32, *property_start);
        }
    }

    #[test]
    fn test_propertymap_property_ptr_compatibility() {
        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::TypeDef, 100), (TableId::Property, 50)],
            false,
            false,
            false,
        ));

        // Test scenarios that work with PropertyPtr indirection
        let property_ptr_cases = vec![
            (1, 1), // Direct property access
            (2, 3), // Property range with indirection
            (3, 8), // Larger property range
            (4, 0), // Type with no properties
        ];

        for (parent, property_start) in property_ptr_cases {
            let property_map = PropertyMapRaw {
                rid: 1,
                token: Token::new(0x15000001),
                offset: 0,
                parent,
                property_list: property_start,
            };

            let mut buffer = vec![0u8; <PropertyMapRaw as TableRow>::row_size(&sizes) as usize];
            let mut offset = 0;
            property_map
                .row_write(&mut buffer, &mut offset, 1, &sizes)
                .unwrap();

            // Verify round-trip works regardless of PropertyPtr usage
            let mut read_offset = 0;
            let read_back = PropertyMapRaw::row_read(&buffer, &mut read_offset, 1, &sizes).unwrap();

            assert_eq!(property_map.parent, read_back.parent);
            assert_eq!(property_map.property_list, read_back.property_list);
        }
    }

    #[test]
    fn test_propertymap_known_binary_format() {
        // Test with known binary data from reader tests
        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::TypeDef, 1), (TableId::Property, 1)],
            false,
            false,
            false,
        ));

        let property_map = PropertyMapRaw {
            rid: 1,
            token: Token::new(0x15000001),
            offset: 0,
            parent: 0x0101,
            property_list: 0x0202,
        };

        let mut buffer = vec![0u8; <PropertyMapRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;
        property_map
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        // Expected data based on reader test format
        let expected = vec![
            0x01, 0x01, // parent
            0x02, 0x02, // property_list
        ];

        assert_eq!(buffer, expected);
    }
}
