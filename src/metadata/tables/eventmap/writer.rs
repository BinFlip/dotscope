//! Implementation of `RowWritable` for `EventMapRaw` metadata table entries.
//!
//! This module provides binary serialization support for the `EventMap` table (ID 0x12),
//! enabling writing of event ownership mapping back to .NET PE files. The EventMap table
//! establishes ownership relationships between types and their events by defining contiguous
//! ranges in the Event table, enabling efficient enumeration of all events declared by
//! a particular type.
//!
//! ## Table Structure (ECMA-335 §II.22.12)
//!
//! | Field | Type | Description |
//! |-------|------|-------------|
//! | `Parent` | TypeDef table index | Type that owns the events |
//! | `EventList` | Event table index | First event owned by the parent type |
//!
//! ## Sorted Table Structure
//!
//! EventMap tables are sorted by Parent token for efficient binary search lookup.
//! This enables O(log n) lookup of events by owning type and efficient range-based
//! iteration through all events owned by a specific type.

use crate::{
    metadata::tables::{
        eventmap::EventMapRaw,
        types::{RowWritable, TableId, TableInfoRef},
    },
    utils::write_le_at_dyn,
    Result,
};

impl RowWritable for EventMapRaw {
    /// Serialize an EventMap table row to binary format
    ///
    /// Writes the row data according to ECMA-335 §II.22.12 specification:
    /// - `parent`: TypeDef table index (type that owns the events)
    /// - `event_list`: Event table index (first event owned by the parent type)
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

        // Write Event table index for event_list
        write_le_at_dyn(
            data,
            offset,
            self.event_list,
            sizes.is_large(TableId::Event),
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::metadata::tables::{
        eventmap::EventMapRaw,
        types::{RowReadable, RowWritable, TableId, TableInfo, TableRow},
    };
    use crate::metadata::token::Token;

    #[test]
    fn test_eventmap_row_size() {
        // Test with small tables
        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::TypeDef, 100), (TableId::Event, 50)],
            false,
            false,
            false,
        ));

        let expected_size = 2 + 2; // parent(2) + event_list(2)
        assert_eq!(<EventMapRaw as TableRow>::row_size(&sizes), expected_size);

        // Test with large tables
        let sizes_large = Arc::new(TableInfo::new_test(
            &[(TableId::TypeDef, 0x10000), (TableId::Event, 0x10000)],
            false,
            false,
            false,
        ));

        let expected_size_large = 4 + 4; // parent(4) + event_list(4)
        assert_eq!(
            <EventMapRaw as TableRow>::row_size(&sizes_large),
            expected_size_large
        );
    }

    #[test]
    fn test_eventmap_row_write_small() {
        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::TypeDef, 100), (TableId::Event, 50)],
            false,
            false,
            false,
        ));

        let event_map = EventMapRaw {
            rid: 1,
            token: Token::new(0x12000001),
            offset: 0,
            parent: 0x0101,
            event_list: 0x0202,
        };

        let mut buffer = vec![0u8; <EventMapRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;

        event_map
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        // Verify the written data
        let expected = vec![
            0x01, 0x01, // parent: 0x0101, little-endian
            0x02, 0x02, // event_list: 0x0202, little-endian
        ];

        assert_eq!(buffer, expected);
        assert_eq!(offset, expected.len());
    }

    #[test]
    fn test_eventmap_row_write_large() {
        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::TypeDef, 0x10000), (TableId::Event, 0x10000)],
            false,
            false,
            false,
        ));

        let event_map = EventMapRaw {
            rid: 1,
            token: Token::new(0x12000001),
            offset: 0,
            parent: 0x01010101,
            event_list: 0x02020202,
        };

        let mut buffer = vec![0u8; <EventMapRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;

        event_map
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        // Verify the written data
        let expected = vec![
            0x01, 0x01, 0x01, 0x01, // parent: 0x01010101, little-endian
            0x02, 0x02, 0x02, 0x02, // event_list: 0x02020202, little-endian
        ];

        assert_eq!(buffer, expected);
        assert_eq!(offset, expected.len());
    }

    #[test]
    fn test_eventmap_round_trip() {
        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::TypeDef, 100), (TableId::Event, 50)],
            false,
            false,
            false,
        ));

        let original = EventMapRaw {
            rid: 42,
            token: Token::new(0x1200002A),
            offset: 0,
            parent: 25,     // TypeDef index 25
            event_list: 10, // Event index 10
        };

        // Write to buffer
        let mut buffer = vec![0u8; <EventMapRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;
        original
            .row_write(&mut buffer, &mut offset, 42, &sizes)
            .unwrap();

        // Read back
        let mut read_offset = 0;
        let read_back = EventMapRaw::row_read(&buffer, &mut read_offset, 42, &sizes).unwrap();

        // Verify round-trip
        assert_eq!(original.rid, read_back.rid);
        assert_eq!(original.token, read_back.token);
        assert_eq!(original.parent, read_back.parent);
        assert_eq!(original.event_list, read_back.event_list);
    }

    #[test]
    fn test_eventmap_different_ranges() {
        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::TypeDef, 100), (TableId::Event, 50)],
            false,
            false,
            false,
        ));

        // Test different event range configurations
        let test_cases = vec![
            (1, 1),   // First type, first event
            (2, 5),   // Second type, starting at event 5
            (10, 15), // Mid-range type and events
            (50, 30), // High type index, mid event range
            (1, 0),   // Type with no events (event_list = 0)
        ];

        for (parent_index, event_start) in test_cases {
            let event_map = EventMapRaw {
                rid: 1,
                token: Token::new(0x12000001),
                offset: 0,
                parent: parent_index,
                event_list: event_start,
            };

            let mut buffer = vec![0u8; <EventMapRaw as TableRow>::row_size(&sizes) as usize];
            let mut offset = 0;
            event_map
                .row_write(&mut buffer, &mut offset, 1, &sizes)
                .unwrap();

            // Round-trip test
            let mut read_offset = 0;
            let read_back = EventMapRaw::row_read(&buffer, &mut read_offset, 1, &sizes).unwrap();

            assert_eq!(event_map.parent, read_back.parent);
            assert_eq!(event_map.event_list, read_back.event_list);
        }
    }

    #[test]
    fn test_eventmap_edge_cases() {
        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::TypeDef, 100), (TableId::Event, 50)],
            false,
            false,
            false,
        ));

        // Test with zero values
        let zero_map = EventMapRaw {
            rid: 1,
            token: Token::new(0x12000001),
            offset: 0,
            parent: 0,
            event_list: 0,
        };

        let mut buffer = vec![0u8; <EventMapRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;
        zero_map
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        let expected = vec![
            0x00, 0x00, // parent: 0
            0x00, 0x00, // event_list: 0
        ];

        assert_eq!(buffer, expected);

        // Test with maximum values for 2-byte indexes
        let max_map = EventMapRaw {
            rid: 1,
            token: Token::new(0x12000001),
            offset: 0,
            parent: 0xFFFF,
            event_list: 0xFFFF,
        };

        let mut buffer = vec![0u8; <EventMapRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;
        max_map
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        assert_eq!(buffer.len(), 4); // Both 2-byte fields
    }

    #[test]
    fn test_eventmap_sorted_order() {
        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::TypeDef, 100), (TableId::Event, 50)],
            false,
            false,
            false,
        ));

        // Test that EventMap entries can be written in sorted order by parent
        let entries = [
            (1, 1),  // Type 1, events starting at 1
            (2, 5),  // Type 2, events starting at 5
            (3, 10), // Type 3, events starting at 10
            (5, 15), // Type 5, events starting at 15 (Type 4 has no events)
        ];

        for (i, (parent, event_start)) in entries.iter().enumerate() {
            let event_map = EventMapRaw {
                rid: i as u32 + 1,
                token: Token::new(0x12000001 + i as u32),
                offset: 0,
                parent: *parent,
                event_list: *event_start,
            };

            let mut buffer = vec![0u8; <EventMapRaw as TableRow>::row_size(&sizes) as usize];
            let mut offset = 0;
            event_map
                .row_write(&mut buffer, &mut offset, i as u32 + 1, &sizes)
                .unwrap();

            // Verify the parent is written correctly (should be in ascending order)
            let written_parent = u16::from_le_bytes([buffer[0], buffer[1]]);
            assert_eq!(written_parent as u32, *parent);

            let written_event_list = u16::from_le_bytes([buffer[2], buffer[3]]);
            assert_eq!(written_event_list as u32, *event_start);
        }
    }

    #[test]
    fn test_eventmap_known_binary_format() {
        // Test with known binary data from reader tests
        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::TypeDef, 1), (TableId::Event, 1)],
            false,
            false,
            false,
        ));

        let event_map = EventMapRaw {
            rid: 1,
            token: Token::new(0x12000001),
            offset: 0,
            parent: 0x0101,
            event_list: 0x0202,
        };

        let mut buffer = vec![0u8; <EventMapRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;
        event_map
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        // Expected data based on reader test format
        let expected = vec![
            0x01, 0x01, // parent
            0x02, 0x02, // event_list
        ];

        assert_eq!(buffer, expected);
    }
}
