use crate::{
    metadata::{
        tables::{EventMapRaw, RowReadable, TableId, TableInfoRef},
        token::Token,
    },
    utils::read_le_at_dyn,
    Result,
};

impl RowReadable for EventMapRaw {
    /// Read an `EventMap` row from the metadata tables stream
    ///
    /// Parses one `EventMap` table row from the binary metadata stream, handling
    /// variable-size indexes based on table size information. Advances the offset
    /// to point to the next row after successful parsing.
    ///
    /// # Arguments
    ///
    /// * `data` - The metadata tables stream binary data
    /// * `offset` - Current position in the stream (updated after reading)
    /// * `rid` - Row identifier for this `EventMap` entry (1-based)
    /// * `sizes` - Table size information for determining index sizes
    ///
    /// # Returns
    ///
    /// Returns a parsed [`EventMapRaw`] instance with all fields populated
    /// from the binary data.
    ///
    /// # Errors
    ///
    /// - The data stream is truncated or corrupted
    /// - Index values exceed expected ranges
    /// - Binary parsing encounters invalid data
    fn row_read(data: &[u8], offset: &mut usize, rid: u32, sizes: &TableInfoRef) -> Result<Self> {
        let offset_org = *offset;

        let parent = read_le_at_dyn(data, offset, sizes.is_large(TableId::TypeDef))?;
        let event_list = read_le_at_dyn(data, offset, sizes.is_large(TableId::Event))?;

        Ok(EventMapRaw {
            rid,
            token: Token::new(0x1200_0000 + rid),
            offset: offset_org,
            parent,
            event_list,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::metadata::tables::{MetadataTable, TableId, TableInfo};

    use super::*;

    #[test]
    fn crafted_short() {
        let data = vec![
            0x01, 0x01, // parent
            0x02, 0x02, // event_list
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::TypeDef, 1), (TableId::Event, 1)],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<EventMapRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: EventMapRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x12000001);
            assert_eq!(row.parent, 0x0101);
            assert_eq!(row.event_list, 0x0202);
        };

        {
            for row in table.iter() {
                eval(row);
            }
        }

        {
            let row = table.get(1).unwrap();
            eval(row);
        }
    }

    #[test]
    fn crafted_long() {
        let data = vec![
            0x01, 0x01, 0x01, 0x01, // parent
            0x02, 0x02, 0x02, 0x02, // event_list
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::TypeDef, u16::MAX as u32 + 3),
                (TableId::Event, u16::MAX as u32 + 3),
            ],
            true,
            true,
            true,
        ));
        let table = MetadataTable::<EventMapRaw>::new(&data, u16::MAX as u32 + 3, sizes).unwrap();

        let eval = |row: EventMapRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x12000001);
            assert_eq!(row.parent, 0x01010101);
            assert_eq!(row.event_list, 0x02020202);
        };

        {
            for row in table.iter() {
                eval(row);
            }
        }

        {
            let row = table.get(1).unwrap();
            eval(row);
        }
    }
}
