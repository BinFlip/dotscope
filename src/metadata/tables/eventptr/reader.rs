use crate::{
    metadata::{
        tables::{EventPtrRaw, RowReadable, TableId, TableInfoRef},
        token::Token,
    },
    utils::read_le_at_dyn,
    Result,
};

impl RowReadable for EventPtrRaw {
    /// Read an `EventPtr` row from the metadata tables stream
    ///
    /// Parses one `EventPtr` table row from the binary metadata stream, handling
    /// variable-size indexes based on table size information. Advances the offset
    /// to point to the next row after successful parsing.
    ///
    /// # Arguments
    ///
    /// * `data` - The metadata tables stream binary data
    /// * `offset` - Current position in the stream (updated after reading)
    /// * `rid` - Row identifier for this `EventPtr` entry (1-based)
    /// * `sizes` - Table size information for determining index sizes
    ///
    /// # Returns
    ///
    /// Returns a parsed [`EventPtrRaw`] instance with all fields populated
    /// from the binary data.
    ///
    /// # Errors
    ///
    /// - The data stream is truncated or corrupted
    /// - Event index values exceed expected ranges
    /// - Binary parsing encounters invalid data
    fn row_read(data: &[u8], offset: &mut usize, rid: u32, sizes: &TableInfoRef) -> Result<Self> {
        Ok(EventPtrRaw {
            rid,
            token: Token::new(0x1300_0000 + rid),
            offset: *offset,
            event: read_le_at_dyn(data, offset, sizes.is_large(TableId::Event))?,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::metadata::tables::{MetadataTable, TableId, TableInfo};

    #[test]
    fn crafted_short() {
        let data = vec![
            0x01, 0x01, // event (index into Event table)
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Event, 1)],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<EventPtrRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: EventPtrRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x13000001);
            assert_eq!(row.event, 0x0101);
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
            0x01, 0x01, 0x01, 0x01, // event (index into Event table)
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Event, u16::MAX as u32 + 3)],
            true,
            true,
            true,
        ));
        let table = MetadataTable::<EventPtrRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: EventPtrRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x13000001);
            assert_eq!(row.event, 0x01010101);
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
