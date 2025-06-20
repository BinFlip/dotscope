use crate::{
    file::io::read_le_at_dyn,
    metadata::{
        tables::{PropertyPtrRaw, RowReadable, TableId, TableInfoRef},
        token::Token,
    },
    Result,
};

impl RowReadable for PropertyPtrRaw {
    /// Calculates the byte size of a `PropertyPtr` table row.
    ///
    /// The row size depends on the Property table size:
    /// - 2 bytes if Property table has ≤ 65535 rows
    /// - 4 bytes if Property table has > 65535 rows
    ///
    /// ## Arguments
    ///
    /// * `sizes` - Table size information for index size calculation
    ///
    /// ## Returns
    ///
    /// The size in bytes required for a single `PropertyPtr` table row
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* property */ sizes.table_index_bytes(TableId::Property)
        )
    }

    /// Reads a `PropertyPtr` table row from the metadata stream.
    ///
    /// Parses a single `PropertyPtr` entry from the raw metadata bytes,
    /// extracting the property index and constructing the complete
    /// table entry with metadata token and offset information.
    ///
    /// ## Arguments
    ///
    /// * `data` - The raw metadata bytes containing the table
    /// * `offset` - Current read position (updated after reading)
    /// * `rid` - The 1-based row identifier for this entry
    /// * `sizes` - Table size information for proper index parsing
    ///
    /// ## Returns
    ///
    /// * `Ok(PropertyPtrRaw)` - Successfully parsed table entry
    /// * `Err(_)` - Parsing failed due to insufficient data or corruption
    ///
    /// ## Errors
    ///
    /// * [`crate::error::Error::OutOfBounds`] - Insufficient data for complete entry
    /// * [`crate::error::Error::Malformed`] - Malformed table entry structure
    fn row_read(data: &[u8], offset: &mut usize, rid: u32, sizes: &TableInfoRef) -> Result<Self> {
        Ok(PropertyPtrRaw {
            rid,
            token: Token::new(0x1600_0000 + rid),
            offset: *offset,
            property: read_le_at_dyn(data, offset, sizes.is_large(TableId::Property))?,
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
            0x01, 0x01, // property (index into Property table)
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Property, 1)],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<PropertyPtrRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: PropertyPtrRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x16000001);
            assert_eq!(row.property, 0x0101);
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
            0x01, 0x01, 0x01, 0x01, // property (index into Property table)
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Property, u16::MAX as u32 + 3)],
            true,
            true,
            true,
        ));
        let table = MetadataTable::<PropertyPtrRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: PropertyPtrRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x16000001);
            assert_eq!(row.property, 0x01010101);
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
