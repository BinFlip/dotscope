use crate::{
    file::io::read_le_at_dyn,
    metadata::{
        tables::{PropertyMapRaw, RowReadable, TableId, TableInfoRef},
        token::Token,
    },
    Result,
};

impl RowReadable for PropertyMapRaw {
    /// Calculates the byte size of a `PropertyMap` table row.
    ///
    /// The size depends on whether the `TypeDef` and Property tables use 2-byte or 4-byte indices,
    /// which is determined by the number of rows in each table.
    ///
    /// ## Size Calculation
    /// - **parent**: 2 or 4 bytes (depending on `TypeDef` table size)
    /// - **`property_list`**: 2 or 4 bytes (depending on Property table size)
    ///
    /// ## Arguments
    /// * `sizes` - Table size information for determining index sizes
    ///
    /// ## Returns
    /// The total byte size of a `PropertyMap` table row (4 or 8 bytes).
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* parent */        sizes.table_index_bytes(TableId::TypeDef) +
            /* property_list */ sizes.table_index_bytes(TableId::Property)
        )
    }

    /// Reads a `PropertyMap` entry from the metadata byte stream.
    ///
    /// This method parses the binary representation of a `PropertyMap` table row and creates
    /// a [`PropertyMapRaw`] instance with the appropriate metadata token.
    ///
    /// ## Binary Format
    /// The data is read in little-endian format:
    /// 1. **parent** - Index into `TypeDef` table (2 or 4 bytes)
    /// 2. **`property_list`** - Index into Property table (2 or 4 bytes)
    ///
    /// ## Arguments
    /// * `data` - The metadata byte stream
    /// * `offset` - Current position in the stream (updated after reading)
    /// * `rid` - The 1-based row identifier for this entry
    /// * `sizes` - Table size information for determining index sizes
    ///
    /// ## Returns
    /// A new [`PropertyMapRaw`] instance with the parsed data and generated metadata token.
    ///
    /// ## Errors
    /// Returns an error if the data cannot be read or is malformed.
    fn row_read(data: &[u8], offset: &mut usize, rid: u32, sizes: &TableInfoRef) -> Result<Self> {
        let offset_org = *offset;

        let parent = read_le_at_dyn(data, offset, sizes.is_large(TableId::TypeDef))?;
        let property_list = read_le_at_dyn(data, offset, sizes.is_large(TableId::Property))?;

        Ok(PropertyMapRaw {
            rid,
            token: Token::new(0x1500_0000 + rid),
            offset: offset_org,
            parent,
            property_list,
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
            0x02, 0x02, // property_list
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::TypeDef, 1), (TableId::Property, 1)],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<PropertyMapRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: PropertyMapRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x15000001);
            assert_eq!(row.parent, 0x0101);
            assert_eq!(row.property_list, 0x0202);
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
            0x02, 0x02, 0x02, 0x02, // property_list
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::TypeDef, u16::MAX as u32 + 3),
                (TableId::Property, u16::MAX as u32 + 3),
            ],
            true,
            true,
            true,
        ));
        let table =
            MetadataTable::<PropertyMapRaw>::new(&data, u16::MAX as u32 + 3, sizes).unwrap();

        let eval = |row: PropertyMapRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x15000001);
            assert_eq!(row.parent, 0x01010101);
            assert_eq!(row.property_list, 0x02020202);
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
