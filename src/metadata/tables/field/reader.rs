use crate::{
    metadata::{
        tables::{FieldRaw, RowReadable, TableInfoRef},
        token::Token,
    },
    utils::{read_le_at, read_le_at_dyn},
    Result,
};

impl RowReadable for FieldRaw {
    fn row_read(data: &[u8], offset: &mut usize, rid: u32, sizes: &TableInfoRef) -> Result<Self> {
        Ok(FieldRaw {
            rid,
            token: Token::new(0x0400_0000 + rid),
            offset: *offset,
            flags: u32::from(read_le_at::<u16>(data, offset)?),
            name: read_le_at_dyn(data, offset, sizes.is_large_str())?,
            signature: read_le_at_dyn(data, offset, sizes.is_large_blob())?,
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
            0x01, 0x01, // flags
            0x02, 0x02, // name
            0x03, 0x03, // signature
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Field, 1)],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<FieldRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: FieldRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x04000001);
            assert_eq!(row.flags, 0x0101);
            assert_eq!(row.name, 0x0202);
            assert_eq!(row.signature, 0x0303);
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
            0x01, 0x01, // flags
            0x02, 0x02, 0x02, 0x02, // name
            0x03, 0x03, 0x03, 0x03, // signature
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Field, 1)],
            true,
            true,
            true,
        ));
        let table = MetadataTable::<FieldRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: FieldRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x04000001);
            assert_eq!(row.flags, 0x0101);
            assert_eq!(row.name, 0x02020202);
            assert_eq!(row.signature, 0x03030303);
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
