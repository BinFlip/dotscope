use crate::{
    metadata::{
        tables::{LocalConstantRaw, RowReadable, TableInfoRef},
        token::Token,
    },
    utils::read_le_at_dyn,
    Result,
};

impl RowReadable for LocalConstantRaw {
    fn row_read(data: &[u8], offset: &mut usize, rid: u32, sizes: &TableInfoRef) -> Result<Self> {
        Ok(LocalConstantRaw {
            rid,
            token: Token::new(0x3400_0000 + rid),
            offset: *offset,
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
            0x01, 0x00, // name (2 bytes, short strings heap) - 0x0001
            0x02, 0x00, // signature (2 bytes, short blob heap) - 0x0002
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::LocalConstant, 1)],
            false, // large tables
            false, // large strings
            false, // large blob
        ));
        let table = MetadataTable::<LocalConstantRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: LocalConstantRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x34000001);
            assert_eq!(row.name, 0x0001);
            assert_eq!(row.signature, 0x0002);
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
            0x01, 0x00, 0x00, 0x00, // name (4 bytes, large strings heap) - 0x00000001
            0x02, 0x00, // signature (2 bytes, normal blob heap) - 0x0002
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::LocalConstant, 1)],
            true,  // large strings
            false, // large blob
            false, // large GUID
        ));
        let table = MetadataTable::<LocalConstantRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: LocalConstantRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x34000001);
            assert_eq!(row.name, 0x00000001);
            assert_eq!(row.signature, 0x0002);
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
