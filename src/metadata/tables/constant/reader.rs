use crate::{
    file::io::{read_le_at, read_le_at_dyn},
    metadata::{
        tables::{CodedIndex, CodedIndexType, ConstantRaw, RowReadable, TableInfoRef},
        token::Token,
    },
    Result,
};

impl RowReadable for ConstantRaw {
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* c_type */    1 +
            /* padding */   1 +
            /* parent */    sizes.coded_index_bytes(CodedIndexType::HasConstant) +
            /* value */     sizes.blob_bytes()
        )
    }

    fn row_read(data: &[u8], offset: &mut usize, rid: u32, sizes: &TableInfoRef) -> Result<Self> {
        let offset_org = *offset;

        let c_type = read_le_at::<u8>(data, offset)?;
        *offset += 1; // Padding

        Ok(ConstantRaw {
            rid,
            token: Token::new(0x0B00_0000 + rid),
            offset: offset_org,
            base: c_type,
            parent: CodedIndex::read(data, offset, sizes, CodedIndexType::HasConstant)?,
            value: read_le_at_dyn(data, offset, sizes.is_large_blob())?,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::metadata::tables::{MetadataTable, TableId, TableInfo};

    use super::*;
    use crate::metadata::token::Token;

    #[test]
    fn crafted_short() {
        let data = vec![
            0x01, // type
            0x00, // padding
            0x02, 0x02, // parent
            0x03, 0x03, // value
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Property, 1)],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<ConstantRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: ConstantRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x0B000001);
            assert_eq!(row.base, 0x01);
            assert_eq!(
                row.parent,
                CodedIndex {
                    tag: TableId::Property,
                    row: 128,
                    token: Token::new(128 | 0x17000000),
                }
            );
            assert_eq!(row.value, 0x303);
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
            0x01, // type
            0x00, // padding
            0x02, 0x02, 0x02, 0x02, // parent
            0x03, 0x03, 0x03, 0x03, // value
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Property, u16::MAX as u32 + 3)],
            true,
            true,
            true,
        ));
        let table = MetadataTable::<ConstantRaw>::new(&data, u16::MAX as u32 + 3, sizes).unwrap();

        let eval = |row: ConstantRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x0B000001);
            assert_eq!(row.base, 0x1);
            assert_eq!(
                row.parent,
                CodedIndex {
                    tag: TableId::Property,
                    row: 0x808080,
                    token: Token::new(0x808080 | 0x17000000),
                }
            );
            assert_eq!(row.value, 0x3030303);
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
