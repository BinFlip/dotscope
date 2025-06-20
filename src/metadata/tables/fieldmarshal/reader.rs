use crate::{
    file::io::read_le_at_dyn,
    metadata::{
        tables::{CodedIndex, CodedIndexType, FieldMarshalRaw, RowReadable, TableInfoRef},
        token::Token,
    },
    Result,
};

impl RowReadable for FieldMarshalRaw {
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* parent */      sizes.coded_index_bytes(CodedIndexType::HasFieldMarshal) +
            /* native_type */ sizes.blob_bytes()
        )
    }

    fn row_read(data: &[u8], offset: &mut usize, rid: u32, sizes: &TableInfoRef) -> Result<Self> {
        let offset_org = *offset;

        Ok(FieldMarshalRaw {
            rid,
            token: Token::new(0x0D00_0000 + rid),
            offset: offset_org,
            parent: CodedIndex::read(data, offset, sizes, CodedIndexType::HasFieldMarshal)?,
            native_type: read_le_at_dyn(data, offset, sizes.is_large_blob())?,
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
            0x02, 0x02, // parent
            0x03, 0x03, // native_type
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Field, 1), (TableId::Param, 1)],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<FieldMarshalRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: FieldMarshalRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x0D000001);
            assert_eq!(
                row.parent,
                CodedIndex {
                    tag: TableId::Field,
                    row: 257,
                    token: Token::new(257 | 0x04000000),
                }
            );
            assert_eq!(row.native_type, 0x303);
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
            0x02, 0x02, 0x02, 0x02, // parent
            0x03, 0x03, 0x03, 0x03, // native_type
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::Field, u16::MAX as u32 + 3),
                (TableId::Param, u16::MAX as u32 + 3),
            ],
            true,
            true,
            true,
        ));
        let table =
            MetadataTable::<FieldMarshalRaw>::new(&data, u16::MAX as u32 + 3, sizes).unwrap();

        let eval = |row: FieldMarshalRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x0D000001);
            assert_eq!(
                row.parent,
                CodedIndex {
                    tag: TableId::Field,
                    row: 0x1010101,
                    token: Token::new(0x1010101 | 0x04000000),
                }
            );
            assert_eq!(row.native_type, 0x3030303);
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
