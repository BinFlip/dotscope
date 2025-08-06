use crate::{
    metadata::{
        tables::{CodedIndex, CodedIndexType, CustomAttributeRaw, RowReadable, TableInfoRef},
        token::Token,
    },
    utils::read_le_at_dyn,
    Result,
};

impl RowReadable for CustomAttributeRaw {
    fn row_read(data: &[u8], offset: &mut usize, rid: u32, sizes: &TableInfoRef) -> Result<Self> {
        Ok(CustomAttributeRaw {
            rid,
            token: Token::new(0x0C00_0000 + rid),
            offset: *offset,
            parent: CodedIndex::read(data, offset, sizes, CodedIndexType::HasCustomAttribute)?,
            constructor: CodedIndex::read(
                data,
                offset,
                sizes,
                CodedIndexType::CustomAttributeType,
            )?,
            value: read_le_at_dyn(data, offset, sizes.is_large_blob())?,
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
            0x02, 0x02, // parent
            0x03, 0x03, // type
            0x04, 0x04, // value
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::TypeDef, 1), (TableId::MethodDef, 1)],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<CustomAttributeRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: CustomAttributeRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x0C000001);
            assert_eq!(
                row.parent,
                CodedIndex::new(TableId::TypeRef, 16, CodedIndexType::HasCustomAttribute)
            );
            assert_eq!(
                row.constructor,
                CodedIndex::new(TableId::MemberRef, 96, CodedIndexType::CustomAttributeType)
            );
            assert_eq!(row.value, 0x404);
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
            0x03, 0x03, 0x03, 0x03, // type
            0x04, 0x04, 0x04, 0x04, // value
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::TypeDef, u16::MAX as u32 + 3),
                (TableId::MethodDef, u16::MAX as u32 + 3),
            ],
            true,
            true,
            true,
        ));
        let table =
            MetadataTable::<CustomAttributeRaw>::new(&data, u16::MAX as u32 + 3, sizes).unwrap();

        let eval = |row: CustomAttributeRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x0C000001);
            assert_eq!(
                row.parent,
                CodedIndex::new(
                    TableId::TypeRef,
                    0x101010,
                    CodedIndexType::HasCustomAttribute
                )
            );
            assert_eq!(
                row.constructor,
                CodedIndex::new(
                    TableId::MemberRef,
                    0x606060,
                    CodedIndexType::CustomAttributeType
                )
            );
            assert_eq!(row.value, 0x4040404);
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
