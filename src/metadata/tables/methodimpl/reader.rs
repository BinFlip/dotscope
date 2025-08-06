use crate::{
    metadata::{
        tables::{CodedIndex, CodedIndexType, MethodImplRaw, RowReadable, TableId, TableInfoRef},
        token::Token,
    },
    utils::read_le_at_dyn,
    Result,
};

impl RowReadable for MethodImplRaw {
    fn row_read(data: &[u8], offset: &mut usize, rid: u32, sizes: &TableInfoRef) -> Result<Self> {
        Ok(MethodImplRaw {
            rid,
            token: Token::new(0x1900_0000 + rid),
            offset: *offset,
            class: read_le_at_dyn(data, offset, sizes.is_large(TableId::TypeDef))?,
            method_body: CodedIndex::read(data, offset, sizes, CodedIndexType::MethodDefOrRef)?,
            method_declaration: CodedIndex::read(
                data,
                offset,
                sizes,
                CodedIndexType::MethodDefOrRef,
            )?,
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
            0x01, 0x01, // class
            0x02, 0x00, // method_body (tag 0 = MethodDef, index = 1)
            0x02, 0x00, // method_declaration (tag 0 = MethodDef, index = 1)
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::MethodImpl, 1),
                (TableId::TypeDef, 10),
                (TableId::MethodDef, 10),
                (TableId::MemberRef, 10),
            ],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<MethodImplRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: MethodImplRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x19000001);
            assert_eq!(row.class, 0x0101);
            assert_eq!(
                row.method_body,
                CodedIndex::new(TableId::MethodDef, 1, CodedIndexType::MethodDefOrRef)
            );
            assert_eq!(
                row.method_declaration,
                CodedIndex::new(TableId::MethodDef, 1, CodedIndexType::MethodDefOrRef)
            );
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
            0x01, 0x01, 0x01, 0x01, // class
            0x02, 0x00, 0x00, 0x00, // method_body (tag 0 = MethodDef, index = 1)
            0x02, 0x00, 0x00, 0x00, // method_declaration (tag 0 = MethodDef, index = 1)
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::MethodImpl, u16::MAX as u32 + 3),
                (TableId::TypeDef, u16::MAX as u32 + 3),
                (TableId::MethodDef, u16::MAX as u32 + 3),
                (TableId::MemberRef, u16::MAX as u32 + 3),
            ],
            true,
            true,
            true,
        ));
        let table = MetadataTable::<MethodImplRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: MethodImplRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x19000001);
            assert_eq!(row.class, 0x01010101);
            assert_eq!(
                row.method_body,
                CodedIndex::new(TableId::MethodDef, 1, CodedIndexType::MethodDefOrRef)
            );
            assert_eq!(
                row.method_declaration,
                CodedIndex::new(TableId::MethodDef, 1, CodedIndexType::MethodDefOrRef)
            );
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
