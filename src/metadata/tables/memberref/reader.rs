use crate::{
    metadata::{
        tables::{CodedIndex, CodedIndexType, MemberRefRaw, RowReadable, TableInfoRef},
        token::Token,
    },
    utils::read_le_at_dyn,
    Result,
};

impl RowReadable for MemberRefRaw {
    fn row_read(data: &[u8], offset: &mut usize, rid: u32, sizes: &TableInfoRef) -> Result<Self> {
        Ok(MemberRefRaw {
            rid,
            token: Token::new(0x0A00_0000 + rid),
            offset: *offset,
            class: CodedIndex::read(data, offset, sizes, CodedIndexType::MemberRefParent)?,
            name: read_le_at_dyn(data, offset, sizes.is_large_str())?,
            signature: read_le_at_dyn(data, offset, sizes.is_large_blob())?,
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
            0x01, 0x01, // class
            0x02, 0x02, // name
            0x03, 0x03, // signature
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::MethodDef, 1)],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<MemberRefRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: MemberRefRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x0A000001);
            assert_eq!(
                row.class,
                CodedIndex::new(TableId::TypeRef, 32, CodedIndexType::MemberRefParent)
            );
            assert_eq!(row.name, 0x202);
            assert_eq!(row.signature, 0x303);
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
            0x02, 0x02, 0x02, 0x02, // name
            0x03, 0x03, 0x03, 0x03, // signature
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::TypeDef, u16::MAX as u32 + 3)],
            true,
            true,
            true,
        ));
        let table = MetadataTable::<MemberRefRaw>::new(&data, u16::MAX as u32 + 3, sizes).unwrap();

        let eval = |row: MemberRefRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x0A000001);
            assert_eq!(
                row.class,
                CodedIndex::new(TableId::TypeRef, 0x202020, CodedIndexType::MemberRefParent)
            );
            assert_eq!(row.name, 0x2020202);
            assert_eq!(row.signature, 0x3030303);
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
