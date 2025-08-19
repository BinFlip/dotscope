use crate::{
    metadata::{
        tables::{CodedIndex, CodedIndexType, GenericParamRaw, RowReadable, TableInfoRef},
        token::Token,
    },
    utils::{read_le_at, read_le_at_dyn},
    Result,
};

impl RowReadable for GenericParamRaw {
    fn row_read(data: &[u8], offset: &mut usize, rid: u32, sizes: &TableInfoRef) -> Result<Self> {
        Ok(GenericParamRaw {
            rid,
            token: Token::new(0x2A00_0000 + rid),
            offset: *offset,
            number: u32::from(read_le_at::<u16>(data, offset)?),
            flags: u32::from(read_le_at::<u16>(data, offset)?),
            owner: CodedIndex::read(data, offset, sizes, CodedIndexType::TypeOrMethodDef)?,
            name: read_le_at_dyn(data, offset, sizes.is_large_str())?,
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
            0x01, 0x01, // number
            0x02, 0x02, // flags
            0x02, 0x00, // owner (tag 0 = TypeDef, index = 1)
            0x04, 0x04, // name
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::GenericParam, 1),
                (TableId::TypeDef, 10),
                (TableId::MethodDef, 10),
            ],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<GenericParamRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: GenericParamRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x2A000001);
            assert_eq!(row.number, 0x0101);
            assert_eq!(row.flags, 0x0202);
            assert_eq!(
                row.owner,
                CodedIndex::new(TableId::TypeDef, 1, CodedIndexType::TypeOrMethodDef)
            );
            assert_eq!(row.name, 0x0404);
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
            0x01, 0x01, // number
            0x02, 0x02, // flags
            0x02, 0x00, 0x00, 0x00, // owner (tag 0 = TypeDef, index = 1)
            0x04, 0x04, 0x04, 0x04, // name
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::GenericParam, u16::MAX as u32 + 3),
                (TableId::TypeDef, u16::MAX as u32 + 3),
                (TableId::MethodDef, u16::MAX as u32 + 3),
            ],
            true,
            true,
            true,
        ));
        let table = MetadataTable::<GenericParamRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: GenericParamRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x2A000001);
            assert_eq!(row.number, 0x0101);
            assert_eq!(row.flags, 0x0202);
            assert_eq!(
                row.owner,
                CodedIndex::new(TableId::TypeDef, 1, CodedIndexType::TypeOrMethodDef)
            );
            assert_eq!(row.name, 0x04040404);
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
