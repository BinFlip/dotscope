use crate::{
    metadata::{
        tables::{CodedIndex, CodedIndexType, EventRaw, RowReadable, TableInfoRef},
        token::Token,
    },
    utils::{read_le_at, read_le_at_dyn},
    Result,
};

impl RowReadable for EventRaw {
    fn row_read(data: &[u8], offset: &mut usize, rid: u32, sizes: &TableInfoRef) -> Result<Self> {
        let offset_org = *offset;

        let flags = u32::from(read_le_at::<u16>(data, offset)?);
        let name = read_le_at_dyn(data, offset, sizes.is_large_str())?;
        let event_type = CodedIndex::read(data, offset, sizes, CodedIndexType::TypeDefOrRef)?;

        Ok(EventRaw {
            rid,
            token: Token::new(0x1400_0000 + rid),
            offset: offset_org,
            flags,
            name,
            event_type,
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
            0x01, 0x01, // flags
            0x02, 0x02, // name
            0x00, 0x03, // event_type (tag 0 = TypeDef, index 3)
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::TypeDef, 1),
                (TableId::TypeRef, 1),
                (TableId::TypeSpec, 1),
            ],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<EventRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: EventRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x14000001);
            assert_eq!(row.flags, 0x0101);
            assert_eq!(row.name, 0x0202);
            assert_eq!(
                row.event_type,
                CodedIndex::new(TableId::TypeDef, 192, CodedIndexType::TypeDefOrRef)
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
            0x01, 0x01, // flags
            0x02, 0x02, 0x02, 0x02, // name
            0x00, 0x03, 0x03, 0x03, // event_type (tag 0 = TypeDef, index 3)
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::TypeDef, u16::MAX as u32 + 3),
                (TableId::TypeRef, 1),
                (TableId::TypeSpec, 1),
            ],
            true,
            true,
            true,
        ));
        let table = MetadataTable::<EventRaw>::new(&data, u16::MAX as u32 + 3, sizes).unwrap();

        let eval = |row: EventRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x14000001);
            assert_eq!(row.flags, 0x0101);
            assert_eq!(row.name, 0x02020202);
            assert_eq!(
                row.event_type,
                CodedIndex::new(TableId::TypeDef, 0xC0C0C0, CodedIndexType::TypeDefOrRef)
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
