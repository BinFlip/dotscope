use crate::{
    metadata::{
        tables::{
            CodedIndex, CodedIndexType, GenericParamConstraintRaw, RowReadable, TableId,
            TableInfoRef,
        },
        token::Token,
    },
    utils::read_le_at_dyn,
    Result,
};

impl RowReadable for GenericParamConstraintRaw {
    fn row_read(data: &[u8], offset: &mut usize, rid: u32, sizes: &TableInfoRef) -> Result<Self> {
        Ok(GenericParamConstraintRaw {
            rid,
            token: Token::new(0x2C00_0000 + rid),
            offset: *offset,
            owner: read_le_at_dyn(data, offset, sizes.is_large(TableId::GenericParam))?,
            constraint: CodedIndex::read(data, offset, sizes, CodedIndexType::TypeDefOrRef)?,
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
            0x01, 0x01, // owner
            0x08, 0x00, // constraint (tag 0 = TypeDef, index = 2)
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::GenericParamConstraint, 1),
                (TableId::GenericParam, 10),
                (TableId::TypeDef, 10),
                (TableId::TypeRef, 10),
                (TableId::TypeSpec, 10),
            ],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<GenericParamConstraintRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: GenericParamConstraintRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x2C000001);
            assert_eq!(row.owner, 0x0101);
            assert_eq!(
                row.constraint,
                CodedIndex::new(TableId::TypeDef, 2, CodedIndexType::TypeDefOrRef)
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
            0x01, 0x01, 0x01, 0x01, // owner
            0x08, 0x00, 0x00, 0x00, // constraint (tag 0 = TypeDef, index = 2)
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::GenericParamConstraint, u16::MAX as u32 + 3),
                (TableId::GenericParam, u16::MAX as u32 + 3),
                (TableId::TypeDef, u16::MAX as u32 + 3),
                (TableId::TypeRef, u16::MAX as u32 + 3),
                (TableId::TypeSpec, u16::MAX as u32 + 3),
            ],
            true,
            true,
            true,
        ));
        let table = MetadataTable::<GenericParamConstraintRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: GenericParamConstraintRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x2C000001);
            assert_eq!(row.owner, 0x01010101);
            assert_eq!(
                row.constraint,
                CodedIndex::new(TableId::TypeDef, 2, CodedIndexType::TypeDefOrRef)
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
