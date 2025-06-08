use crate::{
    file::io::read_le_at_dyn,
    metadata::{
        streams::tables::types::{RowDefinition, TableInfoRef},
        token::Token,
    },
    Result,
};

#[derive(Clone, Debug)]
/// `TypeSpec`, ID = 0x1B
pub struct TypeSpecRaw {
    /// `RowID`
    pub rid: u32,
    /// Token
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// an index into the Blob heap
    pub signature: u32,
}

impl<'a> RowDefinition<'a> for TypeSpecRaw {
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* signature */ sizes.blob_bytes()
        )
    }

    fn read_row(
        data: &'a [u8],
        offset: &mut usize,
        rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<Self> {
        Ok(TypeSpecRaw {
            rid,
            token: Token::new(0x1B00_0000 + rid),
            offset: *offset,
            signature: read_le_at_dyn(data, offset, sizes.is_large_blob())?,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::metadata::streams::{MetadataTable, TableId, TableInfo};

    #[test]
    fn crafted_short() {
        let data = vec![
            0x01, 0x01, // signature
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::TypeSpec, 1)],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<TypeSpecRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: TypeSpecRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x1B000001);
            assert_eq!(row.signature, 0x0101);
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
            0x01, 0x01, 0x01, 0x01, // signature
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::TypeSpec, 1)],
            true,
            true,
            true,
        ));
        let table = MetadataTable::<TypeSpecRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: TypeSpecRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x1B000001);
            assert_eq!(row.signature, 0x01010101);
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
