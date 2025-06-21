use crate::{
    file::io::read_le_at_dyn,
    metadata::{
        tables::{NestedClassRaw, RowReadable, TableId, TableInfoRef},
        token::Token,
    },
    Result,
};

impl RowReadable for NestedClassRaw {
    /// Reads a single `NestedClass` table row from binary data.
    ///
    /// Parses the binary representation according to ECMA-335 §II.22.32:
    /// 1. **`NestedClass`** (2-4 bytes): Index into `TypeDef` table for nested type
    /// 2. **`EnclosingClass`** (2-4 bytes): Index into `TypeDef` table for enclosing type
    ///
    /// ## Arguments
    /// * `data` - Binary data containing the table
    /// * `offset` - Current read position (updated by this method)
    /// * `rid` - Row identifier for this entry
    /// * `sizes` - Table size information for proper index width calculation
    ///
    /// ## Returns
    /// Parsed [`NestedClassRaw`] instance with populated fields
    ///
    /// ## Errors
    /// - Insufficient data remaining at offset
    /// - Data corruption or malformed structure
    /// - Invalid `TypeDef` index values
    fn row_read(data: &[u8], offset: &mut usize, rid: u32, sizes: &TableInfoRef) -> Result<Self> {
        Ok(NestedClassRaw {
            rid,
            token: Token::new(0x2900_0000 + rid),
            offset: *offset,
            nested_class: read_le_at_dyn(data, offset, sizes.is_large(TableId::TypeDef))?,
            enclosing_class: read_le_at_dyn(data, offset, sizes.is_large(TableId::TypeDef))?,
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
            0x01, 0x01, // nested_class
            0x02, 0x02, // enclosing_class
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::NestedClass, 1), (TableId::TypeDef, 10)],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<NestedClassRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: NestedClassRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x29000001);
            assert_eq!(row.nested_class, 0x0101);
            assert_eq!(row.enclosing_class, 0x0202);
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
            0x01, 0x01, 0x01, 0x01, // nested_class
            0x02, 0x02, 0x02, 0x02, // enclosing_class
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::NestedClass, u16::MAX as u32 + 3),
                (TableId::TypeDef, u16::MAX as u32 + 3),
            ],
            true,
            true,
            true,
        ));
        let table = MetadataTable::<NestedClassRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: NestedClassRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x29000001);
            assert_eq!(row.nested_class, 0x01010101);
            assert_eq!(row.enclosing_class, 0x02020202);
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
