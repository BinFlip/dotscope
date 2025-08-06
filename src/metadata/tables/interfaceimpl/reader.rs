use crate::{
    metadata::{
        tables::{
            CodedIndex, CodedIndexType, InterfaceImplRaw, RowReadable, TableId, TableInfoRef,
        },
        token::Token,
    },
    utils::read_le_at_dyn,
    Result,
};

impl RowReadable for InterfaceImplRaw {
    /// Reads a single `InterfaceImpl` table row from binary metadata stream.
    ///
    /// Parses the binary representation of an `InterfaceImpl` entry, reading fields
    /// in the order specified by ECMA-335 and handling variable-size indexes
    /// based on table sizing information.
    ///
    /// # Arguments
    /// * `data` - Binary data containing the table row
    /// * `offset` - Current read position, updated after reading
    /// * `rid` - Row identifier for this entry
    /// * `sizes` - Table sizing information for variable-width fields
    ///
    /// # Returns
    /// * `Ok(InterfaceImplRaw)` - Successfully parsed table row
    /// * `Err(_)` - Binary data reading or parsing error
    fn row_read(data: &[u8], offset: &mut usize, rid: u32, sizes: &TableInfoRef) -> Result<Self> {
        Ok(InterfaceImplRaw {
            rid,
            token: Token::new(0x0900_0000 + rid),
            offset: *offset,
            class: read_le_at_dyn(data, offset, sizes.is_large(TableId::TypeDef))?,
            interface: CodedIndex::read(data, offset, sizes, CodedIndexType::TypeDefOrRef)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::metadata::tables::{MetadataTable, TableInfo};

    use super::*;

    #[test]
    fn crafted_short() {
        let data = vec![
            0x01, 0x01, // class
            0x02, 0x02, // interface
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::InterfaceImpl, 1)],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<InterfaceImplRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: InterfaceImplRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x09000001);
            assert_eq!(row.class, 0x0101);
            assert_eq!(
                row.interface,
                CodedIndex::new(TableId::TypeSpec, 0x80, CodedIndexType::TypeDefOrRef)
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
            0x02, 0x02, 0x02, 0x02, // interface
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::TypeDef, u16::MAX as u32 + 2)],
            true,
            true,
            true,
        ));
        let table =
            MetadataTable::<InterfaceImplRaw>::new(&data, u16::MAX as u32 + 2, sizes).unwrap();

        let eval = |row: InterfaceImplRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x09000001);
            assert_eq!(row.class, 0x01010101);
            assert_eq!(
                row.interface,
                CodedIndex::new(TableId::TypeSpec, 0x808080, CodedIndexType::TypeDefOrRef)
            );
        };

        {
            let row = table.get(1).unwrap();
            eval(row);
        }
    }
}
