use crate::{
    metadata::{
        tables::{
            CodedIndex, CodedIndexType, MethodSemanticsRaw, RowReadable, TableId, TableInfoRef,
        },
        token::Token,
    },
    utils::{read_le_at, read_le_at_dyn},
    Result,
};

impl RowReadable for MethodSemanticsRaw {
    /// Reads a single `MethodSemantics` table row from binary data.
    ///
    /// Parses the binary representation according to ECMA-335 §II.22.28:
    /// 1. **Semantics** (2 bytes): Bitmask of semantic attributes
    /// 2. **Method** (2-4 bytes): Index into `MethodDef` table
    /// 3. **Association** (2-4 bytes): `HasSemantics` coded index
    ///
    /// ## Arguments
    /// * `data` - Binary data containing the table
    /// * `offset` - Current read position (updated by this method)
    /// * `rid` - Row identifier for this entry (1-based)
    /// * `sizes` - Table size information for proper index width calculation
    ///
    /// ## Returns
    /// Parsed [`MethodSemanticsRaw`] instance with populated fields
    ///
    /// ## Errors
    ///
    /// - Insufficient data remaining at offset
    /// - Invalid coded index encoding
    /// - Data corruption or malformed structure
    fn row_read(data: &[u8], offset: &mut usize, rid: u32, sizes: &TableInfoRef) -> Result<Self> {
        Ok(MethodSemanticsRaw {
            rid,
            token: Token::new(0x1800_0000 + rid),
            offset: *offset,
            semantics: u32::from(read_le_at::<u16>(data, offset)?),
            method: read_le_at_dyn(data, offset, sizes.is_large(TableId::MethodDef))?,
            association: CodedIndex::read(data, offset, sizes, CodedIndexType::HasSemantics)?,
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
            0x01, 0x01, // semantics
            0x02, 0x02, // method
            0x02, 0x00, // association (tag 0 = Event, index = 1)
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::MethodSemantics, 1),
                (TableId::MethodDef, 10),
                (TableId::Event, 10),
                (TableId::Property, 10),
            ],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<MethodSemanticsRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: MethodSemanticsRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x18000001);
            assert_eq!(row.semantics, 0x0101);
            assert_eq!(row.method, 0x0202);
            assert_eq!(
                row.association,
                CodedIndex::new(TableId::Event, 1, CodedIndexType::HasSemantics)
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
            0x01, 0x01, // semantics
            0x02, 0x02, 0x02, 0x02, // method
            0x02, 0x00, 0x00, 0x00, // association (tag 0 = Event, index = 1)
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::MethodSemantics, u16::MAX as u32 + 3),
                (TableId::MethodDef, u16::MAX as u32 + 3),
                (TableId::Event, u16::MAX as u32 + 3),
                (TableId::Property, u16::MAX as u32 + 3),
            ],
            true,
            true,
            true,
        ));
        let table = MetadataTable::<MethodSemanticsRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: MethodSemanticsRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x18000001);
            assert_eq!(row.semantics, 0x0101);
            assert_eq!(row.method, 0x02020202);
            assert_eq!(
                row.association,
                CodedIndex::new(TableId::Event, 1, CodedIndexType::HasSemantics)
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
