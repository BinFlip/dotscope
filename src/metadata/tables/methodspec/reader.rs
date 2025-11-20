use crate::{
    metadata::{
        tables::{CodedIndex, CodedIndexType, MethodSpecRaw, RowReadable, TableInfoRef},
        token::Token,
    },
    utils::read_le_at_dyn,
    Result,
};

impl RowReadable for MethodSpecRaw {
    /// Reads a single `MethodSpec` table row from binary data.
    ///
    /// Parses the binary representation according to ECMA-335 §II.22.29:
    /// 1. **Method** (2-4 bytes): `MethodDefOrRef` coded index to the generic method
    /// 2. **Instantiation** (2-4 bytes): Index into blob heap containing signature
    ///
    /// ## Arguments
    /// * `data` - Binary data containing the table
    /// * `offset` - Current read position (updated by this method)
    /// * `rid` - Row identifier for this entry (1-based)
    /// * `sizes` - Table size information for proper index width calculation
    ///
    /// ## Returns
    /// Parsed [`MethodSpecRaw`] instance with populated fields
    ///
    /// ## Errors
    /// Returns an error if:
    /// - Insufficient data remaining at offset
    /// - Invalid coded index encoding
    /// - Data corruption or malformed structure
    fn row_read(data: &[u8], offset: &mut usize, rid: u32, sizes: &TableInfoRef) -> Result<Self> {
        Ok(MethodSpecRaw {
            rid,
            token: Token::new(0x2B00_0000 + rid),
            offset: *offset,
            method: CodedIndex::read(data, offset, sizes, CodedIndexType::MethodDefOrRef)?,
            instantiation: read_le_at_dyn(data, offset, sizes.is_large_blob())?,
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
            0x01, 0x00, // method
            0x02, 0x02, // instantiation
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::MethodSpec, 1),
                (TableId::MethodDef, 10),
                (TableId::MemberRef, 10),
            ],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<MethodSpecRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: MethodSpecRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x2B000001);
            assert_eq!(
                row.method,
                CodedIndex::new(TableId::MemberRef, 0, CodedIndexType::MethodDefOrRef)
            );
            assert_eq!(row.instantiation, 0x0202);
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
            0x01, 0x00, 0x00, 0x00, // method
            0x02, 0x02, 0x02, 0x02, // instantiation
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::MethodSpec, u16::MAX as u32 + 3),
                (TableId::MethodDef, u16::MAX as u32 + 3),
                (TableId::MemberRef, u16::MAX as u32 + 3),
            ],
            true,
            true,
            true,
        ));
        let table = MetadataTable::<MethodSpecRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: MethodSpecRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x2B000001);
            assert_eq!(
                row.method,
                CodedIndex::new(TableId::MemberRef, 0, CodedIndexType::MethodDefOrRef)
            );
            assert_eq!(row.instantiation, 0x02020202);
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
