use crate::{
    file::io::read_le_at_dyn,
    metadata::{
        tables::{CodedIndex, CodedIndexType, RowReadable, TableInfoRef, TypeRefRaw},
        token::Token,
    },
    Result,
};

impl<'a> RowReadable<'a> for TypeRefRaw {
    /// Calculates the byte size of a `TypeRef` table row.
    ///
    /// The row size depends on the size configuration of heaps and tables:
    /// - `ResolutionScope`: 2 or 4 bytes depending on `ResolutionScope` coded index size
    /// - TypeName/TypeNamespace: 2 or 4 bytes depending on string heap size
    ///
    /// ## Arguments
    /// * `sizes` - Table size information for calculating index widths
    ///
    /// ## Returns
    /// The total byte size required for one `TypeRef` table row.
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* resolution_scope */  sizes.coded_index_bytes(CodedIndexType::ResolutionScope) +
            /* type_namespace */    sizes.str_bytes() +
            /* type_name */         sizes.str_bytes()
        )
    }

    /// Reads a `TypeRef` table row from binary metadata.
    ///
    /// Parses the binary representation of a `TypeRef` table row according to the
    /// ECMA-335 specification, handling variable-width indexes based on heap and
    /// table sizes.
    ///
    /// ## Arguments
    /// * `data` - Binary metadata containing the `TypeRef` table
    /// * `offset` - Current read position, updated after reading
    /// * `rid` - Row identifier for this entry (1-based)
    /// * `sizes` - Table size information for parsing variable-width fields
    ///
    /// ## Returns
    /// Returns a [`crate::metadata::tables::typeref::raw::TypeRefRaw`] instance with all fields populated from the binary data.
    ///
    /// ## Errors
    /// Returns an error if the binary data is insufficient or malformed.
    fn row_read(
        data: &'a [u8],
        offset: &mut usize,
        rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<Self> {
        Ok(TypeRefRaw {
            rid,
            token: Token::new(0x0100_0000 + rid),
            offset: *offset,
            resolution_scope: CodedIndex::read(
                data,
                offset,
                sizes,
                CodedIndexType::ResolutionScope,
            )?,
            type_name: read_le_at_dyn(data, offset, sizes.is_large_str())?,
            type_namespace: read_le_at_dyn(data, offset, sizes.is_large_str())?,
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
            0x01, 0x01, // resolution_scope
            0x02, 0x02, // type_name
            0x03, 0x03, // type_namespace
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Field, 1)],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<TypeRefRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: TypeRefRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x01000001);
            assert_eq!(
                row.resolution_scope,
                CodedIndex {
                    tag: TableId::ModuleRef,
                    row: 64,
                    token: Token::new(64 | 0x1A000000),
                }
            );
            assert_eq!(row.type_name, 0x0202);
            assert_eq!(row.type_namespace, 0x0303);
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
            0x01, 0x01, 0x01, 0x01, // resolution_scope
            0x02, 0x02, 0x02, 0x02, // type_name
            0x03, 0x03, 0x03, 0x03, // type_namespace
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::TypeRef, 1),
                (TableId::AssemblyRef, u16::MAX as u32 + 2),
            ],
            true,
            true,
            true,
        ));
        let table = MetadataTable::<TypeRefRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: TypeRefRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x01000001);
            assert_eq!(
                row.resolution_scope,
                CodedIndex {
                    tag: TableId::ModuleRef,
                    row: 0x404040,
                    token: Token::new(0x404040 | 0x1A000000),
                }
            );
            assert_eq!(row.type_name, 0x02020202);
            assert_eq!(row.type_namespace, 0x03030303);
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
