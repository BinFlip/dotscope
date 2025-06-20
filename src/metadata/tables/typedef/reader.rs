use crate::{
    file::io::{read_le_at, read_le_at_dyn},
    metadata::{
        tables::{CodedIndex, CodedIndexType, RowReadable, TableId, TableInfoRef, TypeDefRaw},
        token::Token,
    },
    Result,
};

impl RowReadable for TypeDefRaw {
    /// Calculates the byte size of a `TypeDef` table row.
    ///
    /// The row size depends on the size configuration of various heaps and tables:
    /// - Flags: Always 4 bytes
    /// - TypeName/TypeNamespace: 2 or 4 bytes depending on string heap size
    /// - Extends: 2 or 4 bytes depending on coded index size for `TypeDefOrRef`
    /// - FieldList/MethodList: 2 or 4 bytes depending on target table sizes
    ///
    /// ## Arguments
    /// * `sizes` - Table size information for calculating index widths
    ///
    /// ## Returns
    /// The total byte size required for one `TypeDef` table row.
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* flags */             4 +
            /* type_name */         sizes.str_bytes() +
            /* type_namespace */    sizes.str_bytes() +
            /* extends */           sizes.coded_index_bytes(CodedIndexType::TypeDefOrRef) +
            /* field_list */        sizes.table_index_bytes(TableId::Field) +
            /* method_list */       sizes.table_index_bytes(TableId::MethodDef)
        )
    }

    /// Reads a `TypeDef` table row from binary metadata.
    ///
    /// Parses the binary representation of a `TypeDef` table row according to the
    /// ECMA-335 specification, handling variable-width indexes based on heap and
    /// table sizes.
    ///
    /// ## Arguments
    /// * `data` - Binary metadata containing the `TypeDef` table
    /// * `offset` - Current read position, updated after reading
    /// * `rid` - Row identifier for this entry (1-based)
    /// * `sizes` - Table size information for parsing variable-width fields
    ///
    /// ## Returns
    /// Returns a [`TypeDefRaw`] instance with all fields populated from the binary data.
    ///
    /// ## Errors
    /// Returns an error if the binary data is insufficient or malformed.
    fn row_read(data: &[u8], offset: &mut usize, rid: u32, sizes: &TableInfoRef) -> Result<Self> {
        Ok(TypeDefRaw {
            rid,
            token: Token::new(0x0200_0000 + rid),
            offset: *offset,
            flags: read_le_at::<u32>(data, offset)?,
            type_name: read_le_at_dyn(data, offset, sizes.is_large_str())?,
            type_namespace: read_le_at_dyn(data, offset, sizes.is_large_str())?,
            extends: CodedIndex::read(data, offset, sizes, CodedIndexType::TypeDefOrRef)?,
            field_list: read_le_at_dyn(data, offset, sizes.is_large(TableId::Field))?,
            method_list: read_le_at_dyn(data, offset, sizes.is_large(TableId::MethodDef))?,
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
            0x00, 0x00, 0x00, 0x01, // flags
            0x42, 0x00, // type_name
            0x43, 0x00, // type_namespace
            0x00, 0x02, // extends
            0x00, 0x03, // field_list
            0x00, 0x04, // method_list
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Field, 1), (TableId::MethodDef, 1)],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<TypeDefRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: TypeDefRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x02000001);
            assert_eq!(row.flags, 0x01000000);
            assert_eq!(row.type_name, 0x42);
            assert_eq!(row.type_namespace, 0x43);
            assert_eq!(
                row.extends,
                CodedIndex {
                    tag: TableId::TypeDef,
                    row: 0x80,
                    token: Token::new(0x80 | 0x02000000),
                }
            );
            assert_eq!(row.field_list, 0x0300);
            assert_eq!(row.method_list, 0x0400);
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
            0x00, 0x00, 0x00, 0x01, // flags
            0x00, 0x00, 0x00, 0x02, // type_name
            0x00, 0x00, 0x00, 0x03, // type_namespace
            0x00, 0x00, 0x00, 0x04, // extends
            0x00, 0x00, 0x00, 0x05, // field_list
            0x00, 0x00, 0x00, 0x06, // method_list
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::Field, u16::MAX as u32 + 2),
                (TableId::MethodDef, u16::MAX as u32 + 2),
                (TableId::TypeDef, u16::MAX as u32 + 2),
                (TableId::TypeRef, u16::MAX as u32 + 2),
                (TableId::TypeSpec, u16::MAX as u32 + 2),
            ],
            true,
            true,
            true,
        ));
        let table = MetadataTable::<TypeDefRaw>::new(&data, u16::MAX as u32 + 2, sizes).unwrap();

        let eval = |row: TypeDefRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x02000001);
            assert_eq!(row.flags, 0x01000000);
            assert_eq!(row.type_name, 0x02000000);
            assert_eq!(row.type_namespace, 0x03000000);
            assert_eq!(
                row.extends,
                CodedIndex {
                    tag: TableId::TypeDef,
                    row: 0x1000000,
                    token: Token::new(0x1000000 | 0x02000000),
                }
            );
            assert_eq!(row.field_list, 0x05000000);
            assert_eq!(row.method_list, 0x06000000);
        };

        {
            let row = table.get(1).unwrap();
            eval(row);
        }
    }
}
