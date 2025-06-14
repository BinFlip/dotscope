use std::sync::Arc;

use crate::{
    file::io::{read_le_at, read_le_at_dyn},
    metadata::{
        streams::Strings,
        tables::{
            CodedIndex, CodedIndexType, ExportedType, ExportedTypeRc, RowDefinition, TableInfoRef,
        },
        token::Token,
        typesystem::CilTypeReference,
    },
    Result,
};

#[derive(Clone, Debug)]
/// The `ExportedType` table contains information about types that are exported from the current assembly,
/// but defined in other modules of the assembly. `TableId` = 0x27
pub struct ExportedTypeRaw {
    /// `RowID`
    pub rid: u32,
    /// Token
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// a 4-byte bitmask of type `TypeAttributes`, §II.23.1.15
    pub flags: u32,
    /// a 4-byte index into the `TypeDef` (foreign) table (this is a hint only, name + namespace are used primarily.
    /// If `type_def_id` happens to match, it has been resolved correctly. `type_def_id` can be 0)
    pub type_def_id: u32,
    /// an index into the String heap
    pub name: u32,
    /// an index into the String heap
    pub namespace: u32,
    /// an index into the `Implementation` coding index
    pub implementation: CodedIndex,
}

impl ExportedTypeRaw {
    /// Convert an `ExportedTypeRaw`, into a `ExportedType` which has indexes resolved and owns the referenced data
    ///
    /// ## Arguments
    /// * `get_ref` - Closure to resolve coded indexes
    /// * 'string'  - The #String heap
    ///
    /// # Errors
    /// Returns an error if string lookup fails or if implementation resolution fails
    pub fn to_owned<F>(&self, get_ref: F, string: &Strings) -> Result<ExportedTypeRc>
    where
        F: Fn(&CodedIndex) -> CilTypeReference,
    {
        let implementation = match get_ref(&self.implementation) {
            CilTypeReference::None => {
                return Err(malformed_error!(
                    "Failed to resolve implementation token - {}",
                    self.implementation.token.value()
                ))
            }
            resolved => resolved,
        };

        Ok(Arc::new(ExportedType {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            flags: self.flags,
            type_def_id: self.type_def_id | 0x0200_0000,
            name: string.get(self.name as usize)?.to_string(),
            namespace: if self.namespace == 0 {
                None
            } else {
                Some(string.get(self.namespace as usize)?.to_string())
            },
            implementation,
            custom_attributes: Arc::new(boxcar::Vec::new()),
        }))
    }

    /// Apply an `ExportedTypeRaw` entry to update related metadata structures.
    ///
    /// `ExportedType` entries define types that are exported from this assembly but may be
    /// implemented in other files or assemblies. They are primarily metadata descriptors
    /// and don't require cross-table updates during the dual variant resolution phase.
    ///
    /// # Errors
    /// Always returns `Ok(())` as `ExportedType` entries don't modify other tables.
    pub fn apply(&self) -> Result<()> {
        Ok(())
    }
}

impl<'a> RowDefinition<'a> for ExportedTypeRaw {
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* flags */          4 +
            /* type_def_id */    4 +
            /* type_name */      sizes.str_bytes() +
            /* type_namespace */ sizes.str_bytes() +
            /* implementation */ sizes.coded_index_bytes(CodedIndexType::Implementation)
        )
    }

    fn read_row(
        data: &'a [u8],
        offset: &mut usize,
        rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<Self> {
        Ok(ExportedTypeRaw {
            rid,
            token: Token::new(0x2700_0000 + rid),
            offset: *offset,
            flags: read_le_at::<u32>(data, offset)?,
            type_def_id: read_le_at::<u32>(data, offset)?,
            name: read_le_at_dyn(data, offset, sizes.is_large_str())?,
            namespace: read_le_at_dyn(data, offset, sizes.is_large_str())?,
            implementation: CodedIndex::read(data, offset, sizes, CodedIndexType::Implementation)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::tables::{MetadataTable, TableId, TableInfo};

    #[test]
    fn crafted_short() {
        let data = vec![
            0x01, 0x01, 0x01, 0x01, // flags
            0x02, 0x02, 0x02, 0x02, // type_def_id
            0x03, 0x03, // type_name
            0x04, 0x04, // type_namespace
            0x04, 0x00, // implementation (tag 0 = File, index = 1)
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::ExportedType, 1),
                (TableId::File, 10),        // Add File table
                (TableId::AssemblyRef, 10), // Add AssemblyRef table
            ],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<ExportedTypeRaw>::new(&data, 1, sizes.clone()).unwrap();

        let eval = |row: ExportedTypeRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x27000001);
            assert_eq!(row.flags, 0x01010101);
            assert_eq!(row.type_def_id, 0x02020202);
            assert_eq!(row.name, 0x0303);
            assert_eq!(row.namespace, 0x0404);
            assert_eq!(
                row.implementation,
                CodedIndex {
                    tag: TableId::File,
                    row: 1,
                    token: Token::new(1 | 0x26000000),
                }
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
            0x01, 0x01, 0x01, 0x01, // flags
            0x02, 0x02, 0x02, 0x02, // type_def_id
            0x03, 0x03, 0x03, 0x03, // type_name
            0x04, 0x04, 0x04, 0x04, // type_namespace
            0x04, 0x00, 0x00, 0x00, // implementation (tag 0 = File, index = 1)
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::ExportedType, u16::MAX as u32 + 3),
                (TableId::File, u16::MAX as u32 + 3), // Add File table
                (TableId::AssemblyRef, u16::MAX as u32 + 3), // Add AssemblyRef table
            ],
            true,
            true,
            true,
        ));
        let table = MetadataTable::<ExportedTypeRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: ExportedTypeRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x27000001);
            assert_eq!(row.flags, 0x01010101);
            assert_eq!(row.type_def_id, 0x02020202);
            assert_eq!(row.name, 0x03030303);
            assert_eq!(row.namespace, 0x04040404);
            assert_eq!(
                row.implementation,
                CodedIndex {
                    tag: TableId::File,
                    row: 1,
                    token: Token::new(1 | 0x26000000),
                }
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
