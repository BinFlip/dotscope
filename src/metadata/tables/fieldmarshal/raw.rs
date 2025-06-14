use std::sync::Arc;

use crate::{
    file::io::read_le_at_dyn,
    metadata::{
        marshalling::parse_marshalling_descriptor,
        streams::Blob,
        tables::{
            CodedIndex, CodedIndexType, FieldMap, FieldMarshal, FieldMarshalRc, ParamMap,
            RowDefinition, TableId, TableInfoRef,
        },
        token::Token,
        typesystem::CilTypeReference,
    },
    Result,
};

#[derive(Clone, Debug)]
/// The `FieldMarshal` table specifies marshaling information for fields and parameters. `TableId` = 0x0D
pub struct FieldMarshalRaw {
    /// `RowID`
    pub rid: u32,
    /// Token
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// an index into Field or Param table; more precisely, a `HasFieldMarshal` (§II.24.2.6) coded index
    pub parent: CodedIndex,
    /// an index into the Blob heap
    pub native_type: u32,
}

impl FieldMarshalRaw {
    /// Apply an `FieldMarshalRaw` to the relevant entries of types (e.g. fields, methods and parameters)
    ///
    /// ## Arguments
    /// * 'blob'        - The #Blob heap
    /// * 'params'      - All parsed `Param` entries
    /// * 'fields'      - All parsed `Field` entries
    ///
    /// # Errors
    /// Returns an error if blob lookup fails, marshalling descriptor parsing fails, or field/param lookup fails
    pub fn apply(&self, blob: &Blob, params: &ParamMap, fields: &FieldMap) -> Result<()> {
        let marshal = parse_marshalling_descriptor(blob.get(self.native_type as usize)?)?;

        match self.parent.tag {
            TableId::Field => match fields.get(&self.parent.token) {
                Some(field) => field
                    .value()
                    .marshal
                    .set(marshal)
                    .map_err(|_| malformed_error!("Marshal info already set for field")),
                None => Err(malformed_error!(
                    "Failed to resolve field token - {}",
                    self.parent.token.value()
                )),
            },
            TableId::Param => match params.get(&self.parent.token) {
                Some(param) => param
                    .value()
                    .marshal
                    .set(marshal)
                    .map_err(|_| malformed_error!("Marshal info already set for param")),
                None => Err(malformed_error!(
                    "Failed to resolve param token - {}",
                    self.parent.token.value()
                )),
            },
            _ => Err(malformed_error!(
                "Invalid parent token - {}",
                self.parent.token.value()
            )),
        }
    }

    /// Convert an `FieldMarshalRaw`, into a `FieldMarshal` which has indexes resolved and owns the referenced data
    ///
    /// ## Arguments
    /// * 'blob'        - The #Blob heap
    /// * 'params'      - All parsed `Param` entries
    /// * 'fields'      - All parsed `Field` entries
    ///
    /// # Errors
    /// Returns an error if blob lookup fails, marshalling descriptor parsing fails, or parent resolution fails
    pub fn to_owned<F>(&self, get_ref: F, blob: &Blob) -> Result<FieldMarshalRc>
    where
        F: Fn(&CodedIndex) -> CilTypeReference,
    {
        let parent = get_ref(&self.parent);
        if matches!(parent, CilTypeReference::None) {
            return Err(malformed_error!(
                "Failed to resolve parent token - {}",
                self.parent.token.value()
            ));
        }

        Ok(Arc::new(FieldMarshal {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            parent,
            native_type: Arc::new(parse_marshalling_descriptor(
                blob.get(self.native_type as usize)?,
            )?),
        }))
    }
}

impl<'a> RowDefinition<'a> for FieldMarshalRaw {
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* parent */      sizes.coded_index_bytes(CodedIndexType::HasFieldMarshal) +
            /* native_type */ sizes.blob_bytes()
        )
    }

    fn read_row(
        data: &'a [u8],
        offset: &mut usize,
        rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<Self> {
        let offset_org = *offset;

        Ok(FieldMarshalRaw {
            rid,
            token: Token::new(0x0D00_0000 + rid),
            offset: offset_org,
            parent: CodedIndex::read(data, offset, sizes, CodedIndexType::HasFieldMarshal)?,
            native_type: read_le_at_dyn(data, offset, sizes.is_large_blob())?,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::metadata::tables::{MetadataTable, TableId, TableInfo};

    use super::*;

    #[test]
    fn crafted_short() {
        let data = vec![
            0x02, 0x02, // parent
            0x03, 0x03, // native_type
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Field, 1), (TableId::Param, 1)],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<FieldMarshalRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: FieldMarshalRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x0D000001);
            assert_eq!(
                row.parent,
                CodedIndex {
                    tag: TableId::Field,
                    row: 257,
                    token: Token::new(257 | 0x04000000),
                }
            );
            assert_eq!(row.native_type, 0x303);
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
            0x02, 0x02, 0x02, 0x02, // parent
            0x03, 0x03, 0x03, 0x03, // native_type
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::Field, u16::MAX as u32 + 3),
                (TableId::Param, u16::MAX as u32 + 3),
            ],
            true,
            true,
            true,
        ));
        let table =
            MetadataTable::<FieldMarshalRaw>::new(&data, u16::MAX as u32 + 3, sizes).unwrap();

        let eval = |row: FieldMarshalRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x0D000001);
            assert_eq!(
                row.parent,
                CodedIndex {
                    tag: TableId::Field,
                    row: 0x1010101,
                    token: Token::new(0x1010101 | 0x04000000),
                }
            );
            assert_eq!(row.native_type, 0x3030303);
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
