use crossbeam_skiplist::SkipMap;
use std::sync::Arc;

use crate::{
    file::io::{read_le_at, read_le_at_dyn},
    metadata::{
        streams::{
            Blob, CodedIndex, CodedIndexType, FieldMap, ParamMap, PropertyMap, RowDefinition,
            TableId, TableInfoRef,
        },
        token::Token,
        typesystem::{CilPrimitive, CilTypeReference},
    },
    Result,
};

/// A map that holds the mapping of Token to parsed `Constant`
pub type ConstantMap = SkipMap<Token, ConstantRc>;
/// A vector that holds a list of `Constant`
pub type ConstantList = Arc<boxcar::Vec<ConstantRc>>;
/// A reference to a `Constant`
pub type ConstantRc = Arc<Constant>;

/// The Constant table stores constant values for fields, parameters, and properties. Similar to `ConstantRaw` but
/// with resolved indexes and owned data
pub struct Constant {
    /// `RowID`
    pub rid: u32,
    /// Token
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// a 1-byte constant, followed by a 1-byte padding zero); see §II.23.1.16. The encoding of Type for the
    /// nullref value for `FieldInit` in ilasm (§II.16.2) is `ELEMENT_TYPE_CLASS` with a Value of a 4-byte zero.
    /// Unlike uses of `ELEMENT_TYPE_CLASS` in signatures, this one is not followed by a type toke
    pub c_type: u8,
    /// an index into the `Param`, `Field`, or `Property` table; more precisely, a `HasConstant` (§II.24.2.6) coded index
    pub parent: CilTypeReference,
    /// The const value
    pub value: Arc<CilPrimitive>,
}

#[derive(Clone, Debug)]
/// The Constant table stores constant values for fields, parameters, and properties. `TableId` = 0x0B
pub struct ConstantRaw {
    /// `RowID`
    pub rid: u32,
    /// Token
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// a 1-byte constant, followed by a 1-byte padding zero); see §II.23.1.16. The encoding of Type for the
    /// nullref value for `FieldInit` in ilasm (§II.16.2) is `ELEMENT_TYPE_CLASS` with a Value of a 4-byte zero.
    /// Unlike uses of `ELEMENT_TYPE_CLASS` in signatures, this one is not followed by a type toke
    pub base: u8,
    /// an index into the `Param`, `Field`, or `Property` table; more precisely, a `HasConstant` (§II.24.2.6) coded index
    pub parent: CodedIndex,
    /// an index into the Blob heap
    pub value: u32,
}

impl ConstantRaw {
    /// Apply an `ConstantRaw` to the relevant entries of types (e.g. fields, methods and parameters)
    ///
    /// ## Arguments
    /// * 'blob'        - The #Blob heap
    /// * 'params'      - All parsed `Param` entries
    /// * 'fields'      - All parsed `Field` entries
    /// * 'properties'  - All parsed `Property` entries
    ///
    /// # Errors
    /// Returns an error if:
    /// - The blob heap lookup fails for the constant value
    /// - The primitive value cannot be constructed from the blob data
    /// - The parent reference points to a non-existent entry in the respective table
    pub fn apply(
        &self,
        blob: &Blob,
        params: &ParamMap,
        fields: &FieldMap,
        properties: &PropertyMap,
    ) -> Result<()> {
        let default = CilPrimitive::from_blob(self.base, blob.get(self.value as usize)?)?;
        match self.parent.tag {
            TableId::Field => match fields.get(&self.parent.token) {
                Some(field) => field
                    .value()
                    .default
                    .set(default)
                    .map_err(|_| malformed_error!("Default value already set for field")),
                None => Err(malformed_error!(
                    "Failed to resolve field token - {}",
                    self.parent.token.value()
                )),
            },
            TableId::Param => match params.get(&self.parent.token) {
                Some(param) => param
                    .value()
                    .default
                    .set(default)
                    .map_err(|_| malformed_error!("Default value already set for param")),
                None => Err(malformed_error!(
                    "Failed to resolve param token - {}",
                    self.parent.token.value()
                )),
            },
            TableId::Property => match properties.get(&self.parent.token) {
                Some(property) => property
                    .value()
                    .default
                    .set(default)
                    .map_err(|_| malformed_error!("Default value already set for property")),
                None => Err(malformed_error!(
                    "Failed to resolve property token - {}",
                    self.parent.token.value()
                )),
            },
            _ => Err(malformed_error!(
                "Invalid parent token - {}",
                self.parent.token.value()
            )),
        }
    }

    /// Convert an `ConstantRaw`, into a `Constant` which has indexes resolved and owns the referenced data
    ///
    /// ## Arguments
    /// * 'blob'        - The #Blob heap
    /// * 'params'      - All parsed `Param` entries
    /// * 'fields'      - All parsed `Field` entries
    /// * 'properties'  - All parsed `Property` entries
    ///
    /// # Errors
    /// Returns an error if:
    /// - The blob heap lookup fails for the constant value
    /// - The primitive value cannot be constructed from the blob data
    /// - The parent reference cannot be resolved to a valid type reference
    pub fn to_owned(
        &self,
        blob: &Blob,
        params: &ParamMap,
        fields: &FieldMap,
        properties: &PropertyMap,
    ) -> Result<ConstantRc> {
        Ok(Arc::new(Constant {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            c_type: self.base,
            parent: match self.parent.tag {
                TableId::Param => match params.get(&self.parent.token) {
                    Some(param) => CilTypeReference::Param(param.value().clone()),
                    None => {
                        return Err(malformed_error!(
                            "Failed to resolve param token - {}",
                            self.parent.token.value()
                        ))
                    }
                },
                TableId::Field => match fields.get(&self.parent.token) {
                    Some(field) => CilTypeReference::Field(field.value().clone()),
                    None => {
                        return Err(malformed_error!(
                            "Failed to resolve field token - {}",
                            self.parent.token.value()
                        ))
                    }
                },
                TableId::Property => match properties.get(&self.parent.token) {
                    Some(property) => CilTypeReference::Property(property.value().clone()),
                    None => {
                        return Err(malformed_error!(
                            "Failed to resolve property token - {}",
                            self.parent.token.value()
                        ))
                    }
                },
                _ => {
                    return Err(malformed_error!(
                        "Invalid parent token - {}",
                        self.parent.token.value()
                    ))
                }
            },
            value: Arc::new(CilPrimitive::from_blob(
                self.base,
                blob.get(self.value as usize)?,
            )?),
        }))
    }
}

impl<'a> RowDefinition<'a> for ConstantRaw {
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* c_type */    1 +
            /* padding */   1 +
            /* parent */    sizes.coded_index_bytes(CodedIndexType::HasConstant) +
            /* value */     sizes.blob_bytes()
        )
    }

    fn read_row(
        data: &'a [u8],
        offset: &mut usize,
        rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<Self> {
        let offset_org = *offset;

        let c_type = read_le_at::<u8>(data, offset)?;
        *offset += 1; // Padding

        Ok(ConstantRaw {
            rid,
            token: Token::new(0x0B00_0000 + rid),
            offset: offset_org,
            base: c_type,
            parent: CodedIndex::read(data, offset, sizes, CodedIndexType::HasConstant)?,
            value: read_le_at_dyn(data, offset, sizes.is_large_blob())?,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::metadata::streams::tables::types::{MetadataTable, TableId, TableInfo};

    use super::*;

    #[test]
    fn crafted_short() {
        let data = vec![
            0x01, // type
            0x00, // padding
            0x02, 0x02, // parent
            0x03, 0x03, // value
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Property, 1)],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<ConstantRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: ConstantRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x0B000001);
            assert_eq!(row.base, 0x01);
            assert_eq!(
                row.parent,
                CodedIndex {
                    tag: TableId::Property,
                    row: 128,
                    token: Token::new(128 | 0x17000000),
                }
            );
            assert_eq!(row.value, 0x303);
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
            0x01, // type
            0x00, // padding
            0x02, 0x02, 0x02, 0x02, // parent
            0x03, 0x03, 0x03, 0x03, // value
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Property, u16::MAX as u32 + 3)],
            true,
            true,
            true,
        ));
        let table = MetadataTable::<ConstantRaw>::new(&data, u16::MAX as u32 + 3, sizes).unwrap();

        let eval = |row: ConstantRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x0B000001);
            assert_eq!(row.base, 0x1);
            assert_eq!(
                row.parent,
                CodedIndex {
                    tag: TableId::Property,
                    row: 0x808080,
                    token: Token::new(0x808080 | 0x17000000),
                }
            );
            assert_eq!(row.value, 0x3030303);
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
