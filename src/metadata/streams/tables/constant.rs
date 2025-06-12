use crossbeam_skiplist::SkipMap;
use std::sync::Arc;

use crate::{
    file::io::{read_le_at, read_le_at_dyn},
    metadata::{
        streams::{Blob, CodedIndex, CodedIndexType, RowDefinition, TableInfoRef},
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

impl Constant {
    /// Apply a `Constant` to set the default value on the parent entity (field, parameter, or property)
    ///
    /// # Errors
    /// Returns an error if the default value is already set for the parent entity,
    /// or if the constant value is not compatible with the target type
    pub fn apply(&self) -> Result<()> {
        match &self.parent {
            CilTypeReference::Field(field) => {
                if !field.signature.base.accepts_constant(&self.value) {
                    return Err(malformed_error!(
                        "Constant type {:?} is not compatible with field type: {:?} (token: {})",
                        self.value.kind,
                        field.signature.base,
                        self.token.value()
                    ));
                }

                field
                    .default
                    .set(self.value.as_ref().clone())
                    .map_err(|_| malformed_error!("Default value already set for field"))
            }
            CilTypeReference::Param(param) => {
                if let Some(param_type) = param.base.get() {
                    if let Some(param_type_strong) = param_type.upgrade() {
                        if !param_type_strong.accepts_constant(&self.value) {
                            return Err(malformed_error!(
                                "Constant type {:?} is not compatible with parameter type {} (token: {})",
                                self.value.kind,
                                param_type_strong.fullname(),
                                self.token.value()
                            ));
                        }
                    }
                }

                param
                    .default
                    .set(self.value.as_ref().clone())
                    .map_err(|_| malformed_error!("Default value already set for param"))
            }
            CilTypeReference::Property(property) => {
                if !property.signature.base.accepts_constant(&self.value) {
                    return Err(malformed_error!(
                        "Constant type {:?} is not compatible with property type: {:?} (token: {})",
                        self.value.kind,
                        property.signature.base,
                        self.token.value()
                    ));
                }

                property
                    .default
                    .set(self.value.as_ref().clone())
                    .map_err(|_| malformed_error!("Default value already set for property"))
            }
            _ => Err(malformed_error!(
                "Invalid parent type for constant - {}",
                self.token.value()
            )),
        }
    }
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
    /// * `get_ref` - A closure that resolves coded indices to `CilTypeReference`
    /// * 'blob'    - The #Blob heap
    ///
    /// # Errors
    /// Returns an error if:
    /// - The blob heap lookup fails for the constant value
    /// - The primitive value cannot be constructed from the blob data
    /// - The parent reference cannot be resolved to a valid type reference
    /// - The default value is already set for the parent entity
    pub fn apply<F>(&self, get_ref: F, blob: &Blob) -> Result<()>
    where
        F: Fn(&CodedIndex) -> CilTypeReference,
    {
        let parent = get_ref(&self.parent);
        let default = CilPrimitive::from_blob(self.base, blob.get(self.value as usize)?)?;

        match &parent {
            CilTypeReference::Field(field) => {
                if !field.signature.base.accepts_constant(&default) {
                    return Err(malformed_error!(
                        "Constant type {:?} is not compatible with field type: {:?} (token: {})",
                        default.kind,
                        field.signature.base,
                        self.token.value()
                    ));
                }

                field
                    .default
                    .set(default)
                    .map_err(|_| malformed_error!("Default value already set for field"))
            }
            CilTypeReference::Param(param) => {
                if let Some(param_type) = param.base.get() {
                    if let Some(param_type_strong) = param_type.upgrade() {
                        if !param_type_strong.accepts_constant(&default) {
                            return Err(malformed_error!(
                                "Constant type {:?} is not compatible with parameter type {} (token: {})",
                                default.kind,
                                param_type_strong.fullname(),
                                self.token.value()
                            ));
                        }
                    }
                }

                param
                    .default
                    .set(default)
                    .map_err(|_| malformed_error!("Default value already set for param"))
            }
            CilTypeReference::Property(property) => {
                if !property.signature.base.accepts_constant(&default) {
                    return Err(malformed_error!(
                        "Constant type {:?} is not compatible with property type: {:?} (token: {})",
                        default.kind,
                        property.signature.base,
                        self.token.value()
                    ));
                }

                property
                    .default
                    .set(default)
                    .map_err(|_| malformed_error!("Default value already set for property"))
            }
            _ => Err(malformed_error!(
                "Invalid parent type for constant - {}",
                self.parent.token.value()
            )),
        }
    }

    /// Convert an `ConstantRaw`, into a `Constant` which has indexes resolved and owns the referenced data
    ///
    /// ## Arguments
    /// * `get_ref` - A closure that resolves coded indices to `CilTypeReference`
    /// * 'blob'    - The #Blob heap
    ///
    /// # Errors
    /// Returns an error if:
    /// - The blob heap lookup fails for the constant value
    /// - The primitive value cannot be constructed from the blob data
    /// - The parent reference cannot be resolved to a valid type reference
    pub fn to_owned<F>(&self, get_ref: F, blob: &Blob) -> Result<ConstantRc>
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

        Ok(Arc::new(Constant {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            c_type: self.base,
            parent,
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
