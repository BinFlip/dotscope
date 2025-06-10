use crossbeam_skiplist::SkipMap;
use std::sync::{Arc, OnceLock};

use crate::{
    file::io::{read_le_at, read_le_at_dyn},
    metadata::{
        customattributes::CustomAttributeValueList,
        streams::{CodedIndex, CodedIndexType, RowDefinition, Strings, TableInfoRef},
        token::Token,
        typesystem::{CilTypeRefList, CilTypeReference},
    },
    Result,
};

#[allow(non_snake_case)]
/// All possible flags for `GenericParamAttributes`
pub mod GenericParamAttributes {
    /// The generic parameter is covariant
    pub const VARIANCE_MASK: u32 = 0x0003;
    /// The generic parameter is covariant
    pub const COVARIANT: u32 = 0x0001;
    /// The generic parameter is contravariant
    pub const CONTRAVARIANT: u32 = 0x0002;
    /// The generic parameter has a special constraint
    pub const SPECIAL_CONSTRAINT_MASK: u32 = 0x001C;
    /// The generic parameter has a reference type constraint
    pub const REFERENCE_TYPE_CONSTRAINT: u32 = 0x0004;
    /// The generic parameter has a value type constraint
    pub const NOT_NULLABLE_VALUE_TYPE_CONSTRAINT: u32 = 0x0008;
    /// The generic parameter has a constructor constraint
    pub const DEFAULT_CONSTRUCTOR_CONSTRAINT: u32 = 0x0010;
}

/// A map that holds the mapping of Token to parsed `GenericParam`
pub type GenericParamMap = SkipMap<Token, GenericParamRc>;
/// A vector that holds a list of `GenericParam`
pub type GenericParamList = Arc<boxcar::Vec<GenericParamRc>>;
/// A reference to a `GenericParam`
pub type GenericParamRc = Arc<GenericParam>;

/// The `GenericParam` table defines generic parameters for generic types and methods. Similar to `GenericParamRaw` but
/// with resolved indexes and owned data
pub struct GenericParam {
    /// `RowID`
    pub rid: u32,
    /// Token
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// a 2-byte index of the generic parameter, numbered left-to-right, from zero
    pub number: u32,
    /// a 2-byte bitmask of type `GenericParamAttributes`, §II.23.1.7
    pub flags: u32,
    /// The owner of this `GenericParam`
    pub owner: OnceLock<CilTypeReference>,
    /// The contrained type that applies to this `GenericParam`
    pub constraints: CilTypeRefList,
    /// Name of the generic parameter
    pub name: String,
    /// Custom attributes applied to this `GenericParam`
    pub custom_attributes: CustomAttributeValueList,
}

impl GenericParam {
    /// Apply an `GenericParam` - The owner will be updated with the new `GenericParam` entry
    ///
    /// # Errors
    /// Returns an error if the owner type reference is invalid or not set
    pub fn apply(self: &Arc<Self>) -> Result<()> {
        match self.owner.get() {
            Some(owner) => match owner {
                CilTypeReference::TypeDef(cil_type) => {
                    if let Some(generic_params) = cil_type.generic_params() {
                        generic_params.push(self.clone());
                    }

                    Ok(())
                }
                CilTypeReference::MethodDef(method) => {
                    if let Some(method) = method.upgrade() {
                        method.generic_params.push(self.clone());
                    }

                    Ok(())
                }
                _ => Err(malformed_error!("Invalid owner type reference")),
            },
            None => Err(malformed_error!("No owner type reference")),
        }
    }
}

#[derive(Clone, Debug)]
/// The `GenericParam` table defines generic parameters for generic types and methods. `TableId` = 0x2A
pub struct GenericParamRaw {
    /// `RowID`
    pub rid: u32,
    /// Token
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// a 2-byte index of the generic parameter, numbered left-to-right, from zero
    pub number: u32,
    /// a 2-byte bitmask of type `GenericParamAttributes`, §II.23.1.7
    pub flags: u32,
    /// an index into the `TypeOrMethodDef` coding index
    pub owner: CodedIndex,
    /// an index into the String heap
    pub name: u32,
}

impl GenericParamRaw {
    /// Convert an `GenericParamRaw`, into a `GenericParam` which has indexes resolved and owns the referenced data.
    ///
    /// ## Arguments
    /// * 'strings' - The #String heap
    /// * 'types'   - All parsed `CilType` entries
    /// * 'methods' - All parsed `MethodDef` entries
    ///
    /// # Errors
    /// Returns an error if string lookup fails or if owner resolution fails
    pub fn to_owned<F>(&self, get_ref: F, strings: &Strings) -> Result<GenericParamRc>
    where
        F: Fn(&CodedIndex) -> CilTypeReference,
    {
        let owner_ref = get_ref(&self.owner);
        if matches!(owner_ref, CilTypeReference::None) {
            return Err(malformed_error!(
                "Failed to resolve owner token - {}",
                self.owner.token.value()
            ));
        }

        let owner = OnceLock::new();
        owner.set(owner_ref).ok();

        Ok(Arc::new(GenericParam {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            number: self.number,
            flags: self.flags,
            owner,
            constraints: Arc::new(boxcar::Vec::new()),
            name: strings.get(self.name as usize)?.to_string(),
            custom_attributes: Arc::new(boxcar::Vec::new()),
        }))
    }
}

impl<'a> RowDefinition<'a> for GenericParamRaw {
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* number */ 2 +
            /* flags */  2 +
            /* owner */  sizes.coded_index_bytes(CodedIndexType::TypeOrMethodDef) +
            /* name */   sizes.str_bytes()
        )
    }

    fn read_row(
        data: &'a [u8],
        offset: &mut usize,
        rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<Self> {
        Ok(GenericParamRaw {
            rid,
            token: Token::new(0x2A00_0000 + rid),
            offset: *offset,
            number: u32::from(read_le_at::<u16>(data, offset)?),
            flags: u32::from(read_le_at::<u16>(data, offset)?),
            owner: CodedIndex::read(data, offset, sizes, CodedIndexType::TypeOrMethodDef)?,
            name: read_le_at_dyn(data, offset, sizes.is_large_str())?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::streams::{MetadataTable, TableId, TableInfo};

    #[test]
    fn crafted_short() {
        let data = vec![
            0x01, 0x01, // number
            0x02, 0x02, // flags
            0x02, 0x00, // owner (tag 0 = TypeDef, index = 1)
            0x04, 0x04, // name
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::GenericParam, 1),
                (TableId::TypeDef, 10),
                (TableId::MethodDef, 10),
            ],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<GenericParamRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: GenericParamRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x2A000001);
            assert_eq!(row.number, 0x0101);
            assert_eq!(row.flags, 0x0202);
            assert_eq!(
                row.owner,
                CodedIndex {
                    tag: TableId::TypeDef,
                    row: 1,
                    token: Token::new(1 | 0x02000000),
                }
            );
            assert_eq!(row.name, 0x0404);
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
            0x01, 0x01, // number
            0x02, 0x02, // flags
            0x02, 0x00, 0x00, 0x00, // owner (tag 0 = TypeDef, index = 1)
            0x04, 0x04, 0x04, 0x04, // name
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::GenericParam, u16::MAX as u32 + 3),
                (TableId::TypeDef, u16::MAX as u32 + 3),
                (TableId::MethodDef, u16::MAX as u32 + 3),
            ],
            true,
            true,
            true,
        ));
        let table = MetadataTable::<GenericParamRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: GenericParamRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x2A000001);
            assert_eq!(row.number, 0x0101);
            assert_eq!(row.flags, 0x0202);
            assert_eq!(
                row.owner,
                CodedIndex {
                    tag: TableId::TypeDef,
                    row: 1,
                    token: Token::new(1 | 0x02000000),
                }
            );
            assert_eq!(row.name, 0x04040404);
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
