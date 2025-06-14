use std::sync::{Arc, OnceLock};

use crate::{
    file::io::{read_le_at, read_le_at_dyn},
    metadata::{
        streams::Strings,
        tables::{
            CodedIndex, CodedIndexType, GenericParam, GenericParamRc, RowDefinition, TableInfoRef,
        },
        token::Token,
        typesystem::CilTypeReference,
    },
    Result,
};

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
    use crate::metadata::tables::{MetadataTable, TableId, TableInfo};

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
