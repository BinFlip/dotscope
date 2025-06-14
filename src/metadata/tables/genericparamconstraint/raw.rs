use std::sync::Arc;

use crate::{
    file::io::read_le_at_dyn,
    metadata::{
        tables::{
            CodedIndex, CodedIndexType, GenericParamConstraint, GenericParamConstraintRc,
            GenericParamMap, RowDefinition, TableId, TableInfoRef,
        },
        token::Token,
        typesystem::TypeRegistry,
        validation::ConstraintValidator,
    },
    Result,
};

#[derive(Clone, Debug)]
/// The `GenericParamConstraint` table defines constraints on generic parameters. `TableId` = 0x2C
pub struct GenericParamConstraintRaw {
    /// `RowID`
    pub rid: u32,
    /// Token
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// an index into the `GenericParam` table
    pub owner: u32,
    /// an index into the `TypeDefOrRef` coded index
    pub constraint: CodedIndex,
}

impl GenericParamConstraintRaw {
    /// Apply an `GenericParamConstraintRaw` to the relevant entries of types (e.g. fields, methods and parameters)
    ///
    /// ## Arguments
    /// * '`generic_params`'  - All parsed `GenericParam` entries
    /// * 'types'           - All parsed `TypeDef`, `TypeRef` and `TypeSpec` entries
    ///
    /// # Errors
    /// Returns an error if constraint or generic parameter lookup fails, or if
    /// constraint compatibility validation fails
    pub fn apply(&self, generic_params: &GenericParamMap, types: &TypeRegistry) -> Result<()> {
        let Some(constraint) = types.get(&self.constraint.token) else {
            return Err(malformed_error!(
                "Failed to resolve constraint token - {}",
                self.constraint.token
            ));
        };

        match generic_params.get(&Token::new(self.owner | 0x2A00_0000)) {
            Some(owner) => {
                ConstraintValidator::validate_constraint(
                    &constraint,
                    owner.value().flags,
                    &owner.value().name,
                    owner.value().token.value(),
                )?;

                owner.value().constraints.push(constraint.into());
                Ok(())
            }
            None => Err(malformed_error!(
                "Invalid owner token - {}",
                self.owner | 0x2A00_0000
            )),
        }
    }

    /// Convert an `GenericParamConstraintRaw`, into a `GenericParamConstraint` which has indexes resolved and owns the referenced data
    ///
    /// ## Arguments
    /// * '`generic_params`'  - All parsed `GenericParam` entries
    /// * 'types'           - All parsed `TypeDef`, `TypeRef` and `TypeSpec` entries
    ///
    /// # Errors
    /// Returns an error if generic parameter or constraint type lookup fails
    pub fn to_owned(
        &self,
        generic_params: &GenericParamMap,
        types: &TypeRegistry,
    ) -> Result<GenericParamConstraintRc> {
        Ok(Arc::new(GenericParamConstraint {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            owner: match generic_params.get(&Token::new(self.owner | 0x2A00_0000)) {
                Some(owner) => owner.value().clone(),
                None => {
                    return Err(malformed_error!(
                        "Failed to generic_param token - {}",
                        self.owner | 0x2A00_0000
                    ))
                }
            },
            constraint: match types.get(&self.constraint.token) {
                Some(constraint) => constraint,
                None => {
                    return Err(malformed_error!(
                        "Failed to resolve constraint type token - {}",
                        self.constraint.token.value()
                    ))
                }
            },
            custom_attributes: Arc::new(boxcar::Vec::new()),
        }))
    }
}

impl<'a> RowDefinition<'a> for GenericParamConstraintRaw {
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* owner */      sizes.table_index_bytes(TableId::GenericParam) +
            /* constraint */ sizes.coded_index_bytes(CodedIndexType::TypeDefOrRef)
        )
    }

    fn read_row(
        data: &'a [u8],
        offset: &mut usize,
        rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<Self> {
        Ok(GenericParamConstraintRaw {
            rid,
            token: Token::new(0x2C00_0000 + rid),
            offset: *offset,
            owner: read_le_at_dyn(data, offset, sizes.is_large(TableId::GenericParam))?,
            constraint: CodedIndex::read(data, offset, sizes, CodedIndexType::TypeDefOrRef)?,
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
            0x01, 0x01, // owner
            0x08, 0x00, // constraint (tag 0 = TypeDef, index = 2)
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::GenericParamConstraint, 1),
                (TableId::GenericParam, 10),
                (TableId::TypeDef, 10),
                (TableId::TypeRef, 10),
                (TableId::TypeSpec, 10),
            ],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<GenericParamConstraintRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: GenericParamConstraintRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x2C000001);
            assert_eq!(row.owner, 0x0101);
            assert_eq!(
                row.constraint,
                CodedIndex {
                    tag: TableId::TypeDef,
                    row: 2,
                    token: Token::new(2 | 0x02000000),
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
            0x01, 0x01, 0x01, 0x01, // owner
            0x08, 0x00, 0x00, 0x00, // constraint (tag 0 = TypeDef, index = 2)
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::GenericParamConstraint, u16::MAX as u32 + 3),
                (TableId::GenericParam, u16::MAX as u32 + 3),
                (TableId::TypeDef, u16::MAX as u32 + 3),
                (TableId::TypeRef, u16::MAX as u32 + 3),
                (TableId::TypeSpec, u16::MAX as u32 + 3),
            ],
            true,
            true,
            true,
        ));
        let table = MetadataTable::<GenericParamConstraintRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: GenericParamConstraintRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x2C000001);
            assert_eq!(row.owner, 0x01010101);
            assert_eq!(
                row.constraint,
                CodedIndex {
                    tag: TableId::TypeDef,
                    row: 2,
                    token: Token::new(2 | 0x02000000)
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
