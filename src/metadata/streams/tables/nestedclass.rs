use crossbeam_skiplist::SkipMap;
use std::{collections::HashMap, sync::Arc};

use crate::{
    file::io::read_le_at_dyn,
    metadata::{
        streams::{MetadataTable, RowDefinition, TableId, TableInfoRef},
        token::Token,
        typesystem::{CilTypeRc, TypeRegistry},
        validation::NestedClassValidator,
    },
    Result,
};

/// A map that holds the mapping of Token to parsed `NestedClass`
pub type NestedClassMap = SkipMap<Token, NestedClassRc>;
/// A vector that holds a list of `NestedClass`
pub type NestedClassList = Arc<boxcar::Vec<NestedClassRc>>;
/// A reference to a `NestedClass`
pub type NestedClassRc = Arc<NestedClass>;

/// The `NestedClass` table defines the relationship between nested types and their enclosing types. Similar to `NestedClassRaw` but
/// with resolved indexes and owned data
pub struct NestedClass {
    /// `RowID`
    pub rid: u32,
    /// Token
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// an index into the `TypeDef` table
    pub nested_class: CilTypeRc,
    /// an index into the `TypeDef` table
    pub enclosing_class: CilTypeRc,
}

impl NestedClass {
    /// Apply a `NestedClass` to update the enclosing type with the nested type reference.
    ///
    /// Since this is the owned structure, all references are already resolved, so we can
    /// efficiently update the enclosing type without re-resolving anything.
    ///
    /// # Errors
    /// Returns an error if the enclosing class and nested class are the same type,
    /// or if nested class validation fails.
    pub fn apply(&self) -> Result<()> {
        NestedClassValidator::validate_nested_relationship(
            self.nested_class.token,
            self.enclosing_class.token,
        )?;

        self.enclosing_class
            .nested_types
            .push(self.nested_class.clone().into());
        Ok(())
    }
}

#[derive(Clone, Debug)]
/// The `NestedClass` table defines the relationship between nested types and their enclosing types. `TableId` = 0x29
pub struct NestedClassRaw {
    /// `RowID`
    pub rid: u32,
    /// Token
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// an index into the `TypeDef` table
    pub nested_class: u32,
    /// an index into the `TypeDef` table
    pub enclosing_class: u32,
}

impl NestedClassRaw {
    /// Apply all `NestedClassRaw` to the relevant entries of types (e.g. fields, methods and parameters)
    ///
    /// # Errors
    ///
    /// Returns an error if nested class validation fails or if referenced types
    /// cannot be found in the type registry.
    ///
    /// ## Arguments
    /// * 'classes'  - The metadatatable of the nested classes
    /// * 'types'    - All parsed `CilType` entries
    pub fn apply(classes: &MetadataTable<NestedClassRaw>, types: &TypeRegistry) -> Result<()> {
        let mut mapping: HashMap<u32, Vec<u32>> = HashMap::new();

        for row in classes {
            let nested_token = Token::new(row.nested_class | 0x0200_0000);
            let enclosing_token = Token::new(row.enclosing_class | 0x0200_0000);

            NestedClassValidator::validate_nested_relationship(nested_token, enclosing_token)?;

            mapping
                .entry(row.enclosing_class | 0x0200_0000)
                .or_default()
                .push(row.nested_class | 0x0200_0000);
        }

        for (enclosing, nested_classes) in mapping {
            match types.get(&Token::new(enclosing)) {
                Some(cil_type) => {
                    for nested_class in nested_classes {
                        match types.get(&Token::new(nested_class)) {
                            Some(nested_type) => {
                                _ = cil_type.nested_types.push(nested_type.clone().into());
                            }
                            None => {
                                return Err(malformed_error!(
                                    "Failed to resolve nested_class type - {}",
                                    nested_class
                                ))
                            }
                        }
                    }
                }
                None => {
                    return Err(malformed_error!(
                        "Failed to resolve enclosing_class type - {}",
                        enclosing
                    ))
                }
            }
        }

        Ok(())
    }

    /// Convert an `NestedClassRaw`, into a `NestedClass` which has indexes resolved and owns the referenced data
    ///
    /// ## Arguments
    /// * 'types'   - All parsed `CilType` entries
    ///
    /// # Errors
    /// Returns an error if the nested class or enclosing class types cannot be resolved.
    pub fn to_owned(&self, types: &TypeRegistry) -> Result<NestedClassRc> {
        Ok(Arc::new(NestedClass {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            nested_class: match types.get(&Token::new(self.nested_class | 0x0200_0000)) {
                Some(class) => class.clone(),
                None => {
                    return Err(malformed_error!(
                        "Failed to resolve nested_class type - {}",
                        self.nested_class | 0x0200_0000
                    ))
                }
            },
            enclosing_class: match types.get(&Token::new(self.enclosing_class | 0x0200_0000)) {
                Some(class) => class.clone(),
                None => {
                    return Err(malformed_error!(
                        "Failed to resolve enclosing_class - {}",
                        self.enclosing_class | 0x0200_0000
                    ))
                }
            },
        }))
    }
}

impl<'a> RowDefinition<'a> for NestedClassRaw {
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* nested_class */    sizes.table_index_bytes(TableId::TypeDef) +
            /* enclosing_class */ sizes.table_index_bytes(TableId::TypeDef)
        )
    }

    fn read_row(
        data: &'a [u8],
        offset: &mut usize,
        rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<Self> {
        Ok(NestedClassRaw {
            rid,
            token: Token::new(0x2900_0000 + rid),
            offset: *offset,
            nested_class: read_le_at_dyn(data, offset, sizes.is_large(TableId::TypeDef))?,
            enclosing_class: read_le_at_dyn(data, offset, sizes.is_large(TableId::TypeDef))?,
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
            0x01, 0x01, // nested_class
            0x02, 0x02, // enclosing_class
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::NestedClass, 1), (TableId::TypeDef, 10)],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<NestedClassRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: NestedClassRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x29000001);
            assert_eq!(row.nested_class, 0x0101);
            assert_eq!(row.enclosing_class, 0x0202);
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
            0x01, 0x01, 0x01, 0x01, // nested_class
            0x02, 0x02, 0x02, 0x02, // enclosing_class
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::NestedClass, u16::MAX as u32 + 3),
                (TableId::TypeDef, u16::MAX as u32 + 3),
            ],
            true,
            true,
            true,
        ));
        let table = MetadataTable::<NestedClassRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: NestedClassRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x29000001);
            assert_eq!(row.nested_class, 0x01010101);
            assert_eq!(row.enclosing_class, 0x02020202);
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
