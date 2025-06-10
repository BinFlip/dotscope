use crossbeam_skiplist::SkipMap;
use std::sync::Arc;

use crate::{
    file::io::{read_le_at, read_le_at_dyn},
    metadata::{
        method::{MethodMap, MethodRc},
        streams::{
            CodedIndex, CodedIndexType, EventMap, PropertyMap, RowDefinition, TableId, TableInfoRef,
        },
        token::Token,
        typesystem::CilTypeReference,
    },
    Result,
};

/// A map that holds the mapping of Token to parsed `MethodSemantics`
pub type MethodSemanticsMap = SkipMap<Token, MethodSemanticsRc>;
/// A vector that holds a list of `MethodSemantics`
pub type MethodSemanticsList = Arc<boxcar::Vec<MethodSemanticsRc>>;
/// A reference to a `MethodSemantics`
pub type MethodSemanticsRc = Arc<MethodSemantics>;

#[allow(non_snake_case)]
/// All possible flags for `MethodSemanticsAttributes`
pub mod MethodSemanticsAttributes {
    /// Setter for property
    pub const SETTER: u32 = 0x0001;
    /// Getter for property
    pub const GETTER: u32 = 0x0002;
    /// Other method for property or event
    pub const OTHER: u32 = 0x0004;
    /// `AddOn` method for event
    pub const ADD_ON: u32 = 0x0008;
    /// `RemoveOn` method for event
    pub const REMOVE_ON: u32 = 0x0010;
    /// Fire method for event
    pub const FIRE: u32 = 0x0020;
}

/// The `MethodSemantics` table specifies the relationship between methods and events or properties.
/// It defines which methods are getters, setters, adders, removers, etc. Similar to `ConstantRaw` but
/// with resolved indexes and owned data
pub struct MethodSemantics {
    /// `RowID`
    pub rid: u32,
    /// Token
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// a 2-byte bitmask of type `MethodSemanticsAttributes`, §II.23.1.12
    pub semantics: u32,
    /// an index into the `MethodDef` table
    pub method: MethodRc,
    /// a `HasSemantics` coded index
    pub association: CilTypeReference,
}

impl MethodSemantics {
    /// Apply a `MethodSemantics` entry - The associated type fill be updated to have it's getter/setter set
    ///
    /// # Errors
    /// Returns an error if the semantics attributes are invalid or if the property/event
    /// assignment fails.
    pub fn apply(&self) -> Result<()> {
        match &self.association {
            CilTypeReference::Property(property) => match self.semantics {
                MethodSemanticsAttributes::SETTER => property
                    .fn_setter
                    .set(self.method.clone().into())
                    .map_err(|_| malformed_error!("Property setter already set")),
                MethodSemanticsAttributes::GETTER => property
                    .fn_getter
                    .set(self.method.clone().into())
                    .map_err(|_| malformed_error!("Property getter already set")),
                MethodSemanticsAttributes::OTHER => property
                    .fn_other
                    .set(self.method.clone().into())
                    .map_err(|_| malformed_error!("Property other already set")),
                _ => Err(malformed_error!("Invalid property semantics")),
            },
            CilTypeReference::Event(event) => match self.semantics {
                MethodSemanticsAttributes::ADD_ON => event
                    .fn_on_add
                    .set(self.method.clone().into())
                    .map_err(|_| malformed_error!("Event add method already set")),
                MethodSemanticsAttributes::REMOVE_ON => event
                    .fn_on_remove
                    .set(self.method.clone().into())
                    .map_err(|_| malformed_error!("Event remove method already set")),
                MethodSemanticsAttributes::FIRE => event
                    .fn_on_raise
                    .set(self.method.clone().into())
                    .map_err(|_| malformed_error!("Event raise method already set")),
                MethodSemanticsAttributes::OTHER => event
                    .fn_on_other
                    .set(self.method.clone().into())
                    .map_err(|_| malformed_error!("Event other method already set")),
                _ => Err(malformed_error!("Invalid event semantics")),
            },
            _ => Err(malformed_error!("Invalid association")),
        }
    }
}

#[derive(Clone, Debug)]
/// The `MethodSemantics` table specifies the relationship between methods and events or properties.
/// It defines which methods are getters, setters, adders, removers, etc. `TableId` = 0x18
pub struct MethodSemanticsRaw {
    /// `RowID`
    pub rid: u32,
    /// Token
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// a 2-byte bitmask of type `MethodSemanticsAttributes`, §II.23.1.12
    pub semantics: u32,
    /// an index into the `MethodDef` table
    pub method: u32,
    /// an index into the `HasSemantics` coding index
    pub association: CodedIndex,
}

impl MethodSemanticsRaw {
    /// Apply an `MethodSemanticsRaw` to the relevant entries of types (e.g. fields, methods and parameters)
    ///
    /// ## Arguments
    /// * 'methods'     - All parsed `MethodDef` entries
    /// * 'events'      - All parsed `Event` entries
    /// * 'properties'  - All parsed `Property` entries
    ///
    /// # Errors
    /// Returns an error if the method token cannot be resolved or if the association
    /// coded index cannot be parsed correctly.
    pub fn apply(
        &self,
        methods: &MethodMap,
        events: &EventMap,
        properties: &PropertyMap,
    ) -> Result<()> {
        let Some(method) = methods.get(&Token::new(self.method | 0x0600_0000)) else {
            return Err(malformed_error!(
                "Failed to resolve method token - {}",
                self.method | 0x0600_0000
            ));
        };

        match self.association.tag {
            TableId::Property => match properties.get(&self.association.token) {
                Some(found_type) => match self.semantics {
                    MethodSemanticsAttributes::SETTER => {
                        found_type
                            .value()
                            .fn_setter
                            .set(method.value().clone().into())
                            .map_err(|_| malformed_error!("Property `setter` already set"))?;
                        Ok(())
                    }
                    MethodSemanticsAttributes::GETTER => {
                        found_type
                            .value()
                            .fn_getter
                            .set(method.value().clone().into())
                            .map_err(|_| malformed_error!("Property `getter` already set"))?;
                        Ok(())
                    }
                    MethodSemanticsAttributes::OTHER => {
                        found_type
                            .value()
                            .fn_other
                            .set(method.value().clone().into())
                            .map_err(|_| malformed_error!("Property `other` method already set"))?;
                        Ok(())
                    }
                    _ => Err(malformed_error!("Invalid property semantics")),
                },
                None => Err(malformed_error!(
                    "Failed to resolve property association token - {}",
                    self.association.token.value()
                )),
            },
            TableId::Event => match events.get(&self.association.token) {
                Some(found_type) => match self.semantics {
                    MethodSemanticsAttributes::ADD_ON => {
                        found_type
                            .value()
                            .fn_on_add
                            .set(method.value().clone().into())
                            .map_err(|_| malformed_error!("Event `add` method already set"))?;
                        Ok(())
                    }
                    MethodSemanticsAttributes::REMOVE_ON => {
                        found_type
                            .value()
                            .fn_on_remove
                            .set(method.value().clone().into())
                            .map_err(|_| malformed_error!("Event `remove` method already set"))?;
                        Ok(())
                    }
                    MethodSemanticsAttributes::FIRE => {
                        found_type
                            .value()
                            .fn_on_raise
                            .set(method.value().clone().into())
                            .map_err(|_| malformed_error!("Event `raise` method already set"))?;
                        Ok(())
                    }
                    MethodSemanticsAttributes::OTHER => {
                        found_type
                            .value()
                            .fn_on_other
                            .set(method.value().clone().into())
                            .map_err(|_| malformed_error!("Event `other` method already set"))?;
                        Ok(())
                    }
                    _ => Err(malformed_error!("Invalid event semantics")),
                },
                None => Err(malformed_error!(
                    "Failed to resolve event association token - {}",
                    self.association.token.value()
                )),
            },
            _ => Err(malformed_error!(
                "Invalid association token - {}",
                self.association.token.value()
            )),
        }
    }

    /// Convert an `MethodSemanticsRaw`, into a `MethodSemantics` which has indexes resolved and owns the referenced data
    ///
    /// ## Arguments
    /// * 'methods'     - All parsed `MethodDef` entries
    /// * 'events'      - All parsed `Event` entries
    /// * 'properties'  - All parsed `Property` entries
    ///
    /// # Errors
    /// Returns an error if the method token cannot be resolved or if the association
    /// coded index cannot be parsed correctly.
    pub fn to_owned(
        &self,
        methods: &MethodMap,
        events: &EventMap,
        properties: &PropertyMap,
    ) -> Result<MethodSemanticsRc> {
        Ok(Arc::new(MethodSemantics {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            semantics: self.semantics,
            method: match methods.get(&Token::new(self.method | 0x0600_0000)) {
                Some(method) => method.value().clone(),
                None => {
                    return Err(malformed_error!(
                        "Failed to resolve methoddef token - {}",
                        self.method | 0x0600_0000
                    ))
                }
            },
            association: match self.association.tag {
                TableId::Event => match events.get(&self.association.token) {
                    Some(event) => CilTypeReference::Event(event.value().clone()),
                    None => {
                        return Err(malformed_error!(
                            "Failed to resolve event association token - {}",
                            self.association.token.value()
                        ))
                    }
                },
                TableId::Property => match properties.get(&self.association.token) {
                    Some(property) => CilTypeReference::Property(property.value().clone()),
                    None => {
                        return Err(malformed_error!(
                            "Failed to resolve property association token - {}",
                            self.association.token.value()
                        ))
                    }
                },
                _ => {
                    return Err(malformed_error!(
                        "Invalid association token - {}",
                        self.association.token.value()
                    ))
                }
            },
        }))
    }
}

impl<'a> RowDefinition<'a> for MethodSemanticsRaw {
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* semantics */   2 +
            /* method */      sizes.table_index_bytes(TableId::MethodDef) +
            /* association */ sizes.coded_index_bytes(CodedIndexType::HasSemantics)
        )
    }

    fn read_row(
        data: &'a [u8],
        offset: &mut usize,
        rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<Self> {
        Ok(MethodSemanticsRaw {
            rid,
            token: Token::new(0x1800_0000 + rid),
            offset: *offset,
            semantics: u32::from(read_le_at::<u16>(data, offset)?),
            method: read_le_at_dyn(data, offset, sizes.is_large(TableId::MethodDef))?,
            association: CodedIndex::read(data, offset, sizes, CodedIndexType::HasSemantics)?,
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
            0x01, 0x01, // semantics
            0x02, 0x02, // method
            0x02, 0x00, // association (tag 0 = Event, index = 1)
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::MethodSemantics, 1),
                (TableId::MethodDef, 10),
                (TableId::Event, 10),
                (TableId::Property, 10),
            ],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<MethodSemanticsRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: MethodSemanticsRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x18000001);
            assert_eq!(row.semantics, 0x0101);
            assert_eq!(row.method, 0x0202);
            assert_eq!(
                row.association,
                CodedIndex {
                    tag: TableId::Event,
                    row: 1,
                    token: Token::new(1 | 0x14000000),
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
            0x01, 0x01, // semantics
            0x02, 0x02, 0x02, 0x02, // method
            0x02, 0x00, 0x00, 0x00, // association (tag 0 = Event, index = 1)
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::MethodSemantics, u16::MAX as u32 + 3),
                (TableId::MethodDef, u16::MAX as u32 + 3),
                (TableId::Event, u16::MAX as u32 + 3),
                (TableId::Property, u16::MAX as u32 + 3),
            ],
            true,
            true,
            true,
        ));
        let table = MetadataTable::<MethodSemanticsRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: MethodSemanticsRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x18000001);
            assert_eq!(row.semantics, 0x0101);
            assert_eq!(row.method, 0x02020202);
            assert_eq!(
                row.association,
                CodedIndex {
                    tag: TableId::Event,
                    row: 1,
                    token: Token::new(1 | 0x14000000),
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
