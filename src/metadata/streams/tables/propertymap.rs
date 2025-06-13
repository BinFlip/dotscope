use crossbeam_skiplist::SkipMap;
use std::sync::Arc;

use crate::{
    file::io::read_le_at_dyn,
    metadata::{
        streams::{
            MetadataTable, PropertyList, PropertyMap, PropertyPtrMap, RowDefinition, TableId,
            TableInfoRef,
        },
        token::Token,
        typesystem::{CilTypeRef, TypeRegistry},
    },
    Result,
};

/// A map that holds the mapping of Token to parsed resolved `PropertyMapEntry`
pub type PropertyMapEntryMap = SkipMap<Token, PropertyMapEntryRc>;
/// A vector that holds a list of resolved `PropertyMapEntry`
pub type PropertyMapEntryList = Arc<boxcar::Vec<PropertyMapEntryRc>>;
/// A reference to a resolved `PropertyMapEntry`
pub type PropertyMapEntryRc = Arc<PropertyMapEntry>;

/// The resolved `PropertyMap` entry that maps properties to their parent types. Similar to `PropertyMapRaw` but
/// with resolved indexes and owned data.
pub struct PropertyMapEntry {
    /// `RowID`
    pub rid: u32,
    /// Token
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// The parent type that owns these properties
    pub parent: CilTypeRef,
    /// The list of properties belonging to the parent type
    pub properties: PropertyList,
}

impl PropertyMapEntry {
    /// Apply a `PropertyMapEntry` to update the parent type with its properties.
    ///
    /// Since this is the owned structure, all references are already resolved, so we can
    /// efficiently update the parent type without re-resolving anything.
    ///
    /// # Errors
    /// Returns an error if the parent type reference is invalid or if property assignment fails.
    pub fn apply(&self) -> Result<()> {
        if let Some(parent_type) = self.parent.upgrade() {
            for (_, property) in self.properties.iter() {
                _ = parent_type.properties.push(property.clone());
            }
            Ok(())
        } else {
            Err(malformed_error!(
                "PropertyMapEntry parent type reference is no longer valid"
            ))
        }
    }
}

#[derive(Clone, Debug)]
/// The `PropertyMap` table maps properties to their parent types. `TableId` = 0x15
pub struct PropertyMapRaw {
    /// `RowID`
    pub rid: u32,
    /// Token
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// an index into the `TypeDef` table
    pub parent: u32,
    /// an index into the Property table
    pub property_list: u32,
}

impl PropertyMapRaw {
    /// Helper method to resolve property list range and build the property vector
    ///
    /// This logic is shared between `apply()` and `to_owned()` methods to avoid duplication.
    fn resolve_property_list(
        &self,
        properties: &PropertyMap,
        property_ptr: &PropertyPtrMap,
        map: &MetadataTable<PropertyMapRaw>,
    ) -> Result<PropertyList> {
        if self.property_list == 0 || properties.is_empty() {
            return Ok(Arc::new(boxcar::Vec::new()));
        }

        let next_row_id = self.rid + 1;
        let start = self.property_list as usize;
        let end = if next_row_id > map.row_count() {
            properties.len() + 1
        } else {
            match map.get(next_row_id) {
                Some(next_row) => next_row.property_list as usize,
                None => {
                    return Err(malformed_error!(
                        "Failed to resolve property_end from next row - {}",
                        next_row_id
                    ))
                }
            }
        };

        if start > properties.len() || end > (properties.len() + 1) || end < start {
            return Ok(Arc::new(boxcar::Vec::new()));
        }

        let property_list = Arc::new(boxcar::Vec::with_capacity(end - start));
        for counter in start..end {
            let actual_property_token = if property_ptr.is_empty() {
                let token_value = counter | 0x1700_0000;
                Token::new(
                    u32::try_from(token_value)
                        .map_err(|_| malformed_error!("Property counter overflow"))?,
                )
            } else {
                let property_ptr_token_value =
                    u32::try_from(counter | 0x0E00_0000).map_err(|_| {
                        malformed_error!(
                            "PropertyPtr token value too large: {}",
                            counter | 0x0E00_0000
                        )
                    })?;
                let property_ptr_token = Token::new(property_ptr_token_value);

                match property_ptr.get(&property_ptr_token) {
                    Some(property_ptr_entry) => {
                        let actual_property_rid = property_ptr_entry.value().property;
                        let actual_property_token_value = u32::try_from(
                            actual_property_rid as usize | 0x1700_0000,
                        )
                        .map_err(|_| {
                            malformed_error!(
                                "Property token value too large: {}",
                                actual_property_rid as usize | 0x1700_0000
                            )
                        })?;
                        Token::new(actual_property_token_value)
                    }
                    None => {
                        return Err(malformed_error!(
                            "Failed to resolve PropertyPtr - {}",
                            counter | 0x0E00_0000
                        ))
                    }
                }
            };

            match properties.get(&actual_property_token) {
                Some(property) => _ = property_list.push(property.value().clone()),
                None => {
                    return Err(malformed_error!(
                        "Failed to resolve property - {}",
                        actual_property_token.value()
                    ))
                }
            }
        }

        Ok(property_list)
    }

    /// Convert a `PropertyMapRaw` into a `PropertyMapEntry` which has indexes resolved and owns the referenced data.
    ///
    /// The `PropertyMap` table maps types to their properties. The resolved variant contains the parent type
    /// reference and the actual list of resolved Property entries.
    ///
    /// ## Arguments
    /// * 'types' - The type registry for resolving parent types
    /// * 'properties' - The property map for resolving property references
    /// * 'property_ptr' - All parsed `PropertyPtr` entries for indirection resolution
    /// * 'map' - The `MetadataTable` for `PropertyMapRaw` entries (needed for list range resolution)
    ///
    /// # Errors
    /// Returns an error if the referenced type or properties cannot be resolved.
    pub fn to_owned(
        &self,
        types: &TypeRegistry,
        properties: &PropertyMap,
        property_ptr: &PropertyPtrMap,
        map: &MetadataTable<PropertyMapRaw>,
    ) -> Result<PropertyMapEntryRc> {
        let parent = match types.get(&Token::new(self.parent | 0x0200_0000)) {
            Some(parent_type) => parent_type.into(),
            None => {
                return Err(malformed_error!(
                    "Failed to resolve parent type - {}",
                    self.parent | 0x0200_0000
                ))
            }
        };

        Ok(Arc::new(PropertyMapEntry {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            parent,
            properties: self.resolve_property_list(properties, property_ptr, map)?,
        }))
    }

    /// Apply an `PropertyMapRaw` to the relevant entries of types (e.g. fields, methods and parameters)
    ///
    /// ## Arguments
    /// * 'types'       - All parsed `TypeDef` entries
    /// * 'properties'  - All parsed `Property` entries
    /// * '`property_ptr`' - All parsed `PropertyPtr` entries for indirection resolution
    /// * 'map'         - The `MetadataTable` for `PropertyMapRaw` entries
    ///
    /// # Errors
    /// Returns an error if the `property_list` is invalid or if the parent type cannot be found.
    pub fn apply(
        &self,
        types: &TypeRegistry,
        properties: &PropertyMap,
        property_ptr: &PropertyPtrMap,
        map: &MetadataTable<PropertyMapRaw>,
    ) -> Result<()> {
        let property_list = self.resolve_property_list(properties, property_ptr, map)?;

        if property_list.is_empty() && (self.property_list != 0 && !properties.is_empty()) {
            return Err(malformed_error!("Invalid property_list"));
        }

        match types.get(&Token::new(self.parent | 0x0200_0000)) {
            Some(entry) => {
                for (_, property) in property_list.iter() {
                    _ = entry.properties.push(property.clone());
                }
                Ok(())
            }
            None => Err(malformed_error!(
                "Failed to resolve parent - {}",
                self.parent | 0x0200_0000
            )),
        }
    }
}

impl<'a> RowDefinition<'a> for PropertyMapRaw {
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* parent */        sizes.table_index_bytes(TableId::TypeDef) +
            /* property_list */ sizes.table_index_bytes(TableId::Property)
        )
    }

    fn read_row(
        data: &'a [u8],
        offset: &mut usize,
        rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<Self> {
        let offset_org = *offset;

        let parent = read_le_at_dyn(data, offset, sizes.is_large(TableId::TypeDef))?;
        let property_list = read_le_at_dyn(data, offset, sizes.is_large(TableId::Property))?;

        Ok(PropertyMapRaw {
            rid,
            token: Token::new(0x1500_0000 + rid),
            offset: offset_org,
            parent,
            property_list,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::metadata::streams::tables::types::{MetadataTable, TableId, TableInfo};

    use super::*;

    #[test]
    fn crafted_short() {
        let data = vec![
            0x01, 0x01, // parent
            0x02, 0x02, // property_list
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::TypeDef, 1), (TableId::Property, 1)],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<PropertyMapRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: PropertyMapRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x15000001);
            assert_eq!(row.parent, 0x0101);
            assert_eq!(row.property_list, 0x0202);
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
            0x01, 0x01, 0x01, 0x01, // parent
            0x02, 0x02, 0x02, 0x02, // property_list
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::TypeDef, u16::MAX as u32 + 3),
                (TableId::Property, u16::MAX as u32 + 3),
            ],
            true,
            true,
            true,
        ));
        let table =
            MetadataTable::<PropertyMapRaw>::new(&data, u16::MAX as u32 + 3, sizes).unwrap();

        let eval = |row: PropertyMapRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x15000001);
            assert_eq!(row.parent, 0x01010101);
            assert_eq!(row.property_list, 0x02020202);
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
