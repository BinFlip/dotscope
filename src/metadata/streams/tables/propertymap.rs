use crate::{
    file::io::read_le_at_dyn,
    metadata::{
        streams::{MetadataTable, PropertyMap, RowDefinition, TableId, TableInfoRef},
        token::Token,
        typesystem::TypeRegistry,
    },
    Result,
};

// This type doesn't need the 'regular' typedefs, as it's only ever directly applied (for now?)

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
    /// Apply an `PropertyMapRaw` to the relevant entries of types (e.g. fields, methods and parameters)
    ///
    /// ## Arguments
    /// * 'types'       - All parsed `TypeDef` entries
    /// * 'properties'  - All parsed `Property` entries
    /// * 'map'         - The `MetadataTable` for `PropertyMapRaw` entries
    ///
    /// # Errors
    /// Returns an error if the `property_list` is invalid or if the parent type cannot be found.
    pub fn apply(
        &self,
        types: &TypeRegistry,
        properties: &PropertyMap,
        map: &MetadataTable<PropertyMapRaw>,
    ) -> Result<()> {
        if self.property_list == 0 || properties.is_empty() {
            return Err(malformed_error!("Invalid property_list"));
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
            return Err(malformed_error!("Invalid property_list"));
        }

        match types.get(&Token::new(self.parent | 0x0200_0000)) {
            Some(entry) => {
                for counter in start..end {
                    match properties
                        .get(&Token::new(u32::try_from(counter | 0x1700_0000).map_err(
                            |_| malformed_error!("Property counter overflow"),
                        )?)) {
                        Some(param) => _ = entry.properties.push(param.value().clone()),
                        None => {
                            return Err(malformed_error!(
                                "Failed to resolve property - {}",
                                counter | 0x1700_0000
                            ))
                        }
                    }
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
