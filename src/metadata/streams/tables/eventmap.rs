use crate::{
    file::io::read_le_at_dyn,
    metadata::{
        streams::{EventMap, MetadataTable, RowDefinition, TableId, TableInfoRef},
        token::Token,
        typesystem::TypeRegistry,
    },
    Result,
};

// This type doesn't need the 'regular' typedefs, as it's only ever directly applied (for now?)

#[derive(Clone, Debug)]
/// The `EventMap` table maps events to their parent types. `TableId` = 0x12
pub struct EventMapRaw {
    /// `RowID`
    pub rid: u32,
    /// Token
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// an index into the `TypeDef` table
    pub parent: u32,
    /// an index into the Event table
    pub event_list: u32,
}

impl EventMapRaw {
    /// Apply an `EventMapRaw` to the relevant entries of types (e.g. fields, methods and parameters)
    ///
    /// ## Arguments
    /// * 'types'   - All parsed `TypeDef` entries
    /// * 'events'  - All parsed `Event` entries
    /// * 'map'     - The `MetadataTable` for `EventMapRaw` entries
    ///
    /// # Errors
    /// Returns an error if the event list is invalid or if type lookup fails
    pub fn apply(
        &self,
        types: &TypeRegistry,
        events: &EventMap,
        map: &MetadataTable<EventMapRaw>,
    ) -> Result<()> {
        let event_list = if self.event_list == 0 || events.is_empty() {
            return Err(malformed_error!("Invalid event list"));
        } else {
            let next_row_id = self.rid + 1;

            let start = self.event_list as usize;
            let end = if next_row_id > map.row_count() {
                events.len() + 1
            } else {
                match map.get(next_row_id) {
                    Some(next_row) => next_row.event_list as usize,
                    None => {
                        return Err(malformed_error!(
                            "Failed to resolve event_end from next row - {}",
                            next_row_id
                        ))
                    }
                }
            };

            if start > events.len() || end > (events.len() + 1) || end < start {
                Vec::new()
            } else {
                let mut event_list = Vec::with_capacity(end - start);
                for counter in start..end {
                    let token_value = counter | 0x1400_0000;
                    let token = Token::new(u32::try_from(token_value).map_err(|_| {
                        malformed_error!("Token value {} exceeds u32 range", token_value)
                    })?);
                    match events.get(&token) {
                        Some(param) => event_list.push(param.value().clone()),
                        None => {
                            return Err(malformed_error!(
                                "Failed to resolv event - {}",
                                counter | 0x1400_0000
                            ))
                        }
                    }
                }

                event_list
            }
        };

        match types.get(&Token::new(self.parent | 0x0200_0000)) {
            Some(event_parent) => {
                for entry in &event_list {
                    _ = event_parent.events.push(entry.clone());
                }
                Ok(())
            }
            None => Err(malformed_error!(
                "Invalid parent token - {}",
                self.parent | 0x0200_0000
            )),
        }
    }
}

impl<'a> RowDefinition<'a> for EventMapRaw {
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* parent */     sizes.table_index_bytes(TableId::TypeDef) +
            /* event_list */ sizes.table_index_bytes(TableId::Event)
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
        let event_list = read_le_at_dyn(data, offset, sizes.is_large(TableId::Event))?;

        Ok(EventMapRaw {
            rid,
            token: Token::new(0x1200_0000 + rid),
            offset: offset_org,
            parent,
            event_list,
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
            0x02, 0x02, // event_list
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::TypeDef, 1), (TableId::Event, 1)],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<EventMapRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: EventMapRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x12000001);
            assert_eq!(row.parent, 0x0101);
            assert_eq!(row.event_list, 0x0202);
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
            0x02, 0x02, 0x02, 0x02, // event_list
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::TypeDef, u16::MAX as u32 + 3),
                (TableId::Event, u16::MAX as u32 + 3),
            ],
            true,
            true,
            true,
        ));
        let table = MetadataTable::<EventMapRaw>::new(&data, u16::MAX as u32 + 3, sizes).unwrap();

        let eval = |row: EventMapRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x12000001);
            assert_eq!(row.parent, 0x01010101);
            assert_eq!(row.event_list, 0x02020202);
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
