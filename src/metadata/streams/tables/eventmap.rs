use crossbeam_skiplist::SkipMap;
use std::sync::Arc;

use crate::{
    file::io::read_le_at_dyn,
    metadata::{
        streams::{EventList, EventMap, MetadataTable, RowDefinition, TableId, TableInfoRef},
        token::Token,
        typesystem::{CilTypeRef, TypeRegistry},
    },
    Result,
};

/// A map that holds the mapping of Token to parsed resolved `EventMapEntry`
pub type EventMapEntryMap = SkipMap<Token, EventMapEntryRc>;
/// A vector that holds a list of resolved `EventMapEntry`
pub type EventMapEntryList = Arc<boxcar::Vec<EventMapEntryRc>>;
/// A reference to a resolved `EventMapEntry`
pub type EventMapEntryRc = Arc<EventMapEntry>;

/// The resolved `EventMap` entry that maps events to their parent types. Similar to `EventMapRaw` but
/// with resolved indexes and owned data.
pub struct EventMapEntry {
    /// `RowID`
    pub rid: u32,
    /// Token
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// The parent type that owns these events
    pub parent: CilTypeRef,
    /// The list of events belonging to the parent type
    pub events: EventList,
}

impl EventMapEntry {
    /// Apply an `EventMapEntry` to update the parent type with its events.
    ///
    /// Since this is the owned structure, all references are already resolved, so we can
    /// efficiently update the parent type without re-resolving anything.
    ///
    /// # Errors
    /// Returns an error if the parent type reference is invalid or if event assignment fails.
    pub fn apply(&self) -> Result<()> {
        if let Some(parent_type) = self.parent.upgrade() {
            for (_, event) in self.events.iter() {
                _ = parent_type.events.push(event.clone());
            }
            Ok(())
        } else {
            Err(malformed_error!(
                "EventMapEntry parent type reference is no longer valid"
            ))
        }
    }
}

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
    /// Helper method to resolve event list range and build the event vector
    ///
    /// This logic is shared between `apply()` and `to_owned()` methods to avoid duplication.
    fn resolve_event_list(
        &self,
        events: &EventMap,
        map: &MetadataTable<EventMapRaw>,
    ) -> Result<Vec<crate::metadata::streams::EventRc>> {
        if self.event_list == 0 || events.is_empty() {
            return Ok(Vec::new());
        }

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
            return Ok(Vec::new());
        }

        let mut event_list = Vec::with_capacity(end - start);
        for counter in start..end {
            let token_value = counter | 0x1400_0000;
            let token =
                Token::new(u32::try_from(token_value).map_err(|_| {
                    malformed_error!("Token value {} exceeds u32 range", token_value)
                })?);
            match events.get(&token) {
                Some(event) => event_list.push(event.value().clone()),
                None => {
                    return Err(malformed_error!(
                        "Failed to resolve event - {}",
                        counter | 0x1400_0000
                    ))
                }
            }
        }

        Ok(event_list)
    }

    /// Convert an `EventMapRaw` into an `EventMapEntry` which has indexes resolved and owns the referenced data.
    ///
    /// The `EventMap` table maps types to their events. The resolved variant contains the parent type
    /// reference and the actual list of resolved Event entries.
    ///
    /// ## Arguments
    /// * 'types' - The type registry for resolving parent types
    /// * 'events' - The event map for resolving event references
    /// * 'map' - The `MetadataTable` for `EventMapRaw` entries (needed for list range resolution)
    ///
    /// # Errors
    /// Returns an error if the referenced type or events cannot be resolved.
    pub fn to_owned(
        &self,
        types: &TypeRegistry,
        events: &EventMap,
        map: &MetadataTable<EventMapRaw>,
    ) -> Result<EventMapEntryRc> {
        // Resolve parent type
        let parent = match types.get(&Token::new(self.parent | 0x0200_0000)) {
            Some(parent_type) => parent_type.into(),
            None => {
                return Err(malformed_error!(
                    "Failed to resolve parent type - {}",
                    self.parent | 0x0200_0000
                ))
            }
        };

        // Resolve event list using the helper method
        let event_list_vec = self.resolve_event_list(events, map)?;
        let event_list = Arc::new(boxcar::Vec::new());
        for event in event_list_vec {
            _ = event_list.push(event);
        }

        Ok(Arc::new(EventMapEntry {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            parent,
            events: event_list,
        }))
    }

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
        // Use the helper method to resolve event list
        let event_list = self.resolve_event_list(events, map)?;

        if event_list.is_empty() && (self.event_list != 0 && !events.is_empty()) {
            return Err(malformed_error!("Invalid event list"));
        }

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
