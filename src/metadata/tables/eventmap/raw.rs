//! Raw `EventMap` table representation.
//!
//! This module provides the [`crate::metadata::tables::eventmap::raw::EventMapRaw`] struct
//! for low-level access to `EventMap` metadata table data with unresolved indexes and table references.
//! This represents the binary format of `EventMap` records as they appear in the metadata tables stream,
//! requiring resolution to create usable data structures.
//!
//! # `EventMap` Table Format
//!
//! The `EventMap` table (0x12) establishes ownership relationships between types and events
//! with these fields:
//! - **`Parent`** (2/4 bytes): `TypeDef` table index for the type that owns the events
//! - **`EventList`** (2/4 bytes): `Event` table index pointing to the first owned event
//!
//! `EventMap` entries define contiguous ranges of events owned by specific types. The range
//! for type N extends from `EventList[N]` to `EventList[N+1]`-1, enabling efficient enumeration
//! of all events belonging to a particular type.
//!
//! # Sorted Table Structure
//!
//! `EventMap` tables are sorted by Parent token for efficient binary search lookup.
//! This enables O(log n) lookup of events by owning type and efficient range-based
//! iteration through all events owned by a specific type.
//!
//! # Reference
//! - [ECMA-335 II.22.12](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `EventMap` table specification

use std::sync::Arc;

use crate::{
    file::io::read_le_at_dyn,
    metadata::{
        tables::{
            EventList, EventMap, EventMapEntry, EventMapEntryRc, EventPtrMap, MetadataTable,
            RowDefinition, TableId, TableInfoRef,
        },
        token::Token,
        typesystem::TypeRegistry,
    },
    Result,
};

#[derive(Clone, Debug)]
/// Raw `EventMap` table row with unresolved indexes and table references
///
/// Represents the binary format of an `EventMap` metadata table entry (table ID 0x12) as stored
/// in the metadata tables stream. All type and event references are stored as table indexes
/// that must be resolved using the appropriate tables and registries.
///
/// `EventMap` entries establish ownership relationships between types and their events by
/// defining contiguous ranges in the Event table. This enables efficient enumeration
/// of all events declared by a particular type.
///
/// # Range Resolution
///
/// `EventMap` entries define event ranges implicitly:
/// - Events from `EventList`\[i\] to `EventList`\[i+1\]-1 belong to Parent\[i\]
/// - The final entry's range extends to the end of the Event table
/// - Empty ranges are valid and indicate types with no events
///
/// # Reference
/// - [ECMA-335 II.22.12](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `EventMap` table specification
pub struct EventMapRaw {
    /// Row identifier within the `EventMap` metadata table
    ///
    /// The 1-based index of this `EventMap` row. Used for metadata token generation
    /// and cross-referencing with other metadata structures.
    pub rid: u32,

    /// Metadata token for this `EventMap` row
    ///
    /// Combines the table identifier (0x12 for `EventMap`) with the row ID to create
    /// a unique token. Format: `0x12000000 | rid`
    pub token: Token,

    /// Byte offset of this row within the metadata tables stream
    ///
    /// Physical location of the raw `EventMap` data within the metadata binary format.
    /// Used for debugging and low-level metadata analysis.
    pub offset: usize,

    /// Parent type table index (unresolved)
    ///
    /// Index into the `TypeDef` table identifying the type that owns the events
    /// in this range. Must be resolved using the type registry to obtain the
    /// actual type reference.
    pub parent: u32,

    /// Event list starting index (unresolved)
    ///
    /// Index into the Event table pointing to the first event owned by the parent
    /// type. The range extends to the next `EventMap` entry's `event_list` value (or
    /// end of Event table for the final entry).
    pub event_list: u32,
}

impl EventMapRaw {
    /// Resolve event list range and build the event vector
    ///
    /// This helper method resolves the contiguous range of events owned by the parent
    /// type and builds a thread-safe collection of resolved event references. The range
    /// is determined by this entry's `event_list` index and the next entry's `event_list`
    /// index (or end of Event table).
    ///
    /// # Range Calculation
    ///
    /// - **Start**: `self.event_list` (inclusive)
    /// - **End**: Next `EventMap` entry's `event_list` (exclusive) or end of Event table
    /// - **`EventPtr` Indirection**: Handles `EventPtr` table if present for level of indirection
    ///
    /// # Arguments
    ///
    /// * `events` - Event table for resolving event references
    /// * `event_ptr` - `EventPtr` table for indirection resolution (if present)
    /// * `map` - `EventMap` table for determining range boundaries
    ///
    /// # Returns
    ///
    /// Returns a thread-safe collection of resolved events in the specified range.
    ///
    /// # Errors
    ///
    /// - Range calculation fails due to invalid next row lookup
    /// - Event token resolution fails
    /// - `EventPtr` indirection resolution fails
    /// - Event lookup in the Event table fails
    fn resolve_event_list(
        &self,
        events: &EventMap,
        event_ptr: &EventPtrMap,
        map: &MetadataTable<EventMapRaw>,
    ) -> Result<EventList> {
        if self.event_list == 0 || events.is_empty() {
            return Ok(Arc::new(boxcar::Vec::new()));
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
            return Ok(Arc::new(boxcar::Vec::new()));
        }

        let event_list = Arc::new(boxcar::Vec::with_capacity(end - start));
        for counter in start..end {
            let actual_event_token = if event_ptr.is_empty() {
                let token_value = counter | 0x1400_0000;
                Token::new(u32::try_from(token_value).map_err(|_| {
                    malformed_error!("Token value {} exceeds u32 range", token_value)
                })?)
            } else {
                let event_ptr_token_value = u32::try_from(counter | 0x0D00_0000).map_err(|_| {
                    malformed_error!("EventPtr token value too large: {}", counter | 0x0D00_0000)
                })?;
                let event_ptr_token = Token::new(event_ptr_token_value);

                match event_ptr.get(&event_ptr_token) {
                    Some(event_ptr_entry) => {
                        let actual_event_rid = event_ptr_entry.value().event;
                        let actual_event_token_value = u32::try_from(
                            actual_event_rid as usize | 0x1400_0000,
                        )
                        .map_err(|_| {
                            malformed_error!(
                                "Event token value too large: {}",
                                actual_event_rid as usize | 0x1400_0000
                            )
                        })?;
                        Token::new(actual_event_token_value)
                    }
                    None => {
                        return Err(malformed_error!(
                            "Failed to resolve EventPtr - {}",
                            counter | 0x0D00_0000
                        ))
                    }
                }
            };

            match events.get(&actual_event_token) {
                Some(event) => _ = event_list.push(event.value().clone()),
                None => {
                    return Err(malformed_error!(
                        "Failed to resolve event - {}",
                        actual_event_token.value()
                    ))
                }
            }
        }

        Ok(event_list)
    }

    /// Convert to owned `EventMapEntry` with resolved references and owned data
    ///
    /// This method converts the raw `EventMap` entry into a fully resolved [`EventMapEntry`]
    /// structure with owned data and resolved cross-references. The resulting structure
    /// provides immediate access to the parent type and owned events without requiring
    /// additional table lookups.
    ///
    /// # Arguments
    ///
    /// * `types` - The type registry for resolving the parent type reference
    /// * `events` - The Event table for resolving event references in the range
    /// * `event_ptr` - The `EventPtr` table for indirection resolution (if present)
    /// * `map` - The `EventMap` table for determining event range boundaries
    ///
    /// # Returns
    ///
    /// Returns [`EventMapEntryRc`] (Arc-wrapped [`EventMapEntry`]) on success, providing
    /// shared ownership of the resolved `EventMap` data.
    ///
    /// # Errors
    ///
    /// - The parent type lookup fails in the type registry
    /// - Event range resolution fails due to invalid boundaries
    /// - Event lookup fails for any event in the resolved range
    /// - `EventPtr` indirection resolution fails
    pub fn to_owned(
        &self,
        types: &TypeRegistry,
        events: &EventMap,
        event_ptr: &EventPtrMap,
        map: &MetadataTable<EventMapRaw>,
    ) -> Result<EventMapEntryRc> {
        let parent = match types.get(&Token::new(self.parent | 0x0200_0000)) {
            Some(parent_type) => parent_type.into(),
            None => {
                return Err(malformed_error!(
                    "Failed to resolve parent type - {}",
                    self.parent | 0x0200_0000
                ))
            }
        };

        Ok(Arc::new(EventMapEntry {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            parent,
            events: self.resolve_event_list(events, event_ptr, map)?,
        }))
    }

    /// Apply this `EventMap` entry during metadata loading
    ///
    /// Processes the raw `EventMap` entry and establishes the ownership relationship
    /// between the parent type and its events. This method resolves the event range,
    /// looks up all events in that range, and adds them to the parent type's event
    /// collection.
    ///
    /// # Arguments
    ///
    /// * `types` - The type registry containing all parsed `TypeDef` entries
    /// * `events` - The Event table containing all parsed Event entries
    /// * `event_ptr` - The `EventPtr` table for indirection resolution (if present)
    /// * `map` - The `EventMap` table for determining event range boundaries
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on successful event assignment, or an error if:
    /// - Event list resolution fails due to invalid range boundaries
    /// - Event list validation fails (inconsistent with table state)
    /// - Parent type lookup fails in the type registry
    /// - Event assignment to parent type fails
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] if the event list is invalid, parent type lookup
    /// fails, or event assignment encounters metadata inconsistencies.
    pub fn apply(
        &self,
        types: &TypeRegistry,
        events: &EventMap,
        event_ptr: &EventPtrMap,
        map: &MetadataTable<EventMapRaw>,
    ) -> Result<()> {
        let event_list = self.resolve_event_list(events, event_ptr, map)?;

        if event_list.is_empty() && (self.event_list != 0 && !events.is_empty()) {
            return Err(malformed_error!("Invalid event list"));
        }

        match types.get(&Token::new(self.parent | 0x0200_0000)) {
            Some(event_parent) => {
                for (_, entry) in event_list.iter() {
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
    /// Calculate the byte size of an `EventMap` table row
    ///
    /// Computes the total size in bytes required to store one `EventMap` table row
    /// based on the table size information. The size depends on whether large
    /// table indexes are required for `TypeDef` and Event tables.
    ///
    /// # Row Structure
    ///
    /// - **parent**: 2 or 4 bytes (`TypeDef` table index)
    /// - **`event_list`**: 2 or 4 bytes (Event table index)
    ///
    /// # Arguments
    ///
    /// * `sizes` - Table size information determining index byte sizes
    ///
    /// # Returns
    ///
    /// Returns the total byte size required for one `EventMap` table row.
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* parent */     sizes.table_index_bytes(TableId::TypeDef) +
            /* event_list */ sizes.table_index_bytes(TableId::Event)
        )
    }

    /// Read an `EventMap` row from the metadata tables stream
    ///
    /// Parses one `EventMap` table row from the binary metadata stream, handling
    /// variable-size indexes based on table size information. Advances the offset
    /// to point to the next row after successful parsing.
    ///
    /// # Arguments
    ///
    /// * `data` - The metadata tables stream binary data
    /// * `offset` - Current position in the stream (updated after reading)
    /// * `rid` - Row identifier for this `EventMap` entry (1-based)
    /// * `sizes` - Table size information for determining index sizes
    ///
    /// # Returns
    ///
    /// Returns a parsed [`EventMapRaw`] instance with all fields populated
    /// from the binary data.
    ///
    /// # Errors
    ///
    /// - The data stream is truncated or corrupted
    /// - Index values exceed expected ranges
    /// - Binary parsing encounters invalid data
    fn row_read(
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

    use crate::metadata::tables::{MetadataTable, TableId, TableInfo};

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
