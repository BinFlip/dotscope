//! Raw Event table representation.
//!
//! This module provides the [`crate::metadata::tables::event::raw::EventRaw`] struct
//! for low-level access to Event metadata table data with unresolved heap indexes and coded indices.
//! This represents the binary format of event records as they appear in the metadata tables stream,
//! requiring resolution to create usable data structures.
//!
//! # Event Table Format
//!
//! The Event table (0x14) contains event definitions with these fields:
//! - **EventFlags** (2 bytes): Event attributes bitmask
//! - **Name** (2/4 bytes): String heap index for event name
//! - **EventType** (2/4 bytes): TypeDefOrRef coded index for event handler type
//!
//! Events define notification mechanisms that types can expose. They are associated
//! with accessor methods (add/remove/raise/other) through the MethodSemantics table.
//!
//! # Reference
//! - [ECMA-335 II.22.13](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Event table specification

use std::sync::{Arc, OnceLock};

use crate::{
    file::io::{read_le_at, read_le_at_dyn},
    metadata::{
        streams::Strings,
        tables::{CodedIndex, CodedIndexType, Event, EventRc, RowDefinition, TableInfoRef},
        token::Token,
        typesystem::TypeRegistry,
    },
    Result,
};

#[derive(Clone, Debug)]
/// Raw Event table row with unresolved indexes and coded indices
///
/// Represents the binary format of an Event metadata table entry (table ID 0x14) as stored
/// in the metadata tables stream. All string references and type references are stored as
/// indexes that must be resolved using the appropriate heaps and type registry.
///
/// Events define notification mechanisms that allow objects to communicate state changes
/// to interested observers. Each event has a name, flags, and an associated delegate type
/// that defines the signature for event handlers.
///
/// # Reference
/// - [ECMA-335 II.22.13](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Event table specification
pub struct EventRaw {
    /// Row identifier within the Event metadata table
    ///
    /// The 1-based index of this event row. Used for metadata token generation
    /// and cross-referencing with other metadata structures.
    pub rid: u32,

    /// Metadata token for this event row
    ///
    /// Combines the table identifier (0x14 for Event) with the row ID to create
    /// a unique token. Format: `0x14000000 | rid`
    pub token: Token,

    /// Byte offset of this row within the metadata tables stream
    ///
    /// Physical location of the raw event data within the metadata binary format.
    /// Used for debugging and low-level metadata analysis.
    pub offset: usize,

    /// Event flags bitmask (unresolved)
    ///
    /// 2-byte bitmask using [`crate::metadata::tables::event::EventAttributes`] constants.
    /// Controls special naming and runtime behavior for the event.
    /// See [ECMA-335 II.23.1.4] for flag definitions.
    pub flags: u32,

    /// Event name string heap index (unresolved)
    ///
    /// Index into the String heap containing the event name. Must be resolved
    /// using the String heap to obtain the actual event name string.
    pub name: u32,

    /// Event handler type coded index (unresolved)
    ///
    /// TypeDefOrRef coded index referencing the delegate type that defines the
    /// event handler signature. Can point to TypeDef, TypeRef, or TypeSpec tables.
    /// Must be resolved using the type registry to obtain the actual type reference.
    pub event_type: CodedIndex,
}

impl EventRaw {
    /// Convert to owned Event with resolved references and owned data
    ///
    /// This method converts the raw event into a fully resolved [`Event`] structure
    /// with owned data and resolved references. The resulting structure provides
    /// immediate access to event information without requiring additional heap
    /// lookups or type resolution.
    ///
    /// # Arguments
    ///
    /// * `strings` - The String heap for resolving event name
    /// * `types` - The type registry for resolving event handler type references
    ///
    /// # Returns
    ///
    /// Returns [`EventRc`] (Arc-wrapped [`Event`]) on success, providing shared ownership
    /// of the resolved event data.
    ///
    /// # Errors
    ///
    /// - The string heap lookup fails for the event name
    /// - The type registry lookup fails for the event handler type
    /// - The event type coded index cannot be resolved to a valid type
    pub fn to_owned(&self, strings: &Strings, types: &TypeRegistry) -> Result<EventRc> {
        Ok(Arc::new(Event {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            flags: self.flags,
            name: strings.get(self.name as usize)?.to_string(),
            event_type: match types.get(&self.event_type.token) {
                Some(parent) => parent.into(),
                None => {
                    return Err(malformed_error!(
                        "Failed to resolve event type token - {}",
                        self.event_type.token.value()
                    ))
                }
            },
            fn_on_add: OnceLock::new(),
            fn_on_other: OnceLock::new(),
            fn_on_raise: OnceLock::new(),
            fn_on_remove: OnceLock::new(),
            custom_attributes: Arc::new(boxcar::Vec::new()),
        }))
    }

    /// Apply this event entry during metadata loading
    ///
    /// Processes the raw event entry and handles any cross-table relationships or
    /// metadata updates required during the loading phase. Events themselves don't
    /// directly modify other metadata tables, but this method provides a consistent
    /// interface for the loading framework.
    ///
    /// # Implementation Details
    ///
    /// Events define notification interfaces but don't create direct relationships
    /// with other metadata during initial loading. Event accessor methods (add/remove/raise/other)
    /// are resolved separately through the MethodSemantics table processing, which occurs
    /// after basic table loading is complete.
    ///
    /// # Returns
    ///
    /// Always returns `Ok(())` since events don't perform cross-table modifications
    /// during the initial loading phase.
    pub fn apply(&self) -> Result<()> {
        Ok(())
    }
}

impl<'a> RowDefinition<'a> for EventRaw {
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* flags */      2 +
            /* name */       sizes.str_bytes() +
            /* event_type */ sizes.coded_index_bytes(CodedIndexType::TypeDefOrRef)
        )
    }

    fn read_row(
        data: &'a [u8],
        offset: &mut usize,
        rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<Self> {
        let offset_org = *offset;

        let flags = u32::from(read_le_at::<u16>(data, offset)?);
        let name = read_le_at_dyn(data, offset, sizes.is_large_str())?;
        let event_type = CodedIndex::read(data, offset, sizes, CodedIndexType::TypeDefOrRef)?;

        Ok(EventRaw {
            rid,
            token: Token::new(0x1400_0000 + rid),
            offset: offset_org,
            flags,
            name,
            event_type,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::metadata::tables::{MetadataTable, TableId, TableInfo};

    use super::*;

    #[test]
    fn crafted_short() {
        let data = vec![
            0x01, 0x01, // flags
            0x02, 0x02, // name
            0x00, 0x03, // event_type (tag 0 = TypeDef, index 3)
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::TypeDef, 1),
                (TableId::TypeRef, 1),
                (TableId::TypeSpec, 1),
            ],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<EventRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: EventRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x14000001);
            assert_eq!(row.flags, 0x0101);
            assert_eq!(row.name, 0x0202);
            assert_eq!(
                row.event_type,
                CodedIndex {
                    tag: TableId::TypeDef,
                    row: 192,
                    token: Token::new(192 | 0x02000000),
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
            0x01, 0x01, // flags
            0x02, 0x02, 0x02, 0x02, // name
            0x00, 0x03, 0x03, 0x03, // event_type (tag 0 = TypeDef, index 3)
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::TypeDef, u16::MAX as u32 + 3),
                (TableId::TypeRef, 1),
                (TableId::TypeSpec, 1),
            ],
            true,
            true,
            true,
        ));
        let table = MetadataTable::<EventRaw>::new(&data, u16::MAX as u32 + 3, sizes).unwrap();

        let eval = |row: EventRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x14000001);
            assert_eq!(row.flags, 0x0101);
            assert_eq!(row.name, 0x02020202);
            assert_eq!(
                row.event_type,
                CodedIndex {
                    tag: TableId::TypeDef,
                    row: 0xC0C0C0,
                    token: Token::new(0xC0C0C0 | 0x02000000)
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
