use crossbeam_skiplist::SkipMap;
use std::sync::{Arc, OnceLock};

use crate::{
    file::io::{read_le_at, read_le_at_dyn},
    metadata::{
        method::MethodRef,
        streams::{CodedIndex, CodedIndexType, RowDefinition, Strings, TableInfoRef},
        token::Token,
        typesystem::{CilTypeRef, TypeRegistry},
    },
    Result,
};

#[allow(non_snake_case)]
/// All possible flags for `EventAttributes`
pub mod EventAttributes {
    /// Event is special
    pub const SPECIAL_NAME: u32 = 0x0200;
    /// CLI provides 'special' behavior, depending upon the name of the event
    pub const RTSPECIAL_NAME: u32 = 0x0400;
}

/// A map that holds the mapping of Token to parsed `Event`
pub type EventMap = SkipMap<Token, EventRc>;
/// A vector that holds a list of `Event`
pub type EventList = Arc<boxcar::Vec<EventRc>>;
/// A reference to an `Event`
pub type EventRc = Arc<Event>;

/// Represents an Event that a Type can have. Similar to `EventRaw` but with resolved indexes and owned data.
pub struct Event {
    /// `RowID`
    pub rid: u32,
    /// Token
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// a 2-byte bitmask of type `EventAttributes`, §II.23.1.4
    pub flags: u32,
    /// The name of the event
    pub name: String,
    /// an index into a `TypeDef`, a `TypeRef`, or `TypeSpec` table; more precisely, a `TypeDefOrRef` (§II.24.2.6) coded index
    pub event_type: CilTypeRef,
    /// The `Method` that triggers '`OnAdd`'
    pub fn_on_add: OnceLock<MethodRef>,
    /// The `Method` that triggers '`OnRemove`'
    pub fn_on_remove: OnceLock<MethodRef>,
    /// The `Method` that triggers '`OnRaise`'
    pub fn_on_raise: OnceLock<MethodRef>,
    /// The `Method` that triggers '`OnOther`'
    pub fn_on_other: OnceLock<MethodRef>,
}

#[derive(Clone, Debug)]
/// The Event table defines events for types. Each entry includes the event name, flags, and event type. `TableId` = 0x14
pub struct EventRaw {
    /// `RowID`
    pub rid: u32,
    /// Token
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// a 2-byte bitmask of type `EventAttributes`, §II.23.1.4
    pub flags: u32,
    /// an index into the String heap
    pub name: u32,
    /// an index into a `TypeDef`, a `TypeRef`, or `TypeSpec` table; more precisely, a `TypeDefOrRef` (§II.24.2.6) coded index
    pub event_type: CodedIndex,
}

impl EventRaw {
    /// Convert an `EventRaw`, into a `Event` which has indexes resolved and owns the referenced data
    ///
    /// ## Arguments
    /// * 'strings'     - The #String heap
    /// * 'types'       - All parsed `CilType` entries
    ///
    /// # Errors
    /// Returns an error if the string lookup fails or if type resolution fails
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
        }))
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
    use crate::metadata::streams::tables::types::{MetadataTable, TableId, TableInfo};

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
