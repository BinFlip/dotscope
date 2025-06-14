use std::sync::Arc;

use crate::{
    file::io::read_le_at_dyn,
    metadata::{
        tables::{EventPtr, EventPtrRc, RowDefinition, TableId, TableInfoRef},
        token::Token,
    },
    Result,
};

#[derive(Clone, Debug)]
/// The `EventPtr` table provides indirection for Event table access in `#-` streams.
/// Table ID = 0x13
///
/// This table is only present in assemblies using uncompressed metadata streams (`#-`).
/// It contains a single column with 1-based indices into the Event table, providing
/// an indirection layer that allows for more flexible event ordering and access patterns.
///
/// ## ECMA-335 Specification
/// From ECMA-335, Partition II, Section 22.19:
/// > The EventPtr table is an auxiliary table used by the CLI loaders to implement
/// > a more complex event layout than the simple sequential layout provided by the Event table.
/// > Each row contains an index into the Event table.
///
/// ## Usage in `#-` Streams
/// When the metadata uses the `#-` (uncompressed) stream format instead of `#~` (compressed),
/// the `EventPtr` table may be present to provide indirection. If present:
/// 1. Event references should resolve through `EventPtr` first
/// 2. If `EventPtr` is empty or missing, fall back to direct Event table indexing
/// 3. The indirection allows for non-sequential event ordering
pub struct EventPtrRaw {
    /// Row ID (1-based index)
    pub rid: u32,
    /// Token for this `EventPtr` entry
    pub token: Token,
    /// Byte offset of this entry in the metadata stream
    pub offset: usize,
    /// 1-based index into the Event table
    pub event: u32,
}

impl EventPtrRaw {
    /// Convert a `EventPtrRaw` into a `EventPtr` with resolved data
    ///
    /// # Errors
    /// This method currently doesn't fail, but returns Result for consistency
    /// with other table conversion methods.
    pub fn to_owned(&self) -> Result<EventPtrRc> {
        Ok(Arc::new(EventPtr {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            event: self.event,
        }))
    }

    /// Apply a `EventPtrRaw` entry to update related metadata structures.
    ///
    /// `EventPtr` entries provide indirection for event access but don't directly
    /// modify other metadata structures during parsing. The indirection logic
    /// is handled at the table resolution level.
    ///
    /// # Errors
    /// Always returns `Ok(())` as `EventPtr` entries don't modify other tables directly.
    pub fn apply(&self) -> Result<()> {
        Ok(())
    }
}

impl<'a> RowDefinition<'a> for EventPtrRaw {
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* event */ sizes.table_index_bytes(TableId::Event)
        )
    }

    fn read_row(
        data: &'a [u8],
        offset: &mut usize,
        rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<Self> {
        Ok(EventPtrRaw {
            rid,
            token: Token::new(0x1300_0000 + rid),
            offset: *offset,
            event: read_le_at_dyn(data, offset, sizes.is_large(TableId::Event))?,
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
            0x01, 0x01, // event (index into Event table)
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Event, 1)],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<EventPtrRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: EventPtrRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x13000001);
            assert_eq!(row.event, 0x0101);
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
            0x01, 0x01, 0x01, 0x01, // event (index into Event table)
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Event, u16::MAX as u32 + 3)],
            true,
            true,
            true,
        ));
        let table = MetadataTable::<EventPtrRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: EventPtrRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x13000001);
            assert_eq!(row.event, 0x01010101);
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
