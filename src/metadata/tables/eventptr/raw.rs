//! Raw `EventPtr` table representation.
//!
//! This module provides the [`crate::metadata::tables::eventptr::raw::EventPtrRaw`] struct
//! for low-level access to `EventPtr` metadata table data with unresolved indexes.
//! This represents the binary format of `EventPtr` records as they appear in the metadata
//! tables stream, providing indirection for event table access and requiring resolution
//! to create usable data structures.
//!
//! # `EventPtr` Table Format
//!
//! The `EventPtr` table (0x13) provides event indirection with this field:
//! - **Event** (2/4 bytes): Event table index pointing to the actual event
//!
//! `EventPtr` tables serve as an indirection layer for event access, primarily used
//! in edit-and-continue scenarios where the original event table ordering may have
//! been disrupted. The table maps logical event positions to physical event locations.
//!
//! # Indirection Mechanism
//!
//! When `EventPtr` is present:
//! 1. Event references resolve through `EventPtr` first
//! 2. `EventPtr` entries map logical indexes to actual Event table positions
//! 3. If `EventPtr` is absent, direct Event table indexing is used
//! 4. Enables non-sequential event ordering while maintaining logical consistency
//!
//! # Edit-and-Continue Support
//!
//! `EventPtr` tables are commonly found in assemblies that have undergone edit-and-continue
//! operations, where code modifications may require event relocation while preserving
//! existing metadata references.
//!
//! # Reference
//! - [ECMA-335 II.22.14](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `EventPtr` table specification

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
/// Raw `EventPtr` table row with unresolved event index
///
/// Represents the binary format of an `EventPtr` metadata table entry (table ID 0x13) as stored
/// in the metadata tables stream. `EventPtr` entries provide indirection for event table access,
/// primarily used in edit-and-continue scenarios where event ordering has been modified.
///
/// The `EventPtr` table serves as a mapping layer between logical event positions and physical
/// event locations in the Event table, enabling non-contiguous event arrangements while
/// maintaining consistent logical references.
///
/// # Indirection Logic
///
/// `EventPtr` provides the following indirection pattern:
/// - **Logical Index**: Position in `EventPtr` table (used by referencing metadata)
/// - **Physical Index**: Value stored in `EventPtr` entry (actual Event table position)
/// - **Resolution**: Logical → `EventPtr[Logical]` → `Event[Physical]`
///
/// # Edit-and-Continue Context
///
/// `EventPtr` tables are typically present only when needed for edit-and-continue scenarios:
/// - Original event ordering disrupted by code modifications
/// - Logical event references must remain stable across edit sessions
/// - Physical event locations may change but logical access remains consistent
///
/// # Reference
/// - [ECMA-335 II.22.14](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `EventPtr` table specification
pub struct EventPtrRaw {
    /// Row identifier within the `EventPtr` metadata table
    ///
    /// The 1-based index of this `EventPtr` row. Used for metadata token generation
    /// and logical event indexing in indirection scenarios.
    pub rid: u32,

    /// Metadata token for this `EventPtr` row
    ///
    /// Combines the table identifier (0x13 for `EventPtr`) with the row ID to create
    /// a unique token. Format: `0x13000000 | rid`
    pub token: Token,

    /// Byte offset of this row within the metadata tables stream
    ///
    /// Physical location of the raw `EventPtr` data within the metadata binary format.
    /// Used for debugging and low-level metadata analysis.
    pub offset: usize,

    /// Event table index (unresolved)
    ///
    /// 1-based index into the Event table pointing to the actual event. This provides
    /// the physical location mapping for the logical event position represented by
    /// this `EventPtr` entry's row ID.
    pub event: u32,
}

impl EventPtrRaw {
    /// Convert to owned `EventPtr` with validated data
    ///
    /// This method converts the raw `EventPtr` entry into a fully validated [`EventPtr`]
    /// structure with owned data. Since `EventPtr` entries contain only a single event
    /// reference, the conversion is straightforward and primarily serves to establish
    /// the owned data pattern consistent with other metadata tables.
    ///
    /// # Returns
    ///
    /// Returns [`EventPtrRc`] (Arc-wrapped [`EventPtr`]) on success, providing
    /// shared ownership of the validated `EventPtr` data.
    ///
    /// # Errors
    ///
    /// Currently doesn't fail, but returns [`Result`] for consistency with other
    /// table conversion methods and future validation requirements.
    pub fn to_owned(&self) -> Result<EventPtrRc> {
        Ok(Arc::new(EventPtr {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            event: self.event,
        }))
    }

    /// Apply this `EventPtr` entry during metadata loading
    ///
    /// Processes the raw `EventPtr` entry as part of the metadata loading framework.
    /// Unlike other metadata tables, `EventPtr` entries don't directly modify other
    /// metadata structures since they serve purely as an indirection mechanism.
    ///
    /// # Returns
    ///
    /// Always returns `Ok(())` since `EventPtr` entries don't perform cross-table
    /// modifications during the initial loading phase.
    ///
    /// # Errors
    ///
    /// This function never returns an error; it always returns `Ok(())`.
    pub fn apply(&self) -> Result<()> {
        Ok(())
    }
}

impl<'a> RowDefinition<'a> for EventPtrRaw {
    /// Calculate the byte size of an `EventPtr` table row
    ///
    /// Computes the total size in bytes required to store one `EventPtr` table row
    /// based on the table size information. The size depends on whether large
    /// table indexes are required for the Event table.
    ///
    /// # Row Structure
    ///
    /// - **event**: 2 or 4 bytes (Event table index)
    ///
    /// # Arguments
    ///
    /// * `sizes` - Table size information determining index byte sizes
    ///
    /// # Returns
    ///
    /// Returns the total byte size required for one `EventPtr` table row.
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* event */ sizes.table_index_bytes(TableId::Event)
        )
    }

    /// Read an `EventPtr` row from the metadata tables stream
    ///
    /// Parses one `EventPtr` table row from the binary metadata stream, handling
    /// variable-size indexes based on table size information. Advances the offset
    /// to point to the next row after successful parsing.
    ///
    /// # Arguments
    ///
    /// * `data` - The metadata tables stream binary data
    /// * `offset` - Current position in the stream (updated after reading)
    /// * `rid` - Row identifier for this `EventPtr` entry (1-based)
    /// * `sizes` - Table size information for determining index sizes
    ///
    /// # Returns
    ///
    /// Returns a parsed [`EventPtrRaw`] instance with all fields populated
    /// from the binary data.
    ///
    /// # Errors
    ///
    /// - The data stream is truncated or corrupted
    /// - Event index values exceed expected ranges
    /// - Binary parsing encounters invalid data
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
