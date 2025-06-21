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
    metadata::{
        tables::{EventPtr, EventPtrRc, TableId, TableInfoRef, TableRow},
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

impl TableRow for EventPtrRaw {
    /// Calculate the binary size of one `EventPtr` table row
    ///
    /// Computes the total byte size required for one `EventPtr` row based on the
    /// current metadata table sizes. The row size depends on whether the Event
    /// table uses 2-byte or 4-byte indices.
    ///
    /// # Arguments
    /// * `sizes` - Table sizing information for calculating variable-width fields
    ///
    /// # Returns
    /// Total byte size of one `EventPtr` table row
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* event */ sizes.table_index_bytes(TableId::Event)
        )
    }
}
