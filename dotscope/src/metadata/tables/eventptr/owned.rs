//! Owned `EventPtr` table representation.
//!
//! This module provides the [`crate::metadata::tables::eventptr::owned::EventPtr`] struct
//! for working with resolved `EventPtr` metadata with owned data and direct event references.
//! This represents the processed form of `EventPtr` entries after raw table data has been
//! converted and validated during the dual variant resolution phase.
//!
//! # `EventPtr` Entry Structure
//!
//! Each `EventPtr` entry provides indirection for event access in edit-and-continue
//! scenarios. The entry contains:
//! - **Event Reference**: Direct index to the actual event in the Event table
//! - **Metadata**: Row identifier, token, and offset information
//!
//! # Indirection Purpose
//!
//! `EventPtr` tables serve as an indirection layer when the original event table
//! ordering has been disrupted:
//! - **Edit-and-Continue**: Code modifications may require event relocation
//! - **Logical Ordering**: Maintains consistent logical event indexes
//! - **Physical Mapping**: Maps logical indexes to actual event locations
//!
//! # Stream Format Context
//!
//! `EventPtr` tables are typically present in uncompressed metadata streams (#~)
//! rather than compressed streams (#-), often in edit-and-continue scenarios
//! where metadata has been modified after initial compilation.
//!
//! # Reference
//! - [ECMA-335 II.22.14](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `EventPtr` table specification

use crate::metadata::token::Token;

/// Resolved `EventPtr` entry with owned data and direct event references
///
/// Represents a fully processed `EventPtr` table entry where the event reference
/// has been validated and is ready for use in event indirection resolution.
/// `EventPtr` entries provide a mapping from logical event indexes to physical
/// event locations in the Event table.
///
/// Each `EventPtr` entry serves as an indirection point for event access, primarily
/// used in edit-and-continue scenarios where the original event table ordering
/// may have been modified. The indirection allows maintaining stable logical
/// references while accommodating physical table changes.
///
/// # Edit-and-Continue Context
///
/// `EventPtr` entries are most commonly found in assemblies that have undergone
/// edit-and-continue operations, where maintaining consistent event references
/// across code modifications requires an indirection layer.
pub struct EventPtr {
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

    /// Index into the Event table pointing to the actual event
    ///
    /// 1-based index that identifies the physical location of the event in the
    /// Event table. This provides the indirection mapping from logical event
    /// positions to actual event locations.
    pub event: u32,
}
