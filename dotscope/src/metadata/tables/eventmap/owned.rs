//! Owned `EventMap` table representation.
//!
//! This module provides the [`crate::metadata::tables::eventmap::owned::EventMapEntry`] struct
//! for working with resolved `EventMap` metadata with owned data and resolved cross-references.
//! This represents the processed form of `EventMap` entries after raw table data has been converted
//! and all heap references have been resolved during the dual variant resolution phase.
//!
//! # `EventMap` Entry Structure
//!
//! Each `EventMap` entry establishes ownership between a type and a contiguous range
//! of events. The entry contains:
//! - **Parent Type**: Resolved reference to the type that owns the events
//! - **Event List**: Collection of events belonging to the parent type
//! - **Metadata**: Row identifier, token, and offset information
//!
//! # Reference
//! - [ECMA-335 II.22.12](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `EventMap` table specification

use crate::{
    metadata::{tables::EventList, token::Token, typesystem::CilTypeRef},
    Result,
};

/// Resolved `EventMap` entry with owned data and resolved cross-references
///
/// Represents a fully processed `EventMap` table entry where all heap references
/// have been resolved and cross-table relationships have been established. Each
/// entry defines the ownership relationship between a type and a contiguous range
/// of events.
///
/// `EventMap` entries are used to efficiently associate events with their declaring
/// types and enable enumeration of all events owned by a particular type. The
/// relationship is established through contiguous ranges in the `Event` table.
pub struct EventMapEntry {
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

    /// Weak reference to the parent type that owns the events
    ///
    /// Points to the [`CilType`](crate::metadata::typesystem::CilType) that declares
    /// the events in this range. Uses a weak reference to prevent circular ownership
    /// between types and their event maps.
    pub parent: CilTypeRef,

    /// Thread-safe collection of events belonging to the parent type
    ///
    /// Contains all [`Event`](crate::metadata::tables::Event) instances that are
    /// owned by the parent type. Events are stored in a thread-safe collection
    /// that supports concurrent access and modification.
    pub events: EventList,
}

impl EventMapEntry {
    /// Apply this `EventMap` entry to update the parent type with its events
    ///
    /// Transfers all events from this `EventMap` entry to the parent type's event
    /// collection, establishing the ownership relationship. This method is called
    /// during metadata loading to populate type definitions with their associated
    /// events.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on successful event assignment, or an error if:
    /// - The parent type reference is no longer valid (type was dropped)
    /// - Event assignment to the parent type fails
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] if the parent type reference is invalid or if
    /// event assignment fails due to metadata inconsistencies.
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
