use crate::{
    metadata::{tables::EventList, token::Token, typesystem::CilTypeRef},
    Result,
};

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
