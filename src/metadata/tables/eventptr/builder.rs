//! Builder for constructing `EventPtr` table entries
//!
//! This module provides the [`crate::metadata::tables::eventptr::EventPtrBuilder`] which enables fluent construction
//! of `EventPtr` metadata table entries. The builder follows the established
//! pattern used across all table builders in the library.
//!
//! # Usage Example
//!
//! ```rust,ignore
//! use dotscope::prelude::*;
//!
//! let builder_context = BuilderContext::new();
//!
//! let eventptr_token = EventPtrBuilder::new()
//!     .event(4)                      // Points to Event table RID 4
//!     .build(&mut builder_context)?;
//! ```

use crate::{
    cilassembly::BuilderContext,
    metadata::{
        tables::{EventPtrRaw, TableDataOwned, TableId},
        token::Token,
    },
    Error, Result,
};

/// Builder for constructing `EventPtr` table entries
///
/// Provides a fluent interface for building `EventPtr` metadata table entries.
/// These entries provide indirection for event access when logical and physical
/// event ordering differs, primarily in edit-and-continue scenarios.
///
/// # Required Fields
/// - `event`: Event table RID that this pointer references
///
/// # Indirection Context
///
/// The EventPtr table provides a mapping layer between logical event references
/// and physical Event table entries. This enables:
/// - Event reordering during edit-and-continue operations
/// - Non-sequential event arrangements while maintaining logical consistency
/// - Runtime event hot-reload and debugging interception
/// - Stable event references across code modification sessions
///
/// # Examples
///
/// ```rust,ignore
/// use dotscope::prelude::*;
///
/// // Create event pointer for edit-and-continue
/// let ptr1 = EventPtrBuilder::new()
///     .event(8)   // Points to Event table entry 8
///     .build(&mut context)?;
///
/// // Create pointer for reordered event layout
/// let ptr2 = EventPtrBuilder::new()
///     .event(3)   // Points to Event table entry 3
///     .build(&mut context)?;
///
/// // Multiple pointers for complex event arrangements
/// let ptr3 = EventPtrBuilder::new()
///     .event(15)  // Points to Event table entry 15
///     .build(&mut context)?;
/// ```
#[derive(Debug, Clone)]
pub struct EventPtrBuilder {
    /// Event table RID that this pointer references
    event: Option<u32>,
}

impl EventPtrBuilder {
    /// Creates a new `EventPtrBuilder` with default values
    ///
    /// Initializes a new builder instance with all fields unset. The caller
    /// must provide the required event RID before calling build().
    ///
    /// # Returns
    /// A new `EventPtrBuilder` instance ready for configuration
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::prelude::*;
    ///
    /// let builder = EventPtrBuilder::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self { event: None }
    }

    /// Sets the Event table RID
    ///
    /// Specifies which Event table entry this pointer references. This creates
    /// the indirection mapping from the EventPtr RID (logical index) to the
    /// actual Event table entry (physical index).
    ///
    /// # Parameters
    /// - `event`: The Event table RID to reference
    ///
    /// # Returns
    /// Self for method chaining
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::prelude::*;
    ///
    /// // Point to first event
    /// let builder = EventPtrBuilder::new()
    ///     .event(1);
    ///
    /// // Point to a later event for reordering
    /// let builder = EventPtrBuilder::new()
    ///     .event(12);
    /// ```
    #[must_use]
    pub fn event(mut self, event: u32) -> Self {
        self.event = Some(event);
        self
    }

    /// Builds and adds the `EventPtr` entry to the metadata
    ///
    /// Validates all required fields, creates the `EventPtr` table entry,
    /// and adds it to the builder context. Returns a token that can be used
    /// to reference this event pointer entry.
    ///
    /// # Parameters
    /// - `context`: Mutable reference to the builder context
    ///
    /// # Returns
    /// - `Ok(Token)`: Token referencing the created event pointer entry
    /// - `Err(Error)`: If validation fails or table operations fail
    ///
    /// # Errors
    /// - Missing required field (event RID)
    /// - Table operations fail due to metadata constraints
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::prelude::*;
    ///
    /// let mut context = BuilderContext::new();
    /// let token = EventPtrBuilder::new()
    ///     .event(4)
    ///     .build(&mut context)?;
    /// ```
    pub fn build(self, context: &mut BuilderContext) -> Result<Token> {
        let event = self
            .event
            .ok_or_else(|| Error::ModificationInvalidOperation {
                details: "Event RID is required for EventPtr".to_string(),
            })?;

        let next_rid = context.next_rid(TableId::EventPtr);
        let token = Token::new(((TableId::EventPtr as u32) << 24) | next_rid);

        let event_ptr = EventPtrRaw {
            rid: next_rid,
            token,
            offset: 0,
            event,
        };

        context.table_row_add(TableId::EventPtr, TableDataOwned::EventPtr(event_ptr))?;
        Ok(token)
    }
}

impl Default for EventPtrBuilder {
    /// Creates a default `EventPtrBuilder`
    ///
    /// Equivalent to calling [`EventPtrBuilder::new()`].
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cilassembly::BuilderContext, test::factories::table::assemblyref::get_test_assembly,
    };

    #[test]
    fn test_eventptr_builder_new() {
        let builder = EventPtrBuilder::new();

        assert!(builder.event.is_none());
    }

    #[test]
    fn test_eventptr_builder_default() {
        let builder = EventPtrBuilder::default();

        assert!(builder.event.is_none());
    }

    #[test]
    fn test_eventptr_builder_basic() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);
        let token = EventPtrBuilder::new()
            .event(1)
            .build(&mut context)
            .expect("Should build successfully");

        assert_eq!(token.table(), TableId::EventPtr as u8);
        assert_eq!(token.row(), 1);
        Ok(())
    }

    #[test]
    fn test_eventptr_builder_reordering() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);
        let token = EventPtrBuilder::new()
            .event(12) // Point to later event for reordering
            .build(&mut context)
            .expect("Should build successfully");

        assert_eq!(token.table(), TableId::EventPtr as u8);
        assert_eq!(token.row(), 1);
        Ok(())
    }

    #[test]
    fn test_eventptr_builder_missing_event() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);
        let result = EventPtrBuilder::new().build(&mut context);

        assert!(result.is_err());
        match result.unwrap_err() {
            Error::ModificationInvalidOperation { details } => {
                assert!(details.contains("Event RID is required"));
            }
            _ => panic!("Expected ModificationInvalidOperation error"),
        }
        Ok(())
    }

    #[test]
    fn test_eventptr_builder_clone() {
        let builder = EventPtrBuilder::new().event(4);

        let cloned = builder.clone();
        assert_eq!(builder.event, cloned.event);
    }

    #[test]
    fn test_eventptr_builder_debug() {
        let builder = EventPtrBuilder::new().event(9);

        let debug_str = format!("{builder:?}");
        assert!(debug_str.contains("EventPtrBuilder"));
        assert!(debug_str.contains("event"));
    }

    #[test]
    fn test_eventptr_builder_fluent_interface() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Test method chaining
        let token = EventPtrBuilder::new()
            .event(20)
            .build(&mut context)
            .expect("Should build successfully");

        assert_eq!(token.table(), TableId::EventPtr as u8);
        assert_eq!(token.row(), 1);
        Ok(())
    }

    #[test]
    fn test_eventptr_builder_multiple_builds() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Build first pointer
        let token1 = EventPtrBuilder::new()
            .event(8)
            .build(&mut context)
            .expect("Should build first pointer");

        // Build second pointer
        let token2 = EventPtrBuilder::new()
            .event(3)
            .build(&mut context)
            .expect("Should build second pointer");

        // Build third pointer
        let token3 = EventPtrBuilder::new()
            .event(15)
            .build(&mut context)
            .expect("Should build third pointer");

        assert_eq!(token1.row(), 1);
        assert_eq!(token2.row(), 2);
        assert_eq!(token3.row(), 3);
        assert_ne!(token1, token2);
        assert_ne!(token2, token3);
        Ok(())
    }

    #[test]
    fn test_eventptr_builder_large_event_rid() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);
        let token = EventPtrBuilder::new()
            .event(0xFFFF) // Large Event RID
            .build(&mut context)
            .expect("Should handle large event RID");

        assert_eq!(token.table(), TableId::EventPtr as u8);
        assert_eq!(token.row(), 1);
        Ok(())
    }

    #[test]
    fn test_eventptr_builder_event_ordering_scenario() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Simulate event reordering: logical order 1,2,3 -> physical order 10,5,12
        let logical_to_physical = [(1, 10), (2, 5), (3, 12)];

        let mut tokens = Vec::new();
        for (logical_idx, physical_event) in logical_to_physical {
            let token = EventPtrBuilder::new()
                .event(physical_event)
                .build(&mut context)
                .expect("Should build event pointer");
            tokens.push((logical_idx, token));
        }

        // Verify logical ordering is preserved in tokens
        for (i, (logical_idx, token)) in tokens.iter().enumerate() {
            assert_eq!(*logical_idx, i + 1);
            assert_eq!(token.row(), (i + 1) as u32);
        }

        Ok(())
    }

    #[test]
    fn test_eventptr_builder_zero_event() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Test with event 0 (typically invalid but should not cause builder to fail)
        let result = EventPtrBuilder::new().event(0).build(&mut context);

        // Should build successfully even with event 0
        assert!(result.is_ok());
        Ok(())
    }

    #[test]
    fn test_eventptr_builder_edit_continue_scenario() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Simulate edit-and-continue where events are reordered after code modifications
        let reordered_events = [3, 1, 2]; // Physical reordering

        let mut event_pointers = Vec::new();
        for &physical_event in &reordered_events {
            let pointer_token = EventPtrBuilder::new()
                .event(physical_event)
                .build(&mut context)
                .expect("Should build event pointer for edit-continue");
            event_pointers.push(pointer_token);
        }

        // Verify stable logical tokens despite physical reordering
        for (i, token) in event_pointers.iter().enumerate() {
            assert_eq!(token.table(), TableId::EventPtr as u8);
            assert_eq!(token.row(), (i + 1) as u32);
        }

        Ok(())
    }

    #[test]
    fn test_eventptr_builder_type_event_scenario() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Simulate type with multiple events that need indirection
        let type_events = [5, 10, 7, 15, 2]; // Events in custom order

        let mut event_pointers = Vec::new();
        for &event_rid in &type_events {
            let pointer_token = EventPtrBuilder::new()
                .event(event_rid)
                .build(&mut context)
                .expect("Should build event pointer");
            event_pointers.push(pointer_token);
        }

        // Verify event pointers maintain logical sequence
        for (i, token) in event_pointers.iter().enumerate() {
            assert_eq!(token.table(), TableId::EventPtr as u8);
            assert_eq!(token.row(), (i + 1) as u32);
        }

        Ok(())
    }

    #[test]
    fn test_eventptr_builder_hot_reload_scenario() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Simulate hot-reload where new event implementations replace existing ones
        let new_event_implementations = [100, 200, 300];
        let mut pointer_tokens = Vec::new();

        for &new_event in &new_event_implementations {
            let pointer_token = EventPtrBuilder::new()
                .event(new_event)
                .build(&mut context)
                .expect("Should build pointer for hot-reload");
            pointer_tokens.push(pointer_token);
        }

        // Verify pointer tokens maintain stable references for hot-reload
        assert_eq!(pointer_tokens.len(), 3);
        for (i, token) in pointer_tokens.iter().enumerate() {
            assert_eq!(token.table(), TableId::EventPtr as u8);
            assert_eq!(token.row(), (i + 1) as u32);
        }

        Ok(())
    }

    #[test]
    fn test_eventptr_builder_complex_indirection_scenario() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Simulate complex indirection with non-sequential event arrangement
        let complex_mapping = [25, 1, 50, 10, 75, 5, 100];

        let mut pointer_sequence = Vec::new();
        for &physical_event in &complex_mapping {
            let token = EventPtrBuilder::new()
                .event(physical_event)
                .build(&mut context)
                .expect("Should build complex indirection mapping");
            pointer_sequence.push(token);
        }

        // Verify complex indirection maintains logical consistency
        assert_eq!(pointer_sequence.len(), 7);
        for (i, token) in pointer_sequence.iter().enumerate() {
            assert_eq!(token.table(), TableId::EventPtr as u8);
            assert_eq!(token.row(), (i + 1) as u32);
        }

        Ok(())
    }
}
