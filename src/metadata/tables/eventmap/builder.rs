//! # EventMap Builder
//!
//! Provides a fluent API for building EventMap table entries that establish ownership relationships
//! between types and their events. The EventMap table defines contiguous ranges of events that belong
//! to specific types, enabling efficient enumeration and lookup of events by owning type.
//!
//! ## Overview
//!
//! The `EventMapBuilder` enables creation of event map entries with:
//! - Parent type specification (required)
//! - Event list starting index specification (required)
//! - Validation of type tokens and event indices
//! - Automatic token generation and metadata management
//!
//! ## Usage
//!
//! ```rust,ignore
//! # use dotscope::prelude::*;
//! # use std::path::Path;
//! # let view = CilAssemblyView::from_file(Path::new("test.dll"))?;
//! # let assembly = CilAssembly::new(view);
//! # let mut context = BuilderContext::new(assembly);
//!
//! // Create a type first
//! let type_token = TypeDefBuilder::new()
//!     .name("MyClass")
//!     .namespace("MyApp")
//!     .public_class()
//!     .build(&mut context)?;
//!
//! // Create handler type token
//! let handler_token = TypeRefBuilder::new()
//!     .name("EventHandler")
//!     .namespace("System")
//!     .resolution_scope(CodedIndex::new(TableId::AssemblyRef, 1))
//!     .build(&mut context)?;
//!
//! // Create events
//! let event1_token = EventBuilder::new()
//!     .name("OnDataChanged")
//!     .event_type(handler_token.try_into()?)
//!     .build(&mut context)?;
//!
//! let event2_token = EventBuilder::new()
//!     .name("OnSizeChanged")
//!     .event_type(handler_token.try_into()?)
//!     .build(&mut context)?;
//!
//! // Create an event map entry for the type
//! let event_map_token = EventMapBuilder::new()
//!     .parent(type_token)
//!     .event_list(event1_token.row()) // Starting event index
//!     .build(&mut context)?;
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Design
//!
//! The builder follows the established pattern with:
//! - **Validation**: Parent type and event list index are required and validated
//! - **Type Verification**: Ensures parent token is valid and points to TypeDef table
//! - **Token Generation**: Metadata tokens are created automatically
//! - **Range Support**: Supports defining contiguous event ranges for efficient lookup

use crate::{
    cilassembly::BuilderContext,
    metadata::{
        tables::{EventMapRaw, TableDataOwned, TableId},
        token::Token,
    },
    Error, Result,
};

/// Builder for creating EventMap table entries.
///
/// `EventMapBuilder` provides a fluent API for creating entries in the EventMap
/// metadata table, which establishes ownership relationships between types and their events
/// through contiguous ranges of Event table entries.
///
/// # Purpose
///
/// The EventMap table serves several key functions:
/// - **Event Ownership**: Defines which types own which events
/// - **Range Management**: Establishes contiguous ranges of events owned by types
/// - **Efficient Lookup**: Enables O(log n) lookup of events by owning type
/// - **Event Enumeration**: Supports efficient iteration through all events of a type
/// - **Metadata Organization**: Maintains sorted order for optimal access patterns
///
/// # Builder Pattern
///
/// The builder provides a fluent interface for constructing EventMap entries:
///
/// ```rust,ignore
/// # use dotscope::prelude::*;
/// # use std::path::Path;
/// # let view = CilAssemblyView::from_file(Path::new("test.dll"))?;
/// # let assembly = CilAssembly::new(view);
/// # let mut context = BuilderContext::new(assembly);
/// # let type_token = Token::new(0x02000001);
///
/// let event_map_token = EventMapBuilder::new()
///     .parent(type_token)
///     .event_list(1) // Starting event index
///     .build(&mut context)?;
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Validation
///
/// The builder enforces the following constraints:
/// - **Parent Required**: A parent type token must be provided
/// - **Parent Validation**: Parent token must be a valid TypeDef table token
/// - **Event List Required**: An event list starting index must be provided
/// - **Index Validation**: Event list index must be greater than 0
/// - **Token Validation**: Parent token row cannot be 0
///
/// # Integration
///
/// EventMap entries integrate with other metadata structures:
/// - **TypeDef**: References specific types in the TypeDef table as parent
/// - **Event**: Points to starting positions in the Event table for range definition
/// - **EventPtr**: Supports indirection through EventPtr table when present
/// - **Metadata Loading**: Establishes event ownership during type loading
#[derive(Debug, Clone)]
pub struct EventMapBuilder {
    /// The token of the parent type that owns the events
    parent: Option<Token>,
    /// The starting index in the Event table for this type's events
    event_list: Option<u32>,
}

impl Default for EventMapBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl EventMapBuilder {
    /// Creates a new `EventMapBuilder` instance.
    ///
    /// Returns a builder with all fields unset, ready for configuration
    /// through the fluent API methods.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::prelude::*;
    /// let builder = EventMapBuilder::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            parent: None,
            event_list: None,
        }
    }

    /// Sets the parent type token that owns the events.
    ///
    /// The parent must be a valid TypeDef token that represents the type
    /// that declares and owns the events in the specified range.
    ///
    /// # Arguments
    ///
    /// * `parent_token` - Token of the TypeDef table entry
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// # use dotscope::prelude::*;
    /// # use std::path::Path;
    /// # let view = CilAssemblyView::from_file(Path::new("test.dll"))?;
    /// # let assembly = CilAssembly::new(view);
    /// # let mut context = BuilderContext::new(assembly);
    /// let type_token = TypeDefBuilder::new()
    ///     .name("EventfulClass")
    ///     .namespace("MyApp")
    ///     .public_class()
    ///     .build(&mut context)?;
    ///
    /// let builder = EventMapBuilder::new()
    ///     .parent(type_token);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn parent(mut self, parent_token: Token) -> Self {
        self.parent = Some(parent_token);
        self
    }

    /// Sets the starting index in the Event table for this type's events.
    ///
    /// This index defines the beginning of the contiguous range of events
    /// owned by the parent type. The range extends to the next EventMap entry's
    /// event_list index (or end of Event table for the final entry).
    ///
    /// # Arguments
    ///
    /// * `event_list_index` - 1-based index into the Event table
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::prelude::*;
    /// let builder = EventMapBuilder::new()
    ///     .event_list(1); // Start from first event
    /// ```
    #[must_use]
    pub fn event_list(mut self, event_list_index: u32) -> Self {
        self.event_list = Some(event_list_index);
        self
    }

    /// Builds the EventMap entry and adds it to the assembly.
    ///
    /// This method validates all required fields, verifies the parent token is valid,
    /// validates the event list index, creates the EventMap table entry, and returns the
    /// metadata token for the new entry.
    ///
    /// # Arguments
    ///
    /// * `context` - The builder context for the assembly being modified
    ///
    /// # Returns
    ///
    /// Returns the metadata token for the newly created EventMap entry.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The parent token is not set
    /// - The parent token is not a valid TypeDef token
    /// - The parent token row is 0
    /// - The event list index is not set
    /// - The event list index is 0
    /// - There are issues adding the table row
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// # use dotscope::prelude::*;
    /// # use std::path::Path;
    /// # let view = CilAssemblyView::from_file(Path::new("test.dll"))?;
    /// # let assembly = CilAssembly::new(view);
    /// # let mut context = BuilderContext::new(assembly);
    /// # let type_token = Token::new(0x02000001);
    ///
    /// let event_map_token = EventMapBuilder::new()
    ///     .parent(type_token)
    ///     .event_list(1)
    ///     .build(&mut context)?;
    ///
    /// println!("Created EventMap with token: {}", event_map_token);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn build(self, context: &mut BuilderContext) -> Result<Token> {
        let parent_token = self
            .parent
            .ok_or_else(|| Error::ModificationInvalidOperation {
                details: "Parent token is required for EventMap".to_string(),
            })?;

        let event_list_index =
            self.event_list
                .ok_or_else(|| Error::ModificationInvalidOperation {
                    details: "Event list index is required for EventMap".to_string(),
                })?;

        if parent_token.table() != TableId::TypeDef as u8 {
            return Err(Error::ModificationInvalidOperation {
                details: format!(
                    "Parent token must be a TypeDef token, got table ID: {}",
                    parent_token.table()
                ),
            });
        }

        if parent_token.row() == 0 {
            return Err(Error::ModificationInvalidOperation {
                details: "Parent token row cannot be 0".to_string(),
            });
        }

        if event_list_index == 0 {
            return Err(Error::ModificationInvalidOperation {
                details: "Event list index cannot be 0".to_string(),
            });
        }

        let rid = context.next_rid(TableId::EventMap);
        let token = Token::from_parts(TableId::EventMap, rid);

        let event_map = EventMapRaw {
            rid,
            token,
            offset: 0, // Will be set during binary generation
            parent: parent_token.row(),
            event_list: event_list_index,
        };

        let table_data = TableDataOwned::EventMap(event_map);
        context.table_row_add(TableId::EventMap, table_data)?;

        Ok(token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        metadata::tables::TableId, test::factories::table::assemblyref::get_test_assembly,
    };

    #[test]
    fn test_event_map_builder_basic() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Create a TypeDef for testing
        let type_token = crate::metadata::tables::TypeDefBuilder::new()
            .name("EventfulClass")
            .namespace("MyApp")
            .public_class()
            .build(&mut context)?;

        let token = EventMapBuilder::new()
            .parent(type_token)
            .event_list(1)
            .build(&mut context)?;

        // Verify the token has the correct table ID
        assert_eq!(token.table(), TableId::EventMap as u8);
        assert!(token.row() > 0);

        Ok(())
    }

    #[test]
    fn test_event_map_builder_default() -> Result<()> {
        let builder = EventMapBuilder::default();
        assert!(builder.parent.is_none());
        assert!(builder.event_list.is_none());
        Ok(())
    }

    #[test]
    fn test_event_map_builder_missing_parent() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        let result = EventMapBuilder::new().event_list(1).build(&mut context);

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Parent token is required"));

        Ok(())
    }

    #[test]
    fn test_event_map_builder_missing_event_list() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Create a TypeDef for testing
        let type_token = crate::metadata::tables::TypeDefBuilder::new()
            .name("EventfulClass")
            .namespace("MyApp")
            .public_class()
            .build(&mut context)?;

        let result = EventMapBuilder::new()
            .parent(type_token)
            .build(&mut context);

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Event list index is required"));

        Ok(())
    }

    #[test]
    fn test_event_map_builder_invalid_parent_token() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Use an invalid token (not TypeDef)
        let invalid_token = Token::new(0x04000001); // Field token instead of TypeDef

        let result = EventMapBuilder::new()
            .parent(invalid_token)
            .event_list(1)
            .build(&mut context);

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Parent token must be a TypeDef token"));

        Ok(())
    }

    #[test]
    fn test_event_map_builder_zero_row_parent() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Use a zero row token
        let zero_token = Token::new(0x02000000);

        let result = EventMapBuilder::new()
            .parent(zero_token)
            .event_list(1)
            .build(&mut context);

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Parent token row cannot be 0"));

        Ok(())
    }

    #[test]
    fn test_event_map_builder_zero_event_list() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Create a TypeDef for testing
        let type_token = crate::metadata::tables::TypeDefBuilder::new()
            .name("EventfulClass")
            .namespace("MyApp")
            .public_class()
            .build(&mut context)?;

        let result = EventMapBuilder::new()
            .parent(type_token)
            .event_list(0) // Zero event list index is invalid
            .build(&mut context);

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Event list index cannot be 0"));

        Ok(())
    }

    #[test]
    fn test_event_map_builder_multiple_entries() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Create TypeDefs for testing
        let type1_token = crate::metadata::tables::TypeDefBuilder::new()
            .name("EventfulClass1")
            .namespace("MyApp")
            .public_class()
            .build(&mut context)?;

        let type2_token = crate::metadata::tables::TypeDefBuilder::new()
            .name("EventfulClass2")
            .namespace("MyApp")
            .public_class()
            .build(&mut context)?;

        let map1_token = EventMapBuilder::new()
            .parent(type1_token)
            .event_list(1)
            .build(&mut context)?;

        let map2_token = EventMapBuilder::new()
            .parent(type2_token)
            .event_list(3)
            .build(&mut context)?;

        // Verify tokens are different and sequential
        assert_ne!(map1_token, map2_token);
        assert_eq!(map1_token.table(), TableId::EventMap as u8);
        assert_eq!(map2_token.table(), TableId::EventMap as u8);
        assert_eq!(map2_token.row(), map1_token.row() + 1);

        Ok(())
    }

    #[test]
    fn test_event_map_builder_various_event_indices() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Test with different event list indices
        let test_indices = [1, 5, 10, 20, 100];

        for (i, &index) in test_indices.iter().enumerate() {
            let type_token = crate::metadata::tables::TypeDefBuilder::new()
                .name(format!("EventfulClass{i}"))
                .namespace("MyApp")
                .public_class()
                .build(&mut context)?;

            let map_token = EventMapBuilder::new()
                .parent(type_token)
                .event_list(index)
                .build(&mut context)?;

            assert_eq!(map_token.table(), TableId::EventMap as u8);
            assert!(map_token.row() > 0);
        }

        Ok(())
    }

    #[test]
    fn test_event_map_builder_fluent_api() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Create a TypeDef for testing
        let type_token = crate::metadata::tables::TypeDefBuilder::new()
            .name("FluentTestClass")
            .namespace("MyApp")
            .public_class()
            .build(&mut context)?;

        // Test fluent API chaining
        let token = EventMapBuilder::new()
            .parent(type_token)
            .event_list(5)
            .build(&mut context)?;

        assert_eq!(token.table(), TableId::EventMap as u8);
        assert!(token.row() > 0);

        Ok(())
    }

    #[test]
    fn test_event_map_builder_clone() {
        let parent_token = Token::new(0x02000001);

        let builder1 = EventMapBuilder::new().parent(parent_token).event_list(1);
        let builder2 = builder1.clone();

        assert_eq!(builder1.parent, builder2.parent);
        assert_eq!(builder1.event_list, builder2.event_list);
    }

    #[test]
    fn test_event_map_builder_debug() {
        let parent_token = Token::new(0x02000001);

        let builder = EventMapBuilder::new().parent(parent_token).event_list(1);
        let debug_str = format!("{builder:?}");
        assert!(debug_str.contains("EventMapBuilder"));
    }
}
