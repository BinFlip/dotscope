//! `EventMap` table loader implementation.
//!
//! This module provides the [`crate::metadata::tables::eventmap::loader::EventMapLoader`]
//! for loading `EventMap` metadata table entries during the metadata parsing process.
//! `EventMap` tables associate types with their owned events, enabling efficient enumeration
//! of events defined by a particular type, integrating this data with existing metadata entries.
//!
//! # Dependencies
//!
//! Loading requires these tables to be processed first:
//! - [`Event`](crate::metadata::tables::Event) - Event definitions  
//! - [`EventPtr`](crate::metadata::tables::EventPtr) - Event pointer indirection (if present)
//!
//! # Reference
//! - [ECMA-335 II.22.12](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `EventMap` table specification

use crate::{
    metadata::{
        loader::{LoaderContext, MetadataLoader},
        tables::EventMapRaw,
    },
    prelude::TableId,
    Result,
};

/// Metadata loader for `EventMap` table entries
///
/// Handles the loading and processing of `EventMap` metadata table entries during metadata
/// parsing. `EventMap` tables define ownership relationships between types and events,
/// allowing efficient discovery of all events declared by a particular type.
pub(crate) struct EventMapLoader;

impl MetadataLoader for EventMapLoader {
    /// Load and process `EventMap` metadata table entries
    ///
    /// Processes all `EventMap` table entries, converting them from raw format to owned
    /// data structures with resolved cross-references. Each entry establishes the
    /// relationship between a type and the range of events it owns.
    ///
    /// # Arguments
    ///
    /// * `context` - The metadata loading context containing:
    ///   - `meta` - Metadata headers and table access
    ///   - `types` - Type registry for type resolution
    ///   - `event` - `Event` table for event resolution
    ///   - `event_ptr` - `EventPtr` table for indirection resolution
    ///   - `event_map` - Target collection for processed entries
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on successful processing of all entries, or an error if:
    /// - Raw entry conversion fails
    /// - Cross-reference resolution fails  
    /// - Entry registration fails
    fn load(&self, context: &LoaderContext) -> Result<()> {
        if let Some(header) = context.meta.as_ref() {
            if let Some(table) = header.table::<EventMapRaw>() {
                table.par_iter().try_for_each(|row| {
                    let owned =
                        row.to_owned(context.types, &context.event, &context.event_ptr, table)?;
                    owned.apply()?;

                    context.event_map.insert(row.token, owned);
                    Ok(())
                })?;
            }
        }
        Ok(())
    }

    /// Returns the table identifier for `EventMap` table
    ///
    /// # Returns
    ///
    /// Returns [`TableId::EventMap`] (0x12) identifying this as the `EventMap` table loader.
    fn table_id(&self) -> TableId {
        TableId::EventMap
    }

    /// Returns the table dependencies required before loading `EventMap` entries
    ///
    /// `EventMap` loading requires `Event` and `EventPtr` tables to be loaded first to
    /// resolve cross-references correctly.
    ///
    /// # Returns
    ///
    /// Returns a slice containing:
    /// - [`TableId::Event`] - Required for event reference resolution
    /// - [`TableId::EventPtr`] - Required for event pointer indirection (if present)
    fn dependencies(&self) -> &'static [TableId] {
        &[TableId::Event, TableId::EventPtr]
    }
}
