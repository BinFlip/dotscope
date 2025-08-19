//! `EncLog` table loader implementation
//!
//! Provides the [`crate::metadata::tables::enclog::loader::EncLogLoader`] implementation for loading Edit-and-Continue log entries
//! from the ECMA-335 `EncLog` table (0x1E). This loader processes debugging metadata that tracks
//! modifications made during Edit-and-Continue debugging sessions.
//!
//! # Table Structure
//!
//! The `EncLog` table contains Edit-and-Continue operation tracking information:
//! - **Token**: Metadata token identifying the affected element
//! - **`FuncCode`**: Operation code (create=0, update=1, delete=2)
//!
//! # Usage Context
//!
//! This table is only present in assemblies that have been modified during debugging
//! sessions using Edit-and-Continue functionality. It enables the runtime to understand
//! what metadata elements have been added, modified, or removed during debugging.
//!
//! # Reference
//! - [ECMA-335 II.22.12](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `EncLog` table specification

use crate::{
    metadata::{
        loader::{LoaderContext, MetadataLoader},
        tables::{EncLogRaw, TableId},
    },
    Result,
};

/// Loader for the `EncLog` metadata table
///
/// Implements [`crate::metadata::loader::MetadataLoader`] to process the `EncLog` table (0x1E)
/// which contains Edit-and-Continue log entries that track metadata modifications made during
/// debugging sessions. This table records all changes to help the runtime understand what
/// has been modified during active debugging.
pub(crate) struct EncLogLoader;

impl MetadataLoader for EncLogLoader {
    /// Load Edit-and-Continue log entries from the `EncLog` table
    ///
    /// Processes `EncLog` table rows (if present) and stores the Edit-and-Continue operation
    /// information in the loader context. The `EncLog` table is optional and only present
    /// in assemblies that have been modified during debugging sessions.
    ///
    /// # Arguments
    /// * `context` - Loader context containing metadata tables and storage collections
    ///
    /// # Returns
    /// * `Ok(())` - `EncLog` entries successfully loaded or table not present
    /// * `Err(`[`crate::Error`]`)` - Malformed data or processing error
    fn load(&self, context: &LoaderContext) -> Result<()> {
        if let Some(header) = context.meta {
            if let Some(table) = header.table::<EncLogRaw>() {
                table.par_iter().try_for_each(|row| {
                    let owned = row.to_owned()?;

                    context.enc_log.insert(row.token, owned);
                    Ok(())
                })?;
            }
        }
        Ok(())
    }

    /// Returns the table identifier for the `EncLog` table
    ///
    /// # Returns
    /// [`crate::metadata::tables::TableId::EncLog`] (0x1E)
    fn table_id(&self) -> TableId {
        TableId::EncLog
    }

    /// Returns the list of table dependencies
    ///
    /// The `EncLog` table has no dependencies on other metadata tables or heaps,
    /// as it contains only metadata tokens and operation codes.
    ///
    /// # Returns
    /// Empty slice - no table dependencies
    fn dependencies(&self) -> &'static [TableId] {
        &[]
    }
}
