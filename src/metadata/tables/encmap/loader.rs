//! `EncMap` table loader implementation
//!
//! Provides the [`crate::metadata::tables::encmap::loader::EncMapLoader`] implementation for loading Edit-and-Continue token mappings
//! from the ECMA-335 `EncMap` table (0x1F). This loader processes debugging metadata that maps
//! original tokens to their updated versions after Edit-and-Continue operations.
//!
//! # Table Structure
//!
//! The `EncMap` table contains token mapping information:
//! - **Token**: Original metadata token before editing
//!
//! # Usage Context
//!
//! This table is only present in assemblies that have been modified during debugging
//! sessions using Edit-and-Continue functionality. It enables debuggers to correlate
//! pre-edit and post-edit metadata tokens during debugging sessions.
//!
//! # Reference
//! - [ECMA-335 II.22.13](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `EncMap` table specification

use crate::{
    metadata::{
        loader::{LoaderContext, MetadataLoader},
        tables::{EncMapRaw, TableId},
    },
    Result,
};

/// Loader for the `EncMap` metadata table
///
/// Implements [`crate::metadata::loader::MetadataLoader`] to process the `EncMap` table (0x1F)
/// which contains Edit-and-Continue token mappings that correlate original metadata tokens
/// with their updated versions after code modifications during debugging sessions.
pub(crate) struct EncMapLoader;

impl MetadataLoader for EncMapLoader {
    /// Load Edit-and-Continue token mappings from the `EncMap` table
    ///
    /// Processes `EncMap` table rows (if present) and stores the token mapping
    /// information in the loader context. The `EncMap` table is optional and only present
    /// in assemblies that have been modified during debugging sessions.
    ///
    /// # Arguments
    /// * `context` - Loader context containing metadata tables and storage collections
    ///
    /// # Returns
    /// * `Ok(())` - `EncMap` entries successfully loaded or table not present
    /// * `Err(`[`crate::Error`]`)` - Malformed data or processing error
    fn load(&self, context: &LoaderContext) -> Result<()> {
        if let Some(header) = context.meta {
            if let Some(table) = header.table::<EncMapRaw>() {
                table.par_iter().try_for_each(|row| {
                    let owned = row.to_owned()?;

                    context.enc_map.insert(row.token, owned);
                    Ok(())
                })?;
            }
        }
        Ok(())
    }

    /// Returns the table identifier for the `EncMap` table
    ///
    /// # Returns
    /// [`crate::metadata::tables::TableId::EncMap`] (0x1F)
    fn table_id(&self) -> TableId {
        TableId::EncMap
    }

    /// Returns the list of table dependencies
    ///
    /// The `EncMap` table has no dependencies on other metadata tables or heaps,
    /// as it contains only metadata tokens.
    ///
    /// # Returns
    /// Empty slice - no table dependencies
    fn dependencies(&self) -> &'static [TableId] {
        &[]
    }
}
