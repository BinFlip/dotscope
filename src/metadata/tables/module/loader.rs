//! # Module Table Loader
//!
//! This module provides the loader implementation for the [`Module`](crate::metadata::tables::Module) table,
//! which contains information about the current module including its name, GUID (Mvid), and generation.
//! The Module table always contains exactly one row per PE file, representing the module identity.
//!
//! ## Purpose
//!
//! The [`ModuleLoader`] processes the single [`crate::metadata::tables::ModuleRaw`] entry during metadata loading,
//! converting it to an owned [`crate::metadata::tables::Module`] instance with resolved strings and GUIDs.
//! The module entry serves as the fundamental identity for the current assembly.
//!
//! ## Table Dependencies
//!
//! The Module table has no dependencies and is one of the first tables loaded:
//! - No external table references
//! - Only depends on metadata heaps (strings, GUIDs)
//! - Serves as foundation for other table loading
//!
//! ## Error Conditions
//!
//! - No Module table is present in the metadata
//! - String heap entries are malformed or missing
//! - GUID heap entries are malformed or missing
//! - Module has already been set (duplicate loading)

use crate::{
    metadata::{
        loader::{LoaderContext, MetadataLoader},
        tables::{ModuleRaw, TableId},
    },
    Result,
};

/// Loader implementation for the Module metadata table.
///
/// This loader processes the single [`crate::metadata::tables::ModuleRaw`] entry, converting it to
/// an owned [`crate::metadata::tables::Module`] instance with resolved strings and GUIDs.
/// The Module table always contains exactly one row that provides identity information
/// for the current assembly module.
pub(crate) struct ModuleLoader;

impl MetadataLoader for ModuleLoader {
    /// Loads and processes the single Module table entry.
    ///
    /// ## Arguments
    /// * `context` - The loader context containing metadata tables and storage
    ///
    /// ## Errors
    ///
    /// - No Module table is present in the metadata
    /// - The Module table is empty (should always have one row)
    /// - String or GUID heap entries cannot be resolved
    /// - Module has already been set (duplicate loading attempt)
    fn load(&self, context: &LoaderContext) -> Result<()> {
        if let (Some(tables_header), Some(strings), Some(guids)) =
            (context.meta, context.strings, context.guids)
        {
            if let Some(table) = tables_header.table::<ModuleRaw>() {
                if let Some(row) = table.get(1) {
                    let owned = row.to_owned(strings, guids)?;

                    context
                        .module
                        .set(owned)
                        .map_err(|_| malformed_error!("Module has already been set"))?;
                    return Ok(());
                }
            }
        }

        Err(malformed_error!("No module has been found"))
    }

    /// Returns the table identifier for Module.
    ///
    /// ## Returns
    /// [`crate::metadata::tables::TableId::Module`] (0x00)
    fn table_id(&self) -> TableId {
        TableId::Module
    }

    /// Returns the table dependencies for Module loading.
    ///
    /// The Module table has no dependencies as it only references metadata heaps
    /// (strings and GUIDs) and serves as a foundation table for other metadata loading.
    /// It is typically one of the first tables loaded in the dependency resolution process.
    ///
    /// ## Returns
    /// Empty array as Module table has no table dependencies
    fn dependencies(&self) -> &'static [TableId] {
        &[]
    }
}
