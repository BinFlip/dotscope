//! # ModuleRef Table Loader
//!
//! This module provides the loader implementation for the [`ModuleRef`](crate::metadata::tables::ModuleRef) table,
//! which contains references to external modules that are required by the current assembly.
//! ModuleRef entries identify multi-module assemblies and their dependencies.
//!
//! ## Purpose
//!
//! The [`ModuleRefLoader`] processes [`crate::metadata::tables::ModuleRefRaw`] entries during metadata loading,
//! converting them to owned [`ModuleRef`](crate::metadata::tables::ModuleRef) instances with resolved module names.
//! These entries represent references to external modules that contain types or methods
//! used by the current assembly.
//!
//! ## Table Dependencies
//!
//! The ModuleRef table has no dependencies on other metadata tables:
//! - Only depends on the string heap for module name resolution
//! - Can be loaded early in the dependency resolution process
//! - Serves as a foundation for cross-module references
//!
//! ## Error Conditions
//!
//! - String heap entries are malformed or missing
//! - ModuleRef table contains invalid data
//! - Token conflicts occur during storage

use crate::{
    metadata::{
        loader::{LoaderContext, MetadataLoader},
        tables::ModuleRefRaw,
    },
    prelude::TableId,
    Result,
};

/// Loader implementation for the ModuleRef metadata table.
///
/// This loader processes [`crate::metadata::tables::ModuleRefRaw`] entries, converting them to
/// owned [`crate::metadata::tables::ModuleRef`] instances with resolved module names.
/// ModuleRef entries represent references to external modules that contain types or methods
/// used by the current assembly.
pub(crate) struct ModuleRefLoader;

impl MetadataLoader for ModuleRefLoader {
    /// Loads and processes all ModuleRef table entries.
    ///
    /// ## Arguments
    /// * `context` - The loader context containing metadata tables and storage
    ///
    /// ## Errors
    /// Returns an error if:
    /// - String heap entries cannot be resolved or are malformed
    /// - ModuleRef table contains invalid or corrupted data
    /// - Storage operations fail due to token conflicts
    fn load(&self, context: &LoaderContext) -> Result<()> {
        if let (Some(header), Some(strings)) = (context.meta, context.strings) {
            if let Some(table) = header.table::<ModuleRefRaw>(TableId::ModuleRef) {
                table.par_iter().try_for_each(|row| {
                    let res = row.to_owned(strings)?;

                    context.module_ref.insert(row.token, res.clone());
                    Ok(())
                })?;
            }
        }
        Ok(())
    }

    /// Returns the table identifier for ModuleRef.
    ///
    /// ## Returns
    /// [`crate::metadata::tables::TableId::ModuleRef`] (0x1A)
    fn table_id(&self) -> TableId {
        TableId::ModuleRef
    }

    /// Returns the table dependencies for ModuleRef loading.
    ///
    /// The ModuleRef table has no dependencies as it only references the string heap
    /// for module name resolution. It can be loaded early in the dependency resolution
    /// process and serves as a foundation for cross-module references.
    ///
    /// ## Returns
    /// Empty array as ModuleRef table has no table dependencies
    fn dependencies(&self) -> &'static [TableId] {
        &[]
    }
}
