//! `ImportScope` table loader for metadata processing
//!
//! This module provides the [`ImportScopeLoader`] implementation for processing
//! `ImportScope` table data during metadata loading. The loader handles parallel
//! processing and integration with the broader loader context.

use crate::{
    metadata::{
        loader::{LoaderContext, MetadataLoader},
        tables::TableId,
    },
    Result,
};

/// Loader for the `ImportScope` metadata table
///
/// Implements [`MetadataLoader`] to process the `ImportScope` table (0x35)
/// which defines the import scopes that organize imported namespaces and types
/// in Portable PDB format. Import scopes enable hierarchical organization of
/// debugging information for namespace resolution and type lookup.
///
/// # Processing Strategy
///
/// The loader uses parallel processing to efficiently handle import scope entries,
/// resolving blob heap references to decode import declarations and building the
/// complete scope hierarchy for runtime debugging support.
///
/// # Dependencies
///
/// This loader depends on the #Blob heap being available in the loader context
/// for resolving import declarations and nested scope data.
///
/// # Reference
/// * [Portable PDB Format - ImportScope Table](https://github.com/dotnet/core/blob/main/Documentation/diagnostics/portable_pdb.md#importscope-table-0x35)
pub struct ImportScopeLoader;

impl MetadataLoader for ImportScopeLoader {
    fn load(&self, context: &LoaderContext) -> Result<()> {
        if let Some(header) = context.meta {
            if let Some(table) = header.table::<crate::metadata::tables::ImportScopeRaw>() {
                if let Some(blobs) = context.blobs {
                    table.par_iter().try_for_each(|row| {
                        let import_scope = row.to_owned(blobs)?;
                        context
                            .import_scope
                            .insert(import_scope.token, import_scope);
                        Ok(())
                    })?;
                }
            }
        }
        Ok(())
    }

    fn table_id(&self) -> TableId {
        TableId::ImportScope
    }

    fn dependencies(&self) -> &'static [TableId] {
        &[]
    }
}
