//! `LocalScope` table loader for metadata processing
//!
//! This module provides the [`LocalScopeLoader`] implementation for processing
//! ``LocalScope`` table data during metadata loading. The loader handles parallel
//! processing and integration with the broader loader context.

use crate::{
    metadata::{
        loader::{LoaderContext, MetadataLoader},
        tables::TableId,
    },
    Result,
};

/// Loader for the `LocalScope` metadata table
///
/// Implements [`MetadataLoader`] to process the `LocalScope` table (0x32)
/// which defines the scope ranges where local variables and constants are active
/// within methods in Portable PDB format. This loader handles the conversion from
/// raw binary data to structured scope metadata for debugging support.
///
/// # Processing Strategy
///
/// The loader uses parallel processing to efficiently handle large numbers of local
/// scope entries, resolving table references and building the complete scope
/// metadata map for quick runtime access during debugging operations.
///
/// # Dependencies
///
/// This loader depends on several other metadata tables that must be loaded first:
/// - `MethodDef`: For method references
/// - `ImportScope`: For namespace import context
/// - `LocalVariable`: For variable list references
/// - `LocalConstant`: For constant list references
///
/// # Reference
/// * [Portable PDB Format - LocalScope Table](https://github.com/dotnet/core/blob/main/Documentation/diagnostics/portable_pdb.md#localscope-table-0x32)
pub struct LocalScopeLoader;

impl MetadataLoader for LocalScopeLoader {
    fn load(&self, context: &LoaderContext) -> Result<()> {
        if let Some(header) = context.meta {
            if let Some(table) = header.table::<crate::metadata::tables::LocalScopeRaw>() {
                table.par_iter().try_for_each(|row| {
                    let local_scope = row.to_owned(
                        context.method_def,
                        &context.import_scope,
                        &context.local_variable,
                        &context.local_constant,
                        table,
                    )?;
                    context.local_scope.insert(local_scope.token, local_scope);
                    Ok(())
                })?;
            }
        }
        Ok(())
    }

    fn table_id(&self) -> TableId {
        TableId::LocalScope
    }

    fn dependencies(&self) -> &'static [TableId] {
        &[
            TableId::MethodDef,
            TableId::ImportScope,
            TableId::LocalVariable,
            TableId::LocalConstant,
        ]
    }
}
