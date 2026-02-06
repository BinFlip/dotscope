//! `LocalConstant` table loader for metadata processing
//!
//! This module provides the [`LocalConstantLoader`] implementation for processing
//! `LocalConstant` table data during metadata loading. The loader handles parallel
//! processing and integration with the broader loader context.

use crate::{
    metadata::{
        diagnostics::DiagnosticCategory,
        loader::{LoaderContext, MetadataLoader},
        tables::TableId,
    },
    Result,
};

/// Loader for the `LocalConstant` metadata table
///
/// Implements [`MetadataLoader`] to process the `LocalConstant` table (0x34)
/// which stores information about local constants within method scopes,
/// including their names, signatures, and constant values in Portable PDB format.
/// This loader handles the conversion from raw binary data to structured constant
/// metadata for debugging support.
///
/// # Processing Strategy
///
/// The loader uses parallel processing to efficiently handle large numbers of local
/// constant entries, resolving heap references and building the complete constant
/// metadata map for quick runtime access during debugging operations.
///
/// # Dependencies
///
/// This loader depends on the #Strings and #Blob heaps being available in the
/// loader context for resolving constant names and signature data.
///
/// # Reference
/// * [Portable PDB Format - LocalConstant Table](https://github.com/dotnet/core/blob/main/Documentation/diagnostics/portable_pdb.md#localconstant-table-0x34)
pub(crate) struct LocalConstantLoader;

impl MetadataLoader for LocalConstantLoader {
    fn load(&self, context: &LoaderContext) -> Result<()> {
        let (Some(header), Some(strings), Some(blobs)) =
            (context.meta, context.strings, context.blobs)
        else {
            return Ok(());
        };
        let Some(table) = header.table::<crate::metadata::tables::LocalConstantRaw>() else {
            return Ok(());
        };

        table.par_iter().try_for_each(|row| {
            let token_msg = || format!("local constant 0x{:08x}", row.token.value());

            let Some(local_constant) = context.handle_result(
                row.to_owned(strings, blobs),
                DiagnosticCategory::Method,
                token_msg,
            )?
            else {
                return Ok(());
            };

            context
                .local_constant
                .insert(local_constant.token, local_constant);
            Ok(())
        })
    }

    fn table_id(&self) -> Option<TableId> {
        Some(TableId::LocalConstant)
    }

    fn dependencies(&self) -> &'static [TableId] {
        &[]
    }
}
