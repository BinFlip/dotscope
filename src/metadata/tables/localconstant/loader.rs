//! `LocalConstant` table loader for metadata processing
//!
//! This module provides the [`LocalConstantLoader`] implementation for processing
//! `LocalConstant` table data during metadata loading. The loader handles parallel
//! processing and integration with the broader loader context.

use crate::{
    metadata::{
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
        if let Some(header) = context.meta {
            if let Some(table) = header.table::<crate::metadata::tables::LocalConstantRaw>() {
                if let (Some(strings), Some(blobs)) = (context.strings, context.blobs) {
                    table.par_iter().try_for_each(|row| {
                        let local_constant = row.to_owned(strings, blobs)?;
                        context
                            .local_constant
                            .insert(local_constant.token, local_constant);
                        Ok(())
                    })?;
                }
            }
        }
        Ok(())
    }

    fn table_id(&self) -> TableId {
        TableId::LocalConstant
    }

    fn dependencies(&self) -> &'static [TableId] {
        &[]
    }
}
