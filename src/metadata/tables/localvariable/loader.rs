//! `LocalVariable` table loader for metadata processing
//!
//! This module provides the [`LocalVariableLoader`] implementation for processing
//! `LocalVariable` table data during metadata loading. The loader handles parallel
//! processing and integration with the broader loader context.

use crate::{
    metadata::{
        loader::{LoaderContext, MetadataLoader},
        tables::TableId,
    },
    Result,
};

/// Loader for the `LocalVariable` metadata table
///
/// Implements [`MetadataLoader`] to process the `LocalVariable` table (0x33)
/// which stores information about local variables within method scopes,
/// including their names, signatures, and attributes in Portable PDB format.
/// This loader handles the conversion from raw binary data to structured variable
/// metadata for debugging support.
///
/// # Processing Strategy
///
/// The loader uses parallel processing to efficiently handle large numbers of local
/// variable entries, resolving heap references and building the complete variable
/// metadata map for quick runtime access during debugging operations.
///
/// # Dependencies
///
/// This loader depends on the #Strings heap being available in the loader context
/// for resolving variable name strings.
///
/// # Reference
/// * [Portable PDB Format - LocalVariable Table](https://github.com/dotnet/core/blob/main/Documentation/diagnostics/portable_pdb.md#localvariable-table-0x33)
pub struct LocalVariableLoader;

impl MetadataLoader for LocalVariableLoader {
    fn load(&self, context: &LoaderContext) -> Result<()> {
        if let Some(header) = context.meta {
            if let Some(table) = header.table::<crate::metadata::tables::LocalVariableRaw>() {
                if let Some(strings) = context.strings {
                    table.par_iter().try_for_each(|row| {
                        let local_variable = row.to_owned(strings)?;
                        context
                            .local_variable
                            .insert(local_variable.token, local_variable);
                        Ok(())
                    })?;
                }
            }
        }
        Ok(())
    }

    fn table_id(&self) -> TableId {
        TableId::LocalVariable
    }

    fn dependencies(&self) -> &'static [TableId] {
        &[]
    }
}
