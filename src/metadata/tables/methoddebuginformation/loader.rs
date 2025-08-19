//! `MethodDebugInformation` table loader implementation
//!
//! Provides the [`MethodDebugInformationLoader`] implementation for loading method debugging
//! metadata from the Portable PDB `MethodDebugInformation` table (0x31). This loader is responsible
//! for processing debugging information that maps IL instructions to source code locations,
//! essential for providing step-through debugging capabilities.
//!
//! # Table Structure
//!
//! The `MethodDebugInformation` table contains debugging information for methods:
//! - **Document**: Coded index reference to the source document
//! - **`SequencePoints`**: Blob heap reference containing encoded sequence point data
//!
//! # Loading Process
//!
//! The loader processes method debug information entries in parallel, resolving heap references
//! and storing the complete debugging metadata in the loader context for use by debugging tools
//! and runtime environments.
//!
//! # Reference
//! * [Portable PDB Format - MethodDebugInformation Table](https://github.com/dotnet/core/blob/main/Documentation/diagnostics/portable_pdb.md#methoddebuginformation-table-0x31)

use crate::{
    metadata::{
        loader::{LoaderContext, MetadataLoader},
        tables::{MethodDebugInformationRaw, TableId},
    },
    Result,
};

/// Loader for the `MethodDebugInformation` metadata table
///
/// Implements [`MetadataLoader`] to process the `MethodDebugInformation` table (0x31)
/// which contains debugging information for methods in Portable PDB format. This loader
/// handles the conversion from raw binary data to structured debugging metadata that
/// can be used by development tools and debuggers.
///
/// # Processing Strategy
///
/// The loader uses parallel processing to efficiently handle large numbers of method
/// debug information entries, resolving heap references and building the complete
/// debugging metadata map for quick runtime access.
///
/// # Dependencies
///
/// This loader has no dependencies on other metadata tables, as it only references
/// heap data and coded indices that are resolved during the loading process.
///
/// # Reference
/// * [Portable PDB Format - `MethodDebugInformation` Table](https://github.com/dotnet/core/blob/main/Documentation/diagnostics/portable_pdb.md#methoddebuginformation-table-0x31)
pub struct MethodDebugInformationLoader;

impl MetadataLoader for MethodDebugInformationLoader {
    fn load(&self, context: &LoaderContext) -> Result<()> {
        if let (Some(header), Some(blob)) = (context.meta, context.blobs) {
            if let Some(table) = header.table::<MethodDebugInformationRaw>() {
                table.par_iter().try_for_each(|row| {
                    let method_debug_info = row.to_owned(blob)?;
                    context
                        .method_debug_information
                        .insert(method_debug_info.token, method_debug_info);
                    Ok(())
                })?;
            }
        }
        Ok(())
    }

    fn table_id(&self) -> TableId {
        TableId::MethodDebugInformation
    }

    fn dependencies(&self) -> &'static [TableId] {
        &[]
    }
}
