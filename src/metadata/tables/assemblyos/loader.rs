//! `AssemblyOS` table loader implementation
//!
//! Provides the [`crate::metadata::tables::assemblyos::loader::AssemblyOsLoader`] implementation for loading operating system information
//! from the ECMA-335 `AssemblyOS` table (0x22). This loader processes platform-specific metadata
//! that specifies which operating systems the assembly is designed to run on.
//!
//! # Table Structure
//!
//! The `AssemblyOS` table contains platform identification information:
//! - **`OSPlatformId`**: Operating system platform identifier
//! - **`OSMajorVersion`**: Major version number of the target OS
//! - **`OSMinorVersion`**: Minor version number of the target OS
//!
//! # Usage Context
//!
//! This table is rarely used in modern .NET assemblies and is considered legacy.
//! Most assemblies are designed to be platform-neutral and rely on the runtime
//! to handle platform-specific concerns.
//!
//! # Reference
//! - [ECMA-335 II.22.3](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `AssemblyOS` table specification

use crate::{
    metadata::{
        loader::{LoaderContext, MetadataLoader},
        tables::{AssemblyOsRaw, TableId},
    },
    Result,
};

/// Loader for the `AssemblyOS` metadata table
///
/// Implements [`crate::metadata::loader::MetadataLoader`] to process the `AssemblyOS` table (0x22)
/// which contains operating system platform information for the current assembly. This table
/// specifies the target operating systems and versions that the assembly is designed to support.
pub(crate) struct AssemblyOsLoader;

impl MetadataLoader for AssemblyOsLoader {
    /// Load operating system metadata from the `AssemblyOS` table
    ///
    /// Processes `AssemblyOS` table rows (if present) and stores the operating system
    /// compatibility information in the loader context. The `AssemblyOS` table is optional
    /// and rarely present in modern .NET assemblies.
    ///
    /// # Arguments
    /// * `context` - Loader context containing metadata tables
    ///
    /// # Returns
    /// * `Ok(())` - `AssemblyOS` successfully loaded or table not present
    /// * `Err(`[`crate::Error`]`)` - Malformed data or duplicate `AssemblyOS` information
    fn load(&self, context: &LoaderContext) -> Result<()> {
        if let Some(header) = context.meta {
            if let Some(table) = header.table::<AssemblyOsRaw>() {
                if let Some(row) = table.get(1) {
                    let owned = row.to_owned()?;

                    context
                        .assembly_os
                        .set(owned)
                        .map_err(|_| malformed_error!("AssemblyOs has already been set"))?;
                    return Ok(());
                }
            }
        }
        Ok(())
    }

    /// Returns the table identifier for the `AssemblyOS` table
    ///
    /// # Returns
    /// [`crate::metadata::tables::TableId::AssemblyOS`] (0x22)
    fn table_id(&self) -> TableId {
        TableId::AssemblyOS
    }

    /// Returns the list of table dependencies
    ///
    /// The `AssemblyOS` table has no dependencies on other metadata tables or heaps,
    /// as it contains only platform identification integers.
    ///
    /// # Returns
    /// Empty slice - no table dependencies
    fn dependencies(&self) -> &'static [TableId] {
        &[]
    }
}
