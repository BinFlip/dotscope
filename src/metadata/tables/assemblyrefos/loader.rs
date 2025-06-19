//! `AssemblyRefOS` table loader implementation.
//!
//! This module provides the loader implementation for the `AssemblyRefOS` metadata table,
//! which contains operating system compatibility information for external assembly references.
//! The [`crate::metadata::tables::assemblyrefos::loader::AssemblyRefOsLoader`] processes
//! OS requirements and integrates them with existing assembly reference data.
//!
//! # Architecture
//!
//! The loader follows the standard metadata loading pattern, implementing the
//! [`crate::metadata::loader::MetadataLoader`] trait to process table data and integrate
//! OS compatibility information with previously loaded [`crate::metadata::tables::assemblyref::AssemblyRef`] entries.
//!
//! # Key Components
//!
//! - [`crate::metadata::tables::assemblyrefos::loader::AssemblyRefOsLoader`] - Main loader implementation
//! - [`crate::metadata::tables::assemblyrefos::AssemblyRefOsRaw`] - Raw table row structure
//! - [`crate::metadata::loader::LoaderContext`] - Context for loading operations
//!
//! # Table Structure
//!
//! The `AssemblyRefOS` table contains zero or more rows that specify OS requirements for assembly references:
//! - **`OSPlatformId`**: Operating system platform identifier
//! - **`OSMajorVersion`**: Major version of the target OS
//! - **`OSMinorVersion`**: Minor version of the target OS  
//! - **`AssemblyRef`**: Reference to the corresponding `AssemblyRef` table entry
//!
//! # Dependencies
//!
//! This loader depends on the `AssemblyRef` table being loaded first, as it needs to update
//! existing assembly reference entries with OS compatibility information.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::loader`] - Core metadata loading infrastructure
//! - [`crate::metadata::tables::assemblyref`] - Assembly reference table entries
//! - [`crate::metadata::tables::assemblyrefos`] - `AssemblyRefOS` table types
//!
//! # References
//!
//! - [ECMA-335 II.22.7](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `AssemblyRefOS` table specification

use crate::{
    metadata::{
        loader::{LoaderContext, MetadataLoader},
        tables::AssemblyRefOsRaw,
    },
    prelude::TableId,
    Result,
};

/// Loader for the `AssemblyRefOS` metadata table
///
/// Implements [`crate::metadata::loader::MetadataLoader`] to process the `AssemblyRefOS` table (0x25)
/// which contains operating system compatibility information for external assembly references.
/// This table specifies platform requirements for each referenced assembly dependency.
///
/// # Thread Safety
///
/// This type is [`Send`] and [`Sync`] as it contains no mutable state and all operations
/// are read-only during the metadata loading phase. The loader uses parallel iteration
/// for performance when processing multiple `AssemblyRefOS` entries.
pub(crate) struct AssemblyRefOsLoader;

impl MetadataLoader for AssemblyRefOsLoader {
    /// Load `AssemblyRefOS` metadata and integrate with assembly references
    ///
    /// Processes all rows in the `AssemblyRefOS` table, resolving references to the
    /// `AssemblyRef` table and updating existing assembly references with operating
    /// system compatibility information.
    ///
    /// # Arguments
    ///
    /// * `context` - [`crate::metadata::loader::LoaderContext`] containing metadata tables and storage collections
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All `AssemblyRefOS` entries successfully processed and integrated
    /// * `Err(`[`crate::Error`]`)` - Processing failed due to malformed data or missing dependencies
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] in the following cases:
    /// - `AssemblyRef` table references are invalid or missing
    /// - `AssemblyRefOS` table structure is malformed
    /// - Integration with existing assembly references fails
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and uses parallel iteration for performance.
    /// Updates to assembly references are handled through atomic operations.
    fn load(&self, context: &LoaderContext) -> Result<()> {
        if let Some(ref header) = context.meta {
            if let Some(table) = header.table::<AssemblyRefOsRaw>(TableId::AssemblyRefOS) {
                table.par_iter().try_for_each(|row| {
                    let owned = row.to_owned(context.assembly_ref)?;
                    owned.apply()?;

                    context.assembly_ref_os.insert(row.token, owned);
                    Ok(())
                })?;
            }
        }
        Ok(())
    }

    /// Returns the table identifier for `AssemblyRefOS`
    ///
    /// Provides the [`TableId::AssemblyRefOS`] constant used to identify this table
    /// type within the metadata loading framework.
    fn table_id(&self) -> TableId {
        TableId::AssemblyRefOS
    }

    /// Returns the table dependencies for `AssemblyRefOS` loading
    ///
    /// Specifies that `AssemblyRefOS` loading depends on the `AssemblyRef` table,
    /// ensuring that assembly references are loaded before OS compatibility
    /// data is integrated.
    fn dependencies(&self) -> &'static [TableId] {
        &[TableId::AssemblyRef]
    }
}
