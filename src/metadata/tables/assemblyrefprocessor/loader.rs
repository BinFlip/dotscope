//! `AssemblyRefProcessor` table loader implementation.
//!
//! This module provides the [`crate::metadata::tables::assemblyrefprocessor::loader::AssemblyRefProcessorLoader`]
//! implementation for loading `AssemblyRefProcessor` metadata from the ECMA-335 `AssemblyRefProcessor` table (0x24).
//! The loader processes processor architecture compatibility information for external assembly references
//! and integrates it with existing assembly reference data.
//!
//! # Architecture
//!
//! The loader follows the standard metadata loading pattern, implementing the
//! [`crate::metadata::loader::MetadataLoader`] trait to process table data and integrate
//! processor compatibility information with previously loaded [`crate::metadata::tables::assemblyref::AssemblyRef`] entries.
//!
//! # Key Components
//!
//! - [`crate::metadata::tables::assemblyrefprocessor::loader::AssemblyRefProcessorLoader`] - Main loader implementation
//! - [`crate::metadata::tables::assemblyrefprocessor::AssemblyRefProcessorRaw`] - Raw table row structure
//! - [`crate::metadata::loader::LoaderContext`] - Context for loading operations
//!
//! # Table Structure
//!
//! The `AssemblyRefProcessor` table contains zero or more rows that specify processor requirements for assembly references:
//! - **Processor**: Processor architecture identifier (x86, x64, ARM, etc.)
//! - **`AssemblyRef`**: Reference to the corresponding `AssemblyRef` table entry
//!
//! # Dependencies
//!
//! This loader depends on the `AssemblyRef` table being loaded first, as it needs to update
//! existing assembly reference entries with processor compatibility information.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::loader`] - Core metadata loading infrastructure
//! - [`crate::metadata::tables::assemblyref`] - Assembly reference table entries
//! - [`crate::metadata::tables::assemblyrefprocessor`] - `AssemblyRefProcessor` table types
//!
//! # References
//!
//! - [ECMA-335 II.22.8](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `AssemblyRefProcessor` table specification

use crate::{
    metadata::{
        loader::{LoaderContext, MetadataLoader},
        tables::AssemblyRefProcessorRaw,
    },
    prelude::TableId,
    Result,
};

/// Loader for the `AssemblyRefProcessor` metadata table
///
/// Implements [`crate::metadata::loader::MetadataLoader`] to process the `AssemblyRefProcessor` table (0x24)
/// which contains processor architecture compatibility information for external assembly references.
/// This table specifies processor requirements for each referenced assembly dependency, enabling
/// assemblies to declare explicit processor architecture constraints.
///
/// # Historical Context
///
/// The `AssemblyRefProcessor` table is rarely used in modern .NET assemblies and is considered legacy.
/// It was designed for early .NET Framework scenarios where assemblies might need explicit processor
/// compatibility declarations. Modern .NET relies on runtime platform abstraction and JIT compilation.
///
/// # Thread Safety
///
/// This type is [`Send`] and [`Sync`] as it contains no mutable state and all operations
/// are read-only during the metadata loading phase. The loader uses parallel iteration
/// for performance when processing multiple `AssemblyRefProcessor` entries.
pub(crate) struct AssemblyRefProcessorLoader;

impl MetadataLoader for AssemblyRefProcessorLoader {
    /// Load `AssemblyRefProcessor` metadata and integrate with assembly references
    ///
    /// Processes all rows in the `AssemblyRefProcessor` table, resolving references to the
    /// `AssemblyRef` table and updating existing assembly references with processor
    /// architecture compatibility information. Each processed entry is stored in the
    /// loader context for subsequent access.
    ///
    /// # Arguments
    ///
    /// * `context` - [`crate::metadata::loader::LoaderContext`] containing metadata tables and storage collections
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All `AssemblyRefProcessor` entries successfully processed and integrated
    /// * `Err(`[`crate::Error`]`)` - Processing failed due to malformed data or missing dependencies
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] in the following cases:
    /// - `AssemblyRef` table references are invalid or missing
    /// - `AssemblyRefProcessor` table structure is malformed
    /// - Integration with existing assembly references fails
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and uses parallel iteration for performance.
    /// Updates to assembly references are handled through atomic operations.
    fn load(&self, context: &LoaderContext) -> Result<()> {
        if let Some(header) = context.meta {
            if let Some(table) = header.table::<AssemblyRefProcessorRaw>() {
                table.par_iter().try_for_each(|row| {
                    let owned = row.to_owned(context.assembly_ref)?;
                    owned.apply()?;

                    context.assembly_ref_processor.insert(row.token, owned);
                    Ok(())
                })?;
            }
        }
        Ok(())
    }

    /// Returns the table identifier for `AssemblyRefProcessor`
    ///
    /// Provides the [`crate::prelude::TableId::AssemblyRefProcessor`] constant used to identify this table
    /// type within the metadata loading framework.
    fn table_id(&self) -> TableId {
        TableId::AssemblyRefProcessor
    }

    /// Returns the table dependencies for `AssemblyRefProcessor` loading
    ///
    /// Specifies that `AssemblyRefProcessor` loading depends on the `AssemblyRef` table,
    /// ensuring that assembly references are loaded before processor compatibility
    /// data is integrated. This dependency ordering prevents resolution failures
    /// during the loading process.
    fn dependencies(&self) -> &'static [TableId] {
        &[TableId::AssemblyRef]
    }
}
