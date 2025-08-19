//! Document table loader implementation.
//!
//! This module provides the [`crate::metadata::tables::document::DocumentLoader`] implementation for loading document information
//! from the Portable PDB Document table (0x30). This loader processes debugging metadata that provides information
//! about source documents referenced in the debug information, integrating this data with existing metadata entries.
//!
//! # Key Components
//!
//! - [`crate::metadata::tables::document::DocumentLoader`] - Main loader for processing Document table data
//!
//! # Thread Safety
//!
//! All loading operations use parallel processing with proper synchronization,
//! enabling concurrent processing of multiple document entries.

use crate::metadata::loader::{LoaderContext, MetadataLoader};
use crate::metadata::tables::types::TableId;
use crate::metadata::tables::DocumentRaw;
use crate::prelude::*;
use rayon::prelude::*;

/// Loader implementation for the Document table in Portable PDB format.
///
/// This loader processes the Document table (0x30) from Portable PDB metadata, which contains
/// information about source documents referenced in debug information. Each document entry
/// includes the document name, hash algorithm, hash value, and source language identifier.
///
/// Implements [`crate::metadata::loader::MetadataLoader`] to process the Document table,
/// resolving heap indices and creating fully resolved document structures.
///
/// ## Loading Process
///
/// 1. **Table Validation**: Verifies the Document table exists and has valid row count
/// 2. **Parallel Processing**: Uses parallel iteration for efficient loading of document entries
/// 3. **Index Mapping**: Creates token-based mappings for efficient document lookups
/// 4. **Context Storage**: Stores the processed document map in the loader context
///
/// ## Usage
///
/// The loader is automatically invoked during metadata loading and populates the
/// `document` field in the [`crate::metadata::loader::LoaderContext`]. Document information can be accessed
/// through the context for debug information processing and source code mapping.
///
/// ## Reference
/// * [Portable PDB Format - Document Table](https://github.com/dotnet/core/blob/main/Documentation/diagnostics/portable_pdb.md#document-table-0x30)
pub struct DocumentLoader;

impl MetadataLoader for DocumentLoader {
    fn load(&self, context: &LoaderContext) -> Result<()> {
        if let (Some(header), Some(strings), Some(blob), Some(guid)) =
            (context.meta, context.strings, context.blobs, context.guids)
        {
            if let Some(table) = header.table::<DocumentRaw>() {
                table
                    .par_iter()
                    .map(|row| {
                        let document = row.to_owned(strings, blob, guid)?;
                        context.document.insert(document.token, document);
                        Ok(())
                    })
                    .collect::<Result<Vec<_>>>()?;
            }
        }
        Ok(())
    }

    /// Returns the table identifier for the Document table.
    ///
    /// # Returns
    /// [`crate::metadata::tables::types::TableId::Document`] (0x30)
    fn table_id(&self) -> TableId {
        TableId::Document
    }

    /// Returns the list of table dependencies for Document loading.
    ///
    /// The Document table has no dependencies as it contains self-contained
    /// document metadata with only heap references.
    ///
    /// # Returns
    /// Empty slice - no table dependencies required
    fn dependencies(&self) -> &'static [TableId] {
        &[]
    }
}
