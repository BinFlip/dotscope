//! Document table loader implementation
//!
//! Provides the [`crate::metadata::tables::document::loader::DocumentLoader`] implementation for loading document information
//! from the Portable PDB Document table (0x30). This loader processes debugging metadata that provides information
//! about source documents referenced in the debug information.

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
/// `document` field in the [`LoaderContext`]. Document information can be accessed
/// through the context for debug information processing and source code mapping.
///
/// ```rust,ignore
/// use dotscope::prelude::*;
///
/// # fn example() -> dotscope::Result<()> {
/// # let file_path = "path/to/assembly.dll";
/// let file = File::from_file(file_path)?;
/// let metadata = file.metadata()?;
///
/// // Access document information through the loader context
/// if let Some(document_map) = &metadata.context.document {
///     for (token, document) in document_map.iter() {
///         println!("Document {}: {}", token.table_index(), document.name());
///     }
/// }
/// # Ok(())
/// # }
/// ```
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

    fn table_id(&self) -> TableId {
        TableId::Document
    }

    fn dependencies(&self) -> &'static [TableId] {
        &[]
    }
}
