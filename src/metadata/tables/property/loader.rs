//! # Property Table Loader
//!
//! This module provides loading functionality for the Property metadata table (ID 0x17).
//! The Property table defines properties exposed by types, including their attributes,
//! names, and type signatures for both getter and setter methods.
//!
//! ## Purpose
//!
//! The Property table serves as the foundation for .NET property system:
//! - Defines property names and signatures for types
//! - Provides property attributes and flags (special name, `RTSpecialName`, etc.)
//! - Enables property-based reflection and metadata queries
//! - Supports property mapping through `PropertyMap` table relationships
//!
//! ## Dependencies
//!
//! - **String Heap**: Required for property name resolution
//! - **Blob Heap**: Required for property signature parsing
//! - **`PropertyMap` Table**: Links properties to their declaring types
//!
//! ## References
//!
//! - ECMA-335, Partition II, §22.34 - Property table specification
//! - [`crate::metadata::tables::PropertyRaw`] - Raw table entry structure
//! - [`crate::metadata::tables::Property`] - Owned table entry type

use crate::{
    metadata::{
        loader::{LoaderContext, MetadataLoader},
        tables::PropertyRaw,
    },
    prelude::TableId,
    Result,
};

/// Loader for Property metadata table entries.
///
/// This loader handles the loading and processing of the Property table (0x17),
/// which defines properties exposed by types including their names, signatures,
/// and attributes. It uses parallel processing for performance and resolves
/// property names and signatures from the metadata heaps.
pub(crate) struct PropertyLoader;

impl MetadataLoader for PropertyLoader {
    /// Loads all Property table entries from the metadata.
    ///
    /// This method processes the Property table if present in the metadata header,
    /// using parallel iteration for performance. Each raw entry is converted to
    /// its owned representation with resolved strings and signatures, then stored
    /// in the loader context for subsequent access.
    ///
    /// ## Arguments
    ///
    /// * `context` - The loader context containing metadata and storage
    ///
    /// ## Returns
    ///
    /// * `Ok(())` - All entries loaded successfully
    /// * `Err(Error)` - Missing heaps, conversion error, or storage error
    fn load(&self, context: &LoaderContext) -> Result<()> {
        if let (Some(header), Some(strings), Some(blob)) =
            (context.meta, context.strings, context.blobs)
        {
            if let Some(table) = header.table::<PropertyRaw>() {
                table.par_iter().try_for_each(|row| {
                    let res = row.to_owned(strings, blob)?;

                    context.property.insert(row.token, res.clone());
                    Ok(())
                })?;
            }
        }

        Ok(())
    }

    /// Returns the table identifier for the Property table.
    ///
    /// ## Returns
    ///
    /// * [`TableId::Property`] - The table identifier (0x17)
    fn table_id(&self) -> TableId {
        TableId::Property
    }

    /// Returns the table dependencies for the Property table.
    ///
    /// The Property table has no direct table dependencies as it contains
    /// primitive fields and heap references rather than table indexes.
    /// However, it requires string and blob heaps for name and signature resolution.
    ///
    /// ## Returns
    ///
    /// * `&[]` - Empty slice indicating no table dependencies
    fn dependencies(&self) -> &'static [TableId] {
        &[]
    }
}
