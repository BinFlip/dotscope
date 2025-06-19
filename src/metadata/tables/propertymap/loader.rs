//! # `PropertyMap` Table Loader
//!
//! This module provides loading functionality for the `PropertyMap` metadata table (ID 0x15).
//! The `PropertyMap` table establishes the relationship between types and their properties,
//! defining which properties belong to which type definitions and enabling property
//! enumeration and lookup operations.
//!
//! ## Purpose
//!
//! The `PropertyMap` table serves as the foundation for type-property relationships:
//! - Maps type definitions to their associated properties
//! - Enables property enumeration for reflection operations
//! - Supports property inheritance and override resolution
//! - Provides efficient property lookup by type
//!
//! ## Dependencies
//!
//! - **Property Table**: Required for property reference resolution
//! - **`PropertyPtr` Table**: Required for property indirection resolution
//! - **`TypeDef` Table**: Required for type definition resolution
//! - **`TypeRef` Table**: Required for external type resolution
//! - **`TypeSpec` Table**: Required for constructed type resolution
//!
//! ## References
//!
//! - ECMA-335, Partition II, §22.35 - `PropertyMap` table specification
//! - [`crate::metadata::tables::PropertyMapRaw`] - Raw table entry structure
//! - [`crate::metadata::tables::PropertyMap`] - Owned table entry type

use crate::{
    metadata::{
        loader::{LoaderContext, MetadataLoader},
        tables::PropertyMapRaw,
    },
    prelude::TableId,
    Result,
};

/// Loader for `PropertyMap` metadata table entries.
///
/// This loader handles the loading and processing of the `PropertyMap` table (0x15),
/// which establishes relationships between types and their properties. It resolves
/// complex dependencies including type references and property collections while
/// validating property-type relationships during the loading process.
pub(crate) struct PropertyMapLoader;

impl MetadataLoader for PropertyMapLoader {
    /// Loads all `PropertyMap` table entries from the metadata.
    ///
    /// This method processes the `PropertyMap` table if present in the metadata header,
    /// using parallel iteration for performance. Each raw entry is converted to its
    /// owned representation with resolved type and property references, validated for
    /// correctness, and stored in the loader context for subsequent access.
    ///
    /// ## Arguments
    ///
    /// * `context` - The loader context containing metadata and storage
    ///
    /// ## Returns
    ///
    /// * `Ok(())` - All entries loaded successfully
    /// * `Err(Error)` - Missing dependencies, validation error, or storage error
    fn load(&self, context: &LoaderContext) -> Result<()> {
        if let Some(header) = context.meta.as_ref() {
            if let Some(table) = header.table::<PropertyMapRaw>() {
                table.par_iter().try_for_each(|row| {
                    let owned = row.to_owned(
                        context.types,
                        &context.property,
                        &context.property_ptr,
                        table,
                    )?;
                    owned.apply()?;

                    context.property_map.insert(row.token, owned);
                    Ok(())
                })?;
            }
        }

        Ok(())
    }

    /// Returns the table identifier for the `PropertyMap` table.
    ///
    /// ## Returns
    ///
    /// * [`TableId::PropertyMap`] - The table identifier (0x15)
    fn table_id(&self) -> TableId {
        TableId::PropertyMap
    }

    /// Returns the table dependencies for the `PropertyMap` table.
    ///
    /// The `PropertyMap` table has several critical dependencies for proper resolution
    /// of type-property relationships and property reference validation.
    ///
    /// ## Dependencies
    ///
    /// - **Property**: Required for property definition resolution
    /// - **`PropertyPtr`**: Required for property indirection resolution
    /// - **`TypeDef`**: Required for type definition resolution
    /// - **`TypeRef`**: Required for external type resolution
    /// - **`TypeSpec`**: Required for constructed type resolution
    ///
    /// ## Returns
    ///
    /// * `&[TableId]` - Array of required table dependencies
    fn dependencies(&self) -> &'static [TableId] {
        &[
            TableId::Property,
            TableId::PropertyPtr,
            TableId::TypeDef,
            TableId::TypeRef,
            TableId::TypeSpec,
        ]
    }
}
