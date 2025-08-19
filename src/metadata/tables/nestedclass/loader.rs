//! # `NestedClass` Table Loader
//!
//! This module provides the loader implementation for the [`NestedClass`](crate::metadata::tables::NestedClass) table,
//! which defines nested type relationships between enclosing and nested types.
//! `NestedClass` entries establish the hierarchical structure of nested types in .NET assemblies.
//!
//! ## Purpose
//!
//! The [`NestedClassLoader`] processes [`crate::metadata::tables::NestedClassRaw`] entries during metadata loading,
//! converting them to owned [`NestedClass`](crate::metadata::tables::NestedClass) instances with resolved type references.
//! These entries define which types are nested within other types, enabling proper
//! type hierarchy resolution and visibility scoping.
//!
//! ## Table Dependencies
//!
//! The `NestedClass` table depends on type definition and reference tables:
//! - [`crate::metadata::tables::TableId::TypeDef`] - For locally defined types
//! - [`crate::metadata::tables::TableId::TypeRef`] - For external type references
//! - [`crate::metadata::tables::TableId::TypeSpec`] - For constructed type specifications
//!
//! These dependencies ensure that type references can be properly resolved during loading.
//!
//! ## Error Conditions
//!
//! - Type references cannot be resolved or are invalid
//! - `NestedClass` table contains malformed or corrupted data
//! - Circular nesting relationships are detected
//! - Token conflicts occur during storage
//!
use crate::{
    metadata::{
        loader::{LoaderContext, MetadataLoader},
        tables::NestedClassRaw,
    },
    prelude::TableId,
    Result,
};

/// Loader implementation for the `NestedClass` metadata table.
///
/// This loader processes [`crate::metadata::tables::NestedClassRaw`] entries, converting them to
/// owned [`crate::metadata::tables::NestedClass`] instances with resolved type references.
/// `NestedClass` entries define the hierarchical relationships between enclosing and nested types,
/// establishing proper type visibility and scoping rules.
pub(crate) struct NestedClassLoader;

impl MetadataLoader for NestedClassLoader {
    /// Loads and processes all `NestedClass` table entries.
    ///
    /// ## Arguments
    /// * `context` - The loader context containing metadata tables and storage
    ///
    /// ## Errors
    ///
    /// - Type references cannot be resolved or are invalid
    /// - `NestedClass` table contains malformed or corrupted data
    /// - Circular nesting relationships are detected during processing
    /// - Storage operations fail due to token conflicts
    ///
    fn load(&self, context: &LoaderContext) -> Result<()> {
        if let Some(header) = context.meta.as_ref() {
            if let Some(table) = header.table::<NestedClassRaw>() {
                table.par_iter().try_for_each(|row| {
                    let owned = row.to_owned(context.types)?;
                    owned.apply()?;

                    context.nested_class.insert(row.token, owned);
                    Ok(())
                })?;
            }
        }

        Ok(())
    }

    /// Returns the table identifier for `NestedClass`.
    ///
    /// ## Returns
    /// [`crate::metadata::tables::TableId::NestedClass`] (0x29)
    fn table_id(&self) -> TableId {
        TableId::NestedClass
    }

    /// Returns the table dependencies for `NestedClass` loading.
    ///
    /// The `NestedClass` table depends on type definition and reference tables to resolve
    /// nested and enclosing type relationships. These dependencies ensure that all
    /// referenced types are available during nested class processing.
    ///
    /// ## Dependencies
    /// - [`crate::metadata::tables::TableId::TypeRef`] - External type references
    /// - [`crate::metadata::tables::TableId::TypeDef`] - Local type definitions
    /// - [`crate::metadata::tables::TableId::TypeSpec`] - Constructed type specifications
    ///
    /// ## Returns
    /// Array of table IDs that must be loaded before `NestedClass` processing
    fn dependencies(&self) -> &'static [TableId] {
        &[TableId::TypeRef, TableId::TypeDef, TableId::TypeSpec]
    }
}
