//! # `MethodSemantics` Table Loader
//!
//! This module provides the loader implementation for the [`MethodSemantics`](crate::metadata::tables::MethodSemantics) table,
//! which specifies the relationship between methods and events or properties in .NET metadata.
//! It defines which methods are getters, setters, adders, removers, etc.
//!
//! ## Purpose
//!
//! The [`MethodSemanticsLoader`] processes raw [`MethodSemanticsRaw`] entries during metadata loading,
//! converting them to owned [`MethodSemantics`](crate::metadata::tables::MethodSemantics) instances with resolved references and applying
//! the semantic relationships to the associated properties and events.
//!
//! ## Table Dependencies
//!
//! The `MethodSemantics` table depends on:
//! - [`Event`](crate::metadata::tables::Event) - For event semantic associations
//! - [`EventMap`](crate::metadata::tables::EventMap) - For event mapping resolution
//! - [`Property`](crate::metadata::tables::Property) - For property semantic associations  
//! - [`PropertyMap`](crate::metadata::tables::PropertyMap) - For property mapping resolution
//!
//! ## Error Conditions
//!
//! - Method references cannot be resolved
//! - Association coded indexes are malformed
//! - Semantic relationships conflict (e.g., duplicate setters)
//! - Required dependency tables are missing or malformed

use crate::{
    metadata::{
        loader::{LoaderContext, MetadataLoader},
        tables::MethodSemanticsRaw,
    },
    prelude::TableId,
    Result,
};

/// Loader implementation for the `MethodSemantics` metadata table.
///
/// This loader processes [`crate::metadata::tables::MethodSemanticsRaw`] entries, converting them to
/// owned [`crate::metadata::tables::MethodSemantics`] instances with resolved references and applying
/// semantic relationships to properties and events.
pub(crate) struct MethodSemanticsLoader;

impl MetadataLoader for MethodSemanticsLoader {
    /// Loads and processes all `MethodSemantics` table entries.
    ///
    /// ## Arguments
    /// * `context` - The loader context containing metadata tables and storage
    ///
    /// ## Errors
    ///
    /// - Method references cannot be resolved
    /// - Association coded indexes are malformed
    /// - Semantic relationships conflict (e.g., duplicate setters)
    /// - Required dependency tables are missing
    fn load(&self, context: &LoaderContext) -> Result<()> {
        if let Some(header) = context.meta {
            if let Some(table) = header.table::<MethodSemanticsRaw>() {
                table.par_iter().try_for_each(|row| {
                    let owned = row.to_owned(
                        |coded_index| context.get_ref(coded_index),
                        context.method_def,
                    )?;
                    owned.apply()?;

                    context.method_semantics.insert(row.token, owned);
                    Ok(())
                })?;
            }
        }
        Ok(())
    }

    /// Returns the table identifier for `MethodSemantics`.
    ///
    /// ## Returns
    /// [`crate::metadata::tables::TableId::MethodSemantics`] (0x18)
    fn table_id(&self) -> TableId {
        TableId::MethodSemantics
    }

    /// Returns the table dependencies for `MethodSemantics` loading.
    ///
    /// The `MethodSemantics` table requires these tables to be loaded first for proper
    /// association resolution:
    /// - [`Event`](crate::metadata::tables::TableId::Event) - For event semantic associations
    /// - [`EventMap`](crate::metadata::tables::TableId::EventMap) - For event mapping resolution
    /// - [`Property`](crate::metadata::tables::TableId::Property) - For property semantic associations
    /// - [`PropertyMap`](crate::metadata::tables::TableId::PropertyMap) - For property mapping resolution
    ///
    /// ## Returns
    /// Array of required [`crate::metadata::tables::TableId`] dependencies
    fn dependencies(&self) -> &'static [TableId] {
        &[
            TableId::Event,
            TableId::EventMap,
            TableId::Property,
            TableId::PropertyMap,
        ]
    }
}
