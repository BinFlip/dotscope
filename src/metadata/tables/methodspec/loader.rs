//! # `MethodSpec` Table Loader
//!
//! This module provides the loader implementation for the [`MethodSpec`](crate::metadata::tables::MethodSpec) table,
//! which represents instantiations of generic methods in .NET metadata. The `MethodSpec` table is essential
//! for resolving generic method calls with concrete type arguments.
//!
//! ## Purpose
//!
//! The [`MethodSpecLoader`] processes raw [`crate::metadata::tables::MethodSpecRaw`] entries during metadata loading,
//! converting them to owned [`crate::metadata::tables::MethodSpec`] instances with resolved references,
//! parsed generic instantiation signatures, and applied generic arguments to the target methods.
//!
//! ## Table Dependencies
//!
//! The `MethodSpec` table depends on:
//! - [`crate::metadata::tables::TypeDefRaw`] - For type definition resolution
//! - [`crate::metadata::tables::TypeRefRaw`] - For external type references
//! - [`crate::metadata::tables::TypeSpec`] - For constructed type specifications
//! - [`crate::metadata::tables::MethodDefRaw`] - For method definition resolution
//! - [`crate::metadata::tables::MemberRef`] - For member reference resolution

use crate::{
    metadata::{
        loader::{LoaderContext, MetadataLoader},
        tables::MethodSpecRaw,
    },
    prelude::TableId,
    Result,
};

/// Loader implementation for the `MethodSpec` metadata table.
///
/// This loader processes [`crate::metadata::tables::MethodSpecRaw`] entries, converting them to
/// owned [`crate::metadata::tables::MethodSpec`] instances with resolved references, parsed generic
/// instantiation signatures, and applied generic arguments to target methods.
pub(crate) struct MethodSpecLoader;

impl MetadataLoader for MethodSpecLoader {
    /// Loads and processes all `MethodSpec` table entries.
    ///
    /// ## Arguments
    /// * `context` - The loader context containing metadata tables and storage
    ///
    /// ## Errors
    ///
    /// - Method references cannot be resolved (invalid `MethodDefOrRef` coded index)
    /// - Blob heap entries are malformed or missing
    /// - Generic type signatures cannot be parsed
    /// - Type registry cannot resolve generic arguments
    /// - Target methods cannot accept generic instantiations
    fn load(&self, context: &LoaderContext) -> Result<()> {
        if let (Some(header), Some(blob)) = (context.meta, context.blobs) {
            if let Some(table) = header.table::<MethodSpecRaw>() {
                table.par_iter().try_for_each(|row| {
                    let owned = row.to_owned_and_apply(
                        |coded_index| context.get_ref(coded_index),
                        blob,
                        context.types,
                    )?;

                    context.method_spec.insert(row.token, owned);
                    Ok(())
                })?;
            }
        }
        Ok(())
    }

    /// Returns the table identifier for `MethodSpec`.
    ///
    /// ## Returns
    /// [`crate::metadata::tables::TableId::MethodSpec`] (0x2B)
    fn table_id(&self) -> TableId {
        TableId::MethodSpec
    }

    /// Returns the table dependencies for `MethodSpec` loading.
    ///
    /// The `MethodSpec` table requires these tables to be loaded first for proper
    /// reference resolution and generic type instantiation:
    /// - [`TypeDef`](crate::metadata::tables::TableId::TypeDef) - For type definition resolution
    /// - [`TypeRef`](crate::metadata::tables::TableId::TypeRef) - For external type references
    /// - [`TypeSpec`](crate::metadata::tables::TableId::TypeSpec) - For constructed type specifications
    /// - [`MethodDef`](crate::metadata::tables::TableId::MethodDef) - For method definition resolution
    /// - [`MemberRef`](crate::metadata::tables::TableId::MemberRef) - For member reference resolution
    ///
    /// ## Returns
    /// Array of required [`crate::metadata::tables::TableId`] dependencies
    fn dependencies(&self) -> &'static [TableId] {
        &[
            TableId::TypeDef,
            TableId::TypeRef,
            TableId::TypeSpec,
            TableId::MethodDef,
            TableId::MemberRef,
        ]
    }
}
