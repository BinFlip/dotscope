//! `TypeSpec` table loader implementation for .NET metadata parsing.
//!
//! This module provides loading functionality for the `TypeSpec` metadata table, which contains
//! type specifications for generic type instantiations and complex type constructions that
//! cannot be represented by simple `TypeRef` or `TypeDef` entries.
//!
//! ## `TypeSpec` Table Overview
//!
//! The `TypeSpec` table stores signatures for:
//! - **Generic Type Instantiations**: `List<string>`, `Dictionary<int, string>`, etc.
//! - **Array Types**: Multi-dimensional arrays, arrays with bounds
//! - **Pointer Types**: Managed and unmanaged pointers (`int*`, `void*`)
//! - **Reference Types**: By-reference parameters (`ref int`, `out string`)
//! - **Function Pointer Types**: Delegates and function pointer signatures
//! - **Modified Types**: Types with custom modifiers (`volatile`, `const`)
//!
//! ## Dependencies
//!
//! The loader requires these tables to be processed first:
//! - [`TableId::TypeRef`] - External type references used in generic instantiations
//! - [`TableId::TypeDef`] - Local type definitions used as generic arguments
//!
//! ## Reference
//!
//! * [ECMA-335 Partition II, Section 22.39](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `TypeSpec` Table

use crate::{
    metadata::{
        diagnostics::DiagnosticCategory,
        loader::{LoaderContext, MetadataLoader},
    },
    prelude::{TableId, TypeResolver, TypeSpecRaw},
    Result,
};

/// Loader implementation for the `TypeSpec` metadata table.
///
/// This loader processes type specification entries that define complex type constructions
/// such as generic instantiations, arrays, pointers, and other type forms that cannot
/// be represented by simple type references or definitions.
pub(crate) struct TypeSpecLoader;

impl MetadataLoader for TypeSpecLoader {
    /// Loads and processes all entries from the `TypeSpec` metadata table.
    ///
    /// This method performs parallel loading of type specifications, resolving complex
    /// type signatures and storing the results for runtime access. Each type specification
    /// is validated and its signature is fully resolved to ensure type safety.
    ///
    /// ## Arguments
    ///
    /// * `context` - The [`LoaderContext`] containing metadata tables, heaps, and storage
    ///
    /// ## Returns
    ///
    /// - `Ok(())` - All type specifications loaded and validated successfully
    /// - `Err(error)` - Loading failed due to invalid data or unresolvable types
    ///
    /// ## Errors
    ///
    /// - [`crate::Error::Malformed`] - Malformed type signature in blob heap
    /// - [`crate::Error::TypeNotFound`] - Referenced type cannot be resolved
    /// - [`crate::Error::TypeError`] - Type specification violates semantic rules
    fn load(&self, context: &LoaderContext) -> Result<()> {
        let (Some(header), Some(blobs)) = (context.meta, context.blobs) else {
            return Ok(());
        };
        let Some(table) = header.table::<TypeSpecRaw>() else {
            return Ok(());
        };

        table.par_iter().try_for_each(|row| {
            let token_msg = || format!("type spec 0x{:08x}", row.token.value());

            let Some(owned) =
                context.handle_result(row.to_owned(blobs), DiagnosticCategory::Type, token_msg)?
            else {
                return Ok(());
            };

            let mut resolver = TypeResolver::new(context.types.clone()).with_token_init(row.token);

            context.handle_result(
                resolver.resolve(&owned.signature.base),
                DiagnosticCategory::Type,
                token_msg,
            )?;

            context.type_spec.insert(row.token, owned);
            Ok(())
        })
    }

    /// Returns the table identifier for the `TypeSpec` table.
    ///
    /// This method identifies which metadata table this loader is responsible for
    /// processing. The `TypeSpec` table contains type specifications for complex
    /// type constructions that cannot be represented by simple type references.
    ///
    /// ## Returns
    ///
    /// [`TableId::TypeSpec`] - The identifier for the `TypeSpec` metadata table (0x1B)
    fn table_id(&self) -> Option<TableId> {
        Some(TableId::TypeSpec)
    }

    /// Returns the list of tables that must be loaded before processing `TypeSpec` entries.
    ///
    /// Type specifications often reference other types through `TypeRef` or `TypeDef`
    /// entries, so these tables must be processed first to ensure all type references
    /// can be resolved during `TypeSpec` loading.
    ///
    /// ## Returns
    ///
    /// A static slice containing the required table dependencies.
    fn dependencies(&self) -> &'static [TableId] {
        &[TableId::TypeRef, TableId::TypeDef]
    }
}
