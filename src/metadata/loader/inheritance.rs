//! Inheritance chain resolution for .NET metadata.
//!
//! This module provides comprehensive inheritance resolution that runs after TypeDef,
//! TypeRef and TypeSpec have been loaded, ensuring that complex inheritance
//! relationships involving generic type instantiations can be properly resolved.
//!
//! This resolver consolidates all inheritance resolution logic that was previously
//! scattered across individual table loaders, providing a unified and more robust
//! approach to handling circular dependencies.

use crate::{
    metadata::{
        loader::{LoaderContext, MetadataLoader},
        tables::{TableId, TypeDefRaw},
        typesystem::CilTypeReference,
    },
    Error, Result,
};

/// Comprehensive inheritance resolver that runs after all type tables are loaded.
///
/// This resolver handles setting base types for TypeDef entries, consolidating
/// all inheritance resolution logic in one place to properly handle circular
/// dependencies and complex generic type instantiations.
pub(crate) struct InheritanceResolver;

impl MetadataLoader for InheritanceResolver {
    /// Resolves inheritance relationships after all type tables are loaded.
    ///
    /// This method processes all TypeDef entries and resolves their inheritance
    /// relationships in a unified manner, handling all types of base type references
    /// including TypeRef, TypeDef, and TypeSpec (generic instantiations) that could
    /// not be resolved during initial loading due to circular dependencies.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All inheritance relationships resolved successfully
    /// * `Err(_)` - Critical inheritance resolution failure
    fn load(&self, context: &LoaderContext) -> Result<()> {
        if let Some(header) = context.meta {
            if let Some(typedef_table) = header.table::<TypeDefRaw>() {
                typedef_table
                    .par_iter()
                    .try_for_each(|raw_typedef| -> Result<()> {
                        if raw_typedef.extends.row == 0 {
                            return Ok(());
                        }

                        if let Some(type_def) = context.types.get(&raw_typedef.token) {
                                match context.get_ref(&raw_typedef.extends) {
                                    CilTypeReference::TypeDef(type_ref)
                                    | CilTypeReference::TypeRef(type_ref)
                                    | CilTypeReference::TypeSpec(type_ref) => {
                                        let base_type_ref = type_ref.upgrade().ok_or_else(|| {
                                            Error::Error(format!(
                                                "InheritanceResolver: Type reference was dropped for type {}",
                                                type_def.fullname()
                                            ))
                                        })?;

                                        let base_fullname = base_type_ref.fullname();
                                        if let Some(canonical_base_type) = context.types.resolve_type_global(&base_fullname) {
                                            type_def.set_base(&canonical_base_type.into())?;
                                        } else {
                                            type_def.set_base(&base_type_ref.into())?;
                                        }
                                    }
                                    _ => {} // Other types not supported
                            }

                            // Note: Failed resolution is not an error - some TypeSpec references
                            // may legitimately fail to resolve due to incomplete type information
                        }
                        Ok(())
                    })?;
            }
        }

        Ok(())
    }

    /// Returns None since this is a special loader not tied to a specific table.
    fn table_id(&self) -> Option<TableId> {
        None
    }

    /// Returns dependencies for inheritance resolution.
    ///
    /// This resolver must run after all type-related tables are loaded to ensure
    /// all type references can be properly resolved.
    fn dependencies(&self) -> &'static [TableId] {
        &[
            TableId::TypeDef,
            TableId::TypeRef,
            TableId::TypeSpec,
            TableId::InterfaceImpl,
        ]
    }
}
