//! `TypeRef` table loader implementation for .NET metadata.
//!
//! This module provides the [`crate::metadata::tables::typeref::loader::TypeRefLoader`] for processing `TypeRef` table entries,
//! which represent references to types defined in external assemblies or modules.
//! `TypeRef` entries are essential for type resolution in cross-assembly scenarios.
//!
//! ## Purpose
//! The `TypeRef` table contains references to types that are:
//! - Defined in other assemblies (referenced assemblies)
//! - Defined in other modules within the same assembly
//! - Required for type resolution and linking
//!
//! ## Type System Integration
//! - External type references are registered in the imports system
//! - Types are added to the global type registry for resolution
//! - Cross-assembly type linking is enabled
//!
//! ## ECMA-335 Reference
//! See ECMA-335, Partition II, Section 22.38 for `TypeRef` table specification.

use crate::{
    metadata::loader::{LoaderContext, MetadataLoader},
    prelude::{TableId, TypeRefRaw},
    Result,
};

/// Loader implementation for the `TypeRef` metadata table.
///
/// This loader processes `TypeRef` table entries (table ID 0x01) that represent
/// references to types defined in external assemblies or modules. It handles
/// type name resolution, parent assembly/module linking, and integration with
/// both the imports system and global type registry.
pub(crate) struct TypeRefLoader;

impl MetadataLoader for TypeRefLoader {
    /// Loads and processes all `TypeRef` table entries from the metadata.
    ///
    /// ## Arguments
    /// * `context` - Loading context with metadata access and storage facilities
    ///
    /// ## Returns
    /// * `Ok(())` - All `TypeRef` entries processed and registered successfully
    /// * `Err(_)` - Type reference loading or registration failed
    fn load(&self, context: &LoaderContext) -> Result<()> {
        if let (Some(header), Some(strings)) = (context.meta, context.strings) {
            if let Some(table) = header.table::<TypeRefRaw>() {
                table.par_iter().try_for_each(|row| {
                    let new_entry =
                        row.to_owned(|coded_index| context.get_ref(coded_index), strings, true)?;

                    context.types.insert(new_entry);
                    Ok(())
                })?;

                table.par_iter().try_for_each(|row| -> Result<()> {
                    if let Some(type_ref) = context.types.get(&row.token) {
                        if let Some(resolution_scope) =
                            row.resolve_resolution_scope(|coded_index| context.get_ref(coded_index))
                        {
                            type_ref.set_external(resolution_scope)?;
                            context.imports.add_type(&type_ref)?;
                        }
                    }
                    Ok(())
                })?;
            }
        }

        Ok(())
    }

    /// Returns the table identifier for the `TypeRef` table.
    ///
    /// ## Returns
    /// [`crate::metadata::tables::TableId::TypeRef`] (0x01) - The metadata table identifier for external type references
    fn table_id(&self) -> TableId {
        TableId::TypeRef
    }

    /// Returns the dependency list for `TypeRef` table loading.
    ///
    /// The `TypeRef` table depends on tables that can serve as parent scopes
    /// for external type references:
    ///
    /// - **`ModuleRef`**: For types defined in external modules of the same assembly
    /// - **`AssemblyRef`**: For types defined in external referenced assemblies
    ///
    /// These dependencies ensure that parent scope information is available
    /// before processing type references.
    ///
    /// ## Returns
    /// A slice containing the required table dependencies for `TypeRef` loading
    fn dependencies(&self) -> &'static [TableId] {
        &[TableId::ModuleRef, TableId::AssemblyRef]
    }
}
