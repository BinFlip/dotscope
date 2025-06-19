//! `MethodDef` table loader implementation.
//!
//! This module provides the [`MethodDefLoader`] responsible for loading and processing
//! `MethodDef` metadata table entries. The `MethodDef` table defines method implementations
//! within types, including method signatures, implementation details, and parameter
//! information essential for method invocation and reflection in .NET applications.
//!
//! # Purpose
//! The `MethodDef` table is fundamental to type system implementation and method execution:
//! - **Method implementation**: Concrete method definitions with IL code or native implementations
//! - **Signature information**: Method parameters, return types, and calling conventions
//! - **Access control**: Method visibility and security attributes
//! - **Virtual dispatch**: Method overriding and interface implementation support
//! - **Reflection support**: Runtime method discovery and dynamic invocation
//!
//! # Method Implementation Types
//! `MethodDef` entries support different implementation patterns:
//! - **IL methods**: Managed code with Common Intermediate Language implementation
//! - **Native methods**: Platform-specific native code implementations
//! - **Abstract methods**: Interface or abstract class method declarations
//! - **P/Invoke methods**: Platform invocation service for external library calls
//! - **Runtime methods**: Special methods implemented by the runtime system
//!
//! # Table Dependencies
//! - **Param**: Required for resolving method parameter metadata and names
//! - **`ParamPtr`**: Required for parameter pointer indirection (if present)
//!
//! # ECMA-335 Reference
//! See ECMA-335, Partition II, §22.26 for the `MethodDef` table specification.

use crate::{
    metadata::{
        loader::{LoaderContext, MetadataLoader},
        tables::{MethodDefRaw, TableId},
    },
    Result,
};

/// Loader implementation for the `MethodDef` metadata table.
///
/// This loader processes method definition metadata, establishing complete method
/// implementations with parameter information and signature details. It handles
/// parameter resolution, signature parsing, and creates comprehensive method
/// definition objects for type system integration.
pub(crate) struct MethodDefLoader;

impl MetadataLoader for MethodDefLoader {
    /// Loads `MethodDef` table entries and establishes complete method implementations.
    ///
    /// This method iterates through all `MethodDef` table entries, resolving parameter
    /// information and parsing method signatures to create comprehensive method
    /// definition objects. Each entry is converted to an owned structure with complete
    /// parameter metadata for method invocation and reflection operations.
    ///
    /// # Arguments
    /// * `context` - The loading context containing metadata tables, strings, and blob heap
    ///
    /// # Returns
    /// * `Ok(())` - If all `MethodDef` entries were processed successfully
    /// * `Err(_)` - If parameter resolution, signature parsing, or name resolution fails
    fn load(&self, context: &LoaderContext) -> Result<()> {
        if let (Some(header), Some(strings), Some(blobs)) =
            (context.meta, context.strings, context.blobs)
        {
            if let Some(table) = header.table::<MethodDefRaw>(TableId::MethodDef) {
                table.par_iter().try_for_each(|row| {
                    let owned =
                        row.to_owned(strings, blobs, &context.param, &context.param_ptr, table)?;

                    context.method_def.insert(row.token, owned.clone());
                    Ok(())
                })?;
            }
        }

        Ok(())
    }

    /// Returns the table identifier for `MethodDef`.
    ///
    /// # Returns
    /// The [`TableId::MethodDef`] identifier for this table type.
    fn table_id(&self) -> TableId {
        TableId::MethodDef
    }

    /// Returns the dependencies required for loading `MethodDef` entries.
    ///
    /// `MethodDef` table loading requires other tables to resolve parameter information:
    /// - [`TableId::Param`] - For method parameter metadata, names, and attributes
    /// - [`TableId::ParamPtr`] - For parameter pointer indirection (if present in assembly)
    ///
    /// # Returns
    /// Array of table identifiers that must be loaded before `MethodDef` processing.
    fn dependencies(&self) -> &'static [TableId] {
        &[TableId::Param, TableId::ParamPtr]
    }
}
