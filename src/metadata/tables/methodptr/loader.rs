//! `MethodPtr` table loader implementation.
//!
//! This module provides the [`MethodPtrLoader`] responsible for loading and processing
//! `MethodPtr` metadata table entries. The `MethodPtr` table provides an additional level
//! of indirection for accessing `MethodDef` table entries, primarily used for method
//! editing scenarios where method table reorganization is required.
//!
//! # Purpose
//! The `MethodPtr` table serves specialized metadata manipulation scenarios:
//! - **Method table indirection**: Provides stable references during method table reorganization
//! - **Edit-and-continue**: Supports runtime method modification and hot-swapping
//! - **Method versioning**: Enables method replacement without breaking existing references
//! - **Debugging support**: Facilitates debugger method interception and modification
//! - **Incremental compilation**: Allows method updates without full assembly recompilation
//!
//! # Indirection Mechanism
//! `MethodPtr` entries create a logical-to-physical mapping:
//! - **Logical references**: Stable method identifiers used by other metadata tables
//! - **Physical references**: Actual `MethodDef` table entries containing implementation
//! - **Pointer resolution**: Translation from logical to physical method references
//! - **Table reorganization**: Allows `MethodDef` table modifications without breaking references
//!
//! # Usage Context
//! The `MethodPtr` table is optional and typically present only in specialized scenarios:
//! - **Development environments**: IDEs with edit-and-continue functionality
//! - **Debugging sessions**: Debuggers requiring method interception capabilities
//! - **Hot-reload systems**: Runtime environments supporting dynamic method updates
//! - **Incremental builds**: Build systems performing partial assembly updates
//!
//! # Table Dependencies
//! The `MethodPtr` table has no dependencies and must be loaded before other tables
//! that reference methods, as it affects method token resolution throughout the system.
//!
//! # ECMA-335 Reference
//! See ECMA-335, Partition II, §22.28 for the `MethodPtr` table specification.
//!
//! [`MethodPtrLoader`]: crate::metadata::tables::MethodPtrLoader

use crate::{
    metadata::{
        loader::{LoaderContext, MetadataLoader},
        tables::{MethodPtrRaw, TableId},
    },
    Result,
};

/// Loader implementation for the `MethodPtr` metadata table.
///
/// This loader processes method pointer metadata, establishing indirection mappings
/// between logical method references and physical `MethodDef` table entries. It handles
/// the specialized scenarios where method table reorganization or runtime method
/// modification requires stable method reference resolution.
pub(crate) struct MethodPtrLoader;

impl MetadataLoader for MethodPtrLoader {
    /// Loads `MethodPtr` table entries and establishes method indirection mappings.
    ///
    /// This method iterates through all `MethodPtr` table entries, converting them to owned
    /// structures and applying the indirection mappings to the method resolution system.
    /// Each entry establishes a stable logical-to-physical method reference mapping.
    ///
    /// # Arguments
    /// * `context` - The loading context containing metadata tables and method collections
    ///
    /// # Returns
    /// * `Ok(())` - If all `MethodPtr` entries were processed successfully
    /// * `Err(_)` - If entry conversion or indirection mapping application fails
    fn load(&self, context: &LoaderContext) -> Result<()> {
        if let Some(header) = context.meta {
            if let Some(table) = header.table::<MethodPtrRaw>() {
                for row in table {
                    let owned = row.to_owned()?;
                    row.apply()?;

                    context.method_ptr.insert(row.token, owned);
                }
            }
        }
        Ok(())
    }

    /// Returns the table identifier for `MethodPtr`.
    ///
    /// # Returns
    /// The [`TableId::MethodPtr`] identifier for this table type.
    fn table_id(&self) -> TableId {
        TableId::MethodPtr
    }

    /// Returns the dependencies required for loading `MethodPtr` entries.
    ///
    /// `MethodPtr` table loading has no dependencies as it provides the indirection
    /// mechanism that other tables rely on. This table must be loaded before any
    /// tables that reference methods to ensure proper method token resolution.
    ///
    /// # Returns
    /// Empty array as `MethodPtr` has no table dependencies.
    fn dependencies(&self) -> &'static [TableId] {
        &[]
    }
}
