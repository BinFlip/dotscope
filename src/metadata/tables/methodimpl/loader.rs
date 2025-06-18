//! MethodImpl table loader implementation.
//!
//! This module provides the [`MethodImplLoader`] responsible for loading and processing
//! MethodImpl metadata table entries. The MethodImpl table defines method implementation
//! mappings that specify which concrete method implementation provides the behavior
//! for a given method declaration, essential for interface implementation and method
//! overriding in .NET type systems.
//!
//! # Purpose
//! The MethodImpl table is crucial for object-oriented programming and interface contracts:
//! - **Interface implementation**: Maps interface method declarations to concrete implementations
//! - **Method overriding**: Specifies which method implementations override base class methods
//! - **Explicit implementation**: Handles explicit interface member implementation scenarios
//! - **Virtual dispatch**: Establishes method resolution for polymorphic method calls
//! - **Generic method mapping**: Links generic method declarations to specialized implementations
//!
//! # Implementation Mapping Types
//! MethodImpl entries support different kinds of method implementation scenarios:
//! - **Interface implementations**: Concrete class methods implementing interface contracts
//! - **Virtual method overrides**: Derived class methods overriding base class virtual methods
//! - **Explicit implementations**: Methods explicitly implementing specific interface members
//! - **Generic specializations**: Specialized implementations for generic method instantiations
//! - **P/Invoke mappings**: Native method implementations for managed method declarations
//!
//! # Table Dependencies
//! - **TypeDef**: Required for resolving class types that contain implementation mappings
//! - **TypeRef**: Required for resolving external class types in inheritance scenarios
//! - **MethodDef**: Required for resolving concrete method implementations and declarations
//! - **MemberRef**: Required for resolving external method references in implementation mappings
//!
//! # ECMA-335 Reference
//! See ECMA-335, Partition II, §22.27 for the MethodImpl table specification.
use crate::{
    metadata::{
        loader::{LoaderContext, MetadataLoader},
        tables::MethodImplRaw,
    },
    prelude::TableId,
    Result,
};

/// Loader implementation for the MethodImpl metadata table.
///
/// This loader processes method implementation mapping metadata, establishing connections
/// between method declarations and their concrete implementations. It handles interface
/// implementation mappings, method overriding relationships, and virtual dispatch
/// resolution for object-oriented programming support.
pub(crate) struct MethodImplLoader;

impl MetadataLoader for MethodImplLoader {
    /// Loads MethodImpl table entries and establishes method implementation mappings.
    ///
    /// This method iterates through all MethodImpl table entries, resolving class and method
    /// references to create concrete implementation mappings. Each entry is converted to an
    /// owned structure and applied to the type system for method resolution support.
    ///
    /// # Arguments
    /// * `context` - The loading context containing metadata tables and type resolution
    ///
    /// # Returns
    /// * `Ok(())` - If all MethodImpl entries were processed successfully
    /// * `Err(_)` - If class resolution, method resolution, or mapping application fails
    fn load(&self, context: &LoaderContext) -> Result<()> {
        if let Some(header) = context.meta {
            if let Some(table) = header.table::<MethodImplRaw>(TableId::MethodImpl) {
                table.par_iter().try_for_each(|row| {
                    let owned =
                        row.to_owned(|coded_index| context.get_ref(coded_index), context.types)?;
                    owned.apply()?;

                    context.method_impl.insert(row.token, owned);
                    Ok(())
                })?;
            }
        }
        Ok(())
    }

    /// Returns the table identifier for MethodImpl.
    ///
    /// # Returns
    /// The [`TableId::MethodImpl`] identifier for this table type.
    fn table_id(&self) -> TableId {
        TableId::MethodImpl
    }

    /// Returns the dependencies required for loading MethodImpl entries.
    ///
    /// MethodImpl table loading requires other tables to resolve implementation mappings:
    /// - [`TableId::TypeDef`] - For resolving class types containing implementation mappings
    /// - [`TableId::TypeRef`] - For resolving external class types in inheritance scenarios
    /// - [`TableId::MethodDef`] - For resolving concrete method implementations and declarations
    /// - [`TableId::MemberRef`] - For resolving external method references in mappings
    ///
    /// # Returns
    /// Array of table identifiers that must be loaded before `MethodImpl` processing.
    fn dependencies(&self) -> &'static [TableId] {
        &[
            TableId::TypeDef,
            TableId::TypeRef,
            TableId::MethodDef,
            TableId::MemberRef,
        ]
    }
}
