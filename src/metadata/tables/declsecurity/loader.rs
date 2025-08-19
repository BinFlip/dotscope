//! `DeclSecurity` table loader implementation.
//!
//! This module provides the [`crate::metadata::tables::declsecurity::loader::DeclSecurityLoader`]
//! implementation for loading declarative security metadata from the ECMA-335 `DeclSecurity` table (0x0E).
//! The loader processes security declarations that control code access security (CAS) permissions
//! at the assembly, type, and method levels, integrating this data with existing metadata entries.
//!
//! # Table Structure
//!
//! The `DeclSecurity` table contains security declarations with these fields:
//! - **Action**: Security action type (Demand, Assert, Deny, `InheritanceDemand`, etc.)
//! - **Parent**: Target element where security is applied (`HasDeclSecurity` coded index)
//! - **`PermissionSet`**: Serialized permission set data (blob heap reference)
//!
//! Each row represents a single security declaration that can specify required permissions,
//! permission assertions, denials, or inheritance demands for specific metadata elements.
//!
//! # Security Actions
//!
//! Common security actions include:
//! - **Demand**: Require callers to have specific permissions
//! - **Assert**: Temporarily escalate permissions for trusted code
//! - **Deny**: Prevent code from using certain permissions
//! - **`LinkDemand`**: Check permissions at JIT compile time
//! - **`InheritanceDemand`**: Require permissions for inheritance
//!
//! # Reference
//! - [ECMA-335 II.22.11](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `DeclSecurity` table specification
//! - [ECMA-335 II.23.1.16](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `SecurityAction` enumeration

use crate::{
    metadata::{
        loader::{LoaderContext, MetadataLoader},
        tables::DeclSecurityRaw,
    },
    prelude::TableId,
    Result,
};

/// Loader for the `DeclSecurity` metadata table
///
/// Implements [`crate::metadata::loader::MetadataLoader`] to process the `DeclSecurity` table (0x0E)
/// which contains declarative security declarations for assemblies, types, and methods. The loader
/// parses permission sets and applies them to their target metadata elements.
///
/// The `DeclSecurity` table depends on:
/// - **`TypeDef`**: For type-level security declarations
/// - **`MethodDef`**: For method-level security declarations  
/// - **Assembly**: For assembly-level security declarations
/// - **Blob Heap**: For permission set data resolution
///
/// # Errors
///
/// - `DeclSecurity` table row data is malformed or corrupted
/// - Coded index resolution fails for invalid parent references
/// - Permission set blob parsing encounters invalid or malformed data
/// - Security declaration application fails due to incompatible target types
/// - Thread synchronization issues occur during parallel processing
///
pub(crate) struct DeclSecurityLoader;

impl MetadataLoader for DeclSecurityLoader {
    /// Load declarative security metadata from the `DeclSecurity` table
    ///
    /// Processes all `DeclSecurity` table rows in parallel and stores resolved security declarations
    /// in the loader context. Each security declaration specifies permissions or constraints that
    /// apply to assemblies, types, or methods according to the .NET Code Access Security model.
    ///
    /// # Arguments
    /// * `context` - Loader context containing metadata tables, heaps, and resolved references
    ///
    /// # Returns
    /// * `Ok(())` - All security declarations successfully loaded or table not present
    /// * `Err(`[`crate::Error`]`)` - Malformed data, invalid references, or processing failures
    ///
    /// # Security Model Integration
    ///
    /// Security declarations are applied to their target elements, enabling:
    /// - Runtime permission checks for method calls
    /// - Assembly-level security policy enforcement  
    /// - Type inheritance security constraints
    /// - JIT-time security validation
    fn load(&self, context: &LoaderContext) -> Result<()> {
        if let (Some(header), Some(blob)) = (context.meta, context.blobs) {
            if let Some(table) = header.table::<DeclSecurityRaw>() {
                table.par_iter().try_for_each(|row| {
                    let owned = row.to_owned(|coded_index| context.get_ref(coded_index), blob)?;
                    owned.apply()?;

                    context.decl_security.insert(row.token, owned);
                    Ok(())
                })?;
            }
        }
        Ok(())
    }

    /// Returns the table identifier for the `DeclSecurity` table
    ///
    /// # Returns
    /// [`crate::metadata::tables::TableId::DeclSecurity`] (0x0E)
    fn table_id(&self) -> TableId {
        TableId::DeclSecurity
    }

    /// Returns the list of table dependencies required before loading `DeclSecurity`
    ///
    /// The `DeclSecurity` table depends on target metadata elements that can have security
    /// declarations applied to them. These dependencies ensure that parent references
    /// can be properly resolved during the loading process.
    ///
    /// # Returns
    /// Static slice containing:
    /// - [`TableId::TypeDef`] - For type-level security declarations
    /// - [`TableId::MethodDef`] - For method-level security declarations
    /// - [`TableId::Assembly`] - For assembly-level security declarations
    ///
    /// # Dependency Rationale
    ///
    /// Security declarations use the `HasDeclSecurity` coded index to reference their
    /// target elements. These target tables must be loaded first to ensure valid
    /// parent resolution during `DeclSecurity` processing.
    fn dependencies(&self) -> &'static [TableId] {
        &[TableId::TypeDef, TableId::MethodDef, TableId::Assembly]
    }
}
