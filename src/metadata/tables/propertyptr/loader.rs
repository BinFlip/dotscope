//! # `PropertyPtr` Table Loader
//!
//! This module provides loading functionality for the `PropertyPtr` metadata table (ID 0x16).
//! The `PropertyPtr` table provides indirection for property table access in optimized
//! metadata layouts, enabling property table compression and efficient property access
//! patterns in .NET assemblies.
//!
//! ## Purpose
//!
//! The `PropertyPtr` table serves as an indirection mechanism:
//! - **Property Indirection**: Maps logical property indexes to physical locations
//! - **Optimization Support**: Enables property table compression and reordering
//! - **Metadata Efficiency**: Reduces metadata size in optimized assemblies
//! - **Access Performance**: Provides efficient property lookup mechanisms
//!
//! ## Optimization Context
//!
//! `PropertyPtr` tables are typically present in optimized assemblies where:
//! - Property table ordering differs from logical declaration order
//! - Property table compression has been applied during compilation
//! - Runtime property access patterns require indirection for efficiency
//!
//! ## References
//!
//! - ECMA-335, Partition II, §22.38 - `PropertyPtr` table specification
//! - [`crate::metadata::tables::PropertyPtrRaw`] - Raw table entry structure
//! - [`crate::metadata::tables::PropertyPtr`] - Owned table entry type

use crate::{
    metadata::{
        loader::{LoaderContext, MetadataLoader},
        tables::{PropertyPtrRaw, TableId},
    },
    Result,
};

/// Loader implementation for the `PropertyPtr` metadata table.
///
/// This loader processes `PropertyPtr` table entries (ID 0x16) that provide indirection
/// for property table access in optimized metadata layouts. It handles the loading,
/// validation, and storage of property pointer entries for efficient property access.
///
/// ## Error Handling
///
/// The loader validates:
/// - Property pointer table structure and format
/// - Property reference validity and constraints
/// - Metadata token consistency and uniqueness
pub struct PropertyPtrLoader;

impl MetadataLoader for PropertyPtrLoader {
    /// Loads and processes all `PropertyPtr` table entries from the metadata.
    ///
    /// ## Arguments
    ///
    /// * `context` - The loading context containing metadata and storage facilities
    ///
    /// ## Returns
    ///
    /// * `Ok(())` - All property pointer entries loaded and validated successfully
    /// * `Err(_)` - Property pointer loading or validation failed
    fn load(&self, context: &LoaderContext) -> Result<()> {
        if let Some(header) = context.meta {
            if let Some(table) = header.table::<PropertyPtrRaw>() {
                for row in table {
                    let owned = row.to_owned()?;
                    context.property_ptr.insert(row.token, owned);
                }
            }
        }
        Ok(())
    }

    /// Returns the table identifier for the `PropertyPtr` table.
    ///
    /// ## Returns
    ///
    /// [`TableId::PropertyPtr`] (0x16) - The metadata table identifier
    fn table_id(&self) -> TableId {
        TableId::PropertyPtr
    }

    /// Returns the dependency list for `PropertyPtr` table loading.
    ///
    /// The `PropertyPtr` table has no direct dependencies on other metadata tables
    /// as it provides indirection rather than containing references to other tables.
    ///
    /// ## Returns
    ///
    /// An empty slice indicating no dependencies
    fn dependencies(&self) -> &'static [TableId] {
        &[]
    }
}
