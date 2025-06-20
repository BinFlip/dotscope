//! Safe table access trait for type-safe metadata table retrieval.
//!
//! This module defines the `TableAccess` trait which provides a safe, ergonomic
//! way to access metadata tables without requiring both type parameters and table IDs.
//! This eliminates the need for unsafe code in table access while maintaining
//! type safety and performance.

use crate::metadata::tables::{MetadataTable, RowReadable};

/// Trait for safe, type-safe access to metadata tables.
///
/// This trait provides a clean interface for accessing metadata tables using only
/// the row type, automatically mapping to the correct table type. This eliminates
/// the unsafe code previously required and provides a more ergonomic API.
///
/// # Usage
///
/// ```rust
/// use dotscope::metadata::{streams::TablesHeader, tables::TypeDefRaw};
///
/// # fn example(tables: &TablesHeader) -> dotscope::Result<()> {
/// // Type-safe access - no table ID needed
/// if let Some(typedef_table) = tables.table::<TypeDefRaw>() {
///     // Work with the table safely
///     for type_def in typedef_table.iter().take(5) {
///         println!("Type: {}", type_def.type_name);
///     }
/// }
/// # Ok(())
/// # }
/// ```
pub trait TableAccess<'a, T: RowReadable> {
    /// Retrieve a table of the specified type if present.
    ///
    /// # Returns
    /// * `Some(&MetadataTable<T>)` - Reference to the table if present
    /// * `None` - If the table is not present in this assembly
    fn table(&'a self) -> Option<&'a MetadataTable<'a, T>>;
}

/// Generate TableAccess trait implementations for metadata tables.
///
/// This macro creates type-safe implementations of the TableAccess trait,
/// mapping each row type to its corresponding TableData variant and TableId.
/// This eliminates the need for unsafe code while maintaining performance.
///
/// # Arguments
/// * `$raw` - The raw row type (e.g., TypeDefRaw)
/// * `$id` - The TableId variant (e.g., TableId::TypeDef)
/// * `$variant` - The TableData variant (e.g., TypeDef)
///
/// # Example
/// ```rust,ignore
/// impl_table_access!(TypeDefRaw, TableId::TypeDef, TypeDef);
/// impl_table_access!(MethodDefRaw, TableId::MethodDef, MethodDef);
/// ```
#[macro_export]
macro_rules! impl_table_access {
    ($raw:ty, $id:expr, $variant:ident) => {
        impl<'a> TableAccess<'a, $raw> for TablesHeader<'a> {
            fn table(&'a self) -> Option<&'a MetadataTable<'a, $raw>> {
                match self.tables.get($id as usize)? {
                    Some(TableData::$variant(table)) => Some(table),
                    _ => None,
                }
            }
        }
    };
}
