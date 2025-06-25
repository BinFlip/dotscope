//! Core assembly change tracking structure.
//!
//! This module provides the [`crate::cilassembly::changes::assembly::AssemblyChanges`] structure
//! for tracking all modifications made to a .NET assembly during the modification process.
//! It implements sparse change tracking to minimize memory overhead and enable efficient
//! merging operations during assembly output.
//!
//! # Key Components
//!
//! - [`crate::cilassembly::changes::assembly::AssemblyChanges`] - Core change tracking structure for assembly modifications
//!
//! # Architecture
//!
//! The change tracking system uses sparse storage principles - only modified elements
//! are tracked rather than copying entire tables. This enables efficient memory usage
//! for assemblies where only small portions are modified.
//!
//! Key design principles:
//! - **Sparse Storage**: Only modified elements are tracked, not entire tables
//! - **Lazy Allocation**: Change categories are only created when first used
//! - **Efficient Merging**: Changes can be efficiently merged during read operations
//! - **Memory Efficient**: Minimal overhead for read-heavy operations
//!
//! # Usage Examples
//!
//! ```rust,ignore
//! use crate::cilassembly::changes::assembly::AssemblyChanges;
//! use crate::metadata::cilassemblyview::CilAssemblyView;
//! use std::path::Path;
//!
//! # let view = CilAssemblyView::from_file(Path::new("test.dll"))?;
//! let mut changes = AssemblyChanges::new(&view);
//!
//! // Check if any changes have been made
//! if changes.has_changes() {
//!     println!("Assembly has been modified");
//! }
//!
//! // Get modification statistics
//! let table_count = changes.modified_table_count();
//! let string_count = changes.string_additions_count();
//! # Ok::<(), crate::Error>(())
//! ```

use std::collections::HashMap;

use crate::{
    cilassembly::{HeapChanges, TableModifications},
    metadata::{cilassemblyview::CilAssemblyView, tables::TableId},
};

/// Internal structure for tracking all modifications to an assembly.
///
/// This structure uses lazy initialization - it's only created when the first
/// modification is made, and individual change categories are only allocated
/// when first accessed. It works closely with [`crate::cilassembly::CilAssembly`]
/// to provide efficient change tracking during assembly modification operations.
///
/// # Design Principles
///
/// - **Sparse Storage**: Only modified elements are tracked, not entire tables
/// - **Lazy Allocation**: Change categories are only created when first used
/// - **Efficient Merging**: Changes can be efficiently merged during read operations
/// - **Memory Efficient**: Minimal overhead for read-heavy operations
///
/// # Usage Examples
///
/// ```rust,ignore
/// use crate::cilassembly::changes::assembly::AssemblyChanges;
/// use crate::metadata::cilassemblyview::CilAssemblyView;
/// use std::path::Path;
///
/// # let view = CilAssemblyView::from_file(Path::new("test.dll"))?;
/// let changes = AssemblyChanges::new(&view);
///
/// // Check modification status
/// if changes.has_changes() {
///     let table_count = changes.modified_table_count();
///     println!("Modified {} tables", table_count);
/// }
/// # Ok::<(), crate::Error>(())
/// ```
///
/// # Thread Safety
///
/// This type is not [`Send`] or [`Sync`] because it contains mutable state
/// that is not protected by synchronization primitives.
#[derive(Debug, Clone)]
pub struct AssemblyChanges {
    /// Table-level modifications, keyed by table ID
    ///
    /// Each table can have sparse modifications (individual row changes) or
    /// complete replacement. This map only contains entries for tables that
    /// have been modified.
    pub table_changes: HashMap<TableId, TableModifications>,

    /// String heap additions
    ///
    /// Tracks strings that have been added to the #Strings heap. New strings
    /// are appended to preserve existing heap structure.
    pub string_heap_changes: HeapChanges<String>,

    /// Blob heap additions  
    ///
    /// Tracks blobs that have been added to the #Blob heap. New blobs
    /// are appended to preserve existing heap structure.
    pub blob_heap_changes: HeapChanges<Vec<u8>>,

    /// GUID heap additions
    ///
    /// Tracks GUIDs that have been added to the #GUID heap. New GUIDs
    /// are appended to preserve existing heap structure.
    pub guid_heap_changes: HeapChanges<[u8; 16]>,

    /// User string heap additions
    ///
    /// Tracks user strings that have been added to the #US heap. User strings
    /// are typically Unicode string literals used by IL instructions.
    pub userstring_heap_changes: HeapChanges<String>,
}

impl AssemblyChanges {
    /// Creates a new change tracking structure initialized with proper heap sizes from the view.
    ///
    /// All heap changes are initialized with the proper original heap byte sizes
    /// from the view to ensure correct index calculations.
    /// Table changes remain an empty HashMap and are allocated on first use.
    pub fn new(view: &CilAssemblyView) -> Self {
        let string_heap_size = Self::get_heap_byte_size(view, "#Strings");
        let blob_heap_size = Self::get_heap_byte_size(view, "#Blob");
        let guid_heap_size = Self::get_heap_byte_size(view, "#GUID");
        let userstring_heap_size = Self::get_heap_byte_size(view, "#US");

        Self {
            table_changes: HashMap::new(),
            string_heap_changes: HeapChanges::new(string_heap_size),
            blob_heap_changes: HeapChanges::new(blob_heap_size),
            guid_heap_changes: HeapChanges::new(guid_heap_size),
            userstring_heap_changes: HeapChanges::new(userstring_heap_size),
        }
    }

    /// Creates an empty change tracking structure for testing purposes.
    ///
    /// All heap changes start with default sizes (1) for proper indexing.
    pub fn empty() -> Self {
        Self {
            table_changes: HashMap::new(),
            string_heap_changes: HeapChanges::new(1),
            blob_heap_changes: HeapChanges::new(1),
            guid_heap_changes: HeapChanges::new(1),
            userstring_heap_changes: HeapChanges::new(1),
        }
    }

    /// Helper method to get the byte size of a heap by stream name.
    fn get_heap_byte_size(view: &CilAssemblyView, stream_name: &str) -> u32 {
        view.streams()
            .iter()
            .find(|stream| stream.name == stream_name)
            .map(|stream| stream.size)
            .unwrap_or(1)
    }

    /// Returns true if any changes have been made to the assembly.
    ///
    /// This checks if any table changes exist or if any heap has additions.
    pub fn has_changes(&self) -> bool {
        !self.table_changes.is_empty()
            || self.string_heap_changes.has_additions()
            || self.blob_heap_changes.has_additions()
            || self.guid_heap_changes.has_additions()
            || self.userstring_heap_changes.has_additions()
    }

    /// Returns the number of tables that have been modified.
    pub fn modified_table_count(&self) -> usize {
        self.table_changes.len()
    }

    /// Returns the total number of string heap additions.
    pub fn string_additions_count(&self) -> usize {
        self.string_heap_changes.appended_items.len()
    }

    /// Returns the total number of blob heap additions.
    pub fn blob_additions_count(&self) -> usize {
        self.blob_heap_changes.appended_items.len()
    }

    /// Returns an iterator over all modified table IDs.
    pub fn modified_tables(&self) -> impl Iterator<Item = TableId> + '_ {
        self.table_changes.keys().copied()
    }

    /// Gets the table modifications for a specific table, if any.
    ///
    /// # Arguments
    ///
    /// * `table_id` - The [`crate::metadata::tables::TableId`] to query for modifications
    ///
    /// # Returns
    ///
    /// An optional reference to [`crate::cilassembly::TableModifications`] if the table has been modified.
    pub fn get_table_modifications(&self, table_id: TableId) -> Option<&TableModifications> {
        self.table_changes.get(&table_id)
    }

    /// Gets mutable table modifications for a specific table, if any.
    ///
    /// # Arguments
    ///
    /// * `table_id` - The [`crate::metadata::tables::TableId`] to query for modifications
    ///
    /// # Returns
    ///
    /// An optional mutable reference to [`crate::cilassembly::TableModifications`] if the table has been modified.
    pub fn get_table_modifications_mut(
        &mut self,
        table_id: TableId,
    ) -> Option<&mut TableModifications> {
        self.table_changes.get_mut(&table_id)
    }

    /// Calculates the binary heap sizes that will be added during writing.
    ///
    /// Returns a tuple of (strings_size, blob_size, guid_size, userstring_size)
    /// representing the bytes that will be added to each heap in the final binary.
    /// This is used for binary generation and PE file size calculation.
    pub fn binary_heap_sizes(&self) -> (usize, usize, usize, usize) {
        let string_size = self.string_heap_changes.binary_string_heap_size();
        let blob_size = self.blob_heap_changes.binary_blob_heap_size();
        let guid_size = self.guid_heap_changes.binary_guid_heap_size();
        let userstring_size = self.userstring_heap_changes.binary_userstring_heap_size();

        (string_size, blob_size, guid_size, userstring_size)
    }
}

impl Default for AssemblyChanges {
    fn default() -> Self {
        AssemblyChanges::empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cilassembly::HeapChanges;

    #[test]
    fn test_assembly_changes_empty() {
        let changes = AssemblyChanges::empty();
        assert!(!changes.has_changes());
        assert_eq!(changes.modified_table_count(), 0);
        assert_eq!(changes.string_additions_count(), 0);
    }

    #[test]
    fn test_binary_heap_sizes() {
        let mut changes = AssemblyChanges::empty();

        // Test empty state
        let (string_size, blob_size, guid_size, userstring_size) = changes.binary_heap_sizes();
        assert_eq!(string_size, 0);
        assert_eq!(blob_size, 0);
        assert_eq!(guid_size, 0);
        assert_eq!(userstring_size, 0);

        // Add some string heap changes
        let mut string_changes = HeapChanges::new(100);
        string_changes.appended_items.push("Hello".to_string()); // 5 + 1 = 6 bytes
        string_changes.appended_items.push("World".to_string()); // 5 + 1 = 6 bytes
        changes.string_heap_changes = string_changes;

        // Add some blob heap changes
        let mut blob_changes = HeapChanges::new(50);
        blob_changes.appended_items.push(vec![1, 2, 3]); // 1 + 3 = 4 bytes (length < 128)
        blob_changes.appended_items.push(vec![4, 5, 6, 7, 8]); // 1 + 5 = 6 bytes
        changes.blob_heap_changes = blob_changes;

        // Add some GUID heap changes
        let mut guid_changes = HeapChanges::new(1);
        guid_changes.appended_items.push([1; 16]); // 16 bytes
        guid_changes.appended_items.push([2; 16]); // 16 bytes
        changes.guid_heap_changes = guid_changes;

        let (string_size, blob_size, guid_size, userstring_size) = changes.binary_heap_sizes();
        assert_eq!(string_size, 12); // "Hello\0" + "World\0" = 6 + 6
        assert_eq!(blob_size, 10); // (1+3) + (1+5) = 4 + 6
        assert_eq!(guid_size, 32); // 16 + 16
        assert_eq!(userstring_size, 0); // No userstring changes
    }
}
