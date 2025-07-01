//! Heap change tracking for metadata heaps.
//!
//! This module provides the [`crate::cilassembly::changes::heap::HeapChanges`] structure
//! for tracking additions to .NET metadata heaps during assembly modification operations.
//! It supports all standard .NET metadata heaps: #Strings, #Blob, #GUID, and #US (user strings).
//!
//! # Key Components
//!
//! - [`crate::cilassembly::changes::heap::HeapChanges`] - Generic heap change tracker with specialized implementations for different heap types
//!
//! # Architecture
//!
//! .NET metadata heaps are append-only during editing to maintain existing index references.
//! This module tracks only new additions, which are appended to the original heap during
//! binary generation. Each heap type has specialized sizing and indexing behavior:
//!
//! - **#Strings heap**: UTF-8 null-terminated strings
//! - **#Blob heap**: Length-prefixed binary data with compressed lengths
//! - **#GUID heap**: Raw 16-byte GUIDs
//! - **#US heap**: Length-prefixed UTF-16 strings with compressed lengths
//!
//! # Usage Examples
//!
//! ```rust,ignore
//! use crate::cilassembly::changes::heap::HeapChanges;
//!
//! // Track string heap additions
//! let mut string_changes = HeapChanges::<String>::new(100); // Original heap size
//! string_changes.appended_items.push("NewString".to_string());
//!
//! // Check modification status
//! if string_changes.has_additions() {
//!     let count = string_changes.additions_count();
//!     println!("Added {} strings", count);
//! }
//!
//! // Calculate binary size impact
//! let added_bytes = string_changes.binary_string_heap_size();
//! println!("Will add {} bytes to binary", added_bytes);
//! ```
//!
//! # Thread Safety
//!
//! This type is [`Send`] and [`Sync`] when `T` is [`Send`] and [`Sync`], as it only contains
//! owned data without interior mutability.

use std::collections::{HashMap, HashSet};

/// Reference handling strategy for heap item removal operations.
///
/// Defines how the system should handle existing references when a heap item
/// is removed or modified. This gives users control over the behavior when
/// dependencies exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReferenceHandlingStrategy {
    /// Fail the operation if any references exist to the item
    FailIfReferenced,
    /// Remove all references when deleting the item (cascade deletion)
    RemoveReferences,
    /// Replace references with a default/null value (typically index 0)
    NullifyReferences,
}

/// Tracks changes to metadata heaps (strings, blobs, GUIDs, user strings).
///
/// This structure tracks additions, modifications, and removals to .NET metadata heaps.
/// While heaps were traditionally append-only, this extended version supports
/// user-requested modifications and removals with configurable reference handling.
/// [`crate::cilassembly::changes::assembly::AssemblyChanges`] to provide comprehensive
/// modification tracking.
///
/// # Type Parameters
///
/// * `T` - The type of items stored in this heap:
///   - [`String`] for #Strings and #US heaps
///   - [`Vec<u8>`] for #Blob heap  
///   - `[u8; 16]` for #GUID heap
///
/// # Index Management
///
/// Heap indices are byte offsets following .NET runtime conventions:
/// - Index 0 is reserved (points to empty string for #Strings, empty blob for #Blob)
/// - `next_index` starts from `original_heap_byte_size` (where new data begins)
/// - Each addition increments `next_index` by the actual byte size of the added data
///
/// # Usage Examples
///
/// ```rust,ignore
/// use crate::cilassembly::changes::heap::HeapChanges;
///
/// // Create heap tracker for strings
/// let mut changes = HeapChanges::<String>::new(256);
/// changes.appended_items.push("MyString".to_string());
///
/// // Get proper byte indices for added items
/// for (index, string) in changes.string_items_with_indices() {
///     println!("String '{}' at index {}", string, index);
/// }
/// ```
///
/// # Thread Safety
///
/// This type is [`Send`] and [`Sync`] when `T` is [`Send`] and [`Sync`].
#[derive(Debug, Clone)]
pub struct HeapChanges<T> {
    /// Items appended to the heap
    ///
    /// These items will be serialized after the original heap content
    /// during binary generation. The order is preserved to maintain
    /// index assignments.
    pub appended_items: Vec<T>,

    /// Items modified in the original heap
    ///
    /// Maps heap index to new value. These modifications override the
    /// original heap content at the specified indices during binary generation.
    pub modified_items: HashMap<u32, T>,

    /// Indices of items removed from the original heap
    ///
    /// Items at these indices will be skipped during binary generation.
    /// The reference handling strategy determines how existing references
    /// to these indices are managed.
    pub removed_indices: HashSet<u32>,

    /// Reference handling strategy for each removed index
    ///
    /// Maps removed heap index to the strategy that should be used when
    /// handling references to that index. This allows per-removal control
    /// over how dependencies are managed.
    pub removal_strategies: HashMap<u32, ReferenceHandlingStrategy>,

    /// Next byte offset to assign (continues from original heap byte size)
    ///
    /// This offset is incremented by the actual byte size of each new item added
    /// to ensure proper heap indexing following .NET runtime conventions.
    pub next_index: u32,
}

impl<T> HeapChanges<T> {
    /// Creates a new heap changes tracker.
    ///
    /// Initializes a new [`crate::cilassembly::changes::heap::HeapChanges`] instance
    /// with the specified original heap size. This size determines where new
    /// additions will begin in the heap index space.
    ///
    /// # Arguments
    ///
    /// * `original_byte_size` - The byte size of the original heap.
    ///   The next index will be `original_byte_size` (where new data starts).
    ///
    /// # Returns
    ///
    /// A new [`crate::cilassembly::changes::heap::HeapChanges`] instance ready for tracking additions.
    pub fn new(original_byte_size: u32) -> Self {
        Self {
            appended_items: Vec::new(),
            modified_items: HashMap::new(),
            removed_indices: HashSet::new(),
            removal_strategies: HashMap::new(),
            next_index: original_byte_size,
        }
    }

    /// Returns the number of items that have been added to this heap.
    pub fn additions_count(&self) -> usize {
        self.appended_items.len()
    }

    /// Returns true if any items have been added to this heap.
    pub fn has_additions(&self) -> bool {
        !self.appended_items.is_empty()
    }

    /// Returns the number of items that have been modified in this heap.
    pub fn modifications_count(&self) -> usize {
        self.modified_items.len()
    }

    /// Returns true if any items have been modified in this heap.
    pub fn has_modifications(&self) -> bool {
        !self.modified_items.is_empty()
    }

    /// Returns the number of items that have been removed from this heap.
    pub fn removals_count(&self) -> usize {
        self.removed_indices.len()
    }

    /// Returns true if any items have been removed from this heap.
    pub fn has_removals(&self) -> bool {
        !self.removed_indices.is_empty()
    }

    /// Returns true if any changes (additions, modifications, or removals) have been made.
    pub fn has_changes(&self) -> bool {
        self.has_additions() || self.has_modifications() || self.has_removals()
    }

    /// Adds a modification to the heap at the specified index.
    ///
    /// # Arguments
    ///
    /// * `index` - The heap index to modify
    /// * `new_value` - The new value to store at that index
    pub fn add_modification(&mut self, index: u32, new_value: T) {
        self.modified_items.insert(index, new_value);
    }

    /// Adds a removal to the heap at the specified index.
    ///
    /// # Arguments
    ///
    /// * `index` - The heap index to remove
    /// * `strategy` - The reference handling strategy for this removal
    pub fn add_removal(&mut self, index: u32, strategy: ReferenceHandlingStrategy) {
        self.removed_indices.insert(index);
        self.removal_strategies.insert(index, strategy);
    }

    /// Marks an appended item for removal by not including it in the final write.
    /// This is used when removing a newly added string before it's written to disk.
    pub fn mark_appended_for_removal(&mut self, index: u32) {
        self.removed_indices.insert(index);
    }

    /// Gets the modification at the specified index, if any.
    pub fn get_modification(&self, index: u32) -> Option<&T> {
        self.modified_items.get(&index)
    }

    /// Returns true if the specified index has been removed.
    pub fn is_removed(&self, index: u32) -> bool {
        self.removed_indices.contains(&index)
    }

    /// Gets the removal strategy for the specified index, if it's been removed.
    pub fn get_removal_strategy(&self, index: u32) -> Option<ReferenceHandlingStrategy> {
        self.removal_strategies.get(&index).copied()
    }

    /// Returns an iterator over all modified items and their indices.
    pub fn modified_items_iter(&self) -> impl Iterator<Item = (&u32, &T)> {
        self.modified_items.iter()
    }

    /// Returns an iterator over all removed indices.
    pub fn removed_indices_iter(&self) -> impl Iterator<Item = &u32> {
        self.removed_indices.iter()
    }

    /// Returns the index that would be assigned to the next added item.
    pub fn next_index(&self) -> u32 {
        self.next_index
    }

    /// Returns an iterator over all added items with their assigned indices.
    ///
    /// Note: This default implementation assumes each item takes exactly 1 byte,
    /// which is incorrect for heaps with variable-sized entries. Use the specialized
    /// implementations for string and blob heaps that calculate proper byte positions.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let changes = HeapChanges::new(100);
    /// // ... add some items ...
    ///
    /// for (index, item) in changes.items_with_indices() {
    ///     println!("Item at index {}: {:?}", index, item);
    /// }
    /// ```
    pub fn items_with_indices(&self) -> impl Iterator<Item = (u32, &T)> {
        let start_index = self.next_index - self.appended_items.len() as u32;
        self.appended_items
            .iter()
            .enumerate()
            .map(move |(i, item)| (start_index + i as u32, item))
    }

    /// Calculates the size these changes will add to the binary heap.
    ///
    /// This method calculates the actual bytes that would be added to the heap
    /// when writing the binary. The default implementation assumes each item contributes its
    /// size_of value, but specialized implementations should override this for accurate sizing.
    pub fn binary_heap_size(&self) -> usize
    where
        T: Sized,
    {
        self.appended_items.len() * std::mem::size_of::<T>()
    }
}

/// Specialized implementation for string heap changes.
impl HeapChanges<String> {
    /// Calculates the size these string additions will add to the binary #Strings heap.
    ///
    /// The #Strings heap stores UTF-8 encoded null-terminated strings with no length prefixes.
    /// Each string contributes: UTF-8 byte length + 1 null terminator
    pub fn binary_string_heap_size(&self) -> usize {
        self.appended_items
            .iter()
            .map(|s| s.len() + 1) // UTF-8 bytes + null terminator
            .sum()
    }

    /// Returns the total character count of all added strings.
    pub fn total_character_count(&self) -> usize {
        self.appended_items.iter().map(|s| s.len()).sum()
    }

    /// Returns an iterator over all added strings with their correct byte indices.
    ///
    /// This properly calculates byte positions for string heap entries by tracking
    /// the cumulative size of each string including null terminators.
    pub fn string_items_with_indices(&self) -> impl Iterator<Item = (u32, &String)> {
        let mut current_index = self.next_index;
        // Calculate total size of all items to find the starting index
        let total_size: u32 = self
            .appended_items
            .iter()
            .map(|s| (s.len() + 1) as u32) // UTF-8 bytes + null terminator
            .sum();
        current_index -= total_size;

        self.appended_items
            .iter()
            .scan(current_index, |index, item| {
                let current = *index;
                *index += (item.len() + 1) as u32; // UTF-8 bytes + null terminator
                Some((current, item))
            })
    }

    /// Returns an iterator over all added user strings with their correct byte indices.
    ///
    /// This properly calculates byte positions for user string heap entries by tracking
    /// the cumulative size of each string including length prefix, UTF-16 data, null terminator, and terminal byte.
    pub fn userstring_items_with_indices(&self) -> impl Iterator<Item = (u32, &String)> {
        let mut current_index = self.next_index;
        // Calculate total size of all items to find the starting index
        let total_size: u32 = self
            .appended_items
            .iter()
            .map(|s| {
                // UTF-16 encoding: each character can be 2 or 4 bytes
                let utf16_bytes: usize = s.encode_utf16().map(|_| 2).sum(); // Simplified: assume BMP only

                // Total length includes UTF-16 data + terminal byte (1 byte)
                let total_length = utf16_bytes + 1;

                let compressed_length_size = if total_length < 0x80 {
                    1 // Single byte for lengths < 128
                } else if total_length < 0x4000 {
                    2 // Two bytes for lengths < 16384
                } else {
                    4 // Four bytes for larger lengths
                };

                (compressed_length_size + total_length) as u32
            })
            .sum();
        current_index -= total_size;

        self.appended_items
            .iter()
            .scan(current_index, |index, item| {
                let current = *index;
                // Calculate the size of this userstring entry
                let utf16_bytes: usize = item.encode_utf16().map(|_| 2).sum();
                let total_length = utf16_bytes + 1;
                let compressed_length_size = if total_length < 0x80 {
                    1
                } else if total_length < 0x4000 {
                    2
                } else {
                    4
                };
                *index += (compressed_length_size + total_length) as u32;
                Some((current, item))
            })
    }

    /// Calculates the size these userstring additions will add to the binary #US heap.
    ///
    /// The #US heap stores UTF-16 encoded strings with compressed length prefixes (ECMA-335 II.24.2.4).
    /// Each string contributes: compressed_length_size + UTF-16_byte_length + terminal_byte(1)
    pub fn binary_userstring_heap_size(&self) -> usize {
        self.appended_items
            .iter()
            .map(|s| {
                // UTF-16 encoding: each character can be 2 or 4 bytes
                let utf16_bytes: usize = s.encode_utf16().map(|_| 2).sum(); // Simplified: assume BMP only

                // Total length includes UTF-16 data + terminal byte (1 byte)
                let total_length = utf16_bytes + 1;

                let compressed_length_size = if total_length < 0x80 {
                    1 // Single byte for lengths < 128
                } else if total_length < 0x4000 {
                    2 // Two bytes for lengths < 16384
                } else {
                    4 // Four bytes for larger lengths
                };

                compressed_length_size + total_length
            })
            .sum()
    }
}

/// Specialized implementation for blob heap changes.
impl HeapChanges<Vec<u8>> {
    /// Calculates the size these blob additions will add to the binary #Blob heap.
    ///
    /// The #Blob heap stores length-prefixed binary data using compressed integer lengths.
    /// Each blob contributes: compressed_length_size + blob_data_length
    pub fn binary_blob_heap_size(&self) -> usize {
        self.appended_items
            .iter()
            .map(|blob| {
                let length = blob.len();
                let compressed_length_size = if length < 0x80 {
                    1 // Single byte for lengths < 128
                } else if length < 0x4000 {
                    2 // Two bytes for lengths < 16384
                } else {
                    4 // Four bytes for larger lengths
                };
                compressed_length_size + length
            })
            .sum()
    }

    /// Returns the total byte count of all added blobs.
    pub fn total_byte_count(&self) -> usize {
        self.appended_items.iter().map(|b| b.len()).sum()
    }
}

/// Specialized implementation for GUID heap changes.
impl HeapChanges<[u8; 16]> {
    /// Calculates the size these GUID additions will add to the binary #GUID heap.
    ///
    /// The #GUID heap stores raw 16-byte GUIDs with no length prefixes or terminators.
    /// Each GUID contributes exactly 16 bytes.
    pub fn binary_guid_heap_size(&self) -> usize {
        self.appended_items.len() * 16
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_heap_changes_indexing() {
        let mut changes = HeapChanges::new(100);
        assert_eq!(changes.next_index(), 100);
        assert!(!changes.has_additions());
        assert!(!changes.has_changes());

        changes.appended_items.push("test".to_string());
        changes.next_index += 5; // "test" + null terminator = 5 bytes

        assert!(changes.has_additions());
        assert!(changes.has_changes());
        assert_eq!(changes.additions_count(), 1);
        assert_eq!(changes.next_index(), 105);
    }

    #[test]
    fn test_heap_changes_modifications() {
        let mut changes = HeapChanges::<String>::new(100);
        assert!(!changes.has_modifications());
        assert!(!changes.has_changes());

        changes.add_modification(50, "modified".to_string());

        assert!(changes.has_modifications());
        assert!(changes.has_changes());
        assert_eq!(changes.modifications_count(), 1);
        assert_eq!(changes.get_modification(50), Some(&"modified".to_string()));
        assert_eq!(changes.get_modification(99), None);
    }

    #[test]
    fn test_heap_changes_removals() {
        let mut changes = HeapChanges::<String>::new(100);
        assert!(!changes.has_removals());
        assert!(!changes.has_changes());

        changes.add_removal(25, ReferenceHandlingStrategy::FailIfReferenced);

        assert!(changes.has_removals());
        assert!(changes.has_changes());
        assert_eq!(changes.removals_count(), 1);
        assert!(changes.is_removed(25));
        assert!(!changes.is_removed(30));
        assert_eq!(
            changes.get_removal_strategy(25),
            Some(ReferenceHandlingStrategy::FailIfReferenced)
        );
        assert_eq!(changes.get_removal_strategy(30), None);
    }

    #[test]
    fn test_heap_changes_items_with_indices() {
        let mut changes = HeapChanges::new(50);
        changes.appended_items.push("first".to_string());
        changes.appended_items.push("second".to_string());
        changes.next_index = 63; // Simulating 2 additions: 50 + 6 ("first" + null) + 7 ("second" + null)

        let items: Vec<_> = changes.string_items_with_indices().collect();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0], (50, &"first".to_string())); // Starts at original byte size
        assert_eq!(items[1], (56, &"second".to_string())); // 50 + 6 bytes for "first\0"
    }
}
