//! Heap change tracking for metadata heaps.

/// Tracks additions to metadata heaps (strings, blobs, GUIDs, user strings).
///
/// Heaps in .NET metadata are append-only during editing to maintain existing
/// index references. This structure tracks only new additions, which are
/// appended to the original heap during binary generation.
///
/// # Type Parameters
///
/// * `T` - The type of items stored in this heap:
///   - `String` for #Strings and #US heaps
///   - `Vec<u8>` for #Blob heap  
///   - `[u8; 16]` for #GUID heap
///
/// # Index Management
///
/// Heap indices are 1-based following ECMA-335 conventions:
/// - Index 0 is reserved (empty string for #Strings, empty blob for #Blob)
/// - `next_index` starts from `original_heap_size + 1`
/// - Each addition increments `next_index` for the next item
#[derive(Debug, Clone)]
pub struct HeapChanges<T> {
    /// Items appended to the heap
    ///
    /// These items will be serialized after the original heap content
    /// during binary generation. The order is preserved to maintain
    /// index assignments.
    pub appended_items: Vec<T>,

    /// Next index to assign (continues from original heap size)
    ///
    /// This index is incremented for each new item added to ensure
    /// unique, sequential indices for all heap additions.
    pub next_index: u32,
}

impl<T> HeapChanges<T> {
    /// Creates a new heap changes tracker.
    ///
    /// # Arguments
    ///
    /// * `original_size` - The number of items in the original heap.
    ///   The next index will be `original_size + 1`.
    pub fn new(original_size: u32) -> Self {
        Self {
            appended_items: Vec::new(),
            next_index: original_size + 1,
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

    /// Returns the index that would be assigned to the next added item.
    pub fn next_index(&self) -> u32 {
        self.next_index
    }

    /// Returns an iterator over all added items with their assigned indices.
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

    /// Calculates the size these userstring additions will add to the binary #US heap.
    ///
    /// The #US heap stores UTF-16 encoded strings with compressed length prefixes.
    /// Each string contributes: compressed_length_size + UTF-16_byte_length + optional_trailing_byte
    pub fn binary_userstring_heap_size(&self) -> usize {
        self.appended_items
            .iter()
            .map(|s| {
                // UTF-16 encoding: each character can be 2 or 4 bytes
                let utf16_bytes: usize = s.encode_utf16().map(|_| 2).sum(); // Simplified: assume BMP only
                let length = utf16_bytes;

                let compressed_length_size = if length < 0x80 {
                    1 // Single byte for lengths < 128
                } else if length < 0x4000 {
                    2 // Two bytes for lengths < 16384
                } else {
                    4 // Four bytes for larger lengths
                };

                // User strings may have an additional trailing byte
                let trailing_byte = if utf16_bytes % 2 == 1 { 1 } else { 0 };

                compressed_length_size + utf16_bytes + trailing_byte
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
        assert_eq!(changes.next_index(), 101);
        assert!(!changes.has_additions());

        changes.appended_items.push("test".to_string());
        changes.next_index += 1;

        assert!(changes.has_additions());
        assert_eq!(changes.additions_count(), 1);
        assert_eq!(changes.next_index(), 102);
    }

    #[test]
    fn test_heap_changes_items_with_indices() {
        let mut changes = HeapChanges::new(50);
        changes.appended_items.push("first".to_string());
        changes.appended_items.push("second".to_string());
        changes.next_index = 53; // Simulating 2 additions

        let items: Vec<_> = changes.items_with_indices().collect();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0], (51, &"first".to_string()));
        assert_eq!(items[1], (52, &"second".to_string()));
    }
}
