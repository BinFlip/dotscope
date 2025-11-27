//! Mutable assembly representation for editing and modification operations.
//!
//! This module provides [`crate::cilassembly::CilAssembly`], a comprehensive editing layer for .NET assemblies
//! that enables type-safe, efficient modification of metadata tables, heap content, and
//! cross-references while maintaining ECMA-335 compliance.
//!
//! # Design Philosophy
//!
//! ## **Copy-on-Write Semantics**
//! - Original [`crate::metadata::cilassemblyview::CilAssemblyView`] remains immutable and unchanged
//! - Modifications are tracked separately in [`crate::cilassembly::changes::AssemblyChanges`]
//! - Changes are lazily allocated only when modifications are made
//! - Read operations efficiently merge original data with changes
//!
//! ## **Memory Efficiency**
//! - **Sparse Tracking**: Only modified tables/heaps consume memory
//! - **Lazy Initialization**: Change structures created on first modification
//! - **Efficient Storage**: Operations stored chronologically with timestamps
//! - **Memory Estimation**: Built-in memory usage tracking and reporting
//!
//! # Core Components
//!
//! ## **Change Tracking ([`crate::cilassembly::changes::AssemblyChanges`])**
//! Central structure that tracks all modifications:
//! ```text
//! AssemblyChanges
//! ├── string_heap_changes: Option<HeapChanges<String>>      // #Strings (UTF-8)
//! ├── blob_heap_changes: Option<HeapChanges<Vec<u8>>>       // #Blob (binary)
//! ├── guid_heap_changes: Option<HeapChanges<[u8; 16]>>      // #GUID (16-byte)
//! ├── userstring_heap_changes: Option<HeapChanges<String>>  // #US (UTF-16)
//! └── table_changes: HashMap<TableId, TableModifications>
//! ```
//!
//! ## **Table Modifications ([`crate::cilassembly::modifications::TableModifications`])**
//! Two strategies for tracking table changes:
//! - **Sparse**: Individual operations (Insert/Update/Delete) with timestamps
//! - **Replaced**: Complete table replacement for heavily modified tables
//!
//! ## **Operation Types ([`crate::cilassembly::operation::Operation`])**
//! - **Insert(rid, data)**: Add new row with specific RID
//! - **Update(rid, data)**: Modify existing row data  
//! - **Delete(rid)**: Mark row as deleted
//!
//! ## **Validation System**
//! - **Configurable Pipeline**: Multiple validation stages
//! - **Conflict Detection**: Identifies conflicting operations
//! - **Resolution Strategies**: Last-write-wins, merge, reject, etc.
//! - **Cross-Reference Validation**: Ensures referential integrity
//!
//! ## **Index Remapping**
//! - **Heap Index Management**: Tracks new heap indices
//! - **RID Remapping**: Maps original RIDs to final RIDs after consolidation
//! - **Cross-Reference Updates**: Updates all references during binary generation
//!
//! # Usage Patterns
//!
//! ## **Basic Heap Modification**
//! ```rust,ignore
//! # use dotscope::{CilAssemblyView, CilAssembly};
//! # let view = CilAssemblyView::from_mem(vec![])?;
//! let mut assembly = CilAssembly::new(view);
//!
//! // Heap operations return indices for cross-referencing
//! let string_idx = assembly.add_string("MyString")?;
//! let blob_idx = assembly.add_blob(&[0x01, 0x02, 0x03])?;
//! let guid_idx = assembly.add_guid(&[0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
//!                                    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88])?;
//! let userstring_idx = assembly.add_userstring("User String Literal")?;
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## **Table Row Operations**
//! ```rust,ignore
//! # use dotscope::{CilAssemblyView, CilAssembly, metadata::tables::{TableId, TableDataOwned}};
//! # let view = CilAssemblyView::from_mem(vec![])?;
//! let mut assembly = CilAssembly::new(view);
//!
//! // Low-level table modification
//! // let row_data = TableDataOwned::TypeDef(/* ... */);
//! // let rid = assembly.add_table_row(TableId::TypeDef, row_data)?;
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## **Validation and Consistency**
//! ```rust,ignore
//! # use dotscope::{CilAssemblyView, CilAssembly};
//! # let view = CilAssemblyView::from_mem(vec![])?;
//! let mut assembly = CilAssembly::new(view);
//!
//! // Make modifications...
//!
//! // Validate all changes before generating binary
//! assembly.validate_and_apply_changes()?;
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Module Organization
//!
//! Following "one type per file" for maintainability:
//!
//! ## **Core Types**
//! - [`crate::cilassembly::CilAssembly`] - Main mutable assembly (this file)
//! - [`crate::cilassembly::changes::AssemblyChanges`] - Central change tracking
//! - [`crate::cilassembly::changes::heap::HeapChanges`] - Heap modification tracking
//! - [`crate::cilassembly::modifications::TableModifications`] - Table change strategies
//! - [`crate::cilassembly::operation::TableOperation`] - Timestamped operations
//! - [`crate::cilassembly::operation::Operation`] - Operation variants
//!
//! ## **Conflict Resolution ([`crate::cilassembly::resolver`])**
//! Conflict resolution for handling competing operations:
//! - [`crate::cilassembly::resolver::ConflictResolver`] - Conflict resolution strategies
//! - [`crate::cilassembly::resolver::LastWriteWinsResolver`] - Default timestamp-based resolver
//! - [`crate::cilassembly::resolver::Conflict`] & [`crate::cilassembly::resolver::Resolution`] - Conflict types and results
//!
//! ## **Remapping ([`crate::cilassembly::remapping`])**
//! - [`crate::cilassembly::remapping::IndexRemapper`] - Master index/RID remapping
//! - [`crate::cilassembly::remapping::RidRemapper`] - Per-table RID management
//!
//! # Examples
//!
//! ```rust,ignore
//! use dotscope::{CilAssemblyView, CilAssembly};
//! use std::path::Path;
//!
//! // Load and convert to mutable assembly
//! let view = CilAssemblyView::from_path(Path::new("assembly.dll"))?;
//! let mut assembly = CilAssembly::new(view);
//!
//! // Add a string to the heap
//! let string_index = assembly.add_string("Hello, World!")?;
//!
//! // Write modified assembly to new file
//! assembly.write_to_file(Path::new("modified.dll"))?;
//! # Ok::<(), dotscope::Error>(())
//! ```
use crate::{
    file::File,
    metadata::{
        cilassemblyview::CilAssemblyView,
        exports::UnifiedExportContainer,
        imports::UnifiedImportContainer,
        tables::{TableDataOwned, TableId},
        validation::{ValidationConfig, ValidationEngine},
    },
    utils::compressed_uint_size,
    Result,
};

mod builder;
mod builders;
mod changes;
mod modifications;
mod operation;
mod remapping;
mod resolver;
mod writer;

pub use builder::*;
pub use builders::{
    ClassBuilder, EnumBuilder, EventBuilder, InterfaceBuilder, MethodBodyBuilder, MethodBuilder,
    PropertyBuilder,
};
pub use changes::{AssemblyChanges, HeapChanges, ReferenceHandlingStrategy};
pub use modifications::TableModifications;
pub use operation::{Operation, TableOperation};
pub use resolver::LastWriteWinsResolver;

use self::remapping::IndexRemapper;

/// A mutable view of a .NET assembly that tracks changes for editing operations.
///
/// `CilAssembly` provides an editing layer on top of [`crate::metadata::cilassemblyview::CilAssemblyView`], using
/// a copy-on-write strategy to track modifications while preserving the original
/// assembly data. Changes are stored separately and merged when writing to disk.
///
/// # Thread Safety
///
/// `CilAssembly` is **not thread-safe** by default. For concurrent access, wrap in
/// appropriate synchronization primitives.
pub struct CilAssembly {
    view: CilAssemblyView,
    changes: AssemblyChanges,
}

impl CilAssembly {
    /// Creates a new mutable assembly from a read-only view.
    ///
    /// This consumes the `CilAssemblyView` and creates a mutable editing layer
    /// on top of it.
    ///
    /// # Arguments
    ///
    /// * `view` - The read-only assembly view to wrap
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::{CilAssemblyView, CilAssembly};
    /// use std::path::Path;
    ///
    /// let view = CilAssemblyView::from_path(Path::new("assembly.dll"))?;
    /// let assembly = CilAssembly::new(view);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn new(view: CilAssemblyView) -> Self {
        Self {
            changes: AssemblyChanges::new(&view),
            view,
        }
    }

    /// Adds a string to the string heap (#Strings) and returns its index.
    ///
    /// The string is appended to the string heap, maintaining the original
    /// heap structure. The returned index can be used to reference this
    /// string from metadata table rows.
    ///
    /// **Note**: Strings in the #Strings heap are UTF-8 encoded when written
    /// to the binary. This method stores the logical string value
    /// during the editing phase.
    ///
    /// # Arguments
    ///
    /// * `value` - The string to add to the heap
    ///
    /// # Returns
    ///
    /// Returns the heap index that can be used to reference this string.
    /// Indices are 1-based following ECMA-335 conventions.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// # use dotscope::{CilAssemblyView, CilAssembly};
    /// # use std::path::Path;
    /// # let view = CilAssemblyView::from_path(&Path::new("assembly.dll"))?;
    /// let mut assembly = CilAssembly::new(view);
    ///
    /// let hello_index = assembly.add_string("Hello")?;
    /// let world_index = assembly.add_string("World")?;
    ///
    /// assert!(world_index > hello_index);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Currently this function does not return errors, but the Result type is
    /// reserved for future enhancements that may require error handling.
    pub fn string_add(&mut self, value: &str) -> Result<u32> {
        let string_changes = &mut self.changes.string_heap_changes;
        let index = string_changes.next_index;
        string_changes.appended_items.push(value.to_string());
        // Strings are null-terminated, so increment by string length + 1 for null terminator
        string_changes.next_index += u32::try_from(value.len()).unwrap_or(0) + 1;

        Ok(index)
    }

    /// Adds a blob to the blob heap and returns its index.
    ///
    /// The blob data is appended to the blob heap, maintaining the original
    /// heap structure. The returned index can be used to reference this
    /// blob from metadata table rows.
    ///
    /// # Arguments
    ///
    /// * `data` - The blob data to add to the heap
    ///
    /// # Returns
    ///
    /// Returns the heap index that can be used to reference this blob.
    /// Indices are 1-based following ECMA-335 conventions.
    ///
    /// # Errors
    ///
    /// Returns an error if the blob cannot be added to the heap.
    pub fn blob_add(&mut self, data: &[u8]) -> Result<u32> {
        let blob_changes = &mut self.changes.blob_heap_changes;
        let index = blob_changes.next_index;
        blob_changes.appended_items.push(data.to_vec());

        // Blobs have compressed length prefix + data
        let length = data.len();
        let prefix_size = compressed_uint_size(length);
        blob_changes.next_index +=
            u32::try_from(prefix_size).unwrap_or(0) + u32::try_from(length).unwrap_or(0);

        Ok(index)
    }

    /// Adds a GUID to the GUID heap and returns its index.
    ///
    /// The GUID is appended to the GUID heap, maintaining the original
    /// heap structure. The returned index can be used to reference this
    /// GUID from metadata table rows.
    ///
    /// # Arguments
    ///
    /// * `guid` - The 16-byte GUID to add to the heap
    ///
    /// # Returns
    ///
    /// Returns the heap index that can be used to reference this GUID.
    /// Indices are 1-based following ECMA-335 conventions.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// # use dotscope::{CilAssemblyView, CilAssembly};
    /// # use std::path::Path;
    /// # let view = CilAssemblyView::from_path(&Path::new("assembly.dll"))?;
    /// let mut assembly = CilAssembly::new(view);
    ///
    /// let guid = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
    ///             0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
    /// let guid_index = assembly.add_guid(&guid)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if the GUID cannot be added to the heap.
    pub fn guid_add(&mut self, guid: &[u8; 16]) -> Result<u32> {
        let guid_changes = &mut self.changes.guid_heap_changes;

        // GUID heap indices are sequential (1-based), not byte-based
        // Calculate the current GUID count from the original heap size and additions
        let original_heap_size = guid_changes.next_index
            - (u32::try_from(guid_changes.appended_items.len()).unwrap_or(0) * 16);
        let existing_guid_count = original_heap_size / 16;
        let added_guid_count = u32::try_from(guid_changes.appended_items.len()).unwrap_or(0);
        let sequential_index = existing_guid_count + added_guid_count + 1;

        // Store the byte offset for the heap builder to use
        // byte_offset = (sequential_index - 1) * 16 = (existing_guid_count + added_guid_count) * 16
        let byte_offset = guid_changes.next_index;
        guid_changes.append_item_with_index(*guid, byte_offset);
        // GUIDs are fixed 16 bytes each
        guid_changes.next_index += 16;

        Ok(sequential_index)
    }

    /// Adds a user string to the user string heap (#US) and returns its index.
    ///
    /// The user string is appended to the user string heap (#US), maintaining
    /// the original heap structure. User strings are used for string literals
    /// in IL code (e.g., `ldstr` instruction operands) and are stored with
    /// length prefixes and UTF-16 encoding when written to the binary.
    ///
    /// **Note**: User strings in the #US heap are UTF-16 encoded with compressed
    /// length prefixes when written to the binary. This method calculates API
    /// indices based on final string sizes after considering modifications to
    /// ensure consistency with the writer and size calculation logic.
    ///
    /// # Arguments
    ///
    /// * `value` - The string to add to the user string heap
    ///
    /// # Returns
    ///
    /// Returns the heap index that can be used to reference this user string.
    /// Indices are 1-based following ECMA-335 conventions.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// # use dotscope::{CilAssemblyView, CilAssembly};
    /// # use std::path::Path;
    /// # let view = CilAssemblyView::from_path(&Path::new("assembly.dll"))?;
    /// let mut assembly = CilAssembly::new(view);
    ///
    /// let userstring_index = assembly.add_userstring("Hello, World!")?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if the user string cannot be added to the heap.
    pub fn userstring_add(&mut self, value: &str) -> Result<u32> {
        let userstring_changes = &mut self.changes.userstring_heap_changes;
        let index = userstring_changes.next_index;

        userstring_changes.append_item_with_index(value.to_string(), index);

        // Calculate size increment for next index (using original string size for API index stability)
        let utf16_bytes: Vec<u8> = value.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let utf16_length = utf16_bytes.len();
        let total_length = utf16_length + 1; // +1 for terminator byte

        // Calculate compressed length prefix size + UTF-16 data length + terminator
        let prefix_size = compressed_uint_size(total_length);
        userstring_changes.next_index +=
            u32::try_from(prefix_size).unwrap_or(0) + u32::try_from(total_length).unwrap_or(0);

        Ok(index)
    }

    /// Updates an existing string in the string heap at the specified index.
    ///
    /// This modifies the string at the given heap index. The reference handling
    /// is not needed for modifications since the index remains the same.
    ///
    /// # Arguments
    ///
    /// * `index` - The heap index to modify (1-based, following ECMA-335 conventions)
    /// * `new_value` - The new string value to store at that index
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the modification was successful.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// # use dotscope::{CilAssemblyView, CilAssembly};
    /// # use std::path::Path;
    /// # let view = CilAssemblyView::from_path(&Path::new("assembly.dll"))?;
    /// let mut assembly = CilAssembly::new(view);
    ///
    /// // Modify an existing string at index 42
    /// assembly.update_string(42, "Updated String")?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if the string cannot be updated.
    pub fn string_update(&mut self, index: u32, new_value: &str) -> Result<()> {
        self.changes
            .string_heap_changes
            .add_modification(index, new_value.to_string());
        Ok(())
    }

    /// Removes a string from the string heap at the specified index.
    ///
    /// This marks the string at the given heap index for removal. The strategy
    /// parameter controls how existing references to this string are handled.
    ///
    /// # Arguments
    ///
    /// * `index` - The heap index to remove (1-based, following ECMA-335 conventions)
    /// * `strategy` - How to handle existing references to this string
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the removal was successful.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// # use dotscope::{CilAssembly, CilAssemblyView};
    /// # use dotscope::cilassembly::ReferenceHandlingStrategy;
    /// # use std::path::Path;
    /// # let view = CilAssemblyView::from_path(&Path::new("assembly.dll"))?;
    /// let mut assembly = CilAssembly::new(view);
    ///
    /// // Remove string at index 42, fail if references exist
    /// assembly.remove_string(42, ReferenceHandlingStrategy::FailIfReferenced)?;
    ///
    /// // Remove string at index 43, nullify all references
    /// assembly.remove_string(43, ReferenceHandlingStrategy::NullifyReferences)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if the string cannot be removed or if references exist when using FailIfReferenced strategy.
    pub fn string_remove(&mut self, index: u32, strategy: ReferenceHandlingStrategy) -> Result<()> {
        let original_heap_size = self
            .view()
            .streams()
            .iter()
            .find(|s| s.name == "#Strings")
            .map_or(0, |s| s.size);

        if index >= original_heap_size {
            self.changes
                .string_heap_changes
                .mark_appended_for_removal(index);
        } else {
            self.changes
                .string_heap_changes
                .add_removal(index, strategy);
        }
        Ok(())
    }

    /// Updates an existing blob in the blob heap at the specified index.
    ///
    /// # Arguments
    ///
    /// * `index` - The heap index to modify (1-based, following ECMA-335 conventions)
    /// * `new_data` - The new blob data to store at that index
    ///
    /// # Errors
    ///
    /// Returns an error if the blob cannot be updated.
    pub fn blob_update(&mut self, index: u32, new_data: &[u8]) -> Result<()> {
        self.changes
            .blob_heap_changes
            .add_modification(index, new_data.to_vec());
        Ok(())
    }

    /// Removes a blob from the blob heap at the specified index.
    ///
    /// # Arguments
    ///
    /// * `index` - The heap index to remove (1-based, following ECMA-335 conventions)
    /// * `strategy` - How to handle existing references to this blob
    ///
    /// # Errors
    ///
    /// Returns an error if the blob cannot be removed or if references exist when using FailIfReferenced strategy.
    pub fn blob_remove(&mut self, index: u32, strategy: ReferenceHandlingStrategy) -> Result<()> {
        self.changes.blob_heap_changes.add_removal(index, strategy);
        Ok(())
    }

    /// Updates an existing GUID in the GUID heap at the specified index.
    ///
    /// # Arguments
    ///
    /// * `index` - The heap index to modify (1-based sequential index, following ECMA-335 conventions)
    /// * `new_guid` - The new 16-byte GUID to store at that index
    ///
    /// # Errors
    ///
    /// Currently always succeeds, but returns `Result` for future extensibility.
    pub fn guid_update(&mut self, index: u32, new_guid: &[u8; 16]) -> Result<()> {
        // Convert 1-based sequential index to byte offset for HeapChanges lookup
        // GUID heap uses byte offsets internally: byte_offset = (index - 1) * 16
        let byte_offset = (index.saturating_sub(1)) * 16;
        self.changes
            .guid_heap_changes
            .add_modification(byte_offset, *new_guid);
        Ok(())
    }

    /// Removes a GUID from the GUID heap at the specified index.
    ///
    /// # Arguments
    ///
    /// * `index` - The heap index to remove (1-based sequential index, following ECMA-335 conventions)
    /// * `strategy` - How to handle existing references to this GUID
    ///
    /// # Errors
    ///
    /// Currently always succeeds, but returns `Result` for future extensibility.
    pub fn guid_remove(&mut self, index: u32, strategy: ReferenceHandlingStrategy) -> Result<()> {
        // Convert 1-based sequential index to byte offset for HeapChanges lookup
        // GUID heap uses byte offsets internally: byte_offset = (index - 1) * 16
        let byte_offset = (index.saturating_sub(1)) * 16;
        self.changes
            .guid_heap_changes
            .add_removal(byte_offset, strategy);
        Ok(())
    }

    /// Updates an existing user string in the user string heap at the specified index.
    ///
    /// # Arguments
    ///
    /// * `index` - The heap index to modify (1-based, following ECMA-335 conventions)
    /// * `new_value` - The new string value to store at that index
    ///
    /// # Errors
    ///
    /// Currently always succeeds, but returns `Result` for future extensibility.
    pub fn userstring_update(&mut self, index: u32, new_value: &str) -> Result<()> {
        self.changes
            .userstring_heap_changes
            .add_modification(index, new_value.to_string());
        Ok(())
    }

    /// Removes a user string from the user string heap at the specified index.
    ///
    /// # Arguments
    ///
    /// * `index` - The heap index to remove (1-based, following ECMA-335 conventions)
    /// * `strategy` - How to handle existing references to this user string
    ///
    /// # Errors
    ///
    /// Currently always succeeds, but returns `Result` for future extensibility.
    pub fn userstring_remove(
        &mut self,
        index: u32,
        strategy: ReferenceHandlingStrategy,
    ) -> Result<()> {
        self.changes
            .userstring_heap_changes
            .add_removal(index, strategy);
        Ok(())
    }

    /// Replaces the entire string heap (#Strings) with the provided raw data.
    ///
    /// This completely replaces the string heap content, ignoring the original heap.
    /// If there is no existing string heap, a new one will be created. All subsequent
    /// append/modify/remove operations will be applied to this replacement heap
    /// instead of the original.
    ///
    /// # Arguments
    ///
    /// * `heap_data` - The raw bytes that will form the new string heap
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// # use dotscope::{CilAssemblyView, CilAssembly};
    /// # use std::path::Path;
    /// # let view = CilAssemblyView::from_path(&Path::new("assembly.dll"))?;
    /// let mut assembly = CilAssembly::new(view);
    ///
    /// // Replace with custom string heap containing "Hello\0World\0"
    /// let custom_heap = b"Hello\0World\0".to_vec();
    /// assembly.string_add_heap(custom_heap)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Currently always succeeds, but returns `Result` for future extensibility.
    pub fn string_add_heap(&mut self, heap_data: Vec<u8>) -> Result<()> {
        self.changes.string_heap_changes.replace_heap(heap_data);
        Ok(())
    }

    /// Replaces the entire blob heap (#Blob) with the provided raw data.
    ///
    /// This completely replaces the blob heap content, ignoring the original heap.
    /// If there is no existing blob heap, a new one will be created. All subsequent
    /// append/modify/remove operations will be applied to this replacement heap
    /// instead of the original.
    ///
    /// # Arguments
    ///
    /// * `heap_data` - The raw bytes that will form the new blob heap
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// # use dotscope::{CilAssemblyView, CilAssembly};
    /// # use std::path::Path;
    /// # let view = CilAssemblyView::from_path(&Path::new("assembly.dll"))?;
    /// let mut assembly = CilAssembly::new(view);
    ///
    /// // Replace with custom blob heap containing length-prefixed blobs
    /// let custom_heap = vec![0x03, 0x01, 0x02, 0x03, 0x02, 0xFF, 0xFE];
    /// assembly.blob_add_heap(custom_heap)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Currently always succeeds, but returns `Result` for future extensibility.
    pub fn blob_add_heap(&mut self, heap_data: Vec<u8>) -> Result<()> {
        self.changes.blob_heap_changes.replace_heap(heap_data);
        Ok(())
    }

    /// Replaces the entire GUID heap (#GUID) with the provided raw data.
    ///
    /// This completely replaces the GUID heap content, ignoring the original heap.
    /// If there is no existing GUID heap, a new one will be created. All subsequent
    /// append/modify/remove operations will be applied to this replacement heap
    /// instead of the original.
    ///
    /// # Arguments
    ///
    /// * `heap_data` - The raw bytes that will form the new GUID heap (must be 16-byte aligned)
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// # use dotscope::{CilAssemblyView, CilAssembly};
    /// # use std::path::Path;
    /// # let view = CilAssemblyView::from_path(&Path::new("assembly.dll"))?;
    /// let mut assembly = CilAssembly::new(view);
    ///
    /// // Replace with custom GUID heap containing one GUID
    /// let guid = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
    ///             0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
    /// assembly.guid_add_heap(guid.to_vec())?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Currently always succeeds, but returns `Result` for future extensibility.
    pub fn guid_add_heap(&mut self, heap_data: Vec<u8>) -> Result<()> {
        self.changes.guid_heap_changes.replace_heap(heap_data);
        Ok(())
    }

    /// Replaces the entire user string heap (#US) with the provided raw data.
    ///
    /// This completely replaces the user string heap content, ignoring the original heap.
    /// If there is no existing user string heap, a new one will be created. All subsequent
    /// append/modify/remove operations will be applied to this replacement heap
    /// instead of the original.
    ///
    /// # Arguments
    ///
    /// * `heap_data` - The raw bytes that will form the new user string heap
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// # use dotscope::{CilAssemblyView, CilAssembly};
    /// # use std::path::Path;
    /// # let view = CilAssemblyView::from_path(&Path::new("assembly.dll"))?;
    /// let mut assembly = CilAssembly::new(view);
    ///
    /// // Replace with custom user string heap containing UTF-16 strings with length prefixes
    /// let custom_heap = vec![0x07, 0x48, 0x00, 0x65, 0x00, 0x6C, 0x00, 0x01]; // "Hel" + terminator
    /// assembly.userstring_add_heap(custom_heap)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Currently always succeeds, but returns `Result` for future extensibility.
    pub fn userstring_add_heap(&mut self, heap_data: Vec<u8>) -> Result<()> {
        self.changes.userstring_heap_changes.replace_heap(heap_data);
        Ok(())
    }

    /// Updates an existing table row at the specified RID.
    ///
    /// This modifies the row data at the given RID in the specified table.
    ///
    /// # Arguments
    ///
    /// * `table_id` - The table containing the row to modify
    /// * `rid` - The Row ID to modify (1-based, following ECMA-335 conventions)
    /// * `new_row` - The new row data to store at that RID
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the modification was successful.
    ///
    /// # Errors
    ///
    /// Returns an error if the table operation fails or the provided row data is invalid.
    pub fn table_row_update(
        &mut self,
        table_id: TableId,
        rid: u32,
        new_row: TableDataOwned,
    ) -> Result<()> {
        let original_count = self.original_table_row_count(table_id);
        let table_changes = self
            .changes
            .table_changes
            .entry(table_id)
            .or_insert_with(|| TableModifications::new_sparse(original_count + 1));

        let operation = Operation::Update(rid, new_row);
        let table_operation = TableOperation::new(operation);
        table_changes.apply_operation(table_operation)?;
        Ok(())
    }

    /// Removes a table row at the specified RID.
    ///
    /// This marks the row at the given RID for deletion. The strategy parameter
    /// controls how existing references to this row are handled.
    ///
    /// # Arguments
    ///
    /// * `table_id` - The table containing the row to remove
    /// * `rid` - The Row ID to remove (1-based, following ECMA-335 conventions)
    /// * `strategy` - How to handle existing references to this row
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the removal was successful.
    ///
    /// # Errors
    ///
    /// Returns an error if the table operation fails or the specified row does not exist.
    pub fn table_row_remove(
        &mut self,
        table_id: TableId,
        rid: u32,
        _strategy: ReferenceHandlingStrategy,
    ) -> Result<()> {
        let original_count = self.original_table_row_count(table_id);
        let table_changes = self
            .changes
            .table_changes
            .entry(table_id)
            .or_insert_with(|| TableModifications::new_sparse(original_count + 1));

        let operation = Operation::Delete(rid);
        let table_operation = TableOperation::new(operation);
        table_changes.apply_operation(table_operation)?;

        Ok(())
    }

    /// Basic table row addition.
    ///
    /// This is the foundational method for adding rows to tables.
    ///
    /// # Arguments
    ///
    /// * `table_id` - The table to add the row to
    /// * `row` - The row data to add
    ///
    /// # Returns
    ///
    /// Returns the RID (Row ID) of the newly added row. RIDs are 1-based.
    ///
    /// # Errors
    ///
    /// Returns an error if the table cannot be converted to sparse mode.
    pub fn table_row_add(&mut self, table_id: TableId, row: TableDataOwned) -> Result<u32> {
        let original_count = self.original_table_row_count(table_id);
        let table_changes = self
            .changes
            .table_changes
            .entry(table_id)
            .or_insert_with(|| TableModifications::new_sparse(original_count + 1));

        match table_changes {
            TableModifications::Sparse { next_rid, .. } => {
                let new_rid = *next_rid;
                let operation = Operation::Insert(new_rid, row);
                let table_operation = TableOperation::new(operation);
                table_changes.apply_operation(table_operation)?;
                Ok(new_rid)
            }
            TableModifications::Replaced(rows) => {
                let new_rid = u32::try_from(rows.len()).unwrap_or(0) + 1;
                rows.push(row);
                Ok(new_rid)
            }
        }
    }

    /// Validates all pending changes and applies index remapping.
    ///
    /// This method runs the unified validation engine to validate all pending
    /// modifications and resolves any conflicts found. It should be called before
    /// writing the assembly to ensure metadata consistency.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if all validations pass and conflicts are resolved,
    /// or an error describing the first validation failure.
    ///
    /// # Errors
    ///
    /// Returns an error if validation fails or conflicts cannot be resolved.
    pub fn validate_and_apply_changes(&mut self) -> Result<()> {
        let remapper = {
            let engine = ValidationEngine::new(&self.view, ValidationConfig::production())?;
            let result = engine.execute_stage1_validation(&self.view, Some(&self.changes))?;

            result.into_result()?;
            IndexRemapper::build_from_changes(&self.changes, &self.view)
        };

        remapper.apply_to_assembly(&mut self.changes);

        Ok(())
    }

    /// Validates and applies changes using a custom validation configuration.
    ///
    /// This method allows you to specify custom validation settings for different
    /// validation strategies. This is useful when you need different validation
    /// levels (minimal, comprehensive, strict, etc.).
    ///
    /// # Arguments
    ///
    /// * `config` - The [`ValidationConfig`] to use for validation
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if all validations pass and conflicts are resolved,
    /// or an error describing the first validation failure.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use crate::metadata::validation::ValidationConfig;
    ///
    /// # let mut assembly = CilAssembly::from_view(view);
    /// // Use comprehensive validation
    /// assembly.validate_and_apply_changes_with_config(ValidationConfig::comprehensive())?;
    /// # Ok::<(), crate::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if validation fails or conflicts cannot be resolved with the specified configuration.
    pub fn validate_and_apply_changes_with_config(
        &mut self,
        config: ValidationConfig,
    ) -> Result<()> {
        let remapper = {
            let engine = ValidationEngine::new(&self.view, config)?;
            let result = engine.execute_stage1_validation(&self.view, Some(&self.changes))?;

            result.into_result()?;
            IndexRemapper::build_from_changes(&self.changes, &self.view)
        };

        remapper.apply_to_assembly(&mut self.changes);

        Ok(())
    }

    /// Writes the modified assembly to a file.
    ///
    /// This method generates a complete PE file with all modifications applied.
    /// The assembly should already be validated before calling this method.
    ///
    /// # Arguments
    ///
    /// * `path` - The path where the modified assembly should be written
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be written or if the assembly is invalid.
    pub fn write_to_file<P: AsRef<std::path::Path>>(&mut self, path: P) -> Result<()> {
        writer::write_assembly_to_file(self, path)
    }

    /// Gets the original row count for a table
    pub fn original_table_row_count(&self, table_id: TableId) -> u32 {
        if let Some(tables) = self.view.tables() {
            tables.table_row_count(table_id)
        } else {
            0
        }
    }

    /// Gets a reference to the underlying view for read operations.
    pub fn view(&self) -> &CilAssemblyView {
        &self.view
    }

    /// Gets a reference to the underlying PE file.
    ///
    /// This is a convenience method equivalent to `self.view().file()`.
    pub fn file(&self) -> &File {
        self.view.file()
    }

    /// Gets a reference to the changes for write operations.
    pub fn changes(&self) -> &AssemblyChanges {
        &self.changes
    }

    /// Adds a DLL to the native import table.
    ///
    /// Creates a new import descriptor for the specified DLL if it doesn't already exist.
    /// This method provides the foundation for native PE import functionality by managing
    /// DLL dependencies at the assembly level.
    ///
    /// # Arguments
    ///
    /// * `dll_name` - Name of the DLL (e.g., "kernel32.dll", "user32.dll")
    ///
    /// # Returns
    ///
    /// `Ok(())` if the DLL was added successfully, or if it already exists.
    ///
    /// # Errors
    ///
    /// Returns an error if the DLL name is empty or contains invalid characters.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// # use dotscope::{CilAssemblyView, CilAssembly};
    /// # use std::path::Path;
    /// # let view = CilAssemblyView::from_path(Path::new("test.dll"))?;
    /// let mut assembly = CilAssembly::new(view);
    ///
    /// assembly.add_native_import_dll("kernel32.dll")?;
    /// assembly.add_native_import_dll("user32.dll")?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn add_native_import_dll(&mut self, dll_name: &str) -> Result<()> {
        let imports = self.changes.native_imports_mut();
        imports.native_mut().add_dll(dll_name)
    }

    /// Adds a named function import from a specific DLL to the native import table.
    ///
    /// Adds a function import that uses name-based lookup. The DLL will be automatically
    /// added to the import table if it doesn't already exist. This method handles the
    /// complete import process including IAT allocation and Import Lookup Table setup.
    ///
    /// # Arguments
    ///
    /// * `dll_name` - Name of the DLL containing the function
    /// * `function_name` - Name of the function to import
    ///
    /// # Returns
    ///
    /// `Ok(())` if the function was added successfully.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The DLL name or function name is empty
    /// - The function is already imported from this DLL
    /// - There are issues with IAT allocation
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// # use dotscope::{CilAssemblyView, CilAssembly};
    /// # use std::path::Path;
    /// # let view = CilAssemblyView::from_path(Path::new("test.dll"))?;
    /// let mut assembly = CilAssembly::new(view);
    ///
    /// // Add kernel32 functions
    /// assembly.add_native_import_function("kernel32.dll", "GetCurrentProcessId")?;
    /// assembly.add_native_import_function("kernel32.dll", "ExitProcess")?;
    ///
    /// // Add user32 functions  
    /// assembly.add_native_import_function("user32.dll", "MessageBoxW")?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn add_native_import_function(
        &mut self,
        dll_name: &str,
        function_name: &str,
    ) -> Result<()> {
        let imports = self.changes.native_imports_mut();
        imports.add_native_function(dll_name, function_name)
    }

    /// Adds an ordinal-based function import to the native import table.
    ///
    /// Adds a function import that uses ordinal-based lookup instead of name-based.
    /// This can be more efficient and result in smaller import tables, but is less
    /// portable across DLL versions. The DLL will be automatically added if it
    /// doesn't exist.
    ///
    /// # Arguments
    ///
    /// * `dll_name` - Name of the DLL containing the function
    /// * `ordinal` - Ordinal number of the function in the DLL's export table
    ///
    /// # Returns
    ///
    /// `Ok(())` if the function was added successfully.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The DLL name is empty
    /// - The ordinal is 0 (invalid)
    /// - A function with the same ordinal is already imported from this DLL
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// # use dotscope::{CilAssemblyView, CilAssembly};
    /// # use std::path::Path;
    /// # let view = CilAssemblyView::from_path(Path::new("test.dll"))?;
    /// let mut assembly = CilAssembly::new(view);
    ///
    /// // Import MessageBoxW by ordinal (more efficient)
    /// assembly.add_native_import_function_by_ordinal("user32.dll", 120)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn add_native_import_function_by_ordinal(
        &mut self,
        dll_name: &str,
        ordinal: u16,
    ) -> Result<()> {
        let imports = self.changes.native_imports_mut();
        imports.add_native_function_by_ordinal(dll_name, ordinal)
    }

    /// Adds a named function export to the native export table.
    ///
    /// Creates a function export that can be called by other modules. The function
    /// will be accessible by both name and ordinal. This method handles the complete
    /// export process including Export Address Table and Export Name Table setup.
    ///
    /// # Arguments
    ///
    /// * `function_name` - Name of the function to export
    /// * `ordinal` - Ordinal number for the export (must be unique)
    /// * `address` - Function address (RVA) in the image
    ///
    /// # Returns
    ///
    /// `Ok(())` if the function was exported successfully.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The function name is empty
    /// - The ordinal is 0 (invalid) or already in use
    /// - The function name is already exported
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// # use dotscope::{CilAssemblyView, CilAssembly};
    /// # use std::path::Path;
    /// # let view = CilAssemblyView::from_path(Path::new("test.dll"))?;
    /// let mut assembly = CilAssembly::new(view);
    ///
    /// // Export library functions
    /// assembly.add_native_export_function("MyLibraryInit", 1, 0x1000)?;
    /// assembly.add_native_export_function("ProcessData", 2, 0x2000)?;
    /// assembly.add_native_export_function("MyLibraryCleanup", 3, 0x3000)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn add_native_export_function(
        &mut self,
        function_name: &str,
        ordinal: u16,
        address: u32,
    ) -> Result<()> {
        let exports = self.changes.native_exports_mut();
        exports.add_native_function(function_name, ordinal, address)
    }

    /// Adds an ordinal-only function export to the native export table.
    ///
    /// Creates a function export that is accessible by ordinal number only,
    /// without a symbolic name. This can reduce the size of the export table
    /// but makes the exports less discoverable.
    ///
    /// # Arguments
    ///
    /// * `ordinal` - Ordinal number for the export (must be unique)
    /// * `address` - Function address (RVA) in the image
    ///
    /// # Returns
    ///
    /// `Ok(())` if the function was exported successfully.
    ///
    /// # Errors
    ///
    /// Returns an error if the ordinal is 0 (invalid) or already in use.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// # use dotscope::{CilAssemblyView, CilAssembly};
    /// # use std::path::Path;
    /// # let view = CilAssemblyView::from_path(Path::new("test.dll"))?;
    /// let mut assembly = CilAssembly::new(view);
    ///
    /// // Export internal functions by ordinal only
    /// assembly.add_native_export_function_by_ordinal(100, 0x5000)?;
    /// assembly.add_native_export_function_by_ordinal(101, 0x6000)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn add_native_export_function_by_ordinal(
        &mut self,
        ordinal: u16,
        address: u32,
    ) -> Result<()> {
        let exports = self.changes.native_exports_mut();
        exports.add_native_function_by_ordinal(ordinal, address)
    }

    /// Adds an export forwarder to the native export table.
    ///
    /// Creates a function export that forwards calls to a function in another DLL.
    /// The Windows loader resolves forwarders at runtime by loading the target
    /// DLL and finding the specified function. This is useful for implementing
    /// compatibility shims or redirecting calls.
    ///
    /// # Arguments
    ///
    /// * `function_name` - Name of the exported function (can be empty for ordinal-only)
    /// * `ordinal` - Ordinal number for the export (must be unique)
    /// * `target` - Target specification: "DllName.FunctionName" or "DllName.#Ordinal"
    ///
    /// # Returns
    ///
    /// `Ok(())` if the forwarder was added successfully.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The ordinal is 0 (invalid) or already in use
    /// - The function name is already exported (if name is provided)
    /// - The target specification is empty or malformed
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// # use dotscope::{CilAssemblyView, CilAssembly};
    /// # use std::path::Path;
    /// # let view = CilAssemblyView::from_path(Path::new("test.dll"))?;
    /// let mut assembly = CilAssembly::new(view);
    ///
    /// // Forward to functions in other DLLs
    /// assembly.add_native_export_forwarder("GetProcessId", 10, "kernel32.dll.GetCurrentProcessId")?;
    /// assembly.add_native_export_forwarder("MessageBox", 11, "user32.dll.MessageBoxW")?;
    /// assembly.add_native_export_forwarder("OrdinalForward", 12, "mydll.dll.#50")?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn add_native_export_forwarder(
        &mut self,
        function_name: &str,
        ordinal: u16,
        target: &str,
    ) -> Result<()> {
        let exports = self.changes.native_exports_mut();
        exports.add_native_forwarder(function_name, ordinal, target)
    }

    /// Gets read-only access to the unified import container.
    ///
    /// Returns the unified import container that provides access to both CIL and native
    /// PE imports. Returns `None` if no native import operations have been performed.
    ///
    /// # Returns
    ///
    /// Optional reference to the unified import container.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// # use dotscope::{CilAssemblyView, CilAssembly};
    /// # use std::path::Path;
    /// # let view = CilAssemblyView::from_path(Path::new("test.dll"))?;
    /// let assembly = CilAssembly::new(view);
    ///
    /// if let Some(imports) = assembly.native_imports() {
    ///     let dll_names = imports.get_all_dll_names();
    ///     println!("DLL dependencies: {:?}", dll_names);
    /// }
    /// ```
    pub fn native_imports(&self) -> &UnifiedImportContainer {
        self.changes.native_imports()
    }

    /// Gets read-only access to the unified export container.
    ///
    /// Returns the unified export container that provides access to both CIL and native
    /// PE exports. Returns `None` if no native export operations have been performed.
    ///
    /// # Returns
    ///
    /// Optional reference to the unified export container.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// # use dotscope::{CilAssemblyView, CilAssembly};
    /// # use std::path::Path;
    /// # let view = CilAssemblyView::from_path(Path::new("test.dll"))?;
    /// let assembly = CilAssembly::new(view);
    ///
    /// if let Some(exports) = assembly.native_exports() {
    ///     let function_names = exports.get_native_function_names();
    ///     println!("Exported functions: {:?}", function_names);
    /// }
    /// ```
    pub fn native_exports(&self) -> &UnifiedExportContainer {
        self.changes.native_exports()
    }

    /// Stores a method body and allocates a placeholder RVA for it.
    ///
    /// This method stores the method body with a placeholder RVA that will be resolved
    /// to the actual RVA during PE writing when the code section layout is determined.
    /// Used by method builders to store compiled method bodies and get placeholder RVAs
    /// for use in method definition metadata.
    ///
    /// # Arguments
    ///
    /// * `body_bytes` - The complete method body bytes including header and exception handlers
    ///
    /// # Returns
    ///
    /// A placeholder RVA that will be resolved to the actual RVA during binary writing.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// # use dotscope::{CilAssemblyView, CilAssembly};
    /// # use std::path::Path;
    /// # let view = CilAssemblyView::from_path(Path::new("test.dll"))?;
    /// let mut assembly = CilAssembly::new(view);
    ///
    /// let method_body = vec![0x02, 0x17, 0x2A]; // Tiny header + ldc.i4.1 + ret
    /// let placeholder_rva = assembly.store_method_body(method_body);
    /// // placeholder_rva will be resolved to actual RVA during binary writing
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn store_method_body(&mut self, body_bytes: Vec<u8>) -> u32 {
        self.changes.store_method_body(body_bytes)
    }
}

/// Conversion from `CilAssemblyView` to `CilAssembly`.
///
/// This provides the `view.to_owned()` syntax mentioned in the documentation.
impl From<CilAssemblyView> for CilAssembly {
    fn from(view: CilAssemblyView) -> Self {
        Self::new(view)
    }
}

impl std::fmt::Debug for CilAssembly {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CilAssembly")
            .field("original_view", &"<CilAssemblyView>")
            .field("has_changes", &self.changes.has_changes())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::test::factories::table::cilassembly::create_test_typedef_row;
    use crate::Error;

    #[test]
    fn test_convert_from_view() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_path(&path) {
            let _assembly = CilAssembly::new(view);
            // Basic smoke test - conversion should succeed
        }
    }

    #[test]
    fn test_add_string() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_path(&path) {
            let mut assembly = CilAssembly::new(view);

            let index1 = assembly.string_add("Hello").unwrap();
            let index2 = assembly.string_add("World").unwrap();

            assert_ne!(index1, index2);
            assert!(index2 > index1);
        }
    }

    #[test]
    fn test_add_blob() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_path(&path) {
            let mut assembly = CilAssembly::new(view);

            let index1 = assembly.blob_add(&[1, 2, 3]).unwrap();
            let index2 = assembly.blob_add(&[4, 5, 6]).unwrap();

            assert_ne!(index1, index2);
            assert!(index2 > index1);
        }
    }

    #[test]
    fn test_add_guid() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_path(&path) {
            let mut assembly = CilAssembly::new(view);

            let guid1 = [
                0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
                0x77, 0x88,
            ];
            let guid2 = [
                0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                0x88, 0x99,
            ];

            let index1 = assembly.guid_add(&guid1).unwrap();
            let index2 = assembly.guid_add(&guid2).unwrap();

            assert_ne!(index1, index2);
            assert!(index2 > index1);
        }
    }

    #[test]
    fn test_add_userstring() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_path(&path) {
            let mut assembly = CilAssembly::new(view);

            let index1 = assembly.userstring_add("Hello").unwrap();
            let index2 = assembly.userstring_add("World").unwrap();

            assert_ne!(index1, index2);
            assert!(index2 > index1);
        }
    }

    #[test]
    fn test_table_row_assignment_uses_correct_rid() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_path(&path) {
            let mut assembly = CilAssembly::new(view);

            // Get original table size to verify RID calculation
            let original_typedef_count = assembly.original_table_row_count(TableId::TypeDef);

            // Create a minimal TypeDef row for testing
            if let Ok(typedef_row) = create_test_typedef_row() {
                // Add table row should assign RID = original_count + 1
                if let Ok(rid) = assembly.table_row_add(TableId::TypeDef, typedef_row) {
                    assert_eq!(
                        rid,
                        original_typedef_count + 1,
                        "RID should be original count + 1"
                    );

                    // Add another row should get sequential RID
                    if let Ok(typedef_row2) = create_test_typedef_row() {
                        if let Ok(rid2) = assembly.table_row_add(TableId::TypeDef, typedef_row2) {
                            assert_eq!(
                                rid2,
                                original_typedef_count + 2,
                                "Second RID should be sequential"
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn test_validation_pipeline_catches_errors() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_path(&path) {
            let mut assembly = CilAssembly::new(view);

            // Try to add an invalid RID (should be caught by validation)
            if let Ok(typedef_row) = create_test_typedef_row() {
                let table_id = TableId::TypeDef;
                let invalid_operation = Operation::Insert(0, typedef_row); // RID 0 is invalid
                let table_operation = TableOperation::new(invalid_operation);

                // Get changes and manually add the invalid operation
                let table_changes = assembly
                    .changes
                    .table_changes
                    .entry(table_id)
                    .or_insert_with(|| TableModifications::new_sparse(1));

                // This should be caught by validation
                if table_changes.apply_operation(table_operation).is_ok() {
                    // Now try to validate - this should fail
                    let result = assembly.validate_and_apply_changes();
                    assert!(result.is_err(), "Validation should catch RID 0 error");

                    if let Err(e) = result {
                        // Verify it's the right kind of error
                        let error_str = format!("{e:?}");
                        assert!(
                            error_str.contains("invalid RID 0")
                                || error_str.contains("Invalid RID")
                                || error_str.contains("RID 0 is reserved"),
                            "Should be RID validation error: {e}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn test_heap_sizes_are_real() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_path(&path) {
            let assembly = CilAssembly::new(view);

            // Check that heap changes are properly initialized with correct next_index values
            // next_index should be original_heap_size (where the next item will be placed)
            let string_next_index = assembly.changes.string_heap_changes.next_index;
            let blob_next_index = assembly.changes.blob_heap_changes.next_index;
            let guid_next_index = assembly.changes.guid_heap_changes.next_index;
            let userstring_next_index = assembly.changes.userstring_heap_changes.next_index;

            assert_eq!(string_next_index, 203732);
            assert_eq!(blob_next_index, 77816);
            assert_eq!(guid_next_index, 16);
            assert_eq!(userstring_next_index, 53288);
        }
    }

    /// Mono runtime compatibility tests for assembly modification and execution
    mod mono_tests {
        use super::*;
        use crate::metadata::signatures::{
            encode_method_signature, SignatureMethod, SignatureParameter, TypeSignature,
        };
        use crate::metadata::tables::{
            CodedIndex, CodedIndexType, MemberRefBuilder, TableId, TypeRefBuilder,
        };
        use crate::metadata::token::Token;
        use crate::test::mono::reflection::ParameterValue;
        use crate::test::mono::runner::ArchConfig;
        use crate::test::mono::*;

        #[test]
        fn test_mono_runtime_compatibility() -> Result<()> {
            // Create test environment using the new utilities
            let mut env = create_test_environment()?;

            // Define the assembly modification that adds a simple method
            let modify_assembly = |context: &mut BuilderContext| -> Result<()> {
                let _method_token = MethodBuilder::new("DotScopeAddedMethod")
                    .public()
                    .static_method()
                    .parameter("a", TypeSignature::I4)
                    .parameter("b", TypeSignature::I4)
                    .returns(TypeSignature::I4)
                    .implementation(|body| {
                        body.implementation(|asm| {
                            asm.ldarg_0()?.ldarg_1()?.add()?.ret()?;
                            Ok(())
                        })
                    })
                    .build(context)?;
                Ok(())
            };

            // Define the reflection test
            let create_reflection_test = |assembly_path: &std::path::Path| -> String {
                ReflectionTestBuilder::new()
                    .assembly_path(assembly_path)
                    .test_method("DotScopeAddedMethod")
                    .description("Addition 5 + 7 = 12")
                    .parameters(vec![5, 7])
                    .expect(12)
                    .build()
            };

            // Run the complete test workflow
            let results = env.run_complete_test(
                compilation::templates::HELLO_WORLD,
                modify_assembly,
                create_reflection_test,
            )?;

            // Assert all architectures passed all tests
            for result in &results {
                assert!(
                    result.compilation_success,
                    "Compilation failed for {}: {:?}",
                    result.architecture.name, result.errors
                );
                assert!(
                    result.modification_success,
                    "Assembly modification failed for {}: {:?}",
                    result.architecture.name, result.errors
                );
                assert!(
                    result.execution_success,
                    "Mono execution failed for {}: {:?}",
                    result.architecture.name, result.errors
                );
                assert!(
                    result.compatibility_success,
                    "Mono compatibility test failed for {}: {:?}",
                    result.architecture.name, result.errors
                );
                assert!(
                    result.disassembly_success,
                    "Disassembly verification failed for {}: {:?}",
                    result.architecture.name, result.errors
                );
                assert!(
                    result.reflection_success,
                    "Reflection test failed for {}: {:?}",
                    result.architecture.name, result.errors
                );

                // Assert overall success
                assert!(
                    result.is_fully_successful(),
                    "Overall test failed for {} architecture with errors: {:?}",
                    result.architecture.name,
                    result.errors
                );
            }

            // Assert we tested both architectures
            let expected_arch_count = ArchConfig::platform_available_architectures().len();
            assert_eq!(
                results.len(),
                expected_arch_count,
                "Expected to test {} architectures",
                expected_arch_count
            );

            // Verify we have the expected architectures for this platform
            // On Windows: x86 + x64
            // On x86_64 Unix: anycpu + x64
            // On ARM64 Unix: anycpu only
            let arch_names: Vec<String> = results
                .iter()
                .map(|r| r.architecture.name.clone())
                .collect();
            #[cfg(target_os = "windows")]
            {
                assert!(
                    arch_names.contains(&"x86".to_string()),
                    "Missing x86 architecture test"
                );
                assert!(
                    arch_names.contains(&"x64".to_string()),
                    "Missing x64 architecture test"
                );
            }
            #[cfg(all(not(target_os = "windows"), target_arch = "x86_64"))]
            {
                assert!(
                    arch_names.contains(&"anycpu".to_string()),
                    "Missing anycpu architecture test"
                );
                assert!(
                    arch_names.contains(&"x64".to_string()),
                    "Missing x64 architecture test"
                );
            }
            #[cfg(all(not(target_os = "windows"), not(target_arch = "x86_64")))]
            {
                assert!(
                    arch_names.contains(&"anycpu".to_string()),
                    "Missing anycpu architecture test"
                );
            }

            Ok(())
        }

        #[test]
        fn test_mono_enhanced_modifications() -> Result<()> {
            // Create test environment using the new utilities
            let mut env = create_test_environment()?;

            // Test 1: String modification
            let string_results = test_string_modification(&mut env)?;

            // Test 2: Exception handling
            let exception_results = test_exception_handling(&mut env)?;

            // Assert string modification tests passed for both architectures
            for result in &string_results {
                assert!(
                    result.compilation_success,
                    "String test compilation failed for {}: {:?}",
                    result.architecture.name, result.errors
                );
                assert!(
                    result.modification_success,
                    "String test modification failed for {}: {:?}",
                    result.architecture.name, result.errors
                );
                assert!(
                    result.execution_success,
                    "String test execution failed for {}: {:?}",
                    result.architecture.name, result.errors
                );
                assert!(
                    result.compatibility_success,
                    "String test compatibility failed for {}: {:?}",
                    result.architecture.name, result.errors
                );
                assert!(
                    result.disassembly_success,
                    "String test disassembly failed for {}: {:?}",
                    result.architecture.name, result.errors
                );
                assert!(
                    result.reflection_success,
                    "String test reflection failed for {}: {:?}",
                    result.architecture.name, result.errors
                );
                assert!(
                    result.is_fully_successful(),
                    "String modification test failed for {} architecture: {:?}",
                    result.architecture.name,
                    result.errors
                );
            }

            // Assert exception handling tests passed for both architectures
            for result in &exception_results {
                assert!(
                    result.compilation_success,
                    "Exception test compilation failed for {}: {:?}",
                    result.architecture.name, result.errors
                );
                assert!(
                    result.modification_success,
                    "Exception test modification failed for {}: {:?}",
                    result.architecture.name, result.errors
                );
                assert!(
                    result.execution_success,
                    "Exception test execution failed for {}: {:?}",
                    result.architecture.name, result.errors
                );
                assert!(
                    result.compatibility_success,
                    "Exception test compatibility failed for {}: {:?}",
                    result.architecture.name, result.errors
                );
                assert!(
                    result.disassembly_success,
                    "Exception test disassembly failed for {}: {:?}",
                    result.architecture.name, result.errors
                );
                assert!(
                    result.reflection_success,
                    "Exception test reflection failed for {}: {:?}",
                    result.architecture.name, result.errors
                );
                assert!(
                    result.is_fully_successful(),
                    "Exception handling test failed for {} architecture: {:?}",
                    result.architecture.name,
                    result.errors
                );
            }

            // Assert both test suites covered the expected number of architectures
            // On ARM64, only AnyCPU is tested; on x86_64, both AnyCPU and x64 are tested
            let expected_arch_count = ArchConfig::platform_available_architectures().len();
            assert_eq!(
                string_results.len(),
                expected_arch_count,
                "Expected string tests to cover {} architectures",
                expected_arch_count
            );
            assert_eq!(
                exception_results.len(),
                expected_arch_count,
                "Expected exception tests to cover {} architectures",
                expected_arch_count
            );

            Ok(())
        }

        fn test_string_modification(env: &mut TestEnvironment) -> Result<Vec<CompleteTestResult>> {
            // Define the string modification assembly modification
            let modify_assembly = |context: &mut BuilderContext| -> Result<()> {
                // Create method that prints the modified message using Console.WriteLine
                let new_string = "MODIFIED: Hello from enhanced dotscope test!";
                let new_string_index = context.userstring_add(new_string)?;
                let new_string_token = Token::new(0x70000000 | new_string_index);

                // Find the assembly reference containing System.Console
                // .NET 8+ uses separate System.Console assembly, while older frameworks use mscorlib
                let console_assembly_ref = context
                    .find_assembly_ref_by_name("System.Console")
                    .or_else(|| context.find_core_library_ref())
                    .ok_or_else(|| {
                        Error::TypeError(
                            "Could not find System.Console or core library reference".to_string(),
                        )
                    })?;
                let console_assembly_token =
                    Token::new((TableId::AssemblyRef as u32) << 24 | console_assembly_ref.row);
                let console_writeline_ref =
                    create_console_writeline_ref(context, console_assembly_token)?;

                // Add a method that prints the modified string
                let new_string_token_copy = new_string_token;
                let console_writeline_ref_copy = console_writeline_ref;
                let _method_token = MethodBuilder::new("PrintModifiedMessage")
                    .public()
                    .static_method()
                    .returns(TypeSignature::Void)
                    .implementation(move |body| {
                        body.implementation(move |asm| {
                            asm.ldstr(new_string_token_copy)?
                                .call(console_writeline_ref_copy)?
                                .ret()?;
                            Ok(())
                        })
                    })
                    .build(context)?;

                Ok(())
            };

            // Define the reflection test for string modification
            let create_reflection_test = |assembly_path: &std::path::Path| -> String {
                ReflectionTestBuilder::new()
                    .assembly_path(assembly_path)
                    .test_method("PrintModifiedMessage")
                    .description("String modification test")
                    .expect_no_throw()
                    .build()
            };

            // Run the complete test workflow
            env.run_complete_test(
                compilation::templates::HELLO_WORLD,
                modify_assembly,
                create_reflection_test,
            )
        }

        fn test_exception_handling(env: &mut TestEnvironment) -> Result<Vec<CompleteTestResult>> {
            // Define the exception handling assembly modification
            let modify_assembly = |context: &mut BuilderContext| -> Result<()> {
                // Add a string for our success message
                let success_msg_index = context.userstring_add("Exception handler test PASSED!")?;
                let success_token = Token::new(0x70000000 | success_msg_index);

                // Create external references
                let mscorlib_ref = Token::new(0x23000001);
                let _console_writeline_ref = create_console_writeline_ref(context, mscorlib_ref)?;

                // Create a method with try/finally exception handling
                let success_token_copy = success_token;

                let _method_token = MethodBuilder::new("TestExceptionHandler")
                    .public()
                    .static_method()
                    .returns(TypeSignature::String)
                    .implementation(move |body| {
                        // Implement proper try/finally exception handling using the new label-based API
                        body.local("result", TypeSignature::String) // Add local variable to store result
                            .finally_handler_with_labels(
                                "try_start",
                                "try_end",
                                "finally_start",
                                "finally_end",
                            )
                            .implementation(move |asm| {
                                // Try block:
                                asm.label("try_start")? // Start of try block
                                    .ldstr(success_token_copy)? // Load success message
                                    .stloc_0()? // Store to local variable
                                    .leave_s("after_finally")? // Leave protected region
                                    .label("try_end")? // End of try block
                                    // Finally block:
                                    .label("finally_start")? // Start of finally handler
                                    .ldloc_0()? // Load from local (dummy operation)
                                    .stloc_0()? // Store back to local (dummy operation)
                                    .endfinally()? // End finally block
                                    .label("finally_end")? // End of finally handler
                                    // After finally:
                                    .label("after_finally")? // Continuation after finally
                                    .ldloc_0()? // Load result
                                    .ret()?; // Return result

                                Ok(())
                            })
                    })
                    .build(context)?;

                Ok(())
            };

            // Define the reflection test for exception handling
            let create_reflection_test = |assembly_path: &std::path::Path| -> String {
                ReflectionTestBuilder::new()
                    .assembly_path(assembly_path)
                    .test_method("TestExceptionHandler")
                    .description("Exception handler test")
                    .expect("Exception handler test PASSED!")
                    .build()
            };

            // Run the complete test workflow
            env.run_complete_test(
                compilation::templates::HELLO_WORLD,
                modify_assembly,
                create_reflection_test,
            )
        }

        fn create_writeline_signature() -> Result<Vec<u8>> {
            let signature = SignatureMethod {
                has_this: false, // Static method
                explicit_this: false,
                default: true, // Default managed calling convention
                vararg: false,
                cdecl: false,
                stdcall: false,
                thiscall: false,
                fastcall: false,
                param_count_generic: 0,
                param_count: 1, // One string parameter
                return_type: SignatureParameter {
                    modifiers: Vec::new(),
                    by_ref: false,
                    base: TypeSignature::Void, // void return type
                },
                params: vec![SignatureParameter {
                    modifiers: Vec::new(),
                    by_ref: false,
                    base: TypeSignature::String, // string parameter
                }],
                varargs: Vec::new(),
            };

            encode_method_signature(&signature)
        }

        fn create_console_writeline_ref(
            context: &mut BuilderContext,
            mscorlib_ref: Token,
        ) -> Result<Token> {
            // Create TypeRef for System.Console
            let console_typeref = TypeRefBuilder::new()
                .name("Console")
                .namespace("System")
                .resolution_scope(CodedIndex::new(
                    TableId::AssemblyRef,
                    mscorlib_ref.row(),
                    CodedIndexType::ResolutionScope,
                ))
                .build(context)?;

            // Create method signature for Console.WriteLine(string) using the working implementation
            let writeline_signature = create_writeline_signature()?;

            // Create MemberRef for Console.WriteLine method
            let memberref_token = MemberRefBuilder::new()
                .name("WriteLine")
                .class(CodedIndex::new(
                    TableId::TypeRef,
                    console_typeref.row(),
                    CodedIndexType::MemberRefParent,
                ))
                .signature(&writeline_signature)
                .build(context)?;

            Ok(memberref_token)
        }

        #[test]
        fn test_mono_mathematical_operations() -> Result<()> {
            // Test advanced mathematical operations and complex arithmetic
            let mut env = create_test_environment()?;

            let modify_assembly = |context: &mut BuilderContext| -> Result<()> {
                // Create method that performs multiple arithmetic operations
                let _complex_math_method = MethodBuilder::new("ComplexMath")
                    .public()
                    .static_method()
                    .parameter("x", TypeSignature::I4)
                    .parameter("y", TypeSignature::I4)
                    .returns(TypeSignature::I4)
                    .implementation(|body| {
                        body.implementation(|asm| {
                            // Calculate: (x * y) + (x - y) * 2
                            asm.ldarg_0()? // Load x
                                .ldarg_1()? // Load y
                                .mul()? // x * y
                                .ldarg_0()? // Load x again
                                .ldarg_1()? // Load y again
                                .sub()? // x - y
                                .ldc_i4_2()? // Load 2
                                .mul()? // (x - y) * 2
                                .add()? // (x * y) + ((x - y) * 2)
                                .ret()?;
                            Ok(())
                        })
                    })
                    .build(context)?;

                // Create method that performs division and modulo
                let _division_method = MethodBuilder::new("DivideAndRemainder")
                    .public()
                    .static_method()
                    .parameter("dividend", TypeSignature::I4)
                    .parameter("divisor", TypeSignature::I4)
                    .returns(TypeSignature::I4)
                    .implementation(|body| {
                        body.implementation(|asm| {
                            // Calculate: (dividend / divisor) + (dividend % divisor)
                            asm.ldarg_0()? // Load dividend
                                .ldarg_1()? // Load divisor
                                .div()? // dividend / divisor
                                .ldarg_0()? // Load dividend again
                                .ldarg_1()? // Load divisor again
                                .rem()? // dividend % divisor
                                .add()? // quotient + remainder
                                .ret()?;
                            Ok(())
                        })
                    })
                    .build(context)?;

                Ok(())
            };

            let create_reflection_test = |assembly_path: &std::path::Path| -> String {
                ReflectionTestBuilder::new()
                    .assembly_path(assembly_path)
                    .test_method("ComplexMath")
                    .description("ComplexMath(6, 3): (6*3) + (6-3)*2 = 18 + 6 = 24")
                    .parameters(vec![6, 3])
                    .expect(24)
                    .and()
                    .test_method("ComplexMath")
                    .description("ComplexMath(5, 2): (5*2) + (5-2)*2 = 10 + 6 = 16")
                    .parameters(vec![5, 2])
                    .expect(16)
                    .and()
                    .test_method("DivideAndRemainder")
                    .description("DivideAndRemainder(10, 3): (10/3) + (10%3) = 3 + 1 = 4")
                    .parameters(vec![10, 3])
                    .expect(4)
                    .and()
                    .test_method("DivideAndRemainder")
                    .description("DivideAndRemainder(15, 4): (15/4) + (15%4) = 3 + 3 = 6")
                    .parameters(vec![15, 4])
                    .expect(6)
                    .build()
            };

            let results = env.run_complete_test(
                compilation::templates::HELLO_WORLD,
                modify_assembly,
                create_reflection_test,
            )?;

            // Assert all tests passed
            for result in &results {
                assert!(
                    result.is_fully_successful(),
                    "Mathematical operations test failed for {} architecture: {:?}",
                    result.architecture.name,
                    result.errors
                );
            }

            let expected_arch_count = ArchConfig::platform_available_architectures().len();
            assert_eq!(
                results.len(),
                expected_arch_count,
                "Expected to test {} architectures",
                expected_arch_count
            );
            Ok(())
        }

        #[test]
        fn test_mono_local_variables_and_stack_operations() -> Result<()> {
            // Test local variable manipulation and stack operations
            let mut env = create_test_environment()?;

            let modify_assembly = |context: &mut BuilderContext| -> Result<()> {
                // Create method that demonstrates local variable usage
                let _local_vars_method = MethodBuilder::new("TestLocalVariables")
                    .public()
                    .static_method()
                    .parameter("input", TypeSignature::I4)
                    .returns(TypeSignature::I4)
                    .implementation(|body| {
                        body.local("temp1", TypeSignature::I4)
                            .local("temp2", TypeSignature::I4)
                            .implementation(|asm| {
                                // temp1 = input * 2
                                asm.ldarg_0()? // Load input
                                    .ldc_i4_2()? // Load 2
                                    .mul()? // input * 2
                                    .stloc_0()? // Store to temp1
                                    // temp2 = temp1 + 5
                                    .ldloc_0()? // Load temp1
                                    .ldc_i4_5()? // Load 5
                                    .add()? // temp1 + 5
                                    .stloc_1()? // Store to temp2
                                    // return temp2 - temp1
                                    .ldloc_1()? // Load temp2
                                    .ldloc_0()? // Load temp1
                                    .sub()? // temp2 - temp1
                                    .ret()?; // Return result
                                Ok(())
                            })
                    })
                    .build(context)?;

                // Create method that demonstrates stack manipulation
                let _stack_ops_method = MethodBuilder::new("StackOperations")
                    .public()
                    .static_method()
                    .parameter("a", TypeSignature::I4)
                    .parameter("b", TypeSignature::I4)
                    .returns(TypeSignature::I4)
                    .implementation(|body| {
                        body.implementation(|asm| {
                            // Demonstrate dup and pop operations
                            asm.ldarg_0()? // Load a
                                .dup()? // Duplicate a on stack
                                .ldarg_1()? // Load b
                                .add()? // (a + b), with 'a' still on stack
                                .add()? // a + (a + b) = 2a + b
                                .ret()?;
                            Ok(())
                        })
                    })
                    .build(context)?;

                Ok(())
            };

            let create_reflection_test = |assembly_path: &std::path::Path| -> String {
                ReflectionTestBuilder::new()
                    .assembly_path(assembly_path)
                    .test_method("TestLocalVariables")
                    .description("TestLocalVariables(3): temp1=6, temp2=11, result=5")
                    .parameters(vec![3])
                    .expect(5) // (3*2+5) - (3*2) = 11 - 6 = 5
                    .and()
                    .test_method("TestLocalVariables")
                    .description("TestLocalVariables(7): temp1=14, temp2=19, result=5")
                    .parameters(vec![7])
                    .expect(5) // (7*2+5) - (7*2) = 19 - 14 = 5
                    .and()
                    .test_method("StackOperations")
                    .description("StackOperations(4, 3): 2*4 + 3 = 11")
                    .parameters(vec![4, 3])
                    .expect(11) // 2*4 + 3 = 8 + 3 = 11
                    .and()
                    .test_method("StackOperations")
                    .description("StackOperations(2, 5): 2*2 + 5 = 9")
                    .parameters(vec![2, 5])
                    .expect(9) // 2*2 + 5 = 4 + 5 = 9
                    .build()
            };

            let results = env.run_complete_test(
                compilation::templates::HELLO_WORLD,
                modify_assembly,
                create_reflection_test,
            )?;

            // Assert all tests passed
            for result in &results {
                assert!(
                    result.is_fully_successful(),
                    "Local variables test failed for {} architecture: {:?}",
                    result.architecture.name,
                    result.errors
                );
            }

            let expected_arch_count = ArchConfig::platform_available_architectures().len();
            assert_eq!(
                results.len(),
                expected_arch_count,
                "Expected to test {} architectures",
                expected_arch_count
            );
            Ok(())
        }

        #[test]
        fn test_mono_multiple_method_cross_references() -> Result<()> {
            // Test multiple methods that call each other
            let mut env = create_test_environment()?;

            let modify_assembly = |context: &mut BuilderContext| -> Result<()> {
                // Create helper method that doubles a number
                let double_method = MethodBuilder::new("DoubleNumber")
                    .public()
                    .static_method()
                    .parameter("value", TypeSignature::I4)
                    .returns(TypeSignature::I4)
                    .implementation(|body| {
                        body.implementation(|asm| {
                            asm.ldarg_0()?.ldc_i4_2()?.mul()?.ret()?;
                            Ok(())
                        })
                    })
                    .build(context)?;

                // Create helper method that adds 10
                let add_ten_method = MethodBuilder::new("AddTen")
                    .public()
                    .static_method()
                    .parameter("value", TypeSignature::I4)
                    .returns(TypeSignature::I4)
                    .implementation(|body| {
                        body.implementation(|asm| {
                            asm.ldarg_0()?.ldc_i4_s(10)?.add()?.ret()?;
                            Ok(())
                        })
                    })
                    .build(context)?;

                // Create main method that calls both helpers: (x * 2) + 10
                let _main_method = MethodBuilder::new("ProcessNumber")
                    .public()
                    .static_method()
                    .parameter("input", TypeSignature::I4)
                    .returns(TypeSignature::I4)
                    .implementation(move |body| {
                        body.implementation(move |asm| {
                            asm.ldarg_0()? // Load input
                                .call(double_method)? // Call DoubleNumber
                                .call(add_ten_method)? // Call AddTen on result
                                .ret()?; // Return final result
                            Ok(())
                        })
                    })
                    .build(context)?;

                // Create iterative factorial method (avoids recursive call complexity)
                let _factorial_method = MethodBuilder::new("Factorial")
                    .public()
                    .static_method()
                    .parameter("n", TypeSignature::I4)
                    .returns(TypeSignature::I4)
                    .implementation(|body| {
                        body.local("result", TypeSignature::I4)
                            .local("counter", TypeSignature::I4)
                            .implementation(|asm| {
                                // Iterative factorial: result = 1; for(i=1; i<=n; i++) result *= i
                                asm.ldc_i4_1()? // Load 1
                                    .stloc_0()? // result = 1
                                    .ldc_i4_1()? // Load 1
                                    .stloc_1()? // counter = 1
                                    .label("loop_start")?
                                    .ldloc_1()? // Load counter
                                    .ldarg_0()? // Load n
                                    .bgt_s("loop_end")? // Branch if counter > n
                                    .ldloc_0()? // Load result
                                    .ldloc_1()? // Load counter
                                    .mul()? // result * counter
                                    .stloc_0()? // Store back to result
                                    .ldloc_1()? // Load counter
                                    .ldc_i4_1()? // Load 1
                                    .add()? // counter + 1
                                    .stloc_1()? // Store back to counter
                                    .br_s("loop_start")? // Continue loop
                                    .label("loop_end")?
                                    .ldloc_0()? // Load result
                                    .ret()?; // Return result
                                Ok(())
                            })
                    })
                    .build(context)?;

                Ok(())
            };

            let create_reflection_test = |assembly_path: &std::path::Path| -> String {
                ReflectionTestBuilder::new()
                    .assembly_path(assembly_path)
                    .test_method("DoubleNumber")
                    .description("Double 7 = 14")
                    .parameters(vec![7])
                    .expect(14)
                    .and()
                    .test_method("AddTen")
                    .description("Add 10 to 5 = 15")
                    .parameters(vec![5])
                    .expect(15)
                    .and()
                    .test_method("ProcessNumber")
                    .description("Process 3: (3*2)+10 = 16")
                    .parameters(vec![3])
                    .expect(16)
                    .and()
                    .test_method("Factorial")
                    .description("Factorial of 5 = 120")
                    .parameters(vec![5])
                    .expect(120)
                    .and()
                    .test_method("Factorial")
                    .description("Factorial of 1 = 1")
                    .parameters(vec![1])
                    .expect(1)
                    .build()
            };

            let results = env.run_complete_test(
                compilation::templates::HELLO_WORLD,
                modify_assembly,
                create_reflection_test,
            )?;

            // Assert all tests passed
            for result in &results {
                assert!(
                    result.is_fully_successful(),
                    "Cross-reference test failed for {} architecture: {:?}",
                    result.architecture.name,
                    result.errors
                );
            }

            let expected_arch_count = ArchConfig::platform_available_architectures().len();
            assert_eq!(
                results.len(),
                expected_arch_count,
                "Expected to test {} architectures",
                expected_arch_count
            );
            Ok(())
        }

        #[test]
        fn test_mono_blob_heap_and_complex_signatures() -> Result<()> {
            // Test blob heap modifications with complex method signatures
            let mut env = create_test_environment()?;

            let modify_assembly = |context: &mut BuilderContext| -> Result<()> {
                // Create method with multiple parameters of different types
                let _complex_method = MethodBuilder::new("ComplexMethod")
                    .public()
                    .static_method()
                    .parameter("intParam", TypeSignature::I4)
                    .parameter("stringParam", TypeSignature::String)
                    .parameter("boolParam", TypeSignature::Boolean)
                    .returns(TypeSignature::String)
                    .implementation(|body| {
                        body.local("result", TypeSignature::String)
                            .implementation(|asm| {
                                // Create a formatted string result
                                asm.ldstr(Token::new(0x70000001))? // Assume string token exists
                                    .stloc_0()?
                                    .ldloc_0()?
                                    .ret()?;
                                Ok(())
                            })
                    })
                    .build(context)?;

                // Add a string to the userstring heap for the method above
                let result_string_index =
                    context.userstring_add("ComplexMethod executed successfully")?;
                let _result_string_token = Token::new(0x70000000 | result_string_index);

                // Create method that demonstrates different parameter passing
                let _param_test_method = MethodBuilder::new("TestParameters")
                    .public()
                    .static_method()
                    .parameter("a", TypeSignature::I4)
                    .parameter("b", TypeSignature::I4)
                    .parameter("c", TypeSignature::I4)
                    .returns(TypeSignature::I4)
                    .implementation(|body| {
                        body.implementation(|asm| {
                            // Test: (a + b) * c
                            asm.ldarg_0()? // Load a
                                .ldarg_1()? // Load b
                                .add()? // a + b
                                .ldarg_2()? // Load c
                                .mul()? // (a + b) * c
                                .ret()?; // Return result
                            Ok(())
                        })
                    })
                    .build(context)?;

                // Create method that tests boolean logic
                let _bool_method = MethodBuilder::new("BooleanLogic")
                    .public()
                    .static_method()
                    .parameter("flag1", TypeSignature::Boolean)
                    .parameter("flag2", TypeSignature::Boolean)
                    .returns(TypeSignature::Boolean)
                    .implementation(|body| {
                        body.implementation(|asm| {
                            // Test: flag1 AND flag2
                            asm.ldarg_0()? // Load flag1
                                .ldarg_1()? // Load flag2
                                .and()? // flag1 AND flag2
                                .ret()?; // Return result
                            Ok(())
                        })
                    })
                    .build(context)?;

                Ok(())
            };

            let create_reflection_test = |assembly_path: &std::path::Path| -> String {
                ReflectionTestBuilder::new()
                    .assembly_path(assembly_path)
                    .test_method("TestParameters")
                    .description("Test (2+3)*4 = 20")
                    .parameters(vec![
                        ParameterValue::Int32(2),
                        ParameterValue::Int32(3),
                        ParameterValue::Int32(4),
                    ])
                    .expect(20)
                    .and()
                    .test_method("TestParameters")
                    .description("Test (10+5)*2 = 30")
                    .parameters(vec![
                        ParameterValue::Int32(10),
                        ParameterValue::Int32(5),
                        ParameterValue::Int32(2),
                    ])
                    .expect(30)
                    .and()
                    .test_method("BooleanLogic")
                    .description("Test true AND false = false")
                    .parameters(vec![
                        ParameterValue::Boolean(true),
                        ParameterValue::Boolean(false),
                    ])
                    .expect(false)
                    .and()
                    .test_method("BooleanLogic")
                    .description("Test true AND true = true")
                    .parameters(vec![
                        ParameterValue::Boolean(true),
                        ParameterValue::Boolean(true),
                    ])
                    .expect(true)
                    .build()
            };

            let results = env.run_complete_test(
                compilation::templates::HELLO_WORLD,
                modify_assembly,
                create_reflection_test,
            )?;

            // Assert all tests passed
            for result in &results {
                assert!(
                    result.is_fully_successful(),
                    "Blob heap/Complex signature test failed for {} architecture: {:?}",
                    result.architecture.name,
                    result.errors
                );
            }

            let expected_arch_count = ArchConfig::platform_available_architectures().len();
            assert_eq!(
                results.len(),
                expected_arch_count,
                "Expected to test {} architectures",
                expected_arch_count
            );
            Ok(())
        }
    }
}
