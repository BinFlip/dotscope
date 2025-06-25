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
//! - Modifications are tracked separately in [`crate::cilassembly::changes::assembly::AssemblyChanges`]
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
//! ## **Change Tracking ([`crate::cilassembly::changes::assembly::AssemblyChanges`])**
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
//! - [`crate::cilassembly::changes::assembly::AssemblyChanges`] - Central change tracking
//! - [`crate::cilassembly::changes::heap::HeapChanges`] - Heap modification tracking
//! - [`crate::cilassembly::modifications::TableModifications`] - Table change strategies
//! - [`crate::cilassembly::operation::TableOperation`] - Timestamped operations
//! - [`crate::cilassembly::operation::Operation`] - Operation variants
//!
//! ## **Validation ([`crate::cilassembly::validation`])**
//! Consolidated module containing all validation logic:
//! - [`crate::cilassembly::validation::ValidationPipeline`] - Configurable validation stages
//! - [`crate::cilassembly::validation::ValidationStage`] - Individual validation trait
//! - [`crate::cilassembly::validation::ConflictResolver`] - Conflict resolution strategies
//! - [`crate::cilassembly::validation::Conflict`] & [`crate::cilassembly::validation::Resolution`] - Conflict types and results
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
//! let view = CilAssemblyView::from_file(Path::new("assembly.dll"))?;
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
    metadata::{
        cilassemblyview::CilAssemblyView,
        tables::{TableDataOwned, TableId},
    },
    Result,
};

mod builder;
mod changes;
mod modifications;
mod operation;
mod remapping;
mod validation;
mod write;

pub use builder::*;

use self::{
    changes::{AssemblyChanges, HeapChanges},
    modifications::TableModifications,
    operation::{Operation, TableOperation},
    remapping::IndexRemapper,
    validation::ValidationPipeline,
};

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
    /// let view = CilAssemblyView::from_file(Path::new("assembly.dll"))?;
    /// let assembly = CilAssembly::new(view);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
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
    /// # let view = CilAssemblyView::from_file(&Path::new("assembly.dll"))?;
    /// let mut assembly = CilAssembly::new(view);
    ///
    /// let hello_index = assembly.add_string("Hello")?;
    /// let world_index = assembly.add_string("World")?;
    ///
    /// assert!(world_index > hello_index);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn add_string(&mut self, value: &str) -> Result<u32> {
        let string_changes = &mut self.changes.string_heap_changes;
        let index = string_changes.next_index;
        string_changes.appended_items.push(value.to_string());
        // Strings are null-terminated, so increment by string length + 1 for null terminator
        string_changes.next_index += value.len() as u32 + 1;

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
    pub fn add_blob(&mut self, data: &[u8]) -> Result<u32> {
        let blob_changes = &mut self.changes.blob_heap_changes;
        let index = blob_changes.next_index;
        blob_changes.appended_items.push(data.to_vec());

        // Blobs have compressed length prefix + data
        let length = data.len();
        let prefix_size = if length < 128 {
            1
        } else if length < 16384 {
            2
        } else {
            4
        };
        blob_changes.next_index += prefix_size + length as u32;

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
    /// # let view = CilAssemblyView::from_file(&Path::new("assembly.dll"))?;
    /// let mut assembly = CilAssembly::new(view);
    ///
    /// let guid = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
    ///             0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
    /// let guid_index = assembly.add_guid(&guid)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn add_guid(&mut self, guid: &[u8; 16]) -> Result<u32> {
        let guid_changes = &mut self.changes.guid_heap_changes;
        let index = guid_changes.next_index;
        guid_changes.appended_items.push(*guid);
        // GUIDs are fixed 16 bytes each
        guid_changes.next_index += 16;

        Ok(index)
    }

    /// Adds a user string to the user string heap (#US) and returns its index.
    ///
    /// The user string is appended to the user string heap (#US), maintaining
    /// the original heap structure. User strings are used for string literals
    /// in IL code (e.g., `ldstr` instruction operands) and are stored with
    /// length prefixes and UTF-16 encoding when written to the binary.
    ///
    /// **Note**: User strings in the #US heap are UTF-16 encoded with compressed
    /// length prefixes when written to the binary. This method stores
    /// the logical string value during the editing phase.
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
    /// # let view = CilAssemblyView::from_file(&Path::new("assembly.dll"))?;
    /// let mut assembly = CilAssembly::new(view);
    ///
    /// let userstring_index = assembly.add_userstring("Hello, World!")?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn add_userstring(&mut self, value: &str) -> Result<u32> {
        let userstring_changes = &mut self.changes.userstring_heap_changes;
        let index = userstring_changes.next_index;
        userstring_changes.appended_items.push(value.to_string());

        // User strings are UTF-16 encoded with compressed length prefix
        let utf16_bytes: Vec<u8> = value.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        let length = utf16_bytes.len();

        // Calculate compressed length prefix size + UTF-16 data length
        let prefix_size = if length < 128 {
            1
        } else if length < 16384 {
            2
        } else {
            4
        };
        userstring_changes.next_index += prefix_size + length as u32;

        Ok(index)
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
    pub fn add_table_row(&mut self, table_id: TableId, row: TableDataOwned) -> Result<u32> {
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
                let new_rid = rows.len() as u32 + 1;
                rows.push(row);
                Ok(new_rid)
            }
        }
    }

    /// Validates all pending changes and applies index remapping.
    ///
    /// This method runs the complete validation pipeline and resolves any
    /// conflicts found in the pending operations. It should be called before
    /// writing the assembly to ensure metadata consistency.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if all validations pass and conflicts are resolved,
    /// or an error describing the first validation failure.
    pub fn validate_and_apply_changes(&mut self) -> Result<()> {
        let remapper = {
            let pipeline = ValidationPipeline::default();
            pipeline.validate(&self.changes, &self.view)?;

            IndexRemapper::build_from_changes(&self.changes, &self.view)
        };

        remapper.apply_to_assembly(&mut self.changes)?;

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
    pub fn write_to_file<P: AsRef<std::path::Path>>(&self, path: P) -> Result<()> {
        write::write_assembly_to_file(self, path)
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

    /// Gets a reference to the changes for write operations.
    pub fn changes(&self) -> &AssemblyChanges {
        &self.changes
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
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::metadata::{
        tables::{CodedIndex, TableDataOwned, TableId, TypeDefRaw},
        token::Token,
    };

    /// Helper function to create a minimal TypeDef row for testing
    fn create_test_typedef_row() -> Result<TableDataOwned> {
        Ok(TableDataOwned::TypeDef(TypeDefRaw {
            rid: 0,                        // Will be set by the system
            token: Token::new(0x02000000), // Will be updated by the system
            offset: 0,                     // Will be set during binary generation
            flags: 0,
            type_name: 1,                                  // Placeholder string index
            type_namespace: 0,                             // Empty namespace
            extends: CodedIndex::new(TableId::TypeRef, 0), // No base type (0 = null reference)
            field_list: 1,                                 // Placeholder field list
            method_list: 1,                                // Placeholder method list
        }))
    }

    #[test]
    fn test_convert_from_view() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let _assembly = CilAssembly::new(view);
            // Basic smoke test - conversion should succeed
        }
    }

    #[test]
    fn test_add_string() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let mut assembly = CilAssembly::new(view);

            let index1 = assembly.add_string("Hello").unwrap();
            let index2 = assembly.add_string("World").unwrap();

            assert_ne!(index1, index2);
            assert!(index2 > index1);
        }
    }

    #[test]
    fn test_add_blob() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let mut assembly = CilAssembly::new(view);

            let index1 = assembly.add_blob(&[1, 2, 3]).unwrap();
            let index2 = assembly.add_blob(&[4, 5, 6]).unwrap();

            assert_ne!(index1, index2);
            assert!(index2 > index1);
        }
    }

    #[test]
    fn test_add_guid() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let mut assembly = CilAssembly::new(view);

            let guid1 = [
                0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
                0x77, 0x88,
            ];
            let guid2 = [
                0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                0x88, 0x99,
            ];

            let index1 = assembly.add_guid(&guid1).unwrap();
            let index2 = assembly.add_guid(&guid2).unwrap();

            assert_ne!(index1, index2);
            assert!(index2 > index1);
        }
    }

    #[test]
    fn test_add_userstring() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let mut assembly = CilAssembly::new(view);

            let index1 = assembly.add_userstring("Hello").unwrap();
            let index2 = assembly.add_userstring("World").unwrap();

            assert_ne!(index1, index2);
            assert!(index2 > index1);
        }
    }

    #[test]
    fn test_table_row_assignment_uses_correct_rid() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let mut assembly = CilAssembly::new(view);

            // Get original table size to verify RID calculation
            let original_typedef_count = assembly.original_table_row_count(TableId::TypeDef);

            // Create a minimal TypeDef row for testing
            if let Ok(typedef_row) = create_test_typedef_row() {
                // Add table row should assign RID = original_count + 1
                if let Ok(rid) = assembly.add_table_row(TableId::TypeDef, typedef_row) {
                    assert_eq!(
                        rid,
                        original_typedef_count + 1,
                        "RID should be original count + 1"
                    );

                    // Add another row should get sequential RID
                    if let Ok(typedef_row2) = create_test_typedef_row() {
                        if let Ok(rid2) = assembly.add_table_row(TableId::TypeDef, typedef_row2) {
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
        if let Ok(view) = CilAssemblyView::from_file(&path) {
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
                        assert!(
                            e.to_string().contains("Invalid RID"),
                            "Should be RID validation error: {}",
                            e
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn test_heap_sizes_are_real() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
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
}
