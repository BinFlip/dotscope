//! High-level builder APIs.
//!
//! This module provides builder patterns for creating complex metadata
//! structures with automatic cross-reference resolution and validation.
//!
//! # Architecture
//!
//! The builder system centers around [`BuilderContext`], which coordinates
//! all builder operations and provides:
//! - RID management for all tables
//! - Cross-reference validation
//! - Heap management for strings/blobs
//! - Dependency ordering
//!
//! Individual builders for each table type provide fluent APIs for
//! creating metadata rows with type safety and validation.

use std::collections::HashMap;

use crate::{
    metadata::{
        cilassembly::CilAssembly,
        tables::{AssemblyRefRaw, CodedIndex, TableDataOwned, TableId},
        token::Token,
    },
    Result,
};

/// Central coordination context for all builder operations.
///
/// `BuilderContext` serves as the coordination hub for all metadata creation
/// operations, managing RID allocation, cross-reference validation, and
/// integration with the underlying [`CilAssembly`] infrastructure.
///
/// # Key Responsibilities
///
/// - **RID Management**: Track next available RIDs for each table
/// - **Cross-Reference Validation**: Ensure referenced entities exist
/// - **Heap Management**: Add strings/blobs and return indices
/// - **Conflict Detection**: Prevent duplicate entries
/// - **Dependency Ordering**: Ensure dependencies are created first
///
/// # Usage
///
/// ```rust,no_run
/// # use dotscope::{CilAssembly, CilAssemblyView};
/// # use dotscope::metadata::cilassembly::BuilderContext;
/// # use std::path::Path;
/// # let view = CilAssemblyView::from_file(Path::new("test.dll"))?;
/// let mut assembly = CilAssembly::new(view);
/// let mut context = BuilderContext::new(&mut assembly);
///
/// // Use builders through the context
/// // let assembly_token = AssemblyBuilder::new(&mut context)...
/// # Ok::<(), dotscope::Error>(())
/// ```
pub struct BuilderContext<'a> {
    /// Reference to the mutable assembly being modified
    assembly: &'a mut CilAssembly,

    /// Track next available RIDs for each table
    next_rids: HashMap<TableId, u32>,
}

impl<'a> BuilderContext<'a> {
    /// Creates a new builder context for the given assembly.
    ///
    /// This initializes the RID tracking by examining the current state
    /// of all tables in the assembly to determine the next available RID
    /// for each table type. Only tables that actually exist in the loaded
    /// assembly are initialized.
    ///
    /// # Arguments
    ///
    /// * `assembly` - Mutable reference to the assembly to modify
    ///
    /// # Returns
    ///
    /// A new [`BuilderContext`] ready for builder operations.
    pub fn new(assembly: &'a mut CilAssembly) -> Self {
        let mut next_rids = HashMap::new();
        if let Some(tables) = assembly.view.tables() {
            for table_id in tables.present_tables() {
                let existing_count = assembly.original_table_row_count(table_id);
                next_rids.insert(table_id, existing_count + 1);
            }
        }

        Self {
            assembly,
            next_rids,
        }
    }

    /// Adds a string to the assembly's string heap and returns its index.
    ///
    /// This is a convenience method that delegates to the underlying
    /// [`CilAssembly::add_string`] method.
    ///
    /// # Arguments
    ///
    /// * `value` - The string to add to the heap
    ///
    /// # Returns
    ///
    /// The heap index that can be used to reference this string.
    pub fn add_string(&mut self, value: &str) -> Result<u32> {
        self.assembly.add_string(value)
    }

    /// Gets or adds a string to the assembly's string heap, reusing existing strings when possible.
    ///
    /// This method first checks if the string already exists in the heap changes
    /// (within this builder session) and reuses it if found. This helps avoid
    /// duplicate namespace strings and other common strings.
    ///
    /// # Arguments
    ///
    /// * `value` - The string to get or add to the heap
    ///
    /// # Returns
    ///
    /// The heap index that can be used to reference this string.
    pub fn get_or_add_string(&mut self, value: &str) -> Result<u32> {
        if let Some(existing_index) = self.find_existing_string(value) {
            return Ok(existing_index);
        }

        self.add_string(value)
    }

    /// Helper method to find an existing string in the current heap changes.
    ///
    /// This searches through the strings added in the current builder session
    /// to avoid duplicates within the same session.
    fn find_existing_string(&self, value: &str) -> Option<u32> {
        let heap_changes = &self.assembly.changes.string_heap_changes;

        for (index, existing_string) in heap_changes.appended_items.iter().enumerate() {
            if existing_string == value {
                // Convert 0-based index to heap index (accounting for original heap size)
                let heap_size = self.assembly.original_heap_size_string();
                return Some(heap_size + index as u32 + 1);
            }
        }

        None
    }

    /// Adds a blob to the assembly's blob heap and returns its index.
    ///
    /// This is a convenience method that delegates to the underlying
    /// [`CilAssembly::add_blob`] method.
    ///
    /// # Arguments
    ///
    /// * `data` - The blob data to add to the heap
    ///
    /// # Returns
    ///
    /// The heap index that can be used to reference this blob.
    pub fn add_blob(&mut self, data: &[u8]) -> Result<u32> {
        self.assembly.add_blob(data)
    }

    /// Adds a GUID to the assembly's GUID heap and returns its index.
    ///
    /// This is a convenience method that delegates to the underlying
    /// [`CilAssembly::add_guid`] method.
    ///
    /// # Arguments
    ///
    /// * `guid` - The 16-byte GUID to add to the heap
    ///
    /// # Returns
    ///
    /// The heap index that can be used to reference this GUID.
    pub fn add_guid(&mut self, guid: &[u8; 16]) -> Result<u32> {
        self.assembly.add_guid(guid)
    }

    /// Adds a user string to the assembly's user string heap and returns its index.
    ///
    /// This is a convenience method that delegates to the underlying
    /// [`CilAssembly::add_userstring`] method.
    ///
    /// # Arguments
    ///
    /// * `value` - The string to add to the user string heap
    ///
    /// # Returns
    ///
    /// The heap index that can be used to reference this user string.
    pub fn add_userstring(&mut self, value: &str) -> Result<u32> {
        self.assembly.add_userstring(value)
    }

    /// Allocates the next available RID for a table and adds the row.
    ///
    /// This method coordinates RID allocation with the underlying assembly
    /// to ensure no conflicts occur and all RIDs are properly tracked.
    ///
    /// # Arguments
    ///
    /// * `table_id` - The table to add the row to
    /// * `row` - The row data to add
    ///
    /// # Returns
    ///
    /// The RID (Row ID) assigned to the newly created row as a [`Token`].
    pub fn add_table_row(&mut self, table_id: TableId, row: TableDataOwned) -> Result<Token> {
        let rid = self.assembly.add_table_row(table_id, row)?;

        self.next_rids.insert(table_id, rid + 1);

        let token_value = ((table_id as u32) << 24) | rid;
        Ok(Token::new(token_value))
    }

    /// Gets the next available RID for a given table.
    ///
    /// This is useful for builders that need to know what RID will be
    /// assigned before actually creating the row.
    ///
    /// # Arguments
    ///
    /// * `table_id` - The table to query
    ///
    /// # Returns
    ///
    /// The next RID that would be assigned for this table.
    pub fn next_rid(&self, table_id: TableId) -> u32 {
        self.next_rids.get(&table_id).copied().unwrap_or(1)
    }

    /// Finds an AssemblyRef by its name.
    ///
    /// This method searches the AssemblyRef table to find an assembly reference
    /// with the specified name. This is useful for locating specific dependencies
    /// or core libraries.
    ///
    /// # Arguments
    ///
    /// * `name` - The exact name of the assembly to find (case-sensitive)
    ///
    /// # Returns
    ///
    /// A [`CodedIndex`] pointing to the matching AssemblyRef, or None if not found.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use dotscope::metadata::cilassembly::BuilderContext;
    /// # let mut context: BuilderContext = todo!();
    /// // Find a specific library
    /// if let Some(newtonsoft_ref) = context.find_assembly_ref_by_name("Newtonsoft.Json") {
    ///     println!("Found Newtonsoft.Json reference");
    /// }
    ///
    /// // Find core library
    /// if let Some(mscorlib_ref) = context.find_assembly_ref_by_name("mscorlib") {
    ///     println!("Found mscorlib reference");
    /// }
    /// ```
    pub fn find_assembly_ref_by_name(&self, name: &str) -> Option<CodedIndex> {
        if let (Some(assmebly_ref_table), Some(strings)) = (
            self.assembly.view.tables()?.table::<AssemblyRefRaw>(),
            self.assembly.view.strings(),
        ) {
            for (index, assemblyref) in assmebly_ref_table.iter().enumerate() {
                if let Ok(assembly_name) = strings.get(assemblyref.name as usize) {
                    if assembly_name == name {
                        // Convert 0-based index to 1-based RID
                        return Some(CodedIndex::new(TableId::AssemblyRef, (index + 1) as u32));
                    }
                }
            }
        }

        None
    }

    /// Finds the AssemblyRef RID for the core library.
    ///
    /// This method searches the AssemblyRef table to find the core library
    /// reference, which can be any of:
    /// - "mscorlib" (classic .NET Framework)
    /// - "System.Runtime" (.NET Core/.NET 5+)
    /// - "System.Private.CoreLib" (some .NET implementations)
    ///
    /// This is a convenience method that uses [`find_assembly_ref_by_name`] internally.
    ///
    /// # Returns
    ///
    /// A [`CodedIndex`] pointing to the core library AssemblyRef, or None if not found.
    pub fn find_core_library_ref(&self) -> Option<CodedIndex> {
        self.find_assembly_ref_by_name("mscorlib")
            .or_else(|| self.find_assembly_ref_by_name("System.Runtime"))
            .or_else(|| self.find_assembly_ref_by_name("System.Private.CoreLib"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::cilassemblyview::CilAssemblyView;
    use std::path::PathBuf;

    #[test]
    fn test_builder_context_creation() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let mut assembly = CilAssembly::new(view);

            // Check existing table counts
            let assembly_count = assembly.original_table_row_count(TableId::Assembly);
            let typedef_count = assembly.original_table_row_count(TableId::TypeDef);
            let typeref_count = assembly.original_table_row_count(TableId::TypeRef);

            let context = BuilderContext::new(&mut assembly);

            // Verify context is created successfully and RIDs are correct
            assert_eq!(context.next_rid(TableId::Assembly), assembly_count + 1);
            assert_eq!(context.next_rid(TableId::TypeDef), typedef_count + 1);
            assert_eq!(context.next_rid(TableId::TypeRef), typeref_count + 1);
        }
    }

    #[test]
    fn test_builder_context_heap_operations() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let mut assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(&mut assembly);

            // Test string heap operations
            let string_idx = context.add_string("TestString").unwrap();
            assert!(string_idx > 0);

            // Test blob heap operations
            let blob_idx = context.add_blob(&[1, 2, 3, 4]).unwrap();
            assert!(blob_idx > 0);

            // Test GUID heap operations
            let guid = [
                0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
                0x77, 0x88,
            ];
            let guid_idx = context.add_guid(&guid).unwrap();
            assert!(guid_idx > 0);

            // Test user string heap operations
            let userstring_idx = context.add_userstring("User String").unwrap();
            assert!(userstring_idx > 0);
        }
    }

    #[test]
    fn test_builder_context_string_deduplication() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let mut assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(&mut assembly);

            // Add the same namespace string multiple times
            let namespace1 = context.get_or_add_string("MyNamespace").unwrap();
            let namespace2 = context.get_or_add_string("MyNamespace").unwrap();
            let namespace3 = context.get_or_add_string("MyNamespace").unwrap();

            // All should return the same index (deduplication working)
            assert_eq!(namespace1, namespace2);
            assert_eq!(namespace2, namespace3);

            // Different strings should get different indices
            let different_namespace = context.get_or_add_string("DifferentNamespace").unwrap();
            assert_ne!(namespace1, different_namespace);

            // Verify the regular add_string method still creates duplicates
            let duplicate1 = context.add_string("DuplicateTest").unwrap();
            let duplicate2 = context.add_string("DuplicateTest").unwrap();
            assert_ne!(duplicate1, duplicate2); // Should be different indices

            // But get_or_add_string should reuse existing ones
            let reused = context.get_or_add_string("DuplicateTest").unwrap();
            assert_eq!(reused, duplicate1); // Should match the first one added
        }
    }

    #[test]
    fn test_builder_context_dynamic_table_discovery() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let mut assembly = CilAssembly::new(view);

            // Get the expected present tables before creating the context
            let expected_tables: Vec<_> = if let Some(tables) = assembly.view.tables() {
                tables.present_tables().collect()
            } else {
                vec![]
            };

            let context = BuilderContext::new(&mut assembly);

            // Verify that we discover tables dynamically from the actual assembly
            // WindowsBase.dll should have these common tables
            assert!(context.next_rids.contains_key(&TableId::Assembly));
            assert!(context.next_rids.contains_key(&TableId::TypeDef));
            assert!(context.next_rids.contains_key(&TableId::TypeRef));
            assert!(context.next_rids.contains_key(&TableId::MethodDef));
            assert!(context.next_rids.contains_key(&TableId::Field));

            // The RIDs should be greater than 1 (since existing tables have content)
            assert!(*context.next_rids.get(&TableId::TypeDef).unwrap_or(&0) > 1);
            assert!(*context.next_rids.get(&TableId::MethodDef).unwrap_or(&0) > 1);

            // Count how many tables were discovered
            let discovered_table_count = context.next_rids.len();

            // Should be more than just the hardcoded ones (shows dynamic discovery working)
            assert!(
                discovered_table_count > 5,
                "Expected more than 5 tables, found {}",
                discovered_table_count
            );

            // Verify tables match what's actually in the assembly
            assert_eq!(
                context.next_rids.len(),
                expected_tables.len(),
                "BuilderContext should track exactly the same tables as present in assembly"
            );

            for table_id in expected_tables {
                assert!(
                    context.next_rids.contains_key(&table_id),
                    "BuilderContext missing table {:?} that exists in assembly",
                    table_id
                );
            }
        }
    }

    #[test]
    fn test_builder_context_assembly_ref_lookup() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let mut assembly = CilAssembly::new(view);
            let context = BuilderContext::new(&mut assembly);

            // Test general assembly reference lookup - try common assembly names
            // WindowsBase.dll might reference System, System.Core, etc. instead of mscorlib directly
            let system_ref = context.find_assembly_ref_by_name("System.Runtime");
            let system_core_ref = context.find_assembly_ref_by_name("CoreLib");
            let mscorlib_ref = context.find_assembly_ref_by_name("mscorlib");

            // At least one of these should exist in WindowsBase.dll
            let found_any =
                system_ref.is_some() || system_core_ref.is_some() || mscorlib_ref.is_some();
            assert!(
                found_any,
                "Should find at least one common assembly reference in WindowsBase.dll"
            );

            // Test any found reference
            if let Some(ref_info) = system_ref.or(system_core_ref).or(mscorlib_ref) {
                assert_eq!(ref_info.tag, TableId::AssemblyRef);
                assert!(ref_info.row > 0, "Assembly reference RID should be > 0");
            }

            // Test lookup for non-existent assembly
            let nonexistent_ref = context.find_assembly_ref_by_name("NonExistentAssembly");
            assert!(
                nonexistent_ref.is_none(),
                "Should not find non-existent assembly reference"
            );

            // Test with empty string
            let empty_ref = context.find_assembly_ref_by_name("");
            assert!(
                empty_ref.is_none(),
                "Should not find assembly reference for empty string"
            );
        }
    }

    #[test]
    fn test_builder_context_core_library_lookup() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let mut assembly = CilAssembly::new(view);
            let context = BuilderContext::new(&mut assembly);

            // Should find mscorlib (WindowsBase.dll is a .NET Framework assembly)
            let core_lib_ref = context.find_core_library_ref();
            assert!(
                core_lib_ref.is_some(),
                "Should find core library reference in WindowsBase.dll"
            );

            if let Some(core_ref) = core_lib_ref {
                assert_eq!(core_ref.tag, TableId::AssemblyRef);
                assert!(core_ref.row > 0, "Core library RID should be > 0");

                // Verify that the core library lookup is equivalent to the specific lookup
                let specific_mscorlib = context.find_assembly_ref_by_name("mscorlib");
                if specific_mscorlib.is_some() {
                    assert_eq!(
                        core_ref.row,
                        specific_mscorlib.unwrap().row,
                        "Core library lookup should match specific mscorlib lookup"
                    );
                }
            }
        }
    }
}
