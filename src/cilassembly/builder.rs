//! High-level builder APIs.
//!
//! This module provides builder patterns for creating complex metadata
//! structures with automatic cross-reference resolution and validation.
//!
//! # Key Components
//!
//! - [`crate::cilassembly::builder::BuilderContext`] - Central coordination context for all builder operations
//!
//! # Architecture
//!
//! The builder system centers around [`crate::cilassembly::builder::BuilderContext`], which coordinates
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
    cilassembly::CilAssembly,
    metadata::{
        signatures::{
            encode_field_signature, encode_local_var_signature, encode_method_signature,
            encode_property_signature, encode_typespec_signature, SignatureField,
            SignatureLocalVariables, SignatureMethod, SignatureProperty, SignatureTypeSpec,
        },
        tables::{AssemblyRefRaw, CodedIndex, TableDataOwned, TableId},
        token::Token,
    },
    Result,
};

/// Central coordination context for all builder operations.
///
/// `BuilderContext` serves as the coordination hub for all metadata creation
/// operations, managing RID allocation, cross-reference validation, and
/// integration with the underlying [`crate::cilassembly::CilAssembly`] infrastructure.
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
/// ```rust,ignore
/// # use dotscope::prelude::*;
/// # use std::path::Path;
/// # let view = CilAssemblyView::from_file(Path::new("test.dll"))?;
/// let assembly = CilAssembly::new(view);
/// let mut context = BuilderContext::new(assembly);
///
/// // Use builders through the context
/// // let assembly_token = AssemblyBuilder::new(&mut context)...
///
/// // Get the assembly back when done
/// let assembly = context.finish();
/// # Ok::<(), dotscope::Error>(())
/// ```
pub struct BuilderContext {
    /// Owned assembly being modified
    assembly: CilAssembly,

    /// Track next available RIDs for each table
    next_rids: HashMap<TableId, u32>,
}

impl BuilderContext {
    /// Creates a new builder context for the given assembly.
    ///
    /// This takes ownership of the assembly and initializes the RID tracking
    /// by examining the current state of all tables in the assembly to determine
    /// the next available RID for each table type. Only tables that actually
    /// exist in the loaded assembly are initialized.
    ///
    /// # Arguments
    ///
    /// * `assembly` - Assembly to take ownership of and modify
    ///
    /// # Returns
    ///
    /// A new [`crate::cilassembly::builder::BuilderContext`] ready for builder operations.
    pub fn new(assembly: CilAssembly) -> Self {
        let mut next_rids = HashMap::new();
        if let Some(tables) = assembly.view().tables() {
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

    /// Finishes the building process and returns ownership of the assembly.
    ///
    /// This consumes the [`crate::cilassembly::builder::BuilderContext`] and returns the owned [`crate::cilassembly::CilAssembly`]
    /// with all modifications applied. After calling this method, the context
    /// can no longer be used, and the assembly can be written to disk or
    /// used for other operations.
    ///
    /// # Returns
    ///
    /// The owned [`crate::cilassembly::CilAssembly`] with all builder modifications applied.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// # use dotscope::prelude::*;
    /// # use std::path::Path;
    /// # let view = CilAssemblyView::from_file(Path::new("test.dll"))?;
    /// let assembly = CilAssembly::new(view);
    /// let mut context = BuilderContext::new(assembly);
    ///
    /// // Perform builder operations...
    ///
    /// // Get the assembly back and write to file
    /// let assembly = context.finish();
    /// assembly.write_to_file(Path::new("output.dll"))?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn finish(self) -> CilAssembly {
        self.assembly
    }

    /// Adds a string to the assembly's string heap and returns its index.
    ///
    /// This is a convenience method that delegates to the underlying
    /// [`crate::cilassembly::CilAssembly::add_string`] method.
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
        let heap_changes = &self.assembly.changes().string_heap_changes;

        // Use the proper string_items_with_indices iterator to get correct byte offsets
        for (offset, existing_string) in heap_changes.string_items_with_indices() {
            if existing_string == value {
                return Some(offset);
            }
        }

        None
    }

    /// Adds a blob to the assembly's blob heap and returns its index.
    ///
    /// This is a convenience method that delegates to the underlying
    /// [`crate::cilassembly::CilAssembly::add_blob`] method.
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
    /// [`crate::cilassembly::CilAssembly::add_guid`] method.
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
    /// [`crate::cilassembly::CilAssembly::add_userstring`] method.
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
    /// The RID (Row ID) assigned to the newly created row as a [`crate::metadata::token::Token`].
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
    /// A [`crate::metadata::tables::CodedIndex`] pointing to the matching AssemblyRef, or None if not found.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// # use dotscope::prelude::*;
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
    /// This is a convenience method that uses [`crate::cilassembly::builder::BuilderContext::find_assembly_ref_by_name`] internally.
    ///
    /// # Returns
    ///
    /// A [`crate::metadata::tables::CodedIndex`] pointing to the core library AssemblyRef, or None if not found.
    pub fn find_core_library_ref(&self) -> Option<CodedIndex> {
        self.find_assembly_ref_by_name("mscorlib")
            .or_else(|| self.find_assembly_ref_by_name("System.Runtime"))
            .or_else(|| self.find_assembly_ref_by_name("System.Private.CoreLib"))
    }

    /// Adds a method signature to the blob heap and returns its index.
    ///
    /// This encodes the method signature using the dedicated method signature encoder
    /// from the signatures module. The encoder handles all ECMA-335 method signature
    /// format requirements including calling conventions, parameter counts, and type encoding.
    ///
    /// # Arguments
    ///
    /// * `signature` - The method signature to encode and store
    ///
    /// # Returns
    ///
    /// The blob heap index that can be used to reference this signature.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// # use dotscope::prelude::*;
    /// # use dotscope::metadata::signatures::*;
    /// # let mut context: BuilderContext = todo!();
    /// let signature = MethodSignatureBuilder::new()
    ///     .calling_convention_default()
    ///     .returns(TypeSignature::Void)
    ///     .param(TypeSignature::I4)
    ///     .build()?;
    ///
    /// let blob_index = context.add_method_signature(&signature)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn add_method_signature(&mut self, signature: &SignatureMethod) -> Result<u32> {
        let encoded_data = encode_method_signature(signature)?;
        self.add_blob(&encoded_data)
    }

    /// Adds a field signature to the blob heap and returns its index.
    ///
    /// This encodes the field signature using the dedicated field signature encoder
    /// from the signatures module. The encoder handles ECMA-335 field signature format
    /// requirements including custom modifiers and field type encoding.
    ///
    /// # Arguments
    ///
    /// * `signature` - The field signature to encode and store
    ///
    /// # Returns
    ///
    /// The blob heap index that can be used to reference this signature.
    pub fn add_field_signature(&mut self, signature: &SignatureField) -> Result<u32> {
        let encoded_data = encode_field_signature(signature)?;
        self.add_blob(&encoded_data)
    }

    /// Adds a property signature to the blob heap and returns its index.
    ///
    /// This encodes the property signature using the dedicated property signature encoder
    /// from the signatures module. The encoder handles ECMA-335 property signature format
    /// requirements including instance/static properties and indexer parameters.
    ///
    /// # Arguments
    ///
    /// * `signature` - The property signature to encode and store
    ///
    /// # Returns
    ///
    /// The blob heap index that can be used to reference this signature.
    pub fn add_property_signature(&mut self, signature: &SignatureProperty) -> Result<u32> {
        let encoded_data = encode_property_signature(signature)?;
        self.add_blob(&encoded_data)
    }

    /// Adds a local variable signature to the blob heap and returns its index.
    ///
    /// This encodes the local variable signature using the dedicated local variable encoder
    /// from the signatures module. The encoder handles ECMA-335 local variable signature format
    /// requirements including pinned and byref modifiers.
    ///
    /// # Arguments
    ///
    /// * `signature` - The local variable signature to encode and store
    ///
    /// # Returns
    ///
    /// The blob heap index that can be used to reference this signature.
    pub fn add_local_var_signature(&mut self, signature: &SignatureLocalVariables) -> Result<u32> {
        let encoded_data = encode_local_var_signature(signature)?;
        self.add_blob(&encoded_data)
    }

    /// Adds a type specification signature to the blob heap and returns its index.
    ///
    /// This encodes the type specification signature using the dedicated type specification encoder
    /// from the signatures module. Type specification signatures encode complex type signatures
    /// for generic instantiations, arrays, pointers, and other complex types.
    ///
    /// # Arguments
    ///
    /// * `signature` - The type specification signature to encode and store
    ///
    /// # Returns
    ///
    /// The blob heap index that can be used to reference this signature.
    pub fn add_typespec_signature(&mut self, signature: &SignatureTypeSpec) -> Result<u32> {
        let encoded_data = encode_typespec_signature(signature)?;
        self.add_blob(&encoded_data)
    }

    /// Adds a DLL to the native import table.
    ///
    /// Creates a new import descriptor for the specified DLL if it doesn't already exist.
    /// This is the foundation for adding native function imports and should be called
    /// before adding individual functions from the DLL.
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
    /// # use dotscope::prelude::*;
    /// # use std::path::Path;
    /// # let view = CilAssemblyView::from_file(Path::new("test.dll"))?;
    /// let assembly = CilAssembly::new(view);
    /// let mut context = BuilderContext::new(assembly);
    ///
    /// context.add_native_import_dll("kernel32.dll")?;
    /// context.add_native_import_dll("user32.dll")?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn add_native_import_dll(&mut self, dll_name: &str) -> Result<()> {
        self.assembly.add_native_import_dll(dll_name)
    }

    /// Adds a named function import from a specific DLL to the native import table.
    ///
    /// Adds a function import that uses name-based lookup. The DLL will be automatically
    /// added to the import table if it doesn't already exist. This is the most common
    /// form of function importing and provides the best compatibility across DLL versions.
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
    /// # use dotscope::prelude::*;
    /// # use std::path::Path;
    /// # let view = CilAssemblyView::from_file(Path::new("test.dll"))?;
    /// let assembly = CilAssembly::new(view);
    /// let mut context = BuilderContext::new(assembly);
    ///
    /// // Add kernel32 functions
    /// context.add_native_import_function("kernel32.dll", "GetCurrentProcessId")?;
    /// context.add_native_import_function("kernel32.dll", "ExitProcess")?;
    ///
    /// // Add user32 functions  
    /// context.add_native_import_function("user32.dll", "MessageBoxW")?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn add_native_import_function(
        &mut self,
        dll_name: &str,
        function_name: &str,
    ) -> Result<()> {
        self.assembly
            .add_native_import_function(dll_name, function_name)
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
    /// # use dotscope::prelude::*;
    /// # use std::path::Path;
    /// # let view = CilAssemblyView::from_file(Path::new("test.dll"))?;
    /// let assembly = CilAssembly::new(view);
    /// let mut context = BuilderContext::new(assembly);
    ///
    /// // Import MessageBoxW by ordinal (more efficient)
    /// context.add_native_import_function_by_ordinal("user32.dll", 120)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn add_native_import_function_by_ordinal(
        &mut self,
        dll_name: &str,
        ordinal: u16,
    ) -> Result<()> {
        self.assembly
            .add_native_import_function_by_ordinal(dll_name, ordinal)
    }

    /// Adds a named function export to the native export table.
    ///
    /// Creates a function export that can be called by other modules. The function
    /// will be accessible by both name and ordinal. This is the standard way to
    /// export functions from a library.
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
    /// # use dotscope::prelude::*;
    /// # use std::path::Path;
    /// # let view = CilAssemblyView::from_file(Path::new("test.dll"))?;
    /// let assembly = CilAssembly::new(view);
    /// let mut context = BuilderContext::new(assembly);
    ///
    /// // Export library functions
    /// context.add_native_export_function("MyLibraryInit", 1, 0x1000)?;
    /// context.add_native_export_function("ProcessData", 2, 0x2000)?;
    /// context.add_native_export_function("MyLibraryCleanup", 3, 0x3000)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn add_native_export_function(
        &mut self,
        function_name: &str,
        ordinal: u16,
        address: u32,
    ) -> Result<()> {
        self.assembly
            .add_native_export_function(function_name, ordinal, address)
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
    /// # use dotscope::prelude::*;
    /// # use std::path::Path;
    /// # let view = CilAssemblyView::from_file(Path::new("test.dll"))?;
    /// let assembly = CilAssembly::new(view);
    /// let mut context = BuilderContext::new(assembly);
    ///
    /// // Export internal functions by ordinal only
    /// context.add_native_export_function_by_ordinal(100, 0x5000)?;
    /// context.add_native_export_function_by_ordinal(101, 0x6000)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn add_native_export_function_by_ordinal(
        &mut self,
        ordinal: u16,
        address: u32,
    ) -> Result<()> {
        self.assembly
            .add_native_export_function_by_ordinal(ordinal, address)
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
    /// # use dotscope::prelude::*;
    /// # use std::path::Path;
    /// # let view = CilAssemblyView::from_file(Path::new("test.dll"))?;
    /// let assembly = CilAssembly::new(view);
    /// let mut context = BuilderContext::new(assembly);
    ///
    /// // Forward to functions in other DLLs
    /// context.add_native_export_forwarder("GetProcessId", 10, "kernel32.dll.GetCurrentProcessId")?;
    /// context.add_native_export_forwarder("MessageBox", 11, "user32.dll.MessageBoxW")?;
    /// context.add_native_export_forwarder("OrdinalForward", 12, "mydll.dll.#50")?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn add_native_export_forwarder(
        &mut self,
        function_name: &str,
        ordinal: u16,
        target: &str,
    ) -> Result<()> {
        self.assembly
            .add_native_export_forwarder(function_name, ordinal, target)
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
            let assembly = CilAssembly::new(view);

            // Check existing table counts
            let assembly_count = assembly.original_table_row_count(TableId::Assembly);
            let typedef_count = assembly.original_table_row_count(TableId::TypeDef);
            let typeref_count = assembly.original_table_row_count(TableId::TypeRef);

            let context = BuilderContext::new(assembly);

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
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

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
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

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
            let assembly = CilAssembly::new(view);

            // Get the expected present tables before creating the context
            let expected_tables: Vec<_> = if let Some(tables) = assembly.view.tables() {
                tables.present_tables().collect()
            } else {
                vec![]
            };

            let context = BuilderContext::new(assembly);

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
                "Expected more than 5 tables, found {discovered_table_count}"
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
                    "BuilderContext missing table {table_id:?} that exists in assembly"
                );
            }
        }
    }

    #[test]
    fn test_builder_context_assembly_ref_lookup() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let context = BuilderContext::new(assembly);

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
            let assembly = CilAssembly::new(view);
            let context = BuilderContext::new(assembly);

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

    #[test]
    fn test_builder_context_signature_integration() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            // Test signature placeholder methods work and return valid blob indices

            // Create placeholder signatures for testing
            use crate::metadata::signatures::{
                FieldSignatureBuilder, LocalVariableSignatureBuilder, MethodSignatureBuilder,
                PropertySignatureBuilder, TypeSignature, TypeSpecSignatureBuilder,
            };

            // Test method signature integration
            let method_sig = MethodSignatureBuilder::new()
                .calling_convention_default()
                .returns(TypeSignature::Void)
                .build()
                .unwrap();
            let method_blob_idx = context.add_method_signature(&method_sig).unwrap();
            assert!(
                method_blob_idx > 0,
                "Method signature should return valid blob index"
            );

            // Test field signature integration
            let field_sig = FieldSignatureBuilder::new()
                .field_type(TypeSignature::String)
                .build()
                .unwrap();
            let field_blob_idx = context.add_field_signature(&field_sig).unwrap();
            assert!(
                field_blob_idx > 0,
                "Field signature should return valid blob index"
            );
            assert_ne!(
                field_blob_idx, method_blob_idx,
                "Different signatures should get different indices"
            );

            // Test property signature integration
            let property_sig = PropertySignatureBuilder::new()
                .property_type(TypeSignature::I4)
                .build()
                .unwrap();
            let property_blob_idx = context.add_property_signature(&property_sig).unwrap();
            assert!(
                property_blob_idx > 0,
                "Property signature should return valid blob index"
            );

            // Test local variable signature integration
            let localvar_sig = LocalVariableSignatureBuilder::new()
                .add_local(TypeSignature::I4)
                .build()
                .unwrap();
            let localvar_blob_idx = context.add_local_var_signature(&localvar_sig).unwrap();
            assert!(
                localvar_blob_idx > 0,
                "Local var signature should return valid blob index"
            );

            // Test type spec signature integration
            let typespec_sig = TypeSpecSignatureBuilder::new()
                .type_signature(TypeSignature::String)
                .build()
                .unwrap();
            let typespec_blob_idx = context.add_typespec_signature(&typespec_sig).unwrap();
            assert!(
                typespec_blob_idx > 0,
                "Type spec signature should return valid blob index"
            );

            // Verify all blob indices are unique
            let indices = vec![
                method_blob_idx,
                field_blob_idx,
                property_blob_idx,
                localvar_blob_idx,
                typespec_blob_idx,
            ];
            let mut unique_indices = indices.clone();
            unique_indices.sort();
            unique_indices.dedup();
            assert_eq!(
                indices.len(),
                unique_indices.len(),
                "All signature blob indices should be unique"
            );
        }
    }
}
