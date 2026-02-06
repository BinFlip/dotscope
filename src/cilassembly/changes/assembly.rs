//! Core assembly change tracking structure.
//!
//! This module provides the [`crate::cilassembly::changes::AssemblyChanges`] structure
//! for tracking all modifications made to a .NET assembly during the modification process.
//! It implements sparse change tracking to minimize memory overhead and enable efficient
//! merging operations during assembly output.
//!
//! # Key Components
//!
//! - [`crate::cilassembly::changes::AssemblyChanges`] - Core change tracking structure for assembly modifications
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
//! use crate::cilassembly::changes::AssemblyChanges;
//!
//! let mut changes = AssemblyChanges::new();
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

use std::collections::{HashMap, HashSet};

use crate::{
    cilassembly::{ChangeRef, HeapChanges, TableModifications},
    metadata::{exports::UnifiedExportContainer, imports::UnifiedImportContainer, tables::TableId},
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
/// use crate::cilassembly::changes::AssemblyChanges;
///
/// let changes = AssemblyChanges::new();
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

    /// Referenced string heap offsets for substring remapping.
    ///
    /// When heap compaction is enabled, this stores all string offsets that are
    /// actually referenced by metadata tables. This is needed because .NET allows
    /// "substring references" - pointing to any offset within a string entry.
    /// During streaming, these offsets are used to build proper remappings for
    /// substring references when strings shift positions.
    pub referenced_string_offsets: HashSet<u32>,

    /// Native import/export containers for PE import/export tables
    ///
    /// Contains unified containers that manage user modifications to native imports/exports.
    /// These always exist but start empty, following pure copy-on-write semantics.
    pub native_imports: UnifiedImportContainer,
    pub native_exports: UnifiedExportContainer,

    /// Method body storage for new and modified method implementations
    ///
    /// Maps placeholder RVAs to method body bytes for methods created through builders.
    /// The placeholder RVAs are sequential IDs that will be resolved to actual RVAs
    /// during PE writing when the real code section layout is determined.
    pub method_bodies: HashMap<u32, Vec<u8>>,

    /// Next available placeholder RVA for method body allocation
    ///
    /// Tracks the next sequential placeholder ID for method bodies. These placeholders
    /// will be resolved to real RVAs during PE writing based on actual section layout.
    pub next_method_placeholder: u32,

    /// CLR resource data section for embedded managed resources
    ///
    /// This stores the actual resource data bytes that will be written to the
    /// CLR resources section (pointed to by COR20 header's resource_rva/resource_size).
    /// Each resource is stored with a 4-byte length prefix followed by the data.
    /// ManifestResource.offset_field points to offsets within this section.
    pub resource_data: Vec<u8>,

    /// Field initialization data storage for FieldRVA entries
    ///
    /// Maps placeholder RVAs to field data bytes for fields created through builders
    /// or extracted from anti-tamper protected assemblies. The placeholder RVAs are
    /// sequential IDs that will be resolved to actual RVAs during PE writing when
    /// the real .sdata section layout is determined.
    pub field_data: HashMap<u32, Vec<u8>>,

    /// Next available placeholder RVA for field data allocation
    ///
    /// Tracks the next sequential placeholder ID for field data. These placeholders
    /// will be resolved to real RVAs during PE writing based on actual section layout.
    /// Uses a different range than method bodies to avoid conflicts.
    pub next_field_placeholder: u32,
}

impl AssemblyChanges {
    /// Creates a new change tracking structure.
    ///
    /// Initializes all heap change trackers and table change maps to empty state.
    pub fn new() -> Self {
        Self {
            table_changes: HashMap::new(),
            string_heap_changes: HeapChanges::new_strings(),
            blob_heap_changes: HeapChanges::new_blobs(),
            guid_heap_changes: HeapChanges::new_guids(),
            userstring_heap_changes: HeapChanges::new_userstrings(),
            referenced_string_offsets: HashSet::new(),
            native_imports: UnifiedImportContainer::new(),
            native_exports: UnifiedExportContainer::new(),
            method_bodies: HashMap::new(),
            next_method_placeholder: 0xF000_0000, // Start placeholders at high address range
            resource_data: Vec::new(),
            field_data: HashMap::new(),
            next_field_placeholder: 0xE000_0000, // Different range than method bodies
        }
    }

    /// Creates an empty change tracking structure for testing purposes.
    ///
    /// This is an alias for [`Self::new()`].
    pub fn empty() -> Self {
        Self::new()
    }

    /// Returns true if any changes have been made to the assembly.
    ///
    /// This checks if any table changes exist or if any heap has changes (additions, modifications, or removals).
    /// Native containers are checked for emptiness since they always exist but start empty.
    pub fn has_changes(&self) -> bool {
        !self.table_changes.is_empty()
            || self.string_heap_changes.has_changes()
            || self.blob_heap_changes.has_changes()
            || self.guid_heap_changes.has_changes()
            || self.userstring_heap_changes.has_changes()
            || !self.native_imports.is_empty()
            || !self.native_exports.is_empty()
            || !self.resource_data.is_empty()
    }

    /// Returns the number of tables that have been modified.
    pub fn modified_table_count(&self) -> usize {
        self.table_changes.len()
    }

    /// Returns the total number of string heap additions.
    pub fn string_additions_count(&self) -> usize {
        self.string_heap_changes.additions_count()
    }

    /// Returns the total number of blob heap additions.
    pub fn blob_additions_count(&self) -> usize {
        self.blob_heap_changes.additions_count()
    }

    /// Returns the total number of GUID heap additions.
    pub fn guid_additions_count(&self) -> usize {
        self.guid_heap_changes.additions_count()
    }

    /// Returns the total number of user string heap additions.
    pub fn userstring_additions_count(&self) -> usize {
        self.userstring_heap_changes.additions_count()
    }

    /// Returns an iterator over all modified table IDs.
    pub fn modified_tables(&self) -> impl Iterator<Item = TableId> + '_ {
        self.table_changes.keys().copied()
    }

    /// Gets mutable access to the native imports container.
    ///
    /// This method implements pure copy-on-write semantics: the container always exists
    /// but starts empty, tracking only user modifications. The write pipeline is
    /// responsible for unifying original PE data with user changes.
    ///
    /// # Returns
    ///
    /// Mutable reference to the import container containing only user modifications.
    pub fn native_imports_mut(&mut self) -> &mut UnifiedImportContainer {
        &mut self.native_imports
    }

    /// Gets read-only access to the native imports container.
    ///
    /// # Returns
    ///
    /// Reference to the unified import container containing user modifications.
    pub fn native_imports(&self) -> &UnifiedImportContainer {
        &self.native_imports
    }

    /// Gets mutable access to the native exports container.
    ///
    /// This method implements pure copy-on-write semantics: the container always exists
    /// but starts empty, tracking only user modifications. The write pipeline is
    /// responsible for unifying original PE data with user changes.
    ///
    /// # Returns
    ///
    /// Mutable reference to the export container containing only user modifications.
    pub fn native_exports_mut(&mut self) -> &mut UnifiedExportContainer {
        &mut self.native_exports
    }

    /// Gets read-only access to the native exports container.
    ///
    /// # Returns
    ///
    /// Reference to the unified export container containing user modifications.
    pub fn native_exports(&self) -> &UnifiedExportContainer {
        &self.native_exports
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

    /// Returns an iterator over all string heap ChangeRefs.
    ///
    /// This is used during the write phase to resolve all string placeholders.
    pub fn string_change_refs(&self) -> impl Iterator<Item = &super::ChangeRefRc> {
        self.string_heap_changes
            .appended_iter()
            .map(|(_, change_ref)| change_ref)
    }

    /// Returns an iterator over all blob heap ChangeRefs.
    ///
    /// This is used during the write phase to resolve all blob placeholders.
    pub fn blob_change_refs(&self) -> impl Iterator<Item = &super::ChangeRefRc> {
        self.blob_heap_changes
            .appended_iter()
            .map(|(_, change_ref)| change_ref)
    }

    /// Returns an iterator over all GUID heap ChangeRefs.
    ///
    /// This is used during the write phase to resolve all GUID placeholders.
    pub fn guid_change_refs(&self) -> impl Iterator<Item = &super::ChangeRefRc> {
        self.guid_heap_changes
            .appended_iter()
            .map(|(_, change_ref)| change_ref)
    }

    /// Returns an iterator over all user string heap ChangeRefs.
    ///
    /// This is used during the write phase to resolve all user string placeholders.
    pub fn userstring_change_refs(&self) -> impl Iterator<Item = &super::ChangeRefRc> {
        self.userstring_heap_changes
            .appended_iter()
            .map(|(_, change_ref)| change_ref)
    }

    /// Returns an iterator over all table row ChangeRefs for a specific table.
    ///
    /// This is used during the write phase to resolve all table row placeholders.
    pub fn table_change_refs(
        &self,
        table_id: TableId,
    ) -> impl Iterator<Item = (&u32, &super::ChangeRefRc)> {
        self.table_changes
            .get(&table_id)
            .map(crate::cilassembly::TableModifications::change_refs)
            .into_iter()
            .flatten()
    }

    /// Returns an iterator over all ChangeRefs from all tables.
    ///
    /// This is used during the write phase to resolve all table row placeholders.
    pub fn all_table_change_refs(
        &self,
    ) -> impl Iterator<Item = (TableId, &u32, &super::ChangeRefRc)> {
        self.table_changes.iter().flat_map(|(table_id, mods)| {
            mods.change_refs()
                .map(move |(rid, change_ref)| (*table_id, rid, change_ref))
        })
    }

    /// Looks up a ChangeRef by its placeholder value.
    ///
    /// This searches through all heap and table changes to find the ChangeRef
    /// that corresponds to the given placeholder.
    ///
    /// # Arguments
    ///
    /// * `placeholder` - A placeholder value (must have high bit set)
    ///
    /// # Returns
    ///
    /// `Some(&ChangeRefRc)` if found, `None` otherwise.
    pub fn lookup_by_placeholder(&self, placeholder: u32) -> Option<&super::ChangeRefRc> {
        if !ChangeRef::is_placeholder(placeholder) {
            return None;
        }

        let id = ChangeRef::id_from_placeholder(placeholder)?;

        // Search heap changes
        for (_, change_ref) in self.string_heap_changes.appended_iter() {
            if change_ref.id() == id {
                return Some(change_ref);
            }
        }
        for (_, change_ref) in self.blob_heap_changes.appended_iter() {
            if change_ref.id() == id {
                return Some(change_ref);
            }
        }
        for (_, change_ref) in self.guid_heap_changes.appended_iter() {
            if change_ref.id() == id {
                return Some(change_ref);
            }
        }
        for (_, change_ref) in self.userstring_heap_changes.appended_iter() {
            if change_ref.id() == id {
                return Some(change_ref);
            }
        }

        // Search table changes
        for mods in self.table_changes.values() {
            for (_, change_ref) in mods.change_refs() {
                if change_ref.id() == id {
                    return Some(change_ref);
                }
            }
        }

        None
    }

    /// Stores a method body and allocates a placeholder RVA for it.
    ///
    /// This method stores the method body with a sequential placeholder RVA that will
    /// be resolved to the actual RVA during PE writing when the code section layout
    /// is determined.
    ///
    /// # Arguments
    ///
    /// * `body_bytes` - The complete method body bytes including header and exception handlers
    ///
    /// # Returns
    ///
    /// A placeholder RVA that will be resolved to the actual RVA during binary writing.
    pub fn store_method_body(&mut self, body_bytes: Vec<u8>) -> u32 {
        let placeholder_rva = self.next_method_placeholder;

        // Store the method body with placeholder RVA
        self.method_bodies.insert(placeholder_rva, body_bytes);

        // Increment to next placeholder (simple sequential allocation)
        self.next_method_placeholder += 1;

        placeholder_rva
    }

    /// Retrieves a stored method body by its placeholder RVA.
    ///
    /// # Arguments
    ///
    /// * `placeholder_rva` - The placeholder RVA of the method body to retrieve
    ///
    /// # Returns
    ///
    /// Optional reference to the method body bytes if found.
    pub fn get_method_body(&self, placeholder_rva: u32) -> Option<&Vec<u8>> {
        self.method_bodies.get(&placeholder_rva)
    }

    /// Gets the total size of all stored method bodies.
    ///
    /// This is used for calculating the size of the code section during PE writing.
    /// The size includes proper 4-byte alignment padding between method bodies as
    /// required by the method body writer.
    ///
    /// # Returns
    ///
    /// Total size in bytes of all method bodies including alignment padding.
    pub fn method_bodies_total_size(&self) -> crate::Result<u32> {
        self.method_bodies
            .values()
            .map(|body| {
                let size = u32::try_from(body.len())
                    .map_err(|_| malformed_error!("Method body size exceeds u32 range"))?;
                // Align each method body to 4-byte boundary
                Ok((size + 3) & !3)
            })
            .sum()
    }

    /// Gets all method bodies with their placeholder RVAs.
    ///
    /// This is used during PE writing to layout the code section and resolve
    /// placeholder RVAs to actual RVAs based on the final section layout.
    ///
    /// # Returns
    ///
    /// Iterator over (placeholder_rva, method_body_bytes) pairs for all stored method bodies.
    pub fn method_bodies(&self) -> impl Iterator<Item = (u32, &Vec<u8>)> + '_ {
        self.method_bodies
            .iter()
            .map(|(placeholder_rva, body)| (*placeholder_rva, body))
    }

    /// Checks if a placeholder RVA represents a method body managed by this system.
    ///
    /// This is used during PE writing to identify which RVAs in the metadata tables
    /// are placeholders that need to be resolved to actual RVAs.
    ///
    /// # Arguments
    ///
    /// * `rva` - The RVA to check
    ///
    /// # Returns
    ///
    /// True if this RVA is a placeholder managed by the method body system.
    pub fn is_method_body_placeholder(&self, rva: u32) -> bool {
        rva >= 0xF000_0000 && self.method_bodies.contains_key(&rva)
    }

    /// Stores resource data in the CLR resources section and returns its offset.
    ///
    /// This method appends the resource data to the CLR resources section with
    /// the proper .NET format: 4-byte little-endian length prefix followed by the data.
    /// The returned offset is used in the ManifestResource table's offset_field.
    ///
    /// # Arguments
    ///
    /// * `data` - The raw resource data bytes to store
    ///
    /// # Returns
    ///
    /// The offset within the resources section where this resource starts.
    /// This offset points to the length prefix, not the data itself.
    pub fn store_resource_data(&mut self, data: &[u8]) -> u32 {
        // Record the current offset before adding the new resource
        let offset = self.resource_data.len() as u32;

        // Write 4-byte little-endian length prefix
        let len = data.len() as u32;
        self.resource_data.extend_from_slice(&len.to_le_bytes());

        // Write the actual resource data
        self.resource_data.extend_from_slice(data);

        offset
    }

    /// Returns the total size of all stored resource data.
    ///
    /// This includes all length prefixes and data bytes.
    pub fn resource_data_size(&self) -> usize {
        self.resource_data.len()
    }

    /// Returns true if there is any new resource data to write.
    pub fn has_resource_data(&self) -> bool {
        !self.resource_data.is_empty()
    }

    /// Returns a reference to the stored resource data bytes.
    ///
    /// This is used during PE writing to emit the CLR resources section.
    pub fn resource_data_bytes(&self) -> &[u8] {
        &self.resource_data
    }

    /// Stores field initialization data and returns a placeholder RVA.
    ///
    /// The returned placeholder RVA is a temporary identifier that will later
    /// be resolved to the actual RVA during PE writing when the .sdata section
    /// layout is determined. This enables building assemblies with field data
    /// before the final layout is known.
    ///
    /// # Arguments
    ///
    /// * `data` - The field initialization data bytes
    ///
    /// # Returns
    ///
    /// A placeholder RVA that will be resolved to the actual RVA during binary writing.
    pub fn store_field_data(&mut self, data: Vec<u8>) -> u32 {
        let placeholder_rva = self.next_field_placeholder;

        // Store the field data with placeholder RVA
        self.field_data.insert(placeholder_rva, data);

        // Increment to next placeholder (simple sequential allocation)
        self.next_field_placeholder += 1;

        placeholder_rva
    }

    /// Retrieves stored field data by its placeholder RVA.
    ///
    /// # Arguments
    ///
    /// * `placeholder_rva` - The placeholder RVA of the field data to retrieve
    ///
    /// # Returns
    ///
    /// Optional reference to the field data bytes if found.
    pub fn get_field_data(&self, placeholder_rva: u32) -> Option<&Vec<u8>> {
        self.field_data.get(&placeholder_rva)
    }

    /// Gets the total size of all stored field data.
    ///
    /// This is used for calculating the size of the .text section during PE writing.
    /// Includes 4-byte alignment padding between data entries.
    ///
    /// # Returns
    ///
    /// Total size in bytes of all field data including alignment padding.
    pub fn field_data_total_size(&self) -> crate::Result<u32> {
        self.field_data
            .values()
            .map(|data| {
                let size = u32::try_from(data.len())
                    .map_err(|_| malformed_error!("Field data size exceeds u32 range"))?;
                // Align each entry to 4-byte boundary (same as method bodies)
                Ok((size + 3) & !3)
            })
            .sum()
    }

    /// Gets all field data with their placeholder RVAs.
    ///
    /// This is used during PE writing to layout the .sdata section and resolve
    /// placeholder RVAs to actual RVAs based on the final section layout.
    ///
    /// # Returns
    ///
    /// Iterator over (placeholder_rva, field_data_bytes) pairs for all stored field data.
    pub fn field_data_entries(&self) -> impl Iterator<Item = (u32, &Vec<u8>)> + '_ {
        self.field_data
            .iter()
            .map(|(placeholder_rva, data)| (*placeholder_rva, data))
    }

    /// Checks if a placeholder RVA represents field data managed by this system.
    ///
    /// This is used during PE writing to identify which RVAs in the metadata tables
    /// are placeholders that need to be resolved to actual RVAs.
    ///
    /// # Arguments
    ///
    /// * `rva` - The RVA to check
    ///
    /// # Returns
    ///
    /// True if this RVA is a field data placeholder managed by this system.
    pub fn is_field_data_placeholder(&self, rva: u32) -> bool {
        (0xE000_0000..0xF000_0000).contains(&rva) && self.field_data.contains_key(&rva)
    }

    /// Returns true if there is any field data to write.
    pub fn has_field_data(&self) -> bool {
        !self.field_data.is_empty()
    }
}

impl Default for AssemblyChanges {
    fn default() -> Self {
        Self::new()
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
        let mut string_changes = HeapChanges::new_strings();
        let _ = string_changes.append("Hello".to_string()); // 5 + 1 = 6 bytes
        let _ = string_changes.append("World".to_string()); // 5 + 1 = 6 bytes
        changes.string_heap_changes = string_changes;

        // Add some blob heap changes
        let mut blob_changes = HeapChanges::new_blobs();
        let _ = blob_changes.append(vec![1, 2, 3]); // 1 + 3 = 4 bytes (length < 128)
        let _ = blob_changes.append(vec![4, 5, 6, 7, 8]); // 1 + 5 = 6 bytes
        changes.blob_heap_changes = blob_changes;

        // Add some GUID heap changes
        let mut guid_changes = HeapChanges::new_guids();
        let _ = guid_changes.append([1; 16]); // 16 bytes
        let _ = guid_changes.append([2; 16]); // 16 bytes
        changes.guid_heap_changes = guid_changes;

        let (string_size, blob_size, guid_size, userstring_size) = changes.binary_heap_sizes();
        assert_eq!(string_size, 12); // "Hello\0" + "World\0" = 6 + 6
        assert_eq!(blob_size, 10); // (1+3) + (1+5) = 4 + 6
        assert_eq!(guid_size, 32); // 16 + 16
        assert_eq!(userstring_size, 0); // No userstring changes
    }
}
