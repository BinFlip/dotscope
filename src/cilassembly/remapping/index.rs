//! Index remapping for binary generation.
//!
//! This module provides the [`crate::cilassembly::remapping::index::IndexRemapper`] for managing
//! index remapping during the binary generation phase of assembly modification. It handles
//! the complex task of updating all cross-references when heap items are added or table
//! rows are modified, ensuring referential integrity in the final output.
//!
//! # Key Components
//!
//! - [`crate::cilassembly::remapping::index::IndexRemapper`] - Central index remapping coordinator for all heaps and tables
//!
//! # Architecture
//!
//! The index remapping system addresses the challenge of maintaining referential integrity
//! when assembly modifications change the layout of metadata structures:
//!
//! ## Heap Index Remapping
//! When new items are added to metadata heaps (#Strings, #Blob, #GUID, #US), existing
//! indices remain valid but new items receive sequential indices. The remapper maintains
//! mapping tables to track these assignments.
//!
//! ## Table RID Remapping  
//! When table rows are inserted, updated, or deleted, the RID (Row ID) space may be
//! reorganized. The remapper coordinates with [`crate::cilassembly::remapping::rid::RidRemapper`]
//! instances to handle per-table RID management.
//!
//! ## Cross-Reference Updates
//! The final phase applies all remappings to update cross-references throughout the
//! assembly metadata, ensuring all indices and RIDs point to their correct final locations.
//!
//! # Usage Examples
//!
//! ```rust,ignore
//! use crate::cilassembly::remapping::index::IndexRemapper;
//! use crate::cilassembly::changes::AssemblyChanges;
//! use crate::metadata::cilassemblyview::CilAssemblyView;
//! use std::path::Path;
//!
//! # let view = CilAssemblyView::from_path(Path::new("test.dll"));
//! # let mut changes = AssemblyChanges::new(&view);
//! // Build complete remapping from changes
//! let remapper = IndexRemapper::build_from_changes(&changes, &view)?;
//!
//! // Query specific index mappings
//! if let Some(final_index) = remapper.map_string_index(42) {
//!     println!("String index 42 maps to {}", final_index);
//! }
//!
//! // Apply remapping to update cross-references
//! remapper.apply_to_assembly(&mut changes);
//! # Ok::<(), crate::Error>(())
//! ```
//!
//! # Thread Safety
//!
//! This type is not [`Send`] or [`Sync`] as it contains large hash maps that are designed
//! for single-threaded batch processing during binary generation.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::cilassembly::remapping::rid`] - Per-table RID remapping
//! - [`crate::cilassembly::changes::AssemblyChanges`] - Change tracking data
//! - [`crate::cilassembly::write`] - Binary output generation system
//! - [`crate::metadata::cilassemblyview::CilAssemblyView`] - Original assembly data

use std::collections::{HashMap, HashSet};

use crate::{
    cilassembly::{remapping::RidRemapper, AssemblyChanges, HeapChanges, TableModifications},
    malformed_error,
    metadata::{
        cilassemblyview::CilAssemblyView,
        tables::{CodedIndex, TableDataOwned, TableId},
    },
    utils::compressed_uint_size,
    Result,
};

/// Manages index remapping during binary generation phase.
///
/// This struct serves as the central coordinator for all index remapping operations
/// during assembly modification. It maintains separate mapping tables for each metadata
/// heap and delegates table-specific RID remapping to [`crate::cilassembly::remapping::rid::RidRemapper`]
/// instances.
///
/// # Remapping Strategy
///
/// The remapper implements a preservation strategy where:
/// - Original indices are preserved whenever possible
/// - New items receive sequential indices after existing items
/// - Cross-references are updated in a final consolidation phase
/// - All mappings are tracked to enable reverse lookups if needed
///
/// # Memory Layout
///
/// The remapper contains hash maps for each metadata heap type:
/// - **String heap**: UTF-8 strings with null terminators
/// - **Blob heap**: Binary data with compressed length prefixes  
/// - **GUID heap**: Fixed 16-byte GUIDs
/// - **UserString heap**: UTF-16 strings with compressed length prefixes
/// - **Table RIDs**: Per-table row identifier mappings
///
/// # Usage Examples
///
/// ```rust,ignore
/// use crate::cilassembly::remapping::index::IndexRemapper;
/// use crate::cilassembly::changes::AssemblyChanges;
/// use crate::metadata::cilassemblyview::CilAssemblyView;
/// use crate::metadata::tables::TableId;
/// use std::path::Path;
///
/// # let view = CilAssemblyView::from_path(Path::new("test.dll"));
/// # let changes = AssemblyChanges::new(&view);
/// // Build remapper from assembly changes
/// let remapper = IndexRemapper::build_from_changes(&changes, &view)?;
///
/// // Check heap index mappings
/// let final_string_idx = remapper.map_string_index(42);
/// let final_blob_idx = remapper.map_blob_index(100);
///
/// // Access table remappers
/// if let Some(table_remapper) = remapper.get_table_remapper(TableId::TypeDef) {
///     let final_rid = table_remapper.map_rid(5);
/// }
/// # Ok::<(), crate::Error>(())
/// ```
///
/// # Thread Safety
///
/// This type is not [`Send`] or [`Sync`] as it contains large mutable hash maps
/// optimized for single-threaded batch processing.
#[derive(Debug, Clone)]
pub struct IndexRemapper {
    /// String heap: Original index -> Final index
    pub string_map: HashMap<u32, u32>,
    /// String heap: Removed indices (returns None when queried)
    pub string_removed: HashSet<u32>,
    /// Blob heap: Original index -> Final index
    pub blob_map: HashMap<u32, u32>,
    /// Blob heap: Removed indices (returns None when queried)
    pub blob_removed: HashSet<u32>,
    /// GUID heap: Original index -> Final index
    pub guid_map: HashMap<u32, u32>,
    /// GUID heap: Removed indices (returns None when queried)
    pub guid_removed: HashSet<u32>,
    /// UserString heap: Original index -> Final index
    pub userstring_map: HashMap<u32, u32>,
    /// UserString heap: Removed indices (returns None when queried)
    pub userstring_removed: HashSet<u32>,
    /// Per-table RID mapping: Original RID -> Final RID (None = deleted)
    pub table_maps: HashMap<TableId, RidRemapper>,
}

impl IndexRemapper {
    /// Build complete remapping for all modified tables and heaps.
    ///
    /// This method analyzes the provided changes and constructs a comprehensive remapping
    /// strategy for all modified metadata structures. It coordinates heap index remapping
    /// and table RID remapping to ensure referential integrity in the final binary.
    ///
    /// # Arguments
    ///
    /// * `changes` - The [`crate::cilassembly::changes::AssemblyChanges`] containing all modifications
    /// * `original_view` - The original [`crate::metadata::cilassemblyview::CilAssemblyView`] for baseline data
    ///
    /// # Returns
    ///
    /// A new [`crate::cilassembly::remapping::index::IndexRemapper`] with complete mapping tables
    /// for all modified structures.
    ///
    /// # Process
    ///
    /// 1. **Heap Remapping**: Builds index mappings for all modified heaps
    /// 2. **Table Remapping**: Creates RID remappers for all modified tables
    /// 3. **Cross-Reference Preparation**: Prepares for final cross-reference updates
    pub fn build_from_changes(
        changes: &AssemblyChanges,
        original_view: &CilAssemblyView,
    ) -> Result<Self> {
        let mut remapper = Self {
            string_map: HashMap::new(),
            string_removed: HashSet::new(),
            blob_map: HashMap::new(),
            blob_removed: HashSet::new(),
            guid_map: HashMap::new(),
            guid_removed: HashSet::new(),
            userstring_map: HashMap::new(),
            userstring_removed: HashSet::new(),
            table_maps: HashMap::new(),
        };

        remapper.build_heap_remapping(changes, original_view)?;
        remapper.build_table_remapping(changes, original_view);
        Ok(remapper)
    }

    /// Build heap index remapping for all modified heaps.
    ///
    /// This method examines each metadata heap for changes and builds appropriate
    /// index mappings. Only heaps with modifications receive mapping tables to
    /// optimize memory usage.
    ///
    /// # Arguments
    ///
    /// * `changes` - The [`crate::cilassembly::changes::AssemblyChanges`] to analyze
    /// * `original_view` - The original assembly view for baseline heap sizes
    fn build_heap_remapping(
        &mut self,
        changes: &AssemblyChanges,
        original_view: &CilAssemblyView,
    ) -> Result<()> {
        if changes.string_heap_changes.has_changes() {
            self.build_string_mapping(&changes.string_heap_changes, original_view)?;
        }

        if changes.blob_heap_changes.has_changes() {
            self.build_blob_mapping(&changes.blob_heap_changes, original_view)?;
        }

        if changes.guid_heap_changes.has_changes() {
            self.build_guid_mapping(&changes.guid_heap_changes);
        }

        if changes.userstring_heap_changes.has_changes() {
            self.build_userstring_mapping(&changes.userstring_heap_changes);
        }

        Ok(())
    }

    /// Build table RID remapping for all modified tables.
    fn build_table_remapping(
        &mut self,
        changes: &AssemblyChanges,
        original_view: &CilAssemblyView,
    ) {
        for (table_id, table_modifications) in &changes.table_changes {
            let original_count = if let Some(tables) = original_view.tables() {
                tables.table_row_count(*table_id)
            } else {
                0
            };

            match table_modifications {
                TableModifications::Sparse { operations, .. } => {
                    let rid_remapper =
                        RidRemapper::build_from_operations(operations, original_count);
                    self.table_maps.insert(*table_id, rid_remapper);
                }
                TableModifications::Replaced(rows) => {
                    let mut rid_remapper = RidRemapper::new(u32::try_from(rows.len()).unwrap_or(0));

                    // Map each row index to sequential RID
                    for i in 0..rows.len() {
                        let rid = u32::try_from(i + 1).unwrap_or(0);
                        rid_remapper.mapping.insert(rid, Some(rid));
                    }

                    self.table_maps.insert(*table_id, rid_remapper);
                }
            }
        }
    }

    /// Build string heap index mapping.
    ///
    /// String heap indices are byte offsets into the heap, not sequential entry numbers.
    /// This method builds mappings for:
    /// - Removed items: No mapping (returns None when queried)
    /// - Original items: Identity mapping (byte offset unchanged, data zeroed in place)
    /// - Modified items: Remapped to end of heap if new string is larger than original
    /// - Appended items: Mapped to their assigned byte offsets
    ///
    /// Note: The string heap writer zeros out removed items in place rather than
    /// compacting the heap, so original byte offsets remain valid.
    fn build_string_mapping(
        &mut self,
        string_changes: &HeapChanges<String>,
        original_view: &CilAssemblyView,
    ) -> Result<()> {
        // Store removed indices for lookup
        for &removed_index in &string_changes.removed_indices {
            self.string_removed.insert(removed_index);
        }

        // Handle modified strings that need remapping (new string larger than original)
        // These will be appended at the end of the heap
        if let Some(strings_heap) = original_view.strings() {
            let original_heap_size = u32::try_from(strings_heap.data().len())
                .map_err(|_| malformed_error!("String heap size exceeds u32 range"))?;
            let mut next_append_position = original_heap_size;

            // First, collect all modifications that need remapping
            let mut remapped_mods: Vec<(u32, &String)> = Vec::new();

            for (&modified_index, new_string) in &string_changes.modified_items {
                // Find the original string to compare sizes
                if let Some((_offset, original_string)) = strings_heap
                    .iter()
                    .find(|(offset, _)| *offset == modified_index as usize)
                {
                    let original_size = original_string.len() + 1; // +1 for null terminator
                    let new_size = new_string.len() + 1; // +1 for null terminator

                    // If new string is larger than original, it needs remapping
                    if new_size > original_size {
                        remapped_mods.push((modified_index, new_string));
                    }
                    // If it fits in place, no mapping needed (identity)
                }
            }

            // Sort by index for deterministic ordering
            remapped_mods.sort_by_key(|(idx, _)| *idx);

            // Calculate new positions for remapped strings
            for (modified_index, new_string) in remapped_mods {
                self.string_map.insert(modified_index, next_append_position);
                // Advance position: string bytes + null terminator
                let string_size = u32::try_from(new_string.len() + 1)
                    .map_err(|_| malformed_error!("String size exceeds u32 range"))?;
                next_append_position += string_size;
            }
        }

        // Map appended items to their assigned byte offsets
        // The HeapChanges tracks the byte offset for each appended item
        for (vec_index, _) in string_changes.appended_items.iter().enumerate() {
            if let Some(assigned_index) = string_changes.get_appended_item_index(vec_index) {
                // Appended items use identity mapping - the assigned index IS the final index
                self.string_map.insert(assigned_index, assigned_index);
            }
        }

        Ok(())
    }

    /// Build blob heap index mapping.
    ///
    /// Blob heap indices are byte offsets into the heap, not sequential entry numbers.
    /// This method builds mappings for:
    /// - Removed items: No mapping (returns None when queried)
    /// - Original items: Identity mapping (byte offset unchanged, data zeroed in place)
    /// - Modified items: Remapped to end of heap if new blob is larger than original
    /// - Appended items: Mapped to their assigned byte offsets
    ///
    /// Note: The blob heap writer zeros out removed items in place rather than
    /// compacting the heap, so original byte offsets remain valid.
    fn build_blob_mapping(
        &mut self,
        blob_changes: &HeapChanges<Vec<u8>>,
        original_view: &CilAssemblyView,
    ) -> Result<()> {
        // For removed indices, we explicitly do NOT add them to the map.
        // When map_blob_index is called for a removed index, it will return None.
        // The removed_indices set is checked by the caller.

        // Store removed indices for lookup
        for &removed_index in &blob_changes.removed_indices {
            // Mark as removed by not adding to map - the map_blob_index method
            // will check removed_indices and return None
            self.blob_removed.insert(removed_index);
        }

        // Handle modified blobs that need remapping (new blob larger than original)
        // These will be appended at the end of the heap
        if let Some(blob_heap) = original_view.blobs() {
            let original_heap_size = u32::try_from(blob_heap.data().len())
                .map_err(|_| malformed_error!("Blob heap size exceeds u32 range"))?;
            let mut next_append_position = original_heap_size;

            // First, collect all modifications that need remapping
            let mut remapped_mods: Vec<(u32, &Vec<u8>)> = Vec::new();

            for (&modified_index, new_blob) in &blob_changes.modified_items {
                // Find the original blob to compare sizes
                if let Some((_, original_blob)) = blob_heap
                    .iter()
                    .find(|(offset, _)| *offset == modified_index as usize)
                {
                    let original_data_size = original_blob.len();
                    let new_blob_size = new_blob.len();

                    // If new blob is larger than original, it needs remapping
                    if new_blob_size > original_data_size {
                        remapped_mods.push((modified_index, new_blob));
                    }
                    // If it fits in place, no mapping needed (identity)
                }
            }

            // Sort by index for deterministic ordering
            remapped_mods.sort_by_key(|(idx, _)| *idx);

            // Calculate new positions for remapped blobs
            for (modified_index, new_blob) in remapped_mods {
                self.blob_map.insert(modified_index, next_append_position);
                // Advance position: length prefix + blob data
                let prefix_size = u32::try_from(compressed_uint_size(new_blob.len()))
                    .map_err(|_| malformed_error!("Blob prefix size exceeds u32 range"))?;
                let blob_len = u32::try_from(new_blob.len())
                    .map_err(|_| malformed_error!("Blob size exceeds u32 range"))?;
                next_append_position += prefix_size + blob_len;
            }
        }

        // Map appended items to their assigned byte offsets
        // The HeapChanges tracks the byte offset for each appended item
        for (vec_index, _) in blob_changes.appended_items.iter().enumerate() {
            if let Some(assigned_index) = blob_changes.get_appended_item_index(vec_index) {
                // Appended items use identity mapping - the assigned index IS the final index
                self.blob_map.insert(assigned_index, assigned_index);
            }
        }

        Ok(())
    }

    /// Build GUID heap index mapping.
    ///
    /// GUID heap indices are 1-based entry numbers (each GUID is exactly 16 bytes).
    /// This method builds mappings for:
    /// - Removed items: No mapping (returns None when queried)
    /// - Original items: Identity mapping (entry position unchanged, data zeroed in place)
    /// - Appended items: Mapped to their assigned entry indices
    ///
    /// Note: The GUID heap writer zeros out removed items in place rather than
    /// compacting the heap, so original entry indices remain valid.
    fn build_guid_mapping(&mut self, guid_changes: &HeapChanges<[u8; 16]>) {
        // Store removed indices for lookup
        for &removed_index in &guid_changes.removed_indices {
            self.guid_removed.insert(removed_index);
        }

        // Map appended items to their assigned entry indices
        // The HeapChanges tracks the entry index for each appended item
        for (vec_index, _) in guid_changes.appended_items.iter().enumerate() {
            if let Some(assigned_index) = guid_changes.get_appended_item_index(vec_index) {
                // Appended items use identity mapping - the assigned index IS the final index
                self.guid_map.insert(assigned_index, assigned_index);
            }
        }
    }

    /// Build UserString heap index mapping.
    ///
    /// UserString heap indices are byte offsets into the heap, not sequential entry numbers.
    /// This method builds mappings for:
    /// - Removed items: No mapping (returns None when queried)
    /// - Original items: Identity mapping (byte offset unchanged, data zeroed in place)
    /// - Appended items: Mapped to their assigned byte offsets
    ///
    /// Note: The UserString heap writer zeros out removed items in place rather than
    /// compacting the heap, so original byte offsets remain valid.
    fn build_userstring_mapping(&mut self, userstring_changes: &HeapChanges<String>) {
        // Store removed indices for lookup
        for &removed_index in &userstring_changes.removed_indices {
            self.userstring_removed.insert(removed_index);
        }

        // Map appended items to their assigned byte offsets
        // The HeapChanges tracks the byte offset for each appended item
        for (vec_index, _) in userstring_changes.appended_items.iter().enumerate() {
            if let Some(assigned_index) = userstring_changes.get_appended_item_index(vec_index) {
                // Appended items use identity mapping - the assigned index IS the final index
                self.userstring_map.insert(assigned_index, assigned_index);
            }
        }
    }

    /// Update all cross-references in table data using this remapping.
    ///
    /// This method applies the constructed remapping tables to update all cross-references
    /// throughout the assembly metadata. This is the final phase of the remapping process
    /// that ensures referential integrity in the output binary.
    ///
    /// # Arguments
    ///
    /// * `changes` - Mutable reference to [`crate::cilassembly::changes::AssemblyChanges`] to update
    ///
    /// # Returns
    ///
    /// [`Result<()>`] indicating success or failure of the cross-reference update process.
    ///
    /// # Implementation
    ///
    /// This method iterates through all table modifications and updates the following cross-references:
    /// 1. String heap indices - updated using string_map
    /// 2. Blob heap indices - updated using blob_map  
    /// 3. GUID heap indices - updated using guid_map
    /// 4. User string heap indices - updated using userstring_map
    /// 5. RID references - updated using table-specific RID remappers
    /// 6. CodedIndex references - updated using appropriate table RID remappers
    pub fn apply_to_assembly(&self, changes: &mut AssemblyChanges) {
        for table_modifications in changes.table_changes.values_mut() {
            match table_modifications {
                TableModifications::Sparse { operations, .. } => {
                    for table_operation in operations {
                        if let Some(row_data) = table_operation.operation.get_row_data_mut() {
                            self.update_table_data_references(row_data);
                        }
                    }
                }
                TableModifications::Replaced(rows) => {
                    for row_data in rows {
                        self.update_table_data_references(row_data);
                    }
                }
            }
        }
    }

    /// Update all cross-references within a specific table row data.
    ///
    /// This method examines the provided table row data and updates all cross-references
    /// (string indices, blob indices, GUID indices, user string indices, RID references,
    /// and CodedIndex references) using the appropriate remapping tables.
    ///
    /// # Arguments
    ///
    /// * `row_data` - Mutable reference to the [`crate::metadata::tables::TableDataOwned`] to update
    ///
    /// # Returns
    ///
    /// No return value as all operations are infallible.
    fn update_table_data_references(&self, row_data: &mut TableDataOwned) {
        match row_data {
            TableDataOwned::Module(row) => {
                self.update_string_index(&mut row.name);
                self.update_guid_index(&mut row.mvid);
                self.update_guid_index(&mut row.encid);
                self.update_guid_index(&mut row.encbaseid);
            }
            TableDataOwned::TypeRef(row) => {
                self.update_coded_index(&mut row.resolution_scope);
                self.update_string_index(&mut row.type_name);
                self.update_string_index(&mut row.type_namespace);
            }
            TableDataOwned::TypeDef(row) => {
                self.update_string_index(&mut row.type_name);
                self.update_string_index(&mut row.type_namespace);
                self.update_coded_index(&mut row.extends);
                self.update_table_index(&mut row.field_list, TableId::Field);
                self.update_table_index(&mut row.method_list, TableId::MethodDef);
            }
            TableDataOwned::FieldPtr(row) => {
                self.update_table_index(&mut row.field, TableId::Field);
            }
            TableDataOwned::Field(row) => {
                self.update_string_index(&mut row.name);
                self.update_blob_index(&mut row.signature);
            }
            TableDataOwned::MethodPtr(row) => {
                self.update_table_index(&mut row.method, TableId::MethodDef);
            }
            TableDataOwned::MethodDef(row) => {
                self.update_string_index(&mut row.name);
                self.update_blob_index(&mut row.signature);
                self.update_table_index(&mut row.param_list, TableId::Param);
            }
            TableDataOwned::ParamPtr(row) => {
                self.update_table_index(&mut row.param, TableId::Param);
            }
            TableDataOwned::Param(row) => {
                self.update_string_index(&mut row.name);
            }
            TableDataOwned::InterfaceImpl(row) => {
                self.update_table_index(&mut row.class, TableId::TypeDef);
                self.update_coded_index(&mut row.interface);
            }

            // Reference and Attribute Tables (0x0A-0x0E)
            TableDataOwned::MemberRef(row) => {
                self.update_coded_index(&mut row.class);
                self.update_string_index(&mut row.name);
                self.update_blob_index(&mut row.signature);
            }
            TableDataOwned::Constant(row) => {
                self.update_coded_index(&mut row.parent);
                self.update_blob_index(&mut row.value);
            }
            TableDataOwned::CustomAttribute(row) => {
                self.update_coded_index(&mut row.parent);
                self.update_coded_index(&mut row.constructor);
                self.update_blob_index(&mut row.value);
            }
            TableDataOwned::FieldMarshal(row) => {
                self.update_coded_index(&mut row.parent);
                self.update_blob_index(&mut row.native_type);
            }
            TableDataOwned::DeclSecurity(row) => {
                self.update_coded_index(&mut row.parent);
                self.update_blob_index(&mut row.permission_set);
            }
            TableDataOwned::ClassLayout(row) => {
                self.update_table_index(&mut row.parent, TableId::TypeDef);
            }
            TableDataOwned::FieldLayout(row) => {
                self.update_table_index(&mut row.field, TableId::Field);
            }
            TableDataOwned::StandAloneSig(row) => {
                self.update_blob_index(&mut row.signature);
            }
            TableDataOwned::EventMap(row) => {
                self.update_table_index(&mut row.parent, TableId::TypeDef);
                self.update_table_index(&mut row.event_list, TableId::Event);
            }
            TableDataOwned::EventPtr(row) => {
                self.update_table_index(&mut row.event, TableId::Event);
            }
            TableDataOwned::Event(row) => {
                self.update_string_index(&mut row.name);
                self.update_coded_index(&mut row.event_type);
            }
            TableDataOwned::PropertyMap(row) => {
                self.update_table_index(&mut row.parent, TableId::TypeDef);
                self.update_table_index(&mut row.property_list, TableId::Property);
            }
            TableDataOwned::PropertyPtr(row) => {
                self.update_table_index(&mut row.property, TableId::Property);
            }
            TableDataOwned::Property(row) => {
                self.update_string_index(&mut row.name);
                self.update_blob_index(&mut row.signature);
            }
            TableDataOwned::MethodSemantics(row) => {
                self.update_table_index(&mut row.method, TableId::MethodDef);
                self.update_coded_index(&mut row.association);
            }
            TableDataOwned::MethodImpl(row) => {
                self.update_table_index(&mut row.class, TableId::TypeDef);
                self.update_coded_index(&mut row.method_body);
                self.update_coded_index(&mut row.method_declaration);
            }
            TableDataOwned::ModuleRef(row) => {
                self.update_string_index(&mut row.name);
            }
            TableDataOwned::TypeSpec(row) => {
                self.update_blob_index(&mut row.signature);
            }
            TableDataOwned::ImplMap(row) => {
                self.update_coded_index(&mut row.member_forwarded);
                self.update_string_index(&mut row.import_name);
                self.update_table_index(&mut row.import_scope, TableId::ModuleRef);
            }
            TableDataOwned::FieldRVA(row) => {
                self.update_table_index(&mut row.field, TableId::Field);
            }
            TableDataOwned::Assembly(row) => {
                self.update_string_index(&mut row.name);
                self.update_string_index(&mut row.culture);
                self.update_blob_index(&mut row.public_key);
            }
            TableDataOwned::AssemblyProcessor(_)
            | TableDataOwned::AssemblyOS(_)
            | TableDataOwned::EncLog(_)
            | TableDataOwned::EncMap(_) => {
                // No cross-references to update
            }
            TableDataOwned::AssemblyRef(row) => {
                self.update_string_index(&mut row.name);
                self.update_string_index(&mut row.culture);
                self.update_blob_index(&mut row.public_key_or_token);
                self.update_blob_index(&mut row.hash_value);
            }
            TableDataOwned::AssemblyRefProcessor(row) => {
                self.update_table_index(&mut row.assembly_ref, TableId::AssemblyRef);
            }
            TableDataOwned::AssemblyRefOS(row) => {
                self.update_table_index(&mut row.assembly_ref, TableId::AssemblyRef);
            }
            TableDataOwned::File(row) => {
                self.update_string_index(&mut row.name);
                self.update_blob_index(&mut row.hash_value);
            }
            TableDataOwned::ExportedType(row) => {
                self.update_string_index(&mut row.name);
                self.update_string_index(&mut row.namespace);
                self.update_coded_index(&mut row.implementation);
            }
            TableDataOwned::ManifestResource(row) => {
                self.update_string_index(&mut row.name);
                self.update_coded_index(&mut row.implementation);
            }
            TableDataOwned::NestedClass(row) => {
                self.update_table_index(&mut row.nested_class, TableId::TypeDef);
                self.update_table_index(&mut row.enclosing_class, TableId::TypeDef);
            }
            TableDataOwned::GenericParam(row) => {
                self.update_coded_index(&mut row.owner);
                self.update_string_index(&mut row.name);
            }
            TableDataOwned::MethodSpec(row) => {
                self.update_coded_index(&mut row.method);
                self.update_blob_index(&mut row.instantiation);
            }
            TableDataOwned::GenericParamConstraint(row) => {
                self.update_table_index(&mut row.owner, TableId::GenericParam);
                self.update_coded_index(&mut row.constraint);
            }
            TableDataOwned::Document(row) => {
                self.update_blob_index(&mut row.name);
                self.update_guid_index(&mut row.hash_algorithm);
                self.update_blob_index(&mut row.hash);
                self.update_guid_index(&mut row.language);
            }
            TableDataOwned::MethodDebugInformation(row) => {
                self.update_table_index(&mut row.document, TableId::Document);
                self.update_blob_index(&mut row.sequence_points);
            }
            TableDataOwned::LocalScope(row) => {
                self.update_table_index(&mut row.method, TableId::MethodDef);
                self.update_table_index(&mut row.import_scope, TableId::ImportScope);
                self.update_table_index(&mut row.variable_list, TableId::LocalVariable);
                self.update_table_index(&mut row.constant_list, TableId::LocalConstant);
            }
            TableDataOwned::LocalVariable(row) => {
                self.update_string_index(&mut row.name);
            }
            TableDataOwned::LocalConstant(row) => {
                self.update_string_index(&mut row.name);
                self.update_blob_index(&mut row.signature);
            }
            TableDataOwned::ImportScope(row) => {
                self.update_table_index(&mut row.parent, TableId::ImportScope);
                self.update_blob_index(&mut row.imports);
            }
            TableDataOwned::StateMachineMethod(row) => {
                self.update_table_index(&mut row.move_next_method, TableId::MethodDef);
                self.update_table_index(&mut row.kickoff_method, TableId::MethodDef);
            }
            TableDataOwned::CustomDebugInformation(row) => {
                self.update_coded_index(&mut row.parent);
                self.update_guid_index(&mut row.kind);
                self.update_blob_index(&mut row.value);
            }
        }
    }

    /// Update a string heap index reference.
    fn update_string_index(&self, index: &mut u32) {
        if *index != 0 {
            if let Some(new_index) = self.string_map.get(index) {
                *index = *new_index;
            }
        }
    }

    /// Update a blob heap index reference.
    fn update_blob_index(&self, index: &mut u32) {
        if *index != 0 {
            if let Some(new_index) = self.blob_map.get(index) {
                *index = *new_index;
            }
        }
    }

    /// Update a GUID heap index reference.
    fn update_guid_index(&self, index: &mut u32) {
        if *index != 0 {
            if let Some(new_index) = self.guid_map.get(index) {
                *index = *new_index;
            }
        }
    }

    /// Update a user string heap index reference.
    fn update_userstring_index(&self, index: &mut u32) {
        if *index != 0 {
            if let Some(new_index) = self.userstring_map.get(index) {
                *index = *new_index;
            }
        }
    }

    /// Update a direct table RID reference.
    fn update_table_index(&self, index: &mut u32, table_id: TableId) {
        if *index != 0 {
            if let Some(remapper) = self.table_maps.get(&table_id) {
                if let Some(new_rid) = remapper.map_rid(*index) {
                    *index = new_rid;
                }
            }
        }
    }

    /// Update a CodedIndex reference.
    fn update_coded_index(&self, coded_index: &mut CodedIndex) {
        if coded_index.row != 0 {
            if let Some(remapper) = self.table_maps.get(&coded_index.tag) {
                if let Some(new_rid) = remapper.map_rid(coded_index.row) {
                    // Create a new CodedIndex with the updated RID
                    *coded_index = CodedIndex::new(coded_index.tag, new_rid, coded_index.ci_type);
                }
            }
        }
    }

    /// Get the final index for a string heap index.
    ///
    /// String heap indices are byte offsets. For byte-offset heaps:
    /// - Removed indices return `None`
    /// - Non-removed indices return identity mapping (same index)
    /// - Appended items return their assigned byte offset
    ///
    /// # Arguments
    ///
    /// * `original_index` - The original string heap byte offset to map
    ///
    /// # Returns
    ///
    /// `Some(final_index)` if the index is valid, `None` if removed.
    pub fn map_string_index(&self, original_index: u32) -> Option<u32> {
        if self.string_removed.contains(&original_index) {
            None
        } else if let Some(&mapped) = self.string_map.get(&original_index) {
            Some(mapped)
        } else {
            // Identity mapping for non-removed, non-appended indices
            Some(original_index)
        }
    }

    /// Get the final index for a blob heap index.
    ///
    /// Blob heap indices are byte offsets. For byte-offset heaps:
    /// - Removed indices return `None`
    /// - Non-removed indices return identity mapping (same index)
    /// - Appended items return their assigned byte offset
    ///
    /// # Arguments
    ///
    /// * `original_index` - The original blob heap byte offset to map
    ///
    /// # Returns
    ///
    /// `Some(final_index)` if the index is valid, `None` if removed.
    pub fn map_blob_index(&self, original_index: u32) -> Option<u32> {
        if self.blob_removed.contains(&original_index) {
            None
        } else if let Some(&mapped) = self.blob_map.get(&original_index) {
            Some(mapped)
        } else {
            // Identity mapping for non-removed, non-appended indices
            Some(original_index)
        }
    }

    /// Get the final index for a GUID heap index.
    ///
    /// GUID heap uses 1-based entry indices (not byte offsets).
    /// Returns `None` if the index was removed.
    ///
    /// This method is part of the public API for cross-reference updates and external
    /// consumers that need to remap GUID indices after assembly modifications.
    pub fn map_guid_index(&self, original_index: u32) -> Option<u32> {
        if self.guid_removed.contains(&original_index) {
            None
        } else if let Some(&mapped) = self.guid_map.get(&original_index) {
            Some(mapped)
        } else {
            // Identity mapping for non-removed, non-appended indices
            Some(original_index)
        }
    }

    /// Get the final index for a UserString heap index.
    ///
    /// UserString heap indices are byte offsets (like blob heap).
    /// Returns `None` if the index was removed.
    ///
    /// This method is part of the public API for cross-reference updates and external
    /// consumers that need to remap UserString indices after assembly modifications.
    pub fn map_userstring_index(&self, original_index: u32) -> Option<u32> {
        if self.userstring_removed.contains(&original_index) {
            None
        } else if let Some(&mapped) = self.userstring_map.get(&original_index) {
            Some(mapped)
        } else {
            // Identity mapping for non-removed, non-appended indices
            Some(original_index)
        }
    }

    /// Get the RID remapper for a specific table.
    ///
    /// Retrieves the [`crate::cilassembly::remapping::rid::RidRemapper`] instance for a specific
    /// table, if that table has been modified. This provides access to table-specific
    /// RID mapping functionality.
    ///
    /// # Arguments
    ///
    /// * `table_id` - The [`crate::metadata::tables::TableId`] to get the remapper for
    ///
    /// # Returns
    ///
    /// `Some(&RidRemapper)` if the table has modifications, `None` if the table
    /// has not been modified and thus has no remapper.
    pub fn get_table_remapper(&self, table_id: TableId) -> Option<&RidRemapper> {
        self.table_maps.get(&table_id)
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::{
        cilassembly::{
            AssemblyChanges, HeapChanges, Operation, TableModifications, TableOperation,
        },
        metadata::{cilassemblyview::CilAssemblyView, tables::CodedIndexType, token::Token},
        test::factories::table::cilassembly::create_test_row,
    };

    #[test]
    fn test_index_remapper_empty_changes() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_path(&path) {
            let changes = AssemblyChanges::empty();
            let remapper = IndexRemapper::build_from_changes(&changes, &view).unwrap();

            // Empty changes should result in empty mappings
            assert!(remapper.string_map.is_empty());
            assert!(remapper.blob_map.is_empty());
            assert!(remapper.guid_map.is_empty());
            assert!(remapper.userstring_map.is_empty());
            assert!(remapper.table_maps.is_empty());
        }
    }

    #[test]
    fn test_index_remapper_string_heap_mapping() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_path(&path) {
            let mut changes = AssemblyChanges::empty();

            // Add some strings to heap
            let mut string_changes = HeapChanges::new(203731); // WindowsBase.dll string heap size
            string_changes.appended_items.push("Hello".to_string());
            string_changes.appended_items.push("World".to_string());
            string_changes.next_index = 203733; // Original size + 2
            changes.string_heap_changes = string_changes;

            let remapper = IndexRemapper::build_from_changes(&changes, &view).unwrap();

            // Check that original indices are preserved
            assert_eq!(remapper.map_string_index(1), Some(1));
            assert_eq!(remapper.map_string_index(100), Some(100));
            assert_eq!(remapper.map_string_index(203731), Some(203731));

            // Check that new strings get sequential mapping
            assert_eq!(remapper.map_string_index(203732), Some(203732)); // First new string
            assert_eq!(remapper.map_string_index(203733), Some(203733)); // Second new string
        }
    }

    #[test]
    fn test_index_remapper_blob_heap_mapping() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_path(&path) {
            let mut changes = AssemblyChanges::empty();

            // Add some blobs to heap
            let mut blob_changes = HeapChanges::new(77816); // WindowsBase.dll blob heap size
            blob_changes.appended_items.push(vec![1, 2, 3]);
            blob_changes.appended_items.push(vec![4, 5, 6]);
            blob_changes.next_index = 77818; // Original size + 2
            changes.blob_heap_changes = blob_changes;

            let remapper = IndexRemapper::build_from_changes(&changes, &view).unwrap();

            // Check that original indices are preserved
            assert_eq!(remapper.map_blob_index(1), Some(1));
            assert_eq!(remapper.map_blob_index(100), Some(100));
            assert_eq!(remapper.map_blob_index(77816), Some(77816));

            // Check that new blobs get sequential mapping
            assert_eq!(remapper.map_blob_index(77817), Some(77817)); // First new blob
            assert_eq!(remapper.map_blob_index(77818), Some(77818)); // Second new blob
        }
    }

    #[test]
    fn test_index_remapper_table_remapping() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_path(&path) {
            let mut changes = AssemblyChanges::empty();

            // Add table operations
            let mut table_modifications = TableModifications::new_sparse(1);
            let insert_op = TableOperation::new(Operation::Insert(1000, create_test_row()));
            table_modifications.apply_operation(insert_op).unwrap();
            changes
                .table_changes
                .insert(TableId::TypeDef, table_modifications);

            let remapper = IndexRemapper::build_from_changes(&changes, &view).unwrap();

            // Check that table remapper was created
            assert!(remapper.get_table_remapper(TableId::TypeDef).is_some());

            let table_remapper = remapper.get_table_remapper(TableId::TypeDef).unwrap();

            // Verify that the RID mapping works
            assert!(table_remapper.map_rid(1000).is_some());
        }
    }

    #[test]
    fn test_index_remapper_replaced_table() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_path(&path) {
            let mut changes = AssemblyChanges::empty();

            // Create replaced table
            let rows = vec![create_test_row(), create_test_row(), create_test_row()];
            let replaced_modifications = TableModifications::Replaced(rows);
            changes
                .table_changes
                .insert(TableId::TypeDef, replaced_modifications);

            let remapper = IndexRemapper::build_from_changes(&changes, &view).unwrap();

            // Check that table remapper was created
            let table_remapper = remapper.get_table_remapper(TableId::TypeDef).unwrap();

            // Verify replaced table mapping (1:1 mapping for 3 rows)
            assert_eq!(table_remapper.map_rid(1), Some(1));
            assert_eq!(table_remapper.map_rid(2), Some(2));
            assert_eq!(table_remapper.map_rid(3), Some(3));
            assert_eq!(table_remapper.final_row_count(), 3);
        }
    }

    #[test]
    fn test_index_remapper_guid_heap_mapping() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_path(&path) {
            let mut changes = AssemblyChanges::empty();

            // Add some GUIDs to heap
            let mut guid_changes = HeapChanges::new(1); // WindowsBase.dll has 1 GUID (16 bytes / 16 = 1)
            guid_changes.appended_items.push([1; 16]);
            guid_changes.appended_items.push([2; 16]);
            guid_changes.next_index = 3; // Original count + 2
            changes.guid_heap_changes = guid_changes;

            let remapper = IndexRemapper::build_from_changes(&changes, &view).unwrap();

            // Check that original indices are preserved
            assert_eq!(remapper.map_guid_index(1), Some(1));

            // Check that new GUIDs get sequential mapping
            assert_eq!(remapper.map_guid_index(2), Some(2)); // First new GUID
            assert_eq!(remapper.map_guid_index(3), Some(3)); // Second new GUID
        }
    }

    #[test]
    fn test_index_remapper_mixed_changes() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_path(&path) {
            let mut changes = AssemblyChanges::empty();

            // Add string changes with properly assigned byte offsets
            let mut string_changes = HeapChanges::new(203731);
            string_changes.appended_items.push("Test".to_string());
            string_changes.appended_item_indices.push(203731); // Byte offset for appended string
            string_changes.next_index = 203732;
            changes.string_heap_changes = string_changes;

            // Add blob changes with properly assigned byte offsets
            let mut blob_changes = HeapChanges::new(77816);
            blob_changes.appended_items.push(vec![0xAB, 0xCD]);
            blob_changes.appended_item_indices.push(77816); // Byte offset for appended blob
            blob_changes.next_index = 77817;
            changes.blob_heap_changes = blob_changes;

            // Add table changes
            let mut table_modifications = TableModifications::new_sparse(1);
            let insert_op = TableOperation::new(Operation::Insert(500, create_test_row()));
            table_modifications.apply_operation(insert_op).unwrap();
            changes
                .table_changes
                .insert(TableId::TypeDef, table_modifications);

            let remapper = IndexRemapper::build_from_changes(&changes, &view).unwrap();

            // Verify appended item mappings were created
            assert!(!remapper.string_map.is_empty());
            assert!(!remapper.blob_map.is_empty());
            assert!(!remapper.table_maps.is_empty());

            // Test specific mappings - appended items use identity mapping
            assert_eq!(remapper.map_string_index(203731), Some(203731));
            assert_eq!(remapper.map_blob_index(77816), Some(77816));
            assert!(remapper.get_table_remapper(TableId::TypeDef).is_some());

            // Non-appended, non-removed indices also use identity mapping
            assert_eq!(remapper.map_string_index(100), Some(100));
            assert_eq!(remapper.map_blob_index(50), Some(50));
        }
    }

    #[test]
    fn test_heap_identity_mapping_with_removed_items() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_path(&path) {
            let mut changes = AssemblyChanges::empty();

            // Create string heap changes with removed items
            let mut string_changes = HeapChanges::new(10); // Original heap byte size
            string_changes.removed_indices.insert(2); // Remove item at byte offset 2
            string_changes.removed_indices.insert(5); // Remove item at byte offset 5
            string_changes.removed_indices.insert(8); // Remove item at byte offset 8
                                                      // Appended items get assigned byte offsets starting after original heap
            string_changes.appended_items.push("NewString1".to_string());
            string_changes.appended_item_indices.push(10); // Assigned byte offset 10
            string_changes.appended_items.push("NewString2".to_string());
            string_changes.appended_item_indices.push(21); // Assigned byte offset 21
            string_changes.next_index = 32; // Updated next_index
            changes.string_heap_changes = string_changes;

            let remapper = IndexRemapper::build_from_changes(&changes, &view).unwrap();

            // Verify removed items return None
            assert_eq!(remapper.map_string_index(2), None); // Removed
            assert_eq!(remapper.map_string_index(5), None); // Removed
            assert_eq!(remapper.map_string_index(8), None); // Removed

            // Verify non-removed items use identity mapping (byte offsets stay the same)
            assert_eq!(remapper.map_string_index(1), Some(1)); // Identity
            assert_eq!(remapper.map_string_index(3), Some(3)); // Identity
            assert_eq!(remapper.map_string_index(4), Some(4)); // Identity
            assert_eq!(remapper.map_string_index(6), Some(6)); // Identity
            assert_eq!(remapper.map_string_index(7), Some(7)); // Identity
            assert_eq!(remapper.map_string_index(9), Some(9)); // Identity

            // Verify appended items use their assigned byte offsets (identity mapping)
            assert_eq!(remapper.map_string_index(10), Some(10)); // First new string
            assert_eq!(remapper.map_string_index(21), Some(21)); // Second new string
        }
    }

    #[test]
    fn test_cross_reference_integrity_after_remapping() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_path(&path) {
            let mut changes = AssemblyChanges::empty();

            // Create TypeDef with cross-references that need updating
            let mut test_typedef = create_test_row();
            if let TableDataOwned::TypeDef(ref mut typedef_data) = test_typedef {
                typedef_data.type_name = 50; // String index
                typedef_data.type_namespace = 100; // String index
                typedef_data.field_list = 25; // Field table RID
                typedef_data.method_list = 75; // MethodDef table RID
                typedef_data.extends =
                    CodedIndex::new(TableId::TypeRef, 10, CodedIndexType::TypeDefOrRef);
                // CodedIndex
            }

            // Add table operation with the test row
            let mut table_modifications = TableModifications::new_sparse(1);
            let insert_op = TableOperation::new(Operation::Insert(1000, test_typedef));
            table_modifications.apply_operation(insert_op).unwrap();
            changes
                .table_changes
                .insert(TableId::TypeDef, table_modifications);

            // Create string heap changes to test cross-reference updating
            let mut string_changes = HeapChanges::new(200);
            string_changes.removed_indices.insert(60); // Remove an index
            string_changes.removed_indices.insert(90); // Remove another index
            string_changes.appended_items.push("TestString".to_string());
            changes.string_heap_changes = string_changes;

            // Build remapper and apply cross-reference updates
            let remapper = IndexRemapper::build_from_changes(&changes, &view).unwrap();
            let mut updated_changes = changes;

            // Apply cross-reference remapping
            remapper.apply_to_assembly(&mut updated_changes);

            // Verify cross-references were updated correctly
            if let Some(TableModifications::Sparse { operations, .. }) =
                updated_changes.table_changes.get(&TableId::TypeDef)
            {
                if let Some(TableDataOwned::TypeDef(typedef_data)) =
                    operations[0].operation.get_row_data()
                {
                    // String indices use identity mapping (no compaction)
                    // Original index 50 stays 50 (not removed)
                    assert_eq!(typedef_data.type_name, 50);
                    // Original index 100 stays 100 (not removed, identity mapping)
                    assert_eq!(typedef_data.type_namespace, 100);

                    // Table RIDs should remain unchanged if no table remapping
                    assert_eq!(typedef_data.field_list, 25);
                    assert_eq!(typedef_data.method_list, 75);

                    // CodedIndex should remain unchanged if target table not remapped
                    assert_eq!(typedef_data.extends.row, 10);
                    assert_eq!(typedef_data.extends.tag, TableId::TypeRef);
                }
            }
        }
    }

    #[test]
    fn test_multiple_heap_identity_mapping() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_path(&path) {
            let mut changes = AssemblyChanges::empty();

            // Test blob heap - byte offset based, identity mapping
            let mut blob_changes = HeapChanges::new(20);
            blob_changes.removed_indices.insert(3);
            blob_changes.removed_indices.insert(7);
            blob_changes.removed_indices.insert(15);
            // Appended items with assigned byte offsets
            blob_changes.appended_items.push(vec![0x01, 0x02]);
            blob_changes.appended_item_indices.push(20);
            blob_changes.appended_items.push(vec![0x03, 0x04]);
            blob_changes.appended_item_indices.push(23);
            blob_changes.next_index = 26;
            changes.blob_heap_changes = blob_changes;

            // Test GUID heap - 1-based entry indices, identity mapping
            let mut guid_changes = HeapChanges::new(80); // 5 GUIDs = 80 bytes
            guid_changes.removed_indices.insert(2);
            guid_changes.removed_indices.insert(4);
            guid_changes.appended_items.push([0xFF; 16]);
            guid_changes.appended_item_indices.push(6); // 6th GUID entry
            guid_changes.next_index = 96;
            changes.guid_heap_changes = guid_changes;

            // Test user string heap - byte offset based, identity mapping
            let mut userstring_changes = HeapChanges::new(15);
            userstring_changes.removed_indices.insert(1);
            userstring_changes.removed_indices.insert(10);
            userstring_changes
                .appended_items
                .push("UserString1".to_string());
            userstring_changes.appended_item_indices.push(15);
            userstring_changes.next_index = 38;
            changes.userstring_heap_changes = userstring_changes;

            let remapper = IndexRemapper::build_from_changes(&changes, &view).unwrap();

            // Verify blob heap - identity mapping, removed returns None
            assert_eq!(remapper.map_blob_index(3), None); // Removed
            assert_eq!(remapper.map_blob_index(7), None); // Removed
            assert_eq!(remapper.map_blob_index(15), None); // Removed
            assert_eq!(remapper.map_blob_index(1), Some(1)); // Identity
            assert_eq!(remapper.map_blob_index(2), Some(2)); // Identity
            assert_eq!(remapper.map_blob_index(4), Some(4)); // Identity
            assert_eq!(remapper.map_blob_index(5), Some(5)); // Identity
            assert_eq!(remapper.map_blob_index(6), Some(6)); // Identity
            assert_eq!(remapper.map_blob_index(8), Some(8)); // Identity
            assert_eq!(remapper.map_blob_index(20), Some(20)); // Appended, identity

            // Verify GUID heap - identity mapping, removed returns None
            assert_eq!(remapper.map_guid_index(2), None); // Removed
            assert_eq!(remapper.map_guid_index(4), None); // Removed
            assert_eq!(remapper.map_guid_index(1), Some(1)); // Identity
            assert_eq!(remapper.map_guid_index(3), Some(3)); // Identity
            assert_eq!(remapper.map_guid_index(5), Some(5)); // Identity
            assert_eq!(remapper.map_guid_index(6), Some(6)); // Appended, identity

            // Verify user string heap - identity mapping, removed returns None
            assert_eq!(remapper.map_userstring_index(1), None); // Removed
            assert_eq!(remapper.map_userstring_index(10), None); // Removed
            assert_eq!(remapper.map_userstring_index(2), Some(2)); // Identity
            assert_eq!(remapper.map_userstring_index(5), Some(5)); // Identity
            assert_eq!(remapper.map_userstring_index(11), Some(11)); // Identity
            assert_eq!(remapper.map_userstring_index(15), Some(15)); // Appended, identity
        }
    }

    #[test]
    fn test_edge_case_empty_heaps() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_path(&path) {
            let mut changes = AssemblyChanges::empty();

            // Test with empty heaps (only default size 1)
            let string_changes = HeapChanges::new(1);
            let blob_changes = HeapChanges::new(1);
            let guid_changes = HeapChanges::new(0); // GUID heap can be empty
            let userstring_changes = HeapChanges::new(1);

            changes.string_heap_changes = string_changes;
            changes.blob_heap_changes = blob_changes;
            changes.guid_heap_changes = guid_changes;
            changes.userstring_heap_changes = userstring_changes;

            let remapper = IndexRemapper::build_from_changes(&changes, &view).unwrap();

            // All heap maps should be empty since no appended items were added
            assert!(remapper.string_map.is_empty());
            assert!(remapper.blob_map.is_empty());
            assert!(remapper.guid_map.is_empty());
            assert!(remapper.userstring_map.is_empty());

            // With identity mapping, non-removed indices return identity mapping (not None)
            // Querying any index that isn't explicitly in removed set returns identity mapping
            assert_eq!(remapper.map_string_index(1), Some(1));
            assert_eq!(remapper.map_blob_index(1), Some(1));
            assert_eq!(remapper.map_guid_index(1), Some(1));
            assert_eq!(remapper.map_userstring_index(1), Some(1));
        }
    }

    #[test]
    fn test_edge_case_all_items_removed() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_path(&path) {
            let mut changes = AssemblyChanges::empty();

            // Test scenario where all original items are removed
            let mut string_changes = HeapChanges::new(5);
            for i in 1..=5 {
                string_changes.removed_indices.insert(i);
            }
            // Appended item gets assigned byte offset at original_heap_size
            string_changes
                .appended_items
                .push("OnlyNewString".to_string());
            string_changes.appended_item_indices.push(5); // Byte offset 5
            changes.string_heap_changes = string_changes;

            let remapper = IndexRemapper::build_from_changes(&changes, &view).unwrap();

            // All removed indices should return None
            for i in 1..=5 {
                assert_eq!(remapper.map_string_index(i), None);
            }

            // The new string at byte offset 5 uses identity mapping
            assert_eq!(remapper.map_string_index(5), None); // But 5 was also removed - removed takes precedence

            // Non-removed, non-appended indices use identity mapping
            assert_eq!(remapper.map_string_index(6), Some(6)); // Identity mapping
        }
    }

    #[test]
    fn test_cross_reference_update_comprehensive() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_path(&path) {
            let mut changes = AssemblyChanges::empty();

            // Create a complex row with multiple types of cross-references
            let complex_row =
                TableDataOwned::CustomAttribute(crate::metadata::tables::CustomAttributeRaw {
                    rid: 1,
                    token: Token::new(0x0C000001),
                    offset: 0,
                    parent: CodedIndex::new(
                        TableId::TypeDef,
                        15,
                        CodedIndexType::HasCustomAttribute,
                    ), // CodedIndex reference
                    constructor: CodedIndex::new(
                        TableId::MethodDef,
                        25,
                        CodedIndexType::CustomAttributeType,
                    ), // CodedIndex reference
                    value: 150, // Blob heap index
                });

            // Add table operation
            let mut table_modifications = TableModifications::new_sparse(1);
            let insert_op = TableOperation::new(Operation::Insert(2000, complex_row));
            table_modifications.apply_operation(insert_op).unwrap();
            changes
                .table_changes
                .insert(TableId::CustomAttribute, table_modifications);

            // Create heap changes that will affect the cross-references
            let mut blob_changes = HeapChanges::new(200);
            blob_changes.removed_indices.insert(100); // Remove blob at 100
            blob_changes.removed_indices.insert(120); // Remove blob at 120
            changes.blob_heap_changes = blob_changes;

            // Create table RID remapping for the referenced tables
            let mut typedef_modifications = TableModifications::new_sparse(20);
            let delete_op = TableOperation::new(Operation::Delete(10)); // Delete TypeDef RID 10
            typedef_modifications.apply_operation(delete_op).unwrap();
            changes
                .table_changes
                .insert(TableId::TypeDef, typedef_modifications);

            let remapper = IndexRemapper::build_from_changes(&changes, &view).unwrap();
            let mut updated_changes = changes;

            // Apply cross-reference updates
            remapper.apply_to_assembly(&mut updated_changes);

            // Verify the CustomAttribute row was updated correctly
            if let Some(TableModifications::Sparse { operations, .. }) =
                updated_changes.table_changes.get(&TableId::CustomAttribute)
            {
                if let Some(TableDataOwned::CustomAttribute(attr_data)) =
                    operations[0].operation.get_row_data()
                {
                    // Blob index uses identity mapping (150 stays 150, removed items are zeroed in place)
                    assert_eq!(attr_data.value, 150);

                    // CodedIndex references should be updated for RID remapping (RID 15 -> 14 after deleting RID 10)
                    assert_eq!(attr_data.parent.row, 14);
                    assert_eq!(attr_data.parent.tag, TableId::TypeDef);
                    assert_eq!(attr_data.constructor.row, 25); // MethodDef RID unchanged since no MethodDef table changes
                    assert_eq!(attr_data.constructor.tag, TableId::MethodDef);
                }
            }
        }
    }

    #[test]
    fn test_large_heap_performance() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_path(&path) {
            let mut changes = AssemblyChanges::empty();

            // Simulate a large heap with many removals (performance test)
            let mut string_changes = HeapChanges::new(10000);
            // Remove every 10th item (removed items are zeroed in place, no compaction)
            for i in (10..10000).step_by(10) {
                string_changes.removed_indices.insert(i);
            }
            // Add many new strings (they would be appended at byte offsets beyond original heap)
            for i in 0..1000 {
                string_changes.appended_items.push(format!("TestString{i}"));
            }
            changes.string_heap_changes = string_changes;

            let start = std::time::Instant::now();
            let remapper = IndexRemapper::build_from_changes(&changes, &view).unwrap();
            let build_time = start.elapsed();

            // Verify identity mapping works correctly (no compaction)
            assert_eq!(remapper.map_string_index(5), Some(5)); // Not removed, identity
            assert_eq!(remapper.map_string_index(10), None); // Removed
            assert_eq!(remapper.map_string_index(15), Some(15)); // Not removed, identity
            assert_eq!(remapper.map_string_index(25), Some(25)); // Not removed, identity

            // Test that performance is reasonable (should complete in well under 1 second)
            assert!(
                build_time.as_millis() < 1000,
                "Heap remapping took too long: {build_time:?}"
            );

            println!("Large heap remapping completed in: {build_time:?}");
        }
    }
}
