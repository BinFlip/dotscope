//! Index remapping for binary generation.

use std::collections::HashMap;

use crate::{
    metadata::{
        cilassembly::{remapping::RidRemapper, AssemblyChanges, HeapChanges, TableModifications},
        cilassemblyview::CilAssemblyView,
        tables::TableId,
    },
    Result,
};

/// Manages index remapping during binary generation phase.
pub struct IndexRemapper {
    /// String heap: Original index -> Final index  
    pub string_map: HashMap<u32, u32>,
    /// Blob heap: Original index -> Final index
    pub blob_map: HashMap<u32, u32>,
    /// GUID heap: Original index -> Final index
    pub guid_map: HashMap<u32, u32>,
    /// UserString heap: Original index -> Final index
    pub userstring_map: HashMap<u32, u32>,
    /// Per-table RID mapping: Original RID -> Final RID (None = deleted)
    pub table_maps: HashMap<TableId, RidRemapper>,
}

impl IndexRemapper {
    /// Build complete remapping for all modified tables and heaps.
    pub fn build_from_changes(changes: &AssemblyChanges, original_view: &CilAssemblyView) -> Self {
        let mut remapper = Self {
            string_map: HashMap::new(),
            blob_map: HashMap::new(),
            guid_map: HashMap::new(),
            userstring_map: HashMap::new(),
            table_maps: HashMap::new(),
        };

        remapper.build_heap_remapping(changes, original_view);
        remapper.build_table_remapping(changes, original_view);
        remapper
    }

    /// Build heap index remapping for all modified heaps.
    fn build_heap_remapping(&mut self, changes: &AssemblyChanges, original_view: &CilAssemblyView) {
        if changes.string_heap_changes.has_additions() {
            self.build_string_mapping(&changes.string_heap_changes, original_view);
        }

        if changes.blob_heap_changes.has_additions() {
            self.build_blob_mapping(&changes.blob_heap_changes, original_view);
        }

        if changes.guid_heap_changes.has_additions() {
            self.build_guid_mapping(&changes.guid_heap_changes, original_view);
        }

        if changes.userstring_heap_changes.has_additions() {
            self.build_userstring_mapping(&changes.userstring_heap_changes, original_view);
        }
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
                    let mut rid_remapper = RidRemapper::new(rows.len() as u32);

                    // Map each row index to sequential RID
                    for i in 0..rows.len() {
                        let rid = (i + 1) as u32;
                        rid_remapper.mapping.insert(rid, Some(rid));
                    }

                    self.table_maps.insert(*table_id, rid_remapper);
                }
            }
        }
    }

    /// Build string heap index mapping.
    fn build_string_mapping(
        &mut self,
        string_changes: &HeapChanges<String>,
        original_view: &CilAssemblyView,
    ) {
        let original_size = original_view
            .streams()
            .iter()
            .find(|stream| stream.name == "#Strings")
            .map(|stream| stream.size)
            .unwrap_or(1);

        for i in 1..=original_size {
            self.string_map.insert(i, i);
        }

        for (i, _) in string_changes.appended_items.iter().enumerate() {
            let index = original_size + 1 + i as u32;
            self.string_map.insert(index, index);
        }
    }

    /// Build blob heap index mapping.
    fn build_blob_mapping(
        &mut self,
        blob_changes: &HeapChanges<Vec<u8>>,
        original_view: &CilAssemblyView,
    ) {
        let original_size = original_view
            .streams()
            .iter()
            .find(|stream| stream.name == "#Blob")
            .map(|stream| stream.size)
            .unwrap_or(1);

        for i in 1..=original_size {
            self.blob_map.insert(i, i);
        }

        for (i, _) in blob_changes.appended_items.iter().enumerate() {
            let index = original_size + 1 + i as u32;
            self.blob_map.insert(index, index);
        }
    }

    /// Build GUID heap index mapping.
    fn build_guid_mapping(
        &mut self,
        guid_changes: &HeapChanges<[u8; 16]>,
        original_view: &CilAssemblyView,
    ) {
        let original_count = original_view
            .streams()
            .iter()
            .find(|stream| stream.name == "#GUID")
            .map(|stream| stream.size / 16)
            .unwrap_or(0);

        for i in 1..=original_count {
            self.guid_map.insert(i, i);
        }

        for (i, _) in guid_changes.appended_items.iter().enumerate() {
            let index = original_count + 1 + i as u32;
            self.guid_map.insert(index, index);
        }
    }

    /// Build UserString heap index mapping.
    fn build_userstring_mapping(
        &mut self,
        userstring_changes: &HeapChanges<String>,
        original_view: &CilAssemblyView,
    ) {
        let original_size = original_view
            .streams()
            .iter()
            .find(|stream| stream.name == "#US")
            .map(|stream| stream.size)
            .unwrap_or(1);

        for i in 1..=original_size {
            self.userstring_map.insert(i, i);
        }

        for (i, _) in userstring_changes.appended_items.iter().enumerate() {
            let index = original_size + 1 + i as u32;
            self.userstring_map.insert(index, index);
        }
    }

    /// Update all cross-references in table data using this remapping.
    pub fn apply_to_assembly(&self, changes: &mut AssemblyChanges) -> Result<()> {
        // For now, this is a placeholder that would update cross-references
        // The actual implementation would traverse all table data and update
        // any references to strings, blobs, or other table RIDs

        // TODO: Implement cross-reference updating
        // This would involve:
        // 1. Iterating through all table operations
        // 2. For each operation, examining the table data
        // 3. Finding any string indices, blob indices, or RID references
        // 4. Updating them using the appropriate mapping

        let _ = changes; // Silence unused parameter warning
        Ok(())
    }

    /// Get the final index for a string heap index.
    pub fn map_string_index(&self, original_index: u32) -> Option<u32> {
        self.string_map.get(&original_index).copied()
    }

    /// Get the final index for a blob heap index.
    pub fn map_blob_index(&self, original_index: u32) -> Option<u32> {
        self.blob_map.get(&original_index).copied()
    }

    /// Get the final index for a GUID heap index.
    pub fn map_guid_index(&self, original_index: u32) -> Option<u32> {
        self.guid_map.get(&original_index).copied()
    }

    /// Get the final index for a UserString heap index.
    pub fn map_userstring_index(&self, original_index: u32) -> Option<u32> {
        self.userstring_map.get(&original_index).copied()
    }

    /// Get the RID remapper for a specific table.
    pub fn get_table_remapper(&self, table_id: TableId) -> Option<&RidRemapper> {
        self.table_maps.get(&table_id)
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::metadata::{
        cilassembly::{
            AssemblyChanges, HeapChanges, Operation, TableModifications, TableOperation,
        },
        cilassemblyview::CilAssemblyView,
        tables::{CodedIndex, TableDataOwned, TableId, TypeDefRaw},
        token::Token,
    };

    fn create_test_row() -> TableDataOwned {
        TableDataOwned::TypeDef(TypeDefRaw {
            rid: 0,
            token: Token::new(0x02000000),
            offset: 0,
            flags: 0,
            type_name: 1,
            type_namespace: 0,
            extends: CodedIndex::new(TableId::TypeRef, 0),
            field_list: 1,
            method_list: 1,
        })
    }

    #[test]
    fn test_index_remapper_empty_changes() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let changes = AssemblyChanges::empty();
            let remapper = IndexRemapper::build_from_changes(&changes, &view);

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
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let mut changes = AssemblyChanges::empty();

            // Add some strings to heap
            let mut string_changes = HeapChanges::new(203732); // WindowsBase.dll string heap size
            string_changes.appended_items.push("Hello".to_string());
            string_changes.appended_items.push("World".to_string());
            string_changes.next_index = 203734; // Original size + 2
            changes.string_heap_changes = string_changes;

            let remapper = IndexRemapper::build_from_changes(&changes, &view);

            // Check that original indices are preserved
            assert_eq!(remapper.map_string_index(1), Some(1));
            assert_eq!(remapper.map_string_index(100), Some(100));
            assert_eq!(remapper.map_string_index(203732), Some(203732));

            // Check that new strings get sequential mapping
            assert_eq!(remapper.map_string_index(203733), Some(203733)); // First new string
            assert_eq!(remapper.map_string_index(203734), Some(203734)); // Second new string
        }
    }

    #[test]
    fn test_index_remapper_blob_heap_mapping() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let mut changes = AssemblyChanges::empty();

            // Add some blobs to heap
            let mut blob_changes = HeapChanges::new(77816); // WindowsBase.dll blob heap size
            blob_changes.appended_items.push(vec![1, 2, 3]);
            blob_changes.appended_items.push(vec![4, 5, 6]);
            blob_changes.next_index = 77818; // Original size + 2
            changes.blob_heap_changes = blob_changes;

            let remapper = IndexRemapper::build_from_changes(&changes, &view);

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
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let mut changes = AssemblyChanges::empty();

            // Add table operations
            let mut table_modifications = TableModifications::new_sparse(1);
            let insert_op = TableOperation::new(Operation::Insert(1000, create_test_row()));
            table_modifications.apply_operation(insert_op).unwrap();
            changes
                .table_changes
                .insert(TableId::TypeDef, table_modifications);

            let remapper = IndexRemapper::build_from_changes(&changes, &view);

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
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let mut changes = AssemblyChanges::empty();

            // Create replaced table
            let rows = vec![create_test_row(), create_test_row(), create_test_row()];
            let replaced_modifications = TableModifications::Replaced(rows);
            changes
                .table_changes
                .insert(TableId::TypeDef, replaced_modifications);

            let remapper = IndexRemapper::build_from_changes(&changes, &view);

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
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let mut changes = AssemblyChanges::empty();

            // Add some GUIDs to heap
            let mut guid_changes = HeapChanges::new(1); // WindowsBase.dll has 1 GUID (16 bytes / 16 = 1)
            guid_changes.appended_items.push([1; 16]);
            guid_changes.appended_items.push([2; 16]);
            guid_changes.next_index = 3; // Original count + 2
            changes.guid_heap_changes = guid_changes;

            let remapper = IndexRemapper::build_from_changes(&changes, &view);

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
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let mut changes = AssemblyChanges::empty();

            // Add string changes
            let mut string_changes = HeapChanges::new(203732);
            string_changes.appended_items.push("Test".to_string());
            string_changes.next_index = 203733;
            changes.string_heap_changes = string_changes;

            // Add blob changes
            let mut blob_changes = HeapChanges::new(77816);
            blob_changes.appended_items.push(vec![0xAB, 0xCD]);
            blob_changes.next_index = 77817;
            changes.blob_heap_changes = blob_changes;

            // Add table changes
            let mut table_modifications = TableModifications::new_sparse(1);
            let insert_op = TableOperation::new(Operation::Insert(500, create_test_row()));
            table_modifications.apply_operation(insert_op).unwrap();
            changes
                .table_changes
                .insert(TableId::TypeDef, table_modifications);

            let remapper = IndexRemapper::build_from_changes(&changes, &view);

            // Verify all mappings were created
            assert!(!remapper.string_map.is_empty());
            assert!(!remapper.blob_map.is_empty());
            assert!(!remapper.table_maps.is_empty());

            // Test specific mappings
            assert_eq!(remapper.map_string_index(203733), Some(203733));
            assert_eq!(remapper.map_blob_index(77817), Some(77817));
            assert!(remapper.get_table_remapper(TableId::TypeDef).is_some());
        }
    }
}
