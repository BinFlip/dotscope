//! RID remapping for specific tables.

use crate::metadata::cilassembly::{Operation, TableOperation};
use std::collections::{BTreeSet, HashMap};

/// Handles RID remapping for a specific table.
#[derive(Debug, Clone)]
pub struct RidRemapper {
    pub mapping: HashMap<u32, Option<u32>>,
    next_rid: u32,
    final_count: u32,
}

impl RidRemapper {
    pub fn new(row_count: u32) -> Self {
        Self {
            mapping: HashMap::new(),
            next_rid: row_count + 1,
            final_count: row_count,
        }
    }

    /// Build remapping from a sequence of table operations.
    ///
    /// This processes operations chronologically to build a mapping from original RIDs
    /// to final RIDs, handling insertions, deletions, and ensuring sequential final RIDs.
    pub fn build_from_operations(operations: &[TableOperation], original_count: u32) -> Self {
        let mut remapper = Self {
            mapping: HashMap::new(),
            next_rid: original_count + 1,
            final_count: original_count,
        };

        let mut deleted_rids = BTreeSet::new();
        let mut inserted_rids = BTreeSet::new();

        // Process operations chronologically to handle conflicts
        let mut sorted_operations = operations.to_vec();
        sorted_operations.sort_by_key(|op| op.timestamp);

        for operation in &sorted_operations {
            match &operation.operation {
                Operation::Insert(rid, _) => {
                    inserted_rids.insert(*rid);
                    deleted_rids.remove(rid); // Remove from deleted if previously deleted
                }
                Operation::Delete(rid) => {
                    deleted_rids.insert(*rid);
                    inserted_rids.remove(rid); // Remove from inserted if previously inserted
                }
                Operation::Update(rid, _) => {
                    // Update doesn't change RID existence, just ensure it's not marked as deleted
                    deleted_rids.remove(rid);
                }
            }
        }

        remapper.build_sequential_mapping(original_count, &inserted_rids, &deleted_rids);
        remapper
    }

    /// Build sequential RID mapping ensuring no gaps in final RIDs.
    ///
    /// This creates a mapping that ensures all final RIDs are sequential starting from 1,
    /// which is required for valid metadata tables.
    fn build_sequential_mapping(
        &mut self,
        original_count: u32,
        inserted_rids: &BTreeSet<u32>,
        deleted_rids: &BTreeSet<u32>,
    ) {
        let mut final_rid = 1u32;

        // First, map all original RIDs that aren't deleted
        for original_rid in 1..=original_count {
            if !deleted_rids.contains(&original_rid) {
                self.mapping.insert(original_rid, Some(final_rid));
                final_rid += 1;
            } else {
                // Mark deleted RIDs as None
                self.mapping.insert(original_rid, None);
            }
        }

        // Then, map all inserted RIDs
        for &inserted_rid in inserted_rids {
            if inserted_rid > original_count {
                // Only map RIDs that are actually new (beyond original count)
                self.mapping.insert(inserted_rid, Some(final_rid));
                final_rid += 1;
            }
            // If inserted_rid <= original_count, it was handled above
        }

        // Update final count and next RID
        self.final_count = final_rid - 1;
        self.next_rid = final_rid;
    }

    /// Get final RID for an original RID.
    ///
    /// Returns the final RID that the original RID should map to, or None if the RID was deleted.
    pub fn map_rid(&self, original_rid: u32) -> Option<u32> {
        // Check if we have an explicit mapping
        if let Some(mapped_rid) = self.mapping.get(&original_rid) {
            *mapped_rid // This could be Some(final_rid) or None (for deleted)
        } else {
            // No explicit mapping - this means the RID was unchanged
            // This can happen for original RIDs that had no operations applied
            if original_rid > 0 && original_rid <= self.final_count {
                Some(original_rid)
            } else {
                None
            }
        }
    }

    /// Returns the total number of rows after all operations are applied.
    pub fn final_row_count(&self) -> u32 {
        self.final_count
    }

    /// Returns the next available RID for new insertions.
    pub fn next_available_rid(&self) -> u32 {
        self.next_rid
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::cilassembly::{Operation, TableOperation};
    use crate::metadata::tables::{CodedIndex, TableDataOwned, TableId, TypeDefRaw};
    use crate::metadata::token::Token;

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
    fn test_rid_remapper_no_operations() {
        let operations = vec![];
        let remapper = RidRemapper::build_from_operations(&operations, 5);

        // With no operations, original RIDs should map to themselves
        assert_eq!(remapper.map_rid(1), Some(1));
        assert_eq!(remapper.map_rid(5), Some(5));
        assert_eq!(remapper.final_row_count(), 5);
        assert_eq!(remapper.next_available_rid(), 6);
    }

    #[test]
    fn test_rid_remapper_simple_insert() {
        let insert_op = TableOperation::new(Operation::Insert(10, create_test_row()));
        let operations = vec![insert_op];
        let remapper = RidRemapper::build_from_operations(&operations, 5);

        // Original RIDs should map to themselves
        assert_eq!(remapper.map_rid(1), Some(1));
        assert_eq!(remapper.map_rid(5), Some(5));

        // New RID should be mapped sequentially after originals
        assert_eq!(remapper.map_rid(10), Some(6));
        assert_eq!(remapper.final_row_count(), 6);
        assert_eq!(remapper.next_available_rid(), 7);
    }

    #[test]
    fn test_rid_remapper_delete_operations() {
        let delete_op = TableOperation::new(Operation::Delete(3));
        let operations = vec![delete_op];
        let remapper = RidRemapper::build_from_operations(&operations, 5);

        // Non-deleted RIDs should be mapped sequentially
        assert_eq!(remapper.map_rid(1), Some(1));
        assert_eq!(remapper.map_rid(2), Some(2));
        assert_eq!(remapper.map_rid(3), None); // Deleted
        assert_eq!(remapper.map_rid(4), Some(3)); // Shifted down
        assert_eq!(remapper.map_rid(5), Some(4)); // Shifted down

        assert_eq!(remapper.final_row_count(), 4);
        assert_eq!(remapper.next_available_rid(), 5);
    }

    #[test]
    fn test_rid_remapper_complex_operations() {
        let operations = vec![
            TableOperation::new(Operation::Insert(10, create_test_row())),
            TableOperation::new(Operation::Delete(2)),
            TableOperation::new(Operation::Insert(11, create_test_row())),
            TableOperation::new(Operation::Update(4, create_test_row())),
        ];
        let remapper = RidRemapper::build_from_operations(&operations, 5);

        // Expected mapping:
        // Original: 1,2,3,4,5 -> Delete(2) -> 1,3,4,5 -> Insert(10,11) -> 1,3,4,5,10,11
        // Final:    1,2,3,4,5,6 (sequential)

        assert_eq!(remapper.map_rid(1), Some(1));
        assert_eq!(remapper.map_rid(2), None); // Deleted
        assert_eq!(remapper.map_rid(3), Some(2)); // Shifted down
        assert_eq!(remapper.map_rid(4), Some(3)); // Shifted down (and updated)
        assert_eq!(remapper.map_rid(5), Some(4)); // Shifted down
        assert_eq!(remapper.map_rid(10), Some(5)); // First insert
        assert_eq!(remapper.map_rid(11), Some(6)); // Second insert

        assert_eq!(remapper.final_row_count(), 6);
        assert_eq!(remapper.next_available_rid(), 7);
    }

    #[test]
    fn test_rid_remapper_insert_delete_conflict() {
        // Test conflict resolution through chronological ordering
        let mut operations = vec![
            TableOperation::new(Operation::Insert(10, create_test_row())),
            TableOperation::new(Operation::Delete(10)),
        ];

        // Make sure delete comes after insert chronologically
        std::thread::sleep(std::time::Duration::from_micros(1));
        operations[1] = TableOperation::new(Operation::Delete(10));

        let remapper = RidRemapper::build_from_operations(&operations, 5);

        // The delete should win (RID 10 should not exist in final mapping)
        assert_eq!(remapper.map_rid(10), None);
        assert_eq!(remapper.final_row_count(), 5); // No change from original
    }
}
