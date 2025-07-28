//! RID remapping for specific tables.
//!
//! This module provides the [`crate::cilassembly::remapping::rid::RidRemapper`] for managing
//! Row ID (RID) remapping within individual metadata tables during assembly modification.
//! It handles the complex task of maintaining sequential RID allocation while processing
//! chronological operations that may insert, update, or delete table rows.
//!
//! # Key Components
//!
//! - [`crate::cilassembly::remapping::rid::RidRemapper`] - Per-table RID remapping with conflict resolution
//!
//! # Architecture
//!
//! The RID remapping system addresses the fundamental requirement that metadata table
//! RIDs must remain sequential (1, 2, 3, ...) in the final binary, even when operations
//! create gaps or insert rows with non-sequential RIDs.
//!
//! ## Core Challenges
//!
//! ### Sequential RID Requirement
//! ECMA-335 requires that table RIDs be sequential starting from 1 with no gaps.
//! When operations delete rows or insert with arbitrary RIDs, the remapper must
//! create a new sequential assignment.
//!
//! ### Temporal Ordering
//! Operations are processed in chronological order based on timestamps to ensure
//! deterministic conflict resolution when multiple operations target the same RID.
//!
//! ### Cross-Reference Preservation
//! All cross-references throughout the assembly must be updated to use the new
//! sequential RIDs while maintaining their semantic meaning.
//!
//! ## Remapping Process
//!
//! 1. **Operation Analysis**: Process all operations chronologically to determine final state
//! 2. **Conflict Resolution**: Apply last-write-wins logic for overlapping operations
//! 3. **Sequential Assignment**: Create gap-free sequential mapping for surviving rows
//! 4. **Cross-Reference Updates**: Update all references to use new RIDs
//!
//! # Usage Examples
//!
//! ```rust,ignore
//! use crate::cilassembly::remapping::rid::RidRemapper;
//! use crate::cilassembly::operation::{Operation, TableOperation};
//! use crate::metadata::tables::TableDataOwned;
//!
//! // Build remapper from table operations
//! // let operations = vec![/* TableOperation instances */];
//! let original_count = 5; // Original table had 5 rows
//! // let remapper = RidRemapper::build_from_operations(&operations, original_count);
//!
//! // Query RID mappings
//! // if let Some(final_rid) = remapper.map_rid(3) {
//! //     println!("Original RID 3 maps to final RID {}", final_rid);
//! // } else {
//! //     println!("RID 3 was deleted");
//! // }
//!
//! // Get table statistics
//! // let final_count = remapper.final_row_count();
//! // let next_rid = remapper.next_available_rid();
//! ```
//!
//! # Thread Safety
//!
//! This type is [`Send`] and [`Sync`] as it contains only owned data structures
//! with no interior mutability, making it safe for concurrent read access.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::cilassembly::remapping::index::IndexRemapper`] - Overall remapping coordination
//! - [`crate::cilassembly::operation`] - Operation definitions and temporal ordering
//! - [`crate::cilassembly::modifications::TableModifications`] - Table change tracking
//! - [`crate::cilassembly::write`] - Binary generation and cross-reference updates

use crate::cilassembly::{Operation, TableOperation};
use std::collections::{BTreeSet, HashMap};

/// Handles RID remapping for a specific table.
///
/// This struct manages the complex process of remapping Row IDs (RIDs) within a single
/// metadata table to ensure sequential allocation in the final binary. It processes
/// chronological operations, resolves conflicts, and maintains the ECMA-335 requirement
/// that table RIDs be sequential starting from 1 with no gaps.
///
/// # Remapping Strategy
///
/// The remapper implements a two-phase strategy:
/// 1. **Analysis Phase**: Process all operations chronologically to determine the final
///    state of each RID (exists, deleted, or modified)
/// 2. **Assignment Phase**: Create sequential RID assignments for all surviving rows,
///    ensuring no gaps in the final sequence
///
/// # Internal State
///
/// - **Mapping Table**: Maps original RIDs to final RIDs (or None for deleted rows)
/// - **Next RID**: Tracks the next available RID for new insertions  
/// - **Final Count**: Maintains the total number of rows after all operations
///
/// # Conflict Resolution
///
/// When multiple operations target the same RID, the remapper applies last-write-wins
/// conflict resolution based on operation timestamps:
/// - Later timestamps take precedence
/// - Insert followed by Delete results in no row (Delete wins)
/// - Delete followed by Insert results in a row (Insert wins)  
/// - Update operations preserve row existence and remove deletion markers
///
/// # Usage Examples
///
/// ```rust,ignore
/// use crate::cilassembly::remapping::rid::RidRemapper;
/// use crate::cilassembly::operation::{Operation, TableOperation};
/// use crate::metadata::tables::TableDataOwned;
///
/// // Create remapper for table with 10 original rows
/// let mut remapper = RidRemapper::new(10);
///
/// // Or build from operations (more common)
/// // let operations = vec![/* operations */];
/// // let remapper = RidRemapper::build_from_operations(&operations, 10);
///
/// // Query RID mappings
/// match remapper.map_rid(5) {
///     Some(final_rid) => println!("RID 5 maps to {}", final_rid),
///     None => println!("RID 5 was deleted"),
/// }
///
/// // Get table statistics
/// let total_rows = remapper.final_row_count();
/// let next_available = remapper.next_available_rid();
/// ```
///
/// # Thread Safety
///
/// This type is [`Send`] and [`Sync`] as it contains only owned collections
/// with no shared mutable state.
#[derive(Debug, Clone)]
pub struct RidRemapper {
    pub mapping: HashMap<u32, Option<u32>>,
    next_rid: u32,
    final_count: u32,
}

impl RidRemapper {
    /// Creates a new RID remapper for a table with the specified row count.
    ///
    /// This initializes an empty remapper that can be used to build RID mappings
    /// incrementally or as a starting point for operation-based construction.
    ///
    /// # Arguments
    ///
    /// * `row_count` - The number of rows in the original table
    ///
    /// # Returns
    ///
    /// A new [`crate::cilassembly::remapping::rid::RidRemapper`] ready for mapping operations.
    pub fn new(row_count: u32) -> Self {
        Self {
            mapping: HashMap::new(),
            next_rid: row_count + 1,
            final_count: row_count,
        }
    }

    /// Build remapping from a sequence of table operations.
    ///
    /// This is the primary method for constructing RID remappers from table modification
    /// operations. It processes all operations chronologically, applies conflict resolution,
    /// and builds a complete mapping that ensures sequential final RID allocation.
    ///
    /// # Arguments
    ///
    /// * `operations` - Slice of [`crate::cilassembly::operation::TableOperation`] instances to process
    /// * `original_count` - Number of rows in the original table before modifications
    ///
    /// # Returns
    ///
    /// A new [`crate::cilassembly::remapping::rid::RidRemapper`] with complete mapping tables.
    ///
    /// # Process
    ///
    /// 1. **Temporal Sorting**: Sort operations by timestamp for deterministic ordering
    /// 2. **Conflict Resolution**: Apply last-write-wins logic for overlapping RIDs
    /// 3. **State Analysis**: Determine final state (exists/deleted) for each RID
    /// 4. **Sequential Mapping**: Assign gap-free sequential RIDs to surviving rows
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
    /// This internal method creates the actual RID mappings that ensure all final RIDs
    /// are sequential starting from 1, which is required for valid metadata tables per
    /// ECMA-335. It processes original rows first, then inserted rows, to maintain
    /// a logical ordering in the final assignment.
    ///
    /// # Arguments
    ///
    /// * `original_count` - Number of rows in the original table
    /// * `inserted_rids` - Set of RIDs that were inserted by operations
    /// * `deleted_rids` - Set of RIDs that were deleted by operations
    ///
    /// # Algorithm
    ///
    /// 1. **Original Rows**: Map non-deleted original RIDs to sequential positions
    /// 2. **Inserted Rows**: Map inserted RIDs to positions after original rows
    /// 3. **Deleted Tracking**: Mark deleted RIDs as None in the mapping table
    fn build_sequential_mapping(
        &mut self,
        original_count: u32,
        inserted_rids: &BTreeSet<u32>,
        deleted_rids: &BTreeSet<u32>,
    ) {
        let mut final_rid = 1u32;

        // First, map all original RIDs that aren't deleted
        for original_rid in 1..=original_count {
            if deleted_rids.contains(&original_rid) {
                // Mark deleted RIDs as None
                self.mapping.insert(original_rid, None);
            } else {
                self.mapping.insert(original_rid, Some(final_rid));
                final_rid += 1;
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
    /// This method queries the mapping table to determine what final RID an original
    /// RID should map to in the output binary. This is the primary interface for
    /// cross-reference updates during binary generation.
    ///
    /// # Arguments
    ///
    /// * `original_rid` - The original RID to look up
    ///
    /// # Returns
    ///
    /// - `Some(final_rid)` if the RID exists in the final table
    /// - `None` if the RID was deleted or is otherwise invalid
    ///
    /// # Mapping Behavior
    ///
    /// - **Explicit Mappings**: RIDs with operations use stored mappings
    /// - **Implicit Mappings**: Unchanged RIDs may map to themselves
    /// - **Deleted RIDs**: Return None to indicate removal
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
    ///
    /// This count represents the final number of rows that will exist in the
    /// table after all modifications are applied and RID remapping is complete.
    /// It's used for table size calculations during binary generation.
    ///
    /// # Returns
    ///
    /// The final row count as a `u32`.
    pub fn final_row_count(&self) -> u32 {
        self.final_count
    }

    /// Returns the next available RID for new insertions.
    ///
    /// This value represents the RID that would be assigned to the next row
    /// inserted into the table. It's always one greater than the final row count,
    /// maintaining the sequential RID requirement.
    ///
    /// # Returns
    ///
    /// The next available RID as a `u32`.
    pub fn next_available_rid(&self) -> u32 {
        self.next_rid
    }

    /// Returns the original RID that maps to the given final RID.
    ///
    /// This performs a reverse lookup to find which original RID corresponds to a specific
    /// final RID in the sequential mapping. Used during table writing to iterate through
    /// final RIDs in order while accessing the correct original row data.
    ///
    /// # Arguments
    ///
    /// * `final_rid` - The final RID to look up (1-based)
    ///
    /// # Returns
    ///
    /// The original RID that maps to the given final RID, or `None` if no mapping exists.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let remapper = RidRemapper::build_from_operations(&operations, 5);
    /// // If original RID 3 maps to final RID 2 (due to deletions)
    /// assert_eq!(remapper.reverse_lookup(2), Some(3));
    /// ```
    pub fn reverse_lookup(&self, final_rid: u32) -> Option<u32> {
        for (&original_rid, &mapped_rid) in &self.mapping {
            if mapped_rid == Some(final_rid) {
                return Some(original_rid);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cilassembly::{Operation, TableOperation},
        test::factories::table::cilassembly::create_test_row,
    };

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
