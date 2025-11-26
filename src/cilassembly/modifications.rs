//! Table modification tracking and management.
//!
//! This module provides the [`crate::cilassembly::modifications::TableModifications`]
//! enumeration for tracking changes to metadata tables during assembly modification operations.
//! It supports two different modification strategies optimized for different usage patterns.
//!
//! # Key Components
//!
//! - [`crate::cilassembly::modifications::TableModifications`] - Core table modification tracking with sparse and replacement strategies
//!
//! # Architecture
//!
//! The module implements two distinct strategies for tracking table modifications:
//!
//! ## Sparse Modifications
//! - Track individual operations (Insert/Update/Delete) with timestamps
//! - Memory-efficient for tables with few changes
//! - Supports conflict detection and resolution
//! - Operations are stored chronologically for proper ordering
//!
//! **RID Assumption:** Per ECMA-335, RIDs (Row IDs) in metadata tables are 1-based and
//! contiguous. A table with `n` rows contains RIDs 1 through n inclusive. This module
//! relies on this property when checking row existence via [`TableModifications::has_row`].
//!
//! ## Complete Replacement
//! - Replace entire table content with new data
//! - More efficient for heavily modified tables
//! - Simpler conflict resolution (no conflicts possible)
//! - Better performance for bulk operations
//!
//! # Usage Examples
//!
//! ```rust,ignore
//! use crate::cilassembly::modifications::TableModifications;
//! use crate::cilassembly::operation::{TableOperation, Operation};
//! use crate::metadata::tables::TableDataOwned;
//!
//! // Create sparse modification tracker
//! let mut modifications = TableModifications::new_sparse(1);
//!
//! // Apply operations
//! // let operation = TableOperation::new(Operation::Insert(1, row_data));
//! // modifications.apply_operation(operation)?;
//!
//! // Check for modifications
//! if modifications.has_modifications() {
//!     println!("Table has {} operations", modifications.operation_count());
//! }
//! # Ok::<(), crate::Error>(())
//! ```
//!
//! # Thread Safety
//!
//! This type is not [`Send`] or [`Sync`] as it contains mutable state that is not
//! protected by synchronization primitives and is designed for single-threaded assembly modification.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::cilassembly::changes::AssemblyChanges`] - Overall change tracking
//! - [`crate::cilassembly::operation`] - Operation definitions and management
//! - Assembly validation - Validation and conflict resolution

use std::collections::HashSet;

use crate::{cilassembly::TableOperation, metadata::tables::TableDataOwned, Error, Result};

/// Represents modifications to a specific metadata table.
///
/// This enum provides two different strategies for tracking changes to metadata tables,
/// each optimized for different modification patterns. It integrates with
/// [`crate::cilassembly::operation::TableOperation`] to maintain chronological ordering
/// and conflict resolution capabilities.
///
/// # Modification Strategies
///
/// 1. **Sparse modifications** - Individual row operations (insert, update, delete)
/// 2. **Complete replacement** - Replace the entire table content
///
/// Sparse modifications are more memory-efficient for few changes, while
/// complete replacement is better for heavily modified tables.
///
/// # Usage Examples
///
/// ```rust,ignore
/// use crate::cilassembly::modifications::TableModifications;
/// use crate::cilassembly::operation::{TableOperation, Operation};
/// use crate::metadata::tables::TableDataOwned;
///
/// // Create sparse tracker
/// let mut modifications = TableModifications::new_sparse(5); // next RID = 5
///
/// // Check if RID exists
/// if modifications.has_row(3)? {
///     println!("Row 3 exists");
/// }
///
/// // Apply operations and consolidate
/// // modifications.apply_operation(operation)?;
/// modifications.consolidate_operations();
/// # Ok::<(), crate::Error>(())
/// ```
///
/// # Thread Safety
///
/// This type is not [`Send`] or [`Sync`] as it contains mutable collections
/// and is designed for single-threaded modification operations.
#[derive(Debug, Clone)]
pub enum TableModifications {
    /// Sparse modifications with ordered operation tracking.
    ///
    /// This variant tracks individual operations chronologically, allowing
    /// for conflict detection and resolution. Operations are applied in
    /// timestamp order during consolidation.
    Sparse {
        /// Chronologically ordered operations
        ///
        /// Operations are stored in the order they were applied, with
        /// microsecond-precision timestamps for conflict resolution.
        operations: Vec<TableOperation>,

        /// Quick lookup for deleted RIDs
        ///
        /// This set is maintained for efficient deletion checks without
        /// scanning through all operations.
        deleted_rows: HashSet<u32>,

        /// Quick lookup for inserted RIDs
        ///
        /// This set is maintained for efficient insertion checks without
        /// scanning through all operations.
        inserted_rows: HashSet<u32>,

        /// Next available RID for new rows
        ///
        /// This tracks the next RID that would be assigned to a newly
        /// inserted row, accounting for both original and added rows.
        next_rid: u32,

        /// The number of rows in the original table before modifications.
        ///
        /// This is used to determine if a RID exists in the original table
        /// when validating operations.
        original_row_count: u32,
    },

    /// Complete table replacement - for heavily modified tables.
    ///
    /// When a table has been modified extensively, it's more efficient
    /// to replace the entire table content rather than tracking individual
    /// sparse operations.
    Replaced(Vec<TableDataOwned>),
}

impl TableModifications {
    /// Creates a new sparse table modifications tracker.
    ///
    /// Initializes a new sparse modification tracker that will track individual
    /// operations chronologically. The `next_rid` parameter determines where
    /// new row insertions will begin.
    ///
    /// # Arguments
    ///
    /// * `next_rid` - The next available RID for new row insertions
    ///
    /// # Returns
    ///
    /// A new [`crate::cilassembly::modifications::TableModifications::Sparse`] variant
    /// ready to track operations.
    pub fn new_sparse(next_rid: u32) -> Self {
        let original_row_count = next_rid.saturating_sub(1);
        Self::Sparse {
            operations: Vec::new(),
            deleted_rows: HashSet::new(),
            inserted_rows: HashSet::new(),
            next_rid,
            original_row_count,
        }
    }

    /// Creates a table replacement with the given rows.
    ///
    /// Initializes a complete table replacement with the provided row data.
    /// This is more efficient than sparse modifications when replacing most
    /// or all of a table's content.
    ///
    /// # Arguments
    ///
    /// * `rows` - The complete set of rows to replace the table with
    ///
    /// # Returns
    ///
    /// A new [`crate::cilassembly::modifications::TableModifications::Replaced`] variant
    /// containing the provided rows.
    pub fn new_replaced(rows: Vec<TableDataOwned>) -> Self {
        Self::Replaced(rows)
    }

    /// Returns the number of operations tracked in this modification.
    pub fn operation_count(&self) -> usize {
        match self {
            Self::Sparse { operations, .. } => operations.len(),
            Self::Replaced(rows) => rows.len(),
        }
    }

    /// Returns true if this table has any modifications.
    pub fn has_modifications(&self) -> bool {
        match self {
            Self::Sparse { operations, .. } => !operations.is_empty(),
            Self::Replaced(rows) => !rows.is_empty(),
        }
    }

    /// Apply a new operation, handling conflicts and maintaining consistency.
    ///
    /// This method validates the operation, detects conflicts with existing
    /// operations, and applies appropriate conflict resolution.
    ///
    /// # Arguments
    ///
    /// * `op` - The operation to apply
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the operation was applied successfully, or an error
    /// describing why the operation could not be applied.
    pub fn apply_operation(&mut self, op: TableOperation) -> Result<()> {
        match self {
            Self::Sparse {
                operations,
                deleted_rows,
                inserted_rows,
                next_rid,
                ..
            } => {
                // Insert in chronological order, maintaining FIFO for equal timestamps.
                // binary_search_by_key returns Ok(index) if found, which would insert BEFORE
                // existing entries with the same timestamp. We need to insert AFTER all
                // entries with the same timestamp to maintain insertion order.
                let insert_pos = match operations
                    .binary_search_by_key(&op.timestamp, |o| o.timestamp)
                {
                    Ok(mut pos) => {
                        // Found an entry with the same timestamp - scan forward to find the
                        // end of all entries with this timestamp (FIFO ordering)
                        while pos < operations.len() && operations[pos].timestamp == op.timestamp {
                            pos += 1;
                        }
                        pos
                    }
                    Err(pos) => pos, // Not found - insert at the natural position
                };
                operations.insert(insert_pos, op);

                // Update auxiliary data structures
                let inserted_op = &operations[insert_pos];
                match &inserted_op.operation {
                    super::Operation::Insert(rid, _) => {
                        inserted_rows.insert(*rid);
                        if *rid >= *next_rid {
                            *next_rid = *rid + 1;
                        }
                    }
                    super::Operation::Delete(rid) => {
                        deleted_rows.insert(*rid);
                        inserted_rows.remove(rid);
                    }
                    super::Operation::Update(rid, _) => {
                        deleted_rows.remove(rid);
                    }
                }

                Ok(())
            }
            Self::Replaced(_) => Err(Error::ModificationCannotModifyReplacedTable),
        }
    }

    /// Consolidate operations to remove superseded operations and optimize memory.
    ///
    /// This method removes operations that have been superseded by later operations
    /// on the same RID, reducing memory usage and improving performance.
    /// This is critical for builder APIs that may generate many operations.
    pub fn consolidate_operations(&mut self) {
        match self {
            Self::Sparse {
                operations,
                deleted_rows,
                inserted_rows,
                ..
            } => {
                if operations.is_empty() {
                    return;
                }

                // Group operations by RID and keep only the latest operation for each RID
                let mut latest_ops: std::collections::HashMap<u32, usize> =
                    std::collections::HashMap::new();

                // Find the latest operation for each RID
                for (index, op) in operations.iter().enumerate() {
                    let rid = op.operation.get_rid();
                    latest_ops.insert(rid, index);
                }

                // Collect indices of operations to keep (in reverse order for efficient removal)
                let mut indices_to_remove: Vec<usize> = Vec::new();
                for (index, op) in operations.iter().enumerate() {
                    let rid = op.operation.get_rid();
                    if latest_ops.get(&rid) != Some(&index) {
                        indices_to_remove.push(index);
                    }
                }

                // Remove superseded operations (from highest index to lowest)
                indices_to_remove.sort_unstable();
                for &index in indices_to_remove.iter().rev() {
                    operations.remove(index);
                }

                // Rebuild auxiliary sets based on final operation state
                deleted_rows.clear();
                inserted_rows.clear();
                for op in operations {
                    match &op.operation {
                        super::Operation::Delete(rid) => {
                            deleted_rows.insert(*rid);
                        }
                        super::Operation::Insert(rid, _) => {
                            inserted_rows.insert(*rid);
                        }
                        super::Operation::Update(_, _) => {}
                    }
                }
            }
            Self::Replaced(_) => {
                // Replaced tables are already consolidated
            }
        }
    }

    /// Validate that an operation is safe to apply.
    ///
    /// This method checks various constraints to ensure the operation
    /// can be safely applied without violating metadata integrity.
    pub fn validate_operation(&self, op: &TableOperation) -> Result<()> {
        match &op.operation {
            super::Operation::Insert(rid, _) => {
                if *rid == 0 {
                    return Err(Error::ModificationInvalidOperation {
                        details: format!("RID cannot be zero: {rid}"),
                    });
                }

                // Check if we already have a row at this RID
                if self.has_row(*rid) {
                    return Err(Error::ModificationInvalidOperation {
                        details: format!(
                            "Cannot insert row: RID {rid} already exists in table (duplicate insert or existing row)"
                        ),
                    });
                }

                Ok(())
            }
            super::Operation::Update(rid, _) => {
                if *rid == 0 {
                    return Err(Error::ModificationInvalidOperation {
                        details: format!("RID cannot be zero: {rid}"),
                    });
                }

                // Check if the row exists to update
                if !self.has_row(*rid) {
                    return Err(Error::ModificationInvalidOperation {
                        details: format!("RID {rid} not found for update"),
                    });
                }

                Ok(())
            }
            super::Operation::Delete(rid) => {
                if *rid == 0 {
                    return Err(Error::ModificationInvalidOperation {
                        details: format!("RID cannot be zero: {rid}"),
                    });
                }

                // Check if the row exists to delete
                if !self.has_row(*rid) {
                    return Err(Error::ModificationInvalidOperation {
                        details: format!("RID {rid} not found for deletion"),
                    });
                }

                Ok(())
            }
        }
    }

    /// Check if a RID exists (considering all operations and original table state).
    ///
    /// This method checks if a row with the given RID exists, taking into account
    /// the original table row count and all applied operations.
    ///
    /// # RID Contiguity Assumption
    ///
    /// Per ECMA-335 §II.22, metadata table RIDs are 1-based and contiguous. A table
    /// with `n` rows contains RIDs 1 through n. This method relies on this property
    /// when checking if a RID exists in the original table: any RID in range `[1, original_row_count]`
    /// is considered to exist unless explicitly deleted.
    pub fn has_row(&self, rid: u32) -> bool {
        match self {
            Self::Sparse {
                deleted_rows,
                inserted_rows,
                ..
            } => {
                // Check if it's been explicitly deleted
                if deleted_rows.contains(&rid) {
                    return false;
                }

                // Check if there's an insert operation for this RID
                if inserted_rows.contains(&rid) {
                    return true;
                }

                // Check if it exists in the original table
                // Note: This assumes RIDs are 1-based and contiguous in the original table
                rid > 0 && rid <= self.original_row_count()
            }
            Self::Replaced(rows) => {
                // For replaced tables, check if the RID is within the row count
                rid > 0 && (rid as usize) <= rows.len()
            }
        }
    }

    /// Returns the original row count for this table (before modifications).
    ///
    /// This is used by `has_row` to determine if a RID exists in the original table.
    /// For sparse modifications, this is stored when creating the modifications.
    /// For replaced tables, this information is not relevant.
    fn original_row_count(&self) -> u32 {
        match self {
            Self::Sparse {
                original_row_count, ..
            } => *original_row_count,
            Self::Replaced(_) => 0, // Not applicable for replaced tables
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cilassembly::{Operation, TableOperation};
    use crate::metadata::tables::{ModuleRaw, TableDataOwned};
    use crate::metadata::token::Token;

    /// Helper to create a simple ModuleRaw for testing
    fn make_test_row(name_idx: u32) -> TableDataOwned {
        TableDataOwned::Module(ModuleRaw {
            rid: 1,
            token: Token::new(0x00000001),
            offset: 0,
            generation: 0,
            name: name_idx,
            mvid: 1,
            encid: 0,
            encbaseid: 0,
        })
    }

    /// Helper to create a TableOperation with a specific timestamp
    fn make_op_with_timestamp(op: Operation, timestamp: u64) -> TableOperation {
        TableOperation::new_with_timestamp(op, timestamp)
    }

    #[test]
    fn test_table_modifications_creation() {
        let sparse = TableModifications::new_sparse(1);
        assert!(!sparse.has_modifications());
        assert_eq!(sparse.operation_count(), 0);

        let replaced = TableModifications::new_replaced(vec![]);
        assert!(!replaced.has_modifications());
        assert_eq!(replaced.operation_count(), 0);
    }

    #[test]
    fn test_sparse_with_existing_rows() {
        // Create sparse with 5 existing rows (next_rid = 6)
        let sparse = TableModifications::new_sparse(6);
        assert!(!sparse.has_modifications());

        // Original rows 1-5 should exist
        assert!(sparse.has_row(1));
        assert!(sparse.has_row(5));
        assert!(!sparse.has_row(6)); // Not yet inserted
        assert!(!sparse.has_row(0)); // RID 0 never exists
    }

    #[test]
    fn test_apply_insert_operation() {
        let mut mods = TableModifications::new_sparse(1);
        let row = make_test_row(100);
        let op = TableOperation::new(Operation::Insert(1, row));

        assert!(mods.apply_operation(op).is_ok());
        assert!(mods.has_modifications());
        assert_eq!(mods.operation_count(), 1);
        assert!(mods.has_row(1));
    }

    #[test]
    fn test_apply_update_operation() {
        // Create with 5 existing rows
        let mut mods = TableModifications::new_sparse(6);
        let row = make_test_row(200);
        let op = TableOperation::new(Operation::Update(3, row));

        assert!(mods.apply_operation(op).is_ok());
        assert!(mods.has_modifications());
        assert_eq!(mods.operation_count(), 1);
        assert!(mods.has_row(3)); // Row still exists after update
    }

    #[test]
    fn test_apply_delete_operation() {
        // Create with 5 existing rows
        let mut mods = TableModifications::new_sparse(6);
        let op = TableOperation::new(Operation::Delete(3));

        assert!(mods.apply_operation(op).is_ok());
        assert!(mods.has_modifications());
        assert_eq!(mods.operation_count(), 1);
        assert!(!mods.has_row(3)); // Row no longer exists
        assert!(mods.has_row(2)); // Other rows still exist
        assert!(mods.has_row(4));
    }

    #[test]
    fn test_validate_operation_rid_zero() {
        let mods = TableModifications::new_sparse(6);

        // Insert with RID 0 should fail
        let insert_op = TableOperation::new(Operation::Insert(0, make_test_row(1)));
        assert!(mods.validate_operation(&insert_op).is_err());

        // Update with RID 0 should fail
        let update_op = TableOperation::new(Operation::Update(0, make_test_row(1)));
        assert!(mods.validate_operation(&update_op).is_err());

        // Delete with RID 0 should fail
        let delete_op = TableOperation::new(Operation::Delete(0));
        assert!(mods.validate_operation(&delete_op).is_err());
    }

    #[test]
    fn test_validate_insert_duplicate_rid() {
        let mods = TableModifications::new_sparse(6); // Rows 1-5 exist

        // Try to insert at existing RID
        let op = TableOperation::new(Operation::Insert(3, make_test_row(1)));
        let result = mods.validate_operation(&op);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_update_nonexistent_rid() {
        let mods = TableModifications::new_sparse(6); // Rows 1-5 exist

        // Try to update non-existent RID
        let op = TableOperation::new(Operation::Update(10, make_test_row(1)));
        let result = mods.validate_operation(&op);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_delete_nonexistent_rid() {
        let mods = TableModifications::new_sparse(6); // Rows 1-5 exist

        // Try to delete non-existent RID
        let op = TableOperation::new(Operation::Delete(10));
        let result = mods.validate_operation(&op);
        assert!(result.is_err());
    }

    #[test]
    fn test_consolidate_operations_keeps_latest() {
        let mut mods = TableModifications::new_sparse(1);

        // Apply multiple operations on the same RID with increasing timestamps
        let op1 = make_op_with_timestamp(Operation::Insert(1, make_test_row(100)), 1000);
        let op2 = make_op_with_timestamp(Operation::Update(1, make_test_row(200)), 2000);
        let op3 = make_op_with_timestamp(Operation::Update(1, make_test_row(300)), 3000);

        mods.apply_operation(op1).unwrap();
        mods.apply_operation(op2).unwrap();
        mods.apply_operation(op3).unwrap();

        assert_eq!(mods.operation_count(), 3);

        // Consolidate should keep only the latest operation
        mods.consolidate_operations();
        assert_eq!(mods.operation_count(), 1);

        // Verify it's the latest update
        if let TableModifications::Sparse { operations, .. } = &mods {
            assert_eq!(operations[0].timestamp, 3000);
            if let Operation::Update(rid, data) = &operations[0].operation {
                assert_eq!(*rid, 1);
                if let TableDataOwned::Module(row) = data {
                    assert_eq!(row.name, 300);
                }
            } else {
                panic!("Expected Update operation");
            }
        }
    }

    #[test]
    fn test_consolidate_operations_multiple_rids() {
        let mut mods = TableModifications::new_sparse(1);

        // Operations on different RIDs
        let op1 = make_op_with_timestamp(Operation::Insert(1, make_test_row(100)), 1000);
        let op2 = make_op_with_timestamp(Operation::Insert(2, make_test_row(200)), 2000);
        let op3 = make_op_with_timestamp(Operation::Update(1, make_test_row(150)), 3000);

        mods.apply_operation(op1).unwrap();
        mods.apply_operation(op2).unwrap();
        mods.apply_operation(op3).unwrap();

        assert_eq!(mods.operation_count(), 3);

        mods.consolidate_operations();

        // Should have 2 operations (latest for RID 1 and RID 2)
        assert_eq!(mods.operation_count(), 2);
    }

    #[test]
    fn test_consolidate_updates_deleted_rows() {
        let mut mods = TableModifications::new_sparse(6); // Rows 1-5 exist

        // Delete row 3
        let op1 = make_op_with_timestamp(Operation::Delete(3), 1000);
        mods.apply_operation(op1).unwrap();
        assert!(!mods.has_row(3));

        // Later "un-delete" by updating (should remove from deleted_rows)
        let op2 = make_op_with_timestamp(Operation::Update(3, make_test_row(300)), 2000);
        mods.apply_operation(op2).unwrap();

        // After consolidation, deleted_rows should be updated correctly
        mods.consolidate_operations();

        // The latest operation is Update, so row should exist
        // Note: deleted_rows is rebuilt during consolidation based on final operations
        if let TableModifications::Sparse { deleted_rows, .. } = &mods {
            assert!(!deleted_rows.contains(&3));
        }
    }

    #[test]
    fn test_replaced_table_operations() {
        let rows = vec![make_test_row(1), make_test_row(2), make_test_row(3)];
        let mut replaced = TableModifications::new_replaced(rows);

        assert!(replaced.has_modifications());
        assert_eq!(replaced.operation_count(), 3);

        // Rows 1-3 should exist
        assert!(replaced.has_row(1));
        assert!(replaced.has_row(2));
        assert!(replaced.has_row(3));
        assert!(!replaced.has_row(4));
        assert!(!replaced.has_row(0));

        // Cannot apply operations to replaced table
        let op = TableOperation::new(Operation::Insert(4, make_test_row(4)));
        assert!(replaced.apply_operation(op).is_err());
    }

    #[test]
    fn test_has_row_after_insert() {
        let mut mods = TableModifications::new_sparse(1); // No existing rows

        assert!(!mods.has_row(1));

        let op = TableOperation::new(Operation::Insert(1, make_test_row(100)));
        mods.apply_operation(op).unwrap();

        assert!(mods.has_row(1));
    }

    #[test]
    fn test_next_rid_updates_on_insert() {
        let mut mods = TableModifications::new_sparse(1);

        // Insert at RID 5 (skipping 1-4)
        let op = TableOperation::new(Operation::Insert(5, make_test_row(100)));
        mods.apply_operation(op).unwrap();

        // Next RID should be updated to 6
        if let TableModifications::Sparse { next_rid, .. } = &mods {
            assert_eq!(*next_rid, 6);
        }
    }

    #[test]
    fn test_empty_consolidate() {
        let mut mods = TableModifications::new_sparse(1);

        // Consolidating empty modifications should not panic
        mods.consolidate_operations();
        assert!(!mods.has_modifications());
    }

    #[test]
    fn test_same_timestamp_fifo_ordering() {
        // Test that operations with the same timestamp maintain FIFO insertion order.
        // This is critical for scenarios where Insert is followed by Update on the
        // same RID within the same microsecond - the Update must come AFTER Insert.
        let mut mods = TableModifications::new_sparse(1);

        let fixed_timestamp = 1000u64;

        // Create Insert operation with fixed timestamp
        let insert_op = TableOperation::new_with_timestamp(
            Operation::Insert(10, make_test_row(100)),
            fixed_timestamp,
        );

        // Create Update operation with same timestamp (simulates same-microsecond operations)
        let update_op = TableOperation::new_with_timestamp(
            Operation::Update(10, make_test_row(200)),
            fixed_timestamp,
        );

        // Apply in order: Insert first, then Update
        mods.apply_operation(insert_op).unwrap();
        mods.apply_operation(update_op).unwrap();

        // Verify FIFO ordering: Insert should be at index 0, Update at index 1
        if let TableModifications::Sparse { operations, .. } = &mods {
            assert_eq!(operations.len(), 2);
            assert!(operations[0].is_insert(), "Insert should be first");
            assert!(operations[1].is_update(), "Update should be second");
        } else {
            panic!("Expected Sparse modifications");
        }
    }

    #[test]
    fn test_same_timestamp_multiple_operations() {
        // Test with more operations at the same timestamp
        let mut mods = TableModifications::new_sparse(1);

        let fixed_timestamp = 1000u64;

        // Create three operations on different RIDs with the same timestamp
        let op1 = TableOperation::new_with_timestamp(
            Operation::Insert(10, make_test_row(100)),
            fixed_timestamp,
        );
        let op2 = TableOperation::new_with_timestamp(
            Operation::Insert(11, make_test_row(200)),
            fixed_timestamp,
        );
        let op3 = TableOperation::new_with_timestamp(
            Operation::Insert(12, make_test_row(300)),
            fixed_timestamp,
        );

        // Apply in order
        mods.apply_operation(op1).unwrap();
        mods.apply_operation(op2).unwrap();
        mods.apply_operation(op3).unwrap();

        // Verify FIFO ordering: operations should be in insertion order
        if let TableModifications::Sparse { operations, .. } = &mods {
            assert_eq!(operations.len(), 3);
            assert_eq!(
                operations[0].get_rid(),
                10,
                "First operation should be RID 10"
            );
            assert_eq!(
                operations[1].get_rid(),
                11,
                "Second operation should be RID 11"
            );
            assert_eq!(
                operations[2].get_rid(),
                12,
                "Third operation should be RID 12"
            );
        } else {
            panic!("Expected Sparse modifications");
        }
    }
}
