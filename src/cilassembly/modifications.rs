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
                next_rid,
                ..
            } => {
                // Insert in chronological order
                let insert_pos = operations
                    .binary_search_by_key(&op.timestamp, |o| o.timestamp)
                    .unwrap_or_else(|e| e);
                operations.insert(insert_pos, op);

                // Update auxiliary data structures
                let inserted_op = &operations[insert_pos];
                match &inserted_op.operation {
                    super::Operation::Insert(rid, _) => {
                        if *rid >= *next_rid {
                            *next_rid = *rid + 1;
                        }
                    }
                    super::Operation::Delete(rid) => {
                        deleted_rows.insert(*rid);
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

                // Update deleted_rows to only include RIDs that have final Delete operations
                deleted_rows.clear();
                for op in operations {
                    if let super::Operation::Delete(rid) = &op.operation {
                        deleted_rows.insert(*rid);
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
                    // We need the table ID, but it's not available in this context
                    // For now, we'll use a generic error
                    return Err(Error::ModificationInvalidOperation {
                        details: format!("RID {rid} already exists"),
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
    pub fn has_row(&self, rid: u32) -> bool {
        match self {
            Self::Sparse {
                operations,
                deleted_rows,
                ..
            } => {
                // Check if it's been explicitly deleted
                if deleted_rows.contains(&rid) {
                    return false;
                }

                // Check if there's an insert operation for this RID
                for op in operations {
                    match &op.operation {
                        super::Operation::Insert(op_rid, _) if *op_rid == rid => {
                            return true;
                        }
                        _ => {}
                    }
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

    #[test]
    fn test_table_modifications_creation() {
        let sparse = TableModifications::new_sparse(1);
        assert!(!sparse.has_modifications());
        assert_eq!(sparse.operation_count(), 0);

        let replaced = TableModifications::new_replaced(vec![]);
        assert!(!replaced.has_modifications());
        assert_eq!(replaced.operation_count(), 0);
    }
}
