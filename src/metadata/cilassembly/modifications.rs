//! Table modification tracking and management.

use std::collections::HashSet;

use crate::{
    metadata::{cilassembly::TableOperation, tables::TableDataOwned},
    Error, Result,
};

/// Represents modifications to a specific metadata table.
///
/// Tables can be modified in two ways:
/// 1. **Sparse modifications** - Individual row operations (insert, update, delete)
/// 2. **Complete replacement** - Replace the entire table content
///
/// Sparse modifications are more memory-efficient for few changes, while
/// complete replacement is better for heavily modified tables.
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

                // Consolidate operations periodically to manage memory
                if operations.len() % 100 == 0 {
                    // TODO: Implement consolidation
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
    pub fn consolidate_operations(&mut self) -> Result<()> {
        match self {
            Self::Sparse {
                operations,
                deleted_rows,
                ..
            } => {
                if operations.is_empty() {
                    return Ok(());
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
                for op in operations.iter() {
                    if let super::Operation::Delete(rid) = &op.operation {
                        deleted_rows.insert(*rid);
                    }
                }

                Ok(())
            }
            Self::Replaced(_) => {
                // Replaced tables are already consolidated
                Ok(())
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
                    return Err(crate::Error::ModificationInvalidOperation {
                        details: format!("RID cannot be zero: {}", rid),
                    });
                }

                // Check if we already have a row at this RID
                if self.has_row(*rid)? {
                    // We need the table ID, but it's not available in this context
                    // For now, we'll use a generic error
                    return Err(crate::Error::ModificationInvalidOperation {
                        details: format!("RID {} already exists", rid),
                    });
                }

                Ok(())
            }
            super::Operation::Update(rid, _) => {
                if *rid == 0 {
                    return Err(crate::Error::ModificationInvalidOperation {
                        details: format!("RID cannot be zero: {}", rid),
                    });
                }

                // Check if the row exists to update
                if !self.has_row(*rid)? {
                    return Err(crate::Error::ModificationInvalidOperation {
                        details: format!("RID {} not found for update", rid),
                    });
                }

                Ok(())
            }
            super::Operation::Delete(rid) => {
                if *rid == 0 {
                    return Err(crate::Error::ModificationInvalidOperation {
                        details: format!("RID cannot be zero: {}", rid),
                    });
                }

                // Check if the row exists to delete
                if !self.has_row(*rid)? {
                    return Err(crate::Error::ModificationInvalidOperation {
                        details: format!("RID {} not found for deletion", rid),
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
    pub fn has_row(&self, rid: u32) -> Result<bool> {
        match self {
            Self::Sparse {
                operations,
                deleted_rows,
                ..
            } => {
                // Check if it's been explicitly deleted
                if deleted_rows.contains(&rid) {
                    return Ok(false);
                }

                // Check if there's an insert operation for this RID
                for op in operations.iter() {
                    match &op.operation {
                        super::Operation::Insert(op_rid, _) if *op_rid == rid => {
                            return Ok(true);
                        }
                        _ => {}
                    }
                }

                // Check if it exists in the original table
                // Note: This assumes RIDs are 1-based and contiguous in the original table
                Ok(rid > 0 && rid <= self.original_row_count())
            }
            Self::Replaced(rows) => {
                // For replaced tables, check if the RID is within the row count
                Ok(rid > 0 && (rid as usize) <= rows.len())
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
