//! Operation types for table row modifications.

use crate::metadata::tables::TableDataOwned;
use std::time::{SystemTime, UNIX_EPOCH};

/// Specific operation types that can be applied to table rows.
///
/// These represent the fundamental operations for modifying metadata tables:
/// - **Insert**: Add a new row with a specific RID
/// - **Update**: Modify an existing row's data
/// - **Delete**: Mark a row as deleted
#[derive(Debug, Clone)]
pub enum Operation {
    /// Insert a new row with the specified RID and data.
    ///
    /// # Parameters
    /// * `u32` - The RID (Row ID) to assign to the new row
    /// * `TableDataOwned` - The row data to insert
    ///
    /// # Notes
    /// RIDs must be unique within a table. Attempting to insert with
    /// an existing RID will result in a conflict.
    Insert(u32, TableDataOwned),

    /// Update an existing row with new data.
    ///
    /// # Parameters  
    /// * `u32` - The RID of the row to update
    /// * `TableDataOwned` - The new row data
    ///
    /// # Notes
    /// The target row must exist (either in the original table or
    /// inserted by a previous operation).
    Update(u32, TableDataOwned),

    /// Delete an existing row.
    ///
    /// # Parameters
    /// * `u32` - The RID of the row to delete
    ///
    /// # Notes
    /// The target row must exist (either in the original table or
    /// inserted by a previous operation). Deleted rows are marked
    /// but not immediately removed to preserve RID stability.
    Delete(u32),
}

impl Operation {
    /// Gets the RID that this operation targets.
    pub fn get_rid(&self) -> u32 {
        match self {
            Operation::Insert(rid, _) | Operation::Update(rid, _) | Operation::Delete(rid) => *rid,
        }
    }

    /// Returns a reference to the row data if this operation contains any.
    ///
    /// Returns `Some` for Insert and Update operations, `None` for Delete.
    pub fn get_row_data(&self) -> Option<&TableDataOwned> {
        match self {
            Operation::Insert(_, data) | Operation::Update(_, data) => Some(data),
            Operation::Delete(_) => None,
        }
    }

    /// Returns a mutable reference to the row data if this operation contains any.
    ///
    /// Returns `Some` for Insert and Update operations, `None` for Delete.
    pub fn get_row_data_mut(&mut self) -> Option<&mut TableDataOwned> {
        match self {
            Operation::Insert(_, data) | Operation::Update(_, data) => Some(data),
            Operation::Delete(_) => None,
        }
    }

    /// Returns the operation type as a string for debugging/logging.
    pub fn operation_type(&self) -> &'static str {
        match self {
            Operation::Insert(_, _) => "Insert",
            Operation::Update(_, _) => "Update",
            Operation::Delete(_) => "Delete",
        }
    }
}

/// Individual table operation with temporal ordering for conflict resolution.
///
/// Each operation is timestamped with microsecond precision to enable
/// deterministic conflict resolution when multiple operations target
/// the same RID.
#[derive(Debug, Clone)]
pub struct TableOperation {
    /// Microsecond precision timestamp for ordering operations
    ///
    /// This timestamp is used for conflict resolution when multiple
    /// operations target the same RID. Later timestamps take precedence
    /// in last-write-wins conflict resolution.
    pub timestamp: u64,

    /// The actual operation to perform
    pub operation: Operation,
}

impl TableOperation {
    /// Creates a new table operation with the current timestamp.
    pub fn new(operation: Operation) -> Self {
        Self {
            timestamp: Self::current_timestamp_micros(),
            operation,
        }
    }

    /// Creates a new table operation with a specific timestamp.
    ///
    /// This is primarily used for testing or when replaying operations
    /// from a log where timestamps are preserved.
    pub fn new_with_timestamp(operation: Operation, timestamp: u64) -> Self {
        Self {
            timestamp,
            operation,
        }
    }

    /// Gets the RID that this operation targets.
    pub fn get_rid(&self) -> u32 {
        self.operation.get_rid()
    }

    /// Returns true if this operation creates a new row.
    pub fn is_insert(&self) -> bool {
        matches!(self.operation, Operation::Insert(_, _))
    }

    /// Returns true if this operation modifies an existing row.
    pub fn is_update(&self) -> bool {
        matches!(self.operation, Operation::Update(_, _))
    }

    /// Returns true if this operation deletes a row.
    pub fn is_delete(&self) -> bool {
        matches!(self.operation, Operation::Delete(_))
    }

    /// Gets the current timestamp in microseconds since Unix epoch.
    fn current_timestamp_micros() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_operation_rid_extraction() {
        let delete_op = Operation::Delete(10);
        assert_eq!(delete_op.get_rid(), 10);
        assert_eq!(delete_op.operation_type(), "Delete");
    }

    #[test]
    fn test_operation_timestamp_ordering() {
        let op1 = TableOperation::new(Operation::Delete(1));
        std::thread::sleep(std::time::Duration::from_micros(1));
        let op2 = TableOperation::new(Operation::Delete(2));

        assert!(op2.timestamp > op1.timestamp);
    }
}
