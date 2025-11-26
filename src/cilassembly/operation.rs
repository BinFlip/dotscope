//! Operation types for table row modifications.
//!
//! This module provides the fundamental operation types for modifying metadata table rows
//! during assembly editing operations. It defines both the raw operation variants and the
//! timestamped operation wrapper used for conflict resolution and chronological ordering.
//!
//! # Key Components
//!
//! - [`crate::cilassembly::operation::Operation`] - Core operation variants (Insert/Update/Delete)
//! - [`crate::cilassembly::operation::TableOperation`] - Timestamped operation wrapper for conflict resolution
//!
//! # Architecture
//!
//! The operation system is designed around precise temporal ordering and conflict resolution:
//!
//! ## Operation Types
//! Three fundamental operations are supported:
//! - **Insert**: Create new rows with specific RIDs
//! - **Update**: Modify existing row data while preserving RID
//! - **Delete**: Mark rows as deleted (soft deletion for RID stability)
//!
//! ## Temporal Ordering
//! All operations are timestamped with microsecond precision to enable deterministic
//! conflict resolution when multiple operations target the same RID. The system uses
//! a last-write-wins strategy based on these timestamps.
//!
//! ## Conflict Resolution
//! When operations conflict (multiple operations on the same RID), the system resolves
//! conflicts based on temporal ordering, with later timestamps taking precedence.
//!
//! # Usage Examples
//!
//! ```rust,ignore
//! use crate::cilassembly::operation::{Operation, TableOperation};
//! use crate::metadata::tables::TableDataOwned;
//!
//! // Create operations
//! // let row_data = TableDataOwned::TypeDef(/* ... */);
//! // let insert_op = Operation::Insert(1, row_data);
//! // let delete_op = Operation::Delete(2);
//!
//! // Wrap with timestamps for conflict resolution
//! // let table_op = TableOperation::new(insert_op);
//!
//! // Check operation properties
//! // let rid = table_op.get_rid();
//! // let is_insert = table_op.is_insert();
//! ```
//!
//! # Thread Safety
//!
//! Both [`crate::cilassembly::operation::Operation`] and [`crate::cilassembly::operation::TableOperation`]
//! are [`Send`] and [`Sync`] as they contain only owned data and immutable timestamps.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::cilassembly::modifications::TableModifications`] - Operation storage and application
//! - Assembly validation - Operation validation and conflict detection
//! - [`crate::metadata::tables`] - Table data structures and row types

use crate::metadata::tables::TableDataOwned;
use std::time::{SystemTime, UNIX_EPOCH};

/// Specific operation types that can be applied to table rows.
///
/// This enum defines the three fundamental operations supported by the assembly modification
/// system. Each operation targets a specific RID (Row ID) and maintains referential integrity
/// through the validation system. Operations are typically wrapped in [`crate::cilassembly::operation::TableOperation`]
/// for timestamp-based conflict resolution.
///
/// # Operation Types
///
/// - **Insert**: Add a new row with a specific RID and data
/// - **Update**: Modify an existing row's data while preserving the RID
/// - **Delete**: Mark a row as deleted (soft deletion for RID stability)
///
/// # Usage Examples
///
/// ```rust,ignore
/// use crate::cilassembly::operation::Operation;
/// use crate::metadata::tables::TableDataOwned;
///
/// // Create different operation types
/// // let row_data = TableDataOwned::TypeDef(/* ... */);
/// // let insert = Operation::Insert(1, row_data);
/// // let update = Operation::Update(1, updated_data);
/// // let delete = Operation::Delete(1);
///
/// // Check operation properties
/// // let rid = insert.get_rid();
/// // let op_type = insert.operation_type();
/// // let data = insert.get_row_data();
/// ```
///
/// # Thread Safety
///
/// This type is [`Send`] and [`Sync`] as it contains only owned data
/// with no interior mutability.
#[derive(Debug, Clone)]
pub enum Operation {
    /// Insert a new row with the specified RID and data.
    ///
    /// This operation creates a new row in the target table with the specified RID.
    /// The RID must be unique within the table, and the data must be valid for the
    /// target table type.
    ///
    /// # Parameters
    /// * `u32` - The RID (Row ID) to assign to the new row (must be > 0 and unique)
    /// * [`crate::metadata::tables::TableDataOwned`] - The row data to insert
    ///
    /// # Validation
    /// - RID must be greater than 0 (RID 0 is reserved)
    /// - RID must not already exist in the table
    /// - Row data must be compatible with the target table schema
    ///
    /// # Conflicts
    /// Attempting to insert with an existing RID will result in a conflict
    /// that must be resolved through the validation system.
    Insert(u32, TableDataOwned),

    /// Update an existing row with new data.
    ///
    /// This operation replaces the data of an existing row while preserving its RID.
    /// The target row must exist either in the original table or have been created
    /// by a previous Insert operation.
    ///
    /// # Parameters  
    /// * `u32` - The RID of the row to update (must exist)
    /// * [`crate::metadata::tables::TableDataOwned`] - The new row data
    ///
    /// # Validation
    /// - Target RID must exist in the table (original or inserted)
    /// - RID must be greater than 0
    /// - New row data must be compatible with the target table schema
    ///
    /// # Behavior
    /// - If multiple Update operations target the same RID, the last one (by timestamp) wins
    /// - Update operations can be applied to both original rows and previously inserted rows
    Update(u32, TableDataOwned),

    /// Delete an existing row.
    ///
    /// This operation marks a row as deleted without immediately removing it from
    /// the table structure. This soft deletion approach preserves RID stability
    /// and enables proper conflict resolution with other operations.
    ///
    /// # Parameters
    /// * `u32` - The RID of the row to delete (must exist)
    ///
    /// # Validation
    /// - Target RID must exist in the table (original or inserted)
    /// - RID must be greater than 0
    /// - Row must not already be deleted
    ///
    /// # Behavior
    /// - Rows are marked as deleted but not physically removed
    /// - RID space remains stable (no gaps are filled)
    /// - Delete operations can be superseded by later Insert/Update operations on the same RID
    /// - Multiple Delete operations on the same RID are idempotent
    Delete(u32),
}

impl Operation {
    /// Gets the RID that this operation targets.
    ///
    /// All operations target a specific RID, and this method extracts that RID
    /// regardless of the operation type.
    ///
    /// # Returns
    ///
    /// The target RID as a `u32`. RIDs are 1-based following ECMA-335 conventions.
    pub fn get_rid(&self) -> u32 {
        match self {
            Operation::Insert(rid, _) | Operation::Update(rid, _) | Operation::Delete(rid) => *rid,
        }
    }

    /// Returns a reference to the row data if this operation contains any.
    ///
    /// Insert and Update operations contain row data, while Delete operations do not.
    /// This method provides access to that data when available.
    ///
    /// # Returns
    ///
    /// - `Some(&`[`crate::metadata::tables::TableDataOwned`]`)` for Insert and Update operations
    /// - `None` for Delete operations
    pub fn get_row_data(&self) -> Option<&TableDataOwned> {
        match self {
            Operation::Insert(_, data) | Operation::Update(_, data) => Some(data),
            Operation::Delete(_) => None,
        }
    }

    /// Returns a mutable reference to the row data if this operation contains any.
    ///
    /// Insert and Update operations contain row data, while Delete operations do not.
    /// This method provides mutable access to that data when available for modification.
    ///
    /// # Returns
    ///
    /// - `Some(&mut `[`crate::metadata::tables::TableDataOwned`]`)` for Insert and Update operations
    /// - `None` for Delete operations
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
/// This struct wraps an [`crate::cilassembly::operation::Operation`] with a microsecond-precision
/// timestamp to enable deterministic conflict resolution when multiple operations target
/// the same RID. The timestamp-based ordering ensures that the assembly modification system
/// can consistently resolve conflicts using a last-write-wins strategy.
///
/// # Timestamp Precision
///
/// Timestamps are captured with microsecond precision using [`std::time::SystemTime`] to
/// minimize the likelihood of timestamp collisions during rapid operations. The system
/// uses Unix epoch time for cross-platform consistency.
///
/// # Conflict Resolution
///
/// When multiple operations target the same RID:
/// - Operations are ordered by timestamp (ascending)
/// - Later timestamps take precedence (last-write-wins)
/// - Equal timestamps are resolved using operation type precedence
///
/// # Usage Examples
///
/// ```rust,ignore
/// use crate::cilassembly::operation::{Operation, TableOperation};
/// use crate::metadata::tables::TableDataOwned;
///
/// // Create timestamped operation
/// // let op = Operation::Insert(1, row_data);
/// // let table_op = TableOperation::new(op);
///
/// // Check properties
/// // let rid = table_op.get_rid();
/// // let timestamp = table_op.timestamp;
/// // let is_insert = table_op.is_insert();
/// ```
///
/// # Thread Safety
///
/// This type is [`Send`] and [`Sync`] as it contains only owned data
/// and immutable timestamps.
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
    ///
    /// This method wraps the provided operation with a timestamp captured at
    /// the moment of creation. The timestamp will be used for conflict resolution
    /// if multiple operations target the same RID.
    ///
    /// # Arguments
    ///
    /// * `operation` - The [`crate::cilassembly::operation::Operation`] to wrap with a timestamp
    ///
    /// # Returns
    ///
    /// A new [`crate::cilassembly::operation::TableOperation`] with the current timestamp.
    pub fn new(operation: Operation) -> Self {
        Self {
            timestamp: Self::current_timestamp_micros(),
            operation,
        }
    }

    /// Creates a new table operation with a specific timestamp.
    ///
    /// This method allows precise control over the timestamp, which is useful for
    /// testing scenarios, replaying operations from logs, or when deterministic
    /// ordering is required.
    ///
    /// # Arguments
    ///
    /// * `operation` - The [`crate::cilassembly::operation::Operation`] to wrap
    /// * `timestamp` - The microsecond-precision timestamp to assign
    ///
    /// # Returns
    ///
    /// A new [`crate::cilassembly::operation::TableOperation`] with the specified timestamp.
    pub fn new_with_timestamp(operation: Operation, timestamp: u64) -> Self {
        Self {
            timestamp,
            operation,
        }
    }

    /// Gets the RID that this operation targets.
    ///
    /// Delegates to the wrapped operation's `get_rid()` method to extract
    /// the target RID.
    ///
    /// # Returns
    ///
    /// The target RID as a `u32`.
    pub fn get_rid(&self) -> u32 {
        self.operation.get_rid()
    }

    /// Returns true if this operation creates a new row.
    ///
    /// # Returns
    ///
    /// `true` if the wrapped operation is an [`crate::cilassembly::operation::Operation::Insert`], `false` otherwise.
    pub fn is_insert(&self) -> bool {
        matches!(self.operation, Operation::Insert(_, _))
    }

    /// Returns true if this operation modifies an existing row.
    ///
    /// # Returns
    ///
    /// `true` if the wrapped operation is an [`crate::cilassembly::operation::Operation::Update`], `false` otherwise.
    pub fn is_update(&self) -> bool {
        matches!(self.operation, Operation::Update(_, _))
    }

    /// Returns true if this operation deletes a row.
    ///
    /// # Returns
    ///
    /// `true` if the wrapped operation is an [`crate::cilassembly::operation::Operation::Delete`], `false` otherwise.
    pub fn is_delete(&self) -> bool {
        matches!(self.operation, Operation::Delete(_))
    }

    /// Gets the current timestamp in microseconds since Unix epoch.
    ///
    /// This internal method captures the current system time with microsecond precision
    /// for use in operation timestamping. The timestamp is relative to the Unix epoch
    /// for cross-platform consistency.
    ///
    /// # Returns
    ///
    /// Current timestamp in microseconds since Unix epoch, or 0 if system time
    /// is not available.
    #[allow(clippy::cast_possible_truncation)] // Intentional: timestamp fits in u64 for practical purposes
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
    use crate::test::factories::table::cilassembly::create_test_row;

    #[test]
    fn test_operation_get_rid_for_all_variants() {
        let row_data = create_test_row();

        // Test Insert variant
        let insert_op = Operation::Insert(42, row_data.clone());
        assert_eq!(insert_op.get_rid(), 42);

        // Test Update variant
        let update_op = Operation::Update(100, row_data);
        assert_eq!(update_op.get_rid(), 100);

        // Test Delete variant
        let delete_op = Operation::Delete(10);
        assert_eq!(delete_op.get_rid(), 10);
    }

    #[test]
    fn test_operation_get_row_data_for_all_variants() {
        let row_data = create_test_row();

        // Insert should return Some
        let insert_op = Operation::Insert(1, row_data.clone());
        assert!(insert_op.get_row_data().is_some());

        // Update should return Some
        let update_op = Operation::Update(1, row_data);
        assert!(update_op.get_row_data().is_some());

        // Delete should return None
        let delete_op = Operation::Delete(1);
        assert!(delete_op.get_row_data().is_none());
    }

    #[test]
    fn test_operation_get_row_data_mut_for_all_variants() {
        let row_data = create_test_row();

        // Insert should return Some (mutable)
        let mut insert_op = Operation::Insert(1, row_data.clone());
        assert!(insert_op.get_row_data_mut().is_some());

        // Update should return Some (mutable)
        let mut update_op = Operation::Update(1, row_data);
        assert!(update_op.get_row_data_mut().is_some());

        // Delete should return None
        let mut delete_op = Operation::Delete(1);
        assert!(delete_op.get_row_data_mut().is_none());
    }

    #[test]
    fn test_operation_type_for_all_variants() {
        let row_data = create_test_row();

        let insert_op = Operation::Insert(1, row_data.clone());
        assert_eq!(insert_op.operation_type(), "Insert");

        let update_op = Operation::Update(1, row_data);
        assert_eq!(update_op.operation_type(), "Update");

        let delete_op = Operation::Delete(1);
        assert_eq!(delete_op.operation_type(), "Delete");
    }

    #[test]
    fn test_operation_edge_case_rid_zero() {
        // RID 0 is reserved but the Operation struct doesn't validate - that's up to callers
        let delete_op = Operation::Delete(0);
        assert_eq!(delete_op.get_rid(), 0);
    }

    #[test]
    fn test_operation_edge_case_max_rid() {
        let delete_op = Operation::Delete(u32::MAX);
        assert_eq!(delete_op.get_rid(), u32::MAX);
    }

    #[test]
    fn test_table_operation_new_captures_timestamp() {
        let op = TableOperation::new(Operation::Delete(1));
        // Timestamp should be non-zero (current time)
        assert!(op.timestamp > 0);
    }

    #[test]
    fn test_table_operation_new_with_timestamp() {
        let op = TableOperation::new_with_timestamp(Operation::Delete(1), 12345);
        assert_eq!(op.timestamp, 12345);
    }

    #[test]
    fn test_table_operation_timestamp_ordering() {
        let op1 = TableOperation::new(Operation::Delete(1));
        std::thread::sleep(std::time::Duration::from_micros(10));
        let op2 = TableOperation::new(Operation::Delete(2));

        assert!(op2.timestamp > op1.timestamp);
    }

    #[test]
    fn test_table_operation_get_rid() {
        let row_data = create_test_row();
        let op = TableOperation::new(Operation::Insert(999, row_data));
        assert_eq!(op.get_rid(), 999);
    }

    #[test]
    fn test_table_operation_is_insert() {
        let row_data = create_test_row();

        let insert_op = TableOperation::new(Operation::Insert(1, row_data.clone()));
        assert!(insert_op.is_insert());
        assert!(!insert_op.is_update());
        assert!(!insert_op.is_delete());

        let update_op = TableOperation::new(Operation::Update(1, row_data));
        assert!(!update_op.is_insert());

        let delete_op = TableOperation::new(Operation::Delete(1));
        assert!(!delete_op.is_insert());
    }

    #[test]
    fn test_table_operation_is_update() {
        let row_data = create_test_row();

        let update_op = TableOperation::new(Operation::Update(1, row_data.clone()));
        assert!(update_op.is_update());
        assert!(!update_op.is_insert());
        assert!(!update_op.is_delete());

        let insert_op = TableOperation::new(Operation::Insert(1, row_data));
        assert!(!insert_op.is_update());

        let delete_op = TableOperation::new(Operation::Delete(1));
        assert!(!delete_op.is_update());
    }

    #[test]
    fn test_table_operation_is_delete() {
        let row_data = create_test_row();

        let delete_op = TableOperation::new(Operation::Delete(1));
        assert!(delete_op.is_delete());
        assert!(!delete_op.is_insert());
        assert!(!delete_op.is_update());

        let insert_op = TableOperation::new(Operation::Insert(1, row_data.clone()));
        assert!(!insert_op.is_delete());

        let update_op = TableOperation::new(Operation::Update(1, row_data));
        assert!(!update_op.is_delete());
    }

    #[test]
    fn test_table_operation_clone() {
        let row_data = create_test_row();
        let op = TableOperation::new_with_timestamp(Operation::Insert(42, row_data), 5000);
        let cloned = op.clone();

        assert_eq!(cloned.timestamp, 5000);
        assert_eq!(cloned.get_rid(), 42);
        assert!(cloned.is_insert());
    }
}
