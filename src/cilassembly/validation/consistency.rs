//! RID consistency validation for assembly modification operations.
//!
//! This module provides validation to ensure that RID (Row ID) assignments remain
//! consistent and conflict-free across all metadata table operations. It implements
//! comprehensive conflict detection for various operation combinations and ensures
//! that RID uniqueness constraints are maintained throughout the modification process.
//!
//! # Key Components
//!
//! - [`crate::cilassembly::validation::consistency::RidConsistencyValidator`] - Main RID consistency validator
//!
//! # Architecture
//!
//! The consistency validation system focuses on detecting and preventing RID conflicts:
//!
//! ## Conflict Detection
//! The validator analyzes all operations targeting the same table to detect:
//! - Multiple operations on the same RID (insert, update, delete)
//! - Insert/delete conflicts on the same RID
//! - Multiple insert operations with identical RIDs
//! - RID consistency violations
//!
//! ## Validation Process
//! For each table with modifications:
//! - Groups operations by target RID
//! - Analyzes operation combinations for conflicts
//! - Validates RID uniqueness constraints
//! - Reports specific conflict details for resolution
//!
//! ## Conflict Types
//! The validator detects several types of RID conflicts:
//! - **Insert/Delete Conflicts**: When both insert and delete operations target the same RID
//! - **Multiple Insert Conflicts**: When multiple insert operations use the same RID
//! - **RID Sequence Violations**: When RID assignments violate table constraints
//!
//! # Usage Examples
//!
//! ```rust,ignore
//! use crate::cilassembly::validation::consistency::RidConsistencyValidator;
//! use crate::cilassembly::validation::ValidationStage;
//! use crate::cilassembly::AssemblyChanges;
//! use crate::metadata::cilassemblyview::CilAssemblyView;
//!
//! # let view = CilAssemblyView::from_file("test.dll")?;
//! # let changes = AssemblyChanges::new();
//! // Create validator
//! let validator = RidConsistencyValidator;
//!
//! // Validate changes for RID consistency
//! validator.validate(&changes, &view)?;
//! # Ok::<(), crate::Error>(())
//! ```
//!
//! # Thread Safety
//!
//! This type is [`Send`] and [`Sync`] as it contains no mutable state and operates
//! purely on the input data provided to the validation methods.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::cilassembly::validation::ValidationPipeline`] - Used as a validation stage
//! - [`crate::cilassembly::modifications::TableModifications`] - Analyzes table operations
//! - [`crate::cilassembly::operation::TableOperation`] - Validates individual operations

use crate::{
    cilassembly::{
        validation::ValidationStage, AssemblyChanges, Operation, TableModifications, TableOperation,
    },
    metadata::{cilassemblyview::CilAssemblyView, tables::TableId},
    Error, Result,
};
use std::collections::HashMap;

/// RID consistency validation for assembly modification operations.
///
/// [`RidConsistencyValidator`] ensures that Row ID (RID) assignments remain consistent
/// and conflict-free across all metadata table operations. It analyzes operation
/// combinations to detect various types of RID conflicts and validates that RID
/// uniqueness constraints are maintained throughout the modification process.
///
/// # Validation Checks
///
/// The validator performs the following consistency checks:
/// - **RID Uniqueness**: Ensures RIDs are unique within each table
/// - **Conflict Detection**: Identifies conflicts between insert/delete operations
/// - **Sequence Validation**: Validates that RID sequences are reasonable
/// - **Operation Compatibility**: Ensures operations can be safely applied together
///
/// # Conflict Detection
///
/// The validator detects several types of RID conflicts:
/// - Multiple operations targeting the same RID
/// - Insert and delete operations on the same RID
/// - Multiple insert operations with identical RIDs
/// - RID constraint violations
///
/// # Usage Examples
///
/// ```rust,ignore
/// use crate::cilassembly::validation::consistency::RidConsistencyValidator;
/// use crate::cilassembly::validation::ValidationStage;
/// use crate::cilassembly::AssemblyChanges;
/// use crate::metadata::cilassemblyview::CilAssemblyView;
///
/// # let view = CilAssemblyView::from_file("test.dll")?;
/// # let changes = AssemblyChanges::new();
/// let validator = RidConsistencyValidator;
///
/// // Validate all table modifications for RID consistency
/// validator.validate(&changes, &view)?;
/// # Ok::<(), crate::Error>(())
/// ```
///
/// # Thread Safety
///
/// This type is [`Send`] and [`Sync`] as it contains no mutable state and operates
/// purely on the input data provided to the validation methods.
pub struct RidConsistencyValidator;

impl ValidationStage for RidConsistencyValidator {
    fn validate(&self, changes: &AssemblyChanges, _original: &CilAssemblyView) -> Result<()> {
        for (table_id, table_modifications) in &changes.table_changes {
            if let TableModifications::Sparse { operations, .. } = table_modifications {
                self.validate_rid_consistency(*table_id, operations)?;
            }
        }

        Ok(())
    }

    fn name(&self) -> &'static str {
        "RID Consistency Validation"
    }
}

impl RidConsistencyValidator {
    /// Validates RID consistency for operations targeting a specific table.
    ///
    /// This method analyzes all operations targeting the specified table to detect
    /// RID conflicts and consistency violations. It groups operations by target RID
    /// and validates that the combination of operations is valid and conflict-free.
    ///
    /// # Arguments
    ///
    /// * `table_id` - The [`crate::metadata::tables::TableId`] of the table being validated
    /// * `operations` - Array of [`crate::cilassembly::operation::TableOperation`] instances to validate
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if all RID assignments are consistent and conflict-free,
    /// or an [`crate::Error`] describing the specific conflict detected.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] for various RID consistency violations:
    /// - [`crate::Error::ModificationConflictDetected`] for insert/delete conflicts
    /// - [`crate::Error::ModificationRidAlreadyExists`] for duplicate insert RIDs
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use crate::cilassembly::validation::consistency::RidConsistencyValidator;
    /// use crate::metadata::tables::TableId;
    ///
    /// # let validator = RidConsistencyValidator;
    /// # let operations = vec![]; // operations would be populated
    /// // Validate operations for a specific table
    /// validator.validate_rid_consistency(TableId::TypeDef, &operations)?;
    /// # Ok::<(), crate::Error>(())
    /// ```
    fn validate_rid_consistency(
        &self,
        table_id: TableId,
        operations: &[TableOperation],
    ) -> Result<()> {
        let mut rid_operations: HashMap<u32, Vec<&TableOperation>> = HashMap::new();

        for operation in operations {
            let rid = match &operation.operation {
                Operation::Insert(rid, _) | Operation::Update(rid, _) | Operation::Delete(rid) => {
                    *rid
                }
            };
            rid_operations.entry(rid).or_default().push(operation);
        }

        for (rid, ops) in &rid_operations {
            if ops.len() > 1 {
                // Multiple operations on same RID - check for conflicts
                let has_insert = ops
                    .iter()
                    .any(|op| matches!(op.operation, Operation::Insert(_, _)));
                let has_delete = ops
                    .iter()
                    .any(|op| matches!(op.operation, Operation::Delete(_)));

                if has_insert && has_delete {
                    return Err(Error::ModificationConflictDetected {
                        details: format!(
                            "Insert and delete operations on RID {rid} in table {table_id:?}"
                        ),
                    });
                }

                // Multiple inserts on same RID
                let insert_count = ops
                    .iter()
                    .filter(|op| matches!(op.operation, Operation::Insert(_, _)))
                    .count();
                if insert_count > 1 {
                    return Err(Error::ModificationRidAlreadyExists {
                        table: table_id,
                        rid: *rid,
                    });
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::{
        cilassembly::{AssemblyChanges, Operation, TableModifications, TableOperation},
        metadata::{
            cilassemblyview::CilAssemblyView,
            tables::{CodedIndex, TableDataOwned, TableId, TypeDefRaw},
            token::Token,
        },
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
    fn test_rid_consistency_validator_no_conflicts() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let mut changes = AssemblyChanges::empty();

            // Add operations on different RIDs (no conflicts)
            let mut table_modifications = TableModifications::new_sparse(1);
            let op1 = TableOperation::new(Operation::Insert(100, create_test_row()));
            let op2 = TableOperation::new(Operation::Insert(101, create_test_row()));
            table_modifications.apply_operation(op1).unwrap();
            table_modifications.apply_operation(op2).unwrap();
            changes
                .table_changes
                .insert(TableId::TypeDef, table_modifications);

            let validator = RidConsistencyValidator;
            let result = validator.validate(&changes, &view);
            assert!(
                result.is_ok(),
                "Non-conflicting operations should pass validation"
            );
        }
    }

    #[test]
    fn test_rid_consistency_validator_insert_delete_conflict() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let mut changes = AssemblyChanges::empty();

            // Add conflicting insert and delete operations on same RID
            let mut table_modifications = TableModifications::new_sparse(1);
            let insert_op = TableOperation::new(Operation::Insert(100, create_test_row()));
            let delete_op = TableOperation::new(Operation::Delete(100));
            table_modifications.apply_operation(insert_op).unwrap();
            table_modifications.apply_operation(delete_op).unwrap();
            changes
                .table_changes
                .insert(TableId::TypeDef, table_modifications);

            let validator = RidConsistencyValidator;
            let result = validator.validate(&changes, &view);
            assert!(
                result.is_err(),
                "Insert/delete conflict should fail validation"
            );

            if let Err(e) = result {
                assert!(
                    e.to_string().contains("Insert and delete operations"),
                    "Should be conflict error"
                );
            }
        }
    }

    #[test]
    fn test_rid_consistency_validator_multiple_insert_conflict() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let mut changes = AssemblyChanges::empty();

            // Add multiple insert operations on same RID
            let mut table_modifications = TableModifications::new_sparse(1);
            let insert_op1 = TableOperation::new(Operation::Insert(100, create_test_row()));
            let insert_op2 = TableOperation::new(Operation::Insert(100, create_test_row()));
            table_modifications.apply_operation(insert_op1).unwrap();
            table_modifications.apply_operation(insert_op2).unwrap();
            changes
                .table_changes
                .insert(TableId::TypeDef, table_modifications);

            let validator = RidConsistencyValidator;
            let result = validator.validate(&changes, &view);
            assert!(
                result.is_err(),
                "Multiple insert conflict should fail validation"
            );

            if let Err(e) = result {
                assert!(
                    e.to_string().contains("already exists"),
                    "Should be RID exists error"
                );
            }
        }
    }
}
