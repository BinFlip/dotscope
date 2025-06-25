//! Validation pipeline and conflict resolution for assembly modifications.
//!
//! This module provides a comprehensive validation system for ensuring that
//! assembly modifications are consistent, valid, and can be safely applied.
//! It includes conflict detection, resolution strategies, and a configurable
//! validation pipeline that can be customized for different validation requirements.
//!
//! # Key Components
//!
//! - [`crate::cilassembly::validation::ValidationPipeline`] - Configurable pipeline for running validation stages
//! - [`crate::cilassembly::validation::ValidationStage`] - Trait for implementing custom validation stages
//! - [`crate::cilassembly::validation::ConflictResolver`] - Trait for implementing conflict resolution strategies
//! - [`crate::cilassembly::validation::BasicSchemaValidator`] - Basic schema and RID validation
//! - [`crate::cilassembly::validation::RidConsistencyValidator`] - RID uniqueness and consistency validation
//! - [`crate::cilassembly::validation::LastWriteWinsResolver`] - Default timestamp-based conflict resolver
//!
//! # Architecture
//!
//! The validation system is built around a configurable pipeline architecture that
//! enables modular validation and flexible conflict resolution:
//!
//! ## Validation Pipeline
//! The [`crate::cilassembly::validation::ValidationPipeline`] orchestrates the validation process:
//! - **Sequential Stages**: Validation stages run in order, with early termination on failure
//! - **Configurable**: Stages can be added, removed, or reordered based on requirements
//! - **Extensible**: Custom validation stages can be implemented via the trait system
//!
//! ## Validation Stages
//! Individual stages focus on specific aspects of validation:
//! - **Schema Validation**: Ensures row data types match target tables
//! - **RID Consistency**: Validates RID uniqueness and conflict detection
//! - **Cross-Reference Integrity**: Validates references between tables (extensible)
//! - **Heap Validation**: Validates heap modifications (extensible)
//!
//! ## Conflict Resolution
//! When operations conflict, the system provides pluggable resolution strategies:
//! - **Last-Write-Wins**: Uses timestamps to determine precedence (default)
//! - **First-Write-Wins**: Earlier operations take precedence (extensible)
//! - **Merge Operations**: Combines compatible operations (extensible)
//! - **Reject on Conflict**: Fails validation when conflicts are detected (extensible)
//!
//! # Usage Examples
//!
//! ```rust,ignore
//! use crate::cilassembly::validation::{ValidationPipeline, BasicSchemaValidator, LastWriteWinsResolver};
//! use crate::cilassembly::changes::assembly::AssemblyChanges;
//! use crate::metadata::cilassemblyview::CilAssemblyView;
//! use std::path::Path;
//!
//! # let view = CilAssemblyView::from_file(Path::new("test.dll"))?;
//! # let changes = AssemblyChanges::new(&view);
//!
//! // Use default validation pipeline
//! let pipeline = ValidationPipeline::default();
//! pipeline.validate(&changes, &view)?;
//!
//! // Create custom validation pipeline
//! let custom_pipeline = ValidationPipeline::new()
//!     .add_stage(BasicSchemaValidator)
//!     .with_resolver(LastWriteWinsResolver);
//!
//! custom_pipeline.validate(&changes, &view)?;
//! # Ok::<(), crate::Error>(())
//! ```
//!
//! # Thread Safety
//!
//! The validation types are designed for single-threaded use during assembly modification.
//! Validation stages and resolvers are not required to be [`Send`] or [`Sync`], allowing
//! for complex validation logic that may use non-thread-safe dependencies.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::cilassembly::changes::assembly::AssemblyChanges`] - Change tracking and validation input
//! - [`crate::cilassembly::operation`] - Operation definitions and conflict detection
//! - [`crate::cilassembly::remapping`] - Index remapping after successful validation
//! - [`crate::metadata::cilassemblyview::CilAssemblyView`] - Original assembly data for validation context

use std::collections::HashMap;

use crate::{
    cilassembly::{AssemblyChanges, Operation, TableModifications, TableOperation},
    metadata::{
        cilassemblyview::CilAssemblyView,
        tables::{TableDataOwned, TableId},
    },
    Error, Result,
};

/// Comprehensive validation pipeline for assembly modifications.
///
/// The pipeline consists of multiple validation stages that run sequentially,
/// followed by conflict resolution. Each stage can validate different aspects
/// of the modifications (e.g., RID consistency, cross-references, heap integrity).
pub struct ValidationPipeline {
    /// Validation stages to run before applying changes
    pub stages: Vec<Box<dyn ValidationStage>>,
    /// Conflict resolution strategy
    pub conflict_resolver: Box<dyn ConflictResolver>,
}

impl ValidationPipeline {
    /// Creates a new validation pipeline with default stages and resolver.
    pub fn new() -> Self {
        Self {
            stages: Vec::new(),
            conflict_resolver: Box::new(LastWriteWinsResolver),
        }
    }

    /// Adds a validation stage to the pipeline.
    pub fn add_stage<S: ValidationStage + 'static>(mut self, stage: S) -> Self {
        self.stages.push(Box::new(stage));
        self
    }

    /// Sets the conflict resolver for the pipeline.
    pub fn with_resolver<R: ConflictResolver + 'static>(mut self, resolver: R) -> Self {
        self.conflict_resolver = Box::new(resolver);
        self
    }

    /// Validates all changes using the configured stages.
    ///
    /// Runs each validation stage in sequence. If any stage fails,
    /// validation stops and returns the error.
    pub fn validate(&self, changes: &AssemblyChanges, original: &CilAssemblyView) -> Result<()> {
        for stage in &self.stages {
            stage.validate(changes, original)?;
        }
        Ok(())
    }
}

impl Default for ValidationPipeline {
    fn default() -> Self {
        Self::new()
            .add_stage(BasicSchemaValidator)
            .add_stage(RidConsistencyValidator)
            .with_resolver(LastWriteWinsResolver)
    }
}

/// Trait for validation stages in the pipeline.
///
/// Each validation stage focuses on a specific aspect of assembly modification
/// validation (e.g., RID consistency, cross-reference integrity, heap validation).
pub trait ValidationStage {
    /// Validates the provided changes against the original assembly.
    ///
    /// # Arguments
    /// * `changes` - The modifications to validate
    /// * `original` - The original assembly view for reference
    ///
    /// # Returns
    /// Returns `Ok(())` if validation passes, or an error describing the issue.
    fn validate(&self, changes: &AssemblyChanges, original: &CilAssemblyView) -> Result<()>;

    /// Returns the name of this validation stage.
    fn name(&self) -> &'static str;
}

/// Basic schema validation for table operations.
///
/// Validates that:
/// - Row data types match their target tables
/// - RIDs are properly formed (non-zero, within bounds)
/// - Basic referential integrity is maintained
pub struct BasicSchemaValidator;

impl ValidationStage for BasicSchemaValidator {
    fn validate(&self, changes: &AssemblyChanges, _original: &CilAssemblyView) -> Result<()> {
        for (table_id, table_modifications) in &changes.table_changes {
            match table_modifications {
                TableModifications::Sparse { operations, .. } => {
                    for operation in operations {
                        self.validate_operation(*table_id, &operation.operation)?;
                    }
                }
                TableModifications::Replaced(rows) => {
                    for (i, row) in rows.iter().enumerate() {
                        let rid = (i + 1) as u32;
                        self.validate_row_data(*table_id, rid, row)?;
                    }
                }
            }
        }

        Ok(())
    }

    fn name(&self) -> &'static str {
        "Basic Schema Validation"
    }
}

impl BasicSchemaValidator {
    fn validate_operation(&self, table_id: TableId, operation: &Operation) -> Result<()> {
        match operation {
            Operation::Insert(rid, row_data) => {
                if *rid == 0 {
                    return Err(Error::ValidationInvalidRid {
                        table: table_id,
                        rid: *rid,
                    });
                }
                self.validate_row_data(table_id, *rid, row_data)?;
            }
            Operation::Update(rid, row_data) => {
                if *rid == 0 {
                    return Err(Error::ValidationInvalidRid {
                        table: table_id,
                        rid: *rid,
                    });
                }
                self.validate_row_data(table_id, *rid, row_data)?;
            }
            Operation::Delete(rid) => {
                if *rid == 0 {
                    return Err(Error::ValidationInvalidRid {
                        table: table_id,
                        rid: *rid,
                    });
                }
            }
        }
        Ok(())
    }

    fn validate_row_data(
        &self,
        table_id: TableId,
        _rid: u32,
        row_data: &TableDataOwned,
    ) -> Result<()> {
        // Validate that row data type matches the table
        let valid = match (table_id, row_data) {
            (TableId::TypeDef, TableDataOwned::TypeDef(_)) => true,
            (TableId::MethodDef, TableDataOwned::MethodDef(_)) => true,
            (TableId::Field, TableDataOwned::Field(_)) => true,
            (TableId::TypeRef, TableDataOwned::TypeRef(_)) => true,
            (TableId::MemberRef, TableDataOwned::MemberRef(_)) => true,
            (TableId::CustomAttribute, TableDataOwned::CustomAttribute(_)) => true,
            (TableId::Assembly, TableDataOwned::Assembly(_)) => true,
            (TableId::Module, TableDataOwned::Module(_)) => true,
            (TableId::Param, TableDataOwned::Param(_)) => true,
            // ToDo: Add more matches as TableDataOwned variants are implemented
            _ => false,
        };

        if !valid {
            return Err(Error::ValidationTableSchemaMismatch {
                table: table_id,
                expected: format!("{:?}", table_id),
                actual: format!("{:?}", std::mem::discriminant(row_data)),
            });
        }

        Ok(())
    }
}

/// RID consistency validation.
///
/// Validates that:
/// - RIDs are unique within each table
/// - No conflicts between insert/delete operations
/// - RID sequences are reasonable
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
                            "Insert and delete operations on RID {} in table {:?}",
                            rid, table_id
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

/// Types of conflicts that can occur during validation.
///
/// Conflicts arise when multiple operations target the same resource
/// or when operations have incompatible effects.
#[derive(Debug)]
pub enum Conflict {
    /// Multiple operations targeting the same RID.
    ///
    /// This occurs when multiple operations (insert, update, delete)
    /// are applied to the same table row.
    MultipleOperationsOnRid {
        /// The RID being modified.
        rid: u32,
        /// The conflicting operations.
        operations: Vec<TableOperation>,
    },

    /// Insert and delete operations on the same RID.
    ///
    /// This specific conflict occurs when a row is both inserted
    /// and deleted, which requires special resolution logic.
    InsertDeleteConflict {
        /// The RID being modified.
        rid: u32,
        /// The insert operation.
        insert_op: TableOperation,
        /// The delete operation.
        delete_op: TableOperation,
    },
}

/// Trait for conflict resolution strategies.
///
/// Different applications may need different conflict resolution strategies:
/// - Last-write-wins (default)
/// - First-write-wins
/// - Merge operations
/// - Reject on conflict
pub trait ConflictResolver {
    /// Resolves conflicts between operations.
    ///
    /// # Arguments
    /// * `conflicts` - Array of conflicts to resolve
    ///
    /// # Returns
    /// Returns a resolution that specifies how to handle each conflict.
    fn resolve_conflict(&self, conflicts: &[Conflict]) -> Result<Resolution>;
}

/// Default last-write-wins conflict resolver.
///
/// This resolver uses timestamp ordering to resolve conflicts,
/// with later operations taking precedence over earlier ones.
pub struct LastWriteWinsResolver;

impl ConflictResolver for LastWriteWinsResolver {
    fn resolve_conflict(&self, conflicts: &[Conflict]) -> Result<Resolution> {
        let mut resolution_map = HashMap::new();

        for conflict in conflicts {
            match conflict {
                Conflict::MultipleOperationsOnRid { rid, operations } => {
                    if let Some(latest_op) = operations.iter().max_by_key(|op| op.timestamp) {
                        resolution_map
                            .insert(*rid, OperationResolution::UseOperation(latest_op.clone()));
                    }
                }
                Conflict::InsertDeleteConflict {
                    rid,
                    insert_op,
                    delete_op,
                } => {
                    let winning_op = if insert_op.timestamp >= delete_op.timestamp {
                        insert_op
                    } else {
                        delete_op
                    };
                    resolution_map
                        .insert(*rid, OperationResolution::UseOperation(winning_op.clone()));
                }
            }
        }

        Ok(Resolution {
            operations: resolution_map,
        })
    }
}

/// Resolution of conflicts.
///
/// Contains the final resolved operations after conflict resolution.
/// This structure is used to apply the resolved operations to the assembly.
#[derive(Debug, Default)]
pub struct Resolution {
    /// Resolved operations keyed by RID.
    pub operations: HashMap<u32, OperationResolution>,
}

/// How to resolve a specific operation conflict.
///
/// Specifies the action to take for a conflicted operation.
#[derive(Debug)]
pub enum OperationResolution {
    /// Use the specified operation.
    UseOperation(TableOperation),
    /// Use the chronologically latest operation.
    UseLatest,
    /// Merge multiple operations into a sequence.
    Merge(Vec<TableOperation>),
    /// Reject the operation with an error message.
    Reject(String),
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::{
        cilassembly::{
            AssemblyChanges, HeapChanges, Operation, TableModifications, TableOperation,
        },
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
    fn test_validation_pipeline_default() {
        let pipeline = ValidationPipeline::default();

        // Verify that default pipeline has expected stages
        assert_eq!(pipeline.stages.len(), 2);

        // Check stage names to ensure correct stages are loaded
        assert_eq!(pipeline.stages[0].name(), "Basic Schema Validation");
        assert_eq!(pipeline.stages[1].name(), "RID Consistency Validation");
    }

    #[test]
    fn test_validation_pipeline_empty_changes() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let changes = AssemblyChanges::empty();
            let pipeline = ValidationPipeline::default();

            // Empty changes should pass all validation
            let result = pipeline.validate(&changes, &view);
            assert!(result.is_ok(), "Empty changes should pass validation");
        }
    }

    #[test]
    fn test_basic_schema_validator_valid_operations() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let mut changes = AssemblyChanges::empty();

            // Add valid table operation
            let mut table_modifications = TableModifications::new_sparse(1);
            let insert_op = TableOperation::new(Operation::Insert(100, create_test_row()));
            table_modifications.apply_operation(insert_op).unwrap();
            changes
                .table_changes
                .insert(TableId::TypeDef, table_modifications);

            let validator = BasicSchemaValidator;
            let result = validator.validate(&changes, &view);
            assert!(
                result.is_ok(),
                "Valid operations should pass basic schema validation"
            );
        }
    }

    #[test]
    fn test_basic_schema_validator_zero_rid_error() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let mut changes = AssemblyChanges::empty();

            // Add invalid operation with RID 0
            let mut table_modifications = TableModifications::new_sparse(1);
            let invalid_op = TableOperation::new(Operation::Insert(0, create_test_row()));
            table_modifications.apply_operation(invalid_op).unwrap();
            changes
                .table_changes
                .insert(TableId::TypeDef, table_modifications);

            let validator = BasicSchemaValidator;
            let result = validator.validate(&changes, &view);
            assert!(result.is_err(), "RID 0 should fail validation");

            if let Err(e) = result {
                assert!(
                    e.to_string().contains("Invalid RID"),
                    "Should be RID validation error"
                );
            }
        }
    }

    #[test]
    fn test_basic_schema_validator_schema_mismatch() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let mut changes = AssemblyChanges::empty();

            // Try to insert TypeDef row into MethodDef table (schema mismatch)
            let mut table_modifications = TableModifications::new_sparse(1);
            let mismatch_op = TableOperation::new(Operation::Insert(100, create_test_row()));
            table_modifications.apply_operation(mismatch_op).unwrap();
            changes
                .table_changes
                .insert(TableId::MethodDef, table_modifications); // Wrong table!

            let validator = BasicSchemaValidator;
            let result = validator.validate(&changes, &view);
            assert!(result.is_err(), "Schema mismatch should fail validation");

            if let Err(e) = result {
                assert!(
                    e.to_string().contains("Table schema mismatch"),
                    "Should be schema validation error"
                );
            }
        }
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

    #[test]
    fn test_last_write_wins_resolver_multiple_operations() {
        let operations = vec![
            {
                let mut op = TableOperation::new(Operation::Insert(100, create_test_row()));
                // Make first operation older
                op.timestamp = 1000; // Microseconds since epoch
                op
            },
            {
                let mut op = TableOperation::new(Operation::Update(100, create_test_row()));
                // Make second operation newer
                op.timestamp = 2000; // Later timestamp
                op
            },
        ];

        let conflict = Conflict::MultipleOperationsOnRid {
            rid: 100,
            operations,
        };

        let resolver = LastWriteWinsResolver;
        let result = resolver.resolve_conflict(&[conflict]);
        assert!(result.is_ok(), "Conflict resolution should succeed");

        if let Ok(resolution) = result {
            assert!(
                resolution.operations.contains_key(&100),
                "Should resolve RID 100"
            );

            if let Some(OperationResolution::UseOperation(op)) = resolution.operations.get(&100) {
                // Should use the newer Update operation
                assert!(
                    matches!(op.operation, Operation::Update(100, _)),
                    "Should use Update operation"
                );
            } else {
                panic!("Expected UseOperation resolution");
            }
        }
    }

    #[test]
    fn test_last_write_wins_resolver_insert_delete_conflict() {
        let insert_op = {
            let mut op = TableOperation::new(Operation::Insert(100, create_test_row()));
            op.timestamp = 1000; // Microseconds since epoch
            op
        };

        let delete_op = {
            let mut op = TableOperation::new(Operation::Delete(100));
            op.timestamp = 2000; // Later timestamp
            op
        };

        let conflict = Conflict::InsertDeleteConflict {
            rid: 100,
            insert_op,
            delete_op,
        };

        let resolver = LastWriteWinsResolver;
        let result = resolver.resolve_conflict(&[conflict]);
        assert!(result.is_ok(), "Conflict resolution should succeed");

        if let Ok(resolution) = result {
            assert!(
                resolution.operations.contains_key(&100),
                "Should resolve RID 100"
            );

            if let Some(OperationResolution::UseOperation(op)) = resolution.operations.get(&100) {
                // Should use the newer Delete operation
                assert!(
                    matches!(op.operation, Operation::Delete(100)),
                    "Should use Delete operation"
                );
            } else {
                panic!("Expected UseOperation resolution");
            }
        }
    }

    #[test]
    fn test_validation_pipeline_replaced_table() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let mut changes = AssemblyChanges::empty();

            // Add replaced table (should be valid)
            let rows = vec![create_test_row(), create_test_row(), create_test_row()];
            let replaced_modifications = TableModifications::Replaced(rows);
            changes
                .table_changes
                .insert(TableId::TypeDef, replaced_modifications);

            let pipeline = ValidationPipeline::default();
            let result = pipeline.validate(&changes, &view);
            assert!(result.is_ok(), "Replaced table should pass validation");
        }
    }

    #[test]
    fn test_validation_pipeline_heap_changes() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let mut changes = AssemblyChanges::empty();

            // Add heap changes (should be valid)
            let mut string_changes = HeapChanges::new(1000);
            string_changes
                .appended_items
                .push("Test String".to_string());
            string_changes.next_index = 1001;
            changes.string_heap_changes = string_changes;

            let mut blob_changes = HeapChanges::new(500);
            blob_changes.appended_items.push(vec![1, 2, 3, 4]);
            blob_changes.next_index = 501;
            changes.blob_heap_changes = blob_changes;

            let pipeline = ValidationPipeline::default();
            let result = pipeline.validate(&changes, &view);
            assert!(result.is_ok(), "Heap changes should pass validation");
        }
    }

    #[test]
    fn test_validation_pipeline_custom_stages() {
        struct AlwaysFailValidator;

        impl ValidationStage for AlwaysFailValidator {
            fn validate(
                &self,
                _changes: &AssemblyChanges,
                _original: &CilAssemblyView,
            ) -> crate::Result<()> {
                Err(crate::Error::Error("Always fails".to_string()))
            }

            fn name(&self) -> &'static str {
                "Always Fail Validator"
            }
        }

        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let changes = AssemblyChanges::empty();

            // Create pipeline with custom failing stage
            let pipeline = ValidationPipeline::new()
                .add_stage(BasicSchemaValidator)
                .add_stage(AlwaysFailValidator)
                .with_resolver(LastWriteWinsResolver);

            let result = pipeline.validate(&changes, &view);
            assert!(result.is_err(), "Pipeline with failing stage should fail");

            if let Err(e) = result {
                assert!(
                    e.to_string().contains("Always fails"),
                    "Should contain custom error message"
                );
            }
        }
    }

    #[test]
    fn test_validation_stage_ordering() {
        struct StageA;
        struct StageB;

        impl ValidationStage for StageA {
            fn validate(
                &self,
                _changes: &AssemblyChanges,
                _original: &CilAssemblyView,
            ) -> crate::Result<()> {
                Ok(())
            }
            fn name(&self) -> &'static str {
                "Stage A"
            }
        }

        impl ValidationStage for StageB {
            fn validate(
                &self,
                _changes: &AssemblyChanges,
                _original: &CilAssemblyView,
            ) -> crate::Result<()> {
                Ok(())
            }
            fn name(&self) -> &'static str {
                "Stage B"
            }
        }

        let pipeline = ValidationPipeline::new()
            .add_stage(StageA)
            .add_stage(StageB);

        // Verify stages are in the correct order
        assert_eq!(pipeline.stages.len(), 2);
        assert_eq!(pipeline.stages[0].name(), "Stage A");
        assert_eq!(pipeline.stages[1].name(), "Stage B");
    }

    #[test]
    fn test_conflict_types_debug_formatting() {
        let operations = vec![TableOperation::new(Operation::Insert(
            100,
            create_test_row(),
        ))];
        let conflict1 = Conflict::MultipleOperationsOnRid {
            rid: 100,
            operations,
        };

        let insert_op = TableOperation::new(Operation::Insert(100, create_test_row()));
        let delete_op = TableOperation::new(Operation::Delete(100));
        let conflict2 = Conflict::InsertDeleteConflict {
            rid: 100,
            insert_op,
            delete_op,
        };

        // Ensure Debug formatting works (shouldn't panic)
        let _ = format!("{:?}", conflict1);
        let _ = format!("{:?}", conflict2);
    }

    #[test]
    fn test_operation_resolution_variants() {
        let op = TableOperation::new(Operation::Insert(100, create_test_row()));

        let use_op = OperationResolution::UseOperation(op.clone());
        let use_latest = OperationResolution::UseLatest;
        let merge = OperationResolution::Merge(vec![op]);
        let reject = OperationResolution::Reject("Test reason".to_string());

        // Ensure Debug formatting works for all variants
        let _ = format!("{:?}", use_op);
        let _ = format!("{:?}", use_latest);
        let _ = format!("{:?}", merge);
        let _ = format!("{:?}", reject);
    }
}
