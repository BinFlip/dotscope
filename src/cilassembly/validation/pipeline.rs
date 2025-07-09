//! Validation pipeline orchestration.
//!
//! This module provides the [`ValidationPipeline`] which orchestrates the execution
//! of multiple validation stages in sequence, ensuring comprehensive validation of
//! assembly modifications before they are applied. The pipeline supports configurable
//! validation stages and conflict resolution strategies.
//!
//! # Key Components
//!
//! - [`ValidationPipeline`] - Main pipeline orchestrator for sequential validation
//!
//! # Architecture
//!
//! The validation pipeline follows a sequential execution model:
//!
//! ## Stage Execution
//! - Stages are executed in the order they were added
//! - Each stage validates a specific aspect of the modifications
//! - Execution stops at the first stage that fails
//! - All stages must pass for validation to succeed
//!
//! ## Conflict Resolution
//! - Configured conflict resolver handles operation conflicts
//! - Different strategies available (last-write-wins, first-write-wins, etc.)
//! - Conflict resolution occurs after all stages pass
//!
//! ## Default Configuration
//! - Basic schema validation for ECMA-335 compliance
//! - RID consistency validation for proper row ordering
//! - Referential integrity validation for cross-table references
//! - Last-write-wins conflict resolution
//!
//! # Usage Examples
//!
//! ```rust,ignore
//! use crate::cilassembly::validation::{ValidationPipeline, BasicSchemaValidator};
//! use crate::cilassembly::AssemblyChanges;
//! use crate::metadata::cilassemblyview::CilAssemblyView;
//!
//! # let view = CilAssemblyView::from_file("test.dll")?;
//! # let changes = AssemblyChanges::new();
//! // Use default pipeline
//! let pipeline = ValidationPipeline::default();
//! pipeline.validate(&changes, &view)?;
//!
//! // Custom pipeline with specific stages
//! let custom_pipeline = ValidationPipeline::new()
//!     .add_stage(BasicSchemaValidator)
//!     .add_stage(CustomValidator::new());
//! custom_pipeline.validate(&changes, &view)?;
//! # Ok::<(), crate::Error>(())
//! ```
//!
//! # Thread Safety
//!
//! The pipeline is not [`Send`] or [`Sync`] due to the boxed trait objects
//! for validation stages, but individual validation operations are thread-safe.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::cilassembly::validation::ValidationStage`] - Individual validation stages
//! - [`crate::cilassembly::validation::ConflictResolver`] - Conflict resolution strategies
//! - [`crate::cilassembly::changes`] - Assembly modification data
//! - [`crate::metadata::cilassemblyview`] - Original assembly context

use crate::{
    cilassembly::{
        validation::{
            BasicSchemaValidator, ConflictResolver, LastWriteWinsResolver, ReferenceScanner,
            ReferentialIntegrityValidator, RidConsistencyValidator, ValidationStage,
        },
        AssemblyChanges,
    },
    metadata::cilassemblyview::CilAssemblyView,
    Result,
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

    /// Validates the given changes using all stages in the pipeline.
    ///
    /// This method builds a reference scanner once and shares it among all validation
    /// stages for optimal performance. All stages must pass for validation to succeed.
    ///
    /// # Arguments
    ///
    /// * `changes` - The [`crate::cilassembly::AssemblyChanges`] to validate
    /// * `original` - The original [`crate::metadata::cilassemblyview::CilAssemblyView`] for context
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if all validation stages pass, or an [`crate::Error`] from
    /// the first stage that fails.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] if any validation stage fails.
    pub fn validate(&self, changes: &AssemblyChanges, original: &CilAssemblyView) -> Result<()> {
        let scanner = ReferenceScanner::new(original)?;

        for stage in &self.stages {
            stage.validate(changes, original, Some(&scanner))?;
        }
        Ok(())
    }
}

impl Default for ValidationPipeline {
    fn default() -> Self {
        Self::new()
            .add_stage(BasicSchemaValidator)
            .add_stage(RidConsistencyValidator)
            .add_stage(ReferentialIntegrityValidator::default())
            .with_resolver(LastWriteWinsResolver)
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::{
        cilassembly::{
            AssemblyChanges, HeapChanges, Operation, ReferenceHandlingStrategy, TableModifications,
            TableOperation,
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

        assert_eq!(pipeline.stages.len(), 3);

        assert_eq!(pipeline.stages[0].name(), "Basic Schema Validation");
        assert_eq!(pipeline.stages[1].name(), "RID Consistency Validation");
        assert_eq!(
            pipeline.stages[2].name(),
            "Referential Integrity Validation"
        );
    }

    #[test]
    fn test_validation_pipeline_empty_changes() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let changes = AssemblyChanges::empty();
            let pipeline = ValidationPipeline::default();

            let result = pipeline.validate(&changes, &view);
            assert!(result.is_ok(), "Empty changes should pass validation");
        }
    }

    #[test]
    fn test_validation_pipeline_replaced_table() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let mut changes = AssemblyChanges::empty();

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
                _scanner: Option<&ReferenceScanner>,
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
                _scanner: Option<&ReferenceScanner>,
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
                _scanner: Option<&ReferenceScanner>,
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

        assert_eq!(pipeline.stages.len(), 2);
        assert_eq!(pipeline.stages[0].name(), "Stage A");
        assert_eq!(pipeline.stages[1].name(), "Stage B");
    }

    #[test]
    fn test_validation_pipeline_cached_references() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let changes = AssemblyChanges::empty();
            let pipeline = ValidationPipeline::default();

            let result = pipeline.validate(&changes, &view);
            assert!(result.is_ok(), "Validation should pass with empty changes");
        }
    }

    #[test]
    fn test_validation_pipeline_comprehensive_integration() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let mut changes = AssemblyChanges::empty();

            // Use a more aggressive validation pipeline with NullifyReferences strategy
            let pipeline = ValidationPipeline::new()
                .add_stage(BasicSchemaValidator)
                .add_stage(RidConsistencyValidator)
                .add_stage(ReferentialIntegrityValidator::new(
                    ReferenceHandlingStrategy::NullifyReferences,
                ))
                .with_resolver(LastWriteWinsResolver);

            let mut table_modifications = TableModifications::new_sparse(1);
            let valid_insert = TableOperation::new(Operation::Insert(100, create_test_row()));
            table_modifications.apply_operation(valid_insert).unwrap();
            changes
                .table_changes
                .insert(TableId::TypeDef, table_modifications);

            let mut string_changes = HeapChanges::new(1000);
            string_changes
                .appended_items
                .push("Integration Test String".to_string());
            string_changes.next_index = 1001;
            changes.string_heap_changes = string_changes;

            let mut blob_changes = HeapChanges::new(500);
            blob_changes
                .appended_items
                .push(vec![0x01, 0x02, 0x03, 0x04]);
            blob_changes.next_index = 501;
            changes.blob_heap_changes = blob_changes;

            let result = pipeline.validate(&changes, &view);
            assert!(
                result.is_ok(),
                "Comprehensive validation should pass with valid changes"
            );
        }
    }

    #[test]
    fn test_referential_integrity_validation_with_resolution_strategies() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            // First, let's find a TypeDef that's actually referenced
            // We'll use the ReferenceScanner to find references before testing
            let scanner = ReferenceScanner::new(&view).unwrap();
            let mut referenced_typedef_rid = None;

            // Check TypeDef RIDs 1-10 to find one that's referenced
            if let Some(tables) = view.tables() {
                if let Some(typedef_table) = tables.table::<TypeDefRaw>() {
                    for rid in 1..=std::cmp::min(10, typedef_table.row_count) {
                        let refs = scanner.find_references_to_table_row(TableId::TypeDef, rid);
                        if !refs.is_empty() {
                            referenced_typedef_rid = Some(rid);
                            break;
                        }
                    }
                }
            }

            // Skip test if no referenced TypeDef found
            let referenced_rid = match referenced_typedef_rid {
                Some(rid) => rid,
                None => {
                    // Skip test if no referenced TypeDef found - this is expected for some samples
                    return;
                }
            };

            // Create changes that will cause referential integrity violations
            let mut changes = AssemblyChanges::empty();

            // Delete the TypeDef that we know is referenced
            let mut table_modifications = TableModifications::new_sparse(1);
            let delete_op = TableOperation::new(Operation::Delete(referenced_rid));
            table_modifications.apply_operation(delete_op).unwrap();
            changes
                .table_changes
                .insert(TableId::TypeDef, table_modifications);

            // Test 1: Default FailIfReferenced strategy should fail
            let fail_if_referenced_validator =
                ReferentialIntegrityValidator::new(ReferenceHandlingStrategy::FailIfReferenced);
            let fail_pipeline = ValidationPipeline::new()
                .add_stage(BasicSchemaValidator)
                .add_stage(RidConsistencyValidator)
                .add_stage(fail_if_referenced_validator);

            let result = fail_pipeline.validate(&changes, &view);
            assert!(
                result.is_err(),
                "FailIfReferenced strategy should fail when deleting referenced TypeDef RID {referenced_rid}"
            );

            if let Err(e) = result {
                assert!(
                    e.to_string().contains("referential integrity")
                        || e.to_string().contains("referenced")
                        || e.to_string().contains("integrity"),
                    "Error should mention referential integrity or references: {e}"
                );
            }

            // Test 2: NullifyReferences strategy should succeed and nullify references
            let nullify_validator =
                ReferentialIntegrityValidator::new(ReferenceHandlingStrategy::NullifyReferences);
            let nullify_pipeline = ValidationPipeline::new()
                .add_stage(BasicSchemaValidator)
                .add_stage(RidConsistencyValidator)
                .add_stage(nullify_validator);

            let result = nullify_pipeline.validate(&changes, &view);
            assert!(
                result.is_ok(),
                "NullifyReferences strategy should succeed by nullifying references: {result:?}"
            );

            // Test 3: RemoveReferences strategy should succeed with cascade deletion
            let remove_validator =
                ReferentialIntegrityValidator::new(ReferenceHandlingStrategy::RemoveReferences);
            let remove_pipeline = ValidationPipeline::new()
                .add_stage(BasicSchemaValidator)
                .add_stage(RidConsistencyValidator)
                .add_stage(remove_validator);

            let result = remove_pipeline.validate(&changes, &view);
            assert!(
                result.is_ok(),
                "RemoveReferences strategy should succeed with cascade deletion: {result:?}"
            );
        }
    }
}
