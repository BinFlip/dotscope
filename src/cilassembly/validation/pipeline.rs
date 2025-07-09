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
            BasicSchemaValidator, ConflictResolver, LastWriteWinsResolver,
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
            .add_stage(ReferentialIntegrityValidator::default())
            .with_resolver(LastWriteWinsResolver)
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::{
        cilassembly::{AssemblyChanges, HeapChanges, TableModifications},
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
        assert_eq!(pipeline.stages.len(), 3);

        // Check stage names to ensure correct stages are loaded
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

            // Empty changes should pass all validation
            let result = pipeline.validate(&changes, &view);
            assert!(result.is_ok(), "Empty changes should pass validation");
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
}
