//! Validation pipeline and conflict resolution for assembly modifications.
//!
//! This module provides a comprehensive validation system for ensuring that
//! assembly modifications are consistent, valid, and can be safely applied.
//! It implements a multi-stage validation pipeline with configurable conflict
//! resolution strategies to handle complex modification scenarios.
//!
//! # Key Components
//!
//! - [`crate::cilassembly::validation::ValidationStage`] - Trait for individual validation stages
//! - [`crate::cilassembly::validation::ConflictResolver`] - Trait for conflict resolution strategies
//! - [`crate::cilassembly::validation::ValidationPipeline`] - Main validation pipeline coordinator
//! - [`crate::cilassembly::validation::ReferenceScanner`] - Reference scanning for integrity validation
//! - [`crate::cilassembly::validation::Conflict`] - Types of conflicts that can occur
//! - [`crate::cilassembly::validation::Resolution`] - Conflict resolution results
//!
//! # Architecture
//!
//! The validation system uses a multi-stage pipeline approach:
//!
//! ## Validation Pipeline
//! The system organizes validation into distinct stages:
//! - **Schema Validation**: Ensures modifications conform to ECMA-335 specifications
//! - **Consistency Validation**: Validates RID consistency and operation ordering
//! - **Integrity Validation**: Checks referential integrity and cross-table relationships
//! - **Conflict Resolution**: Resolves conflicts between competing operations
//!
//! ## Conflict Detection
//! The system detects various types of conflicts:
//! - Multiple operations targeting the same RID
//! - Insert/delete conflicts on the same row
//! - Cross-reference violations
//! - Heap index conflicts
//!
//! ## Resolution Strategies
//! Configurable conflict resolution strategies include:
//! - **Last-write-wins**: Most recent operation takes precedence
//! - **First-write-wins**: First operation takes precedence
//! - **Merge operations**: Combine compatible operations
//! - **Reject on conflict**: Fail validation on any conflict
//!
//! ## Integration Points
//! The validation system integrates with:
//! - Assembly modification system for change validation
//! - Reference tracking for integrity checks
//! - Binary generation for safe write operations
//!
//! # Usage Examples
//!
//! ```rust,ignore
//! use crate::cilassembly::validation::{ValidationPipeline, ValidationStage};
//! use crate::cilassembly::AssemblyChanges;
//! use crate::metadata::cilassemblyview::CilAssemblyView;
//!
//! # let view = CilAssemblyView::from_file("test.dll")?;
//! # let changes = AssemblyChanges::new();
//! // Create validation pipeline
//! let mut pipeline = ValidationPipeline::new();
//! pipeline.add_stage(Box::new(SchemaValidator::new()));
//! pipeline.add_stage(Box::new(ConsistencyValidator::new()));
//! pipeline.add_stage(Box::new(IntegrityValidator::new()));
//!
//! // Validate changes
//! let validation_result = pipeline.validate(&changes, &view)?;
//! if validation_result.is_valid() {
//!     println!("All validations passed");
//! } else {
//!     println!("Validation failed: {}", validation_result.error_message());
//! }
//! # Ok::<(), crate::Error>(())
//! ```
//!
//! # Thread Safety
//!
//! The validation system is designed to be [`Send`] and [`Sync`] as it operates
//! on immutable data structures and does not maintain mutable state between
//! validation operations.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::cilassembly::changes`] - Source of modification data to validate
//! - [`crate::cilassembly::references`] - Reference tracking for integrity validation
//! - [`crate::cilassembly::write`] - Binary generation pipeline validation
//! - [`crate::metadata::cilassemblyview`] - Original assembly data for validation context

use crate::{
    cilassembly::{AssemblyChanges, TableOperation},
    metadata::cilassemblyview::CilAssemblyView,
    Result,
};
use std::collections::HashMap;

/// Trait for validation stages in the pipeline.
///
/// Each validation stage focuses on a specific aspect of assembly modification
/// validation (e.g., RID consistency, cross-reference integrity, heap validation).
/// Stages are executed in sequence by the [`crate::cilassembly::validation::ValidationPipeline`]
/// and can abort the validation process if critical issues are found.
///
/// # Implementation Guidelines
///
/// Validation stages should:
/// - Be stateless and thread-safe
/// - Provide clear error messages for validation failures
/// - Focus on a single validation concern
/// - Execute efficiently to avoid pipeline bottlenecks
/// - Be composable with other validation stages
///
/// # Examples
///
/// ```rust,ignore
/// use crate::cilassembly::validation::ValidationStage;
/// use crate::cilassembly::AssemblyChanges;
/// use crate::metadata::cilassemblyview::CilAssemblyView;
///
/// struct CustomValidator;
///
/// impl ValidationStage for CustomValidator {
///     fn validate(&self, changes: &AssemblyChanges, original: &CilAssemblyView) -> Result<()> {
///         // Perform custom validation logic
///         Ok(())
///     }
///
///     fn name(&self) -> &'static str {
///         "Custom Validation"
///     }
/// }
/// ```
pub trait ValidationStage {
    /// Validates the provided changes against the original assembly.
    ///
    /// This method performs stage-specific validation of assembly modifications,
    /// checking for issues that would prevent safe application of the changes.
    /// Each stage should focus on a single validation concern to maintain
    /// separation of concerns and enable modular validation.
    ///
    /// # Arguments
    ///
    /// * `changes` - The [`crate::cilassembly::AssemblyChanges`] containing modifications to validate
    /// * `original` - The original [`crate::metadata::cilassemblyview::CilAssemblyView`] for reference and context
    /// * `scanner` - Optional pre-built [`crate::cilassembly::validation::ReferenceScanner`] for efficient reference tracking
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if validation passes, or an [`crate::Error`] describing
    /// the validation failure if issues are found.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] for various validation failures:
    /// - Invalid RID values or references
    /// - Referential integrity violations
    /// - Schema constraint violations
    /// - Conflicting operations
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use crate::cilassembly::validation::{ValidationStage, ReferenceScanner};
    /// use crate::cilassembly::AssemblyChanges;
    /// use crate::metadata::cilassemblyview::CilAssemblyView;
    ///
    /// # let validator = CustomValidator;
    /// # let changes = AssemblyChanges::new();
    /// # let view = CilAssemblyView::from_file("test.dll")?;
    /// # let scanner = ReferenceScanner::new(&view)?;
    /// // Validate changes with cached reference tracking
    /// match validator.validate(&changes, &view, Some(&scanner)) {
    ///     Ok(()) => println!("Validation passed"),
    ///     Err(e) => println!("Validation failed: {}", e),
    /// }
    /// # Ok::<(), crate::Error>(())
    /// ```
    fn validate(
        &self,
        changes: &AssemblyChanges,
        original: &CilAssemblyView,
        scanner: Option<&ReferenceScanner>,
    ) -> Result<()>;

    /// Returns the name of this validation stage.
    ///
    /// The name is used for logging, error reporting, and debugging purposes.
    /// It should be descriptive and unique within the validation pipeline.
    ///
    /// # Returns
    ///
    /// Returns a static string containing the stage name.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use crate::cilassembly::validation::ValidationStage;
    ///
    /// # let validator = CustomValidator;
    /// let stage_name = validator.name();
    /// println!("Running validation stage: {}", stage_name);
    /// ```
    fn name(&self) -> &'static str;
}

/// Trait for conflict resolution strategies.
///
/// Different applications may need different conflict resolution strategies:
/// - **Last-write-wins (default)**: Most recent operation takes precedence
/// - **First-write-wins**: First operation takes precedence
/// - **Merge operations**: Combine compatible operations
/// - **Reject on conflict**: Fail validation on any conflict
///
/// Conflict resolution is essential for handling scenarios where multiple
/// operations target the same resource, ensuring deterministic behavior
/// and maintaining assembly integrity.
///
/// # Implementation Guidelines
///
/// Conflict resolvers should:
/// - Be deterministic and consistent
/// - Handle all conflict types appropriately
/// - Provide clear resolution decisions
/// - Be configurable for different use cases
/// - Maintain operation ordering guarantees
///
/// # Examples
///
/// ```rust,ignore
/// use crate::cilassembly::validation::{ConflictResolver, Conflict, Resolution};
///
/// struct LastWriteWinsResolver;
///
/// impl ConflictResolver for LastWriteWinsResolver {
///     fn resolve_conflict(&self, conflicts: &[Conflict]) -> Result<Resolution> {
///         let mut resolution = Resolution::default();
///         for conflict in conflicts {
///             // Resolve by choosing the latest operation
///             // Implementation details...
///         }
///         Ok(resolution)
///     }
/// }
/// ```
pub trait ConflictResolver {
    /// Resolves conflicts between operations.
    ///
    /// This method analyzes the provided conflicts and determines how to resolve
    /// them according to the resolver's strategy. The resolution specifies which
    /// operations should be applied and in what order.
    ///
    /// # Arguments
    ///
    /// * `conflicts` - Array of [`Conflict`] instances representing conflicting operations
    ///
    /// # Returns
    ///
    /// Returns a [`Resolution`] that specifies how to handle each conflict,
    /// including which operations to apply and which to reject.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] if conflicts cannot be resolved or if the
    /// resolution strategy encounters invalid conflict states.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use crate::cilassembly::validation::{ConflictResolver, Conflict};
    ///
    /// # let resolver = LastWriteWinsResolver;
    /// # let conflicts = vec![]; // conflicts would be populated
    /// let resolution = resolver.resolve_conflict(&conflicts)?;
    /// for (rid, operation_resolution) in resolution.operations {
    ///     println!("RID {} resolved to: {:?}", rid, operation_resolution);
    /// }
    /// # Ok::<(), crate::Error>(())
    /// ```
    fn resolve_conflict(&self, conflicts: &[Conflict]) -> Result<Resolution>;
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

mod consistency;
mod integrity;
mod pipeline;
mod reference;
mod resolver;
mod schema;

pub use consistency::*;
pub use integrity::*;
pub use pipeline::*;
pub use reference::ReferenceScanner;
pub use resolver::*;
pub use schema::*;
