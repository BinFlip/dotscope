//! Referential integrity validation for assembly modification operations.
//!
//! This module provides comprehensive validation to ensure that referential integrity
//! is maintained across all metadata table operations. It implements sophisticated
//! reference tracking and validation strategies to prevent dangling references and
//! maintain cross-table relationship consistency during assembly modifications.
//!
//! # Key Components
//!
//! - [`crate::cilassembly::validation::integrity::ReferentialIntegrityValidator`] - Main referential integrity validator
//!
//! # Architecture
//!
//! The referential integrity validation system is built around comprehensive reference
//! tracking and configurable handling strategies:
//!
//! ## Reference Tracking
//! The validator uses the [`crate::cilassembly::validation::reference::ReferenceScanner`] to:
//! - Scan all metadata tables for cross-references
//! - Build comprehensive reference maps for efficient lookups
//! - Track both direct references and coded indices
//! - Handle heap references (string, blob, GUID indices)
//!
//! ## Validation Strategies
//! The validator supports multiple reference handling strategies:
//! - **Fail if Referenced**: Prevents deletion of referenced items (default)
//! - **Remove References**: Enables cascading deletion of referencing items
//! - **Nullify References**: Converts references to null rather than leaving dangling pointers
//!
//! ## Performance Optimization
//! The validator uses efficient reference tracking with pre-built reference maps:
//! - Reference tracker built once during scanner construction
//! - O(1) lookup time for all reference queries
//! - Optimized for both single queries and batch operations
//!
//! # Usage Examples
//!
//! ```rust,ignore
//! use crate::cilassembly::validation::integrity::ReferentialIntegrityValidator;
//! use crate::cilassembly::validation::ValidationStage;
//! use crate::cilassembly::{AssemblyChanges, ReferenceHandlingStrategy};
//! use crate::metadata::cilassemblyview::CilAssemblyView;
//!
//! # let view = CilAssemblyView::from_file("test.dll")?;
//! # let changes = AssemblyChanges::new();
//! // Create validator with default strategy
//! let validator = ReferentialIntegrityValidator::default();
//!
//! // Or create with custom strategy
//! let custom_validator = ReferentialIntegrityValidator::new(
//!     ReferenceHandlingStrategy::NullifyReferences
//! );
//!
//! // Validate changes for referential integrity
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
//! - [`crate::cilassembly::validation::reference::ReferenceScanner`] - Performs reference scanning
//! - [`crate::cilassembly::references::ReferenceTracker`] - Provides efficient reference tracking
//! - [`crate::cilassembly::ReferenceHandlingStrategy`] - Configures reference handling behavior

use std::collections::{HashMap, HashSet};

use crate::{
    cilassembly::{
        changes::{HeapChanges, ReferenceHandlingStrategy as HeapReferenceHandlingStrategy},
        references::TableReference,
        validation::{ReferenceScanner, ValidationStage},
        AssemblyChanges, Operation, ReferenceHandlingStrategy, TableModifications,
    },
    metadata::{
        cilassemblyview::CilAssemblyView,
        tables::{CodedIndex, TableDataOwned, TableId},
    },
    Error, Result, TablesHeader,
};

/// Referential integrity validation for assembly modification operations.
///
/// [`ReferentialIntegrityValidator`] ensures that referential integrity is maintained
/// across all metadata table operations by implementing comprehensive reference tracking
/// and configurable handling strategies. It prevents dangling references and maintains
/// cross-table relationship consistency during assembly modifications.
///
/// # Validation Checks
///
/// The validator performs the following referential integrity checks:
/// - **Delete Operation Validation**: Ensures delete operations respect reference handling strategies
/// - **Reference Tracking**: Validates that references to deleted items are properly handled
/// - **Cross-Table Consistency**: Maintains validity of cross-table references after modifications
/// - **Cascading Effects**: Handles cascading reference updates when configured
///
/// # Reference Handling Strategies
///
/// The validator supports multiple strategies for handling references during deletions:
/// - **Fail if Referenced**: Prevents deletion of items that are still referenced elsewhere
/// - **Remove References**: Enables cascading deletion of items that reference the deleted item
/// - **Nullify References**: Converts references to null values rather than leaving dangling pointers
///
/// # Usage Examples
///
/// ```rust,ignore
/// use crate::cilassembly::validation::integrity::ReferentialIntegrityValidator;
/// use crate::cilassembly::validation::ValidationStage;
/// use crate::cilassembly::{AssemblyChanges, ReferenceHandlingStrategy};
/// use crate::metadata::cilassemblyview::CilAssemblyView;
///
/// # let view = CilAssemblyView::from_file("test.dll")?;
/// # let changes = AssemblyChanges::new();
/// // Create validator with default fail-if-referenced strategy
/// let validator = ReferentialIntegrityValidator::default();
///
/// // Or create with custom strategy
/// let custom_validator = ReferentialIntegrityValidator::new(
///     ReferenceHandlingStrategy::NullifyReferences
/// );
///
/// // Validate changes for referential integrity
/// validator.validate(&changes, &view)?;
/// # Ok::<(), crate::Error>(())
/// ```
///
/// # Thread Safety
///
/// This type is [`Send`] and [`Sync`] as it contains no mutable state and operates
/// purely on the input data provided to the validation methods.
pub struct ReferentialIntegrityValidator {
    /// Default strategy to use when none is specified
    pub default_strategy: ReferenceHandlingStrategy,
}

/// Represents a single deletion in a cascade delete operation.
///
/// A [`CascadeDeletion`] tracks the details of a row deletion within a larger
/// cascade delete plan, including its position in the deletion hierarchy and
/// the references that caused the deletion.
///
/// # Cascade Hierarchy
///
/// Cascade deletions form a tree structure where:
/// - Root deletions have depth 0 and no parent
/// - Child deletions have increasing depth values
/// - Each deletion tracks which parent deletion triggered it
///
/// # Reference Tracking
///
/// Each deletion maintains a record of all references that pointed to the
/// deleted row, enabling proper cleanup and validation of the deletion chain.
#[derive(Debug, Clone)]
pub struct CascadeDeletion {
    /// The table ID of the row being deleted
    pub table_id: TableId,
    /// The RID of the row being deleted
    pub rid: u32,
    /// The depth in the cascade (0 for root deletion)
    pub depth: usize,
    /// The parent deletion that caused this deletion (None for root)
    pub parent: Option<(TableId, u32)>,
    /// All references that pointed to this row before deletion
    pub references: Vec<TableReference>,
}

/// Represents a complete cascade delete plan showing all rows that would be deleted.
///
/// A [`CascadeDeletePlan`] provides a comprehensive view of all deletions that would
/// be performed during a cascade delete operation, organized by execution order and
/// depth level for safe and efficient execution.
///
/// # Plan Structure
///
/// The plan organizes deletions to ensure:
/// - Dependencies are respected (children deleted before parents)
/// - Reference integrity is maintained throughout the process
/// - Execution order is deterministic and safe
///
/// # Analysis Support
///
/// The plan provides methods for analyzing the deletion scope:
/// - Total deletion count for impact assessment
/// - Depth analysis for complexity measurement
/// - Table-specific deletion counts for resource planning
#[derive(Debug, Clone)]
pub struct CascadeDeletePlan {
    /// All deletions in the cascade, in execution order
    pub deletions: Vec<CascadeDeletion>,
    /// Total number of rows that would be deleted
    pub total_deletions: usize,
    /// Maximum depth of the cascade
    pub max_depth: usize,
}

impl CascadeDeletePlan {
    /// Creates a new empty cascade delete plan.
    ///
    /// # Returns
    ///
    /// Returns an empty [`CascadeDeletePlan`] ready to receive deletions.
    pub fn new() -> Self {
        Self {
            deletions: Vec::new(),
            total_deletions: 0,
            max_depth: 0,
        }
    }

    /// Adds a deletion to the plan.
    ///
    /// # Arguments
    ///
    /// * `table_id` - The [`crate::metadata::tables::TableId`] of the table containing the row to delete
    /// * `rid` - The row identifier within the table
    /// * `depth` - The depth in the cascade hierarchy (0 for root deletions)
    /// * `parent` - Optional parent deletion that triggered this deletion
    /// * `references` - All references that pointed to this row
    pub fn add_deletion(
        &mut self,
        table_id: TableId,
        rid: u32,
        depth: usize,
        parent: Option<(TableId, u32)>,
        references: Vec<TableReference>,
    ) {
        self.deletions.push(CascadeDeletion {
            table_id,
            rid,
            depth,
            parent,
            references,
        });
        self.total_deletions += 1;
        self.max_depth = self.max_depth.max(depth);
    }

    /// Gets all deletions at a specific depth level.
    ///
    /// # Arguments
    ///
    /// * `depth` - The cascade depth level to retrieve
    ///
    /// # Returns
    ///
    /// Returns a vector of references to all [`CascadeDeletion`] entries at the specified depth.
    pub fn deletions_at_depth(&self, depth: usize) -> Vec<&CascadeDeletion> {
        self.deletions.iter().filter(|d| d.depth == depth).collect()
    }

    /// Gets all deletions for a specific table.
    ///
    /// # Arguments
    ///
    /// * `table_id` - The [`crate::metadata::tables::TableId`] to filter by
    ///
    /// # Returns
    ///
    /// Returns a vector of references to all [`CascadeDeletion`] entries for the specified table.
    pub fn deletions_for_table(&self, table_id: TableId) -> Vec<&CascadeDeletion> {
        self.deletions
            .iter()
            .filter(|d| d.table_id == table_id)
            .collect()
    }

    /// Returns a summary of the cascade delete plan.
    ///
    /// # Returns
    ///
    /// Returns a formatted string summarizing the deletion plan including
    /// total deletion count, depth levels, and per-table breakdowns.
    pub fn summary(&self) -> String {
        if self.deletions.is_empty() {
            return "No deletions required".to_string();
        }

        let mut summary = format!(
            "Cascade delete plan: {} rows across {} depth levels\n",
            self.total_deletions,
            self.max_depth + 1
        );

        let mut table_counts: std::collections::HashMap<TableId, usize> =
            std::collections::HashMap::new();
        for deletion in &self.deletions {
            *table_counts.entry(deletion.table_id).or_insert(0) += 1;
        }

        let mut sorted_tables: Vec<_> = table_counts.iter().collect();
        sorted_tables.sort_by_key(|(table_id, _)| **table_id as u32);

        for (table_id, count) in sorted_tables {
            summary.push_str(&format!("  {}: {} rows\n", *table_id as u32, count));
        }

        summary
    }
}

impl Default for CascadeDeletePlan {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for ReferentialIntegrityValidator {
    fn default() -> Self {
        Self::new(ReferenceHandlingStrategy::FailIfReferenced)
    }
}

impl ReferentialIntegrityValidator {
    /// Creates a new referential integrity validator.
    ///
    /// # Arguments
    ///
    /// * `default_strategy` - The [`crate::cilassembly::ReferenceHandlingStrategy`] to use by default
    ///
    /// # Returns
    ///
    /// A new [`ReferentialIntegrityValidator`] instance.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use crate::cilassembly::validation::integrity::ReferentialIntegrityValidator;
    /// use crate::cilassembly::ReferenceHandlingStrategy;
    ///
    /// let validator = ReferentialIntegrityValidator::new(
    ///     ReferenceHandlingStrategy::NullifyReferences
    /// );
    /// ```
    pub fn new(default_strategy: ReferenceHandlingStrategy) -> Self {
        Self { default_strategy }
    }

    /// Validates referential integrity for delete operations.
    ///
    /// This method checks all delete operations to ensure they respect the specified
    /// reference handling strategy and that referential integrity is maintained.
    /// It builds a reference scanner once for efficient lookups during validation.
    ///
    /// # Arguments
    ///
    /// * `changes` - The [`crate::cilassembly::AssemblyChanges`] containing operations to validate
    /// * `original` - The original [`crate::metadata::cilassemblyview::CilAssemblyView`] for reference scanning
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if all delete operations maintain referential integrity,
    /// or an [`crate::Error`] describing the integrity violation.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationReferentialIntegrity`] if delete operations
    /// would violate referential integrity constraints.
    pub fn validate_delete_operations(
        &self,
        changes: &AssemblyChanges,
        original: &CilAssemblyView,
    ) -> Result<()> {
        let scanner = ReferenceScanner::new(original)?;

        for (table_id, table_modifications) in &changes.table_changes {
            if let TableModifications::Sparse { operations, .. } = table_modifications {
                for operation in operations {
                    if let Operation::Delete(rid) = &operation.operation {
                        self.validate_delete_operation(*table_id, *rid, &scanner)?;
                    }
                }
            }
        }

        self.validate_heap_changes(changes, &scanner)?;
        Ok(())
    }

    /// Validates referential integrity using a cached reference scanner.
    ///
    /// This method provides enhanced performance by accepting a pre-built reference
    /// scanner instead of creating a new one. This is particularly beneficial when
    /// used with the validation pipeline's cached reference tracking, as it allows
    /// multiple validation stages to share the same scanner instance.
    ///
    /// # Performance Benefits
    ///
    /// - **No scanner construction overhead**: Uses provided scanner directly
    /// - **Shared reference tracking**: Multiple stages can use the same scanner
    /// - **Optimized for pipeline use**: Designed for validation pipeline integration
    /// - **Reduced memory allocations**: Avoids duplicate scanner creation
    ///
    /// # Arguments
    ///
    /// * `changes` - The [`crate::cilassembly::AssemblyChanges`] containing operations to validate
    /// * `original` - The original [`crate::metadata::cilassemblyview::CilAssemblyView`] for reference context
    /// * `scanner` - A pre-built [`crate::cilassembly::validation::ReferenceScanner`] for reference tracking
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if all validation checks pass, or an [`crate::Error`] describing
    /// the validation failure.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationReferentialIntegrity`] if validation fails.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use crate::cilassembly::validation::{ReferentialIntegrityValidator, ReferenceScanner};
    /// use crate::cilassembly::AssemblyChanges;
    /// use crate::metadata::cilassemblyview::CilAssemblyView;
    ///
    /// # let view = CilAssemblyView::from_file("test.dll")?;
    /// # let changes = AssemblyChanges::empty();
    /// let validator = ReferentialIntegrityValidator::default();
    /// let scanner = ReferenceScanner::new(&view)?;
    ///
    /// // Use cached scanner for enhanced performance
    /// validator.validate_with_cached_scanner(&changes, &view, &scanner)?;
    /// # Ok::<(), crate::Error>(())
    /// ```
    pub fn validate_with_cached_scanner(
        &self,
        changes: &AssemblyChanges,
        original: &CilAssemblyView,
        scanner: &ReferenceScanner,
    ) -> Result<()> {
        for (table_id, table_modifications) in &changes.table_changes {
            if let TableModifications::Sparse { operations, .. } = table_modifications {
                for operation in operations {
                    if let Operation::Delete(rid) = &operation.operation {
                        self.validate_delete_operation(*table_id, *rid, scanner)?;
                    }
                }
            }
        }

        self.validate_heap_changes(changes, scanner)?;
        self.validate_cross_reference_consistency(changes, original)?;

        Ok(())
    }

    /// Validates a single delete operation for referential integrity.
    ///
    /// This method validates that a specific delete operation can be performed
    /// without violating referential integrity constraints. It uses the provided
    /// scanner for efficient reference lookups.
    ///
    /// # Arguments
    ///
    /// * `table_id` - The [`crate::metadata::tables::TableId`] of the table containing the row to delete
    /// * `rid` - The RID of the row to delete
    /// * `scanner` - The reference scanner to use for finding references
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the delete operation maintains referential integrity,
    /// or an [`crate::Error`] describing the integrity violation.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationReferentialIntegrity`] if the delete operation
    /// would violate referential integrity constraints based on the configured strategy.
    fn validate_delete_operation(
        &self,
        table_id: TableId,
        rid: u32,
        scanner: &ReferenceScanner,
    ) -> Result<()> {
        let references = scanner.find_references_to_table_row(table_id, rid);

        match self.default_strategy {
            ReferenceHandlingStrategy::FailIfReferenced => {
                if !references.is_empty() {
                    let detailed_message =
                        self.create_detailed_reference_error(table_id, rid, &references);
                    return Err(Error::ValidationReferentialIntegrity {
                        message: detailed_message,
                    });
                }
            }
            ReferenceHandlingStrategy::RemoveReferences => {
                self.validate_cascade_delete(table_id, rid, &references, scanner)?;
            }
            ReferenceHandlingStrategy::NullifyReferences => {
                self.validate_nullify_references(table_id, rid, &references)?;
            }
        }

        Ok(())
    }

    /// Finds all references to a specific table row.
    ///
    /// This method uses the [`crate::cilassembly::validation::reference::ReferenceScanner`] to efficiently find all references
    /// to the specified table row across all metadata tables. It can optionally
    /// use cached reference tracking for better performance with multiple queries.
    ///
    /// # Arguments
    ///
    /// * `table_id` - The [`crate::metadata::tables::TableId`] of the table containing the target row
    /// * `rid` - The RID of the target row
    /// * `original` - The original [`crate::metadata::cilassemblyview::CilAssemblyView`] for reference context
    ///
    /// # Returns
    ///
    /// Returns a [`Vec`] of [`crate::cilassembly::references::TableReference`] instances representing
    /// all locations where the target row is referenced.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] if there are issues during reference scanning.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use crate::cilassembly::validation::integrity::ReferentialIntegrityValidator;
    /// use crate::metadata::tables::TableId;
    /// use crate::metadata::cilassemblyview::CilAssemblyView;
    ///
    /// # let validator = ReferentialIntegrityValidator::default();
    /// # let view = CilAssemblyView::from_file("test.dll")?;
    /// // Find all references to TypeDef row 1
    /// let references = validator.find_references_to_table_row(TableId::TypeDef, 1, &view)?;
    /// println!("Found {} references", references.len());
    /// # Ok::<(), crate::Error>(())
    /// ```
    fn find_references_to_table_row(
        &self,
        table_id: TableId,
        rid: u32,
        scanner: &ReferenceScanner,
    ) -> Vec<TableReference> {
        scanner.find_references_to_table_row(table_id, rid)
    }

    /// Generates a cascade delete plan for a specific table row.
    ///
    /// This method builds a complete plan of all rows that would be deleted
    /// in a cascade operation, including the order of deletion and the reasons
    /// for each deletion.
    ///
    /// # Arguments
    ///
    /// * `table_id` - The table ID of the row to delete
    /// * `rid` - The RID of the row to delete
    /// * `original` - The original assembly view for reference context
    ///
    /// # Returns
    ///
    /// Returns a [`CascadeDeletePlan`] containing all rows that would be deleted
    /// and the relationships between them.
    ///
    /// # Errors
    ///
    /// Returns an error if the cascade would be invalid or if critical references
    /// prevent the cascade from being executed.
    pub fn get_cascade_delete_plan(
        &self,
        table_id: TableId,
        rid: u32,
        scanner: &ReferenceScanner,
    ) -> Result<CascadeDeletePlan> {
        let mut plan = CascadeDeletePlan::new();
        let mut visited = HashSet::new();

        self.build_cascade_plan_recursive(
            table_id,
            rid,
            &mut visited,
            &mut plan,
            0,
            None,
            scanner,
        )?;

        Ok(plan)
    }

    /// Recursively builds a cascade deletion plan for a table row and its references.
    ///
    /// This method traverses the reference graph starting from the specified table row,
    /// building a comprehensive cascade deletion plan that includes all dependent rows
    /// that must be deleted to maintain referential integrity. The method implements
    /// cycle detection and depth limiting to prevent infinite recursion.
    ///
    /// # Arguments
    ///
    /// * `table_id` - The [`crate::metadata::tables::TableId`] of the table containing the row
    /// * `rid` - The RID of the row to build the cascade plan for
    /// * `visited` - Set of already visited `(table_id, rid)` pairs for cycle detection
    /// * `plan` - The [`CascadeDeletePlan`] to populate with deletion operations
    /// * `depth` - Current recursion depth for limiting cascade depth
    /// * `parent` - Optional parent `(table_id, rid)` that initiated this deletion
    /// * `scanner` - The [`crate::cilassembly::validation::reference::ReferenceScanner`] for finding references
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the cascade plan is successfully built, or an [`crate::Error`]
    /// if the operation fails due to reference scanning errors or cascade depth limits.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] if:
    /// - Reference scanning fails during traversal
    /// - Maximum cascade depth is exceeded (prevents infinite recursion)
    /// - Circular reference detection fails
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use crate::cilassembly::validation::integrity::ReferentialIntegrityValidator;
    /// use crate::metadata::tables::TableId;
    /// use std::collections::HashSet;
    ///
    /// # let validator = ReferentialIntegrityValidator::default();
    /// # let scanner = ReferenceScanner::new(&view)?;
    /// # let mut plan = CascadeDeletePlan::new();
    /// # let mut visited = HashSet::new();
    /// // Build cascade plan recursively
    /// validator.build_cascade_plan_recursive(
    ///     TableId::TypeDef,
    ///     1,
    ///     &mut visited,
    ///     &mut plan,
    ///     0,
    ///     None,
    ///     &scanner,
    /// )?;
    /// # Ok::<(), crate::Error>(())
    /// ```
    fn build_cascade_plan_recursive(
        &self,
        table_id: TableId,
        rid: u32,
        visited: &mut HashSet<(TableId, u32)>,
        plan: &mut CascadeDeletePlan,
        depth: usize,
        parent: Option<(TableId, u32)>,
        scanner: &ReferenceScanner,
    ) -> Result<()> {
        const MAX_CASCADE_DEPTH: usize = 50;
        if depth > MAX_CASCADE_DEPTH {
            return Err(Error::ValidationReferentialIntegrity {
                message: format!(
                    "Cascade delete depth exceeded maximum of {} levels at {}:{}",
                    MAX_CASCADE_DEPTH, table_id as u32, rid
                ),
            });
        }

        if visited.contains(&(table_id, rid)) {
            return Ok(());
        }

        visited.insert((table_id, rid));
        let references = self.find_references_to_table_row(table_id, rid, scanner);

        for reference in &references {
            if self.is_critical_reference(reference) {
                return Err(Error::ValidationReferentialIntegrity {
                    message: format!(
                        "Cannot cascade delete {}:{} - referenced by critical table {}:{} in column '{}'",
                        table_id as u32, rid,
                        reference.table_id as u32, reference.row_rid, reference.column_name
                    ),
                });
            }
        }

        plan.add_deletion(table_id, rid, depth, parent, references.clone());

        for reference in &references {
            self.build_cascade_plan_recursive(
                reference.table_id,
                reference.row_rid,
                visited,
                plan,
                depth + 1,
                Some((table_id, rid)),
                scanner,
            )?;
        }

        Ok(())
    }

    /// Validates that a cascading delete operation can be performed safely.
    ///
    /// This method recursively validates that when deleting a row, all referencing rows
    /// can also be deleted without violating referential integrity constraints.
    ///
    /// # Arguments
    ///
    /// * `table_id` - The table ID of the row being deleted
    /// * `rid` - The RID of the row being deleted
    /// * `references` - All direct references to this row
    /// * `scanner` - The reference scanner to use for finding references
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the cascade delete is valid, or an error if any part
    /// of the cascade would violate referential integrity.
    fn validate_cascade_delete(
        &self,
        table_id: TableId,
        rid: u32,
        references: &[TableReference],
        scanner: &ReferenceScanner,
    ) -> Result<()> {
        let mut visited = HashSet::new();
        let mut cascade_queue = Vec::new();
        visited.insert((table_id, rid));

        for reference in references {
            if visited.contains(&(reference.table_id, reference.row_rid)) {
                continue;
            }

            self.validate_cascade_delete_recursive(
                reference.table_id,
                reference.row_rid,
                &mut visited,
                &mut cascade_queue,
                0,
                scanner,
            )?;
        }

        Ok(())
    }

    /// Recursively validates a single row in a cascade delete operation.
    ///
    /// This method validates that a specific row can be deleted as part of a cascade,
    /// and recursively validates all rows that reference it.
    ///
    /// # Arguments
    ///
    /// * `table_id` - The table ID of the row being validated
    /// * `rid` - The RID of the row being validated
    /// * `visited` - Set of already-visited rows to prevent cycles
    /// * `cascade_queue` - Queue of rows to be deleted in the cascade
    /// * `depth` - Current recursion depth for safety limits
    /// * `scanner` - The reference scanner to use for finding references
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if this row and all its cascaded deletions are valid.
    ///
    /// # Errors
    ///
    /// Returns an error if the cascade would be invalid or exceed safety limits.
    fn validate_cascade_delete_recursive(
        &self,
        table_id: TableId,
        rid: u32,
        visited: &mut HashSet<(TableId, u32)>,
        cascade_queue: &mut Vec<(TableId, u32)>,
        depth: usize,
        scanner: &ReferenceScanner,
    ) -> Result<()> {
        const MAX_CASCADE_DEPTH: usize = 50;
        if depth > MAX_CASCADE_DEPTH {
            return Err(Error::ValidationReferentialIntegrity {
                message: format!(
                    "Cascade delete depth exceeded maximum of {} levels at {}:{}",
                    MAX_CASCADE_DEPTH, table_id as u32, rid
                ),
            });
        }

        if visited.contains(&(table_id, rid)) {
            return Ok(());
        }

        visited.insert((table_id, rid));
        cascade_queue.push((table_id, rid));
        let references = scanner.find_references_to_table_row(table_id, rid);

        for reference in &references {
            if self.is_critical_reference(reference) {
                return Err(Error::ValidationReferentialIntegrity {
                    message: format!(
                        "Cannot cascade delete {}:{} - referenced by critical table {}:{} in column '{}'",
                        table_id as u32, rid,
                        reference.table_id as u32, reference.row_rid, reference.column_name
                    ),
                });
            }
        }

        for reference in &references {
            self.validate_cascade_delete_recursive(
                reference.table_id,
                reference.row_rid,
                visited,
                cascade_queue,
                depth + 1,
                scanner,
            )?;
        }

        Ok(())
    }

    /// Validates that references can be safely nullified.
    ///
    /// This method checks if all references to a row can be safely set to null
    /// without violating metadata constraints. Some references cannot be nullified
    /// because they represent essential structural relationships in the metadata.
    ///
    /// # Arguments
    ///
    /// * `table_id` - The table ID of the row being deleted
    /// * `rid` - The RID of the row being deleted
    /// * `references` - All references to this row
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if all references can be safely nullified, or an error
    /// if any reference cannot be nullified.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationReferentialIntegrity`] if any reference
    /// cannot be safely nullified due to metadata constraints.
    fn validate_nullify_references(
        &self,
        table_id: TableId,
        rid: u32,
        references: &[TableReference],
    ) -> Result<()> {
        for reference in references {
            if self.is_non_nullable_reference(reference) {
                return Err(Error::ValidationReferentialIntegrity {
                    message: format!(
                        "Cannot nullify reference from {}:{} column '{}' to {}:{} - reference is required",
                        reference.table_id as u32,
                        reference.row_rid,
                        reference.column_name,
                        table_id as u32,
                        rid
                    ),
                });
            }
        }
        Ok(())
    }

    /// Determines if a reference cannot be safely nullified.
    ///
    /// Some references in .NET metadata represent essential structural relationships
    /// that cannot be set to null without breaking the metadata integrity. This method
    /// identifies such references based on the table and column being referenced.
    ///
    /// # Arguments
    ///
    /// * `reference` - The reference to check
    ///
    /// # Returns
    ///
    /// Returns `true` if the reference cannot be safely nullified.
    fn is_non_nullable_reference(&self, reference: &TableReference) -> bool {
        match (reference.table_id, reference.column_name.as_str()) {
            (TableId::TypeDef, "Extends") => false,
            (TableId::TypeDef, "FieldList") => true,
            (TableId::TypeDef, "MethodList") => true,

            (TableId::MethodDef, "ParamList") => true,

            (TableId::Field, "Type") => true,

            (TableId::Param, "Name") => false,

            (TableId::Property, "Type") => true,
            (TableId::Event, "EventType") => true,

            (TableId::CustomAttribute, "Parent") => true,
            (TableId::CustomAttribute, "Type") => true,

            (TableId::MemberRef, "Class") => true,
            (TableId::MemberRef, "Name") => true,
            (TableId::MemberRef, "Signature") => true,

            (TableId::InterfaceImpl, "Class") => true,
            (TableId::InterfaceImpl, "Interface") => true,

            (TableId::MethodImpl, "Class") => true,
            (TableId::MethodImpl, "MethodBody") => true,
            (TableId::MethodImpl, "MethodDeclaration") => true,

            (TableId::GenericParam, "Owner") => true,
            (TableId::GenericParam, "Name") => false,
            _ => false,
        }
    }

    /// Creates a detailed error message for reference validation failures.
    ///
    /// This method analyzes the references and creates a comprehensive error message
    /// that helps users understand why the deletion failed and suggests possible
    /// resolution strategies.
    ///
    /// # Arguments
    ///
    /// * `table_id` - The table ID of the row being deleted
    /// * `rid` - The RID of the row being deleted
    /// * `references` - All references to this row
    ///
    /// # Returns
    ///
    /// A detailed error message explaining the reference validation failure.
    fn create_detailed_reference_error(
        &self,
        table_id: TableId,
        rid: u32,
        references: &[TableReference],
    ) -> String {
        let mut message = format!(
            "Cannot delete {}:{} - still referenced by {} location(s):\n",
            table_id as u32,
            rid,
            references.len()
        );

        let mut table_refs: HashMap<TableId, Vec<&TableReference>> = HashMap::new();

        for reference in references {
            table_refs
                .entry(reference.table_id)
                .or_default()
                .push(reference);
        }

        let mut sorted_tables: Vec<_> = table_refs.iter().collect();
        sorted_tables.sort_by_key(|(table_id, _)| **table_id as u32);

        for (ref_table_id, table_references) in sorted_tables {
            message.push_str(&format!("\n  From {} table:\n", *ref_table_id as u32));

            let mut column_refs: HashMap<String, Vec<&TableReference>> = HashMap::new();

            for reference in table_references {
                column_refs
                    .entry(reference.column_name.clone())
                    .or_default()
                    .push(reference);
            }

            for (column_name, column_references) in column_refs {
                if column_references.len() == 1 {
                    message.push_str(&format!(
                        "    - Row {} column '{}'\n",
                        column_references[0].row_rid, column_name
                    ));
                } else {
                    message.push_str(&format!(
                        "    - Column '{}': {} rows ({})\n",
                        column_name,
                        column_references.len(),
                        column_references
                            .iter()
                            .take(5)
                            .map(|r| r.row_rid.to_string())
                            .collect::<Vec<_>>()
                            .join(", ")
                            + if column_references.len() > 5 {
                                ", ..."
                            } else {
                                ""
                            }
                    ));
                }
            }
        }

        message.push_str("\nPossible solutions:\n");
        message.push_str(
            "  - Use ReferenceHandlingStrategy::RemoveReferences for cascading deletion\n",
        );
        message.push_str(
            "  - Use ReferenceHandlingStrategy::NullifyReferences to set references to null\n",
        );
        message.push_str("  - Manually delete or update the referencing rows first\n");

        let critical_refs: Vec<_> = references
            .iter()
            .filter(|r| self.is_critical_reference(r))
            .collect();

        if !critical_refs.is_empty() {
            message.push_str(&format!(
                "\nWarning: {} critical reference(s) detected that cannot be safely removed:\n",
                critical_refs.len()
            ));

            for critical_ref in critical_refs.iter().take(3) {
                message.push_str(&format!(
                    "  - {}:{} column '{}' (critical system reference)\n",
                    critical_ref.table_id as u32, critical_ref.row_rid, critical_ref.column_name
                ));
            }

            if critical_refs.len() > 3 {
                message.push_str(&format!(
                    "  - ... and {} more critical references\n",
                    critical_refs.len() - 3
                ));
            }
        }

        message
    }

    /// Validates all heap changes for referential integrity.
    ///
    /// This method validates that heap modifications (strings, blobs, GUIDs, user strings)
    /// don't violate referential integrity constraints. It checks that heap items being
    /// removed are not referenced by table columns.
    ///
    /// # Arguments
    ///
    /// * `changes` - The assembly changes containing heap modifications
    /// * `scanner` - The reference scanner to use for finding references
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if all heap changes maintain referential integrity.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationReferentialIntegrity`] if heap changes
    /// would violate referential integrity constraints.
    fn validate_heap_changes(
        &self,
        changes: &AssemblyChanges,
        scanner: &ReferenceScanner,
    ) -> Result<()> {
        self.validate_string_heap_changes(&changes.string_heap_changes, scanner)?;
        self.validate_blob_heap_changes(&changes.blob_heap_changes, scanner)?;
        self.validate_guid_heap_changes(&changes.guid_heap_changes, scanner)?;
        self.validate_userstring_heap_changes(&changes.userstring_heap_changes, scanner)?;
        Ok(())
    }

    /// Validates string heap changes for referential integrity.
    ///
    /// This method checks that string indices being removed are not referenced
    /// by any table columns that use string heap indices.
    ///
    /// # Arguments
    ///
    /// * `heap_changes` - The string heap changes to validate
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if string heap changes maintain referential integrity.
    fn validate_string_heap_changes(
        &self,
        heap_changes: &HeapChanges<String>,
        scanner: &ReferenceScanner,
    ) -> Result<()> {
        for &removed_index in heap_changes.removed_indices_iter() {
            let references = scanner.find_references_to_string_heap_index(removed_index);
            if !references.is_empty() {
                match heap_changes.get_removal_strategy(removed_index) {
                    Some(HeapReferenceHandlingStrategy::FailIfReferenced) => {
                        return Err(Error::ValidationReferentialIntegrity {
                            message: format!(
                                "Cannot remove string at index {} - still referenced by {} table column(s)",
                                removed_index,
                                references.len()
                            ),
                        });
                    }
                    Some(HeapReferenceHandlingStrategy::NullifyReferences) => {
                        self.validate_string_references_nullable(&references)?;
                    }
                    Some(HeapReferenceHandlingStrategy::RemoveReferences) => {
                        return Err(Error::ValidationReferentialIntegrity {
                            message:
                                "RemoveReferences strategy not supported for heap item removal"
                                    .to_string(),
                        });
                    }
                    None => {
                        return Err(Error::ValidationReferentialIntegrity {
                            message: format!(
                                "No removal strategy specified for string at index {removed_index}"
                            ),
                        });
                    }
                }
            }
        }
        Ok(())
    }

    /// Validates blob heap changes for referential integrity.
    fn validate_blob_heap_changes(
        &self,
        heap_changes: &HeapChanges<Vec<u8>>,
        scanner: &ReferenceScanner,
    ) -> Result<()> {
        for &removed_index in heap_changes.removed_indices_iter() {
            let references = scanner.find_references_to_blob_heap_index(removed_index);
            if !references.is_empty() {
                match heap_changes.get_removal_strategy(removed_index) {
                    Some(HeapReferenceHandlingStrategy::FailIfReferenced) => {
                        return Err(Error::ValidationReferentialIntegrity {
                            message: format!(
                                "Cannot remove blob at index {} - still referenced by {} table column(s)",
                                removed_index,
                                references.len()
                            ),
                        });
                    }
                    Some(HeapReferenceHandlingStrategy::NullifyReferences) => {
                        self.validate_blob_references_nullable(&references)?;
                    }
                    Some(HeapReferenceHandlingStrategy::RemoveReferences) => {
                        return Err(Error::ValidationReferentialIntegrity {
                            message:
                                "RemoveReferences strategy not supported for heap item removal"
                                    .to_string(),
                        });
                    }
                    None => {
                        return Err(Error::ValidationReferentialIntegrity {
                            message: format!(
                                "No removal strategy specified for blob at index {removed_index}"
                            ),
                        });
                    }
                }
            }
        }
        Ok(())
    }

    /// Validates GUID heap changes for referential integrity.
    fn validate_guid_heap_changes(
        &self,
        heap_changes: &crate::cilassembly::HeapChanges<[u8; 16]>,
        scanner: &ReferenceScanner,
    ) -> Result<()> {
        for &removed_index in heap_changes.removed_indices_iter() {
            let references = scanner.find_references_to_guid_heap_index(removed_index);
            if !references.is_empty() {
                match heap_changes.get_removal_strategy(removed_index) {
                    Some(HeapReferenceHandlingStrategy::FailIfReferenced) => {
                        return Err(Error::ValidationReferentialIntegrity {
                            message: format!(
                                "Cannot remove GUID at index {} - still referenced by {} table column(s)",
                                removed_index,
                                references.len()
                            ),
                        });
                    }
                    Some(HeapReferenceHandlingStrategy::NullifyReferences) => {
                        self.validate_guid_references_nullable(&references)?;
                    }
                    Some(HeapReferenceHandlingStrategy::RemoveReferences) => {
                        return Err(Error::ValidationReferentialIntegrity {
                            message:
                                "RemoveReferences strategy not supported for heap item removal"
                                    .to_string(),
                        });
                    }
                    None => {
                        return Err(Error::ValidationReferentialIntegrity {
                            message: format!(
                                "No removal strategy specified for GUID at index {removed_index}"
                            ),
                        });
                    }
                }
            }
        }
        Ok(())
    }

    /// Validates user string heap changes for referential integrity.
    fn validate_userstring_heap_changes(
        &self,
        heap_changes: &crate::cilassembly::HeapChanges<String>,
        scanner: &ReferenceScanner,
    ) -> Result<()> {
        for &removed_index in heap_changes.removed_indices_iter() {
            let references = scanner.find_references_to_userstring_heap_index(removed_index);
            if !references.is_empty() {
                match heap_changes.get_removal_strategy(removed_index) {
                    Some(HeapReferenceHandlingStrategy::FailIfReferenced) => {
                        return Err(Error::ValidationReferentialIntegrity {
                            message: format!(
                                "Cannot remove user string at index {} - still referenced by {} location(s)",
                                removed_index,
                                references.len()
                            ),
                        });
                    }
                    Some(HeapReferenceHandlingStrategy::NullifyReferences) => {
                        return Err(Error::ValidationReferentialIntegrity {
                            message: "User string references cannot be nullified - they are used by IL instructions".to_string(),
                        });
                    }
                    Some(HeapReferenceHandlingStrategy::RemoveReferences) => {
                        return Err(Error::ValidationReferentialIntegrity {
                            message:
                                "RemoveReferences strategy not supported for heap item removal"
                                    .to_string(),
                        });
                    }
                    None => {
                        return Err(Error::ValidationReferentialIntegrity {
                            message: format!(
                                "No removal strategy specified for user string at index {removed_index}"
                            ),
                        });
                    }
                }
            }
        }
        Ok(())
    }

    /// Validates that string references can be safely nullified.
    fn validate_string_references_nullable(&self, references: &[TableReference]) -> Result<()> {
        for reference in references {
            if self.is_string_reference_non_nullable(reference) {
                return Err(Error::ValidationReferentialIntegrity {
                    message: format!(
                        "Cannot nullify string reference from {}:{} column '{}' - string reference is required",
                        reference.table_id as u32,
                        reference.row_rid,
                        reference.column_name
                    ),
                });
            }
        }
        Ok(())
    }

    /// Validates that blob references can be safely nullified.
    fn validate_blob_references_nullable(&self, references: &[TableReference]) -> Result<()> {
        for reference in references {
            if self.is_blob_reference_non_nullable(reference) {
                return Err(Error::ValidationReferentialIntegrity {
                    message: format!(
                        "Cannot nullify blob reference from {}:{} column '{}' - blob reference is required",
                        reference.table_id as u32,
                        reference.row_rid,
                        reference.column_name
                    ),
                });
            }
        }
        Ok(())
    }

    /// Validates that GUID references can be safely nullified.
    fn validate_guid_references_nullable(&self, references: &[TableReference]) -> Result<()> {
        for reference in references {
            if self.is_guid_reference_non_nullable(reference) {
                return Err(Error::ValidationReferentialIntegrity {
                    message: format!(
                        "Cannot nullify GUID reference from {}:{} column '{}' - GUID reference is required",
                        reference.table_id as u32,
                        reference.row_rid,
                        reference.column_name
                    ),
                });
            }
        }
        Ok(())
    }

    /// Determines if a string reference cannot be safely nullified.
    fn is_string_reference_non_nullable(&self, reference: &TableReference) -> bool {
        match (reference.table_id, reference.column_name.as_str()) {
            (TableId::TypeDef, "Name") => true,
            (TableId::TypeDef, "Namespace") => false,
            (TableId::MethodDef, "Name") => true,
            (TableId::Field, "Name") => true,
            (TableId::Param, "Name") => false,
            (TableId::Property, "Name") => true,
            (TableId::Event, "Name") => true,
            (TableId::MemberRef, "Name") => true,
            (TableId::ModuleRef, "Name") => true,
            (TableId::AssemblyRef, "Name") => true,
            (TableId::File, "Name") => true,
            (TableId::ManifestResource, "Name") => true,
            (TableId::GenericParam, "Name") => false,
            _ => false,
        }
    }

    /// Determines if a blob reference cannot be safely nullified.
    fn is_blob_reference_non_nullable(&self, reference: &TableReference) -> bool {
        match (reference.table_id, reference.column_name.as_str()) {
            (TableId::TypeDef, "Signature") => false,
            (TableId::MethodDef, "Signature") => true,
            (TableId::Field, "Signature") => true,
            (TableId::Property, "Type") => true,
            (TableId::StandAloneSig, "Signature") => true,
            (TableId::TypeSpec, "Signature") => true,
            (TableId::MethodSpec, "Instantiation") => true,
            (TableId::MemberRef, "Signature") => true,
            (TableId::CustomAttribute, "Value") => false,
            (TableId::Constant, "Value") => true,
            (TableId::FieldMarshal, "NativeType") => true,
            (TableId::DeclSecurity, "PermissionSet") => true,
            _ => false,
        }
    }

    /// Determines if a GUID reference cannot be safely nullified.
    fn is_guid_reference_non_nullable(&self, reference: &TableReference) -> bool {
        match (reference.table_id, reference.column_name.as_str()) {
            (TableId::Module, "Mvid") => true,
            (TableId::Module, "EncId") => false,
            (TableId::Module, "EncBaseId") => false,
            _ => false,
        }
    }

    /// Determines if a reference is from a critical table that shouldn't be auto-deleted.
    ///
    /// Critical tables are those that represent fundamental assembly structure and
    /// should not be automatically deleted during cascade operations. Examples include
    /// the Module table, Assembly table, and other core metadata tables.
    ///
    /// # Arguments
    ///
    /// * `reference` - The reference to check
    ///
    /// # Returns
    ///
    /// Returns `true` if the reference is from a critical table that shouldn't be
    /// automatically deleted.
    fn is_critical_reference(&self, reference: &TableReference) -> bool {
        match reference.table_id {
            TableId::Module => true,
            TableId::Assembly => true,
            TableId::AssemblyRef => true,
            TableId::AssemblyRefProcessor => true,
            TableId::AssemblyRefOS => true,
            TableId::AssemblyProcessor => true,
            TableId::AssemblyOS => true,
            TableId::File => true,
            TableId::ManifestResource => true,
            TableId::ExportedType => true,

            TableId::ModuleRef => false,
            TableId::TypeDef => false,
            TableId::TypeRef => false,
            TableId::TypeSpec => false,
            TableId::Field => false,
            TableId::MethodDef => false,
            TableId::Param => false,
            TableId::Property => false,
            TableId::Event => false,
            TableId::MemberRef => false,
            TableId::EventMap => false,
            TableId::PropertyMap => false,
            TableId::NestedClass => false,
            TableId::ClassLayout => false,
            TableId::FieldLayout => false,
            TableId::FieldRVA => false,
            TableId::FieldPtr => false,
            TableId::MethodPtr => false,
            TableId::ParamPtr => false,
            TableId::EventPtr => false,
            TableId::PropertyPtr => false,
            TableId::CustomAttribute => false,
            TableId::DeclSecurity => false,
            TableId::FieldMarshal => false,
            TableId::InterfaceImpl => false,
            TableId::MethodImpl => false,
            TableId::MethodSemantics => false,
            TableId::ImplMap => false,
            TableId::StandAloneSig => false,
            TableId::Constant => false,
            TableId::GenericParam => false,
            TableId::GenericParamConstraint => false,
            TableId::MethodSpec => false,
            TableId::Document => false,
            TableId::MethodDebugInformation => false,
            TableId::LocalScope => false,
            TableId::LocalVariable => false,
            TableId::LocalConstant => false,
            TableId::ImportScope => false,
            TableId::StateMachineMethod => false,
            TableId::CustomDebugInformation => false,
            TableId::EncLog => false,
            TableId::EncMap => false,
        }
    }

    /// Validates cross-reference consistency after assembly modifications.
    ///
    /// This method ensures that all references between tables remain valid after
    /// modifications have been applied. It checks that:
    /// - Referenced table rows actually exist in their target tables
    /// - Coded indices point to valid table rows
    /// - Heap references point to valid heap indices
    /// - Table modifications don't create dangling references
    ///
    /// # Arguments
    ///
    /// * `changes` - The assembly changes to validate
    /// * `original` - The original assembly view for reference context
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if all cross-references are consistent, or an error
    /// describing the consistency violation.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationReferentialIntegrity`] if cross-reference
    /// consistency violations are detected.
    pub fn validate_cross_reference_consistency(
        &self,
        changes: &AssemblyChanges,
        original: &CilAssemblyView,
    ) -> Result<()> {
        let scanner = ReferenceScanner::new(original)?;

        self.validate_existing_references_consistency(changes, original, &scanner)?;
        self.validate_new_references_consistency(changes, original, &scanner)?;
        self.validate_heap_reference_consistency(changes, original, &scanner)?;

        Ok(())
    }

    /// Validates that existing references still point to valid targets after modifications.
    ///
    /// This method checks that table rows that have been deleted or modified don't
    /// break existing references from other tables.
    fn validate_existing_references_consistency(
        &self,
        changes: &AssemblyChanges,
        original: &CilAssemblyView,
        scanner: &ReferenceScanner,
    ) -> Result<()> {
        for (table_id, table_modifications) in &changes.table_changes {
            match table_modifications {
                TableModifications::Sparse { operations, .. } => {
                    for operation in operations {
                        match &operation.operation {
                            Operation::Delete(rid) => {
                                let references =
                                    scanner.find_references_to_table_row(*table_id, *rid);
                                if !references.is_empty()
                                    && self.default_strategy
                                        == ReferenceHandlingStrategy::FailIfReferenced
                                {
                                    return Err(Error::ValidationReferentialIntegrity {
                                        message: format!(
                                            "Cannot delete {}:{} - still referenced by {} location(s)",
                                            *table_id as u32, rid, references.len()
                                        ),
                                    });
                                }
                            }
                            Operation::Update(rid, row_data) => {
                                self.validate_row_data_references(
                                    *table_id, *rid, row_data, original,
                                )?;
                            }
                            Operation::Insert(rid, row_data) => {
                                self.validate_row_data_references(
                                    *table_id, *rid, row_data, original,
                                )?;
                            }
                        }
                    }
                }
                TableModifications::Replaced(new_rows) => {
                    for (index, row_data) in new_rows.iter().enumerate() {
                        let rid = index as u32 + 1;
                        self.validate_row_data_references(*table_id, rid, row_data, original)?;
                    }
                }
            }
        }

        Ok(())
    }

    /// Validates that new references in added/modified rows are valid.
    ///
    /// This method checks that any new references created by insert or update
    /// operations point to valid target rows.
    fn validate_new_references_consistency(
        &self,
        changes: &AssemblyChanges,
        original: &CilAssemblyView,
        _scanner: &ReferenceScanner,
    ) -> Result<()> {
        for (table_id, table_modifications) in &changes.table_changes {
            match table_modifications {
                TableModifications::Sparse { operations, .. } => {
                    for operation in operations {
                        match &operation.operation {
                            Operation::Insert(rid, row_data) => {
                                self.validate_row_data_references(
                                    *table_id, *rid, row_data, original,
                                )?;
                            }
                            Operation::Update(rid, row_data) => {
                                self.validate_row_data_references(
                                    *table_id, *rid, row_data, original,
                                )?;
                            }
                            Operation::Delete(_) => {}
                        }
                    }
                }
                TableModifications::Replaced(new_rows) => {
                    for (index, row_data) in new_rows.iter().enumerate() {
                        let rid = index as u32 + 1;
                        self.validate_row_data_references(*table_id, rid, row_data, original)?;
                    }
                }
            }
        }

        Ok(())
    }

    /// Validates heap reference consistency after modifications.
    ///
    /// This method checks that heap references remain valid after heap modifications.
    fn validate_heap_reference_consistency(
        &self,
        changes: &AssemblyChanges,
        original: &CilAssemblyView,
        scanner: &ReferenceScanner,
    ) -> Result<()> {
        self.validate_string_heap_consistency(&changes.string_heap_changes, original, scanner)?;
        self.validate_blob_heap_consistency(&changes.blob_heap_changes, original, scanner)?;
        self.validate_guid_heap_consistency(&changes.guid_heap_changes, original, scanner)?;
        self.validate_userstring_heap_consistency(
            &changes.userstring_heap_changes,
            original,
            scanner,
        )?;

        Ok(())
    }

    /// Validates string heap consistency.
    fn validate_string_heap_consistency(
        &self,
        heap_changes: &crate::cilassembly::HeapChanges<String>,
        _original: &CilAssemblyView,
        _scanner: &ReferenceScanner,
    ) -> Result<()> {
        for &removed_index in heap_changes.removed_indices_iter() {
            if removed_index == 0 {
                return Err(Error::ValidationReferentialIntegrity {
                    message:
                        "Cannot remove string at index 0 - this is the null string and is required"
                            .to_string(),
                });
            }
        }

        for (index, _modified_string) in heap_changes.modified_items_iter() {
            if *index == 0 {
                return Err(Error::ValidationReferentialIntegrity {
                    message: "Cannot modify string at index 0 - this is the null string and must remain empty".to_string(),
                });
            }
        }

        Ok(())
    }

    /// Validates blob heap consistency.
    fn validate_blob_heap_consistency(
        &self,
        heap_changes: &HeapChanges<Vec<u8>>,
        _original: &CilAssemblyView,
        _scanner: &ReferenceScanner,
    ) -> Result<()> {
        for &removed_index in heap_changes.removed_indices_iter() {
            if removed_index == 0 {
                return Err(Error::ValidationReferentialIntegrity {
                    message:
                        "Cannot remove blob at index 0 - this is the null blob and is required"
                            .to_string(),
                });
            }
        }

        for (index, _modified_blob) in heap_changes.modified_items_iter() {
            if *index == 0 {
                return Err(Error::ValidationReferentialIntegrity {
                    message: "Cannot modify blob at index 0 - this is the null blob and must remain empty".to_string(),
                });
            }
        }

        Ok(())
    }

    /// Validates GUID heap consistency.
    fn validate_guid_heap_consistency(
        &self,
        heap_changes: &HeapChanges<[u8; 16]>,
        _original: &CilAssemblyView,
        _scanner: &ReferenceScanner,
    ) -> Result<()> {
        for &removed_index in heap_changes.removed_indices_iter() {
            if removed_index == 0 {
                return Err(Error::ValidationReferentialIntegrity {
                    message:
                        "Cannot remove GUID at index 0 - this is the null GUID and is required"
                            .to_string(),
                });
            }
        }

        for (index, _modified_guid) in heap_changes.modified_items_iter() {
            if *index == 0 {
                return Err(Error::ValidationReferentialIntegrity {
                    message: "Cannot modify GUID at index 0 - this is the null GUID and must remain zeros".to_string(),
                });
            }
        }

        Ok(())
    }

    /// Validates user string heap consistency.
    fn validate_userstring_heap_consistency(
        &self,
        heap_changes: &HeapChanges<String>,
        _original: &CilAssemblyView,
        _scanner: &ReferenceScanner,
    ) -> Result<()> {
        for (new_index, _) in heap_changes.items_with_indices() {
            if new_index == 0 {
                return Err(Error::ValidationReferentialIntegrity {
                    message:
                        "User string heap index 0 is reserved and cannot be used for new strings"
                            .to_string(),
                });
            }
        }

        for &removed_index in heap_changes.removed_indices_iter() {
            if removed_index == 0 {
                return Err(Error::ValidationReferentialIntegrity {
                    message:
                        "Cannot remove user string heap index 0 - it may be referenced by IL code"
                            .to_string(),
                });
            }
        }

        Ok(())
    }

    /// Validates all references in a row's data.
    ///
    /// This method examines the row data to ensure all references point to valid targets
    /// in the assembly metadata. It validates coded indices, string/blob heap references,
    /// and direct table references based on the table type.
    fn validate_row_data_references(
        &self,
        table_id: TableId,
        rid: u32,
        row_data: &TableDataOwned,
        original: &CilAssemblyView,
    ) -> Result<()> {
        if rid == 0 {
            return Err(Error::ValidationReferentialIntegrity {
                message: format!(
                    "Invalid RID 0 for row in table {table_id:?} - RIDs must start at 1"
                ),
            });
        }

        let Some(tables) = original.tables() else {
            return Err(Error::ValidationReferentialIntegrity {
                message: "Assembly has no metadata tables".to_string(),
            });
        };

        match (table_id, row_data) {
            (TableId::Module, TableDataOwned::Module(row)) => {
                self.validate_string_heap_reference(row.name, original, "name", table_id, rid)?;
                self.validate_guid_heap_reference(row.mvid, original, "mvid", table_id, rid)?;
                self.validate_guid_heap_reference(row.encid, original, "encid", table_id, rid)?;
                self.validate_guid_heap_reference(
                    row.encbaseid,
                    original,
                    "encbaseid",
                    table_id,
                    rid,
                )?;
            }
            (TableId::TypeRef, TableDataOwned::TypeRef(row)) => {
                self.validate_coded_index_reference(
                    &row.resolution_scope,
                    tables,
                    "resolution_scope",
                    table_id,
                    rid,
                )?;
                self.validate_string_heap_reference(
                    row.type_name,
                    original,
                    "type_name",
                    table_id,
                    rid,
                )?;
                self.validate_string_heap_reference(
                    row.type_namespace,
                    original,
                    "type_namespace",
                    table_id,
                    rid,
                )?;
            }
            (TableId::TypeDef, TableDataOwned::TypeDef(row)) => {
                self.validate_coded_index_reference(
                    &row.extends,
                    tables,
                    "extends",
                    table_id,
                    rid,
                )?;
                self.validate_string_heap_reference(
                    row.type_name,
                    original,
                    "type_name",
                    table_id,
                    rid,
                )?;
                self.validate_string_heap_reference(
                    row.type_namespace,
                    original,
                    "type_namespace",
                    table_id,
                    rid,
                )?;
                self.validate_table_reference(
                    row.field_list,
                    tables,
                    "field_list",
                    table_id,
                    rid,
                    TableId::Field,
                )?;
                self.validate_table_reference(
                    row.method_list,
                    tables,
                    "method_list",
                    table_id,
                    rid,
                    TableId::MethodDef,
                )?;
            }
            (TableId::FieldPtr, TableDataOwned::FieldPtr(row)) => {
                self.validate_table_reference(
                    row.field,
                    tables,
                    "field",
                    table_id,
                    rid,
                    TableId::Field,
                )?;
            }
            (TableId::Field, TableDataOwned::Field(row)) => {
                self.validate_string_heap_reference(row.name, original, "name", table_id, rid)?;
                self.validate_blob_heap_reference(
                    row.signature,
                    original,
                    "signature",
                    table_id,
                    rid,
                )?;
            }
            (TableId::MethodPtr, TableDataOwned::MethodPtr(row)) => {
                self.validate_table_reference(
                    row.method,
                    tables,
                    "method",
                    table_id,
                    rid,
                    TableId::MethodDef,
                )?;
            }
            (TableId::MethodDef, TableDataOwned::MethodDef(row)) => {
                self.validate_string_heap_reference(row.name, original, "name", table_id, rid)?;
                self.validate_blob_heap_reference(
                    row.signature,
                    original,
                    "signature",
                    table_id,
                    rid,
                )?;
                self.validate_table_reference(
                    row.param_list,
                    tables,
                    "param_list",
                    table_id,
                    rid,
                    TableId::Param,
                )?;
            }
            (TableId::ParamPtr, TableDataOwned::ParamPtr(row)) => {
                self.validate_table_reference(
                    row.param,
                    tables,
                    "param",
                    table_id,
                    rid,
                    TableId::Param,
                )?;
            }
            (TableId::Param, TableDataOwned::Param(row)) => {
                self.validate_string_heap_reference(row.name, original, "name", table_id, rid)?;
            }
            (TableId::InterfaceImpl, TableDataOwned::InterfaceImpl(row)) => {
                self.validate_table_reference(
                    row.class,
                    tables,
                    "class",
                    table_id,
                    rid,
                    TableId::TypeDef,
                )?;
                self.validate_coded_index_reference(
                    &row.interface,
                    tables,
                    "interface",
                    table_id,
                    rid,
                )?;
            }

            (TableId::MemberRef, TableDataOwned::MemberRef(row)) => {
                self.validate_coded_index_reference(&row.class, tables, "class", table_id, rid)?;
                self.validate_string_heap_reference(row.name, original, "name", table_id, rid)?;
                self.validate_blob_heap_reference(
                    row.signature,
                    original,
                    "signature",
                    table_id,
                    rid,
                )?;
            }
            (TableId::Constant, TableDataOwned::Constant(row)) => {
                self.validate_coded_index_reference(&row.parent, tables, "parent", table_id, rid)?;
                self.validate_blob_heap_reference(row.value, original, "value", table_id, rid)?;
            }
            (TableId::CustomAttribute, TableDataOwned::CustomAttribute(row)) => {
                self.validate_coded_index_reference(&row.parent, tables, "parent", table_id, rid)?;
                self.validate_coded_index_reference(
                    &row.constructor,
                    tables,
                    "constructor",
                    table_id,
                    rid,
                )?;
                self.validate_blob_heap_reference(row.value, original, "value", table_id, rid)?;
            }
            (TableId::FieldMarshal, TableDataOwned::FieldMarshal(row)) => {
                self.validate_coded_index_reference(&row.parent, tables, "parent", table_id, rid)?;
                self.validate_blob_heap_reference(
                    row.native_type,
                    original,
                    "native_type",
                    table_id,
                    rid,
                )?;
            }
            (TableId::DeclSecurity, TableDataOwned::DeclSecurity(row)) => {
                self.validate_coded_index_reference(&row.parent, tables, "parent", table_id, rid)?;
                self.validate_blob_heap_reference(
                    row.permission_set,
                    original,
                    "permission_set",
                    table_id,
                    rid,
                )?;
            }

            (TableId::ClassLayout, TableDataOwned::ClassLayout(row)) => {
                self.validate_table_reference(
                    row.parent,
                    tables,
                    "parent",
                    table_id,
                    rid,
                    TableId::TypeDef,
                )?;
            }
            (TableId::FieldLayout, TableDataOwned::FieldLayout(row)) => {
                self.validate_table_reference(
                    row.field,
                    tables,
                    "field",
                    table_id,
                    rid,
                    TableId::Field,
                )?;
            }
            (TableId::StandAloneSig, TableDataOwned::StandAloneSig(row)) => {
                self.validate_blob_heap_reference(
                    row.signature,
                    original,
                    "signature",
                    table_id,
                    rid,
                )?;
            }

            (TableId::EventMap, TableDataOwned::EventMap(row)) => {
                self.validate_table_reference(
                    row.parent,
                    tables,
                    "parent",
                    table_id,
                    rid,
                    TableId::TypeDef,
                )?;
                self.validate_table_reference(
                    row.event_list,
                    tables,
                    "event_list",
                    table_id,
                    rid,
                    TableId::Event,
                )?;
            }
            (TableId::EventPtr, TableDataOwned::EventPtr(row)) => {
                self.validate_table_reference(
                    row.event,
                    tables,
                    "event",
                    table_id,
                    rid,
                    TableId::Event,
                )?;
            }
            (TableId::Event, TableDataOwned::Event(row)) => {
                self.validate_string_heap_reference(row.name, original, "name", table_id, rid)?;
                self.validate_coded_index_reference(
                    &row.event_type,
                    tables,
                    "event_type",
                    table_id,
                    rid,
                )?;
            }
            (TableId::PropertyMap, TableDataOwned::PropertyMap(row)) => {
                self.validate_table_reference(
                    row.parent,
                    tables,
                    "parent",
                    table_id,
                    rid,
                    TableId::TypeDef,
                )?;
                self.validate_table_reference(
                    row.property_list,
                    tables,
                    "property_list",
                    table_id,
                    rid,
                    TableId::Property,
                )?;
            }
            (TableId::PropertyPtr, TableDataOwned::PropertyPtr(row)) => {
                self.validate_table_reference(
                    row.property,
                    tables,
                    "property",
                    table_id,
                    rid,
                    TableId::Property,
                )?;
            }
            (TableId::Property, TableDataOwned::Property(row)) => {
                self.validate_string_heap_reference(row.name, original, "name", table_id, rid)?;
                self.validate_blob_heap_reference(
                    row.signature,
                    original,
                    "signature",
                    table_id,
                    rid,
                )?;
            }

            (TableId::MethodSemantics, TableDataOwned::MethodSemantics(row)) => {
                self.validate_table_reference(
                    row.method,
                    tables,
                    "method",
                    table_id,
                    rid,
                    TableId::MethodDef,
                )?;
                self.validate_coded_index_reference(
                    &row.association,
                    tables,
                    "association",
                    table_id,
                    rid,
                )?;
            }
            (TableId::MethodImpl, TableDataOwned::MethodImpl(row)) => {
                self.validate_table_reference(
                    row.class,
                    tables,
                    "class",
                    table_id,
                    rid,
                    TableId::TypeDef,
                )?;
                self.validate_coded_index_reference(
                    &row.method_body,
                    tables,
                    "method_body",
                    table_id,
                    rid,
                )?;
                self.validate_coded_index_reference(
                    &row.method_declaration,
                    tables,
                    "method_declaration",
                    table_id,
                    rid,
                )?;
            }
            (TableId::ModuleRef, TableDataOwned::ModuleRef(row)) => {
                self.validate_string_heap_reference(row.name, original, "name", table_id, rid)?;
            }
            (TableId::TypeSpec, TableDataOwned::TypeSpec(row)) => {
                self.validate_blob_heap_reference(
                    row.signature,
                    original,
                    "signature",
                    table_id,
                    rid,
                )?;
            }
            (TableId::ImplMap, TableDataOwned::ImplMap(row)) => {
                self.validate_coded_index_reference(
                    &row.member_forwarded,
                    tables,
                    "member_forwarded",
                    table_id,
                    rid,
                )?;
                self.validate_string_heap_reference(
                    row.import_name,
                    original,
                    "import_name",
                    table_id,
                    rid,
                )?;
                self.validate_table_reference(
                    row.import_scope,
                    tables,
                    "import_scope",
                    table_id,
                    rid,
                    TableId::ModuleRef,
                )?;
            }

            (TableId::FieldRVA, TableDataOwned::FieldRVA(row)) => {
                self.validate_table_reference(
                    row.field,
                    tables,
                    "field",
                    table_id,
                    rid,
                    TableId::Field,
                )?;
            }
            (TableId::Assembly, TableDataOwned::Assembly(row)) => {
                self.validate_blob_heap_reference(
                    row.public_key,
                    original,
                    "public_key",
                    table_id,
                    rid,
                )?;
                self.validate_string_heap_reference(row.name, original, "name", table_id, rid)?;
                self.validate_string_heap_reference(
                    row.culture,
                    original,
                    "culture",
                    table_id,
                    rid,
                )?;
            }
            (TableId::AssemblyRef, TableDataOwned::AssemblyRef(row)) => {
                self.validate_blob_heap_reference(
                    row.public_key_or_token,
                    original,
                    "public_key_or_token",
                    table_id,
                    rid,
                )?;
                self.validate_string_heap_reference(row.name, original, "name", table_id, rid)?;
                self.validate_string_heap_reference(
                    row.culture,
                    original,
                    "culture",
                    table_id,
                    rid,
                )?;
                self.validate_blob_heap_reference(
                    row.hash_value,
                    original,
                    "hash_value",
                    table_id,
                    rid,
                )?;
            }
            (TableId::File, TableDataOwned::File(row)) => {
                self.validate_string_heap_reference(row.name, original, "name", table_id, rid)?;
                self.validate_blob_heap_reference(
                    row.hash_value,
                    original,
                    "hash_value",
                    table_id,
                    rid,
                )?;
            }

            (TableId::ExportedType, TableDataOwned::ExportedType(row)) => {
                self.validate_string_heap_reference(row.name, original, "name", table_id, rid)?;
                self.validate_string_heap_reference(
                    row.namespace,
                    original,
                    "namespace",
                    table_id,
                    rid,
                )?;
                self.validate_coded_index_reference(
                    &row.implementation,
                    tables,
                    "implementation",
                    table_id,
                    rid,
                )?;
            }
            (TableId::ManifestResource, TableDataOwned::ManifestResource(row)) => {
                self.validate_string_heap_reference(row.name, original, "name", table_id, rid)?;
                self.validate_coded_index_reference(
                    &row.implementation,
                    tables,
                    "implementation",
                    table_id,
                    rid,
                )?;
            }
            (TableId::NestedClass, TableDataOwned::NestedClass(row)) => {
                self.validate_table_reference(
                    row.nested_class,
                    tables,
                    "nested_class",
                    table_id,
                    rid,
                    TableId::TypeDef,
                )?;
                self.validate_table_reference(
                    row.enclosing_class,
                    tables,
                    "enclosing_class",
                    table_id,
                    rid,
                    TableId::TypeDef,
                )?;
            }

            (TableId::GenericParam, TableDataOwned::GenericParam(row)) => {
                self.validate_coded_index_reference(&row.owner, tables, "owner", table_id, rid)?;
                self.validate_string_heap_reference(row.name, original, "name", table_id, rid)?;
            }
            (TableId::MethodSpec, TableDataOwned::MethodSpec(row)) => {
                self.validate_coded_index_reference(&row.method, tables, "method", table_id, rid)?;
                self.validate_blob_heap_reference(
                    row.instantiation,
                    original,
                    "instantiation",
                    table_id,
                    rid,
                )?;
            }
            (TableId::GenericParamConstraint, TableDataOwned::GenericParamConstraint(row)) => {
                self.validate_table_reference(
                    row.owner,
                    tables,
                    "owner",
                    table_id,
                    rid,
                    TableId::GenericParam,
                )?;
                self.validate_coded_index_reference(
                    &row.constraint,
                    tables,
                    "constraint",
                    table_id,
                    rid,
                )?;
            }

            (TableId::Document, TableDataOwned::Document(row)) => {
                self.validate_blob_heap_reference(row.name, original, "name", table_id, rid)?;
                self.validate_guid_heap_reference(
                    row.language,
                    original,
                    "language",
                    table_id,
                    rid,
                )?;
                self.validate_guid_heap_reference(
                    row.hash_algorithm,
                    original,
                    "hash_algorithm",
                    table_id,
                    rid,
                )?;
                self.validate_blob_heap_reference(row.hash, original, "hash", table_id, rid)?;
            }
            (TableId::MethodDebugInformation, TableDataOwned::MethodDebugInformation(row)) => {
                self.validate_table_reference(
                    row.document,
                    tables,
                    "document",
                    table_id,
                    rid,
                    TableId::Document,
                )?;
                self.validate_blob_heap_reference(
                    row.sequence_points,
                    original,
                    "sequence_points",
                    table_id,
                    rid,
                )?;
            }
            (TableId::LocalScope, TableDataOwned::LocalScope(row)) => {
                self.validate_table_reference(
                    row.method,
                    tables,
                    "method",
                    table_id,
                    rid,
                    TableId::MethodDef,
                )?;
                self.validate_table_reference(
                    row.import_scope,
                    tables,
                    "import_scope",
                    table_id,
                    rid,
                    TableId::ImportScope,
                )?;
                self.validate_table_reference(
                    row.variable_list,
                    tables,
                    "variable_list",
                    table_id,
                    rid,
                    TableId::LocalVariable,
                )?;
                self.validate_table_reference(
                    row.constant_list,
                    tables,
                    "constant_list",
                    table_id,
                    rid,
                    TableId::LocalConstant,
                )?;
            }
            (TableId::LocalVariable, TableDataOwned::LocalVariable(row)) => {
                self.validate_string_heap_reference(row.name, original, "name", table_id, rid)?;
            }
            (TableId::LocalConstant, TableDataOwned::LocalConstant(row)) => {
                self.validate_string_heap_reference(row.name, original, "name", table_id, rid)?;
                self.validate_blob_heap_reference(
                    row.signature,
                    original,
                    "signature",
                    table_id,
                    rid,
                )?;
            }
            (TableId::ImportScope, TableDataOwned::ImportScope(row)) => {
                self.validate_table_reference(
                    row.parent,
                    tables,
                    "parent",
                    table_id,
                    rid,
                    TableId::ImportScope,
                )?;
                self.validate_blob_heap_reference(row.imports, original, "imports", table_id, rid)?;
            }
            (TableId::StateMachineMethod, TableDataOwned::StateMachineMethod(row)) => {
                self.validate_table_reference(
                    row.move_next_method,
                    tables,
                    "move_next_method",
                    table_id,
                    rid,
                    TableId::MethodDef,
                )?;
                self.validate_table_reference(
                    row.kickoff_method,
                    tables,
                    "kickoff_method",
                    table_id,
                    rid,
                    TableId::MethodDef,
                )?;
            }
            (TableId::CustomDebugInformation, TableDataOwned::CustomDebugInformation(row)) => {
                self.validate_coded_index_reference(&row.parent, tables, "parent", table_id, rid)?;
                self.validate_guid_heap_reference(row.kind, original, "kind", table_id, rid)?;
                self.validate_blob_heap_reference(row.value, original, "value", table_id, rid)?;
            }

            //(TableId::AssemblyProcessor, TableDataOwned::AssemblyProcessor(_)) => {}
            //(TableId::AssemblyOS, TableDataOwned::AssemblyOS(_)) => {}
            //(TableId::AssemblyRefProcessor, TableDataOwned::AssemblyRefProcessor(_)) => {}
            //(TableId::AssemblyRefOS, TableDataOwned::AssemblyRefOS(_)) => {}
            //(TableId::EncLog, TableDataOwned::EncLog(_)) => {}
            //(TableId::EncMap, TableDataOwned::EncMap(_)) => {}
            _ => {}
        }

        Ok(())
    }

    /// Validates a coded index reference.
    fn validate_coded_index_reference(
        &self,
        coded_index: &CodedIndex,
        tables: &TablesHeader,
        field_name: &str,
        table_id: TableId,
        rid: u32,
    ) -> Result<()> {
        if coded_index.row == 0 {
            return Ok(());
        }
        let target_table_exists = match coded_index.tag {
            TableId::Module => tables.table_row_count(TableId::Module) >= coded_index.row,
            TableId::TypeRef => tables.table_row_count(TableId::TypeRef) >= coded_index.row,
            TableId::TypeDef => tables.table_row_count(TableId::TypeDef) >= coded_index.row,
            TableId::Field => tables.table_row_count(TableId::Field) >= coded_index.row,
            TableId::MethodDef => tables.table_row_count(TableId::MethodDef) >= coded_index.row,
            TableId::Param => tables.table_row_count(TableId::Param) >= coded_index.row,
            TableId::InterfaceImpl => {
                tables.table_row_count(TableId::InterfaceImpl) >= coded_index.row
            }
            TableId::MemberRef => tables.table_row_count(TableId::MemberRef) >= coded_index.row,
            TableId::Constant => tables.table_row_count(TableId::Constant) >= coded_index.row,
            TableId::CustomAttribute => {
                tables.table_row_count(TableId::CustomAttribute) >= coded_index.row
            }
            TableId::DeclSecurity => {
                tables.table_row_count(TableId::DeclSecurity) >= coded_index.row
            }
            TableId::Property => tables.table_row_count(TableId::Property) >= coded_index.row,
            TableId::Event => tables.table_row_count(TableId::Event) >= coded_index.row,
            TableId::StandAloneSig => {
                tables.table_row_count(TableId::StandAloneSig) >= coded_index.row
            }
            TableId::ModuleRef => tables.table_row_count(TableId::ModuleRef) >= coded_index.row,
            TableId::TypeSpec => tables.table_row_count(TableId::TypeSpec) >= coded_index.row,
            TableId::Assembly => tables.table_row_count(TableId::Assembly) >= coded_index.row,
            TableId::AssemblyRef => tables.table_row_count(TableId::AssemblyRef) >= coded_index.row,
            TableId::File => tables.table_row_count(TableId::File) >= coded_index.row,
            TableId::ExportedType => {
                tables.table_row_count(TableId::ExportedType) >= coded_index.row
            }
            TableId::ManifestResource => {
                tables.table_row_count(TableId::ManifestResource) >= coded_index.row
            }
            TableId::GenericParam => {
                tables.table_row_count(TableId::GenericParam) >= coded_index.row
            }
            TableId::MethodSpec => tables.table_row_count(TableId::MethodSpec) >= coded_index.row,
            TableId::GenericParamConstraint => {
                tables.table_row_count(TableId::GenericParamConstraint) >= coded_index.row
            }
            _ => false,
        };

        if !target_table_exists {
            return Err(Error::ValidationReferentialIntegrity {
                message: format!(
                    "Table {:?} row {} field '{}' references non-existent {:?} row {}",
                    table_id, rid, field_name, coded_index.tag, coded_index.row
                ),
            });
        }

        Ok(())
    }

    /// Validates a string heap reference.
    fn validate_string_heap_reference(
        &self,
        index: u32,
        original: &CilAssemblyView,
        field_name: &str,
        table_id: TableId,
        rid: u32,
    ) -> Result<()> {
        if index == 0 {
            return Ok(());
        }
        if let Some(strings) = original.strings() {
            if strings.get(index as usize).is_err() {
                return Err(Error::ValidationReferentialIntegrity {
                    message: format!(
                        "Table {table_id:?} row {rid} field '{field_name}' references non-existent string heap index {index}"
                    ),
                });
            }
        } else {
            return Err(Error::ValidationReferentialIntegrity {
                message: format!(
                    "Table {table_id:?} row {rid} field '{field_name}' references string heap but no string heap is present"
                ),
            });
        }

        Ok(())
    }

    /// Validates a blob heap reference.
    fn validate_blob_heap_reference(
        &self,
        index: u32,
        original: &CilAssemblyView,
        field_name: &str,
        table_id: TableId,
        rid: u32,
    ) -> Result<()> {
        if index == 0 {
            return Ok(());
        }
        if let Some(blobs) = original.blobs() {
            if blobs.get(index as usize).is_err() {
                return Err(Error::ValidationReferentialIntegrity {
                    message: format!(
                        "Table {table_id:?} row {rid} field '{field_name}' references non-existent blob heap index {index}"
                    ),
                });
            }
        } else {
            return Err(Error::ValidationReferentialIntegrity {
                message: format!(
                    "Table {table_id:?} row {rid} field '{field_name}' references blob heap but no blob heap is present"
                ),
            });
        }

        Ok(())
    }

    /// Validates a direct table reference.
    fn validate_table_reference(
        &self,
        reference_rid: u32,
        tables: &crate::metadata::streams::TablesHeader,
        field_name: &str,
        table_id: TableId,
        rid: u32,
        target_table: TableId,
    ) -> Result<()> {
        if reference_rid == 0 {
            return Ok(());
        }
        let target_table_exists = tables.table_row_count(target_table) >= reference_rid;

        if !target_table_exists {
            return Err(Error::ValidationReferentialIntegrity {
                message: format!(
                    "Table {table_id:?} row {rid} field '{field_name}' references non-existent {target_table:?} row {reference_rid}"
                ),
            });
        }

        Ok(())
    }

    /// Validates a GUID heap reference.
    fn validate_guid_heap_reference(
        &self,
        index: u32,
        original: &CilAssemblyView,
        field_name: &str,
        table_id: TableId,
        rid: u32,
    ) -> Result<()> {
        if index == 0 {
            return Ok(());
        }
        if let Some(guids) = original.guids() {
            if guids.get(index as usize).is_err() {
                return Err(Error::ValidationReferentialIntegrity {
                    message: format!(
                        "Table {table_id:?} row {rid} field '{field_name}' references non-existent GUID heap index {index}"
                    ),
                });
            }
        } else {
            return Err(Error::ValidationReferentialIntegrity {
                message: format!(
                    "Table {table_id:?} row {rid} field '{field_name}' references GUID heap but no GUID heap is present"
                ),
            });
        }

        Ok(())
    }
}

impl ValidationStage for ReferentialIntegrityValidator {
    fn validate(
        &self,
        changes: &AssemblyChanges,
        original: &CilAssemblyView,
        scanner: Option<&ReferenceScanner>,
    ) -> Result<()> {
        if let Some(scanner) = scanner {
            self.validate_with_cached_scanner(changes, original, scanner)
        } else {
            self.validate_delete_operations(changes, original)?;
            self.validate_cross_reference_consistency(changes, original)?;
            Ok(())
        }
    }

    fn name(&self) -> &'static str {
        "Referential Integrity Validation"
    }
}
