//! Conflict resolution strategies for assembly modification operations.
//!
//! This module provides conflict resolution strategies for handling conflicting operations
//! during assembly modification. When multiple operations target the same metadata
//! element, resolvers determine which operation should take precedence.
//!
//! # Key Components
//!
//! - [`LastWriteWinsResolver`] - Default conflict resolver using timestamp ordering
//! - [`ConflictResolver`] - Trait for implementing custom resolution strategies
//! - [`Conflict`] - Types of conflicts that can occur during modification
//! - [`Resolution`] - Conflict resolution results
//!
//! # Architecture
//!
//! The conflict resolution system is built around pluggable strategies that can be
//! configured based on application requirements:
//!
//! ## Timestamp-Based Resolution
//! The default [`LastWriteWinsResolver`] uses operation timestamps to determine
//! precedence, with later operations overriding earlier ones.
//!
//! ## Extensible Design
//! The [`ConflictResolver`] trait allows custom resolution strategies
//! to be implemented for specific use cases.
//!
//! # Usage Examples
//!
//! ```rust,ignore
//! use crate::cilassembly::resolver::{LastWriteWinsResolver, ConflictResolver, Conflict};
//!
//! // Create a resolver
//! let resolver = LastWriteWinsResolver;
//!
//! // Resolve conflicts (typically used by validation pipeline)
//! // let conflicts = vec![/* conflicts */];
//! // let resolution = resolver.resolve_conflict(&conflicts)?;
//! # Ok::<(), crate::Error>(())
//! ```
//!
//! # Thread Safety
//!
//! This type is [`Send`] and [`Sync`] as it contains no mutable state and operates
//! purely on the input data.

use crate::{cilassembly::TableOperation, Result};
use std::collections::HashMap;

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
/// use crate::cilassembly::resolver::{ConflictResolver, Conflict, Resolution};
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
    /// use crate::cilassembly::resolver::{ConflictResolver, Conflict};
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

/// Types of conflicts that can occur during modification.
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

/// Default last-write-wins conflict resolver.
///
/// [`LastWriteWinsResolver`] implements a simple conflict resolution strategy that uses
/// operation timestamps to determine precedence. When multiple operations target the same
/// metadata element, the operation with the latest timestamp takes precedence.
///
/// This resolver handles two types of conflicts:
/// - **Multiple Operations on RID**: When several operations target the same table row
/// - **Insert/Delete Conflicts**: When both insert and delete operations target the same RID
///
/// # Usage Examples
///
/// ```rust,ignore
/// use crate::cilassembly::resolver::{LastWriteWinsResolver, ConflictResolver, Conflict};
///
/// let resolver = LastWriteWinsResolver;
///
/// // Typically used by validation pipeline
/// // let conflicts = vec![/* detected conflicts */];
/// // let resolution = resolver.resolve_conflict(&conflicts)?;
/// # Ok::<(), crate::Error>(())
/// ```
///
/// # Thread Safety
///
/// This type is [`Send`] and [`Sync`] as it contains no state and operates purely on
/// the input data provided to the resolution methods.
pub struct LastWriteWinsResolver;

impl ConflictResolver for LastWriteWinsResolver {
    /// Resolves conflicts using last-write-wins strategy.
    ///
    /// This method processes an array of conflicts and determines the winning operation
    /// for each conflicted RID based on timestamp ordering. For each conflict, the
    /// operation with the latest timestamp is selected as the winner.
    ///
    /// # Arguments
    ///
    /// * `conflicts` - Array of [`Conflict`] instances to resolve
    ///
    /// # Returns
    ///
    /// Returns a [`Resolution`] containing the winning operation
    /// for each conflicted RID.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] if resolution processing fails, though this implementation
    /// is designed to always succeed with valid input.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{cilassembly::Operation, test::factories::table::cilassembly::create_test_row};

    #[test]
    fn test_last_write_wins_resolver_multiple_operations() {
        let operations = vec![
            {
                let mut op = TableOperation::new(Operation::Insert(100, create_test_row()));
                op.timestamp = 1000; // Microseconds since epoch
                op
            },
            {
                let mut op = TableOperation::new(Operation::Update(100, create_test_row()));
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
                assert!(
                    matches!(op.operation, Operation::Delete(100)),
                    "Should use Delete operation"
                );
            } else {
                panic!("Expected UseOperation resolution");
            }
        }
    }
}
