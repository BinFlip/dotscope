//! Conflict resolution strategies for validation pipeline.
//!
//! This module provides conflict resolution strategies for handling conflicting operations
//! during the validation pipeline. When multiple operations target the same metadata
//! element, resolvers determine which operation should take precedence.
//!
//! # Key Components
//!
//! - [`crate::cilassembly::validation::resolver::LastWriteWinsResolver`] - Default conflict resolver using timestamp ordering
//!
//! # Architecture
//!
//! The conflict resolution system is built around pluggable strategies that can be
//! configured based on application requirements:
//!
//! ## Timestamp-Based Resolution
//! The default [`crate::cilassembly::validation::resolver::LastWriteWinsResolver`] uses operation timestamps to determine
//! precedence, with later operations overriding earlier ones.
//!
//! ## Extensible Design
//! The [`crate::cilassembly::validation::ConflictResolver`] trait allows custom resolution strategies
//! to be implemented for specific use cases.
//!
//! # Usage Examples
//!
//! ```rust,ignore
//! use crate::cilassembly::validation::resolver::LastWriteWinsResolver;
//! use crate::cilassembly::validation::{ConflictResolver, Conflict};
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
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::cilassembly::validation::ValidationPipeline`] - Uses resolvers for conflict handling
//! - [`crate::cilassembly::validation::ConflictResolver`] - Implements the resolver trait

use crate::{
    cilassembly::validation::{Conflict, ConflictResolver, OperationResolution, Resolution},
    Result,
};
use std::collections::HashMap;

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
/// use crate::cilassembly::validation::resolver::LastWriteWinsResolver;
/// use crate::cilassembly::validation::{ConflictResolver, Conflict};
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
    /// * `conflicts` - Array of [`crate::cilassembly::validation::Conflict`] instances to resolve
    ///
    /// # Returns
    ///
    /// Returns a [`crate::cilassembly::validation::Resolution`] containing the winning operation
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
    use crate::{
        cilassembly::{Operation, TableOperation},
        metadata::{
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
}
