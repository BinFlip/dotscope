//! Reference tracking system for heap and table cross-references.
//!
//! This module provides infrastructure for tracking cross-references between
//! metadata tables and heap entries. It enables safe removal and modification
//! operations by identifying all dependent references that need to be handled
//! according to the user's specified strategy.
//!
//! # Key Components
//!
//! - [`crate::cilassembly::references::TableReference`] - Represents a reference from one metadata location to another
//! - [`crate::cilassembly::references::ReferenceTracker`] - Tracks cross-references between heap entries and table rows
//!
//! # Architecture
//!
//! The reference tracking system maintains bidirectional maps between heap indices
//! and table references to enable efficient lookup operations. This is essential
//! for implementing safe deletion and modification operations that respect referential
//! integrity constraints.
//!
//! ## Reference Types
//! The system tracks references to all four metadata heaps:
//! - **String Heap References**: Points to #Strings heap entries
//! - **Blob Heap References**: Points to #Blob heap entries  
//! - **GUID Heap References**: Points to #GUID heap entries
//! - **User String References**: Points to #US (User String) heap entries
//! - **Table Row References**: Points to specific table rows by RID
//!
//! ## Tracking Strategy
//! References are tracked using hash maps that provide O(1) lookup time for
//! finding all references to a specific heap index or table row. This enables
//! efficient validation during deletion operations.
//!
//! # Usage Examples
//!
//! ```rust,ignore
//! use crate::cilassembly::references::{ReferenceTracker, TableReference};
//! use crate::metadata::tables::TableId;
//!
//! // Create a reference tracker
//! let mut tracker = ReferenceTracker::new();
//!
//! // Create a reference from TypeDef table to string heap
//! let reference = TableReference {
//!     table_id: TableId::TypeDef,
//!     row_rid: 1,
//!     column_name: "Name".to_string(),
//! };
//!
//! // Track the reference
//! tracker.add_string_reference(42, reference);
//!
//! // Check for references before deletion
//! if let Some(refs) = tracker.get_string_references(42) {
//!     println!("String index 42 has {} references", refs.len());
//! }
//!
//! // Remove references when deleting a row
//! tracker.remove_references_from_row(TableId::TypeDef, 1);
//! ```
//!
//! # Thread Safety
//!
//! This type is [`Send`] and [`Sync`] as it contains only owned data without
//! interior mutability. However, the contained hash maps are not designed for
//! concurrent access patterns.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::cilassembly::validation::ReferentialIntegrityValidator`] - Uses reference tracking for validation
//! - [`crate::cilassembly::changes::ReferenceHandlingStrategy`] - Defines how references should be handled during modifications

use crate::metadata::tables::TableId;
use std::collections::HashMap;

/// Represents a reference from one metadata location to another.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableReference {
    /// The table containing the reference
    pub table_id: TableId,
    /// The RID of the row containing the reference
    pub row_rid: u32,
    /// The column name that contains the reference
    pub column_name: String,
}

/// Tracks cross-references between heap entries and table rows.
#[derive(Debug, Default)]
pub struct ReferenceTracker {
    /// Maps string heap indices to all table references that point to them
    string_references: HashMap<u32, Vec<TableReference>>,
    /// Maps blob heap indices to all table references that point to them
    blob_references: HashMap<u32, Vec<TableReference>>,
    /// Maps GUID heap indices to all table references that point to them
    guid_references: HashMap<u32, Vec<TableReference>>,
    /// Maps user string heap indices to all table references that point to them
    userstring_references: HashMap<u32, Vec<TableReference>>,
    /// Maps table RIDs to all table references that point to them
    rid_references: HashMap<(TableId, u32), Vec<TableReference>>,
}

impl ReferenceTracker {
    /// Creates a new empty reference tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a reference from a table row to a string heap index.
    pub fn add_string_reference(&mut self, string_index: u32, reference: TableReference) {
        self.string_references
            .entry(string_index)
            .or_default()
            .push(reference);
    }

    /// Adds a reference from a table row to a blob heap index.
    pub fn add_blob_reference(&mut self, blob_index: u32, reference: TableReference) {
        self.blob_references
            .entry(blob_index)
            .or_default()
            .push(reference);
    }

    /// Adds a reference from a table row to a GUID heap index.
    pub fn add_guid_reference(&mut self, guid_index: u32, reference: TableReference) {
        self.guid_references
            .entry(guid_index)
            .or_default()
            .push(reference);
    }

    /// Adds a reference from a table row to a user string heap index.
    pub fn add_userstring_reference(&mut self, userstring_index: u32, reference: TableReference) {
        self.userstring_references
            .entry(userstring_index)
            .or_default()
            .push(reference);
    }

    /// Adds a reference from one table row to another table row.
    pub fn add_rid_reference(
        &mut self,
        target_table: TableId,
        target_rid: u32,
        reference: TableReference,
    ) {
        self.rid_references
            .entry((target_table, target_rid))
            .or_default()
            .push(reference);
    }

    /// Gets all references to a string heap index.
    pub fn get_string_references(&self, string_index: u32) -> Option<&Vec<TableReference>> {
        self.string_references.get(&string_index)
    }

    /// Gets all references to a blob heap index.
    pub fn get_blob_references(&self, blob_index: u32) -> Option<&Vec<TableReference>> {
        self.blob_references.get(&blob_index)
    }

    /// Gets all references to a GUID heap index.
    pub fn get_guid_references(&self, guid_index: u32) -> Option<&Vec<TableReference>> {
        self.guid_references.get(&guid_index)
    }

    /// Gets all references to a user string heap index.
    pub fn get_userstring_references(&self, userstring_index: u32) -> Option<&Vec<TableReference>> {
        self.userstring_references.get(&userstring_index)
    }

    /// Gets all references to a table row.
    pub fn get_rid_references(&self, table_id: TableId, rid: u32) -> Option<&Vec<TableReference>> {
        self.rid_references.get(&(table_id, rid))
    }

    /// Removes all references originating from a specific table row.
    ///
    /// This is useful when a table row is being deleted - we need to remove
    /// all the references it was making to other items.
    pub fn remove_references_from_row(&mut self, source_table: TableId, source_rid: u32) {
        self.string_references.retain(|_, refs| {
            refs.retain(|r| !(r.table_id == source_table && r.row_rid == source_rid));
            !refs.is_empty()
        });

        self.blob_references.retain(|_, refs| {
            refs.retain(|r| !(r.table_id == source_table && r.row_rid == source_rid));
            !refs.is_empty()
        });

        self.guid_references.retain(|_, refs| {
            refs.retain(|r| !(r.table_id == source_table && r.row_rid == source_rid));
            !refs.is_empty()
        });

        self.userstring_references.retain(|_, refs| {
            refs.retain(|r| !(r.table_id == source_table && r.row_rid == source_rid));
            !refs.is_empty()
        });

        self.rid_references.retain(|_, refs| {
            refs.retain(|r| !(r.table_id == source_table && r.row_rid == source_rid));
            !refs.is_empty()
        });
    }

    /// Returns the total number of tracked references.
    pub fn total_reference_count(&self) -> usize {
        self.string_references
            .values()
            .map(|v| v.len())
            .sum::<usize>()
            + self
                .blob_references
                .values()
                .map(|v| v.len())
                .sum::<usize>()
            + self
                .guid_references
                .values()
                .map(|v| v.len())
                .sum::<usize>()
            + self
                .userstring_references
                .values()
                .map(|v| v.len())
                .sum::<usize>()
            + self.rid_references.values().map(|v| v.len()).sum::<usize>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reference_tracker_basic() {
        let mut tracker = ReferenceTracker::new();

        let reference = TableReference {
            table_id: TableId::TypeDef,
            row_rid: 1,
            column_name: "Name".to_string(),
        };

        tracker.add_string_reference(42, reference.clone());

        let refs = tracker.get_string_references(42).unwrap();
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0], reference);

        assert_eq!(tracker.total_reference_count(), 1);
    }

    #[test]
    fn test_remove_references_from_row() {
        let mut tracker = ReferenceTracker::new();

        let reference1 = TableReference {
            table_id: TableId::TypeDef,
            row_rid: 1,
            column_name: "Name".to_string(),
        };

        let reference2 = TableReference {
            table_id: TableId::TypeDef,
            row_rid: 2,
            column_name: "Name".to_string(),
        };

        tracker.add_string_reference(42, reference1);
        tracker.add_string_reference(42, reference2);

        assert_eq!(tracker.total_reference_count(), 2);

        // Remove all references from row 1
        tracker.remove_references_from_row(TableId::TypeDef, 1);

        assert_eq!(tracker.total_reference_count(), 1);
        let remaining_refs = tracker.get_string_references(42).unwrap();
        assert_eq!(remaining_refs.len(), 1);
        assert_eq!(remaining_refs[0].row_rid, 2);
    }
}
