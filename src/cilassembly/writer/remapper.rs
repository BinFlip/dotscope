//! RID remapping for table row deletions.
//!
//! When rows are deleted from metadata tables, all subsequent rows shift down to fill
//! the gaps. This module provides the [`RidRemapper`] which calculates the new RIDs
//! and applies remapping to all cross-table references during the write phase.
//!
//! # The Problem
//!
//! When `table_row_remove()` deletes row 5 from a 10-row table:
//! - Rows 1-4 remain unchanged
//! - Row 5 is removed
//! - Rows 6-10 shift down to become rows 5-9
//!
//! But other tables still reference the OLD RIDs:
//! - `TypeDef.method_list` might point to method RID 7 (now RID 6)
//! - `CustomAttribute.parent` might point to `0x06000007` (now `0x06000006`)
//!
//! # Solution
//!
//! The remapper:
//! 1. Builds a mapping from old RIDs to new RIDs for each table with deletions
//! 2. During table serialization, applies this mapping to all reference fields
//!
//! # Algorithm
//!
//! For a table with deletions, iterate through all original RIDs:
//! - If deleted: skip (don't increment new RID counter)
//! - If not deleted: map old RID → new RID, increment counter
//!
//! This handles multiple deletions correctly since we count all gaps.
//!
//! # Example
//!
//! Original table with 10 rows, delete rows 3 and 7:
//! ```text
//! Old RID:  1  2  3  4  5  6  7  8  9  10
//! Deleted:        ✗           ✗
//! New RID:  1  2  -  3  4  5  -  6  7  8
//!
//! Remapping: 4→3, 5→4, 6→5, 8→6, 9→7, 10→8
//! ```
//!
//! # References
//!
//! - ECMA-335 §II.22 - Metadata logical format
//! - ECMA-335 §II.24.2.6 - Coded indices

use std::collections::{HashMap, HashSet};

use crate::{
    cilassembly::{AssemblyChanges, TableModifications},
    metadata::tables::{
        AssemblyOsRaw, AssemblyProcessorRaw, AssemblyRaw, AssemblyRefOsRaw,
        AssemblyRefProcessorRaw, AssemblyRefRaw, ClassLayoutRaw, CodedIndex, ConstantRaw,
        CustomAttributeRaw, CustomDebugInformationRaw, DeclSecurityRaw, DocumentRaw, EncLogRaw,
        EncMapRaw, EventMapRaw, EventPtrRaw, EventRaw, ExportedTypeRaw, FieldLayoutRaw,
        FieldMarshalRaw, FieldPtrRaw, FieldRaw, FieldRvaRaw, FileRaw, GenericParamConstraintRaw,
        GenericParamRaw, ImplMapRaw, ImportScopeRaw, InterfaceImplRaw, LocalConstantRaw,
        LocalScopeRaw, LocalVariableRaw, ManifestResourceRaw, MemberRefRaw,
        MethodDebugInformationRaw, MethodDefRaw, MethodImplRaw, MethodPtrRaw, MethodSemanticsRaw,
        MethodSpecRaw, ModuleRaw, ModuleRefRaw, NestedClassRaw, ParamPtrRaw, ParamRaw,
        PropertyMapRaw, PropertyPtrRaw, PropertyRaw, StandAloneSigRaw, StateMachineMethodRaw,
        TableDataOwned, TableId, TypeDefRaw, TypeRefRaw, TypeSpecRaw,
    },
};

/// Remaps RIDs after row deletions to maintain valid cross-table references.
///
/// When rows are deleted from metadata tables, all subsequent rows shift down.
/// This struct tracks those shifts and provides methods to remap references
/// in other tables that point to the shifted rows.
///
/// # Building the Remapper
///
/// The remapper is built from `AssemblyChanges` before writing tables:
///
/// ```rust,ignore
/// let remapper = RidRemapper::from_changes(&changes, &original_counts);
/// ```
///
/// # Applying Remapping
///
/// During table serialization, call `remap_references` on each row:
///
/// ```rust,ignore
/// row.remap_references(&remapper);
/// ```
#[derive(Debug, Default)]
pub struct RidRemapper {
    /// For each table with deletions: maps old RID → new RID
    ///
    /// Only RIDs that actually change are stored. If an old RID maps to itself
    /// (no rows before it were deleted), it won't be in the map.
    ///
    /// Note: This includes "continuation" mappings for deleted rows (pointing to
    /// the next surviving row). For signature remapping, use `typedef_remap()`
    /// which excludes deleted rows.
    remaps: HashMap<TableId, HashMap<u32, u32>>,

    /// Tables that have any deletions (for quick lookup)
    tables_with_deletions: HashSet<TableId>,

    /// For each table with deletions: the set of deleted RIDs
    ///
    /// Used to filter out deleted RIDs when remapping type tokens in signatures,
    /// since deleted types shouldn't be remapped to other types.
    deleted_rids: HashMap<TableId, HashSet<u32>>,
}

impl RidRemapper {
    /// Creates an empty remapper with no mappings.
    ///
    /// Use this when there are no deletions in any table.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Returns `true` if there are no deletions requiring remapping.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tables_with_deletions.is_empty()
    }

    /// Returns `true` if the specified table has any deletions.
    #[must_use]
    pub fn has_deletions(&self, table_id: TableId) -> bool {
        self.tables_with_deletions.contains(&table_id)
    }

    /// Builds a remapper from assembly changes.
    ///
    /// Examines all table modifications to find deletions, then calculates
    /// the new RID for each surviving row.
    ///
    /// # Arguments
    ///
    /// * `changes` - The assembly changes containing table modifications
    /// * `original_counts` - Map from TableId to original row count (before modifications)
    ///
    /// # Returns
    ///
    /// A `RidRemapper` with mappings for all tables that have deletions.
    #[must_use]
    pub fn from_changes(
        changes: &AssemblyChanges,
        original_counts: &HashMap<TableId, u32>,
    ) -> Self {
        let mut remaps = HashMap::new();
        let mut tables_with_deletions = HashSet::new();
        let mut deleted_rids = HashMap::new();

        for (table_id, table_mods) in &changes.table_changes {
            if let TableModifications::Sparse { deleted_rows, .. } = table_mods {
                if deleted_rows.is_empty() {
                    continue;
                }

                tables_with_deletions.insert(*table_id);
                deleted_rids.insert(*table_id, deleted_rows.clone());

                let original_count = original_counts.get(table_id).copied().unwrap_or(0);
                let remap = Self::calculate_remapping(deleted_rows, original_count);

                if !remap.is_empty() {
                    remaps.insert(*table_id, remap);
                }
            }
        }

        Self {
            remaps,
            tables_with_deletions,
            deleted_rids,
        }
    }

    /// Calculates the RID remapping for a single table.
    ///
    /// # Algorithm
    ///
    /// Iterate through all original RIDs (1..=original_count):
    /// - If the RID is in `deleted_rows`, skip it (don't increment new_rid)
    /// - Otherwise, if old_rid != new_rid, record the mapping
    /// - Increment new_rid for each surviving row
    ///
    /// Also tracks the "continuation" for deleted rows - the new RID of the first
    /// surviving row after a deleted row. This is needed for "list start" fields
    /// like param_list, method_list, and field_list.
    ///
    /// # Arguments
    ///
    /// * `deleted_rows` - Set of RIDs that have been deleted
    /// * `original_count` - Total number of rows before deletions
    ///
    /// # Returns
    ///
    /// HashMap mapping old RIDs to new RIDs (includes both surviving rows that
    /// changed AND deleted rows mapped to their continuation)
    fn calculate_remapping(deleted_rows: &HashSet<u32>, original_count: u32) -> HashMap<u32, u32> {
        let mut remap = HashMap::new();
        let mut new_rid = 1u32;

        // First pass: calculate new RIDs for surviving rows
        let mut surviving_rids: Vec<(u32, u32)> = Vec::new();
        for old_rid in 1..=original_count {
            if deleted_rows.contains(&old_rid) {
                continue;
            }
            surviving_rids.push((old_rid, new_rid));
            if old_rid != new_rid {
                remap.insert(old_rid, new_rid);
            }
            new_rid += 1;
        }

        // Second pass: for deleted rows, find the "continuation" RID
        // This is the new RID of the first surviving row after the deleted row
        let final_new_rid = new_rid; // One past the last new RID
        for old_rid in 1..=original_count {
            if !deleted_rows.contains(&old_rid) {
                continue; // Skip surviving rows
            }

            // Find the first surviving row after this deleted row
            let continuation = surviving_rids
                .iter()
                .find(|(orig, _)| *orig > old_rid)
                .map(|(_, new)| *new)
                .unwrap_or(final_new_rid); // If no surviving row after, point past end

            remap.insert(old_rid, continuation);
        }

        // Third pass: handle the "continuation" value (one past the original end)
        // In .NET, tables like MethodDef use param_list/field_list/method_list values
        // that can point one past the end of the table to indicate "no items".
        // When rows are deleted, this continuation value must also be remapped.
        let old_continuation = original_count + 1;
        if old_continuation != final_new_rid {
            remap.insert(old_continuation, final_new_rid);
        }

        remap
    }

    /// Remaps a direct RID reference to a specific table.
    ///
    /// If the target table has deletions and this RID needs remapping,
    /// returns the new RID. Otherwise returns the original RID unchanged.
    ///
    /// # Arguments
    ///
    /// * `target_table` - The table that the RID references
    /// * `old_rid` - The original RID value
    ///
    /// # Returns
    ///
    /// The remapped RID if it changed, or the original RID if unchanged.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// // If MethodDef row 7 became row 6 after deletions:
    /// let new_rid = remapper.remap_rid(TableId::MethodDef, 7);
    /// assert_eq!(new_rid, 6);
    /// ```
    #[must_use]
    pub fn remap_rid(&self, target_table: TableId, old_rid: u32) -> u32 {
        // RID 0 is null reference, never remap
        if old_rid == 0 {
            return 0;
        }

        self.remaps
            .get(&target_table)
            .and_then(|map| map.get(&old_rid))
            .copied()
            .unwrap_or(old_rid)
    }

    /// Returns the TypeDef RID remapping for signature blob processing.
    ///
    /// Signature blobs contain TypeDefOrRefOrSpec encoded tokens that reference
    /// TypeDef rows. When TypeDef rows are deleted and RIDs shift, these embedded
    /// tokens must also be updated.
    ///
    /// **Important**: This method filters out deleted TypeDef RIDs from the remapping.
    /// The general remapping includes "continuation" values for deleted rows (pointing
    /// to the next surviving row), which is correct for list pointers but WRONG for
    /// type references. If a signature references a deleted type, remapping it to the
    /// next surviving type would silently corrupt the type system.
    ///
    /// # Returns
    ///
    /// A HashMap mapping old TypeDef RIDs to new RIDs for surviving rows only,
    /// or `None` if there are no TypeDef deletions.
    ///
    /// # Example
    ///
    /// If TypeDef rows 1, 2, 3, 4, 5 exist and row 3 is deleted:
    /// - Full remap: {3→3, 4→3, 5→4} (3→3 is continuation pointing to what was row 4)
    /// - Signature remap: {4→3, 5→4} (excludes deleted row 3)
    #[must_use]
    pub fn typedef_remap(&self) -> Option<HashMap<u32, u32>> {
        let full_remap = self.remaps.get(&TableId::TypeDef)?;
        let deleted = self.deleted_rids.get(&TableId::TypeDef);

        // Filter out deleted RIDs - they should NOT be remapped to other types
        let filtered: HashMap<u32, u32> = full_remap
            .iter()
            .filter(|(old_rid, _)| deleted.is_none_or(|d| !d.contains(old_rid)))
            .map(|(&k, &v)| (k, v))
            .collect();

        if filtered.is_empty() {
            None
        } else {
            Some(filtered)
        }
    }

    /// Returns the TypeRef RID remapping for signature blob processing.
    ///
    /// Signature blobs contain TypeDefOrRefOrSpec encoded tokens that reference
    /// TypeRef rows (external type references). When TypeRef rows are deleted
    /// and RIDs shift, these embedded tokens must also be updated.
    ///
    /// **Important**: Like `typedef_remap()`, this method filters out deleted
    /// TypeRef RIDs from the remapping to avoid corrupting type references.
    ///
    /// # Returns
    ///
    /// A HashMap mapping old TypeRef RIDs to new RIDs for surviving rows only,
    /// or `None` if there are no TypeRef deletions.
    #[must_use]
    pub fn typeref_remap(&self) -> Option<HashMap<u32, u32>> {
        let full_remap = self.remaps.get(&TableId::TypeRef)?;
        let deleted = self.deleted_rids.get(&TableId::TypeRef);

        // Filter out deleted RIDs - they should NOT be remapped to other types
        let filtered: HashMap<u32, u32> = full_remap
            .iter()
            .filter(|(old_rid, _)| deleted.is_none_or(|d| !d.contains(old_rid)))
            .map(|(&k, &v)| (k, v))
            .collect();

        if filtered.is_empty() {
            None
        } else {
            Some(filtered)
        }
    }

    /// Remaps a coded index reference.
    ///
    /// Coded indices encode both the target table (in the tag) and the RID.
    /// This method extracts the table from the tag, remaps the RID if needed,
    /// and updates the coded index in place.
    ///
    /// # Arguments
    ///
    /// * `coded_index` - Mutable reference to the coded index to remap
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// // CustomAttribute.parent pointing to MethodDef row 7
    /// let mut ci = CodedIndex::new(TableId::MethodDef, 7, CodedIndexType::HasCustomAttribute);
    /// remapper.remap_coded_index(&mut ci);
    /// // If MethodDef row 7 became row 6, ci.row is now 6
    /// ```
    pub fn remap_coded_index(&self, coded_index: &mut CodedIndex) {
        // Null coded indices (row 0) are never remapped
        if coded_index.row == 0 {
            return;
        }

        let table_id = coded_index.tag;
        if let Some(table_remap) = self.remaps.get(&table_id) {
            if let Some(&new_rid) = table_remap.get(&coded_index.row) {
                coded_index.row = new_rid;
                // Update the token to reflect the new row
                coded_index.token = crate::metadata::token::Token::from_parts(table_id, new_rid);
            }
        }
    }

    /// Returns the number of tables that have remappings.
    #[must_use]
    pub fn table_count(&self) -> usize {
        self.remaps.len()
    }

    /// Returns the total number of RID remappings across all tables.
    #[must_use]
    pub fn total_remappings(&self) -> usize {
        self.remaps.values().map(|m| m.len()).sum()
    }

    /// Builds a token remapping for IL instruction patching.
    ///
    /// IL instructions use metadata tokens (table_id << 24 | rid). When rows are
    /// deleted and RIDs shift, the tokens in IL code must also be updated.
    ///
    /// This method converts all RID remappings to token remappings by prepending
    /// the table ID to each RID.
    ///
    /// # Returns
    ///
    /// A HashMap mapping old tokens to new tokens, suitable for patching IL code.
    ///
    /// # Example
    ///
    /// If MethodDef RID 7 → 6 after deletion, this produces:
    /// `0x06000007 → 0x06000006`
    #[must_use]
    pub fn build_token_remapping(&self) -> HashMap<u32, u32> {
        let mut token_remap = HashMap::new();

        for (table_id, rid_map) in &self.remaps {
            // Get the table ID byte (upper 8 bits of token)
            let table_byte = (*table_id as u32) << 24;

            for (&old_rid, &new_rid) in rid_map {
                // Skip RID 0 (null) and unchanged mappings
                if old_rid == 0 || old_rid == new_rid {
                    continue;
                }

                let old_token = table_byte | old_rid;
                let new_token = table_byte | new_rid;
                token_remap.insert(old_token, new_token);
            }
        }

        token_remap
    }
}

/// Trait for remapping cross-table RID references in metadata table rows.
///
/// Each table type implements this to remap its specific reference fields
/// (both direct RID references and coded indices) when rows are deleted
/// from referenced tables.
///
/// This is the complement to `ResolvePlaceholders` - while that trait resolves
/// heap references, this trait handles table row references.
pub trait RemapReferences {
    /// Remaps all cross-table references in this row.
    ///
    /// # Arguments
    ///
    /// * `remapper` - The RID remapper containing old→new RID mappings
    fn remap_references(&mut self, remapper: &RidRemapper);
}

impl RemapReferences for TypeRefRaw {
    fn remap_references(&mut self, remapper: &RidRemapper) {
        // ResolutionScope: Module, ModuleRef, AssemblyRef, TypeRef
        remapper.remap_coded_index(&mut self.resolution_scope);
    }
}

impl RemapReferences for TypeDefRaw {
    fn remap_references(&mut self, remapper: &RidRemapper) {
        // Extends: TypeDef, TypeRef, TypeSpec
        remapper.remap_coded_index(&mut self.extends);

        // FieldList: direct RID into Field table
        self.field_list = remapper.remap_rid(TableId::Field, self.field_list);

        // MethodList: direct RID into MethodDef table
        self.method_list = remapper.remap_rid(TableId::MethodDef, self.method_list);
    }
}

impl RemapReferences for MethodDefRaw {
    fn remap_references(&mut self, remapper: &RidRemapper) {
        // ParamList: direct RID into Param table
        self.param_list = remapper.remap_rid(TableId::Param, self.param_list);
    }
}

impl RemapReferences for InterfaceImplRaw {
    fn remap_references(&mut self, remapper: &RidRemapper) {
        // Class: direct RID into TypeDef table
        self.class = remapper.remap_rid(TableId::TypeDef, self.class);

        // Interface: TypeDef, TypeRef, TypeSpec
        remapper.remap_coded_index(&mut self.interface);
    }
}

impl RemapReferences for MemberRefRaw {
    fn remap_references(&mut self, remapper: &RidRemapper) {
        // Class: TypeDef, TypeRef, ModuleRef, MethodDef, TypeSpec
        remapper.remap_coded_index(&mut self.class);
    }
}

impl RemapReferences for ConstantRaw {
    fn remap_references(&mut self, remapper: &RidRemapper) {
        // Parent: Field, Param, Property
        remapper.remap_coded_index(&mut self.parent);
    }
}

impl RemapReferences for CustomAttributeRaw {
    fn remap_references(&mut self, remapper: &RidRemapper) {
        // Parent: HasCustomAttribute (22 tables!)
        remapper.remap_coded_index(&mut self.parent);

        // Constructor: MethodDef, MemberRef
        remapper.remap_coded_index(&mut self.constructor);
    }
}

impl RemapReferences for FieldMarshalRaw {
    fn remap_references(&mut self, remapper: &RidRemapper) {
        // Parent: Field, Param
        remapper.remap_coded_index(&mut self.parent);
    }
}

impl RemapReferences for DeclSecurityRaw {
    fn remap_references(&mut self, remapper: &RidRemapper) {
        // Parent: TypeDef, MethodDef, Assembly
        remapper.remap_coded_index(&mut self.parent);
    }
}

impl RemapReferences for ClassLayoutRaw {
    fn remap_references(&mut self, remapper: &RidRemapper) {
        // Parent: direct RID into TypeDef table
        self.parent = remapper.remap_rid(TableId::TypeDef, self.parent);
    }
}

impl RemapReferences for FieldLayoutRaw {
    fn remap_references(&mut self, remapper: &RidRemapper) {
        // Field: direct RID into Field table
        self.field = remapper.remap_rid(TableId::Field, self.field);
    }
}

impl RemapReferences for EventMapRaw {
    fn remap_references(&mut self, remapper: &RidRemapper) {
        // Parent: direct RID into TypeDef table
        self.parent = remapper.remap_rid(TableId::TypeDef, self.parent);

        // EventList: direct RID into Event table
        self.event_list = remapper.remap_rid(TableId::Event, self.event_list);
    }
}

impl RemapReferences for EventRaw {
    fn remap_references(&mut self, remapper: &RidRemapper) {
        // EventType: TypeDef, TypeRef, TypeSpec
        remapper.remap_coded_index(&mut self.event_type);
    }
}

impl RemapReferences for PropertyMapRaw {
    fn remap_references(&mut self, remapper: &RidRemapper) {
        // Parent: direct RID into TypeDef table
        self.parent = remapper.remap_rid(TableId::TypeDef, self.parent);

        // PropertyList: direct RID into Property table
        self.property_list = remapper.remap_rid(TableId::Property, self.property_list);
    }
}

impl RemapReferences for MethodSemanticsRaw {
    fn remap_references(&mut self, remapper: &RidRemapper) {
        // Method: direct RID into MethodDef table
        self.method = remapper.remap_rid(TableId::MethodDef, self.method);

        // Association: Event, Property
        remapper.remap_coded_index(&mut self.association);
    }
}

impl RemapReferences for MethodImplRaw {
    fn remap_references(&mut self, remapper: &RidRemapper) {
        // Class: direct RID into TypeDef table
        self.class = remapper.remap_rid(TableId::TypeDef, self.class);

        // MethodBody: MethodDef, MemberRef
        remapper.remap_coded_index(&mut self.method_body);

        // MethodDeclaration: MethodDef, MemberRef
        remapper.remap_coded_index(&mut self.method_declaration);
    }
}

impl RemapReferences for ImplMapRaw {
    fn remap_references(&mut self, remapper: &RidRemapper) {
        // MemberForwarded: Field, MethodDef
        remapper.remap_coded_index(&mut self.member_forwarded);

        // ImportScope: direct RID into ModuleRef table
        self.import_scope = remapper.remap_rid(TableId::ModuleRef, self.import_scope);
    }
}

impl RemapReferences for FieldRvaRaw {
    fn remap_references(&mut self, remapper: &RidRemapper) {
        // Field: direct RID into Field table
        self.field = remapper.remap_rid(TableId::Field, self.field);
    }
}

impl RemapReferences for AssemblyRefRaw {
    fn remap_references(&mut self, _remapper: &RidRemapper) {
        // AssemblyRef has no cross-table references, only heap refs
    }
}

impl RemapReferences for ExportedTypeRaw {
    fn remap_references(&mut self, remapper: &RidRemapper) {
        // Implementation: File, AssemblyRef, ExportedType
        remapper.remap_coded_index(&mut self.implementation);
    }
}

impl RemapReferences for ManifestResourceRaw {
    fn remap_references(&mut self, remapper: &RidRemapper) {
        // Implementation: File, AssemblyRef (ExportedType not valid here per spec)
        remapper.remap_coded_index(&mut self.implementation);
    }
}

impl RemapReferences for NestedClassRaw {
    fn remap_references(&mut self, remapper: &RidRemapper) {
        // NestedClass: direct RID into TypeDef table
        self.nested_class = remapper.remap_rid(TableId::TypeDef, self.nested_class);

        // EnclosingClass: direct RID into TypeDef table
        self.enclosing_class = remapper.remap_rid(TableId::TypeDef, self.enclosing_class);
    }
}

impl RemapReferences for GenericParamRaw {
    fn remap_references(&mut self, remapper: &RidRemapper) {
        // Owner: TypeDef, MethodDef
        remapper.remap_coded_index(&mut self.owner);
    }
}

impl RemapReferences for MethodSpecRaw {
    fn remap_references(&mut self, remapper: &RidRemapper) {
        // Method: MethodDef, MemberRef
        remapper.remap_coded_index(&mut self.method);
    }
}

impl RemapReferences for GenericParamConstraintRaw {
    fn remap_references(&mut self, remapper: &RidRemapper) {
        // Owner: direct RID into GenericParam table
        self.owner = remapper.remap_rid(TableId::GenericParam, self.owner);

        // Constraint: TypeDef, TypeRef, TypeSpec
        remapper.remap_coded_index(&mut self.constraint);
    }
}

impl RemapReferences for ModuleRaw {
    fn remap_references(&mut self, _remapper: &RidRemapper) {}
}

impl RemapReferences for FieldPtrRaw {
    fn remap_references(&mut self, _remapper: &RidRemapper) {}
}

impl RemapReferences for FieldRaw {
    fn remap_references(&mut self, _remapper: &RidRemapper) {}
}

impl RemapReferences for MethodPtrRaw {
    fn remap_references(&mut self, _remapper: &RidRemapper) {}
}

impl RemapReferences for ParamPtrRaw {
    fn remap_references(&mut self, _remapper: &RidRemapper) {}
}

impl RemapReferences for ParamRaw {
    fn remap_references(&mut self, _remapper: &RidRemapper) {}
}

impl RemapReferences for StandAloneSigRaw {
    fn remap_references(&mut self, _remapper: &RidRemapper) {}
}

impl RemapReferences for EventPtrRaw {
    fn remap_references(&mut self, _remapper: &RidRemapper) {}
}

impl RemapReferences for PropertyPtrRaw {
    fn remap_references(&mut self, _remapper: &RidRemapper) {}
}

impl RemapReferences for PropertyRaw {
    fn remap_references(&mut self, _remapper: &RidRemapper) {}
}

impl RemapReferences for ModuleRefRaw {
    fn remap_references(&mut self, _remapper: &RidRemapper) {}
}

impl RemapReferences for TypeSpecRaw {
    fn remap_references(&mut self, _remapper: &RidRemapper) {}
}

impl RemapReferences for EncLogRaw {
    fn remap_references(&mut self, _remapper: &RidRemapper) {}
}

impl RemapReferences for EncMapRaw {
    fn remap_references(&mut self, _remapper: &RidRemapper) {}
}

impl RemapReferences for AssemblyRaw {
    fn remap_references(&mut self, _remapper: &RidRemapper) {}
}

impl RemapReferences for AssemblyProcessorRaw {
    fn remap_references(&mut self, _remapper: &RidRemapper) {}
}

impl RemapReferences for AssemblyOsRaw {
    fn remap_references(&mut self, _remapper: &RidRemapper) {}
}

impl RemapReferences for AssemblyRefProcessorRaw {
    fn remap_references(&mut self, _remapper: &RidRemapper) {}
}

impl RemapReferences for AssemblyRefOsRaw {
    fn remap_references(&mut self, _remapper: &RidRemapper) {}
}

impl RemapReferences for FileRaw {
    fn remap_references(&mut self, _remapper: &RidRemapper) {}
}

impl RemapReferences for DocumentRaw {
    fn remap_references(&mut self, _remapper: &RidRemapper) {}
}

impl RemapReferences for MethodDebugInformationRaw {
    fn remap_references(&mut self, _remapper: &RidRemapper) {}
}

impl RemapReferences for LocalScopeRaw {
    fn remap_references(&mut self, _remapper: &RidRemapper) {}
}

impl RemapReferences for LocalVariableRaw {
    fn remap_references(&mut self, _remapper: &RidRemapper) {}
}

impl RemapReferences for LocalConstantRaw {
    fn remap_references(&mut self, _remapper: &RidRemapper) {}
}

impl RemapReferences for ImportScopeRaw {
    fn remap_references(&mut self, _remapper: &RidRemapper) {}
}

impl RemapReferences for StateMachineMethodRaw {
    fn remap_references(&mut self, _remapper: &RidRemapper) {}
}

impl RemapReferences for CustomDebugInformationRaw {
    fn remap_references(&mut self, _remapper: &RidRemapper) {}
}

impl RemapReferences for TableDataOwned {
    fn remap_references(&mut self, remapper: &RidRemapper) {
        match self {
            TableDataOwned::TypeRef(r) => r.remap_references(remapper),
            TableDataOwned::TypeDef(r) => r.remap_references(remapper),
            TableDataOwned::MethodDef(r) => r.remap_references(remapper),
            TableDataOwned::InterfaceImpl(r) => r.remap_references(remapper),
            TableDataOwned::MemberRef(r) => r.remap_references(remapper),
            TableDataOwned::Constant(r) => r.remap_references(remapper),
            TableDataOwned::CustomAttribute(r) => r.remap_references(remapper),
            TableDataOwned::FieldMarshal(r) => r.remap_references(remapper),
            TableDataOwned::DeclSecurity(r) => r.remap_references(remapper),
            TableDataOwned::ClassLayout(r) => r.remap_references(remapper),
            TableDataOwned::FieldLayout(r) => r.remap_references(remapper),
            TableDataOwned::EventMap(r) => r.remap_references(remapper),
            TableDataOwned::Event(r) => r.remap_references(remapper),
            TableDataOwned::PropertyMap(r) => r.remap_references(remapper),
            TableDataOwned::MethodSemantics(r) => r.remap_references(remapper),
            TableDataOwned::MethodImpl(r) => r.remap_references(remapper),
            TableDataOwned::ImplMap(r) => r.remap_references(remapper),
            TableDataOwned::FieldRVA(r) => r.remap_references(remapper),
            TableDataOwned::AssemblyRef(r) => r.remap_references(remapper),
            TableDataOwned::ExportedType(r) => r.remap_references(remapper),
            TableDataOwned::ManifestResource(r) => r.remap_references(remapper),
            TableDataOwned::NestedClass(r) => r.remap_references(remapper),
            TableDataOwned::GenericParam(r) => r.remap_references(remapper),
            TableDataOwned::MethodSpec(r) => r.remap_references(remapper),
            TableDataOwned::GenericParamConstraint(r) => r.remap_references(remapper),
            // Tables without cross-table references
            TableDataOwned::Module(_)
            | TableDataOwned::FieldPtr(_)
            | TableDataOwned::Field(_)
            | TableDataOwned::MethodPtr(_)
            | TableDataOwned::ParamPtr(_)
            | TableDataOwned::Param(_)
            | TableDataOwned::EventPtr(_)
            | TableDataOwned::Property(_)
            | TableDataOwned::PropertyPtr(_)
            | TableDataOwned::ModuleRef(_)
            | TableDataOwned::TypeSpec(_)
            | TableDataOwned::StandAloneSig(_)
            | TableDataOwned::EncLog(_)
            | TableDataOwned::EncMap(_)
            | TableDataOwned::Assembly(_)
            | TableDataOwned::AssemblyProcessor(_)
            | TableDataOwned::AssemblyOS(_)
            | TableDataOwned::AssemblyRefProcessor(_)
            | TableDataOwned::AssemblyRefOS(_)
            | TableDataOwned::File(_)
            | TableDataOwned::Document(_)
            | TableDataOwned::MethodDebugInformation(_)
            | TableDataOwned::LocalScope(_)
            | TableDataOwned::LocalVariable(_)
            | TableDataOwned::LocalConstant(_)
            | TableDataOwned::ImportScope(_)
            | TableDataOwned::StateMachineMethod(_)
            | TableDataOwned::CustomDebugInformation(_) => {
                // No cross-table references to remap
            }
        }
    }
}

impl RidRemapper {
    /// Check if a table needs remapping based on the tables it references.
    ///
    /// Returns true if any of the tables that `table_id` references have deletions.
    #[must_use]
    pub fn needs_remapping(&self, table_id: TableId) -> bool {
        if self.is_empty() {
            return false;
        }

        table_id.references().iter().any(|t| self.has_deletions(*t))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::tables::CodedIndexType;

    #[test]
    fn test_calculate_remapping_no_deletions() {
        let deleted = HashSet::new();
        let remap = RidRemapper::calculate_remapping(&deleted, 10);
        assert!(remap.is_empty());
    }

    #[test]
    fn test_calculate_remapping_single_deletion() {
        let mut deleted = HashSet::new();
        deleted.insert(3);

        let remap = RidRemapper::calculate_remapping(&deleted, 10);

        // Row 3 deleted, rows 4-10 shift down by 1
        assert_eq!(remap.get(&1), None); // unchanged
        assert_eq!(remap.get(&2), None); // unchanged
        assert_eq!(remap.get(&3), Some(&3)); // deleted, maps to continuation (first surviving row after = 4→3)
        assert_eq!(remap.get(&4), Some(&3)); // 4 → 3
        assert_eq!(remap.get(&5), Some(&4)); // 5 → 4
        assert_eq!(remap.get(&10), Some(&9)); // 10 → 9
    }

    #[test]
    fn test_calculate_remapping_multiple_deletions() {
        let mut deleted = HashSet::new();
        deleted.insert(3);
        deleted.insert(7);

        let remap = RidRemapper::calculate_remapping(&deleted, 10);

        // Rows 3 and 7 deleted
        // Row 1-2: unchanged
        // Row 3: deleted
        // Row 4-6: shift by 1 (4→3, 5→4, 6→5)
        // Row 7: deleted
        // Row 8-10: shift by 2 (8→6, 9→7, 10→8)
        assert_eq!(remap.get(&1), None);
        assert_eq!(remap.get(&2), None);
        assert_eq!(remap.get(&4), Some(&3));
        assert_eq!(remap.get(&5), Some(&4));
        assert_eq!(remap.get(&6), Some(&5));
        assert_eq!(remap.get(&8), Some(&6));
        assert_eq!(remap.get(&9), Some(&7));
        assert_eq!(remap.get(&10), Some(&8));
    }

    #[test]
    fn test_calculate_remapping_consecutive_deletions() {
        let mut deleted = HashSet::new();
        deleted.insert(3);
        deleted.insert(4);
        deleted.insert(5);

        let remap = RidRemapper::calculate_remapping(&deleted, 10);

        // Rows 3, 4, 5 deleted
        // Row 6-10: shift by 3
        assert_eq!(remap.get(&1), None);
        assert_eq!(remap.get(&2), None);
        assert_eq!(remap.get(&6), Some(&3));
        assert_eq!(remap.get(&7), Some(&4));
        assert_eq!(remap.get(&10), Some(&7));
    }

    #[test]
    fn test_calculate_remapping_first_row_deleted() {
        let mut deleted = HashSet::new();
        deleted.insert(1);

        let remap = RidRemapper::calculate_remapping(&deleted, 5);

        // Row 1 deleted, all others shift
        assert_eq!(remap.get(&2), Some(&1));
        assert_eq!(remap.get(&3), Some(&2));
        assert_eq!(remap.get(&4), Some(&3));
        assert_eq!(remap.get(&5), Some(&4));
    }

    #[test]
    fn test_calculate_remapping_last_row_deleted() {
        let mut deleted = HashSet::new();
        deleted.insert(10);

        let remap = RidRemapper::calculate_remapping(&deleted, 10);

        // Last row deleted, surviving rows 1-9 unchanged
        // Two entries needed:
        // - Deleted row 10 maps to continuation (10 = new past-end)
        // - Old continuation (11) maps to new continuation (10)
        assert_eq!(remap.len(), 2);
        assert_eq!(remap.get(&10), Some(&10)); // deleted, maps to new past-end
        assert_eq!(remap.get(&11), Some(&10)); // old continuation maps to new past-end
    }

    #[test]
    fn test_remap_rid() {
        let mut deleted = HashSet::new();
        deleted.insert(3);

        let mut remaps = HashMap::new();
        remaps.insert(
            TableId::MethodDef,
            RidRemapper::calculate_remapping(&deleted, 10),
        );

        let mut deleted_rids = HashMap::new();
        deleted_rids.insert(TableId::MethodDef, deleted);

        let remapper = RidRemapper {
            remaps,
            tables_with_deletions: [TableId::MethodDef].into_iter().collect(),
            deleted_rids,
        };

        // RID 0 never remapped (null reference)
        assert_eq!(remapper.remap_rid(TableId::MethodDef, 0), 0);

        // Unchanged RIDs
        assert_eq!(remapper.remap_rid(TableId::MethodDef, 1), 1);
        assert_eq!(remapper.remap_rid(TableId::MethodDef, 2), 2);

        // Remapped RIDs
        assert_eq!(remapper.remap_rid(TableId::MethodDef, 4), 3);
        assert_eq!(remapper.remap_rid(TableId::MethodDef, 5), 4);

        // Table without deletions returns original
        assert_eq!(remapper.remap_rid(TableId::Field, 5), 5);
    }

    #[test]
    fn test_remap_coded_index() {
        let mut deleted = HashSet::new();
        deleted.insert(3);

        let mut remaps = HashMap::new();
        remaps.insert(
            TableId::MethodDef,
            RidRemapper::calculate_remapping(&deleted, 10),
        );

        let mut deleted_rids = HashMap::new();
        deleted_rids.insert(TableId::MethodDef, deleted);

        let remapper = RidRemapper {
            remaps,
            tables_with_deletions: [TableId::MethodDef].into_iter().collect(),
            deleted_rids,
        };

        // Coded index pointing to MethodDef row 5 (should become 4)
        let mut ci = CodedIndex::new(TableId::MethodDef, 5, CodedIndexType::HasCustomAttribute);
        remapper.remap_coded_index(&mut ci);
        assert_eq!(ci.row, 4);
        assert_eq!(ci.token.row(), 4);

        // Coded index pointing to TypeDef (no deletions in that table)
        let mut ci2 = CodedIndex::new(TableId::TypeDef, 5, CodedIndexType::HasCustomAttribute);
        remapper.remap_coded_index(&mut ci2);
        assert_eq!(ci2.row, 5); // unchanged
    }

    #[test]
    fn test_remap_coded_index_null() {
        let remapper = RidRemapper::empty();

        // Null coded index should never be remapped
        let mut ci = CodedIndex::new(TableId::MethodDef, 0, CodedIndexType::HasCustomAttribute);
        remapper.remap_coded_index(&mut ci);
        assert_eq!(ci.row, 0);
    }

    #[test]
    fn test_typedef_remap_references() {
        let mut deleted = HashSet::new();
        deleted.insert(3); // Delete method 3

        let mut remaps = HashMap::new();
        remaps.insert(
            TableId::MethodDef,
            RidRemapper::calculate_remapping(&deleted, 10),
        );

        let mut deleted_rids = HashMap::new();
        deleted_rids.insert(TableId::MethodDef, deleted);

        let remapper = RidRemapper {
            remaps,
            tables_with_deletions: [TableId::MethodDef].into_iter().collect(),
            deleted_rids,
        };

        let mut typedef = TypeDefRaw {
            rid: 1,
            token: crate::metadata::token::Token::new(0x02000001),
            offset: 0,
            flags: 0,
            type_name: 0,
            type_namespace: 0,
            extends: CodedIndex::null(CodedIndexType::TypeDefOrRef),
            field_list: 1,
            method_list: 5, // Points to MethodDef row 5
        };

        typedef.remap_references(&remapper);

        // method_list 5 should become 4 (row 3 was deleted)
        assert_eq!(typedef.method_list, 4);
    }

    #[test]
    fn test_typedef_remap_excludes_deleted_rids() {
        // Test that typedef_remap() correctly excludes deleted TypeDefs
        // for signature remapping
        let mut deleted = HashSet::new();
        deleted.insert(3); // Delete TypeDef 3

        let mut remaps = HashMap::new();
        remaps.insert(
            TableId::TypeDef,
            RidRemapper::calculate_remapping(&deleted, 5),
        );

        let mut deleted_rids = HashMap::new();
        deleted_rids.insert(TableId::TypeDef, deleted);

        let remapper = RidRemapper {
            remaps,
            tables_with_deletions: [TableId::TypeDef].into_iter().collect(),
            deleted_rids,
        };

        // Get the signature-safe typedef remap
        let sig_remap = remapper.typedef_remap().expect("should have remap");

        // The full remap would have {3→3, 4→3, 5→4}
        // But the signature remap should NOT include 3 (the deleted row)
        assert!(
            !sig_remap.contains_key(&3),
            "deleted RID should not be in signature remap"
        );

        // Surviving rows that shifted should still be included
        assert_eq!(sig_remap.get(&4), Some(&3), "row 4 should map to 3");
        assert_eq!(sig_remap.get(&5), Some(&4), "row 5 should map to 4");
    }

    #[test]
    fn test_typedef_remap_with_no_typedef_deletions() {
        // Test that typedef_remap() returns None when only other tables have deletions
        let mut deleted = HashSet::new();
        deleted.insert(3);

        let mut remaps = HashMap::new();
        remaps.insert(
            TableId::MethodDef, // Only MethodDef has deletions, not TypeDef
            RidRemapper::calculate_remapping(&deleted, 10),
        );

        let mut deleted_rids = HashMap::new();
        deleted_rids.insert(TableId::MethodDef, deleted);

        let remapper = RidRemapper {
            remaps,
            tables_with_deletions: [TableId::MethodDef].into_iter().collect(),
            deleted_rids,
        };

        // Should return None since there are no TypeDef deletions
        assert!(remapper.typedef_remap().is_none());
    }
}
