//! Statistics tracking for cleanup operations.
//!
//! Provides [`CleanupStats`] to track what was removed during cleanup,
//! useful for reporting and debugging.

use std::fmt;

/// Statistics from a cleanup operation.
///
/// Tracks the number of items removed in each category, providing
/// visibility into what the cleanup process accomplished.
#[derive(Debug, Clone, Default)]
pub struct CleanupStats {
    /// Number of types (TypeDef) removed.
    pub types_removed: usize,
    /// Number of methods (MethodDef) removed.
    pub methods_removed: usize,
    /// Number of MethodSpecs removed.
    pub methodspecs_removed: usize,
    /// Number of fields removed.
    pub fields_removed: usize,
    /// Number of custom attributes removed.
    pub attributes_removed: usize,
    /// Number of parameters (Param) removed.
    pub params_removed: usize,
    /// Number of StandAloneSig entries removed.
    pub standalonesigs_removed: usize,
    /// Number of GenericParam entries removed.
    pub genericparams_removed: usize,
    /// Number of GenericParamConstraint entries removed.
    pub genericparam_constraints_removed: usize,
    /// Number of InterfaceImpl entries removed.
    pub interfaceimpls_removed: usize,
    /// Number of MethodImpl entries removed.
    pub methodimpls_removed: usize,
    /// Number of MethodSemantics entries removed.
    pub methodsemantics_removed: usize,
    /// Number of NestedClass entries removed.
    pub nestedclasses_removed: usize,
    /// Number of ClassLayout entries removed.
    pub classlayouts_removed: usize,
    /// Number of FieldRVA entries removed.
    pub fieldrvas_removed: usize,
    /// Number of FieldLayout entries removed.
    pub fieldlayouts_removed: usize,
    /// Number of FieldMarshal entries removed.
    pub fieldmarshals_removed: usize,
    /// Number of Constant entries removed.
    pub constants_removed: usize,
    /// Number of DeclSecurity entries removed.
    pub declsecurities_removed: usize,
    /// Number of ImplMap entries removed.
    pub implmaps_removed: usize,
    /// Number of EventMap entries removed.
    pub eventmaps_removed: usize,
    /// Number of PropertyMap entries removed.
    pub propertymaps_removed: usize,
    /// Number of TypeRef entries removed (orphaned).
    pub typerefs_removed: usize,
    /// Number of MemberRef entries removed (orphaned).
    pub memberrefs_removed: usize,
    /// Number of TypeSpec entries removed (orphaned).
    pub typespecs_removed: usize,
    /// Number of PE sections excluded.
    pub sections_excluded: usize,
    /// Number of unreferenced string heap entries marked for removal.
    pub strings_compacted: usize,
    /// Number of unreferenced blob heap entries marked for removal.
    pub blobs_compacted: usize,
    /// Number of unreferenced GUID heap entries marked for removal.
    pub guids_compacted: usize,
}

impl CleanupStats {
    /// Creates a new empty stats instance.
    ///
    /// All counters are initialized to zero.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the total number of metadata entries removed.
    ///
    /// This includes all table entries: types, methods, fields, attributes,
    /// parameters, signatures, and all orphaned metadata entries.
    #[must_use]
    pub fn total_removed(&self) -> usize {
        self.types_removed
            + self.methods_removed
            + self.methodspecs_removed
            + self.fields_removed
            + self.attributes_removed
            + self.params_removed
            + self.standalonesigs_removed
            + self.genericparams_removed
            + self.genericparam_constraints_removed
            + self.interfaceimpls_removed
            + self.methodimpls_removed
            + self.methodsemantics_removed
            + self.nestedclasses_removed
            + self.classlayouts_removed
            + self.fieldrvas_removed
            + self.fieldlayouts_removed
            + self.fieldmarshals_removed
            + self.constants_removed
            + self.declsecurities_removed
            + self.implmaps_removed
            + self.eventmaps_removed
            + self.propertymaps_removed
            + self.typerefs_removed
            + self.memberrefs_removed
            + self.typespecs_removed
    }

    /// Returns true if any items were removed or sections excluded.
    ///
    /// Checks all removal counters, section exclusions, and heap compaction.
    #[must_use]
    pub fn has_changes(&self) -> bool {
        self.total_removed() > 0 || self.sections_excluded > 0 || self.heap_entries_compacted() > 0
    }

    /// Returns the total number of heap entries marked for compaction.
    ///
    /// This is the sum of compacted strings, blobs, and GUIDs.
    #[must_use]
    pub fn heap_entries_compacted(&self) -> usize {
        self.strings_compacted + self.blobs_compacted + self.guids_compacted
    }

    /// Returns the count of primary items removed (types, methods, fields).
    ///
    /// Primary items are the main metadata entries that were explicitly deleted,
    /// as opposed to orphaned entries that were removed as a consequence.
    #[must_use]
    pub fn primary_removed(&self) -> usize {
        self.types_removed + self.methods_removed + self.fields_removed
    }

    /// Returns the count of orphaned metadata entries removed.
    ///
    /// Orphaned entries are metadata that became unreferenced after the
    /// primary deletions were applied (e.g., parameters of deleted methods).
    #[must_use]
    pub fn orphans_removed(&self) -> usize {
        self.total_removed() - self.primary_removed() - self.attributes_removed
    }

    /// Merges stats from another cleanup operation into this one.
    ///
    /// All counters from `other` are added to the corresponding counters
    /// in `self`. This is useful when combining stats from multiple passes.
    pub fn merge(&mut self, other: &CleanupStats) {
        self.types_removed += other.types_removed;
        self.methods_removed += other.methods_removed;
        self.methodspecs_removed += other.methodspecs_removed;
        self.fields_removed += other.fields_removed;
        self.attributes_removed += other.attributes_removed;
        self.params_removed += other.params_removed;
        self.standalonesigs_removed += other.standalonesigs_removed;
        self.genericparams_removed += other.genericparams_removed;
        self.genericparam_constraints_removed += other.genericparam_constraints_removed;
        self.interfaceimpls_removed += other.interfaceimpls_removed;
        self.methodimpls_removed += other.methodimpls_removed;
        self.methodsemantics_removed += other.methodsemantics_removed;
        self.nestedclasses_removed += other.nestedclasses_removed;
        self.classlayouts_removed += other.classlayouts_removed;
        self.fieldrvas_removed += other.fieldrvas_removed;
        self.fieldlayouts_removed += other.fieldlayouts_removed;
        self.fieldmarshals_removed += other.fieldmarshals_removed;
        self.constants_removed += other.constants_removed;
        self.declsecurities_removed += other.declsecurities_removed;
        self.implmaps_removed += other.implmaps_removed;
        self.eventmaps_removed += other.eventmaps_removed;
        self.propertymaps_removed += other.propertymaps_removed;
        self.typerefs_removed += other.typerefs_removed;
        self.memberrefs_removed += other.memberrefs_removed;
        self.typespecs_removed += other.typespecs_removed;
        self.sections_excluded += other.sections_excluded;
        self.strings_compacted += other.strings_compacted;
        self.blobs_compacted += other.blobs_compacted;
        self.guids_compacted += other.guids_compacted;
    }
}

impl fmt::Display for CleanupStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if !self.has_changes() {
            return write!(f, "No changes");
        }

        let mut parts = Vec::new();

        if self.types_removed > 0 {
            parts.push(format!("{} types", self.types_removed));
        }
        if self.methods_removed > 0 {
            parts.push(format!("{} methods", self.methods_removed));
        }
        if self.fields_removed > 0 {
            parts.push(format!("{} fields", self.fields_removed));
        }
        if self.attributes_removed > 0 {
            parts.push(format!("{} attributes", self.attributes_removed));
        }

        let orphans = self.orphans_removed();
        if orphans > 0 {
            parts.push(format!("{} orphaned entries", orphans));
        }

        if self.sections_excluded > 0 {
            parts.push(format!("{} sections excluded", self.sections_excluded));
        }

        let heap_compacted = self.heap_entries_compacted();
        if heap_compacted > 0 {
            parts.push(format!("{} heap entries compacted", heap_compacted));
        }

        write!(f, "Removed: {}", parts.join(", "))
    }
}

#[cfg(test)]
mod tests {
    use crate::cilassembly::cleanup::CleanupStats;

    #[test]
    fn test_stats_default() {
        let stats = CleanupStats::new();
        assert_eq!(stats.total_removed(), 0);
        assert!(!stats.has_changes());
    }

    #[test]
    fn test_stats_counting() {
        let mut stats = CleanupStats::new();
        stats.types_removed = 5;
        stats.methods_removed = 10;
        stats.params_removed = 20;

        assert_eq!(stats.primary_removed(), 15);
        assert_eq!(stats.orphans_removed(), 20);
        assert_eq!(stats.total_removed(), 35);
        assert!(stats.has_changes());
    }

    #[test]
    fn test_stats_merge() {
        let mut stats1 = CleanupStats::new();
        stats1.types_removed = 5;

        let mut stats2 = CleanupStats::new();
        stats2.methods_removed = 10;

        stats1.merge(&stats2);

        assert_eq!(stats1.types_removed, 5);
        assert_eq!(stats1.methods_removed, 10);
    }

    #[test]
    fn test_stats_display() {
        let mut stats = CleanupStats::new();
        stats.types_removed = 3;
        stats.methods_removed = 7;
        stats.params_removed = 15;

        let display = stats.to_string();
        assert!(display.contains("3 types"));
        assert!(display.contains("7 methods"));
        assert!(display.contains("orphaned"));
    }

    #[test]
    fn test_stats_display_empty() {
        let stats = CleanupStats::new();
        assert_eq!(stats.to_string(), "No changes");
    }
}
