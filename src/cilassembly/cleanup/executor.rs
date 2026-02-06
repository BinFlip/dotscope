//! Cleanup execution logic for applying cleanup requests.
//!
//! This module provides the main entry point for executing cleanup operations
//! on a [`CilAssembly`]. It coordinates the process of:
//!
//! 1. Expanding type deletions to include all their members
//! 2. Applying explicit deletions to the assembly changes
//! 3. Removing orphaned metadata entries
//!
//! The executor ensures deletions are applied in the correct order to maintain
//! referential integrity and avoid RID shifting issues.

use std::collections::{BTreeSet, HashSet};

use crate::{
    cilassembly::{
        cleanup::{
            compaction::mark_unreferenced_heap_entries,
            orphans::{remove_all_orphans, OrphanContext},
            CleanupRequest, CleanupStats,
        },
        CilAssembly,
    },
    metadata::{
        tables::{FieldRaw, MethodDefRaw, TableId, TypeDefRaw},
        token::Token,
    },
    Result,
};

/// Executes cleanup operations on a [`CilAssembly`].
///
/// This is the main entry point for cleanup. It processes the [`CleanupRequest`],
/// applying all specified deletions and removing orphaned metadata.
///
/// # Process
///
/// 1. **Expand types**: When a type is marked for deletion, all its methods
///    and fields are also collected for deletion.
///
/// 2. **Apply deletions**: Deletions are applied in order:
///    - Methods (sorted by RID descending)
///    - MethodSpecs (sorted by RID descending)
///    - Fields (sorted by RID descending)
///    - Types (sorted by RID descending)
///    - Attributes
///
/// 3. **Remove orphans**: If `remove_orphans` is enabled, cascading orphan
///    removal is performed for all related metadata tables.
///
/// # Arguments
///
/// * `assembly` - The assembly to modify
/// * `request` - The cleanup request specifying what to delete
///
/// # Returns
///
/// Statistics about what was removed.
///
/// # Example
///
/// ```rust,ignore
/// use dotscope::cilassembly::cleanup::{CleanupRequest, execute_cleanup};
///
/// let mut request = CleanupRequest::new();
/// request.add_type(protection_type_token);
///
/// let stats = execute_cleanup(&mut assembly, &request)?;
/// println!("Removed {} types, {} methods", stats.types_removed, stats.methods_removed);
/// ```
pub fn execute_cleanup(
    assembly: &mut CilAssembly,
    request: &CleanupRequest,
) -> Result<CleanupStats> {
    let mut stats = CleanupStats::new();

    if request.is_empty() {
        return Ok(stats);
    }

    // Phase 1: Expand type deletions to include all members
    let (type_methods, type_fields) = expand_type_members(assembly, request)?;

    // Combine explicit deletions with expanded members (using BTreeSet for sorted order)
    let mut all_methods: BTreeSet<Token> = request.methods().copied().collect();
    all_methods.extend(type_methods);

    let mut all_fields: BTreeSet<Token> = request.fields().copied().collect();
    all_fields.extend(type_fields);

    // Phase 2: Apply deletions in correct order
    // Track what was actually removed for orphan context
    let mut removed_types: HashSet<Token> = HashSet::new();
    let mut removed_methods: HashSet<Token> = HashSet::new();
    let mut removed_fields: HashSet<Token> = HashSet::new();

    // 2a: Remove methods (in descending RID order to avoid shifting issues)
    for method_token in all_methods.iter().rev() {
        if assembly
            .table_row_remove(TableId::MethodDef, method_token.row())
            .is_ok()
        {
            removed_methods.insert(*method_token);
            stats.methods_removed += 1;
        }
    }

    // 2b: Remove MethodSpecs (in descending RID order)
    for spec_token in request.methodspecs() {
        if assembly
            .table_row_remove(TableId::MethodSpec, spec_token.row())
            .is_ok()
        {
            stats.methodspecs_removed += 1;
        }
    }

    // 2c: Remove fields (in descending RID order)
    for field_token in all_fields.iter().rev() {
        if assembly
            .table_row_remove(TableId::Field, field_token.row())
            .is_ok()
        {
            removed_fields.insert(*field_token);
            stats.fields_removed += 1;
        }
    }

    // 2d: Remove types (in descending RID order)
    for type_token in request.types() {
        if assembly
            .table_row_remove(TableId::TypeDef, type_token.row())
            .is_ok()
        {
            removed_types.insert(*type_token);
            stats.types_removed += 1;
        }
    }

    // 2e: Remove explicit attributes (in descending RID order)
    for attr_token in request.attributes() {
        if assembly
            .table_row_remove(TableId::CustomAttribute, attr_token.row())
            .is_ok()
        {
            stats.attributes_removed += 1;
        }
    }

    // Phase 3: Remove orphaned metadata (if enabled)
    if request.remove_orphans() {
        let ctx = OrphanContext::new(&removed_types, &removed_methods, &removed_fields);
        let orphan_stats = remove_all_orphans(assembly, &ctx)?;
        stats.merge(&orphan_stats);
    }

    // Phase 4: Remove empty types (if enabled)
    if request.remove_empty_types() {
        let empty_removed = remove_empty_types(assembly)?;
        stats.types_removed += empty_removed;
    }

    // Phase 5: Compact heaps (mark unreferenced entries for removal)
    // Currently only compacts #Blob and #GUID heaps. #Strings heap compaction
    // is disabled due to the substring reference problem - see compaction.rs docs.
    let compaction_stats = mark_unreferenced_heap_entries(assembly)?;
    stats.blobs_compacted = compaction_stats.blobs_removed;
    stats.guids_compacted = compaction_stats.guids_removed;
    stats.strings_compacted = compaction_stats.strings_removed;

    // Track excluded sections count
    stats.sections_excluded = request.excluded_sections().len();

    Ok(stats)
}

/// Expands type deletions to include all their members.
///
/// For each type marked for deletion, collects all its methods and fields
/// so they can be deleted along with the type.
///
/// # Arguments
///
/// * `assembly` - The assembly to read type information from
/// * `request` - The cleanup request containing types to delete
///
/// # Returns
///
/// A tuple of (methods_to_delete, fields_to_delete) tokens.
fn expand_type_members(
    assembly: &CilAssembly,
    request: &CleanupRequest,
) -> Result<(HashSet<Token>, HashSet<Token>)> {
    let mut methods = HashSet::new();
    let mut fields = HashSet::new();

    let view = assembly.view();
    let Some(tables) = view.tables() else {
        return Ok((methods, fields));
    };

    let Some(typedef_table) = tables.table::<TypeDefRaw>() else {
        return Ok((methods, fields));
    };

    let methoddef_table = tables.table::<MethodDefRaw>();
    let field_table = tables.table::<FieldRaw>();

    let type_count = typedef_table.row_count;

    for type_token in request.types() {
        let type_rid = type_token.row();

        let Some(typedef) = typedef_table.get(type_rid) else {
            continue;
        };

        // Get method range for this type
        if let Some(methoddef_table) = &methoddef_table {
            let method_start = typedef.method_list;
            let method_end = if type_rid < type_count {
                typedef_table
                    .get(type_rid + 1)
                    .map_or(methoddef_table.row_count + 1, |t| t.method_list)
            } else {
                methoddef_table.row_count + 1
            };

            for method_rid in method_start..method_end {
                methods.insert(Token::from_parts(TableId::MethodDef, method_rid));
            }
        }

        // Get field range for this type
        if let Some(field_table) = &field_table {
            let field_start = typedef.field_list;
            let field_end = if type_rid < type_count {
                typedef_table
                    .get(type_rid + 1)
                    .map_or(field_table.row_count + 1, |t| t.field_list)
            } else {
                field_table.row_count + 1
            };

            for field_rid in field_start..field_end {
                fields.insert(Token::from_parts(TableId::Field, field_rid));
            }
        }
    }

    Ok((methods, fields))
}

/// Removes types that have no remaining methods or fields.
///
/// After cleanup, some types may become empty shells with no members.
/// This function identifies and removes such types.
///
/// # Arguments
///
/// * `assembly` - The assembly to modify
///
/// # Returns
///
/// The number of empty types removed.
fn remove_empty_types(assembly: &mut CilAssembly) -> Result<usize> {
    // Collect empty type RIDs
    let empty_types: Vec<u32> = {
        let view = assembly.view();
        let Some(tables) = view.tables() else {
            return Ok(0);
        };

        let Some(typedef_table) = tables.table::<TypeDefRaw>() else {
            return Ok(0);
        };

        let methoddef_count = tables.table::<MethodDefRaw>().map_or(0, |t| t.row_count);
        let field_count = tables.table::<FieldRaw>().map_or(0, |t| t.row_count);

        let type_count = typedef_table.row_count;

        let mut empty = Vec::new();

        for type_rid in 1..=type_count {
            let Some(typedef) = typedef_table.get(type_rid) else {
                continue;
            };

            // Skip <Module> (RID 1) - it's special
            if type_rid == 1 {
                continue;
            }

            // Calculate method count for this type
            let method_start = typedef.method_list;
            let method_end = if type_rid < type_count {
                typedef_table
                    .get(type_rid + 1)
                    .map_or(methoddef_count + 1, |t| t.method_list)
            } else {
                methoddef_count + 1
            };
            let method_count = method_end.saturating_sub(method_start);

            // Calculate field count for this type
            let field_start = typedef.field_list;
            let field_end = if type_rid < type_count {
                typedef_table
                    .get(type_rid + 1)
                    .map_or(field_count + 1, |t| t.field_list)
            } else {
                field_count + 1
            };
            let field_count_type = field_end.saturating_sub(field_start);

            // Type is empty if it has no methods and no fields
            if method_count == 0 && field_count_type == 0 {
                empty.push(type_rid);
            }
        }

        empty
    };

    // Remove empty types (in reverse RID order)
    let mut removed = 0;
    for rid in empty_types.into_iter().rev() {
        if assembly.table_row_remove(TableId::TypeDef, rid).is_ok() {
            removed += 1;
        }
    }

    Ok(removed)
}

#[cfg(test)]
mod tests {
    use crate::{
        cilassembly::cleanup::CleanupRequest,
        metadata::{tables::TableId, token::Token},
    };

    #[test]
    fn test_execute_cleanup_empty_request() {
        // This test would require a real assembly, so we just verify
        // the function signature and basic logic
        let request = CleanupRequest::new();
        assert!(request.is_empty());
    }

    #[test]
    fn test_cleanup_request_with_types() {
        let mut request = CleanupRequest::new();
        request.add_type(Token::from_parts(TableId::TypeDef, 5));
        request.add_method(Token::from_parts(TableId::MethodDef, 10));

        assert!(!request.is_empty());
        assert_eq!(request.types_len(), 1);
        assert_eq!(request.methods_len(), 1);
    }
}
