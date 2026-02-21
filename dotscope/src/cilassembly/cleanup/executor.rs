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
            orphans::{self, DeletionContext},
            references::{collect_pre_deletion_references, scan_method_body_tokens},
            utils::{list_range, try_remove},
            CleanupRequest, CleanupStats,
        },
        CilAssembly,
    },
    metadata::{
        tables::{CustomAttributeRaw, FieldRaw, MethodDefRaw, TableId, TypeDefRaw},
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
/// println!("Removed {} types, {} methods",
///     stats.get(TableId::TypeDef), stats.get(TableId::MethodDef));
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
    let (type_methods, type_fields) = expand_type_members(assembly, request);

    // Combine explicit deletions with expanded members (using BTreeSet for sorted order)
    let mut all_methods: BTreeSet<Token> = request.methods().copied().collect();
    all_methods.extend(type_methods);

    let mut all_fields: BTreeSet<Token> = request.fields().copied().collect();
    all_fields.extend(type_fields);

    let all_types: BTreeSet<Token> = request.types().copied().collect();

    // Phase 1.5: Pre-deletion reference scan
    // Collect all tokens referenced by entities about to be deleted.
    // This must happen BEFORE deletion while method bodies and metadata
    // are still accessible. Used for cascade-based reference cleanup.
    let mut pre_refs =
        collect_pre_deletion_references(assembly, &all_methods, &all_fields, &all_types);

    // Merge rewrite-orphaned tokens (from SSA passes that neutralized calls)
    // into cascade candidates, so the existing cascade logic handles
    // MemberRef → TypeRef → AssemblyRef removal.
    pre_refs
        .il_tokens
        .extend(request.rewrite_orphaned_tokens().iter().copied());

    // Capture constructor tokens of explicitly-deleted CustomAttributes as
    // cascade candidates. These attributes may have Module as parent (not a
    // deleted type), so collect_pre_deletion_references won't capture them.
    {
        let view = assembly.view();
        if let Some(tables) = view.tables() {
            if let Some(attr_table) = tables.table::<CustomAttributeRaw>() {
                for attr_token in request.attributes() {
                    if let Some(attr) = attr_table.get(attr_token.row()) {
                        pre_refs.il_tokens.insert(attr.constructor.token);
                    }
                }
            }
        }
    }

    // Phase 2: Apply deletions in correct order
    // Track what was actually removed for deletion context
    let mut removed_types: HashSet<Token> = HashSet::new();
    let mut removed_methods: HashSet<Token> = HashSet::new();
    let mut removed_fields: HashSet<Token> = HashSet::new();

    // 2a: Remove methods (in descending RID order to avoid shifting issues)
    for method_token in all_methods.iter().rev() {
        if try_remove(assembly, TableId::MethodDef, method_token.row()) {
            removed_methods.insert(*method_token);
            stats.add(TableId::MethodDef, 1);
        }
    }

    // 2b: Remove MethodSpecs (in descending RID order)
    for spec_token in request.methodspecs() {
        if try_remove(assembly, TableId::MethodSpec, spec_token.row()) {
            stats.add(TableId::MethodSpec, 1);
        }
    }

    // 2c: Remove fields (in descending RID order)
    for field_token in all_fields.iter().rev() {
        if try_remove(assembly, TableId::Field, field_token.row()) {
            removed_fields.insert(*field_token);
            stats.add(TableId::Field, 1);
        }
    }

    // 2d: Remove types (in descending RID order)
    for type_token in request.types() {
        if try_remove(assembly, TableId::TypeDef, type_token.row()) {
            removed_types.insert(*type_token);
            stats.add(TableId::TypeDef, 1);
        }
    }

    // 2e: Remove explicit attributes (in descending RID order)
    for attr_token in request.attributes() {
        if try_remove(assembly, TableId::CustomAttribute, attr_token.row()) {
            stats.add(TableId::CustomAttribute, 1);
        }
    }

    // 2f: Remove AssemblyRefs (in descending RID order)
    for asmref_token in request.assemblyrefs() {
        if try_remove(assembly, TableId::AssemblyRef, asmref_token.row()) {
            stats.add(TableId::AssemblyRef, 1);
        }
    }

    // 2g: Remove ModuleRefs (in descending RID order)
    for modref_token in request.modulerefs() {
        if try_remove(assembly, TableId::ModuleRef, modref_token.row()) {
            stats.add(TableId::ModuleRef, 1);
        }
    }

    // Cache body tokens once — used by both Phase 3 and Phase 4.
    // Since Phase 3 only removes empty types (which by definition have NO methods),
    // the body token set is identical between the two calls.
    let body_tokens = scan_method_body_tokens(assembly);

    // Phase 3: Remove empty types (if enabled)
    // This MUST run before cascade reference cleanup (Phase 4) so that
    // TypeRef/AssemblyRef entries referenced only by empty types (e.g.,
    // System.ValueType for empty structs) are properly cascade-removed.
    if request.remove_empty_types() {
        let (empty_removed, empty_type_tokens) = remove_empty_types(assembly, &body_tokens);
        stats.add(TableId::TypeDef, empty_removed);

        if !empty_type_tokens.is_empty() {
            // Track empty type deletions for deletion context
            removed_types.extend(empty_type_tokens.iter().copied());

            let empty_methods = HashSet::new();
            let empty_fields = HashSet::new();
            let empty_ctx = DeletionContext::new(&empty_type_tokens, &empty_methods, &empty_fields);
            let type_dep_stats = orphans::remove_type_dependents(assembly, &empty_ctx);
            stats.merge(&type_dep_stats);
        }
    }

    // Phase 4: Remove dependent metadata and cascade references (if enabled)
    if request.remove_orphans() {
        let ctx = DeletionContext::new(&removed_types, &removed_methods, &removed_fields);
        let orphan_stats = orphans::remove_parent_child_dependents(assembly, &ctx, &pre_refs);
        stats.merge(&orphan_stats);

        let cascade_stats = orphans::cascade_reference_cleanup(assembly, &pre_refs, &body_tokens);
        stats.merge(&cascade_stats);
    }

    // Phase 5: Compact heaps (mark unreferenced entries for removal)
    // Currently only compacts #Blob and #GUID heaps. #Strings heap compaction
    // is disabled due to the substring reference problem - see compaction.rs docs.
    let compaction_stats = mark_unreferenced_heap_entries(assembly)?;
    stats.blobs_compacted = compaction_stats.blobs;
    stats.guids_compacted = compaction_stats.guids;
    stats.strings_compacted = compaction_stats.strings;

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
) -> (HashSet<Token>, HashSet<Token>) {
    let mut methods = HashSet::new();
    let mut fields = HashSet::new();

    let view = assembly.view();
    let Some(tables) = view.tables() else {
        return (methods, fields);
    };

    let Some(typedef_table) = tables.table::<TypeDefRaw>() else {
        return (methods, fields);
    };

    let methoddef_count = tables.table::<MethodDefRaw>().map_or(0, |t| t.row_count);
    let field_count = tables.table::<FieldRaw>().map_or(0, |t| t.row_count);
    let type_count = typedef_table.row_count;

    for type_token in request.types() {
        let type_rid = type_token.row();

        let Some(typedef) = typedef_table.get(type_rid) else {
            continue;
        };

        // Get method range for this type
        let method_range = list_range(type_rid, type_count, methoddef_count, |rid| {
            typedef_table.get(rid).map(|t| t.method_list)
        });
        // Override start with actual typedef's method_list
        for method_rid in typedef.method_list..method_range.end {
            methods.insert(Token::from_parts(TableId::MethodDef, method_rid));
        }

        // Get field range for this type
        let field_range = list_range(type_rid, type_count, field_count, |rid| {
            typedef_table.get(rid).map(|t| t.field_list)
        });
        // Override start with actual typedef's field_list
        for field_rid in typedef.field_list..field_range.end {
            fields.insert(Token::from_parts(TableId::Field, field_rid));
        }
    }

    (methods, fields)
}

/// Removes types that have no remaining methods or fields.
///
/// After cleanup, some types may become empty shells with no members.
/// This function identifies and removes such types, returning both the
/// count and the set of removed type tokens for cascading cleanup.
///
/// # Arguments
///
/// * `assembly` - The assembly to modify
/// * `body_tokens` - Pre-computed set of tokens referenced from method bodies
///
/// # Returns
///
/// A tuple of (count of empty types removed, set of removed type tokens).
fn remove_empty_types(
    assembly: &mut CilAssembly,
    body_tokens: &HashSet<Token>,
) -> (usize, HashSet<Token>) {
    // Collect all TypeDef RIDs referenced in method bodies — these must not be removed
    // even if they have no methods/fields (e.g., value types used with newarr/box/unbox).
    let referenced_typedefs: HashSet<u32> = body_tokens
        .iter()
        .filter(|t| t.is_table(TableId::TypeDef))
        .map(|t| t.row())
        .collect();

    // Collect empty type RIDs
    let empty_types: Vec<u32> = {
        let view = assembly.view();
        let Some(tables) = view.tables() else {
            return (0, HashSet::new());
        };

        let Some(typedef_table) = tables.table::<TypeDefRaw>() else {
            return (0, HashSet::new());
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

            // Skip types that are still referenced in method bodies
            if referenced_typedefs.contains(&type_rid) {
                continue;
            }

            // Calculate method count for this type
            let method_range = list_range(type_rid, type_count, methoddef_count, |rid| {
                typedef_table.get(rid).map(|t| t.method_list)
            });
            let method_count = method_range.end.saturating_sub(typedef.method_list);

            // Calculate field count for this type
            let field_range = list_range(type_rid, type_count, field_count, |rid| {
                typedef_table.get(rid).map(|t| t.field_list)
            });
            let field_count_type = field_range.end.saturating_sub(typedef.field_list);

            // Type is empty if it has no methods and no fields
            if method_count == 0 && field_count_type == 0 {
                empty.push(type_rid);
            }
        }

        empty
    };

    // Remove empty types (in reverse RID order)
    let mut removed = 0;
    let mut removed_tokens = HashSet::new();
    for rid in empty_types.into_iter().rev() {
        if try_remove(assembly, TableId::TypeDef, rid) {
            removed += 1;
            removed_tokens.insert(Token::from_parts(TableId::TypeDef, rid));
        }
    }

    (removed, removed_tokens)
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
