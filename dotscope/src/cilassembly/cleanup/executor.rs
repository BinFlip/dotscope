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
            references::{
                collect_pre_deletion_references, collect_typedefs_from_field_signatures,
                scan_method_body_tokens,
            },
            utils::{is_cctor_method, list_range, try_remove},
            CleanupRequest, CleanupStats,
        },
        CilAssembly,
    },
    metadata::{
        tables::{
            CustomAttributeRaw, FieldRaw, InterfaceImplRaw, MethodDefRaw, MethodImplRaw,
            MethodSemanticsRaw, MethodSpecRaw, TableId, TypeDefRaw,
        },
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
        if request.is_protected(*method_token) {
            continue;
        }
        if try_remove(assembly, TableId::MethodDef, method_token.row()) {
            removed_methods.insert(*method_token);
            stats.add(TableId::MethodDef, 1);
        }
    }

    // 2b: Remove MethodSpecs (in descending RID order)
    for spec_token in request.methodspecs() {
        if request.is_protected(*spec_token) {
            continue;
        }
        if try_remove(assembly, TableId::MethodSpec, spec_token.row()) {
            stats.add(TableId::MethodSpec, 1);
        }
    }

    // 2c: Remove fields (in descending RID order)
    for field_token in all_fields.iter().rev() {
        if request.is_protected(*field_token) {
            continue;
        }
        if try_remove(assembly, TableId::Field, field_token.row()) {
            removed_fields.insert(*field_token);
            stats.add(TableId::Field, 1);
        }
    }

    // Cache body tokens before type removal. This includes:
    // - Token operands from IL bytecode of surviving methods
    // - TypeDef/TypeRef tokens from StandAloneSig blobs (local variable signatures)
    // The latter ensures types referenced only via local variable types are protected
    // from removal, preventing dangling StandAloneSig references in the output.
    let body_tokens = scan_method_body_tokens(assembly);

    // Collect TypeDef RIDs that are still referenced by surviving method signatures.
    // These must not be removed even if explicitly requested, because their removal
    // would leave invalid type references in StandAloneSig blobs.
    let sig_referenced_typedefs: HashSet<u32> = body_tokens
        .iter()
        .filter(|t| t.is_table(TableId::TypeDef))
        .map(|t| t.row())
        .collect();

    // 2d: Remove types (in descending RID order)
    for type_token in request.types() {
        if request.is_protected(*type_token) {
            continue;
        }
        if sig_referenced_typedefs.contains(&type_token.row()) {
            continue;
        }
        if try_remove(assembly, TableId::TypeDef, type_token.row()) {
            removed_types.insert(*type_token);
            stats.add(TableId::TypeDef, 1);
        }
    }

    // 2d+: Cascade-delete nested types whose enclosing type was deleted.
    // Without this, nested types survive as orphaned TypeDefs after their
    // enclosing type is removed. Their members (methods, fields) must also
    // be removed.
    let orphaned_nested = orphans::collect_orphaned_nested_types(
        assembly,
        &DeletionContext::new(&removed_types, &removed_methods, &removed_fields),
    );
    if !orphaned_nested.is_empty() {
        // Expand nested types to their members
        let (nested_methods, nested_fields) = {
            let mut nested_request = CleanupRequest::new();
            for &t in &orphaned_nested {
                nested_request.add_type(t);
            }
            expand_type_members(assembly, &nested_request)
        };

        // Remove nested type members (descending RID)
        let mut nested_methods_sorted: Vec<_> = nested_methods.into_iter().collect();
        nested_methods_sorted.sort_by(|a, b| b.cmp(a));
        for method_token in &nested_methods_sorted {
            if try_remove(assembly, TableId::MethodDef, method_token.row()) {
                removed_methods.insert(*method_token);
                stats.add(TableId::MethodDef, 1);
            }
        }
        let mut nested_fields_sorted: Vec<_> = nested_fields.into_iter().collect();
        nested_fields_sorted.sort_by(|a, b| b.cmp(a));
        for field_token in &nested_fields_sorted {
            if try_remove(assembly, TableId::Field, field_token.row()) {
                removed_fields.insert(*field_token);
                stats.add(TableId::Field, 1);
            }
        }

        // Remove the nested TypeDefs themselves (descending RID)
        let mut sorted_nested: Vec<_> = orphaned_nested.clone();
        sorted_nested.sort_by_key(|t| std::cmp::Reverse(t.row()));
        for type_token in &sorted_nested {
            if try_remove(assembly, TableId::TypeDef, type_token.row()) {
                removed_types.insert(*type_token);
                stats.add(TableId::TypeDef, 1);
            }
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

    // 2h: Remove explicit ManifestResource rows (in descending RID order).
    //
    // This handles embedded resources whose payload lives in the PE's CLR
    // resource section. For rows with a non-zero `implementation` target,
    // this is still safe — the row is marked deleted and the generic
    // orphan sweep (`remove_orphan_manifestresources`) is a no-op for an
    // already-deleted row. Embedded payload bytes are dropped
    // automatically during PE regeneration: the writer's resource-section
    // compaction loop consults `is_row_deleted(TableId::ManifestResource, rid)`
    // and skips the entry, then rewrites `offset_field` on surviving rows
    // via `resource_offset_remap`.
    for res_token in request.manifest_resources() {
        if try_remove(assembly, TableId::ManifestResource, res_token.row()) {
            stats.add(TableId::ManifestResource, 1);
        }
    }

    // Phase 2.5: Dead definition elimination (unified fixpoint).
    //
    // After explicit deletions, methods and fields that were ONLY referenced
    // by the deleted entities become unreferenced. The cascade principle:
    // "if something was referenced by deleted entities and is no longer
    // referenced by any surviving entity, it is dead and should be removed."
    //
    // A MethodDef is considered "still alive" if it is referenced by ANY of:
    // - IL bytecode in a surviving method body (call, callvirt, newobj, etc.)
    // - MethodSpec.method (generic instantiation)
    // - CustomAttribute.constructor (attribute constructor)
    // - MethodSemantics.method (property getter/setter, event add/remove)
    // - MethodImpl.method_body or method_declaration (explicit overrides)
    //
    // A Field is considered "still alive" if it is referenced from any
    // surviving method's IL (ldfld, stfld, ldsfld, stsfld, ldflda, ldsflda).
    //
    // This is a fixpoint loop because each round of cascade-deleted definitions
    // may reveal further unreferenced definitions (transitive chains).
    if request.remove_orphans() {
        const MAX_CASCADE_ROUNDS: usize = 10;
        for _round in 0..MAX_CASCADE_ROUNDS {
            // Compute the full set of alive tokens from both IL bytecode
            // and all metadata tables that reference methods/fields.
            let alive_methods = collect_alive_method_tokens(assembly);
            let alive_fields = collect_alive_field_tokens(assembly);

            // Find MethodDef tokens from pre_refs that are no longer referenced
            // by any surviving entity.
            let dead_methods: Vec<Token> = pre_refs
                .il_tokens
                .iter()
                .filter(|t| t.is_table(TableId::MethodDef))
                .filter(|t| !alive_methods.contains(t))
                .filter(|t| !removed_methods.contains(t))
                .filter(|t| {
                    !assembly
                        .changes()
                        .is_row_deleted(TableId::MethodDef, t.row())
                })
                // Safety: never cascade-remove .cctor methods — they are
                // invoked by the runtime on first type access, not via IL.
                .filter(|t| !is_cctor_method(assembly, t.row()))
                .filter(|t| !request.is_protected(**t))
                .copied()
                .collect();

            // Find Field tokens from pre_refs that are no longer referenced
            // by any surviving entity. Only cascade-remove fields that appear
            // in pre_refs (were referenced by explicitly or previously deleted
            // entities) to avoid removing pre-existing unreferenced fields
            // that may be used via reflection.
            let dead_fields: Vec<Token> = pre_refs
                .il_tokens
                .iter()
                .filter(|t| t.is_table(TableId::Field))
                .filter(|t| !alive_fields.contains(t))
                .filter(|t| !removed_fields.contains(t))
                .filter(|t| !assembly.changes().is_row_deleted(TableId::Field, t.row()))
                .filter(|t| !request.is_protected(**t))
                .copied()
                .collect();

            if dead_methods.is_empty() && dead_fields.is_empty() {
                break;
            }

            // Collect pre-deletion refs from dead definitions BEFORE deleting
            // them, so their references feed into subsequent cascade rounds
            // and the MemberRef/TypeRef cascade.
            let dead_methods_set: BTreeSet<Token> = dead_methods.iter().copied().collect();
            let dead_fields_set: BTreeSet<Token> = dead_fields.iter().copied().collect();
            let empty_types = BTreeSet::new();
            let new_refs = collect_pre_deletion_references(
                assembly,
                &dead_methods_set,
                &dead_fields_set,
                &empty_types,
            );
            pre_refs.il_tokens.extend(new_refs.il_tokens);
            pre_refs.typeref_rids.extend(new_refs.typeref_rids);
            pre_refs
                .standalonesig_rids
                .extend(new_refs.standalonesig_rids);

            // Delete methods in reverse RID order to avoid shifting issues.
            let mut method_count = 0usize;
            for token in dead_methods.iter().rev() {
                if try_remove(assembly, TableId::MethodDef, token.row()) {
                    removed_methods.insert(*token);
                    method_count += 1;
                }
            }
            stats.add(TableId::MethodDef, method_count);

            // Delete fields in reverse RID order.
            let mut field_count = 0usize;
            for token in dead_fields.iter().rev() {
                if try_remove(assembly, TableId::Field, token.row()) {
                    removed_fields.insert(*token);
                    field_count += 1;
                }
            }
            stats.add(TableId::Field, field_count);
        }
    }

    // Rescan body tokens after MethodDef cascade — the set may have changed
    // significantly and both Phase 3 (empty types) and Phase 4 (reference
    // cascade) need an accurate snapshot.
    let body_tokens = scan_method_body_tokens(assembly);

    // Phase 3: Remove empty types (if enabled)
    // This MUST run before cascade reference cleanup (Phase 4) so that
    // TypeRef/AssemblyRef entries referenced only by empty types (e.g.,
    // System.ValueType for empty structs) are properly cascade-removed.
    if request.remove_empty_types() {
        let (empty_removed, empty_type_tokens) =
            remove_empty_types(assembly, &body_tokens, request);
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
    request: &CleanupRequest,
) -> (usize, HashSet<Token>) {
    // Collect all TypeDef RIDs referenced in method bodies — these must not be removed
    // even if they have no methods/fields (e.g., value types used with newarr/box/unbox).
    let mut referenced_typedefs: HashSet<u32> = body_tokens
        .iter()
        .filter(|t| t.is_table(TableId::TypeDef))
        .map(|t| t.row())
        .collect();

    // Also collect TypeDef RIDs referenced by surviving field signatures.
    // Types like `__StaticArrayInitTypeSize=N` have no methods/fields of their
    // own but are referenced from FieldDef signature blobs (e.g., for
    // RuntimeHelpers.InitializeArray backing fields). Without this, they'd be
    // incorrectly removed as "empty types", leaving dangling blob references.
    let field_sig_refs = collect_typedefs_from_field_signatures(assembly);
    referenced_typedefs.extend(
        field_sig_refs
            .iter()
            .filter(|t| t.is_table(TableId::TypeDef))
            .map(|t| t.row()),
    );

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

            // Skip protected types — these were created by code generation
            // and must survive cleanup regardless of whether they appear empty.
            if request.is_protected(Token::from_parts(TableId::TypeDef, type_rid)) {
                continue;
            }

            // Skip types that are still referenced in method bodies.
            // ClassLayout types (explicit-size value types) are also protected
            // when referenced — they exist to provide memory layout for array
            // init data (e.g., `__StaticArrayInitTypeSize=N` backing types).
            if referenced_typedefs.contains(&type_rid) {
                continue;
            }
            // Unreferenced ClassLayout types are safe to remove — they're
            // infrastructure whose consumers have already been deleted.
            // Note: referenced ClassLayout types are already protected above.

            // Calculate method count for this type — only count non-deleted rows.
            // Using the raw range (next_type.method_list - this_type.method_list) is
            // incorrect after deletions: a type whose methods were all deleted still
            // has a non-zero range, so we must check each row individually.
            let method_range = list_range(type_rid, type_count, methoddef_count, |rid| {
                typedef_table.get(rid).map(|t| t.method_list)
            });
            let live_method_count = (typedef.method_list..method_range.end)
                .filter(|&rid| !assembly.changes().is_row_deleted(TableId::MethodDef, rid))
                .count();

            // Calculate field count for this type — same logic.
            let field_range = list_range(type_rid, type_count, field_count, |rid| {
                typedef_table.get(rid).map(|t| t.field_list)
            });
            let live_field_count = (typedef.field_list..field_range.end)
                .filter(|&rid| !assembly.changes().is_row_deleted(TableId::Field, rid))
                .count();

            // Type is empty if it has no surviving methods and no surviving fields,
            // AND is not an interface or abstract class that legitimately has none.
            if live_method_count == 0 && live_field_count == 0 {
                // Skip interface types — they legitimately have no members in metadata
                // when all their members are inherited or defined elsewhere.
                // ECMA-335 §II.23.1.15: Interface = 0x20
                if typedef.flags & 0x20 != 0 {
                    continue;
                }

                // Skip types that are base classes of other surviving types.
                // Abstract base classes may have no direct members but provide
                // type hierarchy structure that must be preserved.
                let is_base_class = typedef_table.iter().any(|other| {
                    other.rid != type_rid
                        && !empty.contains(&other.rid)
                        && other.extends.tag == TableId::TypeDef
                        && other.extends.row == type_rid
                });
                if is_base_class {
                    continue;
                }

                // Skip types that appear in InterfaceImpl as the interface being implemented.
                if let Some(iface_impl) = tables.table::<InterfaceImplRaw>() {
                    let is_implemented = iface_impl.iter().any(|row| {
                        row.interface.tag == TableId::TypeDef && row.interface.row == type_rid
                    });
                    if is_implemented {
                        continue;
                    }
                }

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

/// Collects the complete set of MethodDef tokens that are still alive.
///
/// A MethodDef is considered alive if it is referenced from ANY of:
///
/// 1. **IL bytecode** — `call`, `callvirt`, `newobj`, `ldftn`, `ldvirtftn`
///    instructions in surviving method bodies (via `scan_method_body_tokens`)
/// 2. **MethodSpec.method** — generic instantiations that are themselves
///    referenced from IL. A MethodSpec token in IL → its underlying MethodDef
///    is alive.
/// 3. **CustomAttribute.constructor** — attribute constructors on surviving
///    entities.
/// 4. **MethodSemantics.method** — property getters/setters, event add/remove
///    handlers on surviving types.
/// 5. **MethodImpl.method_body / method_declaration** — explicit interface
///    overrides on surviving types.
fn collect_alive_method_tokens(assembly: &CilAssembly) -> HashSet<Token> {
    // Start with IL body tokens (all token operands from surviving method bodies).
    let body_tokens = scan_method_body_tokens(assembly);

    let mut alive: HashSet<Token> = body_tokens
        .iter()
        .filter(|t| t.is_table(TableId::MethodDef))
        .copied()
        .collect();

    let view = assembly.view();
    let Some(tables) = view.tables() else {
        return alive;
    };

    // MethodSpec.method → if the MethodSpec token is referenced from IL,
    // the underlying MethodDef is alive.
    if let Some(methodspec_table) = tables.table::<MethodSpecRaw>() {
        for row in methodspec_table {
            if assembly
                .changes()
                .is_row_deleted(TableId::MethodSpec, row.rid)
            {
                continue;
            }
            let spec_token = Token::from_parts(TableId::MethodSpec, row.rid);
            if body_tokens.contains(&spec_token) && row.method.token.is_table(TableId::MethodDef) {
                alive.insert(row.method.token);
            }
        }
    }

    // CustomAttribute.constructor → if the attribute is not deleted,
    // its constructor method is alive.
    if let Some(attr_table) = tables.table::<CustomAttributeRaw>() {
        for row in attr_table {
            if assembly
                .changes()
                .is_row_deleted(TableId::CustomAttribute, row.rid)
            {
                continue;
            }
            if row.constructor.token.is_table(TableId::MethodDef) {
                alive.insert(row.constructor.token);
            }
        }
    }

    // MethodSemantics.method → property getters/setters, event add/remove.
    // These are alive if the row itself is not deleted.
    if let Some(sem_table) = tables.table::<MethodSemanticsRaw>() {
        for row in sem_table {
            if assembly
                .changes()
                .is_row_deleted(TableId::MethodSemantics, row.rid)
            {
                continue;
            }
            let method_token = Token::from_parts(TableId::MethodDef, row.method);
            alive.insert(method_token);
        }
    }

    // MethodImpl.method_body / method_declaration → explicit overrides.
    if let Some(impl_table) = tables.table::<MethodImplRaw>() {
        for row in impl_table {
            if assembly
                .changes()
                .is_row_deleted(TableId::MethodImpl, row.rid)
            {
                continue;
            }
            if row.method_body.token.is_table(TableId::MethodDef) {
                alive.insert(row.method_body.token);
            }
            if row.method_declaration.token.is_table(TableId::MethodDef) {
                alive.insert(row.method_declaration.token);
            }
        }
    }

    alive
}

/// Collects the complete set of Field tokens that are still alive.
///
/// A field is considered alive if it is referenced from any surviving method's
/// IL bytecode (`ldfld`, `stfld`, `ldsfld`, `stsfld`, `ldflda`, `ldsflda`).
///
/// Unlike methods, fields have no equivalent to MethodSemantics/MethodImpl/
/// CustomAttribute.constructor that would keep them alive independently of IL.
/// Fields referenced only by FieldRVA/Constant/FieldLayout are dependent
/// entries that get cleaned up when the field itself is removed.
fn collect_alive_field_tokens(assembly: &CilAssembly) -> HashSet<Token> {
    let body_tokens = scan_method_body_tokens(assembly);
    body_tokens
        .into_iter()
        .filter(|t| t.is_table(TableId::Field))
        .collect()
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
