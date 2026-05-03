//! Generic cleanup utilities for deobfuscation.
//!
//! This module provides deobfuscation-specific cleanup operations that build on
//! the generic [`cilassembly::cleanup`](crate::cilassembly::cleanup) infrastructure.
//!
//! The deobfuscation cleanup adds:
//! - Dead method collection from analysis
//! - Entry point protection (preserves public methods, constructors, etc.)
//! - Obfuscated name renaming
//! - Event logging for statistics
//!
//! # Usage
//!
//! Obfuscator-specific modules should:
//! 1. Detect what tokens need to be removed (types, methods, fields)
//! 2. Create a [`CleanupRequest`](crate::cilassembly::CleanupRequest) with those tokens
//! 3. Call [`execute_cleanup`] to perform the cleanup
//!
//! # Example
//!
//! ```rust,ignore
//! use dotscope::cilassembly::CleanupRequest;
//! use dotscope::deobfuscation::cleanup::execute_cleanup;
//! use dotscope::deobfuscation::DerivedStats;
//!
//! let mut request = CleanupRequest::new();
//! request.add_type(some_type_token);
//! request.add_method(some_method_token);
//! request.add_field(some_field_token);
//!
//! let assembly = execute_cleanup(assembly, Some(request), &ctx)?;
//! // Statistics are derived from the event log
//! let stats = DerivedStats::from_log(&ctx.events);
//! println!("{}", stats.summary());
//! ```

use std::collections::{hash_map::Entry, BTreeMap, BTreeSet, HashMap, HashSet};

use crate::{
    cilassembly::{
        compute_entry_points, find_unreferenced_types, CilAssembly, CleanupRequest, GeneratorConfig,
    },
    compiler::{EventKind, ProxyDevirtualizationPass},
    deobfuscation::{
        context::AnalysisContext, engine::DeobfuscationEngine, renamer, techniques::Detections,
    },
    metadata::{
        tables::{
            AssemblyRaw, FieldRaw, ModuleRaw, NestedClassRaw, TableDataOwned, TableId, TypeDefRaw,
        },
        token::Token,
        typesystem::wellknown,
        validation::ValidationConfig,
    },
    CilObject, Result,
};

/// Builds a complete cleanup request from detection results and analysis state.
///
/// This consolidates all cleanup sources into a single request:
/// 1. Merges technique-specific cleanup requests (from each detected technique)
/// 2. Adds removable decryptors (fully-emulated, safe to remove)
/// 3. Adds unreferenced infrastructure types (detected via call graph analysis)
/// 4. Adds dead methods (if aggressive mode enabled)
/// 5. Adds neutralized tokens as cascade candidates
/// 6. Sweeps empty module methods
///
/// The resulting request is complete — it can be used for both neutralization
/// (to know which tokens to neutralize) and final cleanup (to perform deletions).
///
/// # Arguments
///
/// * `engine` - The deobfuscation engine (provides technique registry).
/// * `ctx` - The analysis context containing SSA functions, dead methods, and config.
/// * `detections` - The detection results from all techniques.
/// * `assembly` - The assembly being deobfuscated.
/// * `ssa_call_graph` - The SSA-derived call graph (caller → callees).
pub(crate) fn build_cleanup_request(
    engine: &DeobfuscationEngine,
    ctx: &AnalysisContext,
    detections: &Detections,
    assembly: &CilObject,
    ssa_call_graph: &BTreeMap<Token, BTreeSet<Token>>,
) -> CleanupRequest {
    // Start with technique-merged cleanup
    let registry = engine.technique_registry();
    let mut request = detections.merged_cleanup();
    for tech in registry.sorted_techniques(detections) {
        if !detections.is_detected(tech.id()) {
            continue;
        }
        let detection = detections.get(tech.id()).unwrap();
        if let Some(tech_cleanup) = tech.cleanup(detection) {
            request.merge(&tech_cleanup);
        }
    }

    // Protect registered decryptors that were NOT fully decrypted.
    // Techniques may unconditionally mark decryptor methods for cleanup, but
    // if emulation failed for any call site, the method must survive — deleting
    // it would leave broken call sites that reference a now-missing method.
    // Only fully-decrypted methods are safe to remove.
    let removable = ctx.decryptors.removable_decryptors();
    for token in ctx.decryptors.registered_tokens() {
        if !removable.contains(&token) {
            request.protect_token(token);
        }
    }

    // Add decryptors that were fully emulated and are now safe to remove.
    for token in removable {
        request.add_method(token);
    }

    // Pre-scan: mark <Module> methods as dead if they have no live callers.
    sweep_dead_module_methods(assembly, &mut request, ssa_call_graph, ctx);

    // Mark orphaned proxy forwarding stubs as devirtualized. These are mild
    // proxy stubs that were only called from infrastructure code (e.g., .cctor)
    // that was subsequently neutralized. The neutralization removed the calls
    // but didn't use mark_inlined, so the stubs have zero callers in the SSA
    // call graph but was_inlined is false. Detecting the proxy pattern confirms
    // they're trivial forwarding stubs, safe to delete.
    mark_orphaned_proxy_stubs(assembly, &request, ssa_call_graph, ctx);

    // Sweep for inlined/devirtualized proxy methods in ALL types.
    sweep_inlined_unreferenced_methods(assembly, &mut request, ssa_call_graph, ctx);

    // Find and add unreferenced infrastructure types via call graph analysis.
    // This uses cluster analysis: candidate types that only reference each
    // other (and already-deleted entities) are detected as isolated
    // infrastructure and removed.
    let unreferenced_types = find_unreferenced_types(assembly, ssa_call_graph, &request);
    for type_token in unreferenced_types {
        request.add_type(type_token);
    }

    // Add dead methods from analysis (aggressive mode only)
    let aggressive = ctx.config.cleanup.remove_unused_methods;
    if aggressive {
        let entry_points = compute_entry_points(assembly, aggressive);
        for token in ctx.dead_methods.iter() {
            let token = *token;
            if !entry_points.contains(&token) {
                request.add_method(token);
            }
        }
    }

    // Remove types whose methods are ALL dead or devirtualized.
    remove_dispensable_types(assembly, &mut request, ctx);

    // Add tokens neutralized by SSA passes as cascade candidates.
    if ctx.config.cleanup.remove_orphan_metadata {
        let neutralized = ctx.neutralized_tokens.iter().map(|t| *t);
        request.add_rewrite_orphaned_tokens(neutralized);
    }

    // Detect empty module methods and add to cleanup request.
    sweep_empty_module_cctor(assembly, &mut request, ctx);

    request
}

/// Executes cleanup with a complete request.
///
/// The request is expected to arrive complete (built by [`build_cleanup_request`]).
/// This function applies renames if enabled, repairs metadata anomalies, logs
/// deletions, and delegates to the cilassembly executor.
///
/// # Arguments
///
/// * `assembly` - The assembly to clean up (consumed and regenerated).
/// * `cleanup_request` - Optional complete cleanup request. If `None`, a default
///   request is created from the analysis context configuration.
/// * `ctx` - The analysis context containing configuration and event log.
///
/// # Returns
///
/// A new `CilObject` with the requested cleanup applied and names renamed.
///
/// # Errors
///
/// Returns an error if string heap updates fail during renaming, or if
/// regeneration of the cleaned assembly fails.
pub fn execute_cleanup(
    assembly: CilObject,
    cleanup_request: Option<CleanupRequest>,
    ctx: &AnalysisContext,
) -> Result<CilObject> {
    let request = cleanup_request.unwrap_or_else(|| {
        CleanupRequest::with_settings(
            ctx.config.cleanup.remove_orphan_metadata,
            ctx.config.cleanup.remove_empty_types,
        )
    });

    // Determine if we should rename obfuscated names
    let rename_obfuscated = ctx.config.cleanup.rename_obfuscated_names;

    // Nothing to do.
    //
    // Metadata repairs (`repair_*` below) must run even when the request is
    // empty — some samples (notably .NET Reactor's SuppressIldasm) have no
    // technique-driven deletions but still carry ECMA-335 violations that
    // break strict-mode reload. `needs_metadata_repair` short-circuits the
    // exit when any of those violations are present.
    if !request.has_deletions()
        && request.excluded_sections().is_empty()
        && !rename_obfuscated
        && !needs_metadata_repair(&assembly)
    {
        return Ok(assembly);
    }

    // Log what we're cleaning
    let types_count = request.types_len();
    let methods_count = request.methods_len();
    let fields_count = request.fields_len();

    if types_count > 0 || methods_count > 0 || fields_count > 0 {
        log::info!("Cleanup: {types_count} types, {methods_count} methods, {fields_count} fields");
    }

    for section_name in request.excluded_sections() {
        ctx.events
            .record(EventKind::ArtifactRemoved)
            .message(format!("Removing artifact section: {section_name}"));
    }

    // Log individual removals before consuming the assembly
    log_cleanup_request(&request, &assembly, ctx);

    // Collect rename entries while CilObject is still alive (before consumption).
    // The smart renamer needs CilObject-level APIs (types(), resolver(), member_ref())
    // for metadata queries — these aren't available on CilAssembly.
    let rename_entries = if rename_obfuscated {
        Some(renamer::renames_collect(
            &assembly,
            ctx.config.cleanup.smart_rename.as_ref(),
        )?)
    } else {
        None
    };

    // Convert directly — no reparsing needed (consumes CilObject)
    let mut cil_assembly = assembly.into_assembly();

    // Repair metadata anomalies injected by obfuscators.
    // ECMA-335 §22.2: Assembly table shall contain zero or one row.
    // Some obfuscators inject duplicate rows to confuse tooling.
    repair_duplicate_assembly_rows(&mut cil_assembly, ctx);

    // ECMA-335 §22.30: Module table shall contain exactly one row.
    // .NET Reactor's SuppressIldasm injects a duplicate Module row to
    // break parsers and the schema validator.
    repair_duplicate_module_rows(&mut cil_assembly, ctx);

    // ECMA-335 §22.30: Module row 1's `EncId` and `EncBaseId` are GUID
    // heap indices that must be 0 (no value) or point inside the heap.
    // .NET Reactor's SuppressIldasm sets them to 0xFFFF to break loaders
    // that don't bounds-check the lookup.
    repair_invalid_module_guids(&mut cil_assembly, ctx);

    // ECMA-335 §22.37: TypeDef names must be unique within (name, namespace, enclosingClass).
    // Some obfuscators inject duplicate nested types (e.g., multiple <>c closures).
    // Empty duplicates are removed directly; non-empty ones are added to the cleanup request.
    let duplicate_types = repair_duplicate_typedef_rows(&mut cil_assembly, ctx);

    // ECMA-335 §22.15: Global fields (<Module>) must have CompilerControlled, Private, or Public access.
    // Some obfuscators set invalid access flags (e.g., Assembly/Family) on <Module> fields.
    repair_global_field_visibility(&mut cil_assembly, ctx);

    // Clone excluded sections before moving request
    let excluded_sections: HashSet<String> = request.excluded_sections().clone();

    // Add non-empty duplicate types to cleanup request for deletion
    let mut request = request;
    for token in duplicate_types {
        request.add_type(token);
    }

    // Add cleanup request (the actual cleanup is executed during generation)
    cil_assembly.add_cleanup(&request);

    // Apply collected renames to the string heap
    if let Some(entries) = rename_entries {
        let count = renamer::renames_apply(&mut cil_assembly, entries)?;
        if count > 0 {
            ctx.events
                .record(EventKind::ArtifactRemoved)
                .message(format!(
                    "Renamed {count} obfuscated names to simple identifiers"
                ));
        }
    }

    // Regenerate with excluded sections
    // The cleanup is automatically executed during into_cilobject_with
    let generator_config = GeneratorConfig::default().with_excluded_sections(excluded_sections);
    cil_assembly.into_cilobject_with(ValidationConfig::analysis(), generator_config)
}

/// Logs cleanup request details to the event log.
///
/// Records an [`EventKind::ArtifactRemoved`] event for each type, method,
/// field, and custom attribute scheduled for removal. Type events include
/// the fully-qualified name when available; methods and fields log their
/// token values.
fn log_cleanup_request(request: &CleanupRequest, assembly: &CilObject, ctx: &AnalysisContext) {
    // Log type removals
    for type_token in request.types() {
        if let Some(cil_type) = assembly.types().get(type_token) {
            ctx.events
                .record(EventKind::ArtifactRemoved)
                .message(format!(
                    "Removing type: {} (0x{:08X})",
                    cil_type.name,
                    type_token.value()
                ));
        } else {
            ctx.events
                .record(EventKind::ArtifactRemoved)
                .message(format!("Removing type: TypeDef RID {}", type_token.row()));
        }
    }

    // Log method removals
    for method_token in request.methods() {
        ctx.events
            .record(EventKind::ArtifactRemoved)
            .method(*method_token)
            .message("Removing method");
    }

    // Log field removals
    for field_token in request.fields() {
        ctx.events
            .record(EventKind::ArtifactRemoved)
            .message(format!("Removing field 0x{:08X}", field_token.value()));
    }

    // Log attribute removals
    for attr_token in request.attributes() {
        ctx.events
            .record(EventKind::ArtifactRemoved)
            .message(format!(
                "Removing custom attribute 0x{:08X}",
                attr_token.value()
            ));
    }
}

/// Repairs duplicate Assembly table rows injected by obfuscators.
///
/// ECMA-335 §22.2 requires the Assembly table to contain at most 1 row.
/// Some obfuscators inject extra rows to confuse decompilers and analysis tools.
/// This removes any rows beyond the first, keeping the original assembly identity.
fn repair_duplicate_assembly_rows(cil_assembly: &mut CilAssembly, ctx: &AnalysisContext) {
    let row_count = cil_assembly.original_table_row_count(TableId::Assembly);
    if row_count <= 1 {
        return;
    }

    // Remove duplicate rows (keep RID 1, remove RID 2..N)
    let duplicates = row_count - 1;
    for rid in (2..=row_count).rev() {
        if let Err(e) = cil_assembly.table_row_remove(TableId::Assembly, rid) {
            log::warn!("Failed to remove duplicate Assembly row {rid}: {e}");
        }
    }

    log::info!(
        "Repaired Assembly table: removed {duplicates} duplicate row(s) (ECMA-335 §22.2 violation)"
    );
    ctx.events
        .record(EventKind::ArtifactRemoved)
        .message(format!(
            "Repaired Assembly table: removed {duplicates} duplicate row(s)"
        ));
}

/// Repairs duplicate Module table rows injected by obfuscators.
///
/// ECMA-335 §22.30 requires the Module table to contain exactly one row.
/// .NET Reactor's SuppressIldasm protection injects a second row to break
/// parsers and our `SchemaValidator` (`shared/schema.rs:135`). Removes any
/// rows beyond the first, keeping the original module identity.
fn repair_duplicate_module_rows(cil_assembly: &mut CilAssembly, ctx: &AnalysisContext) {
    let row_count = cil_assembly.original_table_row_count(TableId::Module);
    if row_count <= 1 {
        return;
    }

    let duplicates = row_count - 1;
    for rid in (2..=row_count).rev() {
        if let Err(e) = cil_assembly.table_row_remove(TableId::Module, rid) {
            log::warn!("Failed to remove duplicate Module row {rid}: {e}");
        }
    }

    log::info!(
        "Repaired Module table: removed {duplicates} duplicate row(s) (ECMA-335 §22.30 violation)"
    );
    ctx.events
        .record(EventKind::ArtifactRemoved)
        .message(format!(
            "Repaired Module table: removed {duplicates} duplicate row(s)"
        ));
}

/// Repairs out-of-bounds GUID indices on Module row 1.
///
/// ECMA-335 §22.30: `EncId` / `EncBaseId` are `#GUID` heap indices that must
/// be 0 (no value) or point inside the heap. .NET Reactor's SuppressIldasm
/// injects `0xFFFF` to crash strict loaders that look the indices up
/// without bounds checking — dotscope's loader fails at
/// `streams/guid.rs:505` with `Out of Bounds`, which then blocks the
/// roundtrip reload.
///
/// Clamps any out-of-bounds value back to 0 (the standard "no value"
/// sentinel). The user-visible Mvid is left untouched.
fn repair_invalid_module_guids(cil_assembly: &mut CilAssembly, ctx: &AnalysisContext) {
    let guid_count: u32 = cil_assembly
        .view()
        .guids()
        .map_or(0, |g| (g.data().len() / 16) as u32);

    let Some(tables) = cil_assembly.view().tables() else {
        return;
    };
    let Some(module_table) = tables.table::<ModuleRaw>() else {
        return;
    };
    let Some(row) = module_table.get(1) else {
        return;
    };

    let bad_encid = row.encid != 0 && row.encid > guid_count;
    let bad_encbaseid = row.encbaseid != 0 && row.encbaseid > guid_count;

    if !bad_encid && !bad_encbaseid {
        return;
    }

    let original_encid = row.encid;
    let original_encbaseid = row.encbaseid;
    let fixed = ModuleRaw {
        rid: row.rid,
        token: row.token,
        offset: row.offset,
        generation: row.generation,
        name: row.name,
        mvid: row.mvid,
        encid: if bad_encid { 0 } else { row.encid },
        encbaseid: if bad_encbaseid { 0 } else { row.encbaseid },
    };

    if let Err(e) = cil_assembly.table_row_update(TableId::Module, 1, TableDataOwned::Module(fixed))
    {
        log::warn!("Failed to repair Module row 1 GUID indices: {e}");
        return;
    }

    log::info!(
        "Repaired Module row 1 GUIDs: encid {original_encid} → 0 ({}), encbaseid {original_encbaseid} → 0 ({}); heap has {guid_count} GUID(s)",
        if bad_encid { "fixed" } else { "kept" },
        if bad_encbaseid { "fixed" } else { "kept" },
    );
    ctx.events
        .record(EventKind::ArtifactRemoved)
        .message(format!(
            "Repaired Module row 1: cleared out-of-bounds ENC GUID indices \
             (encid={original_encid}, encbaseid={original_encbaseid})"
        ));
}

/// Returns `true` if the assembly carries any ECMA-335 metadata-table
/// violation that the `repair_*` functions know how to fix.
///
/// Used by [`execute_cleanup`] to bypass its early-exit when a cleanup
/// request is otherwise empty: a sample with only metadata corruption
/// (e.g. .NET Reactor's SuppressIldasm) needs cleanup to actually run.
///
/// Currently checks:
/// - Duplicate `Module` rows (`row_count > 1`).
/// - Duplicate `Assembly` rows (`row_count > 1`).
/// - Module row 1's `EncId` / `EncBaseId` pointing outside the `#GUID`
///   heap.
///
/// All other repairs in this module either run only when there is a
/// pre-existing reason for cleanup (e.g. duplicate TypeDefs piggyback on
/// the technique-driven deletions that already trigger cleanup) or are
/// triggered explicitly by techniques.
fn needs_metadata_repair(assembly: &CilObject) -> bool {
    let Some(tables) = assembly.tables() else {
        return false;
    };

    if let Some(t) = tables.table::<ModuleRaw>() {
        if t.row_count > 1 {
            return true;
        }
        if let Some(row) = t.get(1) {
            let guid_count: u32 = assembly.guids().map_or(0, |g| (g.data().len() / 16) as u32);
            if (row.encid != 0 && row.encid > guid_count)
                || (row.encbaseid != 0 && row.encbaseid > guid_count)
            {
                return true;
            }
        }
    }

    if let Some(t) = tables.table::<AssemblyRaw>() {
        if t.row_count > 1 {
            return true;
        }
    }

    false
}

/// Detects duplicate TypeDef rows with the same (name, namespace, enclosingClass) tuple.
///
/// ECMA-335 §22.37 rule 1: No two rows shall have the same combination of
/// TypeName, TypeNamespace, and enclosing class. Some obfuscators (e.g., BitMono)
/// inject duplicate nested types like `<>c` which cause peverify failures.
///
/// Strategy:
/// - Empty duplicates (no methods, no fields) are removed outright along with
///   their NestedClass entries.
/// - Non-empty duplicates are returned as tokens to be added to the cleanup
///   request for deletion during the normal cleanup phase.
fn repair_duplicate_typedef_rows(
    cil_assembly: &mut CilAssembly,
    ctx: &AnalysisContext,
) -> Vec<Token> {
    let Some(tables) = cil_assembly.view().tables() else {
        return Vec::new();
    };
    let Some(strings) = cil_assembly.view().strings() else {
        return Vec::new();
    };

    // Build a NestedClass map: nested_type_rid → (enclosing_type_rid, nestedclass_rid)
    let nested_class_entries: Vec<(u32, u32, u32)> = tables
        .table::<NestedClassRaw>()
        .map(|rows| {
            rows.into_iter()
                .map(|r| (r.nested_class, r.enclosing_class, r.rid))
                .collect()
        })
        .unwrap_or_default();

    let nested_class_map: HashMap<u32, u32> = nested_class_entries
        .iter()
        .map(|&(nested, enclosing, _)| (nested, enclosing))
        .collect();

    // Collect TypeDef rows to check for duplicates and emptiness
    let typedef_rows: Vec<TypeDefRaw> = tables
        .table::<TypeDefRaw>()
        .map(|t| t.into_iter().collect())
        .unwrap_or_default();

    let method_count = cil_assembly.original_table_row_count(TableId::MethodDef);
    let field_count = cil_assembly.original_table_row_count(TableId::Field);

    // Scan for duplicates based on (name, namespace, enclosing_class)
    let mut seen: HashMap<(String, String, u32), u32> = HashMap::new();
    let mut duplicates_to_remove: Vec<u32> = Vec::new();
    let mut duplicates_for_cleanup: Vec<Token> = Vec::new();

    for row in &typedef_rows {
        let name = strings
            .get(row.type_name as usize)
            .unwrap_or_default()
            .to_string();
        let namespace = strings
            .get(row.type_namespace as usize)
            .unwrap_or_default()
            .to_string();
        let enclosing = nested_class_map.get(&row.rid).copied().unwrap_or(0);

        let key = (name, namespace, enclosing);
        if let Entry::Vacant(entry) = seen.entry(key) {
            entry.insert(row.rid);
        } else {
            // Check if the duplicate has methods or fields
            let method_start = row.method_list;
            let method_end = typedef_rows
                .iter()
                .find(|t| t.rid == row.rid + 1)
                .map(|t| t.method_list)
                .unwrap_or(method_count + 1);
            let field_start = row.field_list;
            let field_end = typedef_rows
                .iter()
                .find(|t| t.rid == row.rid + 1)
                .map(|t| t.field_list)
                .unwrap_or(field_count + 1);

            let has_methods = method_end > method_start;
            let has_fields = field_end > field_start;

            if !has_methods && !has_fields {
                // Empty duplicate — safe to remove directly
                duplicates_to_remove.push(row.rid);
            } else {
                // Non-empty duplicate — schedule for cleanup deletion
                duplicates_for_cleanup.push(Token::from_parts(TableId::TypeDef, row.rid));
            }
        }
    }

    if duplicates_to_remove.is_empty() && duplicates_for_cleanup.is_empty() {
        return Vec::new();
    }

    let removed_count = duplicates_to_remove.len();
    let cleanup_count = duplicates_for_cleanup.len();

    // Remove empty duplicates directly
    if !duplicates_to_remove.is_empty() {
        let dup_set: HashSet<u32> = duplicates_to_remove.iter().copied().collect();

        // Remove corresponding NestedClass entries first
        for &(nested, _, nc_rid) in &nested_class_entries {
            if dup_set.contains(&nested) {
                if let Err(e) = cil_assembly.table_row_remove(TableId::NestedClass, nc_rid) {
                    log::warn!("Failed to remove NestedClass row {nc_rid}: {e}");
                }
            }
        }

        // Remove duplicate TypeDef rows (in reverse order)
        for rid in duplicates_to_remove.iter().rev() {
            if let Err(e) = cil_assembly.table_row_remove(TableId::TypeDef, *rid) {
                log::warn!("Failed to remove duplicate TypeDef row {rid}: {e}");
            }
        }
    }

    let total = removed_count + cleanup_count;
    log::info!(
        "Repaired TypeDef table: {removed_count} removed, {cleanup_count} scheduled for cleanup ({total} total duplicates, ECMA-335 §22.37)"
    );
    ctx.events
        .record(EventKind::ArtifactRemoved)
        .message(format!(
            "Repaired TypeDef table: {removed_count} removed, {cleanup_count} scheduled for cleanup ({total} duplicates)"
        ));

    duplicates_for_cleanup
}

/// Repairs invalid field visibility on `<Module>` global fields.
///
/// ECMA-335 §22.15 rule 4: Fields owned by `<Module>` (global fields) must have
/// accessibility `CompilerControlled` (0), `Private` (1), or `Public` (6).
/// Some obfuscators set invalid values like `Assembly` (3) or `Family` (4).
///
/// This corrects any invalid access to `Private` (1), which is the most
/// restrictive valid option and unlikely to break anything.
fn repair_global_field_visibility(cil_assembly: &mut CilAssembly, ctx: &AnalysisContext) {
    let Some(tables) = cil_assembly.view().tables() else {
        return;
    };
    let Some(typedefs) = tables.table::<TypeDefRaw>() else {
        return;
    };

    // Find <Module> type (always RID 1) and its field range
    let typedef_rows: Vec<TypeDefRaw> = typedefs.into_iter().collect();
    if typedef_rows.is_empty() {
        return;
    }
    let module_type = &typedef_rows[0];
    let field_start = module_type.field_list;
    let field_end = if typedef_rows.len() > 1 {
        typedef_rows[1].field_list
    } else {
        // If there's only one type, the field end is the total field count + 1
        cil_assembly.original_table_row_count(TableId::Field) + 1
    };

    if field_start >= field_end {
        return;
    }

    // Check each <Module> field for invalid access
    let Some(fields_table) = tables.table::<FieldRaw>() else {
        return;
    };
    let fields: Vec<FieldRaw> = fields_table.into_iter().collect();
    let mut repaired = 0;

    for rid in field_start..field_end {
        let idx = (rid - 1) as usize;
        if idx >= fields.len() {
            break;
        }
        let field = &fields[idx];
        let access = field.flags & 0x0007; // FieldAccessMask per ECMA-335 §II.23.1.5

        // Valid access for global fields: CompilerControlled(0), Private(1), or Public(6)
        if !matches!(access, 0x0000 | 0x0001 | 0x0006) {
            let mut fixed = field.clone();
            fixed.flags = (fixed.flags & !0x0007) | 0x0001; // Set to Private
            if let Err(e) =
                cil_assembly.table_row_update(TableId::Field, rid, TableDataOwned::Field(fixed))
            {
                log::warn!("Failed to repair <Module> field {rid} visibility: {e}");
            } else {
                repaired += 1;
            }
        }
    }

    if repaired > 0 {
        log::info!(
            "Repaired {repaired} <Module> field(s) with invalid visibility (ECMA-335 §22.15)"
        );
        ctx.events
            .record(EventKind::ArtifactRemoved)
            .message(format!(
                "Repaired {repaired} <Module> field(s) with invalid visibility"
            ));
    }
}

/// Sweeps dead `<Module>` methods via reverse call graph analysis.
///
/// After techniques tag their decryptor/initializer methods for deletion,
/// other `<Module>` helper methods (LZMA decompression, etc.) may have no
/// remaining callers. This checks the SSA call graph and treats a method
/// as dead if every caller is already tagged for deletion.
///
/// Runs in a fixpoint loop to handle transitive chains (e.g., `.cctor` →
/// `Initialize` → LZMA helper).
fn sweep_dead_module_methods(
    assembly: &CilObject,
    request: &mut CleanupRequest,
    ssa_call_graph: &BTreeMap<Token, BTreeSet<Token>>,
    ctx: &AnalysisContext,
) {
    let Some(module_type) = assembly.types().module_type() else {
        return;
    };

    let mut deleted_methods: HashSet<Token> = request.methods().copied().collect();
    let deleted_types: HashSet<Token> = request.types().copied().collect();

    // Expand deleted types to include their method tokens
    let type_registry = assembly.types();
    for type_token in &deleted_types {
        if let Some(cil_type) = type_registry.get(type_token) {
            for m in cil_type.methods() {
                deleted_methods.insert(m.token);
            }
        }
    }

    // Build reverse call graph: callee → set of callers
    let mut callers_of: HashMap<Token, HashSet<Token>> = HashMap::new();
    for (caller, callees) in ssa_call_graph {
        for callee in callees {
            callers_of.entry(*callee).or_default().insert(*caller);
        }
    }

    // Fixpoint: each round may reveal methods whose callers are now all dead
    loop {
        let mut newly_dead = Vec::new();
        for method in module_type.methods() {
            if deleted_methods.contains(&method.token) {
                continue;
            }
            let callers = callers_of.get(&method.token);
            let has_callers = callers.is_some_and(|c| !c.is_empty());
            // A method is dead if it has known callers and ALL of them are deleted.
            let all_callers_deleted =
                has_callers && callers.unwrap().iter().all(|c| deleted_methods.contains(c));

            // Methods with NO callers in the SSA graph are conservatively kept —
            // the SSA call graph only covers successfully-converted methods, so
            // "no callers" may mean the caller wasn't converted to SSA.
            // Exception: if the method was inlined by the proxy devirtualization
            // pass, "no callers" means ALL call sites were replaced with direct
            // calls — the method is truly dead, not just missing from the graph.
            let inlined_and_unreferenced = !has_callers && ctx.was_inlined(method.token);

            if method.is_cctor() {
                // .cctor is invoked by the runtime, not via IL — it has
                // no callers. Instead check callees: if ALL its callees
                // are already deleted, the .cctor is pure infrastructure.
                if let Some(callees) = ssa_call_graph.get(&method.token) {
                    if !callees.is_empty() && callees.iter().all(|c| deleted_methods.contains(c)) {
                        newly_dead.push(method.token);
                    }
                }
            } else if all_callers_deleted || inlined_and_unreferenced {
                newly_dead.push(method.token);
            }
        }
        if newly_dead.is_empty() {
            break;
        }
        for token in &newly_dead {
            deleted_methods.insert(*token);
            request.add_method(*token);
        }
    }
}

/// Scans the assembly IL for mild proxy stubs and adds them to the cleanup request.
///
/// A mild proxy stub has IL pattern: `[ldarg*] call/callvirt <external> ret`.
/// The call target must be external (MemberRef to a non-local method) to avoid
/// false positives on methods that happen to forward to internal helpers.
///
/// This catches proxy stubs whose SSA-level detection failed because:
/// - CFF obfuscation was applied to larger proxy stubs (detected by CFF
///   unflattening but simplified too late for the proxy pass)
/// - The SSA was modified by passes that broke the proxy pattern
///
/// Marks orphaned proxy forwarding stubs as devirtualized.
///
/// After neutralization removes calls from infrastructure code (e.g., .cctor),
/// mild proxy stubs may have zero callers without `mark_inlined` being set
/// (neutralization NOPs calls, it doesn't use the proxy devirt path).
/// This function detects these orphaned stubs by checking the proxy forwarding
/// pattern on methods with SSA, zero callers, and no entry point status.
fn mark_orphaned_proxy_stubs(
    assembly: &CilObject,
    request: &CleanupRequest,
    ssa_call_graph: &BTreeMap<Token, BTreeSet<Token>>,
    ctx: &AnalysisContext,
) {
    let deleted_methods: HashSet<Token> = request.methods().copied().collect();

    // Build set of methods that have at least one live caller
    let mut has_caller: HashSet<Token> = HashSet::new();
    for (caller, callees) in ssa_call_graph {
        if deleted_methods.contains(caller) {
            continue;
        }
        for callee in callees {
            has_caller.insert(*callee);
        }
    }

    let entry_token = assembly.cor20header().entry_point_token;

    for entry in ctx.ssa_functions.iter() {
        let token = *entry.key();
        if token.table() != 0x06
            || deleted_methods.contains(&token)
            || has_caller.contains(&token)
            || ctx.was_inlined(token)
            || ctx.was_devirtualized(token)
            || token.value() == entry_token
        {
            continue;
        }

        // Skip constructors and static constructors
        if let Some(name) = assembly.resolve_method_name(token) {
            if name == ".ctor" || name == ".cctor" {
                continue;
            }
        }

        // Check if this is a proxy forwarding stub via live SSA pattern.
        let is_proxy = ctx
            .with_ssa(token, |ssa| {
                ProxyDevirtualizationPass::detect_proxy_pattern(ssa).is_some()
            })
            .unwrap_or(false);

        if is_proxy {
            ctx.mark_devirtualized(token);
        }
    }
}

/// Sweeps ALL types for methods that were inlined by the SSA proxy
/// devirtualization pass and have no remaining callers in the SSA call graph.
/// Unlike `sweep_dead_module_methods` (which only handles `<Module>`), this
/// catches proxy stubs that ConfuserEx injects into user types.
fn sweep_inlined_unreferenced_methods(
    assembly: &CilObject,
    request: &mut CleanupRequest,
    ssa_call_graph: &BTreeMap<Token, BTreeSet<Token>>,
    ctx: &AnalysisContext,
) {
    let deleted_methods: HashSet<Token> = request.methods().copied().collect();

    // Build reverse call graph: callee → set of live callers
    let mut callers_of: HashMap<Token, HashSet<Token>> = HashMap::new();
    for (caller, callees) in ssa_call_graph {
        if deleted_methods.contains(caller) {
            continue;
        }
        for callee in callees {
            callers_of.entry(*callee).or_default().insert(*caller);
        }
    }

    let registry = assembly.types();
    for type_entry in registry.iter() {
        let cil_type = type_entry.value();
        if cil_type.is_module_type() {
            continue; // Already handled by sweep_dead_module_methods
        }
        for method in cil_type.methods() {
            if deleted_methods.contains(&method.token) || method.is_cctor() || method.is_ctor() {
                continue;
            }
            let has_callers = callers_of.get(&method.token).is_some_and(|c| !c.is_empty());
            if has_callers {
                continue;
            }
            // A method with no callers in the post-SSA call graph is dead if:
            // - was_inlined: all direct call sites were devirtualized
            // - was_devirtualized: only reachable through deleted callers (e.g.,
            //   delegate targets of deleted strong proxy stubs)
            if ctx.was_inlined(method.token) || ctx.was_devirtualized(method.token) {
                request.add_method(method.token);
            }
        }
    }
}

/// Removes types whose methods are ALL dead or devirtualized.
///
/// After proxy devirtualization replaces calls to obfuscator wrapper methods,
/// the wrapper type's methods become unreferenced. If every method of a type
/// is either inlined (proxy devirt) or dead (global DCE), the type is
/// obfuscator infrastructure and should be deleted.
fn remove_dispensable_types(
    assembly: &CilObject,
    request: &mut CleanupRequest,
    ctx: &AnalysisContext,
) {
    let registry = assembly.types();
    for type_entry in registry.iter() {
        let token: Token = *type_entry.key();
        if token.table() != 0x02 {
            continue;
        }
        if request.types().any(|t| *t == token) {
            continue;
        }
        let cil_type = type_entry.value();
        let methods: Vec<_> = cil_type
            .methods()
            .map(|m| (m.token, m.is_cctor()))
            .collect();
        if methods.is_empty() {
            continue;
        }
        // A type is dispensable if every method is either:
        // - inlined (proxy devirtualization replaced all call sites)
        // - dead (global DCE found no callers)
        // - a .cctor (runtime-invoked, but only exists to initialize
        //   the above — dispensable when all other methods are gone)
        let all_dispensable = methods
            .iter()
            .all(|(m, is_cctor)| *is_cctor || ctx.was_inlined(*m) || ctx.is_dead(*m));
        // Require at least one non-cctor method to be dispensable
        // (avoids deleting types that only have a .cctor)
        let has_dispensable_methods = methods
            .iter()
            .any(|(m, is_cctor)| !is_cctor && (ctx.was_inlined(*m) || ctx.is_dead(*m)));
        if all_dispensable && has_dispensable_methods {
            request.add_type(token);
        }
    }
}

/// Sweeps empty `<Module>` methods after neutralization.
///
/// Scans all methods in `<Module>` that were processed by the SSA pipeline
/// and marks those with <= 1 instruction (just `ret`) for removal. This covers
/// the module `.cctor` (after anti-tamper/anti-debug removal) and other
/// infrastructure methods (anti-debug hooks, etc.) that become empty bodies
/// after the neutralization pass NOP'd their contents.
///
/// `.cctor` methods are always safe to delete when empty because they are
/// invoked by the runtime on first type access, not via explicit IL calls.
/// Non-`.cctor` methods are only deleted if they are known dead (not called
/// by any surviving method). This prevents deleting junk methods that are
/// still referenced — deleting them would shift RIDs and create dangling
/// call targets in the callers.
fn sweep_empty_module_cctor(
    assembly: &CilObject,
    request: &mut CleanupRequest,
    ctx: &AnalysisContext,
) {
    let Some(module_type) = assembly.types().module_type() else {
        return;
    };

    for (_, method_ref) in module_type.methods.iter() {
        let Some(method) = method_ref.upgrade() else {
            continue;
        };

        let Some(ssa_func) = ctx.ssa_functions.get(&method.token) else {
            continue;
        };

        if ssa_func.instruction_count() <= 1 {
            let is_cctor = method.name == wellknown::members::CCTOR;
            let is_dead = ctx.dead_methods.contains(&method.token);

            if !is_cctor && !is_dead {
                continue;
            }

            log::debug!(
                "Sweep: empty module method 0x{:08X} ({}) with {} instructions",
                method.token.value(),
                method.name,
                ssa_func.instruction_count()
            );
            request.add_method(method.token);
        }
    }
}

/// Creates a standard cleanup request from the analysis context configuration.
///
/// Returns `None` if cleanup is disabled. Otherwise returns a `CleanupRequest`
/// with orphan removal and empty type settings from the config.
///
/// # Arguments
///
/// * `ctx` - The analysis context whose cleanup configuration is inspected.
///
/// # Returns
///
/// `Some(CleanupRequest)` with settings derived from the config, or `None`
/// if all cleanup options are disabled.
pub(crate) fn create_cleanup_request(ctx: &AnalysisContext) -> Option<CleanupRequest> {
    let cleanup_config = &ctx.config.cleanup;
    if !cleanup_config.any_enabled() {
        return None;
    }

    Some(CleanupRequest::with_settings(
        cleanup_config.remove_orphan_metadata,
        cleanup_config.remove_empty_types,
    ))
}

#[cfg(test)]
mod tests {
    use crate::{
        cilassembly::CleanupRequest,
        deobfuscation::utils::{is_obfuscated_name, is_special_name},
        metadata::token::Token,
    };

    #[test]
    fn test_cleanup_request_builder() {
        let mut request = CleanupRequest::new();
        request
            .add_type(Token::new(0x02000001))
            .add_method(Token::new(0x06000001))
            .add_field(Token::new(0x04000001));

        assert!(request.has_deletions());
        assert_eq!(request.types_len(), 1);
        assert_eq!(request.methods_len(), 1);
        assert_eq!(request.fields_len(), 1);
    }

    #[test]
    fn test_is_obfuscated_name() {
        assert!(!is_obfuscated_name("MyClass"));
        assert!(!is_obfuscated_name("Main"));
        assert!(is_obfuscated_name("\u{200B}test"));
        assert!(is_obfuscated_name("te\u{200D}st"));
    }

    #[test]
    fn test_is_obfuscated_name_spaces() {
        // BitMono FullRenamer produces space-containing names from word pools
        assert!(is_obfuscated_name(
            "Translate Start <FixedUpdate>b__4_0.get_Syntax"
        ));
        assert!(is_obfuscated_name(
            "get_Syntax get_AllowedCaller get_RebindActionMap"
        ));
        assert!(is_obfuscated_name("A B"));
        // Single words without spaces are not obfuscated
        assert!(!is_obfuscated_name("ValidName"));
        assert!(!is_obfuscated_name("get_Value"));
    }

    #[test]
    fn test_is_special_name() {
        assert!(is_special_name(".ctor"));
        assert!(is_special_name(".cctor"));
        assert!(is_special_name("<Module>"));
        assert!(is_special_name("get_Value"));
        assert!(!is_special_name("MyMethod"));
    }

    #[test]
    fn test_is_special_name_rejects_spaces() {
        // Space-containing names with get_/set_ prefixes should NOT be treated as special
        assert!(!is_special_name("get_Syntax get_AllowedCaller"));
        assert!(!is_special_name("set_Value some_other_word"));
        assert!(!is_special_name(".ctor with spaces"));
        assert!(!is_special_name("<Module> extra"));
        // But angle-bracket-wrapped CLR names with spaces are legitimate
        assert!(is_special_name("<Generic Parameter>"));
        assert!(is_special_name("<Generic Method Parameter>"));
        // Legitimate special names still work
        assert!(is_special_name("get_Value"));
        assert!(is_special_name("set_Item"));
        assert!(is_special_name("add_Click"));
        assert!(is_special_name("remove_Changed"));
    }
}
