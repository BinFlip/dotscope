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

use std::collections::HashSet;

use crate::{
    cilassembly::{CilAssembly, CleanupRequest, GeneratorConfig},
    compiler::EventKind,
    deobfuscation::{context::AnalysisContext, renamer},
    metadata::{
        tables::TableId, token::Token, typesystem::wellknown, validation::ValidationConfig,
    },
    CilObject, Result,
};

/// Executes unified cleanup combining an obfuscator's request with dead methods.
///
/// This is the main entry point for cleanup after deobfuscation. It:
/// 1. Starts with the obfuscator's cleanup request (if any)
/// 2. Merges in dead methods from analysis
/// 3. Executes cleanup via the `CilAssembly` infrastructure
/// 4. Handles renaming and section exclusion
/// 5. Regenerates the assembly
///
/// # Arguments
///
/// * `assembly` - The assembly to clean up (consumed and regenerated).
/// * `obfuscator_request` - Optional cleanup request from the obfuscator-specific
///   technique. If `None`, a default request is created from the analysis context
///   configuration.
/// * `ctx` - The analysis context containing dead methods, neutralized tokens,
///   configuration settings, and event log.
///
/// # Returns
///
/// A new `CilObject` with the requested types, methods, fields, and sections
/// removed, and any obfuscated names renamed. The assembly is regenerated
/// with strict validation.
///
/// # Errors
///
/// Returns an error if the assembly cannot be parsed from its raw bytes,
/// if string heap updates fail during renaming, or if regeneration of
/// the cleaned assembly fails.
pub fn execute_cleanup(
    assembly: CilObject,
    obfuscator_request: Option<CleanupRequest>,
    ctx: &AnalysisContext,
) -> Result<CilObject> {
    // Start with obfuscator's request or create a new one with config settings
    let mut request = obfuscator_request.unwrap_or_else(|| {
        CleanupRequest::with_settings(
            ctx.config.cleanup.remove_orphan_metadata,
            ctx.config.cleanup.remove_empty_types,
        )
    });

    // Add dead methods from analysis
    let aggressive = ctx.config.cleanup.remove_unused_methods;
    if aggressive {
        let entry_points = compute_entry_points(&assembly, aggressive);
        for token in ctx.dead_methods.iter() {
            let token = *token;
            if !entry_points.contains(&token) {
                request.add_method(token);
            }
        }
    }

    // Add tokens neutralized by SSA passes as cascade candidates.
    // These are MemberRef tokens from Call/CallVirt instructions that passes
    // NOP'd (e.g., AntiDebug removing DateTime calls, CalltoCalli removing
    // reflection trampolines). If they're no longer referenced by any surviving
    // method body, the cascade will remove them and their parent TypeRef/AssemblyRef.
    if ctx.config.cleanup.remove_orphan_metadata {
        let neutralized = ctx.neutralized_tokens.iter().map(|t| *t);
        request.add_rewrite_orphaned_tokens(neutralized);
    }

    // Determine if we should rename obfuscated names
    let rename_obfuscated = ctx.config.cleanup.rename_obfuscated_names;

    // Detect empty module .cctor and add to cleanup request.
    // ModuleRef/AssemblyRef orphan removal is handled by the CilAssembly executor's
    // orphan removal phase (Phase 3) — see orphans.rs.
    sweep_empty_module_cctor(&assembly, &mut request, ctx);

    // Nothing to do
    if !request.has_deletions() && request.excluded_sections().is_empty() && !rename_obfuscated {
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

    // Clone excluded sections before moving request
    let excluded_sections: HashSet<String> = request.excluded_sections().clone();

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

/// Adds methods from a `boxcar::Vec<Token>` to the cleanup request, skipping
/// entry point methods that should be protected.
///
/// This is the standard pattern for adding protection methods to cleanup: iterate
/// the token collection, check each against `is_entry_point()`, and only add
/// non-entry-point methods.
///
/// # Arguments
///
/// * `request` - The cleanup request to add methods to.
/// * `assembly` - The assembly used to resolve method metadata and entry point.
/// * `tokens` - The method tokens to consider for removal.
/// * `aggressive` - If `true`, trust dead-code analysis and only protect the
///   assembly entry point and static constructors. If `false`, also protect
///   public methods as potential external API.
pub(crate) fn add_safe_methods(
    request: &mut CleanupRequest,
    assembly: &CilObject,
    tokens: &boxcar::Vec<Token>,
    aggressive: bool,
) {
    for (_, token) in tokens {
        if !is_entry_point(assembly, *token, aggressive) {
            request.add_method(*token);
        }
    }
}

/// Pre-computes the set of entry-point method tokens that should not be removed.
///
/// This avoids calling [`is_entry_point`] per dead method (which does a linear
/// scan over all methods each time), reducing the overall complexity from
/// O(dead_methods * all_methods) to O(all_methods).
fn compute_entry_points(assembly: &CilObject, aggressive: bool) -> HashSet<Token> {
    let mut entry_points = HashSet::new();

    // Assembly entry point
    let entry_token_val = assembly.cor20header().entry_point_token;
    if entry_token_val != 0 {
        entry_points.insert(Token::new(entry_token_val));
    }

    for method_entry in assembly.methods() {
        let method = method_entry.value();

        // Static constructors are special runtime entry points
        if method.is_cctor() {
            entry_points.insert(method.token);
            continue;
        }

        if aggressive {
            continue;
        }

        // In non-aggressive mode, protect public methods as potential external API.
        // Exception: public methods in <Module> are obfuscator infrastructure.
        if method.is_public() {
            let in_module = assembly.types().module_type().is_some_and(|module_type| {
                module_type
                    .methods
                    .iter()
                    .any(|(_, r)| r.upgrade().is_some_and(|m| m.token == method.token))
            });
            if !in_module {
                entry_points.insert(method.token);
            }
        }
    }

    entry_points
}

/// Checks if a method is an entry point that should not be removed.
///
/// Entry points include the assembly's declared entry point (e.g., `Main`),
/// static constructors (`.cctor`), and — in non-aggressive mode — public methods
/// outside the `<Module>` type.
///
/// # Arguments
///
/// * `assembly` - The assembly containing the method.
/// * `method_token` - The token of the method to check.
/// * `aggressive` - If `true`, only protect the assembly entry point and static
///   constructors. If `false`, also protect public methods.
///
/// # Returns
///
/// `true` if the method should be preserved, `false` if it is safe to remove.
pub(crate) fn is_entry_point(assembly: &CilObject, method_token: Token, aggressive: bool) -> bool {
    // Check if it's the assembly entry point
    let entry_token = assembly.cor20header().entry_point_token;
    if entry_token != 0 && Token::new(entry_token) == method_token {
        return true;
    }

    let method_entry = assembly
        .methods()
        .iter()
        .find(|m| m.value().token == method_token);

    let Some(entry) = method_entry else {
        return false;
    };

    let method = entry.value();

    // Static constructors are special runtime entry points
    if method.is_cctor() {
        return true;
    }

    // In aggressive mode, we trust the dead code analysis for everything else
    if aggressive {
        return false;
    }

    // In non-aggressive mode, protect public methods as potential external API.
    // Exception: public methods in <Module> are obfuscator infrastructure
    // (e.g., constant decryptors, anti-tamper hooks) — not real entry points.
    let in_module = assembly.types().module_type().is_some_and(|module_type| {
        module_type
            .methods
            .iter()
            .any(|(_, r)| r.upgrade().is_some_and(|m| m.token == method_token))
    });
    if method.is_public() && !in_module {
        return true;
    }

    false
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
