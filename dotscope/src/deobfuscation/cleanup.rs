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
    deobfuscation::{
        context::AnalysisContext,
        obfuscators::utils::{is_obfuscated_name, is_special_name},
    },
    metadata::{
        tables::{FieldRaw, MethodDefRaw, ParamRaw, TypeDefRaw},
        token::Token,
        validation::ValidationConfig,
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
        for token in ctx.dead_methods.iter() {
            let token = *token;
            if !is_entry_point(&assembly, token, aggressive) {
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
        let neutralized: Vec<Token> = ctx.neutralized_tokens.iter().map(|t| *t).collect();
        if !neutralized.is_empty() {
            request.add_rewrite_orphaned_tokens(neutralized);
        }
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
        ctx.events.record(EventKind::Info).message(format!(
            "Cleanup: {types_count} types, {methods_count} methods, {fields_count} fields"
        ));
    }

    for section_name in request.excluded_sections() {
        ctx.events
            .record(EventKind::ArtifactRemoved)
            .message(format!("Removing artifact section: {section_name}"));
    }

    // Create CilAssembly and add cleanup request
    let bytes = assembly.file().data().to_vec();
    let mut cil_assembly = CilAssembly::from_bytes(bytes)?;

    // Log individual removals
    log_cleanup_request(&request, &assembly, ctx);

    // Clone excluded sections before moving request
    let excluded_sections: HashSet<String> = request.excluded_sections().clone();

    // Add cleanup request (the actual cleanup is executed during generation)
    cil_assembly.add_cleanup(&request);

    // Handle renaming
    if rename_obfuscated {
        let count = rename_obfuscated_names(&mut cil_assembly);
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

/// Detects and marks an empty module `.cctor` for removal.
///
/// If the module `.cctor` was processed by the SSA pipeline and its final
/// instruction count is <= 1 (just a `ret`), it has become effectively empty
/// after neutralization and should be removed.
fn sweep_empty_module_cctor(
    assembly: &CilObject,
    request: &mut CleanupRequest,
    ctx: &AnalysisContext,
) {
    let Some(cctor_token) = assembly.types().module_cctor() else {
        return;
    };

    // Only consider if the SSA pipeline processed this method
    let Some(ssa_func) = ctx.ssa_functions.get(&cctor_token) else {
        return;
    };

    // If the .cctor has at most 1 instruction (just `ret`), it's empty
    if ssa_func.instruction_count() <= 1 {
        log::debug!(
            "Sweep: empty module .cctor (0x{:08X}) with {} instructions",
            cctor_token.value(),
            ssa_func.instruction_count()
        );
        request.add_method(cctor_token);
    }
}

/// Creates a standard cleanup request from the analysis context configuration.
///
/// Returns `None` if cleanup is disabled. Otherwise returns a `CleanupRequest`
/// with orphan removal and empty type settings from the config.
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

/// Checks if a method is an entry point that should not be removed.
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

    // In non-aggressive mode, protect public methods as potential external API
    if method.is_public() {
        return true;
    }

    // Instance constructors in public types could be called externally
    if method.is_ctor() && method.is_public() {
        return true;
    }

    false
}

/// Generator for simple sequential names.
#[derive(Debug, Default)]
struct SimpleNameGenerator {
    types: usize,
    methods: usize,
    fields: usize,
    params: usize,
}

impl SimpleNameGenerator {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn next_type_name(&mut self) -> String {
        let name = Self::index_to_name(self.types);
        self.types += 1;
        name
    }

    pub fn next_method_name(&mut self) -> String {
        let name = Self::index_to_name_lower(self.methods);
        self.methods += 1;
        name
    }

    pub fn next_field_name(&mut self) -> String {
        let name = format!("f_{}", Self::index_to_name_lower(self.fields));
        self.fields += 1;
        name
    }

    pub fn next_param_name(&mut self) -> String {
        let name = format!("p_{}", Self::index_to_name_lower(self.params));
        self.params += 1;
        name
    }

    #[must_use]
    pub fn index_to_name(mut index: usize) -> String {
        let mut result = String::new();
        loop {
            let remainder = index % 26;
            // Safe: remainder is always 0..25 from modulo 26
            #[allow(clippy::cast_possible_truncation)]
            result.insert(0, (b'A' + remainder as u8) as char);
            if index < 26 {
                break;
            }
            index = index / 26 - 1;
        }
        result
    }

    #[must_use]
    pub fn index_to_name_lower(mut index: usize) -> String {
        let mut result = String::new();
        loop {
            let remainder = index % 26;
            // Safe: remainder is always 0..25 from modulo 26
            #[allow(clippy::cast_possible_truncation)]
            result.insert(0, (b'a' + remainder as u8) as char);
            if index < 26 {
                break;
            }
            index = index / 26 - 1;
        }
        result
    }
}

/// Renames obfuscated type, method, and field names to simple identifiers.
fn rename_obfuscated_names(cil_assembly: &mut CilAssembly) -> usize {
    let mut renamed_count = 0;
    let mut name_generator = SimpleNameGenerator::new();

    let view = cil_assembly.view();
    let Some(tables) = view.tables() else {
        return 0;
    };

    let Some(strings) = view.strings() else {
        return 0;
    };

    let mut names_to_rename: Vec<(u32, String)> = Vec::new();

    // Collect obfuscated names from TypeDef
    if let Some(typedef_table) = tables.table::<TypeDefRaw>() {
        for rid in 1..=typedef_table.row_count {
            if let Some(typedef) = typedef_table.get(rid) {
                if rid == 1 {
                    continue;
                }

                let name_index = typedef.type_name;
                if name_index > 0 {
                    if let Ok(name) = strings.get(name_index as usize) {
                        if is_obfuscated_name(name)
                            && !is_special_name(name)
                            && !names_to_rename.iter().any(|(idx, _)| *idx == name_index)
                        {
                            let new_name = name_generator.next_type_name();
                            names_to_rename.push((name_index, new_name));
                        }
                    }
                }
            }
        }
    }

    // Collect obfuscated method names from MethodDef
    if let Some(methoddef_table) = tables.table::<MethodDefRaw>() {
        for rid in 1..=methoddef_table.row_count {
            if let Some(methoddef) = methoddef_table.get(rid) {
                let name_index = methoddef.name;
                if name_index > 0 {
                    if let Ok(name) = strings.get(name_index as usize) {
                        if is_obfuscated_name(name)
                            && !is_special_name(name)
                            && !names_to_rename.iter().any(|(idx, _)| *idx == name_index)
                        {
                            let new_name = name_generator.next_method_name();
                            names_to_rename.push((name_index, new_name));
                        }
                    }
                }
            }
        }
    }

    // Collect obfuscated field names from Field
    if let Some(field_table) = tables.table::<FieldRaw>() {
        for rid in 1..=field_table.row_count {
            if let Some(field) = field_table.get(rid) {
                let name_index = field.name;
                if name_index > 0 {
                    if let Ok(name) = strings.get(name_index as usize) {
                        if is_obfuscated_name(name)
                            && !is_special_name(name)
                            && !names_to_rename.iter().any(|(idx, _)| *idx == name_index)
                        {
                            let new_name = name_generator.next_field_name();
                            names_to_rename.push((name_index, new_name));
                        }
                    }
                }
            }
        }
    }

    // Collect obfuscated parameter names from Param
    if let Some(param_table) = tables.table::<ParamRaw>() {
        for rid in 1..=param_table.row_count {
            if let Some(param) = param_table.get(rid) {
                let name_index = param.name;
                if name_index > 0 {
                    if let Ok(name) = strings.get(name_index as usize) {
                        if is_obfuscated_name(name)
                            && !is_special_name(name)
                            && !names_to_rename.iter().any(|(idx, _)| *idx == name_index)
                        {
                            let new_name = name_generator.next_param_name();
                            names_to_rename.push((name_index, new_name));
                        }
                    }
                }
            }
        }
    }

    // Apply the renames to the string heap
    for (string_index, new_name) in &names_to_rename {
        if cil_assembly.string_update(*string_index, new_name).is_ok() {
            renamed_count += 1;
        }
    }

    renamed_count
}

#[cfg(test)]
mod tests {
    use crate::{
        cilassembly::CleanupRequest,
        deobfuscation::{
            cleanup::SimpleNameGenerator,
            obfuscators::utils::{is_obfuscated_name, is_special_name},
        },
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
    fn test_name_generator() {
        assert_eq!(SimpleNameGenerator::index_to_name(0), "A");
        assert_eq!(SimpleNameGenerator::index_to_name(25), "Z");
        assert_eq!(SimpleNameGenerator::index_to_name(26), "AA");
        assert_eq!(SimpleNameGenerator::index_to_name(27), "AB");
        assert_eq!(SimpleNameGenerator::index_to_name(702), "AAA");
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

    /// Regression test: renaming obfuscated names must preserve TypeRef substring
    /// references in the string heap. The .NET string heap uses substring sharing
    /// (e.g., "Console" as a suffix of "writeToConsole"), and the generator must
    /// correctly remap these after heap modifications.
    #[test]
    fn test_rename_preserves_typeref_substring_references() {
        use crate::{cilassembly::CilAssembly, metadata::validation::ValidationConfig, CilObject};

        let path = "tests/samples/packers/bitmono/0.39.0/bitmono_renamer.exe";
        if !std::path::Path::new(path).exists() {
            eprintln!("Skipping: sample not found");
            return;
        }

        let assembly =
            CilObject::from_path_with_validation(path, ValidationConfig::analysis()).unwrap();
        let bytes = assembly.file().data().to_vec();
        let mut cil_assembly = CilAssembly::from_bytes(bytes).unwrap();

        let count = super::rename_obfuscated_names(&mut cil_assembly);
        assert!(count > 0, "Expected at least one rename");

        // Generate and validate with production strictness — this catches broken
        // TypeRef string offsets that would result in "Out of Bounds" errors.
        let output = cil_assembly
            .into_cilobject_with(
                ValidationConfig::production(),
                crate::cilassembly::GeneratorConfig::default(),
            )
            .expect("Generation with renames should produce valid assembly");

        // Double-check: reload from bytes with production validation
        let output_bytes = output.file().data();
        CilObject::from_mem_with_validation(output_bytes.to_vec(), ValidationConfig::production())
            .expect("Roundtrip after rename should pass production validation");
    }
}
