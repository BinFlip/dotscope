//! Post-deobfuscation cleanup for ConfuserEx.
//!
//! This module handles removal of protection artifacts after SSA-based
//! deobfuscation completes, producing clean output binaries.
//!
//! # Cleanup Targets
//!
//! - Decryptor methods (if fully decrypted AND dead)
//! - Protection methods (anti-tamper, anti-debug, resource handlers)
//! - Empty types (after method removal)
//! - Orphaned metadata (Param, CustomAttribute entries)
//!
//! # Architecture
//!
//! This module uses the generic cleanup infrastructure from
//! [`crate::deobfuscation::cleanup`]. ConfuserEx-specific logic:
//!
//! 1. Collect tokens to remove from ConfuserEx findings
//! 2. Build a [`CleanupRequest`] with those tokens
//! 3. Call [`execute_cleanup`] to perform the cleanup
//! 4. Handle ConfuserEx-specific post-processing (section removal, renaming)

use std::collections::HashSet;

use crate::{
    assembly::Operand,
    cilassembly::CleanupRequest,
    deobfuscation::{
        cleanup::is_entry_point,
        context::AnalysisContext,
        obfuscators::confuserex::{findings::ConfuserExFindings, ConfuserExObfuscator},
    },
    metadata::{method::Method, signatures::TypeSignature, tables::TableId, token::Token},
    prelude::FlowType,
    CilObject,
};

/// Collects tokens to remove from ConfuserEx findings.
///
/// This function builds a `CleanupRequest` from the detection findings,
/// identifying all protection infrastructure that should be removed.
fn build_cleanup_request(
    findings: &ConfuserExFindings,
    assembly: &CilObject,
    ctx: &AnalysisContext,
) -> CleanupRequest {
    let mut request = CleanupRequest::with_settings(
        ctx.config.cleanup.remove_orphan_metadata,
        ctx.config.cleanup.remove_empty_types,
    );
    let aggressive = ctx.config.cleanup.remove_unused_methods;

    // 1. Collect removable decryptors (methods that are fully decrypted)
    // Note: removable_decryptors() already filters to decryptors where ALL calls
    // were successfully transformed, so we don't check is_dead() - if all calls
    // were decrypted, the method has no live callers by definition.
    if ctx.config.cleanup.remove_decryptors {
        for token in ctx.decryptors.removable_decryptors() {
            if !is_entry_point(assembly, token, aggressive) {
                request.add_method(token);
            }
        }
    }

    // 2. Collect protection methods
    if ctx.config.cleanup.remove_protection_methods {
        // Anti-tamper methods
        for (_, token) in findings.anti_tamper_methods.iter() {
            if !is_entry_point(assembly, *token, aggressive) {
                request.add_method(*token);
            }
        }

        // Anti-debug methods
        for (_, token) in findings.anti_debug_methods.iter() {
            if !is_entry_point(assembly, *token, aggressive) {
                request.add_method(*token);
            }
        }

        // Resource handler methods
        for (_, token) in findings.resource_handler_methods.iter() {
            if !is_entry_point(assembly, *token, aggressive) {
                request.add_method(*token);
            }
        }

        // Decryptor methods from detection - only remove if fully decrypted
        // (all call sites transformed). Check against decryptor context rather than
        // is_dead() since call graph may not reflect post-decryption state.
        for (_, token) in findings.decryptor_methods.iter() {
            let fully_decrypted = ctx.decryptors.is_fully_decrypted(*token);
            if fully_decrypted && !is_entry_point(assembly, *token, aggressive) {
                request.add_method(*token);
            }
        }

        // Native x86 helper methods (converted to CIL, but still infrastructure)
        for (_, native_helper) in findings.native_helpers.iter() {
            if !is_entry_point(assembly, native_helper.token, aggressive) {
                request.add_method(native_helper.token);
            }
        }
    }

    // 3. Collect obfuscator infrastructure types
    for (_, type_token) in findings.obfuscator_type_tokens.iter() {
        request.add_type(*type_token);
    }

    // 4. Collect constant data backing types (ConfuserEx encrypted data)
    for (_, type_token) in findings.constant_data_types.iter() {
        request.add_type(*type_token);
    }

    // 5. Collect constant data fields for FieldRVA cleanup
    for (_, field_token) in findings.constant_data_fields.iter() {
        request.add_field(*field_token);
    }

    // 5b. Collect infrastructure fields (byte[], Assembly fields in <Module>)
    // These are static fields only used by protection infrastructure
    if ctx.config.cleanup.remove_protection_methods {
        for (_, field_token) in findings.infrastructure_fields.iter() {
            request.add_field(*field_token);
        }
    }

    // 6. Collect protection infrastructure types (types nested in <Module> that are internal)
    // These are support types (LZMA decoder, delegates, etc.) no longer needed after deobfuscation
    if ctx.config.cleanup.remove_protection_methods {
        for (_, type_token) in findings.protection_infrastructure_types.iter() {
            request.add_type(*type_token);
        }
    }

    // 7. Collect state machine infrastructure (CFGCtx type and methods)
    // When CFG mode is used, the state machine struct and its methods become dead
    // after decryption completes since all usages are replaced with constants.
    if let Some(ref provider) = findings.statemachine_provider {
        let semantics = provider.semantics();

        // Add the state machine type (CFGCtx struct)
        if let Some(type_token) = semantics.type_token {
            request.add_type(type_token);
        }

        // Add the state machine methods (.ctor and Next)
        if let Some(init_token) = semantics.init_method {
            request.add_method(init_token);
        }
        if let Some(update_token) = semantics.update_method {
            request.add_method(update_token);
        }
    }

    // 8. Collect MethodSpec tokens that instantiate methods being removed.
    // MethodSpec tokens (table 0x2B) are generic method instantiations like
    // Decryptor<string>.Decrypt(). When we remove the base MethodDef, we must
    // also remove all MethodSpec entries that reference it.
    for (methodspec, base_method) in ctx.decryptors.all_methodspec_mappings() {
        if request.is_deleted(base_method) {
            request.add_methodspec(methodspec);
        }
    }

    // 9. Find helper methods that become dead when protection methods are removed.
    // These are methods only called by protection code (resource handlers, decryptors, etc.)
    // that serve no purpose after deobfuscation.
    if ctx.config.cleanup.remove_protection_methods {
        let helper_methods = find_dead_helper_methods(assembly, &request);
        for method_token in helper_methods {
            if !is_entry_point(assembly, method_token, aggressive) {
                request.add_method(method_token);
            }
        }
    }

    request
}

/// Builds a cleanup request for ConfuserEx artifacts.
///
/// This is the main entry point called by `cleanup_request()`.
/// Returns a CleanupRequest that the engine will execute.
pub fn build_request(
    obfuscator: &ConfuserExObfuscator,
    assembly: &CilObject,
    ctx: &AnalysisContext,
) -> Option<CleanupRequest> {
    let cleanup_config = &ctx.config.cleanup;
    if !cleanup_config.any_enabled() {
        return None;
    }

    let findings_guard = obfuscator.findings.read().ok()?;
    let findings = findings_guard.as_ref()?;

    let mut request = build_cleanup_request(findings, assembly, ctx);

    // Add excluded sections from findings
    if cleanup_config.remove_artifact_sections {
        for (_, section_name) in findings.artifact_sections.iter() {
            request.exclude_section(section_name.clone());
        }
    }

    // Note: Module .cctor neutralization will be handled by a future neutralization pass
    // that uses taint analysis to surgically remove protection initialization code
    // while preserving legitimate static initialization.

    if request.has_deletions() || !request.excluded_sections().is_empty() {
        Some(request)
    } else {
        None
    }
}

/// Checks if a method has a byte[] -> byte[] transformation signature.
///
/// ConfuserEx decompression helpers like `byte[] b(byte[])` transform encrypted
/// byte arrays into decrypted ones. This pattern indicates a decompression/decryption helper.
fn is_byte_array_transform_signature(method: &Method) -> bool {
    let sig = &method.signature;

    // Check return type is byte[] (SZArray of U1)
    let returns_byte_array = is_byte_array_type(&sig.return_type.base);

    // Check has exactly one parameter that is byte[]
    let takes_byte_array = sig.params.len() == 1 && is_byte_array_type(&sig.params[0].base);

    returns_byte_array && takes_byte_array
}

/// Checks if a TypeSignature represents a byte[] (SZArray of U1).
fn is_byte_array_type(sig: &TypeSignature) -> bool {
    match sig {
        TypeSignature::SzArray(inner) => matches!(*inner.base, TypeSignature::U1),
        _ => false,
    }
}

/// Checks if a method uses decompression-related types.
///
/// ConfuserEx infrastructure methods use MemoryStream, DeflateStream, GZipStream,
/// or custom LZMA decoders for unpacking encrypted data.
fn uses_decompression_types(assembly: &CilObject, method: &Method) -> bool {
    // Decompression-related type names to look for
    const DECOMPRESSION_TYPES: &[&str] = &[
        "MemoryStream",
        "DeflateStream",
        "GZipStream",
        "BinaryReader",
        "Lzma",
        "LzmaDecoder",
        "SevenZip",
    ];

    for instr in method.instructions() {
        // Check newobj and call instructions for decompression types
        if instr.flow_type != FlowType::Call {
            continue;
        }

        let Operand::Token(token) = &instr.operand else {
            continue;
        };

        // Check MemberRef targets
        if token.is_table(TableId::MemberRef) {
            if let Some(member_ref) = assembly.refs_members().get(token) {
                let member = member_ref.value();

                // Check the declaring type name
                let type_name = member.declaredby.name().unwrap_or_default();
                if DECOMPRESSION_TYPES.iter().any(|t| type_name.contains(t)) {
                    return true;
                }

                // Also check method name for stream operations
                if (member.name.contains("Read")
                    || member.name.contains("Decompress")
                    || member.name.contains("Inflate"))
                    && type_name.contains("Stream")
                {
                    return true;
                }
            }
        }

        // Check MethodDef targets (calls to local methods)
        if token.is_table(TableId::MethodDef) {
            if let Some(method_entry) = assembly.methods().get(token) {
                let target = method_entry.value();

                // Check if calling into a type with decompression-related name
                if let Some(owner) = target.declaring_type_rc() {
                    if DECOMPRESSION_TYPES.iter().any(|t| owner.name.contains(t)) {
                        return true;
                    }
                }
            }
        }
    }

    // Also check local variable types
    for (_, local) in method.local_vars.iter() {
        let type_name = format!("{:?}", local.base);
        if DECOMPRESSION_TYPES.iter().any(|t| type_name.contains(t)) {
            return true;
        }
    }

    false
}

/// Checks if a method creates Thread with ParameterizedThreadStart (anti-debug pattern).
///
/// ConfuserEx anti-debug creates background threads that check for debuggers.
/// Pattern: `new Thread(new ParameterizedThreadStart(...))` with `IsBackground = true`
fn creates_thread_with_delegate(
    assembly: &CilObject,
    method: &Method,
    request: &CleanupRequest,
) -> bool {
    let mut has_thread_ctor = false;
    let mut has_parameterized_thread_start = false;
    let mut references_removed_type = false;

    for instr in method.instructions() {
        if instr.flow_type != FlowType::Call && instr.mnemonic != "newobj" {
            continue;
        }

        let Operand::Token(token) = &instr.operand else {
            continue;
        };

        // Check MemberRef for Thread and delegate constructors
        if token.is_table(TableId::MemberRef) {
            if let Some(member_ref) = assembly.refs_members().get(token) {
                let member = member_ref.value();
                let type_name = member.declaredby.name().unwrap_or_default();

                if type_name == "Thread" && member.name == ".ctor" {
                    has_thread_ctor = true;
                }
                if type_name == "ParameterizedThreadStart" && member.name == ".ctor" {
                    has_parameterized_thread_start = true;
                }
            }
        }

        // Check if ldftn loads a method from a type being removed
        if instr.mnemonic == "ldftn" {
            if let Operand::Token(fn_token) = &instr.operand {
                if fn_token.is_table(TableId::MethodDef) {
                    if let Some(method_entry) = assembly.methods().get(fn_token) {
                        let target = method_entry.value();
                        if let Some(owner) = target.declaring_type_rc() {
                            if request.is_deleted(owner.token) {
                                references_removed_type = true;
                            }
                        }
                    }
                }
            }
        }
    }

    // Strong signal: creates Thread with ParameterizedThreadStart pointing to removed type
    has_thread_ctor && (has_parameterized_thread_start || references_removed_type)
}

/// Finds helper methods that become dead when protection methods are removed.
///
/// A helper method is one that:
/// 1. Is called only by methods that are being removed (protection methods)
/// 2. Or is called only by types that are being removed
/// 3. Or is a decryptor initialization method called only from `.cctor`
/// 4. Or is a decompression helper (byte[] -> byte[]) called only from `.cctor`
/// 5. Or uses decompression types (MemoryStream, DeflateStream) and is only called from `.cctor`
///
/// These methods serve no purpose after deobfuscation and should be removed.
///
/// # Arguments
///
/// * `assembly` - The assembly to scan
/// * `request` - The cleanup request containing methods and types being removed
///
/// # Returns
///
/// A set of method tokens that should also be removed as dead helpers.
fn find_dead_helper_methods(assembly: &CilObject, request: &CleanupRequest) -> HashSet<Token> {
    let mut dead_helpers: HashSet<Token> = HashSet::new();

    // Find the module .cctor token
    let cctor_token = assembly.methods().iter().find_map(|entry| {
        let method = entry.value();
        if method.is_cctor() {
            if let Some(owner) = method.declaring_type_rc() {
                if owner.name == "<Module>" {
                    return Some(method.token);
                }
            }
        }
        None
    });

    // For each method, check if it should be removed
    for method_entry in assembly.methods() {
        let method = method_entry.value();
        let method_token = method.token;

        // Skip if already being removed
        if request.is_deleted(method_token) {
            continue;
        }

        // Skip if method is in a type being removed (will be removed anyway)
        if let Some(owner_type) = method.declaring_type_rc() {
            if request.is_deleted(owner_type.token) {
                continue;
            }
        }

        // Check if this method is only called by methods being removed OR only from .cctor
        let mut called_by_removed = false;
        let mut called_by_cctor_only = false;
        let mut called_by_non_removed = false;
        let mut call_count = 0;

        // Check all callers across the assembly
        for other_method_entry in assembly.methods() {
            let other_method = other_method_entry.value();
            let caller_token = other_method.token;

            // Check if this method calls our target
            let calls_target = other_method.instructions().any(|instr| {
                if let Operand::Token(t) = &instr.operand {
                    t == &method_token
                } else {
                    false
                }
            });

            if calls_target {
                call_count += 1;
                if request.is_deleted(caller_token) {
                    called_by_removed = true;
                } else if Some(caller_token) == cctor_token {
                    called_by_cctor_only = true;
                } else {
                    called_by_non_removed = true;
                    break; // Early exit - has a non-removed caller
                }
            }
        }

        // Case 1: Called only by methods being removed
        if called_by_removed && !called_by_non_removed && !called_by_cctor_only {
            dead_helpers.insert(method_token);
            continue;
        }

        // Case 2: Called only from .cctor and looks like protection infrastructure
        // Heuristics for protection initialization:
        // - In <Module> type
        // - Static method with void() signature
        // - Many locals (decryptor init often has 50+ locals for array setup)
        if called_by_cctor_only && !called_by_non_removed && call_count > 0 {
            let is_in_module = method
                .declaring_type
                .get()
                .and_then(|dt| dt.upgrade())
                .map(|owner| owner.name == "<Module>")
                .unwrap_or(false);

            let is_void_no_params = method.signature.return_type.base == TypeSignature::Void
                && method.signature.params.is_empty();

            let has_many_locals = method.local_vars.count() >= 10;

            // If it's a static void() method in <Module> with many locals, it's likely
            // decryptor initialization that should be removed
            if is_in_module && is_void_no_params && has_many_locals {
                dead_helpers.insert(method_token);
                continue;
            }

            // Case 3: Decompression helper - byte[] -> byte[] signature in <Module>
            // ConfuserEx uses methods like `byte[] b(byte[])` for LZMA decompression
            let is_byte_array_helper = is_in_module && is_byte_array_transform_signature(method);
            if is_byte_array_helper {
                dead_helpers.insert(method_token);
                continue;
            }

            // Case 4: Method uses decompression types (MemoryStream, DeflateStream, etc.)
            // These are infrastructure methods for unpacking encrypted data
            if is_in_module && uses_decompression_types(assembly, method) {
                dead_helpers.insert(method_token);
                continue;
            }
        }

        // Case 5: Called only by removed methods OR .cctor, and is a decompression helper
        // This catches helpers that might be called by both .cctor and other infrastructure
        if (called_by_removed || called_by_cctor_only) && !called_by_non_removed && call_count > 0 {
            let is_in_module = method
                .declaring_type
                .get()
                .and_then(|dt| dt.upgrade())
                .map(|owner| owner.name == "<Module>")
                .unwrap_or(false);

            // Strong signal: method is in <Module>, uses streams, and only infrastructure calls it
            if is_in_module && uses_decompression_types(assembly, method) {
                dead_helpers.insert(method_token);
                continue;
            }
        }
    }

    // Find methods that create infrastructure types (delegates, streams for protection)
    // These are often called from .cctor to set up protection infrastructure
    for method_entry in assembly.methods() {
        let method = method_entry.value();
        let method_token = method.token;

        if request.is_deleted(method_token) || dead_helpers.contains(&method_token) {
            continue;
        }

        let is_in_module = method
            .declaring_type
            .get()
            .and_then(|dt| dt.upgrade())
            .map(|owner| owner.name == "<Module>")
            .unwrap_or(false);

        if !is_in_module {
            continue;
        }

        // Check if method creates Thread with ParameterizedThreadStart (anti-debug pattern)
        // or creates delegates pointing to infrastructure types
        let creates_protection_objects = creates_thread_with_delegate(assembly, method, request);

        if creates_protection_objects {
            // Verify it's only called from .cctor or removed methods
            let has_live_caller = assembly.methods().iter().any(|other_entry| {
                let other = other_entry.value();
                let caller_token = other.token;

                if request.is_deleted(caller_token)
                    || dead_helpers.contains(&caller_token)
                    || Some(caller_token) == cctor_token
                {
                    return false;
                }

                other.instructions().any(|instr| {
                    if let Operand::Token(t) = &instr.operand {
                        t == &method_token
                    } else {
                        false
                    }
                })
            });

            if !has_live_caller {
                dead_helpers.insert(method_token);
            }
        }
    }

    // Iterate to find transitive dead helpers (helpers called only by other helpers)
    loop {
        let mut new_dead: HashSet<Token> = HashSet::new();

        for method_entry in assembly.methods() {
            let method = method_entry.value();
            let method_token = method.token;

            if request.is_deleted(method_token) || dead_helpers.contains(&method_token) {
                continue;
            }

            let mut called_by_dead_only = false;
            let mut called_by_live = false;

            for other_method_entry in assembly.methods() {
                let other_method = other_method_entry.value();
                let caller_token = other_method.token;

                let calls_target = other_method.instructions().any(|instr| {
                    if let Operand::Token(t) = &instr.operand {
                        t == &method_token
                    } else {
                        false
                    }
                });

                if calls_target {
                    if request.is_deleted(caller_token) || dead_helpers.contains(&caller_token) {
                        called_by_dead_only = true;
                    } else {
                        called_by_live = true;
                        break;
                    }
                }
            }

            if called_by_dead_only && !called_by_live {
                new_dead.insert(method_token);
            }
        }

        if new_dead.is_empty() {
            break;
        }
        dead_helpers.extend(new_dead);
    }

    dead_helpers
}

#[cfg(test)]
mod tests {
    use crate::{
        deobfuscation::{DeobfuscationEngine, EngineConfig},
        metadata::validation::ValidationConfig,
        CilObject,
    };

    /// Comprehensive test for ConfuserEx cleanup.
    ///
    /// This test verifies the full cleanup pipeline:
    /// 1. Loads a ConfuserEx-protected sample
    /// 2. Runs the full deobfuscation engine
    /// 3. Validates the output with production-level validation
    /// 4. Verifies protection artifacts were removed:
    ///    - ConfuserEx marker types (ConfusedByAttribute, etc.)
    ///    - Artifact sections (numeric section names)
    ///    - Protection infrastructure (types, methods reduced)
    #[test]
    fn test_cleanup_full_pipeline() {
        let sample_path = "tests/samples/packers/confuserex/mkaring_normal.exe";

        // Skip if sample doesn't exist
        if !std::path::Path::new(sample_path).exists() {
            eprintln!("Skipping test: sample not found at {}", sample_path);
            return;
        }

        // Load original for comparison
        let original =
            CilObject::from_path_with_validation(sample_path, ValidationConfig::analysis())
                .expect("Original should load");

        let original_type_count = original.types().len();

        let original_sections: Vec<String> = original
            .file()
            .sections()
            .iter()
            .map(|s| s.name.clone())
            .collect();

        // Run deobfuscation
        let config = EngineConfig::default();
        let mut engine = DeobfuscationEngine::new(config);
        let (deobfuscated, result) = engine
            .process_file(sample_path)
            .expect("Deobfuscation should succeed");

        // 1. Verify deobfuscation made changes
        let stats = result.stats();
        assert!(
            stats.methods_transformed > 0 || stats.constants_folded > 0,
            "Deobfuscation should have made some changes"
        );

        // 2. Reload with production validation to verify valid output
        let deobfuscated_bytes = deobfuscated.file().data().to_vec();
        let reloaded =
            CilObject::from_mem_with_validation(deobfuscated_bytes, ValidationConfig::production());

        assert!(
            reloaded.is_ok(),
            "Deobfuscated assembly should pass production validation: {:?}",
            reloaded.err()
        );

        let reloaded = reloaded.unwrap();

        // 3. Verify assembly structure is intact
        assert!(reloaded.module().is_some(), "Assembly should have a module");
        assert!(
            reloaded.assembly().is_some(),
            "Assembly should have assembly metadata"
        );

        let entry_token = reloaded.cor20header().entry_point_token;
        assert!(entry_token != 0, "Entry point should still exist");

        // 4. Verify types were reduced (protection infrastructure removed)
        let deobfuscated_type_count = reloaded.types().len();

        assert!(
            deobfuscated_type_count <= original_type_count,
            "Should have same or fewer types after cleanup: {} vs {}",
            deobfuscated_type_count,
            original_type_count
        );

        // 5. Verify ConfuserEx marker types are removed
        let has_confuser_types = deobfuscated.types().iter().any(|t| {
            let type_info = t.value();
            type_info.name.contains("Confuser")
                || type_info.name.contains("ConfusedBy")
                || type_info.namespace.contains("Confuser")
        });

        assert!(
            !has_confuser_types,
            "ConfuserEx marker types should be removed after cleanup"
        );

        // 6. Verify artifact sections are removed (if any existed)
        let original_artifact_sections: Vec<_> = original_sections
            .iter()
            .filter(|name| !name.is_empty() && name.chars().all(|c| c.is_ascii_digit()))
            .collect();

        if !original_artifact_sections.is_empty() {
            let deobfuscated_sections: Vec<String> = deobfuscated
                .file()
                .sections()
                .iter()
                .map(|s| s.name.clone())
                .collect();

            let remaining_artifacts: Vec<&String> = deobfuscated_sections
                .iter()
                .filter(|name| !name.is_empty() && name.chars().all(|c| c.is_ascii_digit()))
                .collect();

            assert!(
                remaining_artifacts.is_empty(),
                "Artifact sections should be removed, but found: {:?}",
                remaining_artifacts
            );
        }
    }
}
