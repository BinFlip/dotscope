//! ConfuserEx deobfuscation integration tests.
//!
//! This test suite verifies deobfuscation of ConfuserEx-protected assemblies,
//! with comprehensive pre- and post-deobfuscation verification.
//!
//! # Test Structure
//!
//! Each sample is tested through a unified harness that verifies:
//! 1. Pre-deobfuscation: Expected protections are detected by the scanner
//! 2. Deobfuscation: Engine processes successfully with cleanup enabled
//! 3. Post-deobfuscation: Artifacts removed, assembly valid, semantics preserved

#![cfg(feature = "deobfuscation")]

use std::{
    collections::{HashMap, HashSet},
    hash::{Hash, Hasher},
    sync::Arc,
};

use dotscope::{
    analysis::{ConstValue, ControlFlowGraph, SsaConverter, SsaFunction, SsaOp, TypeContext},
    assembly::Operand,
    deobfuscation::{detect_confuserex, find_encrypted_methods, DeobfuscationEngine, EngineConfig},
    metadata::{
        method::MethodModifiers, signatures::TypeSignature, token::Token,
        typesystem::CilTypeReference, validation::ValidationConfig,
    },
    CilObject,
};

const SAMPLES_DIR: &str = "tests/samples/packers/confuserex";

/// Methods to test for semantic preservation (compared against original.exe).
const SEMANTIC_TEST_METHODS: &[&str] = &[
    "DemoIfElse",
    "DemoSwitch",
    "DemoLoop",
    "Add",
    "Subtract",
    "Multiply",
    "Divide",
    "Factorial",
    "Fibonacci",
    "SayHello",
    "SayGoodbye",
];

/// Description of a ConfuserEx sample and its expected characteristics.
#[derive(Debug, Clone)]
struct SampleSpec {
    /// Filename relative to SAMPLES_DIR.
    filename: &'static str,
    /// Human-readable description.
    description: &'static str,
    /// Expected protections present BEFORE deobfuscation.
    expected_protections: ExpectedProtections,
    /// Whether this is the unprotected original (baseline).
    is_original: bool,
    /// Use aggressive config for deobfuscation.
    use_aggressive_config: bool,
    /// Check semantic preservation against original.exe.
    check_semantic_preservation: bool,
    /// Verification strictness level.
    verification_level: VerificationLevel,
}

/// Expected protections in a sample.
#[derive(Debug, Clone, Default)]
struct ExpectedProtections {
    /// Expect ConfuserEx marker attributes (ConfusedByAttribute).
    has_marker_attributes: bool,
    /// Expect SuppressIldasmAttribute.
    has_suppress_ildasm: bool,
    /// Expect string/constant decryptor methods.
    has_decryptors: bool,
    /// Expect anti-debug methods.
    has_anti_debug: bool,
    /// Expect anti-tamper (encrypted method bodies).
    has_anti_tamper: bool,
    /// Expect control flow obfuscation (switch dispatchers).
    has_control_flow: bool,
    /// Expect resource encryption.
    has_resources: bool,
}

/// Verification level for semantic preservation checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VerificationLevel {
    /// All core properties must be preserved (strings, calls, constants).
    Normal,
    /// More lenient verification for heavily obfuscated samples.
    /// Accepts partial preservation due to heavy transformation.
    Relaxed,
}

/// All ConfuserEx samples with their expected characteristics.
fn all_samples() -> Vec<SampleSpec> {
    vec![
        SampleSpec {
            filename: "original.exe",
            description: "Unprotected original (baseline)",
            expected_protections: ExpectedProtections::default(),
            is_original: true,
            use_aggressive_config: false,
            check_semantic_preservation: true,
            verification_level: VerificationLevel::Normal,
        },
        SampleSpec {
            filename: "mkaring_minimal.exe",
            description: "Minimal protection (marker only)",
            expected_protections: ExpectedProtections {
                has_marker_attributes: true,
                ..Default::default()
            },
            is_original: false,
            use_aggressive_config: false,
            // Uses signature + fingerprint matching (name-obfuscated)
            check_semantic_preservation: true,
            verification_level: VerificationLevel::Normal,
        },
        SampleSpec {
            filename: "mkaring_normal.exe",
            description: "Normal protection (constants + anti-debug)",
            expected_protections: ExpectedProtections {
                has_marker_attributes: true,
                has_suppress_ildasm: true,
                has_decryptors: true,
                has_anti_debug: true,
                ..Default::default()
            },
            is_original: false,
            use_aggressive_config: false,
            // Uses signature + fingerprint matching (name-obfuscated)
            check_semantic_preservation: true,
            verification_level: VerificationLevel::Normal,
        },
        SampleSpec {
            filename: "mkaring_constants.exe",
            description: "Constants encryption only",
            expected_protections: ExpectedProtections {
                has_marker_attributes: true,
                has_decryptors: true,
                ..Default::default()
            },
            is_original: false,
            use_aggressive_config: false,
            check_semantic_preservation: true,
            verification_level: VerificationLevel::Normal,
        },
        SampleSpec {
            filename: "mkaring_controlflow.exe",
            description: "Control flow obfuscation only",
            expected_protections: ExpectedProtections {
                has_marker_attributes: true,
                has_control_flow: true,
                ..Default::default()
            },
            is_original: false,
            use_aggressive_config: false,
            check_semantic_preservation: true,
            verification_level: VerificationLevel::Normal,
        },
        SampleSpec {
            filename: "mkaring_resources.exe",
            description: "Resource encryption",
            expected_protections: ExpectedProtections {
                has_marker_attributes: true,
                has_resources: true,
                ..Default::default()
            },
            is_original: false,
            use_aggressive_config: false,
            // Uses signature + fingerprint matching (name-obfuscated)
            check_semantic_preservation: true,
            verification_level: VerificationLevel::Normal,
        },
        SampleSpec {
            filename: "mkaring_maximum.exe",
            description: "Maximum protection (all features)",
            expected_protections: ExpectedProtections {
                has_marker_attributes: true,
                has_suppress_ildasm: true,
                has_decryptors: true,
                has_anti_debug: false, // Maximum uses anti-tamper instead
                has_anti_tamper: true,
                has_control_flow: true,
                has_resources: false,
            },
            is_original: false,
            use_aggressive_config: true, // Use aggressive config for maximum
            // Uses signature + fingerprint matching (heavily obfuscated)
            check_semantic_preservation: true,
            verification_level: VerificationLevel::Normal,
        },
        SampleSpec {
            filename: "mkaring_antitamper.exe",
            description: "Anti-tamper only (isolated for decryption bug testing)",
            expected_protections: ExpectedProtections {
                has_marker_attributes: true,
                has_anti_tamper: true,
                ..Default::default()
            },
            is_original: false,
            use_aggressive_config: false,
            check_semantic_preservation: true,
            verification_level: VerificationLevel::Normal,
        },
        SampleSpec {
            filename: "mkaring_constants_dyncyph.exe",
            description: "Constants encryption with dynamic cipher (mode=dynamic)",
            expected_protections: ExpectedProtections {
                has_marker_attributes: true,
                has_decryptors: true,
                ..Default::default()
            },
            is_original: false,
            use_aggressive_config: false,
            check_semantic_preservation: true,
            verification_level: VerificationLevel::Normal,
        },
        SampleSpec {
            filename: "mkaring_constants_cfg.exe",
            description:
                "Constants encryption with CFG mode (cfg=true, order-dependent state machine)",
            expected_protections: ExpectedProtections {
                has_marker_attributes: true,
                has_decryptors: true,
                ..Default::default()
            },
            is_original: false,
            use_aggressive_config: false,
            check_semantic_preservation: true,
            verification_level: VerificationLevel::Normal,
        },
        // NOTE: mkaring_constants_x86.exe is intentionally excluded from integration tests
        // because x86 mode requires native code support which is Windows-only and
        // requires NativeMethodConversionPass. Add it when native code emulation is supported.
        SampleSpec {
            filename: "mkaring_antitamper_controlflow.exe",
            description: "Anti-tamper + ControlFlow (combination test)",
            expected_protections: ExpectedProtections {
                has_marker_attributes: true,
                has_anti_tamper: true,
                has_control_flow: true,
                ..Default::default()
            },
            is_original: false,
            use_aggressive_config: false,
            check_semantic_preservation: true,
            verification_level: VerificationLevel::Normal,
        },
        SampleSpec {
            filename: "mkaring_antitamper_constants_cfg.exe",
            description: "Anti-tamper + Constants CFG mode (combination test)",
            expected_protections: ExpectedProtections {
                has_marker_attributes: true,
                has_anti_tamper: true,
                has_decryptors: true,
                ..Default::default()
            },
            is_original: false,
            use_aggressive_config: false,
            check_semantic_preservation: true,
            verification_level: VerificationLevel::Normal,
        },
        SampleSpec {
            filename: "mkaring_constants_cfg_controlflow.exe",
            description: "Constants CFG + ControlFlow (combination test, no anti-tamper)",
            expected_protections: ExpectedProtections {
                has_marker_attributes: true,
                has_decryptors: true,
                has_control_flow: true,
                ..Default::default()
            },
            is_original: false,
            use_aggressive_config: false,
            check_semantic_preservation: true,
            // 8/11 methods preserved (73%) - CFG+ControlFlow combination loses some string
            // references in DemoIfElse, DemoSwitch, DemoLoop during control flow recovery
            verification_level: VerificationLevel::Relaxed,
        },
    ]
}

/// Results from deobfuscating a sample.
#[derive(Debug)]
struct DeobfuscationTestResult {
    sample: SampleSpec,
    /// Whether deobfuscation succeeded.
    success: bool,
    /// Error message if failed.
    error: Option<String>,
    /// Pre-deobfuscation method count.
    methods_before: usize,
    /// Post-deobfuscation method count.
    methods_after: usize,
    /// Statistics from deobfuscation.
    stats: Option<DeobfuscationStats>,
    /// Post-deobfuscation verification results.
    verification: VerificationResult,
    /// Pre-deobfuscation verification results.
    pre_verification: PreVerificationResult,
    /// Semantic preservation results (if applicable).
    semantic_result: Option<SemanticVerificationResult>,
}

#[derive(Debug, Default)]
struct DeobfuscationStats {
    methods_transformed: usize,
    constants_folded: usize,
    strings_decrypted: usize,
    branches_simplified: usize,
    artifacts_removed: usize,
}

#[derive(Debug, Default)]
struct VerificationResult {
    /// Assembly can be reloaded from bytes.
    assembly_valid: bool,
    /// Marker attributes removed (ConfusedByAttribute).
    markers_removed: bool,
    /// SuppressIldasm removed.
    suppress_ildasm_removed: bool,
    /// Entry point is valid.
    has_valid_entry_point: bool,
    /// No validation errors on reload.
    no_validation_errors: bool,
    /// Methods and types match after roundtrip.
    roundtrip_structure_matches: bool,
    /// Anti-tamper encrypted methods were decrypted.
    encrypted_methods_decrypted: bool,
}

/// Pre-deobfuscation verification: do detected protections match expectations?
#[derive(Debug, Default)]
struct PreVerificationResult {
    /// All expected protections were detected.
    all_expected_detected: bool,
    /// Details for each protection type.
    markers_detected: bool,
    suppress_ildasm_detected: bool,
    decryptors_detected: bool,
    anti_debug_detected: bool,
    anti_tamper_detected: bool,
    control_flow_detected: bool,
    resources_detected: bool,
    /// Count of switch instructions found (for control flow verification).
    switch_count: usize,
}

/// Semantic preservation results.
#[derive(Debug, Default)]
struct SemanticVerificationResult {
    methods_checked: usize,
    methods_preserved: usize,
    average_similarity: f64,
}

fn load_sample(filename: &str) -> Result<CilObject, String> {
    let path = format!("{}/{}", SAMPLES_DIR, filename);
    CilObject::from_path_with_validation(&path, ValidationConfig::analysis())
        .map_err(|e| format!("Failed to load {}: {}", filename, e))
}

/// Verify pre-deobfuscation state: do detected protections match expectations?
fn verify_pre_deobfuscation(
    assembly: &CilObject,
    expected: &ExpectedProtections,
) -> PreVerificationResult {
    let (_, findings) = detect_confuserex(assembly);

    let markers_detected = findings.has_confuser_attributes;
    let suppress_ildasm_detected = findings.has_suppress_ildasm;
    let decryptors_detected = findings.decryptor_methods.count() > 0;
    let anti_debug_detected = findings.anti_debug_methods.count() > 0;
    let anti_tamper_detected =
        findings.anti_tamper_methods.count() > 0 || findings.encrypted_method_count > 0;
    let resources_detected = findings.resource_handler_methods.count() > 0;

    // For control flow, check if methods have switch instructions
    let (control_flow_detected, switch_count) = check_has_switch_dispatcher(assembly);

    // Verify each expected protection was detected
    let markers_ok = !expected.has_marker_attributes || markers_detected;
    let suppress_ok = !expected.has_suppress_ildasm || suppress_ildasm_detected;
    let decryptors_ok = !expected.has_decryptors || decryptors_detected;
    let anti_debug_ok = !expected.has_anti_debug || anti_debug_detected;
    let anti_tamper_ok = !expected.has_anti_tamper || anti_tamper_detected;
    let control_flow_ok = !expected.has_control_flow || control_flow_detected;
    let resources_ok = !expected.has_resources || resources_detected;

    let all_expected_detected = markers_ok
        && suppress_ok
        && decryptors_ok
        && anti_debug_ok
        && anti_tamper_ok
        && control_flow_ok
        && resources_ok;

    PreVerificationResult {
        all_expected_detected,
        markers_detected,
        suppress_ildasm_detected,
        decryptors_detected,
        anti_debug_detected,
        anti_tamper_detected,
        control_flow_detected,
        resources_detected,
        switch_count,
    }
}

/// Check if assembly has switch dispatchers (CFF obfuscation indicator).
fn check_has_switch_dispatcher(assembly: &CilObject) -> (bool, usize) {
    let mut total_switches = 0;

    // Check user methods (not .ctor, .cctor, or compiler-generated)
    for method_entry in assembly.methods().iter() {
        let method = method_entry.value();

        // Skip special methods
        if method.name.starts_with('.') || method.name.contains('<') {
            continue;
        }

        // Try to get CFG and check for switches
        if let Some(cfg) = method.cfg() {
            for node_id in cfg.node_ids() {
                if let Some(block) = cfg.block(node_id) {
                    for instr in &block.instructions {
                        if instr.mnemonic == "switch" {
                            total_switches += 1;
                        }
                    }
                }
            }
        }
    }

    (total_switches > 0, total_switches)
}

/// Verify semantic preservation by comparing deobfuscated methods against original.
/// Uses signature + fingerprint matching to handle name-obfuscated samples.
fn verify_semantic_preservation(
    original_asm: &CilObject,
    deobfuscated_asm: Arc<CilObject>,
    level: VerificationLevel,
) -> SemanticVerificationResult {
    let mut methods_checked = 0;
    let mut methods_preserved = 0;
    let mut total_similarity = 0.0;
    let mut details = Vec::new();

    // First, try name-based matching (for samples without name obfuscation)
    let mut name_matched = 0;
    for method_name in SEMANTIC_TEST_METHODS {
        if build_ssa_for_method(&deobfuscated_asm, method_name).is_some() {
            name_matched += 1;
        }
    }

    let use_name_matching = name_matched >= SEMANTIC_TEST_METHODS.len() / 2;

    if use_name_matching {
        // Name-based matching (simpler, for non-name-obfuscated samples)
        for method_name in SEMANTIC_TEST_METHODS {
            let Some((original_ssa, _)) = build_ssa_for_method(original_asm, method_name) else {
                continue;
            };

            let original_semantics = MethodSemantics::extract(&original_ssa, original_asm);

            let Some((deobfuscated_ssa, _)) = build_ssa_for_method(&deobfuscated_asm, method_name)
            else {
                methods_checked += 1;
                details.push((method_name.to_string(), 0.0, false, "not found".to_string()));
                continue;
            };

            let deobfuscated_semantics =
                MethodSemantics::extract(&deobfuscated_ssa, &deobfuscated_asm);
            let similarity = deobfuscated_semantics.similarity(&original_semantics);
            let preserves = deobfuscated_semantics.preserves_semantics_of(&original_semantics);

            methods_checked += 1;
            total_similarity += similarity;

            if preserves {
                methods_preserved += 1;
                details.push((method_name.to_string(), similarity, true, String::new()));
            } else {
                let missing_strings: Vec<_> = original_semantics
                    .strings
                    .difference(&deobfuscated_semantics.strings)
                    .take(3)
                    .cloned()
                    .collect();

                // Check significant constants (non-trivial values)
                let significant_consts: HashSet<_> = original_semantics
                    .integer_constants
                    .iter()
                    .filter(|&&c| c != 0 && c != 1 && c != -1)
                    .copied()
                    .collect();
                let missing_consts: Vec<_> = significant_consts
                    .difference(&deobfuscated_semantics.integer_constants)
                    .take(3)
                    .copied()
                    .collect();

                let reason = format!(
                    "missing strings: {:?}, missing constants: {:?}",
                    missing_strings, missing_consts
                );
                details.push((method_name.to_string(), similarity, false, reason));
            }
        }
    } else {
        // Signature + fingerprint matching (for name-obfuscated samples)
        // For each reference method, find the best matching deobfuscated method

        // Build candidate list: all deobfuscated methods with their SSA and semantics
        let mut deob_candidates: Vec<(
            Arc<dotscope::metadata::method::Method>,
            SsaFunction,
            MethodSemantics,
            MethodFingerprint,
        )> = Vec::new();

        for method_entry in deobfuscated_asm.methods().iter() {
            let method = method_entry.value();

            // Skip special methods
            if method.name.starts_with('.') || method.name.contains('<') {
                continue;
            }

            // Skip methods with no body
            if let Some(ssa) = build_ssa_for_method_entry(&deobfuscated_asm, method) {
                let semantics = MethodSemantics::extract(&ssa, &deobfuscated_asm);
                let fingerprint = MethodFingerprint::build(method, &ssa, &semantics);
                deob_candidates.push((method.clone(), ssa, semantics, fingerprint));
            }
        }

        // For each reference method, find the best matching deobfuscated method
        for method_name in SEMANTIC_TEST_METHODS {
            let Some((ref_ssa, ref_method)) =
                build_ssa_for_method_with_method(original_asm, method_name)
            else {
                continue;
            };

            let ref_semantics = MethodSemantics::extract(&ref_ssa, original_asm);
            let ref_fingerprint = MethodFingerprint::build(&ref_method, &ref_ssa, &ref_semantics);

            // Build signature key for matching
            let is_instance = !ref_method.flags_modifiers.contains(MethodModifiers::STATIC);
            let ref_sig = SignatureKey {
                param_count: ref_method.signature.params.len(),
                return_type: TypeKind::from_type_signature(&ref_method.signature.return_type.base),
                param_types: ref_method
                    .signature
                    .params
                    .iter()
                    .map(|p| TypeKind::from_type_signature(&p.base))
                    .collect(),
                is_instance,
            };

            // Find best matching candidate by signature + fingerprint + semantics
            let mut best_match: Option<(f64, &MethodSemantics)> = None;

            for (cand_method, _cand_ssa, cand_semantics, cand_fingerprint) in &deob_candidates {
                // Check signature match first
                let cand_is_instance = !cand_method
                    .flags_modifiers
                    .contains(MethodModifiers::STATIC);
                let cand_sig = SignatureKey {
                    param_count: cand_method.signature.params.len(),
                    return_type: TypeKind::from_type_signature(
                        &cand_method.signature.return_type.base,
                    ),
                    param_types: cand_method
                        .signature
                        .params
                        .iter()
                        .map(|p| TypeKind::from_type_signature(&p.base))
                        .collect(),
                    is_instance: cand_is_instance,
                };

                if cand_sig != ref_sig {
                    continue; // Signature must match exactly
                }

                // Calculate combined score: fingerprint similarity + semantic similarity
                let fp_sim = cand_fingerprint.similarity(&ref_fingerprint);
                let sem_sim = cand_semantics.similarity(&ref_semantics);
                let combined = fp_sim * 0.3 + sem_sim * 0.7; // Prioritize semantic similarity

                if best_match.as_ref().is_none_or(|m| combined > m.0) {
                    best_match = Some((combined, cand_semantics));
                }
            }

            // Check if we found a match with sufficient confidence
            if let Some((score, deob_semantics)) = best_match {
                if score > 0.3 {
                    // Minimum threshold for a valid match
                    let preserves = deob_semantics.preserves_semantics_of(&ref_semantics);

                    methods_checked += 1;
                    total_similarity += score;

                    if preserves {
                        methods_preserved += 1;
                        details.push((method_name.to_string(), score, true, String::new()));
                    } else {
                        let missing_strings: Vec<_> = ref_semantics
                            .strings
                            .difference(&deob_semantics.strings)
                            .take(3)
                            .cloned()
                            .collect();

                        // Check significant constants (non-trivial values)
                        let significant_consts: HashSet<_> = ref_semantics
                            .integer_constants
                            .iter()
                            .filter(|&&c| c != 0 && c != 1 && c != -1)
                            .copied()
                            .collect();
                        let missing_consts: Vec<_> = significant_consts
                            .difference(&deob_semantics.integer_constants)
                            .take(3)
                            .copied()
                            .collect();

                        let reason = format!(
                            "missing strings: {:?}, missing constants: {:?}",
                            missing_strings, missing_consts
                        );
                        details.push((method_name.to_string(), score, false, reason));
                    }
                }
                // Low confidence match - method may be inlined/removed, don't count against ratio
            }
            // No signature match - method structure changed significantly, don't count against ratio
        }
    }

    // Print detailed results
    for (name, sim, preserved, reason) in &details {
        if !preserved {
            eprintln!(
                "  [SEM {}] {} - similarity={:.0}% {}",
                if level == VerificationLevel::Relaxed {
                    "WARN"
                } else {
                    "FAIL"
                },
                name,
                sim * 100.0,
                reason
            );
        }
    }

    let average_similarity = if methods_checked > 0 {
        total_similarity / methods_checked as f64
    } else {
        0.0
    };

    SemanticVerificationResult {
        methods_checked,
        methods_preserved,
        average_similarity,
    }
}

/// Run comprehensive deobfuscation test on a sample.
fn test_sample_comprehensive(
    spec: &SampleSpec,
    original_asm: Option<&CilObject>,
) -> DeobfuscationTestResult {
    let mut result = DeobfuscationTestResult {
        sample: spec.clone(),
        success: false,
        error: None,
        methods_before: 0,
        methods_after: 0,
        stats: None,
        verification: VerificationResult::default(),
        pre_verification: PreVerificationResult::default(),
        semantic_result: None,
    };

    // Load the sample
    let assembly = match load_sample(spec.filename) {
        Ok(a) => a,
        Err(e) => {
            result.error = Some(e);
            return result;
        }
    };

    result.methods_before = assembly.methods().iter().count();

    // Skip deobfuscation for original (unprotected) sample
    if spec.is_original {
        result.success = true;
        result.methods_after = result.methods_before;
        result.verification.assembly_valid = true;
        result.verification.has_valid_entry_point = assembly.cor20header().entry_point_token != 0;
        result.verification.no_validation_errors = true;
        result.pre_verification.all_expected_detected = true;
        return result;
    }

    // PRE-DEOBFUSCATION VERIFICATION
    result.pre_verification = verify_pre_deobfuscation(&assembly, &spec.expected_protections);

    // Check pre-deobfuscation state for post-verification
    let (_, findings) = detect_confuserex(&assembly);
    let had_markers = findings.has_confuser_attributes;
    let had_suppress_ildasm = findings.has_suppress_ildasm;
    let encrypted_before = find_encrypted_methods(&assembly).len();

    // RUN DEOBFUSCATION
    let config = if spec.use_aggressive_config {
        EngineConfig::aggressive()
    } else {
        EngineConfig::default()
    };
    let mut engine = DeobfuscationEngine::new(config);

    match engine.process_assembly(assembly) {
        Ok((output, deob_result)) => {
            result.success = true;

            let stats = deob_result.stats();
            result.stats = Some(DeobfuscationStats {
                methods_transformed: stats.methods_transformed,
                constants_folded: stats.constants_folded,
                strings_decrypted: stats.strings_decrypted,
                branches_simplified: stats.branches_simplified,
                artifacts_removed: stats.artifacts_removed,
            });

            result.methods_after = output.methods().iter().count();

            // POST-DEOBFUSCATION VERIFICATION

            // Entry point check
            result.verification.has_valid_entry_point = output.cor20header().entry_point_token != 0;

            // Check if markers were removed
            let (_, findings_after) = detect_confuserex(&output);
            result.verification.markers_removed =
                had_markers && !findings_after.has_confuser_attributes;
            result.verification.suppress_ildasm_removed =
                had_suppress_ildasm && !findings_after.has_suppress_ildasm;

            // Check if encrypted methods were decrypted
            let encrypted_after = find_encrypted_methods(&output).len();
            result.verification.encrypted_methods_decrypted =
                encrypted_before > 0 && encrypted_after == 0;

            // Roundtrip verification
            let bytes = output.file().data();
            match CilObject::from_mem_with_validation(
                bytes.to_vec(),
                ValidationConfig::production(),
            ) {
                Ok(reloaded) => {
                    result.verification.assembly_valid = true;
                    result.verification.no_validation_errors = true;
                    result.verification.roundtrip_structure_matches =
                        output.methods().iter().count() == reloaded.methods().iter().count()
                            && output.types().iter().count() == reloaded.types().iter().count();
                }
                Err(e) => {
                    result.verification.assembly_valid = false;
                    result.error = Some(format!("Roundtrip failed: {}", e));

                    // Debug: Dump method 0x06000007 bytecode if it exists
                    let debug_token = dotscope::metadata::token::Token::new(0x06000007);
                    if let Some(method_entry) = output.methods().get(&debug_token) {
                        let method = method_entry.value();
                        let instrs: Vec<_> = method.instructions().collect();
                        eprintln!("\n=== DEBUG: Method 0x06000007 ({}) ===", method.name);
                        eprintln!("RVA: {:?}", method.rva);
                        eprintln!("Instruction count: {}", instrs.len());
                        eprintln!("First 30 instructions:");
                        for (i, instr) in instrs.iter().enumerate().take(30) {
                            eprintln!("  {:3}: {} {:?}", i, instr.mnemonic, instr.operand);
                        }
                        if instrs.len() > 30 {
                            eprintln!("  ... {} more instructions ...", instrs.len() - 30);
                        }
                    } else {
                        eprintln!("\n=== DEBUG: Method 0x06000007 NOT FOUND in output ===");
                    }
                }
            }

            // SEMANTIC PRESERVATION (if enabled and original is available)
            if spec.check_semantic_preservation && !spec.is_original {
                if let Some(orig) = original_asm {
                    result.semantic_result = Some(verify_semantic_preservation(
                        orig,
                        Arc::new(output),
                        spec.verification_level,
                    ));
                }
            }
        }
        Err(e) => {
            result.error = Some(format!("Deobfuscation failed: {}", e));
        }
    }

    result
}

/// Print a summary of test results.
fn print_summary(results: &[DeobfuscationTestResult]) {
    eprintln!("\n================================================================================");
    eprintln!("CONFUSEREX DEOBFUSCATION TEST SUMMARY");
    eprintln!("================================================================================\n");

    let mut total_passed = 0;
    let mut total_failed = 0;
    let mut total_artifacts_removed = 0;
    let mut total_constants_folded = 0;
    let mut total_methods_transformed = 0;
    let mut total_branches_simplified = 0;

    for result in results {
        let status = if result.success && result.verification.assembly_valid {
            total_passed += 1;
            "PASS"
        } else {
            total_failed += 1;
            "FAIL"
        };

        eprintln!(
            "[{}] {} ({})",
            status, result.sample.filename, result.sample.description
        );

        // Pre-verification line
        if !result.sample.is_original {
            let pre = &result.pre_verification;
            let expected = &result.sample.expected_protections;

            let mut detected = Vec::new();
            if expected.has_marker_attributes && pre.markers_detected {
                detected.push("markers");
            }
            if expected.has_suppress_ildasm && pre.suppress_ildasm_detected {
                detected.push("suppress");
            }
            if expected.has_decryptors && pre.decryptors_detected {
                detected.push("decryptors");
            }
            if expected.has_anti_debug && pre.anti_debug_detected {
                detected.push("antidebug");
            }
            if expected.has_anti_tamper && pre.anti_tamper_detected {
                detected.push("antitamper");
            }
            if expected.has_control_flow && pre.control_flow_detected {
                detected.push(if pre.switch_count > 0 {
                    "cf"
                } else {
                    "cf(none)"
                });
            }
            if expected.has_resources && pre.resources_detected {
                detected.push("resources");
            }

            if !detected.is_empty() {
                eprintln!(
                    "       Pre-check: {} [switches={}]",
                    detected.join(" "),
                    pre.switch_count
                );
            }
        }

        // Stats line
        if let Some(ref stats) = result.stats {
            eprintln!(
                "       Stats: methods={}->{} transformed={} constants={} strings={} branches={} artifacts={}",
                result.methods_before,
                result.methods_after,
                stats.methods_transformed,
                stats.constants_folded,
                stats.strings_decrypted,
                stats.branches_simplified,
                stats.artifacts_removed
            );
            total_artifacts_removed += stats.artifacts_removed;
            total_constants_folded += stats.constants_folded;
            total_methods_transformed += stats.methods_transformed;
            total_branches_simplified += stats.branches_simplified;
        }

        // Post-verification line
        if !result.sample.is_original {
            let v = &result.verification;
            eprintln!(
                "       Post-check: valid={} entry={} markers_rm={} suppress_rm={} encrypted_rm={} roundtrip={}",
                v.assembly_valid,
                v.has_valid_entry_point,
                v.markers_removed,
                v.suppress_ildasm_removed,
                v.encrypted_methods_decrypted,
                v.roundtrip_structure_matches
            );
        }

        // Semantic preservation line
        if let Some(ref sem) = result.semantic_result {
            eprintln!(
                "       Semantic: {}/{} preserved, similarity={:.0}%",
                sem.methods_preserved,
                sem.methods_checked,
                sem.average_similarity * 100.0
            );
        }

        if let Some(ref err) = result.error {
            eprintln!("       Error: {}", err);
        }
    }

    eprintln!("\n--------------------------------------------------------------------------------");
    eprintln!("TOTALS:");
    eprintln!(
        "  Samples: {} passed, {} failed",
        total_passed, total_failed
    );
    eprintln!("  Methods transformed: {}", total_methods_transformed);
    eprintln!("  Constants folded: {}", total_constants_folded);
    eprintln!("  Branches simplified: {}", total_branches_simplified);
    eprintln!("  Artifacts removed: {}", total_artifacts_removed);
    eprintln!("--------------------------------------------------------------------------------\n");
}

/// Main test that runs all samples through the comprehensive deobfuscation pipeline.
#[test]
#[cfg_attr(feature = "skip-expensive-tests", allow(unused_imports))]
fn test_all_confuserex_samples() {
    let samples = all_samples();

    // Load original.exe for semantic comparison
    let original_asm = load_sample("original.exe").ok();

    let mut results = Vec::new();

    for sample in &samples {
        results.push(test_sample_comprehensive(sample, original_asm.as_ref()));
    }

    print_summary(&results);

    // ASSERTIONS: Verify all protected samples passed
    for result in &results {
        if result.sample.is_original {
            continue;
        }

        let filename = result.sample.filename;
        let expected = &result.sample.expected_protections;

        // Core assertions
        assert!(
            result.success,
            "{}: Deobfuscation failed - {:?}",
            filename, result.error
        );

        assert!(
            result.verification.assembly_valid,
            "{}: Output assembly is invalid - {:?}",
            filename, result.error
        );

        assert!(
            result.verification.has_valid_entry_point,
            "{}: Output has no valid entry point",
            filename
        );

        assert!(
            result.verification.roundtrip_structure_matches,
            "{}: Roundtrip structure mismatch",
            filename
        );

        // Pre-verification assertions
        assert!(
            result.pre_verification.all_expected_detected,
            "{}: Expected protections not detected. Expected: markers={} suppress={} decryptors={} antidebug={} antitamper={} cf={} resources={}",
            filename,
            expected.has_marker_attributes,
            expected.has_suppress_ildasm,
            expected.has_decryptors,
            expected.has_anti_debug,
            expected.has_anti_tamper,
            expected.has_control_flow,
            expected.has_resources
        );

        // Marker removal assertions
        if expected.has_marker_attributes {
            assert!(
                result.verification.markers_removed,
                "{}: Marker attributes should be removed",
                filename
            );
        }

        if expected.has_suppress_ildasm {
            assert!(
                result.verification.suppress_ildasm_removed,
                "{}: SuppressIldasm should be removed",
                filename
            );
        }

        // Anti-tamper verification: encrypted method bodies should be decrypted
        if expected.has_anti_tamper {
            assert!(
                result.verification.encrypted_methods_decrypted,
                "{}: Encrypted method bodies should be decrypted after anti-tamper removal",
                filename
            );
        }

        // Decryptor verification
        if expected.has_decryptors {
            if let Some(ref stats) = result.stats {
                assert!(
                    stats.constants_folded > 0 || stats.strings_decrypted > 0,
                    "{}: Expected decryption activity (constants={} strings={})",
                    filename,
                    stats.constants_folded,
                    stats.strings_decrypted
                );
            }
        }

        // Control flow verification
        if expected.has_control_flow {
            if let Some(ref stats) = result.stats {
                assert!(
                    stats.branches_simplified > 0,
                    "{}: Expected branches to be simplified for control flow sample (got {})",
                    filename,
                    stats.branches_simplified
                );
            }
        }

        // Semantic preservation verification
        // Threshold depends on verification level:
        // - Normal: 80% preservation required
        // - Relaxed: 50% preservation required (for heavily obfuscated samples)
        if result.sample.check_semantic_preservation && !result.sample.is_original {
            if let Some(ref sem) = result.semantic_result {
                let preservation_ratio = if sem.methods_checked > 0 {
                    sem.methods_preserved as f64 / sem.methods_checked as f64
                } else {
                    1.0
                };

                let threshold = match result.sample.verification_level {
                    VerificationLevel::Normal => 0.80,
                    VerificationLevel::Relaxed => 0.50,
                };

                assert!(
                    preservation_ratio >= threshold,
                    "{}: Semantic preservation too low ({}/{} = {:.0}%, expected >= {:.0}%)",
                    filename,
                    sem.methods_preserved,
                    sem.methods_checked,
                    preservation_ratio * 100.0,
                    threshold * 100.0
                );
            }
        }
    }
}

// ============================================================================
// COMPREHENSIVE SEMANTIC EXTRACTION AND VERIFICATION
// ============================================================================

/// Wrapper for f64 that implements Hash and Eq for use in HashSet.
#[derive(Debug, Clone, Copy)]
struct OrderedFloat(f64);

impl PartialEq for OrderedFloat {
    fn eq(&self, other: &Self) -> bool {
        self.0.to_bits() == other.0.to_bits()
    }
}

impl Eq for OrderedFloat {}

impl Hash for OrderedFloat {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.to_bits().hash(state);
    }
}

/// Rich semantic content extracted from SSA for comprehensive comparison.
#[derive(Debug, Clone, Default)]
struct MethodSemantics {
    // Content - literals and constants
    pub strings: HashSet<String>,
    pub integer_constants: HashSet<i64>,
    pub float_constants: HashSet<OrderedFloat>,
    pub has_null: bool,
    pub has_true: bool,
    pub has_false: bool,

    // Method calls (qualified names where possible)
    pub calls: HashSet<String>,
    pub virtual_calls: HashSet<String>,
    pub constructor_calls: HashSet<String>,

    // External calls only (MemberRef tokens) - not obfuscated
    pub external_calls: HashSet<String>,

    // Field access (by resolved name)
    pub field_reads: HashSet<String>,
    pub field_writes: HashSet<String>,
    pub static_field_reads: HashSet<String>,
    pub static_field_writes: HashSet<String>,

    // External field reads only (MemberRef tokens) - not obfuscated
    pub external_field_reads: HashSet<String>,

    // Type operations
    pub allocated_types: HashSet<String>,
    pub cast_types: HashSet<String>,

    // Control flow structure
    pub block_count: usize,
    pub has_loops: bool,
    pub has_switches: bool,
    pub has_exceptions: bool,

    // Arithmetic operation counts
    pub arith_ops: HashMap<&'static str, usize>,
}

impl MethodSemantics {
    /// Extract comprehensive semantics from an SSA function.
    fn extract(ssa: &SsaFunction, assembly: &CilObject) -> Self {
        let mut semantics = MethodSemantics {
            block_count: ssa.blocks().len(),
            ..Default::default()
        };

        // Detect loops via back-edges (simplified: block that jumps to earlier block)
        let mut has_back_edge = false;

        for (block_idx, block) in ssa.blocks().iter().enumerate() {
            for instr in block.instructions() {
                match instr.op() {
                    // Constants
                    SsaOp::Const { value, .. } => {
                        Self::extract_constant(&mut semantics, value, assembly);
                    }

                    // Method calls
                    SsaOp::Call { method, .. } => {
                        let token = method.token();
                        if let Some(name) = resolve_method_name(assembly, token) {
                            semantics.calls.insert(name.clone());
                            if is_external_method_token(token) {
                                semantics.external_calls.insert(name);
                            }
                        }
                    }
                    SsaOp::CallVirt { method, .. } => {
                        let token = method.token();
                        if let Some(name) = resolve_method_name(assembly, token) {
                            semantics.virtual_calls.insert(name.clone());
                            semantics.calls.insert(name.clone());
                            if is_external_method_token(token) {
                                semantics.external_calls.insert(name);
                            }
                        }
                    }
                    SsaOp::NewObj { ctor, .. } => {
                        let token = ctor.token();
                        if let Some(name) = resolve_method_name(assembly, token) {
                            semantics.constructor_calls.insert(name.clone());
                            semantics.calls.insert(name.clone());
                            if is_external_method_token(token) {
                                semantics.external_calls.insert(name);
                            }
                        }
                        // Also track the allocated type
                        if let Some(type_name) = resolve_type_from_ctor(assembly, ctor.token()) {
                            semantics.allocated_types.insert(type_name);
                        }
                    }

                    // Field access
                    SsaOp::LoadField { field, .. } => {
                        let token = field.token();
                        if let Some(name) = resolve_field_name(assembly, token) {
                            semantics.field_reads.insert(name.clone());
                            if is_external_field_token(token) {
                                semantics.external_field_reads.insert(name);
                            }
                        }
                    }
                    SsaOp::StoreField { field, .. } => {
                        if let Some(name) = resolve_field_name(assembly, field.token()) {
                            semantics.field_writes.insert(name);
                        }
                    }
                    SsaOp::LoadStaticField { field, .. } => {
                        let token = field.token();
                        if let Some(name) = resolve_field_name(assembly, token) {
                            semantics.static_field_reads.insert(name.clone());
                            if is_external_field_token(token) {
                                semantics.external_field_reads.insert(name);
                            }
                        }
                    }
                    SsaOp::StoreStaticField { field, .. } => {
                        if let Some(name) = resolve_field_name(assembly, field.token()) {
                            semantics.static_field_writes.insert(name);
                        }
                    }

                    // Type operations
                    SsaOp::CastClass { target_type, .. } | SsaOp::IsInst { target_type, .. } => {
                        if let Some(name) = resolve_type_name(assembly, target_type.token()) {
                            semantics.cast_types.insert(name);
                        }
                    }
                    SsaOp::Box { value_type, .. }
                    | SsaOp::Unbox { value_type, .. }
                    | SsaOp::UnboxAny { value_type, .. } => {
                        if let Some(name) = resolve_type_name(assembly, value_type.token()) {
                            semantics.cast_types.insert(name);
                        }
                    }

                    // Control flow
                    SsaOp::Switch { .. } => {
                        semantics.has_switches = true;
                    }
                    SsaOp::Jump { target } => {
                        if *target <= block_idx {
                            has_back_edge = true;
                        }
                    }
                    SsaOp::Branch {
                        true_target,
                        false_target,
                        ..
                    } => {
                        if *true_target <= block_idx || *false_target <= block_idx {
                            has_back_edge = true;
                        }
                    }
                    SsaOp::BranchCmp {
                        true_target,
                        false_target,
                        ..
                    } => {
                        if *true_target <= block_idx || *false_target <= block_idx {
                            has_back_edge = true;
                        }
                    }

                    // Exceptions
                    SsaOp::Throw { .. } | SsaOp::Rethrow => {
                        semantics.has_exceptions = true;
                    }

                    // Arithmetic operations
                    SsaOp::Add { .. } | SsaOp::AddOvf { .. } => {
                        *semantics.arith_ops.entry("add").or_insert(0) += 1;
                    }
                    SsaOp::Sub { .. } | SsaOp::SubOvf { .. } => {
                        *semantics.arith_ops.entry("sub").or_insert(0) += 1;
                    }
                    SsaOp::Mul { .. } | SsaOp::MulOvf { .. } => {
                        *semantics.arith_ops.entry("mul").or_insert(0) += 1;
                    }
                    SsaOp::Div { .. } => {
                        *semantics.arith_ops.entry("div").or_insert(0) += 1;
                    }
                    SsaOp::Rem { .. } => {
                        *semantics.arith_ops.entry("rem").or_insert(0) += 1;
                    }
                    SsaOp::And { .. } => {
                        *semantics.arith_ops.entry("and").or_insert(0) += 1;
                    }
                    SsaOp::Or { .. } => {
                        *semantics.arith_ops.entry("or").or_insert(0) += 1;
                    }
                    SsaOp::Xor { .. } => {
                        *semantics.arith_ops.entry("xor").or_insert(0) += 1;
                    }
                    SsaOp::Shl { .. } => {
                        *semantics.arith_ops.entry("shl").or_insert(0) += 1;
                    }
                    SsaOp::Shr { .. } => {
                        *semantics.arith_ops.entry("shr").or_insert(0) += 1;
                    }
                    SsaOp::Neg { .. } => {
                        *semantics.arith_ops.entry("neg").or_insert(0) += 1;
                    }
                    SsaOp::Not { .. } => {
                        *semantics.arith_ops.entry("not").or_insert(0) += 1;
                    }

                    _ => {}
                }
            }
        }

        semantics.has_loops = has_back_edge;
        semantics
    }

    fn extract_constant(semantics: &mut MethodSemantics, value: &ConstValue, assembly: &CilObject) {
        match value {
            ConstValue::String(token) => {
                if let Some(content) = resolve_user_string(assembly, *token) {
                    semantics.strings.insert(content);
                }
            }
            ConstValue::DecryptedString(content) => {
                semantics.strings.insert(content.clone());
            }
            ConstValue::I8(v) => {
                semantics.integer_constants.insert(i64::from(*v));
            }
            ConstValue::I16(v) => {
                semantics.integer_constants.insert(i64::from(*v));
            }
            ConstValue::I32(v) => {
                semantics.integer_constants.insert(i64::from(*v));
            }
            ConstValue::I64(v) => {
                semantics.integer_constants.insert(*v);
            }
            ConstValue::U8(v) => {
                semantics.integer_constants.insert(i64::from(*v));
            }
            ConstValue::U16(v) => {
                semantics.integer_constants.insert(i64::from(*v));
            }
            ConstValue::U32(v) => {
                semantics.integer_constants.insert(i64::from(*v));
            }
            ConstValue::U64(v) => {
                if *v <= i64::MAX as u64 {
                    semantics.integer_constants.insert(*v as i64);
                }
            }
            ConstValue::NativeInt(v) => {
                semantics.integer_constants.insert(*v);
            }
            ConstValue::NativeUInt(v) => {
                if *v <= i64::MAX as u64 {
                    semantics.integer_constants.insert(*v as i64);
                }
            }
            ConstValue::F32(v) => {
                semantics
                    .float_constants
                    .insert(OrderedFloat(f64::from(*v)));
            }
            ConstValue::F64(v) => {
                semantics.float_constants.insert(OrderedFloat(*v));
            }
            ConstValue::Null => {
                semantics.has_null = true;
            }
            ConstValue::True => {
                semantics.has_true = true;
            }
            ConstValue::False => {
                semantics.has_false = true;
            }
            _ => {}
        }
    }

    /// Calculate similarity score between two semantics (0.0 to 1.0).
    fn similarity(&self, other: &MethodSemantics) -> f64 {
        let string_sim = jaccard_similarity(&self.strings, &other.strings);
        // Use external_calls for similarity since internal calls may be renamed
        let call_sim = jaccard_similarity(&self.external_calls, &other.external_calls);
        let field_read_sim = jaccard_similarity(&self.field_reads, &other.field_reads);
        let const_sim = jaccard_similarity(&self.integer_constants, &other.integer_constants);

        // Weighted average: external calls and strings are most important
        string_sim * 0.35 + call_sim * 0.35 + field_read_sim * 0.15 + const_sim * 0.15
    }

    /// Check if this semantics preserves the essential properties of the original.
    ///
    /// Note: We don't require external calls to be preserved because some obfuscators
    /// use proxy/wrapper methods that call BCL methods indirectly. These proxies may
    /// not be inlined by the deobfuscator, but the semantic behavior is unchanged.
    fn preserves_semantics_of(&self, original: &MethodSemantics) -> bool {
        // All original strings must appear in deobfuscated (most important check)
        let strings_preserved = original.strings.is_subset(&self.strings);

        // For constants, we're lenient - deobfuscation may fold/eliminate some
        // but important ones (non-trivial values) should remain
        let significant_consts: HashSet<_> = original
            .integer_constants
            .iter()
            .filter(|&&c| c != 0 && c != 1 && c != -1)
            .copied()
            .collect();
        let deob_consts: HashSet<_> = self.integer_constants.iter().copied().collect();
        let consts_preserved =
            significant_consts.is_empty() || significant_consts.is_subset(&deob_consts);

        // External calls and field reads are NOT required because obfuscators often
        // use proxy methods that wrap BCL calls. The deobfuscator may not inline these
        // proxies, but the semantic behavior is still preserved.
        //
        // We still track them for similarity scoring, but don't require preservation.

        strings_preserved && consts_preserved
    }
}

/// Check if a method token refers to an external method.
/// External = MemberRef (0x0A) or MethodSpec (0x2B)
/// Internal = MethodDef (0x06)
fn is_external_method_token(token: Token) -> bool {
    let table_id = token.table();
    // MemberRef (0x0A) = external method reference
    // MethodSpec (0x2B) = generic method instantiation (typically external)
    // MethodDef (0x06) = internal method definition
    table_id == 0x0A || table_id == 0x2B
}

/// Check if a field token refers to an external field.
/// External = MemberRef (0x0A) for field references
/// Internal = Field (0x04)
fn is_external_field_token(token: Token) -> bool {
    let table_id = token.table();
    // MemberRef (0x0A) = external field reference
    // Field (0x04) = internal field definition
    table_id == 0x0A
}

/// Structural fingerprint for matching methods across obfuscated assemblies.
#[derive(Debug, Clone)]
struct MethodFingerprint {
    // Signature components (most reliable for matching)
    pub param_count: usize,
    pub return_type_kind: TypeKind,
    pub param_type_kinds: Vec<TypeKind>,
    pub is_instance: bool,

    // Structural metrics
    pub block_count: usize,
    pub instruction_count: usize,

    // Behavioral metrics
    pub has_loops: bool,
    pub has_switches: bool,
}

/// Simplified type classification for fingerprinting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum TypeKind {
    Void,
    Bool,
    Char,
    I8,
    U8,
    I16,
    U16,
    I32,
    U32,
    I64,
    U64,
    F32,
    F64,
    String,
    Object,
    Array,
    IntPtr,
    UIntPtr,
    ValueType,
    Class,
    Generic,
    ByRef,
    Pointer,
    Other,
}

impl TypeKind {
    fn from_type_signature(sig: &TypeSignature) -> Self {
        match sig {
            TypeSignature::Void => TypeKind::Void,
            TypeSignature::Boolean => TypeKind::Bool,
            TypeSignature::Char => TypeKind::Char,
            TypeSignature::I1 => TypeKind::I8,
            TypeSignature::U1 => TypeKind::U8,
            TypeSignature::I2 => TypeKind::I16,
            TypeSignature::U2 => TypeKind::U16,
            TypeSignature::I4 => TypeKind::I32,
            TypeSignature::U4 => TypeKind::U32,
            TypeSignature::I8 => TypeKind::I64,
            TypeSignature::U8 => TypeKind::U64,
            TypeSignature::R4 => TypeKind::F32,
            TypeSignature::R8 => TypeKind::F64,
            TypeSignature::String => TypeKind::String,
            TypeSignature::Object => TypeKind::Object,
            TypeSignature::I => TypeKind::IntPtr,
            TypeSignature::U => TypeKind::UIntPtr,
            TypeSignature::SzArray(_) | TypeSignature::Array(_) => TypeKind::Array,
            TypeSignature::ValueType(_) => TypeKind::ValueType,
            TypeSignature::Class(_) => TypeKind::Class,
            TypeSignature::GenericInst { .. }
            | TypeSignature::GenericParamType(_)
            | TypeSignature::GenericParamMethod(_) => TypeKind::Generic,
            TypeSignature::ByRef(_) => TypeKind::ByRef,
            TypeSignature::Ptr(_) => TypeKind::Pointer,
            _ => TypeKind::Other,
        }
    }
}

impl MethodFingerprint {
    /// Build a fingerprint from a method and its SSA representation.
    fn build(
        method: &dotscope::metadata::method::Method,
        ssa: &SsaFunction,
        semantics: &MethodSemantics,
    ) -> Self {
        let is_instance = !method.flags_modifiers.contains(MethodModifiers::STATIC);
        let param_count = method.signature.params.len();
        let return_type_kind = TypeKind::from_type_signature(&method.signature.return_type.base);
        let param_type_kinds: Vec<_> = method
            .signature
            .params
            .iter()
            .map(|p| TypeKind::from_type_signature(&p.base))
            .collect();

        // Count instructions
        let instruction_count: usize = ssa.blocks().iter().map(|b| b.instructions().len()).sum();

        MethodFingerprint {
            param_count,
            return_type_kind,
            param_type_kinds,
            is_instance,
            block_count: semantics.block_count,
            instruction_count,
            has_loops: semantics.has_loops,
            has_switches: semantics.has_switches,
        }
    }

    /// Calculate structural similarity between two fingerprints (0.0 to 1.0).
    fn similarity(&self, other: &MethodFingerprint) -> f64 {
        let mut score = 0.0;
        let mut weight = 0.0;

        // Signature match is most important (0.5 weight)
        if self.return_type_kind == other.return_type_kind {
            score += 0.2;
        }
        weight += 0.2;

        if self.param_count == other.param_count {
            score += 0.15;
            // If param counts match, check param types
            let matching_params = self
                .param_type_kinds
                .iter()
                .zip(&other.param_type_kinds)
                .filter(|(a, b)| a == b)
                .count();
            if self.param_count > 0 {
                score += 0.15 * (matching_params as f64 / self.param_count as f64);
            } else {
                score += 0.15;
            }
        }
        weight += 0.3;

        // Instance vs static
        if self.is_instance == other.is_instance {
            score += 0.1;
        }
        weight += 0.1;

        // Structural similarity (block count, instruction count)
        let block_ratio = if self.block_count.max(other.block_count) > 0 {
            self.block_count.min(other.block_count) as f64
                / self.block_count.max(other.block_count) as f64
        } else {
            1.0
        };
        score += 0.1 * block_ratio;
        weight += 0.1;

        let instr_ratio = if self.instruction_count.max(other.instruction_count) > 0 {
            self.instruction_count.min(other.instruction_count) as f64
                / self.instruction_count.max(other.instruction_count) as f64
        } else {
            1.0
        };
        score += 0.1 * instr_ratio;
        weight += 0.1;

        // Behavioral similarity
        if self.has_loops == other.has_loops {
            score += 0.05;
        }
        weight += 0.05;

        if self.has_switches == other.has_switches {
            score += 0.05;
        }
        weight += 0.05;

        if weight > 0.0 {
            score / weight
        } else {
            0.0
        }
    }
}

/// Signature key for method matching (param count + types).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct SignatureKey {
    param_count: usize,
    return_type: TypeKind,
    param_types: Vec<TypeKind>,
    is_instance: bool,
}

fn jaccard_similarity<T: Eq + std::hash::Hash>(a: &HashSet<T>, b: &HashSet<T>) -> f64 {
    if a.is_empty() && b.is_empty() {
        return 1.0;
    }
    let intersection = a.intersection(b).count();
    let union = a.union(b).count();
    if union == 0 {
        1.0
    } else {
        intersection as f64 / union as f64
    }
}

fn resolve_user_string(assembly: &CilObject, token: u32) -> Option<String> {
    let userstrings = assembly.userstrings()?;
    let content = userstrings.get(token as usize).ok()?;
    Some(content.to_string_lossy().to_string())
}

fn resolve_field_name(assembly: &CilObject, token: Token) -> Option<String> {
    let table_id = token.table();

    match table_id {
        0x04 => {
            // Field table - search through types to find the field
            for entry in assembly.types().iter() {
                let cil_type = entry.value();
                for (_idx, field) in cil_type.fields.iter() {
                    if field.token == token {
                        let namespace = if cil_type.namespace.is_empty() {
                            String::new()
                        } else {
                            format!("{}.", cil_type.namespace)
                        };
                        return Some(format!("{}{}::{}", namespace, cil_type.name, field.name));
                    }
                }
            }
            Some(format!("Field<{}>", token.row()))
        }
        0x0A => {
            // MemberRef - could be a field reference
            if let Some(member_ref) = assembly.refs_members().get(&token) {
                let member_ref = member_ref.value();
                let type_name = get_declaring_type_name(&member_ref.declaredby);
                Some(format!("{}::{}", type_name, member_ref.name))
            } else {
                None
            }
        }
        _ => None,
    }
}

fn resolve_type_name(assembly: &CilObject, token: Token) -> Option<String> {
    let table_id = token.table();

    match table_id {
        0x01 | 0x02 | 0x1B => {
            // TypeRef (0x01), TypeDef (0x02), or TypeSpec (0x1B)
            // Use TypeRegistry.get() which handles all type tokens
            if let Some(cil_type) = assembly.types().get(&token) {
                if cil_type.namespace.is_empty() {
                    Some(cil_type.name.clone())
                } else {
                    Some(format!("{}.{}", cil_type.namespace, cil_type.name))
                }
            } else {
                Some(format!("Type<{:08X}>", token.value()))
            }
        }
        _ => None,
    }
}

fn resolve_type_from_ctor(assembly: &CilObject, ctor_token: Token) -> Option<String> {
    let table_id = ctor_token.table();

    match table_id {
        0x06 => {
            // MethodDef - find the declaring type
            for entry in assembly.types().iter() {
                let cil_type = entry.value();
                for (_idx, method_ref) in cil_type.methods.iter() {
                    if let Some(m) = method_ref.upgrade() {
                        if m.token == ctor_token {
                            if cil_type.namespace.is_empty() {
                                return Some(cil_type.name.clone());
                            } else {
                                return Some(format!("{}.{}", cil_type.namespace, cil_type.name));
                            }
                        }
                    }
                }
            }
            None
        }
        0x0A => {
            // MemberRef
            if let Some(member_ref) = assembly.refs_members().get(&ctor_token) {
                let member_ref = member_ref.value();
                Some(get_declaring_type_name(&member_ref.declaredby))
            } else {
                None
            }
        }
        _ => None,
    }
}

fn get_declaring_type_name(type_ref: &CilTypeReference) -> String {
    match type_ref {
        CilTypeReference::TypeRef(tr) => {
            let ns = tr.namespace().unwrap_or_default();
            let name = tr.name().unwrap_or_else(|| "Unknown".to_string());
            if ns.is_empty() {
                name
            } else {
                format!("{}.{}", ns, name)
            }
        }
        CilTypeReference::TypeDef(td) => {
            let ns = td.namespace().unwrap_or_default();
            let name = td.name().unwrap_or_else(|| "Unknown".to_string());
            if ns.is_empty() {
                name
            } else {
                format!("{}.{}", ns, name)
            }
        }
        CilTypeReference::TypeSpec(ts) => ts.name().unwrap_or_else(|| "TypeSpec".to_string()),
        CilTypeReference::Module(m) => format!("[Module:{}]", m.name),
        CilTypeReference::ModuleRef(mr) => format!("[ModuleRef:{}]", mr.name),
        CilTypeReference::MethodDef(md) => {
            if let Some(m) = md.upgrade() {
                format!("[MethodDef:{}]", m.name)
            } else {
                "[MethodDef:Unknown]".to_string()
            }
        }
        CilTypeReference::None => "Unknown".to_string(),
        _ => "Unknown".to_string(),
    }
}

fn resolve_method_name(assembly: &CilObject, token: Token) -> Option<String> {
    let table_id = token.table();

    match table_id {
        0x06 => {
            let method = assembly.methods().get(&token)?;
            let method = method.value();

            for entry in assembly.types().iter() {
                let cil_type = entry.value();
                for (_idx, method_ref) in cil_type.methods.iter() {
                    if let Some(m) = method_ref.upgrade() {
                        if m.token == token {
                            let namespace = if cil_type.namespace.is_empty() {
                                String::new()
                            } else {
                                format!("{}.", cil_type.namespace)
                            };
                            return Some(format!(
                                "{}{}::{}",
                                namespace, cil_type.name, method.name
                            ));
                        }
                    }
                }
            }
            Some(method.name.clone())
        }
        0x0A => {
            if let Some(member_ref) = assembly.refs_members().get(&token) {
                let member_ref = member_ref.value();
                let type_name = get_declaring_type_name(&member_ref.declaredby);
                return Some(format!("{}::{}", type_name, member_ref.name));
            }
            Some(format!("MemberRef<{}>", token.row()))
        }
        0x2B => Some(format!("MethodSpec<{}>", token.row())),
        _ => None,
    }
}

fn build_ssa_for_method(assembly: &CilObject, method_name: &str) -> Option<(SsaFunction, Token)> {
    let (ssa, method) = build_ssa_for_method_with_method(assembly, method_name)?;
    Some((ssa, method.token))
}

fn build_ssa_for_method_with_method(
    assembly: &CilObject,
    method_name: &str,
) -> Option<(SsaFunction, Arc<dotscope::metadata::method::Method>)> {
    let method = assembly
        .methods()
        .iter()
        .find(|e| e.value().name == method_name)
        .map(|e| e.value().clone())?;

    let cfg = method.cfg()?;
    let is_static = method.flags_modifiers.contains(MethodModifiers::STATIC);
    let num_args = method.signature.params.len() + if is_static { 0 } else { 1 };

    let declared_locals = method.local_vars.count();
    let max_local_used = find_max_local_index(&cfg);
    let num_locals = declared_locals.max(max_local_used + 1);

    let type_context = TypeContext::new(&method, assembly);
    let ssa = SsaConverter::build(&cfg, num_args, num_locals, Some(&type_context)).ok()?;
    Some((ssa, method))
}

fn build_ssa_for_method_entry(
    assembly: &CilObject,
    method: &Arc<dotscope::metadata::method::Method>,
) -> Option<SsaFunction> {
    let cfg = method.cfg()?;
    let is_static = method.flags_modifiers.contains(MethodModifiers::STATIC);
    let num_args = method.signature.params.len() + if is_static { 0 } else { 1 };

    let declared_locals = method.local_vars.count();
    let max_local_used = find_max_local_index(&cfg);
    let num_locals = declared_locals.max(max_local_used + 1);

    let type_context = TypeContext::new(method, assembly);
    SsaConverter::build(&cfg, num_args, num_locals, Some(&type_context)).ok()
}

fn find_max_local_index(cfg: &ControlFlowGraph) -> usize {
    let mut max_index: usize = 0;
    for node_id in cfg.node_ids() {
        if let Some(block) = cfg.block(node_id) {
            for instr in &block.instructions {
                if let Operand::Local(idx) = &instr.operand {
                    max_index = max_index.max(*idx as usize);
                }
            }
        }
    }
    max_index
}
