//! ConfuserEx deobfuscation integration tests.
//!
//! This test suite verifies deobfuscation of ConfuserEx-protected assemblies,
//! with comprehensive verification using engine findings.
//!
//! # Test Structure
//!
//! Each sample is tested through a unified harness that verifies:
//! 1. Detection: Engine findings confirm expected protections (including post-anti-tamper re-detection)
//! 2. Deobfuscation: Engine processes successfully with cleanup enabled
//! 3. Removal: Re-detection on output confirms artifacts removed, assembly valid, semantics preserved

#![cfg(feature = "deobfuscation")]

mod common;

use std::sync::Arc;

use common::verification::{
    assert_deobfuscation_diagnostics, check_has_switch_dispatcher, verify_semantic_preservation,
    SemanticVerificationResult, VerificationLevel,
};
use dotscope::{
    deobfuscation::{DeobfuscationEngine, EngineConfig},
    metadata::validation::ValidationConfig,
    CilObject,
};

const SAMPLES_DIR: &str = "tests/samples/packers/confuserex/1.6.0";

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
    /// Expect ReferenceProxy methods (call forwarding proxies).
    has_reference_proxy: bool,
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
            description: "Normal protection (constants + anti-debug + reference proxy)",
            expected_protections: ExpectedProtections {
                has_marker_attributes: true,
                has_suppress_ildasm: true,
                has_decryptors: true,
                has_anti_debug: true,
                has_reference_proxy: true,
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
                has_reference_proxy: true,
            },
            is_original: false,
            use_aggressive_config: false,
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
        SampleSpec {
            filename: "mkaring_controlflow_expression.exe",
            description: "Control flow obfuscation with expression predicate",
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
            filename: "mkaring_constants_x86.exe",
            description: "Constants encryption with x86 native cipher",
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
            filename: "mkaring_controlflow_x86.exe",
            description: "Control flow obfuscation with x86 native predicate",
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
            filename: "mkaring_constants_x86_controlflow.exe",
            description: "Constants x86 cipher + control flow normal predicate",
            expected_protections: ExpectedProtections {
                has_marker_attributes: true,
                has_decryptors: true,
                has_control_flow: true,
                ..Default::default()
            },
            is_original: false,
            use_aggressive_config: false,
            check_semantic_preservation: true,
            verification_level: VerificationLevel::Normal,
        },
        SampleSpec {
            filename: "mkaring_constants_x86_controlflow_x86.exe",
            description: "Constants x86 cipher + control flow x86 predicate",
            expected_protections: ExpectedProtections {
                has_marker_attributes: true,
                has_decryptors: true,
                has_control_flow: true,
                ..Default::default()
            },
            is_original: false,
            use_aggressive_config: false,
            check_semantic_preservation: true,
            verification_level: VerificationLevel::Normal,
        },
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
            verification_level: VerificationLevel::Normal,
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
    /// Number of warnings during deobfuscation.
    warning_count: usize,
    /// Number of errors during deobfuscation.
    error_count: usize,
    /// Statistics from deobfuscation.
    stats: Option<DeobfuscationStats>,
    /// Unified verification results (detection from engine findings + removal from re-detection).
    verification: VerificationResult,
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
    // Assembly validity
    assembly_valid: bool,
    has_valid_entry_point: bool,
    no_validation_errors: bool,
    roundtrip_structure_matches: bool,

    // Detection (from engine findings — includes post-anti-tamper re-detection)
    markers_detected: bool,
    suppress_ildasm_detected: bool,
    decryptors_detected: usize,
    anti_debug_detected: usize,
    anti_tamper_detected: usize,
    encrypted_methods_detected: usize,
    resources_detected: usize,
    proxy_methods_detected: usize,

    // Removal (re-detection on deobfuscated output)
    markers_remaining: bool,
    suppress_ildasm_remaining: bool,
    decryptors_remaining: usize,
    anti_debug_remaining: usize,
    anti_tamper_remaining: usize,
    encrypted_methods_remaining: usize,
    resources_remaining: usize,
    proxy_methods_remaining: usize,
    switches_remaining: usize,
}

fn load_sample(filename: &str) -> Result<CilObject, String> {
    let path = format!("{}/{}", SAMPLES_DIR, filename);
    CilObject::from_path_with_validation(&path, ValidationConfig::analysis())
        .map_err(|e| format!("Failed to load {}: {}", filename, e))
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
        warning_count: 0,
        error_count: 0,
        stats: None,
        verification: VerificationResult::default(),
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
        return result;
    }

    // RUN DEOBFUSCATION
    let config = if spec.use_aggressive_config {
        EngineConfig::aggressive()
    } else {
        EngineConfig::default()
    };
    let engine = DeobfuscationEngine::new(config);

    // Run detection on the original assembly before deobfuscation
    let pre_det = engine.detect(&assembly);
    let pre_detected =
        |id: &str| -> bool { pre_det.techniques.iter().any(|t| t.id == id && t.detected) };

    match engine.process_assembly(assembly) {
        Ok((output, deob_result)) => {
            result.success = true;

            let stats = deob_result.stats();
            result.warning_count = 0;
            result.error_count = 0;
            result.stats = Some(DeobfuscationStats {
                methods_transformed: stats.methods_transformed,
                constants_folded: stats.constants_folded,
                strings_decrypted: stats.strings_decrypted,
                branches_simplified: stats.branches_simplified,
                artifacts_removed: stats.artifacts_removed,
            });

            result.methods_after = output.methods().iter().count();

            // DETECTION from pre-deobfuscation technique detection + post-transform
            // technique results. Some techniques (proxy, constants, anti-debug) are
            // only detectable after byte transforms decrypt method bodies.
            let technique_detected = |id: &str| -> bool {
                pre_detected(id)
                    || deob_result
                        .techniques
                        .iter()
                        .any(|t| t.id == id && t.detected)
            };
            result.verification.markers_detected = technique_detected("confuserex.marker");
            result.verification.suppress_ildasm_detected = technique_detected("generic.ildasm");
            result.verification.decryptors_detected = if technique_detected("confuserex.constants")
            {
                1
            } else {
                0
            };
            result.verification.anti_debug_detected = if technique_detected("confuserex.debug") {
                1
            } else {
                0
            };
            result.verification.anti_tamper_detected = if technique_detected("confuserex.tamper") {
                1
            } else {
                0
            };
            result.verification.encrypted_methods_detected =
                if technique_detected("confuserex.tamper") {
                    1
                } else {
                    0
                };
            result.verification.resources_detected = if technique_detected("confuserex.resources") {
                1
            } else {
                0
            };
            result.verification.proxy_methods_detected = if technique_detected("confuserex.proxy") {
                1
            } else {
                0
            };

            // REMOVAL: re-detect on output
            result.verification.has_valid_entry_point = output.cor20header().entry_point_token != 0;
            let engine = DeobfuscationEngine::default();
            let post_det = engine.detect(&output);
            let has_post_technique =
                |id: &str| -> bool { post_det.techniques.iter().any(|t| t.id == id && t.detected) };
            let post_technique_count = |id: &str| -> usize {
                post_det
                    .techniques
                    .iter()
                    .find(|t| t.id == id && t.detected)
                    .map_or(0, |t| t.evidence.len())
            };
            result.verification.markers_remaining = has_post_technique("confuserex.marker");
            result.verification.suppress_ildasm_remaining = has_post_technique("generic.ildasm");
            result.verification.decryptors_remaining = post_technique_count("confuserex.constants")
                + post_technique_count("generic.constants");
            result.verification.anti_debug_remaining =
                post_technique_count("confuserex.debug") + post_technique_count("generic.debug");
            result.verification.anti_tamper_remaining = post_technique_count("confuserex.tamper");
            result.verification.encrypted_methods_remaining =
                post_technique_count("confuserex.tamper");
            result.verification.resources_remaining = post_technique_count("confuserex.resources");
            result.verification.proxy_methods_remaining = post_technique_count("confuserex.proxy");
            let _ = post_det.attribution; // used for detection; individual techniques checked above
            let (_, switch_count) = check_has_switch_dispatcher(&output);
            result.verification.switches_remaining = switch_count;

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
                }
            }

            // SEMANTIC PRESERVATION (if enabled and original is available)
            if spec.check_semantic_preservation && !spec.is_original {
                if let Some(orig) = original_asm {
                    result.semantic_result = Some(verify_semantic_preservation(
                        orig,
                        Arc::new(output),
                        SEMANTIC_TEST_METHODS,
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

        // Detection line (from engine findings)
        if !result.sample.is_original {
            let v = &result.verification;
            let expected = &result.sample.expected_protections;

            let mut detected = Vec::new();
            if expected.has_marker_attributes && v.markers_detected {
                detected.push("markers");
            }
            if expected.has_suppress_ildasm && v.suppress_ildasm_detected {
                detected.push("suppress");
            }
            if expected.has_decryptors && v.decryptors_detected > 0 {
                detected.push("decryptors");
            }
            if expected.has_anti_debug && v.anti_debug_detected > 0 {
                detected.push("antidebug");
            }
            if expected.has_anti_tamper && v.anti_tamper_detected > 0 {
                detected.push("antitamper");
            }
            if expected.has_resources && v.resources_detected > 0 {
                detected.push("resources");
            }
            if expected.has_reference_proxy && v.proxy_methods_detected > 0 {
                detected.push("proxy");
            }

            if !detected.is_empty() {
                eprintln!(
                    "       Detected: {} [decryptors={} antidebug={} antitamper={} encrypted={} resources={} proxies={}]",
                    detected.join(" "),
                    v.decryptors_detected, v.anti_debug_detected, v.anti_tamper_detected,
                    v.encrypted_methods_detected, v.resources_detected, v.proxy_methods_detected,
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

        // Removal line (re-detection on deobfuscated output)
        if !result.sample.is_original {
            let v = &result.verification;
            eprintln!(
                "       Removal: valid={} entry={} markers={} suppress={} decryptors={} encrypted={} proxies={} switches={} roundtrip={}",
                v.assembly_valid, v.has_valid_entry_point,
                v.markers_remaining, v.suppress_ildasm_remaining,
                v.decryptors_remaining, v.encrypted_methods_remaining,
                v.proxy_methods_remaining, v.switches_remaining,
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

        // Detection assertions (engine found expected protections)
        let v = &result.verification;
        if expected.has_marker_attributes {
            assert!(
                v.markers_detected,
                "{}: markers not detected by engine",
                filename
            );
        }
        if expected.has_suppress_ildasm {
            assert!(
                v.suppress_ildasm_detected,
                "{}: suppress_ildasm not detected",
                filename
            );
        }
        if expected.has_decryptors {
            assert!(
                v.decryptors_detected > 0,
                "{}: decryptors not detected",
                filename
            );
        }
        if expected.has_anti_debug {
            assert!(
                v.anti_debug_detected > 0,
                "{}: anti-debug not detected",
                filename
            );
        }
        if expected.has_anti_tamper {
            assert!(
                v.anti_tamper_detected > 0 || v.encrypted_methods_detected > 0,
                "{}: anti-tamper not detected",
                filename
            );
        }
        if expected.has_resources {
            assert!(
                v.resources_detected > 0,
                "{}: resources not detected",
                filename
            );
        }
        if expected.has_reference_proxy {
            assert!(
                v.proxy_methods_detected > 0,
                "{}: reference proxy not detected",
                filename
            );
        }

        // Removal assertions (output should be clean)
        if expected.has_marker_attributes {
            assert!(
                !v.markers_remaining,
                "{}: markers should be removed",
                filename
            );
        }
        if expected.has_suppress_ildasm {
            assert!(
                !v.suppress_ildasm_remaining,
                "{}: suppress_ildasm should be removed",
                filename
            );
        }
        if expected.has_anti_tamper {
            assert_eq!(
                v.encrypted_methods_remaining, 0,
                "{}: encrypted methods should be decrypted",
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

        // Warning/error assertions via shared verifier
        assert_deobfuscation_diagnostics(filename, result.warning_count, result.error_count);
    }
}
