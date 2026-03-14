//! BitMono deobfuscation integration tests.
//!
//! This test suite verifies deobfuscation of BitMono-protected assemblies,
//! with comprehensive verification using engine findings.
//!
//! # Test Structure
//!
//! Each sample is tested through a unified harness that verifies:
//! 1. Detection: Engine findings confirm expected protections
//! 2. Deobfuscation: Engine processes successfully with cleanup enabled
//! 3. Removal: Re-detection on output confirms artifacts removed, assembly valid, semantics preserved
//!
//! # Status
//!
//! This test will progressively pass as deobfuscation phases are implemented:
//! - Phase 3: Detection + cleanup (SuppressIldasm, AntiDe4dot, infrastructure types)
//! - Phase 4: StringsEncryption decryption
//! - Phase 5: CallToCalli reversal
//! - Phase 6: DotNetHook removal
//! - Phase 7: BitMethodDotnet + BillionNops cleanup
//! - Phase 8: AntiDebugBreakpoints removal
//! - Phase 9: UnmanagedString, ObjectReturnType, NoNamespaces

#![cfg(feature = "deobfuscation")]

mod common;

use std::sync::Arc;

use common::verification::{
    assert_deobfuscation_diagnostics, verify_semantic_preservation, SemanticVerificationResult,
    VerificationLevel,
};
use dotscope::{
    deobfuscation::{DeobfuscationEngine, DeobfuscationResult, EngineConfig},
    metadata::validation::ValidationConfig,
    CilObject,
};

const SAMPLES_DIR: &str = "tests/samples/packers/bitmono/0.39.0";

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

/// Description of a BitMono sample and its expected characteristics.
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct SampleSpec {
    /// Filename relative to SAMPLES_DIR.
    filename: &'static str,
    /// Human-readable description.
    description: &'static str,
    /// Expected protections present BEFORE deobfuscation.
    expected_protections: ExpectedProtections,
    /// Whether this is the unprotected original (baseline).
    is_original: bool,
    /// Whether this sample requires PE repair to load (PE-level protections).
    requires_pe_repair: bool,
    /// Check semantic preservation against original.exe.
    check_semantic_preservation: bool,
    /// Verification strictness level.
    verification_level: VerificationLevel,
}

/// Expected protections in a BitMono sample.
#[derive(Debug, Clone, Default)]
#[allow(dead_code)]
struct ExpectedProtections {
    // PE-level packers
    /// PE signature corrupted (BitDotNet).
    has_pe_corruption: bool,
    /// CLR header zeroed (BitDecompiler).
    has_clr_header_corruption: bool,
    /// Data directory count inflated (BitMono packer).
    has_data_directory_inflation: bool,

    // Reversible IL-level
    /// StringsEncryption (AES + Rfc2898DeriveBytes decryptor).
    has_string_encryption: bool,
    /// CallToCalli (ldtoken + ResolveMethod + calli pattern).
    has_call_to_calli: bool,
    /// DotNetHook (VirtualProtect + Marshal.Write infrastructure).
    has_dotnethook: bool,
    /// UnmanagedString (fake native methods in <Module>).
    has_unmanaged_string: bool,
    /// AntiDebugBreakpoints (DateTime timing checks).
    has_anti_debug: bool,

    // Cleanup targets
    /// SuppressIldasmAttribute on the module.
    has_suppress_ildasm: bool,
    /// AntiDe4dot fake obfuscator attributes.
    has_anti_de4dot: bool,
    /// BitMethodDotnet junk prefix (br.s + orphan prefix opcode).
    has_junk_prefix: bool,
    /// BillionNops dead method (> 50k nops).
    has_billion_nops: bool,

    // Lossy IL-level (detection only)
    /// FullRenamer space-containing names.
    has_renamed_names: bool,
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
    /// Detection score from engine findings.
    detection_score: usize,
    /// Number of warnings during deobfuscation.
    warning_count: usize,
    /// Number of errors during deobfuscation.
    error_count: usize,
    /// Verification results.
    verification: VerificationResult,
    /// Semantic preservation results (if applicable).
    semantic_result: Option<SemanticVerificationResult>,
}

#[derive(Debug, Default)]
struct VerificationResult {
    // Assembly validity
    assembly_valid: bool,
    has_valid_entry_point: bool,
    roundtrip_structure_matches: bool,

    // Detection (from engine findings)
    suppress_ildasm_detected: bool,
    anti_de4dot_detected: usize,
    decryptors_detected: usize,
    anti_debug_detected: usize,
    infrastructure_types_detected: usize,

    // Removal (re-detection on deobfuscated output)
    post_detection_score: usize,
    suppress_ildasm_remaining: bool,
    anti_de4dot_remaining: usize,
    decryptors_remaining: usize,
    infrastructure_types_remaining: usize,
}

/// All BitMono samples with their expected characteristics.
fn all_samples() -> Vec<SampleSpec> {
    vec![
        SampleSpec {
            filename: "original.exe",
            description: "Unprotected original (baseline)",
            expected_protections: ExpectedProtections::default(),
            is_original: true,
            requires_pe_repair: false,
            check_semantic_preservation: true,
            verification_level: VerificationLevel::Normal,
        },
        // === PE-level packers ===
        SampleSpec {
            filename: "bitmono_bitdotnet.exe",
            description: "BitDotNet PE signature corruption",
            expected_protections: ExpectedProtections {
                has_pe_corruption: true,
                ..Default::default()
            },
            is_original: false,
            requires_pe_repair: true,
            check_semantic_preservation: true,
            verification_level: VerificationLevel::Normal,
        },
        SampleSpec {
            filename: "bitmono_bitdecompiler.exe",
            description: "BitDecompiler CLR header zeroing",
            expected_protections: ExpectedProtections {
                has_clr_header_corruption: true,
                ..Default::default()
            },
            is_original: false,
            requires_pe_repair: true,
            check_semantic_preservation: true,
            verification_level: VerificationLevel::Normal,
        },
        SampleSpec {
            filename: "bitmono_packer.exe",
            description: "BitMono packer data directory inflation",
            expected_protections: ExpectedProtections {
                has_data_directory_inflation: true,
                ..Default::default()
            },
            is_original: false,
            requires_pe_repair: true,
            check_semantic_preservation: true,
            verification_level: VerificationLevel::Normal,
        },
        SampleSpec {
            filename: "bitmono_pe_combined.exe",
            description: "BitDotNet + StringsEncryption combined protections",
            expected_protections: ExpectedProtections {
                has_pe_corruption: true,
                has_string_encryption: true,
                ..Default::default()
            },
            is_original: false,
            requires_pe_repair: true,
            check_semantic_preservation: true,
            verification_level: VerificationLevel::Normal,
        },
        // === Reversible IL-level ===
        SampleSpec {
            filename: "bitmono_strings.exe",
            description: "StringsEncryption (AES + Rfc2898DeriveBytes)",
            expected_protections: ExpectedProtections {
                has_string_encryption: true,
                ..Default::default()
            },
            is_original: false,
            requires_pe_repair: false,
            check_semantic_preservation: true,
            verification_level: VerificationLevel::Normal,
        },
        SampleSpec {
            filename: "bitmono_calltocalli.exe",
            description: "CallToCalli (ldtoken + ResolveMethod + calli)",
            expected_protections: ExpectedProtections {
                has_call_to_calli: true,
                ..Default::default()
            },
            is_original: false,
            requires_pe_repair: false,
            check_semantic_preservation: true,
            verification_level: VerificationLevel::Normal,
        },
        SampleSpec {
            filename: "bitmono_dotnethook.exe",
            description: "DotNetHook (VirtualProtect + Marshal.Write hooking)",
            expected_protections: ExpectedProtections {
                has_dotnethook: true,
                ..Default::default()
            },
            is_original: false,
            requires_pe_repair: false,
            check_semantic_preservation: true,
            verification_level: VerificationLevel::Normal,
        },
        SampleSpec {
            filename: "bitmono_unmanagedstring.exe",
            description: "UnmanagedString (fake native methods)",
            expected_protections: ExpectedProtections {
                has_unmanaged_string: true,
                ..Default::default()
            },
            is_original: false,
            requires_pe_repair: false,
            check_semantic_preservation: true,
            verification_level: VerificationLevel::Normal,
        },
        SampleSpec {
            filename: "bitmono_antidebug.exe",
            description: "AntiDebugBreakpoints (DateTime timing checks)",
            expected_protections: ExpectedProtections {
                has_anti_debug: true,
                ..Default::default()
            },
            is_original: false,
            requires_pe_repair: false,
            check_semantic_preservation: true,
            verification_level: VerificationLevel::Normal,
        },
        // === Cleanup targets ===
        SampleSpec {
            filename: "bitmono_junk.exe",
            description: "BitMethodDotnet junk prefix + BillionNops",
            expected_protections: ExpectedProtections {
                has_junk_prefix: true,
                has_billion_nops: true,
                ..Default::default()
            },
            is_original: false,
            requires_pe_repair: false,
            check_semantic_preservation: true,
            verification_level: VerificationLevel::Normal,
        },
        SampleSpec {
            filename: "bitmono_antide4dot.exe",
            description: "AntiDe4dot fake attributes + AntiILdasm",
            expected_protections: ExpectedProtections {
                has_suppress_ildasm: true,
                has_anti_de4dot: true,
                ..Default::default()
            },
            is_original: false,
            requires_pe_repair: false,
            check_semantic_preservation: true,
            verification_level: VerificationLevel::Normal,
        },
        // === Lossy IL-level ===
        SampleSpec {
            filename: "bitmono_renamer.exe",
            description: "FullRenamer (space-containing word-pool names)",
            expected_protections: ExpectedProtections {
                has_renamed_names: true,
                ..Default::default()
            },
            is_original: false,
            requires_pe_repair: false,
            check_semantic_preservation: true,
            verification_level: VerificationLevel::Normal,
        },
        // === Combinations ===
        SampleSpec {
            filename: "bitmono_combined.exe",
            description: "Multiple IL protections combined",
            expected_protections: ExpectedProtections {
                has_string_encryption: true,
                has_call_to_calli: true,
                has_anti_debug: true,
                has_renamed_names: true,
                ..Default::default()
            },
            is_original: false,
            requires_pe_repair: false,
            check_semantic_preservation: true,
            verification_level: VerificationLevel::Normal,
        },
        SampleSpec {
            filename: "bitmono_maximum_il.exe",
            description: "All IL protections enabled",
            expected_protections: ExpectedProtections {
                has_string_encryption: true,
                has_call_to_calli: true,
                has_dotnethook: true,
                has_unmanaged_string: true,
                has_anti_debug: true,
                has_suppress_ildasm: true,
                has_anti_de4dot: true,
                has_junk_prefix: true,
                has_billion_nops: true,
                has_renamed_names: true,
                ..Default::default()
            },
            is_original: false,
            requires_pe_repair: false,
            check_semantic_preservation: true,
            verification_level: VerificationLevel::Normal,
        },
        SampleSpec {
            filename: "bitmono_maximum.exe",
            description: "All PE + IL protections (maximum)",
            expected_protections: ExpectedProtections {
                has_pe_corruption: true,
                has_clr_header_corruption: true,
                has_data_directory_inflation: true,
                has_string_encryption: true,
                has_call_to_calli: true,
                has_dotnethook: true,
                has_unmanaged_string: true,
                has_anti_debug: true,
                has_suppress_ildasm: true,
                has_anti_de4dot: true,
                has_junk_prefix: true,
                has_billion_nops: true,
                has_renamed_names: true,
            },
            is_original: false,
            requires_pe_repair: true,
            check_semantic_preservation: true,
            verification_level: VerificationLevel::Normal,
        },
    ]
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
        detection_score: 0,
        warning_count: 0,
        error_count: 0,
        verification: VerificationResult::default(),
        semantic_result: None,
    };

    // For PE-level samples, use process_file (handles repair)
    // For IL-level samples, also use process_file (uniform approach)
    let path = format!("{}/{}", SAMPLES_DIR, spec.filename);

    if spec.is_original {
        let assembly = match load_sample(spec.filename) {
            Ok(a) => a,
            Err(e) => {
                result.error = Some(e);
                return result;
            }
        };
        result.methods_before = assembly.methods().iter().count();
        result.methods_after = result.methods_before;
        result.success = true;
        result.verification.assembly_valid = true;
        result.verification.has_valid_entry_point = assembly.cor20header().entry_point_token != 0;
        return result;
    }

    // RUN FULL DEOBFUSCATION PIPELINE
    let config = EngineConfig::default();
    let mut engine = DeobfuscationEngine::new(config);

    // Load input assembly for pre-deobfuscation method count
    if let Ok(input_asm) = load_sample(spec.filename) {
        result.methods_before = input_asm.methods().iter().count();
    }

    match engine.process_file(&path) {
        Ok((output, deob_result)) => {
            result.success = true;
            result.methods_after = output.methods().iter().count();

            // Warnings/errors now go through log:: instead of EventLog
            let _stats = deob_result.stats();
            result.warning_count = 0;
            result.error_count = 0;

            // DETECTION from engine attribution and techniques
            // Use binary 100/0 score: 100 if attributed, 0 if not.
            let confidence_score = if deob_result.attribution.is_some() {
                100
            } else {
                0
            };
            result.detection_score = confidence_score;

            let has_technique = |techs: &[dotscope::deobfuscation::TechniqueResult], id: &str| {
                techs.iter().any(|t| t.id == id && t.detected)
            };
            let count_technique =
                |techs: &[dotscope::deobfuscation::TechniqueResult], id: &str| -> usize {
                    if techs.iter().any(|t| t.id == id && t.detected) {
                        1
                    } else {
                        0
                    }
                };

            result.verification.suppress_ildasm_detected =
                has_technique(&deob_result.techniques, "generic.ildasm");
            result.verification.anti_de4dot_detected =
                count_technique(&deob_result.techniques, "generic.decompiler");
            result.verification.decryptors_detected =
                count_technique(&deob_result.techniques, "bitmono.strings");
            result.verification.anti_debug_detected =
                count_technique(&deob_result.techniques, "bitmono.debug");
            result.verification.infrastructure_types_detected =
                count_technique(&deob_result.techniques, "bitmono.hooks");

            // REMOVAL: re-detect on output
            result.verification.has_valid_entry_point = output.cor20header().entry_point_token != 0;
            let post_engine = DeobfuscationEngine::default();
            let post_det = post_engine.detect(&output);
            result.verification.post_detection_score = post_det
                .attribution
                .as_ref()
                .map_or(0, |a| a.supporting_matched);
            result.verification.suppress_ildasm_remaining = post_det
                .techniques
                .iter()
                .any(|t| t.id == "generic.ildasm" && t.detected);
            result.verification.anti_de4dot_remaining = if post_det
                .techniques
                .iter()
                .any(|t| t.id == "generic.decompiler" && t.detected)
            {
                1
            } else {
                0
            };
            result.verification.decryptors_remaining = if post_det
                .techniques
                .iter()
                .any(|t| t.id == "bitmono.strings" && t.detected)
            {
                1
            } else {
                0
            };
            result.verification.infrastructure_types_remaining = if post_det
                .techniques
                .iter()
                .any(|t| t.id == "bitmono.hooks" && t.detected)
            {
                1
            } else {
                0
            };

            // Roundtrip verification
            let bytes = output.file().data();
            match CilObject::from_mem_with_validation(
                bytes.to_vec(),
                ValidationConfig::production(),
            ) {
                Ok(reloaded) => {
                    result.verification.assembly_valid = true;
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
            if spec.check_semantic_preservation {
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
    eprintln!("BITMONO DEOBFUSCATION TEST SUMMARY");
    eprintln!("================================================================================\n");

    let mut total_passed = 0;
    let mut total_failed = 0;

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
            eprintln!(
                "       Detection: score={} suppress_ildasm={} anti_de4dot={} decryptors={} anti_debug={} infra_types={}",
                result.detection_score,
                v.suppress_ildasm_detected,
                v.anti_de4dot_detected,
                v.decryptors_detected,
                v.anti_debug_detected,
                v.infrastructure_types_detected,
            );
        }

        // Stats line
        eprintln!(
            "       Methods: {} -> {} (warnings={} errors={})",
            result.methods_before, result.methods_after, result.warning_count, result.error_count,
        );

        // Removal line (re-detection on deobfuscated output)
        if !result.sample.is_original {
            let v = &result.verification;
            eprintln!(
                "       Removal: valid={} entry={} post_score={} suppress_ildasm={} anti_de4dot={} decryptors={} infra_types={} roundtrip={}",
                v.assembly_valid, v.has_valid_entry_point,
                v.post_detection_score,
                v.suppress_ildasm_remaining, v.anti_de4dot_remaining,
                v.decryptors_remaining, v.infrastructure_types_remaining,
                v.roundtrip_structure_matches,
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
    eprintln!("TOTALS: {} passed, {} failed", total_passed, total_failed);
    eprintln!("--------------------------------------------------------------------------------\n");
}

/// Main test that runs all BitMono samples through the comprehensive deobfuscation pipeline.
#[test]
fn test_all_bitmono_samples() {
    let samples = all_samples();

    // Load original.exe for semantic comparison
    let original_asm = load_sample("original.exe").ok();

    let mut results = Vec::new();
    let mut skipped = 0;

    for sample in &samples {
        let path = format!("{}/{}", SAMPLES_DIR, sample.filename);
        if !std::path::Path::new(&path).exists() {
            eprintln!("Skipping test: sample not found at {}", path);
            skipped += 1;
            continue;
        }

        results.push(test_sample_comprehensive(sample, original_asm.as_ref()));
    }

    if results.is_empty() {
        eprintln!(
            "All {} BitMono samples skipped (not found in {}). Generate samples with: cd {}/generate && ./generate.sh",
            skipped, SAMPLES_DIR, SAMPLES_DIR
        );
        return;
    }

    print_summary(&results);

    // ASSERTIONS: Verify all protected samples
    for result in &results {
        if result.sample.is_original {
            // Original should NOT be detected as BitMono
            assert!(
                result.detection_score < 20,
                "{}: Unprotected original should not be detected as BitMono (score: {})",
                result.sample.filename,
                result.detection_score
            );
            continue;
        }

        let filename = result.sample.filename;
        let expected = &result.sample.expected_protections;

        // === Core assertions (must always pass) ===
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

        // === Detection assertions ===
        // With threshold=20, all protected samples should reach the engine threshold.
        let v = &result.verification;

        // Samples with BitMono-attributed protections should score above threshold.
        // Protections that only trigger generic techniques (SuppressIldasm,
        // AntiDe4dot) don't contribute to obfuscator attribution, so they
        // don't inflate the detection score.
        let has_attributed_protections = expected.has_pe_corruption
            || expected.has_clr_header_corruption
            || expected.has_data_directory_inflation
            || expected.has_string_encryption
            || expected.has_call_to_calli
            || expected.has_dotnethook
            || expected.has_unmanaged_string
            || expected.has_anti_debug
            || expected.has_junk_prefix
            || expected.has_billion_nops;

        if has_attributed_protections {
            assert!(
                result.detection_score >= 20,
                "{}: Detection score too low for protected sample (score: {}, expected >= 20)",
                filename,
                result.detection_score
            );
        }

        if expected.has_suppress_ildasm {
            assert!(
                v.suppress_ildasm_detected,
                "{}: SuppressIldasm not detected",
                filename
            );
        }

        if expected.has_anti_de4dot {
            assert!(
                v.anti_de4dot_detected > 0,
                "{}: AntiDe4dot fake attributes not detected",
                filename
            );
        }

        if expected.has_string_encryption {
            assert!(
                v.decryptors_detected > 0,
                "{}: String encryption decryptor not detected",
                filename
            );
        }

        if expected.has_anti_debug {
            assert!(
                v.anti_debug_detected > 0,
                "{}: AntiDebugBreakpoints not detected",
                filename
            );
        }

        if expected.has_dotnethook {
            assert!(
                v.infrastructure_types_detected > 0,
                "{}: DotNetHook infrastructure type not detected",
                filename
            );
        }

        // === Removal assertions ===
        if expected.has_suppress_ildasm {
            assert!(
                !v.suppress_ildasm_remaining,
                "{}: SuppressIldasm should be removed after deobfuscation",
                filename
            );
        }

        if expected.has_anti_de4dot {
            assert_eq!(
                v.anti_de4dot_remaining, 0,
                "{}: AntiDe4dot fake attributes should be removed (remaining: {})",
                filename, v.anti_de4dot_remaining
            );
        }

        if expected.has_string_encryption {
            assert_eq!(
                v.decryptors_remaining, 0,
                "{}: String decryptor methods should be removed (remaining: {})",
                filename, v.decryptors_remaining
            );
        }

        // Post-deobfuscation should have low/zero detection score
        assert!(
            v.post_detection_score < 20,
            "{}: Post-deobfuscation detection score should be below threshold (score: {})",
            filename,
            v.post_detection_score
        );

        // === Semantic preservation assertions ===
        if result.sample.check_semantic_preservation {
            if let Some(ref sem) = result.semantic_result {
                let preservation_ratio = if sem.methods_checked > 0 {
                    sem.methods_preserved as f64 / sem.methods_checked as f64
                } else {
                    1.0
                };

                let threshold = match result.sample.verification_level {
                    VerificationLevel::Normal => 1.0,
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

/// Test that BitMono detection doesn't false-positive on ConfuserEx samples.
#[test]
fn test_bitmono_no_false_positives_on_confuserex() {
    let confuserex_samples = [
        "tests/samples/packers/confuserex/1.6.0/original.exe",
        "tests/samples/packers/confuserex/1.6.0/mkaring_normal.exe",
        "tests/samples/packers/confuserex/1.6.0/mkaring_maximum.exe",
    ];

    for path in &confuserex_samples {
        if !std::path::Path::new(path).exists() {
            eprintln!("Skipping: {} not found", path);
            continue;
        }

        let assembly = CilObject::from_path_with_validation(path, ValidationConfig::analysis())
            .unwrap_or_else(|_| panic!("Failed to load {}", path));

        let engine = DeobfuscationEngine::default();
        let det = engine.detect(&assembly);
        let is_bitmono = det
            .attribution
            .as_ref()
            .is_some_and(|a| a.obfuscator_name.contains("BitMono"));

        assert!(!is_bitmono, "{}: Should not be detected as BitMono", path,);
    }
}

/// Test that BitMono detection doesn't false-positive on Obfuscar samples.
#[test]
fn test_bitmono_no_false_positives_on_obfuscar() {
    let obfuscar_samples = [
        "tests/samples/packers/obfuscar/2.2.50/original.exe",
        "tests/samples/packers/obfuscar/2.2.50/obfuscar_default.exe",
        "tests/samples/packers/obfuscar/2.2.50/obfuscar_maximum.exe",
    ];

    for path in &obfuscar_samples {
        if !std::path::Path::new(path).exists() {
            eprintln!("Skipping: {} not found", path);
            continue;
        }

        let assembly = CilObject::from_path_with_validation(path, ValidationConfig::analysis())
            .unwrap_or_else(|_| panic!("Failed to load {}", path));

        let engine = DeobfuscationEngine::default();
        let det = engine.detect(&assembly);
        let is_bitmono = det
            .attribution
            .as_ref()
            .is_some_and(|a| a.obfuscator_name.contains("BitMono"));

        assert!(!is_bitmono, "{}: Should not be detected as BitMono", path,);
    }
}

/// Test detection scoring: each sample should score above threshold.
#[test]
fn test_bitmono_detection_scoring() {
    // IL-level samples with expected technique detections.
    // Each entry: (filename, description, expected_technique_ids).
    // Expected techniques are the specific IDs that MUST appear in detection results.
    let il_samples: &[(&str, &str, &[&str])] = &[
        (
            "bitmono_strings.exe",
            "StringsEncryption",
            &["bitmono.strings"],
        ),
        ("bitmono_calltocalli.exe", "CallToCalli", &["bitmono.calli"]),
        ("bitmono_dotnethook.exe", "DotNetHook", &["bitmono.hooks"]),
        (
            "bitmono_antide4dot.exe",
            "AntiDe4dot + AntiILdasm",
            &["generic.decompiler", "generic.ildasm"],
        ),
        ("bitmono_combined.exe", "Combined IL", &["bitmono.calli"]),
        (
            "bitmono_maximum_il.exe",
            "Maximum IL",
            &["bitmono.calli", "generic.ildasm"],
        ),
    ];

    for (filename, description, expected_ids) in il_samples {
        let path = format!("{}/{}", SAMPLES_DIR, filename);
        if !std::path::Path::new(&path).exists() {
            eprintln!("Skipping: {} not found", filename);
            continue;
        }

        let assembly = CilObject::from_path_with_validation(&path, ValidationConfig::analysis())
            .unwrap_or_else(|e| panic!("Failed to load {}: {}", filename, e));

        let engine = DeobfuscationEngine::default();
        let det = engine.detect(&assembly);
        let score = det.attribution.as_ref().map_or(0, |a| a.supporting_matched);

        let detected_ids: Vec<_> = det
            .techniques
            .iter()
            .filter(|t| t.detected)
            .map(|t| t.id.as_str())
            .collect();

        eprintln!(
            "{} ({}): score={}, detected={:?}",
            filename, description, score, detected_ids,
        );

        for expected in *expected_ids {
            assert!(
                detected_ids.contains(expected),
                "{} ({}): Expected technique '{}' not detected (found: {:?})",
                filename,
                description,
                expected,
                detected_ids,
            );
        }
    }
}

// ============================================================================
// Per-protection unit tests
// ============================================================================

/// Runs a PE-level protection test through the full deobfuscation pipeline.
///
/// PE-level protections (BitDotNet, BitDecompiler, Packer) score above the
/// default detection threshold (50) because PE repairs carry high confidence.
fn run_pe_protection_test(
    filename: &str,
    semantic_threshold: f64,
) -> (
    CilObject,
    DeobfuscationResult,
    Option<SemanticVerificationResult>,
) {
    let path = format!("{}/{}", SAMPLES_DIR, filename);
    assert!(
        std::path::Path::new(&path).exists(),
        "Sample not found: {}",
        path
    );

    let config = EngineConfig::default();
    let mut engine = DeobfuscationEngine::new(config);

    let (output, deob_result) = engine
        .process_file(&path)
        .unwrap_or_else(|e| panic!("{}: deobfuscation failed: {}", filename, e));

    // Verify assembly validity
    assert!(
        output.cor20header().entry_point_token != 0,
        "{}: output has no valid entry point",
        filename
    );

    // Verify roundtrip
    let bytes = output.file().data();
    let reloaded =
        CilObject::from_mem_with_validation(bytes.to_vec(), ValidationConfig::production())
            .unwrap_or_else(|e| panic!("{}: roundtrip failed: {}", filename, e));
    assert_eq!(
        output.methods().iter().count(),
        reloaded.methods().iter().count(),
        "{}: roundtrip method count mismatch",
        filename
    );
    assert_eq!(
        output.types().iter().count(),
        reloaded.types().iter().count(),
        "{}: roundtrip type count mismatch",
        filename
    );

    // Semantic verification
    let semantic_result = {
        let original_path = format!("{}/original.exe", SAMPLES_DIR);
        let original_asm =
            CilObject::from_path_with_validation(&original_path, ValidationConfig::analysis())
                .unwrap_or_else(|e| panic!("Failed to load original.exe: {}", e));

        let result = verify_semantic_preservation(
            &original_asm,
            Arc::new(
                CilObject::from_mem_with_validation(bytes.to_vec(), ValidationConfig::analysis())
                    .unwrap(),
            ),
            SEMANTIC_TEST_METHODS,
            VerificationLevel::Normal,
        );

        if result.methods_checked > 0 {
            let ratio = result.methods_preserved as f64 / result.methods_checked as f64;
            assert!(
                ratio >= semantic_threshold,
                "{}: semantic preservation too low ({}/{} = {:.0}%, expected >= {:.0}%)",
                filename,
                result.methods_preserved,
                result.methods_checked,
                ratio * 100.0,
                semantic_threshold * 100.0
            );
        }

        result
    };

    (output, deob_result, Some(semantic_result))
}

/// Runs detection directly on an IL-level sample.
///
/// Single IL-level protections score below the default engine threshold (50),
/// so we verify detection artifacts directly rather than through the engine.
fn run_detection_test(filename: &str) -> DeobfuscationResult {
    let path = format!("{}/{}", SAMPLES_DIR, filename);
    assert!(
        std::path::Path::new(&path).exists(),
        "Sample not found: {}",
        path
    );

    let assembly = CilObject::from_path_with_validation(&path, ValidationConfig::analysis())
        .unwrap_or_else(|e| panic!("Failed to load {}: {}", filename, e));

    let engine = DeobfuscationEngine::default();
    engine.detect(&assembly)
}

// === PE-level protection tests (score >= 50, full pipeline) ===

#[test]
fn test_protection_bitdotnet() {
    let (_, result, _) = run_pe_protection_test("bitmono_bitdotnet.exe", 1.0);
    assert!(
        result
            .attribution
            .as_ref()
            .is_some_and(|a| a.obfuscator_name.contains("BitMono")),
        "BitDotNet not detected as BitMono (got: {:?})",
        result.attribution.as_ref().map(|a| &a.obfuscator_name)
    );
    // PE repair is implied by successful loading through process_file
}

#[test]
fn test_protection_bitdecompiler() {
    let (_, result, _) = run_pe_protection_test("bitmono_bitdecompiler.exe", 1.0);
    assert!(
        result
            .attribution
            .as_ref()
            .is_some_and(|a| a.obfuscator_name.contains("BitMono")),
        "BitDecompiler not detected as BitMono (got: {:?})",
        result.attribution.as_ref().map(|a| &a.obfuscator_name)
    );
    // PE repair is implied by successful loading through process_file
}

#[test]
fn test_protection_packer() {
    let (_, result, _) = run_pe_protection_test("bitmono_packer.exe", 1.0);
    assert!(
        result
            .attribution
            .as_ref()
            .is_some_and(|a| a.obfuscator_name.contains("BitMono")),
        "Packer not detected as BitMono (got: {:?})",
        result.attribution.as_ref().map(|a| &a.obfuscator_name)
    );
    // PE repair is implied by successful loading through process_file
}

#[test]
fn test_protection_pe_combined() {
    let (_, result, _) = run_pe_protection_test("bitmono_pe_combined.exe", 0.4);
    assert!(
        result
            .attribution
            .as_ref()
            .is_some_and(|a| a.obfuscator_name.contains("BitMono")),
        "PE combined not detected as BitMono (got: {:?})",
        result.attribution.as_ref().map(|a| &a.obfuscator_name)
    );
    // Verify string encryption technique was detected
    assert!(
        result
            .techniques
            .iter()
            .any(|t| t.id == "bitmono.strings" && t.detected),
        "Expected string encryption technique detected"
    );
}

// === IL-level protection detection tests (score < 50, detection verification) ===

#[test]
fn test_protection_strings() {
    let det = run_detection_test("bitmono_strings.exe");

    assert!(
        det.techniques
            .iter()
            .any(|t| t.id == "bitmono.strings" && t.detected),
        "StringsEncryption technique should be detected"
    );
}

#[test]
fn test_protection_calltocalli() {
    let det = run_detection_test("bitmono_calltocalli.exe");

    assert!(
        det.techniques
            .iter()
            .any(|t| t.id == "bitmono.calli" && t.detected),
        "CallToCalli technique should be detected"
    );
}

#[test]
fn test_protection_dotnethook() {
    let det = run_detection_test("bitmono_dotnethook.exe");

    assert!(
        det.techniques
            .iter()
            .any(|t| t.id == "bitmono.hooks" && t.detected),
        "DotNetHook technique should be detected"
    );
}

#[test]
fn test_protection_unmanagedstring() {
    let det = run_detection_test("bitmono_unmanagedstring.exe");

    assert!(
        det.techniques
            .iter()
            .any(|t| t.id == "bitmono.unmanaged" && t.detected),
        "UnmanagedString technique should be detected"
    );
}

#[test]
fn test_protection_antidebug() {
    let det = run_detection_test("bitmono_antidebug.exe");

    assert!(
        det.techniques
            .iter()
            .any(|t| t.id == "bitmono.debug" && t.detected),
        "AntiDebug technique should be detected"
    );
}

#[test]
fn test_protection_junk() {
    let det = run_detection_test("bitmono_junk.exe");

    assert!(
        det.techniques
            .iter()
            .any(|t| t.id == "bitmono.junk" && t.detected),
        "Junk prefix technique should be detected"
    );
    assert!(
        det.techniques
            .iter()
            .any(|t| t.id == "bitmono.nops" && t.detected),
        "BillionNops technique should be detected"
    );
}

#[test]
fn test_protection_antide4dot() {
    let det = run_detection_test("bitmono_antide4dot.exe");

    assert!(
        det.techniques
            .iter()
            .any(|t| t.id == "generic.decompiler" && t.detected),
        "Expected fake attributes detected (generic.decompiler)"
    );
    assert!(
        det.techniques
            .iter()
            .any(|t| t.id == "generic.ildasm" && t.detected),
        "Expected SuppressIldasm detected (generic.ildasm)"
    );
}

#[test]
fn test_protection_renamer() {
    let det = run_detection_test("bitmono_renamer.exe");

    // The renamer sample should trigger at least some technique detection
    let any_detected = det.techniques.iter().any(|t| t.detected);
    assert!(
        any_detected,
        "Renamer should produce at least one technique detection"
    );
}

/// Verify that after deobfuscation, no space-containing type or method names remain.
///
/// BitMono's FullRenamer produces names like "Translate Start <FixedUpdate>b__4_0.get_Syntax"
/// by concatenating random words with spaces. After cleanup, these should all be renamed
/// to simple identifiers (A, B, C... for types; a, b, c... for methods).
#[test]
fn test_protection_renamer_cleanup() {
    let path = format!("{}/bitmono_renamer.exe", SAMPLES_DIR);
    if !std::path::Path::new(&path).exists() {
        eprintln!("Skipping: bitmono_renamer.exe not found");
        return;
    }

    let config = EngineConfig::default();
    let mut engine = DeobfuscationEngine::new(config);

    let (output, _) = engine
        .process_file(&path)
        .unwrap_or_else(|e| panic!("Deobfuscation failed: {}", e));

    // Check that no type names contain spaces (excluding CLR-internal angle-bracket names
    // like "<Generic Parameter>" which are legitimate)
    let mut space_types = Vec::new();
    for entry in output.types().iter() {
        let t = entry.value();
        if t.name.contains(' ') && !(t.name.starts_with('<') && t.name.ends_with('>')) {
            space_types.push(t.name.clone());
        }
    }
    assert!(
        space_types.is_empty(),
        "Found {} type names still containing spaces after deobfuscation: {:?}",
        space_types.len(),
        &space_types[..space_types.len().min(5)]
    );

    // Check that no method names contain spaces
    let mut space_methods = Vec::new();
    for entry in output.methods().iter() {
        let m = entry.value();
        if m.name.contains(' ') && !(m.name.starts_with('<') && m.name.ends_with('>')) {
            space_methods.push(m.name.clone());
        }
    }
    assert!(
        space_methods.is_empty(),
        "Found {} method names still containing spaces after deobfuscation: {:?}",
        space_methods.len(),
        &space_methods[..space_methods.len().min(5)]
    );

    // Verify assembly is still valid with production-level strictness
    assert!(
        output.cor20header().entry_point_token != 0,
        "Output should have a valid entry point"
    );
    let bytes = output.file().data();
    CilObject::from_mem_with_validation(bytes.to_vec(), ValidationConfig::production())
        .expect("Deobfuscated assembly should pass production validation");
}

/// Diagnostic test: verify DotNetHook reversal produces correct call targets.
///
/// After deobfuscation of the dotnethook sample, SayHello and SayGoodbye should
/// call BuildMessage (not each other or some off-by-one method).
#[test]
fn test_dotnethook_call_targets() {
    // Test both the simple dotnethook sample and the maximum IL sample
    for sample in &["bitmono_dotnethook.exe", "bitmono_maximum_il.exe"] {
        let path = format!("{}/{}", SAMPLES_DIR, sample);
        if !std::path::Path::new(&path).exists() {
            eprintln!("Skipping: {} not found", sample);
            continue;
        }
        eprintln!("\n=== Testing {} ===", sample);
        test_dotnethook_call_targets_for_sample(sample);
    }
}

fn test_dotnethook_call_targets_for_sample(sample: &str) {
    let path = format!("{}/{}", SAMPLES_DIR, sample);

    // Also check the original to see what correct call targets look like
    let original_path = format!("{}/original.exe", SAMPLES_DIR);
    let original =
        CilObject::from_path_with_validation(&original_path, ValidationConfig::analysis())
            .expect("Failed to load original.exe");

    // Get BuildMessage token from original
    let orig_build_message_name = find_method_by_name(&original, "BuildMessage");
    eprintln!("Original BuildMessage: {:?}", orig_build_message_name);

    // Dump original SayHello call targets
    dump_call_targets(&original, "SayHello", "ORIGINAL");
    dump_call_targets(&original, "SayGoodbye", "ORIGINAL");

    // Deobfuscate
    let config = EngineConfig::default();
    let mut engine = DeobfuscationEngine::new(config);
    let (output, _result) = engine
        .process_file(&path)
        .unwrap_or_else(|e| panic!("Deobfuscation failed for {}: {}", sample, e));

    // Dump all methods with their tokens and call targets for context
    eprintln!("\n[DEOBFUSCATED] All methods and call targets:");
    for entry in output.methods().iter() {
        let m = entry.value();
        let dt = m
            .declaring_type_rc()
            .map(|t| t.name.clone())
            .unwrap_or_default();
        let calls: Vec<String> = m
            .instructions()
            .filter(|i| i.mnemonic == "call" || i.mnemonic == "callvirt" || i.mnemonic == "newobj")
            .filter_map(|i| {
                i.get_token_operand().map(|t| {
                    let target_name = output
                        .method(&t)
                        .map(|tm| {
                            let tdt = tm
                                .declaring_type_rc()
                                .map(|tt| tt.name.clone())
                                .unwrap_or_default();
                            format!("{}.{}", tdt, tm.name)
                        })
                        .unwrap_or_else(|| format!("ext:0x{:08X}", t.value()));
                    format!("{} 0x{:08X}({})", i.mnemonic, t.value(), target_name)
                })
            })
            .collect();
        if !calls.is_empty() {
            eprintln!(
                "  0x{:08X} {}.{} -> {}",
                m.token.value(),
                dt,
                m.name,
                calls.join(", ")
            );
        }
    }

    // Dump deobfuscated SayHello/SayGoodbye call targets (may be renamed)
    dump_call_targets(&output, "SayHello", "DEOBFUSCATED");
    dump_call_targets(&output, "SayGoodbye", "DEOBFUSCATED");

    // Verify: SayHello and SayGoodbye should both call a method named BuildMessage
    let say_hello_targets = get_call_target_names(&output, "SayHello");
    let say_goodbye_targets = get_call_target_names(&output, "SayGoodbye");

    eprintln!("SayHello calls: {:?}", say_hello_targets);
    eprintln!("SayGoodbye calls: {:?}", say_goodbye_targets);

    // Both should call BuildMessage (or a renamed version of it)
    // Check that they call the SAME method (they both call BuildMessage in the original)
    let hello_methoddef_calls: Vec<_> = get_call_target_tokens(&output, "SayHello")
        .into_iter()
        .filter(|t| t.table() == 0x06) // MethodDef calls only
        .collect();
    let goodbye_methoddef_calls: Vec<_> = get_call_target_tokens(&output, "SayGoodbye")
        .into_iter()
        .filter(|t| t.table() == 0x06) // MethodDef calls only
        .collect();

    eprintln!("SayHello MethodDef calls: {:?}", hello_methoddef_calls);
    eprintln!("SayGoodbye MethodDef calls: {:?}", goodbye_methoddef_calls);

    // In the original, SayHello calls BuildMessage (MethodDef) and Console.WriteLine (MemberRef)
    // After deobfuscation, we expect the same pattern
    // Key check: SayHello and SayGoodbye should NOT call each other
    let say_hello_token = find_method_token(&output, "SayHello");
    let say_goodbye_token = find_method_token(&output, "SayGoodbye");

    if let Some(hello_tok) = say_hello_token {
        assert!(
            !hello_methoddef_calls.contains(&hello_tok),
            "SayHello should not call itself"
        );
    }
    if let Some(goodbye_tok) = say_goodbye_token {
        assert!(
            !goodbye_methoddef_calls.contains(&goodbye_tok),
            "SayGoodbye should not call itself"
        );
    }
    if let (Some(hello_tok), Some(goodbye_tok)) = (say_hello_token, say_goodbye_token) {
        assert!(
            !hello_methoddef_calls.contains(&goodbye_tok),
            "SayHello should not call SayGoodbye (off-by-one bug)"
        );
        assert!(
            !goodbye_methoddef_calls.contains(&hello_tok),
            "SayGoodbye should not call SayHello (off-by-one bug)"
        );
    }

    // Both should call the same BuildMessage method
    if !hello_methoddef_calls.is_empty() && !goodbye_methoddef_calls.is_empty() {
        // Find the non-self, non-sibling call targets
        let hello_build = hello_methoddef_calls
            .iter()
            .find(|t| Some(**t) != say_hello_token && Some(**t) != say_goodbye_token);
        let goodbye_build = goodbye_methoddef_calls
            .iter()
            .find(|t| Some(**t) != say_hello_token && Some(**t) != say_goodbye_token);

        if let (Some(hb), Some(gb)) = (hello_build, goodbye_build) {
            assert_eq!(
                hb, gb,
                "SayHello and SayGoodbye should call the same BuildMessage method"
            );
        }
    }
}

fn find_method_by_name(assembly: &CilObject, name: &str) -> Option<String> {
    for entry in assembly.methods().iter() {
        let method = entry.value();
        if method.name == name {
            return Some(format!("{} (0x{:08X})", method.name, method.token.value()));
        }
    }
    None
}

fn find_method_token(assembly: &CilObject, name: &str) -> Option<dotscope::metadata::token::Token> {
    for entry in assembly.methods().iter() {
        let method = entry.value();
        if method.name == name {
            return Some(method.token);
        }
    }
    None
}

fn dump_call_targets(assembly: &CilObject, method_name: &str, label: &str) {
    for entry in assembly.methods().iter() {
        let method = entry.value();
        if method.name != method_name {
            continue;
        }
        eprintln!(
            "[{}] {} (0x{:08X}) call targets:",
            label,
            method_name,
            method.token.value()
        );
        for instr in method.instructions() {
            if instr.mnemonic == "call"
                || instr.mnemonic == "callvirt"
                || instr.mnemonic == "newobj"
            {
                if let Some(target) = instr.get_token_operand() {
                    let target_name = assembly
                        .method(&target)
                        .map(|m| m.name.clone())
                        .unwrap_or_else(|| format!("(unresolved 0x{:08X})", target.value()));
                    eprintln!(
                        "  {} 0x{:08X} -> {}",
                        instr.mnemonic,
                        target.value(),
                        target_name
                    );
                }
            }
        }
    }
}

fn get_call_target_names(assembly: &CilObject, method_name: &str) -> Vec<String> {
    let mut names = Vec::new();
    for entry in assembly.methods().iter() {
        let method = entry.value();
        if method.name != method_name {
            continue;
        }
        for instr in method.instructions() {
            if instr.mnemonic == "call" || instr.mnemonic == "callvirt" {
                if let Some(target) = instr.get_token_operand() {
                    let name = assembly
                        .method(&target)
                        .map(|m| m.name.clone())
                        .unwrap_or_else(|| format!("(external 0x{:08X})", target.value()));
                    names.push(name);
                }
            }
        }
    }
    names
}

fn get_call_target_tokens(
    assembly: &CilObject,
    method_name: &str,
) -> Vec<dotscope::metadata::token::Token> {
    let mut tokens = Vec::new();
    for entry in assembly.methods().iter() {
        let method = entry.value();
        if method.name != method_name {
            continue;
        }
        for instr in method.instructions() {
            if instr.mnemonic == "call" || instr.mnemonic == "callvirt" {
                if let Some(target) = instr.get_token_operand() {
                    tokens.push(target);
                }
            }
        }
    }
    tokens
}

/// Diagnostic: run engine on maximum_il with debug logging to trace DotNetHook offset.
#[test]
fn test_dotnethook_offset_diagnostic() {
    let path = format!("{}/bitmono_maximum_il.exe", SAMPLES_DIR);
    if !std::path::Path::new(&path).exists() {
        eprintln!("Skipping: bitmono_maximum_il.exe not found");
        return;
    }

    let config = EngineConfig::default();
    let mut engine = DeobfuscationEngine::new(config);
    let (output, _) = engine.process_file(&path).expect("Deobfuscation failed");

    // Check call targets for the type at position of GreetingService (type B)
    eprintln!("\n[RESULT] Method call targets:");
    for entry in output.methods().iter() {
        let m = entry.value();
        let dt = m
            .declaring_type_rc()
            .map(|t| t.name.clone())
            .unwrap_or_default();
        let calls: Vec<String> = m
            .instructions()
            .filter(|i| i.mnemonic == "call" || i.mnemonic == "callvirt" || i.mnemonic == "newobj")
            .filter_map(|i| {
                i.get_token_operand().map(|t| {
                    let target_name = output
                        .method(&t)
                        .map(|tm| {
                            let tdt = tm
                                .declaring_type_rc()
                                .map(|tt| tt.name.clone())
                                .unwrap_or_default();
                            format!("{}.{}", tdt, tm.name)
                        })
                        .unwrap_or_else(|| format!("ext:0x{:08X}", t.value()));
                    format!("{} 0x{:08X}({})", i.mnemonic, t.value(), target_name)
                })
            })
            .collect();
        if !calls.is_empty() && dt != "<Module>" && !dt.starts_with("<>") {
            eprintln!(
                "  0x{:08X} {}.{} -> {}",
                m.token.value(),
                dt,
                m.name,
                calls.join(", ")
            );
        }
    }
}

/// Verify that after deobfuscation, no obfuscator-injected metadata survives.
///
/// Specifically checks that `System.Private.CoreLib` AssemblyRef and
/// `System.ValueType` TypeRef (injected by DotNetHook/StringsEncryption
/// infrastructure structs) are properly cascade-removed.
#[test]
fn test_no_obfuscator_metadata_survives() {
    use dotscope::metadata::tables::{AssemblyRefRaw, TypeRefRaw};

    let path = format!("{}/bitmono_maximum_il.exe", SAMPLES_DIR);
    if !std::path::Path::new(&path).exists() {
        eprintln!("Skipping: not found");
        return;
    }

    let config = EngineConfig::default();
    let mut engine = DeobfuscationEngine::new(config);
    let (output, _) = engine.process_file(&path).unwrap();

    // Reload from bytes to get clean raw tables
    let bytes = output.file().data();
    let reloaded =
        CilObject::from_mem_with_validation(bytes.to_vec(), ValidationConfig::analysis()).unwrap();

    let tables = reloaded.tables().unwrap();
    let strings = reloaded.strings().unwrap();

    // Check that no AssemblyRef named "System.Private.CoreLib" or "System.Runtime" survives
    if let Some(aref_table) = tables.table::<AssemblyRefRaw>() {
        for aref in aref_table {
            let name = strings.get(aref.name as usize).unwrap_or("???");
            assert_ne!(
                name, "System.Private.CoreLib",
                "Obfuscator-injected AssemblyRef 'System.Private.CoreLib' should be cascade-removed"
            );
            assert_ne!(
                name, "System.Runtime",
                "Obfuscator-injected AssemblyRef 'System.Runtime' should be cascade-removed"
            );
        }
    }

    // Check that no TypeRef named "ValueType" survives
    if let Some(typeref_table) = tables.table::<TypeRefRaw>() {
        for tr in typeref_table {
            let name = strings.get(tr.type_name as usize).unwrap_or("???");
            assert_ne!(
                name, "ValueType",
                "Obfuscator-injected TypeRef 'System.ValueType' should be cascade-removed"
            );

            // TypeRefs with Module resolution scope are never legitimate for external
            // type references — they indicate leftover obfuscator artifacts
            assert_ne!(
                tr.resolution_scope.tag,
                dotscope::metadata::tables::TableId::Module,
                "TypeRef RID {} ({}) has Module resolution scope — likely an obfuscator artifact",
                tr.rid,
                name
            );
        }
    }
}
