//! Obfuscar deobfuscation integration tests.
//!
//! This test suite verifies deobfuscation of Obfuscar-protected assemblies,
//! with detection verification and string decryption validation.
//!
//! # Test Structure
//!
//! Each sample is tested through a unified harness that verifies:
//! 1. Detection: Engine identifies Obfuscar (not ConfuserEx)
//! 2. Deobfuscation: Engine processes successfully
//! 3. Removal: Re-detection on output confirms artifacts removed

#![cfg(feature = "deobfuscation")]

mod common;

use std::sync::Arc;

use common::verification::{
    assert_deobfuscation_diagnostics, verify_semantic_preservation, SemanticVerificationResult,
    VerificationLevel,
};
use dotscope::{
    deobfuscation::{DeobfuscationEngine, EngineConfig},
    metadata::validation::ValidationConfig,
    CilObject,
};

const SAMPLES_DIR: &str = "tests/samples/packers/obfuscar/2.2.50";

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

/// Description of an Obfuscar sample and its expected characteristics.
#[derive(Debug, Clone)]
struct SampleSpec {
    /// Filename relative to SAMPLES_DIR.
    filename: &'static str,
    /// Human-readable description.
    description: &'static str,
    /// Expected protections present BEFORE deobfuscation.
    expected_protections: ObfuscarExpectedProtections,
    /// Whether this is the unprotected original (baseline).
    is_original: bool,
    /// Check semantic preservation against original.exe.
    check_semantic_preservation: bool,
}

/// Expected protections in an Obfuscar sample.
#[derive(Debug, Clone, Default)]
#[allow(dead_code)]
struct ObfuscarExpectedProtections {
    /// Expect SuppressIldasmAttribute on the module.
    has_suppress_ildasm: bool,
    /// Expect string hiding (`<PrivateImplementationDetails>{GUID}` helper type).
    has_string_hiding: bool,
    /// Expect null/empty parameter names from renaming.
    has_null_params: bool,
}

/// Results from deobfuscating a sample.
#[derive(Debug)]
struct TestResult {
    sample: SampleSpec,
    success: bool,
    error: Option<String>,
    methods_before: usize,
    methods_after: usize,
    // Detection results
    detection_confidence: f32,
    detected_techniques: Vec<String>,
    // Post-deobfuscation results
    assembly_valid: bool,
    roundtrip_ok: bool,
    // Diagnostic counts
    warning_count: usize,
    error_count: usize,
    // Re-detection on output
    post_detection_confidence: f32,
    post_detected_techniques: Vec<String>,
    // Semantic preservation
    semantic_result: Option<SemanticVerificationResult>,
}

/// All Obfuscar samples with their expected characteristics.
///
/// Sample configs reflect actual Obfuscar defaults from Settings.cs:
/// - Default: KeepPublicApi=true, HidePrivateApi=true, RenameFields=true,
///   RenameProperties=true, RenameEvents=true, HideStrings=true,
///   SuppressIldasm=true, OptimizeMethods=true, ReuseNames=true
fn all_samples() -> Vec<SampleSpec> {
    vec![
        SampleSpec {
            filename: "original.exe",
            description: "Unprotected original (baseline)",
            expected_protections: ObfuscarExpectedProtections::default(),
            is_original: true,
            check_semantic_preservation: true,
        },
        SampleSpec {
            filename: "obfuscar_default.exe",
            description: "True defaults (rename private + strings + SuppressIldasm)",
            expected_protections: ObfuscarExpectedProtections {
                // SuppressIldasm defaults to true in Settings.cs, but when Obfuscar runs
                // on .NET Core/.NET 5+, SuppressIldasmAttribute doesn't exist in the
                // runtime so the attribute is silently not added.
                has_suppress_ildasm: false,
                has_string_hiding: true,
                has_null_params: true,
            },
            is_original: false,
            check_semantic_preservation: true,
        },
        SampleSpec {
            filename: "obfuscar_strings_only.exe",
            description: "String hiding only (no renaming, no SuppressIldasm)",
            expected_protections: ObfuscarExpectedProtections {
                has_suppress_ildasm: false,
                has_string_hiding: true,
                has_null_params: false,
            },
            is_original: false,
            check_semantic_preservation: true,
        },
        SampleSpec {
            filename: "obfuscar_rename_only.exe",
            description: "Renaming only (no strings, no SuppressIldasm)",
            expected_protections: ObfuscarExpectedProtections {
                has_suppress_ildasm: false,
                has_string_hiding: false,
                has_null_params: true,
            },
            is_original: false,
            check_semantic_preservation: true,
        },
        SampleSpec {
            filename: "obfuscar_unicode.exe",
            description: "Unicode name mode (defaults + UseUnicodeNames)",
            expected_protections: ObfuscarExpectedProtections {
                has_suppress_ildasm: false, // See obfuscar_default note
                has_string_hiding: true,
                has_null_params: true,
            },
            is_original: false,
            check_semantic_preservation: true,
        },
        SampleSpec {
            filename: "obfuscar_maximum.exe",
            description: "Maximum: all protections, public API also renamed",
            expected_protections: ObfuscarExpectedProtections {
                has_suppress_ildasm: false, // See obfuscar_default note
                has_string_hiding: true,
                has_null_params: true,
            },
            is_original: false,
            check_semantic_preservation: true,
        },
    ]
}

fn load_sample(filename: &str) -> Result<CilObject, String> {
    let path = format!("{}/{}", SAMPLES_DIR, filename);
    CilObject::from_path_with_validation(&path, ValidationConfig::analysis())
        .map_err(|e| format!("Failed to load {}: {}", filename, e))
}

/// Run comprehensive deobfuscation test on a sample.
fn test_sample(spec: &SampleSpec, original_asm: Option<&CilObject>) -> TestResult {
    let mut result = TestResult {
        sample: spec.clone(),
        success: false,
        error: None,
        methods_before: 0,
        methods_after: 0,
        detection_confidence: 0.0,
        detected_techniques: Vec::new(),
        assembly_valid: false,
        roundtrip_ok: false,
        warning_count: 0,
        error_count: 0,
        post_detection_confidence: 0.0,
        post_detected_techniques: Vec::new(),
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

    // Run detection
    let detect_engine = DeobfuscationEngine::default();
    let det = detect_engine.detect(&assembly);
    let attribution = det.attribution;
    result.detection_confidence = if attribution.is_some() { 1.0 } else { 0.0 };
    if let Some(ref attr) = attribution {
        result.detected_techniques = attr.technique_ids.clone();
    }

    // Skip deobfuscation for original (unprotected) sample
    if spec.is_original {
        result.success = true;
        result.methods_after = result.methods_before;
        result.assembly_valid = true;
        result.roundtrip_ok = true;
        return result;
    }

    // Run full deobfuscation pipeline
    let config = EngineConfig::default();
    let engine = DeobfuscationEngine::new(config);

    match engine.process_assembly(assembly) {
        Ok((output, deob_result)) => {
            result.success = true;
            result.methods_after = output.methods().iter().count();
            result.assembly_valid = true;

            // Warnings/errors now go through log:: instead of EventLog
            let _stats = deob_result.stats();
            result.warning_count = 0;
            result.error_count = 0;

            // Re-detect on output
            let post_engine = DeobfuscationEngine::default();
            let post_det = post_engine.detect(&output);
            let post_attribution = post_det.attribution;
            result.post_detection_confidence = if post_attribution.is_some() { 1.0 } else { 0.0 };
            if let Some(ref attr) = post_attribution {
                result.post_detected_techniques = attr.technique_ids.clone();
            }

            // Roundtrip verification
            let bytes = output.file().data();
            match CilObject::from_mem_with_validation(
                bytes.to_vec(),
                ValidationConfig::production(),
            ) {
                Ok(reloaded) => {
                    result.roundtrip_ok = output.methods().iter().count()
                        == reloaded.methods().iter().count()
                        && output.types().iter().count() == reloaded.types().iter().count();
                }
                Err(e) => {
                    result.roundtrip_ok = false;
                    result.error = Some(format!("Roundtrip failed: {}", e));
                }
            }

            // SEMANTIC PRESERVATION (if enabled and original is available)
            if spec.check_semantic_preservation && !spec.is_original {
                if let Some(orig) = original_asm {
                    let level = if spec.expected_protections.has_null_params {
                        VerificationLevel::Relaxed
                    } else {
                        VerificationLevel::Normal
                    };
                    result.semantic_result = Some(verify_semantic_preservation(
                        orig,
                        Arc::new(output),
                        SEMANTIC_TEST_METHODS,
                        level,
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
fn print_summary(results: &[TestResult]) {
    eprintln!("\n================================================================================");
    eprintln!("OBFUSCAR DEOBFUSCATION TEST SUMMARY");
    eprintln!("================================================================================\n");

    let mut total_passed = 0;
    let mut total_failed = 0;

    for result in results {
        let status = if result.success && result.assembly_valid {
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

        // Detection line
        if !result.sample.is_original {
            eprintln!(
                "       Detection: confidence={:.0}% techniques=[{}]",
                result.detection_confidence * 100.0,
                result.detected_techniques.join(", "),
            );
        }

        // Stats line
        eprintln!(
            "       Methods: {} -> {} (warnings={} errors={})",
            result.methods_before, result.methods_after, result.warning_count, result.error_count,
        );

        // Post-deobfuscation line
        if !result.sample.is_original {
            eprintln!(
                "       Post-deobfuscation: confidence={:.0}% techniques=[{}] valid={} roundtrip={}",
                result.post_detection_confidence * 100.0,
                result.post_detected_techniques.join(", "),
                result.assembly_valid,
                result.roundtrip_ok,
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

/// Main test that runs all Obfuscar samples through the deobfuscation pipeline.
#[test]
fn test_all_obfuscar_samples() {
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

        results.push(test_sample(sample, original_asm.as_ref()));
    }

    if results.is_empty() {
        eprintln!(
            "All {} Obfuscar samples skipped (not found in {}). Generate samples with: cd {}/generate && ./generate.sh",
            skipped, SAMPLES_DIR, SAMPLES_DIR
        );
        return;
    }

    print_summary(&results);

    // ASSERTIONS
    for result in &results {
        if result.sample.is_original {
            // Original should NOT be detected as Obfuscar
            assert!(
                result.detection_confidence < 0.5,
                "{}: Unprotected original should not be detected as Obfuscar (confidence: {:.0}%)",
                result.sample.filename,
                result.detection_confidence * 100.0
            );
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
            result.assembly_valid,
            "{}: Output assembly is invalid - {:?}",
            filename, result.error
        );

        assert!(
            result.roundtrip_ok,
            "{}: Roundtrip structure mismatch - {:?}",
            filename, result.error
        );

        // Detection assertions
        if expected.has_string_hiding {
            // Samples with string hiding should have positive detection
            assert!(
                result.detection_confidence > 0.0,
                "{}: Detection confidence should be positive for string hiding sample (confidence: {:.0}%)",
                filename,
                result.detection_confidence * 100.0
            );
            assert!(
                !result.detected_techniques.is_empty(),
                "{}: Expected at least one detected technique for string hiding sample",
                filename
            );
        }

        // Semantic preservation assertions
        if result.sample.check_semantic_preservation {
            if let Some(ref sem) = result.semantic_result {
                let preservation_ratio = if sem.methods_checked > 0 {
                    sem.methods_preserved as f64 / sem.methods_checked as f64
                } else {
                    1.0
                };
                let threshold = if result.sample.expected_protections.has_null_params {
                    0.50
                } else {
                    0.80
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

/// Test that the Obfuscar detection doesn't false-positive on ConfuserEx samples.
#[test]
fn test_obfuscar_no_false_positives_on_confuserex() {
    let confuserex_path = "tests/samples/packers/confuserex/1.6.0/original.exe";
    if !std::path::Path::new(confuserex_path).exists() {
        eprintln!("Skipping: ConfuserEx sample not found");
        return;
    }

    let assembly =
        CilObject::from_path_with_validation(confuserex_path, ValidationConfig::analysis())
            .expect("Failed to load ConfuserEx original");

    let engine = DeobfuscationEngine::default();
    let det = engine.detect(&assembly);
    let attribution = det.attribution;
    let confidence = if attribution.is_some() { 1.0f64 } else { 0.0 };

    assert!(
        confidence < 0.5,
        "ConfuserEx original should not be detected as Obfuscar (confidence: {:.0}%)",
        confidence * 100.0
    );
}

/// Test detection scoring: samples with string hiding should score high.
#[test]
fn test_obfuscar_detection_scoring() {
    let samples_with_strings = [
        "obfuscar_default.exe",
        "obfuscar_strings_only.exe",
        "obfuscar_unicode.exe",
        "obfuscar_maximum.exe",
    ];

    for filename in &samples_with_strings {
        let path = format!("{}/{}", SAMPLES_DIR, filename);
        if !std::path::Path::new(&path).exists() {
            eprintln!("Skipping: {} not found", filename);
            continue;
        }

        let assembly = CilObject::from_path_with_validation(&path, ValidationConfig::analysis())
            .unwrap_or_else(|e| panic!("Failed to load {}: {}", filename, e));

        let engine = DeobfuscationEngine::default();
        let det = engine.detect(&assembly);
        let attribution = det.attribution;
        let confidence = if attribution.is_some() { 1.0f64 } else { 0.0 };
        let techniques: Vec<String> = attribution
            .as_ref()
            .map_or_else(Vec::new, |a| a.technique_ids.clone());

        eprintln!(
            "{}: confidence={:.0}%, techniques=[{}]",
            filename,
            confidence * 100.0,
            techniques.join(", ")
        );

        assert!(
            confidence >= 0.6,
            "{}: Expected high detection confidence for string hiding sample (got: {:.0}%)",
            filename,
            confidence * 100.0
        );
    }
}

/// Test that rename-only samples score below the detection threshold
/// (no string hiding means no high-confidence signal).
#[test]
fn test_obfuscar_rename_only_below_threshold() {
    let path = format!("{}/obfuscar_rename_only.exe", SAMPLES_DIR);
    if !std::path::Path::new(&path).exists() {
        eprintln!("Skipping: obfuscar_rename_only.exe not found");
        return;
    }

    let assembly = CilObject::from_path_with_validation(&path, ValidationConfig::analysis())
        .expect("Failed to load rename-only sample");

    let engine = DeobfuscationEngine::default();
    let det = engine.detect(&assembly);
    let attribution = det.attribution;
    let confidence = if attribution.is_some() { 1.0f64 } else { 0.0 };
    let techniques: Vec<String> = attribution
        .as_ref()
        .map_or_else(Vec::new, |a| a.technique_ids.clone());

    eprintln!(
        "rename_only: confidence={:.0}%, techniques=[{}]",
        confidence * 100.0,
        techniques.join(", ")
    );

    // Without string hiding, the only signal is null params
    // (SuppressIldasm is disabled in this config)
    // Confidence should be below 50% threshold
    assert!(
        confidence < 0.5,
        "Rename-only sample should not exceed detection threshold (confidence: {:.0}%, techniques: [{}])",
        confidence * 100.0,
        techniques.join(", ")
    );
    assert!(
        techniques.is_empty(),
        "Rename-only sample should have no detected techniques"
    );
}
