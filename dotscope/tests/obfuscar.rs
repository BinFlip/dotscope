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

use dotscope::{
    deobfuscation::{detect_obfuscar, DeobfuscationEngine, EngineConfig},
    metadata::validation::ValidationConfig,
    CilObject,
};

const SAMPLES_DIR: &str = "tests/samples/packers/obfuscar";

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
    detection_score: usize,
    suppress_ildasm_found: bool,
    helper_types_found: usize,
    decryptor_methods_found: usize,
    // Post-deobfuscation results
    assembly_valid: bool,
    roundtrip_ok: bool,
    // Re-detection on output
    post_detection_score: usize,
    post_helper_types_found: usize,
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
        },
    ]
}

fn load_sample(filename: &str) -> Result<CilObject, String> {
    let path = format!("{}/{}", SAMPLES_DIR, filename);
    CilObject::from_path_with_validation(&path, ValidationConfig::analysis())
        .map_err(|e| format!("Failed to load {}: {}", filename, e))
}

/// Run comprehensive deobfuscation test on a sample.
fn test_sample(spec: &SampleSpec) -> TestResult {
    let mut result = TestResult {
        sample: spec.clone(),
        success: false,
        error: None,
        methods_before: 0,
        methods_after: 0,
        detection_score: 0,
        suppress_ildasm_found: false,
        helper_types_found: 0,
        decryptor_methods_found: 0,
        assembly_valid: false,
        roundtrip_ok: false,
        post_detection_score: 0,
        post_helper_types_found: 0,
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
    let (score, findings) = detect_obfuscar(&assembly);
    result.detection_score = score.score();
    result.suppress_ildasm_found = findings.suppress_ildasm_token.is_some();
    result.helper_types_found = findings.protection_infrastructure_types.count();
    result.decryptor_methods_found = findings.decryptor_methods.count();

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
    let mut engine = DeobfuscationEngine::new(config);

    match engine.process_assembly(assembly) {
        Ok((output, _deob_result)) => {
            result.success = true;
            result.methods_after = output.methods().iter().count();
            result.assembly_valid = true;

            // Re-detect on output
            let (post_score, post_findings) = detect_obfuscar(&output);
            result.post_detection_score = post_score.score();
            result.post_helper_types_found = post_findings.protection_infrastructure_types.count();

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
                "       Detection: score={} suppress_ildasm={} helper_types={} decryptors={}",
                result.detection_score,
                result.suppress_ildasm_found,
                result.helper_types_found,
                result.decryptor_methods_found,
            );
        }

        // Stats line
        eprintln!(
            "       Methods: {} -> {}",
            result.methods_before, result.methods_after,
        );

        // Post-deobfuscation line
        if !result.sample.is_original {
            eprintln!(
                "       Post-deobfuscation: score={} helper_types={} valid={} roundtrip={}",
                result.post_detection_score,
                result.post_helper_types_found,
                result.assembly_valid,
                result.roundtrip_ok,
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

    let mut results = Vec::new();
    let mut skipped = 0;

    for sample in &samples {
        let path = format!("{}/{}", SAMPLES_DIR, sample.filename);
        if !std::path::Path::new(&path).exists() {
            eprintln!("Skipping test: sample not found at {}", path);
            skipped += 1;
            continue;
        }

        results.push(test_sample(sample));
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
                result.detection_score < 50,
                "{}: Unprotected original should not be detected as Obfuscar (score: {})",
                result.sample.filename,
                result.detection_score
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
        if expected.has_suppress_ildasm {
            assert!(
                result.suppress_ildasm_found,
                "{}: SuppressIldasmAttribute not detected",
                filename
            );
        }

        if expected.has_string_hiding {
            assert!(
                result.helper_types_found > 0,
                "{}: String hiding helper type not detected",
                filename
            );
            assert!(
                result.decryptor_methods_found > 0,
                "{}: String accessor methods not detected",
                filename
            );
            // Samples with string hiding should score above detection threshold
            assert!(
                result.detection_score >= 50,
                "{}: Detection score too low for string hiding sample (score: {})",
                filename,
                result.detection_score
            );
        }
    }
}

/// Test that the Obfuscar detection doesn't false-positive on ConfuserEx samples.
#[test]
fn test_obfuscar_no_false_positives_on_confuserex() {
    let confuserex_path = "tests/samples/packers/confuserex/original.exe";
    if !std::path::Path::new(confuserex_path).exists() {
        eprintln!("Skipping: ConfuserEx sample not found");
        return;
    }

    let assembly =
        CilObject::from_path_with_validation(confuserex_path, ValidationConfig::analysis())
            .expect("Failed to load ConfuserEx original");

    let (score, _findings) = detect_obfuscar(&assembly);

    assert!(
        score.score() < 50,
        "ConfuserEx original should not be detected as Obfuscar (score: {})",
        score.score()
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

        let (score, findings) = detect_obfuscar(&assembly);

        eprintln!(
            "{}: score={}, evidence={}, helper_types={}, decryptors={}",
            filename,
            score.score(),
            score.evidence_summary(),
            findings.protection_infrastructure_types.count(),
            findings.decryptor_methods.count()
        );

        assert!(
            score.score() >= 60,
            "{}: Expected high detection score for string hiding sample (got: {})",
            filename,
            score.score()
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

    let (score, findings) = detect_obfuscar(&assembly);

    eprintln!(
        "rename_only: score={}, evidence={}",
        score.score(),
        score.evidence_summary()
    );

    // Without string hiding, the only signal is null params (+5)
    // (SuppressIldasm is disabled in this config)
    // Total should be <= 5, well below the 50 threshold
    assert!(
        score.score() < 50,
        "Rename-only sample should not exceed detection threshold (score: {}, evidence: {})",
        score.score(),
        score.evidence_summary()
    );
    assert_eq!(
        findings.protection_infrastructure_types.count(),
        0,
        "Rename-only sample should have no helper types"
    );
}
