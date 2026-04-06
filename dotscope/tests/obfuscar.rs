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

use common::{
    framework::{
        assert_common_requirements, load_sample, print_summary, run_deobfuscation_test,
        ProcessMode, SampleSpec, SEMANTIC_TEST_METHODS,
    },
    verification::{StructuralConfig, VerificationLevel},
};
use dotscope::{
    deobfuscation::{DeobfuscationEngine, EngineConfig},
    metadata::validation::ValidationConfig,
    CilObject,
};

const SAMPLES_DIR: &str = "tests/samples/packers/obfuscar/2.2.50";

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

/// All Obfuscar samples with their expected characteristics.
///
/// Sample configs reflect actual Obfuscar defaults from Settings.cs:
/// - Default: KeepPublicApi=true, HidePrivateApi=true, RenameFields=true,
///   RenameProperties=true, RenameEvents=true, HideStrings=true,
///   SuppressIldasm=true, OptimizeMethods=true, ReuseNames=true
fn all_samples() -> Vec<SampleSpec<ObfuscarExpectedProtections>> {
    vec![
        SampleSpec {
            filename: "original.exe",
            description: "Unprotected original (baseline)",
            expected_protections: ObfuscarExpectedProtections::default(),
            is_original: true,
            check_semantic_preservation: true,
            verification_level: VerificationLevel::Normal,
            check_structural_match: false,
            structural_config: StructuralConfig::default(),
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
            verification_level: VerificationLevel::Normal,
            check_structural_match: false,
            structural_config: StructuralConfig::default(),
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
            verification_level: VerificationLevel::Normal,
            check_structural_match: false,
            structural_config: StructuralConfig::default(),
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
            verification_level: VerificationLevel::Normal,
            check_structural_match: false,
            structural_config: StructuralConfig::default(),
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
            verification_level: VerificationLevel::Normal,
            check_structural_match: false,
            structural_config: StructuralConfig::default(),
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
            verification_level: VerificationLevel::Normal,
            check_structural_match: false,
            structural_config: StructuralConfig::default(),
        },
    ]
}

/// Main test that runs all Obfuscar samples through the deobfuscation pipeline.
#[test]
fn test_all_obfuscar_samples() {
    let samples = all_samples();

    // Load original.exe for semantic comparison
    let original_asm = load_sample(SAMPLES_DIR, "original.exe").ok();

    let mut results = Vec::new();
    let mut skipped = 0;

    for sample in &samples {
        let path = format!("{}/{}", SAMPLES_DIR, sample.filename);
        if !std::path::Path::new(&path).exists() {
            eprintln!("Skipping test: sample not found at {}", path);
            skipped += 1;
            continue;
        }

        results.push(run_deobfuscation_test(
            sample,
            SAMPLES_DIR,
            original_asm.as_ref(),
            SEMANTIC_TEST_METHODS,
            EngineConfig::default(),
            ProcessMode::Assembly,
        ));
    }

    if results.is_empty() {
        eprintln!(
            "All {} Obfuscar samples skipped (not found in {}). Generate samples with: cd {}/generate && ./generate.sh",
            skipped, SAMPLES_DIR, SAMPLES_DIR
        );
        return;
    }

    print_summary(&results, "OBFUSCAR", |result| {
        if !result.sample.is_original {
            eprintln!(
                "       Detection: confidence={:.0}% techniques=[{}]",
                result.detection.confidence() * 100.0,
                result.detection.technique_ids.join(", "),
            );
        }
    });

    // ASSERTIONS
    for result in &results {
        if result.sample.is_original {
            // Original should NOT be detected as Obfuscar
            assert!(
                result.detection.confidence() < 0.5,
                "{}: Unprotected original should not be detected as Obfuscar (confidence: {:.0}%)",
                result.sample.filename,
                result.detection.confidence() * 100.0
            );
            continue;
        }

        let filename = result.sample.filename;
        let expected = &result.sample.expected_protections;

        // Common assertions: core validity, semantic preservation, structural match, diagnostics
        let semantic_threshold = if expected.has_null_params { 0.85 } else { 0.90 };
        assert_common_requirements(result, None, semantic_threshold, true);

        // Detection assertions
        if expected.has_string_hiding {
            assert!(
                result.detection.confidence() > 0.0,
                "{}: Detection confidence should be positive for string hiding sample (confidence: {:.0}%)",
                filename,
                result.detection.confidence() * 100.0
            );
            assert!(
                !result.detection.technique_ids.is_empty(),
                "{}: Expected at least one detected technique for string hiding sample",
                filename
            );
        }
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
