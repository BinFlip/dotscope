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

use common::{
    framework::{
        assert_common_requirements, load_sample, print_summary, run_deobfuscation_test,
        ProcessMode, SampleSpec, TestResult, SEMANTIC_TEST_METHODS,
    },
    verification::{StructuralConfig, VerificationLevel},
};
use dotscope::deobfuscation::EngineConfig;

const SAMPLES_DIR: &str = "tests/samples/packers/confuserex/1.6.0";

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
fn all_samples() -> Vec<SampleSpec<ExpectedProtections>> {
    vec![
        SampleSpec {
            filename: "original.exe",
            description: "Unprotected original (baseline)",
            expected_protections: ExpectedProtections::default(),
            is_original: true,
            check_semantic_preservation: true,
            verification_level: VerificationLevel::Normal,
            check_structural_match: false,
            structural_config: StructuralConfig::default(),
        },
        SampleSpec {
            filename: "mkaring_minimal.exe",
            description: "Minimal protection (marker only)",
            expected_protections: ExpectedProtections {
                has_marker_attributes: true,
                ..Default::default()
            },
            is_original: false,
            check_semantic_preservation: true,
            verification_level: VerificationLevel::Normal,
            check_structural_match: true,
            structural_config: StructuralConfig {
                check_type_names: false,
                ..Default::default()
            },
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
            check_semantic_preservation: true,
            verification_level: VerificationLevel::Normal,
            check_structural_match: true,
            structural_config: StructuralConfig {
                check_type_names: false,
                ..Default::default()
            },
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
            check_semantic_preservation: true,
            verification_level: VerificationLevel::Normal,
            check_structural_match: true,
            structural_config: StructuralConfig::default(),
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
            check_semantic_preservation: true,
            verification_level: VerificationLevel::Normal,
            check_structural_match: true,
            structural_config: StructuralConfig::default(),
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
            check_semantic_preservation: true,
            verification_level: VerificationLevel::Normal,
            check_structural_match: true,
            structural_config: StructuralConfig::default(),
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
            check_semantic_preservation: true,
            verification_level: VerificationLevel::Normal,
            check_structural_match: true,
            structural_config: StructuralConfig {
                check_type_names: false,
                ..Default::default()
            },
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
            check_semantic_preservation: true,
            verification_level: VerificationLevel::Normal,
            check_structural_match: true,
            structural_config: StructuralConfig::default(),
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
            check_semantic_preservation: true,
            verification_level: VerificationLevel::Normal,
            check_structural_match: true,
            structural_config: StructuralConfig::default(),
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
            check_semantic_preservation: true,
            verification_level: VerificationLevel::Normal,
            check_structural_match: true,
            structural_config: StructuralConfig::default(),
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
            check_semantic_preservation: true,
            verification_level: VerificationLevel::Normal,
            check_structural_match: true,
            structural_config: StructuralConfig::default(),
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
            check_semantic_preservation: true,
            verification_level: VerificationLevel::Normal,
            check_structural_match: true,
            structural_config: StructuralConfig::default(),
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
            check_semantic_preservation: true,
            verification_level: VerificationLevel::Normal,
            check_structural_match: true,
            structural_config: StructuralConfig::default(),
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
            check_semantic_preservation: true,
            verification_level: VerificationLevel::Normal,
            check_structural_match: true,
            structural_config: StructuralConfig::default(),
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
            check_semantic_preservation: true,
            verification_level: VerificationLevel::Normal,
            check_structural_match: true,
            structural_config: StructuralConfig::default(),
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
            check_semantic_preservation: true,
            verification_level: VerificationLevel::Normal,
            check_structural_match: true,
            structural_config: StructuralConfig::default(),
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
            check_semantic_preservation: true,
            verification_level: VerificationLevel::Normal,
            check_structural_match: true,
            structural_config: StructuralConfig::default(),
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
            check_semantic_preservation: true,
            verification_level: VerificationLevel::Normal,
            check_structural_match: true,
            structural_config: StructuralConfig::default(),
        },
    ]
}

/// Main test that runs all samples through the comprehensive deobfuscation pipeline.
#[test]
#[cfg_attr(feature = "skip-expensive-tests", ignore)]
fn test_all_confuserex_samples() {
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
            "All {} ConfuserEx samples skipped (not found in {})",
            skipped, SAMPLES_DIR
        );
        return;
    }

    print_confuserex_summary(&results);

    // ASSERTIONS: Verify all protected samples passed
    for result in &results {
        if result.sample.is_original {
            continue;
        }

        let filename = result.sample.filename;
        let expected = &result.sample.expected_protections;

        // Common assertions: core validity, semantic preservation, structural match, diagnostics
        let semantic_threshold = match result.sample.verification_level {
            VerificationLevel::Normal => 0.70,
            VerificationLevel::Relaxed => 0.50,
        };
        assert_common_requirements(result, None, semantic_threshold, false);

        // Detection assertions (engine found expected protections)
        if expected.has_marker_attributes {
            assert!(
                result.detection.has_technique("confuserex.marker"),
                "{}: markers not detected by engine",
                filename
            );
        }
        if expected.has_suppress_ildasm {
            assert!(
                result.detection.has_technique("generic.ildasm"),
                "{}: suppress_ildasm not detected",
                filename
            );
        }
        if expected.has_decryptors {
            assert!(
                result.detection.has_technique("confuserex.constants"),
                "{}: decryptors not detected",
                filename
            );
        }
        if expected.has_anti_debug {
            assert!(
                result.detection.has_technique("confuserex.debug"),
                "{}: anti-debug not detected",
                filename
            );
        }
        if expected.has_anti_tamper {
            assert!(
                result.detection.has_technique("confuserex.tamper"),
                "{}: anti-tamper not detected",
                filename
            );
        }
        if expected.has_resources {
            assert!(
                result.detection.has_technique("confuserex.resources"),
                "{}: resources not detected",
                filename
            );
        }
        if expected.has_reference_proxy {
            assert!(
                result.detection.has_technique("confuserex.proxy"),
                "{}: reference proxy not detected",
                filename
            );
        }

        // Removal assertions (output should be clean)
        if expected.has_marker_attributes {
            assert!(
                !result.post_detection.has_technique("confuserex.marker"),
                "{}: markers should be removed",
                filename
            );
        }
        if expected.has_suppress_ildasm {
            assert!(
                !result.post_detection.has_technique("generic.ildasm"),
                "{}: suppress_ildasm should be removed",
                filename
            );
        }
        if expected.has_anti_tamper {
            assert_eq!(
                result
                    .post_detection
                    .technique_evidence_count("confuserex.tamper"),
                0,
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
    }
}

/// ConfuserEx-specific summary with detection and stats detail.
fn print_confuserex_summary(results: &[TestResult<ExpectedProtections>]) {
    print_summary(results, "CONFUSEREX", |result| {
        // Detection line (from engine findings)
        if !result.sample.is_original {
            let expected = &result.sample.expected_protections;
            let det = &result.detection;

            let mut detected = Vec::new();
            if expected.has_marker_attributes && det.has_technique("confuserex.marker") {
                detected.push("markers");
            }
            if expected.has_suppress_ildasm && det.has_technique("generic.ildasm") {
                detected.push("suppress");
            }
            if expected.has_decryptors && det.has_technique("confuserex.constants") {
                detected.push("decryptors");
            }
            if expected.has_anti_debug && det.has_technique("confuserex.debug") {
                detected.push("antidebug");
            }
            if expected.has_anti_tamper && det.has_technique("confuserex.tamper") {
                detected.push("antitamper");
            }
            if expected.has_resources && det.has_technique("confuserex.resources") {
                detected.push("resources");
            }
            if expected.has_reference_proxy && det.has_technique("confuserex.proxy") {
                detected.push("proxy");
            }

            if !detected.is_empty() {
                eprintln!(
                    "       Detected: {} [decryptors={} antidebug={} antitamper={} resources={} proxies={}]",
                    detected.join(" "),
                    det.technique_evidence_count("confuserex.constants"),
                    det.technique_evidence_count("confuserex.debug"),
                    det.technique_evidence_count("confuserex.tamper"),
                    det.technique_evidence_count("confuserex.resources"),
                    det.technique_evidence_count("confuserex.proxy"),
                );
            }
        }

        // Stats line
        if let Some(ref stats) = result.stats {
            eprintln!(
                "       Stats: transformed={} constants={} strings={} branches={} artifacts={}",
                stats.methods_transformed,
                stats.constants_folded,
                stats.strings_decrypted,
                stats.branches_simplified,
                stats.artifacts_removed
            );
        }

        // Removal line (re-detection on deobfuscated output)
        if !result.sample.is_original {
            let post = &result.post_detection;
            eprintln!(
                "       Removal: valid={} entry={} markers={} suppress={} decryptors={} proxies={} roundtrip={}",
                result.assembly_valid,
                result.has_valid_entry_point,
                post.has_technique("confuserex.marker"),
                post.has_technique("generic.ildasm"),
                post.technique_evidence_count("confuserex.constants")
                    + post.technique_evidence_count("generic.constants"),
                post.technique_evidence_count("confuserex.proxy"),
                result.roundtrip_ok
            );
        }
    });

    // Print aggregate stats
    let mut total_artifacts = 0;
    let mut total_constants = 0;
    let mut total_methods = 0;
    let mut total_branches = 0;
    for result in results {
        if let Some(ref stats) = result.stats {
            total_artifacts += stats.artifacts_removed;
            total_constants += stats.constants_folded;
            total_methods += stats.methods_transformed;
            total_branches += stats.branches_simplified;
        }
    }
    eprintln!("  Methods transformed: {}", total_methods);
    eprintln!("  Constants folded: {}", total_constants);
    eprintln!("  Branches simplified: {}", total_branches);
    eprintln!("  Artifacts removed: {}", total_artifacts);
    eprintln!("--------------------------------------------------------------------------------\n");
}
