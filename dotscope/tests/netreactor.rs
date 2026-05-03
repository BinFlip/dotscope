//! .NET Reactor deobfuscation integration tests.
//!
//! This test suite verifies deobfuscation of .NET Reactor-protected assemblies.
//!
//! # Test Structure
//!
//! Each sample is tested through a unified harness that verifies:
//! 1. Detection: Engine identifies .NET Reactor
//! 2. Deobfuscation: Engine processes successfully
//! 3. Removal: Re-detection on output confirms artifacts removed
//!
//! # Protection Stages (from NETReactorSlayer analysis)
//!
//! .NET Reactor applies protections in strict order. NecroBit (Stage 1) must be
//! reversed first as it encrypts all method bodies, making other stages inoperable.
//!
//! | Stage | Protection | Sample Coverage |
//! |-------|-----------|-----------------|
//! | 1 | NecroBit (method body encryption) | reactor_necrobit, reactor_full |
//! | 2 | Control flow (opaque constants) | reactor_controlflow, reactor_full |
//! | 3 | Anti-tamper/debug | reactor_antitamp, reactor_full |
//! | 6 | String encryption (AES) | reactor_strings, reactor_full |
//! | 7 | Resource encryption | reactor_resources, reactor_full |

#![cfg(feature = "deobfuscation")]

mod common;

use common::{
    framework::{
        load_sample, print_summary, run_deobfuscation_test, ProcessMode, SampleSpec,
        SEMANTIC_TEST_METHODS,
    },
    verification::{StructuralConfig, VerificationLevel},
};
use dotscope::{deobfuscation::EngineConfig, metadata::validation::ValidationConfig, CilObject};

const SAMPLES_DIR: &str = "tests/samples/packers/netreactor/7.5.0";

/// Expected protections in a .NET Reactor sample.
#[derive(Debug, Clone, Default)]
#[allow(dead_code)]
struct ReactorExpectedProtections {
    /// NecroBit method body encryption (Stage 1).
    has_necrobit: bool,
    /// String encryption via AES (Stage 6).
    has_string_encryption: bool,
    /// Control flow obfuscation via opaque field constants (Stage 2).
    has_control_flow: bool,
    /// Anti-tamper protection (Stage 3).
    has_anti_tamper: bool,
    /// Resource encryption (Stage 7).
    has_resource_encryption: bool,
    /// Symbol renaming/obfuscation (Stage 15).
    has_obfuscation: bool,
    /// SuppressIldasm attribute.
    has_suppress_ildasm: bool,
    /// Native x86 EXE stub.
    has_native_exe: bool,
    /// Anti strong name removal (Stage 12).
    has_anti_strong: bool,
    /// Pre-JIT native code conversion.
    has_prejit: bool,
    /// Output compression.
    has_compression: bool,
    /// Code virtualization (VM-protected methods via [Obfuscation] attribute).
    has_virtualization: bool,
}

/// All .NET Reactor samples with their expected characteristics.
///
/// Samples are generated with .NET Reactor 7.5.0 via Chocolatey.
/// Each variant exercises specific protections in isolation or combination.
fn all_samples() -> Vec<SampleSpec<ReactorExpectedProtections>> {
    vec![
        SampleSpec {
            filename: "original.exe",
            description: "Unprotected original (baseline)",
            expected_protections: ReactorExpectedProtections::default(),
            is_original: true,
            check_semantic_preservation: true,
            verification_level: VerificationLevel::Normal,
            check_structural_match: false,
            structural_config: StructuralConfig::default(),
        },
        SampleSpec {
            filename: "reactor_necrobit.exe",
            description: "NecroBit only (method body encryption)",
            expected_protections: ReactorExpectedProtections {
                has_necrobit: true,
                ..Default::default()
            },
            is_original: false,
            check_semantic_preservation: true,
            verification_level: VerificationLevel::Normal,
            check_structural_match: false,
            structural_config: StructuralConfig::default(),
        },
        SampleSpec {
            filename: "reactor_strings.exe",
            description: "String encryption only (AES)",
            expected_protections: ReactorExpectedProtections {
                has_string_encryption: true,
                ..Default::default()
            },
            is_original: false,
            check_semantic_preservation: true,
            verification_level: VerificationLevel::Normal,
            check_structural_match: false,
            structural_config: StructuralConfig::default(),
        },
        SampleSpec {
            filename: "reactor_controlflow.exe",
            description: "Control flow obfuscation (level 5)",
            expected_protections: ReactorExpectedProtections {
                has_control_flow: true,
                ..Default::default()
            },
            is_original: false,
            check_semantic_preservation: true,
            verification_level: VerificationLevel::Normal,
            check_structural_match: false,
            structural_config: StructuralConfig::default(),
        },
        SampleSpec {
            filename: "reactor_controlflow_max.exe",
            description: "Control flow obfuscation (level 9, maximum)",
            expected_protections: ReactorExpectedProtections {
                has_control_flow: true,
                ..Default::default()
            },
            is_original: false,
            check_semantic_preservation: true,
            verification_level: VerificationLevel::Normal,
            check_structural_match: false,
            structural_config: StructuralConfig::default(),
        },
        SampleSpec {
            filename: "reactor_resources.exe",
            description: "Resource encryption only",
            expected_protections: ReactorExpectedProtections {
                has_resource_encryption: true,
                ..Default::default()
            },
            is_original: false,
            check_semantic_preservation: true,
            verification_level: VerificationLevel::Normal,
            check_structural_match: false,
            structural_config: StructuralConfig::default(),
        },
        SampleSpec {
            filename: "reactor_antitamp.exe",
            description: "Anti-tamper only",
            expected_protections: ReactorExpectedProtections {
                has_anti_tamper: true,
                ..Default::default()
            },
            is_original: false,
            check_semantic_preservation: true,
            verification_level: VerificationLevel::Normal,
            check_structural_match: false,
            structural_config: StructuralConfig::default(),
        },
        SampleSpec {
            filename: "reactor_obfuscation.exe",
            description: "Symbol renaming (non-public)",
            expected_protections: ReactorExpectedProtections {
                has_obfuscation: true,
                ..Default::default()
            },
            is_original: false,
            check_semantic_preservation: true,
            verification_level: VerificationLevel::Normal,
            check_structural_match: false,
            structural_config: StructuralConfig::default(),
        },
        SampleSpec {
            filename: "reactor_suppressildasm.exe",
            description: "SuppressIldasm only",
            expected_protections: ReactorExpectedProtections {
                has_suppress_ildasm: true,
                ..Default::default()
            },
            is_original: false,
            check_semantic_preservation: true,
            verification_level: VerificationLevel::Normal,
            check_structural_match: false,
            structural_config: StructuralConfig::default(),
        },
        SampleSpec {
            filename: "reactor_necrobit_strings.exe",
            description: "NecroBit + string encryption",
            expected_protections: ReactorExpectedProtections {
                has_necrobit: true,
                has_string_encryption: true,
                ..Default::default()
            },
            is_original: false,
            check_semantic_preservation: true,
            verification_level: VerificationLevel::Normal,
            check_structural_match: false,
            structural_config: StructuralConfig::default(),
        },
        SampleSpec {
            filename: "reactor_necrobit_strings_cff.exe",
            description: "NecroBit + strings + control flow (level 5)",
            expected_protections: ReactorExpectedProtections {
                has_necrobit: true,
                has_string_encryption: true,
                has_control_flow: true,
                ..Default::default()
            },
            is_original: false,
            check_semantic_preservation: true,
            verification_level: VerificationLevel::Normal,
            check_structural_match: false,
            structural_config: StructuralConfig::default(),
        },
        SampleSpec {
            filename: "reactor_antistrong.exe",
            description: "Anti strong name removal only",
            expected_protections: ReactorExpectedProtections {
                has_anti_strong: true,
                ..Default::default()
            },
            is_original: false,
            check_semantic_preservation: true,
            verification_level: VerificationLevel::Normal,
            check_structural_match: false,
            structural_config: StructuralConfig::default(),
        },
        SampleSpec {
            filename: "reactor_prejit.exe",
            description: "Pre-JIT native code conversion",
            expected_protections: ReactorExpectedProtections {
                has_prejit: true,
                ..Default::default()
            },
            is_original: false,
            check_semantic_preservation: true,
            verification_level: VerificationLevel::Normal,
            check_structural_match: false,
            structural_config: StructuralConfig::default(),
        },
        SampleSpec {
            filename: "reactor_compression.exe",
            description: "Output compression only",
            expected_protections: ReactorExpectedProtections {
                has_compression: true,
                ..Default::default()
            },
            is_original: false,
            check_semantic_preservation: true,
            verification_level: VerificationLevel::Normal,
            check_structural_match: false,
            structural_config: StructuralConfig::default(),
        },
        SampleSpec {
            filename: "reactor_full.exe",
            description: "Full protection (all enabled, CFF level 9)",
            expected_protections: ReactorExpectedProtections {
                has_necrobit: true,
                has_string_encryption: true,
                has_control_flow: true,
                has_anti_tamper: true,
                has_resource_encryption: true,
                has_obfuscation: true,
                has_suppress_ildasm: true,
                has_anti_strong: true,
                has_compression: true,
                ..Default::default()
            },
            is_original: false,
            check_semantic_preservation: true,
            verification_level: VerificationLevel::Normal,
            check_structural_match: false,
            structural_config: StructuralConfig::default(),
        },
        SampleSpec {
            filename: "reactor_nativeexe.exe",
            description: "Native x86 EXE stub + NecroBit",
            expected_protections: ReactorExpectedProtections {
                has_necrobit: true,
                has_native_exe: true,
                ..Default::default()
            },
            is_original: false,
            check_semantic_preservation: false, // Native stub may alter execution model
            verification_level: VerificationLevel::Relaxed,
            check_structural_match: false,
            structural_config: StructuralConfig::default(),
        },
        SampleSpec {
            filename: "reactor_virtualization.exe",
            description: "Code virtualization only (VM on 8 attributed methods)",
            expected_protections: ReactorExpectedProtections {
                has_virtualization: true,
                ..Default::default()
            },
            is_original: false,
            check_semantic_preservation: false, // VM replaces method bodies with stubs
            verification_level: VerificationLevel::Relaxed,
            check_structural_match: false,
            structural_config: StructuralConfig::default(),
        },
        SampleSpec {
            filename: "reactor_virtualization_full.exe",
            description: "Code virtualization + all protections",
            expected_protections: ReactorExpectedProtections {
                has_necrobit: true,
                has_string_encryption: true,
                has_control_flow: true,
                has_anti_tamper: true,
                has_resource_encryption: true,
                has_obfuscation: true,
                has_suppress_ildasm: true,
                has_anti_strong: true,
                has_compression: true,
                has_virtualization: true,
                ..Default::default()
            },
            is_original: false,
            check_semantic_preservation: false, // VM + full protection
            verification_level: VerificationLevel::Relaxed,
            check_structural_match: false,
            structural_config: StructuralConfig::default(),
        },
    ]
}

/// Verify that .NET Reactor samples can be loaded and parsed.
///
/// This is the first-pass test: before detection techniques are implemented,
/// we verify that the PE/metadata parser handles .NET Reactor binaries correctly.
#[test]
fn test_netreactor_samples_loadable() {
    let samples = all_samples();
    let mut loaded = 0;
    let mut skipped = 0;

    for sample in &samples {
        let path = format!("{}/{}", SAMPLES_DIR, sample.filename);
        if !std::path::Path::new(&path).exists() {
            skipped += 1;
            continue;
        }

        // Use analysis-level validation: .NET Reactor samples (especially NecroBit)
        // have encrypted method bodies that fail strict owned-type validation.
        let result = CilObject::from_path_with_validation(&path, ValidationConfig::analysis());
        match result {
            Ok(asm) => {
                loaded += 1;
                eprintln!(
                    "  [OK] {} — {} methods",
                    sample.filename,
                    asm.methods().len(),
                );
            }
            Err(e) => {
                // Native EXE stubs may not parse as standard .NET assemblies
                if sample.expected_protections.has_native_exe {
                    eprintln!(
                        "  [SKIP] {} — native exe stub, load error expected: {}",
                        sample.filename, e
                    );
                } else {
                    panic!(
                        "{}: Failed to load .NET Reactor sample: {}",
                        sample.filename, e
                    );
                }
            }
        }
    }

    if loaded == 0 {
        eprintln!(
            "All {} .NET Reactor samples skipped (not found in {}).",
            skipped, SAMPLES_DIR
        );
        eprintln!("Generate samples with: ./regenerate.sh netreactor");
        return;
    }

    eprintln!("\n.NET Reactor: {loaded} loaded, {skipped} skipped");
}

/// Main test that runs all .NET Reactor samples through the deobfuscation pipeline.
///
/// Currently a stub — will be expanded as detection and deobfuscation techniques
/// are implemented. The test gracefully handles missing samples and missing
/// detection support.
#[test]
#[cfg_attr(feature = "skip-expensive-tests", ignore)]
fn test_all_netreactor_samples() {
    let samples = all_samples();

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
            "All {} .NET Reactor samples skipped (not found in {}).",
            skipped, SAMPLES_DIR
        );
        eprintln!("Generate samples with: ./regenerate.sh netreactor");
        return;
    }

    print_summary(&results, "NET REACTOR", |result| {
        if !result.sample.is_original {
            eprintln!(
                "       Detection: confidence={:.0}% techniques=[{}]",
                result.detection.confidence() * 100.0,
                result.detection.technique_ids.join(", "),
            );
        }
    });

    // ASSERTIONS — expand as detection techniques are implemented
    for result in &results {
        if result.sample.is_original {
            assert!(
                result.detection.confidence() < 0.5,
                "{}: Unprotected original should not be detected as .NET Reactor (confidence: {:.0}%)",
                result.sample.filename,
                result.detection.confidence() * 100.0
            );
            continue;
        }

        // Once detection is implemented, add assertions here:
        // - Verify correct technique detection per sample
        // - Verify deobfuscation success
        // - Verify semantic preservation
    }
}
