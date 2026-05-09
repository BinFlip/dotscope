#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    missing_docs
)]

//! Shared integration test framework for deobfuscation tests.
//!
//! Provides common types, harness functions, and assertion helpers used across
//! all obfuscator integration tests (ConfuserEx, BitMono, JIEJIE.NET, Obfuscar).

#![allow(dead_code)]

use std::{fmt::Debug, sync::Arc};

use super::verification::{
    assert_deobfuscation_diagnostics, assert_structural_match, verify_semantic_preservation,
    AssemblyStats, SemanticVerificationResult, StructuralConfig, VerificationLevel,
};
use dotscope::{
    deobfuscation::{DeobfuscationEngine, DeobfuscationResult, EngineConfig},
    metadata::validation::ValidationConfig,
    CilObject,
};

/// The 17 standard methods used for semantic preservation checks across all
/// obfuscator test suites. Each obfuscator's original.exe contains these
/// methods and every deobfuscated output is compared against them.
pub const SEMANTIC_TEST_METHODS: &[&str] = &[
    // Original TestApp methods
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
    // Extended pattern methods
    "DemoCharOperations",
    "DemoEnumArguments",
    "DemoTypeOf",
    "DemoStaticArrayInit",
    "DemoLockAndUsing",
    "DemoEmbeddedResources",
];

/// Description of a sample and its expected characteristics.
///
/// Generic over `P` so each obfuscator can define its own expected-protections struct.
#[derive(Debug, Clone)]
pub struct SampleSpec<P: Clone + Debug> {
    /// Filename relative to the samples directory.
    pub filename: &'static str,
    /// Human-readable description.
    pub description: &'static str,
    /// Expected protections present BEFORE deobfuscation.
    pub expected_protections: P,
    /// Whether this is the unprotected original (baseline).
    pub is_original: bool,
    /// Check semantic preservation against original.exe.
    pub check_semantic_preservation: bool,
    /// Verification strictness level.
    pub verification_level: VerificationLevel,
    /// Check structural match against original.exe.
    pub check_structural_match: bool,
    /// Structural match configuration overrides.
    pub structural_config: StructuralConfig,
}

/// How the engine processes the sample.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessMode {
    /// Use `engine.process_assembly(assembly)`.
    Assembly,
    /// Use `engine.process_file(&path)`.
    File,
}

/// Pipeline statistics extracted from deobfuscation results.
#[derive(Debug, Clone, Default)]
pub struct PipelineStats {
    pub methods_transformed: usize,
    pub constants_folded: usize,
    pub strings_decrypted: usize,
    pub branches_simplified: usize,
    pub artifacts_removed: usize,
}

/// A single technique detection result.
#[derive(Debug, Clone)]
pub struct DetectedTechnique {
    pub id: String,
    pub detected: bool,
    pub evidence_count: usize,
}

/// Aggregated detection information.
#[derive(Debug, Clone, Default)]
pub struct DetectionInfo {
    pub techniques: Vec<DetectedTechnique>,
    pub obfuscator_name: Option<String>,
    pub technique_ids: Vec<String>,
    pub supporting_matched: usize,
}

impl DetectionInfo {
    /// Build from a `DeobfuscationResult`.
    pub fn from_results(result: &DeobfuscationResult) -> Self {
        let techniques: Vec<DetectedTechnique> = result
            .techniques
            .iter()
            .map(|t| DetectedTechnique {
                id: t.id.clone(),
                detected: t.detected,
                evidence_count: t.evidence.len(),
            })
            .collect();

        let (obfuscator_name, technique_ids, supporting_matched) =
            if let Some(ref attr) = result.attribution {
                (
                    Some(attr.obfuscator_name.clone()),
                    attr.technique_ids.clone(),
                    attr.supporting_matched,
                )
            } else {
                (None, Vec::new(), 0)
            };

        Self {
            techniques,
            obfuscator_name,
            technique_ids,
            supporting_matched,
        }
    }

    /// Merge pipeline attribution into pre-detection info.
    pub fn merge(&mut self, pipeline: &DetectionInfo) {
        // Pipeline attribution is authoritative — it combines both IL and
        // SSA-detected techniques. Prefer it when present.
        if pipeline.obfuscator_name.is_some() {
            self.obfuscator_name = pipeline.obfuscator_name.clone();
            self.technique_ids = pipeline.technique_ids.clone();
            self.supporting_matched = pipeline.supporting_matched;
        }
        // Merge technique lists (pipeline may discover additional techniques)
        for pt in &pipeline.techniques {
            if !self.techniques.iter().any(|t| t.id == pt.id) {
                self.techniques.push(pt.clone());
            } else if pt.detected {
                // Upgrade existing to detected if pipeline found it
                if let Some(existing) = self.techniques.iter_mut().find(|t| t.id == pt.id) {
                    existing.detected = true;
                    existing.evidence_count = existing.evidence_count.max(pt.evidence_count);
                }
            }
        }
    }

    /// Check if a technique was detected.
    pub fn has_technique(&self, id: &str) -> bool {
        self.techniques.iter().any(|t| t.id == id && t.detected)
    }

    /// Get evidence count for a technique.
    pub fn technique_evidence_count(&self, id: &str) -> usize {
        self.techniques
            .iter()
            .find(|t| t.id == id && t.detected)
            .map_or(0, |t| t.evidence_count)
    }

    /// Confidence as a simple 0.0/1.0 based on whether attribution is present.
    pub fn confidence(&self) -> f32 {
        if self.obfuscator_name.is_some() {
            1.0
        } else {
            0.0
        }
    }
}

/// Results from deobfuscating a sample.
#[derive(Debug)]
pub struct TestResult<P: Clone + Debug> {
    pub sample: SampleSpec<P>,
    pub success: bool,
    pub error: Option<String>,
    pub methods_before: usize,
    pub methods_after: usize,
    pub warning_count: usize,
    pub error_count: usize,
    pub assembly_valid: bool,
    pub has_valid_entry_point: bool,
    pub roundtrip_ok: bool,
    /// Pre-detection merged with pipeline detection.
    pub detection: DetectionInfo,
    /// Re-detection on deobfuscated output.
    pub post_detection: DetectionInfo,
    pub switches_remaining: usize,
    pub stats: Option<PipelineStats>,
    pub semantic_result: Option<SemanticVerificationResult>,
    pub deobfuscated_stats: Option<AssemblyStats>,
}

/// Load a sample from the samples directory.
pub fn load_sample(samples_dir: &str, filename: &str) -> Result<CilObject, String> {
    let path = format!("{}/{}", samples_dir, filename);
    CilObject::from_path_with_validation(&path, ValidationConfig::analysis())
        .map_err(|e| format!("Failed to load {}: {}", filename, e))
}

/// Run the full deobfuscation test harness on a sample.
pub fn run_deobfuscation_test<P: Clone + Debug>(
    spec: &SampleSpec<P>,
    samples_dir: &str,
    original_asm: Option<&CilObject>,
    semantic_methods: &[&str],
    config: EngineConfig,
    mode: ProcessMode,
) -> TestResult<P> {
    let mut result = TestResult {
        sample: spec.clone(),
        success: false,
        error: None,
        methods_before: 0,
        methods_after: 0,
        warning_count: 0,
        error_count: 0,
        assembly_valid: false,
        has_valid_entry_point: false,
        roundtrip_ok: false,
        detection: DetectionInfo::default(),
        post_detection: DetectionInfo::default(),
        switches_remaining: 0,
        stats: None,
        semantic_result: None,
        deobfuscated_stats: None,
    };

    let path = format!("{}/{}", samples_dir, spec.filename);

    // For File mode, try to load the assembly for pre-deobfuscation method count
    // (it may fail for PE-corrupted samples — that's fine).
    if mode == ProcessMode::File {
        if let Ok(input_asm) = load_sample(samples_dir, spec.filename) {
            result.methods_before = input_asm.methods().iter().count();
        }
    }

    // For Assembly mode, load normally
    if mode == ProcessMode::Assembly {
        let assembly = match load_sample(samples_dir, spec.filename) {
            Ok(a) => a,
            Err(e) => {
                result.error = Some(e);
                return result;
            }
        };
        result.methods_before = assembly.methods().iter().count();

        // Run pre-detection (IL + SSA)
        let detect_engine = DeobfuscationEngine::default();
        let pre_det = detect_engine.detect(&assembly);
        result.detection = DetectionInfo::from_results(&pre_det);

        // Original samples: early return with success
        if spec.is_original {
            result.success = true;
            result.methods_after = result.methods_before;
            result.assembly_valid = true;
            result.has_valid_entry_point = assembly.cor20header().entry_point_token != 0;
            result.roundtrip_ok = true;
            return result;
        }

        // Run full deobfuscation pipeline
        let engine = DeobfuscationEngine::new(config);
        match engine.process_assembly(assembly) {
            Ok((output, deob_result)) => {
                populate_success_result(
                    &mut result,
                    &output,
                    &deob_result,
                    spec,
                    original_asm,
                    semantic_methods,
                );
            }
            Err(e) => {
                result.error = Some(format!("Deobfuscation failed: {}", e));
            }
        }
    } else {
        // File mode — original check
        if spec.is_original {
            if let Ok(assembly) = load_sample(samples_dir, spec.filename) {
                result.methods_before = assembly.methods().iter().count();
                result.methods_after = result.methods_before;
                result.success = true;
                result.assembly_valid = true;
                result.has_valid_entry_point = assembly.cor20header().entry_point_token != 0;
                result.roundtrip_ok = true;
            }
            return result;
        }

        // Run full pipeline via process_file
        let engine = DeobfuscationEngine::new(config);
        match engine.process_file(&path) {
            Ok((output, deob_result)) => {
                // For File mode, detection comes from the pipeline result
                result.detection = DetectionInfo::from_results(&deob_result);
                populate_success_result(
                    &mut result,
                    &output,
                    &deob_result,
                    spec,
                    original_asm,
                    semantic_methods,
                );
            }
            Err(e) => {
                result.error = Some(format!("Deobfuscation failed: {}", e));
            }
        }
    }

    result
}

/// Populate result fields after successful deobfuscation.
fn populate_success_result<P: Clone + Debug>(
    result: &mut TestResult<P>,
    output: &CilObject,
    deob_result: &DeobfuscationResult,
    spec: &SampleSpec<P>,
    original_asm: Option<&CilObject>,
    semantic_methods: &[&str],
) {
    result.success = true;
    result.methods_after = output.methods().iter().count();

    // Merge pipeline attribution into detection
    let pipeline_detection = DetectionInfo::from_results(deob_result);
    result.detection.merge(&pipeline_detection);

    // Stats
    let stats = deob_result.stats();
    result.stats = Some(PipelineStats {
        methods_transformed: stats.methods_transformed,
        constants_folded: stats.constants_folded,
        strings_decrypted: stats.strings_decrypted,
        branches_simplified: stats.branches_simplified,
        artifacts_removed: stats.artifacts_removed,
    });
    result.warning_count = 0;
    result.error_count = 0;

    // Entry point
    result.has_valid_entry_point = output.cor20header().entry_point_token != 0;

    // Re-detect on output
    let post_engine = DeobfuscationEngine::default();
    let post_det = post_engine.detect(output);
    result.post_detection = DetectionInfo::from_results(&post_det);

    // Roundtrip verification
    let bytes = output.file().data();
    match CilObject::from_mem_with_validation(bytes.to_vec(), ValidationConfig::production()) {
        Ok(reloaded) => {
            result.assembly_valid = true;
            result.roundtrip_ok = output.methods().iter().count()
                == reloaded.methods().iter().count()
                && output.types().iter().count() == reloaded.types().iter().count();
        }
        Err(e) => {
            result.assembly_valid = false;
            result.roundtrip_ok = false;
            result.error = Some(format!("Roundtrip failed: {}", e));
        }
    }

    // Collect structural stats
    let output_size = output.file().data().len() as u64;
    result.deobfuscated_stats = Some(AssemblyStats::from_assembly(output, output_size));

    // Semantic preservation
    if spec.check_semantic_preservation && !spec.is_original {
        if let Some(orig) = original_asm {
            // Need to reload output from bytes for Arc ownership
            let output_bytes = output.file().data().to_vec();
            if let Ok(output_copy) =
                CilObject::from_mem_with_validation(output_bytes, ValidationConfig::analysis())
            {
                result.semantic_result = Some(verify_semantic_preservation(
                    orig,
                    Arc::new(output_copy),
                    semantic_methods,
                    spec.verification_level,
                ));
            }
        }
    }
}

/// Assert common requirements that apply to all deobfuscated samples.
///
/// `semantic_threshold` is the minimum preservation ratio (e.g. 0.95).
/// `require_all_preserved` controls whether `methods_preserved == methods_checked` is asserted.
pub fn assert_common_requirements<P: Clone + Debug>(
    result: &TestResult<P>,
    original_stats: Option<&AssemblyStats>,
    semantic_threshold: f64,
    require_all_preserved: bool,
) {
    let filename = result.sample.filename;

    // Core: must succeed
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
        result.has_valid_entry_point,
        "{}: Output has no valid entry point",
        filename
    );

    assert!(
        result.roundtrip_ok,
        "{}: Roundtrip structure mismatch - {:?}",
        filename, result.error
    );

    // Semantic preservation (skip for original/unobfuscated samples)
    if result.sample.check_semantic_preservation && !result.sample.is_original {
        if let Some(ref sem) = result.semantic_result {
            let preservation_ratio = if sem.methods_checked > 0 {
                sem.methods_preserved as f64 / sem.methods_checked as f64
            } else {
                1.0
            };

            if require_all_preserved {
                assert_eq!(
                    sem.methods_preserved,
                    sem.methods_checked,
                    "{}: Not all methods preserved ({}/{} methods, avg similarity {:.0}%)",
                    filename,
                    sem.methods_preserved,
                    sem.methods_checked,
                    sem.average_similarity * 100.0
                );
            }

            assert!(
                preservation_ratio >= semantic_threshold,
                "{}: Semantic preservation too low ({}/{} = {:.0}%, expected >= {:.0}%)",
                filename,
                sem.methods_preserved,
                sem.methods_checked,
                preservation_ratio * 100.0,
                semantic_threshold * 100.0
            );
        }
    }

    // Structural match against original
    if result.sample.check_structural_match {
        if let (Some(orig_stats), Some(ref deob_stats)) =
            (original_stats, &result.deobfuscated_stats)
        {
            assert_structural_match(
                orig_stats,
                deob_stats,
                filename,
                &result.sample.structural_config,
            );
        }
    }

    // Diagnostics
    assert_deobfuscation_diagnostics(filename, result.warning_count, result.error_count);
}

/// Print a summary of test results.
///
/// `extra_lines_fn` is called per-result to emit obfuscator-specific detection lines.
pub fn print_summary<P: Clone + Debug, F>(results: &[TestResult<P>], label: &str, extra_lines_fn: F)
where
    F: Fn(&TestResult<P>),
{
    eprintln!("\n================================================================================",);
    eprintln!("{} DEOBFUSCATION TEST SUMMARY", label);
    eprintln!("================================================================================\n",);

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

        // Obfuscator-specific detection lines
        extra_lines_fn(result);

        // Stats line
        eprintln!(
            "       Methods: {} -> {} (warnings={} errors={})",
            result.methods_before, result.methods_after, result.warning_count, result.error_count,
        );

        // Post-deobfuscation line
        if !result.sample.is_original {
            eprintln!(
                "       Post-deobfuscation: confidence={:.0}% techniques=[{}] valid={} roundtrip={}",
                result.post_detection.confidence() * 100.0,
                result.post_detection.technique_ids.join(", "),
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
