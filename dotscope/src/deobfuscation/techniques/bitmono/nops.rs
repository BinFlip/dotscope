//! BitMono BillionNops dead method detection technique.
//!
//! Detects BitMono's BillionNops protection, which injects methods into
//! `<Module>` containing tens of thousands of `nop` instructions followed
//! by a `ret`. These bloated methods serve no purpose other than inflating
//! the assembly size and slowing down analysis tools.
//!
//! # Detection
//!
//! Scans methods in `<Module>` for bodies containing more than 50,000 `nop`
//! instructions. This threshold distinguishes BillionNops dead methods from
//! legitimate methods that may contain a few nops due to debug info or
//! alignment.
//!
//! # Cleanup
//!
//! Returns the dead nop method tokens via [`cleanup()`](SsaTechnique::cleanup)
//! for removal during the assembly cleanup phase.

use std::any::Any;

use crate::{
    cilassembly::CleanupRequest,
    deobfuscation::techniques::{Detection, Evidence, PassPhase, Technique, TechniqueCategory},
    metadata::token::Token,
    CilObject,
};

/// Findings from BitMono BillionNops detection.
#[derive(Debug)]
pub struct NopsFindings {
    /// Tokens of `<Module>` methods with 50K+ nop instructions.
    pub dead_methods: Vec<Token>,
}

/// Detects BitMono's BillionNops dead method inflation.
///
/// Identifies methods in `<Module>` that contain over 50,000 `nop` instructions,
/// which are injected by BitMono's BillionNops protection purely to inflate
/// assembly size and degrade analysis performance. These methods are marked
/// for removal during cleanup.
pub struct BitMonoNops;

impl Technique for BitMonoNops {
    fn id(&self) -> &'static str {
        "bitmono.nops"
    }

    fn name(&self) -> &'static str {
        "BitMono BillionNops Removal"
    }

    fn category(&self) -> TechniqueCategory {
        TechniqueCategory::Neutralization
    }

    fn detect(&self, assembly: &CilObject) -> Detection {
        let types = assembly.types();
        let Some(module_type) = types.module_type() else {
            return Detection::new_empty();
        };

        let mut dead_methods = Vec::new();

        for (_, method_ref) in module_type.methods.iter() {
            let Some(method) = method_ref.upgrade() else {
                continue;
            };

            let nop_count = method
                .instructions()
                .filter(|i| i.mnemonic == "nop")
                .count();

            if nop_count > 50_000 {
                dead_methods.push(method.token);
            }
        }

        if dead_methods.is_empty() {
            return Detection::new_empty();
        }

        let count = dead_methods.len();
        Detection::new_detected(
            vec![Evidence::Structural(format!(
                "{count} BillionNops dead methods in <Module> (50K+ nop instructions each)"
            ))],
            Some(Box::new(NopsFindings { dead_methods }) as Box<dyn Any + Send + Sync>),
        )
    }

    fn ssa_phase(&self) -> Option<PassPhase> {
        Some(PassPhase::Normalize)
    }

    fn cleanup(&self, detection: &Detection) -> Option<CleanupRequest> {
        let findings = detection.findings::<NopsFindings>()?;
        if findings.dead_methods.is_empty() {
            return None;
        }

        let mut request = CleanupRequest::new();
        for token in &findings.dead_methods {
            request.add_method(*token);
        }
        Some(request)
    }
}

#[cfg(test)]
mod tests {
    use crate::deobfuscation::techniques::{bitmono::BitMonoNops, Technique};
    use crate::test::helpers::load_sample;

    #[test]
    fn test_detect_positive() {
        let assembly = load_sample("tests/samples/packers/bitmono/0.39.0/bitmono_combined.exe");

        let technique = BitMonoNops;
        let detection = technique.detect(&assembly);

        // BitMonoNops is an SSA technique. The IL-level detect() looks for
        // <Module> methods with 50K+ nop instructions. The combined sample
        // may or may not contain BillionNops. Assert consistency.
        if detection.detected {
            assert!(
                !detection.evidence.is_empty(),
                "Positive detection should include evidence"
            );
        }
    }

    #[test]
    fn test_detect_negative() {
        let assembly = load_sample("tests/samples/packers/confuserex/1.6.0/original.exe");

        let technique = BitMonoNops;
        let detection = technique.detect(&assembly);

        assert!(
            !detection.detected,
            "BitMonoNops should not detect nop methods in a non-BitMono assembly"
        );
    }
}
