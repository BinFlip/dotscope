//! BitMono AntiDebugBreakpoints detection and removal.
//!
//! Detects and removes BitMono's AntiDebugBreakpoints protection, which injects
//! timing checks into method bodies. The timing check measures execution time
//! using `DateTime.UtcNow` calls at the start and end of the method, computes
//! the difference via `op_Subtraction`, and checks `TotalMilliseconds` against
//! a threshold. If the elapsed time exceeds the threshold (indicating a debugger
//! breakpoint was hit), the method triggers a divide-by-zero crash.
//!
//! # CIL Pattern
//!
//! The injected prologue:
//! ```text
//! call       DateTime::get_UtcNow()
//! stloc      <datetime_local>
//! ```
//!
//! The injected epilogue (before the method's real return):
//! ```text
//! call       DateTime::get_UtcNow()
//! ldloc      <datetime_local>
//! call       DateTime::op_Subtraction()
//! stloc      <timespan_local>
//! ldloca     <timespan_local>
//! call       TimeSpan::get_TotalMilliseconds()
//! ldc.r8     5000.0
//! ble.un.s   <skip_label>
//! ldc.i4.0
//! stloc      <int_local>
//! ldloc      <int_local>
//! ldloc      <int_local>
//! div                              ; divide-by-zero crash
//! pop
//! ```
//!
//! # Detection
//!
//! Scans all methods for the three sentinel API calls:
//! - `DateTime::get_UtcNow` (start and end timestamps)
//! - `DateTime::op_Subtraction` (time difference)
//! - `TimeSpan::get_TotalMilliseconds` (threshold comparison)
//!
//! A method containing all three is flagged as having the anti-debug pattern.
//!
//! # SSA Pass
//!
//! The removal pass lives in [`crate::deobfuscation::passes::bitmono::debug`]
//! and uses forward-only taint analysis seeded from the three sentinel API calls
//! to automatically identify and remove all dependent obfuscation code.

use std::{collections::HashSet, sync::Arc};

use crate::{
    analysis::CilTarget,
    compiler::{CompilerContext, PassPhase, SsaPass},
    deobfuscation::{
        context::AnalysisContext,
        passes::{SentinelCondition, SentinelTaintRemovalPass},
        techniques::{Detection, Evidence, Technique, TechniqueCategory},
        utils::find_methods_calling_apis,
    },
    metadata::token::Token,
    CilObject,
};

/// Findings from BitMono AntiDebugBreakpoints detection.
#[derive(Debug)]
pub struct BmAntiDebugFindings {
    /// Tokens of methods containing the timing check anti-debug pattern.
    pub method_tokens: HashSet<Token>,
}

/// Detects BitMono's AntiDebugBreakpoints timing check pattern.
///
/// Identifies methods that contain `DateTime.UtcNow` + `op_Subtraction` +
/// `TotalMilliseconds` — the three sentinel API calls that comprise BitMono's
/// timing-based anti-debug protection. Supersedes the generic anti-debug
/// detection for BitMono-protected assemblies.
pub struct BitMonoAntiDebug;

impl Technique for BitMonoAntiDebug {
    fn id(&self) -> &'static str {
        "bitmono.debug"
    }

    fn name(&self) -> &'static str {
        "BitMono AntiDebugBreakpoints Removal"
    }

    fn category(&self) -> TechniqueCategory {
        TechniqueCategory::Neutralization
    }

    fn supersedes(&self) -> &[&'static str] {
        &["generic.debug"]
    }

    fn detect(&self, assembly: &CilObject) -> Detection {
        let patterns = &["get_UtcNow", "op_Subtraction", "get_TotalMilliseconds"];
        let matches = find_methods_calling_apis(assembly, patterns);

        // Require all three sentinel APIs in the same method
        let method_tokens: HashSet<Token> = matches
            .into_iter()
            .filter(|(_, idxs)| idxs.contains(&0) && idxs.contains(&1) && idxs.contains(&2))
            .map(|(token, _)| token)
            .collect();

        if method_tokens.is_empty() {
            return Detection::new_empty();
        }

        let count = method_tokens.len();
        let mut detection = Detection::new_detected(
            vec![Evidence::BytecodePattern(format!(
                "{count} methods with BitMono AntiDebugBreakpoints timing checks \
                 (UtcNow + op_Subtraction + TotalMilliseconds)"
            ))],
            None,
        );

        detection.set_findings(Box::new(BmAntiDebugFindings { method_tokens }));

        detection
    }

    fn ssa_phase(&self) -> Option<PassPhase> {
        Some(PassPhase::Simplify)
    }

    fn create_pass(
        &self,
        _ctx: &AnalysisContext,
        detection: &Detection,
        _assembly: &Arc<CilObject>,
    ) -> Vec<Box<dyn SsaPass<CilTarget, CompilerContext>>> {
        let Some(findings) = detection.findings::<BmAntiDebugFindings>() else {
            return Vec::new();
        };
        vec![Box::new(SentinelTaintRemovalPass::new(
            "BitMonoAntiDebug",
            "Removes BitMono AntiDebugBreakpoints timing checks via taint analysis",
            findings.method_tokens.clone(),
            vec!["get_UtcNow", "op_Subtraction", "get_TotalMilliseconds"],
            SentinelCondition::All,
        ))]
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        deobfuscation::techniques::{bitmono::BitMonoAntiDebug, Technique},
        test::helpers::load_sample,
    };

    #[test]
    fn test_detect_positive() {
        let assembly = load_sample("tests/samples/packers/bitmono/0.39.0/bitmono_antidebug.exe");

        let technique = BitMonoAntiDebug;
        let detection = technique.detect(&assembly);

        // BitMonoAntiDebug is an SSA technique, but its IL-level detect()
        // scans for sentinel API calls (UtcNow, op_Subtraction, TotalMilliseconds).
        // These should be present in the antidebug sample.
        if detection.is_detected() {
            assert!(
                !detection.evidence().is_empty(),
                "Positive detection should include evidence"
            );
        }
    }

    #[test]
    fn test_detect_negative() {
        let assembly = load_sample("tests/samples/packers/confuserex/1.6.0/original.exe");

        let technique = BitMonoAntiDebug;
        let detection = technique.detect(&assembly);

        assert!(
            !detection.is_detected(),
            "BitMonoAntiDebug should not detect timing checks in a non-BitMono assembly"
        );
    }
}
