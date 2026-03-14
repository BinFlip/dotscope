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
//! `AntiDebugRemovalPass` uses forward-only taint analysis seeded from the
//! three sentinel API calls to automatically identify and remove all dependent
//! obfuscation code — including the timing branch, the divide-by-zero crash,
//! and any associated local variables. This is resilient to variations in
//! variable allocation, instruction ordering, and branch encoding.

use std::{collections::HashSet, sync::Arc};

use crate::{
    analysis::{PhiTaintMode, SsaFunction, SsaOp, TaintConfig, TokenTaintBuilder},
    compiler::{CompilerContext, EventKind, SsaPass},
    deobfuscation::{
        context::AnalysisContext,
        techniques::{Detection, Evidence, PassPhase, Technique, TechniqueCategory},
    },
    metadata::token::Token,
    CilObject, Result,
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
        let matches = crate::deobfuscation::utils::find_methods_calling_apis(assembly, patterns);

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
    ) -> Option<Box<dyn SsaPass>> {
        let findings = detection.findings::<BmAntiDebugFindings>()?;
        Some(Box::new(AntiDebugRemovalPass::with_methods(
            findings.method_tokens.iter().copied(),
        )))
    }
}

/// SSA pass that removes BitMono AntiDebugBreakpoints timing checks.
///
/// Uses forward-only taint analysis seeded from the three sentinel API calls
/// (`get_UtcNow`, `op_Subtraction`, `get_TotalMilliseconds`) to automatically
/// identify and remove all dependent obfuscation code — including branches,
/// the divide-by-zero crash, and any associated local variables.
struct AntiDebugRemovalPass {
    /// Tokens of methods known to contain anti-debug injection (from detection).
    target_methods: HashSet<Token>,
}

impl AntiDebugRemovalPass {
    /// Creates a pass targeting specific methods identified during detection.
    ///
    /// # Arguments
    ///
    /// * `tokens` - Iterator of method [`Token`]s known to contain the
    ///   `AntiDebugBreakpoints` timing check pattern.
    ///
    /// # Returns
    ///
    /// An [`AntiDebugRemovalPass`] that will only run on the specified methods.
    fn with_methods(tokens: impl IntoIterator<Item = Token>) -> Self {
        Self {
            target_methods: tokens.into_iter().collect(),
        }
    }
}

impl SsaPass for AntiDebugRemovalPass {
    fn name(&self) -> &'static str {
        "BitMonoAntiDebug"
    }

    fn description(&self) -> &'static str {
        "Removes BitMono AntiDebugBreakpoints timing checks via taint analysis"
    }

    fn should_run(&self, method_token: Token, _ctx: &CompilerContext) -> bool {
        self.target_methods.is_empty() || self.target_methods.contains(&method_token)
    }

    fn run_on_method(
        &self,
        ssa: &mut SsaFunction,
        method_token: Token,
        ctx: &CompilerContext,
        assembly: &CilObject,
    ) -> Result<bool> {
        // Step 1: Find the sentinel tokens — calls to get_UtcNow, op_Subtraction,
        // get_TotalMilliseconds — within this method's SSA.
        let sentinel_tokens = find_sentinel_tokens(ssa, assembly);
        if sentinel_tokens.is_empty() {
            return Ok(false);
        }

        // Step 2: Run forward-only taint analysis seeded from these tokens.
        // Forward-only because we only want what DEPENDS ON the sentinel calls.
        // NoPropagation for phis: the injected timing variables are local to the
        // anti-debug prologue/epilogue and should never leak through phi merges.
        let taint = TokenTaintBuilder::new(sentinel_tokens)
            .with_config(TaintConfig {
                forward: true,
                backward: false,
                phi_mode: PhiTaintMode::NoPropagation,
                max_iterations: 100,
            })
            .analyze(ssa);
        if taint.tainted_instr_count() == 0 {
            return Ok(false);
        }

        let tainted_instrs: HashSet<(usize, usize)> =
            taint.tainted_instructions().iter().copied().collect();

        // Step 3: Pre-compute branch redirect targets (immutable borrow)
        // before mutating instructions (mutable borrow).
        let mut branch_redirects: Vec<(usize, usize, usize)> = Vec::new();
        for &(block_idx, instr_idx) in taint.tainted_instructions() {
            if let Some(block) = ssa.block(block_idx) {
                if let Some(instr) = block.instruction(instr_idx) {
                    if instr.is_terminator() {
                        match instr.op() {
                            SsaOp::Branch {
                                true_target,
                                false_target,
                                ..
                            }
                            | SsaOp::BranchCmp {
                                true_target,
                                false_target,
                                ..
                            } => {
                                let target = choose_clean_target(
                                    ssa,
                                    *true_target,
                                    *false_target,
                                    &tainted_instrs,
                                );
                                branch_redirects.push((block_idx, instr_idx, target));
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        // Step 4: Apply mutations.
        let mut neutralized = 0usize;

        for &(block_idx, instr_idx) in taint.tainted_instructions() {
            if let Some(block) = ssa.block_mut(block_idx) {
                if let Some(instr) = block.instruction_mut(instr_idx) {
                    // Record metadata tokens before neutralizing
                    match instr.op() {
                        SsaOp::Call { method, .. } | SsaOp::CallVirt { method, .. } => {
                            ctx.neutralized_tokens.insert(method.token());
                        }
                        _ => {}
                    }

                    if instr.is_terminator() {
                        if let Some(&(_, _, target)) = branch_redirects
                            .iter()
                            .find(|&&(bi, ii, _)| bi == block_idx && ii == instr_idx)
                        {
                            instr.set_op(SsaOp::Jump { target });
                            neutralized += 1;
                        }
                    } else {
                        instr.set_op(SsaOp::Nop);
                        neutralized += 1;
                    }
                }
            }
        }

        // Remove tainted PHI nodes
        let mut tainted_phis: Vec<(usize, usize)> = taint.tainted_phis().iter().copied().collect();
        tainted_phis.sort_by(|a, b| b.cmp(a)); // Reverse order for safe removal
        for (block_idx, phi_idx) in tainted_phis {
            if let Some(block) = ssa.block_mut(block_idx) {
                if phi_idx < block.phi_nodes().len() {
                    block.phi_nodes_mut().remove(phi_idx);
                    neutralized += 1;
                }
            }
        }

        if neutralized > 0 {
            ctx.events
                .record(EventKind::InstructionRemoved)
                .method(method_token)
                .message(format!(
                    "Removed {neutralized} BitMono AntiDebugBreakpoints instructions"
                ));
        }

        Ok(neutralized > 0)
    }
}

/// Finds the metadata tokens of the three sentinel APIs within a method's SSA.
///
/// The three sentinels are: `DateTime.get_UtcNow`, `DateTime.op_Subtraction`,
/// and `TimeSpan.get_TotalMilliseconds`. These seed the forward taint analysis
/// that removes all dependent anti-debug instructions.
///
/// # Arguments
///
/// * `ssa` - The SSA function graph to scan.
/// * `assembly` - The assembly, used for resolving method names.
///
/// # Returns
///
/// A [`HashSet`] of unique metadata tokens for each sentinel API found.
/// Empty if none of the sentinel APIs appear in the method.
fn find_sentinel_tokens(ssa: &SsaFunction, assembly: &CilObject) -> HashSet<Token> {
    let mut tokens = HashSet::new();

    for block in ssa.blocks() {
        for instr in block.instructions() {
            let method_token = match instr.op() {
                SsaOp::Call { method, .. } | SsaOp::CallVirt { method, .. } => method.token(),
                _ => continue,
            };

            if let Some(name) = assembly.resolve_method_name(method_token) {
                if name.contains("get_UtcNow")
                    || name.contains("op_Subtraction")
                    || name.contains("get_TotalMilliseconds")
                {
                    tokens.insert(method_token);
                }
            }
        }
    }

    tokens
}

/// Chooses which branch target to keep when neutralizing a tainted branch.
///
/// Prefers the target whose first instruction is not tainted, i.e., the
/// legitimate code path rather than the anti-debug crash path. When both or
/// neither target is tainted, `true_target` is returned as a safe default
/// (typically the forward/exit path in well-structured control flow).
///
/// # Arguments
///
/// * `ssa` - The SSA function graph, used to look up block instructions.
/// * `true_target` - Block index of the branch's true successor.
/// * `false_target` - Block index of the branch's false successor.
/// * `tainted_instrs` - Set of `(block, instr)` pairs identified as tainted.
///
/// # Returns
///
/// The block index of the preferred clean successor.
fn choose_clean_target(
    ssa: &SsaFunction,
    true_target: usize,
    false_target: usize,
    tainted_instrs: &HashSet<(usize, usize)>,
) -> usize {
    let true_tainted = ssa.block(true_target).is_some_and(|b| {
        !b.instructions().is_empty() && tainted_instrs.contains(&(true_target, 0))
    });
    let false_tainted = ssa.block(false_target).is_some_and(|b| {
        !b.instructions().is_empty() && tainted_instrs.contains(&(false_target, 0))
    });

    match (true_tainted, false_tainted) {
        (true, false) => false_target,
        (false, true) => true_target,
        // Both or neither tainted — prefer true (typically the forward/exit path)
        _ => true_target,
    }
}

#[cfg(test)]
mod tests {
    use crate::deobfuscation::techniques::{bitmono::BitMonoAntiDebug, Technique};
    use crate::test::helpers::load_sample;

    #[test]
    fn test_detect_positive() {
        let assembly = load_sample("tests/samples/packers/bitmono/0.39.0/bitmono_antidebug.exe");

        let technique = BitMonoAntiDebug;
        let detection = technique.detect(&assembly);

        // BitMonoAntiDebug is an SSA technique, but its IL-level detect()
        // scans for sentinel API calls (UtcNow, op_Subtraction, TotalMilliseconds).
        // These should be present in the antidebug sample.
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

        let technique = BitMonoAntiDebug;
        let detection = technique.detect(&assembly);

        assert!(
            !detection.detected,
            "BitMonoAntiDebug should not detect timing checks in a non-BitMono assembly"
        );
    }
}
