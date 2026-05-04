//! Generic sentinel-based taint removal pass.
//!
//! Removes injected protection code by seeding forward-only taint analysis from
//! configurable sentinel API calls, then neutralizing all dependent instructions.
//! This is the shared implementation used by multiple obfuscator-specific techniques
//! (BitMono timing checks, ConfuserEx debugger checks, etc.).
//!
//! # Algorithm
//!
//! 1. Scan the method for `Call`/`CallVirt` instructions matching the sentinel patterns
//! 2. Check the [`SentinelCondition`] — skip the method if sentinel co-occurrence
//!    requirements are not met
//! 3. Run forward-only taint analysis from matched sentinel tokens
//! 4. NOP all tainted non-terminator instructions
//! 5. Replace tainted branch terminators with unconditional jumps to the clean
//!    successor (the branch that does NOT lead to the crash/exit path)
//! 6. Remove tainted PHI nodes
//!
//! # False Positive Mitigation
//!
//! The [`SentinelCondition`] enum controls method-level gating:
//! - [`All`](SentinelCondition::All): every sentinel pattern must appear (strongest gate)
//! - [`AtLeast(n)`](SentinelCondition::AtLeast): at least N distinct patterns must appear
//! - [`Any`](SentinelCondition::Any): any single pattern suffices (weakest gate, relies on
//!   `target_methods` from detection for safety)
//!
//! Within a qualifying method, only instructions reachable via data-flow from sentinel
//! tokens are removed — legitimate code that doesn't depend on sentinel results is
//! preserved.
//!
//! # Example (BitMono timing checks)
//!
//! ```text
//! // Before (anti-debug prologue + epilogue):
//! v0 = call DateTime::get_UtcNow()         // sentinel #1
//! ...
//! v5 = call DateTime::get_UtcNow()         // sentinel #1 (end)
//! v6 = call DateTime::op_Subtraction(v5, v0)  // sentinel #2
//! v7 = call TimeSpan::get_TotalMilliseconds(v6)  // sentinel #3
//! v8 = Const(5000.0)
//! BranchCmp(v7 > v8, crash_block, normal_block)
//!
//! // After:
//! Nop (was get_UtcNow)
//! ...
//! Nop (was get_UtcNow)
//! Nop (was op_Subtraction)
//! Nop (was get_TotalMilliseconds)
//! Nop (was Const 5000.0)
//! Jump(normal_block)
//! ```

use std::collections::HashSet;

use crate::{
    analysis::{PhiTaintMode, SsaFunction, SsaOp, TaintConfig, TokenTaintBuilder},
    compiler::{CompilerContext, EventKind, ModificationScope, SsaPass},
    deobfuscation::utils::resolve_qualified_method_name,
    metadata::token::Token,
    CilObject, Result,
};

/// Controls how many sentinel patterns must co-occur in a method for the pass
/// to activate.
///
/// This is the primary false-positive mitigation mechanism. The taint analysis
/// itself is precise (only data-flow-dependent instructions are removed), but
/// the sentinel condition prevents the pass from running on methods where the
/// sentinel APIs appear in legitimate user code.
#[derive(Debug, Clone)]
pub enum SentinelCondition {
    /// All sentinel patterns must be present in the method.
    ///
    /// Strongest gate — use when the sentinel set forms a known chain
    /// (e.g., BitMono's `UtcNow` → `op_Subtraction` → `TotalMilliseconds`).
    All,
    /// At least one sentinel pattern must be present.
    ///
    /// Weakest gate — only safe when combined with a tight `target_methods`
    /// set from detection.
    Any,
    /// At least N distinct sentinel patterns must be present.
    ///
    /// Middle ground — e.g., `AtLeast(2)` for "any 2 of 5 anti-debug APIs."
    AtLeast(usize),
}

impl SentinelCondition {
    /// Checks whether the condition is satisfied given the number of distinct
    /// sentinel patterns matched and the total number of sentinel patterns.
    ///
    /// # Arguments
    ///
    /// * `matched` - Number of distinct sentinel patterns found in the method.
    /// * `total` - Total number of sentinel patterns configured on the pass.
    fn is_satisfied(&self, matched: usize, total: usize) -> bool {
        match self {
            Self::All => matched >= total,
            Self::Any => matched >= 1,
            Self::AtLeast(n) => matched >= *n,
        }
    }
}

/// Generic sentinel-based taint removal pass.
///
/// Scans methods for calls matching configurable sentinel API name patterns,
/// then uses forward-only taint analysis to surgically remove all dependent
/// instructions. Used by BitMono (timing checks), ConfuserEx (debugger checks),
/// and potentially any obfuscator that injects protection code seeded from
/// known API calls.
pub struct SentinelTaintRemovalPass {
    /// Display name for this pass instance (e.g., "BitMonoAntiDebug").
    pass_name: &'static str,
    /// Display description for this pass instance.
    pass_description: &'static str,
    /// Tokens of methods known to contain protection injection (from detection).
    /// Empty means "run on all methods" (relies on sentinel condition for gating).
    target_methods: HashSet<Token>,
    /// Substrings to match against resolved method names. A call instruction
    /// whose resolved name contains any of these strings is a sentinel.
    sentinel_patterns: Vec<&'static str>,
    /// How many distinct sentinel patterns must co-occur for the pass to activate.
    condition: SentinelCondition,
}

impl SentinelTaintRemovalPass {
    /// Creates a new sentinel taint removal pass.
    ///
    /// # Arguments
    ///
    /// * `pass_name` - Short identifier for logging/events (e.g., `"BitMonoAntiDebug"`).
    /// * `pass_description` - Human-readable description for the pass scheduler.
    /// * `target_methods` - Set of method tokens to process. Pass an empty set to
    ///   run on all methods (sentinel condition still applies).
    /// * `sentinel_patterns` - Substrings matched against resolved call target names.
    ///   A call whose resolved name contains any pattern is treated as a sentinel.
    /// * `condition` - How many distinct patterns must co-occur for activation.
    pub fn new(
        pass_name: &'static str,
        pass_description: &'static str,
        target_methods: HashSet<Token>,
        sentinel_patterns: Vec<&'static str>,
        condition: SentinelCondition,
    ) -> Self {
        Self {
            pass_name,
            pass_description,
            target_methods,
            sentinel_patterns,
            condition,
        }
    }
}

impl SsaPass for SentinelTaintRemovalPass {
    fn name(&self) -> &'static str {
        self.pass_name
    }

    fn description(&self) -> &'static str {
        self.pass_description
    }

    fn modification_scope(&self) -> ModificationScope {
        ModificationScope::CfgModifying
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
        // Step 1: Find sentinel tokens and check co-occurrence condition.
        let (sentinel_tokens, distinct_count) =
            find_sentinel_tokens(ssa, assembly, &self.sentinel_patterns);
        if !self
            .condition
            .is_satisfied(distinct_count, self.sentinel_patterns.len())
        {
            return Ok(false);
        }
        if sentinel_tokens.is_empty() {
            return Ok(false);
        }

        // Step 2: Run forward-only taint analysis seeded from sentinel tokens.
        // Forward-only because we only want what DEPENDS ON the sentinel calls.
        // NoPropagation for phis: injected protection variables are local to the
        // protection prologue/epilogue and should never leak through phi merges.
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
                            neutralized = neutralized.saturating_add(1);
                        }
                    } else {
                        instr.set_op(SsaOp::Nop);
                        neutralized = neutralized.saturating_add(1);
                    }
                }
            }
        }

        // Step 5: Remove tainted PHI nodes (reverse order for safe removal).
        let mut tainted_phis: Vec<(usize, usize)> = taint.tainted_phis().iter().copied().collect();
        tainted_phis.sort_by(|a, b| b.cmp(a));
        for (block_idx, phi_idx) in tainted_phis {
            if let Some(block) = ssa.block_mut(block_idx) {
                if phi_idx < block.phi_nodes().len() {
                    block.phi_nodes_mut().remove(phi_idx);
                    neutralized = neutralized.saturating_add(1);
                }
            }
        }

        if neutralized > 0 {
            ctx.events
                .record(EventKind::InstructionRemoved)
                .method(method_token)
                .message(format!(
                    "{}: removed {neutralized} tainted instructions",
                    self.pass_name,
                ));
        }

        Ok(neutralized > 0)
    }
}

/// Finds metadata tokens of sentinel API calls within a method's SSA.
///
/// Scans all `Call`/`CallVirt` instructions and checks whether the resolved
/// method name contains any of the sentinel patterns.
///
/// # Arguments
///
/// * `ssa` - The SSA function graph to scan.
/// * `assembly` - The assembly, used for resolving method names.
/// * `sentinel_patterns` - Substrings to match against resolved method names.
///
/// # Returns
///
/// A tuple of:
/// - The set of unique metadata tokens for matched sentinel calls
/// - The number of distinct sentinel patterns that were matched (for condition checking)
fn find_sentinel_tokens(
    ssa: &SsaFunction,
    assembly: &CilObject,
    sentinel_patterns: &[&str],
) -> (HashSet<Token>, usize) {
    let mut tokens = HashSet::new();
    let mut matched_patterns: HashSet<usize> = HashSet::new();

    for block in ssa.blocks() {
        for instr in block.instructions() {
            let method_token = match instr.op() {
                SsaOp::Call { method, .. } | SsaOp::CallVirt { method, .. } => method.token(),
                _ => continue,
            };

            if let Some(name) = resolve_qualified_method_name(assembly, method_token) {
                for (idx, pattern) in sentinel_patterns.iter().enumerate() {
                    if name.contains(pattern) {
                        tokens.insert(method_token);
                        matched_patterns.insert(idx);
                    }
                }
            }
        }
    }

    (tokens, matched_patterns.len())
}

/// Chooses which branch target to keep when neutralizing a tainted branch.
///
/// Prefers the target whose first instruction is not tainted, i.e., the
/// legitimate code path rather than the crash/exit path. When both or
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
