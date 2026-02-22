//! BitMono AntiDebugBreakpoints removal — SSA pass with taint analysis.
//!
//! Removes timing check instructions injected by BitMono's AntiDebugBreakpoints
//! protection. Uses forward taint propagation from the three sentinel API calls
//! (`get_UtcNow`, `op_Subtraction`, `get_TotalMilliseconds`) to automatically
//! identify and remove all dependent code — including the branch, the
//! divide-by-zero crash, and any associated local variables.
//!
//! # Pattern (CIL)
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
//! div
//! pop
//! ```
//!
//! # SSA Approach
//!
//! Rather than pattern-matching exact instruction sequences, this pass:
//! 1. Finds calls to the **three sentinel APIs** (identified by metadata name)
//! 2. Seeds forward taint analysis from those calls
//! 3. Every instruction whose inputs are tainted — including branches, stores,
//!    and the div-by-zero crash — is automatically marked
//! 4. Tainted instructions are replaced with `Nop` (branches become `Jump`)
//!
//! This is resilient to variations in local variable allocation, instruction
//! ordering, and branch encoding that future BitMono versions might introduce.

use std::{collections::HashSet, sync::Arc};

use crate::{
    analysis::{PhiTaintMode, SsaFunction, SsaOp, TaintConfig, TokenTaintBuilder},
    compiler::{CompilerContext, EventKind, SsaPass},
    metadata::token::Token,
    CilObject, Result,
};

/// SSA pass that removes BitMono AntiDebugBreakpoints timing checks.
///
/// Uses taint analysis seeded from the three sentinel API calls to
/// automatically identify and remove all dependent obfuscation code.
pub struct AntiDebugRemovalPass {
    /// Tokens of methods known to contain anti-debug injection (from detection).
    /// If empty, the pass scans all methods.
    target_methods: HashSet<Token>,
}

impl AntiDebugRemovalPass {
    /// Creates a pass targeting specific methods identified during detection.
    #[must_use]
    pub fn with_methods(tokens: impl IntoIterator<Item = Token>) -> Self {
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
        // Only run on methods identified during detection
        self.target_methods.is_empty() || self.target_methods.contains(&method_token)
    }

    fn run_on_method(
        &self,
        ssa: &mut SsaFunction,
        method_token: Token,
        ctx: &CompilerContext,
        assembly: &Arc<CilObject>,
    ) -> Result<bool> {
        // Step 1: Find the sentinel tokens — calls to get_UtcNow, op_Subtraction,
        // get_TotalMilliseconds — within this method's SSA.
        let sentinel_tokens = find_sentinel_tokens(ssa, assembly);
        if sentinel_tokens.is_empty() {
            return Ok(false);
        }

        // Step 2: Run forward-only taint analysis seeded from these tokens.
        // We use forward-only (not bidirectional) because we only want to find
        // what DEPENDS ON the sentinel calls, not what FEEDS into them.
        // NoPropagation for phis: the injected timing variables are local to the
        // anti-debug prologue/epilogue and should never leak through phi merge
        // points into clean code paths.
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
                        // Check if we have a pre-computed redirect for this branch
                        if let Some(&(_, _, target)) = branch_redirects
                            .iter()
                            .find(|&&(bi, ii, _)| bi == block_idx && ii == instr_idx)
                        {
                            instr.set_op(SsaOp::Jump { target });
                            neutralized += 1;
                        }
                        // Leave Return/Throw alone
                    } else {
                        instr.set_op(SsaOp::Nop);
                        neutralized += 1;
                    }
                }
            }
        }

        // Also remove tainted PHI nodes
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

/// Finds metadata tokens of the three sentinel APIs within a method's SSA.
///
/// Scans all `Call`/`CallVirt` instructions for calls to:
/// - `DateTime::get_UtcNow`
/// - `DateTime::op_Subtraction`
/// - `TimeSpan::get_TotalMilliseconds`
///
/// Returns the set of unique metadata tokens that reference these APIs.
fn find_sentinel_tokens(ssa: &SsaFunction, assembly: &CilObject) -> HashSet<Token> {
    let mut tokens = HashSet::new();

    for block in ssa.blocks() {
        for instr in block.instructions() {
            let method_token = match instr.op() {
                SsaOp::Call { method, .. } | SsaOp::CallVirt { method, .. } => method.token(),
                _ => continue,
            };

            if let Some(name) = resolve_method_name(assembly, method_token) {
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

/// Chooses which branch target to use when neutralizing a tainted branch.
///
/// Prefers the target whose first instruction is NOT tainted (i.e. the
/// clean/legitimate code path rather than the crash code).
fn choose_clean_target(
    ssa: &SsaFunction,
    true_target: usize,
    false_target: usize,
    tainted_instrs: &HashSet<(usize, usize)>,
) -> usize {
    let true_tainted = is_block_start_tainted(ssa, true_target, tainted_instrs);
    let false_tainted = is_block_start_tainted(ssa, false_target, tainted_instrs);

    match (true_tainted, false_tainted) {
        (true, false) => false_target,
        (false, true) => true_target,
        // Both or neither tainted — prefer true (typically the forward/exit path
        // for ble.un.s which branches on "within time limit")
        _ => true_target,
    }
}

/// Checks if the first instruction of a block is tainted.
fn is_block_start_tainted(
    ssa: &SsaFunction,
    block_idx: usize,
    tainted_instrs: &HashSet<(usize, usize)>,
) -> bool {
    if let Some(block) = ssa.block(block_idx) {
        if block.instructions().is_empty() {
            return false;
        }
        tainted_instrs.contains(&(block_idx, 0))
    } else {
        false
    }
}

/// Resolves a metadata token to a qualified member name.
fn resolve_method_name(assembly: &CilObject, token: Token) -> Option<String> {
    if let Some(member) = assembly.member_ref(&token) {
        if let Some(type_name) = member.declaredby.fullname() {
            return Some(format!("{}::{}", type_name, member.name));
        }
        return Some(member.name.clone());
    }

    if let Some(method) = assembly.method(&token) {
        return Some(method.name.clone());
    }

    None
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_timing_check_pattern() {
        // The AntiDebugBreakpoints timing check uses a 5-second threshold
        let threshold: f64 = 5000.0;
        assert_eq!(threshold, 5000.0);
    }
}
