//! Block merging pass for eliminating trampoline blocks.
//!
//! This pass identifies and eliminates "trampoline" blocks - blocks that contain
//! only a single unconditional jump instruction. By redirecting predecessors to
//! jump directly to the target, we simplify the control flow graph.
//!
//! # Example
//!
//! Before:
//! ```text
//! B0: jump B1
//! B1: jump B4
//! B4: ... actual code ...
//! ```
//!
//! After:
//! ```text
//! B0: jump B4
//! B4: ... actual code ...
//! ```
//!
//! # Algorithm
//!
//! 1. Identify trampoline blocks (no phi nodes, single jump instruction)
//! 2. For each trampoline, find its ultimate target (following jump chains)
//! 3. Update all predecessor blocks to jump directly to the target
//! 4. Clear the trampoline block (it becomes unreachable)
//!
//! The pass runs iteratively until no more trampolines are found.

use std::{collections::HashMap, sync::Arc};

use crate::{
    analysis::SsaFunction,
    compiler::{pass::SsaPass, passes::utils::resolve_chain, CompilerContext, EventKind, EventLog},
    metadata::token::Token,
    CilObject, Result,
};

/// Maximum iterations to prevent infinite loops.
const MAX_ITERATIONS: usize = 50;

/// Block merging pass for eliminating trampoline blocks.
///
/// A trampoline block is a block that:
/// - Has no phi nodes
/// - Contains only a single unconditional jump instruction
///
/// This pass redirects all edges that go through trampolines directly to their
/// ultimate targets, simplifying the control flow graph.
pub struct BlockMergingPass;

impl Default for BlockMergingPass {
    fn default() -> Self {
        Self::new()
    }
}

impl BlockMergingPass {
    /// Creates a new block merging pass.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Redirects all jumps that go to trampolines to their ultimate targets.
    ///
    /// # Arguments
    ///
    /// * `ssa` - The SSA function to modify.
    /// * `trampolines` - Map of trampoline blocks to their direct targets.
    /// * `method_token` - Token for change tracking.
    /// * `changes` - Event log for recording changes.
    ///
    /// # Returns
    ///
    /// The number of redirections performed.
    fn redirect_to_ultimate_targets(
        ssa: &mut SsaFunction,
        trampolines: &HashMap<usize, usize>,
        method_token: Token,
        changes: &mut EventLog,
    ) -> usize {
        if trampolines.is_empty() {
            return 0;
        }

        // Precompute ultimate targets for all trampolines using shared utility
        let ultimate_targets: HashMap<usize, usize> = trampolines
            .keys()
            .map(|&t| (t, resolve_chain(trampolines, t)))
            .collect();

        let mut redirected = 0;

        // Update all branch targets in all blocks
        for block_idx in 0..ssa.block_count() {
            if let Some(block) = ssa.block_mut(block_idx) {
                for instr in block.instructions_mut() {
                    let op = instr.op_mut();
                    let old_targets = op.successors();

                    // Redirect each trampoline to its ultimate target
                    let mut changed = false;
                    for (&trampoline, &ultimate) in &ultimate_targets {
                        if op.redirect_target(trampoline, ultimate) {
                            changed = true;
                        }
                    }

                    if changed {
                        let new_targets = op.successors();
                        changes
                            .record(EventKind::BranchSimplified)
                            .at(method_token, block_idx)
                            .message(format!(
                                "redirected through trampoline: {:?} -> {:?}",
                                old_targets, new_targets
                            ));
                        redirected += 1;
                    }
                }
            }
        }

        redirected
    }

    /// Clears trampoline blocks that are no longer referenced.
    ///
    /// After redirecting all edges away from trampolines, they become unreachable
    /// and can be cleared. This is done by the DCE pass, but we record the event.
    ///
    /// # Arguments
    ///
    /// * `ssa` - The SSA function to modify.
    /// * `trampolines` - The trampoline blocks to clear.
    /// * `method_token` - Token for change tracking.
    /// * `changes` - Event log for recording changes.
    ///
    /// # Returns
    ///
    /// The number of blocks cleared.
    fn clear_trampolines(
        ssa: &mut SsaFunction,
        trampolines: &HashMap<usize, usize>,
        method_token: Token,
        changes: &mut EventLog,
    ) -> usize {
        let mut cleared = 0;

        for &block_idx in trampolines.keys() {
            if let Some(block) = ssa.block_mut(block_idx) {
                if !block.instructions().is_empty() {
                    block.instructions_mut().clear();
                    changes
                        .record(EventKind::BlockRemoved)
                        .at(method_token, block_idx)
                        .message(format!("cleared trampoline block B{block_idx}"));
                    cleared += 1;
                }
            }
        }

        cleared
    }

    /// Runs a single iteration of block merging.
    ///
    /// # Returns
    ///
    /// The number of changes made (redirections + cleared blocks).
    fn run_iteration(ssa: &mut SsaFunction, method_token: Token, changes: &mut EventLog) -> usize {
        let trampolines = ssa.find_trampoline_blocks(true);

        if trampolines.is_empty() {
            return 0;
        }

        let redirected =
            Self::redirect_to_ultimate_targets(ssa, &trampolines, method_token, changes);
        let cleared = Self::clear_trampolines(ssa, &trampolines, method_token, changes);

        redirected + cleared
    }
}

impl SsaPass for BlockMergingPass {
    fn name(&self) -> &'static str {
        "block-merging"
    }

    fn description(&self) -> &'static str {
        "Eliminates trampoline blocks (single-jump blocks)"
    }

    fn run_on_method(
        &self,
        ssa: &mut SsaFunction,
        method_token: Token,
        ctx: &CompilerContext,
        _assembly: &Arc<CilObject>,
    ) -> Result<bool> {
        let mut changes = EventLog::new();

        // Iterate until fixed point
        for _ in 0..MAX_ITERATIONS {
            let iteration_changes = Self::run_iteration(ssa, method_token, &mut changes);

            if iteration_changes == 0 {
                break;
            }
        }

        let changed = !changes.is_empty();
        if changed {
            ctx.events.merge(changes);
        }
        Ok(changed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        analysis::{SsaFunctionBuilder, SsaOp},
        test::helpers::test_assembly_arc,
    };

    #[test]
    fn test_redirect_simple() {
        let mut ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
            // B0: entry, jump to B1 (trampoline)
            f.block(0, |b| b.jump(1));
            // B1: trampoline to B2
            f.block(1, |b| b.jump(2));
            // B2: actual code
            f.block(2, |b| b.ret());
        });

        let pass = BlockMergingPass::new();
        let ctx = crate::compiler::CompilerContext::new(std::sync::Arc::new(
            crate::analysis::CallGraph::new(),
        ));
        let assembly = test_assembly_arc();

        let changed = pass
            .run_on_method(&mut ssa, Token::new(0x06000001), &ctx, &assembly)
            .unwrap();
        assert!(changed);

        // B0 should now jump directly to B2
        if let Some(block) = ssa.block(0) {
            if let Some(instr) = block.instructions().first() {
                if let SsaOp::Jump { target } = instr.op() {
                    assert_eq!(*target, 2);
                }
            }
        }

        // B1 should be cleared (empty)
        if let Some(block) = ssa.block(1) {
            assert!(
                block.instructions().is_empty(),
                "B1 should be cleared, but has {} instructions",
                block.instructions().len()
            );
        }
    }

    #[test]
    fn test_chain_of_trampolines() {
        // B0 -> B1 -> B2 -> B3 (actual code)
        let mut ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
            f.block(0, |b| b.jump(1));
            f.block(1, |b| b.jump(2));
            f.block(2, |b| b.jump(3));
            f.block(3, |b| b.ret());
        });

        let pass = BlockMergingPass::new();
        let ctx = crate::compiler::CompilerContext::new(std::sync::Arc::new(
            crate::analysis::CallGraph::new(),
        ));
        let assembly = test_assembly_arc();

        let changed = pass
            .run_on_method(&mut ssa, Token::new(0x06000001), &ctx, &assembly)
            .unwrap();
        assert!(changed);

        // B0 should jump directly to B3 (following the chain)
        if let Some(block) = ssa.block(0) {
            if let Some(instr) = block.instructions().first() {
                if let SsaOp::Jump { target } = instr.op() {
                    assert_eq!(*target, 3, "B0 should jump to B3, not B{}", *target);
                }
            }
        }

        // B1 and B2 should be cleared
        for i in 1..=2 {
            if let Some(block) = ssa.block(i) {
                assert!(block.instructions().is_empty(), "B{} should be cleared", i);
            }
        }
    }
}
