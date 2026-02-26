//! Block merging pass for eliminating trampoline blocks.
//!
//! This pass identifies and eliminates "trampoline" blocks - blocks that contain
//! only a single unconditional jump instruction. By redirecting predecessors to
//! jump directly to the target, we simplify the control flow graph.
//!
//! # Entry Block Handling
//!
//! The entry block (B0) is handled specially because it has no predecessors to
//! redirect. When B0 is a trampoline, the target block is inlined into B0
//! (if safe) or the method is marked for code regeneration. This generically
//! handles anti-disassembly patterns where obfuscators inject junk bytes after
//! an unconditional branch at method start (e.g., `br.s +N` followed by garbage).
//! The SSA builder never decodes the unreachable junk, so regenerating the IL
//! from SSA produces clean output.
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
//! 5. If the entry block is a trampoline, inline target or mark for regeneration
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
                                "redirected through trampoline: {old_targets:?} -> {new_targets:?}"
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

    /// Simplifies an entry block that is just a trampoline (unconditional jump).
    ///
    /// Non-entry trampolines are handled by `run_iteration` which redirects
    /// predecessors and clears the block. The entry block (B0) has no
    /// predecessors, so that approach doesn't work — there's nothing to
    /// redirect.
    ///
    /// Instead, when B0 is a trampoline to B_target:
    ///
    /// - If B_target has exactly one predecessor (B0) and no phi nodes, we
    ///   inline B_target's instructions into B0 and clear B_target.
    /// - Otherwise, we just mark the method as modified so codegen regenerates
    ///   clean IL without the original junk bytes (e.g., anti-disassembly
    ///   garbage injected by obfuscators like BitMono's junk prefix).
    fn simplify_entry_trampoline(
        ssa: &mut SsaFunction,
        method_token: Token,
        changes: &mut EventLog,
    ) {
        // Check if B0 is a trampoline
        let target = match ssa.block(0).and_then(|b| b.is_trampoline()) {
            Some(t) => t,
            None => return,
        };

        let preds = ssa.block_predecessors(target);
        let target_has_phis = ssa
            .block(target)
            .map_or(true, |b| !b.phi_nodes().is_empty());

        if preds.len() == 1 && preds[0] == 0 && !target_has_phis {
            // Safe to inline: B_target's only external predecessor is B0 and it
            // has no phis. Move B_target's instructions into B0.
            let target_instrs = ssa
                .block(target)
                .map(|b| b.instructions().to_vec())
                .unwrap_or_default();

            if let Some(entry) = ssa.block_mut(0) {
                entry.instructions_mut().clear();
                *entry.instructions_mut() = target_instrs;

                // Redirect any self-references: if B_target had a back-edge to
                // itself (e.g., a loop), those now need to point to B0 since
                // B_target's content lives in B0.
                for instr in entry.instructions_mut() {
                    instr.op_mut().redirect_target(target, 0);
                }
            }

            if let Some(target_block) = ssa.block_mut(target) {
                target_block.instructions_mut().clear();
            }

            changes
                .record(EventKind::BlockRemoved)
                .at(method_token, 0)
                .message(format!(
                    "inlined entry trampoline: B0 jump to B{target} merged into B0"
                ));
        } else {
            // Can't inline (multiple predecessors or phis), but mark as modified
            // so codegen regenerates clean IL without original junk bytes.
            changes
                .record(EventKind::BranchSimplified)
                .at(method_token, 0)
                .message(format!(
                    "entry block is trampoline to B{target} (regenerating clean IL)"
                ));
        }
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

        // Iterate until fixed point (non-entry trampolines)
        for _ in 0..MAX_ITERATIONS {
            let iteration_changes = Self::run_iteration(ssa, method_token, &mut changes);

            if iteration_changes == 0 {
                break;
            }
        }

        // Handle entry block trampoline — B0 has no predecessors so the
        // redirect-and-clear approach above can't handle it. Instead, inline
        // the target block when safe, or just mark for regeneration.
        Self::simplify_entry_trampoline(ssa, method_token, &mut changes);

        let changed = !changes.is_empty();
        if changed {
            ctx.events.merge(&changes);
        }
        Ok(changed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;

    use crate::{
        analysis::{CallGraph, SsaFunctionBuilder, SsaOp},
        compiler::{CompilerContext, SsaPass},
        metadata::token::Token,
        test::helpers::test_assembly_arc,
    };

    #[test]
    fn test_redirect_simple() {
        let mut ssa = SsaFunctionBuilder::new(0, 0)
            .build_with(|f| {
                // B0: entry, jump to B1 (trampoline)
                f.block(0, |b| b.jump(1));
                // B1: trampoline to B2
                f.block(1, |b| b.jump(2));
                // B2: actual code
                f.block(2, |b| b.ret());
            })
            .unwrap();

        let pass = BlockMergingPass::new();
        let ctx = CompilerContext::new(Arc::new(CallGraph::new()));
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
        let mut ssa = SsaFunctionBuilder::new(0, 0)
            .build_with(|f| {
                f.block(0, |b| b.jump(1));
                f.block(1, |b| b.jump(2));
                f.block(2, |b| b.jump(3));
                f.block(3, |b| b.ret());
            })
            .unwrap();

        let pass = BlockMergingPass::new();
        let ctx = CompilerContext::new(Arc::new(CallGraph::new()));
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

    #[test]
    fn test_entry_trampoline_inlined() {
        // B0 is a trampoline to B1, B1 has only B0 as predecessor.
        // B0's content should be replaced with B1's instructions.
        let mut ssa = SsaFunctionBuilder::new(0, 0)
            .build_with(|f| {
                f.block(0, |b| b.jump(1));
                f.block(1, |b| b.ret());
            })
            .unwrap();

        let pass = BlockMergingPass::new();
        let ctx = CompilerContext::new(Arc::new(CallGraph::new()));
        let assembly = test_assembly_arc();

        let changed = pass
            .run_on_method(&mut ssa, Token::new(0x06000001), &ctx, &assembly)
            .unwrap();
        assert!(changed, "entry trampoline should trigger a change");

        // B0 should now contain B1's ret instruction
        let block0 = ssa.block(0).unwrap();
        assert_eq!(block0.instruction_count(), 1);
        assert!(
            matches!(block0.instructions()[0].op(), SsaOp::Return { .. }),
            "B0 should contain ret after inlining, got {:?}",
            block0.instructions()[0].op()
        );

        // B1 should be cleared
        let block1 = ssa.block(1).unwrap();
        assert!(
            block1.instructions().is_empty(),
            "B1 should be cleared after inlining"
        );
    }

    #[test]
    fn test_entry_trampoline_with_loop() {
        // B0: jump B1, B1: branch(cond, B2, B3), B2: jump B1 (loop), B3: ret.
        // The non-entry pass redirects B1's branch from B2 to B1 (self-loop),
        // then the entry trampoline logic inlines B1 into B0.
        // The self-reference to B1 should be redirected to B0.
        let mut ssa = SsaFunctionBuilder::new(0, 0)
            .build_with(|f| {
                f.block(0, |b| b.jump(1));
                f.block(1, |b| {
                    let cond = b.const_i32(1);
                    b.branch(cond, 2, 3);
                });
                f.block(2, |b| b.jump(1)); // back-edge to B1
                f.block(3, |b| b.ret());
            })
            .unwrap();

        let pass = BlockMergingPass::new();
        let ctx = CompilerContext::new(Arc::new(CallGraph::new()));
        let assembly = test_assembly_arc();

        let changed = pass
            .run_on_method(&mut ssa, Token::new(0x06000001), &ctx, &assembly)
            .unwrap();
        assert!(changed);

        // B0 should now contain B1's code (const + branch) with the
        // self-reference redirected from B1 to B0
        let block0 = ssa.block(0).unwrap();
        assert_eq!(
            block0.instruction_count(),
            2,
            "B0 should have const + branch"
        );
        if let SsaOp::Branch {
            true_target,
            false_target,
            ..
        } = block0.instructions()[1].op()
        {
            assert_eq!(*true_target, 0, "self-loop should point to B0 after inline");
            assert_eq!(*false_target, 3, "exit should still point to B3");
        } else {
            panic!("expected Branch in B0");
        }
    }

    #[test]
    fn test_entry_trampoline_not_inlined_multi_pred() {
        // B0: jump B1, B1: code, B2: jump B1 (B1 has preds B0 AND B2).
        // Can't inline B1 into B0, but method should be marked as changed.
        let mut ssa = SsaFunctionBuilder::new(0, 0)
            .build_with(|f| {
                f.block(0, |b| b.jump(1));
                f.block(1, |b| {
                    let cond = b.const_i32(1);
                    b.branch(cond, 2, 3);
                });
                f.block(2, |b| {
                    // Not a trampoline — has nop + jump (2 instructions)
                    b.nop();
                    b.jump(1);
                });
                f.block(3, |b| b.ret());
            })
            .unwrap();

        let pass = BlockMergingPass::new();
        let ctx = CompilerContext::new(Arc::new(CallGraph::new()));
        let assembly = test_assembly_arc();

        let changed = pass
            .run_on_method(&mut ssa, Token::new(0x06000001), &ctx, &assembly)
            .unwrap();
        assert!(
            changed,
            "entry trampoline should mark as changed even when target can't be inlined"
        );

        // B0 should still be a jump (B1 has 2 predecessors: B0 and B2)
        let block0 = ssa.block(0).unwrap();
        assert_eq!(block0.instruction_count(), 1);
        assert!(
            matches!(block0.instructions()[0].op(), SsaOp::Jump { .. }),
            "B0 should remain a jump when target has multiple external predecessors"
        );
    }

    #[test]
    fn test_no_entry_trampoline() {
        // B0 has actual code — not a trampoline. Should report no changes.
        let mut ssa = SsaFunctionBuilder::new(0, 0)
            .build_with(|f| {
                f.block(0, |b| b.ret());
            })
            .unwrap();

        let pass = BlockMergingPass::new();
        let ctx = CompilerContext::new(Arc::new(CallGraph::new()));
        let assembly = test_assembly_arc();

        let changed = pass
            .run_on_method(&mut ssa, Token::new(0x06000001), &ctx, &assembly)
            .unwrap();
        assert!(!changed, "non-trampoline entry should report no changes");
    }
}
