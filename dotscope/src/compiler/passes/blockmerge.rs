//! Block merging pass for simplifying control flow.
//!
//! Two optimizations:
//!
//! 1. **Trampoline elimination** — removes blocks containing only an unconditional
//!    jump by redirecting predecessors to the ultimate target.
//!
//! 2. **Block coalescing** — merges a block into its sole predecessor when the
//!    predecessor's only successor is that block. This eliminates unnecessary
//!    block boundaries in straight-line code (common after CFF reconstruction).
//!    Phi nodes in the successor are converted to Copy instructions since they
//!    have exactly one incoming edge.
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
//! # Trampoline Elimination Example
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
//! # Block Coalescing Example
//!
//! Before (after CFF reconstruction):
//! ```text
//! B5: v1 = call Foo()
//!     jump B6
//! B6: callvirt Bar(v1)
//!     jump B7
//! ```
//!
//! After:
//! ```text
//! B5: v1 = call Foo()
//!     callvirt Bar(v1)
//!     jump B7
//! ```

use std::collections::{HashMap, HashSet};

use crate::{
    analysis::{PhiOperand, SsaFunction, SsaInstruction, SsaOp},
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

    /// Merges blocks connected by a single edge.
    ///
    /// When Block A's only successor is Block B (via `Jump`) and Block B's only
    /// predecessor is Block A, the two blocks can be merged: Block A's terminator
    /// is replaced by Block B's instructions. Any phi nodes in Block B are
    /// converted to Copy instructions (they have exactly one incoming edge).
    ///
    /// Blocks involved in exception handler boundaries are excluded because
    /// merging them would break the handler region structure.
    fn coalesce_blocks(
        ssa: &mut SsaFunction,
        method_token: Token,
        changes: &mut EventLog,
    ) -> usize {
        let mut merged = 0;

        // Collect exception handler boundary blocks.
        //
        // Region *start* blocks (try_start, handler_start, filter_start) must not
        // be used as the MERGE TARGET because absorbing a predecessor outside the
        // region would pull non-region code into the region.
        //
        // Region *end* blocks (try_end, handler_end) must not be used as the MERGE
        // SOURCE because absorbing a successor outside the region would extend the
        // region past its intended boundary.
        //
        // Merging within a region is safe: if A is a try_start and B is the next
        // block inside the same try body, merging B into A keeps the try region
        // starting at A.
        let mut no_merge_into: HashSet<usize> = HashSet::new();
        let mut no_merge_from: HashSet<usize> = HashSet::new();
        for handler in ssa.exception_handlers() {
            if let Some(b) = handler.try_start_block {
                no_merge_into.insert(b);
            }
            if let Some(b) = handler.try_end_block {
                no_merge_from.insert(b);
            }
            if let Some(b) = handler.handler_start_block {
                no_merge_into.insert(b);
            }
            if let Some(b) = handler.handler_end_block {
                no_merge_from.insert(b);
            }
            if let Some(b) = handler.filter_start_block {
                no_merge_into.insert(b);
            }
        }

        // Iterate until fixed point.
        for _ in 0..MAX_ITERATIONS {
            let mut iteration_merges = 0;

            // Build predecessor counts for all blocks.
            let block_count = ssa.block_count();
            let mut pred_counts: Vec<usize> = vec![0; block_count];
            let mut pred_of: Vec<Option<usize>> = vec![None; block_count];
            for idx in 0..block_count {
                let successors = ssa
                    .block(idx)
                    .and_then(|b| b.terminator_op())
                    .map(SsaOp::successors)
                    .unwrap_or_default();
                for succ in successors {
                    if succ < block_count {
                        pred_counts[succ] += 1;
                        pred_of[succ] = Some(idx);
                    }
                }
            }
            // Entry block has an implicit edge.
            pred_counts[0] += 1;

            // Find mergeable pairs: A -> B where A's terminator is Jump(B),
            // B has exactly 1 predecessor, and neither is a handler boundary.
            let mut pairs: Vec<(usize, usize)> = Vec::new();
            let mut consumed: HashSet<usize> = HashSet::new();
            for a_idx in 0..block_count {
                if consumed.contains(&a_idx) {
                    continue;
                }
                let b_idx = match ssa.block(a_idx).and_then(|b| b.terminator_op()) {
                    Some(SsaOp::Jump { target }) => *target,
                    _ => continue,
                };
                if b_idx >= block_count || b_idx == a_idx {
                    continue;
                }
                if pred_counts[b_idx] != 1 {
                    continue;
                }
                if no_merge_from.contains(&a_idx) || no_merge_into.contains(&b_idx) {
                    continue;
                }
                // B must have instructions (not already cleared).
                let b_empty = ssa.block(b_idx).is_none_or(|b| b.instructions().is_empty());
                if b_empty {
                    continue;
                }
                pairs.push((a_idx, b_idx));
                consumed.insert(a_idx);
                consumed.insert(b_idx);
            }

            for (a_idx, b_idx) in pairs {
                // Convert B's phi nodes to Copy instructions.
                let phi_copies: Vec<SsaInstruction> = ssa
                    .block(b_idx)
                    .map(|b| {
                        b.phi_nodes()
                            .iter()
                            .filter_map(|phi| {
                                // Single predecessor → exactly one operand.
                                let operand = phi.operands().first()?;
                                let dest = phi.result();
                                let src = operand.value();
                                if dest == src {
                                    return None; // Self-copy, skip.
                                }
                                Some(SsaInstruction::synthetic(SsaOp::Copy { dest, src }))
                            })
                            .collect()
                    })
                    .unwrap_or_default();

                // Take B's instructions.
                let b_instrs: Vec<SsaInstruction> = ssa
                    .block(b_idx)
                    .map(|b| b.instructions().to_vec())
                    .unwrap_or_default();

                // Remove A's terminator (the Jump) and append phi copies + B's instructions.
                if let Some(a_block) = ssa.block_mut(a_idx) {
                    // Pop the Jump terminator.
                    let instrs = a_block.instructions_mut();
                    if instrs
                        .last()
                        .is_some_and(|i| matches!(i.op(), SsaOp::Jump { .. }))
                    {
                        instrs.pop();
                    }
                    // Append phi copies then B's instructions.
                    instrs.extend(phi_copies);
                    instrs.extend(b_instrs);
                }

                // Update B's internal self-references to point to A.
                if let Some(a_block) = ssa.block_mut(a_idx) {
                    for instr in a_block.instructions_mut() {
                        instr.op_mut().redirect_target(b_idx, a_idx);
                    }
                }

                // Clear B.
                if let Some(b_block) = ssa.block_mut(b_idx) {
                    b_block.phi_nodes_mut().clear();
                    b_block.instructions_mut().clear();
                }

                // Redirect any other block that referenced B to now reference A.
                // This handles the case where B had successors that now become A's
                // successors — their phi operands need predecessor updates.
                for phi_block_idx in 0..block_count {
                    if phi_block_idx == a_idx || phi_block_idx == b_idx {
                        continue;
                    }
                    if let Some(block) = ssa.block_mut(phi_block_idx) {
                        for phi in block.phi_nodes_mut() {
                            for operand in phi.operands_mut() {
                                if operand.predecessor() == b_idx {
                                    *operand = PhiOperand::new(operand.value(), a_idx);
                                }
                            }
                        }
                    }
                }

                changes
                    .record(EventKind::BlockRemoved)
                    .at(method_token, b_idx)
                    .message(format!("coalesced B{b_idx} into B{a_idx}"));

                iteration_merges += 1;
            }

            merged += iteration_merges;
            if iteration_merges == 0 {
                break;
            }
        }

        merged
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
        let target_has_phis = ssa.block(target).is_none_or(|b| !b.phi_nodes().is_empty());

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
        "Eliminates trampoline blocks and coalesces single-edge block pairs"
    }

    fn run_on_method(
        &self,
        ssa: &mut SsaFunction,
        method_token: Token,
        ctx: &CompilerContext,
        _assembly: &CilObject,
    ) -> Result<bool> {
        let mut changes = EventLog::new();

        // Phase 1: Eliminate trampoline blocks (jump-only blocks).
        for _ in 0..MAX_ITERATIONS {
            let iteration_changes = Self::run_iteration(ssa, method_token, &mut changes);

            if iteration_changes == 0 {
                break;
            }
        }

        // Phase 2: Handle entry block trampoline — B0 has no predecessors so the
        // redirect-and-clear approach above can't handle it. Instead, inline
        // the target block when safe, or just mark for regeneration.
        Self::simplify_entry_trampoline(ssa, method_token, &mut changes);

        // Phase 3: Coalesce non-trivial blocks connected by a single edge.
        // After trampoline elimination and CFF reconstruction, there may be
        // blocks with actual instructions connected by unconditional jumps
        // where the successor has a single predecessor. Merging these produces
        // larger blocks, reducing cross-block stores in the codegen.
        Self::coalesce_blocks(ssa, method_token, &mut changes);

        let changed = !changes.is_empty();
        if changed {
            ctx.events.merge(&changes);
        }
        Ok(changed)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::{
        analysis::{CallGraph, SsaFunctionBuilder, SsaOp},
        compiler::{passes::blockmerge::BlockMergingPass, CompilerContext, SsaPass},
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

    #[test]
    fn test_coalesce_single_edge_blocks() {
        // B0: const + jump B1, B1: const + jump B2, B2: ret.
        // B0→B1 and B1→B2 are single-edge pairs that should be coalesced.
        let mut ssa = SsaFunctionBuilder::new(0, 0)
            .build_with(|f| {
                f.block(0, |b| {
                    let _ = b.const_i32(42);
                    b.jump(1);
                });
                f.block(1, |b| {
                    let _ = b.const_i32(99);
                    b.jump(2);
                });
                f.block(2, |b| b.ret());
            })
            .unwrap();

        let pass = BlockMergingPass::new();
        let ctx = CompilerContext::new(Arc::new(CallGraph::new()));
        let assembly = test_assembly_arc();

        let changed = pass
            .run_on_method(&mut ssa, Token::new(0x06000001), &ctx, &assembly)
            .unwrap();
        assert!(changed, "block coalescing should trigger changes");

        // B0 should now contain all instructions: two consts + ret
        let block0 = ssa.block(0).unwrap();
        assert!(
            block0.instruction_count() >= 3,
            "B0 should have at least 3 instructions after coalescing, got {}",
            block0.instruction_count()
        );
        assert!(
            matches!(
                block0.instructions().last().map(|i| i.op()),
                Some(SsaOp::Return { .. })
            ),
            "B0's last instruction should be ret"
        );

        // B1 and B2 should be cleared
        for i in 1..=2 {
            if let Some(block) = ssa.block(i) {
                assert!(
                    block.instructions().is_empty(),
                    "B{i} should be cleared after coalescing"
                );
            }
        }
    }

    #[test]
    fn test_coalesce_preserves_multi_predecessor_blocks() {
        // B0: branch(cond, B1, B2), B1: jump B3, B2: jump B3, B3: ret.
        // B3 has two predecessors — should NOT be coalesced.
        let mut ssa = SsaFunctionBuilder::new(0, 0)
            .build_with(|f| {
                f.block(0, |b| {
                    let c = b.const_i32(1);
                    b.branch(c, 1, 2);
                });
                f.block(1, |b| {
                    let _ = b.const_i32(10);
                    b.jump(3);
                });
                f.block(2, |b| {
                    let _ = b.const_i32(20);
                    b.jump(3);
                });
                f.block(3, |b| b.ret());
            })
            .unwrap();

        let pass = BlockMergingPass::new();
        let ctx = CompilerContext::new(Arc::new(CallGraph::new()));
        let assembly = test_assembly_arc();

        pass.run_on_method(&mut ssa, Token::new(0x06000001), &ctx, &assembly)
            .unwrap();

        // B3 should still exist with instructions (not merged)
        let block3 = ssa.block(3).unwrap();
        assert!(
            !block3.instructions().is_empty(),
            "B3 should NOT be coalesced (has 2 predecessors)"
        );
    }
}
