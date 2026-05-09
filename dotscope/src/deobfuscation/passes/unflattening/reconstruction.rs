//! CFG reconstruction from trace trees.
//!
//! This module handles the reconstruction phase of control flow unflattening:
//! converting a trace tree (built by [`super::tracer`]) back into clean SSA.
//!
//! # Overview
//!
//! The reconstruction process involves:
//!
//! 1. **Patch Plan Extraction**: Analyze the trace tree to determine:
//!    - Which blocks should redirect to which targets (bypassing the dispatcher)
//!    - Which variables are state-tainted (CFF machinery to remove)
//!    - Which blocks need cloning (merge points with different targets)
//!
//! 2. **Patch Application**: Modify the SSA in place:
//!    - Redirect block terminators from dispatcher to actual targets
//!    - Clone merge blocks when multiple paths converge with different targets
//!    - Filter out state-tainted instructions
//!    - Clear the dispatcher block
//!
//! 3. **SSA Rebuild**: After patching, `SsaFunction::rebuild_ssa()` is called to
//!    reconstruct proper PHI nodes for the new CFG structure.
//!
//! # Algorithm
//!
//! The key insight is that the trace tree captures the *actual* execution flow
//! through the CFF state machine. Each `StateTransition` node represents a
//! state change that we want to eliminate by redirecting control flow directly.
//!
//! For example, if the tree shows:
//! ```text
//! Block 5 -> StateTransition(target=7) -> Block 7 -> ...
//! ```
//!
//! We patch block 5 to jump directly to block 7, bypassing the dispatcher.
//!
//! ## Merge Point Handling
//!
//! When multiple paths through the tree converge at the same block but with
//! different next targets, we need to clone the block:
//!
//! ```text
//! Path A: Block 5 -> merge_block -> target 7
//! Path B: Block 6 -> merge_block -> target 9
//! ```
//!
//! We keep `merge_block` for path A and clone it as `merge_block'` for path B.

use std::collections::{BTreeMap, BTreeSet};

use analyssa::BitSet;

use crate::{
    analysis::{SsaBlock, SsaFunction, SsaInstruction, SsaOp, SsaVarId},
    deobfuscation::passes::unflattening::tracer::{TraceNode, TraceTerminator, TraceTree},
};

type PhiOperands = Vec<(usize, SsaVarId)>;
type BlockPhiData = Vec<(usize, Vec<(SsaVarId, PhiOperands)>)>;

/// Result of unflattening a CFG.
#[derive(Debug)]
pub struct ReconstructionResult {
    /// Number of state transitions eliminated.
    pub state_transitions_removed: usize,
    /// Number of user branches preserved.
    pub user_branches_preserved: usize,
    /// Number of blocks in the function.
    pub block_count: usize,
    /// Whether the dispatcher block is still needed by unresolved blocks.
    ///
    /// When `true`, the unflattening was only partial — some blocks still
    /// route through the dispatcher because their dispatch values couldn't
    /// be resolved. The caller should skip applying the partial result to
    /// avoid corrupting SSA phi nodes at the dispatcher merge point.
    pub dispatcher_still_needed: bool,
}

/// A plan for patching the SSA to remove CFF.
#[derive(Debug)]
pub struct PatchPlan {
    /// Dispatcher block indices (one per CFF dispatcher in the method).
    pub dispatcher_blocks: Vec<usize>,

    /// Variables that are state-related (CFF machinery).
    pub state_tainted: BitSet,

    /// Block redirects: (source_block, new_target).
    /// These blocks currently jump to dispatcher but should jump to new_target.
    pub redirects: Vec<(usize, usize)>,

    /// Source blocks whose redirects originated from StateTransition nodes.
    /// Redirects from LoopBack nodes (which may be cross-contamination from
    /// exploring other dispatchers' switches as user switches) are NOT in
    /// this set. Used to filter out cross-contamination in multi-dispatcher
    /// methods.
    state_transition_sources: BTreeSet<usize>,

    /// Blocks that need cloning: merge_block -> [(predecessor, target), ...]
    /// These are blocks where multiple paths converge with different targets.
    /// We clone the merge block for each path.
    pub clone_requests: BTreeMap<usize, Vec<(usize, usize)>>,

    /// Blocks in execution order (for debugging/verification).
    pub execution_order: Vec<usize>,

    /// Branch-collapse requests: `source_block -> new_target`.
    ///
    /// When a state transition's path enters the dispatcher through a
    /// BranchCmp/Branch overflow check (e.g. NETReactor `bcmp state == Const`
    /// on the dispatcher's default fall-through chain), the traced arm is the
    /// only live path in the unflattened graph. Apply replaces the source's
    /// BranchCmp/Branch terminator with a `Jump { target: new_target }` so the
    /// dead arm is eliminated while the live arm's user-code blocks still
    /// execute sequentially before the separate redirect rewires the final
    /// jump-to-dispatcher block.
    pub(crate) branch_collapses: BTreeMap<usize, usize>,

    /// Number of state transitions removed.
    pub state_transitions_removed: usize,

    /// Number of user branches preserved.
    pub user_branches_preserved: usize,
}

impl PatchPlan {
    fn new(dispatcher_block: usize, state_tainted: BitSet) -> Self {
        Self {
            dispatcher_blocks: vec![dispatcher_block],
            state_tainted,
            redirects: Vec::new(),
            state_transition_sources: BTreeSet::new(),
            clone_requests: BTreeMap::new(),
            execution_order: Vec::new(),
            branch_collapses: BTreeMap::new(),
            state_transitions_removed: 0,
            user_branches_preserved: 0,
        }
    }

    fn add_branch_collapse(&mut self, source: usize, target: usize) {
        if source == target {
            return;
        }
        // First wins on conflict — multiple traces may visit the same overflow
        // check through different state-match arms. Keeping the first avoids
        // thrashing the terminator.
        self.branch_collapses.entry(source).or_insert(target);
    }

    /// Returns true if the given block is one of the dispatcher blocks.
    pub fn is_dispatcher_block(&self, block: usize) -> bool {
        self.dispatcher_blocks.contains(&block)
    }

    fn add_redirect(&mut self, source: usize, target: usize, predecessor: Option<usize>) {
        // Self-redirects are always wrong — they create infinite loops.
        // They occur when the evaluator can't resolve the next CFF state
        // (e.g., handler CFF where the second dispatch depends on values
        // the evaluator lost track of). Skip them silently.
        if source == target {
            return;
        }
        // Check for conflict: same source with different target
        if let Some(&(_, existing_target)) = self.redirects.iter().find(|&&(s, _)| s == source) {
            if existing_target != target {
                // Conflict! This source is a merge point needing cloning.
                // Add both the existing and new paths to clone requests.
                let entry = self.clone_requests.entry(source).or_default();

                // Ensure the original (first) redirect's path is present.
                // The first redirect may have been added without a predecessor
                // (e.g., from the root-level trace where external_predecessor
                // is None), so its entry wasn't recorded in clone_requests.
                // The first path keeps the original block during cloning (its
                // predecessor isn't used for redirect, only its target matters).
                if !entry.iter().any(|(_, t)| *t == existing_target) {
                    entry.push((usize::MAX, existing_target));
                }

                if let Some(pred) = predecessor {
                    // Deduplicate by (predecessor, target) pair — not just
                    // predecessor. A user branch's TRUE and FALSE paths can
                    // share the same predecessor (the branch block) but route
                    // the merge block to different CFF targets. Both entries
                    // are needed for correct cloning.
                    if !entry.iter().any(|(p, t)| *p == pred && *t == target) {
                        entry.push((pred, target));
                    }
                }
            }
            return; // Don't add duplicate redirect
        }

        // First time seeing this source - record it and track predecessor for potential cloning
        self.redirects.push((source, target));

        // Also record in clone_requests in case we need it later
        if let Some(pred) = predecessor {
            let entry = self.clone_requests.entry(source).or_default();
            entry.push((pred, target));
        }
    }

    /// Returns redirects that are safe to apply (no conflicts/cloning needed).
    pub(crate) fn safe_redirects(&self) -> Vec<(usize, usize)> {
        self.redirects
            .iter()
            .filter(|(source, _)| {
                // Safe if this block only has one target (not a merge point)
                self.clone_requests.get(source).is_none_or(|v| v.len() <= 1)
            })
            .copied()
            .collect()
    }

    /// Returns blocks that need cloning with their (predecessor, target) pairs.
    pub(crate) fn blocks_to_clone(&self) -> Vec<(usize, Vec<(usize, usize)>)> {
        self.clone_requests
            .iter()
            .filter(|(_, paths)| paths.len() > 1) // Only clone if multiple paths
            .map(|(&block, paths)| (block, paths.clone()))
            .collect()
    }

    fn add_to_execution_order(&mut self, block: usize) {
        if !self.execution_order.contains(&block) && !self.is_dispatcher_block(block) {
            self.execution_order.push(block);
        }
    }
}

/// Extracts a patch plan from a trace tree.
///
/// This analyzes the trace tree to determine:
/// - Which blocks should redirect to which targets (skip dispatcher)
/// - Which variables are state-tainted (for later instruction filtering)
/// - Which blocks need cloning (merge points with different targets)
///
/// # Arguments
///
/// * `tree` - The trace tree built by [`trace_method_tree`]
///
/// # Returns
///
/// `Some(PatchPlan)` if the tree contains a dispatcher and can be patched,
/// `None` if no dispatcher was detected.
///
/// [`trace_method_tree`]: super::tracer::trace_method_tree
pub fn extract_patch_plan(tree: &TraceTree, ssa: &SsaFunction) -> Option<PatchPlan> {
    let dispatcher = tree.dispatcher.as_ref()?;

    let mut plan = PatchPlan::new(dispatcher.block, tree.state_tainted.clone());

    // Walk the main trace tree and extract redirects
    // Start with no external predecessor since we're at the root
    extract_redirects_from_node(&tree.root, dispatcher.block, &mut plan, None, ssa);

    // Walk exception handler traces and merge their redirects into the same plan.
    // Handler blocks may contain their own CFF dispatchers that need unflattening.
    for handler_trace in &tree.handler_traces {
        extract_redirects_from_node(&handler_trace.root, dispatcher.block, &mut plan, None, ssa);
    }

    // Filter out cross-contamination redirects. When tracing for one dispatcher,
    // the tracer explores OTHER dispatchers' switches as user switches. LoopBack
    // terminators at those foreign switches generate spurious redirects for blocks
    // that don't belong to this dispatcher's CFF region. Only keep redirects that
    // originated from StateTransition nodes (the actual CFF state machine redirects).
    plan.redirects
        .retain(|&(source, _)| plan.state_transition_sources.contains(&source));
    plan.clone_requests
        .retain(|source, _| plan.state_transition_sources.contains(source));

    Some(plan)
}

/// Merges multiple patch plans into a single combined plan.
///
/// This is used when a method contains multiple independent CFF dispatchers
/// (e.g., one per exception handler region in ConfuserEx). Each dispatcher
/// is traced independently, producing its own patch plan. This function
/// combines them so all patches are applied in a single pass before
/// `rebuild_ssa()`, avoiding the block renumbering corruption that occurs
/// when dispatchers are processed iteratively.
///
/// # Arguments
///
/// * `plans` - Individual patch plans, one per dispatcher.
///
/// # Returns
///
/// A single `PatchPlan` with all dispatcher blocks, redirects, taint sets,
/// and clone requests merged.
pub fn merge_patch_plans(plans: Vec<PatchPlan>) -> PatchPlan {
    if plans.is_empty() {
        return PatchPlan {
            dispatcher_blocks: Vec::new(),
            state_tainted: BitSet::new(0),
            redirects: Vec::new(),
            state_transition_sources: BTreeSet::new(),
            clone_requests: BTreeMap::new(),
            execution_order: Vec::new(),
            branch_collapses: BTreeMap::new(),
            state_transitions_removed: 0,
            user_branches_preserved: 0,
        };
    }

    if plans.len() == 1 {
        if let Some(only) = plans.into_iter().next() {
            return only;
        }
        // Unreachable: we just checked len() == 1, but handle defensively.
        return PatchPlan {
            dispatcher_blocks: Vec::new(),
            state_tainted: BitSet::new(0),
            redirects: Vec::new(),
            state_transition_sources: BTreeSet::new(),
            clone_requests: BTreeMap::new(),
            execution_order: Vec::new(),
            branch_collapses: BTreeMap::new(),
            state_transitions_removed: 0,
            user_branches_preserved: 0,
        };
    }

    // Determine the tainted BitSet size (all plans share the same SSA, so same size)
    let taint_size = plans
        .iter()
        .map(|p| p.state_tainted.len())
        .max()
        .unwrap_or(0);
    let mut merged = PatchPlan {
        dispatcher_blocks: Vec::new(),
        state_tainted: BitSet::new(taint_size),
        redirects: Vec::new(),
        state_transition_sources: BTreeSet::new(),
        clone_requests: BTreeMap::new(),
        execution_order: Vec::new(),
        branch_collapses: BTreeMap::new(),
        state_transitions_removed: 0,
        user_branches_preserved: 0,
    };

    for plan in plans {
        merged.dispatcher_blocks.extend(&plan.dispatcher_blocks);
        merged.state_tainted.union_with(&plan.state_tainted);
        merged
            .state_transition_sources
            .extend(&plan.state_transition_sources);

        // Merge redirects, checking for conflicts
        for (source, target) in plan.redirects {
            if let Some(&(_, existing_target)) =
                merged.redirects.iter().find(|&&(s, _)| s == source)
            {
                if existing_target != target {
                    log::warn!(
                        "CFF merge: redirect conflict for block {} (target {} vs {}), keeping first",
                        source,
                        existing_target,
                        target
                    );
                    continue;
                }
                // Duplicate (same source, same target) — skip
                continue;
            }
            merged.redirects.push((source, target));
        }

        // Merge clone requests
        for (block, paths) in plan.clone_requests {
            merged
                .clone_requests
                .entry(block)
                .or_default()
                .extend(paths);
        }

        // Merge execution order (deduplicated)
        for block in plan.execution_order {
            if !merged.execution_order.contains(&block) {
                merged.execution_order.push(block);
            }
        }

        // Merge branch collapses (first wins on conflict)
        for (source, target) in plan.branch_collapses {
            merged.branch_collapses.entry(source).or_insert(target);
        }

        merged.state_transitions_removed = merged
            .state_transitions_removed
            .saturating_add(plan.state_transitions_removed);
        merged.user_branches_preserved = merged
            .user_branches_preserved
            .saturating_add(plan.user_branches_preserved);
    }

    merged
}

/// Returns true if an SSA op is safe to consider "pure CFG plumbing" — only
/// data motion (Const/Copy/Phi) or a Jump terminator. Used to identify
/// dispatcher prep-chain blocks that can be bypassed when redirecting case
/// blocks.
fn is_pure_prep_op(op: &SsaOp) -> bool {
    matches!(
        op,
        SsaOp::Const { .. } | SsaOp::Copy { .. } | SsaOp::Jump { .. } | SsaOp::Nop
    )
}

/// Returns true if `block_idx` is a state-overflow chain block — a block whose
/// terminator is a `BranchCmp` comparing the state variable against a constant
/// (NETReactor's `bcmp state == K, case_K, next_check` pattern on the
/// dispatcher's default arm), and whose non-terminator body is only pure
/// plumbing.
///
/// Redirecting a case block directly to such a chain block lands the rewritten
/// edge on machinery that will compare a now-undefined state operand and fall
/// through into another case, creating self-loops after state-tainted
/// filtering. The caller should advance the effective redirect target through
/// consecutive chain blocks in the trace's `continues` visit list.
fn is_state_chain_block(ssa: &SsaFunction, block_idx: usize, state_tainted: &BitSet) -> bool {
    let Some(block) = ssa.block(block_idx) else {
        return false;
    };
    let term_is_state_check = matches!(block.terminator_op(), Some(SsaOp::BranchCmp { left, right, .. })
        if state_tainted.contains(left.index()) || state_tainted.contains(right.index()));
    if !term_is_state_check {
        return false;
    }
    let instrs = block.instructions();
    let non_term_count = instrs.len().saturating_sub(1);
    instrs
        .iter()
        .take(non_term_count)
        .all(|instr| is_pure_prep_op(instr.op()))
}

/// Extracts redirect information from a trace tree.
///
/// Walks the tree iteratively via an explicit worklist to avoid blowing the
/// thread stack on methods with hundreds of CFF state transitions (each is
/// its own StateTransition node and the recursive version spent one frame per
/// transition).
///
/// `external_predecessor` is used when a node is a sub-trace spawned from a
/// UserBranch/UserSwitch. It represents the block that branched to this
/// sub-trace's first block, needed for proper merge point detection when the
/// first block appears in multiple paths.
fn extract_redirects_from_node(
    node: &TraceNode,
    dispatcher_block: usize,
    plan: &mut PatchPlan,
    external_predecessor: Option<usize>,
    ssa: &SsaFunction,
) {
    let mut stack: Vec<(&TraceNode, Option<usize>)> = Vec::new();
    stack.push((node, external_predecessor));

    while let Some((node, external_predecessor)) = stack.pop() {
        // Add non-dispatcher blocks to execution order
        for &block in &node.blocks_visited {
            plan.add_to_execution_order(block);
        }

        match &node.terminator {
            TraceTerminator::StateTransition {
                target_block,
                continues,
                ..
            } => {
                // When the dispatcher's switch falls through to its default and
                // the default is an overflow chain (`bcmp state == K, case : next`
                // repeated), `target_block` points at the chain's first block.
                // Redirecting there lands on state-check machinery that — after
                // state-tainted filtering — folds through an arbitrary chain
                // arm and re-enters a case block, producing a self-loop. The
                // traced `continues` node already walked the chain with concrete
                // state, so the first non-chain block in its visit list is the
                // real user-code target. Advance `target_block` to it.
                let effective_target = {
                    let mut t = *target_block;
                    if is_state_chain_block(ssa, t, &plan.state_tainted) {
                        for &b in &continues.blocks_visited {
                            if !is_state_chain_block(ssa, b, &plan.state_tainted) {
                                t = b;
                                break;
                            }
                        }
                    }
                    t
                };
                let target_block = &effective_target;
                // Find the LAST non-dispatcher block — the one that jumps to dispatcher.
                // We redirect it to bypass the dispatcher and go directly to target.
                //
                // For example, with blocks_visited=[9, 10, 2]:
                // - Block 9 jumps to block 10 (keep this edge)
                // - Block 10 jumps to dispatcher (redirect to target)
                // - Block 2 is the dispatcher (being bypassed)
                //
                // This preserves block 10's code while bypassing the dispatcher.
                // If multiple paths converge at block 10 with different targets,
                // conflict detection will prevent the redirect.
                let last_pred = node
                    .blocks_visited
                    .iter()
                    .rev()
                    .find(|&&b| b != dispatcher_block)
                    .copied();
                let first_pred = node
                    .blocks_visited
                    .iter()
                    .find(|&&b| b != dispatcher_block)
                    .copied();

                // When the trace walks through intermediate blocks to reach the
                // dispatcher (NETReactor inserts a `stloc state; ldloc state` prep
                // chain between every case block and the switch), the "last block
                // that jumps to the dispatcher" is a prep block shared across every
                // path. Picking it as pred_block causes unresolvable redirect conflicts.
                // If the intermediate blocks are pure CFG plumbing (no user-visible
                // side effects — only Const/Copy/Phi), use the FIRST non-dispatcher
                // block instead so each case block gets its own redirect.
                //
                // When `first` ends in a BranchCmp/Branch (e.g., NETReactor
                // overflow-dispatch `bcmp state == Const ? case : next`), we
                // can't simply use it as pred_block — `set_target` would collapse
                // both branch arms to the same target, skipping over intervening
                // user-code blocks like B103 → B11 (lock body) in the true arm.
                // Instead, we keep `last` as pred_block (the block that actually
                // jumps to the dispatcher) AND additionally collapse `first`'s
                // BranchCmp to a Jump at the NEXT visited block — the arm the
                // trace resolved. This preserves the sequential execution of the
                // user-code intermediates while still bypassing the dispatcher.
                let mut collapse_first_branch: Option<(usize, usize)> = None;
                let pred_block = match (first_pred, last_pred) {
                    (Some(first), Some(last)) if first != last => {
                        let mut intermediates_are_pure = true;
                        let start_idx = node
                            .blocks_visited
                            .iter()
                            .position(|&b| b == first)
                            .unwrap_or(0);
                        let end_idx = node
                            .blocks_visited
                            .iter()
                            .position(|&b| b == last)
                            .unwrap_or(node.blocks_visited.len());
                        let interior_start = start_idx.saturating_add(1);
                        if end_idx > interior_start {
                            let intermediate_blocks: BTreeSet<usize> = node
                                .blocks_visited
                                .get(interior_start..end_idx)
                                .map(|s| s.iter().copied().collect())
                                .unwrap_or_default();
                            for iwv in &node.instructions {
                                if !intermediate_blocks.contains(&iwv.block_idx) {
                                    continue;
                                }
                                if !is_pure_prep_op(iwv.instruction.op()) {
                                    intermediates_are_pure = false;
                                    break;
                                }
                            }
                        } else {
                            intermediates_are_pure = false;
                        }
                        let first_is_jump_terminated = ssa
                            .block(first)
                            .and_then(|b| b.terminator_op())
                            .is_some_and(|op| {
                                matches!(op, SsaOp::Jump { .. } | SsaOp::Leave { .. })
                            });
                        if intermediates_are_pure && first_is_jump_terminated {
                            Some(first)
                        } else if intermediates_are_pure {
                            // first has a Branch/BranchCmp overflow check: collapse
                            // it to Jump at the next visited block, then use `last`
                            // for the dispatcher bypass redirect.
                            let next_in_path = node
                                .blocks_visited
                                .get(start_idx.saturating_add(1))
                                .copied();
                            if let Some(next) = next_in_path {
                                collapse_first_branch = Some((first, next));
                            }
                            Some(last)
                        } else {
                            Some(last)
                        }
                    }
                    _ => last_pred,
                };

                // Find what block leads INTO the pred block (for merge point tracking)
                let predecessor_of_pred = if let Some(pred) = pred_block {
                    node.blocks_visited
                        .iter()
                        .position(|&b| b == pred)
                        .and_then(|pos| {
                            if pos > 0 {
                                node.blocks_visited.get(pos.saturating_sub(1)).copied()
                            } else {
                                external_predecessor
                            }
                        })
                } else {
                    None
                };

                if let Some(pred) = pred_block {
                    // This block should redirect to target_block instead of dispatcher
                    plan.add_redirect(pred, *target_block, predecessor_of_pred);
                    plan.state_transition_sources.insert(pred);
                    plan.state_transitions_removed =
                        plan.state_transitions_removed.saturating_add(1);
                } else if let Some(ext_pred) = external_predecessor {
                    // The sub-trace starts directly at the dispatcher (no preceding user blocks).
                    // This happens when a user branch at method entry sends one path directly
                    // to the dispatcher block. Redirect the external predecessor's
                    // dispatcher-targeting edge to the actual target.
                    plan.add_redirect(ext_pred, *target_block, None);
                    plan.state_transition_sources.insert(ext_pred);
                    plan.state_transitions_removed =
                        plan.state_transitions_removed.saturating_add(1);
                }

                // If the first visited block is a BranchCmp overflow check, add
                // a supplementary redirect that collapses its branch to the next
                // visited block (the arm the trace resolved). Flagged as a
                // branch-collapse redirect so apply_patch_plan can replace the
                // BranchCmp terminator with a Jump, preserving the traced arm's
                // user-code execution while eliminating the dead state-check.
                if let Some((src, next)) = collapse_first_branch {
                    plan.add_branch_collapse(src, next);
                }

                // Continue processing the rest of the trace.
                // The continues trace starts at target_block, and its predecessor is
                // pred_block (the block that was redirected to go to target_block).
                // Fall back to external_predecessor when pred_block is None
                // (direct-to-dispatcher path).
                stack.push((continues, pred_block.or(external_predecessor)));
            }

            TraceTerminator::UserBranch {
                block,
                true_branch,
                false_branch,
                ..
            } => {
                plan.user_branches_preserved = plan.user_branches_preserved.saturating_add(1);
                // For user branches, the branch block is the predecessor of both sub-traces.
                // This is crucial for proper merge point detection when a block is both
                // an entry path target (from the branch) and a CFF case target.
                // Push in reverse so pops give true_branch first (preserving recursive order).
                stack.push((false_branch, Some(*block)));
                stack.push((true_branch, Some(*block)));
            }

            TraceTerminator::UserSwitch {
                block,
                cases,
                default,
                ..
            } => {
                plan.user_branches_preserved = plan.user_branches_preserved.saturating_add(1);
                // For user switches, the switch block is the predecessor of all
                // case sub-traces. The recursive version processed all cases in
                // order, then the default — to reproduce that order with a LIFO
                // stack, push the default first, then the cases in reverse.
                stack.push((default, Some(*block)));
                for (_, case_node) in cases.iter().rev() {
                    stack.push((case_node, Some(*block)));
                }
            }

            TraceTerminator::Exit { block } => {
                plan.add_to_execution_order(*block);
            }

            TraceTerminator::LoopBack { target_block, .. } => {
                // LoopBack means a loop back-edge through the CFF dispatcher: the
                // path "source → dispatcher → target" should become a natural loop
                // edge "source → target".
                //
                // Usually the parent StateTransition already added this redirect.
                // However, in CFF patterns where multiple switch cases share the
                // same target block (e.g., JIEJIE.NET), the parent's pred_block
                // resolution can yield None, causing it to miss the redirect.
                // Adding it here as a safety net is always correct — add_redirect
                // deduplicates identical (source, target) pairs.
                //
                // We use external_predecessor (set by the parent call site) as the
                // redirect source, since this node's blocks_visited is typically
                // just [target_block] (the loop header / destination, not the source).
                if let Some(pred) = external_predecessor {
                    plan.add_redirect(pred, *target_block, external_predecessor);
                    plan.state_transition_sources.insert(pred);
                    plan.state_transitions_removed =
                        plan.state_transitions_removed.saturating_add(1);
                }
                plan.add_to_execution_order(*target_block);
            }

            TraceTerminator::Stopped { .. } | TraceTerminator::PendingStateTransition { .. } => {
                // Trace halted due to a limit or unresolvable control flow.
                // Nothing to extract.
            }
        }
    }
}

/// Applies a patch plan to an SSA function, removing CFF machinery.
///
/// This modifies the SSA in place by:
/// 1. Redirecting block terminators from dispatcher to their actual targets
/// 2. Cloning merge blocks when multiple paths converge with different targets
/// 3. Filtering out state-tainted instructions (CFF machinery)
/// 4. Propagating user variable PHIs to new merge points
/// 5. Cleaning up orphaned references
///
/// # Arguments
///
/// * `ssa` - The SSA function to patch (modified in place)
/// * `plan` - The patch plan extracted from the trace tree
///
/// # Returns
///
/// A [`ReconstructionResult`] containing statistics about the patching:
/// - Number of state transitions removed
/// - Number of user branches preserved
/// - Final block count
pub fn apply_patch_plan(ssa: &mut SsaFunction, plan: &PatchPlan) -> ReconstructionResult {
    // Apply only safe redirects (skip conflicting merge points that need cloning)
    let safe = plan.safe_redirects();
    let to_clone = plan.blocks_to_clone();

    // Apply safe redirects (blocks that don't need cloning).
    //
    // The source may be either the direct CASE→DISP edge block (ConfuserEx-style)
    // or the start of a CASE→prep→...→DISP chain (NETReactor-style where the
    // dispatcher has intermediate prep blocks for state setup). For Jump
    // terminators we overwrite the target outright, which correctly bypasses
    // multi-hop prep chains; for Branch/Switch terminators we fall back to
    // edge-rewriting relative to any dispatcher block.
    for &(source_block, new_target) in &safe {
        let is_jump = ssa
            .block(source_block)
            .and_then(|b| b.terminator_op())
            .is_some_and(|op| matches!(op, SsaOp::Jump { .. } | SsaOp::Leave { .. }));
        if let Some(block) = ssa.block_mut(source_block) {
            if is_jump {
                block.set_target(new_target);
            } else {
                for &db in &plan.dispatcher_blocks {
                    block.redirect_target(db, new_target);
                }
            }
        }
    }

    // Apply branch collapses: at each source block with a recorded collapse,
    // replace the BranchCmp/Branch terminator with a Jump to the traced arm's
    // next block. This eliminates NETReactor overflow-dispatch machinery (e.g.
    // `bcmp state == 13 ? B_match : B_next_check`) from the unflattened CFG
    // while preserving the intervening user-code blocks that the separate
    // redirect chain walks to reach the state transition's target.
    for (&source_block, &new_target) in &plan.branch_collapses {
        if let Some(block) = ssa.block_mut(source_block) {
            let current = block
                .terminator_op()
                .map(|op| matches!(op, SsaOp::Branch { .. } | SsaOp::BranchCmp { .. }))
                .unwrap_or(false);
            if current {
                if let Some(term) = block.instructions_mut().last_mut() {
                    *term = SsaInstruction::synthetic(SsaOp::Jump { target: new_target });
                }
            }
        }
    }

    // Handle merge points by cloning blocks
    // For each merge block, clone it for all predecessors except the first
    // Track clone mappings: clone_index -> original_index
    let mut clone_map: BTreeMap<usize, usize> = BTreeMap::new();
    let mut cloned_blocks = Vec::new();
    for (merge_block, paths) in &to_clone {
        if paths.len() < 2 {
            continue;
        }

        // Get the merge block content - we'll clone it for each path
        let merge_content = ssa.block(*merge_block).cloned();
        let Some(original_block) = merge_content else {
            continue;
        };

        // First path keeps the original block - update its terminator.
        // Only redirect Jump terminators. Branch/BranchCmp blocks are user
        // branches that must preserve both targets — cloning them with
        // set_target would collapse both branch arms to the same target.
        let Some(&(_, first_target)) = paths.first() else {
            continue;
        };
        let is_user_branch = ssa
            .block(*merge_block)
            .and_then(|b| b.terminator_op())
            .is_some_and(|op| {
                matches!(
                    op,
                    SsaOp::Branch { .. } | SsaOp::BranchCmp { .. } | SsaOp::Switch { .. }
                )
            });
        if is_user_branch {
            // User branch block: don't clone, don't redirect.
            // The redirect already points predecessors to this block;
            // its branches are user code that should be preserved.
            continue;
        }
        if let Some(block) = ssa.block_mut(*merge_block) {
            block.set_target(first_target);
        }

        // For remaining paths, create clones
        for &(pred, target) in paths.iter().skip(1) {
            let new_block_idx = ssa.block_count().saturating_add(cloned_blocks.len());

            // Track the clone mapping
            clone_map.insert(new_block_idx, *merge_block);

            // Clone the block with new ID and updated terminator
            let mut cloned = original_block.clone();
            cloned.set_id(new_block_idx);

            // Instead of manually replacing PHI results with operand values (which
            // can create cycles when PHI operands have mutual dependencies), we take
            // a simpler approach:
            //
            // 1. Keep only the PHI operand from this predecessor
            // 2. Let rebuild_ssa handle the proper conversion
            //
            // This avoids creating cycles because:
            // - PHI nodes are properly handled by the SSA reconstruction algorithm
            // - The algorithm correctly handles dominance relationships
            // - We don't risk creating references to values defined later in the block
            //
            // Note: The PHI will be trivial (single operand) after this, and rebuild_ssa
            // will either eliminate it or convert it to a proper definition.
            for phi in cloned.phi_nodes_mut() {
                // Keep only the operand from this predecessor
                phi.operands_mut().retain(|op| op.predecessor() == pred);
            }

            // Remove PHIs that now have no operands (shouldn't happen, but be safe)
            cloned
                .phi_nodes_mut()
                .retain(|phi| !phi.operands().is_empty());

            // Set terminator to jump directly to target
            cloned.set_target(target);

            // Track: predecessor needs to redirect to this clone
            cloned_blocks.push((pred, cloned, *merge_block));
        }
    }

    // Add all cloned blocks to SSA
    for (pred, mut cloned, original_merge) in cloned_blocks {
        let new_block_idx = cloned.id();

        // Redirect the predecessor to point to the clone instead of the merge block
        if let Some(pred_block) = ssa.block_mut(pred) {
            pred_block.redirect_target(original_merge, new_block_idx);
        }

        // Filter state instructions from the clone
        filter_state_instructions(&mut cloned, &plan.state_tainted, &plan.dispatcher_blocks);

        // Add the clone to SSA
        ssa.blocks_mut().push(cloned);
    }

    // Filter out state-tainted instructions ONLY from blocks that were patched.
    // Unresolved blocks (not redirected or cloned) must keep their CFF machinery
    // so they remain functional. Stripping state instructions from unresolved
    // blocks would remove their Jump-to-dispatcher terminators, orphaning them.
    let mut patched_blocks = BitSet::new(ssa.block_count());
    for &(source, _) in &safe {
        patched_blocks.insert(source);
    }
    for (merge_block, _) in &to_clone {
        patched_blocks.insert(*merge_block);
    }

    for block_idx in patched_blocks.iter() {
        // Don't filter state instructions from blocks that still have a
        // switch terminator (including handler CFF dispatchers). The switch
        // needs its state computation (call + rem.un) to remain functional.
        // These blocks will either be fully cleared later (when no longer
        // needed) or their state will be folded by constant propagation.
        let has_switch = ssa
            .block(block_idx)
            .and_then(|b| b.terminator_op())
            .is_some_and(|op| matches!(op, SsaOp::Switch { .. }));
        if plan.is_dispatcher_block(block_idx) || has_switch {
            continue;
        }
        if let Some(block) = ssa.block_mut(block_idx) {
            filter_state_instructions(block, &plan.state_tainted, &plan.dispatcher_blocks);
        }
    }

    // Materialize dispatcher phi resolutions as explicit copies.
    //
    // When a case block (e.g., B4) is redirected to bypass the dispatcher and
    // jump directly to the next case block (e.g., B5), the phi nodes at the
    // dispatcher carried user values between iterations. Without materializing
    // these, rebuild_ssa() cannot recover the data flow because the phi
    // definitions are destroyed when the dispatcher is cleared.
    //
    // For each redirected edge (source → new_target), we resolve the phi chain
    // through dispatcher blocks and insert Copy instructions at the end of the
    // source block.
    materialize_dispatcher_phis(ssa, plan, &patched_blocks);

    // Check if the dispatcher is still needed. A block that jumps to the
    // dispatcher blocks unflattening only if it's reachable from OUTSIDE the
    // dispatcher. Blocks whose only predecessors are dispatcher blocks (dead
    // CFF case targets never dispatched during execution) are cleared along
    // with the dispatcher.
    let unresolved: Vec<usize> = (0..ssa.block_count())
        .filter(|&bi| {
            !patched_blocks.contains(bi)
                && !plan.is_dispatcher_block(bi)
                && ssa
                    .block(bi)
                    .and_then(|b| b.terminator_op())
                    .is_some_and(|op| match op {
                        SsaOp::Jump { target } => plan.is_dispatcher_block(*target),
                        SsaOp::BranchCmp {
                            true_target,
                            false_target,
                            ..
                        } => {
                            plan.is_dispatcher_block(*true_target)
                                || plan.is_dispatcher_block(*false_target)
                        }
                        _ => false,
                    })
        })
        .collect();

    let dispatcher_still_needed = unresolved.iter().any(|&bi| {
        ssa.block_predecessors(bi)
            .iter()
            .any(|&pred| !plan.is_dispatcher_block(pred))
    });

    if !dispatcher_still_needed {
        for &db in &plan.dispatcher_blocks {
            if let Some(dispatcher) = ssa.block_mut(db) {
                dispatcher.clear();
            }
        }
        for &bi in &unresolved {
            if ssa
                .block_predecessors(bi)
                .iter()
                .all(|&pred| plan.is_dispatcher_block(pred))
            {
                if let Some(block) = ssa.block_mut(bi) {
                    block.clear();
                }
            }
        }
    }

    // NOTE: PHI propagation and variable definition cleanup is NOT done here.
    // After apply_patch_plan returns, the caller must call SsaFunction::rebuild_ssa()
    // to reconstruct proper SSA form with correct PHI nodes for the new CFG structure.

    ReconstructionResult {
        state_transitions_removed: plan.state_transitions_removed,
        user_branches_preserved: plan.user_branches_preserved,
        block_count: ssa.block_count(),
        dispatcher_still_needed,
    }
}

/// Filters out state-tainted instructions from a block.
///
/// An instruction is filtered if:
/// - Its output (def) is state-tainted, OR
/// - Any of its inputs (uses) are state-tainted
///
/// **Exception**: `Const` instructions are always preserved, even if their
/// def variable is state-tainted. CFF state update constants (e.g.,
/// `v_state = Const(42)`) become dead code after the dispatcher redirect
/// and are cleaned up by subsequent dead code elimination passes. Filtering
/// them here risks removing legitimate user constants (strings, integers)
/// whose SSA variables were coincidentally tainted through PHI propagation
/// in combined-protection scenarios (e.g., CFF + string encryption where
/// resolved string constants share PHI merge points with state variables).
///
/// Terminator instructions are NOT filtered (they're handled by redirect).
fn filter_state_instructions(
    block: &mut SsaBlock,
    state_tainted: &BitSet,
    dispatcher_blocks: &[usize],
) {
    block.instructions_mut().retain(|instr| {
        // Always keep terminators - they're handled separately
        if instr.is_terminator() {
            // But skip jumps to any dispatcher (they've been redirected)
            if let SsaOp::Jump { target } = instr.op() {
                if dispatcher_blocks.contains(target) {
                    return false; // Remove jump to dispatcher
                }
            }
            return true;
        }

        // Preserve Const instructions unconditionally. Dead state constants
        // are removed by later DCE; user constants must survive.
        if matches!(instr.op(), SsaOp::Const { .. }) {
            return true;
        }

        // Check if instruction is state-tainted
        let def_tainted = instr
            .def()
            .is_some_and(|d| state_tainted.contains(d.index()));
        let uses_tainted = instr
            .uses()
            .iter()
            .any(|u| state_tainted.contains(u.index()));

        // Remove instructions whose output is state infrastructure.
        if def_tainted {
            return false;
        }

        // For uses-only tainted instructions: preserve Call/CallVirt because
        // they may compute user-visible values from state-derived constants.
        // Example: JIEJIE.NET typeof container — `GetTypeInstance(state_index)`
        // returns a System.Type needed by user code, even though the index
        // argument is derived from the CFF state machine's Int32ValueContainer.
        if uses_tainted {
            return matches!(instr.op(), SsaOp::Call { .. } | SsaOp::CallVirt { .. });
        }

        true
    });
}

/// Materializes dispatcher phi resolutions as explicit Copy instructions.
///
/// When CFF unflattening redirects a case block to bypass the dispatcher, the
/// dispatcher's phi nodes — which carried user values between loop iterations —
/// are about to be destroyed. This function resolves those phis along each
/// redirected edge and inserts Copy instructions so that `rebuild_ssa()` can
/// see the data flow.
///
/// For a redirected edge `source → new_target` that originally went through
/// dispatcher blocks `source → D1 → D2 → new_target`, this resolves the phi
/// chain: for each phi at D2, trace back through D1's phis to find the
/// concrete value coming from `source`, and insert `phi_result = value` as a
/// Copy in `source`.
fn materialize_dispatcher_phis(ssa: &mut SsaFunction, plan: &PatchPlan, patched_blocks: &BitSet) {
    if plan.dispatcher_blocks.is_empty() {
        return;
    }

    // Identify all blocks in the dispatcher loop: the dispatcher blocks themselves
    // plus any "back-edge" blocks between case blocks and the dispatcher.
    //
    // The typical CFF pattern has: case_block → back_edge (B1) → dispatcher (B2).
    // Both B1 and B2 have phis that carry user values between iterations.
    //
    // We detect back-edge blocks by two criteria:
    // 1. They have phis with operands from patched (case) blocks
    // 2. They are predecessors of the dispatcher (directly or transitively)
    let dispatcher_set: BTreeSet<usize> = plan.dispatcher_blocks.iter().copied().collect();
    let mut loop_blocks: Vec<usize> = plan.dispatcher_blocks.clone();
    let mut loop_block_set: BTreeSet<usize> = dispatcher_set.clone();

    // Find back-edge blocks: blocks with phis whose operands come from
    // patched case blocks. These blocks sit between case blocks and the
    // dispatcher, funneling values through phis.
    for block_idx in 0..ssa.block_count() {
        if loop_block_set.contains(&block_idx) {
            continue;
        }
        if patched_blocks.contains(block_idx) {
            continue;
        }
        let Some(block) = ssa.block(block_idx) else {
            continue;
        };
        if block.phi_nodes().is_empty() {
            continue;
        }
        // Check if any phi has an operand from a patched case block
        let has_patched_predecessor = block.phi_nodes().iter().any(|phi| {
            phi.operands()
                .iter()
                .any(|op| patched_blocks.contains(op.predecessor()))
        });
        if has_patched_predecessor {
            loop_blocks.push(block_idx);
            loop_block_set.insert(block_idx);
        }
    }

    // Sort loop blocks: back-edge blocks first (not in dispatcher_set),
    // then dispatcher blocks. This ensures we resolve back-edge phis
    // before dispatcher phis that depend on them.
    loop_blocks.sort_by_key(|&b| if dispatcher_set.contains(&b) { 1 } else { 0 });

    // Collect the phi data from all loop blocks before mutating.
    let dispatcher_phis: BlockPhiData = loop_blocks
        .iter()
        .filter_map(|&db| {
            ssa.block(db).map(|block| {
                let phis = block
                    .phi_nodes()
                    .iter()
                    .filter(|phi| !plan.state_tainted.contains(phi.result().index()))
                    .map(|phi| {
                        let operands: Vec<(usize, SsaVarId)> = phi
                            .operands()
                            .iter()
                            .map(|op| (op.predecessor(), op.value()))
                            .collect();
                        (phi.result(), operands)
                    })
                    .collect();
                (db, phis)
            })
        })
        .collect();

    if dispatcher_phis.is_empty() {
        return;
    }

    // Build a lookup: loop_block → (phi_result → operands)
    let mut phi_lookup: BTreeMap<usize, BTreeMap<SsaVarId, Vec<(usize, SsaVarId)>>> =
        BTreeMap::new();
    for (db, phis) in &dispatcher_phis {
        let map: BTreeMap<SsaVarId, Vec<(usize, SsaVarId)>> = phis
            .iter()
            .map(|(result, operands)| (*result, operands.clone()))
            .collect();
        phi_lookup.insert(*db, map);
    }

    let loop_block_set: BTreeSet<usize> = loop_blocks.iter().copied().collect();

    // For each dispatcher phi, find the concrete value: the operand from a
    // patched case block that provides a NON-pass-through value (i.e., a value
    // that is NOT itself a dispatcher-phi result).
    //
    // Then substitute all uses of the phi-result variable in non-provider
    // blocks with the concrete value. This eliminates stale references to
    // variables defined only by the now-destroyed dispatcher phis.
    let phi_result_set: BTreeSet<SsaVarId> = dispatcher_phis
        .iter()
        .flat_map(|(_, phis)| phis.iter().map(|(r, _)| *r))
        .collect();

    // For each phi, find which block(s) provide a concrete (non-phi-result) value
    let mut concrete_for_phi: BTreeMap<SsaVarId, (usize, SsaVarId)> = BTreeMap::new();
    for (_, phis) in &dispatcher_phis {
        for (phi_result, operands) in phis {
            for &(pred, val) in operands {
                if !patched_blocks.contains(pred) || loop_block_set.contains(&pred) {
                    continue;
                }
                // Pass-through: val is the phi result itself or another phi result
                if val == *phi_result || phi_result_set.contains(&val) {
                    continue;
                }
                concrete_for_phi.insert(*phi_result, (pred, val));
            }
        }
    }

    if concrete_for_phi.is_empty() {
        return;
    }

    // Resolve phi values along the execution path and substitute uses.
    //
    // Process blocks in execution order (from the trace tree). For each block,
    // resolve the dispatcher phis from the PREVIOUS block's perspective, then
    // substitute all uses of phi-result variables in this block.
    //
    // The key: each block's phi resolution builds on the previous block's.
    // When a phi operand from block B is itself a phi result (pass-through),
    // we use the accumulated resolution to get the concrete value.
    let mut accumulated: BTreeMap<SsaVarId, SsaVarId> = BTreeMap::new();

    for &block_idx in &plan.execution_order {
        if !patched_blocks.contains(block_idx) || loop_block_set.contains(&block_idx) {
            continue;
        }

        // Apply accumulated resolution to THIS block's instructions
        if !accumulated.is_empty() {
            if let Some(block) = ssa.block_mut(block_idx) {
                for instr in block.instructions_mut() {
                    for (&phi_var, &concrete_val) in &accumulated {
                        instr.op_mut().replace_uses(phi_var, concrete_val);
                    }
                }
            }
        }

        // Compute this block's phi resolution for the NEXT block.
        // For each dispatcher phi, find the operand from this block and
        // resolve transitively using the accumulated map.
        for &db in &loop_blocks {
            let Some(phis) = phi_lookup.get(&db) else {
                continue;
            };
            for (phi_result, operands) in phis {
                if let Some(&(_, val)) = operands.iter().find(|&&(pred, _)| pred == block_idx) {
                    // Resolve transitively
                    let concrete = accumulated.get(&val).copied().unwrap_or(val);
                    if *phi_result != concrete {
                        accumulated.insert(*phi_result, concrete);
                    }
                }
            }
        }
    }
}

/// Analyzes a trace tree and returns statistics without modifying anything.
///
/// This is a read-only analysis function that reports what would change
/// if [`apply_patch_plan`] were called. Useful for previewing changes
/// or collecting metrics without side effects.
///
/// # Arguments
///
/// * `tree` - The trace tree to analyze
/// * `original` - The original SSA function (for block count)
///
/// # Returns
///
/// `Some(ReconstructionResult)` with statistics if the tree has a dispatcher,
/// `None` if no dispatcher was detected.
pub fn reconstruct_from_tree(
    tree: &TraceTree,
    original: &SsaFunction,
) -> Option<ReconstructionResult> {
    let plan = extract_patch_plan(tree, original)?;

    Some(ReconstructionResult {
        state_transitions_removed: plan.state_transitions_removed,
        user_branches_preserved: plan.user_branches_preserved,
        block_count: original.block_count(),
        dispatcher_still_needed: false, // Preview only — actual value computed during apply
    })
}

#[cfg(test)]
mod tests {
    use crate::{
        analysis::{
            ConstValue, PhiNode, PhiOperand, SsaBlock, SsaFunction, SsaInstruction, SsaOp,
            SsaVarId, VariableOrigin,
        },
        deobfuscation::passes::unflattening::{
            reconstruction::reconstruct_from_tree, tracer::trace_method_tree, UnflattenConfig,
        },
    };

    /// Creates a simple CFF-like SSA function for testing.
    fn create_simple_cff() -> SsaFunction {
        let mut ssa = SsaFunction::new(0, 1);
        let state_var = SsaVarId::from_index(0);
        let const_var = SsaVarId::from_index(1);

        // B0: entry - set initial state and jump to dispatcher
        let mut b0 = SsaBlock::new(0);
        b0.add_instruction(SsaInstruction::synthetic(SsaOp::Const {
            dest: const_var,
            value: ConstValue::I32(0),
        }));
        b0.add_instruction(SsaInstruction::synthetic(SsaOp::Jump { target: 1 }));
        ssa.add_block(b0);

        // B1: dispatcher with switch
        let mut b1 = SsaBlock::new(1);
        let mut phi = PhiNode::new(state_var, VariableOrigin::Local(0));
        phi.add_operand(PhiOperand::new(const_var, 0));
        b1.add_phi(phi);
        b1.add_instruction(SsaInstruction::synthetic(SsaOp::Switch {
            value: state_var,
            targets: vec![2, 3, 4],
            default: 5,
        }));
        ssa.add_block(b1);

        // B2, B3, B4: case blocks that jump back to dispatcher
        for i in 2..=4 {
            let mut b = SsaBlock::new(i);
            b.add_instruction(SsaInstruction::synthetic(SsaOp::Jump { target: 1 }));
            ssa.add_block(b);
        }

        // B5: exit
        let mut b5 = SsaBlock::new(5);
        b5.add_instruction(SsaInstruction::synthetic(SsaOp::Return { value: None }));
        ssa.add_block(b5);

        ssa
    }

    #[test]
    fn test_reconstruct_simple_cff() {
        let ssa = create_simple_cff();
        let config = UnflattenConfig::default();
        let tree = trace_method_tree(&ssa, &config, None);

        assert!(tree.dispatcher.is_some(), "Should detect dispatcher");

        let result = reconstruct_from_tree(&tree, &ssa);
        assert!(result.is_some(), "Reconstruction should succeed");

        let result = result.unwrap();
        println!("=== Reconstruction Result ===");
        println!("Blocks: {}", result.block_count);
        println!(
            "State transitions removed: {}",
            result.state_transitions_removed
        );
        println!(
            "User branches preserved: {}",
            result.user_branches_preserved
        );

        // Should have removed state transitions
        assert!(
            result.state_transitions_removed > 0,
            "Should remove at least one state transition"
        );

        // Reconstructed function should have blocks
        assert!(result.block_count > 0, "Should have blocks in output");
    }

    /// Creates a CFF with a user branch inside a case block.
    fn create_cff_with_user_branch() -> SsaFunction {
        let mut ssa = SsaFunction::new(1, 1); // 1 arg, 1 local
        let state_var = SsaVarId::from_index(0);
        let init_state = SsaVarId::from_index(1);
        let const_one = SsaVarId::from_index(2);
        let arg0 = SsaVarId::from_index(3);
        let user_zero = SsaVarId::from_index(4);
        let cmp_result = SsaVarId::from_index(5);

        // B0: entry - set initial state = 0 and jump to dispatcher
        let mut b0 = SsaBlock::new(0);
        b0.add_instruction(SsaInstruction::synthetic(SsaOp::Const {
            dest: init_state,
            value: ConstValue::I32(0),
        }));
        b0.add_instruction(SsaInstruction::synthetic(SsaOp::Const {
            dest: arg0,
            value: ConstValue::I32(42), // simulate arg > 0
        }));
        b0.add_instruction(SsaInstruction::synthetic(SsaOp::Jump { target: 1 }));
        ssa.add_block(b0);

        // B1: dispatcher with switch
        let mut b1 = SsaBlock::new(1);
        let mut phi = PhiNode::new(state_var, VariableOrigin::Local(0));
        phi.add_operand(PhiOperand::new(init_state, 0)); // from entry
        phi.add_operand(PhiOperand::new(const_one, 3)); // from B3a
        phi.add_operand(PhiOperand::new(const_one, 4)); // from B3b
        b1.add_phi(phi);
        b1.add_instruction(SsaInstruction::synthetic(SsaOp::Switch {
            value: state_var,
            targets: vec![2, 5], // case 0 -> B2, case 1 -> B5
            default: 6,
        }));
        ssa.add_block(b1);

        // B2: case 0 - has USER BRANCH (condition NOT tainted by state)
        let mut b2 = SsaBlock::new(2);
        b2.add_instruction(SsaInstruction::synthetic(SsaOp::Const {
            dest: const_one,
            value: ConstValue::I32(1),
        }));
        b2.add_instruction(SsaInstruction::synthetic(SsaOp::Const {
            dest: user_zero,
            value: ConstValue::I32(0),
        }));
        b2.add_instruction(SsaInstruction::synthetic(SsaOp::Cgt {
            dest: cmp_result,
            left: arg0,
            right: user_zero,
            unsigned: false,
        }));
        b2.add_instruction(SsaInstruction::synthetic(SsaOp::Branch {
            condition: cmp_result,
            true_target: 3,  // B3a
            false_target: 4, // B3b
        }));
        ssa.add_block(b2);

        // B3a: true branch of user condition - sets state = 1
        let mut b3a = SsaBlock::new(3);
        b3a.add_instruction(SsaInstruction::synthetic(SsaOp::Jump { target: 1 }));
        ssa.add_block(b3a);

        // B3b: false branch of user condition - also sets state = 1
        let mut b3b = SsaBlock::new(4);
        b3b.add_instruction(SsaInstruction::synthetic(SsaOp::Jump { target: 1 }));
        ssa.add_block(b3b);

        // B5: case 1 - exit path
        let mut b5 = SsaBlock::new(5);
        b5.add_instruction(SsaInstruction::synthetic(SsaOp::Return { value: None }));
        ssa.add_block(b5);

        // B6: default - exit
        let mut b6 = SsaBlock::new(6);
        b6.add_instruction(SsaInstruction::synthetic(SsaOp::Return { value: None }));
        ssa.add_block(b6);

        ssa
    }

    #[test]
    fn test_reconstruct_with_user_branch() {
        let ssa = create_cff_with_user_branch();
        let config = UnflattenConfig::default();
        let tree = trace_method_tree(&ssa, &config, None);

        assert!(tree.dispatcher.is_some(), "Should detect dispatcher");
        assert!(
            tree.stats.user_branch_count > 0,
            "Should have user branches"
        );

        let result = reconstruct_from_tree(&tree, &ssa);
        assert!(result.is_some(), "Reconstruction should succeed");

        let result = result.unwrap();
        println!("=== Reconstruction with User Branch ===");
        println!("Blocks: {}", result.block_count);
        println!(
            "State transitions removed: {}",
            result.state_transitions_removed
        );
        println!(
            "User branches preserved: {}",
            result.user_branches_preserved
        );

        // Should preserve user branches
        assert!(
            result.user_branches_preserved > 0,
            "Should preserve user branches"
        );

        println!("Block count: {}", result.block_count);
    }
}
