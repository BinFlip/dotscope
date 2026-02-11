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

use std::collections::{HashMap, HashSet};

use crate::{
    analysis::{SsaBlock, SsaFunction, SsaOp, SsaVarId},
    deobfuscation::passes::unflattening::tracer::{TraceNode, TraceTerminator, TraceTree},
};

/// Result of unflattening a CFG.
#[derive(Debug)]
pub struct ReconstructionResult {
    /// Number of state transitions eliminated.
    pub state_transitions_removed: usize,
    /// Number of user branches preserved.
    pub user_branches_preserved: usize,
    /// Number of blocks in the function.
    pub block_count: usize,
}

/// A plan for patching the SSA to remove CFF.
#[derive(Debug)]
pub struct PatchPlan {
    /// Dispatcher block index.
    pub dispatcher_block: usize,

    /// Variables that are state-related (CFF machinery).
    pub state_tainted: HashSet<SsaVarId>,

    /// Block redirects: (source_block, new_target).
    /// These blocks currently jump to dispatcher but should jump to new_target.
    pub redirects: Vec<(usize, usize)>,

    /// Blocks that need cloning: merge_block -> [(predecessor, target), ...]
    /// These are blocks where multiple paths converge with different targets.
    /// We clone the merge block for each path.
    pub clone_requests: HashMap<usize, Vec<(usize, usize)>>,

    /// Blocks in execution order (for debugging/verification).
    pub execution_order: Vec<usize>,

    /// Number of state transitions removed.
    pub state_transitions_removed: usize,

    /// Number of user branches preserved.
    pub user_branches_preserved: usize,
}

impl PatchPlan {
    fn new(dispatcher_block: usize, state_tainted: HashSet<SsaVarId>) -> Self {
        Self {
            dispatcher_block,
            state_tainted,
            redirects: Vec::new(),
            clone_requests: HashMap::new(),
            execution_order: Vec::new(),
            state_transitions_removed: 0,
            user_branches_preserved: 0,
        }
    }

    fn add_redirect(&mut self, source: usize, target: usize, predecessor: Option<usize>) {
        // Check for conflict: same source with different target
        if let Some(&(_, existing_target)) = self.redirects.iter().find(|&&(s, _)| s == source) {
            if existing_target != target {
                // Conflict! This source is a merge point needing cloning.
                // Add both the existing and new paths to clone requests
                let entry = self.clone_requests.entry(source).or_default();

                // Find the predecessor for the existing redirect (if we have it)
                // For now, we'll add the new one; the existing one was added when first seen
                if let Some(pred) = predecessor {
                    if !entry.iter().any(|(p, _)| *p == pred) {
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
    fn safe_redirects(&self) -> Vec<(usize, usize)> {
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
    fn blocks_to_clone(&self) -> Vec<(usize, Vec<(usize, usize)>)> {
        self.clone_requests
            .iter()
            .filter(|(_, paths)| paths.len() > 1) // Only clone if multiple paths
            .map(|(&block, paths)| (block, paths.clone()))
            .collect()
    }

    fn add_to_execution_order(&mut self, block: usize) {
        if !self.execution_order.contains(&block) && block != self.dispatcher_block {
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
pub fn extract_patch_plan(tree: &TraceTree) -> Option<PatchPlan> {
    let dispatcher = tree.dispatcher.as_ref()?;

    let mut plan = PatchPlan::new(dispatcher.block, tree.state_tainted.clone());

    // Walk the tree and extract redirects
    // Start with no external predecessor since we're at the root
    extract_redirects_from_node(&tree.root, dispatcher.block, &mut plan, None);

    Some(plan)
}

/// Recursively extracts redirect information from a trace node.
///
/// `external_predecessor` is used when this node is a sub-trace spawned from a UserBranch/UserSwitch.
/// It represents the block that branched to this sub-trace's first block, which is needed
/// for proper merge point detection when the first block appears in multiple paths.
fn extract_redirects_from_node(
    node: &TraceNode,
    dispatcher_block: usize,
    plan: &mut PatchPlan,
    external_predecessor: Option<usize>,
) {
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
            // Find the LAST non-dispatcher block - this is the one that jumps to dispatcher.
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
            // Find the LAST non-dispatcher block that jumps to the dispatcher
            let pred_block = node
                .blocks_visited
                .iter()
                .rev()
                .find(|&&b| b != dispatcher_block)
                .copied();

            // Find what block leads INTO the pred block (for merge point tracking)
            // In blocks_visited=[9, 10, 2], if pred=10, its predecessor is 9
            //
            // IMPORTANT: If pred is at position 0 (start of this trace), we use the
            // external_predecessor which was passed from the parent UserBranch/UserSwitch.
            // This ensures proper merge point detection when a block appears in multiple
            // sub-traces (e.g., both as an entry path target and a CFF case target).
            let predecessor_of_pred = if let Some(pred) = pred_block {
                // Find position of pred in blocks_visited
                node.blocks_visited
                    .iter()
                    .position(|&b| b == pred)
                    .and_then(|pos| {
                        if pos > 0 {
                            Some(node.blocks_visited[pos - 1])
                        } else {
                            // Position 0 - use external predecessor if available
                            external_predecessor
                        }
                    })
            } else {
                None
            };

            if let Some(pred) = pred_block {
                // This block should redirect to target_block instead of dispatcher
                plan.add_redirect(pred, *target_block, predecessor_of_pred);
                plan.state_transitions_removed += 1;
            }

            // Continue processing the rest of the trace
            // The continues trace starts at target_block, and its predecessor is pred_block
            // (the block that was redirected to go to target_block)
            extract_redirects_from_node(continues, dispatcher_block, plan, pred_block);
        }

        TraceTerminator::UserBranch {
            block,
            true_branch,
            false_branch,
            ..
        } => {
            plan.user_branches_preserved += 1;
            // For user branches, the branch block is the predecessor of both sub-traces.
            // This is crucial for proper merge point detection when a block is both
            // an entry path target (from the branch) and a CFF case target.
            extract_redirects_from_node(true_branch, dispatcher_block, plan, Some(*block));
            extract_redirects_from_node(false_branch, dispatcher_block, plan, Some(*block));
        }

        TraceTerminator::UserSwitch {
            block,
            cases,
            default,
            ..
        } => {
            plan.user_branches_preserved += 1;
            // For user switches, the switch block is the predecessor of all case sub-traces.
            for (_, case_node) in cases {
                extract_redirects_from_node(case_node, dispatcher_block, plan, Some(*block));
            }
            extract_redirects_from_node(default, dispatcher_block, plan, Some(*block));
        }

        TraceTerminator::Exit { block } => {
            plan.add_to_execution_order(*block);
        }

        TraceTerminator::LoopBack { .. } | TraceTerminator::Stopped { .. } => {
            // LoopBack means we tried to visit target_block again with the same state.
            // The blocks_visited here is typically just [target_block] since we returned
            // immediately upon detecting the loop.
            //
            // The actual back-edge redirect was already handled by the parent
            // StateTransition node. We don't need to add another redirect here.
            //
            // Stopped means the trace was halted. Nothing more to extract in either case.
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

    // Apply safe redirects (blocks that don't need cloning)
    for &(source_block, new_target) in &safe {
        if let Some(block) = ssa.block_mut(source_block) {
            block.redirect_target(plan.dispatcher_block, new_target);
        }
    }

    // Handle merge points by cloning blocks
    // For each merge block, clone it for all predecessors except the first
    // Track clone mappings: clone_index -> original_index
    let mut clone_map: HashMap<usize, usize> = HashMap::new();
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

        // First path keeps the original block - just update its terminator
        let (_, first_target) = paths[0];
        if let Some(block) = ssa.block_mut(*merge_block) {
            block.set_target(first_target);
        }

        // For remaining paths, create clones
        for &(pred, target) in paths.iter().skip(1) {
            let new_block_idx = ssa.block_count() + cloned_blocks.len();

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
        filter_state_instructions(&mut cloned, &plan.state_tainted, plan.dispatcher_block);

        // Add the clone to SSA
        ssa.blocks_mut().push(cloned);
    }

    // Filter out state-tainted instructions from all original blocks
    let original_block_count = ssa.block_count();

    for block_idx in 0..original_block_count {
        if let Some(block) = ssa.block_mut(block_idx) {
            filter_state_instructions(block, &plan.state_tainted, plan.dispatcher_block);
        }
    }

    // Clear the dispatcher block entirely - it's no longer reachable since all blocks
    // that used to jump to it now jump directly to their targets.
    if let Some(dispatcher) = ssa.block_mut(plan.dispatcher_block) {
        dispatcher.clear();
    }

    // NOTE: PHI propagation and variable definition cleanup is NOT done here.
    // After apply_patch_plan returns, the caller must call SsaFunction::rebuild_ssa()
    // to reconstruct proper SSA form with correct PHI nodes for the new CFG structure.

    ReconstructionResult {
        state_transitions_removed: plan.state_transitions_removed,
        user_branches_preserved: plan.user_branches_preserved,
        block_count: ssa.block_count(),
    }
}

/// Filters out state-tainted instructions from a block.
///
/// An instruction is filtered if:
/// - Its output (def) is state-tainted, OR
/// - Any of its inputs (uses) are state-tainted
///
/// Terminator instructions are NOT filtered (they're handled by redirect).
fn filter_state_instructions(
    block: &mut SsaBlock,
    state_tainted: &HashSet<SsaVarId>,
    dispatcher: usize,
) {
    block.instructions_mut().retain(|instr| {
        // Always keep terminators - they're handled separately
        if instr.is_terminator() {
            // But skip jumps to dispatcher (they've been redirected)
            if let SsaOp::Jump { target } = instr.op() {
                if *target == dispatcher {
                    return false; // Remove jump to dispatcher
                }
            }
            return true;
        }

        // Check if instruction is state-tainted
        let def_tainted = instr.def().is_some_and(|d| state_tainted.contains(&d));
        let uses_tainted = instr.uses().iter().any(|u| state_tainted.contains(u));

        // Keep if NOT tainted
        !def_tainted && !uses_tainted
    });
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
    let plan = extract_patch_plan(tree)?;

    Some(ReconstructionResult {
        state_transitions_removed: plan.state_transitions_removed,
        user_branches_preserved: plan.user_branches_preserved,
        block_count: original.block_count(),
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
        let state_var = SsaVarId::new();
        let const_var = SsaVarId::new();

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
        let tree = trace_method_tree(&ssa, &config);

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
        let state_var = SsaVarId::new();
        let init_state = SsaVarId::new();
        let const_one = SsaVarId::new();
        let arg0 = SsaVarId::new();
        let user_zero = SsaVarId::new();
        let cmp_result = SsaVarId::new();

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
        let tree = trace_method_tree(&ssa, &config);

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
