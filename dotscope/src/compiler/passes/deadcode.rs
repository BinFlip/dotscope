//! Dead code elimination pass.
//!
//! This pass performs comprehensive dead code elimination including:
//!
//! 1. **Unreachable block elimination**: Remove blocks that cannot be reached
//! 2. **Dead instruction elimination**: Remove instructions whose results are unused
//! 3. **Trivial phi elimination**: Remove phi nodes with only one unique operand
//! 4. **Dead phi elimination**: Remove phi nodes whose results are never used
//! 5. **Phi operand pruning**: Remove stale operands from unreachable predecessors
//! 6. **Self-referential phi simplification**: Simplify phis like `v1 = phi(v1, v2)` to `v1 = v2`
//!
//! # Algorithm
//!
//! The pass uses an iterative worklist algorithm:
//! 1. Mark entry block and exception handlers as roots
//! 2. Compute reachable blocks via control flow traversal
//! 3. Prune phi operands from unreachable predecessors
//! 4. Compute live variables via reverse dataflow
//! 5. Remove dead definitions and trivial phis
//! 6. Repeat until no changes (fixed point)
//!
//! # Prerequisites
//!
//! This pass works best after constant propagation and branch simplification,
//! as those passes may expose more dead code.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::Arc,
};

use crate::{
    analysis::{PhiAnalyzer, PhiNode, SsaCfg, SsaFunction, SsaInstruction, SsaOp, SsaVarId},
    compiler::{pass::SsaPass, CompilerContext, EventKind, EventLog},
    metadata::token::Token,
    utils::graph::{algorithms, NodeId},
    CilObject, Result,
};

/// Maximum iterations for the fixed-point algorithm to prevent infinite loops.
const MAX_ITERATIONS: usize = 100;

/// Finds blocks that have dead code after terminator instructions.
///
/// Identifies blocks where a return, throw, or other terminator is followed
/// by unreachable instructions that should be removed. This can happen when
/// control flow simplification leaves behind unreachable code.
///
/// # Arguments
///
/// * `ssa` - The SSA function to analyze.
///
/// # Returns
///
/// A vector of (block index, first dead instruction index) pairs.
#[must_use]
pub fn find_dead_tails(ssa: &SsaFunction) -> Vec<(usize, usize)> {
    ssa.iter_blocks()
        .filter_map(|(block_idx, block)| {
            // Find first terminator
            for (instr_idx, instr) in block.instructions().iter().enumerate() {
                if instr.op().is_terminator() && instr_idx < block.instruction_count() - 1 {
                    // There are instructions after the terminator
                    return Some((block_idx, instr_idx + 1));
                }
            }
            None
        })
        .collect()
}

/// Dead code elimination pass.
///
/// Removes unreachable blocks and unused definitions to simplify the SSA graph.
/// Uses an iterative algorithm to handle cascading dead code.
pub struct DeadCodeEliminationPass;

impl Default for DeadCodeEliminationPass {
    fn default() -> Self {
        Self::new()
    }
}

impl DeadCodeEliminationPass {
    /// Creates a new dead code elimination pass.
    ///
    /// # Returns
    ///
    /// A new instance of `DeadCodeEliminationPass`.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Finds all reachable blocks starting from entry and exception handlers.
    ///
    /// Uses the graph infrastructure's BFS traversal to find blocks reachable from:
    /// - Block 0 (the entry block)
    /// - Exception handler blocks from SSA exception handler info
    /// - Fallback: blocks starting with `EndFinally` or `Rethrow` instructions
    ///
    /// Exception handlers are treated as additional roots since they may be
    /// reachable via implicit exception edges that are not explicitly represented
    /// in the SSA graph.
    ///
    /// # Arguments
    ///
    /// * `ssa` - The SSA function to analyze.
    ///
    /// # Returns
    ///
    /// A set of block indices that are reachable from the entry point or exception handlers.
    fn find_reachable_blocks(ssa: &SsaFunction) -> HashSet<usize> {
        if ssa.block_count() == 0 {
            return HashSet::new();
        }

        // Build CFG view for graph traversal
        let cfg = SsaCfg::from_ssa(ssa);

        // Use BFS from entry block (block 0) to find reachable nodes
        let mut reachable: HashSet<usize> = algorithms::bfs(&cfg, NodeId::new(0))
            .map(|n: NodeId| n.index())
            .collect();

        // Collect exception handler entry blocks from SSA exception handler info
        let mut exception_roots: HashSet<usize> = HashSet::new();
        for handler in ssa.exception_handlers() {
            // Add handler start block as a root
            if let Some(handler_block) = handler.handler_start_block {
                if !reachable.contains(&handler_block) {
                    exception_roots.insert(handler_block);
                }
            }
            // Add filter start block for FILTER handlers
            if let Some(filter_block) = handler.filter_start_block {
                if !reachable.contains(&filter_block) {
                    exception_roots.insert(filter_block);
                }
            }
        }

        // Fallback: find exception handler blocks by instruction patterns
        // (for methods where exception handler info wasn't preserved)
        for (block_idx, block) in ssa.iter_blocks() {
            if reachable.contains(&block_idx) || exception_roots.contains(&block_idx) {
                continue;
            }
            // Check if this block starts with exception handling instructions
            if let Some(first_instr) = block.instructions().first() {
                // EndFinally and Rethrow indicate exception handler blocks
                if matches!(first_instr.op(), SsaOp::EndFinally | SsaOp::Rethrow) {
                    exception_roots.insert(block_idx);
                }
            }
        }

        // Traverse from each exception handler root
        for root in exception_roots {
            for node in algorithms::bfs(&cfg, NodeId::new(root)) {
                let node: NodeId = node;
                reachable.insert(node.index());
            }
        }

        reachable
    }

    /// Computes reverse post-order of reachable blocks for efficient dataflow traversal.
    ///
    /// Reverse post-order (RPO) is an ordering where each block appears before its
    /// successors (except for back edges in loops). This ordering is optimal for
    /// forward dataflow analysis as it minimizes the number of iterations needed
    /// to reach a fixed point.
    ///
    /// Uses the graph infrastructure's `reverse_postorder` algorithm.
    ///
    /// # Arguments
    ///
    /// * `ssa` - The SSA function containing the blocks.
    /// * `reachable` - The set of reachable block indices to include in the ordering.
    ///
    /// # Returns
    ///
    /// A vector of block indices in reverse post-order. The entry block appears first,
    /// and exit blocks appear last.
    fn compute_reverse_postorder(ssa: &SsaFunction, reachable: &HashSet<usize>) -> Vec<usize> {
        if ssa.block_count() == 0 || reachable.is_empty() {
            return Vec::new();
        }

        // Build CFG view for graph traversal
        let cfg = SsaCfg::from_ssa(ssa);

        // Use the graph infrastructure's reverse_postorder from entry block
        let mut rpo: Vec<usize> = algorithms::reverse_postorder(&cfg, NodeId::new(0))
            .into_iter()
            .map(|n: NodeId| n.index())
            .filter(|idx| reachable.contains(idx))
            .collect();

        // Handle any remaining reachable blocks (exception handlers) not covered
        // by traversal from entry. Add them in sorted order for determinism.
        let in_rpo: HashSet<usize> = rpo.iter().copied().collect();
        let mut additional: Vec<usize> = reachable
            .iter()
            .copied()
            .filter(|idx| !in_rpo.contains(idx))
            .collect();
        additional.sort_unstable();

        // For exception handlers, compute RPO from each root
        for &root in &additional {
            let handler_rpo: Vec<usize> = algorithms::reverse_postorder(&cfg, NodeId::new(root))
                .into_iter()
                .map(|n: NodeId| n.index())
                .filter(|idx| reachable.contains(idx) && !rpo.contains(idx))
                .collect();
            rpo.extend(handler_rpo);
        }

        rpo
    }

    /// Prunes phi operands that originate from unreachable predecessor blocks.
    ///
    /// When blocks become unreachable, phi nodes in their successors may still
    /// reference values from those unreachable blocks. This function removes
    /// such stale operands to maintain SSA invariants.
    ///
    /// # Arguments
    ///
    /// * `ssa` - The SSA function to modify.
    /// * `reachable` - The set of reachable block indices.
    ///
    /// # Returns
    ///
    /// The number of phi operands that were pruned.
    fn prune_phi_operands(ssa: &mut SsaFunction, reachable: &HashSet<usize>) -> usize {
        // First, build a set of all defined variables
        // This includes variables defined by instructions and PHIs in reachable blocks
        let mut defined_vars: HashSet<SsaVarId> = HashSet::new();

        for &block_idx in reachable {
            if let Some(block) = ssa.block(block_idx) {
                // Variables defined by PHIs
                for phi in block.phi_nodes() {
                    defined_vars.insert(phi.result());
                }
                // Variables defined by instructions
                for instr in block.instructions() {
                    if let Some(def) = instr.def() {
                        defined_vars.insert(def);
                    }
                }
            }
        }

        // Also include argument variables which are defined at entry
        // (but not locals - they need explicit definitions)
        for var in ssa.variables() {
            // Only include arguments (which have implicit definitions at function entry)
            // Locals must have explicit definitions to be considered defined
            if var.origin().is_argument() {
                defined_vars.insert(var.id());
            }
        }

        // Compute actual predecessors from the CFG
        let mut actual_predecessors: HashMap<usize, HashSet<usize>> = HashMap::new();

        for &block_idx in reachable {
            if let Some(block) = ssa.block(block_idx) {
                for successor in block.successors() {
                    actual_predecessors
                        .entry(successor)
                        .or_default()
                        .insert(block_idx);
                }
            }
        }

        let mut pruned = 0;

        for block_idx in reachable.iter().copied() {
            if let Some(block) = ssa.block_mut(block_idx) {
                let preds = actual_predecessors.get(&block_idx);

                for phi in block.phi_nodes_mut() {
                    let operands = phi.operands_mut();
                    let original_len = operands.len();

                    // Skip if already empty (nothing to prune)
                    if original_len == 0 {
                        continue;
                    }

                    // First, identify which operands to keep
                    let to_keep: Vec<bool> = operands
                        .iter()
                        .map(|op| {
                            let pred = op.predecessor();
                            let value = op.value();

                            // Keep if predecessor is in actual predecessors AND value is still defined
                            // Both conditions must be true:
                            // - Predecessor must be a valid CFG edge
                            // - Value must have a definition (not Nop'd or from unreachable code)
                            preds.is_some_and(|p| p.contains(&pred))
                                && defined_vars.contains(&value)
                        })
                        .collect();

                    // Safety check: never leave a PHI completely empty
                    // If all operands would be removed, keep them all
                    let keep_count = to_keep.iter().filter(|&&k| k).count();
                    if keep_count == 0 {
                        // All operands would be removed - this indicates a structural issue
                        // Keep the PHI intact to avoid breaking the code
                        continue;
                    }

                    // Apply the filtering
                    let mut keep_iter = to_keep.iter();
                    operands.retain(|_| *keep_iter.next().unwrap_or(&true));

                    pruned += original_len - operands.len();
                }
            }
        }

        pruned
    }

    /// Computes the set of live variables using reverse dataflow analysis.
    ///
    /// A variable is considered live if any of the following conditions hold:
    /// 1. It's used by a side-effectful instruction (calls, stores, etc.)
    /// 2. It's used as a return value
    /// 3. It's used as a thrown exception value
    /// 4. It's transitively used by another live variable's definition
    ///
    /// The algorithm uses a two-phase approach:
    /// 1. Mark initial live variables (roots) from side-effectful uses
    /// 2. Propagate liveness backwards through the def-use chain
    ///
    /// # Arguments
    ///
    /// * `ssa` - The SSA function to analyze.
    /// * `reachable` - The set of reachable block indices.
    /// * `rpo` - The blocks in reverse post-order for efficient traversal.
    ///
    /// # Returns
    ///
    /// A set of SSA variable IDs that are live (used by observable operations).
    fn compute_live_variables(
        ssa: &SsaFunction,
        reachable: &HashSet<usize>,
        rpo: &[usize],
    ) -> HashSet<SsaVarId> {
        let mut live = HashSet::new();
        let mut worklist = VecDeque::new();

        // Phase 1: Mark variables used by side-effectful operations as live
        for &block_idx in rpo {
            if !reachable.contains(&block_idx) {
                continue;
            }

            if let Some(block) = ssa.block(block_idx) {
                for instr in block.instructions() {
                    let op = instr.op();
                    // Instructions with side effects make their operands live
                    if !op.is_pure() {
                        for var in op.uses() {
                            if live.insert(var) {
                                worklist.push_back(var);
                            }
                        }
                    }

                    // Return values are live
                    if let SsaOp::Return { value: Some(v) } = op {
                        if live.insert(*v) {
                            worklist.push_back(*v);
                        }
                    }

                    // Thrown exceptions are live
                    if let SsaOp::Throw { exception } = op {
                        if live.insert(*exception) {
                            worklist.push_back(*exception);
                        }
                    }
                }
            }
        }

        // Phase 2: Propagate liveness backwards through definitions
        // Build def-to-uses map for efficiency
        let mut def_uses: HashMap<SsaVarId, Vec<SsaVarId>> = HashMap::new();

        for &block_idx in rpo {
            if !reachable.contains(&block_idx) {
                continue;
            }

            if let Some(block) = ssa.block(block_idx) {
                // Instructions
                for instr in block.instructions() {
                    let op = instr.op();
                    if let Some(def) = op.dest() {
                        for use_var in op.uses() {
                            def_uses.entry(def).or_default().push(use_var);
                        }
                    }
                }

                // Phi nodes
                for phi in block.phi_nodes() {
                    let def = phi.result();
                    for operand in phi.operands() {
                        def_uses.entry(def).or_default().push(operand.value());
                    }
                }
            }
        }

        // Worklist algorithm: if a variable is live, its defining uses are live
        while let Some(var) = worklist.pop_front() {
            // Find what uses were needed to define this variable
            if let Some(uses) = def_uses.get(&var) {
                for &use_var in uses {
                    if live.insert(use_var) {
                        worklist.push_back(use_var);
                    }
                }
            }
        }

        live
    }

    /// Finds dead definitions (pure instructions whose results are never used).
    ///
    /// An instruction is dead if:
    /// 1. It defines a variable that is not in the live set
    /// 2. It has no side effects (is pure)
    ///
    /// Instructions with side effects (calls, stores, etc.) are never considered
    /// dead, even if their result is unused, because removing them would change
    /// program behavior.
    ///
    /// # Arguments
    ///
    /// * `ssa` - The SSA function to analyze.
    /// * `reachable` - The set of reachable block indices.
    /// * `live` - The set of live variable IDs.
    ///
    /// # Returns
    ///
    /// A vector of `(block_idx, instruction_idx)` tuples identifying dead instructions.
    fn find_dead_definitions(
        ssa: &SsaFunction,
        reachable: &HashSet<usize>,
        live: &HashSet<SsaVarId>,
        dead_phi_results: &HashSet<SsaVarId>,
    ) -> Vec<(usize, usize)> {
        // Track dead variables for Pop elimination
        let mut dead_vars: HashSet<SsaVarId> = HashSet::new();
        let mut dead = Vec::new();

        for &block_idx in reachable {
            if let Some(block) = ssa.block(block_idx) {
                for (instr_idx, instr) in block.instructions().iter().enumerate() {
                    let op = instr.op();
                    // Skip instructions with side effects
                    if !op.is_pure() {
                        continue;
                    }

                    // Skip Pop in first pass - handled below
                    if matches!(op, SsaOp::Pop { .. }) {
                        continue;
                    }

                    match op.dest() {
                        None => {
                            // Pure instruction with no dest (like Nop) is always dead
                            dead.push((block_idx, instr_idx));
                        }
                        Some(def) => {
                            if !live.contains(&def) {
                                dead.push((block_idx, instr_idx));
                                dead_vars.insert(def);
                            }
                        }
                    }
                }
            }
        }

        // Second pass: find dead Pop instructions
        // Pop is dead if its operand's definer is being removed in this iteration.
        // Note: We intentionally don't check for definers Nop'd in previous iterations
        // because that can cause stack depth mismatches with complex control flow.
        // The basic check (same-iteration removal) handles the common case correctly.
        for &block_idx in reachable {
            if let Some(block) = ssa.block(block_idx) {
                for (instr_idx, instr) in block.instructions().iter().enumerate() {
                    if let SsaOp::Pop { value } = instr.op() {
                        // Check if operand's definer is being removed this iteration
                        let instr_definer_being_removed = dead_vars.contains(value);
                        let phi_definer_being_removed = dead_phi_results.contains(value);

                        if instr_definer_being_removed || phi_definer_being_removed {
                            dead.push((block_idx, instr_idx));
                        }
                    }
                }
            }
        }

        dead
    }

    /// Finds dead phi nodes (phi nodes whose results are never used).
    ///
    /// A phi node is dead if its result variable is not in the live set.
    /// Unlike regular instructions, phi nodes never have side effects,
    /// so they can always be removed if their result is unused.
    ///
    /// # Arguments
    ///
    /// * `ssa` - The SSA function to analyze.
    /// * `reachable` - The set of reachable block indices.
    /// * `live` - The set of live variable IDs.
    ///
    /// # Returns
    ///
    /// A vector of `(block_idx, phi_idx)` tuples identifying dead phi nodes.
    fn find_dead_phis(
        ssa: &SsaFunction,
        reachable: &HashSet<usize>,
        live: &HashSet<SsaVarId>,
    ) -> Vec<(usize, usize)> {
        let mut dead = Vec::new();

        for &block_idx in reachable {
            if let Some(block) = ssa.block(block_idx) {
                for (phi_idx, phi) in block.phi_nodes().iter().enumerate() {
                    if !live.contains(&phi.result()) {
                        dead.push((block_idx, phi_idx));
                    }
                }
            }
        }

        dead
    }

    /// Removes dead instructions by replacing them with `Nop` operations.
    ///
    /// Instructions are processed in reverse order within each block to preserve
    /// indices during removal. Rather than actually removing instructions (which
    /// would shift indices), this function replaces them with `Nop` operations
    /// to maintain the instruction array structure.
    ///
    /// # Arguments
    ///
    /// * `ssa` - The SSA function to modify.
    /// * `dead_defs` - A slice of `(block_idx, instruction_idx)` tuples identifying
    ///   instructions to remove.
    /// * `method_token` - The metadata token of the method, used for change tracking.
    /// * `changes` - The change set to record modifications in.
    fn remove_instructions(
        ssa: &mut SsaFunction,
        dead_defs: &[(usize, usize)],
        method_token: Token,
        changes: &mut EventLog,
    ) {
        // Group by block
        let mut by_block: HashMap<usize, Vec<usize>> = HashMap::new();
        for &(block_idx, instr_idx) in dead_defs {
            by_block.entry(block_idx).or_default().push(instr_idx);
        }

        for (block_idx, mut indices) in by_block {
            // Sort in reverse order to remove from end first
            indices.sort_by(|a, b| b.cmp(a));

            if let Some(block) = ssa.block_mut(block_idx) {
                for instr_idx in indices {
                    if instr_idx < block.instructions().len() {
                        // Replace with Nop instead of removing to preserve indices
                        // during the same iteration
                        if let Some(instr) = block.instructions_mut().get_mut(instr_idx) {
                            // Log with appropriate message based on instruction type
                            let message = if let Some(dest) = instr.op().dest() {
                                format!("dead definition {dest}")
                            } else {
                                format!("dead {}", instr.mnemonic())
                            };
                            instr.set_op(SsaOp::Nop);
                            changes
                                .record(EventKind::InstructionRemoved)
                                .at(method_token, block_idx * 1000 + instr_idx)
                                .message(message);
                        }
                    }
                }
            }
        }
    }

    /// Removes dead phi nodes from their blocks.
    ///
    /// Phi nodes are processed in reverse order within each block to preserve
    /// indices during removal. Unlike instructions, phi nodes are actually
    /// removed from the block rather than replaced with a placeholder.
    ///
    /// # Arguments
    ///
    /// * `ssa` - The SSA function to modify.
    /// * `dead_phis` - A slice of `(block_idx, phi_idx)` tuples identifying phi nodes
    ///   to remove.
    /// * `method_token` - The metadata token of the method, used for change tracking.
    /// * `changes` - The change set to record modifications in.
    fn remove_phis(
        ssa: &mut SsaFunction,
        dead_phis: &[(usize, usize)],
        method_token: Token,
        changes: &mut EventLog,
    ) {
        // Group by block
        let mut by_block: HashMap<usize, Vec<usize>> = HashMap::new();
        for &(block_idx, phi_idx) in dead_phis {
            by_block.entry(block_idx).or_default().push(phi_idx);
        }

        for (block_idx, mut indices) in by_block {
            // Sort in reverse order
            indices.sort_by(|a, b| b.cmp(a));

            if let Some(block) = ssa.block_mut(block_idx) {
                for phi_idx in indices {
                    if phi_idx < block.phi_nodes().len() {
                        block.phi_nodes_mut().remove(phi_idx);
                        changes
                            .record(EventKind::PhiSimplified)
                            .at(method_token, block_idx)
                            .message("removed dead phi node");
                    }
                }
            }
        }
    }

    /// Simplifies trivial phi nodes by performing copy propagation.
    ///
    /// For each trivial phi identified by [`PhiAnalyzer::find_all_trivial`]:
    /// - If a replacement value is provided, the phi is converted to a copy and
    ///   all uses of the phi's result are replaced with the replacement value.
    /// - If no replacement value is provided (fully self-referential phi), the
    ///   phi is simply removed as it represents undefined/unreachable code.
    ///
    /// Phi nodes are processed in reverse order within each block to preserve
    /// indices during modification.
    ///
    /// # Arguments
    ///
    /// * `ssa` - The SSA function to modify.
    /// * `trivial_phis` - A slice of `(block_idx, phi_idx, replacement)` tuples
    ///   from [`PhiAnalyzer::find_all_trivial`].
    /// * `method_token` - The metadata token of the method, used for change tracking.
    /// * `changes` - The change set to record modifications in.
    ///
    /// # Returns
    ///
    /// The number of phi nodes that were simplified.
    fn simplify_trivial_phis(
        ssa: &mut SsaFunction,
        trivial_phis: &[(usize, usize, Option<SsaVarId>)],
        method_token: Token,
        changes: &mut EventLog,
    ) -> usize {
        let mut simplified = 0;

        // Process in reverse order by phi_idx within each block
        let mut by_block: HashMap<usize, Vec<(usize, Option<SsaVarId>)>> = HashMap::new();
        for &(block_idx, phi_idx, replacement) in trivial_phis {
            by_block
                .entry(block_idx)
                .or_default()
                .push((phi_idx, replacement));
        }

        for (block_idx, mut phis) in by_block {
            // Sort by phi_idx in reverse order
            phis.sort_by(|a, b| b.0.cmp(&a.0));

            for (phi_idx, replacement) in phis {
                if let Some(replacement_var) = replacement {
                    // Use the existing simplify_phi_to_copy which handles use replacement
                    if ssa.simplify_phi_to_copy(block_idx, phi_idx, replacement_var) {
                        changes
                            .record(EventKind::PhiSimplified)
                            .at(method_token, block_idx)
                            .message(format!("replaced with {replacement_var}"));
                        simplified += 1;
                    }
                } else {
                    // All self-references - just remove the phi
                    if ssa.remove_phi_unchecked(block_idx, phi_idx) {
                        changes
                            .record(EventKind::PhiSimplified)
                            .at(method_token, block_idx)
                            .message("removed self-referential phi");
                        simplified += 1;
                    }
                }
            }
        }

        simplified
    }

    /// Clears all instructions and phi nodes from unreachable blocks.
    ///
    /// Unreachable blocks are emptied rather than removed to preserve block indices
    /// throughout the SSA graph. This is important because branch targets and phi
    /// operand predecessors reference blocks by index.
    ///
    /// # Arguments
    ///
    /// * `ssa` - The SSA function to modify.
    /// * `reachable` - The set of reachable block indices.
    /// * `method_token` - The metadata token of the method, used for change tracking.
    /// * `changes` - The change set to record modifications in.
    ///
    /// # Returns
    ///
    /// The number of blocks that were cleared.
    fn clear_unreachable_blocks(
        ssa: &mut SsaFunction,
        reachable: &HashSet<usize>,
        method_token: Token,
        changes: &mut EventLog,
    ) -> usize {
        let mut cleared = 0;
        let total_blocks = ssa.block_count();

        for block_idx in 0..total_blocks {
            if !reachable.contains(&block_idx) {
                if let Some(block) = ssa.block_mut(block_idx) {
                    if !block.is_empty() {
                        block.clear();
                        changes
                            .record(EventKind::BlockRemoved)
                            .at(method_token, block_idx)
                            .message(format!("removed unreachable block {block_idx}"));
                        cleared += 1;
                    }
                }
            }
        }

        cleared
    }

    /// Finds instructions without SSA operations (stack simulation artifacts).
    ///
    /// During SSA construction, some CIL instructions (like `ldloc`, `ldarg`) don't
    /// create new SSA definitions - they just read existing variables. These instructions
    /// remain in the instruction list with `op = None` but serve no purpose in SSA form.
    ///
    /// This function identifies such instructions for removal. Only non-terminator
    /// instructions without an SSA operation are considered dead.
    ///
    /// # Arguments
    ///
    /// * `ssa` - The SSA function to analyze.
    /// * `reachable` - The set of reachable block indices.
    ///
    /// # Returns
    ///
    /// A vector of `(block_idx, instruction_idx)` tuples identifying op-less instructions.
    fn find_opless_instructions(
        ssa: &SsaFunction,
        reachable: &HashSet<usize>,
    ) -> Vec<(usize, usize)> {
        let mut opless = Vec::new();

        for &block_idx in reachable {
            if let Some(block) = ssa.block(block_idx) {
                let instr_count = block.instructions().len();
                for (instr_idx, instr) in block.instructions().iter().enumerate() {
                    // Skip the last instruction if it might be a terminator
                    // (terminators should always have an op, but be safe)
                    let is_last = instr_idx == instr_count.saturating_sub(1);

                    // An instruction with Nop op is a stack simulation artifact
                    if matches!(instr.op(), SsaOp::Nop) {
                        // Don't remove the last instruction if the block would become empty
                        // (this preserves block structure for terminators)
                        if !is_last || instr_count > 1 {
                            opless.push((block_idx, instr_idx));
                        }
                    }
                }
            }
        }

        opless
    }

    /// Removes op-less instructions (stack simulation artifacts).
    ///
    /// These instructions have no SSA operation and serve no purpose after
    /// SSA construction. They are removed by actually deleting them from the
    /// instruction list rather than replacing with Nop.
    ///
    /// # Arguments
    ///
    /// * `ssa` - The SSA function to modify.
    /// * `opless` - A slice of `(block_idx, instruction_idx)` tuples.
    /// * `method_token` - The metadata token of the method.
    /// * `changes` - The change set to record modifications.
    ///
    /// # Returns
    ///
    /// The number of instructions removed.
    fn remove_opless_instructions(
        ssa: &mut SsaFunction,
        opless: &[(usize, usize)],
        method_token: Token,
        changes: &mut EventLog,
    ) -> usize {
        if opless.is_empty() {
            return 0;
        }

        // Group by block
        let mut by_block: HashMap<usize, Vec<usize>> = HashMap::new();
        for &(block_idx, instr_idx) in opless {
            by_block.entry(block_idx).or_default().push(instr_idx);
        }

        let mut removed = 0;

        for (block_idx, mut indices) in by_block {
            // Sort in reverse order to remove from end first (preserves indices)
            indices.sort_by(|a, b| b.cmp(a));

            if let Some(block) = ssa.block_mut(block_idx) {
                for instr_idx in indices {
                    if instr_idx < block.instructions().len() {
                        // Get mnemonic for logging before removal
                        let mnemonic = block
                            .instructions()
                            .get(instr_idx)
                            .map_or("unknown", SsaInstruction::mnemonic);

                        block.instructions_mut().remove(instr_idx);
                        changes
                            .record(EventKind::InstructionRemoved)
                            .at(method_token, block_idx * 1000 + instr_idx)
                            .message(format!("removed op-less instruction: {mnemonic}"));
                        removed += 1;
                    }
                }
            }
        }

        removed
    }

    /// Removes all Nop instructions from reachable blocks.
    ///
    /// Nop instructions are dead code that should be removed to simplify
    /// the CFG. This is done before block merging so trampolines can be
    /// properly detected.
    ///
    /// # Arguments
    ///
    /// * `ssa` - The SSA function to modify.
    /// * `reachable` - Set of reachable block indices.
    /// * `method_token` - The method token for change tracking.
    /// * `changes` - Event log for recording changes.
    ///
    /// # Returns
    ///
    /// The number of Nop instructions removed.
    fn remove_nop_instructions(
        ssa: &mut SsaFunction,
        reachable: &HashSet<usize>,
        method_token: Token,
        changes: &mut EventLog,
    ) -> usize {
        let mut removed = 0;

        for &block_idx in reachable {
            if let Some(block) = ssa.block_mut(block_idx) {
                let original_len = block.instructions().len();
                block
                    .instructions_mut()
                    .retain(|instr| !matches!(instr.op(), SsaOp::Nop));
                let new_len = block.instructions().len();
                let nops_removed = original_len - new_len;

                if nops_removed > 0 {
                    changes
                        .record(EventKind::InstructionRemoved)
                        .at(method_token, block_idx)
                        .message(format!("removed {nops_removed} Nop instructions"));
                    removed += nops_removed;
                }
            }
        }

        removed
    }

    /// Runs a single iteration of the dead code elimination algorithm.
    ///
    /// Each iteration performs the following steps:
    /// 1. Find reachable blocks from entry and exception handlers
    /// 2. Clear unreachable blocks
    /// 3. Remove op-less instructions (stack simulation artifacts)
    /// 4. Remove Nop instructions
    /// 5. Prune phi operands from unreachable predecessors
    /// 6. Find and simplify trivial phi nodes
    /// 7. Recompute reachability (may change after phi simplification)
    /// 8. Compute liveness via reverse dataflow
    /// 9. Remove dead phi nodes
    /// 10. Remove dead definitions
    ///
    /// The algorithm is run iteratively until no more changes are made (fixed point).
    ///
    /// # Arguments
    ///
    /// * `ssa` - The SSA function to modify.
    /// * `method_token` - The metadata token of the method, used for change tracking.
    /// * `changes` - The change set to record modifications in.
    ///
    /// # Returns
    ///
    /// The total number of changes made during this iteration. Zero indicates
    /// the algorithm has reached a fixed point.
    fn run_iteration(ssa: &mut SsaFunction, method_token: Token, changes: &mut EventLog) -> usize {
        let mut total_changes = 0;

        // Step 1: Find reachable blocks
        let reachable = Self::find_reachable_blocks(ssa);

        // Step 2: Clear unreachable blocks
        total_changes += Self::clear_unreachable_blocks(ssa, &reachable, method_token, changes);

        // Step 3: Remove op-less instructions (stack simulation artifacts like ldloc/ldarg
        // that weren't decomposed to SSA operations)
        let opless = Self::find_opless_instructions(ssa, &reachable);
        total_changes += Self::remove_opless_instructions(ssa, &opless, method_token, changes);

        // Step 4: Remove Nop instructions (simplifies CFG for block merging)
        total_changes += Self::remove_nop_instructions(ssa, &reachable, method_token, changes);

        // Step 5: Prune phi operands from unreachable predecessors
        total_changes += Self::prune_phi_operands(ssa, &reachable);

        // Step 6: Find and simplify trivial phis (doesn't need liveness)
        // Trivial phis are identified purely by structure (all operands same or self-referential)
        let trivial_phis = PhiAnalyzer::new(ssa).find_all_trivial(&reachable);
        total_changes += Self::simplify_trivial_phis(ssa, &trivial_phis, method_token, changes);

        // Step 7: Recompute reachability after phi simplification
        let reachable = Self::find_reachable_blocks(ssa);

        // Step 8: Compute reverse post-order and liveness for dead code analysis
        let rpo = Self::compute_reverse_postorder(ssa, &reachable);
        let live = Self::compute_live_variables(ssa, &reachable, &rpo);

        // Step 9: Find and remove dead phi nodes (unused results)
        let dead_phis = Self::find_dead_phis(ssa, &reachable, &live);

        // Collect dead phi results for Pop elimination
        let dead_phi_results: HashSet<SsaVarId> = dead_phis
            .iter()
            .filter_map(|&(block_idx, phi_idx)| {
                ssa.block(block_idx)
                    .and_then(|b| b.phi_nodes().get(phi_idx))
                    .map(PhiNode::result)
            })
            .collect();

        Self::remove_phis(ssa, &dead_phis, method_token, changes);
        total_changes += dead_phis.len();

        // Step 10: Find and remove dead definitions (pure ops with unused results)
        let dead_defs = Self::find_dead_definitions(ssa, &reachable, &live, &dead_phi_results);
        Self::remove_instructions(ssa, &dead_defs, method_token, changes);
        total_changes += dead_defs.len();

        total_changes
    }
}

impl SsaPass for DeadCodeEliminationPass {
    fn name(&self) -> &'static str {
        "dead-code-elimination"
    }

    fn description(&self) -> &'static str {
        "Eliminates unreachable code and unused definitions"
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

        // After removing dead instructions and phis, compact the variable table
        // to remove orphaned variable entries
        let compacted = ssa.compact_variables();
        if compacted > 0 {
            changes
                .record(EventKind::VariablesCompacted)
                .at(method_token, compacted)
                .message(format!("removed {compacted} orphaned variables"));
        }

        let changed = !changes.is_empty();
        if changed {
            ctx.events.merge(&changes);
        }
        Ok(changed)
    }
}

/// Global dead method elimination pass.
///
/// This pass operates at the assembly level to identify and mark methods that
/// are never called and are not entry points. Unlike [`DeadCodeEliminationPass`]
/// which operates within a single method, this pass analyzes the call graph
/// across the entire assembly.
///
/// # Algorithm
///
/// The pass uses a worklist algorithm starting from entry points:
/// 1. Initialize the live set with all entry point methods
/// 2. For each live method, add all its callees to the worklist
/// 3. Continue until the worklist is empty
/// 4. Mark all methods not in the live set as dead
///
/// # Entry Points
///
/// Entry points typically include:
/// - The `Main` method
/// - Event handlers
/// - Methods invoked via reflection
/// - Virtual method implementations that may be called polymorphically
pub struct DeadMethodEliminationPass;

impl Default for DeadMethodEliminationPass {
    fn default() -> Self {
        Self::new()
    }
}

impl DeadMethodEliminationPass {
    /// Creates a new dead method elimination pass.
    ///
    /// # Returns
    ///
    /// A new instance of `DeadMethodEliminationPass`.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl SsaPass for DeadMethodEliminationPass {
    fn name(&self) -> &'static str {
        "dead-method-elimination"
    }

    fn is_global(&self) -> bool {
        true
    }

    fn description(&self) -> &'static str {
        "Identifies methods that are never called"
    }

    fn run_on_method(
        &self,
        _ssa: &mut SsaFunction,
        _method_token: Token,
        _ctx: &CompilerContext,
        _assembly: &Arc<CilObject>,
    ) -> Result<bool> {
        // This is a global pass, so run_on_method is not used
        Ok(false)
    }

    fn run_global(&self, ctx: &CompilerContext, _assembly: &Arc<CilObject>) -> Result<bool> {
        let changes = EventLog::new();

        // Build a live call graph from actual SSA calls (not the static call graph).
        // This accounts for inlining and other transformations that may have removed calls.
        let mut ssa_callees: HashMap<Token, HashSet<Token>> = HashMap::new();
        for entry in &ctx.ssa_functions {
            let caller_token = *entry.key();
            let ssa = entry.value();
            let mut callees = HashSet::new();
            for block in ssa.blocks() {
                for instr in block.instructions() {
                    match instr.op() {
                        SsaOp::Call { method, .. }
                        | SsaOp::CallVirt { method, .. }
                        | SsaOp::LoadFunctionPtr { method, .. }
                        | SsaOp::LoadVirtFunctionPtr { method, .. } => {
                            callees.insert(method.token());
                        }
                        SsaOp::NewObj { ctor, .. } => {
                            callees.insert(ctor.token());
                        }
                        _ => {}
                    }
                }
            }
            ssa_callees.insert(caller_token, callees);
        }

        // Methods that are definitely live (entry points and their transitive callees)
        let mut live_methods: HashSet<Token> = ctx.entry_points.iter().map(|e| *e).collect();
        let mut worklist: VecDeque<Token> = live_methods.iter().copied().collect();

        // Mark transitive callees as live using SSA-derived call information
        while let Some(method) = worklist.pop_front() {
            // Use SSA callees if available, otherwise fall back to call graph
            let callees = if let Some(ssa_calls) = ssa_callees.get(&method) {
                ssa_calls.iter().copied().collect::<Vec<_>>()
            } else {
                ctx.call_graph.callees(method)
            };

            for callee in callees {
                if !live_methods.contains(&callee) {
                    live_methods.insert(callee);
                    worklist.push_back(callee);
                }
            }
        }

        // Mark all methods not in live set as dead
        for method in ctx.all_methods() {
            if !live_methods.contains(&method) && !ctx.is_dead(method) {
                ctx.mark_dead(method);
                changes
                    .record(EventKind::MethodMarkedDead)
                    .method(method)
                    .message("method has no live callers");
            }
        }

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

    use super::*;
    use crate::analysis::{
        CallGraph, ConstValue, DefSite, PhiNode, PhiOperand, SsaBlock, SsaFunction,
        SsaFunctionBuilder, SsaInstruction, SsaOp, SsaVariable, VariableOrigin,
    };
    use crate::test::helpers::test_assembly_arc;

    // Helper to create a minimal analysis context for testing
    fn test_context() -> CompilerContext {
        let call_graph = Arc::new(CallGraph::new());
        CompilerContext::new(call_graph)
    }

    #[test]
    fn test_successor_extraction() {
        // Test jump
        let op = SsaOp::Jump { target: 5 };
        assert_eq!(op.successors(), vec![5]);

        // Test branch
        let cond = SsaVarId::new();
        let op = SsaOp::Branch {
            condition: cond,
            true_target: 1,
            false_target: 2,
        };
        assert_eq!(op.successors(), vec![1, 2]);

        // Test switch
        let val = SsaVarId::new();
        let op = SsaOp::Switch {
            value: val,
            targets: vec![1, 2, 3],
            default: 4,
        };
        assert_eq!(op.successors(), vec![1, 2, 3, 4]);

        // Test return (no successors)
        let op = SsaOp::Return { value: None };
        assert!(op.successors().is_empty());

        // Test leave
        let op = SsaOp::Leave { target: 3 };
        assert_eq!(op.successors(), vec![3]);
    }

    #[test]
    fn test_empty_function() {
        let ssa = SsaFunction::new(0, 0);

        let reachable = DeadCodeEliminationPass::find_reachable_blocks(&ssa);
        assert!(reachable.is_empty());
    }

    #[test]
    fn test_single_block_reachable() {
        let ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
            f.block(0, |b| b.ret());
        });

        let reachable = DeadCodeEliminationPass::find_reachable_blocks(&ssa);
        assert_eq!(reachable.len(), 1);
        assert!(reachable.contains(&0));
    }

    #[test]
    fn test_unreachable_block_detection() {
        let ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
            // Block 0: entry, jumps to block 1
            f.block(0, |b| b.jump(1));
            // Block 1: reachable from block 0
            f.block(1, |b| b.ret());
            // Block 2: unreachable
            f.block(2, |b| b.ret());
        });

        let reachable = DeadCodeEliminationPass::find_reachable_blocks(&ssa);
        assert_eq!(reachable.len(), 2);
        assert!(reachable.contains(&0));
        assert!(reachable.contains(&1));
        assert!(!reachable.contains(&2));
    }

    #[test]
    fn test_cascading_dead_code() {
        // Test that iterative DCE removes cascading dead definitions:
        // v1 = 5       (dead after v2 removed)
        // v2 = v1 + 3  (dead after v3 removed)
        // v3 = v2 * 2  (dead - unused)
        // return
        let mut ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
            f.block(0, |b| {
                let v1 = b.const_i32(5);
                let three = b.const_i32(3);
                let v2 = b.add(v1, three);
                let two = b.const_i32(2);
                let _ = b.mul(v2, two);
                b.ret(); // return (no value - nothing is live)
            });
        });

        // Run DCE
        let pass = DeadCodeEliminationPass::new();
        let ctx = test_context();
        let changed = pass
            .run_on_method(&mut ssa, Token::new(0x06000001), &ctx, &test_assembly_arc())
            .unwrap();

        // All pure operations should be marked as dead
        assert!(changed);

        // Only the return should remain as non-Nop
        let block = ssa.block(0).unwrap();
        let non_nop_count = block
            .instructions()
            .iter()
            .filter(|i| !matches!(i.op(), SsaOp::Nop))
            .count();

        assert_eq!(non_nop_count, 1); // Only return
    }

    #[test]
    fn test_dead_phi_elimination() {
        // Test that unused phi nodes are removed
        let mut ssa = {
            let mut v1_out = SsaVarId::new();
            let mut v2_out = SsaVarId::new();
            SsaFunctionBuilder::new(0, 0).build_with(|f| {
                // Block 0: entry, branch
                f.block(0, |b| {
                    let cond = b.const_true();
                    b.branch(cond, 1, 2);
                });
                // Block 1: defines v1
                f.block(1, |b| {
                    v1_out = b.const_i32(10);
                    b.jump(3);
                });
                // Block 2: defines v2
                f.block(2, |b| {
                    v2_out = b.const_i32(20);
                    b.jump(3);
                });
                // Block 3: merge with phi (but result is unused!)
                f.block(3, |b| {
                    let _ = b.phi(&[(1, v1_out), (2, v2_out)]);
                    b.ret(); // Phi result not used!
                });
            })
        };

        // Run DCE
        let pass = DeadCodeEliminationPass::new();
        let ctx = test_context();
        let _changes = pass
            .run_on_method(&mut ssa, Token::new(0x06000001), &ctx, &test_assembly_arc())
            .unwrap();

        // The phi should be removed since its result is never used
        let block3 = ssa.block(3).unwrap();
        assert_eq!(block3.phi_nodes().len(), 0);
    }

    #[test]
    fn test_trivial_phi_single_operand() {
        // Test that phi with single operand is simplified
        let (mut ssa, v1) = {
            let mut v1_out = SsaVarId::new();
            let ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
                // Block 0: defines v1, jumps to block 1
                f.block(0, |b| {
                    v1_out = b.const_i32(42);
                    b.jump(1);
                });
                // Block 1: phi with single operand (trivial)
                f.block(1, |b| {
                    let phi_result = b.phi(&[(0, v1_out)]);
                    b.ret_val(phi_result);
                });
            });
            (ssa, v1_out)
        };

        // Run DCE
        let pass = DeadCodeEliminationPass::new();
        let ctx = test_context();
        let _changes = pass
            .run_on_method(&mut ssa, Token::new(0x06000001), &ctx, &test_assembly_arc())
            .unwrap();

        // Phi should be simplified - uses of phi_result should be replaced with v1
        let block1 = ssa.block(1).unwrap();
        assert_eq!(block1.phi_nodes().len(), 0);

        // Return should now use v1
        if let Some(SsaOp::Return { value }) = block1.terminator_op() {
            assert_eq!(*value, Some(v1));
        }
    }

    #[test]
    fn test_trivial_phi_all_same() {
        // Test that phi where all operands are the same is simplified
        let (mut ssa, v1) = {
            let mut v1_out = SsaVarId::new();
            let ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
                // Block 0: entry, branch
                f.block(0, |b| {
                    let cond = b.const_true();
                    v1_out = b.const_i32(42);
                    b.branch(cond, 1, 2);
                });
                // Block 1: jumps to merge
                f.block(1, |b| b.jump(3));
                // Block 2: jumps to merge
                f.block(2, |b| b.jump(3));
                // Block 3: phi with all same operands (both from v1)
                f.block(3, |b| {
                    let phi_result = b.phi(&[(1, v1_out), (2, v1_out)]);
                    b.ret_val(phi_result);
                });
            });
            (ssa, v1_out)
        };

        // Run DCE
        let pass = DeadCodeEliminationPass::new();
        let ctx = test_context();
        let _changes = pass
            .run_on_method(&mut ssa, Token::new(0x06000001), &ctx, &test_assembly_arc())
            .unwrap();

        // Phi should be simplified
        let block3 = ssa.block(3).unwrap();
        assert_eq!(block3.phi_nodes().len(), 0);

        // Return should now use v1
        if let Some(SsaOp::Return { value }) = block3.terminator_op() {
            assert_eq!(*value, Some(v1));
        }
    }

    #[test]
    fn test_self_referential_phi() {
        // Test phi like phi_var = phi(phi_var, v2) simplifies to phi_var = v2
        // We need to manually construct this since the builder can't create self-references
        let mut ssa = SsaFunction::new(0, 0);

        // Create variables (auto-allocates IDs)
        let v2_var = SsaVariable::new(VariableOrigin::Stack(0), 0, DefSite::instruction(0, 0));
        let v2 = v2_var.id();
        ssa.add_variable(v2_var);

        let phi_variable = SsaVariable::new(VariableOrigin::Stack(1), 0, DefSite::phi(1));
        let phi_var = phi_variable.id();
        ssa.add_variable(phi_variable);

        // Block 0: entry, defines v2, jumps to block 1
        let mut block0 = SsaBlock::new(0);
        block0.add_instruction(SsaInstruction::synthetic(SsaOp::Const {
            dest: v2,
            value: ConstValue::I32(42),
        }));
        block0.add_instruction(SsaInstruction::synthetic(SsaOp::Jump { target: 1 }));
        ssa.add_block(block0);

        // Block 1: loop header with self-referential phi
        // phi_var = phi(v2 from block 0, phi_var from block 1)
        let mut block1 = SsaBlock::new(1);
        let mut phi = PhiNode::new(phi_var, VariableOrigin::Stack(1));
        phi.add_operand(PhiOperand::new(v2, 0)); // from block 0
        phi.add_operand(PhiOperand::new(phi_var, 1)); // from block 1 (self-reference)
        block1.add_phi(phi);
        block1.add_instruction(SsaInstruction::synthetic(SsaOp::Return {
            value: Some(phi_var),
        }));
        ssa.add_block(block1);

        // Run DCE
        let pass = DeadCodeEliminationPass::new();
        let ctx = test_context();
        let _changes = pass
            .run_on_method(&mut ssa, Token::new(0x06000001), &ctx, &test_assembly_arc())
            .unwrap();

        // Phi should be simplified - phi_var = phi(v2, phi_var) becomes phi_var = v2
        let block1 = ssa.block(1).unwrap();
        assert_eq!(block1.phi_nodes().len(), 0);

        // Return should now use v2
        if let Some(SsaOp::Return { value }) = block1.terminator_op() {
            assert_eq!(*value, Some(v2));
        }
    }

    #[test]
    fn test_phi_operand_pruning() {
        // Test that phi operands from unreachable blocks are pruned
        let mut ssa = {
            let mut v1_out = SsaVarId::new();
            let mut v2_out = SsaVarId::new();
            SsaFunctionBuilder::new(0, 0).build_with(|f| {
                // Block 0: entry, always jumps to block 1 (block 2 is unreachable)
                f.block(0, |b| {
                    v1_out = b.const_i32(10);
                    b.jump(1); // Always goes to 1
                });
                // Block 1: reachable merge
                f.block(1, |b| {
                    let phi_result = b.phi(&[(0, v1_out), (2, v2_out)]); // v2 from unreachable block 2
                    b.ret_val(phi_result);
                });
                // Block 2: unreachable
                f.block(2, |b| {
                    v2_out = b.const_i32(20);
                    b.jump(1);
                });
            })
        };

        // Run DCE
        let pass = DeadCodeEliminationPass::new();
        let ctx = test_context();
        let _changes = pass
            .run_on_method(&mut ssa, Token::new(0x06000001), &ctx, &test_assembly_arc())
            .unwrap();

        // Block 2 should be cleared
        let block2 = ssa.block(2).unwrap();
        assert!(block2.instructions().is_empty());

        // Phi in block 1 should be simplified (only one valid operand after pruning)
        let block1 = ssa.block(1).unwrap();
        // After pruning, the phi becomes trivial and should be simplified
        assert_eq!(block1.phi_nodes().len(), 0);
    }

    #[test]
    fn test_side_effect_preservation() {
        // Test that side-effectful operations are not removed
        let (mut ssa, v1) = {
            let mut v1_out = SsaVarId::new();
            let ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
                f.block(0, |b| {
                    // v1 = some value (will be used by call)
                    v1_out = b.const_i32(42);
                    // Call (side effect - should not be removed even if result unused)
                    let method = crate::analysis::MethodRef::new(Token::new(0x06000002));
                    let _ = b.call(method, &[v1_out]);
                    // Return without using call result
                    b.ret();
                });
            });
            (ssa, v1_out)
        };

        // Run DCE
        let pass = DeadCodeEliminationPass::new();
        let ctx = test_context();
        let _changes = pass
            .run_on_method(&mut ssa, Token::new(0x06000001), &ctx, &test_assembly_arc())
            .unwrap();

        // Call should still be there (side effect)
        let block = ssa.block(0).unwrap();
        let has_call = block
            .instructions()
            .iter()
            .any(|i| matches!(i.op(), SsaOp::Call { .. }));
        assert!(has_call);

        // v1 should also be preserved (used by call)
        let has_const = block
            .instructions()
            .iter()
            .any(|i| matches!(i.op(), SsaOp::Const { dest, .. } if *dest == v1));
        assert!(has_const);
    }

    #[test]
    fn test_reverse_postorder() {
        // Create a diamond CFG: 0 -> {1, 2} -> 3
        let ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
            f.block(0, |b| {
                let cond = b.const_true();
                b.branch(cond, 1, 2);
            });
            f.block(1, |b| b.jump(3));
            f.block(2, |b| b.jump(3));
            f.block(3, |b| b.ret());
        });

        let reachable = DeadCodeEliminationPass::find_reachable_blocks(&ssa);
        let rpo = DeadCodeEliminationPass::compute_reverse_postorder(&ssa, &reachable);

        // RPO should have entry first, exit last
        assert_eq!(rpo[0], 0); // Entry
        assert_eq!(*rpo.last().unwrap(), 3); // Exit (merge point)
        assert_eq!(rpo.len(), 4);
    }

    #[test]
    fn test_live_variable_computation() {
        let (ssa, v1, v2) = {
            let mut v1_out = SsaVarId::new();
            let mut v2_out = SsaVarId::new();
            let ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
                f.block(0, |b| {
                    // v1 = 10 (live - used by return)
                    v1_out = b.const_i32(10);
                    // v2 = 20 (dead - not used)
                    v2_out = b.const_i32(20);
                    // return v1
                    b.ret_val(v1_out);
                });
            });
            (ssa, v1_out, v2_out)
        };

        let reachable = DeadCodeEliminationPass::find_reachable_blocks(&ssa);
        let rpo = DeadCodeEliminationPass::compute_reverse_postorder(&ssa, &reachable);
        let live = DeadCodeEliminationPass::compute_live_variables(&ssa, &reachable, &rpo);

        assert!(live.contains(&v1)); // v1 is live (returned)
        assert!(!live.contains(&v2)); // v2 is dead
    }

    #[test]
    fn test_transitive_liveness() {
        // Test that liveness propagates transitively
        // v1 = 5
        // v2 = v1 + 1
        // v3 = v2 * 2
        // return v3
        // All should be live!

        let (ssa, v1, v2, v3, c1, c2) = {
            let mut v1_out = SsaVarId::new();
            let mut v2_out = SsaVarId::new();
            let mut v3_out = SsaVarId::new();
            let mut c1_out = SsaVarId::new();
            let mut c2_out = SsaVarId::new();
            let ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
                f.block(0, |b| {
                    v1_out = b.const_i32(5);
                    c1_out = b.const_i32(1);
                    v2_out = b.add(v1_out, c1_out);
                    c2_out = b.const_i32(2);
                    v3_out = b.mul(v2_out, c2_out);
                    b.ret_val(v3_out);
                });
            });
            (ssa, v1_out, v2_out, v3_out, c1_out, c2_out)
        };

        let reachable = DeadCodeEliminationPass::find_reachable_blocks(&ssa);
        let rpo = DeadCodeEliminationPass::compute_reverse_postorder(&ssa, &reachable);
        let live = DeadCodeEliminationPass::compute_live_variables(&ssa, &reachable, &rpo);

        // All should be live transitively
        assert!(live.contains(&v1));
        assert!(live.contains(&v2));
        assert!(live.contains(&v3));
        assert!(live.contains(&c1));
        assert!(live.contains(&c2));
    }

    #[test]
    fn test_iterative_convergence() {
        // Test that the algorithm converges (doesn't infinite loop)
        let mut ssa = {
            let mut v0_out = SsaVarId::new();
            let mut phi_out = SsaVarId::new();
            SsaFunctionBuilder::new(0, 0).build_with(|f| {
                // Create a loop structure
                f.block(0, |b| {
                    v0_out = b.const_i32(0);
                    b.jump(1);
                });
                f.block(1, |b| {
                    // phi: from entry (v0) and from back edge (v2)
                    phi_out = b.phi(&[(0, v0_out), (1, phi_out)]);
                    // v2 = phi + 1 (unused, becomes back edge value)
                    let one = b.const_i32(1);
                    let _ = b.add(phi_out, one);
                    // Condition to exit loop
                    let cond = b.const_true();
                    b.branch(cond, 2, 1);
                });
                f.block(2, |b| b.ret());
            })
        };

        // Run DCE - should converge
        let pass = DeadCodeEliminationPass::new();
        let ctx = test_context();
        let result =
            pass.run_on_method(&mut ssa, Token::new(0x06000001), &ctx, &test_assembly_arc());

        assert!(result.is_ok());
    }
}
