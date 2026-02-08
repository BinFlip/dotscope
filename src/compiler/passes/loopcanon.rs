//! Loop canonicalization pass.
//!
//! This pass transforms loops into canonical form to enable more effective
//! analysis and optimization. Canonical loops have:
//!
//! - **Single preheader**: A unique block that dominates the loop header and
//!   through which all loop entries pass
//! - **Single latch**: A unique back edge source block
//!
//! # Why Canonicalization Matters
//!
//! Many loop optimizations (loop-invariant code motion, induction variable
//! analysis, loop unrolling) require loops to be in canonical form:
//!
//! ```text
//! Non-canonical:                    Canonical:
//!
//!     A       B                         A       B
//!      \     /                           \     /
//!       \   /                             \   /
//!        v v                               v v
//!     [header]  <--+                  [preheader]
//!         |       |                        |
//!         v       |                        v
//!      [body]     |                   [header]  <--+
//!        / \      |                       |        |
//!       v   \     |                       v        |
//!    [exit] [latch1]                   [body]      |
//!             |   |                      / \       |
//!             |   |                     v   \      |
//!          [latch2]                  [exit] [latch]
//!                                              |
//!                                              +---+
//! ```
//!
//! # Transformations
//!
//! ## Preheader Insertion
//!
//! When a loop header has multiple non-loop predecessors, we insert a preheader:
//!
//! 1. Create a new block with a jump to the header
//! 2. Redirect all non-loop predecessors to the preheader
//! 3. Update phi nodes in the header to receive values from the preheader
//!
//! ## Latch Unification
//!
//! When a loop has multiple back edges (latches), we unify them:
//!
//! 1. Create a new unified latch block with a jump to the header
//! 2. Redirect all original latches to the unified latch
//! 3. Insert phi nodes in the unified latch to merge values from original latches
//! 4. Update phi nodes in the header to receive from the unified latch
//!
//! # Phi Node Handling
//!
//! The pass carefully maintains SSA form by:
//! - Splitting phi operands when inserting preheaders
//! - Merging phi operands when unifying latches
//! - Creating new phi nodes where necessary to preserve value flow

use std::{collections::HashMap, sync::Arc};

use crate::{
    analysis::{
        LoopInfo, PhiNode, PhiOperand, SsaBlock, SsaFunction, SsaInstruction, SsaLoopAnalysis,
        SsaOp, SsaVarId, VariableOrigin,
    },
    compiler::{pass::SsaPass, CompilerContext, EventKind, EventLog},
    metadata::token::Token,
    utils::graph::NodeId,
    CilObject, Result,
};

/// Loop canonicalization pass.
///
/// Transforms loops into canonical form with single preheaders and single latches.
/// This enables more effective loop analysis and optimization.
///
/// # Example
///
/// ```rust,ignore
/// use dotscope::compiler::LoopCanonicalizationPass;
///
/// let pass = LoopCanonicalizationPass::new();
/// let changes = pass.run_on_method(&mut ssa, method_token, &ctx)?;
/// ```
pub struct LoopCanonicalizationPass;

impl Default for LoopCanonicalizationPass {
    fn default() -> Self {
        Self::new()
    }
}

impl LoopCanonicalizationPass {
    /// Creates a new loop canonicalization pass.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Canonicalizes all loops in the SSA function.
    ///
    /// Returns the number of loops that were modified.
    fn canonicalize_loops(
        ssa: &mut SsaFunction,
        method_token: Token,
        changes: &mut EventLog,
    ) -> usize {
        let mut total_modified = 0;

        // We need to iterate until no more changes because inserting blocks
        // can affect loop structure
        loop {
            let forest = ssa.analyze_loops();

            if forest.is_empty() {
                break;
            }

            let mut modified_this_iteration = 0;

            // Process loops from innermost to outermost to avoid invalidating
            // parent loop analysis when modifying inner loops
            for loop_info in forest.by_depth_descending() {
                // Check if this loop needs a preheader
                if !loop_info.has_preheader() {
                    let non_loop_preds = Self::get_non_loop_predecessors(ssa, loop_info);
                    if non_loop_preds.len() > 1 {
                        Self::insert_preheader(
                            ssa,
                            loop_info,
                            &non_loop_preds,
                            method_token,
                            changes,
                        );
                        modified_this_iteration += 1;
                        // After inserting a preheader, we need to re-analyze loops
                        break;
                    }
                }

                // Check if this loop needs latch unification
                if !loop_info.has_single_latch() && loop_info.latches.len() > 1 {
                    Self::unify_latches(ssa, loop_info, method_token, changes);
                    modified_this_iteration += 1;
                    // After unifying latches, we need to re-analyze loops
                    break;
                }
            }

            total_modified += modified_this_iteration;

            if modified_this_iteration == 0 {
                break;
            }
        }

        total_modified
    }

    /// Gets the non-loop predecessor block indices for a loop header.
    fn get_non_loop_predecessors(ssa: &SsaFunction, loop_info: &LoopInfo) -> Vec<usize> {
        let header_idx = loop_info.header.index();
        let mut non_loop_preds = Vec::new();

        // Find all blocks that jump to the header
        for (block_idx, block) in ssa.iter_blocks() {
            if let Some(op) = block.terminator_op() {
                let targets = Self::get_targets(op);
                if targets.contains(&header_idx)
                    && !loop_info.body.contains(&NodeId::new(block_idx))
                {
                    non_loop_preds.push(block_idx);
                }
            }
        }

        non_loop_preds
    }

    /// Extracts all target block indices from a terminator operation.
    fn get_targets(op: &SsaOp) -> Vec<usize> {
        match op {
            SsaOp::Jump { target } | SsaOp::Leave { target } => vec![*target],
            SsaOp::Branch {
                true_target,
                false_target,
                ..
            } => vec![*true_target, *false_target],
            SsaOp::Switch {
                targets, default, ..
            } => {
                let mut all = targets.clone();
                all.push(*default);
                all
            }
            _ => vec![],
        }
    }

    /// Inserts a preheader block for a loop.
    ///
    /// Creates a new block that becomes the single entry point into the loop,
    /// redirecting all non-loop predecessors through it.
    fn insert_preheader(
        ssa: &mut SsaFunction,
        loop_info: &LoopInfo,
        non_loop_preds: &[usize],
        method_token: Token,
        changes: &mut EventLog,
    ) {
        let header_idx = loop_info.header.index();
        let preheader_idx = ssa.block_count();

        // Step 1: Create the preheader block with a jump to the header
        let mut preheader = SsaBlock::new(preheader_idx);
        preheader.add_instruction(SsaInstruction::synthetic(SsaOp::Jump {
            target: header_idx,
        }));

        // Step 2: If the header has phi nodes, we need to handle them carefully.
        // The preheader needs to forward values from non-loop predecessors.
        // We'll create phi nodes in the preheader if there are multiple non-loop preds,
        // or just forward the single value if there's only one.
        if let Some(header) = ssa.block(header_idx) {
            let header_phis: Vec<_> = header.phi_nodes().to_vec();

            for phi in &header_phis {
                // Collect operands from non-loop predecessors
                let non_loop_operands: Vec<_> = phi
                    .operands()
                    .iter()
                    .filter(|op| non_loop_preds.contains(&op.predecessor()))
                    .copied()
                    .collect();

                if non_loop_operands.len() > 1 {
                    // Need a phi node in the preheader to merge these values
                    let new_var = SsaVarId::new();
                    let mut preheader_phi = PhiNode::new(new_var, phi.origin());
                    for op in &non_loop_operands {
                        preheader_phi.add_operand(*op);
                    }
                    preheader.phi_nodes_mut().push(preheader_phi);
                }
            }
        }

        // Step 3: Add the preheader to the function
        ssa.add_block(preheader);

        // Step 4: Redirect all non-loop predecessors to the preheader
        for &pred_idx in non_loop_preds {
            Self::redirect_targets(ssa, pred_idx, header_idx, preheader_idx);
        }

        // Step 5: First, collect information about preheader phis
        let preheader_phi_map: HashMap<VariableOrigin, SsaVarId> = ssa
            .block(preheader_idx)
            .map(|b| {
                b.phi_nodes()
                    .iter()
                    .map(|p| (p.origin(), p.result()))
                    .collect()
            })
            .unwrap_or_default();

        // Step 6: Update phi nodes in the header
        if let Some(header) = ssa.block_mut(header_idx) {
            for phi in header.phi_nodes_mut() {
                let origin = phi.origin();
                let operands = phi.operands_mut();
                let mut loop_operands: Vec<PhiOperand> = Vec::new();
                let mut non_loop_values: Vec<PhiOperand> = Vec::new();

                for op in operands.drain(..) {
                    if non_loop_preds.contains(&op.predecessor()) {
                        non_loop_values.push(op);
                    } else {
                        loop_operands.push(op);
                    }
                }

                // Keep loop operands as-is
                operands.extend(loop_operands);

                // For non-loop values: if there was a phi created in preheader,
                // reference that phi's result; otherwise reference the single value
                if !non_loop_values.is_empty() {
                    if non_loop_values.len() == 1 {
                        // Single non-loop predecessor: just update the predecessor
                        operands.push(PhiOperand::new(non_loop_values[0].value(), preheader_idx));
                    } else if let Some(&preheader_var) = preheader_phi_map.get(&origin) {
                        // Multiple non-loop predecessors: use the phi we created in preheader
                        operands.push(PhiOperand::new(preheader_var, preheader_idx));
                    }
                }
            }
        }

        changes
            .record(EventKind::ControlFlowRestructured)
            .at(method_token, preheader_idx)
            .message(format!(
                "Inserted preheader B{} for loop at B{}",
                preheader_idx, header_idx
            ));
    }

    /// Unifies multiple latch blocks into a single latch.
    ///
    /// Creates a new unified latch block and redirects all original latches to it.
    fn unify_latches(
        ssa: &mut SsaFunction,
        loop_info: &LoopInfo,
        method_token: Token,
        changes: &mut EventLog,
    ) {
        let header_idx = loop_info.header.index();
        let latches: Vec<usize> = loop_info.latches.iter().map(|n| n.index()).collect();
        let unified_latch_idx = ssa.block_count();

        // Step 1: Create the unified latch block
        let mut unified_latch = SsaBlock::new(unified_latch_idx);
        unified_latch.add_instruction(SsaInstruction::synthetic(SsaOp::Jump {
            target: header_idx,
        }));

        // Step 2: If the header has phi nodes with operands from multiple latches,
        // we need to create phi nodes in the unified latch to merge those values.
        let mut latch_phi_vars: HashMap<VariableOrigin, SsaVarId> = HashMap::new();

        if let Some(header) = ssa.block(header_idx) {
            for phi in header.phi_nodes() {
                // Collect operands from latch blocks
                let latch_operands: Vec<_> = phi
                    .operands()
                    .iter()
                    .filter(|op| latches.contains(&op.predecessor()))
                    .copied()
                    .collect();

                if latch_operands.len() > 1 {
                    // Need a phi node in the unified latch
                    let new_var = SsaVarId::new();
                    let mut latch_phi = PhiNode::new(new_var, phi.origin());
                    for op in &latch_operands {
                        latch_phi.add_operand(*op);
                    }
                    latch_phi_vars.insert(phi.origin(), new_var);
                    unified_latch.phi_nodes_mut().push(latch_phi);
                } else if latch_operands.len() == 1 {
                    // Single latch operand - just remember its value
                    latch_phi_vars.insert(phi.origin(), latch_operands[0].value());
                }
            }
        }

        // Step 3: Add the unified latch to the function
        ssa.add_block(unified_latch);

        // Step 4: Redirect all original latches to the unified latch instead of header
        for &latch_idx in &latches {
            Self::redirect_targets(ssa, latch_idx, header_idx, unified_latch_idx);
        }

        // Step 5: Update phi nodes in the header to reference the unified latch
        if let Some(header) = ssa.block_mut(header_idx) {
            for phi in header.phi_nodes_mut() {
                let origin = phi.origin();
                let operands = phi.operands_mut();

                // Remove operands from original latches
                operands.retain(|op| !latches.contains(&op.predecessor()));

                // Add operand from unified latch
                if let Some(&var) = latch_phi_vars.get(&origin) {
                    operands.push(PhiOperand::new(var, unified_latch_idx));
                }
            }
        }

        changes
            .record(EventKind::ControlFlowRestructured)
            .at(method_token, unified_latch_idx)
            .message(format!(
                "Unified {} latches into B{} for loop at B{}",
                latches.len(),
                unified_latch_idx,
                header_idx
            ));
    }

    /// Redirects branch targets in a block from old_target to new_target.
    fn redirect_targets(
        ssa: &mut SsaFunction,
        block_idx: usize,
        old_target: usize,
        new_target: usize,
    ) {
        if let Some(block) = ssa.block_mut(block_idx) {
            if let Some(last) = block.instructions_mut().last_mut() {
                let new_op = match last.op() {
                    SsaOp::Jump { target } if *target == old_target => {
                        Some(SsaOp::Jump { target: new_target })
                    }
                    SsaOp::Leave { target } if *target == old_target => {
                        Some(SsaOp::Leave { target: new_target })
                    }
                    SsaOp::Branch {
                        condition,
                        true_target,
                        false_target,
                    } => {
                        let new_true = if *true_target == old_target {
                            new_target
                        } else {
                            *true_target
                        };
                        let new_false = if *false_target == old_target {
                            new_target
                        } else {
                            *false_target
                        };
                        if new_true != *true_target || new_false != *false_target {
                            Some(SsaOp::Branch {
                                condition: *condition,
                                true_target: new_true,
                                false_target: new_false,
                            })
                        } else {
                            None
                        }
                    }
                    SsaOp::Switch {
                        value,
                        targets,
                        default,
                    } => {
                        let new_targets: Vec<_> = targets
                            .iter()
                            .map(|&t| if t == old_target { new_target } else { t })
                            .collect();
                        let new_default = if *default == old_target {
                            new_target
                        } else {
                            *default
                        };
                        if new_targets != *targets || new_default != *default {
                            Some(SsaOp::Switch {
                                value: *value,
                                targets: new_targets,
                                default: new_default,
                            })
                        } else {
                            None
                        }
                    }
                    _ => None,
                };

                if let Some(new_op) = new_op {
                    last.set_op(new_op);
                }
            }
        }
    }
}

impl SsaPass for LoopCanonicalizationPass {
    fn name(&self) -> &'static str {
        "LoopCanonicalization"
    }

    fn description(&self) -> &'static str {
        "Transforms loops into canonical form with single preheaders and single latches"
    }

    fn run_on_method(
        &self,
        ssa: &mut SsaFunction,
        method_token: Token,
        ctx: &CompilerContext,
        _assembly: &Arc<CilObject>,
    ) -> Result<bool> {
        // Skip very small functions (no loops possible)
        if ssa.block_count() < 2 {
            return Ok(false);
        }

        let mut changes = EventLog::new();
        let modified = Self::canonicalize_loops(ssa, method_token, &mut changes);

        if modified > 0 {
            // Canonicalize the function to clean up and renumber blocks
            ssa.canonicalize();
            ctx.events.merge(changes);
            return Ok(true);
        }

        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::{SsaFunctionBuilder, SsaLoopAnalysis};

    #[test]
    fn test_preheader_insertion() {
        // Create a loop with two entry points:
        // B0 (entry) -> B1 or B2
        // B1 -> B3 (header)
        // B2 -> B3 (header)
        // B3 -> B4 (body)
        // B4 -> B3 (back edge) or B5 (exit)
        // B5: return

        let mut ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
            // B0: entry - branch to B1 or B2
            f.block(0, |b| {
                let cond0 = b.const_true();
                b.branch(cond0, 1, 2);
            });
            // B1: first path to header
            f.block(1, |b| b.jump(3));
            // B2: second path to header
            f.block(2, |b| b.jump(3));
            // B3: header, jump to body
            f.block(3, |b| b.jump(4));
            // B4: body with back edge or exit
            f.block(4, |b| {
                let cond1 = b.const_true();
                b.branch(cond1, 3, 5); // back edge to 3, exit to 5
            });
            // B5: exit
            f.block(5, |b| b.ret());
        });

        // Verify loop exists but doesn't have preheader
        let forest = ssa.analyze_loops();
        assert_eq!(forest.len(), 1);
        let loop_info = &forest.loops()[0];
        assert!(!loop_info.has_preheader());

        // Run canonicalization
        let mut changes = EventLog::new();
        let modified =
            LoopCanonicalizationPass::canonicalize_loops(&mut ssa, Token::new(0), &mut changes);

        assert!(modified > 0);

        // Verify loop now has preheader
        let forest = ssa.analyze_loops();
        assert_eq!(forest.len(), 1);
        let loop_info = &forest.loops()[0];
        assert!(loop_info.has_preheader());
    }

    #[test]
    fn test_latch_unification() {
        // Create a loop with two back edges:
        // B0 -> B1 (header)
        // B1 -> B2, B3
        // B2 -> B1 (back edge 1)
        // B3 -> B1 (back edge 2), B4
        // B4: exit

        let mut ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
            // B0: entry
            f.block(0, |b| b.jump(1));
            // B1: header
            f.block(1, |b| {
                let cond1 = b.const_true();
                b.branch(cond1, 2, 3);
            });
            // B2: latch 1 (back to header)
            f.block(2, |b| b.jump(1));
            // B3: latch 2 or exit
            f.block(3, |b| {
                let cond2 = b.const_true();
                b.branch(cond2, 1, 4); // back edge to 1, exit to 4
            });
            // B4: exit
            f.block(4, |b| b.ret());
        });

        // Verify loop has multiple latches
        let forest = ssa.analyze_loops();
        assert_eq!(forest.len(), 1);
        let loop_info = &forest.loops()[0];
        assert!(!loop_info.has_single_latch());
        assert!(loop_info.latches.len() >= 2);

        // Run canonicalization
        let mut changes = EventLog::new();
        let modified =
            LoopCanonicalizationPass::canonicalize_loops(&mut ssa, Token::new(0), &mut changes);

        assert!(modified > 0);

        // Verify loop now has single latch
        let forest = ssa.analyze_loops();
        assert_eq!(forest.len(), 1);
        let loop_info = &forest.loops()[0];
        assert!(loop_info.has_single_latch());
    }

    #[test]
    fn test_already_canonical_loop() {
        // Create a canonical loop:
        // B0 -> B1 (header) - single entry
        // B1 -> B2
        // B2 -> B1 (single back edge), B3
        // B3: exit

        let mut ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
            // B0: preheader
            f.block(0, |b| b.jump(1));
            // B1: header
            f.block(1, |b| b.jump(2));
            // B2: body/latch
            f.block(2, |b| {
                let cond = b.const_true();
                b.branch(cond, 1, 3); // back edge to 1, exit to 3
            });
            // B3: exit
            f.block(3, |b| b.ret());
        });

        // Verify loop is already canonical
        let forest = ssa.analyze_loops();
        assert_eq!(forest.len(), 1);
        let loop_info = &forest.loops()[0];
        assert!(loop_info.is_canonical());

        // Run canonicalization - should make no changes
        let mut changes = EventLog::new();
        let modified =
            LoopCanonicalizationPass::canonicalize_loops(&mut ssa, Token::new(0), &mut changes);

        assert_eq!(modified, 0);
    }

    #[test]
    fn test_no_loops() {
        // Linear flow: B0 -> B1 -> B2
        let mut ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
            f.block(0, |b| b.jump(1));
            f.block(1, |b| b.jump(2));
            f.block(2, |b| b.ret());
        });

        let forest = ssa.analyze_loops();
        assert!(forest.is_empty());

        let mut changes = EventLog::new();
        let modified =
            LoopCanonicalizationPass::canonicalize_loops(&mut ssa, Token::new(0), &mut changes);

        assert_eq!(modified, 0);
    }
}
