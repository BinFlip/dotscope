//! Control flow simplification pass.
//!
//! Simplifies the control flow graph through several transformations:
//!
//! 1. **Jump threading**: Skip intermediate trampoline blocks
//! 2. **Branch canonicalization**: Simplify `branch cond, B, B` to `jump B`
//! 3. **Unreachable tail removal**: Remove code after unconditional exits
//!
//! Uses an iterative fixed-point algorithm to handle cascading simplifications.
//!
//! ## Example
//!
//! Before:
//! ```text
//! B0: jump B1
//! B1: jump B2
//! B2: ret
//! ```
//!
//! After:
//! ```text
//! B0: jump B2    // Directly to B2
//! B1: jump B2    // Will be eliminated by DCE
//! B2: ret
//! ```
//!

use std::collections::HashMap;

use crate::{
    analysis::{SsaFunction, SsaOp},
    compiler::{
        pass::SsaPass,
        passes::{deadcode::find_dead_tails, utils::resolve_chain},
        CompilerContext, EventKind, EventLog,
    },
    metadata::token::Token,
    Result,
};

/// Maximum iterations for the fixed-point algorithm to prevent infinite loops.
const MAX_ITERATIONS: usize = 100;

/// Control flow simplification pass.
///
/// Performs iterative control flow simplification including:
/// - Jump threading through trampoline blocks
/// - Branch-to-same-target simplification
/// - Dead tail removal (code after terminators)
///
/// The pass iterates until no more changes are made (fixed point).
pub struct ControlFlowSimplificationPass;

impl Default for ControlFlowSimplificationPass {
    fn default() -> Self {
        Self::new()
    }
}

impl ControlFlowSimplificationPass {
    /// Creates a new control flow simplification pass.
    ///
    /// # Returns
    ///
    /// A new `ControlFlowSimplificationPass` instance.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Finds branches where both targets are the same block.
    ///
    /// A branch `branch cond, B, B` can be simplified to `jump B` since
    /// the condition doesn't affect the control flow.
    ///
    /// # Arguments
    ///
    /// * `ssa` - The SSA function to analyze.
    ///
    /// # Returns
    ///
    /// A vector of (block index, target block) pairs for branches to simplify.
    fn find_same_target_branches(ssa: &SsaFunction) -> Vec<(usize, usize)> {
        ssa.iter_blocks()
            .filter_map(|(block_idx, block)| {
                block.terminator_op().and_then(|op| match op {
                    SsaOp::Branch {
                        true_target,
                        false_target,
                        ..
                    } if true_target == false_target => Some((block_idx, *true_target)),
                    _ => None,
                })
            })
            .collect()
    }

    /// Applies jump threading to all control flow instructions.
    ///
    /// Updates jumps, branches, and switches to skip trampoline blocks
    /// and go directly to their ultimate targets.
    ///
    /// # Arguments
    ///
    /// * `ssa` - The SSA function to modify.
    /// * `trampolines` - The map of trampoline blocks.
    /// * `method_token` - The method token for change tracking.
    /// * `changes` - The change set to record modifications.
    ///
    /// # Returns
    ///
    /// The number of control flow instructions that were updated.
    fn apply_jump_threading(
        ssa: &mut SsaFunction,
        trampolines: &HashMap<usize, usize>,
        method_token: Token,
        changes: &mut EventLog,
    ) -> usize {
        // Precompute ultimate targets for all trampolines
        let ultimate_targets: HashMap<usize, usize> = trampolines
            .keys()
            .map(|&t| (t, resolve_chain(trampolines, t)))
            .collect();

        let mut threaded_count = 0;

        for block_idx in 0..ssa.block_count() {
            if let Some(block) = ssa.block_mut(block_idx) {
                if let Some(last) = block.instructions_mut().last_mut() {
                    let op = last.op_mut();
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
                            .record(EventKind::ControlFlowRestructured)
                            .at(method_token, block_idx)
                            .message(format!("jump threaded: {old_targets:?} -> {new_targets:?}"));
                        threaded_count += 1;
                    }
                }
            }
        }

        threaded_count
    }

    /// Simplifies branches where both targets are the same.
    ///
    /// Converts `branch cond, B, B` to `jump B`.
    ///
    /// # Arguments
    ///
    /// * `ssa` - The SSA function to modify.
    /// * `same_target_branches` - The branches to simplify.
    /// * `method_token` - The method token for change tracking.
    /// * `changes` - The change set to record modifications.
    ///
    /// # Returns
    ///
    /// The number of branches that were simplified.
    fn simplify_same_target_branches(
        ssa: &mut SsaFunction,
        same_target_branches: &[(usize, usize)],
        method_token: Token,
        changes: &mut EventLog,
    ) -> usize {
        let mut simplified_count = 0;

        for &(block_idx, target) in same_target_branches {
            if let Some(block) = ssa.block_mut(block_idx) {
                if let Some(last) = block.instructions_mut().last_mut() {
                    last.set_op(SsaOp::Jump { target });
                    changes
                        .record(EventKind::BranchSimplified)
                        .at(method_token, block_idx)
                        .message(format!(
                            "branch to same target simplified: B{block_idx} branch -> jump B{target}"
                        ));
                    simplified_count += 1;
                }
            }
        }

        simplified_count
    }

    /// Removes dead code tails (instructions after terminators).
    ///
    /// # Arguments
    ///
    /// * `ssa` - The SSA function to modify.
    /// * `dead_tails` - The dead tails to remove.
    /// * `method_token` - The method token for change tracking.
    /// * `changes` - The change set to record modifications.
    ///
    /// # Returns
    ///
    /// The number of instructions removed.
    fn remove_dead_tails(
        ssa: &mut SsaFunction,
        dead_tails: &[(usize, usize)],
        method_token: Token,
        changes: &mut EventLog,
    ) -> usize {
        let mut removed_count = 0;

        for &(block_idx, start_idx) in dead_tails {
            if let Some(block) = ssa.block_mut(block_idx) {
                let instr_count = block.instruction_count();
                let to_remove = instr_count.saturating_sub(start_idx);
                for _ in 0..to_remove {
                    block.instructions_mut().pop();
                    removed_count += 1;
                }
                if to_remove > 0 {
                    changes
                        .record(EventKind::InstructionRemoved)
                        .at(method_token, block_idx)
                        .message(format!(
                            "removed {to_remove} dead instructions after terminator in B{block_idx}"
                        ));
                }
            }
        }

        removed_count
    }

    /// Runs a single iteration of control flow simplification.
    ///
    /// # Arguments
    ///
    /// * `ssa` - The SSA function to modify.
    /// * `method_token` - The method token for change tracking.
    /// * `changes` - The change set to record modifications.
    ///
    /// # Returns
    ///
    /// The total number of changes made during this iteration.
    fn run_iteration(ssa: &mut SsaFunction, method_token: Token, changes: &mut EventLog) -> usize {
        let mut total_changes = 0;

        // Step 1: Find and apply jump threading (don't skip entry block)
        let trampolines = ssa.find_trampoline_blocks(false);
        if !trampolines.is_empty() {
            total_changes += Self::apply_jump_threading(ssa, &trampolines, method_token, changes);
        }

        // Step 2: Simplify branches to same target
        let same_target_branches = Self::find_same_target_branches(ssa);
        if !same_target_branches.is_empty() {
            total_changes += Self::simplify_same_target_branches(
                ssa,
                &same_target_branches,
                method_token,
                changes,
            );
        }

        // Step 3: Remove dead tails
        let dead_tails = find_dead_tails(ssa);
        if !dead_tails.is_empty() {
            total_changes += Self::remove_dead_tails(ssa, &dead_tails, method_token, changes);
        }

        total_changes
    }
}

impl SsaPass for ControlFlowSimplificationPass {
    fn name(&self) -> &'static str {
        "control-flow-simplification"
    }

    fn description(&self) -> &'static str {
        "Simplifies control flow by threading jumps and eliminating trampolines"
    }

    fn run_on_method(
        &self,
        ssa: &mut SsaFunction,
        method_token: Token,
        ctx: &CompilerContext,
        _assembly: &std::sync::Arc<crate::CilObject>,
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
            ctx.events.merge(&changes);
        }
        Ok(changed)
    }
}
#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::{
        analysis::{CallGraph, ConstValue, SsaBlock, SsaFunctionBuilder, SsaInstruction, SsaVarId},
        compiler::passes::deadcode::find_dead_tails,
        test::helpers::test_assembly_arc,
    };

    /// Helper to create a minimal analysis context for testing.
    fn test_context() -> CompilerContext {
        let call_graph = Arc::new(CallGraph::new());
        CompilerContext::new(call_graph)
    }

    #[test]
    fn test_find_same_target_branches_none() {
        let ssa = SsaFunctionBuilder::new(3, 0).build_with(|f| {
            f.block(0, |b| {
                let cond = b.const_true();
                b.branch(cond, 1, 2); // Different targets
            });
        });

        let same_targets = ControlFlowSimplificationPass::find_same_target_branches(&ssa);
        assert!(same_targets.is_empty());
    }

    #[test]
    fn test_find_same_target_branches_found() {
        let ssa = SsaFunctionBuilder::new(2, 0).build_with(|f| {
            f.block(0, |b| {
                let cond = b.const_true();
                b.branch(cond, 1, 1); // Same target!
            });
            f.block(1, |b| b.ret());
        });

        let same_targets = ControlFlowSimplificationPass::find_same_target_branches(&ssa);
        assert_eq!(same_targets.len(), 1);
        assert_eq!(same_targets[0], (0, 1));
    }

    #[test]
    fn test_find_same_target_branches_multiple() {
        let ssa = SsaFunctionBuilder::new(4, 0).build_with(|f| {
            f.block(0, |b| {
                let cond = b.const_true();
                b.branch(cond, 2, 2);
            });
            f.block(1, |b| {
                let cond = b.const_true();
                b.branch(cond, 3, 3);
            });
            f.block(2, |b| b.ret());
            f.block(3, |b| b.ret());
        });

        let same_targets = ControlFlowSimplificationPass::find_same_target_branches(&ssa);
        assert_eq!(same_targets.len(), 2);
    }

    #[test]
    fn test_find_dead_tails_empty() {
        let ssa = SsaFunctionBuilder::new(0, 0).build_with(|_f| {});
        let dead_tails = find_dead_tails(&ssa);
        assert!(dead_tails.is_empty());
    }

    #[test]
    fn test_find_dead_tails_with_dead_code() {
        // Need to use manual construction here since builder won't allow
        // instructions after a terminator
        let mut ssa = SsaFunction::new(1, 0);

        let mut block0 = SsaBlock::new(0);
        block0.add_instruction(SsaInstruction::synthetic(SsaOp::Return { value: None }));
        // Dead code after return
        block0.add_instruction(SsaInstruction::synthetic(SsaOp::Const {
            dest: SsaVarId::new(),
            value: ConstValue::I32(42),
        }));
        ssa.add_block(block0);

        let dead_tails = find_dead_tails(&ssa);
        assert_eq!(dead_tails.len(), 1);
        assert_eq!(dead_tails[0], (0, 1));
    }

    #[test]
    fn test_find_dead_tails_no_dead_code() {
        let ssa = SsaFunctionBuilder::new(1, 0).build_with(|f| {
            f.block(0, |b| {
                let _ = b.const_i32(42);
                b.ret();
            });
        });

        let dead_tails = find_dead_tails(&ssa);
        assert!(dead_tails.is_empty());
    }

    #[test]
    fn test_find_dead_tails_multiple_dead_instructions() {
        // Need to use manual construction here since builder won't allow
        // instructions after a terminator
        let mut ssa = SsaFunction::new(1, 0);

        let mut block0 = SsaBlock::new(0);
        block0.add_instruction(SsaInstruction::synthetic(SsaOp::Return { value: None }));
        block0.add_instruction(SsaInstruction::synthetic(SsaOp::Const {
            dest: SsaVarId::new(),
            value: ConstValue::I32(1),
        }));
        block0.add_instruction(SsaInstruction::synthetic(SsaOp::Const {
            dest: SsaVarId::new(),
            value: ConstValue::I32(2),
        }));
        block0.add_instruction(SsaInstruction::synthetic(SsaOp::Const {
            dest: SsaVarId::new(),
            value: ConstValue::I32(3),
        }));
        ssa.add_block(block0);

        let dead_tails = find_dead_tails(&ssa);
        assert_eq!(dead_tails.len(), 1);
        assert_eq!(dead_tails[0], (0, 1)); // Start at index 1
    }

    #[test]
    fn test_pass_empty_function() {
        let pass = ControlFlowSimplificationPass::new();
        let ctx = test_context();
        let mut ssa = SsaFunctionBuilder::new(0, 0).build_with(|_f| {});

        let changed = pass
            .run_on_method(&mut ssa, Token::new(0x06000001), &ctx, &test_assembly_arc())
            .unwrap();
        assert!(!changed);
    }

    #[test]
    fn test_pass_no_simplification_needed() {
        let pass = ControlFlowSimplificationPass::new();
        let ctx = test_context();
        let mut ssa = SsaFunctionBuilder::new(1, 0).build_with(|f| {
            f.block(0, |b| {
                let _ = b.const_i32(42);
                b.ret();
            });
        });

        let changed = pass
            .run_on_method(&mut ssa, Token::new(0x06000001), &ctx, &test_assembly_arc())
            .unwrap();
        assert!(!changed);
    }

    #[test]
    fn test_pass_jump_threading() {
        let pass = ControlFlowSimplificationPass::new();
        let ctx = test_context();
        // Block 0: jump to trampoline
        // Block 1: trampoline to block 2
        // Block 2: return
        let mut ssa = SsaFunctionBuilder::new(3, 0).build_with(|f| {
            f.block(0, |b| b.jump(1));
            f.block(1, |b| b.jump(2));
            f.block(2, |b| b.ret());
        });

        let changed = pass
            .run_on_method(&mut ssa, Token::new(0x06000001), &ctx, &test_assembly_arc())
            .unwrap();
        assert!(changed);

        // Verify block 0 now jumps directly to block 2
        if let Some(block) = ssa.block(0) {
            if let Some(SsaOp::Jump { target }) = block.terminator_op() {
                assert_eq!(*target, 2);
            }
        }
    }

    #[test]
    fn test_pass_leave_threading() {
        let pass = ControlFlowSimplificationPass::new();
        let ctx = test_context();
        // Block 0: leave to trampoline
        // Block 1: trampoline (leave) to block 2
        // Block 2: return
        let mut ssa = SsaFunctionBuilder::new(3, 0).build_with(|f| {
            f.block(0, |b| b.leave(1));
            f.block(1, |b| b.leave(2));
            f.block(2, |b| b.ret());
        });

        let changed = pass
            .run_on_method(&mut ssa, Token::new(0x06000001), &ctx, &test_assembly_arc())
            .unwrap();
        assert!(changed);

        // Verify block 0 now leaves directly to block 2
        if let Some(block) = ssa.block(0) {
            if let Some(SsaOp::Leave { target }) = block.terminator_op() {
                assert_eq!(*target, 2);
            }
        }
    }

    #[test]
    fn test_pass_branch_threading() {
        let pass = ControlFlowSimplificationPass::new();
        let ctx = test_context();
        // Block 0: branch to trampolines
        // Block 1: trampoline to block 3
        // Block 2: trampoline to block 4
        // Block 3, 4: return
        let mut ssa = SsaFunctionBuilder::new(5, 0).build_with(|f| {
            f.block(0, |b| {
                let cond = b.const_true();
                b.branch(cond, 1, 2);
            });
            f.block(1, |b| b.jump(3));
            f.block(2, |b| b.jump(4));
            f.block(3, |b| b.ret());
            f.block(4, |b| b.ret());
        });

        let changed = pass
            .run_on_method(&mut ssa, Token::new(0x06000001), &ctx, &test_assembly_arc())
            .unwrap();
        assert!(changed);

        // Verify branch targets were threaded
        if let Some(block) = ssa.block(0) {
            if let Some(SsaOp::Branch {
                true_target,
                false_target,
                ..
            }) = block.terminator_op()
            {
                assert_eq!(*true_target, 3);
                assert_eq!(*false_target, 4);
            }
        }
    }

    #[test]
    fn test_pass_switch_threading() {
        let pass = ControlFlowSimplificationPass::new();
        let ctx = test_context();
        // Block 0: switch with trampoline targets
        // Blocks 1, 2, 3: trampolines to block 4
        // Block 4: return
        let mut ssa = SsaFunctionBuilder::new(5, 0).build_with(|f| {
            f.block(0, |b| {
                let val = b.const_i32(0);
                b.switch(val, vec![1, 2], 3);
            });
            f.block(1, |b| b.jump(4));
            f.block(2, |b| b.jump(4));
            f.block(3, |b| b.jump(4));
            f.block(4, |b| b.ret());
        });

        let changed = pass
            .run_on_method(&mut ssa, Token::new(0x06000001), &ctx, &test_assembly_arc())
            .unwrap();
        assert!(changed);

        // Verify switch targets were threaded
        if let Some(block) = ssa.block(0) {
            if let Some(SsaOp::Switch {
                targets, default, ..
            }) = block.terminator_op()
            {
                assert!(targets.iter().all(|&t| t == 4));
                assert_eq!(*default, 4);
            }
        }
    }

    #[test]
    fn test_pass_same_target_branch_simplification() {
        let pass = ControlFlowSimplificationPass::new();
        let ctx = test_context();
        // Block 0: branch to same target
        let mut ssa = SsaFunctionBuilder::new(2, 0).build_with(|f| {
            f.block(0, |b| {
                let cond = b.const_true();
                b.branch(cond, 1, 1);
            });
            f.block(1, |b| b.ret());
        });

        let changed = pass
            .run_on_method(&mut ssa, Token::new(0x06000001), &ctx, &test_assembly_arc())
            .unwrap();
        assert!(changed);

        // Verify branch was converted to jump
        if let Some(block) = ssa.block(0) {
            assert!(matches!(
                block.terminator_op(),
                Some(SsaOp::Jump { target: 1 })
            ));
        }
    }

    #[test]
    fn test_pass_dead_tail_removal() {
        // Need to use manual construction here since builder won't allow
        // instructions after a terminator
        let pass = ControlFlowSimplificationPass::new();
        let ctx = test_context();
        let mut ssa = SsaFunction::new(1, 0);

        let mut block0 = SsaBlock::new(0);
        block0.add_instruction(SsaInstruction::synthetic(SsaOp::Return { value: None }));
        block0.add_instruction(SsaInstruction::synthetic(SsaOp::Const {
            dest: SsaVarId::new(),
            value: ConstValue::I32(42),
        }));
        ssa.add_block(block0);

        assert_eq!(ssa.block(0).unwrap().instruction_count(), 2);

        let changed = pass
            .run_on_method(&mut ssa, Token::new(0x06000001), &ctx, &test_assembly_arc())
            .unwrap();
        assert!(changed);

        assert_eq!(ssa.block(0).unwrap().instruction_count(), 1);
    }

    #[test]
    fn test_pass_iterative_convergence() {
        let pass = ControlFlowSimplificationPass::new();
        let ctx = test_context();
        // Create a chain: 0 -> 1 -> 2 -> 3 -> 4
        let mut ssa = SsaFunctionBuilder::new(5, 0).build_with(|f| {
            f.block(0, |b| b.jump(1));
            f.block(1, |b| b.jump(2));
            f.block(2, |b| b.jump(3));
            f.block(3, |b| b.jump(4));
            f.block(4, |b| b.ret());
        });

        let changed = pass
            .run_on_method(&mut ssa, Token::new(0x06000001), &ctx, &test_assembly_arc())
            .unwrap();
        assert!(changed);

        // All jumps should now go directly to block 4
        for i in 0..4 {
            if let Some(block) = ssa.block(i) {
                if let Some(SsaOp::Jump { target }) = block.terminator_op() {
                    assert_eq!(*target, 4);
                }
            }
        }
    }

    #[test]
    fn test_pass_combined_simplifications() {
        // Need to use manual construction here since builder won't allow
        // instructions after a terminator (for the dead tail test case)
        let pass = ControlFlowSimplificationPass::new();
        let ctx = test_context();
        let mut ssa = SsaFunction::new(4, 0);

        // Block 0: branch to same trampoline target
        let mut block0 = SsaBlock::new(0);
        block0.add_instruction(SsaInstruction::synthetic(SsaOp::Branch {
            condition: SsaVarId::new(),
            true_target: 1,
            false_target: 1,
        }));
        ssa.add_block(block0);

        // Block 1: trampoline to block 2
        let mut block1 = SsaBlock::new(1);
        block1.add_instruction(SsaInstruction::synthetic(SsaOp::Jump { target: 2 }));
        ssa.add_block(block1);

        // Block 2: trampoline to block 3
        let mut block2 = SsaBlock::new(2);
        block2.add_instruction(SsaInstruction::synthetic(SsaOp::Jump { target: 3 }));
        ssa.add_block(block2);

        // Block 3: return with dead tail
        let mut block3 = SsaBlock::new(3);
        block3.add_instruction(SsaInstruction::synthetic(SsaOp::Return { value: None }));
        block3.add_instruction(SsaInstruction::synthetic(SsaOp::Nop));
        ssa.add_block(block3);

        let changed = pass
            .run_on_method(&mut ssa, Token::new(0x06000001), &ctx, &test_assembly_arc())
            .unwrap();
        assert!(changed);

        // Block 0 should be a jump to block 3
        if let Some(block) = ssa.block(0) {
            assert!(matches!(
                block.terminator_op(),
                Some(SsaOp::Jump { target: 3 })
            ));
        }

        // Block 3 should have no dead tail
        assert_eq!(ssa.block(3).unwrap().instruction_count(), 1);
    }
}
