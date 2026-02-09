//! Jump threading pass for semantic control flow simplification.
//!
//! This pass threads branches when the condition value can be determined from
//! a specific predecessor path. Unlike the basic trampoline threading in
//! [`ControlFlowSimplificationPass`], this pass evaluates branch conditions
//! based on known values.
//!
//! # Motivation
//!
//! After control-flow unflattening, we often have patterns like:
//!
//! ```text
//! B0: state = 5
//!     jump B1
//!
//! B1: if (state > 0) goto B2 else goto B3
//! ```
//!
//! Jump threading recognizes that coming from B0, the condition `state > 0`
//! is always true (since state=5), and threads B0 directly to B2:
//!
//! ```text
//! B0: state = 5
//!     jump B2   // Threaded!
//!
//! B1: if (state > 0) goto B2 else goto B3
//! ```
//!
//! DCE will later clean up B1 if it becomes unreachable.
//!
//! # Algorithm
//!
//! For each block with a branch terminator:
//! 1. For each predecessor of the block
//! 2. Use path-aware evaluation to determine the condition value from that predecessor
//! 3. If the condition evaluates to a known constant, thread the predecessor
//!    directly to the taken branch target
//!
//! [`ControlFlowSimplificationPass`]: super::ControlFlowSimplificationPass

use std::sync::Arc;

use crate::{
    analysis::{ConstValue, SsaCfg, SsaEvaluator, SsaFunction, SsaOp, SsaVarId},
    compiler::{pass::SsaPass, CompilerContext, EventKind, EventLog},
    metadata::{token::Token, typesystem::PointerSize},
    CilObject, Result,
};

/// Jump threading pass for semantic branch elimination.
///
/// This pass evaluates branch conditions based on values known from specific
/// incoming paths, and threads predecessors directly to the taken target when
/// the branch outcome can be determined.
pub struct JumpThreadingPass;

impl Default for JumpThreadingPass {
    fn default() -> Self {
        Self::new()
    }
}

impl JumpThreadingPass {
    /// Creates a new jump threading pass.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Evaluates a branch condition from a specific predecessor using path-aware evaluation.
    ///
    /// This uses `SsaEvaluator` to:
    /// 1. Evaluate the predecessor block to establish known values
    /// 2. Set the predecessor for phi node resolution
    /// 3. Evaluate the branch block's phi nodes
    /// 4. Resolve the condition value
    ///
    /// Returns the target block if the condition can be determined, None otherwise.
    fn try_thread(
        ssa: &SsaFunction,
        pred_block: usize,
        branch_block: usize,
        condition: SsaVarId,
        true_target: usize,
        false_target: usize,
        ptr_size: PointerSize,
    ) -> Option<usize> {
        let mut eval = SsaEvaluator::new(ssa, ptr_size);

        // Evaluate the predecessor block to establish any constant values
        eval.evaluate_block(pred_block);

        // Set predecessor for phi resolution in the branch block
        eval.set_predecessor(Some(pred_block));

        // Evaluate phi nodes in the branch block (this resolves phis using the predecessor)
        eval.evaluate_phis(branch_block);

        // Try to resolve the condition value with tracing
        let cond_value = eval
            .get_concrete(condition)
            .and_then(ConstValue::as_i64)
            .or_else(|| {
                eval.resolve_with_trace(condition, 10)
                    .and_then(|e| e.as_i64())
            })?;

        if cond_value != 0 {
            Some(true_target)
        } else {
            Some(false_target)
        }
    }

    /// Applies threading by updating the predecessor's terminator.
    fn apply_threading(
        ssa: &mut SsaFunction,
        pred_block: usize,
        _branch_block: usize,
        new_target: usize,
        method_token: Token,
        changes: &mut EventLog,
    ) -> bool {
        let Some(block) = ssa.block_mut(pred_block) else {
            return false;
        };

        let Some(last) = block.instructions_mut().last_mut() else {
            return false;
        };

        match last.op().clone() {
            SsaOp::Jump { target } if target != new_target => {
                last.set_op(SsaOp::Jump { target: new_target });
                changes
                    .record(EventKind::ControlFlowRestructured)
                    .at(method_token, pred_block)
                    .message(format!(
                        "jump threaded: B{} now jumps to B{} (was B{})",
                        pred_block, new_target, target
                    ));
                true
            }
            SsaOp::Branch {
                condition,
                true_target,
                false_target,
            } => {
                // For branches, we thread to the known target
                // We convert the branch to a jump since we know which way it goes
                let old_target = if new_target == true_target {
                    false_target
                } else {
                    true_target
                };
                last.set_op(SsaOp::Jump { target: new_target });
                changes
                    .record(EventKind::BranchSimplified)
                    .at(method_token, pred_block)
                    .message(format!(
                        "branch threaded: B{} condition on {:?} resolved to B{} (eliminated B{})",
                        pred_block, condition, new_target, old_target
                    ));
                true
            }
            SsaOp::Leave { target } if target != new_target => {
                last.set_op(SsaOp::Leave { target: new_target });
                changes
                    .record(EventKind::ControlFlowRestructured)
                    .at(method_token, pred_block)
                    .message(format!(
                        "leave threaded: B{} now leaves to B{} (was B{})",
                        pred_block, new_target, target
                    ));
                true
            }
            _ => false,
        }
    }

    /// Runs jump threading on the SSA function.
    fn run_threading(
        ssa: &mut SsaFunction,
        method_token: Token,
        changes: &mut EventLog,
        ptr_size: PointerSize,
    ) -> bool {
        if ssa.is_empty() {
            return false;
        }

        let cfg = SsaCfg::from_ssa(ssa);

        // Collect threading opportunities first (to avoid borrow issues)
        let mut threadings: Vec<(usize, usize, usize)> = Vec::new();

        for (block_idx, block) in ssa.iter_blocks() {
            // Look for branch terminators
            let Some(SsaOp::Branch {
                condition,
                true_target,
                false_target,
            }) = block.terminator_op()
            else {
                continue;
            };

            // For each predecessor, check if we can thread
            for pred_idx in cfg.block_predecessors(block_idx) {
                if let Some(target) = Self::try_thread(
                    ssa,
                    *pred_idx,
                    block_idx,
                    *condition,
                    *true_target,
                    *false_target,
                    ptr_size,
                ) {
                    // Only thread if we're actually changing the control flow
                    // (i.e., the predecessor doesn't already go directly to target)
                    let pred_target = ssa.block(*pred_idx).and_then(|b| {
                        b.terminator_op().and_then(|op| match op {
                            SsaOp::Jump { target } => Some(*target),
                            SsaOp::Leave { target } => Some(*target),
                            _ => None,
                        })
                    });

                    if pred_target != Some(target) {
                        threadings.push((*pred_idx, block_idx, target));
                    }
                }
            }
        }

        // Apply all threadings
        let mut changed = false;
        for (pred_block, branch_block, new_target) in threadings {
            if Self::apply_threading(
                ssa,
                pred_block,
                branch_block,
                new_target,
                method_token,
                changes,
            ) {
                changed = true;
            }
        }

        changed
    }
}

impl SsaPass for JumpThreadingPass {
    fn name(&self) -> &'static str {
        "jump-threading"
    }

    fn description(&self) -> &'static str {
        "Threads branches when condition is known from predecessor path"
    }

    fn run_on_method(
        &self,
        ssa: &mut SsaFunction,
        method_token: Token,
        ctx: &CompilerContext,
        assembly: &Arc<CilObject>,
    ) -> Result<bool> {
        let ptr_size = PointerSize::from_pe(assembly.file().pe().is_64bit);
        let mut changes = EventLog::new();
        let changed = Self::run_threading(ssa, method_token, &mut changes, ptr_size);

        if changed {
            ctx.events.merge(changes);
        }

        Ok(changed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::{CallGraph, ConstValue, SsaBlock, SsaInstruction};
    use crate::test::helpers::test_assembly_arc;

    fn test_context() -> CompilerContext {
        let call_graph = Arc::new(CallGraph::new());
        CompilerContext::new(call_graph)
    }

    #[test]
    fn test_empty_function() {
        let pass = JumpThreadingPass::new();
        let ctx = test_context();
        let mut ssa = SsaFunction::new(0, 0);

        let changed = pass
            .run_on_method(&mut ssa, Token::new(0x06000001), &ctx, &test_assembly_arc())
            .unwrap();

        assert!(!changed);
    }

    #[test]
    fn test_no_branches() {
        let pass = JumpThreadingPass::new();
        let ctx = test_context();

        // B0: jump to B1
        // B1: return
        let mut block0 = SsaBlock::new(0);
        block0.add_instruction(SsaInstruction::synthetic(SsaOp::Jump { target: 1 }));

        let mut block1 = SsaBlock::new(1);
        block1.add_instruction(SsaInstruction::synthetic(SsaOp::Return { value: None }));

        let mut ssa = SsaFunction::new(0, 0);
        ssa.add_block(block0);
        ssa.add_block(block1);

        let changed = pass
            .run_on_method(&mut ssa, Token::new(0x06000001), &ctx, &test_assembly_arc())
            .unwrap();

        assert!(!changed);
    }

    #[test]
    fn test_thread_with_constant_true() {
        let pass = JumpThreadingPass::new();
        let ctx = test_context();

        // B0: cond = true; jump B1
        // B1: if cond goto B2 else B3
        // Should thread B0 directly to B2
        let cond_var = SsaVarId::new();

        // Block 0: const true, jump to 1
        let mut block0 = SsaBlock::new(0);
        block0.add_instruction(SsaInstruction::synthetic(SsaOp::Const {
            dest: cond_var,
            value: ConstValue::True,
        }));
        block0.add_instruction(SsaInstruction::synthetic(SsaOp::Jump { target: 1 }));

        // Block 1: branch on cond_var
        let mut block1 = SsaBlock::new(1);
        block1.add_instruction(SsaInstruction::synthetic(SsaOp::Branch {
            condition: cond_var,
            true_target: 2,
            false_target: 3,
        }));

        // Block 2 and 3: return
        let mut block2 = SsaBlock::new(2);
        block2.add_instruction(SsaInstruction::synthetic(SsaOp::Return { value: None }));

        let mut block3 = SsaBlock::new(3);
        block3.add_instruction(SsaInstruction::synthetic(SsaOp::Return { value: None }));

        let mut ssa = SsaFunction::new(0, 0);
        ssa.add_block(block0);
        ssa.add_block(block1);
        ssa.add_block(block2);
        ssa.add_block(block3);

        let changed = pass
            .run_on_method(&mut ssa, Token::new(0x06000001), &ctx, &test_assembly_arc())
            .unwrap();

        assert!(changed);

        // Verify B0 now jumps directly to B2
        if let Some(block) = ssa.block(0) {
            assert!(matches!(
                block.terminator_op(),
                Some(SsaOp::Jump { target: 2 })
            ));
        }
    }

    #[test]
    fn test_thread_with_constant_false() {
        let pass = JumpThreadingPass::new();
        let ctx = test_context();

        let cond_var = SsaVarId::new();

        // Block 0: const false, jump to 1
        let mut block0 = SsaBlock::new(0);
        block0.add_instruction(SsaInstruction::synthetic(SsaOp::Const {
            dest: cond_var,
            value: ConstValue::False,
        }));
        block0.add_instruction(SsaInstruction::synthetic(SsaOp::Jump { target: 1 }));

        // Block 1: branch on cond_var
        let mut block1 = SsaBlock::new(1);
        block1.add_instruction(SsaInstruction::synthetic(SsaOp::Branch {
            condition: cond_var,
            true_target: 2,
            false_target: 3,
        }));

        // Block 2 and 3: return
        let mut block2 = SsaBlock::new(2);
        block2.add_instruction(SsaInstruction::synthetic(SsaOp::Return { value: None }));

        let mut block3 = SsaBlock::new(3);
        block3.add_instruction(SsaInstruction::synthetic(SsaOp::Return { value: None }));

        let mut ssa = SsaFunction::new(0, 0);
        ssa.add_block(block0);
        ssa.add_block(block1);
        ssa.add_block(block2);
        ssa.add_block(block3);

        let changed = pass
            .run_on_method(&mut ssa, Token::new(0x06000001), &ctx, &test_assembly_arc())
            .unwrap();

        assert!(changed);

        // Verify B0 now jumps directly to B3 (false branch)
        if let Some(block) = ssa.block(0) {
            assert!(matches!(
                block.terminator_op(),
                Some(SsaOp::Jump { target: 3 })
            ));
        }
    }

    #[test]
    fn test_thread_comparison_greater() {
        let pass = JumpThreadingPass::new();
        let ctx = test_context();

        let x_var = SsaVarId::new();
        let zero_var = SsaVarId::new();
        let cmp_var = SsaVarId::new();

        // Block 0: x = 5; zero = 0; cmp = (x > zero); jump to 1
        let mut block0 = SsaBlock::new(0);
        block0.add_instruction(SsaInstruction::synthetic(SsaOp::Const {
            dest: x_var,
            value: ConstValue::I32(5),
        }));
        block0.add_instruction(SsaInstruction::synthetic(SsaOp::Const {
            dest: zero_var,
            value: ConstValue::I32(0),
        }));
        block0.add_instruction(SsaInstruction::synthetic(SsaOp::Cgt {
            dest: cmp_var,
            left: x_var,
            right: zero_var,
            unsigned: false,
        }));
        block0.add_instruction(SsaInstruction::synthetic(SsaOp::Jump { target: 1 }));

        // Block 1: branch on cmp_var
        let mut block1 = SsaBlock::new(1);
        block1.add_instruction(SsaInstruction::synthetic(SsaOp::Branch {
            condition: cmp_var,
            true_target: 2,
            false_target: 3,
        }));

        // Block 2 and 3: return
        let mut block2 = SsaBlock::new(2);
        block2.add_instruction(SsaInstruction::synthetic(SsaOp::Return { value: None }));

        let mut block3 = SsaBlock::new(3);
        block3.add_instruction(SsaInstruction::synthetic(SsaOp::Return { value: None }));

        let mut ssa = SsaFunction::new(0, 0);
        ssa.add_block(block0);
        ssa.add_block(block1);
        ssa.add_block(block2);
        ssa.add_block(block3);

        let changed = pass
            .run_on_method(&mut ssa, Token::new(0x06000001), &ctx, &test_assembly_arc())
            .unwrap();

        assert!(changed);

        // Verify B0 now jumps directly to B2 (true branch, since 5 > 0)
        if let Some(block) = ssa.block(0) {
            assert!(matches!(
                block.terminator_op(),
                Some(SsaOp::Jump { target: 2 })
            ));
        }
    }

    #[test]
    fn test_no_thread_unknown_condition() {
        let pass = JumpThreadingPass::new();
        let ctx = test_context();

        // Block 0: jump to 1
        // Block 1: branch on x (which has no known definition)
        // Should NOT thread since x is unknown
        let x_var = SsaVarId::new();

        // x has no definition - simulating an argument or external value
        let mut block0 = SsaBlock::new(0);
        block0.add_instruction(SsaInstruction::synthetic(SsaOp::Jump { target: 1 }));

        let mut block1 = SsaBlock::new(1);
        block1.add_instruction(SsaInstruction::synthetic(SsaOp::Branch {
            condition: x_var,
            true_target: 2,
            false_target: 3,
        }));

        let mut block2 = SsaBlock::new(2);
        block2.add_instruction(SsaInstruction::synthetic(SsaOp::Return { value: None }));

        let mut block3 = SsaBlock::new(3);
        block3.add_instruction(SsaInstruction::synthetic(SsaOp::Return { value: None }));

        let mut ssa = SsaFunction::new(1, 0);
        ssa.add_block(block0);
        ssa.add_block(block1);
        ssa.add_block(block2);
        ssa.add_block(block3);

        let changed = pass
            .run_on_method(&mut ssa, Token::new(0x06000001), &ctx, &test_assembly_arc())
            .unwrap();

        // Should NOT change since condition is unknown
        assert!(!changed);
    }

    #[test]
    fn test_pass_name_and_description() {
        let pass = JumpThreadingPass::new();
        assert_eq!(pass.name(), "jump-threading");
        assert!(!pass.description().is_empty());
    }
}
