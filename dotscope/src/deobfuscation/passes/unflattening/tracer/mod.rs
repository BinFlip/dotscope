//! Trace-based CFF analysis.
//!
//! This module implements tracing for control flow unflattening. Given a
//! pre-detected CFF dispatcher (from [`super::detection`]), it builds a tree
//! of all execution paths through the method by:
//!
//! 1. **Evaluate from method entry**: Walk through the SSA, evaluating each
//!    instruction with concrete values using the [`SsaEvaluator`]
//! 2. **Follow state transitions**: When the dispatcher switch evaluates to a
//!    concrete case index, follow that case automatically (CFF machinery)
//! 3. **Fork at user branches**: Branches whose condition does NOT depend on
//!    the state variable are forked to capture both paths (original program logic)
//! 4. **Classify via taint analysis**: Variables derived from the state variable
//!    are marked as state-tainted — the reconstruction phase removes them
//! 5. **Detect loops**: When the same (block, state) pair is revisited, emit a
//!    [`TraceTerminator::LoopBack`] to prevent infinite tree expansion
//!
//! The resulting [`TraceTree`] is consumed by the [`super::reconstruction`] module
//! to extract a [`PatchPlan`](super::reconstruction::PatchPlan) that rewires the
//! CFG, removing dispatcher indirection.
//!
//! [`SsaEvaluator`]: crate::analysis::SsaEvaluator
//!
//! # Module Structure
//!
//! - [`types`]: Public data types ([`TraceTree`], [`TraceNode`], [`TracedDispatcher`], etc.)
//! - [`context`]: Tracing context — owns evaluator, taint state, visit tracking
//! - [`engine`]: Core iterative tracing machine (work stack, terminator dispatch)
//! - [`helpers`]: Standalone helpers (taint propagation, call resolution, statistics)

mod context;
mod engine;
mod helpers;
mod types;

pub use types::*;

use crate::{
    analysis::SsaFunction,
    deobfuscation::passes::unflattening::{
        detection::CffDetector,
        tracer::{
            context::TreeTraceContext,
            engine::trace_from_block,
            helpers::{compute_tree_stats, trace_exception_handlers},
        },
        UnflattenConfig,
    },
    CilObject,
};

/// Traces a method into a tree structure, forking at user branches.
///
/// This is the main entry point for tree-based tracing. It handles:
/// - Detecting the dispatcher upfront via `CffDetector` (SCCP-based)
/// - Following state transitions automatically
/// - Forking at user branches (non-state-dependent conditions)
/// - Detecting loops to avoid infinite expansion
///
/// # Arguments
///
/// * `ssa` - The SSA function to trace
/// * `config` - Configuration controlling tracing limits and behavior
/// * `assembly` - Optional assembly reference for call resolution
///
/// # Returns
///
/// A [`TraceTree`] containing all execution paths through the method.
pub fn trace_method_tree(
    ssa: &SsaFunction,
    config: &UnflattenConfig,
    assembly: Option<&CilObject>,
) -> TraceTree {
    // Detect dispatcher upfront using CffDetector
    let mut detector = CffDetector::new(ssa);
    let dispatcher = detector
        .detect_best()
        .filter(|d| d.confidence >= config.min_confidence)
        .map(|d| TracedDispatcher {
            block: d.block,
            switch_var: d.switch_var,
            targets: d.cases.clone(),
            default: d.default,
            state_var: d.state_phi,
            initial_state: d.initial_state,
        });

    let mut ctx = match dispatcher {
        Some(d) => TreeTraceContext::with_dispatcher(ssa, d, config, assembly),
        None => TreeTraceContext::new(ssa, config, assembly),
    };

    build_trace_tree(&mut ctx)
}

/// Traces a method for a specific pre-detected dispatcher.
///
/// Unlike [`trace_method_tree`] which auto-detects the best dispatcher,
/// this function uses a caller-provided dispatcher. This is used when
/// processing multiple independent CFF dispatchers in a single method
/// (e.g., ConfuserEx inserts separate dispatchers per exception handler
/// region). Each dispatcher is traced independently and the resulting
/// patch plans are merged before applying.
///
/// # Arguments
///
/// * `ssa` - The SSA function to trace
/// * `config` - Configuration controlling tracing limits and behavior
/// * `assembly` - Optional assembly reference for call resolution
/// * `dispatcher` - The pre-detected dispatcher to trace for
/// * `other_dispatcher_blocks` - Block indices of other dispatchers in this method
///
/// # Returns
///
/// A [`TraceTree`] for the given dispatcher.
pub fn trace_for_dispatcher(
    ssa: &SsaFunction,
    config: &UnflattenConfig,
    assembly: Option<&CilObject>,
    dispatcher: TracedDispatcher,
    other_dispatcher_blocks: &[usize],
) -> TraceTree {
    let mut ctx = TreeTraceContext::with_dispatcher(ssa, dispatcher, config, assembly);
    ctx.set_other_dispatcher_blocks(other_dispatcher_blocks.to_vec());

    build_trace_tree(&mut ctx)
}

/// Shared implementation for building a trace tree from an initialized context.
///
/// Both [`trace_method_tree`] and [`trace_for_dispatcher`] delegate to this
/// function after context setup. It traces from block 0, traces exception
/// handlers, propagates taint, and computes statistics.
fn build_trace_tree(ctx: &mut TreeTraceContext<'_>) -> TraceTree {
    let root = trace_from_block(ctx, 0, 0);
    let handler_traces = trace_exception_handlers(ctx);
    ctx.propagate_taint_forward();

    let mut tree = TraceTree::new(root, ctx.ssa().var_id_capacity());
    tree.handler_traces = handler_traces;
    tree.dispatcher = ctx.take_dispatcher();
    tree.state_tainted = ctx.take_state_tainted();

    compute_tree_stats(&tree.root, &mut tree.stats, 0);
    for ht in &tree.handler_traces {
        compute_tree_stats(&ht.root, &mut tree.stats, 0);
    }

    tree
}

#[cfg(test)]
mod tests {
    use crate::{
        analysis::{
            ConstValue, PhiNode, PhiOperand, SsaBlock, SsaFunction, SsaInstruction, SsaOp,
            SsaVarId, VariableOrigin,
        },
        deobfuscation::passes::unflattening::{tracer::trace_method_tree, UnflattenConfig},
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
    fn test_tree_trace_simple_cff() {
        let ssa = create_simple_cff();
        let config = UnflattenConfig::default();
        let tree = trace_method_tree(&ssa, &config, None);

        // Should find the dispatcher
        assert!(tree.dispatcher.is_some(), "Should detect dispatcher");
        let dispatcher = tree.dispatcher.as_ref().unwrap();
        assert_eq!(dispatcher.block, 1);

        // Should have state-tainted variables
        assert!(!tree.state_tainted.is_empty(), "Should have tainted vars");

        // Check stats
        println!("Tree stats: {:?}", tree.stats);
        assert!(tree.stats.node_count >= 1, "Should have at least one node");
    }

    /// Creates a CFF with a user branch inside a case block.
    fn create_cff_with_user_branch() -> SsaFunction {
        let mut ssa = SsaFunction::new(1, 1);
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
            value: ConstValue::I32(42),
        }));
        b0.add_instruction(SsaInstruction::synthetic(SsaOp::Jump { target: 1 }));
        ssa.add_block(b0);

        // B1: dispatcher with switch
        let mut b1 = SsaBlock::new(1);
        let mut phi = PhiNode::new(state_var, VariableOrigin::Local(0));
        phi.add_operand(PhiOperand::new(init_state, 0));
        phi.add_operand(PhiOperand::new(const_one, 3));
        phi.add_operand(PhiOperand::new(const_one, 4));
        b1.add_phi(phi);
        b1.add_instruction(SsaInstruction::synthetic(SsaOp::Switch {
            value: state_var,
            targets: vec![2, 5],
            default: 6,
        }));
        ssa.add_block(b1);

        // B2: case 0 - has USER BRANCH
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
            true_target: 3,
            false_target: 4,
        }));
        ssa.add_block(b2);

        // B3a: true branch
        let mut b3a = SsaBlock::new(3);
        b3a.add_instruction(SsaInstruction::synthetic(SsaOp::Jump { target: 1 }));
        ssa.add_block(b3a);

        // B3b: false branch
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
    fn test_tree_trace_with_user_branch() {
        let ssa = create_cff_with_user_branch();
        let config = UnflattenConfig::default();
        let tree = trace_method_tree(&ssa, &config, None);

        println!("=== Tree Trace with User Branch ===");
        println!("Dispatcher: {:?}", tree.dispatcher);
        println!("Tainted vars: {:?}", tree.state_tainted);
        println!("Stats: {:?}", tree.stats);

        assert!(
            tree.stats.user_branch_count > 0,
            "Should have forked at branches"
        );

        assert!(tree.stats.exit_count > 0, "Should have exit points");

        println!("User branch count: {}", tree.stats.user_branch_count);
        println!("Exit count: {}", tree.stats.exit_count);

        println!(
            "Stats confirm {} user branches were created",
            tree.stats.user_branch_count
        );

        assert!(
            tree.stats.user_branch_count > 0,
            "Stats must show user branches"
        );
    }
}
