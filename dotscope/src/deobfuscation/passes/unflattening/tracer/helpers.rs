//! Standalone helper functions for CFF tracing.
//!
//! These functions are used by the [`super::engine`] and [`super::mod`] modules
//! but are factored out because they represent distinct concerns:
//!
//! - **Exception handler tracing** ([`trace_exception_handlers`]): Traces handler
//!   blocks in parallel, each with an independent context
//! - **Taint propagation** ([`propagate_taint_forward`]): Forward-only taint
//!   analysis to identify all variables derived from CFF state machinery
//! - **Call resolution** ([`resolve_call_result`]): Evaluates x86 predicate
//!   methods (ConfuserEx) by building the callee's SSA and running it
//! - **Expression switch detection** ([`detect_expression_switch`]): Identifies
//!   ConfuserEx "expression" mode branches where both arms select a CFF state
//!   constant merging at a common block
//! - **Statistics** ([`compute_tree_stats`]): Recursive tree traversal counting
//!   nodes, branches, transitions, exits, and max depth

use std::collections::BTreeSet;

use rayon::prelude::*;

use crate::{
    analysis::{
        ConstValue, PhiTaintMode, SsaBlock, SsaEvaluator, SsaFunction, SsaOp, SsaVarId,
        TaintAnalysis, TaintConfig,
    },
    deobfuscation::passes::unflattening::tracer::{
        context::TreeTraceContext,
        engine::trace_from_block,
        types::{HandlerTrace, TraceNode, TraceStats, TraceTerminator},
    },
    metadata::{token::Token, typesystem::PointerSize},
    CilObject,
};
use analyssa::BitSet;

/// Traces exception handler entry blocks that were not visited by the main trace.
///
/// Handler blocks (catch, finally, filter) are only reachable via runtime exceptions,
/// not explicit branches, so the main trace from block 0 never reaches them.
///
/// Each handler trace is fully independent — it uses a fresh evaluator, its own visit
/// state, and its own visit budget. This allows all handlers to be traced in parallel
/// using `fork_for_handler()` to create independent contexts that share only immutable
/// data (SSA, dispatcher info, taint seeds).
pub fn trace_exception_handlers(ctx: &mut TreeTraceContext<'_>) -> Vec<HandlerTrace> {
    let handler_blocks = ctx.unvisited_handler_blocks();
    if handler_blocks.is_empty() {
        return Vec::new();
    }

    // Give each handler a unique node ID offset so they don't collide.
    // Each handler gets a budget of max_block_visits IDs (generous upper bound).
    let id_base = ctx.next_id();
    let id_stride = ctx.max_block_visits();

    // Trace all handlers in parallel — each gets its own independent context
    let handler_traces: Vec<HandlerTrace> = handler_blocks
        .par_iter()
        .enumerate()
        .filter_map(|(i, &handler_start)| {
            let offset = i.saturating_mul(id_stride);
            let mut handler_ctx = ctx.fork_for_handler(id_base.saturating_add(offset));
            let root = trace_from_block(&mut handler_ctx, handler_start, 0);
            Some(HandlerTrace {
                handler_start_block: handler_start,
                root,
            })
        })
        .collect();

    // Advance the parent's node ID counter past all handler IDs
    let total_offset = handler_blocks.len().saturating_mul(id_stride);
    ctx.advance_node_id(id_base.saturating_add(total_offset));

    handler_traces
}

/// Propagates taint forward through instructions using the generic taint analysis.
///
/// Forward propagation: If an instruction uses a tainted variable, its def becomes tainted.
/// This is used to identify all variables that depend on state machinery.
///
/// This function uses the generic TaintAnalysis module with forward-only propagation
/// and NoPropagation for PHI nodes (to avoid over-tainting through merge points).
pub fn propagate_taint_forward(ssa: &SsaFunction, tainted: &mut BitSet) {
    // Configure for forward-only propagation without PHI propagation.
    // PHIs merge values from different paths, and some operands may be user code
    // while others are state machinery. Propagating through PHIs would incorrectly
    // filter user code that happens to share a merge point with state code.
    let config = TaintConfig {
        forward: true,
        backward: false,
        phi_mode: PhiTaintMode::NoPropagation,
        max_iterations: 100,
    };

    let mut taint = TaintAnalysis::new(config);

    // Initialize with existing tainted variables
    taint.add_tainted_vars(tainted.iter().map(SsaVarId::from_index));

    // Run propagation
    taint.propagate(ssa);

    // Update the tainted set with newly discovered tainted variables
    tainted.clear();
    for var in taint.tainted_variables() {
        tainted.insert(var.index());
    }

    // Post-pass: taint PHI results where ALL operands are tainted, then
    // re-propagate forward from newly tainted PHI results. This identifies
    // inner CFF dispatchers (e.g., JIEJIE.NET nested switch patterns) where
    // all incoming values are CFF machinery but the PHI result was not
    // tainted due to NoPropagation.
    let mut changed = true;
    while changed {
        changed = false;
        for block in ssa.blocks() {
            for phi in block.phi_nodes() {
                if !tainted.contains(phi.result().index())
                    && !phi.operands().is_empty()
                    && phi
                        .operands()
                        .iter()
                        .all(|op| tainted.contains(op.value().index()))
                {
                    tainted.insert(phi.result().index());
                    changed = true;
                }
            }
        }
        if changed {
            // Re-propagate forward from newly tainted PHI results
            let config = TaintConfig {
                forward: true,
                backward: false,
                phi_mode: PhiTaintMode::NoPropagation,
                max_iterations: 100,
            };
            let mut taint = TaintAnalysis::new(config);
            taint.add_tainted_vars(tainted.iter().map(SsaVarId::from_index));
            taint.propagate(ssa);
            tainted.clear();
            for var in taint.tainted_variables() {
                tainted.insert(var.index());
            }
        }
    }
}

/// Resolves a method call with concrete arguments by building the callee's SSA and evaluating it.
///
/// This is used for x86 predicate methods in ConfuserEx CFF, where state computation
/// is done via `call <Module>::predicate(arg1, arg2)` instead of inline arithmetic.
pub fn resolve_call_result(
    assembly: &CilObject,
    method_token: Token,
    concrete_args: &[ConstValue],
    pointer_size: PointerSize,
) -> Option<ConstValue> {
    // Look up the method
    let method = assembly.method(&method_token)?;

    // Build SSA for the callee
    let callee_ssa = method.ssa(assembly).ok()?;

    // Create evaluator for the callee
    let mut eval = SsaEvaluator::new(&callee_ssa, pointer_size);

    // Set concrete argument values
    for (var, value) in callee_ssa.argument_variables().zip(concrete_args) {
        eval.set_concrete(var.id(), value.clone());
    }

    // Execute with a safety limit of 50 blocks
    let trace = eval.execute(0, None, 50);

    // If execution didn't complete, we can't resolve the call
    if !trace.is_complete() {
        return None;
    }

    // Find the return value from the last block
    let last_block_idx = trace.last_block()?;
    let last_block = callee_ssa.block(last_block_idx)?;

    // Look for a Return instruction with a value
    for instr in last_block.instructions() {
        if let SsaOp::Return {
            value: Some(ret_var),
        } = instr.op()
        {
            return eval.get_concrete(*ret_var).cloned();
        }
    }

    None
}

/// Detects if a Branch is a CFF "expression switch" — both targets are
/// constant-producer blocks that merge into a single block feeding a
/// tainted CFF state computation. Returns the merge block index if matched.
///
/// ConfuserEx "expression" control flow mode wraps user conditionals so each
/// branch arm selects a different CFF state constant. Without detection, the
/// tracer forks O(2^N) at these branches. With detection, both forks share
/// accumulated tracking state so the false branch stops at the convergence point.
pub fn detect_expression_switch(
    ssa: &SsaFunction,
    true_target: usize,
    false_target: usize,
    tainted: &BitSet,
) -> Option<usize> {
    let (Some(tb), Some(fb)) = (ssa.block(true_target), ssa.block(false_target)) else {
        return None;
    };

    let true_merge = const_producer_target(tb)?;
    let false_merge = const_producer_target(fb)?;

    if true_merge != false_merge {
        return None;
    }

    let merge = ssa.block(true_merge)?;
    if merge.phi_nodes().is_empty() {
        return None;
    }

    let phi_results: BTreeSet<SsaVarId> =
        merge.phi_nodes().iter().map(|phi| phi.result()).collect();

    let feeds_tainted = merge.instructions().iter().any(|instr| match instr.op() {
        SsaOp::Xor { left, right, .. }
        | SsaOp::Add { left, right, .. }
        | SsaOp::Sub { left, right, .. }
        | SsaOp::Mul { left, right, .. } => {
            let one_is_phi = phi_results.contains(left) || phi_results.contains(right);
            let one_is_tainted = tainted.contains(left.index()) || tainted.contains(right.index());
            one_is_phi && one_is_tainted
        }
        _ => false,
    });

    feeds_tainted.then_some(true_merge)
}

/// Checks if a block is a "constant producer" and returns its jump target.
///
/// A constant producer block contains at most 2 non-terminator instructions
/// (all `Const`, `Copy`, or `Conv`) and ends with a `Jump`. These blocks
/// appear in ConfuserEx "expression" mode CFF: each branch arm pushes a
/// different state constant and jumps to a merge block that feeds the
/// dispatcher's state computation.
pub fn const_producer_target(block: &SsaBlock) -> Option<usize> {
    let instrs = block.instructions();
    if instrs.is_empty() {
        return None;
    }

    let target = match instrs.last()?.op() {
        SsaOp::Jump { target } => *target,
        _ => return None,
    };

    let non_term: Vec<_> = instrs.iter().filter(|i| !i.is_terminator()).collect();
    if non_term.len() > 2 {
        return None;
    }
    if !non_term.iter().all(|i| {
        matches!(
            i.op(),
            SsaOp::Const { .. } | SsaOp::Copy { .. } | SsaOp::Conv { .. }
        )
    }) {
        return None;
    }

    Some(target)
}

/// Computes statistics for a trace tree.
pub fn compute_tree_stats(node: &TraceNode, stats: &mut TraceStats, depth: usize) {
    stats.node_count = stats.node_count.saturating_add(1);
    stats.max_depth = stats.max_depth.max(depth);

    let next_depth = depth.saturating_add(1);
    match &node.terminator {
        TraceTerminator::Exit { .. } => {
            stats.exit_count = stats.exit_count.saturating_add(1);
        }
        TraceTerminator::StateTransition { continues, .. } => {
            stats.state_transition_count = stats.state_transition_count.saturating_add(1);
            compute_tree_stats(continues, stats, next_depth);
        }
        TraceTerminator::UserBranch {
            true_branch,
            false_branch,
            ..
        } => {
            stats.user_branch_count = stats.user_branch_count.saturating_add(1);
            compute_tree_stats(true_branch, stats, next_depth);
            compute_tree_stats(false_branch, stats, next_depth);
        }
        TraceTerminator::UserSwitch { cases, default, .. } => {
            stats.user_branch_count = stats.user_branch_count.saturating_add(1);
            for (_, case_node) in cases {
                compute_tree_stats(case_node, stats, next_depth);
            }
            compute_tree_stats(default, stats, next_depth);
        }
        TraceTerminator::Stopped { .. } | TraceTerminator::LoopBack { .. } => {}
        TraceTerminator::PendingStateTransition { .. } => {
            // Internal sentinel — should never appear in the final trace tree
        }
    }
}
