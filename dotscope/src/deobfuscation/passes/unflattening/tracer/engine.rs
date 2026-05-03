//! Core iterative tracing engine.
//!
//! Builds [`TraceTree`](super::types::TraceTree)s by walking SSA blocks,
//! evaluating instructions, and following CFF state transitions. User
//! branches/switches that don't depend on the state variable are forked
//! to capture all execution paths.
//!
//! # Architecture
//!
//! Tracing uses a three-level architecture to avoid stack overflow while
//! maintaining the tree structure:
//!
//! 1. **[`trace_from_block`]** — Outer driver. Manages an explicit work stack
//!    of [`WorkItem`] frames. Processes fork results (branch/switch arms) and
//!    assembles completed sub-trees into the parent node.
//!
//! 2. **[`trace_from_block_linear`]** — Middle layer. Handles state transition
//!    chains iteratively (dispatcher → case → dispatcher → case → ...) without
//!    recursion. When a fork is needed, pushes continuation frames onto the
//!    work stack and returns.
//!
//! 3. **[`trace_from_block_inner`]** — Inner loop. Processes blocks linearly
//!    until hitting a terminator that requires forking or state transition.
//!    Returns either a completed node or a [`ForkRequest`].

use std::collections::{BTreeMap, BTreeSet};

use crate::{
    analysis::{
        CmpKind, ConstValue, SsaBlock, SsaEvaluator, SsaInstruction, SsaOp, SsaVarId,
        VariableOrigin,
    },
    deobfuscation::passes::unflattening::tracer::{
        context::{ContextSnapshot, TreeTraceContext},
        helpers::{const_producer_target, detect_expression_switch, resolve_call_result},
        types::{InstructionWithValues, StopReason, TraceNode, TraceTerminator},
    },
};

/// Continuation frames for the iterative trace work stack.
///
/// Each variant represents a pending operation that was deferred when the
/// tracer encountered a branch or switch fork. Instead of recursing, the
/// tracer pushes these frames and processes them one at a time.
enum WorkItem<'a> {
    /// Start tracing a block. The resulting TraceNode becomes `current_result`.
    TraceBlock { block: usize, depth: usize },

    /// Link a state transition: attach `current_result` as the continuation
    /// of `parent_node` via a `StateTransition` terminator.
    StateTransitionLink {
        parent_node: TraceNode,
        from_state: i64,
        to_state: i64,
        target_block: usize,
    },

    /// After the true arm of a Branch/BranchCmp completes: restore context
    /// snapshot, then trace the false arm. Carries the true arm's result.
    BranchFalseArm {
        parent_node: TraceNode,
        block_idx: usize,
        condition: SsaVarId,
        false_target: usize,
        depth: usize,
        snapshot: ContextSnapshot<'a>,
        case_counts_snapshot: Option<Vec<u8>>,
        is_expr_switch: bool,
    },

    /// After the false arm completes: combine true + false into UserBranch.
    BranchCombine {
        parent_node: TraceNode,
        block_idx: usize,
        condition: SsaVarId,
        true_node: TraceNode,
        expr_switch_restore: Option<(usize, bool)>,
    },

    /// After a switch case completes: restore context and trace the next case,
    /// or if all cases are done, trace the default arm.
    SwitchNextCase {
        parent_node: TraceNode,
        block_idx: usize,
        value: SsaVarId,
        targets: Vec<usize>,
        default_target: usize,
        depth: usize,
        snapshot: ContextSnapshot<'a>,
        completed_cases: Vec<(i64, Box<TraceNode>)>,
        next_case_index: usize,
    },

    /// After the default arm completes: combine all cases into UserSwitch.
    SwitchCombine {
        parent_node: TraceNode,
        block_idx: usize,
        value: SsaVarId,
        cases: Vec<(i64, Box<TraceNode>)>,
    },
}

/// Traces from a block, building the trace tree iteratively.
///
/// State transitions (CFF case dispatches) and user branch/switch forks are
/// all handled via an explicit work stack to avoid stack overflow on deeply
/// nested methods. The resulting `TraceNode` tree is identical to what the
/// recursive version would produce.
pub fn trace_from_block(
    ctx: &mut TreeTraceContext<'_>,
    block_idx: usize,
    depth: usize,
) -> TraceNode {
    let mut work_stack: Vec<WorkItem<'_>> = Vec::new();
    let mut current_result: Option<TraceNode> = None;

    work_stack.push(WorkItem::TraceBlock {
        block: block_idx,
        depth,
    });

    loop {
        let Some(item) = work_stack.pop() else {
            return current_result.expect("trace work stack empty but no result");
        };

        match item {
            WorkItem::TraceBlock { block, depth } => {
                let result = trace_from_block_linear(ctx, block, depth, &mut work_stack);
                current_result = Some(result);
            }

            WorkItem::StateTransitionLink {
                mut parent_node,
                from_state,
                to_state,
                target_block,
            } => {
                let child = current_result
                    .take()
                    .expect("StateTransitionLink: missing child");
                parent_node.set_terminator(TraceTerminator::StateTransition {
                    from_state,
                    to_state,
                    target_block,
                    continues: Box::new(child),
                });
                current_result = Some(parent_node);
            }

            WorkItem::BranchFalseArm {
                parent_node,
                block_idx,
                condition,
                false_target,
                depth,
                snapshot,
                case_counts_snapshot,
                is_expr_switch,
            } => {
                let true_node = current_result
                    .take()
                    .expect("BranchFalseArm: missing true_node");

                // Restore context to the state before the true arm.
                // For expression switches, preserve the visited_case_counts
                // accumulated during the true arm (convergence via shared counts).
                let saved_case_counts = if case_counts_snapshot.is_none() {
                    Some(ctx.case_counts_snapshot())
                } else {
                    None
                };
                ctx.restore(snapshot);
                if let Some(counts) = saved_case_counts {
                    ctx.set_case_counts(counts);
                } else if let Some(ref counts) = case_counts_snapshot {
                    ctx.set_case_counts(counts.clone());
                }

                // Expression switch false arms: reset total_visits, set no_fork
                let expr_restore = if is_expr_switch {
                    Some(ctx.enter_expr_switch_false_arm())
                } else {
                    None
                };

                ctx.evaluator_mut().set_predecessor(Some(block_idx));

                // Push combine (processed AFTER the false arm completes),
                // then the false arm trace (processed FIRST due to stack LIFO).
                work_stack.push(WorkItem::BranchCombine {
                    parent_node,
                    block_idx,
                    condition,
                    true_node,
                    expr_switch_restore: expr_restore,
                });
                work_stack.push(WorkItem::TraceBlock {
                    block: false_target,
                    depth: depth + 1,
                });
            }

            WorkItem::BranchCombine {
                mut parent_node,
                block_idx,
                condition,
                true_node,
                expr_switch_restore,
            } => {
                let false_node = current_result
                    .take()
                    .expect("BranchCombine: missing false_node");

                if let Some(saved) = expr_switch_restore {
                    ctx.exit_expr_switch_false_arm(saved);
                }

                parent_node.set_terminator(TraceTerminator::UserBranch {
                    block: block_idx,
                    condition,
                    true_branch: Box::new(true_node),
                    false_branch: Box::new(false_node),
                });
                current_result = Some(parent_node);
            }

            WorkItem::SwitchNextCase {
                parent_node,
                block_idx,
                value,
                targets,
                default_target,
                depth,
                snapshot,
                mut completed_cases,
                next_case_index,
            } => {
                // Collect the result from the previous case (if any)
                if let Some(prev_result) = current_result.take() {
                    if next_case_index > 0 {
                        #[allow(clippy::cast_possible_wrap)]
                        let case_value = (next_case_index - 1) as i64;
                        completed_cases.push((case_value, Box::new(prev_result)));
                    }
                }

                if next_case_index < targets.len() {
                    // More cases to trace — restore and trace the next one
                    ctx.restore(snapshot.clone_snapshot());
                    ctx.evaluator_mut().set_predecessor(Some(block_idx));

                    let target = targets[next_case_index];

                    work_stack.push(WorkItem::SwitchNextCase {
                        parent_node,
                        block_idx,
                        value,
                        targets,
                        default_target,
                        depth,
                        snapshot,
                        completed_cases,
                        next_case_index: next_case_index + 1,
                    });
                    work_stack.push(WorkItem::TraceBlock {
                        block: target,
                        depth,
                    });
                } else {
                    // All cases done — restore and trace the default arm
                    ctx.restore(snapshot);
                    ctx.evaluator_mut().set_predecessor(Some(block_idx));

                    work_stack.push(WorkItem::SwitchCombine {
                        parent_node,
                        block_idx,
                        value,
                        cases: completed_cases,
                    });
                    work_stack.push(WorkItem::TraceBlock {
                        block: default_target,
                        depth,
                    });
                }
            }

            WorkItem::SwitchCombine {
                mut parent_node,
                block_idx,
                value,
                cases,
            } => {
                let default_node = current_result
                    .take()
                    .expect("SwitchCombine: missing default_node");
                parent_node.set_terminator(TraceTerminator::UserSwitch {
                    block: block_idx,
                    value,
                    cases,
                    default: Box::new(default_node),
                });
                current_result = Some(parent_node);
            }
        }
    }
}

/// Traces linearly from a block, handling state transitions iteratively.
///
/// Returns a completed `TraceNode` when the trace reaches a leaf (exit, loop,
/// stop). When a user branch/switch fork is needed, pushes continuation frames
/// onto the `work_stack` and returns the node-so-far as `current_result` so
/// the outer `trace_from_block` loop can process the fork.
fn trace_from_block_linear<'a>(
    ctx: &mut TreeTraceContext<'a>,
    block_idx: usize,
    depth: usize,
    work_stack: &mut Vec<WorkItem<'a>>,
) -> TraceNode {
    // State transition chain — same iterative mechanism as before.
    let mut transition_chain: Vec<(TraceNode, i64, usize)> = Vec::new();
    let mut entry_block = block_idx;

    let result = loop {
        let (leaf, fork) = trace_from_block_inner(ctx, entry_block, depth);

        if let Some(fork) = fork {
            // The inner tracer hit a branch/switch that needs forking.
            // Push the transition chain (if any) as StateTransitionLink work
            // items, then push the fork work items, and return the leaf node.

            // Push transition chain in forward order: the stack is LIFO, so
            // the FIRST transition (closest to method entry) is pushed first and
            // popped LAST, making it the outermost node (root) of the tree.
            let to_state = ctx.current_state().unwrap_or(0);
            for (parent, from_state, target_block) in transition_chain.drain(..) {
                work_stack.push(WorkItem::StateTransitionLink {
                    parent_node: parent,
                    from_state,
                    to_state,
                    target_block,
                });
            }

            // Push fork continuation items. Use block_idx from the fork
            // (the block where the branch/switch terminator was encountered),
            // NOT leaf.start_block (which may be an earlier block).
            match fork {
                ForkRequest::Branch {
                    block_idx,
                    condition,
                    true_target,
                    false_target,
                    snapshot,
                    case_counts_snapshot,
                    is_expr_switch,
                } => {
                    ctx.evaluator_mut().set_predecessor(Some(block_idx));
                    work_stack.push(WorkItem::BranchFalseArm {
                        parent_node: leaf,
                        block_idx,
                        condition,
                        false_target,
                        depth,
                        snapshot,
                        case_counts_snapshot,
                        is_expr_switch,
                    });
                    work_stack.push(WorkItem::TraceBlock {
                        block: true_target,
                        depth: depth + 1,
                    });
                }
                ForkRequest::Switch {
                    block_idx,
                    value,
                    targets,
                    default_target,
                    snapshot,
                    is_foreign,
                } => {
                    let fork_depth = if is_foreign { depth } else { depth + 1 };
                    if targets.is_empty() {
                        ctx.evaluator_mut().set_predecessor(Some(block_idx));
                        return leaf;
                    }
                    ctx.evaluator_mut().set_predecessor(Some(block_idx));
                    let first_target = targets[0];
                    work_stack.push(WorkItem::SwitchNextCase {
                        parent_node: leaf,
                        block_idx,
                        value,
                        targets,
                        default_target,
                        depth: fork_depth,
                        snapshot,
                        completed_cases: Vec::new(),
                        next_case_index: 1,
                    });
                    work_stack.push(WorkItem::TraceBlock {
                        block: first_target,
                        depth: fork_depth,
                    });
                }
            }

            // Return a dummy node — the actual result will be built by the
            // work stack continuations. The first TraceBlock pushed will set
            // current_result when it completes.
            return TraceNode::new(0, 0);
        }

        // Check if the leaf needs a state transition continuation
        if let Some((from_state, target_block)) = leaf.pending_state_transition() {
            transition_chain.push((leaf, from_state, target_block));
            entry_block = target_block;
            continue;
        }

        // Leaf is complete
        break leaf;
    };

    // Unwind the transition chain
    let to_state = ctx.current_state().unwrap_or(0);
    let mut leaf = result;
    while let Some((mut parent, from_state, target_block)) = transition_chain.pop() {
        parent.set_terminator(TraceTerminator::StateTransition {
            from_state,
            to_state,
            target_block,
            continues: Box::new(leaf),
        });
        leaf = parent;
    }

    leaf
}

/// Fork request returned by the inner tracer when it encounters a user
/// branch or switch that needs to trace multiple arms.
enum ForkRequest<'a> {
    Branch {
        block_idx: usize,
        condition: SsaVarId,
        true_target: usize,
        false_target: usize,
        snapshot: ContextSnapshot<'a>,
        case_counts_snapshot: Option<Vec<u8>>,
        is_expr_switch: bool,
    },
    Switch {
        block_idx: usize,
        value: SsaVarId,
        targets: Vec<usize>,
        default_target: usize,
        snapshot: ContextSnapshot<'a>,
        is_foreign: bool,
    },
}

/// Inner tracing logic — processes blocks linearly until a decision point.
///
/// Walks through consecutive blocks, evaluating instructions and propagating
/// taint. Returns when it hits:
/// - A **state transition** (dispatcher switch resolved) → returns
///   `(node, None)` with a pending state transition for the caller to continue
/// - A **user branch/switch** (non-state-dependent fork) → returns
///   `(node, Some(ForkRequest))` for the caller to trace both arms
/// - A **leaf** (return, throw, loop, stop) → returns `(node, None)` as a
///   completed terminal node
fn trace_from_block_inner<'a>(
    ctx: &mut TreeTraceContext<'a>,
    block_idx: usize,
    depth: usize,
) -> (TraceNode, Option<ForkRequest<'a>>) {
    let mut node = TraceNode::new(ctx.next_id(), block_idx);

    // Safety limits
    if depth > ctx.max_tree_depth() {
        node.set_terminator(TraceTerminator::Stopped {
            reason: StopReason::MaxVisitsExceeded,
        });
        return (node, None);
    }

    // Check for loop: same block visited in the same execution context.
    // The visit key includes the last dispatched case index AND its visit
    // count, so re-entering the same case after a loop exit (with an
    // incremented count) produces a different key and is allowed.
    if ctx.is_visited(block_idx) {
        let state = ctx.current_state().unwrap_or(0);
        node.set_terminator(TraceTerminator::LoopBack {
            target_block: block_idx,
            state,
        });
        return (node, None);
    }
    // Dispatcher target blocks are not marked — their revisit detection is
    // handled by visited_case_counts at the switch handler. Sub-blocks within
    // case chains ARE marked to prevent unbounded expansion.
    if !ctx.is_dispatch_target(block_idx) {
        ctx.mark_visited(block_idx);
    }

    // Bind SSA reference once — it's a shared &SsaFunction that doesn't
    // borrow the mutable parts of ctx, avoiding borrow conflicts with
    // evaluator_mut()/taint()/etc.
    let ssa = ctx.ssa();

    // Process blocks until we hit a decision point
    let mut current_block = block_idx;

    loop {
        // Safety: detect cycles in the linear block chain.
        // If we revisit a block within the same trace_from_block call,
        // we have an unconditional loop (e.g., Jump back-edge).
        if ctx.check_visit_budget() {
            node.set_terminator(TraceTerminator::Stopped {
                reason: StopReason::MaxVisitsExceeded,
            });
            return (node, None);
        }
        // Exempt the dispatcher block — it's intentionally revisited as it dispatches
        // to different case blocks based on the state variable.
        let is_dispatcher = ctx.is_dispatcher_block(current_block);
        if !is_dispatcher
            && current_block != block_idx
            && node.blocks_visited.len() > 1
            && node.blocks_visited[..node.blocks_visited.len() - 1].contains(&current_block)
        {
            let state = ctx.current_state().unwrap_or(0);
            node.set_terminator(TraceTerminator::LoopBack {
                target_block: current_block,
                state,
            });
            return (node, None);
        }

        // Handle dispatcher re-entry: clear stale values and fix predecessor
        let is_dispatcher_reentry = is_dispatcher
            && node.blocks_visited.len() > 1
            && node.blocks_visited[..node.blocks_visited.len() - 1].contains(&current_block);
        if is_dispatcher_reentry {
            if let Some(block) = ssa.block(current_block) {
                for instr in block.instructions() {
                    if let Some(def) = instr.def() {
                        ctx.evaluator_mut().set_unknown(def);
                    }
                }

                if let Some(state_var) = ctx.state_var() {
                    for phi in block.phi_nodes() {
                        if phi.result() == state_var {
                            for op in phi.operands() {
                                let op_pred = op.predecessor();
                                if node.blocks_visited.contains(&op_pred)
                                    && ctx.evaluator().get_concrete(op.value()).is_some()
                                {
                                    ctx.evaluator_mut().set_predecessor(Some(op_pred));
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }

        let Some(block) = ssa.block(current_block) else {
            node.set_terminator(TraceTerminator::Stopped {
                reason: StopReason::UnknownControlFlow {
                    block: current_block,
                },
            });
            return (node, None);
        };

        // Set predecessor for phi evaluation
        if node.blocks_visited.len() > 1 {
            let prev = node.blocks_visited[node.blocks_visited.len() - 2];
            ctx.evaluator_mut().set_predecessor(Some(prev));
        }

        // Bridge loop-carried phi operand values for dispatcher blocks
        if is_dispatcher {
            bridge_phi_operands(ctx, current_block);
        }

        // Evaluate all phis for this block.
        ctx.evaluator_mut().evaluate_phis(current_block);

        // Propagate taint through PHI nodes conservatively: only taint the
        // PHI result if ALL operands are already state-tainted.
        if let Some(block) = ssa.block(current_block) {
            for phi in block.phi_nodes() {
                if !phi.operands().is_empty()
                    && phi.operands().iter().all(|op| ctx.is_tainted(op.value()))
                {
                    ctx.taint(phi.result());
                }
            }
        }

        // Process instructions with cross-scope variable bridging
        for instr in block.instructions() {
            let step = trace_instruction(ctx, instr, current_block);
            node.add_instruction(step);

            // Bridge unknown local-variable references from known definitions
            // of the same local index (cross-scope reaching definitions).
            if let SsaOp::Copy { dest, src } = instr.op() {
                if ctx.evaluator().get(*dest).is_none() {
                    if let Some(src_var) = ssa.variable(*src) {
                        if let VariableOrigin::Local(local_idx) = src_var.origin() {
                            for var in ssa.variables() {
                                if var.id() != *src
                                    && matches!(var.origin(), VariableOrigin::Local(li) if li == local_idx)
                                {
                                    if let Some(val) = ctx.evaluator().get(var.id()).cloned() {
                                        ctx.evaluator_mut().set_symbolic_expr(*dest, val);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Handle terminator
        match handle_terminator(ctx, block, current_block, &mut node, depth) {
            TerminatorResult::Continue(next) => {
                node.visit_block(next);
                current_block = next;
            }
            TerminatorResult::Done => return (node, None),
            TerminatorResult::StateTransition {
                from_state,
                target_block,
            } => {
                node.set_pending_state_transition(from_state, target_block);
                return (node, None);
            }
            TerminatorResult::ForkBranch {
                block_idx,
                condition,
                true_target,
                false_target,
                snapshot,
                case_counts_snapshot,
                is_expr_switch,
            } => {
                return (
                    node,
                    Some(ForkRequest::Branch {
                        block_idx,
                        condition,
                        true_target,
                        false_target,
                        snapshot,
                        case_counts_snapshot,
                        is_expr_switch,
                    }),
                );
            }
            TerminatorResult::ForkSwitch {
                block_idx,
                value,
                targets,
                default_target,
                snapshot,
                is_foreign,
            } => {
                return (
                    node,
                    Some(ForkRequest::Switch {
                        block_idx,
                        value,
                        targets,
                        default_target,
                        snapshot,
                        is_foreign,
                    }),
                );
            }
        }
    }
}

/// Bridges loop-carried phi operand values for dispatcher blocks.
///
/// In CFF dispatcher loops, the phi operand variable from the case block may
/// differ from the variable the evaluator tracked due to SSA variable renaming
/// at loop boundaries. This bridge ensures evaluate_phis can find the value.
fn bridge_phi_operands(ctx: &mut TreeTraceContext<'_>, block_idx: usize) {
    let ssa = ctx.ssa();
    let (Some(sv), Some(block)) = (ctx.state_var(), ssa.block(block_idx)) else {
        return;
    };

    let pred = ctx.evaluator().predecessor();
    for phi in block.phi_nodes() {
        if phi.result() == sv {
            if let Some(op) = phi
                .operands()
                .iter()
                .find(|op| pred.is_some_and(|p| op.predecessor() == p))
            {
                let op_var = op.value();
                if ctx.evaluator().get(op_var).is_none() {
                    if let Some(pred_idx) = pred {
                        if let Some(pred_block) = ssa.block(pred_idx) {
                            let bridged = pred_block
                                .instructions()
                                .iter()
                                .rev()
                                .filter(|i| !i.is_terminator())
                                .find_map(|i| {
                                    i.def().and_then(|d| {
                                        ctx.evaluator().get(d).cloned().map(|v| (d, v))
                                    })
                                });
                            if let Some((_def_var, val)) = bridged {
                                ctx.evaluator_mut().set_symbolic_expr(op_var, val);
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Result of handling a block terminator instruction.
///
/// Tells the inner trace loop how to proceed after processing a block's
/// terminator (jump, branch, switch, return, etc.).
enum TerminatorResult<'a> {
    /// Follow an unconditional edge to the next block (jump, leave).
    /// The caller continues the linear block chain within the same node.
    Continue(usize),
    /// The node is complete — terminator has been set (exit, stop, loop).
    Done,
    /// CFF state transition: the dispatcher resolved to a case block.
    /// The caller should continue iteratively from `target_block`.
    StateTransition {
        from_state: i64,
        target_block: usize,
    },
    /// User branch (non-state-dependent) requires forking into true/false arms.
    ForkBranch {
        block_idx: usize,
        condition: SsaVarId,
        true_target: usize,
        false_target: usize,
        snapshot: ContextSnapshot<'a>,
        case_counts_snapshot: Option<Vec<u8>>,
        is_expr_switch: bool,
    },
    /// User switch (non-state-dependent) requires forking into N case arms + default.
    ForkSwitch {
        block_idx: usize,
        value: SsaVarId,
        targets: Vec<usize>,
        default_target: usize,
        snapshot: ContextSnapshot<'a>,
        is_foreign: bool,
    },
}

/// Handles a block terminator, potentially forking the trace.
fn handle_terminator<'a>(
    ctx: &mut TreeTraceContext<'a>,
    block: &SsaBlock,
    block_idx: usize,
    node: &mut TraceNode,
    depth: usize,
) -> TerminatorResult<'a> {
    let Some(terminator) = block.instructions().last() else {
        node.set_terminator(TraceTerminator::Stopped {
            reason: StopReason::UnknownControlFlow { block: block_idx },
        });
        return TerminatorResult::Done;
    };

    match terminator.op() {
        SsaOp::Jump { target } => TerminatorResult::Continue(*target),

        SsaOp::Leave { target } => TerminatorResult::Continue(*target),

        SsaOp::Branch {
            condition,
            true_target,
            false_target,
        } => {
            if ctx.is_tainted(*condition) {
                // State-dependent branch - evaluate and follow one path
                match ctx
                    .evaluator()
                    .get_concrete(*condition)
                    .and_then(ConstValue::as_i64)
                {
                    Some(v) if v != 0 => TerminatorResult::Continue(*true_target),
                    Some(_) => TerminatorResult::Continue(*false_target),
                    None => {
                        node.set_terminator(TraceTerminator::Stopped {
                            reason: StopReason::UnknownControlFlow { block: block_idx },
                        });
                        TerminatorResult::Done
                    }
                }
            } else {
                handle_user_branch_fork(
                    ctx,
                    block_idx,
                    *true_target,
                    *false_target,
                    *condition,
                    depth,
                )
            }
        }

        SsaOp::BranchCmp {
            left,
            right,
            cmp,
            unsigned,
            true_target,
            false_target,
        } => {
            let left_val = ctx.evaluator().get_concrete(*left).cloned();
            let right_val = ctx.evaluator().get_concrete(*right).cloned();
            let tainted = ctx.is_tainted(*left) || ctx.is_tainted(*right);

            if tainted {
                // State-tainted branch comparison — try to evaluate concretely.
                // NETReactor CFF uses beq overflow checks after the switch dispatcher:
                //   ldloc <state_var>; ldc.i4 <val>; beq <target>
                // The state variable is tainted but has a known concrete value.
                if let (Some(l), Some(r)) = (&left_val, &right_val) {
                    if SsaEvaluator::evaluate_comparison(l, r, *cmp, *unsigned) {
                        return TerminatorResult::Continue(*true_target);
                    }
                    return TerminatorResult::Continue(*false_target);
                }
            }

            // NETReactor overflow dispatch: at blocks on the dispatcher's
            // default fall-through chain, `beq state, <const>` routes each
            // overflow state value to its real case target. After LICM
            // consolidates per-case Consts to a shared dominator, taint
            // attribution is lost and state never becomes concrete here —
            // but the check's *structure* (dispatcher-reachable block,
            // `BranchCmp(var, Const, Eq)`) is still recognizable. Fork the
            // comparison as a CFF continuation: seed state = const on the
            // true arm (so the case body traces through to its next state
            // update), leave state unknown on the false arm (so it chains to
            // subsequent overflow checks or the final fall-through).
            if *cmp == CmpKind::Eq && is_overflow_dispatch_site(ctx, block_idx) {
                let overflow_seed = match (left_val.clone(), right_val.clone()) {
                    (None, Some(r)) => Some((*left, r)),
                    (Some(l), None) => Some((*right, l)),
                    _ => None,
                };
                if let Some((unknown_var, const_val)) = overflow_seed {
                    let snapshot = ctx.snapshot();
                    if let Some(state_var) = ctx.state_var() {
                        ctx.evaluator_mut()
                            .set_concrete(state_var, const_val.clone());
                    }
                    ctx.evaluator_mut().set_concrete(unknown_var, const_val);
                    let case_counts_snapshot = Some(ctx.case_counts_snapshot());
                    return TerminatorResult::ForkBranch {
                        block_idx,
                        condition: unknown_var,
                        true_target: *true_target,
                        false_target: *false_target,
                        snapshot,
                        case_counts_snapshot,
                        is_expr_switch: false,
                    };
                }
            }

            if tainted {
                node.set_terminator(TraceTerminator::Stopped {
                    reason: StopReason::UnknownControlFlow { block: block_idx },
                });
                TerminatorResult::Done
            } else {
                // BranchCmp in no_fork mode has an additional check: allow forking
                // for conditional CFF state transitions even when no_fork is set.
                let is_expr_switch = detect_expression_switch(
                    ctx.ssa(),
                    *true_target,
                    *false_target,
                    ctx.state_tainted(),
                )
                .is_some();

                if ctx.no_fork() && !is_expr_switch {
                    let is_cff_state_transition =
                        is_conditional_state_transition(ctx, *true_target, *false_target);
                    if !is_cff_state_transition {
                        return TerminatorResult::Continue(*true_target);
                    }
                }

                build_fork_branch(
                    ctx,
                    block_idx,
                    *true_target,
                    *false_target,
                    *left,
                    is_expr_switch,
                )
            }
        }

        SsaOp::Switch {
            value,
            targets,
            default,
        } => handle_switch(ctx, node, block_idx, value, targets, default, depth),

        SsaOp::Return { .. } | SsaOp::Throw { .. } => {
            node.set_terminator(TraceTerminator::Exit { block: block_idx });
            TerminatorResult::Done
        }

        _ => {
            node.set_terminator(TraceTerminator::Stopped {
                reason: StopReason::UnknownControlFlow { block: block_idx },
            });
            TerminatorResult::Done
        }
    }
}

/// Handles a user branch fork for both Branch and BranchCmp terminators.
///
/// Detects expression switches, respects no_fork mode, creates snapshot
/// and returns a ForkBranch result.
fn handle_user_branch_fork<'a>(
    ctx: &mut TreeTraceContext<'a>,
    block_idx: usize,
    true_target: usize,
    false_target: usize,
    condition: SsaVarId,
    _: usize,
) -> TerminatorResult<'a> {
    let is_expr_switch =
        detect_expression_switch(ctx.ssa(), true_target, false_target, ctx.state_tainted())
            .is_some();

    // In no_fork mode, only fork for expression switches.
    if ctx.no_fork() && !is_expr_switch {
        return TerminatorResult::Continue(true_target);
    }

    build_fork_branch(
        ctx,
        block_idx,
        true_target,
        false_target,
        condition,
        is_expr_switch,
    )
}

/// Builds a ForkBranch result with the appropriate snapshot.
fn build_fork_branch<'a>(
    ctx: &mut TreeTraceContext<'a>,
    block_idx: usize,
    true_target: usize,
    false_target: usize,
    condition: SsaVarId,
    is_expr_switch: bool,
) -> TerminatorResult<'a> {
    let snapshot = ctx.snapshot();
    let case_counts_snapshot = if is_expr_switch {
        None
    } else {
        Some(ctx.case_counts_snapshot())
    };

    TerminatorResult::ForkBranch {
        block_idx,
        condition,
        true_target,
        false_target,
        snapshot,
        case_counts_snapshot,
        is_expr_switch,
    }
}

/// Checks if a branch is a conditional CFF state transition.
///
/// Both arms are const-producers merging at a common block that reaches the
/// dispatcher. This pattern MUST be forked even in no_fork mode to populate
/// merge-point clone requests.
fn is_conditional_state_transition(
    ctx: &TreeTraceContext<'_>,
    true_target: usize,
    false_target: usize,
) -> bool {
    let Some(db) = ctx.dispatcher_block() else {
        return false;
    };

    let true_merge = ctx.ssa().block(true_target).and_then(const_producer_target);
    let false_merge = ctx
        .ssa()
        .block(false_target)
        .and_then(const_producer_target);

    match (true_merge, false_merge) {
        (Some(tm), Some(fm)) if tm == fm => {
            // Verify the merge block reaches the dispatcher
            let mut block = tm;
            for _ in 0..3 {
                if block == db {
                    return true;
                }
                match ctx.ssa().block(block).and_then(|b| b.terminator_op()) {
                    Some(SsaOp::Jump { target }) => block = *target,
                    _ => break,
                }
            }
            block == db
        }
        _ => false,
    }
}

/// Returns true if `block_idx` sits on the dispatcher's overflow chain.
///
/// NETReactor's default dispatcher target chains one or more
/// `BranchCmp(state_var, Const(N), Eq)` checks to route overflow state values
/// (values greater than the switch table size) to their real case targets.
/// These chain blocks contain only Const/Copy/Jump/Nop and state-tainted
/// BranchCmp terminators — no user work. Detection walks predecessors up to a
/// short bound: if any predecessor is the dispatcher (reached directly or
/// through other pure/overflow blocks), the current block is part of the
/// chain and a tainted BranchCmp can safely be forked as a CFF continuation
/// rather than preserved as user code.
fn is_overflow_dispatch_site(ctx: &TreeTraceContext<'_>, block_idx: usize) -> bool {
    let Some(dispatcher) = ctx.dispatcher_block() else {
        return false;
    };
    if block_idx == dispatcher {
        return false;
    }

    const MAX_HOPS: usize = 8;
    let mut frontier: Vec<usize> = vec![block_idx];
    let mut visited: BTreeSet<usize> = BTreeSet::new();
    visited.insert(block_idx);

    for _ in 0..MAX_HOPS {
        let mut next_frontier: Vec<usize> = Vec::new();
        for &b in &frontier {
            for pred in ctx.ssa().block_predecessors(b) {
                // Reaching the primary dispatcher (directly or through
                // chain blocks) identifies this as an overflow site. A
                // predecessor whose terminator is itself a `Switch` — a
                // nested CFF dispatcher or any foreign dispatcher in this
                // method — also qualifies, since overflow chains hang off
                // such switches' default paths.
                if pred == dispatcher || ctx.is_other_dispatcher(pred) {
                    return true;
                }
                if let Some(pred_block) = ctx.ssa().block(pred) {
                    if matches!(pred_block.terminator_op(), Some(SsaOp::Switch { .. })) {
                        return true;
                    }
                }
                if !visited.insert(pred) {
                    continue;
                }
                let Some(pred_block) = ctx.ssa().block(pred) else {
                    continue;
                };
                // Only chain through blocks that carry no user-visible work:
                // pure CFG plumbing (Const/Copy/Jump/Nop) plus overflow
                // BranchCmp terminators. This prevents false positives when
                // the tainted comparison sits downstream of user code.
                let is_chain_block = pred_block.instructions().iter().all(|instr| {
                    matches!(
                        instr.op(),
                        SsaOp::Const { .. }
                            | SsaOp::Copy { .. }
                            | SsaOp::Jump { .. }
                            | SsaOp::Nop
                            | SsaOp::BranchCmp { .. }
                    )
                });
                if is_chain_block {
                    next_frontier.push(pred);
                }
            }
        }
        if next_frontier.is_empty() {
            break;
        }
        frontier = next_frontier;
    }
    false
}

/// Returns true when `default` leads to an `BranchCmp(_, _, Eq)` overflow
/// check within a short pure-chain. Used to gate the A1 fallback in
/// [`handle_switch`]: we only route a case-loop to the default arm when
/// that arm is structurally an overflow dispatch (not, e.g., a user
/// if/else chain encoded via the switch default).
///
/// "Pure chain" means blocks whose instructions are only Const/Copy/
/// Jump/Nop — the same shape `is_overflow_dispatch_site` recognizes on
/// the predecessor side. A BranchCmp-terminated block with one concrete
/// operand is the hallmark of NETReactor's overflow dispatch.
fn default_has_overflow_check(ctx: &TreeTraceContext<'_>, default: usize) -> bool {
    const MAX_HOPS: usize = 4;
    let mut current = default;
    for _ in 0..MAX_HOPS {
        let Some(block) = ctx.ssa().block(current) else {
            return false;
        };
        match block.terminator_op() {
            Some(SsaOp::BranchCmp {
                cmp: CmpKind::Eq,
                left,
                right,
                ..
            }) => {
                // Confirm at least one operand is a tracked constant (the
                // overflow value). This rules out generic user beq/bne
                // structures that happen to sit on a default arm.
                return ctx.evaluator().get_concrete(*left).is_some()
                    || ctx.evaluator().get_concrete(*right).is_some();
            }
            Some(SsaOp::Jump { target }) => {
                let is_pure = block.instructions().iter().all(|instr| {
                    matches!(
                        instr.op(),
                        SsaOp::Const { .. } | SsaOp::Copy { .. } | SsaOp::Jump { .. } | SsaOp::Nop
                    )
                });
                if !is_pure {
                    return false;
                }
                current = *target;
            }
            _ => return false,
        }
    }
    false
}

/// Handles a switch terminator (dispatcher or user switch).
fn handle_switch<'a>(
    ctx: &mut TreeTraceContext<'a>,
    node: &mut TraceNode,
    block_idx: usize,
    value: &SsaVarId,
    targets: &[usize],
    default: &usize,
    _: usize,
) -> TerminatorResult<'a> {
    let is_dispatcher = ctx.is_dispatcher_block(block_idx);

    let is_argument = ctx
        .ssa()
        .variable(*value)
        .is_some_and(|v| matches!(v.origin(), VariableOrigin::Argument(_)));

    if !is_argument && (is_dispatcher || ctx.is_tainted(*value)) {
        // State-driven switch (dispatcher) - evaluate and follow
        let concrete_value = ctx
            .evaluator()
            .get_concrete(*value)
            .and_then(ConstValue::as_u64)
            .or_else(|| {
                // ECMA-335 §I.12.3.2.2: uninitialized locals are zero-initialized
                let var = ctx.ssa().variable(*value)?;
                let site = var.def_site();
                let is_entry = site.block == 0 && site.instruction.is_none();
                if is_entry && matches!(var.origin(), VariableOrigin::Local(_)) {
                    Some(0)
                } else {
                    None
                }
            });

        if let Some(idx) = concrete_value {
            // Defense-in-depth: verify state variable was resolved
            if is_dispatcher {
                if let Some(state_var) = ctx.state_var() {
                    if ctx.evaluator().get(state_var).is_none() {
                        node.set_terminator(TraceTerminator::Stopped {
                            reason: StopReason::UnknownControlFlow { block: block_idx },
                        });
                        return TerminatorResult::Done;
                    }
                }
            }

            #[allow(clippy::cast_possible_truncation)]
            let idx_usize = idx as usize;
            let target = if idx_usize < targets.len() {
                targets[idx_usize]
            } else {
                *default
            };

            let from_state = ctx.current_state().unwrap_or(0);

            // Check for CFF loop back-edge
            if ctx.is_case_loop(idx_usize, targets.len()) {
                // LoopBack on the real case target. This is the correct
                // response for both:
                //   1. Legitimate user-loop iterations (same case re-entered
                //      as the loop body executes).
                //   2. Tightly-looping CFF paths that the tracer cannot make
                //      further progress on.
                //
                // A previous "A1 fallback" variant routed to the dispatcher's
                // default (overflow chain) with state cleared, meant to work
                // around LICM-induced stuck-state propagation. With the LICM
                // hoist guard now preventing per-edge state Consts from being
                // hoisted into shared preheaders, that workaround would
                // corrupt legitimate user-loop paths (clone the case target
                // into the overflow chain and infinite-loop inside it), so we
                // always prefer LoopBack here.

                let state = ctx.current_state().unwrap_or(0);
                let mut loop_node = TraceNode::new(ctx.next_id(), target);
                loop_node.set_terminator(TraceTerminator::LoopBack {
                    target_block: target,
                    state,
                });

                node.set_terminator(TraceTerminator::StateTransition {
                    from_state,
                    to_state: state,
                    target_block: target,
                    continues: Box::new(loop_node),
                });
                return TerminatorResult::Done;
            }
            ctx.record_case_dispatch(idx_usize);
            ctx.record_case_state(idx_usize, from_state);

            ctx.evaluator_mut().set_predecessor(Some(block_idx));

            TerminatorResult::StateTransition {
                from_state,
                target_block: target,
            }
        } else if is_dispatcher {
            node.set_terminator(TraceTerminator::Stopped {
                reason: StopReason::UnknownControlFlow { block: block_idx },
            });
            TerminatorResult::Done
        } else {
            handle_user_switch(ctx, block_idx, value, targets, default)
        }
    } else {
        handle_user_switch(ctx, block_idx, value, targets, default)
    }
}

/// Handles a user switch by forking for all cases.
fn handle_user_switch<'a>(
    ctx: &mut TreeTraceContext<'a>,
    block_idx: usize,
    value: &SsaVarId,
    targets: &[usize],
    default: &usize,
) -> TerminatorResult<'a> {
    // No-fork mode: follow the evaluated path or first target.
    if ctx.no_fork() {
        let target = ctx
            .evaluator()
            .get_concrete(*value)
            .and_then(|v| v.as_u64())
            .and_then(|idx| targets.get(idx as usize).copied())
            .unwrap_or_else(|| targets.first().copied().unwrap_or(*default));
        return TerminatorResult::Continue(target);
    }

    let is_foreign = ctx.is_other_dispatcher(block_idx);
    let snapshot = ctx.snapshot();

    TerminatorResult::ForkSwitch {
        block_idx,
        value: *value,
        targets: targets.to_vec(),
        default_target: *default,
        snapshot,
        is_foreign,
    }
}

/// Traces a single instruction, evaluating it and recording values.
fn trace_instruction(
    ctx: &mut TreeTraceContext<'_>,
    instr: &SsaInstruction,
    block_idx: usize,
) -> InstructionWithValues {
    // Capture input values BEFORE evaluation
    let input_values: BTreeMap<SsaVarId, i64> = instr
        .uses()
        .iter()
        .filter_map(|&var| {
            ctx.evaluator()
                .get_concrete(var)
                .and_then(ConstValue::as_i64)
                .map(|v| (var, v))
        })
        .collect();

    if ctx.any_tainted(&instr.uses()) {
        if let Some(def) = instr.def() {
            ctx.taint(def);
        }
    }

    // Evaluate the instruction
    ctx.evaluator_mut().evaluate_op(instr.op());

    // Resolve calls with concrete arguments (e.g., x86 predicate methods)
    if let SsaOp::Call {
        dest: Some(dest),
        method,
        args,
    } = instr.op()
    {
        if let Some(assembly) = ctx.assembly() {
            let concrete_args: Option<Vec<ConstValue>> = args
                .iter()
                .map(|&a| ctx.evaluator().get_concrete(a).cloned())
                .collect();
            if let Some(concrete_args) = concrete_args {
                if let Some(result) = resolve_call_result(
                    assembly,
                    method.token(),
                    &concrete_args,
                    ctx.evaluator().pointer_size(),
                ) {
                    ctx.evaluator_mut().set_concrete(*dest, result);
                }
            }
        }
    }

    // Capture output value AFTER evaluation
    let output_value = instr
        .def()
        .and_then(|d| ctx.evaluator().get_concrete(d))
        .and_then(ConstValue::as_i64);

    InstructionWithValues {
        instruction: instr.clone(),
        block_idx,
        input_values,
        output_value,
    }
}
