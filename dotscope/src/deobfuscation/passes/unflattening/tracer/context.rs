//! Tracing context and state management.
//!
//! [`TreeTraceContext`] owns all mutable state for a single trace pass:
//!
//! - **SSA evaluator**: Concrete evaluation of instructions and PHI nodes
//! - **Taint tracking**: Which variables are derived from the CFF state variable
//! - **Visit tracking**: (block, state) pairs visited to detect loops
//! - **Case dispatch tracking**: How many times each switch case was taken
//! - **Fork snapshotting**: [`ContextSnapshot`] saves/restores state at branch points
//!
//! All fields are private — the [`engine`](super::engine) interacts through
//! semantic methods that encapsulate invariants (visit budgets, case loop
//! detection thresholds, expression switch mode transitions).

use std::{collections::BTreeSet, mem};

use crate::{
    analysis::{
        cff_taint_config, ConstValue, SsaEvaluator, SsaFunction, SsaOp, SsaVarId, SsaVariable,
        TaintAnalysis,
    },
    deobfuscation::passes::unflattening::{tracer::types::TracedDispatcher, UnflattenConfig},
    utils::BitSet,
    CilObject,
};

/// Context for tree-based tracing.
///
/// Fields are private — engine and helpers interact through semantic methods
/// that encapsulate the invariants (visit budgets, case dispatch tracking,
/// dispatcher queries, taint propagation).
pub struct TreeTraceContext<'a> {
    ssa: &'a SsaFunction,
    evaluator: SsaEvaluator<'a>,
    assembly: Option<&'a CilObject>,
    dispatcher: Option<TracedDispatcher>,
    state_tainted: BitSet,
    next_node_id: usize,
    total_visits: usize,
    visited_states: BTreeSet<(usize, i64)>,
    last_case_index: usize,
    visited_case_counts: Vec<u8>,
    /// Last state value dispatched to each case, parallel to `visited_case_counts`.
    ///
    /// Used to distinguish a genuine "stuck" dispatcher (same state value
    /// repeated → likely broken state propagation) from legitimate user-loop
    /// iteration (state changes correctly between case visits). The A1
    /// overflow-bypass fallback is only appropriate for the former.
    last_case_state: Vec<Option<i64>>,
    max_block_visits: usize,
    max_tree_depth: usize,
    other_dispatcher_blocks: Vec<usize>,
    no_fork: bool,
}

impl<'a> TreeTraceContext<'a> {
    /// Creates a new tracing context without a pre-detected dispatcher.
    ///
    /// Used by [`trace_method_tree`](super::trace_method_tree) when no CFF
    /// dispatcher was detected, or as the base for
    /// [`with_dispatcher`](Self::with_dispatcher).
    pub fn new(
        ssa: &'a SsaFunction,
        config: &UnflattenConfig,
        assembly: Option<&'a CilObject>,
    ) -> Self {
        Self {
            ssa,
            evaluator: SsaEvaluator::new(ssa, config.pointer_size),
            assembly,
            dispatcher: None,
            state_tainted: BitSet::new(ssa.var_id_capacity()),
            next_node_id: 0,
            total_visits: 0,
            visited_states: BTreeSet::new(),
            last_case_index: usize::MAX,
            visited_case_counts: Vec::new(),
            last_case_state: Vec::new(),
            max_block_visits: config.max_block_visits,
            max_tree_depth: config.max_tree_depth,
            other_dispatcher_blocks: Vec::new(),
            no_fork: false,
        }
    }

    /// Creates a context with a pre-detected dispatcher.
    pub fn with_dispatcher(
        ssa: &'a SsaFunction,
        dispatcher: TracedDispatcher,
        config: &UnflattenConfig,
        assembly: Option<&'a CilObject>,
    ) -> Self {
        let mut ctx = Self::new(ssa, config, assembly);

        // Use generic taint analysis for state variable tracking
        if let Some(state_var) = dispatcher.state_var {
            // Get the state variable's origin to filter PHI chains
            let state_origin = ssa.variable(state_var).map(SsaVariable::origin);

            // Create CFF-specific taint configuration
            let taint_config = cff_taint_config(ssa, dispatcher.block, state_origin);

            // Initialize taint analysis with the state variable as the seed
            let mut taint = TaintAnalysis::new(taint_config);
            taint.add_tainted_var(state_var);

            // Also seed the taint with the BACKWARD direction: variables that
            // DEFINE the state variable through the dispatcher phi's operands.
            // These are the state update values (constants, computed states) from
            // each case block. Without tainting these and their definition chains,
            // filter_state_instructions can't remove the state update instructions,
            // causing CIL stack depth mismatches in codegen.
            if let Some(disp_block) = ssa.block(dispatcher.block) {
                for phi in disp_block.phi_nodes() {
                    if phi.result() == state_var {
                        for op in phi.operands() {
                            taint.add_tainted_var(op.value());
                        }
                    }
                }
            }

            // Run propagation through PHI chains and definition chains.
            taint.propagate(ssa);

            // Transfer tainted variables to context
            for var in taint.tainted_variables() {
                ctx.state_tainted.insert(var.index());
            }
        }

        // Seed the evaluator with the initial state value when available.
        // Optimization passes (copy propagation + DCE) may remove the `ldc.i4 N; stloc`
        // that originally set the initial state, leaving the dispatcher PHI's entry operand
        // undefined. Pre-seeding the operand variable ensures the first dispatch resolves.
        if let (Some(state_var), Some(initial)) = (dispatcher.state_var, dispatcher.initial_state) {
            // Find the entry predecessor by walking from block 0 toward the
            // dispatcher following Jump terminators. After optimization the entry
            // path is linear jumps, but the immediate predecessor of the dispatcher
            // may not be block 0 (e.g., B0 → B1 → B_dispatcher).
            let entry_pred = {
                let mut pred = 0usize;
                let mut current = 0usize;
                for _ in 0..20 {
                    if current == dispatcher.block {
                        break;
                    }
                    pred = current;
                    match ssa.block(current).and_then(|b| b.terminator_op()) {
                        Some(SsaOp::Jump { target }) => current = *target,
                        _ => break,
                    }
                }
                pred
            };

            if let Some(disp_block) = ssa.block(dispatcher.block) {
                for phi in disp_block.phi_nodes() {
                    if phi.result() == state_var {
                        // Find the operand from the entry predecessor and seed its value
                        for op in phi.operands() {
                            if op.predecessor() == entry_pred {
                                #[allow(clippy::cast_possible_truncation)]
                                ctx.evaluator
                                    .set_concrete(op.value(), ConstValue::I32(initial as i32));
                            }
                        }
                    }
                }
            }
        }

        // Size the case visit counter to fit the dispatcher's switch targets
        // (+1 for default, which uses targets.len() as its index).
        ctx.visited_case_counts = vec![0u8; dispatcher.targets.len().saturating_add(1)];
        ctx.last_case_state = vec![None; dispatcher.targets.len().saturating_add(1)];
        ctx.dispatcher = Some(dispatcher);
        ctx
    }

    /// Returns a reference to the SSA function being traced.
    ///
    /// Returns `&'a SsaFunction` (the context's lifetime, not `&self`'s)
    /// so the returned reference doesn't borrow `self` and can coexist with
    /// `&mut self` calls on the context.
    pub fn ssa(&self) -> &'a SsaFunction {
        self.ssa
    }

    /// Returns a reference to the SSA evaluator.
    pub fn evaluator(&self) -> &SsaEvaluator<'a> {
        &self.evaluator
    }

    /// Returns a mutable reference to the SSA evaluator.
    pub fn evaluator_mut(&mut self) -> &mut SsaEvaluator<'a> {
        &mut self.evaluator
    }

    /// Returns the optional assembly reference for call resolution.
    ///
    /// Returns the context's `'a` lifetime, not `&self`'s.
    pub fn assembly(&self) -> Option<&'a CilObject> {
        self.assembly
    }

    /// Allocates and returns the next unique node ID.
    pub fn next_id(&mut self) -> usize {
        let id = self.next_node_id;
        self.next_node_id = self.next_node_id.saturating_add(1);
        id
    }

    /// Returns true if the given block is the CFF dispatcher block.
    pub fn is_dispatcher_block(&self, block: usize) -> bool {
        self.dispatcher.as_ref().is_some_and(|d| d.block == block)
    }

    /// Returns true if the given block is a direct target of the dispatcher
    /// (case block or default).
    pub fn is_dispatch_target(&self, block: usize) -> bool {
        self.dispatcher
            .as_ref()
            .is_some_and(|d| d.targets.contains(&block) || d.default == block)
    }

    /// Returns the state variable (phi at the dispatcher), if detected.
    pub fn state_var(&self) -> Option<SsaVarId> {
        self.dispatcher.as_ref().and_then(|d| d.state_var)
    }

    /// Returns the dispatcher block index, if detected.
    pub fn dispatcher_block(&self) -> Option<usize> {
        self.dispatcher.as_ref().map(|d| d.block)
    }

    /// Returns true if the given block is another CFF dispatcher in the same
    /// method (not the one we're tracing for).
    pub fn is_other_dispatcher(&self, block: usize) -> bool {
        self.other_dispatcher_blocks.contains(&block)
    }

    /// Sets the blocks of other CFF dispatchers in this method.
    pub fn set_other_dispatcher_blocks(&mut self, blocks: Vec<usize>) {
        self.other_dispatcher_blocks = blocks;
    }

    /// Checks if a variable is state-tainted.
    pub fn is_tainted(&self, var: SsaVarId) -> bool {
        self.state_tainted.contains(var.index())
    }

    /// Checks if any of the variables are state-tainted.
    pub fn any_tainted(&self, vars: &[SsaVarId]) -> bool {
        vars.iter().any(|v| self.is_tainted(*v))
    }

    /// Marks a variable as tainted.
    pub fn taint(&mut self, var: SsaVarId) {
        self.state_tainted.insert(var.index());
    }

    /// Returns a reference to the state-tainted variable set.
    pub fn state_tainted(&self) -> &BitSet {
        &self.state_tainted
    }

    /// Returns a mutable reference to the state-tainted variable set.
    pub fn state_tainted_mut(&mut self) -> &mut BitSet {
        &mut self.state_tainted
    }

    /// Propagates taint forward through SSA instructions.
    /// Encapsulates the borrow of both `ssa` and `state_tainted` within one method
    /// to avoid split-borrow issues at call sites.
    pub fn propagate_taint_forward(&mut self) {
        super::helpers::propagate_taint_forward(self.ssa, &mut self.state_tainted);
    }

    /// Gets the current CFF state value (if we can determine it).
    pub fn current_state(&self) -> Option<i64> {
        self.dispatcher
            .as_ref()
            .and_then(|d| d.state_var)
            .and_then(|v| self.evaluator.get_concrete(v))
            .and_then(ConstValue::as_i64)
    }

    /// Computes a visit key for loop detection.
    ///
    /// Uses the CFF state value when available (after dispatcher evaluation),
    /// which allows revisiting blocks with different state machine values
    /// (essential for CFF loop iterations). Falls back to a case-index-based
    /// key at non-dispatcher blocks to prevent infinite recursion while still
    /// allowing re-entry from different CFF case paths.
    fn visit_state(&self) -> i64 {
        self.current_state().unwrap_or_else(|| {
            let count = self
                .visited_case_counts
                .get(self.last_case_index)
                .copied()
                .map_or(0, i64::from);
            (self.last_case_index as i64)
                .wrapping_mul(256)
                .wrapping_add(count)
        })
    }

    /// Checks if we've visited this block in the current execution context.
    pub fn is_visited(&self, block: usize) -> bool {
        self.visited_states.contains(&(block, self.visit_state()))
    }

    /// Marks a block as visited in the current execution context.
    pub fn mark_visited(&mut self, block: usize) {
        self.visited_states.insert((block, self.visit_state()));
    }

    /// Increments the visit counter and returns true if the budget is exceeded.
    pub fn check_visit_budget(&mut self) -> bool {
        self.total_visits = self.total_visits.saturating_add(1);
        self.total_visits > self.max_block_visits
    }

    /// Returns the maximum tree depth allowed.
    pub fn max_tree_depth(&self) -> usize {
        self.max_tree_depth
    }

    /// Records that the dispatcher dispatched to the given case index.
    /// Increments the visit count for the case and updates the last case index.
    pub fn record_case_dispatch(&mut self, case_idx: usize) {
        if let Some(slot) = self.visited_case_counts.get_mut(case_idx) {
            *slot = slot.saturating_add(1);
        }
        self.last_case_index = case_idx;
    }

    /// Returns `true` if the current dispatch to `case_idx` repeats the same
    /// state value that was last used to dispatch that case.
    ///
    /// Used by the A1 overflow-bypass fallback to distinguish a truly stuck
    /// dispatcher (identical state value, no progress) from a legitimate
    /// user-loop iteration (same case but state updated each time).
    ///
    /// `current_state` is the state value on this incoming dispatch. A return
    /// of `true` means "this case was dispatched before with the same state".
    pub fn case_state_is_stuck(&self, case_idx: usize, current_state: i64) -> bool {
        self.last_case_state
            .get(case_idx)
            .and_then(|slot| *slot)
            .is_some_and(|prev| prev == current_state)
    }

    /// Records the state value used for this dispatch of `case_idx`.
    pub fn record_case_state(&mut self, case_idx: usize, state: i64) {
        if let Some(slot) = self.last_case_state.get_mut(case_idx) {
            *slot = Some(state);
        }
    }

    /// Checks if a case index has been visited enough times to indicate a
    /// CFF loop back-edge. The threshold scales with the number of targets
    /// to avoid false positives on small dispatchers.
    pub fn is_case_loop(&self, case_idx: usize, targets_len: usize) -> bool {
        let loop_threshold = (targets_len / 2).max(2) as u8;
        self.visited_case_counts
            .get(case_idx)
            .is_some_and(|count| *count >= loop_threshold)
    }

    /// Returns true when the tracer should follow one path instead of forking
    /// at user branches/switches.
    pub fn no_fork(&self) -> bool {
        self.no_fork
    }

    /// Takes a full snapshot of the mutable context state that must be
    /// preserved across branch/switch forks.
    pub fn snapshot(&self) -> ContextSnapshot<'a> {
        ContextSnapshot {
            evaluator: self.evaluator.clone(),
            visited_states: self.visited_states.clone(),
            last_case_index: self.last_case_index,
            visited_case_counts: self.visited_case_counts.clone(),
            last_case_state: self.last_case_state.clone(),
        }
    }

    /// Restores all mutable context fields from a snapshot, consuming it.
    pub fn restore(&mut self, snap: ContextSnapshot<'a>) {
        self.evaluator = snap.evaluator;
        self.visited_states = snap.visited_states;
        self.last_case_index = snap.last_case_index;
        self.visited_case_counts = snap.visited_case_counts;
        self.last_case_state = snap.last_case_state;
    }

    /// Clones the current visited_case_counts for snapshotting.
    pub fn case_counts_snapshot(&self) -> Vec<u8> {
        self.visited_case_counts.clone()
    }

    /// Overwrites the visited_case_counts (used when restoring expression
    /// switch state across fork arms).
    pub fn set_case_counts(&mut self, counts: Vec<u8>) {
        self.visited_case_counts = counts;
    }

    /// Saves the (total_visits, no_fork) pair and sets expression-switch
    /// false-arm mode (reset visits, enable no_fork). Returns the saved
    /// values for later restoration.
    pub fn enter_expr_switch_false_arm(&mut self) -> (usize, bool) {
        let saved = (self.total_visits, self.no_fork);
        self.total_visits = 0;
        self.no_fork = true;
        saved
    }

    /// Restores total_visits and no_fork from values saved by
    /// [`enter_expr_switch_false_arm`].
    pub fn exit_expr_switch_false_arm(&mut self, saved: (usize, bool)) {
        self.total_visits = saved.0;
        self.no_fork = saved.1;
    }

    /// Takes the dispatcher out of the context (for building the final TraceTree).
    pub fn take_dispatcher(&mut self) -> Option<TracedDispatcher> {
        self.dispatcher.take()
    }

    /// Takes the state-tainted set out of the context (for building the final TraceTree).
    pub fn take_state_tainted(&mut self) -> BitSet {
        mem::take(&mut self.state_tainted)
    }

    /// Returns the handler start blocks that were not visited by the main trace.
    pub fn unvisited_handler_blocks(&self) -> Vec<usize> {
        self.ssa
            .exception_handlers()
            .iter()
            .filter_map(|h| h.handler_start_block)
            .filter(|&block| {
                block < self.ssa.block_count()
                    && !self.visited_states.iter().any(|(b, _)| *b == block)
            })
            .collect()
    }

    /// Creates an independent context for tracing an exception handler.
    ///
    /// Handler traces are self-contained: each has its own evaluator, visit
    /// state, and visit budget. They share only immutable data from the parent
    /// context (`&ssa`, dispatcher info, taint seeds, config limits).
    /// This allows handler traces to run in parallel.
    pub fn fork_for_handler(&self, node_id_offset: usize) -> Self {
        let case_count_len = self.visited_case_counts.len();
        Self {
            ssa: self.ssa,
            evaluator: SsaEvaluator::new(self.ssa, self.evaluator.pointer_size()),
            assembly: self.assembly,
            dispatcher: self.dispatcher.clone(),
            state_tainted: self.state_tainted.clone(),
            next_node_id: node_id_offset,
            total_visits: 0,
            visited_states: BTreeSet::new(),
            last_case_index: usize::MAX,
            visited_case_counts: vec![0u8; case_count_len],
            last_case_state: vec![None; case_count_len],
            max_block_visits: self.max_block_visits,
            max_tree_depth: self.max_tree_depth,
            other_dispatcher_blocks: self.other_dispatcher_blocks.clone(),
            no_fork: false,
        }
    }

    /// Advances the node ID counter past all handler IDs.
    pub fn advance_node_id(&mut self, new_id: usize) {
        self.next_node_id = new_id;
    }

    /// Returns the max_block_visits budget (used for handler ID stride).
    pub fn max_block_visits(&self) -> usize {
        self.max_block_visits
    }
}

/// Snapshot of `TreeTraceContext` mutable state saved at branch/switch fork
/// points. Allows the iterative tracer to restore context before tracing
/// each alternative arm.
pub struct ContextSnapshot<'a> {
    evaluator: SsaEvaluator<'a>,
    visited_states: BTreeSet<(usize, i64)>,
    last_case_index: usize,
    visited_case_counts: Vec<u8>,
    last_case_state: Vec<Option<i64>>,
}

impl<'a> ContextSnapshot<'a> {
    /// Clones this snapshot (used when restoring the same snapshot for
    /// multiple switch case arms).
    pub fn clone_snapshot(&self) -> Self {
        Self {
            evaluator: self.evaluator.clone(),
            visited_states: self.visited_states.clone(),
            last_case_index: self.last_case_index,
            visited_case_counts: self.visited_case_counts.clone(),
            last_case_state: self.last_case_state.clone(),
        }
    }
}
