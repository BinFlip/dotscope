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

use std::mem;

use analyssa::BitSet;
use rustc_hash::FxHashSet;

use crate::{
    analysis::{
        cff_taint_config, ConstValue, EvaluatorMark, SsaEvaluator, SsaFunction, SsaOp, SsaVarId,
        SsaVariable, TaintAnalysis, VariableOrigin,
    },
    deobfuscation::passes::unflattening::{
        tracer::{helpers, types::TracedDispatcher},
        UnflattenConfig,
    },
    CilObject,
};

/// Multiplier applied to `max_block_visits` to derive the monotonic global
/// visit cap.
///
/// Generous enough that methods which trace normally never reach it — only
/// pathological nesting, where the per-arm budget reset would otherwise let
/// tracing run unbounded, is cut off.
const GLOBAL_VISIT_BUDGET_FACTOR: usize = 4;

/// Per-block properties that depend only on the shape of the SSA and on which
/// blocks are dispatchers — never on the values a particular path carries.
///
/// The tracer asks these questions once per block *visit*, and a flattened
/// method is visited millions of times, so answering them by re-walking the
/// CFG turns constant-time predicates into a dominant cost. Every field here is
/// a pure function of `(ssa, dispatcher, other_dispatcher_blocks)`, so a single
/// computation is valid for the whole trace.
struct BlockFacts {
    /// Whether the block is a direct target of the dispatcher switch.
    ///
    /// Replaces a linear scan of the switch's target list, which for a
    /// flattened method has one entry per case.
    dispatch_target: Vec<bool>,

    /// Whether the block is a dispatcher of a *different* CFF instance in the
    /// same method.
    other_dispatcher: Vec<bool>,

    /// Jump target of the block if it is a constant-producer, else `None`.
    ///
    /// See [`helpers::const_producer_target`], which this caches.
    const_producer: Vec<Option<usize>>,

    /// Memoized [`overflow_dispatch_site`](Self::overflow_dispatch_site)
    /// answers: `None` until first queried.
    ///
    /// Computed lazily rather than eagerly because the predecessor walk is
    /// only ever asked about blocks ending in an equality comparison, a small
    /// minority of the CFG.
    overflow_site: Vec<Option<bool>>,
}

impl BlockFacts {
    fn new(ssa: &SsaFunction, dispatcher: Option<&TracedDispatcher>) -> Self {
        let count = ssa.block_count();
        let mut dispatch_target = vec![false; count];
        if let Some(d) = dispatcher {
            for &target in d.targets.iter().chain(std::iter::once(&d.default)) {
                if let Some(slot) = dispatch_target.get_mut(target) {
                    *slot = true;
                }
            }
        }

        let mut const_producer = vec![None; count];
        for block in ssa.blocks() {
            if let Some(slot) = const_producer.get_mut(block.id()) {
                *slot = helpers::const_producer_target(block);
            }
        }

        Self {
            dispatch_target,
            other_dispatcher: vec![false; count],
            const_producer,
            overflow_site: vec![None; count],
        }
    }
}

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
    /// Monotonic visit counter that is never reset, unlike `total_visits`.
    ///
    /// `total_visits` is deliberately reset when entering an expression-switch
    /// false arm so each arm gets its own budget. On heavily nested methods that
    /// reset fires often enough that the effective budget becomes unbounded — a
    /// 348-block ConfuserEx method reached 3.3M block visits against a 50k
    /// budget. This counter is the backstop: it bounds total tracing work per
    /// context while leaving the per-arm budget semantics untouched.
    global_visits: usize,
    /// Hard cap on `global_visits`, derived from `max_block_visits`.
    max_global_visits: usize,
    /// Blocks already entered on the current path, keyed by execution state.
    ///
    /// Only ever grows while a path is followed — [`mark_visited`](Self::mark_visited)
    /// is its sole writer — so a fork records the keys it adds and a restore
    /// removes them again, the same trick the evaluator uses. Copying the set
    /// per fork was the tracer's largest remaining cost once the evaluator
    /// stopped being copied.
    visited_states: FxHashSet<(usize, i64)>,
    /// Keys added to [`visited_states`](Self::visited_states) since journaling
    /// began, oldest first.
    visited_journal: Vec<(usize, i64)>,
    /// Whether [`visited_journal`](Self::visited_journal) is being recorded.
    ///
    /// Latched on by the first snapshot, mirroring the evaluator's own journal.
    visit_journaling: bool,
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
    /// Structural per-block answers, shared by every visit. See [`BlockFacts`].
    facts: BlockFacts,
    /// SSA variables grouped by the local slot they originate from, in variable
    /// table order.
    ///
    /// The cross-scope bridge in the inner trace loop needs "the first variable
    /// for this local that currently has a value". Scanning the whole variable
    /// table for that runs inside the per-instruction loop, making the trace
    /// quadratic in a method's variable count; this index makes it proportional
    /// to the number of versions of the one local involved.
    vars_by_local: Vec<Vec<SsaVarId>>,
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
        let mut vars_by_local: Vec<Vec<SsaVarId>> = Vec::new();
        for var in ssa.variables() {
            if let VariableOrigin::Local(idx) = var.origin() {
                let idx = usize::from(idx);
                if vars_by_local.len() <= idx {
                    vars_by_local.resize_with(idx.saturating_add(1), Vec::new);
                }
                if let Some(slot) = vars_by_local.get_mut(idx) {
                    slot.push(var.id());
                }
            }
        }

        Self {
            ssa,
            evaluator: SsaEvaluator::new(ssa, config.pointer_size),
            assembly,
            dispatcher: None,
            state_tainted: BitSet::new(ssa.var_id_capacity()),
            next_node_id: 0,
            total_visits: 0,
            global_visits: 0,
            max_global_visits: config
                .max_block_visits
                .saturating_mul(GLOBAL_VISIT_BUDGET_FACTOR),
            visited_states: FxHashSet::default(),
            visited_journal: Vec::new(),
            visit_journaling: false,
            last_case_index: usize::MAX,
            visited_case_counts: Vec::new(),
            last_case_state: Vec::new(),
            max_block_visits: config.max_block_visits,
            max_tree_depth: config.max_tree_depth,
            other_dispatcher_blocks: Vec::new(),
            no_fork: false,
            facts: BlockFacts::new(ssa, None),
            vars_by_local,
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
        ctx.facts = BlockFacts::new(ssa, Some(&dispatcher));
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
        self.facts
            .dispatch_target
            .get(block)
            .copied()
            .unwrap_or(false)
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
        self.facts
            .other_dispatcher
            .get(block)
            .copied()
            .unwrap_or(false)
    }

    /// Sets the blocks of other CFF dispatchers in this method.
    pub fn set_other_dispatcher_blocks(&mut self, blocks: Vec<usize>) {
        for slot in &mut self.facts.other_dispatcher {
            *slot = false;
        }
        for &block in &blocks {
            if let Some(slot) = self.facts.other_dispatcher.get_mut(block) {
                *slot = true;
            }
        }
        // `is_overflow_dispatch_site` consults the other-dispatcher set, so any
        // answer cached before this point was computed against a stale one.
        for slot in &mut self.facts.overflow_site {
            *slot = None;
        }
        self.other_dispatcher_blocks = blocks;
    }

    /// Returns the jump target of `block` if it is a constant-producer block.
    ///
    /// Cached form of [`helpers::const_producer_target`].
    pub fn const_producer_target(&self, block: usize) -> Option<usize> {
        self.facts.const_producer.get(block).copied().flatten()
    }

    /// Returns the cached answer for `block`, computing it with `compute` on
    /// first use.
    ///
    /// See [`BlockFacts::overflow_site`] for why this one is lazy.
    pub fn overflow_dispatch_site(
        &mut self,
        block: usize,
        compute: impl FnOnce(&Self) -> bool,
    ) -> bool {
        if let Some(cached) = self.facts.overflow_site.get(block).copied().flatten() {
            return cached;
        }
        let answer = compute(self);
        if let Some(slot) = self.facts.overflow_site.get_mut(block) {
            *slot = Some(answer);
        }
        answer
    }

    /// Returns the SSA variables that originate from local slot `local_idx`, in
    /// variable table order.
    pub fn vars_for_local(&self, local_idx: u16) -> &[SsaVarId] {
        self.vars_by_local
            .get(usize::from(local_idx))
            .map_or(&[], Vec::as_slice)
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
        helpers::propagate_taint_forward(self.ssa, &mut self.state_tainted);
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
        let key = (block, self.visit_state());
        if self.visited_states.insert(key) && self.visit_journaling {
            self.visited_journal.push(key);
        }
    }

    /// Increments the visit counter and returns true if the budget is exceeded.
    pub fn check_visit_budget(&mut self) -> bool {
        self.total_visits = self.total_visits.saturating_add(1);
        self.global_visits = self.global_visits.saturating_add(1);
        self.total_visits > self.max_block_visits || self.global_visits > self.max_global_visits
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

    /// Takes a snapshot of the mutable context state that must be preserved
    /// across branch/switch forks.
    ///
    /// The evaluator is marked rather than copied — see [`ContextSnapshot`].
    pub fn snapshot(&mut self) -> ContextSnapshot {
        self.visit_journaling = true;
        ContextSnapshot {
            evaluator: self.evaluator.checkpoint(),
            visited_mark: self.visited_journal.len(),
            last_case_index: self.last_case_index,
            visited_case_counts: self.visited_case_counts.clone(),
            last_case_state: self.last_case_state.clone(),
        }
    }

    /// Restores all mutable context fields from a snapshot, consuming it.
    pub fn restore(&mut self, snap: ContextSnapshot) {
        self.evaluator.rollback(snap.evaluator);
        while self.visited_journal.len() > snap.visited_mark {
            let Some(key) = self.visited_journal.pop() else {
                break;
            };
            self.visited_states.remove(&key);
        }
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
            global_visits: 0,
            max_global_visits: self.max_global_visits,
            visited_states: FxHashSet::default(),
            visited_journal: Vec::new(),
            visit_journaling: false,
            last_case_index: usize::MAX,
            visited_case_counts: vec![0u8; case_count_len],
            last_case_state: vec![None; case_count_len],
            max_block_visits: self.max_block_visits,
            max_tree_depth: self.max_tree_depth,
            other_dispatcher_blocks: self.other_dispatcher_blocks.clone(),
            no_fork: false,
            facts: BlockFacts {
                dispatch_target: self.facts.dispatch_target.clone(),
                other_dispatcher: self.facts.other_dispatcher.clone(),
                const_producer: self.facts.const_producer.clone(),
                overflow_site: self.facts.overflow_site.clone(),
            },
            vars_by_local: self.vars_by_local.clone(),
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
///
/// The evaluator is held as a mark into its undo journal, not as a copy. A
/// flattened method forks millions of times and the evaluator's state grows
/// with everything the trace has learned, so copying it per fork costs more
/// than the tracing itself — measured at 99% of tracer time on a NetReactor
/// sample. Rolling back to a mark instead costs one entry per value the
/// abandoned arm actually changed.
///
/// This makes fork discipline part of the contract: marks are released in
/// reverse order of creation. The work stack in
/// [`engine`](super::engine) guarantees it — a snapshot lives in a work item,
/// and every item pushed after it is popped before it is.
pub struct ContextSnapshot {
    evaluator: EvaluatorMark,
    visited_mark: usize,
    last_case_index: usize,
    visited_case_counts: Vec<u8>,
    last_case_state: Vec<Option<i64>>,
}

impl ContextSnapshot {
    /// Clones this snapshot (used when restoring the same snapshot for
    /// multiple switch case arms).
    pub fn clone_snapshot(&self) -> Self {
        Self {
            evaluator: self.evaluator.clone(),
            visited_mark: self.visited_mark,
            last_case_index: self.last_case_index,
            visited_case_counts: self.visited_case_counts.clone(),
            last_case_state: self.last_case_state.clone(),
        }
    }
}
