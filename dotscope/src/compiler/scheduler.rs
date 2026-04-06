//! Pass scheduler for orchestrating SSA pass execution.
//!
//! The [`PassScheduler`] manages the execution of SSA optimization passes using
//! capability-based dependency scheduling. Passes declare what they provide and
//! require via [`PassCapability`](super::PassCapability), and the scheduler
//! topologically sorts them into execution layers. Each layer runs to fixpoint
//! with normalization between iterations.
//!
//! # Layer Computation
//!
//! Passes that don't declare capabilities fall back to a numeric layer derived
//! from their original phase assignment (Structure=0, Value=1, Simplify=2,
//! Inline=3). Passes that declare capabilities may be moved to a later layer
//! to satisfy their dependencies.
//!
//! # Normalization
//!
//! Normalize passes (DCE, constant propagation, GVN, etc.) are separate from
//! the layered passes. They run between every layer's fixpoint iterations,
//! cleaning up after each round of structural changes to expose new
//! optimization opportunities.

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
};

use dashmap::DashSet;
use log::debug;
use rayon::prelude::*;

use crate::{
    compiler::{
        context::CompilerContext,
        events::EventKind,
        pass::{ModificationScope, PassCapability, PassPhase, SsaPass},
        state::ProcessingState,
    },
    metadata::token::Token,
    utils::graph::IndexedGraph,
    CilObject, Error, Result,
};

/// Orchestrates SSA pass execution using capability-based scheduling.
///
/// Passes are organized into execution layers computed from their declared
/// capabilities. Each layer runs all its passes to fixpoint with normalization
/// between iterations. The entire pipeline then repeats until global fixpoint
/// or max iterations.
///
/// # Layer Computation
///
/// 1. Each pass starts at a fallback layer based on its phase assignment.
/// 2. If pass A provides capability X and pass B requires X, B is pushed
///    to a layer strictly after A.
/// 3. Cycles in the dependency graph are detected and reported as errors.
///
/// # Example
///
/// ```rust,ignore
/// let mut scheduler = PassScheduler::new(5, 2, 15);
/// scheduler.add(Box::new(value_pass), PassPhase::Value);
/// scheduler.add(Box::new(cff_pass), PassPhase::Structure);
/// scheduler.add(Box::new(dce_pass), PassPhase::Normalize);
/// scheduler.run_pipeline(&ctx, &assembly, None)?;
/// ```
pub struct PassScheduler {
    /// Maximum iterations for the entire pipeline.
    max_iterations: usize,
    /// Number of stable iterations before stopping.
    stable_iterations: usize,
    /// Maximum iterations for a single layer before moving on.
    max_phase_iterations: usize,
    /// All non-normalize passes with their fallback layer number.
    passes: Vec<(Box<dyn SsaPass>, usize)>,
    /// Normalization passes (DCE, GVN, const/copy propagation).
    /// Run after each layer to clean up before the next.
    normalize: Vec<Box<dyn SsaPass>>,
}

impl Default for PassScheduler {
    fn default() -> Self {
        Self::new(5, 2, 15)
    }
}

impl PassScheduler {
    /// Creates a new scheduler with the specified iteration limits.
    ///
    /// # Arguments
    ///
    /// * `max_iterations` - Maximum iterations for the entire pipeline before stopping.
    /// * `stable_iterations` - Stop early if no changes for this many consecutive iterations.
    /// * `max_phase_iterations` - Maximum fixpoint iterations for a single layer before
    ///   moving to the next.
    ///
    /// # Returns
    ///
    /// A new `PassScheduler` with no passes registered.
    #[must_use]
    pub fn new(
        max_iterations: usize,
        stable_iterations: usize,
        max_phase_iterations: usize,
    ) -> Self {
        Self {
            max_iterations,
            stable_iterations,
            max_phase_iterations,
            passes: Vec::new(),
            normalize: Vec::new(),
        }
    }

    /// Returns the number of non-normalize passes registered.
    #[must_use]
    pub fn pass_count(&self) -> usize {
        self.passes.len()
    }

    /// Returns the number of normalization passes registered.
    #[must_use]
    pub fn normalize_count(&self) -> usize {
        self.normalize.len()
    }

    /// Adds a pass to the scheduler with its execution phase.
    ///
    /// Layered passes (`Structure`, `Value`, `Simplify`, `Inline`) are placed
    /// into execution layers based on their phase and capability dependencies.
    /// `Normalize` passes run between every layer's fixpoint iterations and are
    /// excluded from the capability dependency graph.
    ///
    /// If a layered pass declares capabilities (via [`SsaPass::provides`] /
    /// [`SsaPass::requires`]), the scheduler may place it in a later layer
    /// to satisfy dependency constraints.
    ///
    /// # Arguments
    ///
    /// * `pass` - The SSA pass to register.
    /// * `phase` - The execution phase determining when this pass runs.
    pub fn add(&mut self, pass: Box<dyn SsaPass>, phase: PassPhase) {
        match phase {
            PassPhase::Normalize => self.normalize.push(pass),
            _ => self.passes.push((pass, phase.as_layer())),
        }
    }

    /// Computes execution layer assignments from capability dependencies.
    ///
    /// The algorithm has three phases:
    ///
    /// 1. **Graph construction**: Builds a directed graph using [`IndexedGraph`]
    ///    where an edge from pass A to pass B means "A must run before B"
    ///    (A provides a capability that B requires).
    ///
    /// 2. **Cycle validation**: Runs topological sort on the graph. If it fails,
    ///    the graph contains a cycle and the passes cannot be scheduled.
    ///
    /// 3. **Layer assignment**: Each pass starts at its fallback layer, then
    ///    Bellman-Ford relaxation pushes passes forward until every dependency
    ///    constraint `layer[dependent] > layer[provider]` is satisfied.
    ///
    /// Unsatisfied requirements (no provider registered for a required capability)
    /// are silently ignored — the pass stays at its fallback layer. This allows
    /// e.g. CFF to run without `Int32ValueContainer` when JIEJIE.NET is not detected.
    ///
    /// # Returns
    ///
    /// A `Vec<usize>` where element `i` is the layer number for `self.passes[i]`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::SsaError`] if a cycle is detected in the capability
    /// dependencies, including the names of the passes involved in the cycle.
    fn compute_layer_assignment(&self) -> Result<Vec<usize>> {
        let n = self.passes.len();
        if n == 0 {
            return Ok(vec![]);
        }

        // Build capability -> provider indices map
        let mut providers: HashMap<PassCapability, Vec<usize>> = HashMap::new();
        for (i, (pass, _)) in self.passes.iter().enumerate() {
            for &cap in pass.provides() {
                providers.entry(cap).or_default().push(i);
            }
        }

        // Build dependency graph: edge from provider → dependent
        let mut graph: IndexedGraph<usize, ()> = IndexedGraph::with_capacity(n, n);
        for i in 0..n {
            graph.add_node(i);
        }

        // deps[i] = indices of passes that must run before pass i
        let mut deps: Vec<Vec<usize>> = vec![vec![]; n];
        for (i, (pass, _)) in self.passes.iter().enumerate() {
            for &cap in pass.requires() {
                if let Some(provider_indices) = providers.get(&cap) {
                    for &j in provider_indices {
                        if j != i {
                            deps[i].push(j);
                            let _ = graph.add_edge(j, i, ());
                        }
                    }
                }
            }
        }

        // Validate the DAG is acyclic via topological sort
        if graph.topological_sort().is_none() {
            if let Some(cycle) = graph.find_any_cycle() {
                let names: Vec<&str> = cycle.iter().map(|&i| self.passes[i].0.name()).collect();
                return Err(Error::SsaError(format!(
                    "Cycle detected in pass capability dependencies: {}",
                    names.join(" → ")
                )));
            }
            return Err(Error::SsaError(
                "Cycle detected in pass capability dependencies".to_string(),
            ));
        }

        // Bellman-Ford relaxation: push layers forward to satisfy dependencies.
        // Invariant: after convergence, layer[i] > layer[dep] for all deps of i.
        let mut layer: Vec<usize> = self.passes.iter().map(|(_, fallback)| *fallback).collect();
        let mut changed = true;
        while changed {
            changed = false;
            for i in 0..n {
                for &dep in &deps[i] {
                    if layer[i] <= layer[dep] {
                        layer[i] = layer[dep] + 1;
                        changed = true;
                    }
                }
            }
        }

        // Log any passes that were moved from their fallback layer
        if !deps.iter().all(Vec::is_empty) {
            let max_layer = layer.iter().copied().max().unwrap_or(0);
            debug!(
                "Capability scheduling: {} passes across {} layers",
                n,
                max_layer + 1
            );
            for (i, (pass, fallback)) in self.passes.iter().enumerate() {
                if layer[i] != *fallback {
                    debug!(
                        "  pass '{}': layer {} (moved from fallback {})",
                        pass.name(),
                        layer[i],
                        fallback
                    );
                }
            }
        }

        Ok(layer)
    }

    /// Runs normalization passes repeatedly until no pass reports changes.
    ///
    /// Each iteration runs all normalize passes once. If any pass makes changes,
    /// another iteration begins. Stops when a full iteration produces no changes
    /// or `max_phase_iterations` is reached.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The compiler context (shared state, SSA functions, events).
    /// * `passes` - The normalization passes to run.
    /// * `max_phase_iterations` - Maximum fixpoint iterations before giving up.
    /// * `assembly` - Shared reference to the assembly for pass lookups.
    ///
    /// # Returns
    ///
    /// `true` if any pass made changes across all iterations, `false` otherwise.
    ///
    /// # Errors
    ///
    /// Returns an error if any pass fails during execution.
    fn normalize_to_fixpoint(
        ctx: &CompilerContext,
        passes: &mut [Box<dyn SsaPass>],
        max_phase_iterations: usize,
        assembly: &Arc<CilObject>,
        state: Option<&ProcessingState>,
        iteration_modified: Option<&DashSet<Token>>,
    ) -> Result<bool> {
        let mut any_changed = false;

        for _ in 0..max_phase_iterations {
            let changed = Self::run_passes_once(ctx, passes, assembly, state, iteration_modified)?;

            if !changed {
                break;
            }

            any_changed = true;
        }

        Ok(any_changed)
    }

    /// Runs a single execution layer to fixpoint with normalization.
    ///
    /// Each fixpoint iteration:
    /// 1. Runs all passes in the layer once across all methods.
    /// 2. If any pass made changes, runs normalization to fixpoint.
    /// 3. Repeats until no layer pass makes changes or `max_phase_iterations`
    ///    is reached.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The compiler context.
    /// * `all_passes` - The full pass list (layer passes are selected by index).
    /// * `layer_indices` - Indices into `all_passes` for this layer's passes.
    /// * `normalize_passes` - Normalization passes to run between iterations.
    /// * `max_phase_iterations` - Maximum fixpoint iterations for this layer.
    /// * `assembly` - Shared reference to the assembly.
    ///
    /// # Returns
    ///
    /// `true` if any pass made changes during this layer's execution.
    ///
    /// # Errors
    ///
    /// Returns an error if any pass fails during execution.
    #[allow(clippy::too_many_arguments)]
    fn layer_to_fixpoint(
        ctx: &CompilerContext,
        all_passes: &mut [(Box<dyn SsaPass>, usize)],
        layer_indices: &[usize],
        normalize_passes: &mut [Box<dyn SsaPass>],
        max_phase_iterations: usize,
        assembly: &Arc<CilObject>,
        state: Option<&ProcessingState>,
        iteration_modified: Option<&DashSet<Token>>,
    ) -> Result<bool> {
        if layer_indices.is_empty() {
            return Ok(false);
        }

        let mut phase_changed = false;

        for _ in 0..max_phase_iterations {
            let pass_changed = Self::run_layer_passes_once(
                ctx,
                all_passes,
                layer_indices,
                assembly,
                state,
                iteration_modified,
            )?;

            if !pass_changed {
                // Layer converged. Run normalize one final time to clean up
                // any modifications the last layer iteration made to SSA
                // (e.g., CFF unflattening rebuilds SSA, proxy devirt needs
                // to see the final state).
                if phase_changed && !normalize_passes.is_empty() {
                    Self::normalize_to_fixpoint(
                        ctx,
                        normalize_passes,
                        max_phase_iterations,
                        assembly,
                        state,
                        iteration_modified,
                    )?;
                }
                break;
            }

            phase_changed = true;

            if !normalize_passes.is_empty() {
                Self::normalize_to_fixpoint(
                    ctx,
                    normalize_passes,
                    max_phase_iterations,
                    assembly,
                    state,
                    iteration_modified,
                )?;
            }
        }

        Ok(phase_changed)
    }

    /// Runs a contiguous slice of passes once over all methods.
    ///
    /// Used for normalization passes, which are stored as a contiguous
    /// `Vec<Box<dyn SsaPass>>`. For layer passes (which are a subset of
    /// the full pass list), use [`run_layer_passes_once`](Self::run_layer_passes_once).
    ///
    /// The execution order is:
    /// 1. Initialize all passes ([`SsaPass::initialize`]).
    /// 2. Run global passes sequentially ([`SsaPass::run_global`]).
    /// 3. For each non-global pass, run it across all methods in parallel
    ///    via [`run_single_pass`](Self::run_single_pass).
    /// 4. Finalize all passes ([`SsaPass::finalize`]).
    ///
    /// # Arguments
    ///
    /// * `ctx` - The compiler context.
    /// * `passes` - The passes to execute (typically normalization passes).
    /// * `assembly` - Shared reference to the assembly.
    ///
    /// # Returns
    ///
    /// `true` if any pass made changes, `false` otherwise.
    ///
    /// # Errors
    ///
    /// Returns an error if any pass fails during initialization, execution,
    /// or finalization.
    fn run_passes_once(
        ctx: &CompilerContext,
        passes: &mut [Box<dyn SsaPass>],
        assembly: &Arc<CilObject>,
        state: Option<&ProcessingState>,
        iteration_modified: Option<&DashSet<Token>>,
    ) -> Result<bool> {
        for pass in passes.iter_mut() {
            pass.initialize(ctx)?;
        }

        // Dirty filtering: non-full-scan passes see only dirty methods
        let dirty_set = state.map(|s| &s.method_dirty);
        let all_methods = Self::method_order(ctx, None);
        let dirty_methods = Self::method_order(ctx, dirty_set);
        let any_changed = AtomicBool::new(false);

        for pass in passes.iter() {
            if pass.is_global() && pass.run_global(ctx, assembly)? {
                any_changed.store(true, Ordering::Relaxed);
            }
        }

        for pass in passes.iter() {
            if pass.is_global() {
                continue;
            }
            let methods = if pass.requires_full_scan() {
                &all_methods
            } else {
                &dirty_methods
            };
            Self::run_single_pass(
                pass.as_ref(),
                ctx,
                methods,
                assembly,
                &any_changed,
                iteration_modified,
            );
        }

        for pass in passes.iter_mut() {
            pass.finalize(ctx)?;
        }

        Ok(any_changed.load(Ordering::Relaxed))
    }

    /// Runs a subset of passes (identified by indices) once over all methods.
    ///
    /// Used for layer execution, where the passes to run are a non-contiguous
    /// subset of `all_passes` identified by `indices`. The execution follows
    /// the same init → global → per-method → finalize order as
    /// [`run_passes_once`](Self::run_passes_once).
    ///
    /// # Arguments
    ///
    /// * `ctx` - The compiler context.
    /// * `all_passes` - The full pass list (with fallback layer metadata).
    /// * `indices` - Indices into `all_passes` selecting this layer's passes.
    /// * `assembly` - Shared reference to the assembly.
    ///
    /// # Returns
    ///
    /// `true` if any pass made changes, `false` otherwise.
    ///
    /// # Errors
    ///
    /// Returns an error if any pass fails during initialization, execution,
    /// or finalization.
    fn run_layer_passes_once(
        ctx: &CompilerContext,
        all_passes: &mut [(Box<dyn SsaPass>, usize)],
        indices: &[usize],
        assembly: &Arc<CilObject>,
        state: Option<&ProcessingState>,
        iteration_modified: Option<&DashSet<Token>>,
    ) -> Result<bool> {
        for &idx in indices {
            all_passes[idx].0.initialize(ctx)?;
        }

        let dirty_set = state.map(|s| &s.method_dirty);
        let all_methods = Self::method_order(ctx, None);
        let dirty_methods = Self::method_order(ctx, dirty_set);
        let any_changed = AtomicBool::new(false);

        for &idx in indices {
            let pass = &all_passes[idx].0;
            if pass.is_global() && pass.run_global(ctx, assembly)? {
                any_changed.store(true, Ordering::Relaxed);
            }
        }

        for &idx in indices {
            let pass = &all_passes[idx].0;
            if pass.is_global() {
                continue;
            }
            let methods = if pass.requires_full_scan() {
                &all_methods
            } else {
                &dirty_methods
            };
            Self::run_single_pass(
                pass.as_ref(),
                ctx,
                methods,
                assembly,
                &any_changed,
                iteration_modified,
            );
        }

        for &idx in indices {
            all_passes[idx].0.finalize(ctx)?;
        }

        Ok(any_changed.load(Ordering::Relaxed))
    }

    /// Computes the method processing order for parallel pass execution.
    ///
    /// Returns methods sorted in reverse topological order of the call graph
    /// (callees before callers), filtered to only methods that have SSA
    /// representations. When `dirty_only` is provided, further filters to
    /// only methods in the dirty set.
    ///
    /// Falls back to arbitrary iteration order if the call graph has no
    /// topological ordering (e.g., due to recursion).
    fn method_order(ctx: &CompilerContext, dirty_only: Option<&DashSet<Token>>) -> Vec<Token> {
        let topo = ctx.methods_reverse_topological();
        let order: Vec<_> = if topo.is_empty() {
            ctx.all_methods().collect()
        } else {
            topo
        };
        order
            .into_iter()
            .filter(|token| ctx.ssa_functions.contains_key(token))
            .filter(|token| dirty_only.is_none_or(|dirty| dirty.contains(token)))
            .collect()
    }

    /// Runs a single pass across all methods in parallel, tracking changes.
    ///
    /// Methods are processed in parallel using rayon. For each method:
    /// 1. Checks [`SsaPass::should_run`] to skip inapplicable methods.
    /// 2. Removes the SSA from the concurrent map (brief lock).
    /// 3. Calls [`SsaPass::run_on_method`] with no locks held.
    /// 4. If changes were made, repairs or rebuilds SSA based on the pass's
    ///    [`ModificationScope`]:
    ///    - [`UsesOnly`](ModificationScope::UsesOnly) /
    ///      [`InstructionsOnly`](ModificationScope::InstructionsOnly): lightweight
    ///      [`repair_ssa`](crate::analysis::SsaFunction::repair_ssa)
    ///    - [`CfgModifying`](ModificationScope::CfgModifying): full
    ///      [`rebuild_ssa`](crate::analysis::SsaFunction::rebuild_ssa)
    /// 5. Reinserts the SSA and marks the method as processed.
    ///
    /// # Arguments
    ///
    /// * `pass` - The pass to execute (shared reference, must be `Send + Sync`).
    /// * `ctx` - The compiler context containing SSA functions and events.
    /// * `methods` - Method tokens to process, in the order from [`method_order`](Self::method_order).
    /// * `assembly` - Shared reference to the assembly for pass lookups.
    /// * `any_changed` - Atomic flag set to `true` if any method was modified.
    fn run_single_pass(
        pass: &dyn SsaPass,
        ctx: &CompilerContext,
        methods: &[Token],
        assembly: &Arc<CilObject>,
        any_changed: &AtomicBool,
        iteration_modified: Option<&DashSet<Token>>,
    ) {
        let event_snapshot = ctx.events.len();
        let pass_change_count = AtomicUsize::new(0);

        // Passes that read other methods' SSA (e.g., inlining, proxy devirt)
        // need peer SSAs to remain visible in the DashMap during parallel
        // execution. For these passes, we clone the SSA before processing so
        // the original stays readable by other threads. Passes that only
        // modify their own method use the faster remove/insert path.
        let clone_for_visibility = pass.reads_peer_ssa();

        methods.par_iter().for_each(|&method_token| {
            if !pass.should_run(method_token, ctx) {
                return;
            }

            let mut ssa = if clone_for_visibility {
                let Some(ssa_ref) = ctx.ssa_functions.get(&method_token) else {
                    return;
                };
                ssa_ref.clone()
            } else {
                let Some((_, ssa)) = ctx.ssa_functions.remove(&method_token) else {
                    return;
                };
                ssa
            };

            let result = pass.run_on_method(&mut ssa, method_token, ctx, assembly);

            if let Ok(true) = result {
                match pass.modification_scope() {
                    ModificationScope::UsesOnly | ModificationScope::InstructionsOnly => {
                        ssa.repair_ssa();
                    }
                    ModificationScope::CfgModifying => {
                        if let Err(e) = ssa.rebuild_ssa() {
                            log::warn!("SSA rebuild failed for {}: {}", method_token, e);
                        }
                    }
                }
            }

            ctx.ssa_functions.insert(method_token, ssa);

            if let Ok(true) = result {
                any_changed.store(true, Ordering::Relaxed);
                pass_change_count.fetch_add(1, Ordering::Relaxed);
                ctx.processed_methods.insert(method_token);
                if let Some(modified) = iteration_modified {
                    modified.insert(method_token);
                }
            }
        });

        let count = pass_change_count.load(Ordering::Relaxed);
        if count > 0 {
            let event_delta = ctx.events.count_by_kind_since(event_snapshot);
            if event_delta.is_empty() {
                debug!("  pass '{}' changed {} methods", pass.name(), count);
            } else {
                let summary = format_event_delta(&event_delta);
                if summary.is_empty() {
                    debug!("  pass '{}' changed {} methods", pass.name(), count);
                } else {
                    debug!(
                        "  pass '{}' changed {} methods ({})",
                        pass.name(),
                        count,
                        summary
                    );
                }
            }
        }
    }

    /// Runs the complete deobfuscation pipeline.
    ///
    /// Execution proceeds as follows:
    ///
    /// 1. **Layer computation**: Calls [`compute_layer_assignment`](Self::compute_layer_assignment)
    ///    to build the capability DAG and assign each pass to an execution layer.
    ///
    /// 2. **Outer loop** (up to `max_iterations`): For each iteration:
    ///    a. Run each layer to fixpoint via [`layer_to_fixpoint`](Self::layer_to_fixpoint).
    ///    b. On the first iteration only, if no layer made changes, run normalization
    ///    to ensure cleanup passes execute at least once.
    ///    c. Track stability: stop early if no changes for `stable_iterations`
    ///    consecutive iterations.
    ///
    /// Layer assignments are recomputed at the start of each call to `run_pipeline`,
    /// so passes added between calls (e.g., by the detection re-scan loop) are
    /// incorporated automatically.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The compiler context (thread-safe, shared across all passes).
    /// * `assembly` - Shared reference to the assembly being processed.
    ///
    /// # Returns
    ///
    /// The number of outer iterations completed. Pass-level events are
    /// accumulated in `ctx.events`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - A cycle is detected in the capability dependency graph.
    /// - Any pass fails during execution.
    pub fn run_pipeline(
        &mut self,
        ctx: &CompilerContext,
        assembly: &Arc<CilObject>,
        state: Option<&ProcessingState>,
    ) -> Result<usize> {
        let layer_assignment = self.compute_layer_assignment()?;

        // Group pass indices by layer, then discard empty layers
        let num_layers = layer_assignment.iter().copied().max().map_or(0, |m| m + 1);
        let mut layer_indices: Vec<Vec<usize>> = vec![vec![]; num_layers];
        for (i, &layer) in layer_assignment.iter().enumerate() {
            layer_indices[layer].push(i);
        }
        layer_indices.retain(|layer| !layer.is_empty());

        let mut stable_count = 0;
        let mut iterations = 0;
        let max_phase = self.max_phase_iterations;
        let max_iterations = self.max_iterations;
        let stable_iterations = self.stable_iterations;

        for iteration in 0..max_iterations {
            iterations = iteration + 1;
            debug!("Pipeline iteration {}/{}", iterations, max_iterations);

            // Track which methods are modified in this iteration so we can
            // transition unmodified methods from dirty → stable at the end.
            let iteration_modified = DashSet::new();
            let modified_ref = state.map(|_| &iteration_modified);
            let mut iteration_changed = false;

            for layer in &layer_indices {
                if Self::layer_to_fixpoint(
                    ctx,
                    &mut self.passes,
                    layer,
                    &mut self.normalize,
                    max_phase,
                    assembly,
                    state,
                    modified_ref,
                )? {
                    iteration_changed = true;
                }
            }

            // Ensure normalize runs at least once even if no layer pass makes changes
            if iteration == 0 && !iteration_changed && !self.normalize.is_empty() {
                iteration_changed = Self::normalize_to_fixpoint(
                    ctx,
                    &mut self.normalize,
                    max_phase,
                    assembly,
                    state,
                    modified_ref,
                )?;
            }

            // Update dirty/stable tracking at iteration boundary
            if let Some(state) = state {
                if iteration_changed {
                    // Move unmodified dirty methods to stable
                    let dirty: Vec<Token> = state.method_dirty.iter().map(|t| *t).collect();
                    for token in dirty {
                        if !iteration_modified.contains(&token) {
                            state.mark_method_stable(token);
                        }
                    }
                    // Methods modified during this iteration stay dirty for
                    // subsequent passes to see them (already in method_dirty
                    // or re-marked dirty by mark_method_dirty in the pass).
                    for token in iteration_modified.iter() {
                        state.mark_method_dirty(*token);
                    }
                } else {
                    // No changes at all — all dirty methods are now stable
                    let dirty: Vec<Token> = state.method_dirty.iter().map(|t| *t).collect();
                    for token in dirty {
                        state.mark_method_stable(token);
                    }
                }
            }

            if iteration_changed {
                stable_count = 0;
            } else {
                stable_count += 1;
                if stable_count >= stable_iterations {
                    debug!("Pipeline stable after {} iterations", iterations);
                    break;
                }
            }
        }

        Ok(iterations)
    }
}

/// Formats an event-kind delta map into a compact summary string.
///
/// Example: "93 strings decrypted, 115 constants folded"
fn format_event_delta(delta: &HashMap<EventKind, usize>) -> String {
    let mut parts: Vec<String> = delta
        .iter()
        .filter(|(kind, _)| kind.is_transformation())
        .map(|(kind, count)| format!("{} {}", count, kind.description()))
        .collect();
    parts.sort();
    parts.join(", ")
}

#[cfg(test)]
mod tests {
    use crate::{
        analysis::SsaFunction,
        compiler::{
            context::CompilerContext,
            pass::{PassCapability, PassPhase, SsaPass},
            EventKind, PassScheduler,
        },
        metadata::token::Token,
        CilObject, Result,
    };

    /// A minimal [`SsaPass`] implementation for testing.
    ///
    /// Reports changes for `changes_to_make` iterations, then stops.
    struct TestPass {
        name: &'static str,
        changes_to_make: usize,
    }

    impl TestPass {
        fn new(name: &'static str, changes: usize) -> Self {
            Self {
                name,
                changes_to_make: changes,
            }
        }
    }

    impl SsaPass for TestPass {
        fn name(&self) -> &'static str {
            self.name
        }

        fn run_on_method(
            &self,
            _ssa: &mut SsaFunction,
            method_token: Token,
            ctx: &CompilerContext,
            _assembly: &CilObject,
        ) -> Result<bool> {
            for i in 0..self.changes_to_make {
                ctx.events
                    .record(EventKind::ConstantFolded)
                    .at(method_token, i)
                    .message("test");
            }
            Ok(self.changes_to_make > 0)
        }
    }

    /// A test pass that declares [`PassCapability`] provides/requires.
    struct CapabilityPass {
        name: &'static str,
        provides: Vec<PassCapability>,
        requires: Vec<PassCapability>,
    }

    impl SsaPass for CapabilityPass {
        fn name(&self) -> &'static str {
            self.name
        }

        fn run_on_method(
            &self,
            _ssa: &mut SsaFunction,
            _method_token: Token,
            _ctx: &CompilerContext,
            _assembly: &CilObject,
        ) -> Result<bool> {
            Ok(false)
        }

        fn provides(&self) -> &[PassCapability] {
            &self.provides
        }

        fn requires(&self) -> &[PassCapability] {
            &self.requires
        }
    }

    #[test]
    fn test_scheduler_iteration_limits() {
        let scheduler = PassScheduler::new(10, 3, 5);
        assert_eq!(scheduler.max_iterations, 10);
        assert_eq!(scheduler.stable_iterations, 3);
        assert_eq!(scheduler.max_phase_iterations, 5);
    }

    #[test]
    fn test_default_scheduler() {
        let scheduler = PassScheduler::default();
        assert_eq!(scheduler.max_iterations, 5);
        assert_eq!(scheduler.stable_iterations, 2);
        assert_eq!(scheduler.max_phase_iterations, 15);
    }

    #[test]
    fn test_pass_names() {
        let passes: Vec<Box<dyn SsaPass>> = vec![
            Box::new(TestPass::new("pass1", 0)),
            Box::new(TestPass::new("pass2", 0)),
        ];

        assert_eq!(passes.len(), 2);
        assert_eq!(passes[0].name(), "pass1");
        assert_eq!(passes[1].name(), "pass2");
    }

    #[test]
    fn test_add_pass() {
        let mut scheduler = PassScheduler::new(5, 2, 15);
        scheduler.add(
            Box::new(TestPass::new("structure_pass", 0)),
            PassPhase::Structure,
        );
        scheduler.add(Box::new(TestPass::new("value_pass", 0)), PassPhase::Value);
        scheduler.add(
            Box::new(TestPass::new("simplify_pass", 0)),
            PassPhase::Simplify,
        );
        assert_eq!(scheduler.pass_count(), 3);
    }

    /// Verifies that capability dependencies push passes to later layers.
    ///
    /// Setup:
    /// - value-resolver (Value=1) provides `ResolvedStaticFields`
    /// - cff-reconstruction (Structure=0) requires `ResolvedStaticFields` → pushed to layer 2
    /// - opaque-predicates (Simplify=2) requires `RestoredControlFlow` → pushed to layer 3
    #[test]
    fn test_capability_layer_computation() {
        let mut scheduler = PassScheduler::new(5, 2, 15);

        scheduler.add(
            Box::new(CapabilityPass {
                name: "value-resolver",
                provides: vec![PassCapability::ResolvedStaticFields],
                requires: vec![],
            }),
            PassPhase::Value,
        );

        scheduler.add(
            Box::new(CapabilityPass {
                name: "cff-reconstruction",
                provides: vec![PassCapability::RestoredControlFlow],
                requires: vec![PassCapability::ResolvedStaticFields],
            }),
            PassPhase::Structure,
        );

        scheduler.add(
            Box::new(CapabilityPass {
                name: "opaque-predicates",
                provides: vec![PassCapability::SimplifiedPredicates],
                requires: vec![PassCapability::RestoredControlFlow],
            }),
            PassPhase::Simplify,
        );

        let layers = scheduler.compute_layer_assignment().unwrap();
        assert_eq!(layers[0], 1); // value-resolver stays at 1
        assert_eq!(layers[1], 2); // cff-reconstruction pushed from 0 to 2
        assert_eq!(layers[2], 3); // opaque-predicates pushed from 2 to 3
    }

    /// Verifies that passes without capabilities stay at their fallback layers.
    #[test]
    fn test_no_capabilities_uses_fallback() {
        let mut scheduler = PassScheduler::new(5, 2, 15);

        scheduler.add(
            Box::new(TestPass::new("structure", 0)),
            PassPhase::Structure,
        );
        scheduler.add(Box::new(TestPass::new("value", 0)), PassPhase::Value);
        scheduler.add(Box::new(TestPass::new("simplify", 0)), PassPhase::Simplify);

        let layers = scheduler.compute_layer_assignment().unwrap();
        assert_eq!(layers[0], 0);
        assert_eq!(layers[1], 1);
        assert_eq!(layers[2], 2);
    }

    /// Verifies that a pass requiring a capability with no provider stays at fallback.
    ///
    /// This is the ConfuserEx scenario: CFF requires `ResolvedStaticFields` but
    /// no `StaticFieldResolutionPass` is registered (no JIEJIE.NET detected).
    #[test]
    fn test_missing_provider_uses_fallback() {
        let mut scheduler = PassScheduler::new(5, 2, 15);

        scheduler.add(
            Box::new(CapabilityPass {
                name: "cff",
                provides: vec![PassCapability::RestoredControlFlow],
                requires: vec![PassCapability::ResolvedStaticFields],
            }),
            PassPhase::Structure,
        );

        let layers = scheduler.compute_layer_assignment().unwrap();
        assert_eq!(layers[0], 0);
    }

    /// Verifies that mutual capability dependencies are detected as a cycle.
    #[test]
    fn test_cycle_detection() {
        let mut scheduler = PassScheduler::new(5, 2, 15);

        scheduler.add(
            Box::new(CapabilityPass {
                name: "pass-a",
                provides: vec![PassCapability::ResolvedStaticFields],
                requires: vec![PassCapability::RestoredControlFlow],
            }),
            PassPhase::Structure,
        );
        scheduler.add(
            Box::new(CapabilityPass {
                name: "pass-b",
                provides: vec![PassCapability::RestoredControlFlow],
                requires: vec![PassCapability::ResolvedStaticFields],
            }),
            PassPhase::Structure,
        );

        let result = scheduler.compute_layer_assignment();
        assert!(result.is_err());
    }
}
