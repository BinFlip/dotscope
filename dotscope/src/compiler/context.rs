//! Compiler context for interprocedural optimization.
//!
//! The [`CompilerContext`] holds all interprocedural state needed by SSA
//! optimization passes, containing the fields that compiler passes require.

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use dashmap::{DashMap, DashSet};
use rayon::prelude::*;

use crate::{
    analysis::{CallGraph, ConstValue, SsaFunction, SsaVarId, ValueRange},
    compiler::{
        events::EventLog,
        summary::{CallSiteInfo, MethodSummary},
    },
    metadata::token::Token,
};

/// Compiler context for the SSA pipeline phase.
///
/// This struct holds all interprocedural state that pure compiler passes need.
/// It is designed to be self-contained: the `compiler` module can compile
/// independently of `deobfuscation` when only this context is used.
///
/// All collection fields use thread-safe types (`DashMap`, `DashSet`, etc.)
/// to enable parallel processing of methods during pass execution.
pub struct CompilerContext {
    /// Call graph (who calls whom).
    pub call_graph: Arc<CallGraph>,

    /// SSA form for each method (built once, mutated by passes).
    pub ssa_functions: DashMap<Token, SsaFunction>,

    /// Method summaries from interprocedural analysis.
    pub summaries: DashMap<Token, MethodSummary>,

    /// Call site information for each callee.
    /// Key: callee method token, Value: list of call sites.
    pub call_sites: DashMap<Token, boxcar::Vec<CallSiteInfo>>,

    /// Accumulated events from all passes and operations.
    pub events: EventLog,

    /// Methods marked as dead (no live callers, not entry points).
    pub dead_methods: DashSet<Token>,

    /// Methods that have been fully processed by the pass pipeline.
    pub processed_methods: DashSet<Token>,

    /// Entry point methods (Main, event handlers, etc.).
    pub entry_points: DashSet<Token>,

    /// Methods that should not be inlined.
    ///
    /// Populated by the deobfuscation engine with dispatcher and decryptor
    /// tokens before running passes. Pure compiler passes check this set
    /// instead of accessing deobfuscation-specific state.
    pub no_inline: DashSet<Token>,

    /// Methods that were inlined at least once during the inlining pass.
    pub inlined_methods: DashSet<Token>,

    /// Known constant values for SSA variables, per method.
    known_values: DashMap<Token, DashMap<SsaVarId, ConstValue>>,

    /// Known value ranges for SSA variables, per method.
    known_ranges: DashMap<Token, DashMap<SsaVarId, ValueRange>>,

    /// Local variable remappings after optimization, per method.
    local_remappings: DashMap<Token, Vec<Option<u16>>>,

    /// When analysis started.
    start_time: Instant,
}

impl CompilerContext {
    /// Creates a new compiler context.
    #[must_use]
    pub fn new(call_graph: Arc<CallGraph>) -> Self {
        Self {
            call_graph,
            ssa_functions: DashMap::new(),
            summaries: DashMap::new(),
            call_sites: DashMap::new(),
            events: EventLog::new(),
            dead_methods: DashSet::new(),
            processed_methods: DashSet::new(),
            entry_points: DashSet::new(),
            no_inline: DashSet::new(),
            inlined_methods: DashSet::new(),
            known_values: DashMap::new(),
            known_ranges: DashMap::new(),
            local_remappings: DashMap::new(),
            start_time: Instant::now(),
        }
    }

    /// Returns the elapsed time since analysis started.
    #[must_use]
    pub fn elapsed(&self) -> Duration {
        self.start_time.elapsed()
    }

    // ── Dead method tracking ────────────────────────────────────────────

    /// Checks if a method is marked as dead (has no live callers).
    #[must_use]
    pub fn is_dead(&self, token: Token) -> bool {
        self.dead_methods.contains(&token)
    }

    /// Marks a method as dead.
    pub fn mark_dead(&self, token: Token) {
        self.dead_methods.insert(token);
    }

    // ── Entry point tracking ────────────────────────────────────────────

    /// Checks if a method is an entry point.
    #[must_use]
    pub fn is_entry_point(&self, token: Token) -> bool {
        self.entry_points.contains(&token)
    }

    /// Registers a method as an entry point.
    pub fn add_entry_point(&self, token: Token) {
        self.entry_points.insert(token);
    }

    // ── Inlined method tracking ─────────────────────────────────────────

    /// Marks a method as having been inlined at least once.
    pub fn mark_inlined(&self, token: Token) {
        self.inlined_methods.insert(token);
    }

    /// Checks if a method was inlined at least once.
    #[must_use]
    pub fn was_inlined(&self, token: Token) -> bool {
        self.inlined_methods.contains(&token)
    }

    // ── Summary access ──────────────────────────────────────────────────

    /// Executes a closure with a reference to the method summary.
    pub fn with_summary<R, F>(&self, token: Token, f: F) -> Option<R>
    where
        F: FnOnce(&MethodSummary) -> R,
    {
        self.summaries.get(&token).map(|r| f(&r))
    }

    /// Checks if a method is an inline candidate.
    #[must_use]
    pub fn is_inline_candidate(&self, token: Token) -> bool {
        self.summaries
            .get(&token)
            .is_some_and(|r| r.inline_candidate)
    }

    /// Returns the instruction count for a method.
    #[must_use]
    pub fn instruction_count(&self, token: Token) -> Option<usize> {
        self.summaries.get(&token).map(|r| r.instruction_count)
    }

    /// Checks if a method is a string decryptor.
    #[must_use]
    pub fn is_string_decryptor(&self, token: Token) -> bool {
        self.summaries
            .get(&token)
            .is_some_and(|r| r.is_string_decryptor)
    }

    /// Modifies a method summary in place.
    pub fn modify_summary<F>(&self, token: Token, f: F) -> bool
    where
        F: FnOnce(&mut MethodSummary),
    {
        if let Some(mut entry) = self.summaries.get_mut(&token) {
            f(entry.value_mut());
            true
        } else {
            false
        }
    }

    /// Adds or updates a method summary.
    pub fn set_summary(&self, summary: MethodSummary) {
        self.summaries.insert(summary.token, summary);
    }

    // ── Call site access ────────────────────────────────────────────────

    /// Executes a closure with a reference to the call sites for a callee.
    pub fn with_call_sites<R, F>(&self, callee: Token, f: F) -> Option<R>
    where
        F: FnOnce(&boxcar::Vec<CallSiteInfo>) -> R,
    {
        self.call_sites.get(&callee).map(|r| f(&r))
    }

    /// Returns the number of call sites for a callee method.
    #[must_use]
    pub fn call_site_count(&self, callee: Token) -> usize {
        self.call_sites.get(&callee).map_or(0, |r| r.count())
    }

    /// Checks if a callee has any call sites.
    #[must_use]
    pub fn has_call_sites(&self, callee: Token) -> bool {
        self.call_sites.get(&callee).is_some_and(|r| r.count() > 0)
    }

    /// Iterates over all call sites for a callee method.
    pub fn for_each_call_site<F>(&self, callee: Token, mut f: F)
    where
        F: FnMut(&CallSiteInfo),
    {
        if let Some(sites) = self.call_sites.get(&callee) {
            for (_, site) in sites.iter() {
                f(site);
            }
        }
    }

    /// Adds a call site for a callee method.
    pub fn add_call_site(&self, callee: Token, call_site: CallSiteInfo) {
        self.call_sites.entry(callee).or_default().push(call_site);
    }

    /// Returns the constant value of a parameter if all call sites agree.
    #[must_use]
    pub fn parameter_constant(&self, method: Token, param_index: usize) -> Option<ConstValue> {
        self.with_summary(method, |s| s.parameter_constant(param_index).cloned())
            .flatten()
    }

    /// Checks if a method always returns a constant value.
    #[must_use]
    pub fn returns_constant(&self, method: Token) -> Option<ConstValue> {
        self.with_summary(method, |s| s.returns_constant().cloned())
            .flatten()
    }

    // ── SSA function access ─────────────────────────────────────────────

    /// Executes a closure with a reference to the SSA function.
    pub fn with_ssa<R, F>(&self, token: Token, f: F) -> Option<R>
    where
        F: FnOnce(&SsaFunction) -> R,
    {
        self.ssa_functions.get(&token).map(|r| f(&r))
    }

    /// Executes a closure with a mutable reference to the SSA function.
    pub fn with_ssa_mut<R, F>(&self, token: Token, f: F) -> Option<R>
    where
        F: FnOnce(&mut SsaFunction) -> R,
    {
        self.ssa_functions.get_mut(&token).map(|mut r| f(&mut r))
    }

    /// Checks if an SSA function exists for a method.
    #[must_use]
    pub fn has_ssa(&self, token: Token) -> bool {
        self.ssa_functions.contains_key(&token)
    }

    /// Stores an SSA function for a method.
    pub fn set_ssa(&self, token: Token, ssa: SsaFunction) {
        self.ssa_functions.insert(token, ssa);
    }

    /// Removes and returns the SSA function for a method.
    pub fn take_ssa(&self, token: Token) -> Option<SsaFunction> {
        self.ssa_functions.remove(&token).map(|(_, v)| v)
    }

    /// Returns methods in reverse topological order (callees before callers).
    #[must_use]
    pub fn methods_reverse_topological(&self) -> Vec<Token> {
        let mut order = self.call_graph.topological_order().to_vec();
        order.reverse();
        order
    }

    /// Returns methods in topological order (callers before callees).
    #[must_use]
    pub fn methods_topological(&self) -> Vec<Token> {
        self.call_graph.topological_order().to_vec()
    }

    /// Returns an iterator over all method tokens that have SSA functions.
    pub fn all_methods(&self) -> impl Iterator<Item = Token> + '_ {
        self.ssa_functions.iter().map(|r| *r.key())
    }

    /// Returns the count of methods with SSA representations.
    #[must_use]
    pub fn method_count(&self) -> usize {
        self.ssa_functions.len()
    }

    // ── Known values ────────────────────────────────────────────────────

    /// Executes a closure with a reference to a known constant value.
    pub fn with_known_value<R, F>(&self, method: Token, var: SsaVarId, f: F) -> Option<R>
    where
        F: FnOnce(&ConstValue) -> R,
    {
        self.known_values
            .get(&method)
            .and_then(|method_values| method_values.get(&var).map(|r| f(&r)))
    }

    /// Checks if a known value exists for an SSA variable.
    #[must_use]
    pub fn has_known_value(&self, method: Token, var: SsaVarId) -> bool {
        self.known_values
            .get(&method)
            .is_some_and(|m| m.contains_key(&var))
    }

    /// Checks if a known value satisfies a predicate.
    #[must_use]
    pub fn known_value_is<F>(&self, method: Token, var: SsaVarId, predicate: F) -> bool
    where
        F: FnOnce(&ConstValue) -> bool,
    {
        self.known_values
            .get(&method)
            .and_then(|m| m.get(&var).map(|r| predicate(&r)))
            .unwrap_or(false)
    }

    /// Iterates over all known values for a method.
    pub fn for_each_known_value<F>(&self, method: Token, mut f: F)
    where
        F: FnMut(SsaVarId, &ConstValue),
    {
        if let Some(inner) = self.known_values.get(&method) {
            for entry in inner.iter() {
                f(*entry.key(), entry.value());
            }
        }
    }

    /// Records a known constant value for an SSA variable.
    pub fn add_known_value(&self, method: Token, var: SsaVarId, value: ConstValue) {
        self.known_values
            .entry(method)
            .or_default()
            .insert(var, value);
    }

    /// Clears known values for a method when its SSA is modified.
    pub fn clear_known_values(&self, method: Token) {
        self.known_values.remove(&method);
    }

    /// Returns the number of known values for a method.
    #[must_use]
    pub fn known_value_count(&self, method: Token) -> usize {
        self.known_values
            .get(&method)
            .map_or(0, |inner| inner.len())
    }

    // ── Known ranges ────────────────────────────────────────────────────

    /// Records a known value range for an SSA variable.
    pub fn add_known_range(&self, method: Token, var: SsaVarId, range: ValueRange) {
        self.known_ranges
            .entry(method)
            .or_default()
            .insert(var, range);
    }

    /// Executes a closure with a reference to a known value range.
    pub fn with_known_range<R, F>(&self, method: Token, var: SsaVarId, f: F) -> Option<R>
    where
        F: FnOnce(&ValueRange) -> R,
    {
        self.known_ranges
            .get(&method)
            .and_then(|method_ranges| method_ranges.get(&var).map(|r| f(&r)))
    }

    /// Checks if a known range exists for an SSA variable.
    #[must_use]
    pub fn has_known_range(&self, method: Token, var: SsaVarId) -> bool {
        self.known_ranges
            .get(&method)
            .is_some_and(|m| m.contains_key(&var))
    }

    /// Iterates over all known ranges for a method.
    pub fn for_each_known_range<F>(&self, method: Token, mut f: F)
    where
        F: FnMut(SsaVarId, &ValueRange),
    {
        if let Some(inner) = self.known_ranges.get(&method) {
            for entry in inner.iter() {
                f(*entry.key(), entry.value());
            }
        }
    }

    /// Clears known ranges for a method when its SSA is modified.
    pub fn clear_known_ranges(&self, method: Token) {
        self.known_ranges.remove(&method);
    }

    // ── Canonicalization ────────────────────────────────────────────────

    /// Canonicalizes all SSA functions in preparation for code generation.
    pub fn canonicalize_all_ssa(&self) {
        let tokens: Vec<Token> = self.all_methods().collect();

        tokens.par_iter().for_each(|&token| {
            let Some((_, mut ssa)) = self.ssa_functions.remove(&token) else {
                return;
            };

            ssa.canonicalize();
            let remapping = ssa.optimize_locals();

            self.ssa_functions.insert(token, ssa);
            self.local_remappings.insert(token, remapping);
        });
    }

    /// Executes a closure with a reference to the local variable remapping.
    pub fn with_local_remapping<R, F>(&self, token: Token, f: F) -> Option<R>
    where
        F: FnOnce(&[Option<u16>]) -> R,
    {
        self.local_remappings.get(&token).map(|r| f(&r))
    }

    /// Checks if a local variable remapping exists for a method.
    #[must_use]
    pub fn has_local_remapping(&self, token: Token) -> bool {
        self.local_remappings.contains_key(&token)
    }
}
