//! Analysis context for interprocedural deobfuscation.
//!
//! The [`AnalysisContext`] is the central data structure that holds all
//! interprocedural analysis state during the SSA pipeline phase. It is shared
//! by all passes and enables cross-method optimization.

use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::{DashMap, DashSet};
use rayon::prelude::*;

use crate::{
    analysis::{CallGraph, ConstValue, SsaFunction, SsaVarId, ValueRange},
    deobfuscation::{
        changes::EventLog,
        config::EngineConfig,
        decryptors::DecryptorContext,
        detection::DetectionResult,
        statemachine::StateMachineProvider,
        summary::{CallSiteInfo, MethodSummary},
    },
    emulation::Hook,
    metadata::token::Token,
};

/// A factory function that creates a new [`Hook`] instance.
///
/// Hook factories are used instead of storing hooks directly because hooks
/// contain non-Clone types (closures, trait objects). Each emulation process
/// gets fresh hook instances by calling all registered factories.
///
/// This is a boxed closure to allow capturing state (e.g., method tokens to stub).
pub type HookFactory = Box<dyn Fn() -> Hook + Send + Sync>;

/// Analysis context for the SSA pipeline phase.
///
/// This is the "brain" of the deobfuscation system, holding all interprocedural
/// knowledge that enables cross-method optimization:
///
/// - Method summaries (what does each method do?)
/// - Call site information (what constants are passed where?)
/// - Decryptor tracking (via [`DecryptorContext`])
/// - Dead method tracking
/// - Known constant values and ranges
///
/// All collection fields use thread-safe types (`DashMap`, `DashSet`, etc.)
/// to enable parallel processing of methods during pass execution.
pub struct AnalysisContext {
    /// Call graph (who calls whom).
    pub call_graph: Arc<CallGraph>,

    /// SSA form for each method (built once, mutated by passes).
    pub ssa_functions: DashMap<Token, SsaFunction>,

    /// Method summaries from interprocedural analysis.
    pub summaries: DashMap<Token, MethodSummary>,

    /// Call site information for each callee.
    /// Key: callee method token, Value: list of call sites.
    pub call_sites: DashMap<Token, boxcar::Vec<CallSiteInfo>>,

    /// Decryptor tracking for obfuscator-specific string/resource decryption.
    ///
    /// Obfuscator modules register decryptors here during detection, and SSA
    /// passes use it to identify and process decryption calls.
    pub decryptors: DecryptorContext,

    /// Methods marked as dead (no live callers, not entry points).
    pub dead_methods: DashSet<Token>,

    /// Methods that have been fully processed by the pass pipeline.
    pub processed_methods: DashSet<Token>,

    /// Entry point methods (Main, event handlers, etc.).
    pub entry_points: DashSet<Token>,

    /// Dispatcher methods (control flow obfuscation).
    /// Methods are added here when a dispatcher is DETECTED, even if unflattening fails.
    /// Used to prevent inlining of dispatcher methods.
    pub dispatchers: DashSet<Token>,

    /// Successfully unflattened dispatcher methods.
    /// Methods are added here only when redirects were actually computed and applied.
    /// Used to skip methods that have already been processed.
    pub unflattened_dispatchers: DashSet<Token>,

    /// Detected obfuscator(s).
    pub detection_result: DetectionResult,

    /// Accumulated events from all passes and operations.
    pub events: EventLog,

    /// Engine configuration (for pass-specific thresholds).
    pub config: EngineConfig,

    /// When analysis started.
    start_time: Instant,

    /// Known constant values for SSA variables, per method.
    /// Key: method token, Value: map from SSA variable to its known constant value.
    known_values: DashMap<Token, DashMap<SsaVarId, ConstValue>>,

    /// Known value ranges for SSA variables, per method.
    /// Key: method token, Value: map from SSA variable to its known value range.
    known_ranges: DashMap<Token, DashMap<SsaVarId, ValueRange>>,

    /// Local variable remappings after optimization, per method.
    /// Key: method token, Value: remapping where `result[old_index]` = `Some(new_index)`.
    /// Used by code generation to create optimized local variable signatures.
    local_remappings: DashMap<Token, Vec<Option<u16>>>,

    /// Registered hook factories for emulation.
    ///
    /// Obfuscators register hook factories during `initialize_context()` to provide
    /// obfuscator-specific emulation hooks. The decryption pass calls these factories
    /// to get fresh hooks for each emulation process.
    emulation_hooks: boxcar::Vec<HookFactory>,

    /// Methods that need to be executed during emulation template warmup.
    ///
    /// Obfuscators register static constructors (.cctors) here that should run
    /// before decryption emulation begins. This is critical for obfuscators like
    /// ConfuserEx where the .cctor performs expensive initialization (LZMA
    /// decompression) that should happen once on the template, not on every fork.
    ///
    /// The decryption pass executes these methods when creating the template
    /// process, before any forking occurs.
    warmup_methods: boxcar::Vec<Token>,

    /// Methods that were inlined at least once during the inlining pass.
    ///
    /// This tracks methods that had at least one call site inlined. After all
    /// passes complete, methods in this set that have no remaining call sites
    /// can be removed when `remove_unused_methods` is enabled.
    pub inlined_methods: DashSet<Token>,

    /// State machine providers for order-dependent constant decryption.
    ///
    /// Each obfuscator that uses state machines for encryption (e.g., ConfuserEx
    /// with CFGCtx) registers a provider during detection. The decryption pass
    /// queries these providers to determine how to process each method.
    ///
    /// This replaces the previous `statemachine_semantics` and `cfg_mode_methods`
    /// fields with a generic, extensible design.
    pub statemachine_providers: boxcar::Vec<Arc<dyn StateMachineProvider>>,
}

impl AnalysisContext {
    /// Creates a new analysis context with default configuration.
    ///
    /// # Arguments
    ///
    /// * `call_graph` - The precomputed call graph for the assembly.
    ///
    /// # Returns
    ///
    /// A new `AnalysisContext` initialized with empty caches.
    pub fn new(call_graph: Arc<CallGraph>) -> Self {
        Self::with_config(call_graph, EngineConfig::default())
    }

    /// Creates a new analysis context with custom configuration.
    ///
    /// # Arguments
    ///
    /// * `call_graph` - The precomputed call graph for the assembly.
    /// * `config` - Engine configuration with pass-specific thresholds.
    ///
    /// # Returns
    ///
    /// A new `AnalysisContext` initialized with the provided configuration.
    pub fn with_config(call_graph: Arc<CallGraph>, config: EngineConfig) -> Self {
        Self {
            call_graph,
            ssa_functions: DashMap::new(),
            summaries: DashMap::new(),
            call_sites: DashMap::new(),
            decryptors: DecryptorContext::new(),
            dead_methods: DashSet::new(),
            processed_methods: DashSet::new(),
            entry_points: DashSet::new(),
            dispatchers: DashSet::new(),
            unflattened_dispatchers: DashSet::new(),
            detection_result: DetectionResult::default(),
            events: EventLog::new(),
            config,
            start_time: Instant::now(),
            known_values: DashMap::new(),
            known_ranges: DashMap::new(),
            local_remappings: DashMap::new(),
            emulation_hooks: boxcar::Vec::new(),
            warmup_methods: boxcar::Vec::new(),
            inlined_methods: DashSet::new(),
            statemachine_providers: boxcar::Vec::new(),
        }
    }

    /// Returns the elapsed time since analysis started.
    #[must_use]
    pub fn elapsed(&self) -> Duration {
        self.start_time.elapsed()
    }

    /// Checks if a method is marked as dead (has no live callers).
    ///
    /// # Arguments
    ///
    /// * `token` - The metadata token of the method to check.
    ///
    /// # Returns
    ///
    /// `true` if the method has been marked as dead, `false` otherwise.
    #[must_use]
    pub fn is_dead(&self, token: Token) -> bool {
        self.dead_methods.contains(&token)
    }

    /// Marks a method as dead.
    ///
    /// # Arguments
    ///
    /// * `token` - The metadata token of the method to mark as dead.
    pub fn mark_dead(&self, token: Token) {
        self.dead_methods.insert(token);
    }

    /// Checks if a method is an entry point.
    ///
    /// # Arguments
    ///
    /// * `token` - The metadata token of the method to check.
    ///
    /// # Returns
    ///
    /// `true` if the method is registered as an entry point, `false` otherwise.
    #[must_use]
    pub fn is_entry_point(&self, token: Token) -> bool {
        self.entry_points.contains(&token)
    }

    /// Registers a method as an entry point.
    ///
    /// Entry points include Main methods, event handlers, and other methods
    /// that should not be considered dead even without explicit callers.
    ///
    /// # Arguments
    ///
    /// * `token` - The metadata token of the entry point method.
    pub fn add_entry_point(&self, token: Token) {
        self.entry_points.insert(token);
    }

    /// Checks if a method is a dispatcher (control flow obfuscation).
    ///
    /// # Arguments
    ///
    /// * `token` - The metadata token of the method to check.
    ///
    /// # Returns
    ///
    /// `true` if the method has been identified as a dispatcher.
    #[must_use]
    pub fn is_dispatcher(&self, token: Token) -> bool {
        self.dispatchers.contains(&token)
    }

    /// Marks a method as a dispatcher.
    ///
    /// Dispatchers are methods used for control flow flattening that route
    /// execution through a central switch statement.
    ///
    /// # Arguments
    ///
    /// * `token` - The metadata token of the dispatcher method.
    pub fn mark_dispatcher(&self, token: Token) {
        self.dispatchers.insert(token);
    }

    /// Marks a method as having been inlined at least once.
    ///
    /// This is called by the inlining pass when a method is successfully inlined.
    /// Methods marked as inlined that have no remaining call sites after all
    /// passes complete are candidates for removal.
    ///
    /// # Arguments
    ///
    /// * `token` - The metadata token of the method that was inlined.
    pub fn mark_inlined(&self, token: Token) {
        self.inlined_methods.insert(token);
    }

    /// Checks if a method was inlined at least once.
    ///
    /// # Arguments
    ///
    /// * `token` - The metadata token of the method to check.
    ///
    /// # Returns
    ///
    /// `true` if the method was inlined at some call site.
    #[must_use]
    pub fn was_inlined(&self, token: Token) -> bool {
        self.inlined_methods.contains(&token)
    }

    /// Executes a closure with a reference to the method summary.
    ///
    /// This is the preferred way to access summaries as it avoids cloning.
    /// The closure should be quick to execute as a read lock is held.
    ///
    /// # Arguments
    ///
    /// * `token` - The metadata token of the method.
    /// * `f` - A closure that receives a reference to the summary.
    ///
    /// # Returns
    ///
    /// The result of the closure if the summary exists, `None` otherwise.
    pub fn with_summary<R, F>(&self, token: Token, f: F) -> Option<R>
    where
        F: FnOnce(&MethodSummary) -> R,
    {
        self.summaries.get(&token).map(|r| f(&r))
    }

    /// Checks if a method is an inline candidate.
    ///
    /// # Arguments
    ///
    /// * `token` - The metadata token of the method.
    ///
    /// # Returns
    ///
    /// `true` if the method has been marked as an inline candidate.
    #[must_use]
    pub fn is_inline_candidate(&self, token: Token) -> bool {
        self.summaries
            .get(&token)
            .is_some_and(|r| r.inline_candidate)
    }

    /// Returns the instruction count for a method.
    ///
    /// # Arguments
    ///
    /// * `token` - The metadata token of the method.
    ///
    /// # Returns
    ///
    /// The instruction count if the summary exists, `None` otherwise.
    #[must_use]
    pub fn instruction_count(&self, token: Token) -> Option<usize> {
        self.summaries.get(&token).map(|r| r.instruction_count)
    }

    /// Checks if a method is a string decryptor.
    ///
    /// # Arguments
    ///
    /// * `token` - The metadata token of the method.
    ///
    /// # Returns
    ///
    /// `true` if the method has been identified as a string decryptor.
    #[must_use]
    pub fn is_string_decryptor(&self, token: Token) -> bool {
        self.summaries
            .get(&token)
            .is_some_and(|r| r.is_string_decryptor)
    }

    /// Modifies a method summary in place.
    ///
    /// # Arguments
    ///
    /// * `token` - The metadata token of the method.
    /// * `f` - A function that takes a mutable reference to the summary and modifies it.
    ///
    /// # Returns
    ///
    /// `true` if the summary existed and was modified, `false` otherwise.
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
    ///
    /// # Arguments
    ///
    /// * `summary` - The method summary to store. The token is extracted from the summary.
    pub fn set_summary(&self, summary: MethodSummary) {
        self.summaries.insert(summary.token, summary);
    }

    /// Executes a closure with a reference to the call sites for a callee.
    ///
    /// This is the preferred way to access call sites as it avoids cloning.
    ///
    /// # Arguments
    ///
    /// * `callee` - The metadata token of the callee method.
    /// * `f` - A closure that receives a reference to the call sites.
    ///
    /// # Returns
    ///
    /// The result of the closure if call sites exist, `None` otherwise.
    pub fn with_call_sites<R, F>(&self, callee: Token, f: F) -> Option<R>
    where
        F: FnOnce(&boxcar::Vec<CallSiteInfo>) -> R,
    {
        self.call_sites.get(&callee).map(|r| f(&r))
    }

    /// Returns the number of call sites for a callee method.
    ///
    /// # Arguments
    ///
    /// * `callee` - The metadata token of the callee method.
    ///
    /// # Returns
    ///
    /// The number of call sites.
    #[must_use]
    pub fn call_site_count(&self, callee: Token) -> usize {
        self.call_sites.get(&callee).map_or(0, |r| r.count())
    }

    /// Checks if a callee has any call sites.
    ///
    /// # Arguments
    ///
    /// * `callee` - The metadata token of the callee method.
    ///
    /// # Returns
    ///
    /// `true` if there is at least one call site.
    #[must_use]
    pub fn has_call_sites(&self, callee: Token) -> bool {
        self.call_sites.get(&callee).is_some_and(|r| r.count() > 0)
    }

    /// Iterates over all call sites for a callee method.
    ///
    /// # Arguments
    ///
    /// * `callee` - The metadata token of the callee method.
    /// * `f` - A closure called for each call site.
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
    ///
    /// # Arguments
    ///
    /// * `callee` - The metadata token of the method being called.
    /// * `call_site` - Information about the call site.
    pub fn add_call_site(&self, callee: Token, call_site: CallSiteInfo) {
        self.call_sites.entry(callee).or_default().push(call_site);
    }

    /// Returns the constant value of a parameter if all call sites agree.
    ///
    /// # Arguments
    ///
    /// * `method` - The metadata token of the method.
    /// * `param_index` - The zero-based index of the parameter.
    ///
    /// # Returns
    ///
    /// The constant value if all call sites pass the same value, `None` otherwise.
    #[must_use]
    pub fn parameter_constant(&self, method: Token, param_index: usize) -> Option<ConstValue> {
        self.with_summary(method, |s| s.parameter_constant(param_index).cloned())
            .flatten()
    }

    /// Checks if a method always returns a constant value.
    ///
    /// # Arguments
    ///
    /// * `method` - The metadata token of the method.
    ///
    /// # Returns
    ///
    /// The constant return value if the method always returns the same value.
    #[must_use]
    pub fn returns_constant(&self, method: Token) -> Option<ConstValue> {
        self.with_summary(method, |s| s.returns_constant().cloned())
            .flatten()
    }

    /// Executes a closure with a reference to the SSA function.
    ///
    /// # Arguments
    ///
    /// * `token` - The metadata token of the method.
    /// * `f` - A closure that receives a reference to the SSA function.
    ///
    /// # Returns
    ///
    /// The result of the closure if the SSA exists, `None` otherwise.
    pub fn with_ssa<R, F>(&self, token: Token, f: F) -> Option<R>
    where
        F: FnOnce(&SsaFunction) -> R,
    {
        self.ssa_functions.get(&token).map(|r| f(&r))
    }

    /// Executes a closure with a mutable reference to the SSA function.
    ///
    /// # Arguments
    ///
    /// * `token` - The metadata token of the method.
    /// * `f` - A closure that receives a mutable reference to the SSA function.
    ///
    /// # Returns
    ///
    /// The result of the closure if the SSA exists, `None` otherwise.
    pub fn with_ssa_mut<R, F>(&self, token: Token, f: F) -> Option<R>
    where
        F: FnOnce(&mut SsaFunction) -> R,
    {
        self.ssa_functions.get_mut(&token).map(|mut r| f(&mut r))
    }

    /// Checks if an SSA function exists for a method.
    ///
    /// # Arguments
    ///
    /// * `token` - The metadata token of the method.
    ///
    /// # Returns
    ///
    /// `true` if the SSA function exists, `false` otherwise.
    #[must_use]
    pub fn has_ssa(&self, token: Token) -> bool {
        self.ssa_functions.contains_key(&token)
    }

    /// Stores an SSA function for a method.
    ///
    /// # Arguments
    ///
    /// * `token` - The metadata token of the method.
    /// * `ssa` - The SSA function representation.
    pub fn set_ssa(&self, token: Token, ssa: SsaFunction) {
        self.ssa_functions.insert(token, ssa);
    }

    /// Removes and returns the SSA function for a method.
    ///
    /// # Arguments
    ///
    /// * `token` - The metadata token of the method.
    ///
    /// # Returns
    ///
    /// The SSA function if it existed, `None` otherwise.
    pub fn take_ssa(&self, token: Token) -> Option<SsaFunction> {
        self.ssa_functions.remove(&token).map(|(_, v)| v)
    }

    /// Returns methods in reverse topological order (callees before callers).
    ///
    /// This ordering is useful for bottom-up analysis where callees should
    /// be processed before their callers.
    ///
    /// # Returns
    ///
    /// A vector of method tokens in reverse topological order.
    #[must_use]
    pub fn methods_reverse_topological(&self) -> Vec<Token> {
        let mut order = self.call_graph.topological_order().to_vec();
        order.reverse();
        order
    }

    /// Returns methods in topological order (callers before callees).
    ///
    /// This ordering is useful for top-down analysis where callers should
    /// be processed before their callees.
    ///
    /// # Returns
    ///
    /// A vector of method tokens in topological order.
    #[must_use]
    pub fn methods_topological(&self) -> Vec<Token> {
        self.call_graph.topological_order().to_vec()
    }

    /// Returns an iterator over all method tokens that have SSA functions.
    ///
    /// # Returns
    ///
    /// An iterator yielding method tokens.
    pub fn all_methods(&self) -> impl Iterator<Item = Token> + '_ {
        self.ssa_functions.iter().map(|r| *r.key())
    }

    /// Returns the count of methods with SSA representations.
    #[must_use]
    pub fn method_count(&self) -> usize {
        self.ssa_functions.len()
    }

    /// Executes a closure with a reference to a known constant value.
    ///
    /// This is the preferred way to access known values as it avoids cloning.
    ///
    /// # Arguments
    ///
    /// * `method` - The metadata token of the method containing the variable.
    /// * `var` - The SSA variable identifier.
    /// * `f` - A closure that receives a reference to the constant value.
    ///
    /// # Returns
    ///
    /// The result of the closure if the value exists, `None` otherwise.
    pub fn with_known_value<R, F>(&self, method: Token, var: SsaVarId, f: F) -> Option<R>
    where
        F: FnOnce(&ConstValue) -> R,
    {
        self.known_values
            .get(&method)
            .and_then(|method_values| method_values.get(&var).map(|r| f(&r)))
    }

    /// Checks if a known value exists for an SSA variable.
    ///
    /// # Arguments
    ///
    /// * `method` - The metadata token of the method containing the variable.
    /// * `var` - The SSA variable identifier.
    ///
    /// # Returns
    ///
    /// `true` if a constant value is known for this variable.
    #[must_use]
    pub fn has_known_value(&self, method: Token, var: SsaVarId) -> bool {
        self.known_values
            .get(&method)
            .is_some_and(|m| m.contains_key(&var))
    }

    /// Checks if a known value satisfies a predicate.
    ///
    /// # Arguments
    ///
    /// * `method` - The metadata token of the method containing the variable.
    /// * `var` - The SSA variable identifier.
    /// * `predicate` - A closure that tests the value.
    ///
    /// # Returns
    ///
    /// `true` if the value exists and satisfies the predicate.
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
    ///
    /// This is the preferred way to access multiple known values as it avoids
    /// creating an intermediate collection.
    ///
    /// # Arguments
    ///
    /// * `method` - The metadata token of the method.
    /// * `f` - A closure called for each (variable, value) pair.
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
    ///
    /// Caches the constant value for later retrieval by other passes. This enables
    /// interprocedural constant propagation where values discovered in one pass
    /// can be used by subsequent passes.
    ///
    /// # Arguments
    ///
    /// * `method` - The metadata token of the method containing the variable.
    /// * `var` - The SSA variable identifier.
    /// * `value` - The constant value to record.
    pub fn add_known_value(&self, method: Token, var: SsaVarId, value: ConstValue) {
        self.known_values
            .entry(method)
            .or_default()
            .insert(var, value);
    }

    /// Clears known values for a method when its SSA is modified.
    ///
    /// Should be called after SSA transformations that invalidate previously
    /// computed constant values (e.g., instruction replacement or removal).
    ///
    /// # Arguments
    ///
    /// * `method` - The metadata token of the method whose values to clear.
    pub fn clear_known_values(&self, method: Token) {
        self.known_values.remove(&method);
    }

    /// Returns the number of known values for a method.
    ///
    /// # Arguments
    ///
    /// * `method` - The metadata token of the method.
    ///
    /// # Returns
    ///
    /// The count of known constant values for the specified method.
    #[must_use]
    pub fn known_value_count(&self, method: Token) -> usize {
        self.known_values
            .get(&method)
            .map_or(0, |inner| inner.len())
    }

    /// Records a known value range for an SSA variable.
    ///
    /// Caches the value range for later retrieval by other passes. This enables
    /// range-based optimizations like strength reduction for signed operations.
    ///
    /// # Arguments
    ///
    /// * `method` - The metadata token of the method containing the variable.
    /// * `var` - The SSA variable identifier.
    /// * `range` - The value range to record.
    pub fn add_known_range(&self, method: Token, var: SsaVarId, range: ValueRange) {
        self.known_ranges
            .entry(method)
            .or_default()
            .insert(var, range);
    }

    /// Executes a closure with a reference to a known value range.
    ///
    /// This is the preferred way to access known ranges as it avoids cloning.
    ///
    /// # Arguments
    ///
    /// * `method` - The metadata token of the method containing the variable.
    /// * `var` - The SSA variable identifier.
    /// * `f` - A closure that receives a reference to the value range.
    ///
    /// # Returns
    ///
    /// The result of the closure if the range exists, `None` otherwise.
    pub fn with_known_range<R, F>(&self, method: Token, var: SsaVarId, f: F) -> Option<R>
    where
        F: FnOnce(&ValueRange) -> R,
    {
        self.known_ranges
            .get(&method)
            .and_then(|method_ranges| method_ranges.get(&var).map(|r| f(&r)))
    }

    /// Checks if a known range exists for an SSA variable.
    ///
    /// # Arguments
    ///
    /// * `method` - The metadata token of the method containing the variable.
    /// * `var` - The SSA variable identifier.
    ///
    /// # Returns
    ///
    /// `true` if a value range is known for this variable.
    #[must_use]
    pub fn has_known_range(&self, method: Token, var: SsaVarId) -> bool {
        self.known_ranges
            .get(&method)
            .is_some_and(|m| m.contains_key(&var))
    }

    /// Iterates over all known ranges for a method.
    ///
    /// This is the preferred way to access multiple known ranges as it avoids
    /// creating an intermediate collection.
    ///
    /// # Arguments
    ///
    /// * `method` - The metadata token of the method.
    /// * `f` - A closure called for each (variable, range) pair.
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
    ///
    /// Should be called after SSA transformations that invalidate previously
    /// computed value ranges.
    ///
    /// # Arguments
    ///
    /// * `method` - The metadata token of the method whose ranges to clear.
    pub fn clear_known_ranges(&self, method: Token) {
        self.known_ranges.remove(&method);
    }

    /// Canonicalizes all SSA functions in preparation for code generation.
    ///
    /// This should be called after all passes have completed and before
    /// code generation. Canonicalization cleans up the SSA representation
    /// by removing unreachable blocks, consolidating instructions, and
    /// optimizing local variables.
    ///
    /// The local variable remappings are stored and can be retrieved via
    /// [`with_local_remapping()`](Self::with_local_remapping) for creating
    /// optimized local variable signatures.
    pub fn canonicalize_all_ssa(&self) {
        // Collect tokens first, then process in parallel.
        // We use remove/insert to avoid holding shard locks during processing.
        let tokens: Vec<Token> = self.all_methods().collect();

        tokens.par_iter().for_each(|&token| {
            // Remove SSA (brief lock, then released)
            let Some((_, mut ssa)) = self.ssa_functions.remove(&token) else {
                return;
            };

            // Process with no locks held
            ssa.canonicalize();
            let remapping = ssa.optimize_locals();

            // Reinsert SSA and store remapping (brief locks)
            self.ssa_functions.insert(token, ssa);
            self.local_remappings.insert(token, remapping);
        });
    }

    /// Executes a closure with a reference to the local variable remapping.
    ///
    /// After [`canonicalize_all_ssa()`](Self::canonicalize_all_ssa) is called,
    /// this provides access to the mapping from old local indices to new indices.
    /// Unused locals map to `None`, while used locals map to `Some(new_index)`.
    ///
    /// # Arguments
    ///
    /// * `token` - The metadata token of the method.
    /// * `f` - A closure that receives a reference to the remapping slice.
    ///
    /// # Returns
    ///
    /// The result of the closure if a remapping exists, `None` otherwise.
    pub fn with_local_remapping<R, F>(&self, token: Token, f: F) -> Option<R>
    where
        F: FnOnce(&[Option<u16>]) -> R,
    {
        self.local_remappings.get(&token).map(|r| f(&r))
    }

    /// Checks if a local variable remapping exists for a method.
    ///
    /// # Arguments
    ///
    /// * `token` - The metadata token of the method.
    ///
    /// # Returns
    ///
    /// `true` if a remapping has been computed for this method.
    #[must_use]
    pub fn has_local_remapping(&self, token: Token) -> bool {
        self.local_remappings.contains_key(&token)
    }

    /// Registers an emulation hook factory.
    ///
    /// Obfuscators call this during `initialize_context()` to provide hooks
    /// that should be used during decryption emulation. The decryption pass
    /// calls [`create_emulation_hooks()`](Self::create_emulation_hooks) to
    /// get fresh hook instances.
    ///
    /// # Arguments
    ///
    /// * `factory` - A function or closure that creates a new hook instance.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// // In obfuscator's initialize_context():
    /// ctx.register_emulation_hook(create_lzma_hook);
    ///
    /// // With captured state:
    /// let tokens = anti_tamper_tokens.clone();
    /// ctx.register_emulation_hook(move || create_anti_tamper_stub_hook(tokens.clone()));
    /// ```
    pub fn register_emulation_hook<F>(&self, factory: F)
    where
        F: Fn() -> Hook + Send + Sync + 'static,
    {
        self.emulation_hooks.push(Box::new(factory));
    }

    /// Creates fresh hook instances from all registered factories.
    ///
    /// Each call returns new hook instances, which is necessary because
    /// hooks contain non-Clone types. The decryption pass calls this
    /// for each emulation process it creates.
    ///
    /// # Returns
    ///
    /// A vector of hooks created by calling all registered factories.
    #[must_use]
    pub fn create_emulation_hooks(&self) -> Vec<Hook> {
        self.emulation_hooks.iter().map(|(_, f)| f()).collect()
    }

    /// Returns true if any emulation hooks are registered.
    #[must_use]
    pub fn has_emulation_hooks(&self) -> bool {
        !self.emulation_hooks.is_empty()
    }

    /// Returns the emulation max instructions limit from config.
    #[must_use]
    pub fn emulation_max_instructions(&self) -> u64 {
        self.config.emulation_max_instructions
    }

    /// Registers a method to be executed during emulation template warmup.
    ///
    /// Obfuscators call this during `initialize_context()` to register static
    /// constructors (.cctors) that should be run before decryption emulation.
    /// This is critical for performance with obfuscators like ConfuserEx where
    /// the decryptor type's .cctor performs expensive one-time initialization
    /// (e.g., LZMA decompression of the constants buffer).
    ///
    /// The decryption pass executes these methods when creating the template
    /// emulation process, before any forking occurs. This way, all forked
    /// processes inherit the warmed-up state.
    ///
    /// # Arguments
    ///
    /// * `method` - The method token (typically a .cctor) to execute during warmup.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// // In obfuscator's initialize_context():
    /// // Register the decryptor type's .cctor for warmup
    /// if let Some(cctor) = find_decryptor_cctor(assembly, decryptor_token) {
    ///     ctx.register_warmup_method(cctor);
    /// }
    /// ```
    pub fn register_warmup_method(&self, method: Token) {
        if self.warmup_methods.iter().any(|(_, &m)| m == method) {
            return;
        }
        self.warmup_methods.push(method);
    }

    /// Returns all registered warmup methods.
    ///
    /// The decryption pass calls this when creating the template emulation
    /// process to get the list of methods to execute for warmup.
    ///
    /// # Returns
    ///
    /// A vector of method tokens to execute during template warmup.
    #[must_use]
    pub fn warmup_methods(&self) -> Vec<Token> {
        self.warmup_methods.iter().map(|(_, &m)| m).collect()
    }

    /// Returns true if any warmup methods are registered.
    #[must_use]
    pub fn has_warmup_methods(&self) -> bool {
        !self.warmup_methods.is_empty()
    }

    /// Registers a state machine provider for order-dependent decryption.
    ///
    /// Called by obfuscator detection modules when state machine patterns
    /// (like ConfuserEx's CFGCtx) are detected. The provider encapsulates
    /// both the machine semantics and the methods that use it.
    ///
    /// # Arguments
    ///
    /// * `provider` - The state machine provider to register.
    pub fn register_statemachine_provider(&self, provider: Arc<dyn StateMachineProvider>) {
        self.statemachine_providers.push(provider);
    }

    /// Returns true if any state machine providers are registered.
    #[must_use]
    pub fn has_statemachine_providers(&self) -> bool {
        self.statemachine_providers.count() > 0
    }

    /// Finds the state machine provider that applies to a method.
    ///
    /// Searches through registered providers and returns the first one
    /// that claims to handle the specified method.
    ///
    /// # Arguments
    ///
    /// * `method` - The method token to check.
    ///
    /// # Returns
    ///
    /// The provider that handles this method, or `None` if the method
    /// doesn't use any registered state machine.
    #[must_use]
    pub fn get_statemachine_provider_for_method(
        &self,
        method: Token,
    ) -> Option<Arc<dyn StateMachineProvider>> {
        for (_, provider) in self.statemachine_providers.iter() {
            if provider.applies_to_method(method) {
                return Some(Arc::clone(provider));
            }
        }
        None
    }

    /// Returns true if a method uses any state machine for encryption.
    ///
    /// This is the generic replacement for `is_cfg_mode_method()`.
    ///
    /// # Arguments
    ///
    /// * `method` - The method token to check.
    #[must_use]
    pub fn is_statemachine_method(&self, method: Token) -> bool {
        self.get_statemachine_provider_for_method(method).is_some()
    }

    /// Returns all methods that use state machines.
    ///
    /// This is the generic replacement for `cfg_mode_methods()`.
    #[must_use]
    pub fn statemachine_methods(&self) -> Vec<Token> {
        let mut methods = Vec::new();
        for (_, provider) in self.statemachine_providers.iter() {
            methods.extend(provider.methods());
        }
        methods
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::CallGraph;

    #[test]
    fn test_call_site_info() {
        let info = CallSiteInfo {
            caller: Token::new(0x06000001),
            offset: 10,
            arguments: vec![Some(ConstValue::I32(42)), None],
            is_live: true,
        };

        assert_eq!(info.caller, Token::new(0x06000001));
        assert_eq!(info.offset, 10);
        assert_eq!(info.arguments.len(), 2);
    }

    #[test]
    fn test_known_values() {
        let call_graph = Arc::new(CallGraph::new());
        let ctx = AnalysisContext::new(call_graph);

        let method = Token::new(0x06000001);
        let var1 = SsaVarId::new();
        let var2 = SsaVarId::new();
        let var3 = SsaVarId::new();

        // Initially no known values
        assert!(!ctx.has_known_value(method, var1));
        assert_eq!(ctx.known_value_count(method), 0);

        // Add some values
        ctx.add_known_value(method, var1, ConstValue::I32(42));
        ctx.add_known_value(method, var2, ConstValue::I64(100));
        ctx.add_known_value(method, var3, ConstValue::True);

        // Retrieve values
        assert!(ctx.known_value_is(method, var1, |v| *v == ConstValue::I32(42)));
        assert!(ctx.known_value_is(method, var2, |v| *v == ConstValue::I64(100)));
        assert!(ctx.known_value_is(method, var3, |v| *v == ConstValue::True));
        assert_eq!(ctx.known_value_count(method), 3);

        // Update a value
        ctx.add_known_value(method, var1, ConstValue::I32(99));
        assert!(ctx.known_value_is(method, var1, |v| *v == ConstValue::I32(99)));

        // Different method has different values
        let method2 = Token::new(0x06000002);
        assert!(!ctx.has_known_value(method2, var1));
        ctx.add_known_value(method2, var1, ConstValue::I32(1));
        assert!(ctx.known_value_is(method2, var1, |v| *v == ConstValue::I32(1)));
        assert!(ctx.known_value_is(method, var1, |v| *v == ConstValue::I32(99)));

        // Clear values for one method
        ctx.clear_known_values(method);
        assert!(!ctx.has_known_value(method, var1));
        assert_eq!(ctx.known_value_count(method), 0);
        // Other method unaffected
        assert!(ctx.known_value_is(method2, var1, |v| *v == ConstValue::I32(1)));
    }

    #[test]
    fn test_known_values_iterator() {
        let call_graph = Arc::new(CallGraph::new());
        let ctx = AnalysisContext::new(call_graph);

        let method = Token::new(0x06000001);
        let v0 = SsaVarId::new();
        let v1 = SsaVarId::new();
        let v2 = SsaVarId::new();
        ctx.add_known_value(method, v0, ConstValue::I32(1));
        ctx.add_known_value(method, v1, ConstValue::I32(2));
        ctx.add_known_value(method, v2, ConstValue::I32(3));

        let mut count = 0;
        ctx.for_each_known_value(method, |_, _| count += 1);
        assert_eq!(count, 3);
    }

    #[test]
    fn test_thread_safe_access() {
        use std::thread;

        let call_graph = Arc::new(CallGraph::new());
        let ctx = Arc::new(AnalysisContext::new(call_graph));

        let method1 = Token::new(0x06000001);
        let method2 = Token::new(0x06000002);

        // Spawn multiple threads that access different parts of the context
        let handles: Vec<_> = (0..4)
            .map(|i| {
                let ctx = Arc::clone(&ctx);
                let method = if i % 2 == 0 { method1 } else { method2 };
                thread::spawn(move || {
                    for j in 0..100 {
                        let var = SsaVarId::new();
                        ctx.add_known_value(method, var, ConstValue::I32(j));
                        ctx.mark_dead(Token::new(0x06000000 + i * 1000 + j as u32));
                        ctx.add_entry_point(Token::new(0x06000000 + i * 1000 + j as u32));
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }

        // Verify counts
        assert!(ctx.known_value_count(method1) > 0);
        assert!(ctx.known_value_count(method2) > 0);
    }
}
