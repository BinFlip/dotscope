//! Analysis context for interprocedural deobfuscation.
//!
//! The [`AnalysisContext`] wraps a [`CompilerContext`] with deobfuscation-specific
//! state. It implements `Deref<Target = CompilerContext>` so all compiler context
//! methods are accessible directly through `&AnalysisContext`.

use std::{ops::Deref, sync::Arc};

use dashmap::DashSet;

use crate::{
    compiler::CompilerContext,
    deobfuscation::{
        config::EngineConfig, decryptors::DecryptorContext, statemachine::StateMachineProvider,
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
/// This wraps a [`CompilerContext`] (which holds all generic compiler state) with
/// deobfuscation-specific fields for obfuscator detection, emulation hooks,
/// warmup methods, and state machine providers.
///
/// All `CompilerContext` methods and fields are accessible via `Deref`:
/// ```rust,ignore
/// let ctx: &AnalysisContext = ...;
/// ctx.events.record(...);           // via Deref to CompilerContext
/// ctx.add_known_value(...);         // via Deref to CompilerContext
/// ctx.register_warmup_method(...);  // on AnalysisContext directly
/// ```
pub struct AnalysisContext {
    /// The underlying compiler context with all generic pass state.
    pub compiler: CompilerContext,

    /// Decryptor tracking for obfuscator-specific string/resource decryption.
    ///
    /// Obfuscator modules register decryptors here during detection, and SSA
    /// passes use it to identify and process decryption calls.
    pub decryptors: Arc<DecryptorContext>,

    /// Dispatcher methods (control flow obfuscation).
    /// Methods are added here when a dispatcher is DETECTED, even if unflattening fails.
    /// Used to prevent inlining of dispatcher methods.
    pub dispatchers: Arc<DashSet<Token>>,

    /// Successfully unflattened dispatcher methods.
    /// Methods are added here only when redirects were actually computed and applied.
    /// Used to skip methods that have already been processed.
    pub unflattened_dispatchers: Arc<DashSet<Token>>,

    /// Engine configuration (for pass-specific thresholds).
    pub config: EngineConfig,

    /// Registered hook factories for emulation.
    ///
    /// Obfuscators register hook factories during `initialize_context()` to provide
    /// obfuscator-specific emulation hooks. The decryption pass calls these factories
    /// to get fresh hooks for each emulation process.
    pub emulation_hooks: Arc<boxcar::Vec<HookFactory>>,

    /// Methods that need to be executed during emulation template warmup.
    ///
    /// Obfuscators register static constructors (.cctors) here that should run
    /// before decryption emulation begins. This is critical for obfuscators like
    /// ConfuserEx where the .cctor performs expensive initialization (LZMA
    /// decompression) that should happen once on the template, not on every fork.
    pub warmup_methods: Arc<boxcar::Vec<Token>>,

    /// State machine providers for order-dependent constant decryption.
    ///
    /// Each obfuscator that uses state machines for encryption (e.g., ConfuserEx
    /// with CFGCtx) registers a provider during detection. The decryption pass
    /// queries these providers to determine how to process each method.
    pub statemachine_providers: Arc<boxcar::Vec<Arc<dyn StateMachineProvider>>>,
}

impl Deref for AnalysisContext {
    type Target = CompilerContext;

    fn deref(&self) -> &CompilerContext {
        &self.compiler
    }
}

impl AnalysisContext {
    /// Creates a new analysis context with default configuration.
    pub fn new(call_graph: Arc<crate::analysis::CallGraph>) -> Self {
        Self::with_config(call_graph, EngineConfig::default())
    }

    /// Creates a new analysis context with custom configuration.
    pub fn with_config(call_graph: Arc<crate::analysis::CallGraph>, config: EngineConfig) -> Self {
        Self {
            compiler: CompilerContext::new(call_graph),
            decryptors: Arc::new(DecryptorContext::new()),
            dispatchers: Arc::new(DashSet::new()),
            unflattened_dispatchers: Arc::new(DashSet::new()),
            config,
            emulation_hooks: Arc::new(boxcar::Vec::new()),
            warmup_methods: Arc::new(boxcar::Vec::new()),
            statemachine_providers: Arc::new(boxcar::Vec::new()),
        }
    }

    // ── Dispatcher tracking ────────────────────────────────────────────

    /// Checks if a method is a dispatcher (control flow obfuscation).
    #[must_use]
    pub fn is_dispatcher(&self, token: Token) -> bool {
        self.dispatchers.contains(&token)
    }

    /// Marks a method as a dispatcher and adds it to the no-inline set.
    pub fn mark_dispatcher(&self, token: Token) {
        self.dispatchers.insert(token);
        self.compiler.no_inline.insert(token);
    }

    // ── Emulation hooks ────────────────────────────────────────────────

    /// Registers an emulation hook factory.
    ///
    /// Obfuscators call this during `initialize_context()` to provide hooks
    /// that should be used during decryption emulation.
    pub fn register_emulation_hook<F>(&self, factory: F)
    where
        F: Fn() -> Hook + Send + Sync + 'static,
    {
        self.emulation_hooks.push(Box::new(factory));
    }

    /// Creates fresh hook instances from all registered factories.
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

    // ── Warmup methods ─────────────────────────────────────────────────

    /// Registers a method to be executed during emulation template warmup.
    pub fn register_warmup_method(&self, method: Token) {
        if self.warmup_methods.iter().any(|(_, &m)| m == method) {
            return;
        }
        self.warmup_methods.push(method);
    }

    /// Returns all registered warmup methods.
    #[must_use]
    pub fn warmup_methods(&self) -> Vec<Token> {
        self.warmup_methods.iter().map(|(_, &m)| m).collect()
    }

    /// Returns true if any warmup methods are registered.
    #[must_use]
    pub fn has_warmup_methods(&self) -> bool {
        !self.warmup_methods.is_empty()
    }

    // ── State machine providers ────────────────────────────────────────

    /// Registers a state machine provider for order-dependent decryption.
    pub fn register_statemachine_provider(&self, provider: Arc<dyn StateMachineProvider>) {
        self.statemachine_providers.push(provider);
    }

    /// Returns true if any state machine providers are registered.
    #[must_use]
    pub fn has_statemachine_providers(&self) -> bool {
        self.statemachine_providers.count() > 0
    }

    /// Finds the state machine provider that applies to a method.
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
    #[must_use]
    pub fn is_statemachine_method(&self, method: Token) -> bool {
        self.get_statemachine_provider_for_method(method).is_some()
    }

    /// Returns all methods that use state machines.
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
    use crate::{
        analysis::{CallGraph, ConstValue, SsaVarId},
        compiler::CallSiteInfo,
        deobfuscation::context::AnalysisContext,
        metadata::token::Token,
    };

    use std::sync::Arc;

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
