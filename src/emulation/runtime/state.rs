//! Runtime state management for .NET emulation.
//!
//! This module provides [`RuntimeState`], the central coordinator for all runtime
//! services during .NET emulation. It integrates the hook system, native stubs,
//! and application domain state into a unified interface.
//!
//! # Overview
//!
//! The `RuntimeState` serves as the "runtime" layer of the emulation system:
//!
//! ```text
//! +-------------------+
//! |  EmulationEngine  |  <- Executes CIL bytecode
//! +--------+----------+
//!          |
//!          v
//! +--------+----------+
//! |   RuntimeState    |  <- Provides method implementations
//! +--------+----------+
//!          |
//!    +-----+-----+-----+
//!    |     |           |
//!    v     v           v
//!  Hooks Native    AppDomain
//! ```
//!
//! # Key Components
//!
//! The runtime state manages:
//!
//! - [`HookManager`](super::HookManager) - Method interception with pre/post hooks
//! - [`NativeStubRegistry`](super::NativeStubRegistry) - P/Invoke stubs
//! - [`AppDomainState`](super::AppDomainState) - Application domain simulation
//! - [`EmulationConfig`](crate::emulation::process::EmulationConfig) - Configuration
//! - [`UnknownMethodBehavior`](super::UnknownMethodBehavior) - Fallback behavior
//!
//! # Hook Resolution
//!
//! When the emulator needs to handle a method call:
//!
//! 1. **Hook Matching**: Check [`HookManager`](super::HookManager) for matching hooks
//! 2. **Pre-Hook**: Execute pre-hook (can bypass method)
//! 3. **Original/Post-Hook**: Execute original and/or post-hook
//! 4. **Default Behavior**: Apply [`UnknownMethodBehavior`](super::UnknownMethodBehavior)
//!
//! # Examples
//!
//! ## Basic Usage
//!
//! ```ignore
//! use dotscope::emulation::runtime::RuntimeState;
//!
//! // Create with default configuration (BCL hooks registered)
//! let runtime = RuntimeState::new();
//!
//! // Access hooks
//! println!("Hooks registered: {}", runtime.hooks().len());
//! ```
//!
//! ## Custom Configuration
//!
//! ```ignore
//! use dotscope::emulation::runtime::{RuntimeState, RuntimeStateBuilder, Hook};
//! use dotscope::emulation::process::EmulationConfig;
//!
//! let runtime = RuntimeStateBuilder::new()
//!     .config(EmulationConfig::minimal())
//!     .hook(Hook::new("my-hook").match_method_name("Decrypt"))
//!     .build();
//! ```
//!
//! # Thread Safety
//!
//! `RuntimeState` is designed for single-threaded emulation. The state is
//! mutable and should not be shared between threads without external
//! synchronization.

use std::sync::Arc;

use crate::{
    emulation::{
        process::{EmulationConfig, UnknownMethodBehavior},
        runtime::{bcl, hook::HookManager, native, AppDomainState, Hook},
    },
    metadata::token::Token,
};

/// Central runtime state for .NET emulation.
///
/// `RuntimeState` is the main entry point for runtime services during emulation.
/// It coordinates method hook execution, native call handling, and application domain
/// state. Most emulation operations that require "runtime" behavior go through
/// this struct.
///
/// # Creating RuntimeState
///
/// There are several ways to create a `RuntimeState`:
///
/// - [`new()`](Self::new) - Default configuration with BCL hooks and P/Invoke stubs
/// - [`with_config()`](Self::with_config) - Custom configuration
/// - [`RuntimeStateBuilder`] - Fluent builder API
///
/// # Method Resolution
///
/// Method calls are handled through the hook system:
///
/// 1. [`HookManager::execute()`](super::HookManager::execute) checks for matching hooks
/// 2. Pre-hooks can bypass the original method
/// 3. Post-hooks can modify the return value
/// 4. [`UnknownMethodBehavior`](super::UnknownMethodBehavior) applies if no hook matches
///
/// # Examples
///
/// ```ignore
/// use dotscope::emulation::runtime::RuntimeState;
/// use dotscope::emulation::process::EmulationConfig;
/// use std::sync::Arc;
///
/// // Default configuration
/// let runtime = RuntimeState::new();
///
/// // Custom configuration
/// let config = EmulationConfig::minimal();
/// let runtime = RuntimeState::with_config(Arc::new(config));
///
/// // Access components (hooks include both BCL and native P/Invoke hooks)
/// println!("Hooks: {}", runtime.hooks().len());
/// ```
#[derive(Debug)]
pub struct RuntimeState {
    /// Hook manager for method interception (includes BCL and native hooks).
    hooks: HookManager,

    /// Application domain simulation state.
    app_domain: AppDomainState,

    /// Behavior when no hook matches a method call.
    unknown_method_behavior: UnknownMethodBehavior,

    /// Reference to the emulation configuration.
    config: Arc<EmulationConfig>,
}

impl RuntimeState {
    /// Creates a new runtime state with default configuration.
    ///
    /// This creates a runtime with:
    /// - Default BCL hooks enabled
    /// - Default P/Invoke stubs enabled
    /// - Empty application domain state
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use dotscope::emulation::runtime::RuntimeState;
    ///
    /// let runtime = RuntimeState::new();
    /// assert!(!runtime.hooks().is_empty());
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(Arc::new(EmulationConfig::default()))
    }

    /// Creates a new runtime state with the given configuration.
    ///
    /// The configuration controls which default hooks/stubs are registered:
    ///
    /// - `config.stubs.bcl_stubs` - Register BCL method hooks
    /// - `config.stubs.pinvoke_stubs` - Register P/Invoke stubs
    ///
    /// # Arguments
    ///
    /// * `config` - The emulation configuration
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use dotscope::emulation::runtime::RuntimeState;
    /// use dotscope::emulation::process::EmulationConfig;
    /// use std::sync::Arc;
    ///
    /// let config = EmulationConfig::minimal();
    /// let runtime = RuntimeState::with_config(Arc::new(config));
    /// ```
    #[must_use]
    pub fn with_config(config: Arc<EmulationConfig>) -> Self {
        let mut hooks = HookManager::new();

        // Register default BCL hooks based on configuration
        if config.stubs.bcl_stubs {
            bcl::register(&mut hooks);
        }

        // Register default native P/Invoke hooks based on configuration
        if config.stubs.pinvoke_stubs {
            native::register(&mut hooks);
        }

        Self {
            hooks,
            app_domain: AppDomainState::new(),
            unknown_method_behavior: UnknownMethodBehavior::default(),
            config,
        }
    }

    /// Returns a reference to the emulation configuration.
    #[must_use]
    pub fn config(&self) -> &EmulationConfig {
        &self.config
    }

    /// Returns a reference to the hook manager.
    ///
    /// The hook manager provides flexible method interception with support for:
    /// - Multiple matching criteria (name, signature, runtime data)
    /// - Pre/post hooks with bypass capability
    /// - Closure-based handlers
    #[must_use]
    pub fn hooks(&self) -> &HookManager {
        &self.hooks
    }

    /// Returns a mutable reference to the hook manager.
    pub fn hooks_mut(&mut self) -> &mut HookManager {
        &mut self.hooks
    }

    /// Registers a hook for method interception.
    ///
    /// This is a convenience method that delegates to
    /// [`HookManager::register`](super::HookManager::register).
    ///
    /// # Arguments
    ///
    /// * `hook` - The hook to register
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use dotscope::emulation::runtime::{RuntimeState, Hook, PreHookResult};
    ///
    /// let mut runtime = RuntimeState::new();
    /// runtime.register_hook(
    ///     Hook::new("log-calls")
    ///         .match_name("System", "String", "Concat")
    ///         .pre(|ctx, thread| {
    ///             println!("String.Concat called!");
    ///             PreHookResult::Continue
    ///         })
    /// );
    /// ```
    pub fn register_hook(&mut self, hook: Hook) {
        self.hooks.register(hook);
    }

    /// Returns the behavior for unknown method calls.
    #[must_use]
    pub fn unknown_method_behavior(&self) -> UnknownMethodBehavior {
        self.unknown_method_behavior
    }

    /// Sets the behavior for unknown method calls.
    ///
    /// This controls what happens when a method call is encountered
    /// that has no matching hook.
    ///
    /// # Arguments
    ///
    /// * `behavior` - The behavior to use
    pub fn set_unknown_method_behavior(&mut self, behavior: UnknownMethodBehavior) {
        self.unknown_method_behavior = behavior;
    }

    /// Returns a reference to the application domain state.
    #[must_use]
    pub fn app_domain(&self) -> &AppDomainState {
        &self.app_domain
    }

    /// Returns a mutable reference to the application domain state.
    pub fn app_domain_mut(&mut self) -> &mut AppDomainState {
        &mut self.app_domain
    }

    /// Sets the currently executing assembly.
    ///
    /// This is a convenience method that delegates to
    /// [`AppDomainState::set_executing_assembly`](super::AppDomainState::set_executing_assembly).
    ///
    /// # Arguments
    ///
    /// * `token` - The assembly token
    pub fn set_executing_assembly(&mut self, token: Token) {
        self.app_domain.set_executing_assembly(token);
    }

    /// Sets the entry assembly.
    ///
    /// This is a convenience method that delegates to
    /// [`AppDomainState::set_entry_assembly`](super::AppDomainState::set_entry_assembly).
    ///
    /// # Arguments
    ///
    /// * `token` - The assembly token
    pub fn set_entry_assembly(&mut self, token: Token) {
        self.app_domain.set_entry_assembly(token);
    }
}

impl Default for RuntimeState {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for constructing [`RuntimeState`] with custom configuration.
///
/// The builder provides a fluent API for configuring all aspects of the
/// runtime state before construction. This is the recommended way to create
/// a runtime with non-default settings.
///
/// # Examples
///
/// ## Basic Usage
///
/// ```ignore
/// use dotscope::emulation::runtime::RuntimeStateBuilder;
/// use dotscope::emulation::process::EmulationConfig;
///
/// let runtime = RuntimeStateBuilder::new()
///     .config(EmulationConfig::minimal())
///     .build();
/// ```
///
/// ## Adding Custom Hooks
///
/// ```ignore
/// use dotscope::emulation::runtime::{RuntimeStateBuilder, Hook, PreHookResult};
///
/// let runtime = RuntimeStateBuilder::new()
///     .hook(Hook::new("my-hook")
///         .match_method_name("Decrypt")
///         .pre(|ctx, thread| PreHookResult::Continue))
///     .build();
/// ```
///
/// ## Disabling Defaults
///
/// ```ignore
/// use dotscope::emulation::runtime::RuntimeStateBuilder;
///
/// // Start with no default hooks
/// let runtime = RuntimeStateBuilder::new()
///     .no_defaults()
///     .hook(my_hook)
///     .build();
///
/// // Only custom hooks are registered
/// ```
pub struct RuntimeStateBuilder {
    /// The emulation configuration.
    config: EmulationConfig,
    /// Hooks to register after construction.
    hooks: Vec<Hook>,
    /// Whether to register default hooks.
    register_defaults: bool,
    /// Behavior for unknown methods.
    unknown_method_behavior: UnknownMethodBehavior,
}

impl RuntimeStateBuilder {
    /// Creates a new builder with default configuration.
    ///
    /// By default, the builder will:
    /// - Use [`EmulationConfig::default()`]
    /// - Register default BCL hooks and P/Invoke stubs
    ///
    /// Use [`no_defaults()`](Self::no_defaults) to disable default registration.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use dotscope::emulation::runtime::RuntimeStateBuilder;
    ///
    /// let builder = RuntimeStateBuilder::new();
    /// let runtime = builder.build();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: EmulationConfig::default(),
            hooks: Vec::new(),
            register_defaults: true,
            unknown_method_behavior: UnknownMethodBehavior::default(),
        }
    }

    /// Sets the emulation configuration.
    ///
    /// # Arguments
    ///
    /// * `config` - The configuration to use
    ///
    /// # Returns
    ///
    /// The builder for chaining.
    #[must_use]
    pub fn config(mut self, config: EmulationConfig) -> Self {
        self.config = config;
        self
    }

    /// Adds a method hook for interception.
    ///
    /// Hooks are checked in priority order and can bypass or monitor method calls.
    ///
    /// # Arguments
    ///
    /// * `hook` - The hook to add
    ///
    /// # Returns
    ///
    /// The builder for chaining.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use dotscope::emulation::runtime::{RuntimeStateBuilder, Hook, PreHookResult};
    ///
    /// let runtime = RuntimeStateBuilder::new()
    ///     .hook(Hook::new("my-hook")
    ///         .match_method_name("Decrypt")
    ///         .pre(|ctx, thread| PreHookResult::Continue))
    ///     .build();
    /// ```
    #[must_use]
    pub fn hook(mut self, hook: Hook) -> Self {
        self.hooks.push(hook);
        self
    }

    /// Sets the behavior for unknown method calls.
    ///
    /// # Arguments
    ///
    /// * `behavior` - The behavior to use when no hook matches
    ///
    /// # Returns
    ///
    /// The builder for chaining.
    #[must_use]
    pub fn unknown_method_behavior(mut self, behavior: UnknownMethodBehavior) -> Self {
        self.unknown_method_behavior = behavior;
        self
    }

    /// Disables registration of default hooks.
    ///
    /// By default, the builder registers BCL hooks and P/Invoke stubs based on the
    /// configuration. Call this method to start with empty registries and
    /// register only custom hooks.
    ///
    /// # Returns
    ///
    /// The builder for chaining.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use dotscope::emulation::runtime::RuntimeStateBuilder;
    ///
    /// let runtime = RuntimeStateBuilder::new()
    ///     .no_defaults()
    ///     .hook(my_hook)
    ///     .build();
    ///
    /// // Only custom hooks are registered
    /// ```
    #[must_use]
    pub fn no_defaults(mut self) -> Self {
        self.register_defaults = false;
        self
    }

    /// Builds the [`RuntimeState`] with the configured options.
    ///
    /// This method:
    /// 1. Creates a `RuntimeState` with the configuration
    /// 2. Clears default hooks if [`no_defaults()`](Self::no_defaults) was called
    /// 3. Registers all custom hooks
    ///
    /// # Returns
    ///
    /// The constructed `RuntimeState`.
    #[must_use]
    pub fn build(self) -> RuntimeState {
        let mut hooks = HookManager::new();

        // Register defaults if enabled
        if self.register_defaults && self.config.stubs.bcl_stubs {
            bcl::register(&mut hooks);
        }

        // Register native P/Invoke hooks if enabled
        if self.register_defaults && self.config.stubs.pinvoke_stubs {
            native::register(&mut hooks);
        }

        // Add custom hooks
        for hook in self.hooks {
            hooks.register(hook);
        }

        RuntimeState {
            hooks,
            app_domain: AppDomainState::new(),
            unknown_method_behavior: self.unknown_method_behavior,
            config: Arc::new(self.config),
        }
    }
}

impl Default for RuntimeStateBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::emulation::runtime::{HookPriority, PreHookResult};

    #[test]
    fn test_runtime_state_creation() {
        let state = RuntimeState::new();
        assert!(!state.hooks().is_empty()); // Has default BCL hooks
    }

    #[test]
    fn test_runtime_state_with_config() {
        let config = EmulationConfig::minimal();
        let state = RuntimeState::with_config(Arc::new(config));

        // Minimal config has BCL stubs enabled
        assert!(!state.hooks().is_empty());
    }

    #[test]
    fn test_register_custom_hook() {
        let mut state = RuntimeState::new();
        let initial_count = state.hooks().len();

        state.register_hook(
            Hook::new("test-hook")
                .with_priority(HookPriority::HIGH)
                .match_name("Custom", "Type", "Method")
                .pre(|_ctx, _thread| PreHookResult::Continue),
        );

        assert_eq!(state.hooks().len(), initial_count + 1);
    }

    #[test]
    fn test_runtime_state_builder() {
        let state = RuntimeStateBuilder::new()
            .config(EmulationConfig::minimal())
            .hook(
                Hook::new("test-hook")
                    .match_method_name("Test")
                    .pre(|_ctx, _thread| PreHookResult::Continue),
            )
            .build();

        // Should have BCL hooks plus our custom hook
        assert!(!state.hooks().is_empty());
    }

    #[test]
    fn test_builder_no_defaults() {
        let state = RuntimeStateBuilder::new()
            .no_defaults()
            .hook(
                Hook::new("only-hook")
                    .match_method_name("Test")
                    .pre(|_ctx, _thread| PreHookResult::Continue),
            )
            .build();

        // Only our custom hook
        assert_eq!(state.hooks().len(), 1);
    }

    #[test]
    fn test_unknown_method_behavior() {
        let mut state = RuntimeState::new();
        assert_eq!(
            state.unknown_method_behavior(),
            UnknownMethodBehavior::Emulate
        );

        state.set_unknown_method_behavior(UnknownMethodBehavior::Fail);
        assert_eq!(state.unknown_method_behavior(), UnknownMethodBehavior::Fail);
    }

    #[test]
    fn test_app_domain_integration() {
        let mut state = RuntimeState::new();

        state.set_executing_assembly(Token::new(0x20000001));
        state.set_entry_assembly(Token::new(0x20000002));

        assert_eq!(
            state.app_domain().executing_assembly(),
            Some(Token::new(0x20000001))
        );
        assert_eq!(
            state.app_domain().entry_assembly(),
            Some(Token::new(0x20000002))
        );
    }

    #[test]
    fn test_native_hooks() {
        let config = EmulationConfig {
            stubs: crate::emulation::process::StubConfig {
                pinvoke_stubs: true,
                bcl_stubs: false, // Only native hooks
                ..Default::default()
            },
            ..Default::default()
        };

        let state = RuntimeState::with_config(Arc::new(config));

        // Should have native hooks registered (at least 12)
        assert!(state.hooks().len() >= 12);
    }
}
