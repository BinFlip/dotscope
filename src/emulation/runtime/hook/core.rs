//! Hook definition and builder.
//!
//! This module provides the [`Hook`] struct, which combines matchers and handlers
//! to intercept method calls during emulation.

use std::sync::Arc;

use crate::{
    emulation::{
        runtime::hook::{
            matcher::{
                HookMatcher, InternalMethodMatcher, NameMatcher, RuntimeMatcher, SignatureMatcher,
            },
            types::{
                HookContext, HookPriority, PostHookFn, PostHookResult, PreHookFn, PreHookResult,
            },
        },
        EmValue, EmulationThread,
    },
    metadata::typesystem::CilFlavor,
};

/// A configurable hook for method interception.
///
/// Hooks combine matchers (to determine which methods to intercept) with handlers
/// (to define what happens when intercepted). Use the builder pattern to configure
/// matchers and handlers.
///
/// # Building Hooks
///
/// Hooks are constructed using a fluent builder pattern:
///
/// ```rust,no_run
/// use dotscope::emulation::{Hook, PreHookResult, HookPriority};
///
/// let hook = Hook::new("my-hook")
///     .with_priority(HookPriority::HIGH)
///     .match_name("System", "String", "Concat")
///     .pre(|ctx, thread| {
///         println!("String.Concat called!");
///         PreHookResult::Continue
///     });
/// ```
///
/// # Matcher Evaluation
///
/// All matchers on a hook must match for the hook to be applied (AND semantics).
/// A hook with no matchers never matches (safety default).
///
/// # Pre vs Post Hooks
///
/// - **Pre-hooks** run before the original method. They can:
///   - Continue to let the original method run
///   - Bypass the original and return a value directly
///   - Report an error
///
/// - **Post-hooks** run after the original method. They can:
///   - Keep the original return value
///   - Replace the return value
///   - Report an error
///
/// # Examples
///
/// ## Logging Hook
///
/// ```rust,no_run
/// use dotscope::emulation::{Hook, PreHookResult, PostHookResult};
///
/// let hook = Hook::new("log-calls")
///     .match_method_name("Decrypt")
///     .pre(|ctx, thread| {
///         println!("Decrypt called with {} args", ctx.args.len());
///         PreHookResult::Continue
///     })
///     .post(|ctx, thread, result| {
///         println!("Decrypt returned: {:?}", result);
///         PostHookResult::Keep
///     });
/// ```
///
/// ## Bypass Hook
///
/// ```rust,no_run
/// use dotscope::emulation::{Hook, PreHookResult, EmValue};
///
/// let hook = Hook::new("bypass-anti-debug")
///     .match_name("System.Diagnostics", "Debugger", "get_IsAttached")
///     .pre(|ctx, thread| {
///         // Always return false to bypass anti-debugging
///         PreHookResult::Bypass(Some(EmValue::Bool(false)))
///     });
/// ```
pub struct Hook {
    name: String,
    priority: HookPriority,
    matchers: Vec<Box<dyn HookMatcher>>,
    pre_hook: Option<PreHookFn>,
    post_hook: Option<PostHookFn>,
}

impl Hook {
    /// Creates a new hook with the given name.
    ///
    /// The name is used for debugging and logging. It should be descriptive
    /// of what the hook does.
    ///
    /// # Arguments
    ///
    /// * `name` - A descriptive name for the hook
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::emulation::Hook;
    ///
    /// let hook = Hook::new("string-concat-interceptor");
    /// ```
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            priority: HookPriority::NORMAL,
            matchers: Vec::new(),
            pre_hook: None,
            post_hook: None,
        }
    }

    /// Returns the hook's name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the hook's priority.
    #[must_use]
    pub fn priority(&self) -> HookPriority {
        self.priority
    }

    /// Sets the hook's priority.
    ///
    /// Higher priority hooks are checked first. The default is
    /// [`HookPriority::NORMAL`].
    ///
    /// # Arguments
    ///
    /// * `priority` - The priority level
    #[must_use]
    pub fn with_priority(mut self, priority: HookPriority) -> Self {
        self.priority = priority;
        self
    }

    /// Adds a custom matcher.
    ///
    /// Custom matchers can implement any matching logic by implementing
    /// the [`HookMatcher`] trait.
    ///
    /// # Arguments
    ///
    /// * `matcher` - The matcher to add
    #[must_use]
    pub fn add_matcher<M: HookMatcher + 'static>(mut self, matcher: M) -> Self {
        self.matchers.push(Box::new(matcher));
        self
    }

    /// Adds a name-based matcher for namespace, type, and method.
    ///
    /// All three components must match exactly.
    ///
    /// # Arguments
    ///
    /// * `namespace` - The namespace to match
    /// * `type_name` - The type name to match
    /// * `method_name` - The method name to match
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::emulation::Hook;
    ///
    /// let hook = Hook::new("string-concat")
    ///     .match_name("System", "String", "Concat");
    /// ```
    #[must_use]
    pub fn match_name(
        self,
        namespace: impl Into<String>,
        type_name: impl Into<String>,
        method_name: impl Into<String>,
    ) -> Self {
        self.add_matcher(NameMatcher::full(namespace, type_name, method_name))
    }

    /// Adds a matcher for method name only.
    ///
    /// Matches any method with the given name, regardless of namespace or type.
    ///
    /// # Arguments
    ///
    /// * `method_name` - The method name to match
    #[must_use]
    pub fn match_method_name(self, method_name: impl Into<String>) -> Self {
        self.add_matcher(NameMatcher::new().method_name(method_name))
    }

    /// Adds a matcher for type name only.
    ///
    /// Matches any method on types with the given name, regardless of namespace.
    ///
    /// # Arguments
    ///
    /// * `type_name` - The type name to match
    #[must_use]
    pub fn match_type_name(self, type_name: impl Into<String>) -> Self {
        self.add_matcher(NameMatcher::new().type_name(type_name))
    }

    /// Adds a matcher that only matches internal methods (MethodDef).
    ///
    /// Internal methods are defined in the assembly being analyzed. This is
    /// useful for matching obfuscator-generated methods.
    #[must_use]
    pub fn match_internal_method(self) -> Self {
        self.add_matcher(InternalMethodMatcher)
    }

    /// Adds a matcher for P/Invoke (native) method calls.
    ///
    /// This matches calls to unmanaged code through P/Invoke. Both DLL name
    /// and function name must be specified for an exact match.
    ///
    /// # Arguments
    ///
    /// * `dll` - The DLL name (e.g., "kernel32" or "kernel32.dll")
    /// * `function` - The native function name (e.g., "VirtualProtect")
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::emulation::{Hook, PreHookResult, EmValue};
    ///
    /// let hook = Hook::new("virtual-protect-hook")
    ///     .match_native("kernel32", "VirtualProtect")
    ///     .pre(|ctx, thread| {
    ///         // Handle VirtualProtect call
    ///         PreHookResult::Bypass(Some(EmValue::I32(1)))
    ///     });
    /// ```
    #[must_use]
    pub fn match_native(self, dll: impl Into<String>, function: impl Into<String>) -> Self {
        self.add_matcher(super::matcher::NativeMethodMatcher::full(dll, function))
    }

    /// Adds a matcher for any P/Invoke call to a specific DLL.
    ///
    /// This matches all P/Invoke calls to the specified DLL, regardless of
    /// the function name.
    ///
    /// # Arguments
    ///
    /// * `dll` - The DLL name (e.g., "kernel32" or "kernel32.dll")
    #[must_use]
    pub fn match_native_dll(self, dll: impl Into<String>) -> Self {
        self.add_matcher(super::matcher::NativeMethodMatcher::new().dll(dll))
    }

    /// Adds a signature matcher for parameter and return types.
    ///
    /// # Arguments
    ///
    /// * `params` - The expected parameter types
    /// * `return_type` - The expected return type (or `None` for void/any)
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::emulation::Hook;
    /// use dotscope::metadata::typesystem::CilFlavor;
    ///
    /// // Match methods that take (int32, int32) and return int32
    /// let hook = Hook::new("int-transformer")
    ///     .match_signature(vec![CilFlavor::I4, CilFlavor::I4], Some(CilFlavor::I4));
    /// ```
    #[must_use]
    pub fn match_signature(self, params: Vec<CilFlavor>, return_type: Option<CilFlavor>) -> Self {
        let mut matcher = SignatureMatcher::new().params(params);
        if let Some(ret) = return_type {
            matcher = matcher.returns(ret);
        }
        self.add_matcher(matcher)
    }

    /// Adds a runtime matcher that inspects argument values.
    ///
    /// Runtime matchers are evaluated during method call interception and can
    /// inspect actual argument values to make matching decisions.
    ///
    /// # Arguments
    ///
    /// * `description` - Human-readable description for debugging
    /// * `predicate` - Function that returns `true` if the hook should match
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::emulation::{Hook, EmValue, HookContext, EmulationThread};
    ///
    /// let hook = Hook::new("lzma-detector")
    ///     .match_runtime("lzma-header", |ctx: &HookContext<'_>, thread: &EmulationThread| {
    ///         // Check if first arg is a byte[] starting with LZMA magic
    ///         if let Some(EmValue::ObjectRef(r)) = ctx.args.first() {
    ///             if let Some(bytes) = thread.heap().get_array_as_bytes(*r) {
    ///                 return bytes.len() >= 5 && bytes[0] == 0x5D;
    ///             }
    ///         }
    ///         false
    ///     });
    /// ```
    #[must_use]
    pub fn match_runtime<F>(self, description: impl Into<String>, predicate: F) -> Self
    where
        F: Fn(&HookContext<'_>, &EmulationThread) -> bool + Send + Sync + 'static,
    {
        self.add_matcher(RuntimeMatcher::new(description, predicate))
    }

    /// Sets the pre-hook handler.
    ///
    /// Pre-hooks run before the original method and can:
    /// - Continue to let the original method run
    /// - Bypass the original method and return a value directly
    /// - Report an error
    ///
    /// # Arguments
    ///
    /// * `handler` - The pre-hook handler function
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::emulation::{Hook, PreHookResult};
    ///
    /// let hook = Hook::new("log-and-continue")
    ///     .match_method_name("Decrypt")
    ///     .pre(|ctx, thread| {
    ///         println!("Decrypt called!");
    ///         PreHookResult::Continue
    ///     });
    /// ```
    #[must_use]
    pub fn pre<F>(mut self, handler: F) -> Self
    where
        F: Fn(&HookContext<'_>, &mut EmulationThread) -> PreHookResult + Send + Sync + 'static,
    {
        self.pre_hook = Some(Arc::new(handler));
        self
    }

    /// Sets the post-hook handler.
    ///
    /// Post-hooks run after the original method and can:
    /// - Keep the original result unchanged
    /// - Replace the result with a new value
    /// - Report an error
    ///
    /// # Arguments
    ///
    /// * `handler` - The post-hook handler function
    #[must_use]
    pub fn post<F>(mut self, handler: F) -> Self
    where
        F: Fn(&HookContext<'_>, &mut EmulationThread, Option<&EmValue>) -> PostHookResult
            + Send
            + Sync
            + 'static,
    {
        self.post_hook = Some(Arc::new(handler));
        self
    }

    /// Checks if all matchers match the given context.
    ///
    /// Returns `false` if the hook has no matchers (safety default).
    pub fn matches(&self, context: &HookContext<'_>, thread: &EmulationThread) -> bool {
        if self.matchers.is_empty() {
            return false;
        }
        self.matchers.iter().all(|m| m.matches(context, thread))
    }

    /// Executes the pre-hook if present.
    ///
    /// # Returns
    ///
    /// `Some(result)` if a pre-hook is registered, `None` otherwise.
    pub fn execute_pre(
        &self,
        context: &HookContext<'_>,
        thread: &mut EmulationThread,
    ) -> Option<PreHookResult> {
        self.pre_hook.as_ref().map(|hook| hook(context, thread))
    }

    /// Executes the post-hook if present.
    ///
    /// # Returns
    ///
    /// `Some(result)` if a post-hook is registered, `None` otherwise.
    pub fn execute_post(
        &self,
        context: &HookContext<'_>,
        thread: &mut EmulationThread,
        result: Option<&EmValue>,
    ) -> Option<PostHookResult> {
        self.post_hook
            .as_ref()
            .map(|hook| hook(context, thread, result))
    }

    /// Returns true if this hook has a pre-hook handler.
    #[must_use]
    pub fn has_pre_hook(&self) -> bool {
        self.pre_hook.is_some()
    }

    /// Returns true if this hook has a post-hook handler.
    #[must_use]
    pub fn has_post_hook(&self) -> bool {
        self.post_hook.is_some()
    }
}

impl std::fmt::Debug for Hook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hook")
            .field("name", &self.name)
            .field("priority", &self.priority)
            .field("matcher_count", &self.matchers.len())
            .field("has_pre_hook", &self.pre_hook.is_some())
            .field("has_post_hook", &self.post_hook.is_some())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hook_builder() {
        let hook = Hook::new("test-hook")
            .with_priority(HookPriority::HIGH)
            .match_name("System", "String", "Concat");

        assert_eq!(hook.name(), "test-hook");
        assert_eq!(hook.priority(), HookPriority::HIGH);
        assert!(!hook.has_pre_hook());
        assert!(!hook.has_post_hook());
    }

    #[test]
    fn test_hook_with_pre_handler() {
        let hook = Hook::new("test-hook")
            .match_method_name("Test")
            .pre(|_ctx, _thread| PreHookResult::Continue);

        assert!(hook.has_pre_hook());
        assert!(!hook.has_post_hook());
    }

    #[test]
    fn test_hook_with_post_handler() {
        let hook = Hook::new("test-hook")
            .match_method_name("Test")
            .post(|_ctx, _thread, _result| PostHookResult::Keep);

        assert!(!hook.has_pre_hook());
        assert!(hook.has_post_hook());
    }

    #[test]
    fn test_empty_matchers_dont_match() {
        let hook = Hook::new("empty");
        assert!(hook.matchers.is_empty());
    }
}
