//! Hook manager for registering and executing hooks.
//!
//! This module provides [`HookManager`], which maintains a collection of hooks
//! sorted by priority and provides methods for finding and executing matching hooks.

use crate::{
    emulation::{
        runtime::hook::{
            core::Hook,
            types::{HookContext, HookOutcome, PostHookResult, PreHookResult},
        },
        EmValue, EmulationError, EmulationThread,
    },
    Result,
};
use std::cmp::Reverse;

/// Manager for registering and executing hooks.
///
/// The `HookManager` maintains a collection of hooks sorted by priority (highest
/// first). When a method call is intercepted, the manager finds the first matching
/// hook and executes its handlers.
///
/// # Hook Resolution
///
/// When looking for a matching hook:
///
/// 1. Hooks are checked in priority order (highest first)
/// 2. The first hook whose matchers all match is selected
/// 3. Only one hook is executed per method call
///
/// # Examples
///
/// ```rust,ignore
/// use dotscope::emulation::{HookManager, Hook, HookPriority, PreHookResult, EmValue};
///
/// let mut manager = HookManager::new();
///
/// // Register hooks (order doesn't matter, they're sorted by priority)
/// manager.register(
///     Hook::new("low-priority")
///         .with_priority(HookPriority::LOW)
///         .match_method_name("Decrypt")
///         .pre(|ctx, thread| PreHookResult::Continue)
/// );
///
/// manager.register(
///     Hook::new("high-priority")
///         .with_priority(HookPriority::HIGH)
///         .match_method_name("Decrypt")
///         .pre(|ctx, thread| PreHookResult::Bypass(Some(EmValue::I32(42))))
/// );
///
/// // When "Decrypt" is called, "high-priority" matches first
/// ```
#[derive(Default)]
pub struct HookManager {
    hooks: Vec<Hook>,
}

impl HookManager {
    /// Creates a new, empty hook manager.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a hook.
    ///
    /// Hooks are automatically sorted by priority after insertion. Higher
    /// priority hooks are checked first when matching.
    ///
    /// # Arguments
    ///
    /// * `hook` - The hook to register
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let mut manager = HookManager::new();
    /// manager.register(Hook::new("my-hook").match_method_name("Test"));
    /// ```
    pub fn register(&mut self, hook: Hook) {
        self.hooks.push(hook);
        self.hooks.sort_by_key(|h| Reverse(h.priority()));
    }

    /// Finds the first matching hook for the given context.
    ///
    /// Hooks are checked in priority order (highest first). The first hook
    /// whose matchers all match is returned.
    ///
    /// # Arguments
    ///
    /// * `context` - The hook context containing method call information
    /// * `thread` - The emulation thread for runtime data inspection
    ///
    /// # Returns
    ///
    /// The first matching hook, or `None` if no hook matches.
    #[must_use]
    pub fn find_matching<'a>(
        &'a self,
        context: &HookContext<'_>,
        thread: &EmulationThread,
    ) -> Option<&'a Hook> {
        self.hooks.iter().find(|h| h.matches(context, thread))
    }

    /// Executes a method call through the hook system.
    ///
    /// This is the primary entry point for hook execution. It handles the complete
    /// hook lifecycle:
    ///
    /// 1. Find a matching hook (by priority order)
    /// 2. Execute the pre-hook
    /// 3. If pre-hook returns `Continue`, execute the original method via callback
    /// 4. Execute the post-hook on the result
    /// 5. Return the final outcome
    ///
    /// # Arguments
    ///
    /// * `context` - The hook context containing method call information
    /// * `thread` - The emulation thread
    /// * `execute_original` - Callback to execute the original method. Only called
    ///   if a hook matches and returns `Continue`.
    ///
    /// # Returns
    ///
    /// * `Ok(HookOutcome::NoMatch)` - No hook matched; caller should execute normally
    /// * `Ok(HookOutcome::Handled(value))` - Hook handled the call; use this result
    /// * `Err(...)` - Hook execution failed
    ///
    /// # Errors
    ///
    /// Returns an error if a pre-hook or post-hook returns `Error`.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::emulation::{HookContext, HookOutcome};
    ///
    /// let context = HookContext::new(
    ///     method_token,
    ///     "System", "String", "Concat",
    /// );
    ///
    /// let outcome = manager.execute(&context, &mut thread, |thread| {
    ///     // Execute the original method
    ///     Some(EmValue::String(...))
    /// })?;
    ///
    /// match outcome {
    ///     HookOutcome::NoMatch => { /* execute normally */ }
    ///     HookOutcome::Handled(value) => { /* use value */ }
    /// }
    /// ```
    pub fn execute<F>(
        &self,
        context: &HookContext<'_>,
        thread: &mut EmulationThread,
        execute_original: F,
    ) -> Result<HookOutcome>
    where
        F: FnOnce(&mut EmulationThread) -> Option<EmValue>,
    {
        let Some(hook) = self.find_matching(context, thread) else {
            return Ok(HookOutcome::NoMatch);
        };

        let pre_result = hook.execute_pre(context, thread);

        match pre_result {
            Some(PreHookResult::Bypass(value)) => {
                return Ok(HookOutcome::Handled(value));
            }
            Some(PreHookResult::Error(msg)) => {
                return Err(EmulationError::HookError(format!(
                    "Hook '{}' pre-hook error: {}",
                    hook.name(),
                    msg
                ))
                .into());
            }
            Some(PreHookResult::Continue) | None => {
                // Continue to original method execution
            }
        }

        let original_result = execute_original(thread);

        match hook.execute_post(context, thread, original_result.as_ref()) {
            Some(PostHookResult::Replace(new_value)) => Ok(HookOutcome::Handled(new_value)),
            Some(PostHookResult::Error(msg)) => Err(EmulationError::HookError(format!(
                "Hook '{}' post-hook error: {}",
                hook.name(),
                msg
            ))
            .into()),
            Some(PostHookResult::Keep) => Ok(HookOutcome::Handled(original_result)),
            None => {
                // No post-hook. If original_result is None (meaning execute_original didn't
                // actually execute the method), return NoMatch so the caller can try other
                // execution paths. This handles the case where a hook matches during the
                // matching phase but the pre-hook returns Continue and there's no post-hook.
                if original_result.is_none() {
                    Ok(HookOutcome::NoMatch)
                } else {
                    Ok(HookOutcome::Handled(original_result))
                }
            }
        }
    }

    /// Returns the number of registered hooks.
    #[must_use]
    pub fn len(&self) -> usize {
        self.hooks.len()
    }

    /// Returns `true` if no hooks are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.hooks.is_empty()
    }

    /// Returns an iterator over all registered hooks.
    ///
    /// Hooks are yielded in priority order (highest first).
    pub fn iter(&self) -> impl Iterator<Item = &Hook> {
        self.hooks.iter()
    }
}

impl std::fmt::Debug for HookManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HookManager")
            .field("hook_count", &self.hooks.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::emulation::HookPriority;
    use crate::metadata::token::Token;
    use crate::test::emulation::create_test_thread;

    #[test]
    fn test_hook_manager_empty() {
        let manager = HookManager::new();
        assert!(manager.is_empty());
        assert_eq!(manager.len(), 0);
    }

    #[test]
    fn test_hook_manager_registration() {
        let mut manager = HookManager::new();

        manager.register(Hook::new("hook1").match_method_name("Method1"));
        manager.register(Hook::new("hook2").match_method_name("Method2"));

        assert_eq!(manager.len(), 2);
        assert!(!manager.is_empty());
    }

    #[test]
    fn test_hook_manager_priority_sorting() {
        let mut manager = HookManager::new();

        manager.register(
            Hook::new("low")
                .with_priority(HookPriority::LOW)
                .match_method_name("Test"),
        );
        manager.register(
            Hook::new("high")
                .with_priority(HookPriority::HIGH)
                .match_method_name("Test"),
        );
        manager.register(
            Hook::new("normal")
                .with_priority(HookPriority::NORMAL)
                .match_method_name("Test"),
        );

        let names: Vec<_> = manager.iter().map(|h| h.name()).collect();
        assert_eq!(names, vec!["high", "normal", "low"]);
    }

    #[test]
    fn test_execute_no_match() {
        let manager = HookManager::new();
        let mut thread = create_test_thread();
        let context = HookContext::new(Token::new(0x06000001), "System", "String", "Concat");

        let outcome = manager
            .execute(&context, &mut thread, |_| Some(EmValue::I32(100)))
            .unwrap();

        assert!(matches!(outcome, HookOutcome::NoMatch));
    }

    #[test]
    fn test_execute_pre_hook_bypass() {
        let mut manager = HookManager::new();
        let mut thread = create_test_thread();

        // Register a hook that bypasses with a specific value
        manager.register(
            Hook::new("bypass-test")
                .match_name("System", "String", "Test")
                .pre(|_ctx, _thread| PreHookResult::Bypass(Some(EmValue::I32(42)))),
        );

        let context = HookContext::new(Token::new(0x06000001), "System", "String", "Test");
        let original_called = std::sync::atomic::AtomicBool::new(false);

        let outcome = manager
            .execute(&context, &mut thread, |_| {
                original_called.store(true, std::sync::atomic::Ordering::SeqCst);
                Some(EmValue::I32(999))
            })
            .unwrap();

        // Should bypass with 42, original not called
        assert!(matches!(
            outcome,
            HookOutcome::Handled(Some(EmValue::I32(42)))
        ));
        assert!(!original_called.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[test]
    fn test_execute_pre_hook_continue_then_post_hook() {
        let mut manager = HookManager::new();
        let mut thread = create_test_thread();

        // Register a hook that continues, then post-hook modifies the result
        manager.register(
            Hook::new("continue-then-modify")
                .match_name("System", "String", "Test")
                .pre(|_ctx, _thread| PreHookResult::Continue)
                .post(|_ctx, _thread, result| {
                    // Double the original value
                    if let Some(EmValue::I32(v)) = result {
                        PostHookResult::Replace(Some(EmValue::I32(v * 2)))
                    } else {
                        PostHookResult::Keep
                    }
                }),
        );

        let context = HookContext::new(Token::new(0x06000001), "System", "String", "Test");
        let outcome = manager
            .execute(
                &context,
                &mut thread,
                |_| Some(EmValue::I32(50)), // Original returns 50
            )
            .unwrap();

        // Post-hook should double it to 100
        assert!(matches!(
            outcome,
            HookOutcome::Handled(Some(EmValue::I32(100)))
        ));
    }

    #[test]
    fn test_execute_pre_hook_error() {
        let mut manager = HookManager::new();
        let mut thread = create_test_thread();

        manager.register(
            Hook::new("error-test")
                .match_name("System", "String", "Test")
                .pre(|_ctx, _thread| PreHookResult::Error("test error".to_string())),
        );

        let context = HookContext::new(Token::new(0x06000001), "System", "String", "Test");
        let result = manager.execute(&context, &mut thread, |_| Some(EmValue::I32(100)));

        // Should return an error, not an outcome
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("test error"));
    }

    #[test]
    fn test_execute_post_hook_keep() {
        let mut manager = HookManager::new();
        let mut thread = create_test_thread();

        // Post-hook that keeps the original result
        manager.register(
            Hook::new("post-keep")
                .match_name("System", "String", "Test")
                .pre(|_ctx, _thread| PreHookResult::Continue)
                .post(|_ctx, _thread, _result| PostHookResult::Keep),
        );

        let context = HookContext::new(Token::new(0x06000001), "System", "String", "Test");
        let outcome = manager
            .execute(&context, &mut thread, |_| Some(EmValue::I32(123)))
            .unwrap();

        assert!(matches!(
            outcome,
            HookOutcome::Handled(Some(EmValue::I32(123)))
        ));
    }

    #[test]
    fn test_execute_post_hook_error() {
        let mut manager = HookManager::new();
        let mut thread = create_test_thread();

        manager.register(
            Hook::new("post-error")
                .match_name("System", "String", "Test")
                .pre(|_ctx, _thread| PreHookResult::Continue)
                .post(|_ctx, _thread, _result| PostHookResult::Error("post error".to_string())),
        );

        let context = HookContext::new(Token::new(0x06000001), "System", "String", "Test");
        let result = manager.execute(&context, &mut thread, |_| Some(EmValue::I32(100)));

        // Should return an error, not an outcome
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("post error"));
    }
}
