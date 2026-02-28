//! `System.Threading.Monitor` method hooks.
//!
//! Provides lock tracking implementations for monitor operations. Single-threaded
//! emulation has no contention, so locks always succeed, but re-entrant counts
//! are tracked so that `Exit` can detect mismatched releases and `ref bool lockTaken`
//! out parameters are set correctly.
//!
//! # Emulated Methods
//!
//! | Method | Description |
//! |--------|-------------|
//! | `Monitor.Enter(object)` | Acquires lock, increments re-entrant count |
//! | `Monitor.Enter(object, ref bool)` | Acquires lock, sets lockTaken = true |
//! | `Monitor.Exit(object)` | Releases lock, decrements re-entrant count |
//! | `Monitor.TryEnter(...)` | Acquires lock (always succeeds in single-threaded) |
//! | `Monitor.Wait(...)` | Release + re-acquire lock, return true (single-threaded) |
//! | `Monitor.Pulse(object)` | No-op (no threads to wake) |
//! | `Monitor.PulseAll(object)` | No-op (no threads to wake) |

use log::debug;

use crate::emulation::{
    runtime::hook::{Hook, HookContext, HookManager, PreHookResult},
    thread::EmulationThread,
    EmValue,
};

/// Registers all Monitor method hooks with the given hook manager.
pub fn register(manager: &HookManager) {
    manager.register(
        Hook::new("System.Threading.Monitor.Enter")
            .match_name("System.Threading", "Monitor", "Enter")
            .pre(monitor_enter_pre),
    );

    manager.register(
        Hook::new("System.Threading.Monitor.Exit")
            .match_name("System.Threading", "Monitor", "Exit")
            .pre(monitor_exit_pre),
    );

    manager.register(
        Hook::new("System.Threading.Monitor.TryEnter")
            .match_name("System.Threading", "Monitor", "TryEnter")
            .pre(monitor_try_enter_pre),
    );

    manager.register(
        Hook::new("System.Threading.Monitor.Wait")
            .match_name("System.Threading", "Monitor", "Wait")
            .pre(monitor_wait_pre),
    );

    manager.register(
        Hook::new("System.Threading.Monitor.Pulse")
            .match_name("System.Threading", "Monitor", "Pulse")
            .pre(monitor_pulse_pre),
    );

    manager.register(
        Hook::new("System.Threading.Monitor.PulseAll")
            .match_name("System.Threading", "Monitor", "PulseAll")
            .pre(monitor_pulse_pre),
    );
}

/// Extracts the heap object ID from the lock object argument.
///
/// The first argument to all Monitor methods is the lock object. Returns
/// `Some(id)` for valid object references, `None` otherwise.
fn extract_lock_object_id(ctx: &HookContext<'_>) -> Option<u64> {
    ctx.args.first().and_then(|arg| match arg {
        EmValue::ObjectRef(href) => Some(href.id()),
        _ => None,
    })
}

/// Sets the `ref bool lockTaken` out parameter to `true`.
///
/// Scans the arguments for a `ManagedPtr` (the `ref bool` parameter) and
/// writes `I32(1)` through it. Called by both `Enter` and `TryEnter` overloads.
fn set_lock_taken(ctx: &HookContext<'_>, thread: &mut EmulationThread) {
    // The ref bool is always the last argument in Monitor overloads that have it
    if let Some(EmValue::ManagedPtr(ptr)) = ctx.args.last() {
        // Only treat it as lockTaken if there are at least 2 args (object + ref bool)
        if ctx.args.len() >= 2 {
            let _ = thread.store_through_pointer(ptr, EmValue::I32(1));
        }
    }
}

/// Hook for `Monitor.Enter(object)` and `Monitor.Enter(object, ref bool)`.
///
/// Acquires the monitor lock on the object and increments the re-entrant count.
/// For the 2-arg overload, writes `true` to the `ref bool lockTaken` parameter.
fn monitor_enter_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(obj_id) = extract_lock_object_id(ctx) {
        thread.address_space().monitor_enter(obj_id);
    }
    // Set lockTaken = true for the (object, ref bool) overload
    set_lock_taken(ctx, thread);
    PreHookResult::Bypass(None)
}

/// Hook for `Monitor.Exit(object)`.
///
/// Releases the monitor lock, decrementing the re-entrant count. Logs a
/// warning if Exit is called without a matching Enter (this would throw
/// `SynchronizationLockException` in a real runtime).
fn monitor_exit_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(obj_id) = extract_lock_object_id(ctx) {
        if !thread.address_space().monitor_exit(obj_id) {
            debug!(
                "Monitor.Exit: object {} was not locked (mismatched Enter/Exit)",
                obj_id
            );
        }
    }
    PreHookResult::Bypass(None)
}

/// Hook for `Monitor.TryEnter(...)` overloads.
///
/// All overloads acquire the lock (always succeeds in single-threaded emulation)
/// and return `true`. For overloads with `ref bool lockTaken`, writes `true`.
///
/// Overloads:
/// - `TryEnter(object) -> bool`
/// - `TryEnter(object, int) -> bool`
/// - `TryEnter(object, TimeSpan) -> bool`
/// - `TryEnter(object, ref bool)` (void, sets lockTaken)
/// - `TryEnter(object, int, ref bool)` (void, sets lockTaken)
/// - `TryEnter(object, TimeSpan, ref bool)` (void, sets lockTaken)
fn monitor_try_enter_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(obj_id) = extract_lock_object_id(ctx) {
        thread.address_space().monitor_enter(obj_id);
    }
    // Set lockTaken for overloads that have ref bool
    set_lock_taken(ctx, thread);
    // Return true for overloads that return bool; void overloads ignore the value
    PreHookResult::Bypass(Some(EmValue::I32(1)))
}

/// Hook for `Monitor.Wait(...)` overloads.
///
/// In single-threaded emulation there are no other threads to signal, so Wait
/// releases the lock and immediately re-acquires it, simulating an instant
/// signal. Returns `true` (signaled).
///
/// Overloads:
/// - `Wait(object) -> bool`
/// - `Wait(object, int) -> bool`
/// - `Wait(object, TimeSpan) -> bool`
/// - `Wait(object, int, bool) -> bool`
fn monitor_wait_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(obj_id) = extract_lock_object_id(ctx) {
        // Release and immediately re-acquire to simulate instant signal
        thread.address_space().monitor_exit(obj_id);
        thread.address_space().monitor_enter(obj_id);
    }
    // All overloads return bool — true means "signaled before timeout"
    PreHookResult::Bypass(Some(EmValue::I32(1)))
}

/// Hook for `Monitor.Pulse(object)` and `Monitor.PulseAll(object)`.
///
/// No-op in single-threaded emulation — there are no waiting threads to wake.
fn monitor_pulse_pre(_ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    PreHookResult::Bypass(None)
}

#[cfg(test)]
mod tests {
    use crate::emulation::runtime::{bcl::threading::register, hook::HookManager};

    #[test]
    fn test_register_hooks() {
        let manager = HookManager::new();
        register(&manager);
        assert_eq!(manager.len(), 6);
    }
}
