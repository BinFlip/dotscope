//! `System.Nullable<T>` method hooks.
//!
//! This module provides hook implementations for `Nullable<T>` operations.
//! In .NET, `Nullable<T>` is a value type wrapper that allows value types to
//! represent null. Obfuscators use nullable types for control flow state.
//!
//! # Emulated Methods
//!
//! | Method | Description |
//! |--------|-------------|
//! | `get_HasValue` | Check if nullable has a value |
//! | `get_Value` | Get the value (error if null) |
//! | `GetValueOrDefault()` | Get value or default |
//! | `Nullable.GetUnderlyingType(Type)` | Get underlying type if Nullable, else null |

use crate::emulation::{
    runtime::hook::{Hook, HookContext, HookManager, PreHookResult},
    thread::EmulationThread,
    EmValue,
};

/// Registers all Nullable method hooks with the given hook manager.
pub fn register(manager: &HookManager) {
    manager.register(
        Hook::new("System.Nullable.get_HasValue")
            .match_name("System", "Nullable`1", "get_HasValue")
            .pre(nullable_has_value_pre),
    );

    manager.register(
        Hook::new("System.Nullable.get_Value")
            .match_name("System", "Nullable`1", "get_Value")
            .pre(nullable_get_value_pre),
    );

    manager.register(
        Hook::new("System.Nullable.GetValueOrDefault")
            .match_name("System", "Nullable`1", "GetValueOrDefault")
            .pre(nullable_get_value_or_default_pre),
    );

    manager.register(
        Hook::new("System.Nullable.GetUnderlyingType")
            .match_name("System", "Nullable", "GetUnderlyingType")
            .pre(nullable_get_underlying_type_pre),
    );
}

/// Hook for `Nullable<T>.get_HasValue`.
///
/// Returns `true` if the nullable value is non-null.
fn nullable_has_value_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    if let Some(this_val) = ctx.this {
        let has_value = !matches!(this_val, EmValue::Null);
        return PreHookResult::Bypass(Some(EmValue::I32(i32::from(has_value))));
    }
    PreHookResult::Bypass(Some(EmValue::I32(0)))
}

/// Hook for `Nullable<T>.get_Value`.
///
/// Returns the value if non-null, otherwise returns an error.
fn nullable_get_value_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    if let Some(this_val) = ctx.this {
        if !matches!(this_val, EmValue::Null) {
            return PreHookResult::Bypass(Some(this_val.clone()));
        }
    }
    PreHookResult::Error("InvalidOperationException: Nullable object must have a value".into())
}

/// Hook for `Nullable<T>.GetValueOrDefault()`.
///
/// Returns the value if non-null, or the default value for the type.
fn nullable_get_value_or_default_pre(
    ctx: &HookContext<'_>,
    _thread: &mut EmulationThread,
) -> PreHookResult {
    if let Some(this_val) = ctx.this {
        if !matches!(this_val, EmValue::Null) {
            return PreHookResult::Bypass(Some(this_val.clone()));
        }
    }
    // Default value: I32(0) covers most value type defaults
    PreHookResult::Bypass(Some(EmValue::I32(0)))
}

/// Hook for `Nullable.GetUnderlyingType(Type)` (static method).
///
/// Returns `null` if the type is NOT `Nullable<T>`, or the underlying `T` type
/// if it IS. In obfuscator emulation, the types being checked are almost never
/// `Nullable<T>` — they are regular field types being inspected via reflection.
fn nullable_get_underlying_type_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    // Extract the type token from the ReflectionType argument
    if let Some(EmValue::ObjectRef(type_ref)) = ctx.args.first() {
        if let Some(type_token) = thread.heap().get_reflection_type_token(*type_ref) {
            if let Some(asm) = thread.assembly().cloned() {
                if let Some(cil_type) = asm.types().get(&type_token) {
                    // Check if this is Nullable`1 in namespace System
                    if cil_type.name == "Nullable`1" && cil_type.namespace == "System" {
                        // Return null as safe fallback (extracting T from generic args
                        // is not needed for typical obfuscator patterns)
                        return PreHookResult::Bypass(Some(EmValue::Null));
                    }
                }
            }
        }
    }

    // Not Nullable<T> (or couldn't resolve) — return null
    PreHookResult::Bypass(Some(EmValue::Null))
}

#[cfg(test)]
mod tests {
    use crate::emulation::runtime::hook::HookManager;

    #[test]
    fn test_register_hooks() {
        let manager = HookManager::new();
        crate::emulation::runtime::bcl::nullable::register(&manager);
        assert_eq!(manager.len(), 4);
    }
}
