//! `System.Enum` method hooks.
//!
//! This module provides hook implementations for `Enum` operations commonly
//! used in obfuscated code for flag checking and string conversion.
//!
//! # Emulated Methods
//!
//! | Method | Description |
//! |--------|-------------|
//! | `Enum.HasFlag(Enum)` | Bitwise flag check |
//! | `Enum.ToString()` | Convert to integer string (name lookup not supported) |
//! | `Enum.IsDefined(Type, object)` | Always returns true (conservative) |
//! | `Enum.GetUnderlyingType(Type)` | Returns typeof(int) placeholder |
//!
//! # Limitations
//!
//! Full enum metadata lookup (name↔value mapping) requires walking the type's
//! static literal fields, which is not always available during emulation. The
//! implementation provides best-effort support focused on the numeric operations
//! that obfuscators rely on (HasFlag, bitwise ops).

use crate::emulation::{
    memory::HeapObject,
    runtime::hook::{Hook, HookContext, HookManager, PreHookResult},
    thread::EmulationThread,
    EmValue,
};

/// Registers all Enum method hooks with the given hook manager.
pub fn register(manager: &HookManager) {
    manager.register(
        Hook::new("System.Enum.HasFlag")
            .match_name("System", "Enum", "HasFlag")
            .pre(enum_has_flag_pre),
    );

    manager.register(
        Hook::new("System.Enum.ToString")
            .match_name("System", "Enum", "ToString")
            .pre(enum_to_string_pre),
    );

    manager.register(
        Hook::new("System.Enum.IsDefined")
            .match_name("System", "Enum", "IsDefined")
            .pre(enum_is_defined_pre),
    );

    manager.register(
        Hook::new("System.Enum.GetUnderlyingType")
            .match_name("System", "Enum", "GetUnderlyingType")
            .pre(enum_get_underlying_type_pre),
    );
}

/// Extracts the integer value from an enum-like value (boxed or direct).
fn enum_to_i64(value: &EmValue, thread: &EmulationThread) -> Option<i64> {
    match value {
        EmValue::I32(v) => Some(i64::from(*v)),
        EmValue::I64(v) => Some(*v),
        EmValue::NativeInt(v) => Some(*v),
        EmValue::NativeUInt(v) => Some(*v as i64),
        EmValue::ObjectRef(href) => {
            if let Ok(HeapObject::BoxedValue { value, .. }) = thread.heap().get(*href) {
                match *value {
                    EmValue::I32(v) => Some(i64::from(v)),
                    EmValue::I64(v) => Some(v),
                    _ => None,
                }
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Hook for `Enum.HasFlag(Enum flag)`.
///
/// Performs `(this & flag) == flag` on the underlying integer values.
fn enum_has_flag_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(this_val) = ctx.this {
        if let Some(flag_val) = ctx.args.first() {
            if let (Some(this_i), Some(flag_i)) =
                (enum_to_i64(this_val, thread), enum_to_i64(flag_val, thread))
            {
                let result = (this_i & flag_i) == flag_i;
                return PreHookResult::Bypass(Some(EmValue::I32(i32::from(result))));
            }
        }
    }
    PreHookResult::Bypass(Some(EmValue::I32(0)))
}

/// Hook for `Enum.ToString()`.
///
/// Converts the enum's underlying integer value to a string representation.
/// Full name lookup from metadata is not supported; returns the numeric string.
fn enum_to_string_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(this_val) = ctx.this {
        if let Some(int_val) = enum_to_i64(this_val, thread) {
            if let Ok(str_ref) = thread.heap().alloc_string(&int_val.to_string()) {
                return PreHookResult::Bypass(Some(EmValue::ObjectRef(str_ref)));
            }
        }
    }
    PreHookResult::Continue
}

/// Hook for `Enum.IsDefined(Type, object)`.
///
/// Conservative implementation: returns true. In practice, obfuscators rarely
/// depend on the exact result; they use this as a guard before casting.
fn enum_is_defined_pre(_ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    PreHookResult::Bypass(Some(EmValue::I32(1)))
}

/// Hook for `Enum.GetUnderlyingType(Type)`.
///
/// Returns a placeholder ReflectionType for `System.Int32` since most enums
/// have `int` as underlying type.
fn enum_get_underlying_type_pre(
    _ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    // Use a well-known placeholder token for System.Int32
    let type_token = crate::metadata::token::Token::new(0x0100_0001);
    if let Ok(href) = thread.heap().alloc_reflection_type(type_token) {
        return PreHookResult::Bypass(Some(EmValue::ObjectRef(href)));
    }
    PreHookResult::Bypass(Some(EmValue::Null))
}

#[cfg(test)]
mod tests {
    use crate::emulation::runtime::hook::HookManager;

    #[test]
    fn test_register_hooks() {
        let manager = HookManager::new();
        crate::emulation::runtime::bcl::enums::register(&manager);
        assert_eq!(manager.len(), 4);
    }
}
