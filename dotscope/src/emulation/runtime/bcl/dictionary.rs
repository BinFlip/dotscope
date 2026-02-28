//! `System.Collections.Generic.Dictionary` method hooks.
//!
//! This module provides hook implementations for `Dictionary<TKey, TValue>` operations
//! commonly used by obfuscator initialization routines that build lookup tables from
//! encrypted resource data.
//!
//! # Emulated Methods
//!
//! | Method | Description |
//! |--------|-------------|
//! | `Dictionary..ctor()` | Create empty dictionary |
//! | `Dictionary..ctor(int)` | Create dictionary with initial capacity |
//! | `Dictionary.Add(TKey, TValue)` | Add key-value pair |
//! | `Dictionary.ContainsKey(TKey)` | Check if key exists |
//! | `Dictionary.get_Item(TKey)` | Get value by key (indexer) |
//! | `Dictionary.set_Item(TKey, TValue)` | Set value by key (indexer) |
//! | `Dictionary.get_Count` | Get entry count |
//! | `Dictionary.TryGetValue(TKey, out TValue)` | Try to get value, store via out param |
//! | `Dictionary.Remove(TKey)` | Remove entry by key |
//! | `Dictionary.Clear()` | Remove all entries |
//! | `Dictionary.get_Keys` | Get collection of keys |
//! | `Dictionary.get_Values` | Get collection of values |
//! | `Dictionary.ContainsValue(TValue)` | Check if value exists |
//!
//! # Key Types
//!
//! Dictionary keys are stored as [`DictionaryKey`] which supports integers, strings,
//! booleans, chars, and object references. This covers the primary use cases:
//! `Dictionary<int, int>`, `Dictionary<string, object>`, etc.

use crate::emulation::{
    memory::DictionaryKey,
    runtime::hook::{Hook, HookContext, HookManager, PreHookResult},
    thread::EmulationThread,
    EmValue,
};

/// Registers all Dictionary method hooks with the given hook manager.
pub fn register(manager: &HookManager) {
    manager.register(
        Hook::new("System.Collections.Generic.Dictionary..ctor")
            .match_name("System.Collections.Generic", "Dictionary`2", ".ctor")
            .pre(dictionary_ctor_pre),
    );

    manager.register(
        Hook::new("System.Collections.Generic.Dictionary.Add")
            .match_name("System.Collections.Generic", "Dictionary`2", "Add")
            .pre(dictionary_add_pre),
    );

    manager.register(
        Hook::new("System.Collections.Generic.Dictionary.ContainsKey")
            .match_name("System.Collections.Generic", "Dictionary`2", "ContainsKey")
            .pre(dictionary_contains_key_pre),
    );

    manager.register(
        Hook::new("System.Collections.Generic.Dictionary.get_Item")
            .match_name("System.Collections.Generic", "Dictionary`2", "get_Item")
            .pre(dictionary_get_item_pre),
    );

    manager.register(
        Hook::new("System.Collections.Generic.Dictionary.set_Item")
            .match_name("System.Collections.Generic", "Dictionary`2", "set_Item")
            .pre(dictionary_set_item_pre),
    );

    manager.register(
        Hook::new("System.Collections.Generic.Dictionary.get_Count")
            .match_name("System.Collections.Generic", "Dictionary`2", "get_Count")
            .pre(dictionary_get_count_pre),
    );

    manager.register(
        Hook::new("System.Collections.Generic.Dictionary.TryGetValue")
            .match_name("System.Collections.Generic", "Dictionary`2", "TryGetValue")
            .pre(dictionary_try_get_value_pre),
    );

    manager.register(
        Hook::new("System.Collections.Generic.Dictionary.Remove")
            .match_name("System.Collections.Generic", "Dictionary`2", "Remove")
            .pre(dictionary_remove_pre),
    );

    manager.register(
        Hook::new("System.Collections.Generic.Dictionary.Clear")
            .match_name("System.Collections.Generic", "Dictionary`2", "Clear")
            .pre(dictionary_clear_pre),
    );

    manager.register(
        Hook::new("System.Collections.Generic.Dictionary.get_Keys")
            .match_name("System.Collections.Generic", "Dictionary`2", "get_Keys")
            .pre(dictionary_get_keys_pre),
    );

    manager.register(
        Hook::new("System.Collections.Generic.Dictionary.get_Values")
            .match_name("System.Collections.Generic", "Dictionary`2", "get_Values")
            .pre(dictionary_get_values_pre),
    );

    manager.register(
        Hook::new("System.Collections.Generic.Dictionary.ContainsValue")
            .match_name(
                "System.Collections.Generic",
                "Dictionary`2",
                "ContainsValue",
            )
            .pre(dictionary_contains_value_pre),
    );
}

/// Hook for `Dictionary..ctor()` and `Dictionary..ctor(int capacity)`.
fn dictionary_ctor_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(dict_ref)) = ctx.this {
        thread.heap().replace_with_dictionary(*dict_ref);
    }
    PreHookResult::Bypass(None)
}

/// Hook for `Dictionary.Add(TKey, TValue)`.
fn dictionary_add_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(dict_ref)) = ctx.this {
        if let Some(key) = ctx
            .args
            .first()
            .and_then(|v| DictionaryKey::from_emvalue(v, thread.heap()))
        {
            let value = ctx.args.get(1).cloned().unwrap_or(EmValue::Null);
            thread.heap().dictionary_add(*dict_ref, key, value);
        }
    }
    PreHookResult::Bypass(None)
}

/// Hook for `Dictionary.ContainsKey(TKey)`.
fn dictionary_contains_key_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    if let Some(EmValue::ObjectRef(dict_ref)) = ctx.this {
        if let Some(key) = ctx
            .args
            .first()
            .and_then(|v| DictionaryKey::from_emvalue(v, thread.heap()))
        {
            let found = thread.heap().dictionary_contains_key(*dict_ref, &key);
            return PreHookResult::Bypass(Some(EmValue::I32(i32::from(found))));
        }
    }
    PreHookResult::Bypass(Some(EmValue::I32(0)))
}

/// Hook for `Dictionary.get_Item(TKey)` — indexer getter.
fn dictionary_get_item_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(dict_ref)) = ctx.this {
        if let Some(key) = ctx
            .args
            .first()
            .and_then(|v| DictionaryKey::from_emvalue(v, thread.heap()))
        {
            if let Some(value) = thread.heap().dictionary_get(*dict_ref, &key) {
                return PreHookResult::Bypass(Some(value));
            }
        }
    }
    PreHookResult::Error(
        "KeyNotFoundException: The given key was not present in the dictionary".into(),
    )
}

/// Hook for `Dictionary.set_Item(TKey, TValue)` — indexer setter.
fn dictionary_set_item_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(dict_ref)) = ctx.this {
        if let Some(key) = ctx
            .args
            .first()
            .and_then(|v| DictionaryKey::from_emvalue(v, thread.heap()))
        {
            let value = ctx.args.get(1).cloned().unwrap_or(EmValue::Null);
            thread.heap().dictionary_set(*dict_ref, key, value);
        }
    }
    PreHookResult::Bypass(None)
}

/// Hook for `Dictionary.get_Count`.
fn dictionary_get_count_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(dict_ref)) = ctx.this {
        let count = thread.heap().dictionary_count(*dict_ref);
        #[allow(clippy::cast_possible_truncation)]
        return PreHookResult::Bypass(Some(EmValue::I32(count as i32)));
    }
    PreHookResult::Bypass(Some(EmValue::I32(0)))
}

/// Hook for `Dictionary.TryGetValue(TKey, out TValue)`.
///
/// Stores the found value through the out parameter pointer and returns
/// a boolean indicating whether the key was found.
fn dictionary_try_get_value_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    if let Some(EmValue::ObjectRef(dict_ref)) = ctx.this {
        if let Some(key) = ctx
            .args
            .first()
            .and_then(|v| DictionaryKey::from_emvalue(v, thread.heap()))
        {
            if let Some(value) = thread.heap().dictionary_get(*dict_ref, &key) {
                // Store value through the out parameter
                if let Some(ptr) = ctx.args.get(1).and_then(EmValue::as_managed_ptr) {
                    let _ = thread.store_through_pointer(ptr, value);
                }
                return PreHookResult::Bypass(Some(EmValue::I32(1)));
            }
        }
    }
    PreHookResult::Bypass(Some(EmValue::I32(0)))
}

/// Hook for `Dictionary.Remove(TKey)`.
fn dictionary_remove_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(dict_ref)) = ctx.this {
        if let Some(key) = ctx
            .args
            .first()
            .and_then(|v| DictionaryKey::from_emvalue(v, thread.heap()))
        {
            let removed = thread.heap().dictionary_remove(*dict_ref, &key);
            return PreHookResult::Bypass(Some(EmValue::I32(i32::from(removed))));
        }
    }
    PreHookResult::Bypass(Some(EmValue::I32(0)))
}

/// Hook for `Dictionary.Clear()`.
fn dictionary_clear_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(dict_ref)) = ctx.this {
        thread.heap().dictionary_clear(*dict_ref);
    }
    PreHookResult::Bypass(None)
}

/// Hook for `Dictionary.get_Keys`.
///
/// Returns the keys as an array allocated on the heap.
fn dictionary_get_keys_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(dict_ref)) = ctx.this {
        let keys = thread.heap().dictionary_keys(*dict_ref);
        let values: Vec<EmValue> = keys.iter().map(|k| k.to_emvalue(thread.heap())).collect();
        if let Ok(array_ref) = thread
            .heap()
            .alloc_array_with_values(crate::metadata::typesystem::CilFlavor::Object, values)
        {
            return PreHookResult::Bypass(Some(EmValue::ObjectRef(array_ref)));
        }
    }
    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Hook for `Dictionary.get_Values`.
///
/// Returns the values as an array allocated on the heap.
fn dictionary_get_values_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(dict_ref)) = ctx.this {
        let values = thread.heap().dictionary_values(*dict_ref);
        if let Ok(array_ref) = thread
            .heap()
            .alloc_array_with_values(crate::metadata::typesystem::CilFlavor::Object, values)
        {
            return PreHookResult::Bypass(Some(EmValue::ObjectRef(array_ref)));
        }
    }
    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Hook for `Dictionary.ContainsValue(TValue)`.
///
/// Linear scan over all values using [`EmValue::clr_equals`].
fn dictionary_contains_value_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    if let Some(EmValue::ObjectRef(dict_ref)) = ctx.this {
        if let Some(needle) = ctx.args.first() {
            let values = thread.heap().dictionary_values(*dict_ref);
            let found = values.iter().any(|v| v.clr_equals(needle));
            return PreHookResult::Bypass(Some(EmValue::I32(i32::from(found))));
        }
    }
    PreHookResult::Bypass(Some(EmValue::I32(0)))
}

#[cfg(test)]
mod tests {
    use crate::emulation::runtime::hook::HookManager;

    #[test]
    fn test_register_hooks() {
        let manager = HookManager::new();
        crate::emulation::runtime::bcl::dictionary::register(&manager);
        assert_eq!(manager.len(), 12);
    }
}
