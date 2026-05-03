//! `System.Collections` namespace BCL method hooks.
//!
//! This module provides hook implementations for .NET collection types commonly
//! used in obfuscated assemblies for storing intermediate decryption state, building
//! lookup tables, and managing dynamic dispatch targets.
//!
//! # Organization
//!
//! | Module | .NET Type(s) | Description |
//! |--------|-------------|-------------|
//! | [`dictionary`] | `System.Collections.Generic.Dictionary<TKey, TValue>` | Key-value pair storage |
//! | [`generic`] | `System.Collections.Generic.Stack<T>`, `Queue<T>`, `HashSet<T>` | Generic collection types |
//! | [`list`] | `System.Collections.Generic.List<T>` | Dynamic list operations |
//!
//! # Deobfuscation Relevance
//!
//! Collections are used extensively by obfuscators for:
//! - **Dictionary**: Token-to-method mappings, string decryption caches, delegate lookup tables
//! - **List**: Accumulating decrypted values, building method parameter arrays
//! - **Stack/Queue**: Control flow flattening state machines, deferred execution queues
//! - **HashSet**: Tracking visited nodes in anti-tamper graph traversals

mod dictionary;
mod generic;
mod list;

use crate::{
    emulation::{
        memory::DictionaryKey,
        runtime::hook::{Hook, HookContext, HookManager, PreHookResult},
        thread::EmulationThread,
        EmValue,
    },
    Result,
};

/// Registers all `System.Collections` namespace hooks with the given hook manager.
///
/// Delegates to each submodule's `register()` function to install hooks for
/// `Dictionary<TKey, TValue>`, `List<T>`, `Stack<T>`, `Queue<T>`, and `HashSet<T>`,
/// plus non-generic `IEnumerator` and `ReadOnlyCollectionBase` hooks.
///
/// # Arguments
///
/// * `manager` - The [`HookManager`] to register hooks with
pub fn register(manager: &HookManager) -> Result<()> {
    dictionary::register(manager)?;
    generic::register(manager)?;
    list::register(manager)?;

    // Non-generic IEnumerator hooks (used by ReadOnlyCollectionBase, Hashtable, etc.)
    manager.register(
        Hook::new("System.Collections.IEnumerator.MoveNext")
            .match_name("System.Collections", "IEnumerator", "MoveNext")
            .pre(ienumerator_move_next_pre),
    )?;

    manager.register(
        Hook::new("System.Collections.IEnumerator.get_Current")
            .match_name("System.Collections", "IEnumerator", "get_Current")
            .pre(ienumerator_get_current_pre),
    )?;

    manager.register(
        Hook::new("System.Collections.IEnumerator.Reset")
            .match_name("System.Collections", "IEnumerator", "Reset")
            .pre(ienumerator_reset_pre),
    )?;

    manager.register(
        Hook::new("System.Collections.ReadOnlyCollectionBase.GetEnumerator")
            .match_name(
                "System.Collections",
                "ReadOnlyCollectionBase",
                "GetEnumerator",
            )
            .pre(collection_get_enumerator_pre),
    )?;

    manager.register(
        Hook::new("System.Collections.Hashtable..ctor")
            .match_name("System.Collections", "Hashtable", ".ctor")
            .pre(hashtable_ctor_pre),
    )?;

    manager.register(
        Hook::new("System.Collections.Hashtable.Add")
            .match_name("System.Collections", "Hashtable", "Add")
            .pre(hashtable_add_pre),
    )?;

    manager.register(
        Hook::new("System.Collections.Hashtable.ContainsKey")
            .match_name("System.Collections", "Hashtable", "ContainsKey")
            .pre(hashtable_contains_key_pre),
    )?;

    manager.register(
        Hook::new("System.Collections.Hashtable.Contains")
            .match_name("System.Collections", "Hashtable", "Contains")
            .pre(hashtable_contains_key_pre),
    )?;

    manager.register(
        Hook::new("System.Collections.Hashtable.get_Item")
            .match_name("System.Collections", "Hashtable", "get_Item")
            .pre(hashtable_get_item_pre),
    )?;

    manager.register(
        Hook::new("System.Collections.Hashtable.set_Item")
            .match_name("System.Collections", "Hashtable", "set_Item")
            .pre(hashtable_set_item_pre),
    )?;

    manager.register(
        Hook::new("System.Collections.Hashtable.get_Count")
            .match_name("System.Collections", "Hashtable", "get_Count")
            .pre(hashtable_get_count_pre),
    )?;

    Ok(())
}

/// Hook for `IEnumerator.MoveNext()`.
///
/// Returns `false` to indicate no more elements. This is a safe default
/// for enumerators that the emulator cannot fully simulate — it causes
/// `foreach` loops to exit immediately.
fn ienumerator_move_next_pre(
    _ctx: &HookContext<'_>,
    _thread: &mut EmulationThread,
) -> PreHookResult {
    PreHookResult::Bypass(Some(EmValue::I32(0))) // false
}

/// Hook for `IEnumerator.get_Current`.
///
/// Returns `null` since `MoveNext` always returns false.
fn ienumerator_get_current_pre(
    _ctx: &HookContext<'_>,
    _thread: &mut EmulationThread,
) -> PreHookResult {
    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Hook for `IEnumerator.Reset()`. No-op.
fn ienumerator_reset_pre(_ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    PreHookResult::Bypass(None)
}

/// Hook for `ReadOnlyCollectionBase.GetEnumerator()`.
///
/// Returns an empty enumerator object. Combined with `IEnumerator.MoveNext`
/// returning false, this causes any iteration to exit after zero elements.
/// We allocate a real object rather than returning null so that null checks
/// in caller code work correctly.
fn collection_get_enumerator_pre(
    _ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    match thread
        .heap_mut()
        .alloc_object(crate::emulation::tokens::collections::ENUMERATOR)
    {
        Ok(obj_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(obj_ref))),
        Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

/// Hook for `Hashtable..ctor()`.
///
/// Replaces the generic `Object` allocated by `newobj` with a `Dictionary`
/// heap object, enabling real key-value storage.
fn hashtable_ctor_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(this_ref)) = ctx.this {
        let _ = thread.heap_mut().replace_with_dictionary(*this_ref);
    }
    PreHookResult::Bypass(None)
}

/// Hook for `Hashtable.Add(object, object)`.
///
/// Stores a key-value pair in the Dictionary-backed Hashtable.
/// Auto-upgrades the target to a Dictionary if the `.ctor` hook didn't fire
/// (e.g., when CFF obfuscation prevents the constructor call from being reached).
fn hashtable_add_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(this_ref)) = ctx.this {
        let key = ctx
            .args
            .first()
            .and_then(|v| DictionaryKey::from_emvalue(v, thread.heap()));
        let value = ctx.args.get(1).cloned();
        if let (Some(key), Some(value)) = (key, value) {
            // Auto-upgrade to Dictionary if the .ctor hook was skipped
            if !thread.heap().is_dictionary(*this_ref).unwrap_or(false) {
                let _ = thread.heap_mut().replace_with_dictionary(*this_ref);
            }
            let _ = thread.heap_mut().dictionary_set(*this_ref, key, value);
        }
    }
    PreHookResult::Bypass(None)
}

/// Hook for `Hashtable.ContainsKey(object)` / `Hashtable.Contains(object)`.
fn hashtable_contains_key_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    if let Some(EmValue::ObjectRef(this_ref)) = ctx.this {
        if let Some(key) = ctx
            .args
            .first()
            .and_then(|v| DictionaryKey::from_emvalue(v, thread.heap()))
        {
            if let Ok(Some(_)) = thread.heap().dictionary_get(*this_ref, &key) {
                return PreHookResult::Bypass(Some(EmValue::I32(1))); // true
            }
        }
    }
    PreHookResult::Bypass(Some(EmValue::I32(0))) // false
}

/// Hook for `Hashtable.get_Item(object)`.
fn hashtable_get_item_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(this_ref)) = ctx.this {
        if let Some(key) = ctx
            .args
            .first()
            .and_then(|v| DictionaryKey::from_emvalue(v, thread.heap()))
        {
            if let Ok(Some(value)) = thread.heap().dictionary_get(*this_ref, &key) {
                return PreHookResult::Bypass(Some(value));
            }
        }
    }
    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Hook for `Hashtable.set_Item(object, object)`.
fn hashtable_set_item_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(this_ref)) = ctx.this {
        let key = ctx
            .args
            .first()
            .and_then(|v| DictionaryKey::from_emvalue(v, thread.heap()));
        let value = ctx.args.get(1).cloned();
        if let (Some(key), Some(value)) = (key, value) {
            let _ = thread.heap_mut().dictionary_set(*this_ref, key, value);
        }
    }
    PreHookResult::Bypass(None)
}

/// Hook for `Hashtable.get_Count`.
fn hashtable_get_count_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(this_ref)) = ctx.this {
        if let Ok(count) = thread.heap().dictionary_count(*this_ref) {
            #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
            return PreHookResult::Bypass(Some(EmValue::I32(count as i32)));
        }
    }
    PreHookResult::Bypass(Some(EmValue::I32(0)))
}
