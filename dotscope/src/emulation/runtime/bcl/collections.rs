//! `System.Collections.Generic` Stack, Queue, and HashSet method hooks.
//!
//! This module provides hook implementations for `Stack<T>`, `Queue<T>`, and
//! `HashSet<T>` operations used by obfuscator initialization routines.
//!
//! # Emulated Types
//!
//! ## Stack&lt;T&gt; (LIFO)
//! | Method | Description |
//! |--------|-------------|
//! | `.ctor()` | Create empty stack |
//! | `Push(T)` | Push element |
//! | `Pop()` | Pop element |
//! | `Peek()` | Peek at top |
//! | `get_Count` | Get element count |
//! | `Contains(T)` | Check if element exists |
//! | `Clear()` | Remove all elements |
//! | `ToArray()` | Convert to array (LIFO order) |
//!
//! ## Queue&lt;T&gt; (FIFO)
//! | Method | Description |
//! |--------|-------------|
//! | `.ctor()` | Create empty queue |
//! | `Enqueue(T)` | Add to back |
//! | `Dequeue()` | Remove from front |
//! | `Peek()` | Peek at front |
//! | `get_Count` | Get element count |
//! | `Contains(T)` | Check if element exists |
//! | `Clear()` | Remove all elements |
//! | `ToArray()` | Convert to array (FIFO order) |
//!
//! ## HashSet&lt;T&gt;
//! | Method | Description |
//! |--------|-------------|
//! | `.ctor()` | Create empty set |
//! | `Add(T)` | Add element (returns bool) |
//! | `Remove(T)` | Remove element (returns bool) |
//! | `Contains(T)` | Check membership |
//! | `get_Count` | Get element count |
//! | `Clear()` | Remove all elements |
//! | `UnionWith(IEnumerable)` | Add all from collection |

use crate::emulation::{
    memory::{DictionaryKey, HeapObject},
    runtime::hook::{Hook, HookContext, HookManager, PreHookResult},
    thread::EmulationThread,
    EmValue,
};

/// Registers all Stack, Queue, and HashSet hooks with the given hook manager.
pub fn register(manager: &HookManager) {
    register_stack(manager);
    register_queue(manager);
    register_hashset(manager);
}

// ─── Stack<T> ──────────────────────────────────────────────────────────

fn register_stack(manager: &HookManager) {
    manager.register(
        Hook::new("System.Collections.Generic.Stack..ctor")
            .match_name("System.Collections.Generic", "Stack`1", ".ctor")
            .pre(stack_ctor_pre),
    );

    manager.register(
        Hook::new("System.Collections.Generic.Stack.Push")
            .match_name("System.Collections.Generic", "Stack`1", "Push")
            .pre(stack_push_pre),
    );

    manager.register(
        Hook::new("System.Collections.Generic.Stack.Pop")
            .match_name("System.Collections.Generic", "Stack`1", "Pop")
            .pre(stack_pop_pre),
    );

    manager.register(
        Hook::new("System.Collections.Generic.Stack.Peek")
            .match_name("System.Collections.Generic", "Stack`1", "Peek")
            .pre(stack_peek_pre),
    );

    manager.register(
        Hook::new("System.Collections.Generic.Stack.get_Count")
            .match_name("System.Collections.Generic", "Stack`1", "get_Count")
            .pre(stack_get_count_pre),
    );

    manager.register(
        Hook::new("System.Collections.Generic.Stack.Contains")
            .match_name("System.Collections.Generic", "Stack`1", "Contains")
            .pre(stack_contains_pre),
    );

    manager.register(
        Hook::new("System.Collections.Generic.Stack.Clear")
            .match_name("System.Collections.Generic", "Stack`1", "Clear")
            .pre(stack_clear_pre),
    );

    manager.register(
        Hook::new("System.Collections.Generic.Stack.ToArray")
            .match_name("System.Collections.Generic", "Stack`1", "ToArray")
            .pre(stack_to_array_pre),
    );
}

fn stack_ctor_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(stack_ref)) = ctx.this {
        thread.heap().replace_with_stack(*stack_ref);
    }
    PreHookResult::Bypass(None)
}

fn stack_push_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(stack_ref)) = ctx.this {
        let value = ctx.args.first().cloned().unwrap_or(EmValue::Null);
        thread.heap().stack_push(*stack_ref, value);
    }
    PreHookResult::Bypass(None)
}

fn stack_pop_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(stack_ref)) = ctx.this {
        if let Some(value) = thread.heap().stack_pop(*stack_ref) {
            return PreHookResult::Bypass(Some(value));
        }
    }
    PreHookResult::Error("InvalidOperationException: Stack empty".into())
}

fn stack_peek_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(stack_ref)) = ctx.this {
        if let Some(value) = thread.heap().stack_peek(*stack_ref) {
            return PreHookResult::Bypass(Some(value));
        }
    }
    PreHookResult::Error("InvalidOperationException: Stack empty".into())
}

fn stack_get_count_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(stack_ref)) = ctx.this {
        let count = thread.heap().stack_count(*stack_ref);
        #[allow(clippy::cast_possible_truncation)]
        return PreHookResult::Bypass(Some(EmValue::I32(count as i32)));
    }
    PreHookResult::Bypass(Some(EmValue::I32(0)))
}

fn stack_contains_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(stack_ref)) = ctx.this {
        if let Some(needle) = ctx.args.first() {
            if let Ok(HeapObject::Stack { elements }) = thread.heap().get(*stack_ref) {
                let found = elements.iter().any(|e| e.clr_equals(needle));
                return PreHookResult::Bypass(Some(EmValue::I32(i32::from(found))));
            }
        }
    }
    PreHookResult::Bypass(Some(EmValue::I32(0)))
}

fn stack_clear_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(stack_ref)) = ctx.this {
        thread.heap().stack_clear(*stack_ref);
    }
    PreHookResult::Bypass(None)
}

fn stack_to_array_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(stack_ref)) = ctx.this {
        let elements = thread.heap().stack_to_vec(*stack_ref);
        if let Ok(array_ref) = thread
            .heap()
            .alloc_array_with_values(crate::metadata::typesystem::CilFlavor::Object, elements)
        {
            return PreHookResult::Bypass(Some(EmValue::ObjectRef(array_ref)));
        }
    }
    PreHookResult::Bypass(Some(EmValue::Null))
}

// ─── Queue<T> ──────────────────────────────────────────────────────────

fn register_queue(manager: &HookManager) {
    manager.register(
        Hook::new("System.Collections.Generic.Queue..ctor")
            .match_name("System.Collections.Generic", "Queue`1", ".ctor")
            .pre(queue_ctor_pre),
    );

    manager.register(
        Hook::new("System.Collections.Generic.Queue.Enqueue")
            .match_name("System.Collections.Generic", "Queue`1", "Enqueue")
            .pre(queue_enqueue_pre),
    );

    manager.register(
        Hook::new("System.Collections.Generic.Queue.Dequeue")
            .match_name("System.Collections.Generic", "Queue`1", "Dequeue")
            .pre(queue_dequeue_pre),
    );

    manager.register(
        Hook::new("System.Collections.Generic.Queue.Peek")
            .match_name("System.Collections.Generic", "Queue`1", "Peek")
            .pre(queue_peek_pre),
    );

    manager.register(
        Hook::new("System.Collections.Generic.Queue.get_Count")
            .match_name("System.Collections.Generic", "Queue`1", "get_Count")
            .pre(queue_get_count_pre),
    );

    manager.register(
        Hook::new("System.Collections.Generic.Queue.Contains")
            .match_name("System.Collections.Generic", "Queue`1", "Contains")
            .pre(queue_contains_pre),
    );

    manager.register(
        Hook::new("System.Collections.Generic.Queue.Clear")
            .match_name("System.Collections.Generic", "Queue`1", "Clear")
            .pre(queue_clear_pre),
    );

    manager.register(
        Hook::new("System.Collections.Generic.Queue.ToArray")
            .match_name("System.Collections.Generic", "Queue`1", "ToArray")
            .pre(queue_to_array_pre),
    );
}

fn queue_ctor_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(queue_ref)) = ctx.this {
        thread.heap().replace_with_queue(*queue_ref);
    }
    PreHookResult::Bypass(None)
}

fn queue_enqueue_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(queue_ref)) = ctx.this {
        let value = ctx.args.first().cloned().unwrap_or(EmValue::Null);
        thread.heap().queue_enqueue(*queue_ref, value);
    }
    PreHookResult::Bypass(None)
}

fn queue_dequeue_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(queue_ref)) = ctx.this {
        if let Some(value) = thread.heap().queue_dequeue(*queue_ref) {
            return PreHookResult::Bypass(Some(value));
        }
    }
    PreHookResult::Error("InvalidOperationException: Queue empty".into())
}

fn queue_peek_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(queue_ref)) = ctx.this {
        if let Some(value) = thread.heap().queue_peek(*queue_ref) {
            return PreHookResult::Bypass(Some(value));
        }
    }
    PreHookResult::Error("InvalidOperationException: Queue empty".into())
}

fn queue_get_count_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(queue_ref)) = ctx.this {
        let count = thread.heap().queue_count(*queue_ref);
        #[allow(clippy::cast_possible_truncation)]
        return PreHookResult::Bypass(Some(EmValue::I32(count as i32)));
    }
    PreHookResult::Bypass(Some(EmValue::I32(0)))
}

fn queue_contains_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(queue_ref)) = ctx.this {
        if let Some(needle) = ctx.args.first() {
            if let Ok(HeapObject::Queue { elements }) = thread.heap().get(*queue_ref) {
                let found = elements.iter().any(|e| e.clr_equals(needle));
                return PreHookResult::Bypass(Some(EmValue::I32(i32::from(found))));
            }
        }
    }
    PreHookResult::Bypass(Some(EmValue::I32(0)))
}

fn queue_clear_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(queue_ref)) = ctx.this {
        thread.heap().queue_clear(*queue_ref);
    }
    PreHookResult::Bypass(None)
}

fn queue_to_array_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(queue_ref)) = ctx.this {
        let elements = thread.heap().queue_to_vec(*queue_ref);
        if let Ok(array_ref) = thread
            .heap()
            .alloc_array_with_values(crate::metadata::typesystem::CilFlavor::Object, elements)
        {
            return PreHookResult::Bypass(Some(EmValue::ObjectRef(array_ref)));
        }
    }
    PreHookResult::Bypass(Some(EmValue::Null))
}

// ─── HashSet<T> ────────────────────────────────────────────────────────

fn register_hashset(manager: &HookManager) {
    manager.register(
        Hook::new("System.Collections.Generic.HashSet..ctor")
            .match_name("System.Collections.Generic", "HashSet`1", ".ctor")
            .pre(hashset_ctor_pre),
    );

    manager.register(
        Hook::new("System.Collections.Generic.HashSet.Add")
            .match_name("System.Collections.Generic", "HashSet`1", "Add")
            .pre(hashset_add_pre),
    );

    manager.register(
        Hook::new("System.Collections.Generic.HashSet.Remove")
            .match_name("System.Collections.Generic", "HashSet`1", "Remove")
            .pre(hashset_remove_pre),
    );

    manager.register(
        Hook::new("System.Collections.Generic.HashSet.Contains")
            .match_name("System.Collections.Generic", "HashSet`1", "Contains")
            .pre(hashset_contains_pre),
    );

    manager.register(
        Hook::new("System.Collections.Generic.HashSet.get_Count")
            .match_name("System.Collections.Generic", "HashSet`1", "get_Count")
            .pre(hashset_get_count_pre),
    );

    manager.register(
        Hook::new("System.Collections.Generic.HashSet.Clear")
            .match_name("System.Collections.Generic", "HashSet`1", "Clear")
            .pre(hashset_clear_pre),
    );

    manager.register(
        Hook::new("System.Collections.Generic.HashSet.UnionWith")
            .match_name("System.Collections.Generic", "HashSet`1", "UnionWith")
            .pre(hashset_union_with_pre),
    );
}

fn hashset_ctor_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(set_ref)) = ctx.this {
        thread.heap().replace_with_hashset(*set_ref);
    }
    PreHookResult::Bypass(None)
}

fn hashset_add_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(set_ref)) = ctx.this {
        if let Some(key) = ctx
            .args
            .first()
            .and_then(|v| DictionaryKey::from_emvalue(v, thread.heap()))
        {
            let added = thread.heap().hashset_add(*set_ref, key);
            return PreHookResult::Bypass(Some(EmValue::I32(i32::from(added))));
        }
    }
    PreHookResult::Bypass(Some(EmValue::I32(0)))
}

fn hashset_remove_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(set_ref)) = ctx.this {
        if let Some(key) = ctx
            .args
            .first()
            .and_then(|v| DictionaryKey::from_emvalue(v, thread.heap()))
        {
            let removed = thread.heap().hashset_remove(*set_ref, &key);
            return PreHookResult::Bypass(Some(EmValue::I32(i32::from(removed))));
        }
    }
    PreHookResult::Bypass(Some(EmValue::I32(0)))
}

fn hashset_contains_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(set_ref)) = ctx.this {
        if let Some(key) = ctx
            .args
            .first()
            .and_then(|v| DictionaryKey::from_emvalue(v, thread.heap()))
        {
            let found = thread.heap().hashset_contains(*set_ref, &key);
            return PreHookResult::Bypass(Some(EmValue::I32(i32::from(found))));
        }
    }
    PreHookResult::Bypass(Some(EmValue::I32(0)))
}

fn hashset_get_count_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(set_ref)) = ctx.this {
        let count = thread.heap().hashset_count(*set_ref);
        #[allow(clippy::cast_possible_truncation)]
        return PreHookResult::Bypass(Some(EmValue::I32(count as i32)));
    }
    PreHookResult::Bypass(Some(EmValue::I32(0)))
}

fn hashset_clear_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(set_ref)) = ctx.this {
        thread.heap().hashset_clear(*set_ref);
    }
    PreHookResult::Bypass(None)
}

/// Hook for `HashSet.UnionWith(IEnumerable<T>)`.
///
/// Supports array and list sources. Other IEnumerable implementations are ignored.
fn hashset_union_with_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(set_ref)) = ctx.this {
        if let Some(EmValue::ObjectRef(source_ref)) = ctx.args.first() {
            if let Ok(source) = thread.heap().get(*source_ref) {
                let elements: Vec<EmValue> = match source {
                    HeapObject::Array { elements, .. } => elements,
                    HeapObject::List { elements } => elements,
                    _ => Vec::new(),
                };
                for elem in &elements {
                    if let Some(key) = DictionaryKey::from_emvalue(elem, thread.heap()) {
                        thread.heap().hashset_add(*set_ref, key);
                    }
                }
            }
        }
    }
    PreHookResult::Bypass(None)
}

#[cfg(test)]
mod tests {
    use crate::emulation::runtime::hook::HookManager;

    #[test]
    fn test_register_hooks() {
        let manager = HookManager::new();
        crate::emulation::runtime::bcl::collections::register(&manager);
        // Stack: 8 + Queue: 8 + HashSet: 7 = 23
        assert_eq!(manager.len(), 23);
    }
}
