//! `System.Collections.Generic.List<T>` method hooks.
//!
//! This module provides hook implementations for `List<T>` operations
//! commonly used by obfuscator initialization routines that build collections
//! of delegate proxies, field references, and other runtime data.
//!
//! # Emulated Methods
//!
//! | Method | Description |
//! |--------|-------------|
//! | `List..ctor()` | Create empty list |
//! | `List..ctor(int)` | Create list with initial capacity |
//! | `List.Add(T)` | Append element |
//! | `List.Insert(int, T)` | Insert element at index |
//! | `List.Remove(T)` | Remove first matching element |
//! | `List.RemoveAt(int)` | Remove element at index |
//! | `List.get_Item(int)` | Get element by index (indexer) |
//! | `List.set_Item(int, T)` | Set element by index (indexer) |
//! | `List.get_Count` | Get element count |
//! | `List.Contains(T)` | Check if element exists |
//! | `List.IndexOf(T)` | Find index of element |
//! | `List.Clear()` | Remove all elements |
//! | `List.ToArray()` | Convert to array |
//! | `List.Reverse()` | Reverse element order |
//! | `List.Sort()` | No-op (arbitrary comparison not supported) |
//! | `List.AddRange(IEnumerable)` | Append elements from array or list |
//! | `List.get_Capacity` | Get capacity (returns count) |
//! | `List.set_Capacity` | Set capacity (no-op) |
//! | `List.GetEnumerator()` | Get list enumerator |
//!
//! # Enumerator Support
//!
//! `GetEnumerator` returns a heap-allocated enumerator object that stores the
//! list reference and a position counter as fields. `MoveNext` advances the
//! position and `get_Current` returns the element at the current position.
//! Position starts at -1 (before the first element), matching .NET semantics
//! where `MoveNext()` must be called before accessing `Current`.
//!
//! # Equality Semantics
//!
//! `Contains`, `IndexOf`, and `Remove` use [`EmValue::clr_equals`] for element
//! comparison. This correctly handles primitive value types (I32, I64, etc.),
//! string value equality, and reference equality for heap objects. Complex
//! value types that override `Equals` are compared by reference only.

use crate::{
    emulation::{
        memory::HeapObject,
        runtime::hook::{Hook, HookContext, HookManager, PreHookResult},
        thread::EmulationThread,
        EmValue,
    },
    metadata::{token::Token, typesystem::CilFlavor},
};

/// Sentinel tokens for enumerator fields.
///
/// These use table 0x00 which is never used for real metadata tokens,
/// so they won't collide with actual field tokens from assemblies.
const ENUMERATOR_LIST_REF_FIELD: u32 = 0x0000_0001;
const ENUMERATOR_POSITION_FIELD: u32 = 0x0000_0002;

/// Placeholder type token for enumerator heap objects.
/// Uses table 0x7F which doesn't exist in ECMA-335 metadata.
const ENUMERATOR_TYPE_TOKEN: u32 = 0x7FFF_0001;

/// Registers all `List<T>` method hooks with the given hook manager.
pub fn register(manager: &HookManager) {
    // List constructors
    manager.register(
        Hook::new("System.Collections.Generic.List..ctor")
            .match_name("System.Collections.Generic", "List`1", ".ctor")
            .pre(list_ctor_pre),
    );

    // List.Add(T)
    manager.register(
        Hook::new("System.Collections.Generic.List.Add")
            .match_name("System.Collections.Generic", "List`1", "Add")
            .pre(list_add_pre),
    );

    // List.Insert(int, T)
    manager.register(
        Hook::new("System.Collections.Generic.List.Insert")
            .match_name("System.Collections.Generic", "List`1", "Insert")
            .pre(list_insert_pre),
    );

    // List.Remove(T)
    manager.register(
        Hook::new("System.Collections.Generic.List.Remove")
            .match_name("System.Collections.Generic", "List`1", "Remove")
            .pre(list_remove_pre),
    );

    // List.RemoveAt(int)
    manager.register(
        Hook::new("System.Collections.Generic.List.RemoveAt")
            .match_name("System.Collections.Generic", "List`1", "RemoveAt")
            .pre(list_remove_at_pre),
    );

    // List.get_Item(int) — indexer getter
    manager.register(
        Hook::new("System.Collections.Generic.List.get_Item")
            .match_name("System.Collections.Generic", "List`1", "get_Item")
            .pre(list_get_item_pre),
    );

    // List.set_Item(int, T) — indexer setter
    manager.register(
        Hook::new("System.Collections.Generic.List.set_Item")
            .match_name("System.Collections.Generic", "List`1", "set_Item")
            .pre(list_set_item_pre),
    );

    // List.get_Count
    manager.register(
        Hook::new("System.Collections.Generic.List.get_Count")
            .match_name("System.Collections.Generic", "List`1", "get_Count")
            .pre(list_get_count_pre),
    );

    // List.Contains(T)
    manager.register(
        Hook::new("System.Collections.Generic.List.Contains")
            .match_name("System.Collections.Generic", "List`1", "Contains")
            .pre(list_contains_pre),
    );

    // List.IndexOf(T)
    manager.register(
        Hook::new("System.Collections.Generic.List.IndexOf")
            .match_name("System.Collections.Generic", "List`1", "IndexOf")
            .pre(list_index_of_pre),
    );

    // List.Clear()
    manager.register(
        Hook::new("System.Collections.Generic.List.Clear")
            .match_name("System.Collections.Generic", "List`1", "Clear")
            .pre(list_clear_pre),
    );

    // List.ToArray()
    manager.register(
        Hook::new("System.Collections.Generic.List.ToArray")
            .match_name("System.Collections.Generic", "List`1", "ToArray")
            .pre(list_to_array_pre),
    );

    // List.Reverse()
    manager.register(
        Hook::new("System.Collections.Generic.List.Reverse")
            .match_name("System.Collections.Generic", "List`1", "Reverse")
            .pre(list_reverse_pre),
    );

    // List.Sort()
    manager.register(
        Hook::new("System.Collections.Generic.List.Sort")
            .match_name("System.Collections.Generic", "List`1", "Sort")
            .pre(list_sort_pre),
    );

    // List.AddRange(IEnumerable<T>)
    manager.register(
        Hook::new("System.Collections.Generic.List.AddRange")
            .match_name("System.Collections.Generic", "List`1", "AddRange")
            .pre(list_add_range_pre),
    );

    // List.get_Capacity
    manager.register(
        Hook::new("System.Collections.Generic.List.get_Capacity")
            .match_name("System.Collections.Generic", "List`1", "get_Capacity")
            .pre(list_get_capacity_pre),
    );

    // List.set_Capacity
    manager.register(
        Hook::new("System.Collections.Generic.List.set_Capacity")
            .match_name("System.Collections.Generic", "List`1", "set_Capacity")
            .pre(list_set_capacity_pre),
    );

    // List.GetEnumerator()
    manager.register(
        Hook::new("System.Collections.Generic.List.GetEnumerator")
            .match_name("System.Collections.Generic", "List`1", "GetEnumerator")
            .pre(list_get_enumerator_pre),
    );

    // List`1/Enumerator.MoveNext()
    manager.register(
        Hook::new("System.Collections.Generic.List.Enumerator.MoveNext")
            .match_name("System.Collections.Generic", "Enumerator", "MoveNext")
            .pre(enumerator_move_next_pre),
    );

    // List`1/Enumerator.get_Current
    manager.register(
        Hook::new("System.Collections.Generic.List.Enumerator.get_Current")
            .match_name("System.Collections.Generic", "Enumerator", "get_Current")
            .pre(enumerator_get_current_pre),
    );

    // List`1/Enumerator.Dispose()
    manager.register(
        Hook::new("System.Collections.Generic.List.Enumerator.Dispose")
            .match_name("System.Collections.Generic", "Enumerator", "Dispose")
            .pre(enumerator_dispose_pre),
    );

    // List.CopyTo(T[], int)
    manager.register(
        Hook::new("System.Collections.Generic.List.CopyTo")
            .match_name("System.Collections.Generic", "List`1", "CopyTo")
            .pre(list_copy_to_pre),
    );

    // List.GetRange(int, int)
    manager.register(
        Hook::new("System.Collections.Generic.List.GetRange")
            .match_name("System.Collections.Generic", "List`1", "GetRange")
            .pre(list_get_range_pre),
    );

    // List.AsReadOnly()
    manager.register(
        Hook::new("System.Collections.Generic.List.AsReadOnly")
            .match_name("System.Collections.Generic", "List`1", "AsReadOnly")
            .pre(list_as_read_only_pre),
    );
}

/// Hook for `List<T>..ctor()` and `List<T>..ctor(int capacity)`.
///
/// Replaces the pre-allocated generic object with a `HeapObject::List`.
/// The capacity argument (if present) is ignored since our backing `Vec`
/// grows dynamically.
fn list_ctor_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(list_ref)) = ctx.this {
        thread.heap().replace_with_list(*list_ref);
    }
    PreHookResult::Bypass(None)
}

/// Hook for `List<T>.Add(T item)`.
///
/// Appends the item to the end of the list.
fn list_add_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(list_ref)) = ctx.this {
        let value = ctx.args.first().cloned().unwrap_or(EmValue::Null);
        thread.heap().list_add(*list_ref, value);
    }
    PreHookResult::Bypass(None)
}

/// Hook for `List<T>.Insert(int index, T item)`.
///
/// Inserts the item at the specified index, shifting subsequent elements right.
fn list_insert_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(list_ref)) = ctx.this {
        if let Some(EmValue::I32(index)) = ctx.args.first() {
            let value = ctx.args.get(1).cloned().unwrap_or(EmValue::Null);
            #[allow(clippy::cast_sign_loss)]
            thread.heap().list_insert(*list_ref, *index as usize, value);
        }
    }
    PreHookResult::Bypass(None)
}

/// Hook for `List<T>.Remove(T item)`.
///
/// Removes the first occurrence of the specified element using [`EmValue::clr_equals`]
/// for comparison. Returns `true` (1) if an element was removed, `false` (0) otherwise.
fn list_remove_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(list_ref)) = ctx.this {
        if let Some(needle) = ctx.args.first() {
            // Find the index of the first matching element
            let elements = thread.heap().list_to_vec(*list_ref);
            for (i, elem) in elements.iter().enumerate() {
                if elem.clr_equals(needle) {
                    thread.heap().list_remove(*list_ref, i);
                    return PreHookResult::Bypass(Some(EmValue::I32(1)));
                }
            }
        }
    }
    PreHookResult::Bypass(Some(EmValue::I32(0)))
}

/// Hook for `List<T>.RemoveAt(int index)`.
///
/// Removes the element at the specified index, shifting subsequent elements left.
fn list_remove_at_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(list_ref)) = ctx.this {
        if let Some(EmValue::I32(index)) = ctx.args.first() {
            #[allow(clippy::cast_sign_loss)]
            thread.heap().list_remove_at(*list_ref, *index as usize);
        }
    }
    PreHookResult::Bypass(None)
}

/// Hook for `List<T>.get_Item(int index)` — indexer getter (`this[int]`).
///
/// Returns the element at the specified index. In .NET, accessing an invalid
/// index throws `ArgumentOutOfRangeException`; we return `Null` as a fallback.
fn list_get_item_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(list_ref)) = ctx.this {
        if let Some(EmValue::I32(index)) = ctx.args.first() {
            #[allow(clippy::cast_sign_loss)]
            if let Some(value) = thread.heap().list_get(*list_ref, *index as usize) {
                return PreHookResult::Bypass(Some(value));
            }
        }
    }
    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Hook for `List<T>.set_Item(int index, T value)` — indexer setter (`this[int] = value`).
///
/// Replaces the element at the specified index.
fn list_set_item_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(list_ref)) = ctx.this {
        if let Some(EmValue::I32(index)) = ctx.args.first() {
            let value = ctx.args.get(1).cloned().unwrap_or(EmValue::Null);
            #[allow(clippy::cast_sign_loss)]
            thread.heap().list_set(*list_ref, *index as usize, value);
        }
    }
    PreHookResult::Bypass(None)
}

/// Hook for `List<T>.get_Count`.
///
/// Returns the number of elements in the list.
fn list_get_count_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(list_ref)) = ctx.this {
        let count = thread.heap().list_count(*list_ref);
        #[allow(clippy::cast_possible_truncation)]
        return PreHookResult::Bypass(Some(EmValue::I32(count as i32)));
    }
    PreHookResult::Bypass(Some(EmValue::I32(0)))
}

/// Hook for `List<T>.Contains(T item)`.
///
/// Searches the list for an element equal to `item` using [`EmValue::clr_equals`].
/// Returns `true` (1) if found, `false` (0) otherwise.
fn list_contains_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(list_ref)) = ctx.this {
        if let Some(needle) = ctx.args.first() {
            let elements = thread.heap().list_to_vec(*list_ref);
            let found = elements.iter().any(|e| e.clr_equals(needle));
            return PreHookResult::Bypass(Some(EmValue::I32(i32::from(found))));
        }
    }
    PreHookResult::Bypass(Some(EmValue::I32(0)))
}

/// Hook for `List<T>.IndexOf(T item)`.
///
/// Returns the zero-based index of the first occurrence of `item` using
/// [`EmValue::clr_equals`], or -1 if not found.
fn list_index_of_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(list_ref)) = ctx.this {
        if let Some(needle) = ctx.args.first() {
            let elements = thread.heap().list_to_vec(*list_ref);
            for (i, elem) in elements.iter().enumerate() {
                if elem.clr_equals(needle) {
                    #[allow(clippy::cast_possible_truncation)]
                    return PreHookResult::Bypass(Some(EmValue::I32(i as i32)));
                }
            }
        }
    }
    PreHookResult::Bypass(Some(EmValue::I32(-1)))
}

/// Hook for `List<T>.Clear()`.
///
/// Removes all elements from the list, setting Count to 0.
fn list_clear_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(list_ref)) = ctx.this {
        thread.heap().list_clear(*list_ref);
    }
    PreHookResult::Bypass(None)
}

/// Hook for `List<T>.ToArray()`.
///
/// Creates a new array on the heap containing copies of all elements.
/// The element type is set to `Object` since we don't track the generic
/// type parameter at this level.
fn list_to_array_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(list_ref)) = ctx.this {
        let elements = thread.heap().list_to_vec(*list_ref);
        if let Ok(array_ref) = thread
            .heap()
            .alloc_array_with_values(CilFlavor::Object, elements)
        {
            return PreHookResult::Bypass(Some(EmValue::ObjectRef(array_ref)));
        }
    }
    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Hook for `List<T>.Reverse()`.
///
/// Reverses the order of all elements in the list in-place.
fn list_reverse_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(list_ref)) = ctx.this {
        thread.heap().list_reverse(*list_ref);
    }
    PreHookResult::Bypass(None)
}

/// Hook for `List<T>.Sort()`.
///
/// No-op — sorting requires an `IComparer<T>` or `Comparison<T>` delegate,
/// and comparing arbitrary `EmValue` types is not supported. Obfuscation
/// routines typically don't depend on sort order for correctness.
fn list_sort_pre(_ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    PreHookResult::Bypass(None)
}

/// Hook for `List<T>.AddRange(IEnumerable<T> collection)`.
///
/// Appends all elements from the source collection. Supports `HeapObject::Array`
/// and `HeapObject::List` as source types. Other `IEnumerable` implementations
/// are silently ignored (the list remains unchanged).
fn list_add_range_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(list_ref)) = ctx.this {
        if let Some(EmValue::ObjectRef(source_ref)) = ctx.args.first() {
            if let Ok(source_obj) = thread.heap().get(*source_ref) {
                let source_elements: Vec<EmValue> = match source_obj {
                    HeapObject::Array { elements, .. } => elements.clone(),
                    HeapObject::List { elements } => elements.clone(),
                    _ => Vec::new(),
                };
                for elem in source_elements {
                    thread.heap().list_add(*list_ref, elem);
                }
            }
        }
    }
    PreHookResult::Bypass(None)
}

/// Hook for `List<T>.get_Capacity`.
///
/// Returns the count as capacity since we don't track internal capacity
/// separately — our backing `Vec` grows as needed.
fn list_get_capacity_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(list_ref)) = ctx.this {
        let count = thread.heap().list_count(*list_ref);
        #[allow(clippy::cast_possible_truncation)]
        return PreHookResult::Bypass(Some(EmValue::I32(count as i32)));
    }
    PreHookResult::Bypass(Some(EmValue::I32(0)))
}

/// Hook for `List<T>.set_Capacity(int)`.
///
/// No-op — we don't manage internal array capacity. The backing `Vec` grows
/// dynamically as elements are added.
fn list_set_capacity_pre(_ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    PreHookResult::Bypass(None)
}

/// Hook for `List<T>.GetEnumerator()`.
///
/// Creates a heap-allocated enumerator object with two synthetic fields:
/// - Field `0x00000001`: `ObjectRef` to the source list
/// - Field `0x00000002`: `I32` position counter (starts at -1)
///
/// The enumerator follows .NET semantics: position starts before the first
/// element, and `MoveNext()` must be called to advance to each element.
fn list_get_enumerator_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(list_ref)) = ctx.this {
        let list_field = Token::new(ENUMERATOR_LIST_REF_FIELD);
        let pos_field = Token::new(ENUMERATOR_POSITION_FIELD);
        let type_token = Token::new(ENUMERATOR_TYPE_TOKEN);

        let fields = vec![(list_field, CilFlavor::Object), (pos_field, CilFlavor::I4)];

        if let Ok(enum_ref) = thread
            .heap_mut()
            .alloc_object_with_fields(type_token, &fields)
        {
            let _ = thread
                .heap()
                .set_field(enum_ref, list_field, EmValue::ObjectRef(*list_ref));
            let _ = thread
                .heap()
                .set_field(enum_ref, pos_field, EmValue::I32(-1));
            return PreHookResult::Bypass(Some(EmValue::ObjectRef(enum_ref)));
        }
    }
    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Hook for `List<T>.Enumerator.MoveNext()`.
///
/// Advances the enumerator position by one and returns `true` (1) if the new
/// position is valid (within bounds), or `false` (0) if past the end.
fn enumerator_move_next_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(enum_ref)) = ctx.this {
        let list_field = Token::new(ENUMERATOR_LIST_REF_FIELD);
        let pos_field = Token::new(ENUMERATOR_POSITION_FIELD);

        let list_href = thread.heap().get_field(*enum_ref, list_field).ok();
        let current_pos = thread.heap().get_field(*enum_ref, pos_field).ok();

        if let (Some(EmValue::ObjectRef(list_ref)), Some(EmValue::I32(pos))) =
            (list_href, current_pos)
        {
            let new_pos = pos + 1;
            let count = thread.heap().list_count(list_ref);

            let _ = thread
                .heap()
                .set_field(*enum_ref, pos_field, EmValue::I32(new_pos));

            #[allow(clippy::cast_sign_loss)]
            let has_next = (new_pos >= 0) && (new_pos as usize) < count;
            return PreHookResult::Bypass(Some(EmValue::I32(i32::from(has_next))));
        }
    }
    PreHookResult::Bypass(Some(EmValue::I32(0)))
}

/// Hook for `List<T>.Enumerator.get_Current`.
///
/// Returns the element at the enumerator's current position. Returns `Null`
/// if the position is invalid (before `MoveNext` or after end).
fn enumerator_get_current_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    if let Some(EmValue::ObjectRef(enum_ref)) = ctx.this {
        let list_field = Token::new(ENUMERATOR_LIST_REF_FIELD);
        let pos_field = Token::new(ENUMERATOR_POSITION_FIELD);

        let list_href = thread.heap().get_field(*enum_ref, list_field).ok();
        let current_pos = thread.heap().get_field(*enum_ref, pos_field).ok();

        if let (Some(EmValue::ObjectRef(list_ref)), Some(EmValue::I32(pos))) =
            (list_href, current_pos)
        {
            #[allow(clippy::cast_sign_loss)]
            if pos >= 0 {
                if let Some(value) = thread.heap().list_get(list_ref, pos as usize) {
                    return PreHookResult::Bypass(Some(value));
                }
            }
        }
    }
    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Hook for `List<T>.Enumerator.Dispose()`.
///
/// No-op — the enumerator is a managed heap object that will be reclaimed
/// when no longer referenced.
fn enumerator_dispose_pre(_ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    PreHookResult::Bypass(None)
}

/// Hook for `List<T>.CopyTo(T[] array, int arrayIndex)`.
///
/// Copies list elements into the target array starting at the given offset.
fn list_copy_to_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(list_ref)) = ctx.this {
        if let Some(EmValue::ObjectRef(arr_ref)) = ctx.args.first() {
            let offset = ctx
                .args
                .get(1)
                .and_then(EmValue::as_i32)
                .map_or(0, |v| v.max(0) as usize);
            let elements = thread.heap().list_to_vec(*list_ref);
            for (i, elem) in elements.into_iter().enumerate() {
                let _ = thread.heap().set_array_element(*arr_ref, offset + i, elem);
            }
        }
    }
    PreHookResult::Bypass(None)
}

/// Hook for `List<T>.GetRange(int index, int count)`.
///
/// Creates a new List containing a range of elements from the source list.
fn list_get_range_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(list_ref)) = ctx.this {
        if let (Some(EmValue::I32(start)), Some(EmValue::I32(count))) =
            (ctx.args.first(), ctx.args.get(1))
        {
            let elements = thread.heap().list_to_vec(*list_ref);
            let start_idx = (*start).max(0) as usize;
            let cnt = (*count).max(0) as usize;
            let end = (start_idx + cnt).min(elements.len());
            let sub = elements[start_idx.min(elements.len())..end].to_vec();
            if let Ok(new_list) = thread.heap().alloc_list_with_elements(sub) {
                return PreHookResult::Bypass(Some(EmValue::ObjectRef(new_list)));
            }
        }
    }
    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Hook for `List<T>.AsReadOnly()`.
///
/// Returns the same list reference (no immutability enforcement in emulation).
fn list_as_read_only_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(list_ref)) = ctx.this {
        return PreHookResult::Bypass(Some(EmValue::ObjectRef(*list_ref)));
    }
    PreHookResult::Bypass(Some(EmValue::Null))
}

#[cfg(test)]
mod tests {
    use crate::emulation::runtime::hook::HookManager;

    #[test]
    fn test_register_hooks() {
        let manager = HookManager::new();
        crate::emulation::runtime::bcl::list::register(&manager);
        assert_eq!(manager.len(), 24);
    }
}
