//! Collection type operations for the managed heap.
//!
//! This module provides Dictionary, List, Stack, Queue, and HashSet operations
//! on [`ManagedHeap`] objects. Each collection type is stored as a variant of
//! [`HeapObject`] and supports the standard .NET collection operations.

use std::collections::{HashMap, HashSet as StdHashSet, VecDeque};

use crate::{
    emulation::{
        engine::EmulationError,
        memory::heap::{DictionaryKey, HeapObject, ManagedHeap},
        EmValue, HeapRef,
    },
    Result,
};

impl ManagedHeap {
    /// Allocates a new empty Dictionary on the heap.
    ///
    /// # Errors
    ///
    /// Returns error if the heap memory limit is exceeded.
    pub fn alloc_dictionary(&self) -> Result<HeapRef> {
        self.alloc_object_internal(
            HeapObject::Dictionary {
                entries: HashMap::new(),
            },
            None,
        )
    }

    /// Adds a key-value pair to a Dictionary on the heap.
    ///
    /// Returns `true` if the entry was added, `false` if the key already existed
    /// (matching .NET `Dictionary.Add` semantics, though we don't throw).
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn dictionary_add(
        &self,
        heap_ref: HeapRef,
        key: DictionaryKey,
        value: EmValue,
    ) -> Result<bool> {
        let mut state = self
            .state
            .write()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        if let Some(HeapObject::Dictionary { entries }) = state.objects.get_mut(&heap_ref.id()) {
            if entries.contains_key(&key) {
                return Ok(false);
            }
            entries.insert(key, value);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Checks if a Dictionary contains the specified key.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn dictionary_contains_key(&self, heap_ref: HeapRef, key: &DictionaryKey) -> Result<bool> {
        let state = self
            .state
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        if let Some(HeapObject::Dictionary { entries }) = state.objects.get(&heap_ref.id()) {
            Ok(entries.contains_key(key))
        } else {
            Ok(false)
        }
    }

    /// Gets a value from a Dictionary by key.
    ///
    /// Returns `Ok(None)` if the key is not found or the reference is not a Dictionary.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn dictionary_get(
        &self,
        heap_ref: HeapRef,
        key: &DictionaryKey,
    ) -> Result<Option<EmValue>> {
        let state = self
            .state
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        if let Some(HeapObject::Dictionary { entries }) = state.objects.get(&heap_ref.id()) {
            Ok(entries.get(key).cloned())
        } else {
            Ok(None)
        }
    }

    /// Sets a key-value pair in a Dictionary (insert or update).
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn dictionary_set(
        &self,
        heap_ref: HeapRef,
        key: DictionaryKey,
        value: EmValue,
    ) -> Result<()> {
        let mut state = self
            .state
            .write()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        if let Some(HeapObject::Dictionary { entries }) = state.objects.get_mut(&heap_ref.id()) {
            entries.insert(key, value);
        }
        Ok(())
    }

    /// Removes a key from a Dictionary.
    ///
    /// Returns `true` if the key was removed, `false` if it wasn't found.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn dictionary_remove(&self, heap_ref: HeapRef, key: &DictionaryKey) -> Result<bool> {
        let mut state = self
            .state
            .write()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        if let Some(HeapObject::Dictionary { entries }) = state.objects.get_mut(&heap_ref.id()) {
            Ok(entries.remove(key).is_some())
        } else {
            Ok(false)
        }
    }

    /// Clears all entries from a Dictionary.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn dictionary_clear(&self, heap_ref: HeapRef) -> Result<()> {
        let mut state = self
            .state
            .write()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        if let Some(HeapObject::Dictionary { entries }) = state.objects.get_mut(&heap_ref.id()) {
            entries.clear();
        }
        Ok(())
    }

    /// Gets the number of entries in a Dictionary.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn dictionary_count(&self, heap_ref: HeapRef) -> Result<usize> {
        let state = self
            .state
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        if let Some(HeapObject::Dictionary { entries }) = state.objects.get(&heap_ref.id()) {
            Ok(entries.len())
        } else {
            Ok(0)
        }
    }

    /// Returns a clone of all keys in a Dictionary.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn dictionary_keys(&self, heap_ref: HeapRef) -> Result<Vec<DictionaryKey>> {
        let state = self
            .state
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        if let Some(HeapObject::Dictionary { entries }) = state.objects.get(&heap_ref.id()) {
            Ok(entries.keys().cloned().collect())
        } else {
            Ok(Vec::new())
        }
    }

    /// Returns a clone of all values in a Dictionary.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn dictionary_values(&self, heap_ref: HeapRef) -> Result<Vec<EmValue>> {
        let state = self
            .state
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        if let Some(HeapObject::Dictionary { entries }) = state.objects.get(&heap_ref.id()) {
            Ok(entries.values().cloned().collect())
        } else {
            Ok(Vec::new())
        }
    }

    /// Returns the key-value pair at the given index in a Dictionary's iteration order.
    ///
    /// Since `HashMap` does not guarantee stable ordering, the entries are iterated
    /// in whatever order the map provides. This is consistent with .NET's `Dictionary`
    /// which does not guarantee enumeration order.
    ///
    /// Returns `Ok(None)` if the index is out of bounds or the reference is not a Dictionary.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn dictionary_entry_at(
        &self,
        heap_ref: HeapRef,
        index: usize,
    ) -> Result<Option<(DictionaryKey, EmValue)>> {
        let state = self
            .state
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        if let Some(HeapObject::Dictionary { entries }) = state.objects.get(&heap_ref.id()) {
            Ok(entries
                .iter()
                .nth(index)
                .map(|(k, v)| (k.clone(), v.clone())))
        } else {
            Ok(None)
        }
    }

    /// Returns the number of elements in a collection (List or Dictionary).
    ///
    /// This is a convenience method for enumerator support that works across
    /// both collection types. Returns 0 if the reference is not a List or Dictionary.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn collection_count(&self, heap_ref: HeapRef) -> Result<usize> {
        let state = self
            .state
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        match state.objects.get(&heap_ref.id()) {
            Some(HeapObject::List { elements }) => Ok(elements.len()),
            Some(HeapObject::Dictionary { entries }) => Ok(entries.len()),
            _ => Ok(0),
        }
    }

    /// Returns `true` if the given heap reference points to a Dictionary.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn is_dictionary(&self, heap_ref: HeapRef) -> Result<bool> {
        let state = self
            .state
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        Ok(matches!(
            state.objects.get(&heap_ref.id()),
            Some(HeapObject::Dictionary { .. })
        ))
    }

    /// Replaces a heap object with an empty Dictionary.
    ///
    /// This is used by the Dictionary `.ctor` hook to convert the pre-allocated
    /// generic object into a functional `HeapObject::Dictionary`.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn replace_with_dictionary(&self, heap_ref: HeapRef) -> Result<()> {
        let mut state = self
            .state
            .write()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        let id = heap_ref.id();
        Self::preserve_original_type(&mut state, id);
        if state.objects.contains_key(&id) {
            state.objects.insert(
                id,
                HeapObject::Dictionary {
                    entries: HashMap::new(),
                },
            );
        }
        Ok(())
    }

    /// Replaces a heap object with an empty List.
    ///
    /// This is used by the `List<T>` `.ctor` hook to convert the pre-allocated
    /// generic object into a functional `HeapObject::List`.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn replace_with_list(&self, heap_ref: HeapRef) -> Result<()> {
        let mut state = self
            .state
            .write()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        let id = heap_ref.id();
        Self::preserve_original_type(&mut state, id);
        if state.objects.contains_key(&id) {
            state.objects.insert(
                id,
                HeapObject::List {
                    elements: Vec::new(),
                },
            );
        }
        Ok(())
    }

    /// Appends an element to a List.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn list_add(&self, heap_ref: HeapRef, value: EmValue) -> Result<()> {
        let mut state = self
            .state
            .write()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        if let Some(HeapObject::List { elements }) = state.objects.get_mut(&heap_ref.id()) {
            elements.push(value);
        }
        Ok(())
    }

    /// Gets an element from a List by index.
    ///
    /// Returns `Ok(None)` if the index is out of bounds or the reference is not a List.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn list_get(&self, heap_ref: HeapRef, index: usize) -> Result<Option<EmValue>> {
        let state = self
            .state
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        if let Some(HeapObject::List { elements }) = state.objects.get(&heap_ref.id()) {
            Ok(elements.get(index).cloned())
        } else {
            Ok(None)
        }
    }

    /// Sets an element in a List by index.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn list_set(&self, heap_ref: HeapRef, index: usize, value: EmValue) -> Result<()> {
        let mut state = self
            .state
            .write()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        if let Some(HeapObject::List { elements }) = state.objects.get_mut(&heap_ref.id()) {
            if index < elements.len() {
                elements[index] = value;
            }
        }
        Ok(())
    }

    /// Gets the number of elements in a List.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn list_count(&self, heap_ref: HeapRef) -> Result<usize> {
        let state = self
            .state
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        if let Some(HeapObject::List { elements }) = state.objects.get(&heap_ref.id()) {
            Ok(elements.len())
        } else {
            Ok(0)
        }
    }

    /// Inserts an element at the specified index in a List.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn list_insert(&self, heap_ref: HeapRef, index: usize, value: EmValue) -> Result<()> {
        let mut state = self
            .state
            .write()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        if let Some(HeapObject::List { elements }) = state.objects.get_mut(&heap_ref.id()) {
            if index <= elements.len() {
                elements.insert(index, value);
            }
        }
        Ok(())
    }

    /// Removes the element at the specified index from a List.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn list_remove_at(&self, heap_ref: HeapRef, index: usize) -> Result<()> {
        let mut state = self
            .state
            .write()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        if let Some(HeapObject::List { elements }) = state.objects.get_mut(&heap_ref.id()) {
            if index < elements.len() {
                elements.remove(index);
            }
        }
        Ok(())
    }

    /// Clears all elements from a List.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn list_clear(&self, heap_ref: HeapRef) -> Result<()> {
        let mut state = self
            .state
            .write()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        if let Some(HeapObject::List { elements }) = state.objects.get_mut(&heap_ref.id()) {
            elements.clear();
        }
        Ok(())
    }

    /// Removes the element at the given index from a List and returns it.
    ///
    /// Returns `Ok(None)` if the index is out of bounds or the reference is not a List.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn list_remove(&self, heap_ref: HeapRef, index: usize) -> Result<Option<EmValue>> {
        let mut state = self
            .state
            .write()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        if let Some(HeapObject::List { elements }) = state.objects.get_mut(&heap_ref.id()) {
            if index < elements.len() {
                return Ok(Some(elements.remove(index)));
            }
        }
        Ok(None)
    }

    /// Returns a clone of all elements in a List as a Vec.
    ///
    /// Used by `List<T>.ToArray()` to create an array from the list contents.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn list_to_vec(&self, heap_ref: HeapRef) -> Result<Vec<EmValue>> {
        let state = self
            .state
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        if let Some(HeapObject::List { elements }) = state.objects.get(&heap_ref.id()) {
            Ok(elements.clone())
        } else {
            Ok(Vec::new())
        }
    }

    /// Reverses the elements in a List in-place.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn list_reverse(&self, heap_ref: HeapRef) -> Result<()> {
        let mut state = self
            .state
            .write()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        if let Some(HeapObject::List { elements }) = state.objects.get_mut(&heap_ref.id()) {
            elements.reverse();
        }
        Ok(())
    }

    /// Allocates a new list pre-populated with elements.
    ///
    /// Used by `List.GetRange` to create a new sub-list.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::HeapMemoryLimitExceeded`] if heap is out of memory.
    pub fn alloc_list_with_elements(&self, elements: Vec<EmValue>) -> Result<HeapRef> {
        self.alloc_object_internal(HeapObject::List { elements }, None)
    }

    /// Replaces a heap object with an empty Stack.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn replace_with_stack(&self, heap_ref: HeapRef) -> Result<()> {
        let mut state = self
            .state
            .write()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        let id = heap_ref.id();
        Self::preserve_original_type(&mut state, id);
        if state.objects.contains_key(&id) {
            state.objects.insert(
                id,
                HeapObject::Stack {
                    elements: Vec::new(),
                },
            );
        }
        Ok(())
    }

    /// Pushes an element onto a Stack.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn stack_push(&self, heap_ref: HeapRef, value: EmValue) -> Result<()> {
        let mut state = self
            .state
            .write()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        if let Some(HeapObject::Stack { elements }) = state.objects.get_mut(&heap_ref.id()) {
            elements.push(value);
        }
        Ok(())
    }

    /// Pops an element from a Stack (LIFO).
    ///
    /// Returns `Ok(None)` if the stack is empty or the reference is not a Stack.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn stack_pop(&self, heap_ref: HeapRef) -> Result<Option<EmValue>> {
        let mut state = self
            .state
            .write()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        if let Some(HeapObject::Stack { elements }) = state.objects.get_mut(&heap_ref.id()) {
            Ok(elements.pop())
        } else {
            Ok(None)
        }
    }

    /// Peeks at the top element of a Stack without removing it.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn stack_peek(&self, heap_ref: HeapRef) -> Result<Option<EmValue>> {
        let state = self
            .state
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        if let Some(HeapObject::Stack { elements }) = state.objects.get(&heap_ref.id()) {
            Ok(elements.last().cloned())
        } else {
            Ok(None)
        }
    }

    /// Returns the number of elements in a Stack.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn stack_count(&self, heap_ref: HeapRef) -> Result<usize> {
        let state = self
            .state
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        if let Some(HeapObject::Stack { elements }) = state.objects.get(&heap_ref.id()) {
            Ok(elements.len())
        } else {
            Ok(0)
        }
    }

    /// Clears all elements from a Stack.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn stack_clear(&self, heap_ref: HeapRef) -> Result<()> {
        let mut state = self
            .state
            .write()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        if let Some(HeapObject::Stack { elements }) = state.objects.get_mut(&heap_ref.id()) {
            elements.clear();
        }
        Ok(())
    }

    /// Returns a clone of all elements in a Stack (top-first / LIFO order).
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn stack_to_vec(&self, heap_ref: HeapRef) -> Result<Vec<EmValue>> {
        let state = self
            .state
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        if let Some(HeapObject::Stack { elements }) = state.objects.get(&heap_ref.id()) {
            let mut result = elements.clone();
            result.reverse(); // LIFO order: last pushed = first in output
            Ok(result)
        } else {
            Ok(Vec::new())
        }
    }

    /// Replaces a heap object with an empty Queue.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn replace_with_queue(&self, heap_ref: HeapRef) -> Result<()> {
        let mut state = self
            .state
            .write()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        let id = heap_ref.id();
        Self::preserve_original_type(&mut state, id);
        if state.objects.contains_key(&id) {
            state.objects.insert(
                id,
                HeapObject::Queue {
                    elements: VecDeque::new(),
                },
            );
        }
        Ok(())
    }

    /// Enqueues an element to the back of a Queue.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn queue_enqueue(&self, heap_ref: HeapRef, value: EmValue) -> Result<()> {
        let mut state = self
            .state
            .write()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        if let Some(HeapObject::Queue { elements }) = state.objects.get_mut(&heap_ref.id()) {
            elements.push_back(value);
        }
        Ok(())
    }

    /// Dequeues an element from the front of a Queue (FIFO).
    ///
    /// Returns `Ok(None)` if the queue is empty or the reference is not a Queue.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn queue_dequeue(&self, heap_ref: HeapRef) -> Result<Option<EmValue>> {
        let mut state = self
            .state
            .write()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        if let Some(HeapObject::Queue { elements }) = state.objects.get_mut(&heap_ref.id()) {
            Ok(elements.pop_front())
        } else {
            Ok(None)
        }
    }

    /// Peeks at the front element of a Queue without removing it.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn queue_peek(&self, heap_ref: HeapRef) -> Result<Option<EmValue>> {
        let state = self
            .state
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        if let Some(HeapObject::Queue { elements }) = state.objects.get(&heap_ref.id()) {
            Ok(elements.front().cloned())
        } else {
            Ok(None)
        }
    }

    /// Returns the number of elements in a Queue.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn queue_count(&self, heap_ref: HeapRef) -> Result<usize> {
        let state = self
            .state
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        if let Some(HeapObject::Queue { elements }) = state.objects.get(&heap_ref.id()) {
            Ok(elements.len())
        } else {
            Ok(0)
        }
    }

    /// Clears all elements from a Queue.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn queue_clear(&self, heap_ref: HeapRef) -> Result<()> {
        let mut state = self
            .state
            .write()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        if let Some(HeapObject::Queue { elements }) = state.objects.get_mut(&heap_ref.id()) {
            elements.clear();
        }
        Ok(())
    }

    /// Returns a clone of all elements in a Queue (front-first / FIFO order).
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn queue_to_vec(&self, heap_ref: HeapRef) -> Result<Vec<EmValue>> {
        let state = self
            .state
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        if let Some(HeapObject::Queue { elements }) = state.objects.get(&heap_ref.id()) {
            Ok(elements.iter().cloned().collect())
        } else {
            Ok(Vec::new())
        }
    }

    /// Replaces a heap object with an empty HashSet.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn replace_with_hashset(&self, heap_ref: HeapRef) -> Result<()> {
        let mut state = self
            .state
            .write()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        let id = heap_ref.id();
        Self::preserve_original_type(&mut state, id);
        if state.objects.contains_key(&id) {
            state.objects.insert(
                id,
                HeapObject::HashSet {
                    elements: StdHashSet::new(),
                },
            );
        }
        Ok(())
    }

    /// Adds an element to a HashSet. Returns `true` if the element was newly added.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn hashset_add(&self, heap_ref: HeapRef, key: DictionaryKey) -> Result<bool> {
        let mut state = self
            .state
            .write()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        if let Some(HeapObject::HashSet { elements }) = state.objects.get_mut(&heap_ref.id()) {
            Ok(elements.insert(key))
        } else {
            Ok(false)
        }
    }

    /// Removes an element from a HashSet. Returns `true` if the element was removed.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn hashset_remove(&self, heap_ref: HeapRef, key: &DictionaryKey) -> Result<bool> {
        let mut state = self
            .state
            .write()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        if let Some(HeapObject::HashSet { elements }) = state.objects.get_mut(&heap_ref.id()) {
            Ok(elements.remove(key))
        } else {
            Ok(false)
        }
    }

    /// Checks if a HashSet contains the specified element.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn hashset_contains(&self, heap_ref: HeapRef, key: &DictionaryKey) -> Result<bool> {
        let state = self
            .state
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        if let Some(HeapObject::HashSet { elements }) = state.objects.get(&heap_ref.id()) {
            Ok(elements.contains(key))
        } else {
            Ok(false)
        }
    }

    /// Returns the number of elements in a HashSet.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn hashset_count(&self, heap_ref: HeapRef) -> Result<usize> {
        let state = self
            .state
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        if let Some(HeapObject::HashSet { elements }) = state.objects.get(&heap_ref.id()) {
            Ok(elements.len())
        } else {
            Ok(0)
        }
    }

    /// Clears all elements from a HashSet.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn hashset_clear(&self, heap_ref: HeapRef) -> Result<()> {
        let mut state = self
            .state
            .write()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        if let Some(HeapObject::HashSet { elements }) = state.objects.get_mut(&heap_ref.id()) {
            elements.clear();
        }
        Ok(())
    }
}
