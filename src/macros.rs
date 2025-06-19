//! Utility macros for synchronization and threading.
//!
//! This module provides convenience macros for working with Rust's synchronization primitives
//! like [`std::sync::Mutex`], [`std::sync::RwLock`], and [`std::sync::Arc`]. These macros
//! simplify common patterns when working with shared data in concurrent contexts and are
//! primarily used internally by the metadata loading system.
//!
//! # Architecture
//!
//! The macros are organized into three categories:
//! - **Basic Locking**: Direct lock acquisition with panic handling (`lock!`, `read_lock!`, `write_lock!`)
//! - **Functional Style**: Execute closures with automatic lock management (`with_read!`, `with_write!`)
//! - **Collection Operations**: Specialized operations for working with collections of locked data (`map_get_read!`, `for_each_read!`)
//!
//! All macros follow a consistent pattern of automatic panic handling for lock poisoning,
//! treating poisoned locks as unrecoverable errors in the context of metadata analysis.
//!
//! # Key Components
//!
//! - `lock!` - Acquire a mutex lock with panic on failure
//! - `read_lock!` - Acquire a read lock on an `RwLock` with panic on failure
//! - `write_lock!` - Acquire a write lock on an `RwLock` with panic on failure
//! - `with_read!` - Execute a closure with a read lock
//! - `with_write!` - Execute a closure with a write lock
//! - `map_get_read!` - Get an item from a map and acquire a read lock
//! - `for_each_read!` - Iterate over a collection with read locks
//!
//! # Usage Examples
//!
//! ## Basic Locking
//!
//! ```rust,ignore
//! use std::sync::{Mutex, RwLock};
//!
//! let mutex_data = Mutex::new(42);
//! let mut data = lock!(mutex_data);
//! *data = 100;
//!
//! let rwlock_data = RwLock::new(String::from("hello"));
//! let reader = read_lock!(rwlock_data);
//! println!("Value: {}", *reader);
//! ```
//!
//! ## Functional Style
//!
//! ```rust,ignore
//! use std::sync::{Arc, RwLock};
//!
//! let shared_data = Arc::new(RwLock::new(vec![1, 2, 3]));
//!
//! // Execute closure with read access
//! let length = with_read!(shared_data, |vec| vec.len());
//!
//! // Execute closure with write access
//! with_write!(shared_data, |vec| vec.push(4));
//! ```
//!
//! # Error Handling
//!
//! All macros in this module use panic-based error handling for lock poisoning:
//! - **Lock Poisoning**: When a thread panics while holding a lock, all macros will panic with descriptive messages
//! - **Timeout**: No timeout handling is provided; locks are acquired with indefinite blocking
//!
//! This design is appropriate for the metadata loading context where lock poisoning indicates
//! an unrecoverable error in the parsing process.
//!
//! # Thread Safety
//!
//! The macros themselves do not impose additional thread safety requirements beyond
//! the underlying synchronization primitives. All operations preserve the thread safety
//! guarantees of the wrapped [`std::sync::Mutex`] and [`std::sync::RwLock`] types.
//! All macros are thread-safe as they operate on already thread-safe synchronization
//! primitives and do not introduce additional shared state.
//!
//! # Integration
//!
//! These macros integrate primarily with:
//! - [`crate::metadata::loader`] - Metadata loading system for concurrent parsing
//! - [`crate::metadata::tables`] - Shared access to metadata table structures
//! - Internal caching systems that require synchronized access to parsed data

#![allow(unused_macros)]

/// Acquire a mutex lock with automatic panic handling.
///
/// This macro simplifies acquiring a lock on a [`std::sync::Mutex`] by automatically
/// handling lock poisoning with a panic. It's designed for use cases where lock
/// poisoning indicates an unrecoverable error.
///
/// # Panics
///
/// Panics if the mutex is poisoned (another thread panicked while holding the lock).
///
/// # Usage Examples
///
/// ```rust,ignore
/// use std::sync::Mutex;
///
/// let shared_data = Mutex::new(42);
/// let mut data = lock!(shared_data);
/// *data = 100;
/// // Lock is automatically released when `data` goes out of scope
/// ```
macro_rules! lock {
    ($lock:expr) => {
        $lock.lock().expect("Failed to acquire lock")
    };
}

/// Acquire a read lock on an [`std::sync::RwLock`] with automatic panic handling.
///
/// This macro simplifies acquiring a read lock by automatically handling lock
/// poisoning with a panic. Multiple readers can hold the lock simultaneously.
///
/// # Panics
///
/// Panics if the [`std::sync::RwLock`] is poisoned.
///
/// # Usage Examples
///
/// ```rust,ignore
/// use std::sync::RwLock;
///
/// let shared_data = RwLock::new("hello world".to_string());
/// let data = read_lock!(shared_data);
/// println!("Data: {}", *data);
/// // Read lock is automatically released when `data` goes out of scope
/// ```
macro_rules! read_lock {
    ($arc_rwlock:expr) => {
        $arc_rwlock.read().expect("Failed to acquire read lock")
    };
}

/// Acquire a write lock on an [`std::sync::RwLock`] with automatic panic handling.
///
/// This macro simplifies acquiring a write lock by automatically handling lock
/// poisoning with a panic. Only one writer can hold the lock at a time, and
/// no readers can access the data while a write lock is held.
///
/// # Panics
///
/// Panics if the [`std::sync::RwLock`] is poisoned.
///
/// # Usage Examples
///
/// ```rust,ignore
/// use std::sync::RwLock;
///
/// let shared_data = RwLock::new(vec![1, 2, 3]);
/// let mut data = write_lock!(shared_data);
/// data.push(4);
/// // Write lock is automatically released when `data` goes out of scope
/// ```
macro_rules! write_lock {
    ($arc_rwlock:expr) => {
        $arc_rwlock.write().expect("Failed to acquire write lock")
    };
}

/// Execute a closure with read access to shared data.
///
/// This macro acquires a read lock, executes the provided closure with access
/// to the data, and automatically releases the lock when the closure completes.
/// The closure's return value is passed through.
///
/// # Arguments
/// * `$arc_rwlock` - An [`std::sync::RwLock`] to acquire a read lock on
/// * `$closure` - A closure that takes a reference to the locked data
///
/// # Panics
///
/// Panics if the [`std::sync::RwLock`] is poisoned.
///
/// # Usage Examples
///
/// ```rust,ignore
/// use std::sync::{Arc, RwLock};
///
/// let shared_data = Arc::new(RwLock::new("Hello".to_string()));
/// let length = with_read!(shared_data, |data| data.len());
/// assert_eq!(length, 5);
/// ```
macro_rules! with_read {
    ($arc_rwlock:expr, $closure:expr) => {{
        let guard = $arc_rwlock.read().expect("Failed to acquire read lock");
        $closure(&*guard)
    }};
}

/// Execute a closure with write access to shared data.
///
/// This macro acquires a write lock, executes the provided closure with mutable
/// access to the data, and automatically releases the lock when the closure completes.
/// The closure's return value is passed through.
///
/// # Arguments
/// * `$arc_rwlock` - An [`std::sync::RwLock`] to acquire a write lock on
/// * `$closure` - A closure that takes a mutable reference to the locked data
///
/// # Panics
///
/// Panics if the [`std::sync::RwLock`] is poisoned.
///
/// # Usage Examples
///
/// ```rust,ignore
/// use std::sync::{Arc, RwLock};
///
/// let shared_data = Arc::new(RwLock::new(vec![1, 2, 3]));
/// with_write!(shared_data, |data| data.push(4));
///
/// let length = with_read!(shared_data, |data| data.len());
/// assert_eq!(length, 4);
/// ```
macro_rules! with_write {
    ($arc_rwlock:expr, $closure:expr) => {{
        let mut guard = $arc_rwlock.write().expect("Failed to acquire write lock");
        $closure(&mut *guard)
    }};
}

/// Get an item from a map and acquire a read lock on it.
///
/// This macro combines map lookup with read lock acquisition, returning an
/// [`std::option::Option`] containing the locked data if the key exists.
///
/// # Arguments
/// * `$map` - A map-like collection containing [`std::sync::Arc`]<[`std::sync::RwLock`]<`T`>> values
/// * `$key` - The key to look up in the map
///
/// # Returns
/// An [`std::option::Option`] containing a read guard if the key exists, or [`std::option::Option::None`] if not found.
///
/// # Panics
///
/// Panics if the [`std::sync::RwLock`] is poisoned.
///
/// # Usage Examples
///
/// ```rust,ignore
/// use std::collections::HashMap;
/// use std::sync::{Arc, RwLock};
///
/// let mut map = HashMap::new();
/// map.insert(1, Arc::new(RwLock::new("value".to_string())));
///
/// if let Some(guard) = map_get_read!(map, &1) {
///     println!("Found: {}", *guard);
/// }
/// ```
macro_rules! map_get_read {
    ($map:expr, $key:expr) => {{
        $map.get($key).map(|arc_rwlock| read_lock!(arc_rwlock))
    }};
}

/// Iterate over a collection of locked items with read access.
///
/// This macro simplifies iterating over a collection where each item is wrapped
/// in an [`std::sync::Arc`]<[`std::sync::RwLock`]<`T`>>. It automatically acquires
/// a read lock for each item during iteration.
///
/// # Arguments
/// * `$collection` - A collection containing [`std::sync::Arc`]<[`std::sync::RwLock`]<`T`>> items
/// * `$var` - The variable name to bind the locked data to in each iteration
/// * `$body` - The code block to execute for each item
///
/// # Panics
///
/// Panics if any [`std::sync::RwLock`] in the collection is poisoned.
///
/// # Usage Examples
///
/// ```rust,ignore
/// use std::sync::{Arc, RwLock};
///
/// let items = vec![
///     Arc::new(RwLock::new("first".to_string())),
///     Arc::new(RwLock::new("second".to_string())),
/// ];
///
/// for_each_read!(items, item, {
///     println!("Item: {}", *item);
/// });
/// ```
macro_rules! for_each_read {
    ($collection:expr, $var:ident, $body:block) => {
        for item in $collection.iter() {
            let $var = read_lock!(item);
            $body
        }
    };
}
