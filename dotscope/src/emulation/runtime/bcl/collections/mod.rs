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

use crate::{emulation::runtime::hook::HookManager, Result};

/// Registers all `System.Collections` namespace hooks with the given hook manager.
///
/// Delegates to each submodule's `register()` function to install hooks for
/// `Dictionary<TKey, TValue>`, `List<T>`, `Stack<T>`, `Queue<T>`, and `HashSet<T>`.
///
/// # Arguments
///
/// * `manager` - The [`HookManager`] to register hooks with
pub fn register(manager: &HookManager) -> Result<()> {
    dictionary::register(manager)?;
    generic::register(manager)?;
    list::register(manager)?;
    Ok(())
}
