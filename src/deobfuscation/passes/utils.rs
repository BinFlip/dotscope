//! Shared utilities for deobfuscation passes.
//!
//! This module contains common functionality used by multiple passes to avoid
//! code duplication and ensure consistent behavior.

use std::collections::{HashMap, HashSet};

/// Follows a chain of mappings to find the ultimate target.
///
/// Given a map where keys point to values, and values may also be keys,
/// this function follows the chain until reaching a value that is not a key.
/// Handles cycles by stopping when a previously visited key is encountered.
///
/// This is useful for:
/// - Following trampoline chains (block → block → block)
/// - Resolving copy chains (var → var → var)
/// - Any other transitive closure computation
///
/// # Arguments
///
/// * `map` - The mapping to follow.
/// * `start` - The starting key.
///
/// # Returns
///
/// The ultimate target after following the chain.
///
/// # Example
///
/// ```ignore
/// let mut trampolines = HashMap::new();
/// trampolines.insert(1, 2);
/// trampolines.insert(2, 3);
/// // 1 -> 2 -> 3
/// assert_eq!(resolve_chain(&trampolines, 1), 3);
/// ```
#[must_use]
pub fn resolve_chain<K>(map: &HashMap<K, K>, start: K) -> K
where
    K: Copy + std::hash::Hash + Eq,
{
    let mut current = start;
    let mut visited = HashSet::new();

    while let Some(&next) = map.get(&current) {
        if !visited.insert(current) {
            // Cycle detected - return current position
            break;
        }
        current = next;
    }

    current
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_chain_follows_mappings() {
        let mut map = HashMap::new();
        map.insert(1, 2);
        map.insert(2, 3);
        map.insert(3, 4);

        // Should follow the full chain: 1 -> 2 -> 3 -> 4
        assert_eq!(resolve_chain(&map, 1), 4);
        assert_eq!(resolve_chain(&map, 2), 4);
        assert_eq!(resolve_chain(&map, 3), 4);
        // Value not in map returns itself
        assert_eq!(resolve_chain(&map, 4), 4);
    }

    #[test]
    fn test_resolve_chain_handles_cycles() {
        let mut map = HashMap::new();
        map.insert(1, 2);
        map.insert(2, 1); // Cycle: 1 -> 2 -> 1

        // Should terminate without infinite loop
        let result = resolve_chain(&map, 1);
        assert!(result == 1 || result == 2);
    }

    #[test]
    fn test_resolve_chain_single_step() {
        let mut map = HashMap::new();
        map.insert(5, 10);

        assert_eq!(resolve_chain(&map, 5), 10);
    }

    #[test]
    fn test_resolve_chain_empty_map() {
        let map: HashMap<usize, usize> = HashMap::new();
        // Value not in map returns itself
        assert_eq!(resolve_chain(&map, 42), 42);
    }

    #[test]
    fn test_resolve_chain_self_loop() {
        let mut map = HashMap::new();
        map.insert(1, 1); // Self-loop

        // Should terminate
        assert_eq!(resolve_chain(&map, 1), 1);
    }
}
