//! Indexed graph wrapper for domain-typed nodes.
//!
//! This module provides [`IndexedGraph`], a convenience wrapper around [`DirectedGraph`]
//! that automatically handles the mapping between domain types (like `AssemblyIdentity`
//! or `TableId`) and internal `NodeId` indices.
//!
//! # Motivation
//!
//! When working with graph algorithms, domain code often needs to:
//! 1. Build a graph from domain-specific types
//! 2. Run algorithms that work with `NodeId`
//! 3. Map results back to domain types
//!
//! `IndexedGraph` encapsulates this pattern, providing a cleaner API.
//!
//! # Examples
//!
//! ```rust,ignore
//! use dotscope::utils::graph::{IndexedGraph, algorithms};
//!
//! // Create a graph with string keys
//! let mut graph: IndexedGraph<&str, ()> = IndexedGraph::new();
//!
//! // Add nodes using domain types directly
//! graph.add_node("A");
//! graph.add_node("B");
//! graph.add_node("C");
//!
//! // Add edges using domain types
//! graph.add_edge("A", "B", ());
//! graph.add_edge("B", "C", ());
//! graph.add_edge("C", "A", ()); // Creates a cycle
//!
//! // Run algorithms - results are automatically mapped back
//! if let Some(cycle) = graph.find_cycle_from("A") {
//!     println!("Found cycle: {:?}", cycle); // ["A", "B", "C", "A"]
//! }
//! ```

use std::collections::HashMap;
use std::hash::Hash;

use crate::{
    utils::graph::{algorithms, DirectedGraph, NodeId},
    Result,
};

/// A graph wrapper that provides automatic mapping between domain types and `NodeId`.
///
/// `IndexedGraph<K, E>` stores nodes indexed by keys of type `K` (which must be
/// `Hash + Eq + Clone`) and edges with data of type `E`. It maintains bidirectional
/// mappings for efficient lookups in both directions.
///
/// # Type Parameters
///
/// * `K` - The domain key type for nodes (e.g., `AssemblyIdentity`, `TableId`)
/// * `E` - The edge data type
///
/// # Thread Safety
///
/// `IndexedGraph<K, E>` is `Send` and `Sync` when both `K` and `E` are.
#[derive(Debug, Clone)]
pub struct IndexedGraph<K, E>
where
    K: Hash + Eq + Clone,
{
    /// The underlying directed graph (nodes store unit type, keys are separate)
    graph: DirectedGraph<(), E>,
    /// Map from domain key to `NodeId`
    key_to_node: HashMap<K, NodeId>,
    /// Map from `NodeId` to domain key
    node_to_key: HashMap<NodeId, K>,
}

impl<K, E> Default for IndexedGraph<K, E>
where
    K: Hash + Eq + Clone,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<K, E> IndexedGraph<K, E>
where
    K: Hash + Eq + Clone,
{
    /// Creates a new empty indexed graph.
    #[must_use]
    pub fn new() -> Self {
        Self {
            graph: DirectedGraph::new(),
            key_to_node: HashMap::new(),
            node_to_key: HashMap::new(),
        }
    }

    /// Creates a new indexed graph with pre-allocated capacity.
    #[must_use]
    pub fn with_capacity(node_capacity: usize, edge_capacity: usize) -> Self {
        Self {
            graph: DirectedGraph::with_capacity(node_capacity, edge_capacity),
            key_to_node: HashMap::with_capacity(node_capacity),
            node_to_key: HashMap::with_capacity(node_capacity),
        }
    }

    /// Adds a node with the given key, or returns the existing `NodeId` if already present.
    ///
    /// This method is idempotent - calling it multiple times with the same key
    /// will always return the same `NodeId`.
    ///
    /// # Arguments
    ///
    /// * `key` - The domain key for this node
    ///
    /// # Returns
    ///
    /// The `NodeId` associated with this key.
    pub fn add_node(&mut self, key: K) -> NodeId {
        if let Some(&node_id) = self.key_to_node.get(&key) {
            return node_id;
        }

        let node_id = self.graph.add_node(());
        self.key_to_node.insert(key.clone(), node_id);
        self.node_to_key.insert(node_id, key);
        node_id
    }

    /// Adds a directed edge between two nodes identified by their keys.
    ///
    /// If either node doesn't exist, it will be created automatically.
    ///
    /// # Arguments
    ///
    /// * `from` - The source node key
    /// * `to` - The target node key
    /// * `data` - The edge data
    ///
    /// # Returns
    ///
    /// * `Ok(true)` if a new edge was added
    /// * `Ok(false)` if the edge already existed
    /// * `Err(_)` if the edge could not be added
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying graph operation fails.
    pub fn add_edge(&mut self, from: K, to: K, data: E) -> Result<bool>
    where
        E: Clone,
    {
        let from_node = self.add_node(from);
        let to_node = self.add_node(to);

        // Check if edge already exists
        if self.graph.successors(from_node).any(|s| s == to_node) {
            return Ok(false);
        }

        self.graph.add_edge(from_node, to_node, data)?;
        Ok(true)
    }

    /// Returns the `NodeId` for a given key, if it exists.
    #[must_use]
    pub fn get_node_id(&self, key: &K) -> Option<NodeId> {
        self.key_to_node.get(key).copied()
    }

    /// Returns the key for a given `NodeId`, if it exists.
    #[must_use]
    pub fn get_key(&self, node_id: NodeId) -> Option<&K> {
        self.node_to_key.get(&node_id)
    }

    /// Returns the number of nodes in the graph.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.graph.node_count()
    }

    /// Returns the number of edges in the graph.
    #[must_use]
    pub fn edge_count(&self) -> usize {
        self.graph.edge_count()
    }

    /// Returns `true` if the graph contains no nodes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.graph.is_empty()
    }

    /// Returns a reference to the underlying `DirectedGraph`.
    ///
    /// This is useful when you need to pass the graph to algorithms that
    /// work with `DirectedGraph` directly.
    #[must_use]
    pub fn inner(&self) -> &DirectedGraph<(), E> {
        &self.graph
    }

    /// Returns an iterator over all keys in the graph.
    pub fn keys(&self) -> impl Iterator<Item = &K> {
        self.key_to_node.keys()
    }

    /// Maps a vector of `NodeId`s back to domain keys.
    ///
    /// Nodes that don't have a corresponding key are skipped.
    #[must_use]
    pub fn map_nodes_to_keys(&self, nodes: &[NodeId]) -> Vec<K> {
        nodes
            .iter()
            .filter_map(|node_id| self.node_to_key.get(node_id).cloned())
            .collect()
    }

    /// Maps a vector of SCCs (each being a `Vec<NodeId>`) back to domain keys.
    #[must_use]
    pub fn map_sccs_to_keys(&self, sccs: &[Vec<NodeId>]) -> Vec<Vec<K>> {
        sccs.iter().map(|scc| self.map_nodes_to_keys(scc)).collect()
    }
}

// Algorithm convenience methods
impl<K, E> IndexedGraph<K, E>
where
    K: Hash + Eq + Clone,
{
    /// Finds a cycle in the graph starting from the given key.
    ///
    /// Returns the cycle as a vector of domain keys if found, `None` otherwise.
    #[must_use]
    pub fn find_cycle_from(&self, start: &K) -> Option<Vec<K>> {
        let start_node = self.key_to_node.get(start)?;
        let cycle_nodes = algorithms::find_cycle(&self.graph, *start_node)?;
        Some(self.map_nodes_to_keys(&cycle_nodes))
    }

    /// Checks if the graph contains any cycle reachable from the given key.
    #[must_use]
    pub fn has_cycle_from(&self, start: &K) -> bool {
        self.key_to_node
            .get(start)
            .is_some_and(|&start_node| algorithms::has_cycle(&self.graph, start_node))
    }

    /// Finds any cycle in the graph.
    ///
    /// Checks all nodes and returns the first cycle found.
    #[must_use]
    pub fn find_any_cycle(&self) -> Option<Vec<K>> {
        for &start_node in self.key_to_node.values() {
            if let Some(cycle_nodes) = algorithms::find_cycle(&self.graph, start_node) {
                return Some(self.map_nodes_to_keys(&cycle_nodes));
            }
        }
        None
    }

    /// Computes strongly connected components.
    ///
    /// Returns SCCs as vectors of domain keys, in reverse topological order.
    #[must_use]
    pub fn strongly_connected_components(&self) -> Vec<Vec<K>> {
        let sccs = algorithms::strongly_connected_components(&self.graph);
        self.map_sccs_to_keys(&sccs)
    }

    /// Computes a topological ordering of the graph.
    ///
    /// Returns `Some(order)` if the graph is acyclic, `None` if it contains cycles.
    #[must_use]
    pub fn topological_sort(&self) -> Option<Vec<K>> {
        let order = algorithms::topological_sort(&self.graph)?;
        Some(self.map_nodes_to_keys(&order))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_indexed_graph_basic() {
        let mut graph: IndexedGraph<&str, ()> = IndexedGraph::new();

        let a = graph.add_node("A");
        let b = graph.add_node("B");

        assert_eq!(graph.node_count(), 2);
        assert_eq!(graph.get_node_id(&"A"), Some(a));
        assert_eq!(graph.get_node_id(&"B"), Some(b));
        assert_eq!(graph.get_key(a), Some(&"A"));
        assert_eq!(graph.get_key(b), Some(&"B"));
    }

    #[test]
    fn test_indexed_graph_idempotent_add() {
        let mut graph: IndexedGraph<&str, ()> = IndexedGraph::new();

        let a1 = graph.add_node("A");
        let a2 = graph.add_node("A"); // Same key

        assert_eq!(a1, a2);
        assert_eq!(graph.node_count(), 1);
    }

    #[test]
    fn test_indexed_graph_add_edge() {
        let mut graph: IndexedGraph<&str, i32> = IndexedGraph::new();

        // Nodes created automatically
        assert!(graph.add_edge("A", "B", 10).unwrap());
        assert!(graph.add_edge("B", "C", 20).unwrap());

        assert_eq!(graph.node_count(), 3);
        assert_eq!(graph.edge_count(), 2);

        // Duplicate edge not added
        assert!(!graph.add_edge("A", "B", 10).unwrap());
        assert_eq!(graph.edge_count(), 2);
    }

    #[test]
    fn test_indexed_graph_find_cycle() {
        let mut graph: IndexedGraph<&str, ()> = IndexedGraph::new();

        graph.add_edge("A", "B", ()).unwrap();
        graph.add_edge("B", "C", ()).unwrap();
        graph.add_edge("C", "A", ()).unwrap(); // Creates cycle

        let cycle = graph.find_cycle_from(&"A");
        assert!(cycle.is_some());

        let cycle = cycle.unwrap();
        assert!(cycle.contains(&"A"));
        assert!(cycle.contains(&"B"));
        assert!(cycle.contains(&"C"));
    }

    #[test]
    fn test_indexed_graph_no_cycle() {
        let mut graph: IndexedGraph<&str, ()> = IndexedGraph::new();

        graph.add_edge("A", "B", ()).unwrap();
        graph.add_edge("B", "C", ()).unwrap();
        // No back edge

        assert!(graph.find_cycle_from(&"A").is_none());
        assert!(!graph.has_cycle_from(&"A"));
    }

    #[test]
    fn test_indexed_graph_topological_sort() {
        let mut graph: IndexedGraph<&str, ()> = IndexedGraph::new();

        // A -> B -> D
        // A -> C -> D
        graph.add_edge("A", "B", ()).unwrap();
        graph.add_edge("A", "C", ()).unwrap();
        graph.add_edge("B", "D", ()).unwrap();
        graph.add_edge("C", "D", ()).unwrap();

        let order = graph.topological_sort();
        assert!(order.is_some());

        let order = order.unwrap();
        assert_eq!(order.len(), 4);

        // A must come before B, C; B and C must come before D
        let pos = |k: &str| order.iter().position(|&x| x == k).unwrap();
        assert!(pos("A") < pos("B"));
        assert!(pos("A") < pos("C"));
        assert!(pos("B") < pos("D"));
        assert!(pos("C") < pos("D"));
    }

    #[test]
    fn test_indexed_graph_topological_sort_with_cycle() {
        let mut graph: IndexedGraph<&str, ()> = IndexedGraph::new();

        graph.add_edge("A", "B", ()).unwrap();
        graph.add_edge("B", "A", ()).unwrap(); // Cycle

        assert!(graph.topological_sort().is_none());
    }

    #[test]
    fn test_indexed_graph_scc() {
        let mut graph: IndexedGraph<&str, ()> = IndexedGraph::new();

        // Two SCCs: {A, B} and {C}
        graph.add_edge("A", "B", ()).unwrap();
        graph.add_edge("B", "A", ()).unwrap(); // A <-> B cycle
        graph.add_edge("B", "C", ()).unwrap();

        let sccs = graph.strongly_connected_components();
        assert_eq!(sccs.len(), 2);

        // One SCC has 2 elements, one has 1
        let mut sizes: Vec<usize> = sccs.iter().map(|scc| scc.len()).collect();
        sizes.sort();
        assert_eq!(sizes, vec![1, 2]);
    }

    #[test]
    fn test_indexed_graph_with_integers() {
        let mut graph: IndexedGraph<i32, &str> = IndexedGraph::new();

        graph.add_edge(1, 2, "one-two").unwrap();
        graph.add_edge(2, 3, "two-three").unwrap();

        assert_eq!(graph.node_count(), 3);
        assert!(graph.topological_sort().is_some());
    }
}
