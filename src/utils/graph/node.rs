//! Node identifier implementation for directed graphs.
//!
//! This module provides the [`NodeId`] type, a strongly-typed identifier for nodes
//! within a directed graph. The newtype wrapper provides type safety and prevents
//! accidental confusion between node indices and other integer values.

use std::fmt;

/// A strongly-typed identifier for nodes within a directed graph.
///
/// `NodeId` wraps a `usize` index, providing type safety to prevent
/// accidental mixing of node indices with other integer values. Node IDs are assigned
/// sequentially starting from 0 when nodes are added to a graph.
///
/// # Usage
///
/// Node IDs are created by [`DirectedGraph::add_node`](crate::utils::graph::DirectedGraph::add_node)
/// and should not typically be constructed manually. They are used to:
///
/// - Reference nodes when adding edges
/// - Look up node data
/// - Query adjacency relationships
/// - Store analysis results indexed by node
///
/// # Examples
///
/// ```rust,ignore
/// use dotscope::graph::{DirectedGraph, NodeId};
///
/// let mut graph: DirectedGraph<&str, ()> = DirectedGraph::new();
/// let node_a: NodeId = graph.add_node("A");
/// let node_b: NodeId = graph.add_node("B");
///
/// // NodeIds can be compared
/// assert_ne!(node_a, node_b);
///
/// // NodeIds can be used as keys in collections
/// use std::collections::HashMap;
/// let mut data: HashMap<NodeId, i32> = HashMap::new();
/// data.insert(node_a, 42);
/// ```
///
/// # Thread Safety
///
/// `NodeId` is [`Copy`], [`Send`], and [`Sync`], enabling efficient passing between
/// threads and use in concurrent data structures.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeId(pub(crate) usize);

impl NodeId {
    /// Creates a new `NodeId` from a raw index value.
    ///
    /// This constructor is primarily intended for internal use and testing.
    /// Normal usage should obtain `NodeId` values from [`DirectedGraph::add_node`](crate::utils::graph::DirectedGraph::add_node).
    ///
    /// # Arguments
    ///
    /// * `index` - The raw node index (0-based)
    ///
    /// # Returns
    ///
    /// A new `NodeId` wrapping the provided index.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::graph::NodeId;
    ///
    /// let node = NodeId::new(0);
    /// assert_eq!(node.index(), 0);
    /// ```
    #[must_use]
    #[inline]
    pub const fn new(index: usize) -> Self {
        NodeId(index)
    }

    /// Returns the raw index value of this node identifier.
    ///
    /// The index is a 0-based position that can be used to index into vectors
    /// or arrays that store per-node data.
    ///
    /// # Returns
    ///
    /// The underlying index value.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::graph::NodeId;
    ///
    /// let node = NodeId::new(5);
    /// assert_eq!(node.index(), 5);
    ///
    /// // Can be used to index into arrays
    /// let data = vec![10, 20, 30, 40, 50, 60];
    /// let value = data[node.index()];
    /// assert_eq!(value, 60);
    /// ```
    #[must_use]
    #[inline]
    pub const fn index(self) -> usize {
        self.0
    }
}

impl fmt::Debug for NodeId {
    /// Formats the node ID for debugging output.
    ///
    /// The format shows the type name and index value for clear identification
    /// in debug output and logging.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NodeId({})", self.0)
    }
}

impl fmt::Display for NodeId {
    /// Formats the node ID for user display.
    ///
    /// The display format shows just the prefix and index for compact output.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "n{}", self.0)
    }
}

impl From<usize> for NodeId {
    /// Converts a raw `usize` index into a `NodeId`.
    ///
    /// This conversion is provided for convenience but should be used carefully
    /// to avoid creating invalid node IDs that don't correspond to actual nodes
    /// in a graph.
    #[inline]
    fn from(index: usize) -> Self {
        NodeId(index)
    }
}

impl From<NodeId> for usize {
    /// Extracts the raw index from a `NodeId`.
    #[inline]
    fn from(node: NodeId) -> Self {
        node.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, HashSet};

    #[test]
    fn test_node_id_new() {
        let node = NodeId::new(42);
        assert_eq!(node.index(), 42);
    }

    #[test]
    fn test_node_id_index() {
        let node = NodeId::new(100);
        assert_eq!(node.index(), 100);
    }

    #[test]
    fn test_node_id_equality() {
        let node1 = NodeId::new(5);
        let node2 = NodeId::new(5);
        let node3 = NodeId::new(10);

        assert_eq!(node1, node2);
        assert_ne!(node1, node3);
    }

    #[test]
    fn test_node_id_ordering() {
        let node1 = NodeId::new(1);
        let node2 = NodeId::new(2);
        let node3 = NodeId::new(3);

        assert!(node1 < node2);
        assert!(node2 < node3);
        assert!(node1 < node3);

        let mut nodes = vec![node3, node1, node2];
        nodes.sort();
        assert_eq!(nodes, vec![node1, node2, node3]);
    }

    #[test]
    fn test_node_id_hash() {
        let mut set: HashSet<NodeId> = HashSet::new();
        let node1 = NodeId::new(1);
        let node2 = NodeId::new(2);
        let node1_dup = NodeId::new(1);

        set.insert(node1);
        set.insert(node2);
        set.insert(node1_dup); // Should not add duplicate

        assert_eq!(set.len(), 2);
        assert!(set.contains(&node1));
        assert!(set.contains(&node2));
    }

    #[test]
    fn test_node_id_as_map_key() {
        let mut map: HashMap<NodeId, &str> = HashMap::new();
        let node1 = NodeId::new(1);
        let node2 = NodeId::new(2);

        map.insert(node1, "first");
        map.insert(node2, "second");

        assert_eq!(map.get(&node1), Some(&"first"));
        assert_eq!(map.get(&node2), Some(&"second"));
        assert_eq!(map.get(&NodeId::new(3)), None);
    }

    #[test]
    fn test_node_id_copy_semantics() {
        let node1 = NodeId::new(42);
        let node2 = node1; // Copy

        assert_eq!(node1, node2);
        assert_eq!(node1.index(), 42);
        assert_eq!(node2.index(), 42);
    }

    #[test]
    fn test_node_id_from_usize() {
        let node: NodeId = 123usize.into();
        assert_eq!(node.index(), 123);
    }

    #[test]
    fn test_node_id_into_usize() {
        let node = NodeId::new(789);
        let value: usize = node.into();
        assert_eq!(value, 789);
    }

    #[test]
    fn test_node_id_debug_format() {
        let node = NodeId::new(42);
        let debug_str = format!("{node:?}");
        assert_eq!(debug_str, "NodeId(42)");
    }

    #[test]
    fn test_node_id_display_format() {
        let node = NodeId::new(42);
        let display_str = format!("{node}");
        assert_eq!(display_str, "n42");
    }

    #[test]
    fn test_node_id_boundary_values() {
        // Test zero
        let zero = NodeId::new(0);
        assert_eq!(zero.index(), 0);

        // Test large value
        let large = NodeId::new(1_000_000);
        assert_eq!(large.index(), 1_000_000);
    }

    #[test]
    fn test_node_id_array_indexing() {
        let data = vec!["zero", "one", "two", "three"];
        let node = NodeId::new(2);

        assert_eq!(data[node.index()], "two");
    }
}
