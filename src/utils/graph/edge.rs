//! Edge identifier implementation for directed graphs.
//!
//! This module provides the [`EdgeId`] type, a strongly-typed identifier for edges
//! within a directed graph. The newtype wrapper provides type safety and prevents
//! accidental confusion between edge indices and other integer values.

use std::fmt;

/// A strongly-typed identifier for edges within a directed graph.
///
/// `EdgeId` wraps a `usize` index, providing type safety to prevent
/// accidental mixing of edge indices with other integer values or node indices.
/// Edge IDs are assigned sequentially starting from 0 when edges are added to a graph.
///
/// # Usage
///
/// Edge IDs are created by [`DirectedGraph::add_edge`](crate::utils::graph::DirectedGraph::add_edge)
/// and should not typically be constructed manually. They are used to:
///
/// - Reference edges when querying edge data
/// - Look up edge endpoints (source and target nodes)
/// - Store analysis results indexed by edge
///
/// # Examples
///
/// ```rust,ignore
/// use dotscope::graph::{DirectedGraph, NodeId, EdgeId};
///
/// let mut graph: DirectedGraph<&str, &str> = DirectedGraph::new();
/// let a = graph.add_node("A");
/// let b = graph.add_node("B");
/// let edge: EdgeId = graph.add_edge(a, b, "A->B");
///
/// // EdgeIds can be used to query edge information
/// assert_eq!(graph.edge(edge), Some(&"A->B"));
/// assert_eq!(graph.edge_endpoints(edge), Some((a, b)));
/// ```
///
/// # Thread Safety
///
/// `EdgeId` is [`Copy`], [`Send`], and [`Sync`], enabling efficient passing between
/// threads and use in concurrent data structures.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EdgeId(pub(crate) usize);

impl EdgeId {
    /// Creates a new `EdgeId` from a raw index value.
    ///
    /// This constructor is primarily intended for internal use and testing.
    /// Normal usage should obtain `EdgeId` values from [`DirectedGraph::add_edge`](crate::utils::graph::DirectedGraph::add_edge).
    ///
    /// # Arguments
    ///
    /// * `index` - The raw edge index (0-based)
    ///
    /// # Returns
    ///
    /// A new `EdgeId` wrapping the provided index.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::graph::EdgeId;
    ///
    /// let edge = EdgeId::new(0);
    /// assert_eq!(edge.index(), 0);
    /// ```
    #[must_use]
    #[inline]
    pub const fn new(index: usize) -> Self {
        EdgeId(index)
    }

    /// Returns the raw index value of this edge identifier.
    ///
    /// The index is a 0-based position that can be used to index into vectors
    /// or arrays that store per-edge data.
    ///
    /// # Returns
    ///
    /// The underlying index value.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::graph::EdgeId;
    ///
    /// let edge = EdgeId::new(5);
    /// assert_eq!(edge.index(), 5);
    /// ```
    #[must_use]
    #[inline]
    pub const fn index(self) -> usize {
        self.0
    }
}

impl fmt::Debug for EdgeId {
    /// Formats the edge ID for debugging output.
    ///
    /// The format shows the type name and index value for clear identification
    /// in debug output and logging.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EdgeId({})", self.0)
    }
}

impl fmt::Display for EdgeId {
    /// Formats the edge ID for user display.
    ///
    /// The display format shows just the prefix and index for compact output.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "e{}", self.0)
    }
}

impl From<usize> for EdgeId {
    /// Converts a raw `usize` index into an `EdgeId`.
    ///
    /// This conversion is provided for convenience but should be used carefully
    /// to avoid creating invalid edge IDs that don't correspond to actual edges
    /// in a graph.
    #[inline]
    fn from(index: usize) -> Self {
        EdgeId(index)
    }
}

impl From<EdgeId> for usize {
    /// Extracts the raw index from an `EdgeId`.
    #[inline]
    fn from(edge: EdgeId) -> Self {
        edge.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, HashSet};

    #[test]
    fn test_edge_id_new() {
        let edge = EdgeId::new(42);
        assert_eq!(edge.index(), 42);
    }

    #[test]
    fn test_edge_id_index() {
        let edge = EdgeId::new(100);
        assert_eq!(edge.index(), 100);
    }

    #[test]
    fn test_edge_id_equality() {
        let edge1 = EdgeId::new(5);
        let edge2 = EdgeId::new(5);
        let edge3 = EdgeId::new(10);

        assert_eq!(edge1, edge2);
        assert_ne!(edge1, edge3);
    }

    #[test]
    fn test_edge_id_ordering() {
        let edge1 = EdgeId::new(1);
        let edge2 = EdgeId::new(2);
        let edge3 = EdgeId::new(3);

        assert!(edge1 < edge2);
        assert!(edge2 < edge3);
        assert!(edge1 < edge3);

        let mut edges = vec![edge3, edge1, edge2];
        edges.sort();
        assert_eq!(edges, vec![edge1, edge2, edge3]);
    }

    #[test]
    fn test_edge_id_hash() {
        let mut set: HashSet<EdgeId> = HashSet::new();
        let edge1 = EdgeId::new(1);
        let edge2 = EdgeId::new(2);
        let edge1_dup = EdgeId::new(1);

        set.insert(edge1);
        set.insert(edge2);
        set.insert(edge1_dup); // Should not add duplicate

        assert_eq!(set.len(), 2);
        assert!(set.contains(&edge1));
        assert!(set.contains(&edge2));
    }

    #[test]
    fn test_edge_id_as_map_key() {
        let mut map: HashMap<EdgeId, &str> = HashMap::new();
        let edge1 = EdgeId::new(1);
        let edge2 = EdgeId::new(2);

        map.insert(edge1, "first");
        map.insert(edge2, "second");

        assert_eq!(map.get(&edge1), Some(&"first"));
        assert_eq!(map.get(&edge2), Some(&"second"));
        assert_eq!(map.get(&EdgeId::new(3)), None);
    }

    #[test]
    fn test_edge_id_copy_semantics() {
        let edge1 = EdgeId::new(42);
        let edge2 = edge1; // Copy

        assert_eq!(edge1, edge2);
        assert_eq!(edge1.index(), 42);
        assert_eq!(edge2.index(), 42);
    }

    #[test]
    fn test_edge_id_from_usize() {
        let edge: EdgeId = 123usize.into();
        assert_eq!(edge.index(), 123);
    }

    #[test]
    fn test_edge_id_into_usize() {
        let edge = EdgeId::new(789);
        let value: usize = edge.into();
        assert_eq!(value, 789);
    }

    #[test]
    fn test_edge_id_debug_format() {
        let edge = EdgeId::new(42);
        let debug_str = format!("{edge:?}");
        assert_eq!(debug_str, "EdgeId(42)");
    }

    #[test]
    fn test_edge_id_display_format() {
        let edge = EdgeId::new(42);
        let display_str = format!("{edge}");
        assert_eq!(display_str, "e42");
    }

    #[test]
    fn test_edge_id_boundary_values() {
        // Test zero
        let zero = EdgeId::new(0);
        assert_eq!(zero.index(), 0);

        // Test large value
        let large = EdgeId::new(1_000_000);
        assert_eq!(large.index(), 1_000_000);
    }

    #[test]
    fn test_edge_id_array_indexing() {
        let weights = vec![1.5, 2.5, 3.5, 4.5];
        let edge = EdgeId::new(2);

        assert_eq!(weights[edge.index()], 3.5);
    }

    #[test]
    fn test_edge_id_distinct_from_node_id() {
        // This test demonstrates that EdgeId and NodeId are distinct types
        // and cannot be accidentally mixed (verified at compile time)
        use crate::utils::graph::NodeId;

        let node = NodeId::new(5);
        let edge = EdgeId::new(5);

        // Both have the same underlying value but are different types
        assert_eq!(node.index(), edge.index());

        // The following would not compile, demonstrating type safety:
        // let _: NodeId = edge; // Error: expected NodeId, found EdgeId
        // let _: EdgeId = node; // Error: expected EdgeId, found NodeId
    }
}
