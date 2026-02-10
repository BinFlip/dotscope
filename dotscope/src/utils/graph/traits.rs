//! Trait definitions for graph abstractions.
//!
//! This module defines the core traits that enable graph algorithms to work with
//! different graph implementations. By programming against these traits, algorithms
//! can be reused across various graph types without modification.
//!
//! # Architecture
//!
//! The trait hierarchy is designed to be minimal and composable:
//!
//! - [`GraphBase`] - Core properties: node count and node iteration
//! - [`Successors`] - Forward edge traversal (outgoing edges)
//! - [`Predecessors`] - Backward edge traversal (incoming edges)
//! - [`RootedGraph`] - Graphs with a designated entry node (for dominator computation)
//!
//! # Design Principles
//!
//! ## Iterator-Based Traversal
//!
//! All adjacency queries return iterators rather than collections, enabling lazy
//! evaluation and avoiding unnecessary allocations for simple traversals.
//!
//! ## Minimal Requirements
//!
//! Each trait requires only what is necessary for its purpose, allowing different
//! graph implementations to provide only the capabilities they support.

use crate::utils::graph::NodeId;

/// Base trait providing core graph properties.
///
/// This trait defines the fundamental properties that all graphs must have:
/// the number of nodes and the ability to iterate over all node identifiers.
///
/// # Required Methods
///
/// - [`node_count`](GraphBase::node_count) - Returns the total number of nodes
/// - [`node_ids`](GraphBase::node_ids) - Returns an iterator over all node IDs
///
/// # Examples
///
/// ```rust,ignore
/// use dotscope::graph::{DirectedGraph, GraphBase};
///
/// let mut graph: DirectedGraph<&str, ()> = DirectedGraph::new();
/// graph.add_node("A");
/// graph.add_node("B");
///
/// assert_eq!(graph.node_count(), 2);
///
/// let ids: Vec<_> = graph.node_ids().collect();
/// assert_eq!(ids.len(), 2);
/// ```
pub trait GraphBase {
    /// Returns the number of nodes in the graph.
    ///
    /// This count includes all nodes that have been added to the graph,
    /// regardless of their connectivity.
    fn node_count(&self) -> usize;

    /// Returns an iterator over all node identifiers in the graph.
    ///
    /// The iteration order is typically the order in which nodes were added
    /// to the graph (i.e., by ascending `NodeId` index).
    fn node_ids(&self) -> impl Iterator<Item = NodeId>;
}

/// Trait for graphs that support forward edge traversal.
///
/// This trait provides access to the successor nodes of any given node,
/// enabling forward graph traversal and algorithms that follow edges in
/// their natural direction.
///
/// # Required Methods
///
/// - [`successors`](Successors::successors) - Returns an iterator over successor nodes
///
/// # Examples
///
/// ```rust,ignore
/// use dotscope::graph::{DirectedGraph, NodeId, Successors};
///
/// let mut graph: DirectedGraph<&str, ()> = DirectedGraph::new();
/// let a = graph.add_node("A");
/// let b = graph.add_node("B");
/// let c = graph.add_node("C");
///
/// graph.add_edge(a, b, ());
/// graph.add_edge(a, c, ());
///
/// let successors: Vec<NodeId> = graph.successors(a).collect();
/// assert_eq!(successors.len(), 2);
/// assert!(successors.contains(&b));
/// assert!(successors.contains(&c));
/// ```
pub trait Successors: GraphBase {
    /// Returns an iterator over the successor nodes of the given node.
    ///
    /// Successors are nodes that are targets of edges originating from the
    /// specified node. For a directed edge `(u, v)`, node `v` is a successor of `u`.
    ///
    /// # Arguments
    ///
    /// * `node` - The node whose successors to iterate
    ///
    /// # Returns
    ///
    /// An iterator yielding the `NodeId` of each successor node.
    ///
    /// # Panics
    ///
    /// May panic if `node` is not a valid node in the graph.
    fn successors(&self, node: NodeId) -> impl Iterator<Item = NodeId>;
}

/// Trait for graphs that support backward edge traversal.
///
/// This trait provides access to the predecessor nodes of any given node,
/// enabling backward graph traversal and algorithms that need to follow edges
/// in reverse.
///
/// # Required Methods
///
/// - [`predecessors`](Predecessors::predecessors) - Returns an iterator over predecessor nodes
///
/// # Examples
///
/// ```rust,ignore
/// use dotscope::graph::{DirectedGraph, NodeId, Predecessors};
///
/// let mut graph: DirectedGraph<&str, ()> = DirectedGraph::new();
/// let a = graph.add_node("A");
/// let b = graph.add_node("B");
/// let c = graph.add_node("C");
///
/// graph.add_edge(a, c, ());
/// graph.add_edge(b, c, ());
///
/// let predecessors: Vec<NodeId> = graph.predecessors(c).collect();
/// assert_eq!(predecessors.len(), 2);
/// assert!(predecessors.contains(&a));
/// assert!(predecessors.contains(&b));
/// ```
pub trait Predecessors: GraphBase {
    /// Returns an iterator over the predecessor nodes of the given node.
    ///
    /// Predecessors are nodes that are sources of edges targeting the
    /// specified node. For a directed edge `(u, v)`, node `u` is a predecessor of `v`.
    ///
    /// # Arguments
    ///
    /// * `node` - The node whose predecessors to iterate
    ///
    /// # Returns
    ///
    /// An iterator yielding the `NodeId` of each predecessor node.
    ///
    /// # Panics
    ///
    /// May panic if `node` is not a valid node in the graph.
    fn predecessors(&self, node: NodeId) -> impl Iterator<Item = NodeId>;
}

/// Trait for graphs with a designated entry (root) node.
///
/// This trait extends [`Successors`] and [`Predecessors`] to indicate that the
/// graph has a single distinguished entry point. This is essential for algorithms
/// like dominator computation that require a well-defined starting point.
///
/// # Required Methods
///
/// - [`entry`](RootedGraph::entry) - Returns the entry node of the graph
///
/// # Use Cases
///
/// - **Control Flow Graphs**: The entry node is the first basic block
/// - **Call Graphs**: The entry could be the main/entry point method
/// - **Dependency Graphs**: The entry represents the root dependency
///
/// # Examples
///
/// ```rust,ignore
/// use dotscope::graph::{DirectedGraph, NodeId, RootedGraph, Successors, Predecessors};
///
/// // Create a control flow graph with explicit entry
/// struct ControlFlowGraph {
///     graph: DirectedGraph<&'static str, ()>,
///     entry: NodeId,
/// }
///
/// impl dotscope::graph::GraphBase for ControlFlowGraph {
///     fn node_count(&self) -> usize { self.graph.node_count() }
///     fn node_ids(&self) -> impl Iterator<Item = NodeId> { self.graph.node_ids() }
/// }
///
/// impl Successors for ControlFlowGraph {
///     fn successors(&self, node: NodeId) -> impl Iterator<Item = NodeId> {
///         self.graph.successors(node)
///     }
/// }
///
/// impl Predecessors for ControlFlowGraph {
///     fn predecessors(&self, node: NodeId) -> impl Iterator<Item = NodeId> {
///         self.graph.predecessors(node)
///     }
/// }
///
/// impl RootedGraph for ControlFlowGraph {
///     fn entry(&self) -> NodeId { self.entry }
/// }
/// ```
pub trait RootedGraph: Successors + Predecessors {
    /// Returns the entry (root) node of the graph.
    ///
    /// The entry node is the designated starting point for forward traversals
    /// and the root for dominator tree computation. In a control flow graph,
    /// this is typically the first basic block of a function.
    ///
    /// # Returns
    ///
    /// The `NodeId` of the entry node.
    fn entry(&self) -> NodeId;
}

#[cfg(test)]
mod tests {
    use super::*;

    // A minimal test graph implementation for trait testing
    struct TestGraph {
        node_count: usize,
        edges: Vec<(NodeId, NodeId)>,
        entry: NodeId,
    }

    impl TestGraph {
        fn new(node_count: usize, edges: Vec<(NodeId, NodeId)>, entry: NodeId) -> Self {
            TestGraph {
                node_count,
                edges,
                entry,
            }
        }
    }

    impl GraphBase for TestGraph {
        fn node_count(&self) -> usize {
            self.node_count
        }

        fn node_ids(&self) -> impl Iterator<Item = NodeId> {
            (0..self.node_count).map(NodeId::new)
        }
    }

    impl Successors for TestGraph {
        fn successors(&self, node: NodeId) -> impl Iterator<Item = NodeId> {
            self.edges
                .iter()
                .filter(move |(src, _)| *src == node)
                .map(|(_, dst)| *dst)
        }
    }

    impl Predecessors for TestGraph {
        fn predecessors(&self, node: NodeId) -> impl Iterator<Item = NodeId> {
            self.edges
                .iter()
                .filter(move |(_, dst)| *dst == node)
                .map(|(src, _)| *src)
        }
    }

    impl RootedGraph for TestGraph {
        fn entry(&self) -> NodeId {
            self.entry
        }
    }

    #[test]
    fn test_graph_base() {
        let graph = TestGraph::new(5, vec![], NodeId::new(0));
        assert_eq!(graph.node_count(), 5);

        let ids: Vec<NodeId> = graph.node_ids().collect();
        assert_eq!(ids.len(), 5);
        assert_eq!(ids[0], NodeId::new(0));
        assert_eq!(ids[4], NodeId::new(4));
    }

    #[test]
    fn test_successors() {
        let edges = vec![
            (NodeId::new(0), NodeId::new(1)),
            (NodeId::new(0), NodeId::new(2)),
            (NodeId::new(1), NodeId::new(3)),
        ];
        let graph = TestGraph::new(4, edges, NodeId::new(0));

        let succ: Vec<NodeId> = graph.successors(NodeId::new(0)).collect();
        assert_eq!(succ.len(), 2);
        assert!(succ.contains(&NodeId::new(1)));
        assert!(succ.contains(&NodeId::new(2)));

        let succ: Vec<NodeId> = graph.successors(NodeId::new(1)).collect();
        assert_eq!(succ.len(), 1);
        assert!(succ.contains(&NodeId::new(3)));

        let succ: Vec<NodeId> = graph.successors(NodeId::new(3)).collect();
        assert!(succ.is_empty());
    }

    #[test]
    fn test_predecessors() {
        let edges = vec![
            (NodeId::new(0), NodeId::new(2)),
            (NodeId::new(1), NodeId::new(2)),
        ];
        let graph = TestGraph::new(3, edges, NodeId::new(0));

        let pred: Vec<NodeId> = graph.predecessors(NodeId::new(2)).collect();
        assert_eq!(pred.len(), 2);
        assert!(pred.contains(&NodeId::new(0)));
        assert!(pred.contains(&NodeId::new(1)));

        let pred: Vec<NodeId> = graph.predecessors(NodeId::new(0)).collect();
        assert!(pred.is_empty());
    }

    #[test]
    fn test_rooted_graph() {
        let graph = TestGraph::new(3, vec![], NodeId::new(1));
        assert_eq!(graph.entry(), NodeId::new(1));
    }
}
