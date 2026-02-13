//! Core directed graph implementation.
//!
//! This module provides [`DirectedGraph`], the primary graph data structure used
//! throughout the analysis infrastructure. The implementation uses adjacency lists
//! for efficient traversal while maintaining full edge data access.
//!
//! The graph supports both owned and borrowed node data through [`Cow`], enabling
//! zero-copy graph construction when nodes are borrowed from external storage.

use std::borrow::Cow;

use crate::{
    utils::graph::{
        edge::EdgeId,
        node::NodeId,
        traits::{GraphBase, Predecessors, Successors},
    },
    Error, Result,
};

/// Internal storage for edge data and endpoints.
#[derive(Debug, Clone)]
struct EdgeData<E> {
    /// Source node of the edge
    source: NodeId,
    /// Target node of the edge
    target: NodeId,
    /// User-provided edge data
    data: E,
}

/// A directed graph with typed node and edge data.
///
/// `DirectedGraph` provides a flexible, efficient graph implementation suitable for
/// program analysis tasks. It supports:
///
/// - Generic node data (`N`) - Store any data associated with each node
/// - Generic edge data (`E`) - Store any data associated with each edge
/// - Efficient adjacency queries via adjacency lists
/// - Both forward (successors) and backward (predecessors) traversal
/// - Borrowed or owned node storage via [`Cow`]
///
/// # Memory Layout
///
/// The graph uses separate storage for nodes and edges:
///
/// - Nodes are stored in a [`Cow`] slice, allowing borrowed or owned data
/// - Edges are stored in a contiguous vector indexed by `EdgeId`
/// - Adjacency lists (outgoing/incoming) store `EdgeId` references
///
/// This design provides O(1) node/edge access and efficient iteration.
///
/// # Lifetime Parameter
///
/// The `'a` lifetime parameter represents the lifetime of borrowed node data:
/// - Use `DirectedGraph<'static, N, E>` for owned graphs (nodes are `Cow::Owned`)
/// - Use `DirectedGraph<'a, N, E>` when borrowing nodes from external storage
///
/// # Thread Safety
///
/// `DirectedGraph<N, E>` is [`Send`] and [`Sync`] when both `N` and `E` are,
/// enabling safe concurrent read access after construction. The graph does not
/// support concurrent modification; build the graph single-threaded, then use
/// it immutably from multiple threads.
///
/// # Examples
///
/// ## Creating a Simple Graph
///
/// ```rust,ignore
/// use dotscope::graph::{DirectedGraph, NodeId, EdgeId};
///
/// let mut graph: DirectedGraph<&str, i32> = DirectedGraph::new();
///
/// // Add nodes
/// let a = graph.add_node("A");
/// let b = graph.add_node("B");
/// let c = graph.add_node("C");
///
/// // Add edges with weights
/// graph.add_edge(a, b, 10);
/// graph.add_edge(b, c, 20);
/// graph.add_edge(a, c, 30);
///
/// assert_eq!(graph.node_count(), 3);
/// assert_eq!(graph.edge_count(), 3);
/// ```
///
/// ## Traversing the Graph
///
/// ```rust,ignore
/// use dotscope::graph::{DirectedGraph, NodeId, Successors, Predecessors};
///
/// let mut graph: DirectedGraph<char, ()> = DirectedGraph::new();
/// let a = graph.add_node('A');
/// let b = graph.add_node('B');
/// let c = graph.add_node('C');
///
/// graph.add_edge(a, b, ());
/// graph.add_edge(a, c, ());
///
/// // Forward traversal: get successors of A
/// let successors: Vec<_> = graph.successors(a).collect();
/// assert_eq!(successors.len(), 2);
///
/// // Backward traversal: get predecessors of B
/// let predecessors: Vec<_> = graph.predecessors(b).collect();
/// assert_eq!(predecessors, vec![a]);
/// ```
#[derive(Debug, Clone)]
pub struct DirectedGraph<'a, N: Clone, E> {
    /// Node data storage (borrowed or owned)
    nodes: Cow<'a, [N]>,
    /// Edge data storage
    edges: Vec<EdgeData<E>>,
    /// Outgoing edges per node (adjacency list for successors)
    outgoing: Vec<Vec<EdgeId>>,
    /// Incoming edges per node (adjacency list for predecessors)
    incoming: Vec<Vec<EdgeId>>,
}

impl<N: Clone, E> Default for DirectedGraph<'static, N, E> {
    fn default() -> Self {
        Self::new()
    }
}

impl<N: Clone, E> DirectedGraph<'static, N, E> {
    /// Creates a new empty directed graph with owned storage.
    ///
    /// The graph starts with no nodes or edges. Use [`add_node`](Self::add_node)
    /// and [`add_edge`](Self::add_edge) to build up the graph structure.
    ///
    /// # Returns
    ///
    /// A new empty `DirectedGraph`.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::graph::DirectedGraph;
    ///
    /// let graph: DirectedGraph<String, ()> = DirectedGraph::new();
    /// assert!(graph.is_empty());
    /// ```
    #[must_use]
    pub fn new() -> Self {
        DirectedGraph {
            nodes: Cow::Owned(Vec::new()),
            edges: Vec::new(),
            outgoing: Vec::new(),
            incoming: Vec::new(),
        }
    }

    /// Creates a new directed graph with pre-allocated capacity.
    ///
    /// Pre-allocating capacity can improve performance when the approximate
    /// size of the graph is known in advance, by avoiding reallocations
    /// during construction.
    ///
    /// # Arguments
    ///
    /// * `node_capacity` - Expected number of nodes
    /// * `edge_capacity` - Expected number of edges
    ///
    /// # Returns
    ///
    /// A new empty `DirectedGraph` with pre-allocated storage.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::graph::DirectedGraph;
    ///
    /// // Pre-allocate for a graph with ~100 nodes and ~300 edges
    /// let graph: DirectedGraph<i32, ()> = DirectedGraph::with_capacity(100, 300);
    /// assert!(graph.is_empty());
    /// ```
    #[must_use]
    pub fn with_capacity(node_capacity: usize, edge_capacity: usize) -> Self {
        DirectedGraph {
            nodes: Cow::Owned(Vec::with_capacity(node_capacity)),
            edges: Vec::with_capacity(edge_capacity),
            outgoing: Vec::with_capacity(node_capacity),
            incoming: Vec::with_capacity(node_capacity),
        }
    }

    /// Adds a new node with the given data to the graph.
    ///
    /// The node is assigned the next sequential `NodeId`, starting from 0.
    /// The returned `NodeId` can be used to reference this node when adding
    /// edges or querying the graph.
    ///
    /// # Arguments
    ///
    /// * `data` - The data to associate with this node
    ///
    /// # Returns
    ///
    /// The `NodeId` assigned to the new node.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::graph::{DirectedGraph, NodeId};
    ///
    /// let mut graph: DirectedGraph<&str, ()> = DirectedGraph::new();
    ///
    /// let first = graph.add_node("first");
    /// let second = graph.add_node("second");
    ///
    /// assert_eq!(first, NodeId::new(0));
    /// assert_eq!(second, NodeId::new(1));
    /// assert_eq!(graph.node_count(), 2);
    /// ```
    pub fn add_node(&mut self, data: N) -> NodeId {
        let id = NodeId::new(self.nodes.len());
        self.nodes.to_mut().push(data);
        self.outgoing.push(Vec::new());
        self.incoming.push(Vec::new());
        id
    }

    /// Returns a mutable reference to the data associated with the given node.
    ///
    /// # Arguments
    ///
    /// * `node` - The node to look up
    ///
    /// # Returns
    ///
    /// `Some(&mut N)` if the node exists, `None` otherwise.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::graph::DirectedGraph;
    ///
    /// let mut graph: DirectedGraph<String, ()> = DirectedGraph::new();
    /// let node = graph.add_node(String::from("hello"));
    ///
    /// if let Some(data) = graph.node_mut(node) {
    ///     data.push_str(" world");
    /// }
    ///
    /// assert_eq!(graph.node(node), Some(&String::from("hello world")));
    /// ```
    pub fn node_mut(&mut self, node: NodeId) -> Option<&mut N> {
        self.nodes.to_mut().get_mut(node.index())
    }
}

/// Methods for creating graphs with borrowed node storage.
impl<'a, N: Clone, E> DirectedGraph<'a, N, E> {
    /// Creates a new directed graph borrowing nodes from an external slice.
    ///
    /// This enables zero-copy graph construction when nodes already exist
    /// in external storage (e.g., basic blocks from a method).
    ///
    /// The returned graph has borrowed node storage. Edges can still be added
    /// normally as they are always owned. To get an owned graph, use
    /// [`into_owned`](Self::into_owned).
    ///
    /// # Arguments
    ///
    /// * `nodes` - A slice of nodes to borrow
    ///
    /// # Returns
    ///
    /// A new `DirectedGraph` with borrowed nodes and empty adjacency lists.
    /// The caller must add edges separately.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::graph::DirectedGraph;
    ///
    /// let nodes = vec!["A", "B", "C"];
    /// let mut graph: DirectedGraph<&str, ()> = DirectedGraph::from_nodes_borrowed(&nodes);
    ///
    /// // Add edges
    /// graph.add_edge(NodeId::new(0), NodeId::new(1), ())?;
    /// ```
    #[must_use]
    pub fn from_nodes_borrowed(nodes: &'a [N]) -> Self {
        let node_count = nodes.len();
        DirectedGraph {
            nodes: Cow::Borrowed(nodes),
            edges: Vec::new(),
            outgoing: vec![Vec::new(); node_count],
            incoming: vec![Vec::new(); node_count],
        }
    }

    /// Converts this graph into an owned graph with `'static` lifetime.
    ///
    /// If the nodes are already owned, this is efficient. If borrowed,
    /// this clones the node data.
    ///
    /// # Returns
    ///
    /// An owned `DirectedGraph<'static, N, E>`.
    #[must_use]
    pub fn into_owned(self) -> DirectedGraph<'static, N, E> {
        DirectedGraph {
            nodes: Cow::Owned(self.nodes.into_owned()),
            edges: self.edges,
            outgoing: self.outgoing,
            incoming: self.incoming,
        }
    }

    /// Returns `true` if the graph owns its node data.
    ///
    /// Returns `false` if nodes are borrowed from external storage.
    #[must_use]
    pub fn is_owned(&self) -> bool {
        matches!(self.nodes, Cow::Owned(_))
    }

    /// Returns a reference to the data associated with the given node.
    ///
    /// # Arguments
    ///
    /// * `node` - The node to look up
    ///
    /// # Returns
    ///
    /// `Some(&N)` if the node exists, `None` otherwise.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::graph::DirectedGraph;
    ///
    /// let mut graph: DirectedGraph<&str, ()> = DirectedGraph::new();
    /// let node = graph.add_node("hello");
    ///
    /// assert_eq!(graph.node(node), Some(&"hello"));
    /// ```
    #[must_use]
    pub fn node(&self, node: NodeId) -> Option<&N> {
        self.nodes.get(node.index())
    }

    /// Returns the number of nodes in the graph.
    ///
    /// # Returns
    ///
    /// The total node count.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::graph::DirectedGraph;
    ///
    /// let mut graph: DirectedGraph<i32, ()> = DirectedGraph::new();
    /// assert_eq!(graph.node_count(), 0);
    ///
    /// graph.add_node(1);
    /// graph.add_node(2);
    /// assert_eq!(graph.node_count(), 2);
    /// ```
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Returns an iterator over all node identifiers in the graph.
    ///
    /// Nodes are yielded in the order they were added (ascending `NodeId`).
    ///
    /// # Returns
    ///
    /// An iterator yielding each `NodeId` in the graph.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::graph::{DirectedGraph, NodeId};
    ///
    /// let mut graph: DirectedGraph<char, ()> = DirectedGraph::new();
    /// graph.add_node('A');
    /// graph.add_node('B');
    /// graph.add_node('C');
    ///
    /// let ids: Vec<NodeId> = graph.node_ids().collect();
    /// assert_eq!(ids, vec![NodeId::new(0), NodeId::new(1), NodeId::new(2)]);
    /// ```
    pub fn node_ids(&self) -> impl Iterator<Item = NodeId> + '_ {
        (0..self.nodes.len()).map(NodeId::new)
    }

    /// Returns an iterator over all nodes with their identifiers.
    ///
    /// This is useful when you need both the node data and its identifier.
    ///
    /// # Returns
    ///
    /// An iterator yielding `(NodeId, &N)` tuples.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::graph::DirectedGraph;
    ///
    /// let mut graph: DirectedGraph<&str, ()> = DirectedGraph::new();
    /// graph.add_node("first");
    /// graph.add_node("second");
    ///
    /// for (id, data) in graph.nodes() {
    ///     println!("{}: {}", id, data);
    /// }
    /// ```
    pub fn nodes(&self) -> impl Iterator<Item = (NodeId, &N)> + '_ {
        self.nodes
            .iter()
            .enumerate()
            .map(|(i, data)| (NodeId::new(i), data))
    }

    /// Adds a directed edge from `source` to `target` with the given data.
    ///
    /// The edge is assigned the next sequential `EdgeId`, starting from 0.
    /// Multiple edges between the same pair of nodes are allowed (multigraph).
    ///
    /// # Arguments
    ///
    /// * `source` - The source node of the edge
    /// * `target` - The target node of the edge
    /// * `data` - The data to associate with this edge
    ///
    /// # Returns
    ///
    /// The `EdgeId` assigned to the new edge.
    ///
    /// # Panics
    ///
    /// Panics if either `source` or `target` is not a valid node in the graph.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::graph::{DirectedGraph, EdgeId};
    ///
    /// let mut graph: DirectedGraph<&str, &str> = DirectedGraph::new();
    /// let a = graph.add_node("A");
    /// let b = graph.add_node("B");
    ///
    /// let edge = graph.add_edge(a, b, "A->B")?;
    /// assert_eq!(edge, EdgeId::new(0));
    /// assert_eq!(graph.edge_count(), 1);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`Error::GraphError`] if either `source` or `target` node does not exist
    /// in the graph.
    pub fn add_edge(&mut self, source: NodeId, target: NodeId, data: E) -> Result<EdgeId> {
        if source.index() >= self.nodes.len() {
            return Err(Error::GraphError(format!(
                "source node {} does not exist in graph with {} nodes",
                source,
                self.nodes.len()
            )));
        }
        if target.index() >= self.nodes.len() {
            return Err(Error::GraphError(format!(
                "target node {} does not exist in graph with {} nodes",
                target,
                self.nodes.len()
            )));
        }

        let id = EdgeId::new(self.edges.len());
        self.edges.push(EdgeData {
            source,
            target,
            data,
        });

        self.outgoing[source.index()].push(id);
        self.incoming[target.index()].push(id);

        Ok(id)
    }

    /// Returns a reference to the data associated with the given edge.
    ///
    /// # Arguments
    ///
    /// * `edge` - The edge to look up
    ///
    /// # Returns
    ///
    /// `Some(&E)` if the edge exists, `None` otherwise.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::graph::DirectedGraph;
    ///
    /// let mut graph: DirectedGraph<(), &str> = DirectedGraph::new();
    /// let a = graph.add_node(());
    /// let b = graph.add_node(());
    /// let edge = graph.add_edge(a, b, "label");
    ///
    /// assert_eq!(graph.edge(edge), Some(&"label"));
    /// ```
    #[must_use]
    pub fn edge(&self, edge: EdgeId) -> Option<&E> {
        self.edges.get(edge.index()).map(|e| &e.data)
    }

    /// Returns a mutable reference to the data associated with the given edge.
    ///
    /// # Arguments
    ///
    /// * `edge` - The edge to look up
    ///
    /// # Returns
    ///
    /// `Some(&mut E)` if the edge exists, `None` otherwise.
    pub fn edge_mut(&mut self, edge: EdgeId) -> Option<&mut E> {
        self.edges.get_mut(edge.index()).map(|e| &mut e.data)
    }

    /// Returns the source and target nodes of the given edge.
    ///
    /// # Arguments
    ///
    /// * `edge` - The edge to look up
    ///
    /// # Returns
    ///
    /// `Some((source, target))` if the edge exists, `None` otherwise.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::graph::DirectedGraph;
    ///
    /// let mut graph: DirectedGraph<&str, ()> = DirectedGraph::new();
    /// let a = graph.add_node("A");
    /// let b = graph.add_node("B");
    /// let edge = graph.add_edge(a, b, ());
    ///
    /// assert_eq!(graph.edge_endpoints(edge), Some((a, b)));
    /// ```
    #[must_use]
    pub fn edge_endpoints(&self, edge: EdgeId) -> Option<(NodeId, NodeId)> {
        self.edges.get(edge.index()).map(|e| (e.source, e.target))
    }

    /// Returns the number of edges in the graph.
    ///
    /// # Returns
    ///
    /// The total edge count.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::graph::DirectedGraph;
    ///
    /// let mut graph: DirectedGraph<(), ()> = DirectedGraph::new();
    /// let a = graph.add_node(());
    /// let b = graph.add_node(());
    ///
    /// assert_eq!(graph.edge_count(), 0);
    ///
    /// graph.add_edge(a, b, ());
    /// assert_eq!(graph.edge_count(), 1);
    /// ```
    #[must_use]
    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    /// Returns an iterator over all edge identifiers in the graph.
    ///
    /// Edges are yielded in the order they were added (ascending `EdgeId`).
    ///
    /// # Returns
    ///
    /// An iterator yielding each `EdgeId` in the graph.
    pub fn edge_ids(&self) -> impl Iterator<Item = EdgeId> + '_ {
        (0..self.edges.len()).map(EdgeId::new)
    }

    /// Returns an iterator over all edges with their identifiers.
    ///
    /// # Returns
    ///
    /// An iterator yielding `(EdgeId, &E)` tuples.
    pub fn edges(&self) -> impl Iterator<Item = (EdgeId, &E)> + '_ {
        self.edges
            .iter()
            .enumerate()
            .map(|(i, e)| (EdgeId::new(i), &e.data))
    }

    /// Returns an iterator over the successors of the given node.
    ///
    /// Successors are nodes that are targets of edges originating from this node.
    ///
    /// # Arguments
    ///
    /// * `node` - The node whose successors to iterate
    ///
    /// # Returns
    ///
    /// An iterator yielding the `NodeId` of each successor.
    ///
    /// # Panics
    ///
    /// Panics if `node` is not a valid node in the graph.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::graph::{DirectedGraph, NodeId};
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
    /// ```
    pub fn successors(&self, node: NodeId) -> impl Iterator<Item = NodeId> + '_ {
        self.outgoing[node.index()]
            .iter()
            .map(|&edge_id| self.edges[edge_id.index()].target)
    }

    /// Returns an iterator over the predecessors of the given node.
    ///
    /// Predecessors are nodes that are sources of edges targeting this node.
    ///
    /// # Arguments
    ///
    /// * `node` - The node whose predecessors to iterate
    ///
    /// # Returns
    ///
    /// An iterator yielding the `NodeId` of each predecessor.
    ///
    /// # Panics
    ///
    /// Panics if `node` is not a valid node in the graph.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::graph::{DirectedGraph, NodeId};
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
    /// ```
    pub fn predecessors(&self, node: NodeId) -> impl Iterator<Item = NodeId> + '_ {
        self.incoming[node.index()]
            .iter()
            .map(|&edge_id| self.edges[edge_id.index()].source)
    }

    /// Returns an iterator over outgoing edges from the given node.
    ///
    /// This provides access to both the edge ID and edge data for more detailed
    /// edge inspection than [`successors`](Self::successors).
    ///
    /// # Arguments
    ///
    /// * `node` - The node whose outgoing edges to iterate
    ///
    /// # Returns
    ///
    /// An iterator yielding `(EdgeId, &E)` tuples for each outgoing edge.
    ///
    /// # Panics
    ///
    /// Panics if `node` is not a valid node in the graph.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::graph::DirectedGraph;
    ///
    /// let mut graph: DirectedGraph<&str, i32> = DirectedGraph::new();
    /// let a = graph.add_node("A");
    /// let b = graph.add_node("B");
    ///
    /// graph.add_edge(a, b, 42);
    ///
    /// for (edge_id, weight) in graph.outgoing_edges(a) {
    ///     println!("Edge {} has weight {}", edge_id, weight);
    /// }
    /// ```
    pub fn outgoing_edges(&self, node: NodeId) -> impl Iterator<Item = (EdgeId, &E)> + '_ {
        self.outgoing[node.index()]
            .iter()
            .map(|&edge_id| (edge_id, &self.edges[edge_id.index()].data))
    }

    /// Returns an iterator over incoming edges to the given node.
    ///
    /// This provides access to both the edge ID and edge data for more detailed
    /// edge inspection than [`predecessors`](Self::predecessors).
    ///
    /// # Arguments
    ///
    /// * `node` - The node whose incoming edges to iterate
    ///
    /// # Returns
    ///
    /// An iterator yielding `(EdgeId, &E)` tuples for each incoming edge.
    ///
    /// # Panics
    ///
    /// Panics if `node` is not a valid node in the graph.
    pub fn incoming_edges(&self, node: NodeId) -> impl Iterator<Item = (EdgeId, &E)> + '_ {
        self.incoming[node.index()]
            .iter()
            .map(|&edge_id| (edge_id, &self.edges[edge_id.index()].data))
    }

    /// Returns the out-degree (number of outgoing edges) of a node.
    ///
    /// # Arguments
    ///
    /// * `node` - The node to query
    ///
    /// # Returns
    ///
    /// The number of outgoing edges from this node.
    ///
    /// # Panics
    ///
    /// Panics if `node` is not a valid node in the graph.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::graph::DirectedGraph;
    ///
    /// let mut graph: DirectedGraph<(), ()> = DirectedGraph::new();
    /// let a = graph.add_node(());
    /// let b = graph.add_node(());
    /// let c = graph.add_node(());
    ///
    /// graph.add_edge(a, b, ());
    /// graph.add_edge(a, c, ());
    ///
    /// assert_eq!(graph.out_degree(a), 2);
    /// assert_eq!(graph.out_degree(b), 0);
    /// ```
    #[must_use]
    pub fn out_degree(&self, node: NodeId) -> usize {
        self.outgoing[node.index()].len()
    }

    /// Returns the in-degree (number of incoming edges) of a node.
    ///
    /// # Arguments
    ///
    /// * `node` - The node to query
    ///
    /// # Returns
    ///
    /// The number of incoming edges to this node.
    ///
    /// # Panics
    ///
    /// Panics if `node` is not a valid node in the graph.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::graph::DirectedGraph;
    ///
    /// let mut graph: DirectedGraph<(), ()> = DirectedGraph::new();
    /// let a = graph.add_node(());
    /// let b = graph.add_node(());
    /// let c = graph.add_node(());
    ///
    /// graph.add_edge(a, c, ());
    /// graph.add_edge(b, c, ());
    ///
    /// assert_eq!(graph.in_degree(c), 2);
    /// assert_eq!(graph.in_degree(a), 0);
    /// ```
    #[must_use]
    pub fn in_degree(&self, node: NodeId) -> usize {
        self.incoming[node.index()].len()
    }

    /// Returns `true` if the graph contains no nodes.
    ///
    /// # Returns
    ///
    /// `true` if the graph has zero nodes, `false` otherwise.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::graph::DirectedGraph;
    ///
    /// let mut graph: DirectedGraph<(), ()> = DirectedGraph::new();
    /// assert!(graph.is_empty());
    ///
    /// graph.add_node(());
    /// assert!(!graph.is_empty());
    /// ```
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Returns an iterator over entry nodes (nodes with no incoming edges).
    ///
    /// Entry nodes have in-degree of zero and are potential starting points
    /// for graph traversal.
    ///
    /// # Returns
    ///
    /// An iterator yielding the `NodeId` of each entry node.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::graph::{DirectedGraph, NodeId};
    ///
    /// let mut graph: DirectedGraph<&str, ()> = DirectedGraph::new();
    /// let a = graph.add_node("A");
    /// let b = graph.add_node("B");
    /// let c = graph.add_node("C");
    ///
    /// graph.add_edge(a, b, ());
    /// graph.add_edge(a, c, ());
    ///
    /// let entries: Vec<NodeId> = graph.entry_nodes().collect();
    /// assert_eq!(entries, vec![a]);
    /// ```
    pub fn entry_nodes(&self) -> impl Iterator<Item = NodeId> + '_ {
        self.node_ids().filter(|&node| self.in_degree(node) == 0)
    }

    /// Returns an iterator over exit nodes (nodes with no outgoing edges).
    ///
    /// Exit nodes have out-degree of zero and represent terminal points
    /// in the graph.
    ///
    /// # Returns
    ///
    /// An iterator yielding the `NodeId` of each exit node.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::graph::{DirectedGraph, NodeId};
    ///
    /// let mut graph: DirectedGraph<&str, ()> = DirectedGraph::new();
    /// let a = graph.add_node("A");
    /// let b = graph.add_node("B");
    /// let c = graph.add_node("C");
    ///
    /// graph.add_edge(a, b, ());
    /// graph.add_edge(a, c, ());
    ///
    /// let exits: Vec<NodeId> = graph.exit_nodes().collect();
    /// assert_eq!(exits.len(), 2);
    /// assert!(exits.contains(&b));
    /// assert!(exits.contains(&c));
    /// ```
    pub fn exit_nodes(&self) -> impl Iterator<Item = NodeId> + '_ {
        self.node_ids().filter(|&node| self.out_degree(node) == 0)
    }

    /// Checks if the given node ID is valid for this graph.
    ///
    /// # Arguments
    ///
    /// * `node` - The node ID to check
    ///
    /// # Returns
    ///
    /// `true` if the node exists in the graph, `false` otherwise.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::graph::{DirectedGraph, NodeId};
    ///
    /// let mut graph: DirectedGraph<(), ()> = DirectedGraph::new();
    /// let a = graph.add_node(());
    ///
    /// assert!(graph.contains_node(a));
    /// assert!(!graph.contains_node(NodeId::new(999)));
    /// ```
    #[must_use]
    pub fn contains_node(&self, node: NodeId) -> bool {
        node.index() < self.nodes.len()
    }

    /// Checks if the given edge ID is valid for this graph.
    ///
    /// # Arguments
    ///
    /// * `edge` - The edge ID to check
    ///
    /// # Returns
    ///
    /// `true` if the edge exists in the graph, `false` otherwise.
    #[must_use]
    pub fn contains_edge(&self, edge: EdgeId) -> bool {
        edge.index() < self.edges.len()
    }
}

// Implement the GraphBase trait
impl<N: Clone, E> GraphBase for DirectedGraph<'_, N, E> {
    fn node_count(&self) -> usize {
        self.nodes.len()
    }

    fn node_ids(&self) -> impl Iterator<Item = NodeId> {
        (0..self.nodes.len()).map(NodeId::new)
    }
}

// Implement the Successors trait
impl<N: Clone, E> Successors for DirectedGraph<'_, N, E> {
    fn successors(&self, node: NodeId) -> impl Iterator<Item = NodeId> {
        self.outgoing[node.index()]
            .iter()
            .map(|&edge_id| self.edges[edge_id.index()].target)
    }
}

// Implement the Predecessors trait
impl<N: Clone, E> Predecessors for DirectedGraph<'_, N, E> {
    fn predecessors(&self, node: NodeId) -> impl Iterator<Item = NodeId> {
        self.incoming[node.index()]
            .iter()
            .map(|&edge_id| self.edges[edge_id.index()].source)
    }
}

#[cfg(test)]
mod tests {
    use crate::utils::graph::{
        directed::DirectedGraph,
        edge::EdgeId,
        node::NodeId,
        traits::{GraphBase, Predecessors, Successors},
    };

    /// Creates a simple linear graph: A -> B -> C
    fn create_linear_graph() -> DirectedGraph<'static, &'static str, ()> {
        let mut graph = DirectedGraph::new();
        let a = graph.add_node("A");
        let b = graph.add_node("B");
        let c = graph.add_node("C");
        graph.add_edge(a, b, ()).unwrap();
        graph.add_edge(b, c, ()).unwrap();
        graph
    }

    /// Creates a diamond graph: A -> B, A -> C, B -> D, C -> D
    fn create_diamond_graph() -> DirectedGraph<'static, &'static str, ()> {
        let mut graph = DirectedGraph::new();
        let a = graph.add_node("A");
        let b = graph.add_node("B");
        let c = graph.add_node("C");
        let d = graph.add_node("D");
        graph.add_edge(a, b, ()).unwrap();
        graph.add_edge(a, c, ()).unwrap();
        graph.add_edge(b, d, ()).unwrap();
        graph.add_edge(c, d, ()).unwrap();
        graph
    }

    /// Creates a graph with a cycle: A -> B -> C -> A
    fn create_cycle_graph() -> DirectedGraph<'static, &'static str, ()> {
        let mut graph = DirectedGraph::new();
        let a = graph.add_node("A");
        let b = graph.add_node("B");
        let c = graph.add_node("C");
        graph.add_edge(a, b, ()).unwrap();
        graph.add_edge(b, c, ()).unwrap();
        graph.add_edge(c, a, ()).unwrap();
        graph
    }

    #[test]
    fn test_new_graph_is_empty() {
        let graph: DirectedGraph<(), ()> = DirectedGraph::new();
        assert!(graph.is_empty());
        assert_eq!(graph.node_count(), 0);
        assert_eq!(graph.edge_count(), 0);
    }

    #[test]
    fn test_with_capacity() {
        let graph: DirectedGraph<i32, i32> = DirectedGraph::with_capacity(100, 200);
        assert!(graph.is_empty());
        // Capacity is internal; just verify it works
    }

    #[test]
    fn test_default() {
        let graph: DirectedGraph<(), ()> = DirectedGraph::default();
        assert!(graph.is_empty());
    }

    #[test]
    fn test_add_node() {
        let mut graph: DirectedGraph<&str, ()> = DirectedGraph::new();

        let a = graph.add_node("A");
        assert_eq!(a, NodeId::new(0));
        assert_eq!(graph.node_count(), 1);

        let b = graph.add_node("B");
        assert_eq!(b, NodeId::new(1));
        assert_eq!(graph.node_count(), 2);
    }

    #[test]
    fn test_node_access() {
        let mut graph: DirectedGraph<&str, ()> = DirectedGraph::new();
        let a = graph.add_node("hello");

        assert_eq!(graph.node(a), Some(&"hello"));
        assert_eq!(graph.node(NodeId::new(999)), None);
    }

    #[test]
    fn test_node_mut() {
        let mut graph: DirectedGraph<String, ()> = DirectedGraph::new();
        let a = graph.add_node(String::from("hello"));

        if let Some(data) = graph.node_mut(a) {
            data.push_str(" world");
        }

        assert_eq!(graph.node(a), Some(&String::from("hello world")));
    }

    #[test]
    fn test_node_ids_iterator() {
        let mut graph: DirectedGraph<char, ()> = DirectedGraph::new();
        graph.add_node('A');
        graph.add_node('B');
        graph.add_node('C');

        let ids: Vec<NodeId> = graph.node_ids().collect();
        assert_eq!(ids, vec![NodeId::new(0), NodeId::new(1), NodeId::new(2)]);
    }

    #[test]
    fn test_nodes_iterator() {
        let mut graph: DirectedGraph<&str, ()> = DirectedGraph::new();
        graph.add_node("A");
        graph.add_node("B");

        let nodes: Vec<(NodeId, &&str)> = graph.nodes().collect();
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0], (NodeId::new(0), &"A"));
        assert_eq!(nodes[1], (NodeId::new(1), &"B"));
    }

    #[test]
    fn test_add_edge() {
        let mut graph: DirectedGraph<&str, &str> = DirectedGraph::new();
        let a = graph.add_node("A");
        let b = graph.add_node("B");

        let edge = graph.add_edge(a, b, "A->B").unwrap();
        assert_eq!(edge, EdgeId::new(0));
        assert_eq!(graph.edge_count(), 1);
    }

    #[test]
    fn test_edge_access() {
        let mut graph: DirectedGraph<(), &str> = DirectedGraph::new();
        let a = graph.add_node(());
        let b = graph.add_node(());
        let edge = graph.add_edge(a, b, "label").unwrap();

        assert_eq!(graph.edge(edge), Some(&"label"));
        assert_eq!(graph.edge(EdgeId::new(999)), None);
    }

    #[test]
    fn test_edge_endpoints() {
        let mut graph: DirectedGraph<&str, ()> = DirectedGraph::new();
        let a = graph.add_node("A");
        let b = graph.add_node("B");
        let edge = graph.add_edge(a, b, ()).unwrap();

        assert_eq!(graph.edge_endpoints(edge), Some((a, b)));
        assert_eq!(graph.edge_endpoints(EdgeId::new(999)), None);
    }

    #[test]
    fn test_multiple_edges() {
        let mut graph: DirectedGraph<&str, i32> = DirectedGraph::new();
        let a = graph.add_node("A");
        let b = graph.add_node("B");

        // Allow multiple edges between same nodes (multigraph)
        let e1 = graph.add_edge(a, b, 1).unwrap();
        let e2 = graph.add_edge(a, b, 2).unwrap();

        assert_eq!(graph.edge_count(), 2);
        assert_eq!(graph.edge(e1), Some(&1));
        assert_eq!(graph.edge(e2), Some(&2));
    }

    #[test]
    fn test_self_loop() {
        let mut graph: DirectedGraph<&str, ()> = DirectedGraph::new();
        let a = graph.add_node("A");

        let edge = graph.add_edge(a, a, ()).unwrap();
        assert_eq!(graph.edge_endpoints(edge), Some((a, a)));
        assert_eq!(graph.out_degree(a), 1);
        assert_eq!(graph.in_degree(a), 1);
    }

    #[test]
    fn test_add_edge_invalid_source() {
        let mut graph: DirectedGraph<(), ()> = DirectedGraph::new();
        let a = graph.add_node(());
        let result = graph.add_edge(NodeId::new(999), a, ());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("source node"));
    }

    #[test]
    fn test_add_edge_invalid_target() {
        let mut graph: DirectedGraph<(), ()> = DirectedGraph::new();
        let a = graph.add_node(());
        let result = graph.add_edge(a, NodeId::new(999), ());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("target node"));
    }

    #[test]
    fn test_successors() {
        let graph = create_diamond_graph();
        let a = NodeId::new(0);

        let successors: Vec<NodeId> = graph.successors(a).collect();
        assert_eq!(successors.len(), 2);
        assert!(successors.contains(&NodeId::new(1))); // B
        assert!(successors.contains(&NodeId::new(2))); // C
    }

    #[test]
    fn test_predecessors() {
        let graph = create_diamond_graph();
        let d = NodeId::new(3);

        let predecessors: Vec<NodeId> = graph.predecessors(d).collect();
        assert_eq!(predecessors.len(), 2);
        assert!(predecessors.contains(&NodeId::new(1))); // B
        assert!(predecessors.contains(&NodeId::new(2))); // C
    }

    #[test]
    fn test_outgoing_edges() {
        let mut graph: DirectedGraph<&str, i32> = DirectedGraph::new();
        let a = graph.add_node("A");
        let b = graph.add_node("B");
        let c = graph.add_node("C");

        graph.add_edge(a, b, 10).unwrap();
        graph.add_edge(a, c, 20).unwrap();

        let outgoing: Vec<(EdgeId, &i32)> = graph.outgoing_edges(a).collect();
        assert_eq!(outgoing.len(), 2);

        let weights: Vec<i32> = outgoing.iter().map(|(_, &w)| w).collect();
        assert!(weights.contains(&10));
        assert!(weights.contains(&20));
    }

    #[test]
    fn test_incoming_edges() {
        let mut graph: DirectedGraph<&str, i32> = DirectedGraph::new();
        let a = graph.add_node("A");
        let b = graph.add_node("B");
        let c = graph.add_node("C");

        graph.add_edge(a, c, 10).unwrap();
        graph.add_edge(b, c, 20).unwrap();

        let incoming: Vec<(EdgeId, &i32)> = graph.incoming_edges(c).collect();
        assert_eq!(incoming.len(), 2);
    }

    #[test]
    fn test_out_degree() {
        let graph = create_diamond_graph();

        assert_eq!(graph.out_degree(NodeId::new(0)), 2); // A has 2 outgoing
        assert_eq!(graph.out_degree(NodeId::new(1)), 1); // B has 1 outgoing
        assert_eq!(graph.out_degree(NodeId::new(3)), 0); // D has 0 outgoing
    }

    #[test]
    fn test_in_degree() {
        let graph = create_diamond_graph();

        assert_eq!(graph.in_degree(NodeId::new(0)), 0); // A has 0 incoming
        assert_eq!(graph.in_degree(NodeId::new(1)), 1); // B has 1 incoming
        assert_eq!(graph.in_degree(NodeId::new(3)), 2); // D has 2 incoming
    }

    #[test]
    fn test_entry_nodes() {
        let graph = create_diamond_graph();
        let entries: Vec<NodeId> = graph.entry_nodes().collect();

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0], NodeId::new(0)); // Only A is entry
    }

    #[test]
    fn test_exit_nodes() {
        let graph = create_diamond_graph();
        let exits: Vec<NodeId> = graph.exit_nodes().collect();

        assert_eq!(exits.len(), 1);
        assert_eq!(exits[0], NodeId::new(3)); // Only D is exit
    }

    #[test]
    fn test_entry_nodes_with_cycle() {
        let graph = create_cycle_graph();
        let entries: Vec<NodeId> = graph.entry_nodes().collect();

        // No entry nodes in a pure cycle
        assert!(entries.is_empty());
    }

    #[test]
    fn test_contains_node() {
        let mut graph: DirectedGraph<(), ()> = DirectedGraph::new();
        let a = graph.add_node(());

        assert!(graph.contains_node(a));
        assert!(!graph.contains_node(NodeId::new(999)));
    }

    #[test]
    fn test_contains_edge() {
        let mut graph: DirectedGraph<(), ()> = DirectedGraph::new();
        let a = graph.add_node(());
        let b = graph.add_node(());
        let edge = graph.add_edge(a, b, ()).unwrap();

        assert!(graph.contains_edge(edge));
        assert!(!graph.contains_edge(EdgeId::new(999)));
    }

    #[test]
    fn test_graph_clone() {
        let original = create_diamond_graph();
        let cloned = original.clone();

        assert_eq!(original.node_count(), cloned.node_count());
        assert_eq!(original.edge_count(), cloned.edge_count());

        // Verify data is independent
        for node_id in original.node_ids() {
            assert_eq!(original.node(node_id), cloned.node(node_id));
        }
    }

    #[test]
    fn test_graph_base_trait() {
        fn use_graph_base<G: GraphBase>(g: &G) -> usize {
            g.node_count()
        }

        let graph = create_linear_graph();
        assert_eq!(use_graph_base(&graph), 3);
    }

    #[test]
    fn test_successors_trait() {
        fn use_successors<G: Successors>(g: &G, node: NodeId) -> Vec<NodeId> {
            g.successors(node).collect()
        }

        let graph = create_linear_graph();
        let successors = use_successors(&graph, NodeId::new(0));
        assert_eq!(successors, vec![NodeId::new(1)]);
    }

    #[test]
    fn test_predecessors_trait() {
        fn use_predecessors<G: Predecessors>(g: &G, node: NodeId) -> Vec<NodeId> {
            g.predecessors(node).collect()
        }

        let graph = create_linear_graph();
        let predecessors = use_predecessors(&graph, NodeId::new(2));
        assert_eq!(predecessors, vec![NodeId::new(1)]);
    }

    #[test]
    fn test_large_graph() {
        let mut graph: DirectedGraph<usize, ()> = DirectedGraph::with_capacity(1000, 2000);

        // Create 1000 nodes
        for i in 0..1000 {
            graph.add_node(i);
        }

        // Create edges: each node points to next
        for i in 0..999 {
            graph
                .add_edge(NodeId::new(i), NodeId::new(i + 1), ())
                .unwrap();
        }

        assert_eq!(graph.node_count(), 1000);
        assert_eq!(graph.edge_count(), 999);

        // Check first and last
        assert_eq!(graph.out_degree(NodeId::new(0)), 1);
        assert_eq!(graph.out_degree(NodeId::new(999)), 0);
        assert_eq!(graph.in_degree(NodeId::new(0)), 0);
        assert_eq!(graph.in_degree(NodeId::new(999)), 1);
    }
}
