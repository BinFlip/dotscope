//! Generic directed graph infrastructure for program analysis.
//!
//! This module provides a reusable directed graph implementation designed for
//! program analysis tasks such as control flow graphs, call graphs, and dependency
//! analysis. The implementation prioritizes correctness, clear semantics, and
//! efficient algorithms over raw performance.
//!
//! # Architecture
//!
//! The graph module is organized into several components:
//!
//! - **Core Types**: [`NodeId`], [`EdgeId`], and [`DirectedGraph`] provide the fundamental
//!   building blocks for graph representation
//! - **Algorithms**: Standard graph algorithms for traversal, dominator computation,
//!   topological sorting, and cycle detection
//! - **Traits**: Abstraction traits enabling algorithms to work with different graph types
//!
//! # Design Principles
//!
//! ## Strongly-Typed Identifiers
//!
//! Node and edge identifiers use newtype wrappers to prevent accidental mixing of
//! indices and provide type safety at compile time.
//!
//! ## Immutable After Construction
//!
//! Graphs are designed to be built incrementally during construction, then treated
//! as immutable for analysis. This enables safe concurrent access without locks.
//!
//! ## Thread Safety
//!
//! All graph types are [`Send`] and [`Sync`] when their node and edge data types are,
//! enabling safe concurrent analysis across multiple threads.
//!
//! # Key Components
//!
//! - [`NodeId`] - Strongly-typed node identifier
//! - [`EdgeId`] - Strongly-typed edge identifier
//! - [`DirectedGraph`] - Core directed graph implementation with adjacency lists
//! - [`algorithms`] - Graph algorithms (traversal, dominators, SCC, etc.)
//!
//! # Usage Examples
//!
//! ## Creating a Simple Graph
//!
//! ```rust,ignore
//! use dotscope::graph::{DirectedGraph, NodeId};
//!
//! // Create a diamond-shaped graph: A -> B, A -> C, B -> D, C -> D
//! let mut graph: DirectedGraph<&str, &str> = DirectedGraph::new();
//!
//! let a = graph.add_node("A");
//! let b = graph.add_node("B");
//! let c = graph.add_node("C");
//! let d = graph.add_node("D");
//!
//! graph.add_edge(a, b, "A->B");
//! graph.add_edge(a, c, "A->C");
//! graph.add_edge(b, d, "B->D");
//! graph.add_edge(c, d, "C->D");
//!
//! assert_eq!(graph.node_count(), 4);
//! assert_eq!(graph.edge_count(), 4);
//! ```
//!
//! ## Traversing a Graph
//!
//! ```rust,ignore
//! use dotscope::graph::{DirectedGraph, NodeId, algorithms};
//!
//! let mut graph: DirectedGraph<&str, ()> = DirectedGraph::new();
//! let a = graph.add_node("A");
//! let b = graph.add_node("B");
//! let c = graph.add_node("C");
//! graph.add_edge(a, b, ());
//! graph.add_edge(b, c, ());
//!
//! // Depth-first traversal
//! let dfs_order: Vec<NodeId> = algorithms::dfs(&graph, a).collect();
//! assert_eq!(dfs_order.len(), 3);
//! ```
//!
//! ## Computing Dominators
//!
//! ```rust,ignore
//! use dotscope::graph::{DirectedGraph, NodeId, algorithms};
//!
//! let mut graph: DirectedGraph<&str, ()> = DirectedGraph::new();
//! let entry = graph.add_node("entry");
//! let a = graph.add_node("A");
//! let b = graph.add_node("B");
//! let exit = graph.add_node("exit");
//!
//! graph.add_edge(entry, a, ());
//! graph.add_edge(entry, b, ());
//! graph.add_edge(a, exit, ());
//! graph.add_edge(b, exit, ());
//!
//! let dominators = algorithms::compute_dominators(&graph, entry);
//! assert!(dominators.dominates(entry, exit)); // entry dominates exit
//! ```
//!
//! # Thread Safety
//!
//! All types in this module implement [`Send`] and [`Sync`] when their generic
//! parameters do, enabling safe concurrent access for analysis operations.

mod directed;
mod edge;
mod indexed;
mod node;
mod traits;

pub mod algorithms;

// Re-export core types at module level
pub use directed::DirectedGraph;
#[allow(unused_imports)]
pub use edge::EdgeId;
pub use indexed::IndexedGraph;
pub use node::NodeId;
pub use traits::{GraphBase, Predecessors, RootedGraph, Successors};
