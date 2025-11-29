//! Graph algorithms for program analysis.
//!
//! This module provides standard graph algorithms optimized for program analysis
//! tasks such as control flow analysis, dominator computation, and dependency
//! resolution.
//!
//! # Available Algorithms
//!
//! ## Traversal
//!
//! - [`dfs`] - Depth-first search traversal
//! - [`bfs`] - Breadth-first search traversal
//! - [`reverse_postorder`] - Reverse postorder traversal (useful for data flow)
//! - [`postorder`] - Postorder traversal
//!
//! ## Cycle Detection
//!
//! - [`has_cycle`] - Check if a graph contains any cycles
//! - [`find_cycle`] - Find a cycle if one exists
//!
//! ## Topological Ordering
//!
//! - [`topological_sort`] - Compute a topological ordering of nodes
//!
//! ## Dominator Analysis
//!
//! - [`compute_dominators`] - Compute the dominator tree using Lengauer-Tarjan
//! - [`compute_dominance_frontiers`] - Compute dominance frontiers for SSA
//! - [`DominatorTree`] - Result of dominator computation
//!
//! ## Strongly Connected Components
//!
//! - [`strongly_connected_components`] - Tarjan's SCC algorithm
//!
//! # Algorithm Selection
//!
//! | Algorithm | Time Complexity | Use Case |
//! |-----------|-----------------|----------|
//! | DFS/BFS | O(V + E) | General traversal |
//! | Topological Sort | O(V + E) | Dependency ordering |
//! | Dominators | O(V α(V)) | SSA construction, loop analysis |
//! | SCC | O(V + E) | Recursion detection, call graph analysis |
//!
//! # Examples
//!
//! ## Traversal
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
//! // DFS traversal
//! let order: Vec<NodeId> = algorithms::dfs(&graph, a).collect();
//! assert_eq!(order, vec![a, b, c]);
//! ```
//!
//! ## Cycle Detection
//!
//! ```rust,ignore
//! use dotscope::graph::{DirectedGraph, NodeId, algorithms};
//!
//! // Acyclic graph
//! let mut dag: DirectedGraph<(), ()> = DirectedGraph::new();
//! let a = dag.add_node(());
//! let b = dag.add_node(());
//! dag.add_edge(a, b, ());
//!
//! assert!(!algorithms::has_cycle(&dag, a));
//!
//! // Cyclic graph
//! let mut cyclic: DirectedGraph<(), ()> = DirectedGraph::new();
//! let x = cyclic.add_node(());
//! let y = cyclic.add_node(());
//! cyclic.add_edge(x, y, ());
//! cyclic.add_edge(y, x, ());
//!
//! assert!(algorithms::has_cycle(&cyclic, x));
//! ```

mod cycles;
mod dominators;
mod scc;
mod topological;
mod traversal;

// Re-export all public items
pub use cycles::{find_cycle, has_cycle};
#[allow(unused_imports)]
pub use dominators::{compute_dominance_frontiers, compute_dominators, DominatorTree};
pub use scc::{condensation, strongly_connected_components};
pub use topological::topological_sort;
#[allow(unused_imports)]
pub use traversal::{bfs, dfs, postorder, reverse_postorder};
