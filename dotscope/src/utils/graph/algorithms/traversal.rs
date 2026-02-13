//! Graph traversal algorithms.
//!
//! This module provides depth-first and breadth-first traversal algorithms
//! for directed graphs. These are fundamental building blocks for more complex
//! graph algorithms and program analysis.
//!
//! # Algorithms
//!
//! - [`dfs`] - Iterative depth-first search (pre-order)
//! - [`bfs`] - Breadth-first search
//! - [`postorder`] - Depth-first search with post-order visitation
//! - [`reverse_postorder`] - Reverse post-order (useful for forward data flow)
//!
//! # Iteration vs Collection
//!
//! The [`dfs`] and [`bfs`] functions return iterators for lazy evaluation,
//! avoiding unnecessary allocations when only partial traversal is needed.
//! The [`postorder`] and [`reverse_postorder`] functions return collected
//! vectors since the order requires full traversal anyway.

use std::collections::VecDeque;

use crate::utils::graph::{NodeId, Successors};

/// Depth-first search iterator over graph nodes.
///
/// This iterator performs an iterative (non-recursive) depth-first traversal
/// starting from a given node. It visits each reachable node exactly once
/// in pre-order (visiting a node before its descendants).
///
/// # Type Parameters
///
/// * `'g` - Lifetime of the graph reference
/// * `G` - Graph type implementing [`Successors`]
///
/// # Examples
///
/// ```rust,ignore
/// use dotscope::graph::{DirectedGraph, NodeId, algorithms::dfs};
///
/// let mut graph: DirectedGraph<char, ()> = DirectedGraph::new();
/// let a = graph.add_node('A');
/// let b = graph.add_node('B');
/// let c = graph.add_node('C');
/// graph.add_edge(a, b, ());
/// graph.add_edge(a, c, ());
///
/// let visited: Vec<NodeId> = dfs(&graph, a).collect();
/// assert_eq!(visited.len(), 3);
/// assert_eq!(visited[0], a); // A is visited first
/// ```
pub struct DfsIterator<'g, G: Successors> {
    graph: &'g G,
    stack: Vec<NodeId>,
    visited: Vec<bool>,
}

impl<'g, G: Successors> DfsIterator<'g, G> {
    fn new(graph: &'g G, start: NodeId) -> Self {
        let node_count = graph.node_count();
        if start.index() >= node_count {
            return DfsIterator {
                graph,
                stack: Vec::new(),
                visited: Vec::new(),
            };
        }

        let mut visited = vec![false; node_count];
        visited[start.index()] = true;

        DfsIterator {
            graph,
            stack: vec![start],
            visited,
        }
    }
}

impl<G: Successors> Iterator for DfsIterator<'_, G> {
    type Item = NodeId;

    fn next(&mut self) -> Option<Self::Item> {
        let node = self.stack.pop()?;
        if self.visited.is_empty() {
            return None;
        }

        // Push unvisited successors onto the stack in reverse order
        // so that they are visited in the original order
        let successors: Vec<NodeId> = self.graph.successors(node).collect();
        for &succ in successors.iter().rev() {
            if !self.visited[succ.index()] {
                self.visited[succ.index()] = true;
                self.stack.push(succ);
            }
        }

        Some(node)
    }
}

/// Returns a depth-first search iterator starting from the given node.
///
/// The iterator visits each reachable node exactly once in pre-order
/// (visiting a node before its descendants). Nodes not reachable from
/// the start node are not visited.
///
/// # Arguments
///
/// * `graph` - The graph to traverse
/// * `start` - The starting node for traversal
///
/// # Returns
///
/// An iterator yielding `NodeId` in DFS pre-order.
///
/// # Complexity
///
/// - Time: O(V + E) where V is the number of vertices and E is the number of edges
/// - Space: O(V) for the visited set and stack
///
/// # Examples
///
/// ```rust,ignore
/// use dotscope::graph::{DirectedGraph, NodeId, algorithms::dfs};
///
/// let mut graph: DirectedGraph<&str, ()> = DirectedGraph::new();
/// let a = graph.add_node("A");
/// let b = graph.add_node("B");
/// let c = graph.add_node("C");
/// graph.add_edge(a, b, ());
/// graph.add_edge(b, c, ());
///
/// // Visit nodes in DFS order
/// for node in dfs(&graph, a) {
///     println!("Visiting {:?}", node);
/// }
///
/// // Collect all reachable nodes
/// let reachable: Vec<NodeId> = dfs(&graph, a).collect();
/// assert_eq!(reachable.len(), 3);
/// ```
pub fn dfs<G: Successors>(graph: &G, start: NodeId) -> DfsIterator<'_, G> {
    DfsIterator::new(graph, start)
}

/// Breadth-first search iterator over graph nodes.
///
/// This iterator performs a breadth-first traversal starting from a given node.
/// It visits each reachable node exactly once, exploring all nodes at distance d
/// before visiting any node at distance d+1.
///
/// # Type Parameters
///
/// * `'g` - Lifetime of the graph reference
/// * `G` - Graph type implementing [`Successors`]
pub struct BfsIterator<'g, G: Successors> {
    graph: &'g G,
    queue: VecDeque<NodeId>,
    visited: Vec<bool>,
}

impl<'g, G: Successors> BfsIterator<'g, G> {
    fn new(graph: &'g G, start: NodeId) -> Self {
        let node_count = graph.node_count();
        if start.index() >= node_count {
            return BfsIterator {
                graph,
                queue: VecDeque::new(),
                visited: Vec::new(),
            };
        }

        let mut visited = vec![false; node_count];
        visited[start.index()] = true;

        let mut queue = VecDeque::new();
        queue.push_back(start);

        BfsIterator {
            graph,
            queue,
            visited,
        }
    }
}

impl<G: Successors> Iterator for BfsIterator<'_, G> {
    type Item = NodeId;

    fn next(&mut self) -> Option<Self::Item> {
        let node = self.queue.pop_front()?;
        if self.visited.is_empty() {
            return None;
        }

        // Enqueue unvisited successors
        for succ in self.graph.successors(node) {
            if !self.visited[succ.index()] {
                self.visited[succ.index()] = true;
                self.queue.push_back(succ);
            }
        }

        Some(node)
    }
}

/// Returns a breadth-first search iterator starting from the given node.
///
/// The iterator visits each reachable node exactly once, exploring nodes
/// in order of increasing distance from the start. This is useful for
/// finding shortest paths in unweighted graphs.
///
/// # Arguments
///
/// * `graph` - The graph to traverse
/// * `start` - The starting node for traversal
///
/// # Returns
///
/// An iterator yielding `NodeId` in BFS order.
///
/// # Complexity
///
/// - Time: O(V + E) where V is the number of vertices and E is the number of edges
/// - Space: O(V) for the visited set and queue
///
/// # Examples
///
/// ```rust,ignore
/// use dotscope::graph::{DirectedGraph, NodeId, algorithms::bfs};
///
/// let mut graph: DirectedGraph<&str, ()> = DirectedGraph::new();
/// let a = graph.add_node("A");
/// let b = graph.add_node("B");
/// let c = graph.add_node("C");
/// let d = graph.add_node("D");
/// graph.add_edge(a, b, ());
/// graph.add_edge(a, c, ());
/// graph.add_edge(b, d, ());
/// graph.add_edge(c, d, ());
///
/// // BFS visits by distance from start
/// let order: Vec<NodeId> = bfs(&graph, a).collect();
/// assert_eq!(order[0], a);  // Distance 0
/// // B and C are at distance 1 (order may vary)
/// // D is at distance 2
/// assert_eq!(order[3], d);
/// ```
pub fn bfs<G: Successors>(graph: &G, start: NodeId) -> BfsIterator<'_, G> {
    BfsIterator::new(graph, start)
}

/// Computes the postorder traversal of nodes reachable from the start.
///
/// In postorder, a node is visited after all its descendants have been visited.
/// This is useful for algorithms that need to process children before parents.
///
/// # Arguments
///
/// * `graph` - The graph to traverse
/// * `start` - The starting node for traversal
///
/// # Returns
///
/// A vector of `NodeId` in postorder.
///
/// # Complexity
///
/// - Time: O(V + E)
/// - Space: O(V)
///
/// # Examples
///
/// ```rust,ignore
/// use dotscope::graph::{DirectedGraph, NodeId, algorithms::postorder};
///
/// let mut graph: DirectedGraph<&str, ()> = DirectedGraph::new();
/// let a = graph.add_node("A");
/// let b = graph.add_node("B");
/// let c = graph.add_node("C");
/// graph.add_edge(a, b, ());
/// graph.add_edge(b, c, ());
///
/// let order = postorder(&graph, a);
/// // C comes before B, B comes before A
/// assert_eq!(order, vec![c, b, a]);
/// ```
#[allow(clippy::items_after_statements)]
pub fn postorder<G: Successors>(graph: &G, start: NodeId) -> Vec<NodeId> {
    let node_count = graph.node_count();

    // Validate start node - return empty vec if invalid
    if start.index() >= node_count {
        return Vec::new();
    }

    let mut visited = vec![false; node_count];
    let mut result = Vec::with_capacity(node_count);

    // Iterative postorder using explicit stack with state
    #[derive(Clone, Copy)]
    enum State {
        Enter,
        Exit,
    }

    let mut stack = vec![(start, State::Enter)];

    while let Some((node, state)) = stack.pop() {
        match state {
            State::Enter => {
                if visited[node.index()] {
                    continue;
                }
                visited[node.index()] = true;

                // Push exit state for this node (will be processed after children)
                stack.push((node, State::Exit));

                // Push children in reverse order so they're processed in order
                let successors: Vec<NodeId> = graph.successors(node).collect();
                for &succ in successors.iter().rev() {
                    if !visited[succ.index()] {
                        stack.push((succ, State::Enter));
                    }
                }
            }
            State::Exit => {
                result.push(node);
            }
        }
    }

    result
}

/// Computes the reverse postorder traversal of nodes reachable from the start.
///
/// Reverse postorder (RPO) is the reverse of postorder: nodes are visited
/// such that a node comes before any of its successors (in a DAG). This is
/// the preferred iteration order for forward data flow analysis.
///
/// # Arguments
///
/// * `graph` - The graph to traverse
/// * `start` - The starting node for traversal
///
/// # Returns
///
/// A vector of `NodeId` in reverse postorder.
///
/// # Complexity
///
/// - Time: O(V + E)
/// - Space: O(V)
///
/// # Use Cases
///
/// - **Forward data flow analysis**: Iterating in RPO ensures that when analyzing
///   a node, all its predecessors (in a DAG) have already been analyzed
/// - **Dominance frontier computation**: RPO ensures correct order for iterative algorithms
///
/// # Examples
///
/// ```rust,ignore
/// use dotscope::graph::{DirectedGraph, NodeId, algorithms::reverse_postorder};
///
/// let mut graph: DirectedGraph<&str, ()> = DirectedGraph::new();
/// let a = graph.add_node("A");
/// let b = graph.add_node("B");
/// let c = graph.add_node("C");
/// graph.add_edge(a, b, ());
/// graph.add_edge(b, c, ());
///
/// let order = reverse_postorder(&graph, a);
/// // A comes before B, B comes before C
/// assert_eq!(order, vec![a, b, c]);
/// ```
pub fn reverse_postorder<G: Successors>(graph: &G, start: NodeId) -> Vec<NodeId> {
    let mut result = postorder(graph, start);
    result.reverse();
    result
}

#[cfg(test)]
mod tests {
    use crate::utils::graph::{
        algorithms::traversal::{bfs, dfs, postorder, reverse_postorder},
        DirectedGraph, NodeId,
    };

    fn create_linear_graph() -> DirectedGraph<'static, &'static str, ()> {
        let mut graph = DirectedGraph::new();
        let a = graph.add_node("A");
        let b = graph.add_node("B");
        let c = graph.add_node("C");
        graph.add_edge(a, b, ()).unwrap();
        graph.add_edge(b, c, ()).unwrap();
        graph
    }

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

    fn create_tree_graph() -> DirectedGraph<'static, &'static str, ()> {
        //       A
        //      / \
        //     B   C
        //    / \   \
        //   D   E   F
        let mut graph = DirectedGraph::new();
        let a = graph.add_node("A");
        let b = graph.add_node("B");
        let c = graph.add_node("C");
        let d = graph.add_node("D");
        let e = graph.add_node("E");
        let f = graph.add_node("F");
        graph.add_edge(a, b, ()).unwrap();
        graph.add_edge(a, c, ()).unwrap();
        graph.add_edge(b, d, ()).unwrap();
        graph.add_edge(b, e, ()).unwrap();
        graph.add_edge(c, f, ()).unwrap();
        graph
    }

    #[test]
    fn test_dfs_linear() {
        let graph = create_linear_graph();
        let order: Vec<NodeId> = dfs(&graph, NodeId::new(0)).collect();
        assert_eq!(order, vec![NodeId::new(0), NodeId::new(1), NodeId::new(2)]);
    }

    #[test]
    fn test_dfs_diamond() {
        let graph = create_diamond_graph();
        let order: Vec<NodeId> = dfs(&graph, NodeId::new(0)).collect();

        // Should visit all 4 nodes
        assert_eq!(order.len(), 4);

        // A should be first
        assert_eq!(order[0], NodeId::new(0));

        // D should be visited after both B and C are on the path
        // The exact order depends on implementation, but D should be reachable
        assert!(order.contains(&NodeId::new(3)));
    }

    #[test]
    fn test_dfs_cycle() {
        let graph = create_cycle_graph();
        let order: Vec<NodeId> = dfs(&graph, NodeId::new(0)).collect();

        // Should visit each node exactly once despite the cycle
        assert_eq!(order.len(), 3);
        assert_eq!(order[0], NodeId::new(0));
    }

    #[test]
    fn test_dfs_tree() {
        let graph = create_tree_graph();
        let order: Vec<NodeId> = dfs(&graph, NodeId::new(0)).collect();

        // Should visit all 6 nodes
        assert_eq!(order.len(), 6);

        // A should be first
        assert_eq!(order[0], NodeId::new(0));
    }

    #[test]
    fn test_dfs_single_node() {
        let mut graph: DirectedGraph<(), ()> = DirectedGraph::new();
        let a = graph.add_node(());

        let order: Vec<NodeId> = dfs(&graph, a).collect();
        assert_eq!(order, vec![a]);
    }

    #[test]
    fn test_dfs_disconnected() {
        let mut graph: DirectedGraph<&str, ()> = DirectedGraph::new();
        let a = graph.add_node("A");
        let b = graph.add_node("B");
        let _c = graph.add_node("C"); // Disconnected

        graph.add_edge(a, b, ()).unwrap();

        let order: Vec<NodeId> = dfs(&graph, a).collect();

        // Should only visit A and B, not C
        assert_eq!(order.len(), 2);
        assert!(!order.contains(&NodeId::new(2)));
    }

    #[test]
    fn test_bfs_linear() {
        let graph = create_linear_graph();
        let order: Vec<NodeId> = bfs(&graph, NodeId::new(0)).collect();
        assert_eq!(order, vec![NodeId::new(0), NodeId::new(1), NodeId::new(2)]);
    }

    #[test]
    fn test_bfs_diamond() {
        let graph = create_diamond_graph();
        let order: Vec<NodeId> = bfs(&graph, NodeId::new(0)).collect();

        // Should visit all 4 nodes
        assert_eq!(order.len(), 4);

        // A should be first (distance 0)
        assert_eq!(order[0], NodeId::new(0));

        // B and C should be next (distance 1)
        assert!(order[1] == NodeId::new(1) || order[1] == NodeId::new(2));
        assert!(order[2] == NodeId::new(1) || order[2] == NodeId::new(2));

        // D should be last (distance 2)
        assert_eq!(order[3], NodeId::new(3));
    }

    #[test]
    fn test_bfs_tree() {
        let graph = create_tree_graph();
        let order: Vec<NodeId> = bfs(&graph, NodeId::new(0)).collect();

        // Should visit all 6 nodes
        assert_eq!(order.len(), 6);

        // A should be first (level 0)
        assert_eq!(order[0], NodeId::new(0));

        // B and C should be next (level 1)
        let level_1: Vec<NodeId> = order[1..3].to_vec();
        assert!(level_1.contains(&NodeId::new(1)));
        assert!(level_1.contains(&NodeId::new(2)));

        // D, E, F should be last (level 2)
        let level_2: Vec<NodeId> = order[3..6].to_vec();
        assert!(level_2.contains(&NodeId::new(3)));
        assert!(level_2.contains(&NodeId::new(4)));
        assert!(level_2.contains(&NodeId::new(5)));
    }

    #[test]
    fn test_bfs_single_node() {
        let mut graph: DirectedGraph<(), ()> = DirectedGraph::new();
        let a = graph.add_node(());

        let order: Vec<NodeId> = bfs(&graph, a).collect();
        assert_eq!(order, vec![a]);
    }

    #[test]
    fn test_bfs_disconnected() {
        let mut graph: DirectedGraph<&str, ()> = DirectedGraph::new();
        let a = graph.add_node("A");
        let b = graph.add_node("B");
        let _c = graph.add_node("C"); // Disconnected

        graph.add_edge(a, b, ()).unwrap();

        let order: Vec<NodeId> = bfs(&graph, a).collect();

        // Should only visit A and B, not C
        assert_eq!(order.len(), 2);
    }

    #[test]
    fn test_postorder_linear() {
        let graph = create_linear_graph();
        let order = postorder(&graph, NodeId::new(0));

        // Postorder: children before parents
        // C, B, A
        assert_eq!(order, vec![NodeId::new(2), NodeId::new(1), NodeId::new(0)]);
    }

    #[test]
    fn test_postorder_diamond() {
        let graph = create_diamond_graph();
        let order = postorder(&graph, NodeId::new(0));

        // All 4 nodes should be visited
        assert_eq!(order.len(), 4);

        // A should be last (root)
        assert_eq!(*order.last().unwrap(), NodeId::new(0));

        // D should appear before both B and C (since it's their child)
        let d_pos = order.iter().position(|&n| n == NodeId::new(3)).unwrap();
        let b_pos = order.iter().position(|&n| n == NodeId::new(1)).unwrap();
        let c_pos = order.iter().position(|&n| n == NodeId::new(2)).unwrap();

        assert!(d_pos < b_pos || d_pos < c_pos);
    }

    #[test]
    fn test_postorder_tree() {
        let graph = create_tree_graph();
        let order = postorder(&graph, NodeId::new(0));

        // All 6 nodes
        assert_eq!(order.len(), 6);

        // A should be last
        assert_eq!(*order.last().unwrap(), NodeId::new(0));

        // Leaves should come before their parents
        // D and E should come before B
        let d_pos = order.iter().position(|&n| n == NodeId::new(3)).unwrap();
        let e_pos = order.iter().position(|&n| n == NodeId::new(4)).unwrap();
        let b_pos = order.iter().position(|&n| n == NodeId::new(1)).unwrap();

        assert!(d_pos < b_pos);
        assert!(e_pos < b_pos);
    }

    #[test]
    fn test_reverse_postorder_linear() {
        let graph = create_linear_graph();
        let order = reverse_postorder(&graph, NodeId::new(0));

        // Reverse postorder: parents before children
        // A, B, C
        assert_eq!(order, vec![NodeId::new(0), NodeId::new(1), NodeId::new(2)]);
    }

    #[test]
    fn test_reverse_postorder_diamond() {
        let graph = create_diamond_graph();
        let order = reverse_postorder(&graph, NodeId::new(0));

        // All 4 nodes
        assert_eq!(order.len(), 4);

        // A should be first
        assert_eq!(order[0], NodeId::new(0));

        // D should be last
        assert_eq!(*order.last().unwrap(), NodeId::new(3));
    }

    #[test]
    fn test_reverse_postorder_tree() {
        let graph = create_tree_graph();
        let order = reverse_postorder(&graph, NodeId::new(0));

        // All 6 nodes
        assert_eq!(order.len(), 6);

        // A should be first
        assert_eq!(order[0], NodeId::new(0));

        // Parents should come before children
        let a_pos = order.iter().position(|&n| n == NodeId::new(0)).unwrap();
        let b_pos = order.iter().position(|&n| n == NodeId::new(1)).unwrap();
        let d_pos = order.iter().position(|&n| n == NodeId::new(3)).unwrap();

        assert!(a_pos < b_pos);
        assert!(b_pos < d_pos);
    }

    #[test]
    fn test_reverse_postorder_with_cycle() {
        let graph = create_cycle_graph();
        let order = reverse_postorder(&graph, NodeId::new(0));

        // Should still visit all nodes exactly once
        assert_eq!(order.len(), 3);
    }

    #[test]
    fn test_self_loop() {
        let mut graph: DirectedGraph<(), ()> = DirectedGraph::new();
        let a = graph.add_node(());
        graph.add_edge(a, a, ()).unwrap();

        // DFS should visit the node exactly once
        let dfs_order: Vec<NodeId> = dfs(&graph, a).collect();
        assert_eq!(dfs_order, vec![a]);

        // BFS should visit the node exactly once
        let bfs_order: Vec<NodeId> = bfs(&graph, a).collect();
        assert_eq!(bfs_order, vec![a]);

        // Postorder should have the node once
        let post_order = postorder(&graph, a);
        assert_eq!(post_order, vec![a]);
    }

    #[test]
    fn test_multiple_edges() {
        let mut graph: DirectedGraph<(), ()> = DirectedGraph::new();
        let a = graph.add_node(());
        let b = graph.add_node(());
        graph.add_edge(a, b, ()).unwrap();
        graph.add_edge(a, b, ()).unwrap(); // Duplicate edge

        // Should still visit B only once
        let order: Vec<NodeId> = dfs(&graph, a).collect();
        assert_eq!(order, vec![a, b]);
    }

    #[test]
    fn test_iterator_early_termination() {
        let graph = create_tree_graph();

        // Take only first 3 nodes
        let partial: Vec<NodeId> = dfs(&graph, NodeId::new(0)).take(3).collect();
        assert_eq!(partial.len(), 3);
    }
}
