//! Topological sorting for directed acyclic graphs (DAGs).
//!
//! This module provides Kahn's algorithm for computing a topological ordering
//! of nodes in a directed acyclic graph. A topological ordering is a linear
//! ordering of vertices such that for every directed edge (u, v), vertex u
//! comes before v in the ordering.
//!
//! # Use Cases
//!
//! - Dependency resolution (build systems, package managers)
//! - Task scheduling with precedence constraints
//! - Ordering metadata loader execution
//! - Data flow analysis iteration ordering

use std::collections::VecDeque;

use crate::utils::graph::{GraphBase, NodeId, Predecessors, Successors};

/// Computes a topological ordering of nodes reachable from any entry node.
///
/// Uses Kahn's algorithm which processes nodes with no incoming edges first,
/// then removes those nodes and repeats. This produces a valid topological
/// ordering if and only if the graph is acyclic.
///
/// # Arguments
///
/// * `graph` - The graph to sort topologically
///
/// # Returns
///
/// `Some(Vec<NodeId>)` containing nodes in topological order if the graph is
/// acyclic (a DAG), `None` if the graph contains a cycle.
///
/// # Complexity
///
/// - Time: O(V + E) where V is the number of vertices and E is the number of edges
/// - Space: O(V) for the in-degree counts and queue
///
/// # Algorithm
///
/// 1. Compute in-degree for all nodes
/// 2. Initialize queue with all nodes having in-degree 0
/// 3. While queue is not empty:
///    - Remove a node from the queue and add to result
///    - For each successor, decrement its in-degree
///    - If successor's in-degree becomes 0, add to queue
/// 4. If result contains all nodes, return it; otherwise graph has a cycle
///
/// # Examples
///
/// ```rust,ignore
/// use dotscope::graph::{DirectedGraph, NodeId, algorithms::topological_sort};
///
/// // A simple DAG: A -> B -> D, A -> C -> D
/// let mut graph: DirectedGraph<&str, ()> = DirectedGraph::new();
/// let a = graph.add_node("A");
/// let b = graph.add_node("B");
/// let c = graph.add_node("C");
/// let d = graph.add_node("D");
///
/// graph.add_edge(a, b, ());
/// graph.add_edge(a, c, ());
/// graph.add_edge(b, d, ());
/// graph.add_edge(c, d, ());
///
/// let order = topological_sort(&graph);
/// assert!(order.is_some());
///
/// let order = order.unwrap();
/// // A must come before B, C; B and C must come before D
/// let a_pos = order.iter().position(|&n| n == a).unwrap();
/// let d_pos = order.iter().position(|&n| n == d).unwrap();
/// assert!(a_pos < d_pos);
/// ```
///
/// # Cyclic Graph Example
///
/// ```rust,ignore
/// use dotscope::graph::{DirectedGraph, NodeId, algorithms::topological_sort};
///
/// // A graph with a cycle: A -> B -> C -> A
/// let mut graph: DirectedGraph<(), ()> = DirectedGraph::new();
/// let a = graph.add_node(());
/// let b = graph.add_node(());
/// let c = graph.add_node(());
///
/// graph.add_edge(a, b, ());
/// graph.add_edge(b, c, ());
/// graph.add_edge(c, a, ());
///
/// // Cannot topologically sort a graph with cycles
/// assert!(topological_sort(&graph).is_none());
/// ```
pub fn topological_sort<G>(graph: &G) -> Option<Vec<NodeId>>
where
    G: GraphBase + Successors + Predecessors,
{
    let node_count = graph.node_count();
    if node_count == 0 {
        return Some(Vec::new());
    }

    // Compute in-degrees
    let mut in_degree: Vec<usize> = vec![0; node_count];
    for node in graph.node_ids() {
        for _ in graph.predecessors(node) {
            in_degree[node.index()] += 1;
        }
    }

    // Initialize queue with nodes having in-degree 0
    let mut queue: VecDeque<NodeId> = VecDeque::new();
    for node in graph.node_ids() {
        if in_degree[node.index()] == 0 {
            queue.push_back(node);
        }
    }

    let mut result = Vec::with_capacity(node_count);

    while let Some(node) = queue.pop_front() {
        result.push(node);

        for successor in graph.successors(node) {
            in_degree[successor.index()] -= 1;
            if in_degree[successor.index()] == 0 {
                queue.push_back(successor);
            }
        }
    }

    // If we didn't process all nodes, there must be a cycle
    if result.len() == node_count {
        Some(result)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use crate::utils::graph::{algorithms::topological::topological_sort, DirectedGraph, NodeId};

    #[test]
    fn test_topological_sort_empty_graph() {
        let graph: DirectedGraph<(), ()> = DirectedGraph::new();
        let result = topological_sort(&graph);
        assert_eq!(result, Some(Vec::new()));
    }

    #[test]
    fn test_topological_sort_single_node() {
        let mut graph: DirectedGraph<(), ()> = DirectedGraph::new();
        let a = graph.add_node(());
        let result = topological_sort(&graph);
        assert_eq!(result, Some(vec![a]));
    }

    #[test]
    fn test_topological_sort_linear() {
        let mut graph: DirectedGraph<&str, ()> = DirectedGraph::new();
        let a = graph.add_node("A");
        let b = graph.add_node("B");
        let c = graph.add_node("C");
        graph.add_edge(a, b, ()).unwrap();
        graph.add_edge(b, c, ()).unwrap();

        let result = topological_sort(&graph);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), vec![a, b, c]);
    }

    #[test]
    fn test_topological_sort_diamond() {
        let mut graph: DirectedGraph<&str, ()> = DirectedGraph::new();
        let a = graph.add_node("A");
        let b = graph.add_node("B");
        let c = graph.add_node("C");
        let d = graph.add_node("D");
        graph.add_edge(a, b, ()).unwrap();
        graph.add_edge(a, c, ()).unwrap();
        graph.add_edge(b, d, ()).unwrap();
        graph.add_edge(c, d, ()).unwrap();

        let result = topological_sort(&graph);
        assert!(result.is_some());

        let order = result.unwrap();
        assert_eq!(order.len(), 4);

        // Verify ordering constraints
        let pos = |n: NodeId| order.iter().position(|&x| x == n).unwrap();
        assert!(pos(a) < pos(b));
        assert!(pos(a) < pos(c));
        assert!(pos(b) < pos(d));
        assert!(pos(c) < pos(d));
    }

    #[test]
    fn test_topological_sort_simple_cycle() {
        let mut graph: DirectedGraph<(), ()> = DirectedGraph::new();
        let a = graph.add_node(());
        let b = graph.add_node(());
        let c = graph.add_node(());
        graph.add_edge(a, b, ()).unwrap();
        graph.add_edge(b, c, ()).unwrap();
        graph.add_edge(c, a, ()).unwrap();

        assert!(topological_sort(&graph).is_none());
    }

    #[test]
    fn test_topological_sort_self_loop() {
        let mut graph: DirectedGraph<(), ()> = DirectedGraph::new();
        let a = graph.add_node(());
        graph.add_edge(a, a, ()).unwrap();

        assert!(topological_sort(&graph).is_none());
    }

    #[test]
    fn test_topological_sort_disconnected_components() {
        // Two separate chains: A -> B and C -> D
        let mut graph: DirectedGraph<&str, ()> = DirectedGraph::new();
        let a = graph.add_node("A");
        let b = graph.add_node("B");
        let c = graph.add_node("C");
        let d = graph.add_node("D");
        graph.add_edge(a, b, ()).unwrap();
        graph.add_edge(c, d, ()).unwrap();

        let result = topological_sort(&graph);
        assert!(result.is_some());

        let order = result.unwrap();
        assert_eq!(order.len(), 4);

        // Verify ordering within each chain
        let pos = |n: NodeId| order.iter().position(|&x| x == n).unwrap();
        assert!(pos(a) < pos(b));
        assert!(pos(c) < pos(d));
    }

    #[test]
    fn test_topological_sort_partial_cycle() {
        // A -> B -> C -> D
        //      ^       |
        //      +-------+ (cycle B-C-D-B, but A is before the cycle)
        let mut graph: DirectedGraph<&str, ()> = DirectedGraph::new();
        let a = graph.add_node("A");
        let b = graph.add_node("B");
        let c = graph.add_node("C");
        let d = graph.add_node("D");
        graph.add_edge(a, b, ()).unwrap();
        graph.add_edge(b, c, ()).unwrap();
        graph.add_edge(c, d, ()).unwrap();
        graph.add_edge(d, b, ()).unwrap();

        // Has a cycle, so should fail
        assert!(topological_sort(&graph).is_none());
    }

    #[test]
    fn test_topological_sort_multiple_valid_orderings() {
        // A -> C, B -> C (A and B have no ordering constraint)
        let mut graph: DirectedGraph<&str, ()> = DirectedGraph::new();
        let a = graph.add_node("A");
        let b = graph.add_node("B");
        let c = graph.add_node("C");
        graph.add_edge(a, c, ()).unwrap();
        graph.add_edge(b, c, ()).unwrap();

        let result = topological_sort(&graph);
        assert!(result.is_some());

        let order = result.unwrap();
        assert_eq!(order.len(), 3);

        // C must be last, but A and B can be in either order
        let pos = |n: NodeId| order.iter().position(|&x| x == n).unwrap();
        assert!(pos(a) < pos(c));
        assert!(pos(b) < pos(c));
    }

    #[test]
    fn test_topological_sort_wide_dag() {
        // Root -> [A, B, C, D, E] (many independent children)
        let mut graph: DirectedGraph<&str, ()> = DirectedGraph::new();
        let root = graph.add_node("Root");
        let children: Vec<NodeId> = (0..5)
            .map(|_| {
                let child = graph.add_node("Child");
                graph.add_edge(root, child, ()).unwrap();
                child
            })
            .collect();

        let result = topological_sort(&graph);
        assert!(result.is_some());

        let order = result.unwrap();
        assert_eq!(order.len(), 6);

        // Root must come first
        assert_eq!(order[0], root);

        // All children must come after root
        for child in children {
            assert!(order.contains(&child));
        }
    }

    #[test]
    fn test_topological_sort_deep_dag() {
        // A chain: 0 -> 1 -> 2 -> ... -> 99
        let mut graph: DirectedGraph<usize, ()> = DirectedGraph::new();
        let nodes: Vec<NodeId> = (0..100).map(|i| graph.add_node(i)).collect();

        for i in 0..99 {
            graph.add_edge(nodes[i], nodes[i + 1], ()).unwrap();
        }

        let result = topological_sort(&graph);
        assert!(result.is_some());

        let order = result.unwrap();
        assert_eq!(order.len(), 100);

        // Must be in exact order
        for i in 0..100 {
            assert_eq!(order[i], nodes[i]);
        }
    }
}
