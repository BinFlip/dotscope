//! Cycle detection algorithms for directed graphs.
//!
//! This module provides algorithms to detect and find cycles in directed graphs.
//! Cycle detection is essential for:
//!
//! - Validating that dependency graphs are acyclic (DAGs)
//! - Detecting recursive call patterns in call graphs
//! - Identifying loops in control flow graphs

use crate::utils::graph::{NodeId, Successors};

/// Checks if a directed graph contains any cycles reachable from the start node.
///
/// This function uses depth-first search with a recursion stack to detect
/// back edges, which indicate cycles. It only considers nodes reachable
/// from the start node.
///
/// # Arguments
///
/// * `graph` - The graph to check for cycles
/// * `start` - The starting node for the search
///
/// # Returns
///
/// `true` if a cycle is found, `false` otherwise.
///
/// # Complexity
///
/// - Time: O(V + E) where V is the number of vertices and E is the number of edges
/// - Space: O(V) for the visited and recursion stack sets
///
/// # Examples
///
/// ```rust,ignore
/// use dotscope::graph::{DirectedGraph, NodeId, algorithms::has_cycle};
///
/// // Acyclic graph: A -> B -> C
/// let mut dag: DirectedGraph<(), ()> = DirectedGraph::new();
/// let a = dag.add_node(());
/// let b = dag.add_node(());
/// let c = dag.add_node(());
/// dag.add_edge(a, b, ());
/// dag.add_edge(b, c, ());
///
/// assert!(!has_cycle(&dag, a));
///
/// // Cyclic graph: A -> B -> C -> A
/// let mut cyclic: DirectedGraph<(), ()> = DirectedGraph::new();
/// let x = cyclic.add_node(());
/// let y = cyclic.add_node(());
/// let z = cyclic.add_node(());
/// cyclic.add_edge(x, y, ());
/// cyclic.add_edge(y, z, ());
/// cyclic.add_edge(z, x, ());
///
/// assert!(has_cycle(&cyclic, x));
/// ```
pub fn has_cycle<G: Successors>(graph: &G, start: NodeId) -> bool {
    let node_count = graph.node_count();
    if start.index() >= node_count {
        return false;
    }

    let mut visited = vec![false; node_count];
    let mut in_stack = vec![false; node_count];

    has_cycle_dfs(graph, start, &mut visited, &mut in_stack)
}

/// Recursive helper for cycle detection.
fn has_cycle_dfs<G: Successors>(
    graph: &G,
    node: NodeId,
    visited: &mut [bool],
    in_stack: &mut [bool],
) -> bool {
    let idx = node.index();

    if in_stack[idx] {
        // Found a back edge - cycle detected
        return true;
    }

    if visited[idx] {
        // Already processed this node in a different path, no cycle here
        return false;
    }

    visited[idx] = true;
    in_stack[idx] = true;

    for successor in graph.successors(node) {
        if has_cycle_dfs(graph, successor, visited, in_stack) {
            return true;
        }
    }

    in_stack[idx] = false;
    false
}

/// Finds a cycle in a directed graph if one exists, starting from the given node.
///
/// If a cycle is found, returns a vector of nodes forming the cycle (starting
/// and ending with the same node). If no cycle is found, returns `None`.
///
/// # Arguments
///
/// * `graph` - The graph to search for cycles
/// * `start` - The starting node for the search
///
/// # Returns
///
/// `Some(Vec<NodeId>)` containing the cycle path if found, `None` otherwise.
/// The cycle path starts and ends with the same node.
///
/// # Complexity
///
/// - Time: O(V + E)
/// - Space: O(V)
///
/// # Examples
///
/// ```rust,ignore
/// use dotscope::graph::{DirectedGraph, NodeId, algorithms::find_cycle};
///
/// // Cyclic graph: A -> B -> C -> A
/// let mut graph: DirectedGraph<char, ()> = DirectedGraph::new();
/// let a = graph.add_node('A');
/// let b = graph.add_node('B');
/// let c = graph.add_node('C');
/// graph.add_edge(a, b, ());
/// graph.add_edge(b, c, ());
/// graph.add_edge(c, a, ());
///
/// let cycle = find_cycle(&graph, a);
/// assert!(cycle.is_some());
///
/// let cycle_nodes = cycle.unwrap();
/// assert!(cycle_nodes.len() >= 3); // At least 3 nodes in the cycle
/// assert_eq!(cycle_nodes.first(), cycle_nodes.last()); // Forms a cycle
/// ```
pub fn find_cycle<G: Successors>(graph: &G, start: NodeId) -> Option<Vec<NodeId>> {
    let node_count = graph.node_count();
    if start.index() >= node_count {
        return None;
    }

    let mut visited = vec![false; node_count];
    let mut in_stack = vec![false; node_count];
    let mut path = Vec::new();

    find_cycle_dfs(graph, start, &mut visited, &mut in_stack, &mut path)
}

/// Recursive helper for finding a cycle.
fn find_cycle_dfs<G: Successors>(
    graph: &G,
    node: NodeId,
    visited: &mut [bool],
    in_stack: &mut [bool],
    path: &mut Vec<NodeId>,
) -> Option<Vec<NodeId>> {
    let idx = node.index();

    if in_stack[idx] {
        // Found a back edge - extract the cycle
        let cycle_start_pos = path.iter().position(|&n| n == node)?;
        let mut cycle: Vec<NodeId> = path[cycle_start_pos..].to_vec();
        cycle.push(node); // Close the cycle
        return Some(cycle);
    }

    if visited[idx] {
        return None;
    }

    visited[idx] = true;
    in_stack[idx] = true;
    path.push(node);

    for successor in graph.successors(node) {
        if let Some(cycle) = find_cycle_dfs(graph, successor, visited, in_stack, path) {
            return Some(cycle);
        }
    }

    path.pop();
    in_stack[idx] = false;
    None
}

#[cfg(test)]
mod tests {
    use crate::utils::graph::{
        algorithms::cycles::{find_cycle, has_cycle},
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

    fn create_simple_cycle() -> DirectedGraph<'static, &'static str, ()> {
        let mut graph = DirectedGraph::new();
        let a = graph.add_node("A");
        let b = graph.add_node("B");
        let c = graph.add_node("C");
        graph.add_edge(a, b, ()).unwrap();
        graph.add_edge(b, c, ()).unwrap();
        graph.add_edge(c, a, ()).unwrap();
        graph
    }

    fn create_self_loop() -> DirectedGraph<'static, &'static str, ()> {
        let mut graph = DirectedGraph::new();
        let a = graph.add_node("A");
        graph.add_edge(a, a, ()).unwrap();
        graph
    }

    fn create_complex_with_cycle() -> DirectedGraph<'static, &'static str, ()> {
        // A -> B -> C -> D
        //      ^       |
        //      +-------+
        let mut graph = DirectedGraph::new();
        let a = graph.add_node("A");
        let b = graph.add_node("B");
        let c = graph.add_node("C");
        let d = graph.add_node("D");
        graph.add_edge(a, b, ()).unwrap();
        graph.add_edge(b, c, ()).unwrap();
        graph.add_edge(c, d, ()).unwrap();
        graph.add_edge(d, b, ()).unwrap();
        graph
    }

    #[test]
    fn test_has_cycle_linear() {
        let graph = create_linear_graph();
        assert!(!has_cycle(&graph, NodeId::new(0)));
    }

    #[test]
    fn test_has_cycle_diamond() {
        let graph = create_diamond_graph();
        assert!(!has_cycle(&graph, NodeId::new(0)));
    }

    #[test]
    fn test_has_cycle_simple_cycle() {
        let graph = create_simple_cycle();
        assert!(has_cycle(&graph, NodeId::new(0)));
    }

    #[test]
    fn test_has_cycle_self_loop() {
        let graph = create_self_loop();
        assert!(has_cycle(&graph, NodeId::new(0)));
    }

    #[test]
    fn test_has_cycle_complex() {
        let graph = create_complex_with_cycle();
        assert!(has_cycle(&graph, NodeId::new(0)));
    }

    #[test]
    fn test_has_cycle_single_node_no_loop() {
        let mut graph: DirectedGraph<(), ()> = DirectedGraph::new();
        let a = graph.add_node(());
        assert!(!has_cycle(&graph, a));
    }

    #[test]
    fn test_has_cycle_two_separate_cycles() {
        // Two separate cycles not connected
        let mut graph: DirectedGraph<&str, ()> = DirectedGraph::new();
        let a = graph.add_node("A");
        let b = graph.add_node("B");
        let c = graph.add_node("C");
        let d = graph.add_node("D");

        // Cycle 1: A <-> B
        graph.add_edge(a, b, ()).unwrap();
        graph.add_edge(b, a, ()).unwrap();

        // Cycle 2: C <-> D (disconnected from A, B)
        graph.add_edge(c, d, ()).unwrap();
        graph.add_edge(d, c, ()).unwrap();

        // Starting from A should find cycle in first component
        assert!(has_cycle(&graph, a));

        // Starting from C should find cycle in second component
        assert!(has_cycle(&graph, c));
    }

    #[test]
    fn test_find_cycle_linear() {
        let graph = create_linear_graph();
        assert!(find_cycle(&graph, NodeId::new(0)).is_none());
    }

    #[test]
    fn test_find_cycle_diamond() {
        let graph = create_diamond_graph();
        assert!(find_cycle(&graph, NodeId::new(0)).is_none());
    }

    #[test]
    fn test_find_cycle_simple_cycle() {
        let graph = create_simple_cycle();
        let cycle = find_cycle(&graph, NodeId::new(0));

        assert!(cycle.is_some());
        let cycle = cycle.unwrap();

        // Cycle should form a loop (first == last)
        assert_eq!(cycle.first(), cycle.last());

        // Should have at least 3 nodes in a triangle cycle plus the closing node
        assert!(cycle.len() >= 3);
    }

    #[test]
    fn test_find_cycle_self_loop() {
        let graph = create_self_loop();
        let cycle = find_cycle(&graph, NodeId::new(0));

        assert!(cycle.is_some());
        let cycle = cycle.unwrap();

        // Self loop: [A, A]
        assert_eq!(cycle.len(), 2);
        assert_eq!(cycle[0], cycle[1]);
    }

    #[test]
    fn test_find_cycle_complex() {
        let graph = create_complex_with_cycle();
        let cycle = find_cycle(&graph, NodeId::new(0));

        assert!(cycle.is_some());
        let cycle = cycle.unwrap();

        // Cycle B -> C -> D -> B
        assert_eq!(cycle.first(), cycle.last());
    }

    #[test]
    fn test_find_cycle_returns_valid_path() {
        let graph = create_simple_cycle();
        let cycle = find_cycle(&graph, NodeId::new(0)).unwrap();

        // Verify the path is valid: each node connects to the next
        for i in 0..cycle.len() - 1 {
            let current = cycle[i];
            let next = cycle[i + 1];
            let successors: Vec<NodeId> = graph.successors(current).collect();
            assert!(
                successors.contains(&next),
                "Invalid cycle path: no edge from {:?} to {:?}",
                current,
                next
            );
        }
    }

    #[test]
    fn test_find_cycle_disconnected_cycle() {
        // Entry point not in the cycle
        let mut graph: DirectedGraph<&str, ()> = DirectedGraph::new();
        let entry = graph.add_node("Entry");
        let a = graph.add_node("A");
        let b = graph.add_node("B");
        let c = graph.add_node("C");

        graph.add_edge(entry, a, ()).unwrap();
        graph.add_edge(a, b, ()).unwrap();
        graph.add_edge(b, c, ()).unwrap();
        graph.add_edge(c, a, ()).unwrap(); // Cycle: A -> B -> C -> A

        let cycle = find_cycle(&graph, entry);
        assert!(cycle.is_some());
    }
}
