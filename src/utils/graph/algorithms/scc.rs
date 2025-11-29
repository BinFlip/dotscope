//! Strongly Connected Components (SCC) using Tarjan's algorithm.
//!
//! This module provides Tarjan's algorithm for finding strongly connected
//! components in a directed graph. A strongly connected component is a maximal
//! set of vertices such that there is a path from every vertex to every other
//! vertex in the set.
//!
//! # Use Cases
//!
//! - **Recursion detection**: Methods that can call each other form an SCC
//! - **Call graph analysis**: Finding mutually recursive function groups
//! - **Dependency analysis**: Detecting circular dependencies
//! - **Dead code elimination**: Unreachable code forms trivial SCCs

use crate::utils::graph::{NodeId, Successors};

/// Computes the strongly connected components of a directed graph.
///
/// Uses Tarjan's algorithm with a single DFS pass. The algorithm maintains
/// a stack of vertices and assigns each vertex an index and "lowlink" value.
/// When a vertex's lowlink equals its index, it's the root of an SCC.
///
/// # Arguments
///
/// * `graph` - The directed graph to analyze
///
/// # Returns
///
/// A vector of SCCs, where each SCC is a vector of `NodeId`s. The SCCs are
/// returned in **reverse topological order** (i.e., if there's an edge from
/// SCC A to SCC B, then A appears after B in the result).
///
/// # Complexity
///
/// - Time: O(V + E)
/// - Space: O(V)
///
/// # Algorithm
///
/// 1. Perform DFS, assigning each node an index in discovery order
/// 2. Compute lowlink values (minimum index reachable via DFS subtree + back edges)
/// 3. When lowlink[v] == index[v], v is root of an SCC; pop stack until v
///
/// # Examples
///
/// ```rust,ignore
/// use dotscope::graph::{DirectedGraph, NodeId, algorithms::strongly_connected_components};
///
/// // Simple cycle: A -> B -> C -> A
/// let mut graph: DirectedGraph<char, ()> = DirectedGraph::new();
/// let a = graph.add_node('A');
/// let b = graph.add_node('B');
/// let c = graph.add_node('C');
/// graph.add_edge(a, b, ());
/// graph.add_edge(b, c, ());
/// graph.add_edge(c, a, ());
///
/// let sccs = strongly_connected_components(&graph);
/// // All three nodes form a single SCC
/// assert_eq!(sccs.len(), 1);
/// assert_eq!(sccs[0].len(), 3);
/// ```
///
/// # Acyclic Graph Example
///
/// ```rust,ignore
/// use dotscope::graph::{DirectedGraph, NodeId, algorithms::strongly_connected_components};
///
/// // DAG: A -> B -> C
/// let mut graph: DirectedGraph<char, ()> = DirectedGraph::new();
/// let a = graph.add_node('A');
/// let b = graph.add_node('B');
/// let c = graph.add_node('C');
/// graph.add_edge(a, b, ());
/// graph.add_edge(b, c, ());
///
/// let sccs = strongly_connected_components(&graph);
/// // Each node is its own SCC (no cycles)
/// assert_eq!(sccs.len(), 3);
/// for scc in &sccs {
///     assert_eq!(scc.len(), 1);
/// }
/// ```
pub fn strongly_connected_components<G>(graph: &G) -> Vec<Vec<NodeId>>
where
    G: Successors,
{
    let node_count = graph.node_count();
    if node_count == 0 {
        return Vec::new();
    }

    let mut state = TarjanState::new(node_count);

    // Run Tarjan's algorithm from each unvisited node
    for i in 0..node_count {
        let node = NodeId::new(i);
        if state.index[i].is_none() {
            state.strongconnect(graph, node);
        }
    }

    state.sccs
}

/// Internal state for Tarjan's algorithm.
struct TarjanState {
    /// Discovery index for each node (None if not yet visited)
    index: Vec<Option<usize>>,
    /// Lowlink value for each node
    lowlink: Vec<usize>,
    /// Whether a node is currently on the stack
    on_stack: Vec<bool>,
    /// The DFS stack
    stack: Vec<NodeId>,
    /// Current index counter
    current_index: usize,
    /// Collected SCCs
    sccs: Vec<Vec<NodeId>>,
}

impl TarjanState {
    fn new(n: usize) -> Self {
        Self {
            index: vec![None; n],
            lowlink: vec![0; n],
            on_stack: vec![false; n],
            stack: Vec::new(),
            current_index: 0,
            sccs: Vec::new(),
        }
    }

    fn strongconnect<G: Successors>(&mut self, graph: &G, v: NodeId) {
        let v_idx = v.index();

        // Set the depth index for v
        self.index[v_idx] = Some(self.current_index);
        self.lowlink[v_idx] = self.current_index;
        self.current_index += 1;
        self.stack.push(v);
        self.on_stack[v_idx] = true;

        // Consider successors of v
        for w in graph.successors(v) {
            let w_idx = w.index();

            if self.index[w_idx].is_none() {
                // Successor w has not yet been visited; recurse
                self.strongconnect(graph, w);
                self.lowlink[v_idx] = self.lowlink[v_idx].min(self.lowlink[w_idx]);
            } else if self.on_stack[w_idx] {
                // Successor w is on stack and hence in the current SCC
                // Note: index[w] is valid here because w has been visited
                self.lowlink[v_idx] = self.lowlink[v_idx].min(self.index[w_idx].unwrap());
            }
        }

        // If v is a root node, pop the stack and generate an SCC
        if self.lowlink[v_idx] == self.index[v_idx].unwrap() {
            let mut scc = Vec::new();
            loop {
                let w = self.stack.pop().unwrap();
                self.on_stack[w.index()] = false;
                scc.push(w);
                if w == v {
                    break;
                }
            }
            self.sccs.push(scc);
        }
    }
}

/// Returns the condensation graph: a DAG where each SCC is collapsed to a single node.
///
/// The condensation graph has one node per SCC, with edges representing
/// connections between different SCCs. This is always a DAG (directed acyclic
/// graph) since edges within SCCs are collapsed.
///
/// # Arguments
///
/// * `graph` - The original graph
/// * `sccs` - The SCCs as returned by `strongly_connected_components`
///
/// # Returns
///
/// A tuple containing:
/// - A vector mapping each original node to its SCC index
/// - A vector of edges `(from_scc, to_scc)` in the condensation graph
///
/// # Examples
///
/// ```rust,ignore
/// use dotscope::graph::{DirectedGraph, NodeId, algorithms::{strongly_connected_components, condensation}};
///
/// let mut graph: DirectedGraph<char, ()> = DirectedGraph::new();
/// let a = graph.add_node('A');
/// let b = graph.add_node('B');
/// let c = graph.add_node('C');
/// let d = graph.add_node('D');
///
/// // Cycle A -> B -> A, plus C -> D (separate)
/// graph.add_edge(a, b, ());
/// graph.add_edge(b, a, ());
/// graph.add_edge(a, c, ());
/// graph.add_edge(c, d, ());
///
/// let sccs = strongly_connected_components(&graph);
/// let (node_to_scc, edges) = condensation(&graph, &sccs);
///
/// // A and B are in the same SCC
/// assert_eq!(node_to_scc[a.index()], node_to_scc[b.index()]);
/// ```
pub fn condensation<G>(graph: &G, sccs: &[Vec<NodeId>]) -> (Vec<usize>, Vec<(usize, usize)>)
where
    G: Successors,
{
    let node_count = graph.node_count();

    // Build mapping from node to SCC index
    let mut node_to_scc = vec![0; node_count];
    for (scc_idx, scc) in sccs.iter().enumerate() {
        for &node in scc {
            node_to_scc[node.index()] = scc_idx;
        }
    }

    // Find edges between different SCCs
    let mut edges = Vec::new();
    let mut seen_edges = std::collections::HashSet::new();

    for i in 0..node_count {
        let from_node = NodeId::new(i);
        let from_scc = node_to_scc[i];

        for to_node in graph.successors(from_node) {
            let to_scc = node_to_scc[to_node.index()];

            if from_scc != to_scc && seen_edges.insert((from_scc, to_scc)) {
                edges.push((from_scc, to_scc));
            }
        }
    }

    (node_to_scc, edges)
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use crate::utils::graph::{
        algorithms::scc::{condensation, strongly_connected_components},
        DirectedGraph, NodeId,
    };

    #[test]
    fn test_scc_empty_graph() {
        let graph: DirectedGraph<(), ()> = DirectedGraph::new();
        let sccs = strongly_connected_components(&graph);
        assert!(sccs.is_empty());
    }

    #[test]
    fn test_scc_single_node() {
        let mut graph: DirectedGraph<(), ()> = DirectedGraph::new();
        let a = graph.add_node(());

        let sccs = strongly_connected_components(&graph);
        assert_eq!(sccs.len(), 1);
        assert_eq!(sccs[0], vec![a]);
    }

    #[test]
    fn test_scc_single_node_self_loop() {
        let mut graph: DirectedGraph<(), ()> = DirectedGraph::new();
        let a = graph.add_node(());
        graph.add_edge(a, a, ()).unwrap();

        let sccs = strongly_connected_components(&graph);
        assert_eq!(sccs.len(), 1);
        assert_eq!(sccs[0], vec![a]);
    }

    #[test]
    fn test_scc_linear_chain() {
        // A -> B -> C (no cycles)
        let mut graph: DirectedGraph<char, ()> = DirectedGraph::new();
        let a = graph.add_node('A');
        let b = graph.add_node('B');
        let c = graph.add_node('C');
        graph.add_edge(a, b, ()).unwrap();
        graph.add_edge(b, c, ()).unwrap();

        let sccs = strongly_connected_components(&graph);

        // Each node is its own SCC
        assert_eq!(sccs.len(), 3);
        for scc in &sccs {
            assert_eq!(scc.len(), 1);
        }

        // SCCs are in reverse topological order: C, B, A
        let scc_nodes: Vec<NodeId> = sccs.iter().map(|scc| scc[0]).collect();
        assert_eq!(scc_nodes, vec![c, b, a]);
    }

    #[test]
    fn test_scc_simple_cycle() {
        // A -> B -> C -> A
        let mut graph: DirectedGraph<char, ()> = DirectedGraph::new();
        let a = graph.add_node('A');
        let b = graph.add_node('B');
        let c = graph.add_node('C');
        graph.add_edge(a, b, ()).unwrap();
        graph.add_edge(b, c, ()).unwrap();
        graph.add_edge(c, a, ()).unwrap();

        let sccs = strongly_connected_components(&graph);

        // All three nodes form one SCC
        assert_eq!(sccs.len(), 1);
        assert_eq!(sccs[0].len(), 3);

        let scc_set: HashSet<NodeId> = sccs[0].iter().copied().collect();
        assert!(scc_set.contains(&a));
        assert!(scc_set.contains(&b));
        assert!(scc_set.contains(&c));
    }

    #[test]
    fn test_scc_two_nodes_cycle() {
        // A <-> B
        let mut graph: DirectedGraph<char, ()> = DirectedGraph::new();
        let a = graph.add_node('A');
        let b = graph.add_node('B');
        graph.add_edge(a, b, ()).unwrap();
        graph.add_edge(b, a, ()).unwrap();

        let sccs = strongly_connected_components(&graph);

        assert_eq!(sccs.len(), 1);
        assert_eq!(sccs[0].len(), 2);
    }

    #[test]
    fn test_scc_multiple_components() {
        // Two separate cycles: A <-> B and C <-> D
        let mut graph: DirectedGraph<char, ()> = DirectedGraph::new();
        let a = graph.add_node('A');
        let b = graph.add_node('B');
        let c = graph.add_node('C');
        let d = graph.add_node('D');

        graph.add_edge(a, b, ()).unwrap();
        graph.add_edge(b, a, ()).unwrap();
        graph.add_edge(c, d, ()).unwrap();
        graph.add_edge(d, c, ()).unwrap();

        let sccs = strongly_connected_components(&graph);

        assert_eq!(sccs.len(), 2);

        // Each SCC has 2 nodes
        for scc in &sccs {
            assert_eq!(scc.len(), 2);
        }
    }

    #[test]
    fn test_scc_connected_cycles() {
        // Two cycles connected by an edge:
        // A <-> B -> C <-> D
        let mut graph: DirectedGraph<char, ()> = DirectedGraph::new();
        let a = graph.add_node('A');
        let b = graph.add_node('B');
        let c = graph.add_node('C');
        let d = graph.add_node('D');

        graph.add_edge(a, b, ()).unwrap();
        graph.add_edge(b, a, ()).unwrap();
        graph.add_edge(b, c, ()).unwrap();
        graph.add_edge(c, d, ()).unwrap();
        graph.add_edge(d, c, ()).unwrap();

        let sccs = strongly_connected_components(&graph);

        assert_eq!(sccs.len(), 2);

        // One SCC contains {A, B}, another contains {C, D}
        let mut found_ab = false;
        let mut found_cd = false;

        for scc in &sccs {
            let scc_set: HashSet<NodeId> = scc.iter().copied().collect();
            if scc_set.contains(&a) && scc_set.contains(&b) && scc.len() == 2 {
                found_ab = true;
            }
            if scc_set.contains(&c) && scc_set.contains(&d) && scc.len() == 2 {
                found_cd = true;
            }
        }

        assert!(found_ab);
        assert!(found_cd);
    }

    #[test]
    fn test_scc_diamond_no_cycle() {
        // Diamond: A -> B -> D, A -> C -> D (no cycles)
        let mut graph: DirectedGraph<char, ()> = DirectedGraph::new();
        let a = graph.add_node('A');
        let b = graph.add_node('B');
        let c = graph.add_node('C');
        let d = graph.add_node('D');

        graph.add_edge(a, b, ()).unwrap();
        graph.add_edge(a, c, ()).unwrap();
        graph.add_edge(b, d, ()).unwrap();
        graph.add_edge(c, d, ()).unwrap();

        let sccs = strongly_connected_components(&graph);

        // Each node is its own SCC
        assert_eq!(sccs.len(), 4);
        for scc in &sccs {
            assert_eq!(scc.len(), 1);
        }
    }

    #[test]
    fn test_scc_figure_eight() {
        // Figure-8 pattern: A <-> B, B -> C, C <-> D
        // This creates two SCCs connected through B and C
        let mut graph: DirectedGraph<char, ()> = DirectedGraph::new();
        let a = graph.add_node('A');
        let b = graph.add_node('B');
        let c = graph.add_node('C');
        let d = graph.add_node('D');

        graph.add_edge(a, b, ()).unwrap();
        graph.add_edge(b, a, ()).unwrap();
        graph.add_edge(b, c, ()).unwrap();
        graph.add_edge(c, d, ()).unwrap();
        graph.add_edge(d, c, ()).unwrap();

        let sccs = strongly_connected_components(&graph);

        // Two SCCs: {A, B} and {C, D}
        assert_eq!(sccs.len(), 2);
    }

    #[test]
    fn test_scc_reverse_topological_order() {
        // Chain with cycles: (A <-> B) -> (C <-> D) -> E
        let mut graph: DirectedGraph<char, ()> = DirectedGraph::new();
        let a = graph.add_node('A');
        let b = graph.add_node('B');
        let c = graph.add_node('C');
        let d = graph.add_node('D');
        let e = graph.add_node('E');

        graph.add_edge(a, b, ()).unwrap();
        graph.add_edge(b, a, ()).unwrap();
        graph.add_edge(b, c, ()).unwrap();
        graph.add_edge(c, d, ()).unwrap();
        graph.add_edge(d, c, ()).unwrap();
        graph.add_edge(d, e, ()).unwrap();

        let sccs = strongly_connected_components(&graph);

        assert_eq!(sccs.len(), 3);

        // Find which SCC each node belongs to
        let find_scc =
            |node: NodeId| -> usize { sccs.iter().position(|scc| scc.contains(&node)).unwrap() };

        let scc_ab = find_scc(a);
        let scc_cd = find_scc(c);
        let scc_e = find_scc(e);

        // In reverse topological order: E comes first, then CD, then AB
        assert!(scc_e < scc_cd);
        assert!(scc_cd < scc_ab);
    }

    #[test]
    fn test_scc_large_cycle() {
        // Large cycle: 0 -> 1 -> 2 -> ... -> 99 -> 0
        let mut graph: DirectedGraph<usize, ()> = DirectedGraph::new();
        let nodes: Vec<NodeId> = (0..100).map(|i| graph.add_node(i)).collect();

        for i in 0..100 {
            graph.add_edge(nodes[i], nodes[(i + 1) % 100], ()).unwrap();
        }

        let sccs = strongly_connected_components(&graph);

        // All 100 nodes form one SCC
        assert_eq!(sccs.len(), 1);
        assert_eq!(sccs[0].len(), 100);
    }

    #[test]
    fn test_condensation_basic() {
        // A <-> B -> C (single edge to C)
        let mut graph: DirectedGraph<char, ()> = DirectedGraph::new();
        let a = graph.add_node('A');
        let b = graph.add_node('B');
        let c = graph.add_node('C');

        graph.add_edge(a, b, ()).unwrap();
        graph.add_edge(b, a, ()).unwrap();
        graph.add_edge(b, c, ()).unwrap();

        let sccs = strongly_connected_components(&graph);
        let (node_to_scc, edges) = condensation(&graph, &sccs);

        // A and B are in the same SCC
        assert_eq!(node_to_scc[a.index()], node_to_scc[b.index()]);

        // C is in a different SCC
        assert_ne!(node_to_scc[a.index()], node_to_scc[c.index()]);

        // There's one edge in the condensation graph (from {A,B} SCC to {C} SCC)
        assert_eq!(edges.len(), 1);
    }

    #[test]
    fn test_condensation_no_edges() {
        // Two disconnected cycles
        let mut graph: DirectedGraph<char, ()> = DirectedGraph::new();
        let a = graph.add_node('A');
        let b = graph.add_node('B');
        let c = graph.add_node('C');
        let d = graph.add_node('D');

        graph.add_edge(a, b, ()).unwrap();
        graph.add_edge(b, a, ()).unwrap();
        graph.add_edge(c, d, ()).unwrap();
        graph.add_edge(d, c, ()).unwrap();

        let sccs = strongly_connected_components(&graph);
        let (_, edges) = condensation(&graph, &sccs);

        // No edges between SCCs
        assert!(edges.is_empty());
    }

    #[test]
    fn test_condensation_chain() {
        // Chain of SCCs: (A<->B) -> (C<->D) -> E
        let mut graph: DirectedGraph<char, ()> = DirectedGraph::new();
        let a = graph.add_node('A');
        let b = graph.add_node('B');
        let c = graph.add_node('C');
        let d = graph.add_node('D');
        let e = graph.add_node('E');

        graph.add_edge(a, b, ()).unwrap();
        graph.add_edge(b, a, ()).unwrap();
        graph.add_edge(b, c, ()).unwrap();
        graph.add_edge(c, d, ()).unwrap();
        graph.add_edge(d, c, ()).unwrap();
        graph.add_edge(d, e, ()).unwrap();

        let sccs = strongly_connected_components(&graph);
        let (node_to_scc, edges) = condensation(&graph, &sccs);

        // Verify SCC assignments
        assert_eq!(node_to_scc[a.index()], node_to_scc[b.index()]);
        assert_eq!(node_to_scc[c.index()], node_to_scc[d.index()]);
        assert_ne!(node_to_scc[a.index()], node_to_scc[c.index()]);
        assert_ne!(node_to_scc[c.index()], node_to_scc[e.index()]);

        // Two edges in condensation: AB->CD, CD->E
        assert_eq!(edges.len(), 2);
    }

    #[test]
    fn test_scc_disconnected_graph() {
        // Completely disconnected nodes
        let mut graph: DirectedGraph<char, ()> = DirectedGraph::new();
        let _a = graph.add_node('A');
        let _b = graph.add_node('B');
        let _c = graph.add_node('C');

        let sccs = strongly_connected_components(&graph);

        // Each node is its own SCC
        assert_eq!(sccs.len(), 3);
        for scc in &sccs {
            assert_eq!(scc.len(), 1);
        }
    }

    #[test]
    fn test_scc_complex_structure() {
        // Complex graph with multiple SCCs
        //
        //     +---+
        //     v   |
        // A-->B-->C
        // |   |
        // v   v
        // D<->E-->F
        //         |
        //         v
        //         G
        let mut graph: DirectedGraph<char, ()> = DirectedGraph::new();
        let a = graph.add_node('A');
        let b = graph.add_node('B');
        let c = graph.add_node('C');
        let d = graph.add_node('D');
        let e = graph.add_node('E');
        let f = graph.add_node('F');
        let g = graph.add_node('G');

        graph.add_edge(a, b, ()).unwrap();
        graph.add_edge(b, c, ()).unwrap();
        graph.add_edge(c, b, ()).unwrap(); // B <-> C cycle
        graph.add_edge(a, d, ()).unwrap();
        graph.add_edge(b, e, ()).unwrap();
        graph.add_edge(d, e, ()).unwrap();
        graph.add_edge(e, d, ()).unwrap(); // D <-> E cycle
        graph.add_edge(e, f, ()).unwrap();
        graph.add_edge(f, g, ()).unwrap();

        let sccs = strongly_connected_components(&graph);

        // SCCs: {B, C}, {D, E}, {A}, {F}, {G}
        assert_eq!(sccs.len(), 5);

        // Count SCC sizes
        let mut size_counts = std::collections::HashMap::new();
        for scc in &sccs {
            *size_counts.entry(scc.len()).or_insert(0) += 1;
        }

        // Two SCCs of size 2, three of size 1
        assert_eq!(size_counts.get(&2), Some(&2));
        assert_eq!(size_counts.get(&1), Some(&3));
    }
}
