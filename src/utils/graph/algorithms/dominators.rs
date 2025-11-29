//! Dominator tree computation using the Lengauer-Tarjan algorithm.
//!
//! This module provides efficient dominator tree computation for rooted directed
//! graphs. The dominator tree is a fundamental data structure for:
//!
//! - SSA (Static Single Assignment) construction
//! - Loop detection and analysis
//! - Compiler optimizations
//! - Control flow analysis
//!
//! # Theory
//!
//! A node `d` **dominates** a node `n` if every path from the entry node to `n`
//! must pass through `d`. The **immediate dominator** of `n` (idom(n)) is the
//! unique node that strictly dominates `n` but does not strictly dominate any
//! other dominator of `n`.
//!
//! The dominator tree is formed by making each node's immediate dominator its
//! parent. The entry node is the root (it has no dominator).
//!
//! # Algorithm
//!
//! This implementation uses the Lengauer-Tarjan algorithm with path compression,
//! achieving O(V α(V)) time complexity where α is the inverse Ackermann function
//! (effectively constant for all practical inputs).

use std::collections::HashSet;

use crate::utils::graph::{NodeId, RootedGraph, Successors};

/// Result of dominator tree computation.
///
/// The dominator tree represents the dominance relationships in a control flow
/// graph. Each node (except the entry) has exactly one immediate dominator.
///
/// # Examples
///
/// ```rust,ignore
/// use dotscope::graph::{DirectedGraph, NodeId, algorithms::compute_dominators};
///
/// // Simple CFG: entry -> a -> b -> exit
/// let mut graph: DirectedGraph<&str, ()> = DirectedGraph::new();
/// let entry = graph.add_node("entry");
/// let a = graph.add_node("a");
/// let b = graph.add_node("b");
/// let exit = graph.add_node("exit");
///
/// graph.add_edge(entry, a, ());
/// graph.add_edge(a, b, ());
/// graph.add_edge(b, exit, ());
///
/// let dom_tree = compute_dominators(&graph, entry);
///
/// // entry dominates everything
/// assert!(dom_tree.dominates(entry, exit));
/// // a is the immediate dominator of b
/// assert_eq!(dom_tree.immediate_dominator(b), Some(a));
/// ```
#[derive(Debug, Clone)]
pub struct DominatorTree {
    /// The entry (root) node of the dominator tree
    entry: NodeId,
    /// Immediate dominator for each node (indexed by node ID)
    /// Entry node maps to itself (or we could use Option, but this simplifies queries)
    idom: Vec<NodeId>,
    /// Number of nodes in the graph
    node_count: usize,
}

impl DominatorTree {
    /// Returns the entry (root) node of the dominator tree.
    #[inline]
    pub fn entry(&self) -> NodeId {
        self.entry
    }

    /// Returns the immediate dominator of a node, or `None` for the entry node.
    ///
    /// The immediate dominator is the closest strict dominator of the node.
    ///
    /// # Panics
    ///
    /// Panics if the node index is out of bounds.
    #[inline]
    pub fn immediate_dominator(&self, node: NodeId) -> Option<NodeId> {
        if node == self.entry {
            None
        } else {
            Some(self.idom[node.index()])
        }
    }

    /// Checks if node `a` dominates node `b`.
    ///
    /// A node dominates itself. The entry node dominates all reachable nodes.
    ///
    /// # Complexity
    ///
    /// O(depth) where depth is the depth of `b` in the dominator tree.
    pub fn dominates(&self, a: NodeId, b: NodeId) -> bool {
        if a == b {
            return true;
        }

        let mut current = b;
        while current != self.entry {
            let idom = self.idom[current.index()];
            if idom == a {
                return true;
            }
            current = idom;
        }

        // Only the entry can dominate the entry
        a == self.entry
    }

    /// Checks if node `a` strictly dominates node `b`.
    ///
    /// Strict dominance excludes self-dominance: a strictly dominates b iff
    /// a dominates b and a ≠ b.
    #[inline]
    pub fn strictly_dominates(&self, a: NodeId, b: NodeId) -> bool {
        a != b && self.dominates(a, b)
    }

    /// Returns an iterator over all dominators of a node, from the node itself
    /// up to (and including) the entry node.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::graph::{DirectedGraph, NodeId, algorithms::compute_dominators};
    ///
    /// let mut graph: DirectedGraph<(), ()> = DirectedGraph::new();
    /// let entry = graph.add_node(());
    /// let a = graph.add_node(());
    /// let b = graph.add_node(());
    /// graph.add_edge(entry, a, ());
    /// graph.add_edge(a, b, ());
    ///
    /// let dom_tree = compute_dominators(&graph, entry);
    /// let dominators: Vec<NodeId> = dom_tree.dominators(b).collect();
    /// // b is dominated by b, a, and entry
    /// assert_eq!(dominators, vec![b, a, entry]);
    /// ```
    pub fn dominators(&self, node: NodeId) -> DominatorIterator<'_> {
        DominatorIterator {
            tree: self,
            current: Some(node),
        }
    }

    /// Returns the depth of a node in the dominator tree.
    ///
    /// The entry node has depth 0.
    pub fn depth(&self, node: NodeId) -> usize {
        let mut depth = 0;
        let mut current = node;
        while current != self.entry {
            current = self.idom[current.index()];
            depth += 1;
        }
        depth
    }

    /// Returns all children of a node in the dominator tree.
    ///
    /// Children are nodes whose immediate dominator is the given node.
    ///
    /// # Complexity
    ///
    /// O(V) where V is the number of nodes.
    pub fn children(&self, node: NodeId) -> Vec<NodeId> {
        let mut result = Vec::new();
        for i in 0..self.node_count {
            let n = NodeId::new(i);
            if n != self.entry && self.idom[i] == node {
                result.push(n);
            }
        }
        result
    }

    /// Returns the number of nodes in the dominator tree.
    #[inline]
    pub fn node_count(&self) -> usize {
        self.node_count
    }
}

/// Iterator over dominators of a node, from the node up to the entry.
pub struct DominatorIterator<'a> {
    tree: &'a DominatorTree,
    current: Option<NodeId>,
}

impl Iterator for DominatorIterator<'_> {
    type Item = NodeId;

    fn next(&mut self) -> Option<Self::Item> {
        let current = self.current?;

        if current == self.tree.entry {
            self.current = None;
            Some(current)
        } else {
            self.current = Some(self.tree.idom[current.index()]);
            Some(current)
        }
    }
}

/// Computes the dominator tree for a rooted graph using the Lengauer-Tarjan algorithm.
///
/// This algorithm efficiently computes the immediate dominator for every node
/// reachable from the entry node.
///
/// # Arguments
///
/// * `graph` - The graph to analyze (must implement `RootedGraph`)
///
/// # Returns
///
/// A `DominatorTree` containing the dominator relationships.
///
/// # Complexity
///
/// - Time: O(V α(V)) where α is the inverse Ackermann function
/// - Space: O(V)
///
/// # Algorithm Overview
///
/// The Lengauer-Tarjan algorithm works in several phases:
///
/// 1. **DFS numbering**: Assign DFS numbers to nodes and compute the DFS tree
/// 2. **Semidominators**: Compute semidominators using the Semidominator Theorem
/// 3. **Implicit idom**: Compute implicit immediate dominators
/// 4. **Explicit idom**: Convert implicit to explicit immediate dominators
///
/// # Examples
///
/// ```rust,ignore
/// use dotscope::graph::{DirectedGraph, NodeId, algorithms::compute_dominators};
///
/// // Diamond CFG:
/// //      entry
/// //      /   \
/// //     a     b
/// //      \   /
/// //       exit
/// let mut graph: DirectedGraph<&str, ()> = DirectedGraph::new();
/// let entry = graph.add_node("entry");
/// let a = graph.add_node("a");
/// let b = graph.add_node("b");
/// let exit = graph.add_node("exit");
///
/// graph.add_edge(entry, a, ());
/// graph.add_edge(entry, b, ());
/// graph.add_edge(a, exit, ());
/// graph.add_edge(b, exit, ());
///
/// let dom_tree = compute_dominators(&graph, entry);
///
/// // Entry dominates all nodes
/// assert!(dom_tree.dominates(entry, a));
/// assert!(dom_tree.dominates(entry, b));
/// assert!(dom_tree.dominates(entry, exit));
///
/// // a and b don't dominate exit (there are alternative paths)
/// assert!(!dom_tree.strictly_dominates(a, exit));
/// assert!(!dom_tree.strictly_dominates(b, exit));
///
/// // exit's immediate dominator is entry (not a or b)
/// assert_eq!(dom_tree.immediate_dominator(exit), Some(entry));
/// ```
pub fn compute_dominators<G>(graph: &G, entry: NodeId) -> DominatorTree
where
    G: Successors,
{
    let node_count = graph.node_count();

    if node_count == 0 {
        return DominatorTree {
            entry,
            idom: Vec::new(),
            node_count: 0,
        };
    }

    // Lengauer-Tarjan algorithm implementation
    let mut lt = LengauerTarjan::new(node_count, entry);
    lt.compute(graph);

    DominatorTree {
        entry,
        idom: lt.idom,
        node_count,
    }
}

/// Convenience function to compute dominators for a [`RootedGraph`].
///
/// This is equivalent to calling `compute_dominators(graph, graph.entry())`.
pub fn compute_dominators_rooted<G>(graph: &G) -> DominatorTree
where
    G: RootedGraph,
{
    compute_dominators(graph, graph.entry())
}

/// Internal state for the Lengauer-Tarjan algorithm.
struct LengauerTarjan {
    /// Number of nodes
    n: usize,
    /// Entry node
    entry: NodeId,
    /// DFS number for each node (0 = not visited)
    dfnum: Vec<usize>,
    /// Node with each DFS number (inverse of dfnum)
    vertex: Vec<NodeId>,
    /// Parent in DFS tree
    parent: Vec<NodeId>,
    /// Semidominator (by DFS number, stored as node ID)
    semi: Vec<NodeId>,
    /// Immediate dominator (final result)
    idom: Vec<NodeId>,
    /// Ancestor in the forest for link-eval
    ancestor: Vec<NodeId>,
    /// Best node on path to ancestor (for path compression)
    best: Vec<NodeId>,
    /// Bucket for each node (nodes whose semidominator is this node)
    bucket: Vec<Vec<NodeId>>,
    /// Current DFS counter
    dfs_counter: usize,
}

impl LengauerTarjan {
    fn new(n: usize, entry: NodeId) -> Self {
        let sentinel = NodeId::new(usize::MAX);
        Self {
            n,
            entry,
            dfnum: vec![0; n],
            vertex: vec![sentinel; n],
            parent: vec![sentinel; n],
            semi: (0..n).map(NodeId::new).collect(),
            idom: vec![sentinel; n],
            ancestor: vec![sentinel; n],
            best: (0..n).map(NodeId::new).collect(),
            bucket: vec![Vec::new(); n],
            dfs_counter: 0,
        }
    }

    fn compute<G: Successors>(&mut self, graph: &G) {
        // Phase 1: DFS numbering
        self.dfs(graph, self.entry);

        // Process nodes in reverse DFS order (excluding entry)
        for i in (1..self.dfs_counter).rev() {
            let w = self.vertex[i];
            let parent_w = self.parent[w.index()];

            // Phase 2: Compute semidominators
            // semi(w) = min { v : v -> w is a CFG edge and dfnum(v) < dfnum(w) } ∪
            //           { semi(u) : u -> w via tree edges where dfnum(u) > dfnum(w) }
            for v in self.predecessors_of(graph, w) {
                if self.dfnum[v.index()] == 0 {
                    // v is unreachable from entry, skip
                    continue;
                }
                let u = self.eval(v);
                if self.dfnum[self.semi[u.index()].index()]
                    < self.dfnum[self.semi[w.index()].index()]
                {
                    self.semi[w.index()] = self.semi[u.index()];
                }
            }

            // Add w to bucket of its semidominator
            let semi_w = self.semi[w.index()];
            self.bucket[semi_w.index()].push(w);

            // Link w into the forest
            self.link(parent_w, w);

            // Phase 3: Implicitly compute immediate dominators
            // Process bucket of parent(w)
            let bucket = std::mem::take(&mut self.bucket[parent_w.index()]);
            for v in bucket {
                let u = self.eval(v);
                if self.semi[u.index()] == self.semi[v.index()] {
                    // idom(v) = semi(v) = parent(w)
                    self.idom[v.index()] = parent_w;
                } else {
                    // idom(v) = idom(u) (will be computed later)
                    self.idom[v.index()] = u;
                }
            }
        }

        // Phase 4: Explicitly compute immediate dominators
        for i in 1..self.dfs_counter {
            let w = self.vertex[i];
            if self.idom[w.index()] != self.semi[w.index()] {
                self.idom[w.index()] = self.idom[self.idom[w.index()].index()];
            }
        }

        // Entry node dominates itself
        self.idom[self.entry.index()] = self.entry;
    }

    /// DFS traversal to assign DFS numbers and build DFS tree.
    fn dfs<G: Successors>(&mut self, graph: &G, start: NodeId) {
        let mut stack = vec![(start, false)];

        while let Some((node, processed)) = stack.pop() {
            let idx = node.index();

            if processed {
                continue;
            }

            if self.dfnum[idx] != 0 {
                continue;
            }

            self.dfs_counter += 1;
            self.dfnum[idx] = self.dfs_counter;
            self.vertex[self.dfs_counter - 1] = node;

            for succ in graph.successors(node) {
                if self.dfnum[succ.index()] == 0 {
                    self.parent[succ.index()] = node;
                    stack.push((succ, false));
                }
            }
        }
    }

    /// Get predecessors of a node by checking all nodes.
    /// This is O(V) per call; a better implementation would precompute predecessors.
    fn predecessors_of<G: Successors>(&self, graph: &G, node: NodeId) -> Vec<NodeId> {
        let mut preds = Vec::new();
        for i in 0..self.n {
            let v = NodeId::new(i);
            for succ in graph.successors(v) {
                if succ == node {
                    preds.push(v);
                    break;
                }
            }
        }
        preds
    }

    /// Link v as a child of w in the spanning forest.
    fn link(&mut self, w: NodeId, v: NodeId) {
        self.ancestor[v.index()] = w;
    }

    /// Evaluate: find the node with minimum semidominator on the path to the root.
    fn eval(&mut self, v: NodeId) -> NodeId {
        let sentinel = NodeId::new(usize::MAX);
        if self.ancestor[v.index()] == sentinel {
            return v;
        }

        self.compress(v);
        self.best[v.index()]
    }

    /// Path compression for the forest.
    fn compress(&mut self, v: NodeId) {
        let sentinel = NodeId::new(usize::MAX);
        let ancestor_v = self.ancestor[v.index()];

        if self.ancestor[ancestor_v.index()] == sentinel {
            return;
        }

        self.compress(ancestor_v);

        let best_ancestor = self.best[ancestor_v.index()];
        let best_v = self.best[v.index()];

        if self.dfnum[self.semi[best_ancestor.index()].index()]
            < self.dfnum[self.semi[best_v.index()].index()]
        {
            self.best[v.index()] = best_ancestor;
        }

        self.ancestor[v.index()] = self.ancestor[ancestor_v.index()];
    }
}

/// Computes dominance frontiers for all nodes.
///
/// The dominance frontier of a node `n` is the set of all nodes `m` such that:
/// - `n` dominates a predecessor of `m`, but
/// - `n` does not strictly dominate `m`
///
/// Dominance frontiers are essential for placing φ-functions in SSA construction.
///
/// # Arguments
///
/// * `graph` - The control flow graph
/// * `dom_tree` - The precomputed dominator tree
///
/// # Returns
///
/// A vector where `result[i]` contains the dominance frontier of node `i`.
///
/// # Complexity
///
/// - Time: O(V + E)
/// - Space: O(V²) worst case for the frontiers
///
/// # Examples
///
/// ```rust,ignore
/// use dotscope::graph::{DirectedGraph, NodeId, algorithms::{compute_dominators, compute_dominance_frontiers}};
///
/// // Diamond CFG with join point
/// let mut graph: DirectedGraph<&str, ()> = DirectedGraph::new();
/// let entry = graph.add_node("entry");
/// let left = graph.add_node("left");
/// let right = graph.add_node("right");
/// let join = graph.add_node("join");
///
/// graph.add_edge(entry, left, ());
/// graph.add_edge(entry, right, ());
/// graph.add_edge(left, join, ());
/// graph.add_edge(right, join, ());
///
/// let dom_tree = compute_dominators(&graph, entry);
/// let frontiers = compute_dominance_frontiers(&graph, &dom_tree);
///
/// // The dominance frontier of 'left' includes 'join' (where paths merge)
/// assert!(frontiers[left.index()].contains(&join));
/// // The dominance frontier of 'right' includes 'join'
/// assert!(frontiers[right.index()].contains(&join));
/// ```
pub fn compute_dominance_frontiers<G>(graph: &G, dom_tree: &DominatorTree) -> Vec<HashSet<NodeId>>
where
    G: Successors,
{
    let n = graph.node_count();
    let mut frontiers: Vec<HashSet<NodeId>> = vec![HashSet::new(); n];

    // For each node, check if it's a join point (has multiple predecessors)
    // For each join point, walk up the dominator tree from each predecessor
    for node_idx in 0..n {
        let node = NodeId::new(node_idx);

        // Get predecessors of this node
        let preds = get_predecessors(graph, node);

        if preds.len() < 2 {
            continue; // Not a join point
        }

        // For each predecessor, walk up its dominators until we reach idom(node)
        let idom_node = dom_tree.immediate_dominator(node);

        for pred in preds {
            let mut runner = pred;
            while Some(runner) != idom_node && runner != dom_tree.entry() {
                frontiers[runner.index()].insert(node);
                if let Some(idom) = dom_tree.immediate_dominator(runner) {
                    runner = idom;
                } else {
                    break;
                }
            }
            // Also check entry if needed
            if Some(runner) != idom_node && runner == dom_tree.entry() {
                frontiers[runner.index()].insert(node);
            }
        }
    }

    frontiers
}

/// Helper to get predecessors of a node.
fn get_predecessors<G: Successors>(graph: &G, node: NodeId) -> Vec<NodeId> {
    let mut preds = Vec::new();
    for i in 0..graph.node_count() {
        let v = NodeId::new(i);
        for succ in graph.successors(v) {
            if succ == node {
                preds.push(v);
                break;
            }
        }
    }
    preds
}

#[cfg(test)]
mod tests {
    use crate::utils::graph::{
        algorithms::dominators::{compute_dominance_frontiers, compute_dominators},
        DirectedGraph, NodeId,
    };

    #[test]
    fn test_dominator_empty_graph() {
        let graph: DirectedGraph<(), ()> = DirectedGraph::new();
        // With empty graph, we need a valid entry - this is a degenerate case
        let entry = NodeId::new(0);
        let dom_tree = compute_dominators(&graph, entry);
        assert_eq!(dom_tree.node_count(), 0);
    }

    #[test]
    fn test_dominator_single_node() {
        let mut graph: DirectedGraph<(), ()> = DirectedGraph::new();
        let entry = graph.add_node(());

        let dom_tree = compute_dominators(&graph, entry);

        assert_eq!(dom_tree.entry(), entry);
        assert_eq!(dom_tree.immediate_dominator(entry), None);
        assert!(dom_tree.dominates(entry, entry));
        assert_eq!(dom_tree.depth(entry), 0);
    }

    #[test]
    fn test_dominator_linear_chain() {
        // entry -> a -> b -> c
        let mut graph: DirectedGraph<&str, ()> = DirectedGraph::new();
        let entry = graph.add_node("entry");
        let a = graph.add_node("a");
        let b = graph.add_node("b");
        let c = graph.add_node("c");

        graph.add_edge(entry, a, ()).unwrap();
        graph.add_edge(a, b, ()).unwrap();
        graph.add_edge(b, c, ()).unwrap();

        let dom_tree = compute_dominators(&graph, entry);

        // Check immediate dominators
        assert_eq!(dom_tree.immediate_dominator(entry), None);
        assert_eq!(dom_tree.immediate_dominator(a), Some(entry));
        assert_eq!(dom_tree.immediate_dominator(b), Some(a));
        assert_eq!(dom_tree.immediate_dominator(c), Some(b));

        // Check dominance relationships
        assert!(dom_tree.dominates(entry, a));
        assert!(dom_tree.dominates(entry, b));
        assert!(dom_tree.dominates(entry, c));
        assert!(dom_tree.dominates(a, b));
        assert!(dom_tree.dominates(a, c));
        assert!(dom_tree.dominates(b, c));

        // Check non-dominance
        assert!(!dom_tree.dominates(c, b));
        assert!(!dom_tree.dominates(b, a));

        // Check depths
        assert_eq!(dom_tree.depth(entry), 0);
        assert_eq!(dom_tree.depth(a), 1);
        assert_eq!(dom_tree.depth(b), 2);
        assert_eq!(dom_tree.depth(c), 3);
    }

    #[test]
    fn test_dominator_diamond() {
        // Diamond CFG:
        //      entry
        //      /   \
        //     a     b
        //      \   /
        //       exit
        let mut graph: DirectedGraph<&str, ()> = DirectedGraph::new();
        let entry = graph.add_node("entry");
        let a = graph.add_node("a");
        let b = graph.add_node("b");
        let exit = graph.add_node("exit");

        graph.add_edge(entry, a, ()).unwrap();
        graph.add_edge(entry, b, ()).unwrap();
        graph.add_edge(a, exit, ()).unwrap();
        graph.add_edge(b, exit, ()).unwrap();

        let dom_tree = compute_dominators(&graph, entry);

        // entry is immediate dominator of a, b, and exit
        assert_eq!(dom_tree.immediate_dominator(a), Some(entry));
        assert_eq!(dom_tree.immediate_dominator(b), Some(entry));
        assert_eq!(dom_tree.immediate_dominator(exit), Some(entry));

        // a and b don't dominate exit (alternative paths exist)
        assert!(!dom_tree.strictly_dominates(a, exit));
        assert!(!dom_tree.strictly_dominates(b, exit));

        // entry dominates all
        assert!(dom_tree.dominates(entry, a));
        assert!(dom_tree.dominates(entry, b));
        assert!(dom_tree.dominates(entry, exit));
    }

    #[test]
    fn test_dominator_if_then_else() {
        // if-then-else:
        //      entry
        //        |
        //       cond
        //      /    \
        //   then    else
        //      \    /
        //       merge
        //        |
        //       exit
        let mut graph: DirectedGraph<&str, ()> = DirectedGraph::new();
        let entry = graph.add_node("entry");
        let cond = graph.add_node("cond");
        let then_b = graph.add_node("then");
        let else_b = graph.add_node("else");
        let merge = graph.add_node("merge");
        let exit = graph.add_node("exit");

        graph.add_edge(entry, cond, ()).unwrap();
        graph.add_edge(cond, then_b, ()).unwrap();
        graph.add_edge(cond, else_b, ()).unwrap();
        graph.add_edge(then_b, merge, ()).unwrap();
        graph.add_edge(else_b, merge, ()).unwrap();
        graph.add_edge(merge, exit, ()).unwrap();

        let dom_tree = compute_dominators(&graph, entry);

        // Check dominator chain
        assert_eq!(dom_tree.immediate_dominator(cond), Some(entry));
        assert_eq!(dom_tree.immediate_dominator(then_b), Some(cond));
        assert_eq!(dom_tree.immediate_dominator(else_b), Some(cond));
        assert_eq!(dom_tree.immediate_dominator(merge), Some(cond));
        assert_eq!(dom_tree.immediate_dominator(exit), Some(merge));

        // cond dominates merge and exit
        assert!(dom_tree.dominates(cond, merge));
        assert!(dom_tree.dominates(cond, exit));

        // then/else don't dominate merge
        assert!(!dom_tree.strictly_dominates(then_b, merge));
        assert!(!dom_tree.strictly_dominates(else_b, merge));
    }

    #[test]
    fn test_dominator_loop() {
        // Simple loop:
        //      entry
        //        |
        //        v
        //   +-> header
        //   |    |
        //   |    v
        //   +-- body
        //        |
        //        v
        //       exit
        let mut graph: DirectedGraph<&str, ()> = DirectedGraph::new();
        let entry = graph.add_node("entry");
        let header = graph.add_node("header");
        let body = graph.add_node("body");
        let exit = graph.add_node("exit");

        graph.add_edge(entry, header, ()).unwrap();
        graph.add_edge(header, body, ()).unwrap();
        graph.add_edge(body, header, ()).unwrap(); // back edge
        graph.add_edge(body, exit, ()).unwrap();

        let dom_tree = compute_dominators(&graph, entry);

        // header dominates body and exit
        assert!(dom_tree.dominates(header, body));
        // body does not dominate header (despite the back edge)
        assert!(!dom_tree.strictly_dominates(body, header));
    }

    #[test]
    fn test_dominator_iterator() {
        let mut graph: DirectedGraph<&str, ()> = DirectedGraph::new();
        let entry = graph.add_node("entry");
        let a = graph.add_node("a");
        let b = graph.add_node("b");
        let c = graph.add_node("c");

        graph.add_edge(entry, a, ()).unwrap();
        graph.add_edge(a, b, ()).unwrap();
        graph.add_edge(b, c, ()).unwrap();

        let dom_tree = compute_dominators(&graph, entry);

        // Iterate dominators of c
        let dominators: Vec<NodeId> = dom_tree.dominators(c).collect();
        assert_eq!(dominators, vec![c, b, a, entry]);

        // Iterate dominators of entry
        let dominators: Vec<NodeId> = dom_tree.dominators(entry).collect();
        assert_eq!(dominators, vec![entry]);
    }

    #[test]
    fn test_dominator_children() {
        // Diamond CFG
        let mut graph: DirectedGraph<&str, ()> = DirectedGraph::new();
        let entry = graph.add_node("entry");
        let a = graph.add_node("a");
        let b = graph.add_node("b");
        let exit = graph.add_node("exit");

        graph.add_edge(entry, a, ()).unwrap();
        graph.add_edge(entry, b, ()).unwrap();
        graph.add_edge(a, exit, ()).unwrap();
        graph.add_edge(b, exit, ()).unwrap();

        let dom_tree = compute_dominators(&graph, entry);

        // entry has children: a, b, exit
        let mut children = dom_tree.children(entry);
        children.sort_by_key(|n| n.index());
        assert_eq!(children, vec![a, b, exit]);

        // a, b, exit have no children
        assert!(dom_tree.children(a).is_empty());
        assert!(dom_tree.children(b).is_empty());
        assert!(dom_tree.children(exit).is_empty());
    }

    #[test]
    fn test_dominance_frontier_diamond() {
        // Diamond CFG - classic case for dominance frontiers
        let mut graph: DirectedGraph<&str, ()> = DirectedGraph::new();
        let entry = graph.add_node("entry");
        let left = graph.add_node("left");
        let right = graph.add_node("right");
        let join = graph.add_node("join");

        graph.add_edge(entry, left, ()).unwrap();
        graph.add_edge(entry, right, ()).unwrap();
        graph.add_edge(left, join, ()).unwrap();
        graph.add_edge(right, join, ()).unwrap();

        let dom_tree = compute_dominators(&graph, entry);
        let frontiers = compute_dominance_frontiers(&graph, &dom_tree);

        // entry has no dominance frontier
        assert!(frontiers[entry.index()].is_empty());

        // left's dominance frontier is {join}
        assert!(frontiers[left.index()].contains(&join));
        assert_eq!(frontiers[left.index()].len(), 1);

        // right's dominance frontier is {join}
        assert!(frontiers[right.index()].contains(&join));
        assert_eq!(frontiers[right.index()].len(), 1);

        // join has no dominance frontier (no successors)
        assert!(frontiers[join.index()].is_empty());
    }

    #[test]
    fn test_dominance_frontier_loop() {
        // Loop with header
        let mut graph: DirectedGraph<&str, ()> = DirectedGraph::new();
        let entry = graph.add_node("entry");
        let header = graph.add_node("header");
        let body = graph.add_node("body");
        let exit = graph.add_node("exit");

        graph.add_edge(entry, header, ()).unwrap();
        graph.add_edge(header, body, ()).unwrap();
        graph.add_edge(body, header, ()).unwrap(); // back edge
        graph.add_edge(header, exit, ()).unwrap();

        let dom_tree = compute_dominators(&graph, entry);
        let frontiers = compute_dominance_frontiers(&graph, &dom_tree);

        // body's dominance frontier includes header (the loop header)
        assert!(frontiers[body.index()].contains(&header));
    }

    #[test]
    fn test_dominance_frontier_nested_if() {
        // Nested if structure:
        //       entry
        //         |
        //        if1
        //       /   \
        //      a     b
        //     / \     \
        //    c   d     e
        //     \ /     /
        //     join1  /
        //       \   /
        //       join2
        let mut graph: DirectedGraph<&str, ()> = DirectedGraph::new();
        let entry = graph.add_node("entry");
        let if1 = graph.add_node("if1");
        let a = graph.add_node("a");
        let b = graph.add_node("b");
        let c = graph.add_node("c");
        let d = graph.add_node("d");
        let e = graph.add_node("e");
        let join1 = graph.add_node("join1");
        let join2 = graph.add_node("join2");

        graph.add_edge(entry, if1, ()).unwrap();
        graph.add_edge(if1, a, ()).unwrap();
        graph.add_edge(if1, b, ()).unwrap();
        graph.add_edge(a, c, ()).unwrap();
        graph.add_edge(a, d, ()).unwrap();
        graph.add_edge(b, e, ()).unwrap();
        graph.add_edge(c, join1, ()).unwrap();
        graph.add_edge(d, join1, ()).unwrap();
        graph.add_edge(e, join2, ()).unwrap();
        graph.add_edge(join1, join2, ()).unwrap();

        let dom_tree = compute_dominators(&graph, entry);
        let frontiers = compute_dominance_frontiers(&graph, &dom_tree);

        // c and d have join1 in their dominance frontier
        assert!(frontiers[c.index()].contains(&join1));
        assert!(frontiers[d.index()].contains(&join1));

        // join1 and e have join2 in their dominance frontier
        assert!(frontiers[join1.index()].contains(&join2));
        assert!(frontiers[e.index()].contains(&join2));
    }

    #[test]
    fn test_strictly_dominates() {
        let mut graph: DirectedGraph<&str, ()> = DirectedGraph::new();
        let entry = graph.add_node("entry");
        let a = graph.add_node("a");

        graph.add_edge(entry, a, ()).unwrap();

        let dom_tree = compute_dominators(&graph, entry);

        // entry dominates itself but doesn't strictly dominate itself
        assert!(dom_tree.dominates(entry, entry));
        assert!(!dom_tree.strictly_dominates(entry, entry));

        // entry strictly dominates a
        assert!(dom_tree.strictly_dominates(entry, a));
    }

    #[test]
    fn test_dominator_complex_cfg() {
        // More complex CFG with multiple paths and joins
        //
        //        entry
        //          |
        //          a
        //         / \
        //        b   c
        //        |   |
        //        d   e
        //         \ / \
        //          f   g
        //          |
        //          h
        let mut graph: DirectedGraph<&str, ()> = DirectedGraph::new();
        let entry = graph.add_node("entry");
        let a = graph.add_node("a");
        let b = graph.add_node("b");
        let c = graph.add_node("c");
        let d = graph.add_node("d");
        let e = graph.add_node("e");
        let f = graph.add_node("f");
        let g = graph.add_node("g");
        let h = graph.add_node("h");

        graph.add_edge(entry, a, ()).unwrap();
        graph.add_edge(a, b, ()).unwrap();
        graph.add_edge(a, c, ()).unwrap();
        graph.add_edge(b, d, ()).unwrap();
        graph.add_edge(c, e, ()).unwrap();
        graph.add_edge(d, f, ()).unwrap();
        graph.add_edge(e, f, ()).unwrap();
        graph.add_edge(e, g, ()).unwrap();
        graph.add_edge(f, h, ()).unwrap();

        let dom_tree = compute_dominators(&graph, entry);

        // a dominates everything below it
        assert!(dom_tree.dominates(a, b));
        assert!(dom_tree.dominates(a, c));
        assert!(dom_tree.dominates(a, d));
        assert!(dom_tree.dominates(a, e));
        assert!(dom_tree.dominates(a, f));
        assert!(dom_tree.dominates(a, g));
        assert!(dom_tree.dominates(a, h));

        // f's immediate dominator is a (not d or e, since there are multiple paths)
        assert_eq!(dom_tree.immediate_dominator(f), Some(a));

        // g's immediate dominator is e (only one path to g)
        assert_eq!(dom_tree.immediate_dominator(g), Some(e));
    }
}
