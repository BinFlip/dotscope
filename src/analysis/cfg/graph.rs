//! Control Flow Graph implementation.
//!
//! This module provides the main [`ControlFlowGraph`] structure that wraps basic blocks
//! with proper graph semantics and provides access to dominator trees, loops, and traversals.

use std::{collections::HashSet, fmt::Write, sync::OnceLock};

use crate::{
    analysis::cfg::{CfgEdge, CfgEdgeKind},
    assembly::{BasicBlock, FlowType, Operand},
    utils::{
        escape_dot,
        graph::{
            algorithms::{self, DominatorTree},
            DirectedGraph, EdgeId, NodeId,
        },
    },
    Error::GraphError,
    Result,
};

/// Information about a natural loop in the control flow graph.
///
/// A natural loop is a strongly connected region in the CFG with a single entry point
/// (the header). Back edges are edges from within the loop to the header.
///
/// # Examples
///
/// ```rust,ignore
/// use dotscope::analysis::ControlFlowGraph;
///
/// let cfg = ControlFlowGraph::from_basic_blocks(blocks)?;
/// for natural_loop in cfg.loops() {
///     println!("Loop header: {:?}", natural_loop.header);
///     println!("Loop body contains {} blocks", natural_loop.body.len());
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NaturalLoop {
    /// The header block of the loop (single entry point).
    pub header: NodeId,
    /// All blocks that are part of the loop body (including the header).
    pub body: HashSet<NodeId>,
    /// Back edges into the header (source nodes within the loop that jump to header).
    pub back_edges: Vec<NodeId>,
    /// Depth of this loop in the loop nest (0 = outermost).
    pub depth: usize,
}

impl NaturalLoop {
    /// Creates a new natural loop.
    fn new(header: NodeId) -> Self {
        let mut body = HashSet::new();
        body.insert(header);
        Self {
            header,
            body,
            back_edges: Vec::new(),
            depth: 0,
        }
    }

    /// Returns true if this loop contains the given block.
    ///
    /// # Arguments
    ///
    /// * `node` - The node ID to check
    ///
    /// # Returns
    ///
    /// `true` if the block is part of this loop's body, `false` otherwise.
    #[must_use]
    pub fn contains(&self, node: NodeId) -> bool {
        self.body.contains(&node)
    }

    /// Returns the number of blocks in the loop body.
    ///
    /// # Returns
    ///
    /// The count of basic blocks in this loop, including the header.
    #[must_use]
    pub fn size(&self) -> usize {
        self.body.len()
    }
}

/// A control flow graph built from CIL basic blocks.
///
/// The CFG provides a proper graph abstraction over basic blocks with efficient
/// traversal, dominator computation, and loop detection. It wraps an underlying
/// [`DirectedGraph`] and provides domain-specific accessors.
///
/// # Construction
///
/// Create a CFG from decoded basic blocks using [`from_basic_blocks`](Self::from_basic_blocks):
///
/// ```rust,ignore
/// use dotscope::analysis::ControlFlowGraph;
/// use dotscope::assembly::decode_blocks;
///
/// let blocks = decode_blocks(data, offset, rva, Some(size))?;
/// let cfg = ControlFlowGraph::from_basic_blocks(blocks)?;
/// ```
///
/// # Lazy Computation
///
/// Expensive analyses are computed lazily and cached:
///
/// - [`dominators`](Self::dominators) - Dominator tree (computed on first access)
/// - [`dominance_frontiers`](Self::dominance_frontiers) - For SSA phi-node placement
///
/// # Thread Safety
///
/// `ControlFlowGraph` is [`Send`] and [`Sync`]. Lazy-initialized fields use
/// [`OnceLock`] for thread-safe initialization.
///
/// # Lifetime Parameter
///
/// The `'a` lifetime represents the lifetime of borrowed basic block data:
/// - Use `ControlFlowGraph<'static>` for owned CFGs (blocks are `Cow::Owned`)
/// - Use `ControlFlowGraph<'a>` when borrowing blocks from a method
#[derive(Debug)]
pub struct ControlFlowGraph<'a> {
    /// The underlying directed graph structure.
    graph: DirectedGraph<'a, BasicBlock, CfgEdge>,
    /// Index of the entry block (always 0 for method entry).
    entry: NodeId,
    /// Indices of exit blocks (blocks with no successors or return instructions).
    exits: Vec<NodeId>,
    /// Lazily computed dominator tree.
    dominators: OnceLock<DominatorTree>,
    /// Lazily computed dominance frontiers.
    dominance_frontiers: OnceLock<Vec<HashSet<NodeId>>>,
    /// Lazily computed loop information.
    loops: OnceLock<Vec<NaturalLoop>>,
}

impl ControlFlowGraph<'static> {
    /// Creates a new control flow graph from a vector of basic blocks.
    ///
    /// This constructor builds the CFG by:
    /// 1. Adding each basic block as a node
    /// 2. Converting successor relationships into typed edges
    /// 3. Identifying entry and exit blocks
    ///
    /// # Arguments
    ///
    /// * `blocks` - A vector of basic blocks from the decoder
    ///
    /// # Returns
    ///
    /// A new `ControlFlowGraph` or an error if construction fails.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The blocks vector is empty
    /// - Block successor indices are out of range
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::analysis::ControlFlowGraph;
    /// use dotscope::assembly::decode_blocks;
    ///
    /// let blocks = decode_blocks(data, offset, rva, Some(size))?;
    /// let cfg = ControlFlowGraph::from_basic_blocks(blocks)?;
    /// ```
    pub fn from_basic_blocks(blocks: Vec<BasicBlock>) -> Result<Self> {
        if blocks.is_empty() {
            return Err(GraphError(
                "Cannot create CFG from empty block list".to_string(),
            ));
        }

        let block_count = blocks.len();
        let mut graph: DirectedGraph<BasicBlock, CfgEdge> =
            DirectedGraph::with_capacity(block_count, block_count * 2);

        // First pass: add all blocks as nodes
        let node_ids: Vec<NodeId> = blocks
            .into_iter()
            .map(|block| graph.add_node(block))
            .collect();

        // Second pass: add edges based on successor relationships
        for node_id in &node_ids {
            let block = graph.node(*node_id).ok_or_else(|| {
                GraphError(format!(
                    "Internal error: node {} not found in graph",
                    node_id.index()
                ))
            })?;
            let successors = block.successors.clone();
            let last_instruction = block.instructions.last();

            // Determine edge kinds based on the terminating instruction
            let flow_type = last_instruction.map(|i| i.flow_type);

            for (idx, &succ_idx) in successors.iter().enumerate() {
                if succ_idx >= block_count {
                    return Err(GraphError(format!(
                        "Block {} has successor index {} which exceeds block count {}",
                        node_id.index(),
                        succ_idx,
                        block_count
                    )));
                }

                let target_node = node_ids[succ_idx];
                let edge_kind = Self::classify_edge(flow_type, idx, successors.len());
                let edge = CfgEdge::new(succ_idx, edge_kind);

                graph.add_edge(*node_id, target_node, edge)?;
            }
        }

        // Identify entry and exit blocks
        let entry = node_ids[0]; // Method entry is always block 0
        let mut exits: Vec<NodeId> = Vec::new();
        for &node_id in &node_ids {
            let block = graph.node(node_id).ok_or_else(|| {
                GraphError(format!(
                    "Internal error: node {} not found in graph",
                    node_id.index()
                ))
            })?;
            // Exit if no successors or if last instruction is a return
            let is_exit = block.successors.is_empty()
                || block
                    .instructions
                    .last()
                    .is_some_and(|i| i.flow_type == FlowType::Return);
            if is_exit {
                exits.push(node_id);
            }
        }

        Ok(Self {
            graph,
            entry,
            exits,
            dominators: OnceLock::new(),
            dominance_frontiers: OnceLock::new(),
            loops: OnceLock::new(),
        })
    }
}

/// Methods available on any `ControlFlowGraph`, regardless of ownership.
impl<'a> ControlFlowGraph<'a> {
    /// Creates a new control flow graph borrowing blocks from a slice.
    ///
    /// This constructor enables zero-copy CFG construction when blocks are
    /// already stored elsewhere (e.g., in a method's `blocks` field).
    ///
    /// # Arguments
    ///
    /// * `blocks` - A slice of basic blocks to borrow
    ///
    /// # Returns
    ///
    /// A new `ControlFlowGraph` borrowing the blocks, or an error if construction fails.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The blocks slice is empty
    /// - Block successor indices are out of range
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::analysis::ControlFlowGraph;
    ///
    /// // Build CFG borrowing from method's blocks (zero-copy)
    /// if let Some(blocks) = method.blocks.get() {
    ///     let cfg = ControlFlowGraph::from_blocks_ref(blocks)?;
    ///     // cfg is valid as long as `blocks` is valid
    /// }
    /// ```
    pub fn from_blocks_ref(blocks: &'a [BasicBlock]) -> Result<Self> {
        if blocks.is_empty() {
            return Err(GraphError(
                "Cannot create CFG from empty block list".to_string(),
            ));
        }

        let block_count = blocks.len();
        let mut graph: DirectedGraph<'a, BasicBlock, CfgEdge> =
            DirectedGraph::from_nodes_borrowed(blocks);

        // Build edges based on successor relationships
        for (block_idx, block) in blocks.iter().enumerate() {
            let node_id = NodeId::new(block_idx);
            let last_instruction = block.instructions.last();
            let flow_type = last_instruction.map(|i| i.flow_type);

            for (idx, &succ_idx) in block.successors.iter().enumerate() {
                if succ_idx >= block_count {
                    return Err(GraphError(format!(
                        "Block {block_idx} has successor index {succ_idx} which exceeds block count {block_count}"
                    )));
                }

                let target_node = NodeId::new(succ_idx);
                let edge_kind = Self::classify_edge(flow_type, idx, block.successors.len());
                let edge = CfgEdge::new(succ_idx, edge_kind);

                graph.add_edge(node_id, target_node, edge)?;
            }
        }

        // Identify entry and exit blocks
        let entry = NodeId::new(0); // Method entry is always block 0
        let mut exits: Vec<NodeId> = Vec::new();
        for (block_idx, block) in blocks.iter().enumerate() {
            let is_exit = block.successors.is_empty()
                || block
                    .instructions
                    .last()
                    .is_some_and(|i| i.flow_type == FlowType::Return);
            if is_exit {
                exits.push(NodeId::new(block_idx));
            }
        }

        Ok(Self {
            graph,
            entry,
            exits,
            dominators: OnceLock::new(),
            dominance_frontiers: OnceLock::new(),
            loops: OnceLock::new(),
        })
    }

    /// Converts this CFG into an owned CFG with `'static` lifetime.
    ///
    /// If the CFG already owns its blocks, this is efficient. If borrowed,
    /// this clones the block data.
    ///
    /// Note: Cached analysis results (dominators, loops) are preserved if
    /// already computed.
    ///
    /// # Returns
    ///
    /// An owned `ControlFlowGraph<'static>`.
    #[must_use]
    pub fn into_owned(self) -> ControlFlowGraph<'static> {
        ControlFlowGraph {
            graph: self.graph.into_owned(),
            entry: self.entry,
            exits: self.exits,
            dominators: self.dominators,
            dominance_frontiers: self.dominance_frontiers,
            loops: self.loops,
        }
    }

    /// Classifies an edge based on the flow type and position in successor list.
    fn classify_edge(
        flow_type: Option<FlowType>,
        successor_index: usize,
        successor_count: usize,
    ) -> CfgEdgeKind {
        match flow_type {
            Some(FlowType::ConditionalBranch) => {
                // For conditional branches: first successor is the branch target (true),
                // second successor is fall-through (false)
                if successor_index == 0 {
                    CfgEdgeKind::ConditionalTrue
                } else {
                    CfgEdgeKind::ConditionalFalse
                }
            }
            Some(FlowType::Switch) => {
                // For switches: last successor is default, others are cases
                if successor_index == successor_count - 1 && successor_count > 1 {
                    CfgEdgeKind::Switch { case_value: None }
                } else {
                    // Switch case indices are bounded by the number of successors,
                    // which is limited by method body size. Use try_from with fallback.
                    let case_value = i32::try_from(successor_index).ok();
                    CfgEdgeKind::Switch { case_value }
                }
            }
            Some(FlowType::Leave) => CfgEdgeKind::Leave,
            Some(FlowType::EndFinally) => CfgEdgeKind::EndFinally,
            _ => CfgEdgeKind::Unconditional,
        }
    }

    /// Returns the entry block ID.
    ///
    /// The entry block is always the first block in the method body.
    ///
    /// # Returns
    ///
    /// The [`NodeId`] of the entry block.
    #[must_use]
    pub const fn entry(&self) -> NodeId {
        self.entry
    }

    /// Returns the exit block IDs.
    ///
    /// Exit blocks are blocks with no successors or those ending with return instructions.
    ///
    /// # Returns
    ///
    /// A slice of [`NodeId`]s for all exit blocks.
    #[must_use]
    pub fn exits(&self) -> &[NodeId] {
        &self.exits
    }

    /// Returns the number of blocks in the CFG.
    ///
    /// # Returns
    ///
    /// The total count of basic blocks in this control flow graph.
    #[must_use]
    pub fn block_count(&self) -> usize {
        self.graph.node_count()
    }

    /// Returns a reference to the basic block at the given node ID.
    ///
    /// # Arguments
    ///
    /// * `node_id` - The node ID to look up
    ///
    /// # Returns
    ///
    /// A reference to the basic block, or `None` if the ID is invalid.
    #[must_use]
    pub fn block(&self, node_id: NodeId) -> Option<&BasicBlock> {
        self.graph.node(node_id)
    }

    /// Returns the dominator tree for this CFG.
    ///
    /// The dominator tree is computed lazily on first access and cached.
    /// This operation is thread-safe.
    ///
    /// # Returns
    ///
    /// A reference to the dominator tree.
    #[must_use]
    pub fn dominators(&self) -> &DominatorTree {
        self.dominators
            .get_or_init(|| algorithms::compute_dominators(&self.graph, self.entry))
    }

    /// Returns the dominance frontiers for this CFG.
    ///
    /// The dominance frontiers are computed lazily on first access and cached.
    /// This is used for SSA phi-node placement.
    ///
    /// # Returns
    ///
    /// A reference to the dominance frontiers, indexed by node ID.
    #[must_use]
    pub fn dominance_frontiers(&self) -> &Vec<HashSet<NodeId>> {
        self.dominance_frontiers
            .get_or_init(|| algorithms::compute_dominance_frontiers(&self.graph, self.dominators()))
    }

    /// Returns the natural loops detected in this CFG.
    ///
    /// Natural loops are identified using back edge detection based on dominance.
    /// A back edge is an edge from a node to one of its dominators (the loop header).
    /// The loop body is computed by finding all nodes that can reach the back edge
    /// source without going through the header.
    ///
    /// Loops are computed lazily on first access and cached.
    ///
    /// # Returns
    ///
    /// A reference to the vector of natural loops, sorted by header node ID.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::analysis::ControlFlowGraph;
    ///
    /// let cfg = ControlFlowGraph::from_basic_blocks(blocks)?;
    /// for natural_loop in cfg.loops() {
    ///     println!("Loop at {:?} with {} blocks", natural_loop.header, natural_loop.size());
    /// }
    /// ```
    #[must_use]
    pub fn loops(&self) -> &[NaturalLoop] {
        self.loops.get_or_init(|| self.detect_loops())
    }

    /// Detects natural loops in the CFG using back edge analysis.
    ///
    /// A back edge (n -> h) exists when h dominates n. For each back edge,
    /// we find the natural loop by computing all nodes that can reach n
    /// without passing through h, plus h itself.
    fn detect_loops(&self) -> Vec<NaturalLoop> {
        let dominators = self.dominators();
        let mut loops: Vec<NaturalLoop> = Vec::new();

        // Find all back edges: edge (n -> h) where h dominates n
        for node in self.graph.node_ids() {
            for succ in self.graph.successors(node) {
                // Check if successor dominates current node (back edge)
                if dominators.dominates(succ, node) {
                    // Found back edge: node -> succ (succ is loop header)
                    let header = succ;

                    // Check if we already have a loop for this header
                    if let Some(existing_loop) = loops.iter_mut().find(|l| l.header == header) {
                        // Add this back edge source to existing loop
                        existing_loop.back_edges.push(node);
                        self.expand_loop_body(existing_loop, node);
                    } else {
                        // Create new loop
                        let mut natural_loop = NaturalLoop::new(header);
                        natural_loop.back_edges.push(node);
                        self.expand_loop_body(&mut natural_loop, node);
                        loops.push(natural_loop);
                    }
                }
            }
        }

        // Compute loop nesting depths
        Self::compute_loop_depths(&mut loops);

        // Sort by header for deterministic ordering
        loops.sort_by_key(|l| l.header.index());

        loops
    }

    /// Expands the loop body to include all nodes that can reach the back edge source.
    ///
    /// Uses a worklist algorithm: starting from the back edge source, we add
    /// predecessors that aren't the header until we've found all loop body nodes.
    fn expand_loop_body(&self, natural_loop: &mut NaturalLoop, back_edge_source: NodeId) {
        if natural_loop.body.contains(&back_edge_source) {
            return;
        }

        let mut worklist = vec![back_edge_source];

        while let Some(node) = worklist.pop() {
            if natural_loop.body.insert(node) {
                // Node wasn't in body yet, add its predecessors
                for pred in self.graph.predecessors(node) {
                    if pred != natural_loop.header && !natural_loop.body.contains(&pred) {
                        worklist.push(pred);
                    }
                }
            }
        }
    }

    /// Computes the nesting depth for each loop.
    ///
    /// A loop L1 is nested inside L2 if L1's header is contained in L2's body.
    /// The depth is the number of enclosing loops.
    fn compute_loop_depths(loops: &mut [NaturalLoop]) {
        for i in 0..loops.len() {
            let mut depth = 0;
            for j in 0..loops.len() {
                if i != j && loops[j].body.contains(&loops[i].header) {
                    depth += 1;
                }
            }
            loops[i].depth = depth;
        }
    }

    /// Returns true if this CFG contains any loops.
    ///
    /// # Returns
    ///
    /// `true` if the CFG has at least one natural loop, `false` otherwise.
    #[must_use]
    pub fn has_loops(&self) -> bool {
        !self.loops().is_empty()
    }

    /// Returns the innermost loop containing the given node, if any.
    ///
    /// When a block is contained in multiple nested loops, this returns the
    /// loop with the highest nesting depth.
    ///
    /// # Arguments
    ///
    /// * `node` - The node ID to query
    ///
    /// # Returns
    ///
    /// A reference to the innermost [`NaturalLoop`] containing the node,
    /// or `None` if the node is not in any loop.
    #[must_use]
    pub fn innermost_loop(&self, node: NodeId) -> Option<&NaturalLoop> {
        self.loops()
            .iter()
            .filter(|l| l.body.contains(&node))
            .max_by_key(|l| l.depth)
    }

    /// Returns the successor block IDs for a given block.
    ///
    /// # Arguments
    ///
    /// * `node_id` - The node ID to query
    ///
    /// # Returns
    ///
    /// An iterator over successor node IDs.
    pub fn successors(&self, node_id: NodeId) -> impl Iterator<Item = NodeId> + '_ {
        self.graph.successors(node_id)
    }

    /// Returns the predecessor block IDs for a given block.
    ///
    /// # Arguments
    ///
    /// * `node_id` - The node ID to query
    ///
    /// # Returns
    ///
    /// An iterator over predecessor node IDs.
    pub fn predecessors(&self, node_id: NodeId) -> impl Iterator<Item = NodeId> + '_ {
        self.graph.predecessors(node_id)
    }

    /// Returns the outgoing edges from a block.
    ///
    /// # Arguments
    ///
    /// * `node_id` - The node ID to query
    ///
    /// # Returns
    ///
    /// An iterator over (edge_id, target_node_id, edge_data) tuples.
    pub fn outgoing_edges(
        &self,
        node_id: NodeId,
    ) -> impl Iterator<Item = (EdgeId, NodeId, &CfgEdge)> + '_ {
        self.graph
            .outgoing_edges(node_id)
            .filter_map(|(edge_id, edge_data)| {
                self.graph
                    .edge_endpoints(edge_id)
                    .map(|(_, target)| (edge_id, target, edge_data))
            })
    }

    /// Returns blocks in reverse postorder.
    ///
    /// Reverse postorder is useful for forward data flow analysis, as it
    /// ensures predecessors are visited before successors (for acyclic regions).
    ///
    /// # Returns
    ///
    /// A vector of node IDs in reverse postorder.
    #[must_use]
    pub fn reverse_postorder(&self) -> Vec<NodeId> {
        algorithms::reverse_postorder(&self.graph, self.entry)
    }

    /// Returns blocks in postorder.
    ///
    /// Postorder is useful for backward data flow analysis.
    ///
    /// # Returns
    ///
    /// A vector of node IDs in postorder.
    #[must_use]
    pub fn postorder(&self) -> Vec<NodeId> {
        algorithms::postorder(&self.graph, self.entry)
    }

    /// Performs a depth-first traversal starting from the entry block.
    ///
    /// # Returns
    ///
    /// An iterator yielding node IDs in DFS order.
    pub fn dfs(&self) -> impl Iterator<Item = NodeId> + '_ {
        algorithms::dfs(&self.graph, self.entry)
    }

    /// Performs a breadth-first traversal starting from the entry block.
    ///
    /// # Returns
    ///
    /// An iterator yielding node IDs in BFS order.
    pub fn bfs(&self) -> impl Iterator<Item = NodeId> + '_ {
        algorithms::bfs(&self.graph, self.entry)
    }

    /// Returns a reference to the underlying graph.
    ///
    /// This provides access to the full graph API for advanced use cases
    /// such as custom traversals or algorithm applications.
    ///
    /// # Returns
    ///
    /// A reference to the underlying [`DirectedGraph`] structure.
    #[must_use]
    pub fn graph(&self) -> &DirectedGraph<'a, BasicBlock, CfgEdge> {
        &self.graph
    }

    /// Returns an iterator over all node IDs in the graph.
    ///
    /// # Returns
    ///
    /// An iterator yielding all [`NodeId`]s in the graph.
    pub fn node_ids(&self) -> impl Iterator<Item = NodeId> + '_ {
        self.graph.node_ids()
    }

    /// Checks if a block dominates another block.
    ///
    /// Block A dominates block B if every path from the entry to B
    /// must go through A.
    ///
    /// # Arguments
    ///
    /// * `dominator` - The potential dominator block
    /// * `dominated` - The potentially dominated block
    ///
    /// # Returns
    ///
    /// `true` if `dominator` dominates `dominated`.
    #[must_use]
    pub fn dominates(&self, dominator: NodeId, dominated: NodeId) -> bool {
        self.dominators().dominates(dominator, dominated)
    }

    /// Returns the immediate dominator of a block.
    ///
    /// # Arguments
    ///
    /// * `node_id` - The block to query
    ///
    /// # Returns
    ///
    /// The immediate dominator, or `None` for the entry block.
    #[must_use]
    pub fn idom(&self, node_id: NodeId) -> Option<NodeId> {
        self.dominators().immediate_dominator(node_id)
    }

    /// Generates a DOT format representation of this control flow graph.
    ///
    /// The generated DOT can be rendered using Graphviz tools like `dot` or
    /// online viewers. Entry blocks are highlighted in green, exit blocks in red.
    ///
    /// # Arguments
    ///
    /// * `title` - Optional title for the graph (e.g., method name)
    ///
    /// # Returns
    ///
    /// A string containing the DOT representation of the CFG.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::CilObject;
    /// use std::path::Path;
    ///
    /// let assembly = CilObject::from_path(Path::new("test.dll"))?;
    /// for entry in assembly.methods().iter().take(1) {
    ///     let method = entry.value();
    ///     if let Some(cfg) = method.cfg() {
    ///         let dot = cfg.to_dot(Some(&method.name));
    ///         std::fs::write("cfg.dot", dot)?;
    ///     }
    /// }
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[must_use]
    pub fn to_dot(&self, title: Option<&str>) -> String {
        let mut dot = String::new();

        dot.push_str("digraph CFG {\n");
        if let Some(name) = title {
            let _ = writeln!(dot, "    label=\"CFG: {}\";", escape_dot(name));
        }
        dot.push_str("    labelloc=t;\n");
        dot.push_str("    node [shape=box, fontname=\"Courier\", fontsize=10];\n");
        dot.push_str("    edge [fontname=\"Courier\", fontsize=9];\n\n");

        // Generate nodes
        for block_idx in 0..self.block_count() {
            let node_id = NodeId::new(block_idx);
            if let Some(block) = self.block(node_id) {
                let is_entry = node_id == self.entry;
                let is_exit = self.exits.contains(&node_id);

                let node_name = format!("B{block_idx}_{:04X}", block.rva);
                let mut label = format!("B{block_idx}_{:04X}", block.rva);
                if is_entry {
                    label.push_str(" (entry)");
                }
                if is_exit {
                    label.push_str(" (exit)");
                }
                label.push_str("\\l"); // Left-align with newline

                for instr in &block.instructions {
                    // Format: RVA: mnemonic [operand]
                    let _ = write!(label, "{:04X}: {}", instr.rva, escape_dot(instr.mnemonic));

                    match &instr.operand {
                        Operand::None => {}
                        Operand::Immediate(imm) => {
                            let _ = write!(label, " {}", escape_dot(&format!("{imm:?}")));
                        }
                        Operand::Target(addr) => {
                            let _ = write!(label, " 0x{addr:X}");
                        }
                        Operand::Token(tok) => {
                            let _ = write!(label, " {tok:?}");
                        }
                        Operand::Local(idx) => {
                            let _ = write!(label, " V_{idx}");
                        }
                        Operand::Argument(idx) => {
                            let _ = write!(label, " A_{idx}");
                        }
                        Operand::Switch(targets) => {
                            let _ = write!(label, " [{}]", targets.len());
                        }
                    }

                    label.push_str("\\l"); // Left-align newline
                }

                let style = if is_entry {
                    ", style=filled, fillcolor=lightgreen"
                } else if is_exit {
                    ", style=filled, fillcolor=lightcoral"
                } else {
                    ""
                };

                let _ = writeln!(dot, "    {node_name} [label=\"{label}\"{style}];");
            }
        }

        dot.push('\n');

        // Generate edges
        for block_idx in 0..self.block_count() {
            let node_id = NodeId::new(block_idx);
            let source_rva = self.block(node_id).map_or(0, |b| b.rva);
            let source_name = format!("B{block_idx}_{source_rva:04X}");

            for (_, target, edge) in self.outgoing_edges(node_id) {
                let target_rva = self.block(target).map_or(0, |b| b.rva);
                let target_name = format!("B{}_{target_rva:04X}", target.index());

                let edge_label = match edge.kind() {
                    CfgEdgeKind::Unconditional => String::new(),
                    CfgEdgeKind::ConditionalTrue => "true".to_string(),
                    CfgEdgeKind::ConditionalFalse => "false".to_string(),
                    CfgEdgeKind::Switch { case_value } => {
                        case_value.map_or("default".to_string(), |v| format!("case {v}"))
                    }
                    CfgEdgeKind::ExceptionHandler { .. } => "catch".to_string(),
                    CfgEdgeKind::Leave => "leave".to_string(),
                    CfgEdgeKind::EndFinally => "endfinally".to_string(),
                };

                let color = match edge.kind() {
                    CfgEdgeKind::Unconditional => "black",
                    CfgEdgeKind::ConditionalTrue => "green",
                    CfgEdgeKind::ConditionalFalse => "red",
                    CfgEdgeKind::Switch { .. } => "blue",
                    _ => "purple",
                };

                let _ = writeln!(
                    dot,
                    "    {source_name} -> {target_name} [label=\"{}\", color={color}];",
                    escape_dot(&edge_label)
                );
            }
        }

        dot.push_str("}\n");
        dot
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assembly::{Instruction, InstructionCategory, Operand, StackBehavior};

    /// Creates a simple test basic block with minimal data.
    fn make_block(id: usize, successors: Vec<usize>, flow_type: FlowType) -> BasicBlock {
        let mut block = BasicBlock::new(id, 0x1000 + (id * 0x10) as u64, id * 0x10);
        block.successors = successors;

        // Add a dummy instruction with the specified flow type
        let instruction = Instruction {
            rva: block.rva,
            offset: block.offset as u64,
            size: 1,
            opcode: 0,
            prefix: 0,
            mnemonic: "test",
            category: InstructionCategory::ControlFlow,
            flow_type,
            operand: Operand::None,
            stack_behavior: StackBehavior {
                pops: 0,
                pushes: 0,
                net_effect: 0,
            },
            branch_targets: vec![],
        };
        block.instructions.push(instruction);

        block
    }

    #[test]
    fn test_cfg_from_empty_blocks() {
        let result = ControlFlowGraph::from_basic_blocks(vec![]);
        assert!(result.is_err());
    }

    #[test]
    fn test_cfg_single_block() {
        let blocks = vec![make_block(0, vec![], FlowType::Return)];

        let cfg = ControlFlowGraph::from_basic_blocks(blocks).unwrap();

        assert_eq!(cfg.block_count(), 1);
        assert_eq!(cfg.entry(), NodeId::new(0));
        assert_eq!(cfg.exits().len(), 1);
        assert_eq!(cfg.exits()[0], NodeId::new(0));
    }

    #[test]
    fn test_cfg_linear_blocks() {
        // Block 0 -> Block 1 -> Block 2 (return)
        let blocks = vec![
            make_block(0, vec![1], FlowType::Sequential),
            make_block(1, vec![2], FlowType::Sequential),
            make_block(2, vec![], FlowType::Return),
        ];

        let cfg = ControlFlowGraph::from_basic_blocks(blocks).unwrap();

        assert_eq!(cfg.block_count(), 3);
        assert_eq!(cfg.entry(), NodeId::new(0));
        assert_eq!(cfg.exits().len(), 1);

        // Check successors
        let succ_0: Vec<_> = cfg.successors(NodeId::new(0)).collect();
        assert_eq!(succ_0, vec![NodeId::new(1)]);

        let succ_1: Vec<_> = cfg.successors(NodeId::new(1)).collect();
        assert_eq!(succ_1, vec![NodeId::new(2)]);

        let succ_2: Vec<_> = cfg.successors(NodeId::new(2)).collect();
        assert!(succ_2.is_empty());
    }

    #[test]
    fn test_cfg_diamond_shape() {
        // Diamond: 0 -> 1, 0 -> 2, 1 -> 3, 2 -> 3
        let blocks = vec![
            make_block(0, vec![1, 2], FlowType::ConditionalBranch),
            make_block(1, vec![3], FlowType::Sequential),
            make_block(2, vec![3], FlowType::Sequential),
            make_block(3, vec![], FlowType::Return),
        ];

        let cfg = ControlFlowGraph::from_basic_blocks(blocks).unwrap();

        assert_eq!(cfg.block_count(), 4);

        // Check conditional edge kinds
        let edges: Vec<_> = cfg.outgoing_edges(NodeId::new(0)).collect();
        assert_eq!(edges.len(), 2);

        // First edge should be conditional true (edge data is at index 2)
        assert_eq!(*edges[0].2.kind(), CfgEdgeKind::ConditionalTrue);
        // Second edge should be conditional false
        assert_eq!(*edges[1].2.kind(), CfgEdgeKind::ConditionalFalse);

        // Check dominators
        let dominators = cfg.dominators();
        assert!(dominators.dominates(NodeId::new(0), NodeId::new(1)));
        assert!(dominators.dominates(NodeId::new(0), NodeId::new(2)));
        assert!(dominators.dominates(NodeId::new(0), NodeId::new(3)));

        // Block 3 is dominated by 0 but not by 1 or 2
        assert!(!dominators.dominates(NodeId::new(1), NodeId::new(3)));
        assert!(!dominators.dominates(NodeId::new(2), NodeId::new(3)));
    }

    #[test]
    fn test_cfg_with_loop() {
        // Loop: 0 -> 1 -> 2 -> 1 (back edge), 2 -> 3
        let blocks = vec![
            make_block(0, vec![1], FlowType::Sequential),
            make_block(1, vec![2], FlowType::Sequential),
            make_block(2, vec![1, 3], FlowType::ConditionalBranch),
            make_block(3, vec![], FlowType::Return),
        ];

        let cfg = ControlFlowGraph::from_basic_blocks(blocks).unwrap();

        assert_eq!(cfg.block_count(), 4);

        // Block 1 should have two predecessors: 0 and 2
        let pred_1: Vec<_> = cfg.predecessors(NodeId::new(1)).collect();
        assert_eq!(pred_1.len(), 2);
        assert!(pred_1.contains(&NodeId::new(0)));
        assert!(pred_1.contains(&NodeId::new(2)));

        // Block 1 dominates block 2
        assert!(cfg.dominates(NodeId::new(1), NodeId::new(2)));
    }

    #[test]
    fn test_cfg_traversal_orders() {
        // Simple: 0 -> 1 -> 2
        let blocks = vec![
            make_block(0, vec![1], FlowType::Sequential),
            make_block(1, vec![2], FlowType::Sequential),
            make_block(2, vec![], FlowType::Return),
        ];

        let cfg = ControlFlowGraph::from_basic_blocks(blocks).unwrap();

        let dfs_order: Vec<_> = cfg.dfs().collect();
        assert_eq!(dfs_order.len(), 3);
        assert_eq!(dfs_order[0], NodeId::new(0)); // Entry first

        let bfs_order: Vec<_> = cfg.bfs().collect();
        assert_eq!(bfs_order.len(), 3);
        assert_eq!(bfs_order[0], NodeId::new(0)); // Entry first

        let rpo = cfg.reverse_postorder();
        assert_eq!(rpo.len(), 3);
        // In RPO, entry should come first, exit should come last
        assert_eq!(rpo[0], NodeId::new(0));
        assert_eq!(rpo[2], NodeId::new(2));
    }

    #[test]
    fn test_cfg_invalid_successor() {
        // Block with successor index out of range
        let blocks = vec![make_block(0, vec![5], FlowType::Sequential)]; // Only 1 block, but successor is 5

        let result = ControlFlowGraph::from_basic_blocks(blocks);
        assert!(result.is_err());
    }

    #[test]
    fn test_cfg_switch_edges() {
        // Switch with 3 cases
        let blocks = vec![
            make_block(0, vec![1, 2, 3], FlowType::Switch), // switch to 1, 2, 3
            make_block(1, vec![4], FlowType::Sequential),   // case 0
            make_block(2, vec![4], FlowType::Sequential),   // case 1
            make_block(3, vec![4], FlowType::Sequential),   // default
            make_block(4, vec![], FlowType::Return),
        ];

        let cfg = ControlFlowGraph::from_basic_blocks(blocks).unwrap();

        let edges: Vec<_> = cfg.outgoing_edges(NodeId::new(0)).collect();
        assert_eq!(edges.len(), 3);

        // First two edges should be switch cases (edge data is at index 2)
        assert_eq!(
            *edges[0].2.kind(),
            CfgEdgeKind::Switch {
                case_value: Some(0)
            }
        );
        assert_eq!(
            *edges[1].2.kind(),
            CfgEdgeKind::Switch {
                case_value: Some(1)
            }
        );
        // Last edge should be default (None)
        assert_eq!(*edges[2].2.kind(), CfgEdgeKind::Switch { case_value: None });
    }

    #[test]
    fn test_cfg_no_loops() {
        // Linear: 0 -> 1 -> 2 (no loops)
        let blocks = vec![
            make_block(0, vec![1], FlowType::Sequential),
            make_block(1, vec![2], FlowType::Sequential),
            make_block(2, vec![], FlowType::Return),
        ];

        let cfg = ControlFlowGraph::from_basic_blocks(blocks).unwrap();

        assert!(!cfg.has_loops());
        assert_eq!(cfg.loops().len(), 0);
    }

    #[test]
    fn test_cfg_simple_loop_detection() {
        // Simple loop: 0 -> 1 -> 2 -> 1 (back edge), 2 -> 3
        let blocks = vec![
            make_block(0, vec![1], FlowType::Sequential),
            make_block(1, vec![2], FlowType::Sequential),
            make_block(2, vec![1, 3], FlowType::ConditionalBranch),
            make_block(3, vec![], FlowType::Return),
        ];

        let cfg = ControlFlowGraph::from_basic_blocks(blocks).unwrap();

        assert!(cfg.has_loops());
        let loops = cfg.loops();
        assert_eq!(loops.len(), 1);

        let loop0 = &loops[0];
        assert_eq!(loop0.header, NodeId::new(1)); // Block 1 is the loop header
        assert!(loop0.body.contains(&NodeId::new(1))); // Header is in body
        assert!(loop0.body.contains(&NodeId::new(2))); // Block 2 is in body
        assert!(!loop0.body.contains(&NodeId::new(0))); // Block 0 is not in loop
        assert!(!loop0.body.contains(&NodeId::new(3))); // Block 3 is not in loop
        assert_eq!(loop0.back_edges.len(), 1);
        assert_eq!(loop0.back_edges[0], NodeId::new(2)); // Back edge from block 2
        assert_eq!(loop0.depth, 0); // Outermost loop
    }

    #[test]
    fn test_cfg_nested_loops() {
        // Nested loops:
        // 0 -> 1 (outer header) -> 2 (inner header) -> 3 -> 2 (inner back edge)
        //      1 <- 3 (outer back edge)
        //      3 -> 4 (exit)
        let blocks = vec![
            make_block(0, vec![1], FlowType::Sequential),
            make_block(1, vec![2], FlowType::Sequential),
            make_block(2, vec![3], FlowType::Sequential),
            make_block(3, vec![2, 1, 4], FlowType::Switch), // back to 2 (inner), 1 (outer), or exit
            make_block(4, vec![], FlowType::Return),
        ];

        let cfg = ControlFlowGraph::from_basic_blocks(blocks).unwrap();

        assert!(cfg.has_loops());
        let loops = cfg.loops();
        assert_eq!(loops.len(), 2);

        // Should have outer loop (header=1) and inner loop (header=2)
        let outer_loop = loops.iter().find(|l| l.header == NodeId::new(1)).unwrap();
        let inner_loop = loops.iter().find(|l| l.header == NodeId::new(2)).unwrap();

        // Inner loop should have higher depth
        assert!(inner_loop.depth > outer_loop.depth);

        // Inner loop body should be subset of outer loop body
        for node in &inner_loop.body {
            assert!(outer_loop.body.contains(node));
        }
    }

    #[test]
    fn test_cfg_innermost_loop() {
        // Same nested loop structure as above
        let blocks = vec![
            make_block(0, vec![1], FlowType::Sequential),
            make_block(1, vec![2], FlowType::Sequential),
            make_block(2, vec![3], FlowType::Sequential),
            make_block(3, vec![2, 1, 4], FlowType::Switch),
            make_block(4, vec![], FlowType::Return),
        ];

        let cfg = ControlFlowGraph::from_basic_blocks(blocks).unwrap();

        // Block 0 is not in any loop
        assert!(cfg.innermost_loop(NodeId::new(0)).is_none());

        // Block 4 is not in any loop
        assert!(cfg.innermost_loop(NodeId::new(4)).is_none());

        // Block 3 should be in the inner loop (higher depth)
        let innermost = cfg.innermost_loop(NodeId::new(3)).unwrap();
        assert_eq!(innermost.header, NodeId::new(2));
    }

    #[test]
    fn test_cfg_self_loop() {
        // Self-loop: 0 -> 1 -> 1 (self loop), 1 -> 2
        let blocks = vec![
            make_block(0, vec![1], FlowType::Sequential),
            make_block(1, vec![1, 2], FlowType::ConditionalBranch), // Self-loop
            make_block(2, vec![], FlowType::Return),
        ];

        let cfg = ControlFlowGraph::from_basic_blocks(blocks).unwrap();

        assert!(cfg.has_loops());
        let loops = cfg.loops();
        assert_eq!(loops.len(), 1);

        let self_loop = &loops[0];
        assert_eq!(self_loop.header, NodeId::new(1));
        assert_eq!(self_loop.size(), 1); // Only the header itself
        assert_eq!(self_loop.back_edges.len(), 1);
        assert_eq!(self_loop.back_edges[0], NodeId::new(1)); // Self back edge
    }
}
