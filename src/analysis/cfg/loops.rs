//! Extended loop analysis infrastructure.
//!
//! This module provides comprehensive loop analysis beyond basic natural loop detection,
//! including preheader identification, latch detection, exit analysis, and loop
//! classification.
//!
//! # Loop Structure
//!
//! A well-formed loop has the following structure:
//!
//! ```text
//!     [preheader]     <- Single entry predecessor (optional, may need insertion)
//!          |
//!          v
//!     [header] <------+  <- Single entry point, dominates all loop nodes
//!          |          |
//!          v          |
//!     [body ...]      |  <- Loop body nodes
//!          |          |
//!          v          |
//!     [latch] --------+  <- Back edge source(s)
//!          |
//!          v
//!     [exit ...]         <- Exit blocks (outside loop, have predecessor in loop)
//! ```
//!
//! # Loop Types
//!
//! Loops are classified into:
//! - **Pre-tested** (while): Condition checked at header before body
//! - **Post-tested** (do-while): Condition checked at latch after body
//! - **Infinite**: No exit condition (or condition always true)
//! - **Complex**: Multiple back edges or irregular structure
//!
//! # Canonicalization
//!
//! Canonical loops have:
//! - Single preheader (non-loop predecessor to header)
//! - Single latch (single back edge to header)
//! - Dedicated exit blocks (exits have single predecessor)
//!
//! # Generic Loop Detection
//!
//! The [`detect_loops`] function can analyze any graph implementing the required
//! traits (`GraphBase`, `Successors`, `Predecessors`). This enables loop detection
//! on CIL CFGs, SSA CFGs, x86 CFGs, and any other graph structure.
//!
//! ```rust,ignore
//! use dotscope::analysis::cfg::detect_loops;
//! use dotscope::utils::graph::algorithms::compute_dominators;
//!
//! // Works with any graph implementing the traits
//! let dominators = compute_dominators(&graph, entry);
//! let forest = detect_loops(&graph, &dominators);
//! ```

use std::collections::{HashMap, HashSet};

use crate::{
    analysis::{SsaFunction, SsaOp, SsaVarId},
    utils::graph::{algorithms::DominatorTree, GraphBase, NodeId, Predecessors, Successors},
};

/// Classification of loop types based on structure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoopType {
    /// Pre-tested loop (while): exit condition at header.
    /// ```text
    /// while (cond) { body }
    /// ```
    PreTested,

    /// Post-tested loop (do-while): exit condition at latch.
    /// ```text
    /// do { body } while (cond)
    /// ```
    PostTested,

    /// Infinite loop: no exit edges from loop body.
    /// ```text
    /// while (true) { body }
    /// ```
    Infinite,

    /// Complex loop: multiple latches, irregular exits, or irreducible.
    Complex,
}

/// Exit edge information for a loop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoopExit {
    /// The block inside the loop that branches out.
    pub exiting_block: NodeId,
    /// The block outside the loop that is the exit target.
    pub exit_block: NodeId,
}

/// Classification of induction variable update operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InductionUpdateKind {
    /// `i = i + stride` (increment)
    Add,
    /// `i = i - stride` (decrement)
    Sub,
    /// `i = i * stride` (scaling)
    Mul,
    /// Unknown or complex update pattern
    Unknown,
}

/// Represents an induction variable in a loop.
///
/// An induction variable is a variable whose value changes by a fixed amount
/// on each iteration of a loop. Classic examples include loop counters (`i++`).
///
/// # Structure
///
/// An induction variable has:
/// - A phi node at the loop header that merges the initial and updated values
/// - An initial value from outside the loop (preheader)
/// - An updated value computed inside the loop (typically in the latch)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InductionVar {
    /// The phi node result variable at the loop header.
    pub phi_result: SsaVarId,
    /// The initial value (from preheader or outside loop).
    pub init_value: SsaVarId,
    /// The block providing the initial value.
    pub init_block: NodeId,
    /// The updated value (from inside loop, typically latch).
    pub update_value: SsaVarId,
    /// The block providing the updated value.
    pub update_block: NodeId,
    /// The type of update operation.
    pub update_kind: InductionUpdateKind,
    /// The stride (constant value added/subtracted per iteration), if known.
    pub stride: Option<i64>,
}

/// Comprehensive loop information.
///
/// This extends `NaturalLoop` with additional structural information needed
/// for loop canonicalization and optimization.
#[derive(Debug, Clone)]
pub struct LoopInfo {
    /// The header block (single entry point, dominates all loop nodes).
    pub header: NodeId,

    /// All blocks in the loop body (including header).
    pub body: HashSet<NodeId>,

    /// Back edge sources (blocks that jump to the header from within the loop).
    pub latches: Vec<NodeId>,

    /// Preheader block if one exists (single non-loop predecessor of header).
    /// `None` if header has multiple non-loop predecessors or none.
    pub preheader: Option<NodeId>,

    /// Exit edges from the loop.
    pub exits: Vec<LoopExit>,

    /// Loop nesting depth (0 = outermost).
    pub depth: usize,

    /// Classification of the loop type.
    pub loop_type: LoopType,

    /// Parent loop header, if this loop is nested.
    pub parent: Option<NodeId>,

    /// Immediate child loop headers.
    pub children: Vec<NodeId>,
}

impl LoopInfo {
    /// Creates a new `LoopInfo` with the given header.
    #[must_use]
    pub fn new(header: NodeId) -> Self {
        let mut body = HashSet::new();
        body.insert(header);
        Self {
            header,
            body,
            latches: Vec::new(),
            preheader: None,
            exits: Vec::new(),
            depth: 0,
            loop_type: LoopType::Complex,
            parent: None,
            children: Vec::new(),
        }
    }

    /// Returns true if this loop contains the given block.
    #[must_use]
    pub fn contains(&self, node: NodeId) -> bool {
        self.body.contains(&node)
    }

    /// Returns the number of blocks in the loop.
    #[must_use]
    pub fn size(&self) -> usize {
        self.body.len()
    }

    /// Returns true if the loop has a single latch (canonical form).
    #[must_use]
    pub fn has_single_latch(&self) -> bool {
        self.latches.len() == 1
    }

    /// Returns the single latch if there is exactly one.
    #[must_use]
    pub fn single_latch(&self) -> Option<NodeId> {
        if self.latches.len() == 1 {
            Some(self.latches[0])
        } else {
            None
        }
    }

    /// Returns true if the loop has a preheader (canonical form).
    #[must_use]
    pub fn has_preheader(&self) -> bool {
        self.preheader.is_some()
    }

    /// Returns true if the loop is in canonical form.
    ///
    /// A canonical loop has:
    /// - A single preheader
    /// - A single latch
    #[must_use]
    pub fn is_canonical(&self) -> bool {
        self.has_preheader() && self.has_single_latch()
    }

    /// Returns true if this is an innermost loop (no children).
    #[must_use]
    pub fn is_innermost(&self) -> bool {
        self.children.is_empty()
    }

    /// Returns true if this is an outermost loop (no parent).
    #[must_use]
    pub fn is_outermost(&self) -> bool {
        self.parent.is_none()
    }

    /// Returns all exit blocks (blocks outside loop reachable from inside).
    pub fn exit_blocks(&self) -> impl Iterator<Item = NodeId> + '_ {
        self.exits.iter().map(|e| e.exit_block)
    }

    /// Returns all exiting blocks (blocks inside loop that branch out).
    pub fn exiting_blocks(&self) -> impl Iterator<Item = NodeId> + '_ {
        self.exits.iter().map(|e| e.exiting_block)
    }

    /// Returns the number of exits from this loop.
    #[must_use]
    pub fn exit_count(&self) -> usize {
        self.exits.len()
    }

    /// Returns true if the header is also an exiting block.
    ///
    /// This indicates a pre-tested loop (condition at entry).
    #[must_use]
    pub fn header_is_exiting(&self) -> bool {
        self.exits.iter().any(|e| e.exiting_block == self.header)
    }

    /// Returns true if a latch is also an exiting block.
    ///
    /// This indicates a post-tested loop (condition at end).
    #[must_use]
    pub fn latch_is_exiting(&self) -> bool {
        self.exits
            .iter()
            .any(|e| self.latches.contains(&e.exiting_block))
    }

    /// Finds the condition block inside the loop body.
    ///
    /// For control-flow flattened code (e.g., ConfuserEx), the actual loop
    /// condition is often inside a case block rather than at the dispatcher
    /// header. This method searches for blocks with `Branch` instructions
    /// within the loop body.
    ///
    /// # Returns
    ///
    /// - `Some(NodeId)` - The first block found with a conditional branch
    /// - `None` - No conditional branch found in the loop body
    #[must_use]
    pub fn find_condition_in_body(&self, ssa: &SsaFunction) -> Option<NodeId> {
        for &block_id in &self.body {
            if let Some(block) = ssa.block(block_id.index()) {
                if matches!(block.terminator_op(), Some(SsaOp::Branch { .. })) {
                    return Some(block_id);
                }
            }
        }
        None
    }

    /// Finds all conditional blocks within the loop body.
    ///
    /// Unlike [`find_condition_in_body`], this returns all blocks with
    /// conditional branches, useful for complex loops with multiple exit points.
    #[must_use]
    pub fn find_all_conditions_in_body(&self, ssa: &SsaFunction) -> Vec<NodeId> {
        self.body
            .iter()
            .filter(|&&block_id| {
                ssa.block(block_id.index())
                    .is_some_and(|b| matches!(b.terminator_op(), Some(SsaOp::Branch { .. })))
            })
            .copied()
            .collect()
    }

    /// Identifies induction variables in this loop.
    ///
    /// An induction variable is identified by finding phi nodes at the loop
    /// header where:
    /// - One operand comes from outside the loop (initial value)
    /// - One operand comes from inside the loop (updated value)
    ///
    /// The method attempts to classify the update kind (add, sub, etc.) by
    /// analyzing the instruction that produces the update value.
    ///
    /// # Returns
    ///
    /// A vector of [`InductionVar`] structures describing each induction variable.
    #[must_use]
    pub fn find_induction_vars(&self, ssa: &SsaFunction) -> Vec<InductionVar> {
        let mut induction_vars = Vec::new();

        // Get phi nodes at the header
        let Some(header_block) = ssa.block(self.header.index()) else {
            return induction_vars;
        };

        for phi in header_block.phi_nodes() {
            let operands = phi.operands();

            // Need at least 2 operands (init + update)
            if operands.len() < 2 {
                continue;
            }

            // Find operands from inside vs outside the loop
            let (inside_ops, outside_ops): (Vec<&_>, Vec<&_>) = operands
                .iter()
                .partition(|op| self.body.contains(&NodeId::new(op.predecessor())));

            // Classic induction variable: 1 init from outside, 1+ updates from inside
            if outside_ops.len() == 1 && !inside_ops.is_empty() {
                let init_op = outside_ops[0];
                let update_op = inside_ops[0]; // Take first inside operand

                // Try to determine update kind by analyzing the defining instruction
                let (update_kind, stride) =
                    self.analyze_update_instruction(ssa, update_op.value(), phi.result());

                induction_vars.push(InductionVar {
                    phi_result: phi.result(),
                    init_value: init_op.value(),
                    init_block: NodeId::new(init_op.predecessor()),
                    update_value: update_op.value(),
                    update_block: NodeId::new(update_op.predecessor()),
                    update_kind,
                    stride,
                });
            }
        }

        induction_vars
    }

    /// Analyzes an instruction to determine if it's an induction update.
    ///
    /// Looks for patterns like `v = phi_result + const` or `v = phi_result - const`.
    fn analyze_update_instruction(
        &self,
        ssa: &SsaFunction,
        update_var: SsaVarId,
        phi_result: SsaVarId,
    ) -> (InductionUpdateKind, Option<i64>) {
        // Find the instruction that defines update_var
        let Some(var) = ssa.variable(update_var) else {
            return (InductionUpdateKind::Unknown, None);
        };
        let def_site = var.def_site();

        if def_site.is_phi() {
            return (InductionUpdateKind::Unknown, None);
        }

        let Some(block) = ssa.block(def_site.block) else {
            return (InductionUpdateKind::Unknown, None);
        };

        let Some(instr_idx) = def_site.instruction else {
            return (InductionUpdateKind::Unknown, None);
        };

        let Some(instr) = block.instruction(instr_idx) else {
            return (InductionUpdateKind::Unknown, None);
        };

        // Check for Add/Sub patterns
        match instr.op() {
            SsaOp::Add { left, right, .. } => {
                // Check if one operand is the phi result
                if *left == phi_result || *right == phi_result {
                    let other = if *left == phi_result { *right } else { *left };
                    let stride = self.try_get_constant(ssa, other);
                    return (InductionUpdateKind::Add, stride);
                }
            }
            SsaOp::Sub { left, right, .. } => {
                // For subtraction, left should be phi_result
                if *left == phi_result {
                    let stride = self.try_get_constant(ssa, *right);
                    return (InductionUpdateKind::Sub, stride);
                }
            }
            SsaOp::Mul { left, right, .. } => {
                if *left == phi_result || *right == phi_result {
                    let other = if *left == phi_result { *right } else { *left };
                    let stride = self.try_get_constant(ssa, other);
                    return (InductionUpdateKind::Mul, stride);
                }
            }
            _ => {}
        }

        (InductionUpdateKind::Unknown, None)
    }

    /// Attempts to get a constant value from a variable.
    fn try_get_constant(&self, ssa: &SsaFunction, var: SsaVarId) -> Option<i64> {
        let variable = ssa.variable(var)?;
        let def_site = variable.def_site();

        if def_site.is_phi() {
            return None;
        }

        let block = ssa.block(def_site.block)?;
        let instr_idx = def_site.instruction?;
        let instr = block.instruction(instr_idx)?;

        match instr.op() {
            SsaOp::Const { value, .. } => value.as_i64(),
            _ => None,
        }
    }
}

/// Loop forest containing all loops in a function.
///
/// Provides efficient queries for loop membership, nesting, and iteration.
#[derive(Debug, Clone)]
pub struct LoopForest {
    /// All loops indexed by their header block.
    loops: Vec<LoopInfo>,
    /// Map from block to the innermost loop containing it.
    block_to_loop: Vec<Option<usize>>,
}

impl LoopForest {
    /// Creates an empty loop forest.
    #[must_use]
    pub fn new(block_count: usize) -> Self {
        Self {
            loops: Vec::new(),
            block_to_loop: vec![None; block_count],
        }
    }

    /// Adds a loop to the forest.
    pub fn add_loop(&mut self, loop_info: LoopInfo) {
        let loop_idx = self.loops.len();

        // Update block-to-loop mapping for all blocks in this loop
        for &block in &loop_info.body {
            let block_idx = block.index();
            if block_idx < self.block_to_loop.len() {
                // Only update if this is a more deeply nested loop
                if let Some(existing_idx) = self.block_to_loop[block_idx] {
                    if self.loops[existing_idx].depth < loop_info.depth {
                        self.block_to_loop[block_idx] = Some(loop_idx);
                    }
                } else {
                    self.block_to_loop[block_idx] = Some(loop_idx);
                }
            }
        }

        self.loops.push(loop_info);
    }

    /// Returns all loops in the forest.
    #[must_use]
    pub fn loops(&self) -> &[LoopInfo] {
        &self.loops
    }

    /// Returns the number of loops.
    #[must_use]
    pub fn len(&self) -> usize {
        self.loops.len()
    }

    /// Returns true if there are no loops.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.loops.is_empty()
    }

    /// Returns the innermost loop containing the given block.
    #[must_use]
    pub fn innermost_loop(&self, block: NodeId) -> Option<&LoopInfo> {
        let block_idx = block.index();
        if block_idx < self.block_to_loop.len() {
            self.block_to_loop[block_idx].map(|idx| &self.loops[idx])
        } else {
            None
        }
    }

    /// Returns the loop with the given header.
    #[must_use]
    pub fn loop_for_header(&self, header: NodeId) -> Option<&LoopInfo> {
        self.loops.iter().find(|l| l.header == header)
    }

    /// Returns the loop depth for a block (0 if not in any loop).
    #[must_use]
    pub fn loop_depth(&self, block: NodeId) -> usize {
        self.innermost_loop(block).map_or(0, |l| l.depth + 1)
    }

    /// Returns true if a block is in any loop.
    #[must_use]
    pub fn is_in_loop(&self, block: NodeId) -> bool {
        self.innermost_loop(block).is_some()
    }

    /// Iterates over all loops in the forest.
    pub fn iter(&self) -> impl Iterator<Item = &LoopInfo> {
        self.loops.iter()
    }

    /// Returns loops sorted by depth (outermost first).
    #[must_use]
    pub fn by_depth_ascending(&self) -> Vec<&LoopInfo> {
        let mut sorted: Vec<_> = self.loops.iter().collect();
        sorted.sort_by_key(|l| l.depth);
        sorted
    }

    /// Returns loops sorted by depth (innermost first).
    #[must_use]
    pub fn by_depth_descending(&self) -> Vec<&LoopInfo> {
        let mut sorted: Vec<_> = self.loops.iter().collect();
        sorted.sort_by_key(|l| std::cmp::Reverse(l.depth));
        sorted
    }
}

/// Detects all natural loops in a graph using dominance-based back edge detection.
///
/// This is the primary entry point for loop detection. It works with any graph
/// implementing the required traits, enabling loop analysis on various graph types
/// (CIL CFGs, SSA CFGs, x86 CFGs, etc.).
///
/// # Algorithm
///
/// The detection algorithm:
/// 1. Finds back edges using dominance (n → h where h dominates n)
/// 2. For each back edge, computes the natural loop body
/// 3. Computes preheaders, exits, and loop types
/// 4. Establishes nesting relationships
///
/// # Arguments
///
/// * `graph` - Any graph implementing `GraphBase + Successors + Predecessors`
/// * `dominators` - Pre-computed dominator tree for the graph
///
/// # Returns
///
/// A [`LoopForest`] containing all detected loops with their full analysis.
///
/// # Examples
///
/// ```rust,ignore
/// use dotscope::analysis::cfg::detect_loops;
/// use dotscope::utils::graph::algorithms::compute_dominators;
///
/// let dominators = compute_dominators(&graph, graph.entry());
/// let forest = detect_loops(&graph, &dominators);
///
/// for loop_info in forest.loops() {
///     println!("Loop at {:?} with {} blocks", loop_info.header, loop_info.size());
/// }
/// ```
#[must_use]
pub fn detect_loops<G>(graph: &G, dominators: &DominatorTree) -> LoopForest
where
    G: GraphBase + Successors + Predecessors,
{
    let block_count = graph.node_count();
    let mut forest = LoopForest::new(block_count);

    // Collect loops by header
    let mut loops_by_header: HashMap<NodeId, LoopInfo> = HashMap::new();

    // Find all back edges: edge (n -> h) where h dominates n
    for node in graph.node_ids() {
        for succ in graph.successors(node) {
            // Check if successor dominates current node (back edge)
            if dominators.dominates(succ, node) {
                // Found back edge: node -> succ (succ is loop header)
                let header = succ;

                let loop_info = loops_by_header
                    .entry(header)
                    .or_insert_with(|| LoopInfo::new(header));

                loop_info.latches.push(node);
                expand_loop_body(graph, loop_info, node);
            }
        }
    }

    // Compute additional loop information for each loop
    for loop_info in loops_by_header.values_mut() {
        compute_preheader(graph, loop_info);
        compute_exits(graph, loop_info);
        loop_info.loop_type = classify_loop(loop_info);
    }

    // Convert to Vec and compute nesting relationships
    let mut loops: Vec<LoopInfo> = loops_by_header.into_values().collect();
    compute_nesting(&mut loops);

    // Sort by header for deterministic ordering
    loops.sort_by_key(|l| l.header.index());

    // Add all loops to forest
    for loop_info in loops {
        forest.add_loop(loop_info);
    }

    forest
}

/// Checks if a graph has any back edges (loops).
///
/// This is a fast check that returns as soon as the first back edge is found,
/// without building the full loop forest. Use this when you only need to know
/// whether loops exist, not their detailed structure.
///
/// # Arguments
///
/// * `graph` - Any graph implementing `GraphBase + Successors`
/// * `dominators` - Pre-computed dominator tree for the graph
///
/// # Returns
///
/// `true` if at least one back edge exists, `false` otherwise.
///
/// # Examples
///
/// ```rust,ignore
/// use dotscope::analysis::cfg::has_back_edges;
/// use dotscope::utils::graph::algorithms::compute_dominators;
///
/// let dominators = compute_dominators(&graph, graph.entry());
/// if has_back_edges(&graph, &dominators) {
///     println!("Graph contains loops");
/// }
/// ```
#[must_use]
pub fn has_back_edges<G>(graph: &G, dominators: &DominatorTree) -> bool
where
    G: GraphBase + Successors,
{
    for node in graph.node_ids() {
        for succ in graph.successors(node) {
            if dominators.dominates(succ, node) {
                return true;
            }
        }
    }
    false
}

/// Expands the loop body to include all nodes that can reach the latch.
///
/// Uses a worklist algorithm: starting from the latch, we add
/// predecessors that aren't the header until we've found all loop body nodes.
fn expand_loop_body<G>(graph: &G, loop_info: &mut LoopInfo, latch: NodeId)
where
    G: Predecessors,
{
    if loop_info.body.contains(&latch) {
        return;
    }

    let mut worklist = vec![latch];

    while let Some(node) = worklist.pop() {
        if loop_info.body.insert(node) {
            // Node wasn't in body yet, add its predecessors
            for pred in graph.predecessors(node) {
                if pred != loop_info.header && !loop_info.body.contains(&pred) {
                    worklist.push(pred);
                }
            }
        }
    }
}

/// Identifies the preheader for a loop.
///
/// A preheader is a single predecessor of the header that is outside the loop.
/// If the header has multiple non-loop predecessors, there is no preheader.
fn compute_preheader<G>(graph: &G, loop_info: &mut LoopInfo)
where
    G: Predecessors,
{
    let mut non_loop_preds: Vec<NodeId> = Vec::new();

    for pred in graph.predecessors(loop_info.header) {
        if !loop_info.body.contains(&pred) {
            non_loop_preds.push(pred);
        }
    }

    // Preheader exists only if there's exactly one non-loop predecessor
    loop_info.preheader = if non_loop_preds.len() == 1 {
        Some(non_loop_preds[0])
    } else {
        None
    };
}

/// Computes exit edges for a loop.
///
/// An exit edge goes from a block inside the loop to a block outside the loop.
fn compute_exits<G>(graph: &G, loop_info: &mut LoopInfo)
where
    G: Successors,
{
    loop_info.exits.clear();

    for &body_block in &loop_info.body {
        for succ in graph.successors(body_block) {
            if !loop_info.body.contains(&succ) {
                loop_info.exits.push(LoopExit {
                    exiting_block: body_block,
                    exit_block: succ,
                });
            }
        }
    }
}

/// Classifies the loop type based on structure.
fn classify_loop(loop_info: &LoopInfo) -> LoopType {
    // Check for infinite loop (no exits)
    if loop_info.exits.is_empty() {
        return LoopType::Infinite;
    }

    // Check for multiple latches (complex)
    if loop_info.latches.len() > 1 {
        return LoopType::Complex;
    }

    // Get the single latch
    let latch = loop_info.single_latch();

    // Check if all exits are from the latch (post-tested / do-while loop)
    if let Some(latch) = latch {
        let latch_exits = loop_info
            .exits
            .iter()
            .filter(|e| e.exiting_block == latch)
            .count();

        if latch_exits == loop_info.exits.len() && latch_exits > 0 {
            return LoopType::PostTested;
        }
    }

    // Check if header is the only exiting block (pre-tested / while loop)
    let header_exits = loop_info
        .exits
        .iter()
        .filter(|e| e.exiting_block == loop_info.header)
        .count();

    if header_exits == loop_info.exits.len() && header_exits > 0 {
        return LoopType::PreTested;
    }

    // Mixed or irregular exit structure
    LoopType::Complex
}

/// Computes loop nesting relationships and depths.
fn compute_nesting(loops: &mut [LoopInfo]) {
    let n = loops.len();

    // Build header-to-index mapping
    let header_to_idx: HashMap<NodeId, usize> = loops
        .iter()
        .enumerate()
        .map(|(i, l)| (l.header, i))
        .collect();

    // For each loop, find its parent (smallest enclosing loop)
    for i in 0..n {
        let header = loops[i].header;

        // Find all loops that contain this loop's header (except itself)
        let mut candidates: Vec<usize> = (0..n)
            .filter(|&j| j != i && loops[j].body.contains(&header))
            .collect();

        // Parent is the smallest containing loop
        if !candidates.is_empty() {
            candidates.sort_by_key(|&j| loops[j].size());
            let parent_idx = candidates[0];
            loops[i].parent = Some(loops[parent_idx].header);
        }
    }

    // Compute children from parent relationships
    for i in 0..n {
        if let Some(parent_header) = loops[i].parent {
            if let Some(&parent_idx) = header_to_idx.get(&parent_header) {
                loops[parent_idx].children.push(loops[i].header);
            }
        }
    }

    // Compute depths from parent chain
    for i in 0..n {
        let mut depth = 0;
        let mut current = loops[i].parent;
        while let Some(parent_header) = current {
            depth += 1;
            if let Some(&parent_idx) = header_to_idx.get(&parent_header) {
                current = loops[parent_idx].parent;
            } else {
                break;
            }
        }
        loops[i].depth = depth;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_loop_info_creation() {
        let header = NodeId::new(0);
        let loop_info = LoopInfo::new(header);

        assert_eq!(loop_info.header, header);
        assert!(loop_info.contains(header));
        assert_eq!(loop_info.size(), 1);
        assert!(!loop_info.has_single_latch());
        assert!(!loop_info.has_preheader());
        assert!(!loop_info.is_canonical());
    }

    #[test]
    fn test_loop_info_canonical() {
        let header = NodeId::new(1);
        let mut loop_info = LoopInfo::new(header);

        loop_info.preheader = Some(NodeId::new(0));
        loop_info.latches.push(NodeId::new(2));

        assert!(loop_info.has_preheader());
        assert!(loop_info.has_single_latch());
        assert!(loop_info.is_canonical());
    }

    #[test]
    fn test_loop_forest() {
        let mut forest = LoopForest::new(10);

        let mut outer_loop = LoopInfo::new(NodeId::new(1));
        outer_loop.body.insert(NodeId::new(2));
        outer_loop.body.insert(NodeId::new(3));
        outer_loop.depth = 0;

        let mut inner_loop = LoopInfo::new(NodeId::new(2));
        inner_loop.body.insert(NodeId::new(3));
        inner_loop.depth = 1;

        forest.add_loop(outer_loop);
        forest.add_loop(inner_loop);

        assert_eq!(forest.len(), 2);

        // Block 3 should be in inner loop (depth 1)
        assert_eq!(forest.loop_depth(NodeId::new(3)), 2);

        // Block 1 should be in outer loop only
        assert_eq!(forest.loop_depth(NodeId::new(1)), 1);

        // Block 0 should not be in any loop
        assert_eq!(forest.loop_depth(NodeId::new(0)), 0);
    }
}
