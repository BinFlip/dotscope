//! Sparse Conditional Constant Propagation (SCCP).
//!
//! SCCP is a powerful constant propagation algorithm that combines:
//!
//! 1. **Sparse analysis**: Works directly on SSA def-use chains rather than
//!    iterating over all program points
//! 2. **Conditional propagation**: Uses constant branch conditions to prune
//!    unreachable code paths
//!
//! # Algorithm Overview
//!
//! SCCP maintains two lattices:
//! - **Value lattice**: For each SSA variable, tracks whether it's Top (unknown),
//!   Constant (known value), or Bottom (multiple values)
//! - **CFG reachability**: Tracks which CFG edges are executable
//!
//! The algorithm uses two worklists:
//! - **SSA worklist**: Variables whose values have changed
//! - **CFG worklist**: CFG edges that have become executable
//!
//! # Edge-Based Phi Evaluation
//!
//! A key insight from Wegman & Zadeck is that phi nodes should be evaluated
//! based on which **edges** are executable, not which blocks are reachable.
//! This is critical for precision: a block may be reachable via multiple edges,
//! but only some of those edges may have been discovered yet.
//!
//! For example, in a diamond CFG:
//! ```text
//!        B0
//!       /  \
//!      B1  B2
//!       \  /
//!        B3
//! ```
//! If only the edge B0→B1→B3 is executable (because the branch in B0 is constant),
//! the phi in B3 should only consider the operand from B1, not B2.
//!
//! # Differences from Standard Solver
//!
//! Unlike the generic solver, SCCP doesn't use block-level transfer functions.
//! Instead, it processes individual SSA instructions and phi nodes directly,
//! which is more efficient for sparse analyses.
//!
//! # Reference
//!
//! Wegman & Zadeck, "Constant Propagation with Conditional Branches", 1991.

use std::collections::{HashMap, HashSet, VecDeque};

use crate::{
    analysis::{
        dataflow::lattice::MeetSemiLattice, ConstValue, PhiNode, SsaBlock, SsaFunction, SsaOp,
        SsaVarId,
    },
    utils::graph::{NodeId, RootedGraph, Successors},
};

/// Sparse Conditional Constant Propagation analysis.
///
/// This analysis computes which SSA variables have constant values,
/// taking into account that some branches may never be taken.
///
/// # Example
///
/// ```rust,ignore
/// use dotscope::analysis::{ConstantPropagation, ScalarValue};
///
/// let mut sccp = ConstantPropagation::new();
/// let results = sccp.analyze(&ssa, &graph);
///
/// // Check if a variable is constant
/// if let Some(ScalarValue::Constant(c)) = results.get_value(var_id) {
///     println!("{} = {}", var_id, c);
/// }
/// ```
pub struct ConstantPropagation {
    /// Current value for each SSA variable.
    values: HashMap<SsaVarId, ScalarValue>,
    /// Executable CFG edges.
    executable_edges: HashSet<(usize, usize)>,
    /// Blocks that have been marked executable.
    executable_blocks: HashSet<usize>,
    /// SSA worklist: variables whose values have changed.
    ssa_worklist: VecDeque<SsaVarId>,
    /// CFG worklist: edges that have become executable.
    cfg_worklist: VecDeque<(usize, usize)>,
    /// Back edges: edges where the target was already executable when the edge was added.
    /// These represent loop back edges and their values should be treated as unknown.
    back_edges: HashSet<(usize, usize)>,
}

impl ConstantPropagation {
    /// Creates a new constant propagation analysis.
    #[must_use]
    pub fn new() -> Self {
        Self {
            values: HashMap::new(),
            executable_edges: HashSet::new(),
            executable_blocks: HashSet::new(),
            ssa_worklist: VecDeque::new(),
            cfg_worklist: VecDeque::new(),
            back_edges: HashSet::new(),
        }
    }

    /// Runs the SCCP algorithm on the given SSA function.
    ///
    /// The CFG parameter can be any type that implements the required graph traits:
    /// - `RootedGraph` for the entry point
    /// - `Successors` for traversing outgoing edges
    ///
    /// This allows using both `ControlFlowGraph` (from CIL blocks) and `SsaCfg`
    /// (from SSA function terminators).
    ///
    /// Returns the analysis results containing the value for each variable.
    pub fn analyze<G>(&mut self, ssa: &SsaFunction, cfg: &G) -> SccpResult
    where
        G: RootedGraph + Successors,
    {
        self.initialize(ssa, cfg);
        self.propagate(ssa, cfg);

        SccpResult {
            values: self.values.clone(),
            executable_blocks: self.executable_blocks.clone(),
        }
    }

    /// Initializes the analysis state.
    fn initialize<G>(&mut self, ssa: &SsaFunction, cfg: &G)
    where
        G: RootedGraph + Successors,
    {
        self.values.clear();
        self.executable_edges.clear();
        self.executable_blocks.clear();
        self.ssa_worklist.clear();
        self.cfg_worklist.clear();
        self.back_edges.clear();

        // Initialize variable values:
        // - Argument variables (version 0, defined at entry) start as Bottom (unknown input)
        // - All other variables start as Top (no information yet)
        //
        // This distinction is critical: arguments are external inputs that could be anything,
        // while other variables are defined by instructions that SCCP will evaluate.
        // Without this, branch conditions depending on arguments stay at Top forever
        // (since no instruction defines them), causing the branch to never add edges.
        for var in ssa.variables() {
            let initial_value = if var.origin().is_argument()
                && var.version() == 0
                && var.def_site().instruction.is_none()
            {
                // This is the initial definition of an argument - it's an unknown input
                ScalarValue::Bottom
            } else {
                // Regular variable - will be evaluated by instructions
                ScalarValue::Top
            };
            self.values.insert(var.id(), initial_value);
        }

        // Mark entry block as executable
        let entry = cfg.entry().index();
        self.executable_blocks.insert(entry);

        // Add entry block's outgoing edges to CFG worklist
        // For unconditional edges or first visit, add all successors
        for succ in cfg.successors(cfg.entry()) {
            self.cfg_worklist.push_back((entry, succ.index()));
        }

        // Process entry block definitions immediately
        if let Some(block) = ssa.block(entry) {
            self.process_block_definitions(block);
        }
    }

    /// Main propagation loop.
    fn propagate<G>(&mut self, ssa: &SsaFunction, cfg: &G)
    where
        G: RootedGraph + Successors,
    {
        // Process until both worklists are empty
        loop {
            // Process CFG worklist first (to discover new blocks)
            while let Some((from, to)) = self.cfg_worklist.pop_front() {
                if self.executable_edges.insert((from, to)) {
                    // Detect back edges: if the target block was already executable
                    // when this edge is being added, it's a back edge (loop).
                    // PHI operands from back edges represent values that change
                    // across loop iterations and should be treated as unknown.
                    if self.executable_blocks.contains(&to) {
                        self.back_edges.insert((from, to));
                    }
                    // This edge became executable
                    self.process_edge(from, to, ssa, cfg);
                }
            }

            // Process SSA worklist
            if let Some(var) = self.ssa_worklist.pop_front() {
                self.process_variable_uses(var, ssa, cfg);
            } else {
                // Both worklists empty
                break;
            }
        }
    }

    /// Processes a newly executable CFG edge.
    ///
    /// When an edge `(from, to)` becomes executable:
    /// 1. If this is the first edge reaching `to`, mark the block executable and
    ///    process all its definitions
    /// 2. Re-evaluate all phi nodes in `to` since they may now have a new operand
    ///    from the `from` block
    /// 3. If first visit, propagate outgoing edges based on the terminator
    fn process_edge<G>(&mut self, from: usize, to: usize, ssa: &SsaFunction, cfg: &G)
    where
        G: RootedGraph + Successors,
    {
        let first_visit = !self.executable_blocks.contains(&to);

        if first_visit {
            self.executable_blocks.insert(to);

            // Process all definitions in the block
            if let Some(block) = ssa.block(to) {
                self.process_block_definitions(block);
            }
        }

        // Re-evaluate phi nodes in the target block.
        // The new edge (from, to) may contribute a new operand value.
        if let Some(block) = ssa.block(to) {
            for phi in block.phi_nodes() {
                // Only re-evaluate if this phi has an operand from the `from` block
                if phi.operand_from(from).is_some() {
                    let new_value = self.evaluate_phi(phi, to);
                    self.update_value(phi.result(), &new_value);
                }
            }
        }

        // If first visit, propagate outgoing edges based on terminator
        if first_visit {
            if let Some(block) = ssa.block(to) {
                self.propagate_outgoing_edges(to, block, cfg);
            }
        }
    }

    /// Processes all definitions in a block (non-phi instructions).
    ///
    /// This evaluates each instruction and updates the value lattice for any
    /// variables defined by the instruction.
    fn process_block_definitions(&mut self, block: &SsaBlock) {
        for instr in block.instructions() {
            if let Some(def) = instr.def() {
                let value = self.evaluate_instruction(instr.op());
                self.update_value(def, &value);
            }
        }
    }

    /// Processes uses of a variable whose value changed.
    fn process_variable_uses<G>(&mut self, var: SsaVarId, ssa: &SsaFunction, cfg: &G)
    where
        G: RootedGraph + Successors,
    {
        // Find all uses of this variable
        if let Some(ssa_var) = ssa.variable(var) {
            for use_site in ssa_var.uses() {
                let block_id = use_site.block;

                // Skip if block is not executable
                if !self.executable_blocks.contains(&block_id) {
                    continue;
                }

                if use_site.is_phi_operand {
                    // Re-evaluate the phi node
                    if let Some(block) = ssa.block(block_id) {
                        if let Some(phi) = block.phi(use_site.instruction) {
                            let new_value = self.evaluate_phi(phi, block_id);
                            self.update_value(phi.result(), &new_value);
                        }
                    }
                } else {
                    // Re-evaluate the instruction
                    if let Some(block) = ssa.block(block_id) {
                        if let Some(instr) = block.instruction(use_site.instruction) {
                            if let Some(def) = instr.def() {
                                let value = self.evaluate_instruction(instr.op());
                                self.update_value(def, &value);
                            }

                            // Check if this is a branch instruction
                            if instr.is_terminator() {
                                self.propagate_outgoing_edges(block_id, block, cfg);
                            }
                        }
                    }
                }
            }
        }
    }

    /// Propagates outgoing edges from a block based on terminator.
    fn propagate_outgoing_edges<G>(&mut self, block_id: usize, block: &SsaBlock, cfg: &G)
    where
        G: RootedGraph + Successors,
    {
        // Find the terminator instruction
        match block.terminator_op() {
            Some(SsaOp::Branch {
                condition,
                true_target,
                false_target,
            }) => {
                // Conditional branch - check if condition is constant
                match self.get_value(*condition) {
                    ScalarValue::Constant(c) => {
                        // Known branch direction
                        let target = if c.as_bool() == Some(true) {
                            *true_target
                        } else {
                            *false_target
                        };
                        self.add_cfg_edge(block_id, target);
                    }
                    ScalarValue::Top => {
                        // Unknown - don't add edges yet
                    }
                    ScalarValue::Bottom => {
                        // Could go either way - add both edges
                        self.add_cfg_edge(block_id, *true_target);
                        self.add_cfg_edge(block_id, *false_target);
                    }
                }
            }
            Some(SsaOp::Switch {
                value,
                targets,
                default,
            }) => {
                // Switch statement
                match self.get_value(*value) {
                    ScalarValue::Constant(c) => {
                        // Known switch value - use checked conversion to handle negative values
                        if let Some(idx) = c.as_i32().and_then(|i| usize::try_from(i).ok()) {
                            if idx < targets.len() {
                                self.add_cfg_edge(block_id, targets[idx]);
                            } else {
                                self.add_cfg_edge(block_id, *default);
                            }
                        } else {
                            self.add_cfg_edge(block_id, *default);
                        }
                    }
                    ScalarValue::Top | ScalarValue::Bottom => {
                        // Unknown or could be anything - conservatively add all edges.
                        // This is critical for control flow obfuscation where the switch
                        // value is computed dynamically and cannot be statically determined.
                        for &target in targets {
                            self.add_cfg_edge(block_id, target);
                        }
                        self.add_cfg_edge(block_id, *default);
                    }
                }
            }
            Some(SsaOp::Jump { target }) => {
                // Unconditional jump
                self.add_cfg_edge(block_id, *target);
            }
            Some(SsaOp::Return { .. } | SsaOp::Throw { .. } | SsaOp::Rethrow) => {
                // No successors
            }
            _ => {
                // Fall through or unknown terminator - add all CFG successors
                let node = NodeId::new(block_id);
                for succ in cfg.successors(node) {
                    self.add_cfg_edge(block_id, succ.index());
                }
            }
        }
    }

    /// Adds a CFG edge to the worklist if not already executable.
    fn add_cfg_edge(&mut self, from: usize, to: usize) {
        if !self.executable_edges.contains(&(from, to)) {
            self.cfg_worklist.push_back((from, to));
        }
    }

    /// Evaluates a phi node to get its current value.
    ///
    /// This is the key to SCCP's precision: we only consider operands from
    /// **executable edges**, not just reachable blocks. This allows us to
    /// propagate constants through conditional branches more precisely.
    ///
    /// For example, if we have:
    /// ```text
    /// B0: if (true) goto B1 else goto B2
    /// B1: x = 5; goto B3
    /// B2: x = 10; goto B3
    /// B3: y = phi(x from B1, x from B2)
    /// ```
    /// Even though B3 is reachable, only the edge B1→B3 is executable (because
    /// the branch condition is constant true). So y = 5, not bottom.
    ///
    /// # Arguments
    ///
    /// * `phi` - The phi node to evaluate
    /// * `block_id` - The block containing this phi node (needed to check edge executability)
    fn evaluate_phi(&self, phi: &PhiNode, block_id: usize) -> ScalarValue {
        let mut result = ScalarValue::Top;
        let mut has_executable_operand = false;

        for operand in phi.operands() {
            let pred = operand.predecessor();

            // The key SCCP insight: only consider this operand if the specific
            // edge (pred -> block_id) is executable, not just if pred is reachable.
            if !self.executable_edges.contains(&(pred, block_id)) {
                continue;
            }

            has_executable_operand = true;

            // For back edges (loop edges), treat the operand value as Bottom.
            // Back edge values represent loop-carried dependencies that change
            // across iterations. Using the first-iteration value would incorrectly
            // mark the PHI as constant when it's actually varying.
            //
            // Example: Fibonacci loop where b = phi(1, temp)
            // - First iteration: temp = 0 + 1 = 1, so b = phi(1, 1) looks constant
            // - But iteration 2: temp = 1 + 1 = 2, so b should be 2
            // Without this check, SCCP would incorrectly conclude b is always 1.
            let op_value = if self.back_edges.contains(&(pred, block_id)) {
                ScalarValue::Bottom
            } else {
                self.get_value(operand.value())
            };
            result = result.meet(&op_value);

            // Early exit if already bottom
            if result.is_bottom() {
                break;
            }
        }

        // If no operands were from executable edges, return Top (no information yet)
        if !has_executable_operand {
            return ScalarValue::Top;
        }

        result
    }

    /// Evaluates an SSA instruction to get its result value.
    ///
    /// This performs abstract interpretation of the instruction, computing
    /// what value the result would have given the current lattice values
    /// of the operands.
    fn evaluate_instruction(&self, op: &SsaOp) -> ScalarValue {
        match op {
            SsaOp::Const { value, .. } => ScalarValue::Constant(value.clone()),

            SsaOp::Copy { src, .. } => self.get_value(*src),

            SsaOp::Add { left, right, .. } => self.evaluate_binary(*left, *right, ConstValue::add),

            SsaOp::Sub { left, right, .. } => self.evaluate_binary(*left, *right, ConstValue::sub),

            SsaOp::Mul { left, right, .. } => self.evaluate_binary(*left, *right, ConstValue::mul),

            SsaOp::Div { left, right, .. } => self.evaluate_binary(*left, *right, ConstValue::div),

            SsaOp::Rem { left, right, .. } => self.evaluate_binary(*left, *right, ConstValue::rem),

            SsaOp::And { left, right, .. } => {
                self.evaluate_binary(*left, *right, ConstValue::bitwise_and)
            }

            SsaOp::Or { left, right, .. } => {
                self.evaluate_binary(*left, *right, ConstValue::bitwise_or)
            }

            SsaOp::Xor { left, right, .. } => {
                self.evaluate_binary(*left, *right, ConstValue::bitwise_xor)
            }

            SsaOp::Shl { value, amount, .. } => {
                self.evaluate_binary(*value, *amount, ConstValue::shl)
            }

            SsaOp::Shr {
                value,
                amount,
                unsigned,
                ..
            } => {
                let unsigned = *unsigned;
                self.evaluate_binary(*value, *amount, |l, r| l.shr(r, unsigned))
            }

            SsaOp::Ceq { left, right, .. } => self.evaluate_binary(*left, *right, ConstValue::ceq),

            SsaOp::Clt { left, right, .. } => self.evaluate_binary(*left, *right, ConstValue::clt),

            SsaOp::Cgt { left, right, .. } => self.evaluate_binary(*left, *right, ConstValue::cgt),

            SsaOp::Neg { operand, .. } => match self.get_value(*operand) {
                ScalarValue::Top => ScalarValue::Top,
                ScalarValue::Constant(c) => c
                    .negate()
                    .map_or(ScalarValue::Bottom, ScalarValue::Constant),
                ScalarValue::Bottom => ScalarValue::Bottom,
            },

            SsaOp::Not { operand, .. } => match self.get_value(*operand) {
                ScalarValue::Top => ScalarValue::Top,
                ScalarValue::Constant(c) => c
                    .bitwise_not()
                    .map_or(ScalarValue::Bottom, ScalarValue::Constant),
                ScalarValue::Bottom => ScalarValue::Bottom,
            },

            // All other operations produce non-constant results (calls, loads, etc.)
            _ => ScalarValue::Bottom,
        }
    }

    /// Evaluates a binary operation.
    fn evaluate_binary<F>(&self, left: SsaVarId, right: SsaVarId, f: F) -> ScalarValue
    where
        F: FnOnce(&ConstValue, &ConstValue) -> Option<ConstValue>,
    {
        let left_val = self.get_value(left);
        let right_val = self.get_value(right);

        match (&left_val, &right_val) {
            (ScalarValue::Top, _) | (_, ScalarValue::Top) => ScalarValue::Top,
            (ScalarValue::Constant(l), ScalarValue::Constant(r)) => {
                f(l, r).map_or(ScalarValue::Bottom, ScalarValue::Constant)
            }
            _ => ScalarValue::Bottom,
        }
    }

    /// Gets the current value of a variable.
    fn get_value(&self, var: SsaVarId) -> ScalarValue {
        self.values.get(&var).cloned().unwrap_or_default()
    }

    /// Updates a variable's value and adds it to the worklist if changed.
    fn update_value(&mut self, var: SsaVarId, new_value: &ScalarValue) {
        let old_value = self.values.get(&var).cloned().unwrap_or_default();

        // Apply meet to move down the lattice (values can only decrease)
        let final_value = old_value.meet(new_value);

        if final_value != old_value {
            self.values.insert(var, final_value);
            self.ssa_worklist.push_back(var);
        }
    }
}

impl Default for ConstantPropagation {
    fn default() -> Self {
        Self::new()
    }
}

/// Scalar value in the SCCP lattice.
///
/// This forms a simple three-level lattice:
/// - Top: No information (might be any value)
/// - Constant: Known compile-time constant
/// - Bottom: Not a constant (multiple possible values)
#[derive(Debug, Clone, PartialEq, Default)]
pub enum ScalarValue {
    /// No information yet (top of lattice).
    #[default]
    Top,
    /// Known constant value.
    Constant(ConstValue),
    /// Multiple possible values (bottom of lattice).
    Bottom,
}

impl ScalarValue {
    /// Returns `true` if this is the top element.
    #[must_use]
    pub const fn is_top(&self) -> bool {
        matches!(self, Self::Top)
    }

    /// Returns `true` if this is the bottom element.
    #[must_use]
    pub const fn is_bottom(&self) -> bool {
        matches!(self, Self::Bottom)
    }

    /// Returns `true` if this is a known constant.
    #[must_use]
    pub const fn is_constant(&self) -> bool {
        matches!(self, Self::Constant(_))
    }

    /// Returns the constant value if this is a constant.
    #[must_use]
    pub const fn as_constant(&self) -> Option<&ConstValue> {
        match self {
            Self::Constant(c) => Some(c),
            _ => None,
        }
    }
}

impl MeetSemiLattice for ScalarValue {
    fn meet(&self, other: &Self) -> Self {
        match (self, other) {
            // Top meets anything yields the other
            (Self::Top, x) | (x, Self::Top) => x.clone(),

            // Same constants stay constant
            (Self::Constant(a), Self::Constant(b)) if a == b => Self::Constant(a.clone()),

            // Different constants or anything with bottom yields bottom
            _ => Self::Bottom,
        }
    }

    fn is_bottom(&self) -> bool {
        matches!(self, Self::Bottom)
    }
}

/// Results of SCCP analysis.
#[derive(Debug, Clone)]
pub struct SccpResult {
    /// Value for each SSA variable.
    values: HashMap<SsaVarId, ScalarValue>,
    /// Blocks determined to be executable.
    executable_blocks: HashSet<usize>,
}

impl SccpResult {
    /// Creates an empty SCCP result.
    ///
    /// This is useful for testing or when no analysis has been performed.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            values: HashMap::new(),
            executable_blocks: HashSet::new(),
        }
    }

    /// Gets the value of an SSA variable.
    #[must_use]
    pub fn get_value(&self, var: SsaVarId) -> Option<&ScalarValue> {
        self.values.get(&var)
    }

    /// Returns `true` if a variable is known to be constant.
    #[must_use]
    pub fn is_constant(&self, var: SsaVarId) -> bool {
        self.values
            .get(&var)
            .is_some_and(|v| matches!(v, ScalarValue::Constant(_)))
    }

    /// Returns the constant value of a variable if known.
    #[must_use]
    pub fn constant_value(&self, var: SsaVarId) -> Option<&ConstValue> {
        self.values.get(&var).and_then(|v| match v {
            ScalarValue::Constant(c) => Some(c),
            _ => None,
        })
    }

    /// Returns `true` if a block is executable (reachable).
    #[must_use]
    pub fn is_block_executable(&self, block: usize) -> bool {
        self.executable_blocks.contains(&block)
    }

    /// Returns an iterator over all constant variables.
    pub fn constants(&self) -> impl Iterator<Item = (SsaVarId, &ConstValue)> {
        self.values.iter().filter_map(|(var, val)| match val {
            ScalarValue::Constant(c) => Some((*var, c)),
            _ => None,
        })
    }

    /// Returns an iterator over all executable blocks.
    pub fn executable_blocks(&self) -> impl Iterator<Item = usize> + '_ {
        self.executable_blocks.iter().copied()
    }

    /// Returns the number of variables found to be constant.
    #[must_use]
    pub fn constant_count(&self) -> usize {
        self.values
            .values()
            .filter(|v| matches!(v, ScalarValue::Constant(_)))
            .count()
    }

    /// Returns the number of executable blocks.
    #[must_use]
    pub fn executable_block_count(&self) -> usize {
        self.executable_blocks.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scalar_value_meet() {
        // Top meets anything yields the other
        assert_eq!(
            ScalarValue::Top.meet(&ScalarValue::Constant(ConstValue::I32(5))),
            ScalarValue::Constant(ConstValue::I32(5))
        );

        // Same constants stay constant
        assert_eq!(
            ScalarValue::Constant(ConstValue::I32(5))
                .meet(&ScalarValue::Constant(ConstValue::I32(5))),
            ScalarValue::Constant(ConstValue::I32(5))
        );

        // Different constants become bottom
        assert_eq!(
            ScalarValue::Constant(ConstValue::I32(5))
                .meet(&ScalarValue::Constant(ConstValue::I32(10))),
            ScalarValue::Bottom
        );

        // Bottom meets anything yields bottom
        assert_eq!(
            ScalarValue::Bottom.meet(&ScalarValue::Constant(ConstValue::I32(5))),
            ScalarValue::Bottom
        );
    }

    #[test]
    fn test_scalar_value_accessors() {
        let top = ScalarValue::Top;
        let const_val = ScalarValue::Constant(ConstValue::I32(42));
        let bottom = ScalarValue::Bottom;

        assert!(top.is_top());
        assert!(!top.is_constant());
        assert!(!top.is_bottom());

        assert!(!const_val.is_top());
        assert!(const_val.is_constant());
        assert!(!const_val.is_bottom());
        assert_eq!(const_val.as_constant(), Some(&ConstValue::I32(42)));

        assert!(!bottom.is_top());
        assert!(!bottom.is_constant());
        assert!(bottom.is_bottom());
    }

    #[test]
    fn test_sccp_result() {
        let v0 = SsaVarId::new();
        let v1 = SsaVarId::new();
        let v2 = SsaVarId::new();

        let mut values = HashMap::new();
        values.insert(v0, ScalarValue::Constant(ConstValue::I32(42)));
        values.insert(v1, ScalarValue::Bottom);
        values.insert(v2, ScalarValue::Top);

        let mut executable_blocks = HashSet::new();
        executable_blocks.insert(0);
        executable_blocks.insert(1);

        let result = SccpResult {
            values,
            executable_blocks,
        };

        assert!(result.is_constant(v0));
        assert!(!result.is_constant(v1));
        assert!(!result.is_constant(v2));

        assert_eq!(result.constant_value(v0), Some(&ConstValue::I32(42)));
        assert_eq!(result.constant_value(v1), None);

        assert!(result.is_block_executable(0));
        assert!(result.is_block_executable(1));
        assert!(!result.is_block_executable(2));

        assert_eq!(result.constant_count(), 1);
        assert_eq!(result.executable_block_count(), 2);
    }
}
