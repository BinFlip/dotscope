//! Value Range Propagation Pass.
//!
//! This pass performs dataflow-based range analysis to track the possible
//! values of integer variables throughout the control flow graph. It strengthens
//! opaque predicate detection by proving comparisons based on value ranges.
//!
//! # Algorithm
//!
//! Uses a sparse worklist algorithm similar to SCCP:
//! 1. Initialize all variables to `Top` (unknown range)
//! 2. Process definitions to narrow ranges based on operations
//! 3. At conditional branches, narrow ranges for the taken path
//! 4. Use ranges to simplify always-true/false comparisons
//!
//! # Improvements Over Pattern Matching
//!
//! While the `OpaquePredicatePass` uses local pattern matching, this pass
//! propagates ranges through the CFG to catch cases like:
//!
//! ```text
//! B0: x = 5
//!     jump B1
//!
//! B1: y = x + 10     // y ∈ [15, 15]
//!     jump B2
//!
//! B2: if (y > 100)   // Always false: 15 > 100 is false
//!         ...
//! ```
//!
//! The pattern matcher in `OpaquePredicatePass` can't see through the add,
//! but range propagation tracks y = 15 through the CFG.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::Arc,
};

use crate::{
    analysis::{ConstValue, PhiNode, SsaBlock, SsaCfg, SsaFunction, SsaOp, SsaVarId, ValueRange},
    compiler::{pass::SsaPass, CompilerContext, EventKind, EventLog},
    metadata::token::Token,
    utils::graph::{NodeId, RootedGraph, Successors},
    CilObject, Result,
};

/// Value Range Propagation Pass.
///
/// Performs dataflow-based range analysis to strengthen opaque predicate
/// detection and simplify comparisons that can be proven always-true or
/// always-false based on value ranges.
pub struct ValueRangePropagationPass;

impl Default for ValueRangePropagationPass {
    fn default() -> Self {
        Self::new()
    }
}

impl ValueRangePropagationPass {
    /// Creates a new value range propagation pass.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl SsaPass for ValueRangePropagationPass {
    fn name(&self) -> &'static str {
        "value-range-propagation"
    }

    fn description(&self) -> &'static str {
        "Propagates value ranges through CFG to detect opaque predicates"
    }

    fn run_on_method(
        &self,
        ssa: &mut SsaFunction,
        method_token: Token,
        ctx: &CompilerContext,
        _assembly: &Arc<CilObject>,
    ) -> Result<bool> {
        // Run range analysis
        let mut analysis = RangeAnalysis::new();
        let result = analysis.analyze(ssa);

        // Collect transformations to apply
        let changes = EventLog::new();
        let mut branch_simplifications: Vec<(usize, usize, bool)> = Vec::new();
        let mut comparison_replacements: Vec<(usize, usize, SsaVarId, bool)> = Vec::new();

        // Find branches and comparisons that can be simplified
        for (block_idx, block) in ssa.iter_blocks() {
            // Check branch terminator
            if let Some(SsaOp::Branch {
                condition,
                true_target,
                false_target,
            }) = block.terminator_op()
            {
                if let Some(range) = result.get_range(*condition) {
                    // Check if range proves the condition
                    if let Some(is_true) = range.always_equal_to(0) {
                        // always_equal_to(0) being true means always false
                        // always_equal_to(0) being false means possibly non-zero
                        if is_true {
                            // Condition is always 0 (false)
                            branch_simplifications.push((block_idx, *false_target, false));
                        }
                    }

                    // Check if range is a known non-zero constant
                    if let Some(val) = range.as_constant() {
                        if val != 0 {
                            branch_simplifications.push((block_idx, *true_target, true));
                        }
                    }
                }
            }

            // Check comparison instructions
            for (instr_idx, instr) in block.instructions().iter().enumerate() {
                if let Some((dest, value)) = Self::try_simplify_comparison(instr.op(), &result) {
                    comparison_replacements.push((block_idx, instr_idx, dest, value));
                }
            }
        }

        // Apply branch simplifications
        for (block_idx, target, is_true) in branch_simplifications {
            if let Some(block) = ssa.block_mut(block_idx) {
                if let Some(last_instr) = block.instructions_mut().last_mut() {
                    last_instr.set_op(SsaOp::Jump { target });
                    changes
                        .record(EventKind::OpaquePredicateRemoved)
                        .at(method_token, block_idx)
                        .message(format!(
                            "range analysis: condition always {}",
                            if is_true { "true" } else { "false" }
                        ));
                    changes
                        .record(EventKind::BranchSimplified)
                        .at(method_token, block_idx)
                        .message(format!("simplified to unconditional jump to {target}"));
                }
            }
        }

        // Apply comparison replacements
        for (block_idx, instr_idx, dest, value) in comparison_replacements {
            if let Some(block) = ssa.block_mut(block_idx) {
                let const_value = if value {
                    ConstValue::True
                } else {
                    ConstValue::False
                };
                block.instructions_mut()[instr_idx].set_op(SsaOp::Const {
                    dest,
                    value: const_value,
                });
                changes
                    .record(EventKind::ConstantFolded)
                    .at(method_token, instr_idx)
                    .message(format!("range analysis: comparison → {value}"));
            }
        }

        let changed = !changes.is_empty();
        if changed {
            ctx.events.merge(&changes);
        }
        Ok(changed)
    }
}

impl ValueRangePropagationPass {
    /// Tries to simplify a comparison operation using range information.
    ///
    /// Returns `Some((dest, value))` if the comparison can be proven to always
    /// have a constant result, where `value` is the boolean result.
    fn try_simplify_comparison(op: &SsaOp, result: &RangeResult) -> Option<(SsaVarId, bool)> {
        match op {
            SsaOp::Clt {
                dest,
                left,
                right,
                unsigned: _,
            } => {
                let left_range = result.get_range(*left)?;
                let right_range = result.get_range(*right)?;

                // Check if left.max < right.min (always true)
                // or left.min >= right.max (always false)
                if let (Some(l_max), Some(r_min)) = (left_range.max(), right_range.min()) {
                    if l_max < r_min {
                        return Some((*dest, true));
                    }
                }
                if let (Some(l_min), Some(r_max)) = (left_range.min(), right_range.max()) {
                    if l_min >= r_max {
                        return Some((*dest, false));
                    }
                }
                None
            }

            SsaOp::Cgt {
                dest,
                left,
                right,
                unsigned: _,
            } => {
                let left_range = result.get_range(*left)?;
                let right_range = result.get_range(*right)?;

                // Check if left.min > right.max (always true)
                // or left.max <= right.min (always false)
                if let (Some(l_min), Some(r_max)) = (left_range.min(), right_range.max()) {
                    if l_min > r_max {
                        return Some((*dest, true));
                    }
                }
                if let (Some(l_max), Some(r_min)) = (left_range.max(), right_range.min()) {
                    if l_max <= r_min {
                        return Some((*dest, false));
                    }
                }
                None
            }

            SsaOp::Ceq { dest, left, right } => {
                let left_range = result.get_range(*left)?;
                let right_range = result.get_range(*right)?;

                // If both are constants and equal
                if let (Some(l), Some(r)) = (left_range.as_constant(), right_range.as_constant()) {
                    return Some((*dest, l == r));
                }

                // If ranges don't overlap, they can never be equal
                if !Self::ranges_overlap(left_range, right_range) {
                    return Some((*dest, false));
                }

                None
            }

            _ => None,
        }
    }

    /// Checks if two ranges have any overlap.
    fn ranges_overlap(a: &ValueRange, b: &ValueRange) -> bool {
        // If either is Top, they might overlap
        if a.is_top() || b.is_top() {
            return true;
        }
        // If either is Bottom, they don't overlap (empty set)
        if a.is_bottom() || b.is_bottom() {
            return false;
        }

        // Check if a.max >= b.min && a.min <= b.max
        match (a.max(), a.min(), b.max(), b.min()) {
            (Some(a_max), Some(a_min), Some(b_max), Some(b_min)) => {
                a_max >= b_min && a_min <= b_max
            }
            // If any bound is unbounded, they might overlap
            _ => true,
        }
    }
}

/// Sparse range propagation analysis.
///
/// Uses a worklist algorithm similar to SCCP but tracks value ranges
/// instead of just constants.
struct RangeAnalysis {
    /// Current range for each SSA variable.
    ranges: HashMap<SsaVarId, ValueRange>,
    /// Executable CFG edges.
    executable_edges: HashSet<(usize, usize)>,
    /// Blocks that have been marked executable.
    executable_blocks: HashSet<usize>,
    /// SSA worklist: variables whose ranges have changed.
    ssa_worklist: VecDeque<SsaVarId>,
    /// CFG worklist: edges that have become executable.
    cfg_worklist: VecDeque<(usize, usize)>,
}

impl RangeAnalysis {
    /// Creates a new range analysis.
    fn new() -> Self {
        Self {
            ranges: HashMap::new(),
            executable_edges: HashSet::new(),
            executable_blocks: HashSet::new(),
            ssa_worklist: VecDeque::new(),
            cfg_worklist: VecDeque::new(),
        }
    }

    /// Runs the range propagation algorithm.
    fn analyze(&mut self, ssa: &SsaFunction) -> RangeResult {
        let cfg = SsaCfg::from_ssa(ssa);
        self.initialize(ssa, &cfg);
        self.propagate(ssa, &cfg);

        RangeResult {
            ranges: self.ranges.clone(),
        }
    }

    /// Initializes the analysis state.
    fn initialize<G>(&mut self, ssa: &SsaFunction, cfg: &G)
    where
        G: RootedGraph + Successors,
    {
        self.ranges.clear();
        self.executable_edges.clear();
        self.executable_blocks.clear();
        self.ssa_worklist.clear();
        self.cfg_worklist.clear();

        // All variables start as Top (unknown range)
        for var in ssa.variables() {
            self.ranges.insert(var.id(), ValueRange::top());
        }

        // Mark entry block as executable
        let entry = cfg.entry().index();
        self.executable_blocks.insert(entry);

        // Add entry block's outgoing edges
        for succ in cfg.successors(cfg.entry()) {
            self.cfg_worklist.push_back((entry, succ.index()));
        }

        // Process entry block definitions
        if let Some(block) = ssa.block(entry) {
            self.process_block_definitions(block);
        }
    }

    /// Main propagation loop.
    fn propagate<G>(&mut self, ssa: &SsaFunction, cfg: &G)
    where
        G: RootedGraph + Successors,
    {
        // Iteration limit to prevent infinite loops with widening ranges.
        // In practice, analysis should converge quickly for most methods.
        // If we hit this limit, we still have valid (possibly imprecise) results.
        const MAX_ITERATIONS: usize = 10000;
        let mut iterations = 0;

        loop {
            iterations += 1;
            if iterations > MAX_ITERATIONS {
                // Hit iteration limit - return with current results.
                // This can happen with unbounded widening in loops.
                break;
            }

            // Process CFG worklist first
            while let Some((from, to)) = self.cfg_worklist.pop_front() {
                if self.executable_edges.insert((from, to)) {
                    self.process_edge(from, to, ssa, cfg);
                }
            }

            // Process SSA worklist
            if let Some(var) = self.ssa_worklist.pop_front() {
                self.process_variable_uses(var, ssa, cfg);
            } else {
                break;
            }
        }
    }

    /// Processes a newly executable CFG edge.
    fn process_edge<G>(&mut self, from: usize, to: usize, ssa: &SsaFunction, cfg: &G)
    where
        G: RootedGraph + Successors,
    {
        let first_visit = !self.executable_blocks.contains(&to);

        if first_visit {
            self.executable_blocks.insert(to);

            if let Some(block) = ssa.block(to) {
                self.process_block_definitions(block);
            }
        }

        // Re-evaluate phi nodes in target block
        if let Some(block) = ssa.block(to) {
            for phi in block.phi_nodes() {
                if phi.operand_from(from).is_some() {
                    let new_range = self.evaluate_phi(phi, to);
                    self.update_range(phi.result(), &new_range);
                }
            }
        }

        // If first visit, propagate outgoing edges
        if first_visit {
            if let Some(block) = ssa.block(to) {
                self.propagate_outgoing_edges(to, block, cfg);
            }
        }
    }

    /// Processes all definitions in a block.
    fn process_block_definitions(&mut self, block: &SsaBlock) {
        for instr in block.instructions() {
            if let Some(def) = instr.def() {
                let range = self.evaluate_instruction(instr.op());
                self.update_range(def, &range);
            }
        }
    }

    /// Processes uses of a variable whose range changed.
    fn process_variable_uses<G>(&mut self, var: SsaVarId, ssa: &SsaFunction, cfg: &G)
    where
        G: RootedGraph + Successors,
    {
        if let Some(ssa_var) = ssa.variable(var) {
            for use_site in ssa_var.uses() {
                let block_id = use_site.block;

                if !self.executable_blocks.contains(&block_id) {
                    continue;
                }

                if use_site.is_phi_operand {
                    if let Some(block) = ssa.block(block_id) {
                        if let Some(phi) = block.phi(use_site.instruction) {
                            let new_range = self.evaluate_phi(phi, block_id);
                            self.update_range(phi.result(), &new_range);
                        }
                    }
                } else if let Some(block) = ssa.block(block_id) {
                    if let Some(instr) = block.instruction(use_site.instruction) {
                        if let Some(def) = instr.def() {
                            let range = self.evaluate_instruction(instr.op());
                            self.update_range(def, &range);
                        }

                        if instr.is_terminator() {
                            self.propagate_outgoing_edges(block_id, block, cfg);
                        }
                    }
                }
            }
        }
    }

    /// Propagates outgoing edges based on terminator.
    fn propagate_outgoing_edges<G>(&mut self, block_id: usize, block: &SsaBlock, cfg: &G)
    where
        G: RootedGraph + Successors,
    {
        match block.terminator_op() {
            Some(SsaOp::Branch {
                condition,
                true_target,
                false_target,
            }) => {
                let range = self.get_range(*condition);

                // Check if we can determine the branch direction
                if let Some(val) = range.as_constant() {
                    if val != 0 {
                        self.add_cfg_edge(block_id, *true_target);
                    } else {
                        self.add_cfg_edge(block_id, *false_target);
                    }
                } else if range.always_equal_to(0) == Some(true) {
                    // Always zero -> always false
                    self.add_cfg_edge(block_id, *false_target);
                } else if range.is_always_positive() {
                    // Always positive -> always true (non-zero)
                    self.add_cfg_edge(block_id, *true_target);
                } else if range.is_top() {
                    // Unknown - don't add edges yet
                } else {
                    // Could go either way
                    self.add_cfg_edge(block_id, *true_target);
                    self.add_cfg_edge(block_id, *false_target);
                }
            }

            Some(SsaOp::Switch {
                value,
                targets,
                default,
            }) => {
                let range = self.get_range(*value);

                if let Some(idx) = range.as_constant().and_then(|i| usize::try_from(i).ok()) {
                    // Known switch value
                    if idx < targets.len() {
                        self.add_cfg_edge(block_id, targets[idx]);
                    } else {
                        self.add_cfg_edge(block_id, *default);
                    }
                } else {
                    // Unknown - add all edges
                    for &target in targets {
                        self.add_cfg_edge(block_id, target);
                    }
                    self.add_cfg_edge(block_id, *default);
                }
            }

            Some(SsaOp::Jump { target }) => {
                self.add_cfg_edge(block_id, *target);
            }

            Some(SsaOp::Return { .. } | SsaOp::Throw { .. } | SsaOp::Rethrow) => {
                // No successors
            }

            _ => {
                // Fall through - add all CFG successors
                let node = NodeId::new(block_id);
                for succ in cfg.successors(node) {
                    self.add_cfg_edge(block_id, succ.index());
                }
            }
        }
    }

    /// Adds a CFG edge to the worklist.
    fn add_cfg_edge(&mut self, from: usize, to: usize) {
        if !self.executable_edges.contains(&(from, to)) {
            self.cfg_worklist.push_back((from, to));
        }
    }

    /// Evaluates a phi node to get its current range.
    fn evaluate_phi(&self, phi: &PhiNode, block_id: usize) -> ValueRange {
        let mut result = ValueRange::bottom();
        let mut has_executable_operand = false;

        for operand in phi.operands() {
            let pred = operand.predecessor();

            if !self.executable_edges.contains(&(pred, block_id)) {
                continue;
            }

            has_executable_operand = true;
            let op_range = self.get_range(operand.value());

            // Join ranges at merge point
            result = result.join(&op_range);

            // Early exit if we've lost all precision
            if result.is_top() {
                break;
            }
        }

        if !has_executable_operand {
            return ValueRange::top();
        }

        result
    }

    /// Evaluates an instruction to get the range of its result.
    fn evaluate_instruction(&self, op: &SsaOp) -> ValueRange {
        match op {
            SsaOp::Const { value, .. } => {
                if let Some(v) = value.as_i64() {
                    ValueRange::constant(v)
                } else {
                    ValueRange::top()
                }
            }

            SsaOp::Copy { src, .. } => self.get_range(*src),

            SsaOp::Add { left, right, .. } => {
                let l = self.get_range(*left);
                let r = self.get_range(*right);
                l.add(&r)
            }

            SsaOp::Sub { left, right, .. } => {
                let l = self.get_range(*left);
                let r = self.get_range(*right);
                l.sub(&r)
            }

            SsaOp::Mul { left, right, .. } => {
                let l = self.get_range(*left);
                let r = self.get_range(*right);
                l.mul(&r)
            }

            SsaOp::And { left, right, .. } => {
                // AND with a constant produces a bounded range
                let r = self.get_range(*right);
                if let Some(mask) = r.as_constant() {
                    ValueRange::bounded(0, mask.max(0))
                } else {
                    let l = self.get_range(*left);
                    if let Some(mask) = l.as_constant() {
                        ValueRange::bounded(0, mask.max(0))
                    } else {
                        ValueRange::top()
                    }
                }
            }

            SsaOp::Shr {
                value,
                amount,
                unsigned,
                ..
            } => {
                let val_range = self.get_range(*value);
                let amt_range = self.get_range(*amount);

                // If shifting by a known amount
                if let Some(amt) = amt_range.as_constant() {
                    if (0..64).contains(&amt) && *unsigned && val_range.is_always_non_negative() {
                        // Unsigned right shift of non-negative preserves non-negative
                        // and reduces the range
                        if let (Some(min), Some(max)) = (val_range.min(), val_range.max()) {
                            let new_min = min >> amt;
                            let new_max = max >> amt;
                            return ValueRange::bounded(new_min, new_max);
                        }
                    }
                }
                ValueRange::top()
            }

            SsaOp::Rem { left, right, .. } => {
                // x % n produces values in [-(n-1), n-1] for signed
                // or [0, n-1] for unsigned
                let r = self.get_range(*right);
                if let Some(n) = r.as_constant() {
                    if n > 0 {
                        // Positive divisor: result in [0, n-1] if dividend is non-negative
                        let l = self.get_range(*left);
                        if l.is_always_non_negative() {
                            return ValueRange::bounded(0, n - 1);
                        }
                    }
                }
                ValueRange::top()
            }

            SsaOp::ArrayLength { .. } => {
                // Array length is always >= 0
                ValueRange::non_negative()
            }

            SsaOp::NewArr { .. }
            | SsaOp::NewObj { .. }
            | SsaOp::Box { .. }
            | SsaOp::LoadToken { .. } => {
                // References - don't track as numeric ranges
                ValueRange::top()
            }

            // Comparisons produce 0 or 1
            SsaOp::Ceq { .. } | SsaOp::Clt { .. } | SsaOp::Cgt { .. } => ValueRange::bounded(0, 1),

            // All other operations - unknown range
            _ => ValueRange::top(),
        }
    }

    /// Gets the current range of a variable.
    fn get_range(&self, var: SsaVarId) -> ValueRange {
        self.ranges.get(&var).cloned().unwrap_or_default()
    }

    /// Updates a variable's range using meet (intersection).
    fn update_range(&mut self, var: SsaVarId, new_range: &ValueRange) {
        let old_range = self.ranges.get(&var).cloned().unwrap_or_default();

        // For range analysis, we use meet (intersection) to narrow ranges
        // But we need to be careful: at merge points we use join, not meet
        // The evaluate functions already handle this correctly

        // Only update if the range changed
        if *new_range != old_range {
            self.ranges.insert(var, new_range.clone());
            self.ssa_worklist.push_back(var);
        }
    }
}

/// Results of range analysis.
#[derive(Debug)]
struct RangeResult {
    /// Range for each SSA variable.
    ranges: HashMap<SsaVarId, ValueRange>,
}

impl RangeResult {
    /// Gets the range of an SSA variable.
    fn get_range(&self, var: SsaVarId) -> Option<&ValueRange> {
        self.ranges.get(&var)
    }
}

#[cfg(test)]
mod tests {
    use crate::analysis::SsaFunctionBuilder;

    use super::*;

    #[test]
    fn test_pass_metadata() {
        let pass = ValueRangePropagationPass::new();
        assert_eq!(pass.name(), "value-range-propagation");
        assert!(!pass.description().is_empty());
    }

    #[test]
    fn test_constant_range() {
        let (ssa, v0) = {
            let mut v0_out = SsaVarId::new();
            let ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
                f.block(0, |b| {
                    v0_out = b.const_i32(42);
                    b.ret();
                });
            });
            (ssa, v0_out)
        };

        let mut analysis = RangeAnalysis::new();
        let result = analysis.analyze(&ssa);

        let range = result.get_range(v0).unwrap();
        assert!(range.is_constant());
        assert_eq!(range.as_constant(), Some(42));
    }

    #[test]
    fn test_add_range() {
        let (ssa, v2) = {
            let mut v2_out = SsaVarId::new();
            let ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
                f.block(0, |b| {
                    let v0 = b.const_i32(5);
                    let v1 = b.const_i32(10);
                    v2_out = b.add(v0, v1); // 5 + 10 = 15
                    b.ret();
                });
            });
            (ssa, v2_out)
        };

        let mut analysis = RangeAnalysis::new();
        let result = analysis.analyze(&ssa);

        let range = result.get_range(v2).unwrap();
        assert_eq!(range.as_constant(), Some(15));
    }

    #[test]
    fn test_sub_range() {
        let (ssa, v2) = {
            let mut v2_out = SsaVarId::new();
            let ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
                f.block(0, |b| {
                    let v0 = b.const_i32(20);
                    let v1 = b.const_i32(7);
                    v2_out = b.sub(v0, v1); // 20 - 7 = 13
                    b.ret();
                });
            });
            (ssa, v2_out)
        };

        let mut analysis = RangeAnalysis::new();
        let result = analysis.analyze(&ssa);

        let range = result.get_range(v2).unwrap();
        assert_eq!(range.as_constant(), Some(13));
    }

    #[test]
    fn test_and_range() {
        let (ssa, v2) = {
            let mut v2_out = SsaVarId::new();
            let ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
                f.block(0, |b| {
                    let v0 = b.const_i32(1000);
                    let v1 = b.const_i32(0xFF); // Mask to byte range
                    v2_out = b.and(v0, v1);
                    b.ret();
                });
            });
            (ssa, v2_out)
        };

        let mut analysis = RangeAnalysis::new();
        let result = analysis.analyze(&ssa);

        let range = result.get_range(v2).unwrap();
        // AND with 0xFF produces range [0, 255]
        assert_eq!(range.min(), Some(0));
        assert_eq!(range.max(), Some(255));
    }

    #[test]
    fn test_array_length_range() {
        let (ssa, v1) = {
            let mut v1_out = SsaVarId::new();
            let ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
                f.block(0, |b| {
                    let v0 = b.const_null(); // Placeholder array
                    v1_out = b.array_length(v0);
                    b.ret();
                });
            });
            (ssa, v1_out)
        };

        let mut analysis = RangeAnalysis::new();
        let result = analysis.analyze(&ssa);

        let range = result.get_range(v1).unwrap();
        assert!(range.is_always_non_negative());
    }

    #[test]
    fn test_comparison_range() {
        let (ssa, v2) = {
            let mut v2_out = SsaVarId::new();
            let ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
                f.block(0, |b| {
                    let v0 = b.const_i32(5);
                    let v1 = b.const_i32(10);
                    v2_out = b.clt(v0, v1); // 5 < 10
                    b.ret();
                });
            });
            (ssa, v2_out)
        };

        let mut analysis = RangeAnalysis::new();
        let result = analysis.analyze(&ssa);

        let range = result.get_range(v2).unwrap();
        // Comparison produces 0 or 1
        assert_eq!(range.min(), Some(0));
        assert_eq!(range.max(), Some(1));
    }

    #[test]
    fn test_ranges_overlap() {
        // Non-overlapping ranges
        let a = ValueRange::bounded(0, 5);
        let b = ValueRange::bounded(10, 15);
        assert!(!ValueRangePropagationPass::ranges_overlap(&a, &b));

        // Overlapping ranges
        let c = ValueRange::bounded(0, 10);
        let d = ValueRange::bounded(5, 15);
        assert!(ValueRangePropagationPass::ranges_overlap(&c, &d));

        // Same range
        let e = ValueRange::bounded(5, 10);
        assert!(ValueRangePropagationPass::ranges_overlap(&e, &e));

        // Top overlaps with everything
        let top = ValueRange::top();
        assert!(ValueRangePropagationPass::ranges_overlap(&top, &a));

        // Bottom doesn't overlap
        let bottom = ValueRange::bottom();
        assert!(!ValueRangePropagationPass::ranges_overlap(&bottom, &a));
    }

    #[test]
    fn test_try_simplify_clt() {
        let v0 = SsaVarId::new();
        let v1 = SsaVarId::new();
        let dest = SsaVarId::new();

        let mut ranges = HashMap::new();
        ranges.insert(v0, ValueRange::bounded(0, 5)); // [0, 5]
        ranges.insert(v1, ValueRange::bounded(10, 20)); // [10, 20]

        let result = RangeResult { ranges };

        // v0 < v1 should always be true (5 < 10)
        let op = SsaOp::Clt {
            dest,
            left: v0,
            right: v1,
            unsigned: false,
        };
        let simplified = ValueRangePropagationPass::try_simplify_comparison(&op, &result);
        assert_eq!(simplified, Some((dest, true)));
    }

    #[test]
    fn test_try_simplify_cgt() {
        let v0 = SsaVarId::new();
        let v1 = SsaVarId::new();
        let dest = SsaVarId::new();

        let mut ranges = HashMap::new();
        ranges.insert(v0, ValueRange::bounded(100, 200)); // [100, 200]
        ranges.insert(v1, ValueRange::bounded(0, 50)); // [0, 50]

        let result = RangeResult { ranges };

        // v0 > v1 should always be true (100 > 50)
        let op = SsaOp::Cgt {
            dest,
            left: v0,
            right: v1,
            unsigned: false,
        };
        let simplified = ValueRangePropagationPass::try_simplify_comparison(&op, &result);
        assert_eq!(simplified, Some((dest, true)));
    }

    #[test]
    fn test_try_simplify_ceq_never() {
        let v0 = SsaVarId::new();
        let v1 = SsaVarId::new();
        let dest = SsaVarId::new();

        let mut ranges = HashMap::new();
        ranges.insert(v0, ValueRange::bounded(0, 5)); // [0, 5]
        ranges.insert(v1, ValueRange::bounded(10, 20)); // [10, 20]

        let result = RangeResult { ranges };

        // v0 == v1 should always be false (ranges don't overlap)
        let op = SsaOp::Ceq {
            dest,
            left: v0,
            right: v1,
        };
        let simplified = ValueRangePropagationPass::try_simplify_comparison(&op, &result);
        assert_eq!(simplified, Some((dest, false)));
    }

    #[test]
    fn test_try_simplify_ceq_constants() {
        let v0 = SsaVarId::new();
        let v1 = SsaVarId::new();
        let dest = SsaVarId::new();

        let mut ranges = HashMap::new();
        ranges.insert(v0, ValueRange::constant(42));
        ranges.insert(v1, ValueRange::constant(42));

        let result = RangeResult { ranges };

        // v0 == v1 should always be true (both are 42)
        let op = SsaOp::Ceq {
            dest,
            left: v0,
            right: v1,
        };
        let simplified = ValueRangePropagationPass::try_simplify_comparison(&op, &result);
        assert_eq!(simplified, Some((dest, true)));
    }
}
