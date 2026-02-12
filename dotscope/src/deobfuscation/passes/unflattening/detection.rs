//! Control flow flattening detection via structural analysis.
//!
//! This module identifies CFF patterns by analyzing graph properties rather
//! than matching specific opcodes. This makes detection robust across different
//! obfuscators.
//!
//! # Detection Strategy
//!
//! CFF creates a distinctive graph structure:
//!
//! 1. **Large SCC**: The dispatcher and all case blocks form a strongly connected
//!    component (everyone can reach everyone via the dispatcher)
//! 2. **Dominator Pattern**: The dispatcher dominates all case blocks
//! 3. **High Predecessor Count**: The dispatcher has many predecessors (back edges)
//! 4. **Dispatcher Instruction**: A switch or branching pattern controls flow
//!
//! The confidence score combines these signals to distinguish CFF from normal
//! loops or state machines.

use std::collections::HashSet;

use crate::{
    analysis::{SsaFunction, SsaOp, SsaVarId},
    deobfuscation::passes::unflattening::{
        dispatcher::{analyze_switch_dispatcher, Dispatcher, DispatcherInfo},
        statevar::{identify_state_variable, StateVariable},
        UnflattenConfig,
    },
    utils::graph::{
        algorithms::{compute_dominators, DominatorTree},
        GraphBase, NodeId, Successors,
    },
};

/// Entry point into a CFF region.
///
/// CFF can have multiple entry points when there are different paths into
/// the flattened region, each potentially starting with a different initial state.
#[derive(Debug, Clone)]
pub struct EntryPoint {
    /// Index of the entry block (before/at dispatcher).
    pub block: usize,

    /// Initial state value at this entry point (if known).
    pub initial_state: Option<i64>,

    /// Condition to reach this entry (for multiple entries).
    ///
    /// When a function has multiple paths into the CFF, each may have
    /// a different condition. `None` means unconditional entry.
    pub condition: Option<EntryCondition>,

    /// SSA variable that holds the initial state (if identifiable).
    pub state_var: Option<SsaVarId>,
}

/// Condition for reaching an entry point.
#[derive(Debug, Clone)]
pub enum EntryCondition {
    /// Entry is taken when a comparison is true.
    Compare {
        /// The variable being compared.
        var: SsaVarId,
        /// The comparison value.
        value: i64,
        /// True if this is the "equals" case, false for "not equals".
        is_equal: bool,
    },

    /// Entry is a switch case value.
    SwitchCase(i64),

    /// Entry depends on a boolean variable.
    Boolean {
        /// The boolean variable.
        var: SsaVarId,
        /// True if entry when true, false if entry when false.
        when_true: bool,
    },

    /// Entry depends on an argument value.
    Argument {
        /// Argument index.
        index: u16,
        /// Expected value (if known).
        expected: Option<i64>,
    },
}

impl EntryPoint {
    /// Creates a simple entry point with just a block index.
    #[must_use]
    pub fn new(block: usize) -> Self {
        Self {
            block,
            initial_state: None,
            condition: None,
            state_var: None,
        }
    }

    /// Creates an entry point with a known initial state.
    #[must_use]
    pub fn with_state(block: usize, initial_state: i64) -> Self {
        Self {
            block,
            initial_state: Some(initial_state),
            condition: None,
            state_var: None,
        }
    }

    /// Sets the condition for this entry point.
    pub fn with_condition(mut self, condition: EntryCondition) -> Self {
        self.condition = Some(condition);
        self
    }

    /// Sets the state variable for this entry point.
    pub fn with_state_var(mut self, var: SsaVarId) -> Self {
        self.state_var = Some(var);
        self
    }

    /// Returns true if this is an unconditional entry.
    #[must_use]
    pub fn is_unconditional(&self) -> bool {
        self.condition.is_none()
    }

    /// Returns true if the initial state is known.
    #[must_use]
    pub fn has_known_state(&self) -> bool {
        self.initial_state.is_some()
    }
}

/// Adapter to use SsaFunction with graph algorithms.
///
/// This implements the `Successors` trait so we can compute dominators
/// and other graph properties on the SSA CFG.
struct SsaGraphAdapter<'a> {
    ssa: &'a SsaFunction,
}

impl<'a> SsaGraphAdapter<'a> {
    fn new(ssa: &'a SsaFunction) -> Self {
        Self { ssa }
    }
}

impl GraphBase for SsaGraphAdapter<'_> {
    fn node_count(&self) -> usize {
        self.ssa.block_count()
    }

    fn node_ids(&self) -> impl Iterator<Item = NodeId> {
        (0..self.ssa.block_count()).map(NodeId::new)
    }
}

impl Successors for SsaGraphAdapter<'_> {
    fn successors(&self, node: NodeId) -> impl Iterator<Item = NodeId> {
        self.ssa
            .block_successors(node.index())
            .into_iter()
            .map(NodeId::new)
    }
}

/// Detected CFF pattern with analysis metadata.
#[derive(Debug, Clone)]
pub struct CffPattern {
    /// Index of the dispatcher block.
    pub dispatcher_block: usize,

    /// Dispatcher information (switch/if-else chain).
    pub dispatcher: DispatcherInfo,

    /// Identified state variable.
    pub state_var: Option<StateVariable>,

    /// Blocks that are part of the CFF structure (case blocks).
    pub case_blocks: HashSet<usize>,

    /// Entry block (before dispatcher, if separate).
    ///
    /// This is the legacy single-entry field. For new code, prefer
    /// using `entry_points` which supports multiple entries.
    pub entry_block: Option<usize>,

    /// Entry points into the CFF region.
    ///
    /// Most CFF has a single entry point, but some obfuscators create
    /// multiple entries with different initial states based on conditions.
    pub entry_points: Vec<EntryPoint>,

    /// Exit blocks (leave the CFF structure).
    pub exit_blocks: HashSet<usize>,

    /// Confidence score (0.0 - 1.0).
    pub confidence: f64,
}

impl CffPattern {
    /// Returns the number of case blocks.
    #[must_use]
    pub fn case_count(&self) -> usize {
        self.dispatcher.case_count()
    }

    /// Returns true if this pattern looks like ConfuserEx.
    #[must_use]
    pub fn is_confuserex_style(&self) -> bool {
        // ConfuserEx uses switch with modulo transform
        matches!(&self.dispatcher, DispatcherInfo::Switch { transform, .. }
            if transform.modulo_divisor().is_some())
    }

    /// Returns true if this pattern has multiple entry points.
    #[must_use]
    pub fn has_multiple_entries(&self) -> bool {
        self.entry_points.len() > 1
    }

    /// Returns the number of entry points.
    #[must_use]
    pub fn entry_count(&self) -> usize {
        self.entry_points.len()
    }

    /// Returns the primary entry point (first or only entry).
    #[must_use]
    pub fn primary_entry(&self) -> Option<&EntryPoint> {
        self.entry_points.first()
    }

    /// Returns entry points with known initial states.
    #[must_use]
    pub fn entries_with_states(&self) -> Vec<&EntryPoint> {
        self.entry_points
            .iter()
            .filter(|e| e.has_known_state())
            .collect()
    }

    /// Returns all initial states from entry points.
    #[must_use]
    pub fn initial_states(&self) -> Vec<i64> {
        self.entry_points
            .iter()
            .filter_map(|e| e.initial_state)
            .collect()
    }
}

/// CFF detection engine.
pub struct CffDetector<'a> {
    ssa: &'a SsaFunction,
    config: UnflattenConfig,
    /// Cached dominator tree (computed lazily)
    dom_tree: Option<DominatorTree>,
}

impl<'a> CffDetector<'a> {
    /// Creates a new CFF detector with default configuration.
    #[must_use]
    pub fn new(ssa: &'a SsaFunction) -> Self {
        Self {
            ssa,
            config: UnflattenConfig::default(),
            dom_tree: None,
        }
    }

    /// Creates a new CFF detector with the given configuration.
    #[must_use]
    pub fn with_config(ssa: &'a SsaFunction, config: &UnflattenConfig) -> Self {
        Self {
            ssa,
            config: config.clone(),
            dom_tree: None,
        }
    }

    /// Gets or computes the dominator tree.
    fn get_dom_tree(&mut self) -> &DominatorTree {
        let ssa = self.ssa;
        self.dom_tree.get_or_insert_with(|| {
            let adapter = SsaGraphAdapter::new(ssa);
            compute_dominators(&adapter, NodeId::new(0))
        })
    }

    /// Detects the best CFF dispatcher in the function.
    ///
    /// Returns `Some(Dispatcher)` if a dispatcher is found, `None` otherwise.
    /// This is a simpler API that returns just the dispatcher information
    /// without the full CFF pattern metadata.
    pub fn detect_best(&mut self) -> Option<Dispatcher> {
        let pattern = self.detect()?;

        // Convert CffPattern to Dispatcher
        match &pattern.dispatcher {
            DispatcherInfo::Switch {
                block,
                switch_var,
                cases,
                default,
                transform,
            } => {
                let mut dispatcher = Dispatcher::new(*block, *switch_var, cases.clone(), *default);

                // Set state phi if identified
                if let Some(ref state_var) = pattern.state_var {
                    if let Some(phi_var) = state_var.dispatcher_var {
                        dispatcher = dispatcher.with_state_phi(phi_var);
                    }
                }

                dispatcher = dispatcher
                    .with_transform(transform.clone())
                    .with_confidence(pattern.confidence);

                Some(dispatcher)
            }
            DispatcherInfo::IfElseChain {
                head_block,
                state_var,
                comparisons,
                default,
            } => {
                // Convert if-else chain to dispatcher format
                let cases: Vec<usize> = comparisons.iter().map(|(_, target)| *target).collect();
                let default_block = default.unwrap_or(*head_block);

                let mut dispatcher = Dispatcher::new(*head_block, *state_var, cases, default_block);

                if let Some(ref state_var_info) = pattern.state_var {
                    if let Some(phi_var) = state_var_info.dispatcher_var {
                        dispatcher = dispatcher.with_state_phi(phi_var);
                    }
                }

                dispatcher = dispatcher.with_confidence(pattern.confidence);

                Some(dispatcher)
            }
            DispatcherInfo::ComputedJump {
                block,
                target_var,
                jump_table,
                ..
            } => {
                // Convert computed jump to dispatcher format
                // Use first target as default since computed jumps don't have a clear default
                let default_block = jump_table.first().copied().unwrap_or(0);

                let mut dispatcher =
                    Dispatcher::new(*block, *target_var, jump_table.clone(), default_block);

                if let Some(ref state_var_info) = pattern.state_var {
                    if let Some(phi_var) = state_var_info.dispatcher_var {
                        dispatcher = dispatcher.with_state_phi(phi_var);
                    }
                }

                dispatcher = dispatcher.with_confidence(pattern.confidence);

                Some(dispatcher)
            }
        }
    }

    /// Attempts to detect CFF in the function.
    ///
    /// Returns `Some(CffPattern)` if CFF is detected, `None` otherwise.
    pub fn detect(&mut self) -> Option<CffPattern> {
        // Early exit: too few blocks for CFF
        if self.ssa.block_count() < 4 {
            return None;
        }

        // Find candidate dispatcher blocks
        let candidates = self.find_dispatcher_candidates();

        if candidates.is_empty() {
            return None;
        }

        // Score each candidate and pick the best
        let mut best_pattern: Option<CffPattern> = None;
        let mut best_score = 0.0;

        for block_idx in candidates {
            if let Some(pattern) = self.analyze_dispatcher_candidate(block_idx) {
                if pattern.confidence > best_score {
                    best_score = pattern.confidence;
                    best_pattern = Some(pattern);
                }
            }
        }

        best_pattern
    }

    /// Finds blocks that could be dispatchers.
    ///
    /// Dispatchers typically have:
    /// - Multiple predecessors (back edges from case blocks)
    /// - A switch instruction or branching pattern
    fn find_dispatcher_candidates(&self) -> Vec<usize> {
        let mut candidates = Vec::new();

        for block_idx in 0..self.ssa.block_count() {
            if self.is_dispatcher_candidate(block_idx) {
                candidates.push(block_idx);
            }
        }

        candidates
    }

    /// Checks if a block could be a dispatcher.
    fn is_dispatcher_candidate(&self, block_idx: usize) -> bool {
        let Some(block) = self.ssa.block(block_idx) else {
            return false;
        };

        // Must have terminator instructions
        if block.instructions().is_empty() {
            return false;
        }

        // Look for switch or multi-target branch
        let has_switch = block
            .instructions()
            .iter()
            .any(|instr| matches!(instr.op(), SsaOp::Switch { .. }));

        if has_switch {
            // Check predecessor count (should have many back edges).
            // block_predecessors excludes self-loops, but a switch targeting itself
            // is a valid CFF back-edge (e.g., x86-resolved CFF where case blocks
            // were folded into the dispatcher). Count it separately.
            let pred_count = self.ssa.block_predecessors(block_idx).len();
            let has_self_loop = block
                .instructions()
                .iter()
                .any(|i| i.op().successors().contains(&block_idx));
            let effective_preds = pred_count + usize::from(has_self_loop);
            return effective_preds >= 2;
        }

        // Also consider blocks with conditional branches that could be if-else chains
        let has_branch = block
            .instructions()
            .iter()
            .any(|instr| matches!(instr.op(), SsaOp::Branch { .. }));

        if has_branch {
            let pred_count = self.ssa.block_predecessors(block_idx).len();
            // If-else dispatchers typically have even more predecessors
            return pred_count >= 3;
        }

        false
    }

    /// Analyzes a dispatcher candidate and builds a CFF pattern.
    fn analyze_dispatcher_candidate(&mut self, block_idx: usize) -> Option<CffPattern> {
        // Try to identify dispatcher type
        let dispatcher = analyze_switch_dispatcher(self.ssa, block_idx)?;

        // Identify state variable
        let state_var = identify_state_variable(self.ssa, block_idx, dispatcher.dispatch_var());

        // Find case blocks (targets of the dispatcher)
        let case_blocks: HashSet<usize> = dispatcher.all_targets().into_iter().collect();

        // Find exit blocks (blocks that leave the CFF structure)
        let exit_blocks = self.find_exit_blocks(block_idx, &case_blocks);

        // Find entry block (if separate from dispatcher) - legacy
        let entry_block = self.find_entry_block(block_idx);

        // Find all entry points (including multiple entries if present)
        let entry_points = self.find_entry_points(block_idx, &case_blocks, state_var.as_ref());

        // Compute confidence score (includes dominance analysis)
        let confidence = self.compute_confidence(
            block_idx,
            &dispatcher,
            state_var.as_ref(),
            &case_blocks,
            &exit_blocks,
        );

        Some(CffPattern {
            dispatcher_block: block_idx,
            dispatcher,
            state_var,
            case_blocks,
            entry_block,
            entry_points,
            exit_blocks,
            confidence,
        })
    }

    /// Finds blocks that exit the CFF structure.
    fn find_exit_blocks(
        &self,
        dispatcher_block: usize,
        case_blocks: &HashSet<usize>,
    ) -> HashSet<usize> {
        let mut exits = HashSet::new();

        // Check successors of case blocks that don't go back to dispatcher
        for &case_block in case_blocks {
            for succ in self.ssa.block_successors(case_block) {
                if succ != dispatcher_block && !case_blocks.contains(&succ) {
                    exits.insert(succ);
                }
            }
        }

        exits
    }

    /// Finds the entry block (predecessor of dispatcher that isn't a case block).
    fn find_entry_block(&self, dispatcher_block: usize) -> Option<usize> {
        let preds = self.ssa.block_predecessors(dispatcher_block);

        // Entry block is typically block 0 or the first predecessor
        // that doesn't look like it came from a case block
        for pred in preds {
            if pred == 0 {
                return Some(pred);
            }
        }

        // If dispatcher is block 0, there's no separate entry
        if dispatcher_block == 0 {
            return None;
        }

        None
    }

    /// Finds all entry points into the CFF region.
    ///
    /// This method identifies blocks that can enter the CFF, along with
    /// any conditions on those entries. Most CFF has a single entry point,
    /// but some obfuscators create multiple entries.
    fn find_entry_points(
        &self,
        dispatcher_block: usize,
        case_blocks: &HashSet<usize>,
        state_var: Option<&StateVariable>,
    ) -> Vec<EntryPoint> {
        let mut entries = Vec::new();
        let preds = self.ssa.block_predecessors(dispatcher_block);

        // Collect non-case-block predecessors as potential entry points
        let entry_blocks: Vec<usize> = preds
            .iter()
            .filter(|&&pred| !case_blocks.contains(&pred))
            .copied()
            .collect();

        if entry_blocks.is_empty() {
            // No separate entry blocks - dispatcher is the entry
            let entry = EntryPoint::new(dispatcher_block);
            entries.push(entry);
            return entries;
        }

        // Analyze each potential entry block
        for &entry_block in &entry_blocks {
            let mut entry = EntryPoint::new(entry_block);

            // Try to extract initial state from the entry block
            if let Some(initial) = self.extract_initial_state(entry_block, state_var) {
                entry.initial_state = Some(initial);
            }

            // If there are multiple entry blocks, check for conditions
            if entry_blocks.len() > 1 {
                if let Some(condition) = self.extract_entry_condition(entry_block, &entry_blocks) {
                    entry.condition = Some(condition);
                }
            }

            // Track state variable if known
            if let Some(sv) = state_var {
                if let Some(ssa_var) = sv.var.as_ssa_var() {
                    entry.state_var = Some(ssa_var);
                }
            }

            entries.push(entry);
        }

        entries
    }

    /// Extracts the initial state value from an entry block.
    fn extract_initial_state(
        &self,
        block_idx: usize,
        state_var: Option<&StateVariable>,
    ) -> Option<i64> {
        let block = self.ssa.block(block_idx)?;

        // Look for a constant assignment to the state variable
        for instr in block.instructions() {
            if let SsaOp::Const { dest, value } = instr.op() {
                // Check if this constant is assigned to the state variable
                if let Some(sv) = state_var {
                    if let Some(ssa_var) = sv.var.as_ssa_var() {
                        if *dest == ssa_var {
                            return value.as_i64();
                        }
                    }
                }
            }

            // Also check for copy of a constant
            if let SsaOp::Copy { dest, src } = instr.op() {
                if let Some(sv) = state_var {
                    if let Some(ssa_var) = sv.var.as_ssa_var() {
                        if *dest == ssa_var {
                            // Try to get the constant value of src
                            if let Some(SsaOp::Const { value, .. }) = self.ssa.get_definition(*src)
                            {
                                return value.as_i64();
                            }
                        }
                    }
                }
            }
        }

        None
    }

    /// Extracts the condition for reaching an entry block.
    fn extract_entry_condition(
        &self,
        entry_block: usize,
        _all_entries: &[usize],
    ) -> Option<EntryCondition> {
        // Look for blocks that branch to this entry
        let preds = self.ssa.block_predecessors(entry_block);

        for pred in preds {
            let Some(pred_block) = self.ssa.block(pred) else {
                continue;
            };

            // Check for conditional branch to this entry
            for instr in pred_block.instructions() {
                if let SsaOp::Branch {
                    condition,
                    true_target,
                    false_target,
                } = instr.op()
                {
                    // This block branches - check if it's branching to our entry
                    let is_true_branch = *true_target == entry_block;
                    let is_false_branch = *false_target == entry_block;

                    if is_true_branch || is_false_branch {
                        // Found a conditional entry
                        // Try to get more info about the condition - check for equality comparison
                        if let Some(SsaOp::Ceq { left, right, .. }) =
                            self.ssa.get_definition(*condition)
                        {
                            // Check if comparing with a constant
                            if let Some(SsaOp::Const { value, .. }) =
                                self.ssa.get_definition(*right)
                            {
                                if let Some(val) = value.as_i64() {
                                    return Some(EntryCondition::Compare {
                                        var: *left,
                                        value: val,
                                        // Ceq produces 1 when equal, so:
                                        // if branch taken on true, is_equal matches the Ceq
                                        is_equal: is_true_branch,
                                    });
                                }
                            }
                        }

                        // Fallback: just note it's a boolean condition
                        return Some(EntryCondition::Boolean {
                            var: *condition,
                            when_true: is_true_branch,
                        });
                    }
                }
            }
        }

        None
    }

    /// Computes confidence score for a detected CFF pattern.
    ///
    /// The confidence score combines multiple signals:
    /// - Case block count (more = stronger signal)
    /// - State variable presence with phi node
    /// - Back-edge ratio (case blocks returning to dispatcher)
    /// - Dominance relationship (dispatcher dominates case blocks)
    /// - Switch instruction presence
    /// - State transform (modulo operation is a strong indicator)
    fn compute_confidence(
        &mut self,
        dispatcher_block: usize,
        dispatcher: &DispatcherInfo,
        state_var: Option<&StateVariable>,
        case_blocks: &HashSet<usize>,
        exit_blocks: &HashSet<usize>,
    ) -> f64 {
        let mut score = 0.0;
        let case_count = case_blocks.len();

        // Signal 1: Number of case blocks (more = more likely CFF)
        if case_count >= 3 {
            score += 0.10;
        }
        if case_count >= 5 {
            score += 0.05;
        }
        if case_count >= 10 {
            score += 0.05;
        }

        // Signal 2: Has state variable with phi node
        if let Some(sv) = state_var {
            if sv.dispatcher_var.is_some() {
                score += 0.15;
            }
            if sv.def_count() >= case_count.saturating_sub(1) {
                // State updated in most case blocks
                score += 0.10;
            }
        }

        // Signal 3: Dispatcher has many predecessors (back edges)
        let pred_count = self.ssa.block_predecessors(dispatcher_block).len();
        if pred_count >= case_count / 2 {
            score += 0.10;
        }

        // Signal 4: Case blocks mostly go back to dispatcher
        let back_edge_count = case_blocks
            .iter()
            .filter(|&&b| self.ssa.block_successors(b).contains(&dispatcher_block))
            .count();
        // Safe: counts are small integers, precision loss is negligible for scoring
        #[allow(clippy::cast_precision_loss)]
        let back_edge_ratio = back_edge_count as f64 / case_count.max(1) as f64;
        score += back_edge_ratio * 0.10;

        // Signal 5: Has exit blocks (function eventually returns)
        if !exit_blocks.is_empty() {
            score += 0.05;
        }

        // Signal 6: Uses switch instruction (typical for CFF)
        if matches!(dispatcher, DispatcherInfo::Switch { .. }) {
            score += 0.10;
        }

        // Signal 7: Has state transform (modulo is very strong indicator)
        let transform = dispatcher.transform();
        if transform.modulo_divisor().is_some() {
            score += 0.10;
        }

        // Signal 8: Dominance - dispatcher should dominate most case blocks
        // This is a strong structural indicator of CFF
        let dominance_score = self.compute_dominance_score(dispatcher_block, case_blocks);
        score += dominance_score * 0.20;

        score.min(1.0)
    }

    /// Computes a dominance score for CFF detection.
    ///
    /// In a CFF pattern, the dispatcher block should dominate all case blocks
    /// because every path to a case block must go through the dispatcher.
    ///
    /// Returns a value between 0.0 and 1.0 based on how many case blocks
    /// are dominated by the dispatcher.
    fn compute_dominance_score(
        &mut self,
        dispatcher_block: usize,
        case_blocks: &HashSet<usize>,
    ) -> f64 {
        if case_blocks.is_empty() {
            return 0.0;
        }

        // Get the dominator tree
        let dom_tree = self.get_dom_tree();
        let dispatcher_node = NodeId::new(dispatcher_block);

        // Count how many case blocks are dominated by the dispatcher
        let dominated_count = case_blocks
            .iter()
            .filter(|&&case_block| {
                // Skip the dispatcher itself if it's in case_blocks
                if case_block == dispatcher_block {
                    return true;
                }
                let case_node = NodeId::new(case_block);
                dom_tree.dominates(dispatcher_node, case_node)
            })
            .count();

        // Safe: counts are small integers, precision loss is negligible for scoring
        #[allow(clippy::cast_precision_loss)]
        let ratio = dominated_count as f64 / case_blocks.len() as f64;
        ratio
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use crate::{
        analysis::SsaVarId,
        deobfuscation::passes::unflattening::dispatcher::{DispatcherInfo, StateTransform},
    };

    use super::{CffPattern, EntryCondition, EntryPoint};

    #[test]
    fn test_cff_pattern_case_count() {
        // Basic pattern structure test
        let pattern = CffPattern {
            dispatcher_block: 0,
            dispatcher: DispatcherInfo::Switch {
                block: 0,
                switch_var: SsaVarId::new(),
                cases: vec![1, 2, 3, 4, 5],
                default: 6,
                transform: StateTransform::Modulo(5),
            },
            state_var: None,
            case_blocks: HashSet::from([1, 2, 3, 4, 5, 6]),
            entry_block: None,
            entry_points: vec![EntryPoint::with_state(0, 42)],
            exit_blocks: HashSet::new(),
            confidence: 0.8,
        };

        assert_eq!(pattern.case_count(), 5);
        assert!(pattern.is_confuserex_style());
        assert_eq!(pattern.entry_count(), 1);
        assert!(!pattern.has_multiple_entries());
    }

    #[test]
    fn test_entry_point() {
        let entry = EntryPoint::new(0);
        assert!(entry.is_unconditional());
        assert!(!entry.has_known_state());

        let entry_with_state = EntryPoint::with_state(1, 100);
        assert!(entry_with_state.has_known_state());
        assert_eq!(entry_with_state.initial_state, Some(100));

        let var = SsaVarId::new();
        let entry_with_condition = EntryPoint::new(2).with_condition(EntryCondition::Boolean {
            var,
            when_true: true,
        });
        assert!(!entry_with_condition.is_unconditional());
    }

    #[test]
    fn test_cff_pattern_multiple_entries() {
        let pattern = CffPattern {
            dispatcher_block: 1,
            dispatcher: DispatcherInfo::Switch {
                block: 1,
                switch_var: SsaVarId::new(),
                cases: vec![2, 3],
                default: 4,
                transform: StateTransform::Identity,
            },
            state_var: None,
            case_blocks: HashSet::from([2, 3, 4]),
            entry_block: None,
            entry_points: vec![EntryPoint::with_state(0, 10), EntryPoint::with_state(5, 20)],
            exit_blocks: HashSet::from([6]),
            confidence: 0.7,
        };

        assert!(pattern.has_multiple_entries());
        assert_eq!(pattern.entry_count(), 2);
        assert_eq!(pattern.initial_states(), vec![10, 20]);

        let primary = pattern.primary_entry().unwrap();
        assert_eq!(primary.block, 0);
        assert_eq!(primary.initial_state, Some(10));
    }
}
