//! Worklist-based data flow solver.
//!
//! This module provides the iterative solver that computes fixpoints for
//! data flow analyses. It uses a worklist algorithm with reverse postorder
//! traversal for efficiency.
//!
//! # Algorithm
//!
//! The solver iterates until a fixpoint is reached:
//!
//! 1. Initialize all blocks with the initial value
//! 2. Set the boundary value at entry (forward) or exits (backward)
//! 3. Add all blocks to the worklist in reverse postorder
//! 4. While the worklist is non-empty:
//!    a. Remove a block from the worklist
//!    b. Compute the input by meeting values from predecessors/successors
//!    c. Apply the transfer function to get the output
//!    d. If the output changed, add affected blocks to the worklist
//! 5. Call the finalize hook for post-processing
//!
//! # Complexity
//!
//! For most analyses on reducible CFGs, the solver converges in O(n) iterations
//! where n is the number of blocks. The total work is O(n * h) where h is the
//! lattice height (number of times a value can decrease before hitting bottom).

use std::collections::VecDeque;

use crate::{
    analysis::{
        dataflow::{
            framework::{AnalysisResults, DataFlowAnalysis, DataFlowCfg, Direction},
            lattice::MeetSemiLattice,
        },
        SsaFunction,
    },
    utils::graph::NodeId,
};

/// Worklist-based data flow solver.
///
/// This solver computes fixpoints for data flow analyses using an iterative
/// worklist algorithm. It supports both forward and backward analyses.
///
/// # Usage
///
/// ```rust,ignore
/// use dotscope::analysis::{DataFlowSolver, ReachingDefinitions};
///
/// let analysis = ReachingDefinitions::new(&ssa);
/// let mut solver = DataFlowSolver::new(analysis);
/// let results = solver.solve(&ssa, &graph);
///
/// // Access results
/// let in_state = results.in_state(block_id);
/// ```
pub struct DataFlowSolver<A: DataFlowAnalysis> {
    /// The analysis being solved.
    analysis: A,
    /// Input state for each block.
    in_states: Vec<A::Lattice>,
    /// Output state for each block.
    out_states: Vec<A::Lattice>,
    /// Worklist of blocks to process.
    worklist: VecDeque<usize>,
    /// Whether each block is currently in the worklist (for deduplication).
    in_worklist: Vec<bool>,
    /// Number of iterations performed.
    iterations: usize,
}

impl<A: DataFlowAnalysis> DataFlowSolver<A> {
    /// Creates a new solver for the given analysis.
    #[must_use]
    pub fn new(analysis: A) -> Self {
        Self {
            analysis,
            in_states: Vec::new(),
            out_states: Vec::new(),
            worklist: VecDeque::new(),
            in_worklist: Vec::new(),
            iterations: 0,
        }
    }

    /// Solves the data flow analysis to a fixpoint.
    ///
    /// Returns the analysis results containing input and output states
    /// for each basic block.
    pub fn solve<C: DataFlowCfg>(
        mut self,
        ssa: &SsaFunction,
        cfg: &C,
    ) -> AnalysisResults<A::Lattice>
    where
        A::Lattice: Clone,
    {
        let num_blocks = ssa.block_count();
        if num_blocks == 0 {
            return AnalysisResults::new(Vec::new(), Vec::new());
        }

        // Initialize states
        self.initialize(ssa, cfg);

        // Main iteration loop
        self.iterate(ssa, cfg);

        // Finalize
        self.analysis
            .finalize(&self.in_states, &self.out_states, ssa);

        AnalysisResults::new(self.in_states, self.out_states)
    }

    /// Returns the number of iterations performed.
    #[must_use]
    pub const fn iterations(&self) -> usize {
        self.iterations
    }

    /// Initializes the solver state.
    fn initialize<C: DataFlowCfg>(&mut self, ssa: &SsaFunction, cfg: &C)
    where
        A::Lattice: Clone,
    {
        let num_blocks = ssa.block_count();
        let initial = self.analysis.initial(ssa);
        let boundary = self.analysis.boundary(ssa);

        // Initialize all blocks with the initial value
        self.in_states = vec![initial.clone(); num_blocks];
        self.out_states = vec![initial; num_blocks];
        self.in_worklist = vec![false; num_blocks];

        // Set boundary conditions based on direction
        match A::DIRECTION {
            Direction::Forward => {
                // Entry block gets boundary value
                let entry = cfg.entry().index();
                if let Some(slot) = self.in_states.get_mut(entry) {
                    *slot = boundary;
                }
            }
            Direction::Backward => {
                // Exit blocks get boundary value
                for exit in cfg.exits() {
                    let idx = exit.index();
                    if let Some(slot) = self.out_states.get_mut(idx) {
                        *slot = boundary.clone();
                    }
                }
            }
        }

        // Add all blocks to worklist in appropriate order
        let order = match A::DIRECTION {
            Direction::Forward => cfg.reverse_postorder(),
            Direction::Backward => cfg.postorder(),
        };

        for node in order {
            let idx = node.index();
            if let Some(slot) = self.in_worklist.get_mut(idx) {
                self.worklist.push_back(idx);
                *slot = true;
            }
        }
    }

    /// Main iteration loop.
    fn iterate<C: DataFlowCfg>(&mut self, ssa: &SsaFunction, cfg: &C)
    where
        A::Lattice: Clone,
    {
        while let Some(block_idx) = self.worklist.pop_front() {
            if let Some(slot) = self.in_worklist.get_mut(block_idx) {
                *slot = false;
            }
            self.iterations = self.iterations.saturating_add(1);

            let changed = match A::DIRECTION {
                Direction::Forward => self.process_forward(block_idx, ssa, cfg),
                Direction::Backward => self.process_backward(block_idx, ssa, cfg),
            };

            if changed {
                // Add affected blocks to worklist
                self.add_affected_to_worklist(block_idx, cfg);
            }
        }
    }

    /// Processes a block in forward direction.
    ///
    /// Returns `true` if the output state changed.
    fn process_forward<C: DataFlowCfg>(
        &mut self,
        block_idx: usize,
        ssa: &SsaFunction,
        cfg: &C,
    ) -> bool
    where
        A::Lattice: Clone,
    {
        // Compute input by meeting all predecessor outputs
        let node = NodeId::new(block_idx);
        let Some(current_in) = self.in_states.get(block_idx).cloned() else {
            return false;
        };
        let mut input = if cfg.predecessors(node).next().is_none() {
            // Entry block or unreachable - keep current in_state
            current_in.clone()
        } else {
            // Meet all predecessor outputs
            let mut result: Option<A::Lattice> = None;
            for pred in cfg.predecessors(node) {
                let Some(pred_out) = self.out_states.get(pred.index()) else {
                    continue;
                };
                result = Some(match result {
                    None => pred_out.clone(),
                    Some(acc) => acc.meet(pred_out),
                });
            }
            result.unwrap_or_else(|| current_in.clone())
        };

        // Special case: entry block keeps its boundary value
        if node == cfg.entry() {
            input = current_in.clone();
        }

        if let Some(slot) = self.in_states.get_mut(block_idx) {
            *slot = input.clone();
        }

        // Apply transfer function
        let Some(block) = ssa.block(block_idx) else {
            return false;
        };
        let output = self.analysis.transfer(block_idx, block, &input, ssa);

        // Check if output changed
        let Some(out_slot) = self.out_states.get_mut(block_idx) else {
            return false;
        };
        let changed = output != *out_slot;
        *out_slot = output;

        changed
    }

    /// Processes a block in backward direction.
    ///
    /// Returns `true` if the input state changed.
    fn process_backward<C: DataFlowCfg>(
        &mut self,
        block_idx: usize,
        ssa: &SsaFunction,
        cfg: &C,
    ) -> bool
    where
        A::Lattice: Clone,
    {
        // Compute output by meeting all successor inputs
        let node = NodeId::new(block_idx);
        let Some(current_out) = self.out_states.get(block_idx).cloned() else {
            return false;
        };
        let mut output = if cfg.successors(node).next().is_none() {
            // Exit block or dead end - keep current out_state
            current_out.clone()
        } else {
            // Meet all successor inputs
            let mut result: Option<A::Lattice> = None;
            for succ in cfg.successors(node) {
                let Some(succ_in) = self.in_states.get(succ.index()) else {
                    continue;
                };
                result = Some(match result {
                    None => succ_in.clone(),
                    Some(acc) => acc.meet(succ_in),
                });
            }
            result.unwrap_or_else(|| current_out.clone())
        };

        // Special case: exit blocks keep their boundary value
        if cfg.exits().contains(&node) {
            output = current_out.clone();
        }

        if let Some(slot) = self.out_states.get_mut(block_idx) {
            *slot = output.clone();
        }

        // Apply transfer function (backward: input = transfer(output))
        let Some(block) = ssa.block(block_idx) else {
            return false;
        };
        let input = self.analysis.transfer(block_idx, block, &output, ssa);

        // Check if input changed
        let Some(in_slot) = self.in_states.get_mut(block_idx) else {
            return false;
        };
        let changed = input != *in_slot;
        *in_slot = input;

        changed
    }

    /// Adds affected blocks to the worklist after a change.
    fn add_affected_to_worklist<C: DataFlowCfg>(&mut self, block_idx: usize, cfg: &C) {
        let node = NodeId::new(block_idx);

        let enqueue = |idx: usize, list: &mut Vec<bool>, work: &mut VecDeque<usize>| {
            if let Some(slot) = list.get_mut(idx) {
                if !*slot {
                    work.push_back(idx);
                    *slot = true;
                }
            }
        };

        match A::DIRECTION {
            Direction::Forward => {
                // Forward: successors are affected
                for succ in cfg.successors(node) {
                    enqueue(succ.index(), &mut self.in_worklist, &mut self.worklist);
                }
            }
            Direction::Backward => {
                // Backward: predecessors are affected
                for pred in cfg.predecessors(node) {
                    enqueue(pred.index(), &mut self.in_worklist, &mut self.worklist);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::SsaBlock;

    /// A simple constant lattice for testing.
    #[derive(Debug, Clone, PartialEq)]
    enum TestLattice {
        Top,
        Value(i32),
        Bottom,
    }

    impl MeetSemiLattice for TestLattice {
        fn meet(&self, other: &Self) -> Self {
            match (self, other) {
                (Self::Top, x) | (x, Self::Top) => x.clone(),
                (Self::Value(a), Self::Value(b)) if a == b => Self::Value(*a),
                _ => Self::Bottom,
            }
        }

        fn is_bottom(&self) -> bool {
            matches!(self, Self::Bottom)
        }
    }

    /// A trivial analysis that just propagates values unchanged.
    struct TrivialAnalysis;

    impl DataFlowAnalysis for TrivialAnalysis {
        type Lattice = TestLattice;
        const DIRECTION: Direction = Direction::Forward;

        fn boundary(&self, _ssa: &SsaFunction) -> Self::Lattice {
            TestLattice::Value(42)
        }

        fn initial(&self, _ssa: &SsaFunction) -> Self::Lattice {
            TestLattice::Top
        }

        fn transfer(
            &self,
            _block_id: usize,
            _block: &SsaBlock,
            input: &Self::Lattice,
            _ssa: &SsaFunction,
        ) -> Self::Lattice {
            input.clone()
        }
    }

    #[test]
    fn test_solver_iterations() {
        // This is a basic sanity test - full integration tests are elsewhere
        let solver = DataFlowSolver::new(TrivialAnalysis);
        assert_eq!(solver.iterations(), 0);
    }
}
