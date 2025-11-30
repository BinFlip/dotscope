//! Data flow analysis framework trait and direction.
//!
//! This module defines the core abstraction for data flow analyses. Any
//! specific analysis (reaching definitions, liveness, constant propagation)
//! implements the [`DataFlowAnalysis`] trait to work with the solver.

use std::fmt::Debug;

use crate::analysis::{
    dataflow::lattice::MeetSemiLattice, ControlFlowGraph, SsaBlock, SsaFunction,
};

/// Direction of data flow analysis.
///
/// The direction determines how information propagates through the CFG
/// and which operation (meet or join) is used at control flow merge points.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Information flows forward, from entry to exit.
    ///
    /// At join points (blocks with multiple predecessors), values from
    /// all predecessors are combined using the meet operation.
    ///
    /// Examples: reaching definitions, available expressions, constant propagation.
    Forward,

    /// Information flows backward, from exit to entry.
    ///
    /// At split points (blocks with multiple successors), values from
    /// all successors are combined.
    ///
    /// Examples: live variables, very busy expressions.
    Backward,
}

/// A data flow analysis that can be run on SSA form.
///
/// This trait defines the interface for a data flow analysis. Implementations
/// provide the transfer function and boundary conditions; the solver handles
/// iteration to a fixpoint.
///
/// # Type Parameters
///
/// * `L` - The lattice type representing abstract values at each program point
///
/// # Direction
///
/// The `DIRECTION` constant specifies whether this is a forward or backward
/// analysis. The solver uses this to determine iteration order and how to
/// combine values at control flow merge points.
///
/// # Transfer Functions
///
/// The core of any data flow analysis is the transfer function, which
/// describes how flowing through a basic block transforms the abstract state.
///
/// For forward analyses: `out[B] = transfer(B, in[B])`
/// For backward analyses: `in[B] = transfer(B, out[B])`
///
/// # Example
///
/// ```rust,ignore
/// use dotscope::analysis::dataflow::{DataFlowAnalysis, Direction, MeetSemiLattice};
///
/// struct MyAnalysis;
///
/// impl DataFlowAnalysis for MyAnalysis {
///     type Lattice = MyLattice;
///     const DIRECTION: Direction = Direction::Forward;
///
///     fn boundary(&self, _ssa: &SsaFunction) -> Self::Lattice {
///         MyLattice::initial_at_entry()
///     }
///
///     fn initial(&self, _ssa: &SsaFunction) -> Self::Lattice {
///         MyLattice::top()
///     }
///
///     fn transfer(
///         &self,
///         block_id: usize,
///         block: &SsaBlock,
///         input: &Self::Lattice,
///         ssa: &SsaFunction,
///     ) -> Self::Lattice {
///         // Compute the output state from the input state
///         // by applying the block's effects
///         todo!()
///     }
/// }
/// ```
pub trait DataFlowAnalysis {
    /// The lattice type for this analysis.
    ///
    /// This must implement `MeetSemiLattice` to support combining values
    /// at control flow merge points.
    type Lattice: MeetSemiLattice;

    /// The direction of this analysis.
    const DIRECTION: Direction;

    /// Returns the initial value at the boundary of the function.
    ///
    /// For forward analyses, this is the value at function entry.
    /// For backward analyses, this is the value at function exit(s).
    ///
    /// This often represents the "known" information at the boundary,
    /// such as "all parameters are defined" for reaching definitions.
    fn boundary(&self, ssa: &SsaFunction) -> Self::Lattice;

    /// Returns the initial value for interior blocks.
    ///
    /// This is the value used to initialize all non-boundary blocks
    /// before iteration begins. For most analyses, this is the top
    /// element of the lattice (no information).
    fn initial(&self, ssa: &SsaFunction) -> Self::Lattice;

    /// Computes the transfer function for a basic block.
    ///
    /// Given the input state to a block, computes the output state
    /// after flowing through the block.
    ///
    /// # Arguments
    ///
    /// * `block_id` - The index of the block being processed
    /// * `block` - The SSA block
    /// * `input` - The abstract state flowing into (forward) or out of (backward) the block
    /// * `ssa` - The complete SSA function for context
    ///
    /// # Returns
    ///
    /// The abstract state after flowing through the block.
    fn transfer(
        &self,
        block_id: usize,
        block: &SsaBlock,
        input: &Self::Lattice,
        ssa: &SsaFunction,
    ) -> Self::Lattice;

    /// Called when analysis is complete.
    ///
    /// This hook allows analyses to perform post-processing, such as
    /// computing per-instruction results from block-level results.
    ///
    /// The default implementation does nothing.
    fn finalize(
        &mut self,
        _in_states: &[Self::Lattice],
        _out_states: &[Self::Lattice],
        _ssa: &SsaFunction,
        _cfg: &ControlFlowGraph<'_>,
    ) {
        // Default: no post-processing
    }
}

/// Results of a data flow analysis.
///
/// This provides access to the computed abstract values at block boundaries.
#[derive(Debug, Clone)]
pub struct AnalysisResults<L> {
    /// Input state for each block (before transfer function).
    pub in_states: Vec<L>,
    /// Output state for each block (after transfer function).
    pub out_states: Vec<L>,
}

impl<L: Clone> AnalysisResults<L> {
    /// Creates new analysis results with the given states.
    ///
    /// # Arguments
    ///
    /// * `in_states` - The input states for each block
    /// * `out_states` - The output states for each block
    ///
    /// # Returns
    ///
    /// A new [`AnalysisResults`] instance.
    #[must_use]
    pub fn new(in_states: Vec<L>, out_states: Vec<L>) -> Self {
        Self {
            in_states,
            out_states,
        }
    }

    /// Returns the input state for a block.
    ///
    /// # Arguments
    ///
    /// * `block` - The block index to query
    ///
    /// # Returns
    ///
    /// The input state for the block, or `None` if the index is out of bounds.
    #[must_use]
    pub fn in_state(&self, block: usize) -> Option<&L> {
        self.in_states.get(block)
    }

    /// Returns the output state for a block.
    ///
    /// # Arguments
    ///
    /// * `block` - The block index to query
    ///
    /// # Returns
    ///
    /// The output state for the block, or `None` if the index is out of bounds.
    #[must_use]
    pub fn out_state(&self, block: usize) -> Option<&L> {
        self.out_states.get(block)
    }

    /// Returns the number of blocks.
    ///
    /// # Returns
    ///
    /// The total number of blocks in the analysis results.
    #[must_use]
    pub fn block_count(&self) -> usize {
        self.in_states.len()
    }
}
