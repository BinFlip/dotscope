//! Control flow graph view of SSA functions.
//!
//! This module provides [`SsaCfg`], a lightweight CFG view that can be constructed
//! directly from an [`SsaFunction`]. Unlike the CIL-based [`ControlFlowGraph`] which
//! is built from basic blocks, this CFG is derived from SSA block terminators.
//!
//! # Purpose
//!
//! The primary use case is to enable dataflow analyses (like SCCP) that require
//! a CFG to work on SSA functions during deobfuscation passes. Since passes only
//! receive `SsaFunction` (not the original CFG), this module bridges that gap.
//!
//! # Design
//!
//! `SsaCfg` implements the standard graph traits:
//! - [`GraphBase`] - Node count and iteration
//! - [`Successors`] - Forward edge traversal (from terminators)
//! - [`Predecessors`] - Backward edge traversal (computed from successors)
//! - [`RootedGraph`] - Entry node (block 0)
//!
//! This allows it to be used with the existing dataflow analysis infrastructure,
//! particularly the SCCP algorithm in [`crate::analysis::dataflow::sccp`].
//!
//! # Construction
//!
//! The CFG is constructed on-demand from the SSA function:
//!
//! ```rust,ignore
//! use dotscope::analysis::{SsaCfg, SsaFunction};
//!
//! let ssa: SsaFunction = /* ... */;
//! let cfg = SsaCfg::from_ssa(&ssa);
//!
//! // Use with SCCP
//! let mut sccp = ConstantPropagation::new();
//! let results = sccp.analyze(&ssa, &cfg);
//! ```
//!
//! [`ControlFlowGraph`]: crate::analysis::ControlFlowGraph

use crate::{
    analysis::ssa::SsaFunction,
    utils::graph::{
        algorithms::{postorder, reverse_postorder},
        GraphBase, NodeId, Predecessors, RootedGraph, Successors,
    },
};

/// A lightweight control flow graph view of an SSA function.
///
/// This struct provides a CFG interface over an existing [`SsaFunction`],
/// extracting control flow edges from block terminators. It's designed to
/// enable dataflow analyses that require a CFG without duplicating the
/// underlying SSA structure.
///
/// # Performance
///
/// The CFG computes and caches predecessor lists on construction. This is
/// an O(E) operation where E is the number of edges (typically similar to
/// the number of blocks). Once constructed, all queries are O(1) or O(k)
/// where k is the number of adjacent nodes.
///
/// # Lifetime
///
/// The CFG holds a reference to the SSA function it was created from.
/// The CFG must not outlive the SSA function.
#[derive(Debug)]
pub struct SsaCfg<'a> {
    /// Reference to the SSA function.
    ssa: &'a SsaFunction,
    /// Precomputed predecessor lists for each block.
    /// predecessors[block_id] = list of blocks that can jump to block_id.
    predecessors: Vec<Vec<usize>>,
}

impl<'a> SsaCfg<'a> {
    /// Creates a CFG view from an SSA function.
    ///
    /// This extracts control flow edges by examining the terminator of each
    /// SSA block. Predecessors are computed and cached for efficient backward
    /// traversal.
    ///
    /// # Arguments
    ///
    /// * `ssa` - The SSA function to create a CFG view of.
    ///
    /// # Returns
    ///
    /// A new `SsaCfg` view of the given function.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let cfg = SsaCfg::from_ssa(&ssa_function);
    /// assert_eq!(cfg.node_count(), ssa_function.block_count());
    /// ```
    #[must_use]
    pub fn from_ssa(ssa: &'a SsaFunction) -> Self {
        let block_count = ssa.block_count();
        let mut predecessors = vec![Vec::new(); block_count];

        // Build predecessor lists by iterating over all blocks and their terminators
        for block_idx in 0..block_count {
            if let Some(block) = ssa.block(block_idx) {
                // Find the terminator instruction (last instruction that is a terminator)
                let successors = block
                    .instructions()
                    .iter()
                    .rev()
                    .find_map(|instr| {
                        let op = instr.op();
                        if op.is_terminator() {
                            Some(op.successors())
                        } else {
                            None
                        }
                    })
                    .unwrap_or_default();

                // Add this block as a predecessor of each successor
                for succ in successors {
                    if succ < block_count {
                        predecessors[succ].push(block_idx);
                    }
                }
            }
        }

        Self { ssa, predecessors }
    }

    /// Returns the underlying SSA function.
    ///
    /// This can be used to access block and instruction data while
    /// traversing the CFG.
    #[must_use]
    pub const fn ssa(&self) -> &'a SsaFunction {
        self.ssa
    }

    /// Returns the number of blocks in the CFG.
    #[must_use]
    pub fn block_count(&self) -> usize {
        self.ssa.block_count()
    }

    /// Returns true if the CFG has no blocks.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ssa.is_empty()
    }

    /// Returns the successor block indices for a given block.
    ///
    /// Successors are determined by the block's terminator instruction.
    ///
    /// # Arguments
    ///
    /// * `block_idx` - The block index to query.
    ///
    /// # Returns
    ///
    /// A vector of successor block indices. Empty if the block has no
    /// successors (e.g., return, throw) or doesn't exist.
    #[must_use]
    pub fn block_successors(&self, block_idx: usize) -> Vec<usize> {
        self.ssa
            .block(block_idx)
            .and_then(|block| {
                block.instructions().iter().rev().find_map(|instr| {
                    let op = instr.op();
                    if op.is_terminator() {
                        Some(op.successors())
                    } else {
                        None
                    }
                })
            })
            .unwrap_or_default()
    }

    /// Returns the predecessor block indices for a given block.
    ///
    /// # Arguments
    ///
    /// * `block_idx` - The block index to query.
    ///
    /// # Returns
    ///
    /// A slice of predecessor block indices.
    #[must_use]
    pub fn block_predecessors(&self, block_idx: usize) -> &[usize] {
        self.predecessors.get(block_idx).map_or(&[], Vec::as_slice)
    }

    /// Returns the exit nodes of the CFG.
    ///
    /// Exit nodes are blocks with no successors (blocks that end in return,
    /// throw, or other terminating instructions).
    ///
    /// # Returns
    ///
    /// A vector of exit node IDs.
    #[must_use]
    pub fn exits(&self) -> Vec<NodeId> {
        let mut exits = Vec::new();
        for idx in 0..self.ssa.block_count() {
            if self.block_successors(idx).is_empty() {
                exits.push(NodeId::new(idx));
            }
        }
        exits
    }

    /// Returns blocks in postorder traversal.
    ///
    /// Postorder is useful for backward data flow analysis.
    ///
    /// # Returns
    ///
    /// A vector of node IDs in postorder.
    #[must_use]
    pub fn postorder(&self) -> Vec<NodeId> {
        postorder(self, self.entry())
    }

    /// Returns blocks in reverse postorder traversal.
    ///
    /// Reverse postorder is useful for forward data flow analysis.
    ///
    /// # Returns
    ///
    /// A vector of node IDs in reverse postorder.
    #[must_use]
    pub fn reverse_postorder(&self) -> Vec<NodeId> {
        reverse_postorder(self, self.entry())
    }
}

impl GraphBase for SsaCfg<'_> {
    fn node_count(&self) -> usize {
        self.ssa.block_count()
    }

    fn node_ids(&self) -> impl Iterator<Item = NodeId> {
        (0..self.ssa.block_count()).map(NodeId::new)
    }
}

impl Successors for SsaCfg<'_> {
    fn successors(&self, node: NodeId) -> impl Iterator<Item = NodeId> {
        self.block_successors(node.index())
            .into_iter()
            .map(NodeId::new)
    }
}

impl Predecessors for SsaCfg<'_> {
    fn predecessors(&self, node: NodeId) -> impl Iterator<Item = NodeId> {
        self.block_predecessors(node.index())
            .iter()
            .copied()
            .map(NodeId::new)
    }
}

impl RootedGraph for SsaCfg<'_> {
    fn entry(&self) -> NodeId {
        NodeId::new(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::ssa::{SsaBlock, SsaInstruction, SsaOp, SsaVarId};

    /// Creates a simple test SSA function with the given block structure.
    fn create_test_ssa(terminators: Vec<SsaOp>) -> SsaFunction {
        let mut ssa = SsaFunction::new(0, 0);

        for (idx, terminator) in terminators.into_iter().enumerate() {
            let mut block = SsaBlock::new(idx);
            block.add_instruction(SsaInstruction::synthetic(terminator));
            ssa.add_block(block);
        }

        ssa
    }

    #[test]
    fn test_empty_ssa() {
        let ssa = SsaFunction::new(0, 0);
        let cfg = SsaCfg::from_ssa(&ssa);

        assert!(cfg.is_empty());
        assert_eq!(cfg.node_count(), 0);
    }

    #[test]
    fn test_single_block() {
        let ssa = create_test_ssa(vec![SsaOp::Return { value: None }]);
        let cfg = SsaCfg::from_ssa(&ssa);

        assert_eq!(cfg.node_count(), 1);
        assert_eq!(cfg.entry(), NodeId::new(0));
        assert!(cfg.block_successors(0).is_empty());
        assert!(cfg.block_predecessors(0).is_empty());
    }

    #[test]
    fn test_linear_blocks() {
        // B0 -> B1 -> B2 (return)
        let ssa = create_test_ssa(vec![
            SsaOp::Jump { target: 1 },
            SsaOp::Jump { target: 2 },
            SsaOp::Return { value: None },
        ]);
        let cfg = SsaCfg::from_ssa(&ssa);

        assert_eq!(cfg.node_count(), 3);

        // Check successors
        assert_eq!(cfg.block_successors(0), vec![1]);
        assert_eq!(cfg.block_successors(1), vec![2]);
        assert!(cfg.block_successors(2).is_empty());

        // Check predecessors
        assert!(cfg.block_predecessors(0).is_empty());
        assert_eq!(cfg.block_predecessors(1), vec![0]);
        assert_eq!(cfg.block_predecessors(2), vec![1]);
    }

    #[test]
    fn test_diamond_cfg() {
        // B0 (branch) -> B1, B2 -> B3 (return)
        let cond = SsaVarId::new();
        let ssa = create_test_ssa(vec![
            SsaOp::Branch {
                condition: cond,
                true_target: 1,
                false_target: 2,
            },
            SsaOp::Jump { target: 3 },
            SsaOp::Jump { target: 3 },
            SsaOp::Return { value: None },
        ]);
        let cfg = SsaCfg::from_ssa(&ssa);

        assert_eq!(cfg.node_count(), 4);

        // B0 has two successors
        let b0_succs = cfg.block_successors(0);
        assert_eq!(b0_succs.len(), 2);
        assert!(b0_succs.contains(&1));
        assert!(b0_succs.contains(&2));

        // B3 has two predecessors
        let b3_preds = cfg.block_predecessors(3);
        assert_eq!(b3_preds.len(), 2);
        assert!(b3_preds.contains(&1));
        assert!(b3_preds.contains(&2));
    }

    #[test]
    fn test_loop_cfg() {
        // B0 -> B1 (loop) -> B1 (back edge) or B2 (exit)
        let cond = SsaVarId::new();
        let ssa = create_test_ssa(vec![
            SsaOp::Jump { target: 1 },
            SsaOp::Branch {
                condition: cond,
                true_target: 1, // back edge
                false_target: 2,
            },
            SsaOp::Return { value: None },
        ]);
        let cfg = SsaCfg::from_ssa(&ssa);

        assert_eq!(cfg.node_count(), 3);

        // B1 has itself as a predecessor (back edge)
        let b1_preds = cfg.block_predecessors(1);
        assert_eq!(b1_preds.len(), 2);
        assert!(b1_preds.contains(&0));
        assert!(b1_preds.contains(&1)); // self-loop
    }

    #[test]
    fn test_switch_cfg() {
        // B0 (switch) -> B1, B2, B3 (cases), B4 (default)
        let val = SsaVarId::new();
        let ssa = create_test_ssa(vec![
            SsaOp::Switch {
                value: val,
                targets: vec![1, 2, 3],
                default: 4,
            },
            SsaOp::Return { value: None },
            SsaOp::Return { value: None },
            SsaOp::Return { value: None },
            SsaOp::Return { value: None },
        ]);
        let cfg = SsaCfg::from_ssa(&ssa);

        assert_eq!(cfg.node_count(), 5);

        // B0 has 4 successors (3 cases + default)
        let b0_succs = cfg.block_successors(0);
        assert_eq!(b0_succs.len(), 4);
        assert!(b0_succs.contains(&1));
        assert!(b0_succs.contains(&2));
        assert!(b0_succs.contains(&3));
        assert!(b0_succs.contains(&4));
    }

    #[test]
    fn test_graph_traits() {
        let ssa = create_test_ssa(vec![
            SsaOp::Jump { target: 1 },
            SsaOp::Return { value: None },
        ]);
        let cfg = SsaCfg::from_ssa(&ssa);

        // Test GraphBase
        assert_eq!(GraphBase::node_count(&cfg), 2);
        let node_ids: Vec<_> = GraphBase::node_ids(&cfg).collect();
        assert_eq!(node_ids, vec![NodeId::new(0), NodeId::new(1)]);

        // Test Successors
        let succs: Vec<_> = Successors::successors(&cfg, NodeId::new(0)).collect();
        assert_eq!(succs, vec![NodeId::new(1)]);

        // Test Predecessors
        let preds: Vec<_> = Predecessors::predecessors(&cfg, NodeId::new(1)).collect();
        assert_eq!(preds, vec![NodeId::new(0)]);

        // Test RootedGraph
        assert_eq!(RootedGraph::entry(&cfg), NodeId::new(0));
    }
}
