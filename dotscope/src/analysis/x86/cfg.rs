//! Control flow graph construction from x86 instructions.
//!
//! This module builds a CFG from decoded x86 instructions, identifying basic blocks
//! and their successor relationships. It leverages the existing graph infrastructure
//! from [`crate::utils::graph`] for efficient analysis.

use crate::{
    analysis::{
        cfg::has_back_edges,
        x86::types::{DecodedInstruction, X86EdgeKind, X86Instruction},
    },
    utils::graph::{
        algorithms::{compute_dominators, DominatorTree},
        DirectedGraph, GraphBase, NodeId, Predecessors, RootedGraph, Successors,
    },
};
use rustc_hash::FxHashMap;
use std::{collections::BTreeSet, sync::OnceLock};

/// A basic block in the x86 CFG.
#[derive(Debug, Clone)]
pub struct X86BasicBlock {
    /// Index of this block in the function
    pub index: usize,
    /// Offset where this block starts
    pub start_offset: u64,
    /// Offset where this block ends (exclusive, start of next instruction)
    pub end_offset: u64,
    /// Instructions in this block
    pub instructions: Vec<DecodedInstruction>,
}

impl X86BasicBlock {
    /// Returns the terminator instruction, if any.
    #[must_use]
    pub fn terminator(&self) -> Option<&X86Instruction> {
        self.instructions.last().map(|i| &i.instruction)
    }

    /// Returns true if this block ends with a return instruction.
    #[must_use]
    pub fn is_exit(&self) -> bool {
        matches!(self.terminator(), Some(X86Instruction::Ret))
    }

    /// Returns true if this block ends with an unconditional jump.
    #[must_use]
    pub fn is_unconditional_jump(&self) -> bool {
        matches!(self.terminator(), Some(X86Instruction::Jmp { .. }))
    }

    /// Returns true if this block ends with a conditional jump.
    #[must_use]
    pub fn is_conditional_jump(&self) -> bool {
        matches!(self.terminator(), Some(X86Instruction::Jcc { .. }))
    }

    /// Returns true if this block has any unsupported instructions.
    #[must_use]
    pub fn has_unsupported(&self) -> bool {
        self.instructions
            .iter()
            .any(|i| matches!(i.instruction, X86Instruction::Unsupported { .. }))
    }
}

/// Decoded x86 function with control flow graph.
///
/// This structure wraps a `DirectedGraph` with x86-specific functionality,
/// providing lazy-computed analysis results (dominators, etc.).
#[derive(Debug)]
pub struct X86Function {
    /// Bitness (32 or 64)
    pub bitness: u32,
    /// Base address of the function
    pub base_address: u64,
    /// The underlying directed graph
    graph: DirectedGraph<'static, X86BasicBlock, X86EdgeKind>,
    /// Entry block node ID
    entry: NodeId,
    /// Exit block node IDs (blocks ending with ret)
    exits: Vec<NodeId>,
    /// Lazily computed dominator tree
    dominators: OnceLock<DominatorTree>,
}

impl X86Function {
    /// Build a CFG from decoded instructions.
    ///
    /// This identifies basic block boundaries based on:
    /// - Jump targets (start of block)
    /// - Instructions after jumps (start of block)
    /// - Jump/ret instructions (end of block)
    ///
    /// The resulting CFG uses a directed graph internally and provides
    /// lazy-computed analysis (dominators, etc.).
    #[must_use]
    pub fn new(instructions: &[DecodedInstruction], bitness: u32, base_address: u64) -> Self {
        if instructions.is_empty() {
            let graph: DirectedGraph<'static, X86BasicBlock, X86EdgeKind> = DirectedGraph::new();
            return Self {
                bitness,
                base_address,
                graph,
                entry: NodeId::new(0),
                exits: vec![],
                dominators: OnceLock::new(),
            };
        }

        // Step 1: Identify block leaders (offsets that start a basic block)
        let mut leaders = BTreeSet::new();

        // First instruction is always a leader
        leaders.insert(instructions[0].offset);

        // Find jump targets and fallthrough points
        for (i, instr) in instructions.iter().enumerate() {
            match &instr.instruction {
                X86Instruction::Jmp { target } => {
                    // Target is a leader
                    leaders.insert(*target - base_address);
                }
                X86Instruction::Jcc { target, .. } => {
                    // Target is a leader
                    leaders.insert(*target - base_address);
                    // Fallthrough is also a leader (instruction after this one)
                    if i + 1 < instructions.len() {
                        leaders.insert(instructions[i + 1].offset);
                    }
                }
                X86Instruction::Call { .. } => {
                    // Instruction after call is a leader (call returns)
                    if i + 1 < instructions.len() {
                        leaders.insert(instructions[i + 1].offset);
                    }
                }
                X86Instruction::Ret => {
                    // Instruction after ret is a leader (if any)
                    if i + 1 < instructions.len() {
                        leaders.insert(instructions[i + 1].offset);
                    }
                }
                _ => {}
            }
        }

        // Step 2: Build offset -> instruction index map
        let offset_to_index: FxHashMap<u64, usize> = instructions
            .iter()
            .enumerate()
            .map(|(i, instr)| (instr.offset, i))
            .collect();

        // Step 3: Create blocks
        let leader_list: Vec<u64> = leaders.iter().copied().collect();
        let mut blocks: Vec<X86BasicBlock> = Vec::new();
        let mut offset_to_block: FxHashMap<u64, usize> = FxHashMap::default();

        for (block_idx, &leader_offset) in leader_list.iter().enumerate() {
            // Find start instruction index
            let Some(&start_instr_idx) = offset_to_index.get(&leader_offset) else {
                continue; // Leader offset not in our instruction list
            };

            // Find end of this block (exclusive)
            let end_offset = leader_list.get(block_idx + 1).copied().unwrap_or(u64::MAX);

            // Collect instructions for this block
            let mut block_instrs = Vec::new();
            let mut block_end_offset = leader_offset;

            for instr in instructions.iter().skip(start_instr_idx) {
                if instr.offset >= end_offset {
                    break;
                }
                block_end_offset = instr.end_offset();
                block_instrs.push(instr.clone());

                // Stop at terminator instructions
                if instr.instruction.is_terminator() {
                    break;
                }
            }

            if !block_instrs.is_empty() {
                offset_to_block.insert(leader_offset, blocks.len());
                blocks.push(X86BasicBlock {
                    index: blocks.len(),
                    start_offset: leader_offset,
                    end_offset: block_end_offset,
                    instructions: block_instrs,
                });
            }
        }

        // Step 4: Compute edges before building graph (to avoid borrow issues)
        let edges_to_add: Vec<(usize, Vec<(usize, X86EdgeKind)>)> = blocks
            .iter()
            .enumerate()
            .map(|(idx, block)| (idx, compute_edges(block, &offset_to_block, base_address)))
            .collect();

        // Step 5: Build the DirectedGraph
        let mut graph: DirectedGraph<'static, X86BasicBlock, X86EdgeKind> =
            DirectedGraph::with_capacity(blocks.len(), blocks.len() * 2);

        // Add all blocks as nodes
        for block in blocks {
            graph.add_node(block);
        }

        // Step 6: Add edges between blocks
        for (src_idx, edges) in edges_to_add {
            let src_node = NodeId::new(src_idx);
            for (target_idx, edge_kind) in edges {
                let target_node = NodeId::new(target_idx);
                // Ignore errors for edges to non-existent blocks
                let _ = graph.add_edge(src_node, target_node, edge_kind);
            }
        }

        // Step 7: Find entry and exit blocks
        let entry = NodeId::new(0);
        let exits: Vec<NodeId> = graph
            .nodes()
            .filter(|(_, block)| block.is_exit())
            .map(|(id, _)| id)
            .collect();

        Self {
            bitness,
            base_address,
            graph,
            entry,
            exits,
            dominators: OnceLock::new(),
        }
    }

    /// Returns the number of blocks in this function.
    pub fn block_count(&self) -> usize {
        self.graph.node_count()
    }

    /// Returns true if this function has any unsupported instructions.
    pub fn has_unsupported(&self) -> bool {
        self.graph.nodes().any(|(_, block)| block.has_unsupported())
    }

    /// Returns true if this function has loops (back edges).
    ///
    /// A back edge is an edge where the target dominates the source.
    /// Uses the shared `has_back_edges` function for consistency.
    pub fn has_loops(&self) -> bool {
        has_back_edges(&self.graph, self.dominators())
    }

    /// Returns an iterator over all instructions in the function.
    pub fn instructions(&self) -> impl Iterator<Item = &DecodedInstruction> {
        self.graph
            .nodes()
            .flat_map(|(_, block)| block.instructions.iter())
    }

    /// Returns the block at the given index.
    pub fn block(&self, index: usize) -> Option<&X86BasicBlock> {
        self.graph.node(NodeId::new(index))
    }

    /// Returns the entry block node ID.
    pub fn entry(&self) -> NodeId {
        self.entry
    }

    /// Returns the exit block node IDs.
    pub fn exits(&self) -> &[NodeId] {
        &self.exits
    }

    /// Returns an iterator over successor node IDs for a block.
    pub fn successors(&self, node: NodeId) -> impl Iterator<Item = NodeId> + '_ {
        self.graph.successors(node)
    }

    /// Returns an iterator over predecessor node IDs for a block.
    pub fn predecessors(&self, node: NodeId) -> impl Iterator<Item = NodeId> + '_ {
        self.graph.predecessors(node)
    }

    /// Returns a reference to the underlying graph.
    pub fn graph(&self) -> &DirectedGraph<'static, X86BasicBlock, X86EdgeKind> {
        &self.graph
    }

    /// Returns the lazily-computed dominator tree.
    pub fn dominators(&self) -> &DominatorTree {
        self.dominators.get_or_init(|| {
            // The X86Function implements RootedGraph + Successors, so we can use it directly
            compute_dominators(self, self.entry)
        })
    }

    /// Returns an iterator over all node IDs in the graph.
    pub fn node_ids(&self) -> impl Iterator<Item = NodeId> + '_ {
        self.graph.node_ids()
    }

    /// Returns an iterator over all edges with their kinds.
    pub fn edges(&self) -> impl Iterator<Item = (NodeId, NodeId, &X86EdgeKind)> + '_ {
        self.graph.edge_ids().filter_map(move |edge_id| {
            let (src, dst) = self.graph.edge_endpoints(edge_id)?;
            let kind = self.graph.edge(edge_id)?;
            Some((src, dst, kind))
        })
    }

    /// Check if the CFG is reducible (no irreducible loops).
    ///
    /// A CFG is reducible if every back edge goes to a loop header that dominates
    /// the source of the back edge.
    pub fn is_reducible(&self) -> bool {
        fn dfs_check(
            node: NodeId,
            func: &X86Function,
            doms: &DominatorTree,
            visited: &mut [bool],
            in_stack: &mut [bool],
        ) -> bool {
            let idx = node.index();
            visited[idx] = true;
            in_stack[idx] = true;

            for succ in func.graph.successors(node) {
                let succ_idx = succ.index();
                if in_stack[succ_idx] {
                    // This is a back edge (n -> succ where succ is on the stack)
                    // For reducibility, succ must dominate node
                    if !doms.dominates(succ, node) {
                        return false;
                    }
                } else if !visited[succ_idx] && !dfs_check(succ, func, doms, visited, in_stack) {
                    return false;
                }
            }

            in_stack[idx] = false;
            true
        }

        if self.block_count() == 0 {
            return true;
        }

        let doms = self.dominators();

        // A CFG is reducible if for every back edge (n -> h),
        // h dominates n. A back edge is one where h dominates n.
        // By definition, this is always true for back edges, so we check
        // for edges that form cycles but aren't proper back edges.

        // Use DFS to find back edges
        let mut visited = vec![false; self.block_count()];
        let mut in_stack = vec![false; self.block_count()];

        dfs_check(self.entry, self, doms, &mut visited, &mut in_stack)
    }
}

// Implement traits required for dominator computation
impl GraphBase for X86Function {
    fn node_count(&self) -> usize {
        self.graph.node_count()
    }

    fn node_ids(&self) -> impl Iterator<Item = NodeId> {
        self.graph.node_ids()
    }
}

impl Successors for X86Function {
    fn successors(&self, node: NodeId) -> impl Iterator<Item = NodeId> {
        self.graph.successors(node)
    }
}

impl Predecessors for X86Function {
    fn predecessors(&self, node: NodeId) -> impl Iterator<Item = NodeId> {
        self.graph.predecessors(node)
    }
}

impl RootedGraph for X86Function {
    fn entry(&self) -> NodeId {
        self.entry
    }
}

/// Compute the edges (successors with edge kinds) for a block.
fn compute_edges(
    block: &X86BasicBlock,
    offset_to_block: &FxHashMap<u64, usize>,
    base_address: u64,
) -> Vec<(usize, X86EdgeKind)> {
    let mut edges = Vec::new();

    if let Some(term) = block.terminator() {
        match term {
            X86Instruction::Jmp { target } => {
                let target_offset = target - base_address;
                if let Some(&block_idx) = offset_to_block.get(&target_offset) {
                    edges.push((block_idx, X86EdgeKind::Unconditional));
                }
            }
            X86Instruction::Jcc { target, condition } => {
                // Conditional jump: two edges
                // 1. Target (condition true)
                let target_offset = target - base_address;
                if let Some(&block_idx) = offset_to_block.get(&target_offset) {
                    edges.push((
                        block_idx,
                        X86EdgeKind::ConditionalTrue {
                            condition: *condition,
                        },
                    ));
                }
                // 2. Fallthrough (condition false)
                if let Some(&block_idx) = offset_to_block.get(&block.end_offset) {
                    edges.push((
                        block_idx,
                        X86EdgeKind::ConditionalFalse {
                            condition: *condition,
                        },
                    ));
                }
            }
            X86Instruction::Call { target } => {
                // For intraprocedural CFG, call falls through
                if let Some(&block_idx) = offset_to_block.get(&block.end_offset) {
                    edges.push((block_idx, X86EdgeKind::Call { target: *target }));
                }
            }
            X86Instruction::Ret => {
                // No successors - but we mark it as a return edge to a virtual exit
                // For now, we don't add an edge since there's no successor block
            }
            _ => {
                // Non-terminator at end of block - fallthrough
                if let Some(&block_idx) = offset_to_block.get(&block.end_offset) {
                    edges.push((block_idx, X86EdgeKind::Unconditional));
                }
            }
        }
    } else if !block.instructions.is_empty() {
        // Block with no terminator - fallthrough
        if let Some(&block_idx) = offset_to_block.get(&block.end_offset) {
            edges.push((block_idx, X86EdgeKind::Unconditional));
        }
    }

    edges
}

#[cfg(test)]
mod tests {
    use crate::{
        analysis::x86::{
            cfg::X86Function,
            decoder::decode_all,
            types::{X86Condition, X86EdgeKind},
        },
        utils::graph::NodeId,
    };

    #[test]
    fn test_build_cfg_linear() {
        // Linear code: mov eax, 1; add eax, 2; ret
        let bytes = [
            0xb8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
            0x83, 0xc0, 0x02, // add eax, 2
            0xc3, // ret
        ];
        let instructions = decode_all(&bytes, 32, 0x1000).unwrap();
        let cfg = X86Function::new(&instructions, 32, 0x1000);

        assert_eq!(cfg.block_count(), 1);
        assert_eq!(cfg.entry(), NodeId::new(0));
        assert_eq!(cfg.exits().len(), 1);
        assert_eq!(cfg.block(0).unwrap().instructions.len(), 3);
        assert_eq!(cfg.successors(NodeId::new(0)).count(), 0);
    }

    #[test]
    fn test_build_cfg_conditional() {
        // cmp eax, 10
        // je skip
        // add eax, 5
        // skip: ret
        let bytes = [
            0x83, 0xf8, 0x0a, // cmp eax, 10
            0x74, 0x03, // je +3 (to ret)
            0x83, 0xc0, 0x05, // add eax, 5
            0xc3, // ret
        ];
        let instructions = decode_all(&bytes, 32, 0x1000).unwrap();
        let cfg = X86Function::new(&instructions, 32, 0x1000);

        // Should have 3 blocks:
        // Block 0: cmp, je
        // Block 1: add eax, 5
        // Block 2: ret
        assert_eq!(cfg.block_count(), 3);
        assert_eq!(cfg.entry(), NodeId::new(0));

        // Block 0 should have 2 successors (taken and fallthrough)
        assert_eq!(cfg.successors(NodeId::new(0)).count(), 2);

        // Check that the CFG is reducible (simple if-then)
        assert!(cfg.is_reducible());
    }

    #[test]
    fn test_build_cfg_unconditional_jump() {
        // jmp skip
        // nop (unreachable)
        // skip: mov eax, 1
        // ret
        let bytes = [
            0xeb, 0x01, // jmp +1
            0x90, // nop
            0xb8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
            0xc3, // ret
        ];
        let instructions = decode_all(&bytes, 32, 0x1000).unwrap();
        let cfg = X86Function::new(&instructions, 32, 0x1000);

        // Should have blocks
        assert!(cfg.block_count() >= 2);

        // Entry block should have exactly one successor (the jump target)
        assert_eq!(cfg.successors(NodeId::new(0)).count(), 1);
    }

    #[test]
    fn test_build_cfg_loop() {
        // loop: cmp eax, 0
        //       je exit
        //       dec eax
        //       jmp loop
        // exit: ret
        let bytes = [
            0x83, 0xf8, 0x00, // cmp eax, 0
            0x74, 0x04, // je +4 (to ret)
            0x48, // dec eax
            0xeb, 0xf8, // jmp -8 (to cmp)
            0xc3, // ret
        ];
        let instructions = decode_all(&bytes, 32, 0x1000).unwrap();
        let cfg = X86Function::new(&instructions, 32, 0x1000);

        // Should have a loop (back edge)
        assert!(cfg.has_loops());

        // Should be reducible (simple while loop)
        assert!(cfg.is_reducible());
    }

    #[test]
    fn test_empty_input() {
        let cfg = X86Function::new(&[], 32, 0);
        assert_eq!(cfg.block_count(), 0);
    }

    #[test]
    fn test_dominators() {
        // Linear code should have simple dominator tree
        let bytes = [
            0xb8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
            0x83, 0xc0, 0x02, // add eax, 2
            0xc3, // ret
        ];
        let instructions = decode_all(&bytes, 32, 0x1000).unwrap();
        let cfg = X86Function::new(&instructions, 32, 0x1000);

        let doms = cfg.dominators();
        assert_eq!(doms.entry(), NodeId::new(0));
    }

    #[test]
    fn test_edge_kinds() {
        // Conditional code to test edge kinds
        let bytes = [
            0x83, 0xf8, 0x0a, // cmp eax, 10
            0x74, 0x03, // je +3 (to ret)
            0x83, 0xc0, 0x05, // add eax, 5
            0xc3, // ret
        ];
        let instructions = decode_all(&bytes, 32, 0x1000).unwrap();
        let cfg = X86Function::new(&instructions, 32, 0x1000);

        // Check that we have conditional edges
        let mut found_cond_true = false;
        let mut found_cond_false = false;

        for (_, _, kind) in cfg.edges() {
            match kind {
                X86EdgeKind::ConditionalTrue { condition } => {
                    assert_eq!(*condition, X86Condition::E);
                    found_cond_true = true;
                }
                X86EdgeKind::ConditionalFalse { condition } => {
                    assert_eq!(*condition, X86Condition::E);
                    found_cond_false = true;
                }
                _ => {}
            }
        }

        assert!(found_cond_true);
        assert!(found_cond_false);
    }
}
