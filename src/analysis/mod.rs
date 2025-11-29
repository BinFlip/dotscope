//! Program analysis infrastructure for .NET assemblies.
//!
//! This module provides foundational analysis capabilities for understanding and
//! transforming .NET CIL code. It builds upon the generic graph infrastructure
//! in [`crate::utils::graph`] to provide domain-specific analysis tools.
//!
//! # Architecture
//!
//! The analysis module is organized into focused sub-modules:
//!
//! - [`cfg`] - Control Flow Graph construction and analysis
//!
//! # Future Components
//!
//! Planned additions include:
//! - SSA (Static Single Assignment) form transformation
//! - Data flow analysis framework
//! - Call graph construction
//!
//! # Usage
//!
//! ```rust,ignore
//! use dotscope::analysis::ControlFlowGraph;
//! use dotscope::assembly::decode_blocks;
//!
//! // Decode method body into basic blocks
//! let blocks = decode_blocks(data, offset, rva, Some(size))?;
//!
//! // Build control flow graph
//! let cfg = ControlFlowGraph::from_basic_blocks(blocks)?;
//!
//! // Access dominator tree (lazily computed)
//! let dominators = cfg.dominators();
//! assert!(dominators.dominates(cfg.entry(), some_block));
//! ```

pub mod cfg;

// Re-export primary types at module level
pub use cfg::{CfgEdge, CfgEdgeKind, ControlFlowGraph, NaturalLoop};

#[cfg(test)]
mod tests {
    use crate::{
        analysis::{CfgEdgeKind, ControlFlowGraph},
        assembly::{decode_blocks, InstructionAssembler},
        utils::graph::NodeId,
    };

    /// Helper to build bytecode and decode it into a CFG.
    fn build_cfg(assembler: InstructionAssembler) -> ControlFlowGraph {
        let (bytecode, _max_stack) = assembler.finish().expect("Failed to assemble bytecode");
        let blocks =
            decode_blocks(&bytecode, 0, 0x1000, Some(bytecode.len())).expect("Failed to decode");
        ControlFlowGraph::from_basic_blocks(blocks).expect("Failed to build CFG")
    }

    #[test]
    fn test_sequential_method() {
        // Simple method: return arg0 + arg1
        let mut asm = InstructionAssembler::new();
        asm.ldarg_0()
            .unwrap()
            .ldarg_1()
            .unwrap()
            .add()
            .unwrap()
            .ret()
            .unwrap();

        let cfg = build_cfg(asm);

        // Should have exactly one block
        assert_eq!(cfg.block_count(), 1);
        assert!(!cfg.has_loops());

        // Entry and exit should be the same block
        assert_eq!(cfg.entry(), NodeId::new(0));
        assert_eq!(cfg.exits().len(), 1);
        assert_eq!(cfg.exits()[0], NodeId::new(0));
    }

    #[test]
    fn test_nop_sequence() {
        // Method with multiple nops followed by ret
        let mut asm = InstructionAssembler::new();
        asm.nop()
            .unwrap()
            .nop()
            .unwrap()
            .nop()
            .unwrap()
            .ldc_i4_0()
            .unwrap()
            .ret()
            .unwrap();

        let cfg = build_cfg(asm);

        assert_eq!(cfg.block_count(), 1);
        let block = cfg.block(cfg.entry()).unwrap();
        assert_eq!(block.instructions.len(), 5); // 3 nops + ldc.i4.0 + ret
    }

    #[test]
    fn test_simple_if_then() {
        // if (arg0) { return 1; } return 0;
        let mut asm = InstructionAssembler::new();
        asm.ldarg_0()
            .unwrap()
            .brfalse_s("else")
            .unwrap()
            .ldc_i4_1()
            .unwrap()
            .ret()
            .unwrap()
            .label("else")
            .unwrap()
            .ldc_i4_0()
            .unwrap()
            .ret()
            .unwrap();

        let cfg = build_cfg(asm);

        // Should have 3 blocks: entry (with branch), true path, false path
        assert_eq!(cfg.block_count(), 3);
        assert!(!cfg.has_loops());

        // Entry block should have 2 successors (conditional branch)
        let entry_succs: Vec<_> = cfg.successors(cfg.entry()).collect();
        assert_eq!(entry_succs.len(), 2);

        // Check edge kinds - should have conditional true and false
        let edges: Vec<_> = cfg.outgoing_edges(cfg.entry()).collect();
        assert_eq!(edges.len(), 2);
        let edge_kinds: Vec<_> = edges.iter().map(|(_, _, e)| e.kind().clone()).collect();
        assert!(edge_kinds.contains(&CfgEdgeKind::ConditionalTrue));
        assert!(edge_kinds.contains(&CfgEdgeKind::ConditionalFalse));

        // Should have 2 exit blocks (both paths return)
        assert_eq!(cfg.exits().len(), 2);
    }

    #[test]
    fn test_if_then_else_merge() {
        // if (arg0) { x = 1; } else { x = 0; } return x;
        let mut asm = InstructionAssembler::new();
        asm.ldarg_0()
            .unwrap()
            .brfalse_s("else")
            .unwrap()
            .ldc_i4_1()
            .unwrap()
            .br_s("merge")
            .unwrap()
            .label("else")
            .unwrap()
            .ldc_i4_0()
            .unwrap()
            .label("merge")
            .unwrap()
            .ret()
            .unwrap();

        let cfg = build_cfg(asm);

        // Should have 4 blocks: entry, then, else, merge
        assert_eq!(cfg.block_count(), 4);
        assert!(!cfg.has_loops());

        // Should have exactly 1 exit block (the merge block)
        assert_eq!(cfg.exits().len(), 1);

        // Find the merge block (has 2 predecessors and no successors with ret)
        let merge_block = cfg.exits()[0];
        let preds: Vec<_> = cfg.predecessors(merge_block).collect();
        assert_eq!(preds.len(), 2); // Both branches merge here

        // Entry dominates all blocks
        for i in 0..cfg.block_count() {
            assert!(cfg.dominates(cfg.entry(), NodeId::new(i)));
        }
    }

    #[test]
    fn test_nested_conditionals() {
        // if (a) { if (b) { return 1; } return 2; } return 0;
        let mut asm = InstructionAssembler::new();
        asm.ldarg_0()
            .unwrap()
            .brfalse_s("outer_else")
            .unwrap()
            .ldarg_1()
            .unwrap()
            .brfalse_s("inner_else")
            .unwrap()
            .ldc_i4_1()
            .unwrap()
            .ret()
            .unwrap()
            .label("inner_else")
            .unwrap()
            .ldc_i4_2()
            .unwrap()
            .ret()
            .unwrap()
            .label("outer_else")
            .unwrap()
            .ldc_i4_0()
            .unwrap()
            .ret()
            .unwrap();

        let cfg = build_cfg(asm);

        // Should have 5 blocks
        assert_eq!(cfg.block_count(), 5);
        assert!(!cfg.has_loops());

        // Should have 3 exit points
        assert_eq!(cfg.exits().len(), 3);
    }

    #[test]
    fn test_simple_while_loop() {
        // while (arg0 > 0) { arg0--; } return arg0;
        let mut asm = InstructionAssembler::new();
        asm.label("loop_header")
            .unwrap()
            .ldarg_0()
            .unwrap()
            .ldc_i4_0()
            .unwrap()
            .ble_s("loop_exit")
            .unwrap() // if (arg0 <= 0) goto exit
            .ldarg_0()
            .unwrap()
            .ldc_i4_1()
            .unwrap()
            .sub()
            .unwrap()
            .starg_s(0)
            .unwrap() // arg0--
            .br_s("loop_header")
            .unwrap() // back edge
            .label("loop_exit")
            .unwrap()
            .ldarg_0()
            .unwrap()
            .ret()
            .unwrap();

        let cfg = build_cfg(asm);

        // Should have 3 blocks: header, body (combined with back jump), exit
        assert!(cfg.block_count() >= 2);
        assert!(cfg.has_loops());

        // Should have exactly 1 loop
        let loops = cfg.loops();
        assert_eq!(loops.len(), 1);

        let the_loop = &loops[0];
        // Header should be block 0 (loop_header label is at start)
        assert_eq!(the_loop.header, NodeId::new(0));

        // Loop should have at least 1 back edge
        assert!(!the_loop.back_edges.is_empty());

        // Header dominates all loop body blocks
        for &body_node in &the_loop.body {
            assert!(cfg.dominates(the_loop.header, body_node));
        }
    }

    #[test]
    fn test_do_while_loop() {
        // do { arg0--; } while (arg0 > 0); return arg0;
        let mut asm = InstructionAssembler::new();
        asm.label("loop_body")
            .unwrap()
            .ldarg_0()
            .unwrap()
            .ldc_i4_1()
            .unwrap()
            .sub()
            .unwrap()
            .starg_s(0)
            .unwrap() // arg0--
            .ldarg_0()
            .unwrap()
            .ldc_i4_0()
            .unwrap()
            .bgt_s("loop_body")
            .unwrap() // back edge if arg0 > 0
            .ldarg_0()
            .unwrap()
            .ret()
            .unwrap();

        let cfg = build_cfg(asm);

        assert!(cfg.has_loops());
        let loops = cfg.loops();
        assert_eq!(loops.len(), 1);

        // In a do-while, the header is also the body start
        let the_loop = &loops[0];
        assert_eq!(the_loop.header, NodeId::new(0));
    }

    #[test]
    fn test_nested_loops() {
        // for (i = 0; i < n; i++) { for (j = 0; j < m; j++) { ... } }
        let mut asm = InstructionAssembler::new();
        // Outer loop: i = arg0
        asm.ldarg_0()
            .unwrap()
            .stloc_0()
            .unwrap()
            .label("outer_header")
            .unwrap()
            .ldloc_0()
            .unwrap()
            .ldc_i4_0()
            .unwrap()
            .ble_s("outer_exit")
            .unwrap()
            // Inner loop: j = arg1
            .ldarg_1()
            .unwrap()
            .stloc_1()
            .unwrap()
            .label("inner_header")
            .unwrap()
            .ldloc_1()
            .unwrap()
            .ldc_i4_0()
            .unwrap()
            .ble_s("inner_exit")
            .unwrap()
            // Inner body: j--
            .ldloc_1()
            .unwrap()
            .ldc_i4_1()
            .unwrap()
            .sub()
            .unwrap()
            .stloc_1()
            .unwrap()
            .br_s("inner_header")
            .unwrap() // inner back edge
            .label("inner_exit")
            .unwrap()
            // Outer: i--
            .ldloc_0()
            .unwrap()
            .ldc_i4_1()
            .unwrap()
            .sub()
            .unwrap()
            .stloc_0()
            .unwrap()
            .br_s("outer_header")
            .unwrap() // outer back edge
            .label("outer_exit")
            .unwrap()
            .ldc_i4_0()
            .unwrap()
            .ret()
            .unwrap();

        let cfg = build_cfg(asm);

        assert!(cfg.has_loops());
        let loops = cfg.loops();
        assert_eq!(loops.len(), 2);

        // Find inner and outer loops by checking nesting
        let outer_loop = loops.iter().find(|l| l.depth == 0).unwrap();
        let inner_loop = loops.iter().find(|l| l.depth == 1).unwrap();

        // Inner loop should be contained within outer loop's body
        assert!(outer_loop.body.contains(&inner_loop.header));

        // innermost_loop should return the inner loop for nodes in it
        for &node in &inner_loop.body {
            let innermost = cfg.innermost_loop(node);
            assert!(innermost.is_some());
            assert_eq!(innermost.unwrap().header, inner_loop.header);
        }
    }

    #[test]
    fn test_dominator_diamond() {
        // Diamond pattern: entry -> A, entry -> B, A -> merge, B -> merge
        let mut asm = InstructionAssembler::new();
        asm.ldarg_0()
            .unwrap()
            .brfalse_s("b_path")
            .unwrap()
            // A path
            .nop()
            .unwrap()
            .br_s("merge")
            .unwrap()
            .label("b_path")
            .unwrap()
            // B path
            .nop()
            .unwrap()
            .label("merge")
            .unwrap()
            .ret()
            .unwrap();

        let cfg = build_cfg(asm);

        assert_eq!(cfg.block_count(), 4); // entry, A, B, merge

        // Entry dominates everything
        let entry = cfg.entry();
        for i in 0..cfg.block_count() {
            assert!(cfg.dominates(entry, NodeId::new(i)));
        }

        // Find merge block (has 2 predecessors)
        let merge = cfg
            .node_ids()
            .find(|&id| cfg.predecessors(id).count() == 2)
            .unwrap();

        // A and B do NOT dominate merge (alternative paths exist)
        let a_path = NodeId::new(1); // First block after entry's conditional
        let b_path = NodeId::new(2);

        // Neither A nor B strictly dominates merge
        assert!(
            !cfg.dominators().strictly_dominates(a_path, merge)
                || !cfg.dominators().strictly_dominates(b_path, merge)
        );

        // idom(merge) should be entry
        assert_eq!(cfg.idom(merge), Some(entry));
    }

    #[test]
    fn test_dominance_frontiers() {
        // Diamond pattern for phi node placement test
        let mut asm = InstructionAssembler::new();
        asm.ldarg_0()
            .unwrap()
            .brfalse_s("else")
            .unwrap()
            .ldc_i4_1()
            .unwrap()
            .br_s("merge")
            .unwrap()
            .label("else")
            .unwrap()
            .ldc_i4_0()
            .unwrap()
            .label("merge")
            .unwrap()
            .ret()
            .unwrap();

        let cfg = build_cfg(asm);

        let frontiers = cfg.dominance_frontiers();

        // The dominance frontiers should be computed
        assert!(!frontiers.is_empty());

        // Entry's frontier should be empty (it dominates everything)
        assert!(frontiers[cfg.entry().index()].is_empty());
    }

    #[test]
    fn test_reverse_postorder_respects_edges() {
        // Build a simple diamond and verify RPO properties
        let mut asm = InstructionAssembler::new();
        asm.ldarg_0()
            .unwrap()
            .brfalse_s("b")
            .unwrap()
            .nop()
            .unwrap()
            .br_s("merge")
            .unwrap()
            .label("b")
            .unwrap()
            .nop()
            .unwrap()
            .label("merge")
            .unwrap()
            .ret()
            .unwrap();

        let cfg = build_cfg(asm);

        let rpo = cfg.reverse_postorder();

        // Entry should be first
        assert_eq!(rpo[0], cfg.entry());

        // For forward dataflow: predecessors should come before successors (for acyclic parts)
        // This means entry should appear before its successors in RPO
        let entry_pos = rpo.iter().position(|&n| n == cfg.entry()).unwrap();
        for succ in cfg.successors(cfg.entry()) {
            let succ_pos = rpo.iter().position(|&n| n == succ).unwrap();
            assert!(
                entry_pos < succ_pos,
                "Entry should come before successors in RPO"
            );
        }
    }

    #[test]
    fn test_postorder_respects_edges() {
        let mut asm = InstructionAssembler::new();
        asm.ldarg_0()
            .unwrap()
            .ldarg_1()
            .unwrap()
            .add()
            .unwrap()
            .ret()
            .unwrap();

        let cfg = build_cfg(asm);

        let po = cfg.postorder();
        let rpo = cfg.reverse_postorder();

        // Postorder should be reverse of reverse-postorder
        assert_eq!(po.len(), rpo.len());
        for (i, node) in po.iter().enumerate() {
            assert_eq!(*node, rpo[rpo.len() - 1 - i]);
        }
    }

    #[test]
    fn test_unreachable_after_unconditional_branch() {
        // Code after unconditional branch should create separate block
        let mut asm = InstructionAssembler::new();
        asm.br_s("target")
            .unwrap()
            .nop()
            .unwrap() // This is "unreachable" but still encoded
            .label("target")
            .unwrap()
            .ret()
            .unwrap();

        let cfg = build_cfg(asm);

        // The decoder should still create blocks for unreachable code
        // but they won't be connected to the main flow
        assert!(cfg.block_count() >= 2);
    }

    #[test]
    fn test_multiple_returns() {
        // Function with early returns
        let mut asm = InstructionAssembler::new();
        asm.ldarg_0()
            .unwrap()
            .brfalse_s("check2")
            .unwrap()
            .ldc_i4_1()
            .unwrap()
            .ret()
            .unwrap() // Early return 1
            .label("check2")
            .unwrap()
            .ldarg_1()
            .unwrap()
            .brfalse_s("default")
            .unwrap()
            .ldc_i4_2()
            .unwrap()
            .ret()
            .unwrap() // Early return 2
            .label("default")
            .unwrap()
            .ldc_i4_0()
            .unwrap()
            .ret()
            .unwrap(); // Default return

        let cfg = build_cfg(asm);

        // Should have 3 exit blocks
        assert_eq!(cfg.exits().len(), 3);

        // No loops
        assert!(!cfg.has_loops());
    }
}
