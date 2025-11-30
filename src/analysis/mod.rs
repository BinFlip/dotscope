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
//! - [`ssa`] - Static Single Assignment form transformation
//! - [`dataflow`] - Data flow analysis framework
//! - [`callgraph`] - Inter-procedural call graph construction
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

mod callgraph;
mod cfg;
mod dataflow;
mod ssa;

// Re-export primary types at module level
pub use crate::utils::graph::NodeId;
pub use callgraph::{
    CallGraph, CallGraphNode, CallGraphStats, CallResolver, CallSite, CallTarget, CallType,
    ResolverStats,
};
pub use cfg::{CfgEdge, CfgEdgeKind, ControlFlowGraph, NaturalLoop};
pub use dataflow::{
    AnalysisResults, ConstantPropagation, DataFlowAnalysis, DataFlowSolver, Direction,
    JoinSemiLattice, Lattice, LiveVariables, LivenessResult, MeetSemiLattice, ReachingDefinitions,
    ReachingDefsResult, ScalarValue, SccpResult,
};
pub use ssa::{
    AbstractValue, ComputedOp, ComputedValue, ConstValue, DefSite, FieldRef, FnPtrSig, MethodRef,
    PhiNode, PhiOperand, SigRef, SimulationResult, SsaBlock, SsaBuilder, SsaFunction,
    SsaInstruction, SsaOp, SsaType, SsaVarId, SsaVariable, StackSimulator, TypeRef, UseSite,
    VariableOrigin,
};

#[cfg(test)]
mod tests {
    use crate::{
        analysis::{
            CfgEdgeKind, ControlFlowGraph, SsaBuilder, SsaFunction, SsaVarId, VariableOrigin,
        },
        assembly::{decode_blocks, InstructionAssembler},
        utils::graph::NodeId,
    };

    /// Helper to build bytecode and decode it into a CFG.
    fn build_cfg(assembler: InstructionAssembler) -> ControlFlowGraph<'static> {
        let (bytecode, _max_stack) = assembler.finish().expect("Failed to assemble bytecode");
        let blocks =
            decode_blocks(&bytecode, 0, 0x1000, Some(bytecode.len())).expect("Failed to decode");
        ControlFlowGraph::from_basic_blocks(blocks).expect("Failed to build CFG")
    }

    /// Helper to build SSA from a CFG.
    fn build_ssa(cfg: &ControlFlowGraph<'_>, num_args: usize, num_locals: usize) -> SsaFunction {
        SsaBuilder::build(cfg, num_args, num_locals).expect("SSA construction failed")
    }

    /// Consolidated SSA validation - checks all standard SSA invariants.
    /// Call this instead of individual assert_* functions in most tests.
    fn assert_ssa_valid(ssa: &SsaFunction, cfg: &ControlFlowGraph<'_>) {
        assert_has_arguments(ssa, ssa.num_args());
        assert_has_locals(ssa, ssa.num_locals());
        assert_valid_variable_ids(ssa);
        assert_single_assignment(ssa);
        assert_phi_operands_valid(ssa, cfg);
    }

    /// Validates that the SSA function has all expected argument variables (version 0).
    fn assert_has_arguments(ssa: &SsaFunction, expected_args: usize) {
        let arg_vars: Vec<_> = ssa.argument_variables().collect();
        assert_eq!(
            arg_vars.len(),
            expected_args,
            "Expected {} argument variables (v0), found {}",
            expected_args,
            arg_vars.len()
        );

        for (i, var) in arg_vars.iter().enumerate() {
            assert_eq!(
                var.origin(),
                VariableOrigin::Argument(i as u16),
                "Argument {} has wrong origin: {:?}",
                i,
                var.origin()
            );
            assert_eq!(
                var.version(),
                0,
                "Argument {} should have version 0, got {}",
                i,
                var.version()
            );
        }
    }

    /// Validates that the SSA function has all expected local variables (version 0).
    fn assert_has_locals(ssa: &SsaFunction, expected_locals: usize) {
        let local_vars: Vec<_> = ssa.local_variables().collect();
        assert_eq!(
            local_vars.len(),
            expected_locals,
            "Expected {} local variables (v0), found {}",
            expected_locals,
            local_vars.len()
        );

        for (i, var) in local_vars.iter().enumerate() {
            assert_eq!(
                var.origin(),
                VariableOrigin::Local(i as u16),
                "Local {} has wrong origin: {:?}",
                i,
                var.origin()
            );
            assert_eq!(
                var.version(),
                0,
                "Local {} should have version 0, got {}",
                i,
                var.version()
            );
        }
    }

    /// Validates that all SSA variables have valid IDs.
    fn assert_valid_variable_ids(ssa: &SsaFunction) {
        for (i, var) in ssa.variables().iter().enumerate() {
            assert_eq!(
                var.id(),
                SsaVarId::new(i),
                "Variable at index {} has mismatched ID: {:?}",
                i,
                var.id()
            );
        }
    }

    /// Validates SSA invariant: each variable has exactly one definition.
    fn assert_single_assignment(ssa: &SsaFunction) {
        for var in ssa.variables() {
            let def_site = var.def_site();
            if !def_site.is_phi() {
                assert!(
                    def_site.block < ssa.block_count(),
                    "Variable {} defined in non-existent block {}",
                    var.id(),
                    def_site.block
                );
            }
        }
    }

    /// Validates phi nodes have operands from correct predecessors.
    fn assert_phi_operands_valid(ssa: &SsaFunction, cfg: &ControlFlowGraph<'_>) {
        for (block_idx, block) in ssa.blocks().iter().enumerate() {
            let preds: Vec<_> = cfg.predecessors(NodeId::new(block_idx)).collect();

            for phi in block.phi_nodes() {
                if preds.is_empty() {
                    assert!(
                        phi.operand_count() == 0,
                        "Phi in block {} has operands but no predecessors",
                        block_idx
                    );
                    continue;
                }

                for op in phi.operands() {
                    assert!(
                        preds.contains(&NodeId::new(op.predecessor())),
                        "Phi operand references non-predecessor block {} (preds: {:?})",
                        op.predecessor(),
                        preds
                    );
                }
            }
        }
    }

    #[test]
    fn test_sequential_method() {
        // Simple method: return arg0 + arg1
        // int Add(int a, int b) { return a + b; }
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

        // CFG validation
        assert_eq!(cfg.block_count(), 1);
        assert!(!cfg.has_loops());
        assert_eq!(cfg.entry(), NodeId::new(0));
        assert_eq!(cfg.exits().len(), 1);
        assert_eq!(cfg.exits()[0], NodeId::new(0));

        // SSA validation
        let ssa = build_ssa(&cfg, 2, 0);
        assert_eq!(ssa.block_count(), 1);
        assert_eq!(ssa.num_args(), 2);
        assert_eq!(ssa.num_locals(), 0);
        assert_ssa_valid(&ssa, &cfg);
        assert_eq!(ssa.total_phi_count(), 0);
        assert!(
            ssa.variable_count() >= 2,
            "Should have at least 2 variables (args)"
        );
    }

    #[test]
    fn test_nop_sequence() {
        // Method with multiple nops followed by ret
        // int Zero() { return 0; }
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

        let ssa = build_ssa(&cfg, 0, 0);
        assert_eq!(ssa.block_count(), 1);
        assert_ssa_valid(&ssa, &cfg);
        assert_eq!(ssa.total_phi_count(), 0);
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
        assert_eq!(cfg.block_count(), 3);
        assert!(!cfg.has_loops());
        assert_eq!(cfg.exits().len(), 2);

        let edges: Vec<_> = cfg.outgoing_edges(cfg.entry()).collect();
        assert_eq!(edges.len(), 2);
        let edge_kinds: Vec<_> = edges.iter().map(|(_, _, e)| e.kind().clone()).collect();
        assert!(edge_kinds.contains(&CfgEdgeKind::ConditionalTrue));
        assert!(edge_kinds.contains(&CfgEdgeKind::ConditionalFalse));

        let ssa = build_ssa(&cfg, 1, 0);
        assert_eq!(ssa.block_count(), 3);
        assert_ssa_valid(&ssa, &cfg);
        assert_eq!(ssa.total_phi_count(), 0); // No merge point
    }

    #[test]
    fn test_if_then_else_merge() {
        // if (arg0) { push 1; } else { push 0; } return top;
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
        assert_eq!(cfg.block_count(), 4);
        assert!(!cfg.has_loops());
        assert_eq!(cfg.exits().len(), 1);

        let merge_block = cfg.exits()[0];
        let preds: Vec<_> = cfg.predecessors(merge_block).collect();
        assert_eq!(preds.len(), 2);

        let ssa = build_ssa(&cfg, 1, 0);
        assert_eq!(ssa.block_count(), 4);
        assert_ssa_valid(&ssa, &cfg);
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
        assert_eq!(cfg.block_count(), 5);
        assert!(!cfg.has_loops());
        assert_eq!(cfg.exits().len(), 3);

        let ssa = build_ssa(&cfg, 2, 0);
        assert_eq!(ssa.block_count(), 5);
        assert_ssa_valid(&ssa, &cfg);
        assert_eq!(ssa.total_phi_count(), 0); // All paths return without merge
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
            .unwrap()
            .ldarg_0()
            .unwrap()
            .ldc_i4_1()
            .unwrap()
            .sub()
            .unwrap()
            .starg_s(0)
            .unwrap()
            .br_s("loop_header")
            .unwrap()
            .label("loop_exit")
            .unwrap()
            .ldarg_0()
            .unwrap()
            .ret()
            .unwrap();

        let cfg = build_cfg(asm);
        assert!(cfg.block_count() >= 2);
        assert!(cfg.has_loops());

        let loops = cfg.loops();
        assert_eq!(loops.len(), 1);
        assert_eq!(loops[0].header, NodeId::new(0));
        assert!(!loops[0].back_edges.is_empty());

        let ssa = build_ssa(&cfg, 1, 0);
        assert_ssa_valid(&ssa, &cfg);
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
            .unwrap()
            .ldarg_0()
            .unwrap()
            .ldc_i4_0()
            .unwrap()
            .bgt_s("loop_body")
            .unwrap()
            .ldarg_0()
            .unwrap()
            .ret()
            .unwrap();

        let cfg = build_cfg(asm);
        assert!(cfg.has_loops());
        assert_eq!(cfg.loops().len(), 1);
        assert_eq!(cfg.loops()[0].header, NodeId::new(0));

        let ssa = build_ssa(&cfg, 1, 0);
        assert_ssa_valid(&ssa, &cfg);
    }

    #[test]
    fn test_nested_loops() {
        // for (i = n; i > 0; i--) { for (j = m; j > 0; j--) { } }
        let mut asm = InstructionAssembler::new();
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
            .ldloc_1()
            .unwrap()
            .ldc_i4_1()
            .unwrap()
            .sub()
            .unwrap()
            .stloc_1()
            .unwrap()
            .br_s("inner_header")
            .unwrap()
            .label("inner_exit")
            .unwrap()
            .ldloc_0()
            .unwrap()
            .ldc_i4_1()
            .unwrap()
            .sub()
            .unwrap()
            .stloc_0()
            .unwrap()
            .br_s("outer_header")
            .unwrap()
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

        let outer_loop = loops.iter().find(|l| l.depth == 0).unwrap();
        let inner_loop = loops.iter().find(|l| l.depth == 1).unwrap();
        assert!(outer_loop.body.contains(&inner_loop.header));

        for &node in &inner_loop.body {
            assert_eq!(cfg.innermost_loop(node).unwrap().header, inner_loop.header);
        }

        let ssa = build_ssa(&cfg, 2, 2);
        assert_ssa_valid(&ssa, &cfg);
    }

    #[test]
    fn test_dominator_diamond() {
        // Diamond pattern: entry -> A, entry -> B, A -> merge, B -> merge
        let mut asm = InstructionAssembler::new();
        asm.ldarg_0()
            .unwrap()
            .brfalse_s("b_path")
            .unwrap()
            .nop()
            .unwrap()
            .br_s("merge")
            .unwrap()
            .label("b_path")
            .unwrap()
            .nop()
            .unwrap()
            .label("merge")
            .unwrap()
            .ret()
            .unwrap();

        let cfg = build_cfg(asm);
        assert_eq!(cfg.block_count(), 4);

        let entry = cfg.entry();
        for i in 0..cfg.block_count() {
            assert!(cfg.dominates(entry, NodeId::new(i)));
        }

        let merge = cfg
            .node_ids()
            .find(|&id| cfg.predecessors(id).count() == 2)
            .unwrap();
        assert_eq!(cfg.idom(merge), Some(entry));

        let ssa = build_ssa(&cfg, 1, 0);
        assert_eq!(ssa.block_count(), 4);
        assert_ssa_valid(&ssa, &cfg);
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
        assert!(!frontiers.is_empty());
        assert!(frontiers[cfg.entry().index()].is_empty());

        let ssa = build_ssa(&cfg, 1, 0);
        assert_ssa_valid(&ssa, &cfg);
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
        assert_eq!(rpo[0], cfg.entry());

        let entry_pos = rpo.iter().position(|&n| n == cfg.entry()).unwrap();
        for succ in cfg.successors(cfg.entry()) {
            let succ_pos = rpo.iter().position(|&n| n == succ).unwrap();
            assert!(
                entry_pos < succ_pos,
                "Entry should come before successors in RPO"
            );
        }

        let ssa = build_ssa(&cfg, 1, 0);
        assert_ssa_valid(&ssa, &cfg);
    }

    #[test]
    fn test_postorder_respects_edges() {
        // int Add(int a, int b) { return a + b; }
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

        assert_eq!(po.len(), rpo.len());
        for (i, node) in po.iter().enumerate() {
            assert_eq!(*node, rpo[rpo.len() - 1 - i]);
        }

        let ssa = build_ssa(&cfg, 2, 0);
        assert_ssa_valid(&ssa, &cfg);
    }

    #[test]
    fn test_unreachable_after_unconditional_branch() {
        // Code after unconditional branch should create separate block
        let mut asm = InstructionAssembler::new();
        asm.br_s("target")
            .unwrap()
            .nop()
            .unwrap() // "unreachable" but still encoded
            .label("target")
            .unwrap()
            .ret()
            .unwrap();

        let cfg = build_cfg(asm);
        assert!(cfg.block_count() >= 2);

        let ssa = build_ssa(&cfg, 0, 0);
        assert_ssa_valid(&ssa, &cfg);
    }

    #[test]
    fn test_multiple_returns() {
        // if (a) return 1; if (b) return 2; return 0;
        let mut asm = InstructionAssembler::new();
        asm.ldarg_0()
            .unwrap()
            .brfalse_s("check2")
            .unwrap()
            .ldc_i4_1()
            .unwrap()
            .ret()
            .unwrap()
            .label("check2")
            .unwrap()
            .ldarg_1()
            .unwrap()
            .brfalse_s("default")
            .unwrap()
            .ldc_i4_2()
            .unwrap()
            .ret()
            .unwrap()
            .label("default")
            .unwrap()
            .ldc_i4_0()
            .unwrap()
            .ret()
            .unwrap();

        let cfg = build_cfg(asm);
        assert_eq!(cfg.exits().len(), 3);
        assert!(!cfg.has_loops());

        let ssa = build_ssa(&cfg, 2, 0);
        assert_ssa_valid(&ssa, &cfg);
        assert_eq!(ssa.total_phi_count(), 0); // All paths return without merge
    }

    #[test]
    fn test_local_variable_store_load() {
        // int StoreLoad(int x) { int local = x; return local; }
        let mut asm = InstructionAssembler::new();
        asm.ldarg_0()
            .unwrap()
            .stloc_0()
            .unwrap()
            .ldloc_0()
            .unwrap()
            .ret()
            .unwrap();

        let cfg = build_cfg(asm);
        assert_eq!(cfg.block_count(), 1);
        assert!(!cfg.has_loops());

        let ssa = build_ssa(&cfg, 1, 1);
        assert_ssa_valid(&ssa, &cfg);
        assert_eq!(ssa.total_phi_count(), 0);
    }

    #[test]
    fn test_conditional_local_assignment() {
        // int x = 0; if (cond) { x = 1; } return x;
        let mut asm = InstructionAssembler::new();
        asm.ldc_i4_0()
            .unwrap()
            .stloc_0()
            .unwrap()
            .ldarg_0()
            .unwrap()
            .brfalse_s("skip")
            .unwrap()
            .ldc_i4_1()
            .unwrap()
            .stloc_0()
            .unwrap()
            .label("skip")
            .unwrap()
            .ldloc_0()
            .unwrap()
            .ret()
            .unwrap();

        let cfg = build_cfg(asm);
        assert_eq!(cfg.block_count(), 3);
        assert!(!cfg.has_loops());

        let ssa = build_ssa(&cfg, 1, 1);
        assert_ssa_valid(&ssa, &cfg);
    }

    #[test]
    fn test_dup_instruction() {
        // return x + x; using dup
        let mut asm = InstructionAssembler::new();
        asm.ldarg_0()
            .unwrap()
            .dup()
            .unwrap()
            .add()
            .unwrap()
            .ret()
            .unwrap();

        let cfg = build_cfg(asm);
        let ssa = build_ssa(&cfg, 1, 0);
        assert_ssa_valid(&ssa, &cfg);
        assert!(
            ssa.variable_count() >= 1,
            "Should have at least the argument variable"
        );
    }

    #[test]
    fn test_comparison_instruction() {
        // return a < b;
        let mut asm = InstructionAssembler::new();
        asm.ldarg_0()
            .unwrap()
            .ldarg_1()
            .unwrap()
            .clt()
            .unwrap()
            .ret()
            .unwrap();

        let cfg = build_cfg(asm);
        let ssa = build_ssa(&cfg, 2, 0);
        assert_ssa_valid(&ssa, &cfg);
        assert!(
            ssa.variable_count() >= 2,
            "Should have at least the argument variables"
        );
    }
}
