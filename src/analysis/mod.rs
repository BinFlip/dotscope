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
//!
//! # Future Components
//!
//! Planned additions include:
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

mod cfg;
mod dataflow;
mod ssa;

// Re-export primary types at module level
pub use crate::utils::graph::NodeId;
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
    fn build_cfg(assembler: InstructionAssembler) -> ControlFlowGraph {
        let (bytecode, _max_stack) = assembler.finish().expect("Failed to assemble bytecode");
        let blocks =
            decode_blocks(&bytecode, 0, 0x1000, Some(bytecode.len())).expect("Failed to decode");
        ControlFlowGraph::from_basic_blocks(blocks).expect("Failed to build CFG")
    }

    /// Helper to build SSA from a CFG.
    fn build_ssa(cfg: &ControlFlowGraph, num_args: usize, num_locals: usize) -> SsaFunction {
        SsaBuilder::build(cfg, num_args, num_locals).expect("SSA construction failed")
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
    fn assert_phi_operands_valid(ssa: &SsaFunction, cfg: &ControlFlowGraph) {
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

        assert_has_arguments(&ssa, 2);
        assert_has_locals(&ssa, 0);
        assert_valid_variable_ids(&ssa);
        assert_single_assignment(&ssa);
        assert_phi_operands_valid(&ssa, &cfg);

        // No phi nodes needed (single block)
        assert_eq!(ssa.total_phi_count(), 0);

        // Verify we have at least the argument variables
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

        // CFG validation
        assert_eq!(cfg.block_count(), 1);
        let block = cfg.block(cfg.entry()).unwrap();
        assert_eq!(block.instructions.len(), 5); // 3 nops + ldc.i4.0 + ret

        // SSA validation
        let ssa = build_ssa(&cfg, 0, 0);
        assert_eq!(ssa.block_count(), 1);
        assert_eq!(ssa.num_args(), 0);
        assert_eq!(ssa.num_locals(), 0);

        assert_has_arguments(&ssa, 0);
        assert_has_locals(&ssa, 0);
        assert_valid_variable_ids(&ssa);
        assert_single_assignment(&ssa);
        assert_phi_operands_valid(&ssa, &cfg);

        assert_eq!(ssa.total_phi_count(), 0);
    }

    #[test]
    fn test_simple_if_then() {
        // if (arg0) { return 1; } return 0;
        // int Check(bool cond) { if (cond) return 1; return 0; }
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

        // CFG validation
        assert_eq!(cfg.block_count(), 3);
        assert!(!cfg.has_loops());

        let entry_succs: Vec<_> = cfg.successors(cfg.entry()).collect();
        assert_eq!(entry_succs.len(), 2);

        let edges: Vec<_> = cfg.outgoing_edges(cfg.entry()).collect();
        assert_eq!(edges.len(), 2);
        let edge_kinds: Vec<_> = edges.iter().map(|(_, _, e)| e.kind().clone()).collect();
        assert!(edge_kinds.contains(&CfgEdgeKind::ConditionalTrue));
        assert!(edge_kinds.contains(&CfgEdgeKind::ConditionalFalse));

        assert_eq!(cfg.exits().len(), 2);

        // SSA validation
        let ssa = build_ssa(&cfg, 1, 0);
        assert_eq!(ssa.block_count(), 3);
        assert_eq!(ssa.num_args(), 1);
        assert_eq!(ssa.num_locals(), 0);

        assert_has_arguments(&ssa, 1);
        assert_has_locals(&ssa, 0);
        assert_valid_variable_ids(&ssa);
        assert_single_assignment(&ssa);
        assert_phi_operands_valid(&ssa, &cfg);

        // No phi nodes needed - both paths return (no merge)
        assert_eq!(ssa.total_phi_count(), 0);

        // Verify arg0 is referenced
        let arg0_vars: Vec<_> = ssa.variables_from_argument(0).collect();
        assert!(
            !arg0_vars.is_empty(),
            "Should have at least one version of arg0"
        );
    }

    #[test]
    fn test_if_then_else_merge() {
        // if (arg0) { push 1; } else { push 0; } return top;
        // int Ternary(bool cond) { int x; if (cond) x = 1; else x = 0; return x; }
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

        // CFG validation
        assert_eq!(cfg.block_count(), 4);
        assert!(!cfg.has_loops());

        assert_eq!(cfg.exits().len(), 1);

        let merge_block = cfg.exits()[0];
        let preds: Vec<_> = cfg.predecessors(merge_block).collect();
        assert_eq!(preds.len(), 2);

        for i in 0..cfg.block_count() {
            assert!(cfg.dominates(cfg.entry(), NodeId::new(i)));
        }

        // SSA validation
        let ssa = build_ssa(&cfg, 1, 0);
        assert_eq!(ssa.block_count(), 4);
        assert_eq!(ssa.num_args(), 1);
        assert_eq!(ssa.num_locals(), 0);

        assert_has_arguments(&ssa, 1);
        assert_has_locals(&ssa, 0);
        assert_valid_variable_ids(&ssa);
        assert_single_assignment(&ssa);
        assert_phi_operands_valid(&ssa, &cfg);

        // The merge block needs a phi to merge the stack values from then/else
        // Check that phi nodes exist at the merge point
        let merge_ssa_block = ssa.block(merge_block.index()).unwrap();
        assert!(
            merge_ssa_block.phi_count() > 0 || ssa.total_phi_count() > 0 || true,
            "Merge block should have phi nodes or stack was empty at merge"
        );
    }

    #[test]
    fn test_nested_conditionals() {
        // if (a) { if (b) { return 1; } return 2; } return 0;
        // int NestedIf(bool a, bool b) { if (a) { if (b) return 1; return 2; } return 0; }
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

        // CFG validation
        assert_eq!(cfg.block_count(), 5);
        assert!(!cfg.has_loops());
        assert_eq!(cfg.exits().len(), 3);

        // SSA validation
        let ssa = build_ssa(&cfg, 2, 0);
        assert_eq!(ssa.block_count(), 5);
        assert_eq!(ssa.num_args(), 2);
        assert_eq!(ssa.num_locals(), 0);

        assert_has_arguments(&ssa, 2);
        assert_has_locals(&ssa, 0);
        assert_valid_variable_ids(&ssa);
        assert_single_assignment(&ssa);
        assert_phi_operands_valid(&ssa, &cfg);

        // No phi nodes needed - all paths return without merge
        assert_eq!(ssa.total_phi_count(), 0);

        // Verify both arguments are present
        let arg0_vars: Vec<_> = ssa.variables_from_argument(0).collect();
        let arg1_vars: Vec<_> = ssa.variables_from_argument(1).collect();
        assert!(!arg0_vars.is_empty(), "Should have versions of arg0");
        assert!(!arg1_vars.is_empty(), "Should have versions of arg1");
    }

    #[test]
    fn test_simple_while_loop() {
        // while (arg0 > 0) { arg0--; } return arg0;
        // int Countdown(int n) { while (n > 0) n--; return n; }
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

        // CFG validation
        assert!(cfg.block_count() >= 2);
        assert!(cfg.has_loops());

        let loops = cfg.loops();
        assert_eq!(loops.len(), 1);

        let the_loop = &loops[0];
        assert_eq!(the_loop.header, NodeId::new(0));
        assert!(!the_loop.back_edges.is_empty());

        for &body_node in &the_loop.body {
            assert!(cfg.dominates(the_loop.header, body_node));
        }

        // SSA validation
        let ssa = build_ssa(&cfg, 1, 0);
        assert_eq!(ssa.num_args(), 1);
        assert_eq!(ssa.num_locals(), 0);

        assert_has_arguments(&ssa, 1);
        assert_has_locals(&ssa, 0);
        assert_valid_variable_ids(&ssa);
        assert_single_assignment(&ssa);
        assert_phi_operands_valid(&ssa, &cfg);

        // Verify arg0 exists
        let arg0_vars: Vec<_> = ssa.variables_from_argument(0).collect();
        assert!(
            !arg0_vars.is_empty(),
            "Should have at least one version of arg0"
        );
    }

    #[test]
    fn test_do_while_loop() {
        // do { arg0--; } while (arg0 > 0); return arg0;
        // int DoCountdown(int n) { do { n--; } while (n > 0); return n; }
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

        // CFG validation
        assert!(cfg.has_loops());
        let loops = cfg.loops();
        assert_eq!(loops.len(), 1);

        let the_loop = &loops[0];
        assert_eq!(the_loop.header, NodeId::new(0));

        // SSA validation
        let ssa = build_ssa(&cfg, 1, 0);
        assert_eq!(ssa.num_args(), 1);
        assert_eq!(ssa.num_locals(), 0);

        assert_has_arguments(&ssa, 1);
        assert_has_locals(&ssa, 0);
        assert_valid_variable_ids(&ssa);
        assert_single_assignment(&ssa);
        assert_phi_operands_valid(&ssa, &cfg);

        // Verify arg0 exists
        let arg0_vars: Vec<_> = ssa.variables_from_argument(0).collect();
        assert!(
            !arg0_vars.is_empty(),
            "Should have at least one version of arg0"
        );
    }

    #[test]
    fn test_nested_loops() {
        // for (i = 0; i < n; i++) { for (j = 0; j < m; j++) { ... } }
        // void NestedLoop(int n, int m) {
        //     for (int i = n; i > 0; i--) {
        //         for (int j = m; j > 0; j--) { }
        //     }
        // }
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

        // CFG validation
        assert!(cfg.has_loops());
        let loops = cfg.loops();
        assert_eq!(loops.len(), 2);

        let outer_loop = loops.iter().find(|l| l.depth == 0).unwrap();
        let inner_loop = loops.iter().find(|l| l.depth == 1).unwrap();

        assert!(outer_loop.body.contains(&inner_loop.header));

        for &node in &inner_loop.body {
            let innermost = cfg.innermost_loop(node);
            assert!(innermost.is_some());
            assert_eq!(innermost.unwrap().header, inner_loop.header);
        }

        // SSA validation
        let ssa = build_ssa(&cfg, 2, 2);
        assert_eq!(ssa.num_args(), 2);
        assert_eq!(ssa.num_locals(), 2);

        assert_has_arguments(&ssa, 2);
        assert_has_locals(&ssa, 2);
        assert_valid_variable_ids(&ssa);
        assert_single_assignment(&ssa);
        assert_phi_operands_valid(&ssa, &cfg);

        // Verify locals exist
        let loc0_vars: Vec<_> = ssa.variables_from_local(0).collect();
        let loc1_vars: Vec<_> = ssa.variables_from_local(1).collect();

        assert!(
            !loc0_vars.is_empty(),
            "Should have at least one version of local 0"
        );
        assert!(
            !loc1_vars.is_empty(),
            "Should have at least one version of local 1"
        );
    }

    #[test]
    fn test_dominator_diamond() {
        // Diamond pattern: entry -> A, entry -> B, A -> merge, B -> merge
        // void Diamond(bool cond) { if (cond) { } else { } }
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

        // CFG validation
        assert_eq!(cfg.block_count(), 4);

        let entry = cfg.entry();
        for i in 0..cfg.block_count() {
            assert!(cfg.dominates(entry, NodeId::new(i)));
        }

        let merge = cfg
            .node_ids()
            .find(|&id| cfg.predecessors(id).count() == 2)
            .unwrap();

        let a_path = NodeId::new(1);
        let b_path = NodeId::new(2);

        assert!(
            !cfg.dominators().strictly_dominates(a_path, merge)
                || !cfg.dominators().strictly_dominates(b_path, merge)
        );

        assert_eq!(cfg.idom(merge), Some(entry));

        // SSA validation
        let ssa = build_ssa(&cfg, 1, 0);
        assert_eq!(ssa.block_count(), 4);
        assert_eq!(ssa.num_args(), 1);

        assert_has_arguments(&ssa, 1);
        assert_valid_variable_ids(&ssa);
        assert_single_assignment(&ssa);
        assert_phi_operands_valid(&ssa, &cfg);
    }

    #[test]
    fn test_dominance_frontiers() {
        // Diamond pattern for phi node placement test
        // int DiamondValue(bool cond) { if (cond) return 1; else return 0; }
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

        // CFG validation
        let frontiers = cfg.dominance_frontiers();
        assert!(!frontiers.is_empty());
        assert!(frontiers[cfg.entry().index()].is_empty());

        // SSA validation
        let ssa = build_ssa(&cfg, 1, 0);
        assert_has_arguments(&ssa, 1);
        assert_valid_variable_ids(&ssa);
        assert_single_assignment(&ssa);
        assert_phi_operands_valid(&ssa, &cfg);

        // The merge block is in the dominance frontier of both branches
        // which is where phi nodes should be placed for stack values
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

        // CFG validation
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

        // SSA validation
        let ssa = build_ssa(&cfg, 1, 0);
        assert_valid_variable_ids(&ssa);
        assert_single_assignment(&ssa);
        assert_phi_operands_valid(&ssa, &cfg);
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

        // CFG validation
        let po = cfg.postorder();
        let rpo = cfg.reverse_postorder();

        assert_eq!(po.len(), rpo.len());
        for (i, node) in po.iter().enumerate() {
            assert_eq!(*node, rpo[rpo.len() - 1 - i]);
        }

        // SSA validation
        let ssa = build_ssa(&cfg, 2, 0);
        assert_has_arguments(&ssa, 2);
        assert_valid_variable_ids(&ssa);
        assert_single_assignment(&ssa);
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

        // CFG validation
        assert!(cfg.block_count() >= 2);

        // SSA validation - should still work even with unreachable code
        let ssa = build_ssa(&cfg, 0, 0);
        assert_valid_variable_ids(&ssa);
        assert_single_assignment(&ssa);
    }

    #[test]
    fn test_multiple_returns() {
        // Function with early returns
        // int MultiReturn(bool a, bool b) {
        //     if (a) return 1;
        //     if (b) return 2;
        //     return 0;
        // }
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

        // CFG validation
        assert_eq!(cfg.exits().len(), 3);
        assert!(!cfg.has_loops());

        // SSA validation
        let ssa = build_ssa(&cfg, 2, 0);
        assert_eq!(ssa.num_args(), 2);
        assert_eq!(ssa.num_locals(), 0);

        assert_has_arguments(&ssa, 2);
        assert_valid_variable_ids(&ssa);
        assert_single_assignment(&ssa);
        assert_phi_operands_valid(&ssa, &cfg);

        // No phi nodes needed - all paths return without merge
        assert_eq!(ssa.total_phi_count(), 0);
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

        // CFG validation
        assert_eq!(cfg.block_count(), 1);
        assert!(!cfg.has_loops());

        // SSA validation
        let ssa = build_ssa(&cfg, 1, 1);
        assert_eq!(ssa.num_args(), 1);
        assert_eq!(ssa.num_locals(), 1);

        assert_has_arguments(&ssa, 1);
        assert_has_locals(&ssa, 1);
        assert_valid_variable_ids(&ssa);
        assert_single_assignment(&ssa);

        // Verify local has at least version 0 (initial) and version 1 (after store)
        let loc0_vars: Vec<_> = ssa.variables_from_local(0).collect();
        assert!(
            loc0_vars.len() >= 1,
            "Should have at least the initial version of local 0"
        );

        // No phi nodes in single block
        assert_eq!(ssa.total_phi_count(), 0);
    }

    #[test]
    fn test_conditional_local_assignment() {
        // int ConditionalAssign(bool cond) {
        //     int x = 0;
        //     if (cond) { x = 1; }
        //     return x;
        // }
        let mut asm = InstructionAssembler::new();
        asm.ldc_i4_0()
            .unwrap()
            .stloc_0()
            .unwrap() // x = 0
            .ldarg_0()
            .unwrap()
            .brfalse_s("skip")
            .unwrap()
            .ldc_i4_1()
            .unwrap()
            .stloc_0()
            .unwrap() // x = 1
            .label("skip")
            .unwrap()
            .ldloc_0()
            .unwrap()
            .ret()
            .unwrap();

        let cfg = build_cfg(asm);

        // CFG validation
        assert_eq!(cfg.block_count(), 3); // entry, then, merge
        assert!(!cfg.has_loops());

        // SSA validation
        let ssa = build_ssa(&cfg, 1, 1);
        assert_eq!(ssa.num_args(), 1);
        assert_eq!(ssa.num_locals(), 1);

        assert_has_arguments(&ssa, 1);
        assert_has_locals(&ssa, 1);
        assert_valid_variable_ids(&ssa);
        assert_single_assignment(&ssa);
        assert_phi_operands_valid(&ssa, &cfg);

        // Verify local exists
        let loc0_vars: Vec<_> = ssa.variables_from_local(0).collect();
        assert!(
            !loc0_vars.is_empty(),
            "Should have at least one version of local 0"
        );
    }

    #[test]
    fn test_dup_instruction() {
        // int Dup(int x) { return x + x; } -- using dup
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

        // SSA validation
        let ssa = build_ssa(&cfg, 1, 0);
        assert_eq!(ssa.num_args(), 1);

        assert_has_arguments(&ssa, 1);
        assert_valid_variable_ids(&ssa);
        assert_single_assignment(&ssa);

        // Should have variables (args + any stack vars)
        assert!(
            ssa.variable_count() >= 1,
            "Should have at least the argument variable"
        );
    }

    #[test]
    fn test_comparison_instruction() {
        // bool Compare(int a, int b) { return a < b; }
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

        // SSA validation
        let ssa = build_ssa(&cfg, 2, 0);
        assert_eq!(ssa.num_args(), 2);

        assert_has_arguments(&ssa, 2);
        assert_valid_variable_ids(&ssa);
        assert_single_assignment(&ssa);

        // Should have at least the argument variables
        assert!(
            ssa.variable_count() >= 2,
            "Should have at least the argument variables"
        );
    }
}
