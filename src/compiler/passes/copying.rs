//! Copy propagation pass.
//!
//! This pass eliminates redundant copy operations by replacing uses of
//! copy destinations with their sources. This simplifies the SSA graph
//! and enables further optimizations.
//!
//! # Example
//!
//! Before:
//! ```text
//! v1 = v0        // Copy
//! v2 = add v1, 5
//! ret v1
//! ```
//!
//! After (with v1 replaced by v0):
//! ```text
//! v1 = v0        // Can now be eliminated by DCE
//! v2 = add v0, 5
//! ret v0
//! ```
//!
//! # Algorithm
//!
//! The pass uses an iterative fixed-point algorithm:
//!
//! 1. Build a map of all copy-like operations:
//!    - Explicit `Copy` instructions
//!    - Trivial phi nodes (all operands identical after excluding self-references)
//! 2. Resolve copy chains to find ultimate sources (v2 → v1 → v0 becomes v2 → v0)
//! 3. Replace all uses of copy destinations with their ultimate sources
//! 4. Repeat until no more changes (fixed point)
//!
//! Dead code elimination will then remove the now-unused copy instructions.
//!
//! # Complexity
//!
//! - Time: O(n × m) where n is the number of variables and m is the number of iterations
//! - Space: O(n) for the copy map
//!
//! In practice, the algorithm converges quickly (usually 1-3 iterations).

use std::{collections::HashMap, sync::Arc};

use crate::{
    analysis::{PhiAnalyzer, SsaFunction, SsaType, SsaVarId, VariableOrigin},
    compiler::{pass::SsaPass, passes::utils::resolve_chain, CompilerContext, EventKind, EventLog},
    metadata::token::Token,
    CilObject, Result,
};

/// Maximum iterations for the fixed-point algorithm to prevent infinite loops.
const MAX_ITERATIONS: usize = 100;

/// Copy propagation pass.
///
/// Tracks copy operations and propagates the source to all uses of the copy.
/// Uses an iterative fixed-point algorithm to handle cascading copies and
/// newly exposed opportunities after each round of propagation.
///
/// # Handled Cases
///
/// - Direct copy instructions: `v1 = copy v0`
/// - Trivial phi nodes: `v1 = phi(v0, v0, v0)` (all operands identical)
/// - Self-referential phis: `v1 = phi(v0, v1)` → `v1 = v0`
/// - Copy chains: `v2 = v1; v1 = v0` → both map to `v0`
pub struct CopyPropagationPass;

impl Default for CopyPropagationPass {
    fn default() -> Self {
        Self::new()
    }
}

impl CopyPropagationPass {
    /// Creates a new copy propagation pass.
    ///
    /// # Returns
    ///
    /// A new `CopyPropagationPass` instance.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Resolves all copy chains to their ultimate sources.
    ///
    /// Uses the shared `resolve_chain` utility to follow each copy to its
    /// ultimate source, handling cycles correctly.
    ///
    /// # Arguments
    ///
    /// * `copies` - Map of direct copies (dest → immediate source).
    ///
    /// # Returns
    ///
    /// Map of each copy destination to its ultimate source.
    fn resolve_chains(copies: &HashMap<SsaVarId, SsaVarId>) -> HashMap<SsaVarId, SsaVarId> {
        copies
            .iter()
            .map(|(&dest, &src)| (dest, resolve_chain(copies, src)))
            .collect()
    }

    /// Runs a single iteration of copy propagation.
    ///
    /// # Arguments
    ///
    /// * `ssa` - The SSA function to modify.
    /// * `method_token` - The method token for change tracking.
    /// * `changes` - The change set to record modifications.
    /// * `assembly` - The assembly context for type resolution.
    ///
    /// # Returns
    ///
    /// The number of uses that were replaced.
    fn run_iteration(
        ssa: &mut SsaFunction,
        method_token: Token,
        changes: &mut EventLog,
        assembly: &CilObject,
    ) -> usize {
        // Step 1: Collect all copy-like operations
        let copies = PhiAnalyzer::new(ssa).collect_all_copies();

        if copies.is_empty() {
            return 0;
        }

        // Step 2: Resolve chains to ultimate sources
        let resolved = Self::resolve_chains(&copies);

        // Step 3: Propagate types from Local-origin destinations to their sources
        // This ensures that when copy propagation replaces uses of a local variable
        // with its source (e.g., a phi result), the source inherits the local's
        // original type. This is crucial for preserving type information in the
        // final generated code.
        Self::propagate_local_types(ssa, &resolved, assembly);

        // Step 4: Apply propagations
        // Note: replace_uses only affects instructions, not PHI operands. This is the
        // safe default that avoids creating cross-origin PHI operand references which
        // can break rebuild_ssa's assumption that each variable flows to at most one
        // PHI origin.
        let mut total_replaced = 0;

        for (dest, src) in &resolved {
            // Skip identity mappings (can happen with cycles)
            if dest == src {
                continue;
            }

            let replaced = ssa.replace_uses(*dest, *src);

            if replaced > 0 {
                changes
                    .record(EventKind::CopyPropagated)
                    .method(method_token)
                    .message(format!("{dest} → {src} ({replaced} uses)"));
                total_replaced += replaced;
            }
        }

        total_replaced
    }

    /// Propagates types from Local-origin destinations to their ultimate sources.
    ///
    /// When a Local-origin variable is a copy destination (e.g., `local_0 = copy phi_result`),
    /// the source variable should inherit the local's original type. This ensures that
    /// after copy propagation eliminates the intermediate copy, the source retains the
    /// correct type information for code generation.
    ///
    /// This follows the .NET JIT's approach of keeping local slot types (`lvType`)
    /// separate from IR/computational types (`gtType`), ensuring original types are
    /// preserved through optimization.
    fn propagate_local_types(
        ssa: &mut SsaFunction,
        resolved: &HashMap<SsaVarId, SsaVarId>,
        assembly: &CilObject,
    ) {
        // Get the original local types from the SSA function
        let original_types = match ssa.original_local_types() {
            Some(types) => types.to_vec(),
            None => return,
        };

        // Collect type assignments first (can't borrow mutably while iterating)
        let mut type_assignments: Vec<(SsaVarId, SsaType)> = Vec::new();

        for (dest, src) in resolved {
            if dest == src {
                continue;
            }

            // Check if the destination is a Local-origin variable
            let Some(dest_var) = ssa.variable(*dest) else {
                continue;
            };
            let VariableOrigin::Local(local_idx) = dest_var.origin() else {
                continue;
            };

            // Get the original type for this local
            let local_type = match original_types.get(local_idx as usize) {
                Some(sig) => &sig.base,
                None => continue,
            };

            // Convert to SsaType
            let ssa_type = SsaType::from_type_signature(local_type, assembly);

            // Only propagate if the type is known (not Unknown/I32)
            if ssa_type.is_unknown() || matches!(ssa_type, SsaType::I32) {
                continue;
            }

            // Check if the source variable currently has Unknown type
            // Only propagate if we're improving the type information
            let should_propagate = match ssa.variable(*src) {
                Some(src_var) => src_var.var_type().is_unknown(),
                None => false,
            };

            if should_propagate {
                type_assignments.push((*src, ssa_type));
            }
        }

        // Apply type assignments
        for (var_id, ssa_type) in type_assignments {
            if let Some(var) = ssa.variable_mut(var_id) {
                var.set_type(ssa_type);
            }
        }
    }
}

impl SsaPass for CopyPropagationPass {
    fn name(&self) -> &'static str {
        "copy-propagation"
    }

    fn description(&self) -> &'static str {
        "Propagates copy operations, replacing uses with original sources"
    }

    fn run_on_method(
        &self,
        ssa: &mut SsaFunction,
        method_token: Token,
        ctx: &CompilerContext,
        assembly: &Arc<CilObject>,
    ) -> Result<bool> {
        let mut changes = EventLog::new();

        // Iterate until fixed point
        for _ in 0..MAX_ITERATIONS {
            let replaced = Self::run_iteration(ssa, method_token, &mut changes, assembly);

            if replaced == 0 {
                break;
            }
        }

        let changed = !changes.is_empty();
        if changed {
            ctx.events.merge(changes);
        }
        Ok(changed)
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, sync::Arc};

    use crate::{
        analysis::{
            CallGraph, ConstValue, DefSite, PhiAnalyzer, PhiNode, PhiOperand, SsaBlock,
            SsaFunction, SsaFunctionBuilder, SsaInstruction, SsaOp, SsaVarId, SsaVariable,
            VariableOrigin,
        },
        compiler::CompilerContext,
        compiler::{CopyPropagationPass, SsaPass},
        metadata::token::Token,
        test::helpers::test_assembly_arc,
    };

    /// Helper to create a minimal analysis context for testing.
    fn test_context() -> CompilerContext {
        let call_graph = Arc::new(CallGraph::new());
        CompilerContext::new(call_graph)
    }

    #[test]
    fn test_collect_empty_function() {
        let ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
            f.block(0, |b| b.ret());
        });
        let copies = PhiAnalyzer::new(&ssa).collect_all_copies();
        assert!(copies.is_empty());
    }

    #[test]
    fn test_collect_single_copy() {
        let (ssa, v0, v1) = {
            let mut v0_out = SsaVarId::new();
            let mut v1_out = SsaVarId::new();
            let ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
                f.block(0, |b| {
                    let v0 = b.const_i32(42);
                    let v1 = b.copy(v0);
                    v0_out = v0;
                    v1_out = v1;
                    b.ret();
                });
            });
            (ssa, v0_out, v1_out)
        };

        let copies = PhiAnalyzer::new(&ssa).collect_all_copies();
        assert_eq!(copies.len(), 1);
        assert_eq!(copies.get(&v1), Some(&v0));
    }

    #[test]
    fn test_collect_multiple_copies() {
        let (ssa, v0, v1, v2) = {
            let mut v0_out = SsaVarId::new();
            let mut v1_out = SsaVarId::new();
            let mut v2_out = SsaVarId::new();
            let ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
                f.block(0, |b| {
                    let v0 = b.const_i32(42);
                    let v1 = b.copy(v0);
                    let v2 = b.copy(v1);
                    v0_out = v0;
                    v1_out = v1;
                    v2_out = v2;
                    b.ret();
                });
            });
            (ssa, v0_out, v1_out, v2_out)
        };

        let copies = PhiAnalyzer::new(&ssa).collect_all_copies();
        assert_eq!(copies.len(), 2);
        assert_eq!(copies.get(&v1), Some(&v0));
        assert_eq!(copies.get(&v2), Some(&v1));
    }

    #[test]
    fn test_collect_trivial_phi_all_same() {
        let (ssa, v0, v_phi) = {
            let mut v0_out = SsaVarId::new();
            let mut v_phi_out = SsaVarId::new();
            let ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
                f.block(0, |b| {
                    let v0 = b.const_i32(42);
                    let cond = b.const_true();
                    v0_out = v0;
                    b.branch(cond, 1, 2);
                });
                f.block(1, |b| b.jump(3));
                f.block(2, |b| b.jump(3));
                f.block(3, |b| {
                    // phi with all same operands (v0 from both paths)
                    let phi_result = b.phi(&[(1, v0_out), (2, v0_out)]);
                    v_phi_out = phi_result;
                    b.ret_val(phi_result);
                });
            });
            (ssa, v0_out, v_phi_out)
        };

        let copies = PhiAnalyzer::new(&ssa).collect_all_copies();
        assert_eq!(copies.len(), 1);
        assert_eq!(copies.get(&v_phi), Some(&v0));
    }

    #[test]
    fn test_collect_trivial_phi_with_self_reference() {
        // Self-referential phi where the phi references itself (for loop back-edges)
        // We need to manually construct this since the builder can't create self-references
        let mut ssa = SsaFunction::new(0, 0);

        // Create variables (auto-allocates IDs)
        let v0_var = SsaVariable::new(VariableOrigin::Stack(0), 0, DefSite::instruction(0, 0));
        let v0 = v0_var.id();
        ssa.add_variable(v0_var);

        let phi_variable = SsaVariable::new(VariableOrigin::Stack(1), 0, DefSite::phi(1));
        let phi_var = phi_variable.id();
        ssa.add_variable(phi_variable);

        // Block 0: entry, defines v0, jumps to block 1
        let mut block0 = SsaBlock::new(0);
        block0.add_instruction(SsaInstruction::synthetic(SsaOp::Const {
            dest: v0,
            value: ConstValue::I32(42),
        }));
        block0.add_instruction(SsaInstruction::synthetic(SsaOp::Jump { target: 1 }));
        ssa.add_block(block0);

        // Block 1: loop header with self-referential phi
        // phi_var = phi(v0 from block 0, phi_var from block 1)
        let mut block1 = SsaBlock::new(1);
        let mut phi = PhiNode::new(phi_var, VariableOrigin::Stack(1));
        phi.add_operand(PhiOperand::new(v0, 0)); // from block 0
        phi.add_operand(PhiOperand::new(phi_var, 1)); // from block 1 (self-reference)
        block1.add_phi(phi);
        block1.add_instruction(SsaInstruction::synthetic(SsaOp::Return {
            value: Some(phi_var),
        }));
        ssa.add_block(block1);

        let copies = PhiAnalyzer::new(&ssa).collect_all_copies();
        // phi_var = phi(v0, phi_var) should be detected as trivial (phi_var → v0)
        assert_eq!(copies.len(), 1);
        assert_eq!(copies.get(&phi_var), Some(&v0));
    }

    #[test]
    fn test_collect_non_trivial_phi() {
        let ssa = {
            let mut v0_out = SsaVarId::new();
            let mut v1_out = SsaVarId::new();
            SsaFunctionBuilder::new(0, 0).build_with(|f| {
                f.block(0, |b| {
                    let cond = b.const_true();
                    b.branch(cond, 1, 2);
                });
                f.block(1, |b| {
                    let v0 = b.const_i32(10);
                    v0_out = v0;
                    b.jump(3);
                });
                f.block(2, |b| {
                    let v1 = b.const_i32(20);
                    v1_out = v1;
                    b.jump(3);
                });
                f.block(3, |b| {
                    // phi with different operands
                    let phi_result = b.phi(&[(1, v0_out), (2, v1_out)]);
                    b.ret_val(phi_result);
                });
            })
        };

        let copies = PhiAnalyzer::new(&ssa).collect_all_copies();
        // Non-trivial phi should not be collected
        assert!(copies.is_empty());
    }

    #[test]
    fn test_resolve_simple_chain() {
        let v0 = SsaVarId::new();
        let v1 = SsaVarId::new();
        let v2 = SsaVarId::new();
        let mut copies = HashMap::new();
        // v2 → v1 → v0
        copies.insert(v2, v1);
        copies.insert(v1, v0);

        let resolved = CopyPropagationPass::resolve_chains(&copies);

        // Both should resolve to v0
        assert_eq!(resolved.get(&v1), Some(&v0));
        assert_eq!(resolved.get(&v2), Some(&v0));
    }

    #[test]
    fn test_resolve_long_chain() {
        let v0 = SsaVarId::new();
        let v1 = SsaVarId::new();
        let v2 = SsaVarId::new();
        let v3 = SsaVarId::new();
        let v4 = SsaVarId::new();
        let mut copies = HashMap::new();
        // v4 → v3 → v2 → v1 → v0
        copies.insert(v4, v3);
        copies.insert(v3, v2);
        copies.insert(v2, v1);
        copies.insert(v1, v0);

        let resolved = CopyPropagationPass::resolve_chains(&copies);

        // All should resolve to v0
        assert_eq!(resolved.get(&v1), Some(&v0));
        assert_eq!(resolved.get(&v2), Some(&v0));
        assert_eq!(resolved.get(&v3), Some(&v0));
        assert_eq!(resolved.get(&v4), Some(&v0));
    }

    #[test]
    fn test_resolve_cycle() {
        let v1 = SsaVarId::new();
        let v2 = SsaVarId::new();
        let mut copies = HashMap::new();
        // v1 → v2 → v1 (cycle)
        copies.insert(v1, v2);
        copies.insert(v2, v1);

        let resolved = CopyPropagationPass::resolve_chains(&copies);

        // Should handle cycle gracefully (stop at some point in the cycle)
        assert!(resolved.contains_key(&v1));
        assert!(resolved.contains_key(&v2));
    }

    #[test]
    fn test_resolve_multiple_independent_chains() {
        let v0 = SsaVarId::new();
        let v1 = SsaVarId::new();
        let v2 = SsaVarId::new();
        let v3 = SsaVarId::new();
        let v4 = SsaVarId::new();
        let v5 = SsaVarId::new();
        let mut copies = HashMap::new();
        // Chain 1: v2 → v1 → v0
        copies.insert(v2, v1);
        copies.insert(v1, v0);
        // Chain 2: v5 → v4 → v3
        copies.insert(v5, v4);
        copies.insert(v4, v3);

        let resolved = CopyPropagationPass::resolve_chains(&copies);

        // Chain 1 resolves to v0
        assert_eq!(resolved.get(&v1), Some(&v0));
        assert_eq!(resolved.get(&v2), Some(&v0));
        // Chain 2 resolves to v3
        assert_eq!(resolved.get(&v4), Some(&v3));
        assert_eq!(resolved.get(&v5), Some(&v3));
    }

    #[test]
    fn test_trivial_phi_single_operand() {
        let ssa = SsaFunction::new(0, 0);
        let analyzer = PhiAnalyzer::new(&ssa);

        let result = SsaVarId::new();
        let v0 = SsaVarId::new();
        let mut phi = PhiNode::new(result, VariableOrigin::Local(0));
        phi.add_operand(PhiOperand::new(v0, 0));

        let source = analyzer.is_trivial(&phi);
        assert_eq!(source, Some(v0));
    }

    #[test]
    fn test_trivial_phi_all_same_operands() {
        let ssa = SsaFunction::new(0, 0);
        let analyzer = PhiAnalyzer::new(&ssa);

        let result = SsaVarId::new();
        let v0 = SsaVarId::new();
        let mut phi = PhiNode::new(result, VariableOrigin::Local(0));
        phi.add_operand(PhiOperand::new(v0, 0));
        phi.add_operand(PhiOperand::new(v0, 1));
        phi.add_operand(PhiOperand::new(v0, 2));

        let source = analyzer.is_trivial(&phi);
        assert_eq!(source, Some(v0));
    }

    #[test]
    fn test_trivial_phi_with_self_references() {
        let ssa = SsaFunction::new(0, 0);
        let analyzer = PhiAnalyzer::new(&ssa);

        let v0 = SsaVarId::new();
        let v1 = SsaVarId::new();
        let mut phi = PhiNode::new(v1, VariableOrigin::Local(0));
        phi.add_operand(PhiOperand::new(v0, 0)); // Non-self
        phi.add_operand(PhiOperand::new(v1, 1)); // Self-reference
        phi.add_operand(PhiOperand::new(v1, 2)); // Self-reference

        let source = analyzer.is_trivial(&phi);
        assert_eq!(source, Some(v0));
    }

    #[test]
    fn test_non_trivial_phi_different_operands() {
        let ssa = SsaFunction::new(0, 0);
        let analyzer = PhiAnalyzer::new(&ssa);

        let v0 = SsaVarId::new();
        let v1 = SsaVarId::new();
        let v5 = SsaVarId::new();
        let mut phi = PhiNode::new(v5, VariableOrigin::Local(0));
        phi.add_operand(PhiOperand::new(v0, 0));
        phi.add_operand(PhiOperand::new(v1, 1));

        let source = analyzer.is_trivial(&phi);
        assert_eq!(source, None);
    }

    #[test]
    fn test_trivial_phi_all_self_references() {
        let ssa = SsaFunction::new(0, 0);
        let analyzer = PhiAnalyzer::new(&ssa);

        let v1 = SsaVarId::new();
        let mut phi = PhiNode::new(v1, VariableOrigin::Local(0));
        phi.add_operand(PhiOperand::new(v1, 0)); // Self
        phi.add_operand(PhiOperand::new(v1, 1)); // Self

        let source = analyzer.is_trivial(&phi);
        // All self-references means no unique source
        assert_eq!(source, None);
    }

    #[test]
    fn test_propagate_single_copy() {
        let (mut ssa, v0, _v1) = {
            let mut v0_out = SsaVarId::new();
            let mut v1_out = SsaVarId::new();
            let ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
                f.block(0, |b| {
                    let v0 = b.const_i32(42);
                    let v1 = b.copy(v0);
                    let _v2 = b.add(v1, v1);
                    v0_out = v0;
                    v1_out = v1;
                    b.ret_val(v1);
                });
            });
            (ssa, v0_out, v1_out)
        };

        // Run pass
        let pass = CopyPropagationPass::new();
        let ctx = test_context();
        let changed = pass
            .run_on_method(&mut ssa, Token::new(0x06000001), &ctx, &test_assembly_arc())
            .unwrap();

        // Should have propagated v1 → v0
        assert!(changed);

        // Verify: add should now use v0
        let block = ssa.block(0).unwrap();
        let add_instr = &block.instructions()[2];
        if let SsaOp::Add { left, right, .. } = add_instr.op() {
            assert_eq!(*left, v0);
            assert_eq!(*right, v0);
        } else {
            panic!("Expected Add instruction");
        }

        // Verify: return should now use v0
        let ret_instr = &block.instructions()[3];
        if let SsaOp::Return { value } = ret_instr.op() {
            assert_eq!(*value, Some(v0));
        } else {
            panic!("Expected Return instruction");
        }
    }

    #[test]
    fn test_propagate_copy_chain() {
        let (mut ssa, v0) = {
            let mut v0_out = SsaVarId::new();
            let ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
                f.block(0, |b| {
                    let v0 = b.const_i32(42);
                    let v1 = b.copy(v0);
                    let v2 = b.copy(v1);
                    let v3 = b.copy(v2);
                    v0_out = v0;
                    b.ret_val(v3);
                });
            });
            (ssa, v0_out)
        };

        // Run pass
        let pass = CopyPropagationPass::new();
        let ctx = test_context();
        let _changes = pass
            .run_on_method(&mut ssa, Token::new(0x06000001), &ctx, &test_assembly_arc())
            .unwrap();

        // Verify: return should now use v0 (ultimate source)
        let block = ssa.block(0).unwrap();
        if let Some(SsaOp::Return { value }) = block.terminator_op() {
            assert_eq!(*value, Some(v0));
        } else {
            panic!("Expected Return instruction");
        }
    }

    #[test]
    fn test_propagate_trivial_phi() {
        let (mut ssa, v0) = {
            let mut v0_out = SsaVarId::new();
            let ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
                // Block 0: entry
                f.block(0, |b| {
                    v0_out = b.const_i32(42);
                    let cond = b.const_true();
                    b.branch(cond, 1, 2);
                });
                // Block 1
                f.block(1, |b| b.jump(3));
                // Block 2
                f.block(2, |b| b.jump(3));
                // Block 3: trivial phi (both operands are v0)
                f.block(3, |b| {
                    let phi_result = b.phi(&[(1, v0_out), (2, v0_out)]);
                    // Use phi result
                    let _ = b.add(phi_result, phi_result);
                    b.ret_val(phi_result);
                });
            });
            (ssa, v0_out)
        };

        // Run pass
        let pass = CopyPropagationPass::new();
        let ctx = test_context();
        let changed = pass
            .run_on_method(&mut ssa, Token::new(0x06000001), &ctx, &test_assembly_arc())
            .unwrap();

        assert!(changed);

        // Verify: uses of phi should be replaced with v0
        let block3 = ssa.block(3).unwrap();
        let add_instr = &block3.instructions()[0];
        if let SsaOp::Add { left, right, .. } = add_instr.op() {
            assert_eq!(*left, v0);
            assert_eq!(*right, v0);
        }
    }

    #[test]
    fn test_no_propagation_needed() {
        let mut ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
            f.block(0, |b| {
                let v0 = b.const_i32(42);
                b.ret_val(v0); // no copies
            });
        });

        // Run pass
        let pass = CopyPropagationPass::new();
        let ctx = test_context();
        let changed = pass
            .run_on_method(&mut ssa, Token::new(0x06000001), &ctx, &test_assembly_arc())
            .unwrap();

        // No copies, no changes
        assert!(!changed);
    }

    #[test]
    fn test_iterative_convergence() {
        // Test that the pass converges even with complex copy patterns
        let (mut ssa, v0) = {
            let mut v0_out = SsaVarId::new();
            let ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
                f.block(0, |b| {
                    let v0 = b.const_i32(42);
                    v0_out = v0;
                    // Create a chain: v1 = v0, v2 = v1, v3 = v2
                    let v1 = b.copy(v0);
                    let v2 = b.copy(v1);
                    let v3 = b.copy(v2);
                    // Use all copies
                    let v10 = b.add(v1, v2);
                    let v11 = b.add(v10, v3);
                    b.ret_val(v11);
                });
            });
            (ssa, v0_out)
        };

        // Run pass
        let pass = CopyPropagationPass::new();
        let ctx = test_context();
        let result =
            pass.run_on_method(&mut ssa, Token::new(0x06000001), &ctx, &test_assembly_arc());

        // Should complete without error (convergence)
        assert!(result.is_ok());

        // Verify all uses point to v0
        let block = ssa.block(0).unwrap();

        // Check first add: should be add v0, v0
        let add1 = &block.instructions()[4];
        if let SsaOp::Add { left, right, .. } = add1.op() {
            assert_eq!(*left, v0);
            assert_eq!(*right, v0);
        }

        // Check second add: right should be v0
        let add2 = &block.instructions()[5];
        if let SsaOp::Add { right, .. } = add2.op() {
            assert_eq!(*right, v0);
        }
    }

    #[test]
    fn test_copy_not_propagated_to_definition() {
        // Ensure we don't replace the copy's own definition
        let (mut ssa, v0, v1) = {
            let mut v0_out = SsaVarId::new();
            let mut v1_out = SsaVarId::new();
            let ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
                f.block(0, |b| {
                    let v0 = b.const_i32(42);
                    v0_out = v0;
                    let v1 = b.copy(v0);
                    v1_out = v1;
                    b.ret_val(v1);
                });
            });
            (ssa, v0_out, v1_out)
        };

        // Run pass
        let pass = CopyPropagationPass::new();
        let ctx = test_context();
        let _changes = pass
            .run_on_method(&mut ssa, Token::new(0x06000001), &ctx, &test_assembly_arc())
            .unwrap();

        // The copy instruction itself should remain unchanged (dest is still v1)
        let block = ssa.block(0).unwrap();
        let copy_instr = &block.instructions()[1];
        if let SsaOp::Copy { dest, src } = copy_instr.op() {
            assert_eq!(*dest, v1);
            assert_eq!(*src, v0);
        }
    }

    #[test]
    fn test_phi_operands_preserved() {
        // Test that copy propagation does NOT replace PHI operands.
        // This is intentional: replacing PHI operands can create cross-origin
        // references that break rebuild_ssa's assumption that each variable
        // flows to at most one PHI origin.
        let (mut ssa, _v0, v1, v2) = {
            let mut v0_out = SsaVarId::new();
            let mut v1_out = SsaVarId::new();
            let mut v2_out = SsaVarId::new();
            let ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
                // Block 0: entry
                f.block(0, |b| {
                    let v0 = b.const_i32(42);
                    v0_out = v0;
                    let v1 = b.copy(v0);
                    v1_out = v1;
                    let cond = b.const_true();
                    b.branch(cond, 1, 2);
                });
                // Block 1: defines v2
                f.block(1, |b| {
                    v2_out = b.const_i32(100);
                    b.jump(3);
                });
                // Block 2: just jumps
                f.block(2, |b| b.jump(3));
                // Block 3: phi using v1 (copy of v0) and v2
                f.block(3, |b| {
                    let phi_result = b.phi(&[(1, v2_out), (2, v1_out)]);
                    b.ret_val(phi_result);
                });
            });
            (ssa, v0_out, v1_out, v2_out)
        };

        // Run pass
        let pass = CopyPropagationPass::new();
        let ctx = test_context();
        let _changes = pass
            .run_on_method(&mut ssa, Token::new(0x06000001), &ctx, &test_assembly_arc())
            .unwrap();

        // Verify: phi operands should be PRESERVED (not replaced)
        // v1 should remain in the PHI, not be replaced with v0
        let block3 = ssa.block(3).unwrap();
        let phi = &block3.phi_nodes()[0];
        let operand_values: Vec<_> = phi.operands().iter().map(|op| op.value()).collect();

        // One operand should be v2, the other should still be v1 (preserved)
        assert!(operand_values.contains(&v2));
        assert!(operand_values.contains(&v1)); // v1 is preserved, not replaced with v0
    }
}
