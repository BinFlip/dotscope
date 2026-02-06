//! Loop Invariant Code Motion (LICM) Pass.
//!
//! This pass moves computations that produce the same value on every iteration
//! out of loops. This is useful for:
//!
//! - Performance optimization
//! - Cleaning up loop-based obfuscation patterns
//!
//! # Algorithm
//!
//! An instruction is loop-invariant if:
//! 1. All its operands are defined outside the loop, OR
//! 2. All its operands are defined by loop-invariant instructions
//!
//! An instruction can be hoisted if:
//! 1. It is loop-invariant
//! 2. It has no side effects (pure computation)
//! 3. The loop has a preheader where we can place the hoisted code
//!
//! # Example
//!
//! ```text
//! // Before LICM
//! preheader:
//!     a = 5
//!     b = 10
//!     jump header
//!
//! header:
//!     i = phi(0, i')
//!     x = a + b        // Loop invariant!
//!     use(x)
//!     i' = i + 1
//!     branch (i < 10), header, exit
//!
//! // After LICM
//! preheader:
//!     a = 5
//!     b = 10
//!     x = a + b        // Hoisted
//!     jump header
//!
//! header:
//!     i = phi(0, i')
//!     use(x)
//!     i' = i + 1
//!     branch (i < 10), header, exit
//! ```

use std::{
    collections::{HashSet, VecDeque},
    sync::Arc,
};

use crate::{
    analysis::{LoopAnalyzer, LoopInfo, SsaFunction, SsaInstruction, SsaOp, SsaVarId},
    deobfuscation::{changes::EventKind, context::AnalysisContext, pass::SsaPass},
    metadata::token::Token,
    utils::graph::NodeId,
    CilObject, Result,
};

/// Loop Invariant Code Motion Pass.
///
/// Moves loop-invariant computations to the loop preheader.
pub struct LicmPass;

impl Default for LicmPass {
    fn default() -> Self {
        Self::new()
    }
}

impl LicmPass {
    /// Creates a new LICM pass.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl SsaPass for LicmPass {
    fn name(&self) -> &'static str {
        "licm"
    }

    fn description(&self) -> &'static str {
        "Moves loop-invariant computations to loop preheaders"
    }

    fn run_on_method(
        &self,
        ssa: &mut SsaFunction,
        method_token: Token,
        ctx: &AnalysisContext,
        _assembly: &Arc<CilObject>,
    ) -> Result<bool> {
        let forest = LoopAnalyzer::new(ssa).analyze();

        if forest.is_empty() {
            return Ok(false);
        }

        let mut total_hoisted = 0;

        // Process loops from innermost to outermost
        // This allows hoisting from inner loops, then outer loops
        for loop_info in forest.by_depth_descending() {
            // Skip loops without preheaders - we need somewhere to hoist to
            let Some(preheader) = loop_info.preheader else {
                continue;
            };

            // Find invariant instructions
            let invariants = find_loop_invariants(ssa, loop_info);

            if invariants.is_empty() {
                continue;
            }

            // Filter to hoistable instructions
            let hoistable: Vec<_> = invariants
                .into_iter()
                .filter(|(block_idx, instr_idx)| can_hoist(ssa, loop_info, *block_idx, *instr_idx))
                .collect();

            if hoistable.is_empty() {
                continue;
            }

            // Collect instructions to hoist (we need to clone them before mutation)
            let mut to_hoist: Vec<(usize, usize, SsaOp)> = Vec::new();
            for (block_idx, instr_idx) in &hoistable {
                if let Some(block) = ssa.block(*block_idx) {
                    if let Some(instr) = block.instruction(*instr_idx) {
                        to_hoist.push((*block_idx, *instr_idx, instr.op().clone()));
                    }
                }
            }

            // Sort hoistable instructions by their dependency order.
            // Instructions must be hoisted in the order they were originally defined
            // to maintain correct dependencies. Sort by (block_idx, instr_idx).
            to_hoist.sort_by_key(|(block_idx, instr_idx, _)| (*block_idx, *instr_idx));

            // Find the insertion point in the preheader (before the terminator)
            let insert_base = if let Some(preheader_block) = ssa.block(preheader.index()) {
                let instrs = preheader_block.instructions();
                if instrs.is_empty() {
                    0
                } else if instrs.last().is_some_and(|i| i.is_terminator()) {
                    instrs.len().saturating_sub(1)
                } else {
                    instrs.len()
                }
            } else {
                0
            };

            // Apply hoisting - insert all at once to maintain order
            for (i, (block_idx, instr_idx, op)) in to_hoist.iter().enumerate() {
                // Add to preheader
                if let Some(preheader_block) = ssa.block_mut(preheader.index()) {
                    // Create a new instruction with the same op
                    let new_instr = SsaInstruction::synthetic(op.clone());

                    // Insert at position offset by the number of already-inserted instructions
                    let instrs = preheader_block.instructions_mut();
                    instrs.insert(insert_base + i, new_instr);
                }

                // Remove from original location (replace with Nop)
                if let Some(block) = ssa.block_mut(*block_idx) {
                    if let Some(instr) = block.instructions_mut().get_mut(*instr_idx) {
                        instr.set_op(SsaOp::Nop);
                    }
                }

                total_hoisted += 1;
            }
        }

        if total_hoisted > 0 {
            ctx.events
                .record(EventKind::InstructionRemoved)
                .at(method_token, 0)
                .message(format!(
                    "LICM: hoisted {total_hoisted} loop-invariant instructions"
                ));
        }

        Ok(total_hoisted > 0)
    }
}

/// Finds all loop-invariant instructions in a loop.
///
/// An instruction is loop-invariant if all its operands are:
/// - Defined outside the loop, OR
/// - Defined by loop-invariant instructions
///
/// IMPORTANT: PHI nodes at the loop HEADER define induction variables that change
/// each iteration. Instructions using these values are NOT loop-invariant.
fn find_loop_invariants(ssa: &SsaFunction, loop_info: &LoopInfo) -> Vec<(usize, usize)> {
    let mut invariants: HashSet<(usize, usize)> = HashSet::new();
    let mut invariant_defs: HashSet<SsaVarId> = HashSet::new();

    // Collect PHI-defined variables from the loop HEADER only.
    // These are loop induction variables that change each iteration.
    // PHIs at other loop body blocks are path merge points and don't affect invariance.
    let mut header_phi_defs: HashSet<SsaVarId> = HashSet::new();
    if let Some(header_block) = ssa.block(loop_info.header.index()) {
        for phi in header_block.phi_nodes() {
            header_phi_defs.insert(phi.result());
        }
    }

    // Build map of variables defined outside the loop
    let mut outside_defs: HashSet<SsaVarId> = HashSet::new();
    for var in ssa.variables() {
        let def_site = var.def_site();
        if !loop_info.body.contains(&NodeId::new(def_site.block)) {
            outside_defs.insert(var.id());
        }
    }

    let mut changed = true;
    while changed {
        changed = false;

        for body_block in &loop_info.body {
            let block_idx = body_block.index();
            if let Some(block) = ssa.block(block_idx) {
                for (instr_idx, instr) in block.instructions().iter().enumerate() {
                    // Skip if already marked invariant
                    if invariants.contains(&(block_idx, instr_idx)) {
                        continue;
                    }

                    // Skip terminators
                    if instr.is_terminator() {
                        continue;
                    }

                    // Check if instruction is invariant
                    if is_instruction_invariant(
                        instr,
                        &outside_defs,
                        &invariant_defs,
                        &header_phi_defs,
                    ) {
                        invariants.insert((block_idx, instr_idx));
                        if let Some(def) = instr.def() {
                            invariant_defs.insert(def);
                        }
                        changed = true;
                    }
                }
            }
        }
    }

    invariants.into_iter().collect()
}

/// Checks if an instruction is loop-invariant.
///
/// An instruction is NOT loop-invariant if it uses any loop header PHI-defined variable,
/// since those represent induction variables that change each iteration.
fn is_instruction_invariant(
    instr: &SsaInstruction,
    outside_defs: &HashSet<SsaVarId>,
    invariant_defs: &HashSet<SsaVarId>,
    header_phi_defs: &HashSet<SsaVarId>,
) -> bool {
    // Use the built-in uses() method to get all operands
    for operand in instr.op().uses() {
        // If the operand is defined by a PHI at the loop header, it's loop-varying
        if header_phi_defs.contains(&operand) {
            return false;
        }
        // Otherwise check if it's defined outside the loop or by an invariant instruction
        if !outside_defs.contains(&operand) && !invariant_defs.contains(&operand) {
            return false;
        }
    }

    true
}

/// Checks if an instruction can be safely hoisted.
fn can_hoist(ssa: &SsaFunction, loop_info: &LoopInfo, block_idx: usize, instr_idx: usize) -> bool {
    let Some(block) = ssa.block(block_idx) else {
        return false;
    };

    let Some(instr) = block.instruction(instr_idx) else {
        return false;
    };

    // Only hoist pure computations (is_pure is defined on SsaOp)
    if !instr.op().is_pure() {
        return false;
    }

    // Don't hoist if there's no preheader
    if loop_info.preheader.is_none() {
        return false;
    }

    // CRITICAL: Don't hoist if this instruction's result feeds a PHI's back-edge operand.
    // Hoisting such instructions would make the PHI's back-edge operand orphaned or
    // self-referential, breaking the loop structure.
    if let Some(dest) = instr.def() {
        if feeds_phi_back_edge(ssa, loop_info, dest) {
            return false;
        }
    }

    true
}

/// Checks if a variable (directly or indirectly) feeds a PHI's back-edge operand.
///
/// A variable feeds a PHI's back-edge if:
/// 1. The variable is directly used as a PHI operand from a loop body block, OR
/// 2. The variable is used by another instruction whose result feeds a PHI back-edge
fn feeds_phi_back_edge(ssa: &SsaFunction, loop_info: &LoopInfo, var: SsaVarId) -> bool {
    let header_idx = loop_info.header.index();
    let mut worklist: VecDeque<SsaVarId> = VecDeque::new();
    let mut visited: HashSet<SsaVarId> = HashSet::new();

    worklist.push_back(var);
    visited.insert(var);

    while let Some(current) = worklist.pop_front() {
        // Check if this variable is a PHI operand from a back-edge (loop body block)
        if let Some(header_block) = ssa.block(header_idx) {
            for phi in header_block.phi_nodes() {
                for operand in phi.operands() {
                    if operand.value() == current {
                        // Check if the predecessor is in the loop body (back-edge)
                        let pred = operand.predecessor();
                        if loop_info.body.contains(&NodeId::new(pred)) && pred != header_idx {
                            // This is a back-edge operand (from loop body, not the header itself)
                            return true;
                        }
                    }
                }
            }
        }

        // Find instructions that use this variable and add their dests to the worklist
        for body_block_id in &loop_info.body {
            if let Some(body_block) = ssa.block(body_block_id.index()) {
                for instr in body_block.instructions() {
                    if instr.op().uses().contains(&current) {
                        if let Some(dest) = instr.def() {
                            if visited.insert(dest) {
                                worklist.push_back(dest);
                            }
                        }
                    }
                }
            }
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use crate::{
        analysis::{ConstValue, LoopAnalyzer, MethodRef, SsaFunctionBuilder, SsaOp, SsaVarId},
        deobfuscation::{pass::SsaPass, passes::LicmPass},
        metadata::token::Token,
    };

    #[test]
    fn test_pass_metadata() {
        let pass = LicmPass::new();
        assert_eq!(pass.name(), "licm");
        assert!(!pass.description().is_empty());
    }

    #[test]
    fn test_op_is_pure() {
        let add_op = SsaOp::Add {
            dest: SsaVarId::new(),
            left: SsaVarId::new(),
            right: SsaVarId::new(),
        };
        assert!(add_op.is_pure());

        let const_op = SsaOp::Const {
            dest: SsaVarId::new(),
            value: ConstValue::I32(42),
        };
        assert!(const_op.is_pure());

        let call_op = SsaOp::Call {
            dest: Some(SsaVarId::new()),
            method: MethodRef::new(Token::new(0x06000001)),
            args: vec![],
        };
        assert!(!call_op.is_pure());
    }

    #[test]
    fn test_op_uses() {
        let v1 = SsaVarId::new();
        let v2 = SsaVarId::new();
        let dest = SsaVarId::new();

        let op = SsaOp::Add {
            dest,
            left: v1,
            right: v2,
        };
        let uses = op.uses();
        assert_eq!(uses.len(), 2);
        assert!(uses.contains(&v1));
        assert!(uses.contains(&v2));

        let const_op = SsaOp::Const {
            dest,
            value: ConstValue::I32(42),
        };
        assert!(const_op.uses().is_empty());
    }

    #[test]
    fn test_no_loops() {
        // Function with no loops should return false
        let ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
            f.block(0, |b| {
                let _ = b.const_i32(42);
                b.ret();
            });
        });

        let forest = LoopAnalyzer::new(&ssa).analyze();
        assert!(forest.is_empty());
    }

    #[test]
    fn test_loop_without_preheader() {
        // Loop without preheader (multiple entry edges) can't be optimized
        // This creates a function where the loop header has multiple predecessors
        let ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
            // B0: entry with branch to different blocks
            f.block(0, |b| {
                let cond = b.const_true();
                b.branch(cond, 1, 2);
            });
            // B1: goes to loop header
            f.block(1, |b| b.jump(3));
            // B2: also goes to loop header (no single preheader)
            f.block(2, |b| b.jump(3));
            // B3: loop header
            f.block(3, |b| {
                let cond = b.const_true();
                b.branch(cond, 3, 4); // self-loop
            });
            // B4: exit
            f.block(4, |b| b.ret());
        });

        let forest = LoopAnalyzer::new(&ssa).analyze();
        assert!(!forest.is_empty());

        let loop_info = &forest.loops()[0];
        // This loop has multiple entry edges so no preheader
        assert!(!loop_info.has_preheader());
    }

    #[test]
    fn test_simple_loop_has_preheader() {
        // Create a loop with a single preheader
        let ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
            // B0: preheader
            f.block(0, |b| b.jump(1));
            // B1: header with self-loop
            f.block(1, |b| {
                let cond = b.const_true();
                b.branch(cond, 1, 2);
            });
            // B2: exit
            f.block(2, |b| b.ret());
        });

        let forest = LoopAnalyzer::new(&ssa).analyze();
        assert_eq!(forest.len(), 1);

        let loop_info = &forest.loops()[0];
        assert!(loop_info.has_preheader());
    }
}
