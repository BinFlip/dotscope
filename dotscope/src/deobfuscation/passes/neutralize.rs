//! Neutralization pass for removing protection code from methods.
//!
//! This pass surgically removes instructions that reference removed tokens
//! (methods, types, fields) from method bodies, while preserving any legitimate
//! initialization code. This is critical for handling module `.cctor` methods
//! that contain both protection initialization AND user initialization.
//!
//! # Problem
//!
//! When obfuscator infrastructure is removed (decryptor types, anti-tamper methods),
//! methods like the module `.cctor` may still contain calls to those removed entities.
//! Simply removing the `.cctor` would break the assembly if it contains legitimate
//! initialization. We need to:
//!
//! 1. Identify instructions referencing removed tokens
//! 2. Trace all dependent code via taint analysis
//! 3. Remove only tainted instructions
//! 4. Preserve legitimate initialization code
//!
//! # Algorithm
//!
//! For each method passed to the pass:
//! - Scan all instructions for references to removed tokens
//! - Mark those instructions as taint sources
//! - Run bidirectional taint propagation to find all dependent code
//! - Replace tainted instructions with `Nop`
//!
//! Subsequent passes (DCE, block merging) will clean up the `Nop`s.
//!
//! # Example
//!
//! ```rust,ignore
//! use dotscope::compiler::NeutralizationPass;
//!
//! let pass = NeutralizationPass::new(&removed_tokens);
//! pass.run_on_method(&mut ssa, method_token, &ctx, &assembly)?;
//! ```

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use crate::{
    analysis::{find_token_dependencies, SsaFunction, SsaOp},
    compiler::{CompilerContext, EventKind, SsaPass},
    metadata::token::Token,
    CilObject, Result,
};

/// Action to perform on a tainted instruction.
enum InstrAction {
    Nop,
    Jump(usize),
}

/// Pass that neutralizes protection code by removing instructions that
/// reference removed tokens.
///
/// This pass is designed to run BEFORE code generation, after we know which
/// tokens will be removed by cleanup. It modifies the SSA to remove all
/// instructions that depend on those tokens.
///
/// The engine decides which methods to process - this pass simply processes
/// whatever method is passed to it.
pub struct NeutralizationPass<'a> {
    /// Tokens that are being removed (methods, types, fields).
    removed_tokens: &'a HashSet<Token>,
}

impl<'a> NeutralizationPass<'a> {
    /// Creates a new neutralization pass.
    ///
    /// # Arguments
    ///
    /// * `removed_tokens` - Tokens that will be removed by cleanup.
    #[must_use]
    pub fn new(removed_tokens: &'a HashSet<Token>) -> Self {
        Self { removed_tokens }
    }

    /// Checks if a block is "fully tainted" - all PHIs and instructions are tainted.
    ///
    /// A fully tainted block contains only protection code and no legitimate
    /// instructions. This is used to determine branch targets when neutralizing
    /// conditional branches.
    ///
    /// # Arguments
    ///
    /// * `ssa` - The SSA function containing the block.
    /// * `block_idx` - Index of the block to check.
    /// * `tainted_instrs` - Set of tainted instruction locations as `(block, instr_idx)`.
    /// * `tainted_phis` - Set of tainted PHI node locations as `(block, phi_idx)`.
    ///
    /// # Returns
    ///
    /// `true` if all PHIs and instructions in the block are tainted (or if the
    /// block is empty/non-existent), `false` if any legitimate code remains.
    fn is_block_fully_tainted(
        ssa: &SsaFunction,
        block_idx: usize,
        tainted_instrs: &HashSet<(usize, usize)>,
        tainted_phis: &HashSet<(usize, usize)>,
    ) -> bool {
        if let Some(block) = ssa.block(block_idx) {
            // Check all PHIs are tainted
            for phi_idx in 0..block.phi_nodes().len() {
                if !tainted_phis.contains(&(block_idx, phi_idx)) {
                    return false;
                }
            }
            // Check all instructions are tainted
            for instr_idx in 0..block.instructions().len() {
                if !tainted_instrs.contains(&(block_idx, instr_idx)) {
                    return false;
                }
            }
            // Empty blocks are considered fully tainted (nothing legitimate)
            true
        } else {
            true // Non-existent block is "fully tainted"
        }
    }

    /// Finds blocks that can reach an exit (Return/Throw) via reverse reachability.
    ///
    /// Performs a backwards BFS from all exit blocks to find which blocks have
    /// a valid path to method termination. This is used as a fallback when
    /// choosing branch targets during neutralization.
    ///
    /// # Arguments
    ///
    /// * `ssa` - The SSA function to analyze.
    ///
    /// # Returns
    ///
    /// Set of block indices that can reach a `Return` or `Throw` instruction.
    fn find_blocks_reaching_exit(ssa: &SsaFunction) -> HashSet<usize> {
        // Build predecessor map
        let mut predecessors: HashMap<usize, Vec<usize>> = HashMap::new();
        for (block_idx, block) in ssa.blocks().iter().enumerate() {
            for succ in block.successors() {
                predecessors.entry(succ).or_default().push(block_idx);
            }
        }

        // Find exit blocks
        let mut can_reach_exit = HashSet::new();
        let mut worklist: Vec<usize> = Vec::new();
        for (block_idx, block) in ssa.blocks().iter().enumerate() {
            for instr in block.instructions() {
                if matches!(instr.op(), SsaOp::Return { .. } | SsaOp::Throw { .. }) {
                    worklist.push(block_idx);
                    break;
                }
            }
        }

        // BFS backwards
        while let Some(block_idx) = worklist.pop() {
            if can_reach_exit.insert(block_idx) {
                if let Some(preds) = predecessors.get(&block_idx) {
                    worklist.extend(preds.iter().filter(|p| !can_reach_exit.contains(p)));
                }
            }
        }

        can_reach_exit
    }

    /// Chooses which branch target to use when neutralizing a tainted branch.
    ///
    /// When a conditional branch's condition depends on tainted code, the branch
    /// must be replaced with an unconditional jump. This method determines which
    /// target to jump to, preferring paths that lead to legitimate code.
    ///
    /// # Priority
    ///
    /// 1. If one target is fully tainted and the other isn't, choose the non-tainted one
    /// 2. If neither is fully tainted, choose the one that can reach an exit
    /// 3. Fallback to `true_target` (often the forward/exit path)
    ///
    /// # Arguments
    ///
    /// * `ssa` - The SSA function containing the branch.
    /// * `true_target` - Block index of the branch's true target.
    /// * `false_target` - Block index of the branch's false target.
    /// * `tainted_instrs` - Set of tainted instruction locations.
    /// * `tainted_phis` - Set of tainted PHI node locations.
    /// * `can_reach_exit` - Set of blocks that can reach a method exit.
    ///
    /// # Returns
    ///
    /// The block index to jump to (either `true_target` or `false_target`).
    fn choose_branch_target(
        ssa: &SsaFunction,
        true_target: usize,
        false_target: usize,
        tainted_instrs: &HashSet<(usize, usize)>,
        tainted_phis: &HashSet<(usize, usize)>,
        can_reach_exit: &HashSet<usize>,
    ) -> usize {
        let true_tainted =
            Self::is_block_fully_tainted(ssa, true_target, tainted_instrs, tainted_phis);
        let false_tainted =
            Self::is_block_fully_tainted(ssa, false_target, tainted_instrs, tainted_phis);

        match (true_tainted, false_tainted) {
            (true, false) => false_target, // True target is tainted, go to false
            (false, true) => true_target,  // False target is tainted, go to true
            _ => {
                // Neither or both fully tainted - use exit reachability
                let true_reaches = can_reach_exit.contains(&true_target);
                let false_reaches = can_reach_exit.contains(&false_target);
                match (true_reaches, false_reaches) {
                    (false, true) => false_target,
                    _ => true_target, // Both or neither - prefer true (often forward path)
                }
            }
        }
    }

    /// Neutralizes a method by removing instructions that reference removed tokens.
    ///
    /// Uses bidirectional taint analysis to identify all instructions that depend
    /// on the removed tokens, then surgically removes them while preserving
    /// legitimate code.
    ///
    /// # Behavior
    ///
    /// - **Regular instructions**: Replaced with `Nop`
    /// - **PHI nodes**: Removed entirely (their result becomes undefined)
    /// - **Conditional branches**: Replaced with unconditional jumps toward exit paths
    /// - **Other terminators**: Left unchanged (`Return`, `Throw`, etc.)
    ///
    /// # Arguments
    ///
    /// * `ssa` - The SSA function to neutralize. Modified in place.
    ///
    /// # Returns
    ///
    /// The number of elements neutralized (instructions + PHIs + branch conversions).
    fn neutralize_method(&self, ssa: &mut SsaFunction) -> usize {
        if self.removed_tokens.is_empty() {
            return 0;
        }

        // Run taint analysis to find all instructions dependent on removed tokens
        let taint = find_token_dependencies(ssa, self.removed_tokens.iter().copied());
        if taint.tainted_instr_count() == 0 && taint.tainted_phis().is_empty() {
            return 0;
        }

        // Collect tainted sets for block analysis
        let tainted_instrs: HashSet<(usize, usize)> =
            taint.tainted_instructions().iter().copied().collect();
        let tainted_phis_set: HashSet<(usize, usize)> =
            taint.tainted_phis().iter().copied().collect();

        // Find blocks that can reach exit (for fallback target selection)
        let can_reach_exit = Self::find_blocks_reaching_exit(ssa);

        let mut count = 0;

        // 1. Remove tainted PHI nodes
        // Collect PHIs to remove (block_idx, phi_idx) sorted in reverse order
        // so we can remove them without invalidating indices
        let mut tainted_phis: Vec<(usize, usize)> = taint.tainted_phis().iter().copied().collect();
        tainted_phis.sort_by(|a, b| b.cmp(a)); // Sort descending

        for (block_idx, phi_idx) in tainted_phis {
            if let Some(block) = ssa.block_mut(block_idx) {
                if phi_idx < block.phi_nodes().len() {
                    block.phi_nodes_mut().remove(phi_idx);
                    count += 1;
                }
            }
        }

        // 2. Handle tainted instructions (including terminators)
        // First pass: collect what operations to apply (to avoid borrow conflicts)
        let mut actions: Vec<(usize, usize, InstrAction)> = Vec::new();

        for &(block_idx, instr_idx) in taint.tainted_instructions() {
            if let Some(block) = ssa.block(block_idx) {
                if let Some(instr) = block.instructions().get(instr_idx) {
                    let action = if instr.is_terminator() {
                        match instr.op() {
                            SsaOp::Branch {
                                true_target,
                                false_target,
                                ..
                            }
                            | SsaOp::BranchCmp {
                                true_target,
                                false_target,
                                ..
                            } => {
                                let target = Self::choose_branch_target(
                                    ssa,
                                    *true_target,
                                    *false_target,
                                    &tainted_instrs,
                                    &tainted_phis_set,
                                    &can_reach_exit,
                                );
                                Some(InstrAction::Jump(target))
                            }
                            // Leave other terminators (Return, Throw, etc.) alone
                            _ => None,
                        }
                    } else {
                        Some(InstrAction::Nop)
                    };

                    if let Some(action) = action {
                        actions.push((block_idx, instr_idx, action));
                    }
                }
            }
        }

        // Second pass: apply the actions
        for (block_idx, instr_idx, action) in actions {
            if let Some(block) = ssa.block_mut(block_idx) {
                if let Some(instr) = block.instruction_mut(instr_idx) {
                    match action {
                        InstrAction::Nop => instr.set_op(SsaOp::Nop),
                        InstrAction::Jump(target) => instr.set_op(SsaOp::Jump { target }),
                    }
                    count += 1;
                }
            }
        }

        count
    }
}

impl SsaPass for NeutralizationPass<'_> {
    fn name(&self) -> &'static str {
        "neutralization"
    }

    fn description(&self) -> &'static str {
        "Removes instructions referencing removed protection infrastructure"
    }

    fn run_on_method(
        &self,
        ssa: &mut SsaFunction,
        method_token: Token,
        ctx: &CompilerContext,
        _assembly: &Arc<CilObject>,
    ) -> Result<bool> {
        let neutralized = self.neutralize_method(ssa);

        if neutralized > 0 {
            ctx.events
                .record(EventKind::InstructionRemoved)
                .method(method_token)
                .message(format!(
                    "Neutralized {neutralized} instructions referencing removed tokens"
                ));
        }

        Ok(neutralized > 0)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use crate::{
        analysis::{ConstValue, MethodRef, SsaBlock, SsaFunction, SsaInstruction, SsaOp, SsaVarId},
        deobfuscation::passes::NeutralizationPass,
        metadata::token::Token,
    };

    /// Creates a simple SSA function with instructions referencing tokens.
    fn create_test_ssa() -> (SsaFunction, Token, Token) {
        let mut ssa = SsaFunction::new(0, 1);

        let method_token = Token::new(0x06000001);
        let field_token = Token::new(0x04000001);

        let v0 = SsaVarId::new();
        let v1 = SsaVarId::new();
        let v2 = SsaVarId::new();

        // Block 0:
        //   v0 = const 42
        //   v1 = call method_token()  <- references method_token
        //   v2 = add v0, v1            <- depends on v1, should be tainted
        //   ret v2
        let mut b0 = SsaBlock::new(0);

        b0.add_instruction(SsaInstruction::synthetic(SsaOp::Const {
            dest: v0,
            value: ConstValue::I32(42),
        }));

        // Create a call instruction referencing the method token
        let method_ref = MethodRef::new(method_token);

        b0.add_instruction(SsaInstruction::synthetic(SsaOp::Call {
            dest: Some(v1),
            method: method_ref,
            args: vec![],
        }));

        b0.add_instruction(SsaInstruction::synthetic(SsaOp::Add {
            dest: v2,
            left: v0,
            right: v1,
        }));

        b0.add_instruction(SsaInstruction::synthetic(SsaOp::Return { value: Some(v2) }));

        ssa.add_block(b0);

        (ssa, method_token, field_token)
    }

    #[test]
    fn test_neutralization_removes_tainted_instructions() {
        let (mut ssa, method_token, _) = create_test_ssa();

        let mut removed = HashSet::new();
        removed.insert(method_token);

        let pass = NeutralizationPass::new(&removed);
        let count = pass.neutralize_method(&mut ssa);

        // Should have neutralized the call and the add (which depends on call result)
        // The const and return should remain (const is independent, return is terminator)
        assert!(
            count >= 2,
            "Expected at least 2 instructions neutralized, got {}",
            count
        );

        // Verify the call was replaced with Nop
        let block = ssa.block(0).unwrap();
        let call_instr = &block.instructions()[1];
        assert!(matches!(call_instr.op(), SsaOp::Nop));

        // Verify the add was replaced with Nop
        let add_instr = &block.instructions()[2];
        assert!(matches!(add_instr.op(), SsaOp::Nop));

        // Verify return is still there (terminators are preserved)
        let ret_instr = &block.instructions()[3];
        assert!(matches!(ret_instr.op(), SsaOp::Return { .. }));
    }

    #[test]
    fn test_neutralization_preserves_unrelated_code() {
        let (mut ssa, _, field_token) = create_test_ssa();

        // Remove a token that isn't referenced in our test SSA
        let mut removed = HashSet::new();
        removed.insert(field_token);

        let pass = NeutralizationPass::new(&removed);
        let count = pass.neutralize_method(&mut ssa);

        // Nothing should be neutralized
        assert_eq!(count, 0);

        // All instructions should still be there
        let block = ssa.block(0).unwrap();
        assert!(!matches!(block.instructions()[0].op(), SsaOp::Nop));
        assert!(!matches!(block.instructions()[1].op(), SsaOp::Nop));
        assert!(!matches!(block.instructions()[2].op(), SsaOp::Nop));
    }
}
