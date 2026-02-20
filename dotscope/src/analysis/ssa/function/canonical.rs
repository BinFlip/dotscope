//! Canonicalization of SSA functions for clean code generation.
//!
//! Strips Nops, removes empty blocks, compacts block indices, and
//! ensures valid terminators after deobfuscation passes.

use std::collections::{HashMap, HashSet};

use crate::analysis::ssa::{PhiOperand, SsaBlock, SsaFunction, SsaInstruction, SsaOp, SsaVarId};

/// Finds kept predecessors of a removed block during canonicalization.
///
/// When a block is removed, we need to find the actual predecessor blocks
/// (that are being kept) which would flow into the removed block. This is
/// used to properly update PHI node predecessors.
///
/// The function follows predecessor chains through removed blocks until it
/// finds blocks that are being kept (have entries in `block_remap`).
pub(crate) fn find_kept_predecessors(
    removed_block: usize,
    predecessors: &HashMap<usize, Vec<usize>>,
    block_remap: &[Option<usize>],
    redirect_map: &HashMap<usize, usize>,
) -> Vec<usize> {
    let mut result = Vec::new();
    let mut visited = HashSet::new();
    let mut queue = vec![removed_block];

    while let Some(current) = queue.pop() {
        if !visited.insert(current) {
            continue;
        }

        if let Some(preds) = predecessors.get(&current) {
            for &pred in preds {
                if let Some(Some(new_idx)) = block_remap.get(pred) {
                    // This predecessor is kept - add its new index
                    result.push(*new_idx);
                } else if redirect_map.contains_key(&pred) {
                    // This predecessor is also removed - follow the chain
                    queue.push(pred);
                }
            }
        }
    }

    result
}

impl SsaFunction {
    /// Canonicalizes the SSA function for clean code generation.
    ///
    /// This method performs final cleanup after deobfuscation passes:
    ///
    /// 1. **Strip Nop instructions**: Removes all `SsaOp::Nop` instructions
    /// 2. **Identify empty blocks**: Marks blocks with no instructions or phi nodes for removal
    /// 3. **Build redirect map**: For removed blocks, finds their ultimate jump targets
    /// 4. **Update branch targets**: Retargets jumps to skip removed empty blocks
    /// 5. **Update PHI predecessors**: Fixes PHI node operands when predecessor blocks are removed
    /// 6. **Compact blocks**: Removes empty blocks and renumbers remaining blocks contiguously
    ///
    /// This should be called after all deobfuscation passes complete, before
    /// code generation. The resulting SSA is cleaner and easier to convert to IL.
    pub fn canonicalize(&mut self) {
        // Phase 1: Strip Nop instructions from all blocks
        for block in &mut self.blocks {
            block
                .instructions_mut()
                .retain(|instr| !matches!(instr.op(), SsaOp::Nop));
        }

        // Collect blocks that must be preserved:
        // - Exception handler entry blocks
        // - Leave targets (exception handler exit blocks)
        let mut protected_blocks: HashSet<usize> = HashSet::new();

        // Protect exception handler entry blocks
        for handler in &self.exception_handlers {
            if let Some(handler_block) = handler.handler_start_block {
                protected_blocks.insert(handler_block);
            }
            if let Some(filter_block) = handler.filter_start_block {
                protected_blocks.insert(filter_block);
            }
        }

        // Protect Leave targets (exception handler exit blocks)
        for block in &self.blocks {
            if let Some(SsaOp::Leave { target }) = block.terminator_op() {
                protected_blocks.insert(*target);
            }
        }

        // Phase 2: Identify empty blocks and build remapping.
        // An empty block has no instructions AND no phi nodes.
        // Exception: Keep block 0 (entry) and protected exception handler blocks even if empty.
        let mut block_remap: Vec<Option<usize>> = Vec::with_capacity(self.blocks.len());
        let mut new_index = 0usize;

        for (old_index, block) in self.blocks.iter().enumerate() {
            let is_empty = block.instructions().is_empty() && block.phi_nodes().is_empty();
            let is_entry = old_index == 0;
            let is_protected = protected_blocks.contains(&old_index);

            if is_empty && !is_entry && !is_protected {
                block_remap.push(None); // This block will be removed
            } else {
                block_remap.push(Some(new_index));
                new_index += 1;
            }
        }

        // Phase 3: Build redirect map for removed blocks.
        // For each removed block, find its ultimate jump target (following jump chains).
        // If we can't find a redirect for a block, we must keep it instead of removing it.
        let mut redirect_map: HashMap<usize, usize> = HashMap::new();

        for old_index in 0..self.blocks.len() {
            if block_remap[old_index].is_none() {
                // This block is being removed - find where it would jump to
                if let Some(target) = self.find_ultimate_target(old_index, &block_remap) {
                    redirect_map.insert(old_index, target);
                } else {
                    // Can't find a redirect target - we must keep this block.
                    // Reassign it a new index.
                    block_remap[old_index] = Some(new_index);
                    new_index += 1;
                }
            }
        }

        // Build predecessor map for PHI updates (needed for Phase 5).
        // For each block, collect all blocks that have edges TO it.
        let mut predecessors: HashMap<usize, Vec<usize>> = HashMap::new();
        for (block_idx, block) in self.blocks.iter().enumerate() {
            for target in block.successors() {
                predecessors.entry(target).or_default().push(block_idx);
            }
        }

        // Phase 4: Update all branch targets in remaining blocks.
        for block in &mut self.blocks {
            for instr in block.instructions_mut() {
                Self::remap_branch_targets(instr.op_mut(), &block_remap, &redirect_map);
            }
        }

        // Phase 5: Update PHI node predecessors.
        // When a predecessor block is removed, we find the kept blocks that would have
        // flowed into the removed block and use those as the new predecessors.
        //
        // Special case: Some PHI operands may reference orphaned blocks (blocks with no
        // predecessors). This happens when deobfuscation passes modify the CFG without
        // properly updating PHI predecessors. We try to recover these by assigning
        // orphaned values to unaccounted-for predecessors.

        // Process each block's PHI nodes
        for block_idx in 0..self.blocks.len() {
            // Get the predecessors of THIS block (the one containing the PHI)
            // These are the OLD indices of blocks that jump to this block.
            let phi_block_preds: Vec<usize> =
                predecessors.get(&block_idx).cloned().unwrap_or_default();

            // Also compute the NEW indices of kept predecessors
            let kept_phi_block_preds: Vec<usize> = phi_block_preds
                .iter()
                .filter_map(|&old_pred| block_remap.get(old_pred).and_then(|opt| *opt))
                .collect();

            let block = &mut self.blocks[block_idx];
            for phi in block.phi_nodes_mut() {
                // Collect changes first (to avoid borrow issues)
                let mut changes: Vec<(usize, Option<PhiOperand>, Vec<PhiOperand>)> = Vec::new();
                // Track orphaned values (removed operands with no replacement)
                let mut orphaned_values: Vec<SsaVarId> = Vec::new();

                for (op_idx, operand) in phi.operands().iter().enumerate() {
                    let old_pred = operand.predecessor();
                    let value = operand.value();

                    if redirect_map.contains_key(&old_pred) {
                        // This predecessor was removed. Find all kept blocks that flow into it.
                        let kept_preds = find_kept_predecessors(
                            old_pred,
                            &predecessors,
                            &block_remap,
                            &redirect_map,
                        );

                        if kept_preds.is_empty() {
                            // Orphaned operand - track the value for potential recovery below
                            orphaned_values.push(value);
                        }

                        let replacements: Vec<PhiOperand> = kept_preds
                            .into_iter()
                            .map(|new_pred| PhiOperand::new(value, new_pred))
                            .collect();

                        // None = remove this operand, replacements = add these instead
                        changes.push((op_idx, None, replacements));
                    } else if let Some(Some(new_pred)) = block_remap.get(old_pred) {
                        // Predecessor was kept but renumbered - update in place
                        changes.push((op_idx, Some(PhiOperand::new(value, *new_pred)), Vec::new()));
                    }
                }

                // Apply changes in reverse order (to preserve indices when removing)
                for (op_idx, replacement, additions) in changes.into_iter().rev() {
                    if let Some(new_op) = replacement {
                        // Update in place
                        if let Some(operand) = phi.operands_mut().get_mut(op_idx) {
                            *operand = new_op;
                        }
                    } else {
                        // Remove the operand
                        phi.operands_mut().remove(op_idx);
                        // Add replacement operands
                        for op in additions {
                            phi.add_operand(op);
                        }
                    }
                }

                // Post-processing: try to recover orphaned values by assigning them
                // to unaccounted-for predecessors.
                if !orphaned_values.is_empty() {
                    // Get the predecessors that are currently accounted for in the PHI
                    let accounted_preds: HashSet<usize> =
                        phi.operands().iter().map(PhiOperand::predecessor).collect();

                    // Find predecessors that are NOT accounted for
                    let unaccounted_preds: Vec<usize> = kept_phi_block_preds
                        .iter()
                        .copied()
                        .filter(|pred| !accounted_preds.contains(pred))
                        .collect();

                    // Assign orphaned values to unaccounted predecessors
                    for (orphan_val, &unaccounted_pred) in
                        orphaned_values.iter().zip(unaccounted_preds.iter())
                    {
                        phi.add_operand(PhiOperand::new(*orphan_val, unaccounted_pred));
                    }
                }
            }
        }

        // Phase 6: Remove empty blocks and compact block indices.
        let mut kept_blocks: Vec<SsaBlock> = Vec::with_capacity(new_index);
        for (old_index, block) in self.blocks.drain(..).enumerate() {
            if block_remap[old_index].is_some() {
                kept_blocks.push(block);
            }
        }

        // Update block indices in kept blocks
        for (new_idx, block) in kept_blocks.iter_mut().enumerate() {
            block.set_id(new_idx);
        }

        self.blocks = kept_blocks;

        // Phase 7: Remap exception handler block indices.
        for handler in &mut self.exception_handlers {
            handler.remap_block_indices(&block_remap);
        }

        // Phase 8: Ensure the method has a valid terminator.
        self.ensure_valid_terminator();
    }

    /// Ensures the function has a valid terminator path from the entry block.
    ///
    /// This handles the case where all meaningful code has been removed (e.g., after
    /// neutralizing 100% protection code in a module .cctor), leaving only Jumps to
    /// empty blocks. In such cases, we replace the entry block's terminator with a
    /// Return instruction to produce valid IL.
    fn ensure_valid_terminator(&mut self) {
        // Check if the method effectively does nothing useful:
        // - Only has Jump instructions (no actual code)
        // - All Jump targets lead to empty blocks or more Jumps
        let has_useful_code = self.blocks.iter().any(|block| {
            block.instructions().iter().any(|instr| {
                match instr.op() {
                    // Jumps and Nops don't count as useful - they're just control flow
                    SsaOp::Jump { .. } | SsaOp::Nop => false,
                    // Any other instruction (including returns, throws) is useful code
                    _ => true,
                }
            })
        });

        // If there's no useful code, replace entry block with just a Return
        if !has_useful_code {
            if let Some(entry_block) = self.blocks.first_mut() {
                entry_block.instructions_mut().clear();
                entry_block.phi_nodes_mut().clear();
                entry_block
                    .add_instruction(SsaInstruction::synthetic(SsaOp::Return { value: None }));
            }
        }
    }

    /// Finds the ultimate jump target for a block, following jump chains.
    ///
    /// Used during canonicalization to find where an empty block would
    /// ultimately transfer control to.
    fn find_ultimate_target(
        &self,
        block_idx: usize,
        block_remap: &[Option<usize>],
    ) -> Option<usize> {
        let mut visited = HashSet::new();
        let mut current = block_idx;

        while visited.insert(current) {
            let block = self.blocks.get(current)?;

            // Get the terminator's target
            let terminator = block.terminator_op();
            let target = terminator.and_then(|op| match op {
                SsaOp::Jump { target } => Some(*target),
                // For branches, we can't simplify - the block isn't truly empty
                _ => None,
            });

            // Handle the target
            match target {
                Some(t) if block_remap.get(t).copied().flatten().is_some() => {
                    // Target exists in new layout
                    return block_remap.get(t).copied().flatten();
                }
                Some(t) => {
                    // Target is also being removed, follow the chain
                    current = t;
                }
                None => {
                    // No explicit jump target. Check if block is truly empty (no terminator).
                    // In CIL semantics, empty blocks fall through to the next block.
                    if terminator.is_none() && block.instructions().is_empty() {
                        // Try to fall through to the next block
                        let next_block = current + 1;
                        if next_block < self.blocks.len() {
                            if let Some(Some(new_idx)) = block_remap.get(next_block) {
                                // Next block exists in new layout
                                return Some(*new_idx);
                            } else if block_remap.get(next_block).is_some() {
                                // Next block is also being removed, follow the chain
                                current = next_block;
                                continue;
                            }
                        }
                    }
                    // No simple jump target and no fall-through, can't redirect
                    return None;
                }
            }
        }

        None // Cycle detected
    }

    /// Remaps branch targets according to the block remapping.
    fn remap_branch_targets(
        op: &mut SsaOp,
        block_remap: &[Option<usize>],
        redirect_map: &HashMap<usize, usize>,
    ) {
        // Helper closure to remap a single target
        let remap_target = |target: &mut usize| {
            // First try redirect_map (for removed blocks with known targets)
            if let Some(&new_target) = redirect_map.get(target) {
                *target = new_target;
                return;
            }
            // Then try block_remap (for kept blocks)
            if let Some(Some(new_target)) = block_remap.get(*target) {
                *target = *new_target;
            }
        };

        match op {
            SsaOp::Jump { target } | SsaOp::Leave { target } => {
                remap_target(target);
            }
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
                remap_target(true_target);
                remap_target(false_target);
            }
            SsaOp::Switch {
                targets, default, ..
            } => {
                for target in targets.iter_mut() {
                    remap_target(target);
                }
                remap_target(default);
            }
            _ => {}
        }
    }
}
