//! Block duplication and cloning for SSA functions.
//!
//! These methods handle allocating fresh variables, cloning blocks with
//! remapped variable IDs, and updating branch targets.

use std::collections::HashMap;

use crate::analysis::ssa::{
    PhiNode, PhiOperand, SsaBlock, SsaFunction, SsaInstruction, SsaOp, SsaVarId,
};

impl SsaFunction {
    /// Allocates fresh SSA variable IDs for all variables defined in a block.
    ///
    /// This creates new unique IDs for each variable defined by:
    /// - Phi nodes in the block
    /// - Instructions that produce results
    ///
    /// The returned mapping maps old variable IDs to their fresh replacements.
    /// Variables that are only used (not defined) in the block are not included
    /// in the mapping - they should reference the original variables.
    ///
    /// # Arguments
    ///
    /// * `block_idx` - The index of the block to analyze
    ///
    /// # Returns
    ///
    /// A mapping from original variable IDs to fresh IDs, or `None` if the
    /// block index is invalid.
    #[must_use]
    pub fn allocate_fresh_variables_for_block(
        &mut self,
        block_idx: usize,
    ) -> Option<HashMap<SsaVarId, SsaVarId>> {
        let block = self.block(block_idx)?;
        let mut mapping = HashMap::new();

        // Collect IDs to allocate (can't borrow self mutably while reading block)
        let phi_ids: Vec<SsaVarId> = block.phi_nodes().iter().map(|phi| phi.result()).collect();
        let instr_dests: Vec<SsaVarId> = block
            .instructions()
            .iter()
            .filter_map(|instr| instr.op().dest())
            .collect();

        // Allocate fresh IDs for phi node results
        for old_id in phi_ids {
            let new_id = self.var_allocator.alloc();
            mapping.insert(old_id, new_id);
        }

        // Allocate fresh IDs for instruction defs
        for dest in instr_dests {
            let new_id = self.var_allocator.alloc();
            mapping.insert(dest, new_id);
        }

        Some(mapping)
    }

    /// Clones a block with remapped variable IDs.
    ///
    /// This creates a deep copy of the block where all variable references
    /// are transformed through the provided remapping function. Variables
    /// not in the mapping are left unchanged (allowing references to
    /// variables defined outside the block).
    ///
    /// The new block is assigned the specified ID but is NOT automatically
    /// added to the function - the caller must add it explicitly.
    ///
    /// # Arguments
    ///
    /// * `block_idx` - The index of the block to clone
    /// * `new_block_id` - The ID to assign to the cloned block
    /// * `var_remap` - Mapping from old variable IDs to new ones
    /// * `pred_remap` - Optional mapping for predecessor block indices in phi nodes
    ///
    /// # Returns
    ///
    /// A new `SsaBlock` with remapped variables, or `None` if the block doesn't exist.
    #[must_use]
    pub fn clone_block_with_remap(
        &self,
        block_idx: usize,
        new_block_id: usize,
        var_remap: &HashMap<SsaVarId, SsaVarId>,
        pred_remap: Option<&HashMap<usize, usize>>,
    ) -> Option<SsaBlock> {
        let block = self.block(block_idx)?;

        let mut new_block =
            SsaBlock::with_capacity(new_block_id, block.phi_count(), block.instruction_count());

        // Clone phi nodes with remapped variables and predecessors
        for phi in block.phi_nodes() {
            let new_result = var_remap
                .get(&phi.result())
                .copied()
                .unwrap_or(phi.result());
            let mut new_phi = PhiNode::with_capacity(new_result, phi.origin(), phi.operand_count());

            for operand in phi.operands() {
                let new_value = var_remap
                    .get(&operand.value())
                    .copied()
                    .unwrap_or(operand.value());
                let new_pred = pred_remap
                    .and_then(|m| m.get(&operand.predecessor()).copied())
                    .unwrap_or(operand.predecessor());
                new_phi.add_operand(PhiOperand::new(new_value, new_pred));
            }

            new_block.add_phi(new_phi);
        }

        // Clone instructions with remapped variables
        for instr in block.instructions() {
            let new_instr = Self::clone_instruction_with_remap(instr, var_remap);
            new_block.add_instruction(new_instr);
        }

        Some(new_block)
    }

    /// Clones an instruction with remapped variable IDs.
    ///
    /// Creates a copy of the instruction where all variable references are
    /// transformed through the provided mapping. The original CIL instruction
    /// is preserved (cloned) but the SSA operation uses new variable IDs.
    ///
    /// # Arguments
    ///
    /// * `instr` - The instruction to clone
    /// * `var_remap` - Mapping from old variable IDs to new ones
    ///
    /// # Returns
    ///
    /// A new `SsaInstruction` with remapped variables.
    fn clone_instruction_with_remap(
        instr: &SsaInstruction,
        var_remap: &HashMap<SsaVarId, SsaVarId>,
    ) -> SsaInstruction {
        let original = instr.original().clone();

        // Use the remap_variables method on SsaOp
        let new_op = instr
            .op()
            .remap_variables(|old_id| var_remap.get(&old_id).copied());
        let mut new_instr = SsaInstruction::new(original, new_op);
        new_instr.set_result_type(instr.result_type().cloned());
        new_instr
    }

    /// Duplicates a block, creating a complete copy with fresh variables.
    ///
    /// This is a high-level method that:
    /// 1. Allocates fresh variable IDs for all definitions in the block
    /// 2. Creates corresponding `SsaVariable` entries for each new ID
    /// 3. Clones the block with the remapped variables
    /// 4. Adds the new block to the function
    ///
    /// The new block is assigned the next available block ID.
    ///
    /// # Arguments
    ///
    /// * `block_idx` - The index of the block to duplicate
    ///
    /// # Returns
    ///
    /// A tuple of (new_block_id, variable_mapping), or `None` if the block doesn't exist.
    /// The variable_mapping maps original variable IDs to their duplicated counterparts.
    pub fn duplicate_block(
        &mut self,
        block_idx: usize,
    ) -> Option<(usize, HashMap<SsaVarId, SsaVarId>)> {
        // Allocate fresh variables
        let var_remap = self.allocate_fresh_variables_for_block(block_idx)?;

        // Create SsaVariable entries for each new variable via create_variable.
        // We need to collect the info first to avoid borrow conflicts.
        let var_info: Vec<_> = var_remap
            .iter()
            .filter_map(|(&old_id, _)| {
                self.variable(old_id).map(|v| {
                    (
                        old_id,
                        v.origin(),
                        v.version(),
                        v.def_site(),
                        v.var_type().clone(),
                    )
                })
            })
            .collect();
        // Now create new variables — they get fresh IDs from the allocator
        // which match the pre-allocated IDs from allocate_fresh_variables_for_block
        for (_old_id, origin, version, def_site, var_type) in var_info {
            self.create_variable(origin, version, def_site, var_type);
        }

        // Clone the block with new ID
        let new_block_id = self.blocks.len();
        let new_block = self.clone_block_with_remap(block_idx, new_block_id, &var_remap, None)?;
        self.add_block(new_block);

        Some((new_block_id, var_remap))
    }

    /// Updates branch targets in a block to point to new destinations.
    ///
    /// This modifies the terminator instruction of the specified block,
    /// remapping any target block indices according to the provided mapping.
    /// Targets not in the mapping are left unchanged.
    ///
    /// # Arguments
    ///
    /// * `block_idx` - The block whose terminator to update
    /// * `target_remap` - Mapping from old target indices to new ones
    ///
    /// # Returns
    ///
    /// `true` if any targets were updated, `false` otherwise.
    pub fn remap_block_targets(
        &mut self,
        block_idx: usize,
        target_remap: &HashMap<usize, usize>,
    ) -> bool {
        let Some(block) = self.block_mut(block_idx) else {
            return false;
        };
        let Some(last) = block.instructions_mut().last_mut() else {
            return false;
        };
        let new_op = match last.op() {
            SsaOp::Jump { target } => {
                if let Some(&new_target) = target_remap.get(target) {
                    SsaOp::Jump { target: new_target }
                } else {
                    return false;
                }
            }
            SsaOp::Branch {
                condition,
                true_target,
                false_target,
            } => {
                let new_true = target_remap
                    .get(true_target)
                    .copied()
                    .unwrap_or(*true_target);
                let new_false = target_remap
                    .get(false_target)
                    .copied()
                    .unwrap_or(*false_target);
                if new_true == *true_target && new_false == *false_target {
                    return false;
                }
                SsaOp::Branch {
                    condition: *condition,
                    true_target: new_true,
                    false_target: new_false,
                }
            }
            SsaOp::BranchCmp {
                left,
                right,
                cmp,
                unsigned,
                true_target,
                false_target,
            } => {
                let new_true = target_remap
                    .get(true_target)
                    .copied()
                    .unwrap_or(*true_target);
                let new_false = target_remap
                    .get(false_target)
                    .copied()
                    .unwrap_or(*false_target);
                if new_true == *true_target && new_false == *false_target {
                    return false;
                }
                SsaOp::BranchCmp {
                    left: *left,
                    right: *right,
                    cmp: *cmp,
                    unsigned: *unsigned,
                    true_target: new_true,
                    false_target: new_false,
                }
            }
            SsaOp::Switch {
                value,
                targets,
                default,
            } => {
                let new_targets: Vec<usize> = targets
                    .iter()
                    .map(|&t| target_remap.get(&t).copied().unwrap_or(t))
                    .collect();
                let new_default = target_remap.get(default).copied().unwrap_or(*default);
                if new_targets == *targets && new_default == *default {
                    return false;
                }
                SsaOp::Switch {
                    value: *value,
                    targets: new_targets,
                    default: new_default,
                }
            }
            _ => return false,
        };

        last.set_op(new_op);
        true
    }
}
