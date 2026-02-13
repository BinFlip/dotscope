//! SSA basic blocks containing phi nodes and instructions.
//!
//! An SSA block is the SSA-form representation of a CFG basic block. It contains:
//!
//! - **Phi nodes**: At the block entry, merging values from predecessors
//! - **Instructions**: SSA-form instructions with explicit def/use
//!
//! # Block Structure
//!
//! ```text
//! Block B:
//!   // Phi nodes (executed "simultaneously" at block entry)
//!   v3 = phi(v1 from B0, v2 from B1)
//!   v6 = phi(v4 from B0, v5 from B1)
//!
//!   // Instructions (executed sequentially)
//!   v7 = add v3, v6
//!   v8 = mul v7, v3
//!   br B2
//! ```
//!
//! # Semantics
//!
//! Phi nodes are evaluated at block entry before any instructions execute.
//! Conceptually, all phi nodes in a block read their operands simultaneously,
//! then all write their results simultaneously. This avoids ordering issues
//! when one phi's result is used as another phi's operand.
//!
//! # Thread Safety
//!
//! All types in this module are `Send` and `Sync`.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    fmt,
};

use crate::analysis::ssa::{PhiNode, PhiOperand, SsaInstruction, SsaOp, SsaVarId};

/// An SSA basic block with phi nodes and instructions.
///
/// This represents a basic block in SSA form. It maintains a parallel structure
/// to the CFG blocks but with explicit variable information.
///
/// # Examples
///
/// ```rust,ignore
/// use dotscope::analysis::{SsaBlock, PhiNode, SsaInstruction, SsaVarId, VariableOrigin};
///
/// let mut block = SsaBlock::new(0);
///
/// // Add a phi node
/// let v1 = SsaVarId::new();
/// let v2 = SsaVarId::new();
/// let result = SsaVarId::new();
/// let mut phi = PhiNode::new(result, VariableOrigin::Local(0));
/// phi.set_operand(0, v1);
/// phi.set_operand(1, v2);
/// block.add_phi(phi);
///
/// // Add instructions
/// block.add_instruction(some_ssa_instruction);
/// ```
#[derive(Debug, Clone)]
pub struct SsaBlock {
    /// Block index (matches CFG block index).
    id: usize,

    /// Phi nodes at block entry.
    ///
    /// These are evaluated "simultaneously" before any instructions.
    phi_nodes: Vec<PhiNode>,

    /// SSA instructions in execution order.
    instructions: Vec<SsaInstruction>,
}

impl SsaBlock {
    /// Creates a new empty SSA block.
    ///
    /// # Arguments
    ///
    /// * `id` - The block index (should match the corresponding CFG block)
    #[must_use]
    pub fn new(id: usize) -> Self {
        Self {
            id,
            phi_nodes: Vec::new(),
            instructions: Vec::new(),
        }
    }

    /// Creates a new SSA block with pre-allocated capacity.
    ///
    /// # Arguments
    ///
    /// * `id` - The block index
    /// * `phi_capacity` - Expected number of phi nodes
    /// * `instr_capacity` - Expected number of instructions
    #[must_use]
    pub fn with_capacity(id: usize, phi_capacity: usize, instr_capacity: usize) -> Self {
        Self {
            id,
            phi_nodes: Vec::with_capacity(phi_capacity),
            instructions: Vec::with_capacity(instr_capacity),
        }
    }

    /// Returns the block index.
    #[must_use]
    pub const fn id(&self) -> usize {
        self.id
    }

    /// Sets the block index.
    ///
    /// This is used during canonicalization when blocks are renumbered
    /// after empty blocks are removed.
    pub fn set_id(&mut self, id: usize) {
        self.id = id;
    }

    /// Returns the phi nodes in this block.
    #[must_use]
    pub fn phi_nodes(&self) -> &[PhiNode] {
        &self.phi_nodes
    }

    /// Returns a mutable reference to the phi nodes.
    pub fn phi_nodes_mut(&mut self) -> &mut Vec<PhiNode> {
        &mut self.phi_nodes
    }

    /// Returns the instructions in this block.
    #[must_use]
    pub fn instructions(&self) -> &[SsaInstruction] {
        &self.instructions
    }

    /// Returns a mutable reference to the instructions.
    pub fn instructions_mut(&mut self) -> &mut Vec<SsaInstruction> {
        &mut self.instructions
    }

    /// Returns the number of phi nodes.
    #[must_use]
    pub fn phi_count(&self) -> usize {
        self.phi_nodes.len()
    }

    /// Returns the number of instructions.
    #[must_use]
    pub fn instruction_count(&self) -> usize {
        self.instructions.len()
    }

    /// Returns `true` if this block has no phi nodes.
    #[must_use]
    pub fn has_no_phis(&self) -> bool {
        self.phi_nodes.is_empty()
    }

    /// Returns `true` if this block has no instructions.
    #[must_use]
    pub fn has_no_instructions(&self) -> bool {
        self.instructions.is_empty()
    }

    /// Returns `true` if this block is completely empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.phi_nodes.is_empty() && self.instructions.is_empty()
    }

    /// Clears all phi nodes and instructions from this block.
    ///
    /// After calling this method, `is_empty()` will return `true`.
    /// The block ID is preserved.
    pub fn clear(&mut self) {
        self.phi_nodes.clear();
        self.instructions.clear();
    }

    /// Adds a phi node to this block.
    pub fn add_phi(&mut self, phi: PhiNode) {
        self.phi_nodes.push(phi);
    }

    /// Adds an instruction to this block.
    pub fn add_instruction(&mut self, instr: SsaInstruction) {
        self.instructions.push(instr);
    }

    /// Gets a phi node by index.
    #[must_use]
    pub fn phi(&self, index: usize) -> Option<&PhiNode> {
        self.phi_nodes.get(index)
    }

    /// Gets a mutable phi node by index.
    pub fn phi_mut(&mut self, index: usize) -> Option<&mut PhiNode> {
        self.phi_nodes.get_mut(index)
    }

    /// Gets an instruction by index.
    #[must_use]
    pub fn instruction(&self, index: usize) -> Option<&SsaInstruction> {
        self.instructions.get(index)
    }

    /// Gets a mutable instruction by index.
    pub fn instruction_mut(&mut self, index: usize) -> Option<&mut SsaInstruction> {
        self.instructions.get_mut(index)
    }

    /// Gets the terminator instruction (last instruction in the block).
    ///
    /// In well-formed SSA, the last instruction should be a control flow
    /// instruction (Jump, Branch, Switch, Return, etc.).
    #[must_use]
    pub fn terminator(&self) -> Option<&SsaInstruction> {
        self.instructions.last()
    }

    /// Gets the terminator operation if the block has a terminator instruction.
    ///
    /// This is a convenience method combining `terminator()` and `op()`.
    #[must_use]
    pub fn terminator_op(&self) -> Option<&SsaOp> {
        self.instructions.last().map(SsaInstruction::op)
    }

    /// Returns the successor block indices for this block.
    ///
    /// The successors are determined by the terminator instruction:
    /// - Jump/Leave: single target
    /// - Branch/BranchCmp: true and false targets
    /// - Switch: all case targets plus default
    /// - Return/Throw/etc: no successors
    #[must_use]
    pub fn successors(&self) -> Vec<usize> {
        self.terminator_op()
            .map_or_else(Vec::new, super::SsaOp::successors)
    }

    /// Redirects control flow targets from `old_target` to `new_target`.
    ///
    /// This modifies the block's terminator instruction in-place, redirecting any
    /// occurrences of `old_target` to `new_target`. Works with all control flow
    /// instructions: `Jump`, `Leave`, `Branch`, `BranchCmp`, and `Switch`.
    ///
    /// # Arguments
    ///
    /// * `old_target` - The block index to redirect from
    /// * `new_target` - The block index to redirect to
    ///
    /// # Returns
    ///
    /// `true` if any target was changed, `false` otherwise.
    pub fn redirect_target(&mut self, old_target: usize, new_target: usize) -> bool {
        if let Some(terminator) = self.instructions.last_mut() {
            return terminator.op_mut().redirect_target(old_target, new_target);
        }
        false
    }

    /// Sets all control flow targets to a single destination.
    ///
    /// This forces the block to unconditionally transfer control to `target`,
    /// regardless of any branch conditions. For branches, both targets are set
    /// to the same value. For other terminators (like `Return` or `Throw`),
    /// the terminator is replaced with an unconditional `Jump`.
    ///
    /// If the block has no terminator, a `Jump` instruction is added.
    ///
    /// # Arguments
    ///
    /// * `target` - The block index to jump to
    pub fn set_target(&mut self, target: usize) {
        if let Some(terminator) = self.instructions.last_mut() {
            match terminator.op_mut() {
                SsaOp::Jump { target: t } | SsaOp::Leave { target: t } => {
                    *t = target;
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
                    *true_target = target;
                    *false_target = target;
                }
                SsaOp::Switch {
                    targets, default, ..
                } => {
                    *default = target;
                    for t in targets.iter_mut() {
                        *t = target;
                    }
                }
                _ => {
                    // Other terminators (Return, Throw, etc.) - replace with Jump
                    *terminator = SsaInstruction::synthetic(SsaOp::Jump { target });
                }
            }
        } else {
            // No terminator - add a Jump
            self.instructions
                .push(SsaInstruction::synthetic(SsaOp::Jump { target }));
        }
    }

    /// Replaces all uses of `old_var` with `new_var` within this block.
    ///
    /// This replaces uses in both instructions and phi node operands. Instructions
    /// that would become self-referential (where the destination equals `new_var`)
    /// are skipped to maintain SSA validity.
    ///
    /// # Arguments
    ///
    /// * `old_var` - The variable ID to find and replace
    /// * `new_var` - The variable ID to replace with
    ///
    /// # Returns
    ///
    /// The number of uses that were replaced.
    ///
    /// # Note
    ///
    /// This method only replaces uses in instructions, not in PHI operands.
    /// This is the safe default that avoids creating cross-origin PHI operand
    /// references which can break `rebuild_ssa`. For internal operations that
    /// need to also replace PHI operands (like eliminating trivial PHIs), use
    /// `replace_uses_including_phis`.
    pub fn replace_uses(&mut self, old_var: SsaVarId, new_var: SsaVarId) -> usize {
        let mut replaced = 0;

        // Replace in instructions only
        for instr in &mut self.instructions {
            let op = instr.op_mut();
            // Skip if this would create a self-referential instruction
            if let Some(dest) = op.dest() {
                if dest == new_var {
                    continue;
                }
            }
            let count = op.replace_uses(old_var, new_var);
            if count > 0 {
                replaced += count;
            }
        }

        replaced
    }

    /// Replaces all uses of `old_var` with `new_var`, including in PHI operands.
    ///
    /// Unlike [`replace_uses`](Self::replace_uses), this method also replaces uses
    /// in PHI node operands. This is necessary for internal SSA operations that
    /// eliminate PHI nodes and need to forward their values through other PHIs.
    ///
    /// # Arguments
    ///
    /// * `old_var` - The variable ID to find and replace.
    /// * `new_var` - The variable ID to use as the replacement.
    ///
    /// # Returns
    ///
    /// The number of uses that were replaced (in both instructions and PHI operands).
    ///
    /// # Safety
    ///
    /// This method is `pub(crate)` because it can create cross-origin PHI operand
    /// references if misused. The issue: `rebuild_ssa` uses a `phi_operand_origins`
    /// map that can only store ONE origin per variable. If a variable becomes a PHI
    /// operand for PHIs with different origins (e.g., Local(0) and Local(1)), only
    /// one origin is stored, causing incorrect def site classification and broken
    /// PHI placement.
    ///
    /// # When to Use
    ///
    /// Only use this method for:
    /// - **Trivial PHI elimination**: When removing a PHI like `v10 = phi(v5, v5)`,
    ///   we need to replace uses of `v10` with `v5` everywhere, including in other
    ///   PHI operands.
    /// - **Copy propagation within PHIs**: When a copy's destination is a PHI result
    ///   and we're eliminating that PHI.
    ///
    /// For optimization passes (copy propagation, GVN, etc.), use [`replace_uses`]
    /// instead, which safely skips PHI operands.
    pub(crate) fn replace_uses_including_phis(
        &mut self,
        old_var: SsaVarId,
        new_var: SsaVarId,
    ) -> usize {
        let mut replaced = 0;

        // Replace in instructions
        for instr in &mut self.instructions {
            let op = instr.op_mut();
            // Skip if this would create a self-referential instruction
            if let Some(dest) = op.dest() {
                if dest == new_var {
                    continue;
                }
            }
            let count = op.replace_uses(old_var, new_var);
            if count > 0 {
                replaced += count;
            }
        }

        // Replace in phi node operands
        for phi in &mut self.phi_nodes {
            for operand in phi.operands_mut() {
                if operand.value() == old_var {
                    *operand = PhiOperand::new(new_var, operand.predecessor());
                    replaced += 1;
                }
            }
        }

        replaced
    }

    /// Finds a phi node that defines the given variable.
    #[must_use]
    pub fn find_phi_defining(&self, var: SsaVarId) -> Option<&PhiNode> {
        self.phi_nodes.iter().find(|phi| phi.result() == var)
    }

    /// Checks if this block is a trampoline block.
    ///
    /// A trampoline block is one that:
    /// - Has no phi nodes (doesn't merge values from multiple predecessors)
    /// - Contains only a single unconditional control transfer (`Jump` or `Leave`)
    ///
    /// Trampoline blocks can be bypassed by redirecting predecessors directly
    /// to their targets.
    ///
    /// # Returns
    ///
    /// `Some(target)` if this block is a trampoline to `target`, `None` otherwise.
    ///
    /// # Example
    ///
    /// ```ignore
    /// if let Some(target) = block.is_trampoline() {
    ///     // Block is a trampoline to `target`
    /// }
    /// ```
    #[must_use]
    pub fn is_trampoline(&self) -> Option<usize> {
        // Blocks with phi nodes cannot be trampolines (they merge values)
        if !self.phi_nodes.is_empty() {
            return None;
        }

        // Must have exactly one operation
        if self.instructions.len() != 1 {
            return None;
        }

        // That operation must be an unconditional control transfer
        match self.instructions[0].op() {
            SsaOp::Jump { target } | SsaOp::Leave { target } => Some(*target),
            _ => None,
        }
    }

    /// Returns all variables defined in this block.
    ///
    /// This includes phi node results and instruction defs.
    pub fn defined_variables(&self) -> impl Iterator<Item = SsaVarId> + '_ {
        let phi_defs = self.phi_nodes.iter().map(PhiNode::result);
        let instr_defs = self.instructions.iter().filter_map(SsaInstruction::def);
        phi_defs.chain(instr_defs)
    }

    /// Returns all variables used in this block.
    ///
    /// This includes phi operands and instruction uses.
    pub fn used_variables(&self) -> impl Iterator<Item = SsaVarId> + '_ {
        let phi_uses = self.phi_nodes.iter().flat_map(PhiNode::used_variables);
        let instr_uses = self.instructions.iter().flat_map(SsaInstruction::uses);
        phi_uses.chain(instr_uses)
    }

    /// Sorts instructions within this block in topological order based on data dependencies.
    ///
    /// After sorting, if instruction A uses a value defined by instruction B (within this block),
    /// then B will appear before A in the instruction list.
    ///
    /// # Algorithm
    ///
    /// Uses Kahn's algorithm for topological sorting:
    /// 1. Build a dependency graph: instruction -> instructions it depends on
    /// 2. Start with instructions that have no dependencies within the block
    /// 3. Process in order, adding instructions whose dependencies are satisfied
    ///
    /// # Stability
    ///
    /// For instructions with no ordering constraints between them, the original
    /// relative order is preserved where possible.
    ///
    /// # Returns
    ///
    /// `true` if sorting succeeded, `false` if there was a cyclic dependency
    /// (which indicates invalid SSA). When a cycle is detected, the block is
    /// left unchanged.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// // Before: v2 = use(v1); v1 = define(); (invalid order)
    /// let sorted = block.sort_instructions_topologically();
    /// assert!(sorted);
    /// // After: v1 = define(); v2 = use(v1); (valid order)
    /// ```
    pub fn sort_instructions_topologically(&mut self) -> bool {
        if self.instructions.len() <= 1 {
            return true;
        }

        // IMPORTANT: Terminators must always be at the end of the block.
        // Extract terminator instructions first, sort non-terminators, then append terminators.
        // This prevents the sorting algorithm from moving terminators to the middle.
        let mut terminators: Vec<(usize, SsaInstruction)> = Vec::new();
        let mut non_terminator_indices: Vec<usize> = Vec::new();

        for (idx, instr) in self.instructions.iter().enumerate() {
            if instr.is_terminator() {
                terminators.push((idx, instr.clone()));
            } else {
                non_terminator_indices.push(idx);
            }
        }

        // If all instructions are terminators or there's nothing to sort, we're done
        if non_terminator_indices.is_empty() {
            return true;
        }

        // Build map of var_id -> instruction index that defines it (within this block)
        // Only for non-terminator instructions
        let mut def_index: HashMap<SsaVarId, usize> = HashMap::new();
        for &idx in &non_terminator_indices {
            if let Some(dest) = self.instructions[idx].def() {
                def_index.insert(dest, idx);
            }
        }

        // Also include phi node definitions as "available from the start"
        let phi_defs: HashSet<SsaVarId> = self.phi_nodes.iter().map(PhiNode::result).collect();

        // Build dependency graph for non-terminator instructions only
        // Map from original index to position in non_terminator_indices
        let idx_to_pos: HashMap<usize, usize> = non_terminator_indices
            .iter()
            .enumerate()
            .map(|(pos, &idx)| (idx, pos))
            .collect();

        let n = non_terminator_indices.len();
        let mut deps: Vec<HashSet<usize>> = vec![HashSet::new(); n];
        let mut rdeps: Vec<HashSet<usize>> = vec![HashSet::new(); n]; // reverse

        // Track the previous side-effecting instruction position to preserve ordering.
        // Side-effecting operations (Call, CallVirt, Stfld, etc.) must execute in their
        // original order to preserve program semantics (I/O ordering, memory effects).
        let mut prev_side_effect_pos: Option<usize> = None;

        for (pos, &idx) in non_terminator_indices.iter().enumerate() {
            let instr = &self.instructions[idx];

            // Add data dependencies (def-use chains)
            for used in &instr.uses() {
                // Skip if defined by phi (always available)
                if phi_defs.contains(used) {
                    continue;
                }
                // Skip if not defined in this block
                if let Some(&dep_idx) = def_index.get(used) {
                    if dep_idx != idx {
                        if let Some(&dep_pos) = idx_to_pos.get(&dep_idx) {
                            // instruction at pos depends on instruction at dep_pos
                            deps[pos].insert(dep_pos);
                            rdeps[dep_pos].insert(pos);
                        }
                    }
                }
            }

            // Add ordering dependency for side-effecting operations.
            // Each side-effecting instruction depends on the previous one to preserve
            // the original execution order of operations like Console.WriteLine calls.
            if !instr.op().is_pure() {
                if let Some(prev_pos) = prev_side_effect_pos {
                    // This side-effecting instruction depends on the previous one
                    deps[pos].insert(prev_pos);
                    rdeps[prev_pos].insert(pos);
                }
                prev_side_effect_pos = Some(pos);
            }
        }

        // Kahn's algorithm: process instructions with no unsatisfied dependencies
        let mut in_degree: Vec<usize> = deps.iter().map(HashSet::len).collect();
        let mut ready: VecDeque<usize> = VecDeque::new();

        // Find instructions with no dependencies (in_degree == 0)
        // Process in original order for stability
        for (pos, &deg) in in_degree.iter().enumerate() {
            if deg == 0 {
                ready.push_back(pos);
            }
        }

        let mut sorted_positions: Vec<usize> = Vec::with_capacity(n);
        while let Some(pos) = ready.pop_front() {
            sorted_positions.push(pos);

            // Reduce in_degree for dependents
            for &dep_pos in &rdeps[pos] {
                in_degree[dep_pos] -= 1;
                if in_degree[dep_pos] == 0 {
                    ready.push_back(dep_pos);
                }
            }
        }

        // Check for cycles
        if sorted_positions.len() != n {
            // Cycle detected - this shouldn't happen in valid SSA
            // Leave the block unchanged and return false
            return false;
        }

        // Reorder instructions: non-terminators in sorted order, then terminators at end
        let mut temp: Vec<Option<SsaInstruction>> = self.instructions.drain(..).map(Some).collect();

        // First add non-terminator instructions in sorted order
        for pos in sorted_positions {
            let original_idx = non_terminator_indices[pos];
            if let Some(instr) = temp[original_idx].take() {
                self.instructions.push(instr);
            }
        }

        // Then add terminators at the end (in their original relative order)
        // Sort terminators by their original index to preserve order
        terminators.sort_by_key(|(idx, _)| *idx);
        for (_, instr) in terminators {
            self.instructions.push(instr);
        }

        true
    }
}

impl fmt::Display for SsaBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "B{}:", self.id)?;

        for phi in &self.phi_nodes {
            writeln!(f, "  {phi}")?;
        }

        for instr in &self.instructions {
            writeln!(f, "  {instr}")?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        analysis::{
            ssa::{PhiOperand, VariableOrigin},
            SsaFunctionBuilder,
        },
        assembly::{FlowType, Instruction, InstructionCategory, Operand, StackBehavior},
    };

    fn make_test_cil_instruction(mnemonic: &'static str, pops: u8, pushes: u8) -> Instruction {
        Instruction {
            rva: 0x1000,
            offset: 0,
            size: 1,
            opcode: 0x00,
            prefix: 0,
            mnemonic,
            category: InstructionCategory::Arithmetic,
            flow_type: FlowType::Sequential,
            operand: Operand::None,
            stack_behavior: StackBehavior {
                pops,
                pushes,
                net_effect: i8::try_from(i16::from(pushes) - i16::from(pops)).unwrap_or(0),
            },
            branch_targets: vec![],
        }
    }

    #[test]
    fn test_ssa_block_creation() {
        let block = SsaBlock::new(5);
        assert_eq!(block.id(), 5);
        assert!(block.is_empty());
        assert!(block.has_no_phis());
        assert!(block.has_no_instructions());
    }

    #[test]
    fn test_ssa_block_with_capacity() {
        let block = SsaBlock::with_capacity(0, 2, 10);
        assert_eq!(block.id(), 0);
        assert!(block.is_empty());
    }

    #[test]
    fn test_ssa_block_add_phi() {
        let mut block = SsaBlock::new(0);

        let result = SsaVarId::new();
        let v1 = SsaVarId::new();
        let v2 = SsaVarId::new();
        let mut phi = PhiNode::new(result, VariableOrigin::Local(0));
        phi.add_operand(PhiOperand::new(v1, 0));
        phi.add_operand(PhiOperand::new(v2, 1));

        block.add_phi(phi);

        assert!(!block.has_no_phis());
        assert_eq!(block.phi_count(), 1);
        assert!(block.phi(0).is_some());
        assert_eq!(block.phi(0).unwrap().result(), result);
    }

    #[test]
    fn test_ssa_block_add_instruction() {
        let mut block = SsaBlock::new(0);

        let v0 = SsaVarId::new();
        let v1 = SsaVarId::new();
        let v2 = SsaVarId::new();
        let cil = make_test_cil_instruction("add", 2, 1);
        let instr = SsaInstruction::new(
            cil,
            SsaOp::Add {
                dest: v2,
                left: v0,
                right: v1,
            },
        );

        block.add_instruction(instr);

        assert!(!block.has_no_instructions());
        assert_eq!(block.instruction_count(), 1);
        assert!(block.instruction(0).is_some());
    }

    #[test]
    fn test_ssa_block_phi_access() {
        let mut block = SsaBlock::new(0);

        let r1 = SsaVarId::new();
        let r2 = SsaVarId::new();
        block.add_phi(PhiNode::new(r1, VariableOrigin::Local(0)));
        block.add_phi(PhiNode::new(r2, VariableOrigin::Local(1)));

        assert_eq!(block.phi_count(), 2);
        assert!(block.phi(0).is_some());
        assert!(block.phi(1).is_some());
        assert!(block.phi(2).is_none());
    }

    #[test]
    fn test_ssa_block_instruction_access() {
        let mut block = SsaBlock::new(0);

        let cil1 = make_test_cil_instruction("nop", 0, 0);
        let cil2 = make_test_cil_instruction("ret", 0, 0);

        block.add_instruction(SsaInstruction::new(cil1, SsaOp::Nop));
        block.add_instruction(SsaInstruction::new(cil2, SsaOp::Return { value: None }));

        assert_eq!(block.instruction_count(), 2);
        assert!(block.instruction(0).is_some());
        assert!(block.instruction(1).is_some());
        assert!(block.instruction(2).is_none());
    }

    #[test]
    fn test_ssa_block_find_phi_defining() {
        let mut block = SsaBlock::new(0);

        let r1 = SsaVarId::new();
        let r2 = SsaVarId::new();
        let other = SsaVarId::new();
        block.add_phi(PhiNode::new(r1, VariableOrigin::Local(0)));
        block.add_phi(PhiNode::new(r2, VariableOrigin::Local(1)));

        assert!(block.find_phi_defining(r1).is_some());
        assert!(block.find_phi_defining(r2).is_some());
        assert!(block.find_phi_defining(other).is_none());
    }

    #[test]
    fn test_ssa_block_defined_variables() {
        let mut block = SsaBlock::new(0);

        let phi_result = SsaVarId::new();
        let v0 = SsaVarId::new();
        let v1 = SsaVarId::new();
        let instr_result = SsaVarId::new();
        let v2 = SsaVarId::new();

        // Add phi defining phi_result
        block.add_phi(PhiNode::new(phi_result, VariableOrigin::Local(0)));

        // Add instruction defining instr_result
        let cil = make_test_cil_instruction("add", 2, 1);
        let instr = SsaInstruction::new(
            cil,
            SsaOp::Add {
                dest: instr_result,
                left: v0,
                right: v1,
            },
        );
        block.add_instruction(instr);

        // Add instruction with no def
        let cil2 = make_test_cil_instruction("pop", 1, 0);
        block.add_instruction(SsaInstruction::new(cil2, SsaOp::Pop { value: v2 }));

        let defs: Vec<_> = block.defined_variables().collect();
        assert_eq!(defs.len(), 2);
        assert!(defs.contains(&phi_result));
        assert!(defs.contains(&instr_result));
    }

    #[test]
    fn test_ssa_block_used_variables() {
        let mut block = SsaBlock::new(0);

        let phi_result = SsaVarId::new();
        let phi_op1 = SsaVarId::new();
        let phi_op2 = SsaVarId::new();
        let instr_op1 = SsaVarId::new();
        let instr_op2 = SsaVarId::new();
        let instr_result = SsaVarId::new();

        // Add phi using phi_op1, phi_op2
        let mut phi = PhiNode::new(phi_result, VariableOrigin::Local(0));
        phi.add_operand(PhiOperand::new(phi_op1, 0));
        phi.add_operand(PhiOperand::new(phi_op2, 1));
        block.add_phi(phi);

        // Add instruction using instr_op1, instr_op2
        let cil = make_test_cil_instruction("add", 2, 1);
        let instr = SsaInstruction::new(
            cil,
            SsaOp::Add {
                dest: instr_result,
                left: instr_op1,
                right: instr_op2,
            },
        );
        block.add_instruction(instr);

        let uses: Vec<_> = block.used_variables().collect();
        assert_eq!(uses.len(), 4);
        assert!(uses.contains(&phi_op1));
        assert!(uses.contains(&phi_op2));
        assert!(uses.contains(&instr_op1));
        assert!(uses.contains(&instr_op2));
    }

    #[test]
    fn test_ssa_block_display_empty() {
        let block = SsaBlock::new(3);
        let display = format!("{block}");
        assert_eq!(display, "B3:\n");
    }

    #[test]
    fn test_ssa_block_display_with_content() {
        let mut block = SsaBlock::new(1);

        // Add phi
        let mut phi = PhiNode::new(SsaVarId::from_index(3), VariableOrigin::Local(0));
        phi.add_operand(PhiOperand::new(SsaVarId::from_index(1), 0));
        phi.add_operand(PhiOperand::new(SsaVarId::from_index(2), 2));
        block.add_phi(phi);

        // Add instruction
        let cil = make_test_cil_instruction("add", 2, 1);
        let instr = SsaInstruction::new(
            cil,
            SsaOp::Add {
                dest: SsaVarId::from_index(5),
                left: SsaVarId::from_index(3),
                right: SsaVarId::from_index(4),
            },
        );
        block.add_instruction(instr);

        let display = format!("{block}");
        assert!(display.contains("B1:"));
        assert!(display.contains("v3 = phi(v1 from B0, v2 from B2)"));
        assert!(display.contains("v5 = add v3, v4"));
    }

    #[test]
    fn test_ssa_block_mutable_access() {
        let mut block = SsaBlock::new(0);

        let result = SsaVarId::new();
        let operand = SsaVarId::new();
        block.add_phi(PhiNode::new(result, VariableOrigin::Local(0)));

        // Modify phi through mutable access
        if let Some(phi) = block.phi_mut(0) {
            phi.add_operand(PhiOperand::new(operand, 1));
        }

        assert_eq!(block.phi(0).unwrap().operand_count(), 1);
    }

    #[test]
    fn test_is_trampoline_unconditional_jump() {
        let ssa = SsaFunctionBuilder::new(2, 0).build_with(|f| {
            f.block(0, |b| b.jump(1));
            f.block(1, |b| b.ret());
        });

        // Block with single jump is a trampoline
        assert_eq!(ssa.block(0).unwrap().is_trampoline(), Some(1));
        // Block with return is not a trampoline
        assert_eq!(ssa.block(1).unwrap().is_trampoline(), None);
    }

    #[test]
    fn test_is_trampoline_leave_instruction() {
        let ssa = SsaFunctionBuilder::new(2, 0).build_with(|f| {
            f.block(0, |b| b.leave(1));
            f.block(1, |b| b.ret());
        });

        // Leave is also an unconditional transfer - valid trampoline
        assert_eq!(ssa.block(0).unwrap().is_trampoline(), Some(1));
    }

    #[test]
    fn test_is_trampoline_blocked_by_phi_nodes() {
        use crate::analysis::SsaFunctionBuilder;

        let mut ssa = SsaFunctionBuilder::new(2, 0).build_with(|f| {
            f.block(0, |b| b.jump(1));
            f.block(1, |b| b.ret());
        });

        // Adding a phi node makes it not a trampoline (it merges values)
        if let Some(block) = ssa.block_mut(0) {
            block.add_phi(PhiNode::new(SsaVarId::new(), VariableOrigin::Local(0)));
        }

        assert_eq!(ssa.block(0).unwrap().is_trampoline(), None);
    }

    #[test]
    fn test_is_trampoline_blocked_by_multiple_instructions() {
        let ssa = SsaFunctionBuilder::new(2, 0).build_with(|f| {
            f.block(0, |b| {
                let _ = b.const_i32(42); // Extra instruction before jump
                b.jump(1);
            });
            f.block(1, |b| b.ret());
        });

        // Multiple instructions means not a pure trampoline
        assert_eq!(ssa.block(0).unwrap().is_trampoline(), None);
    }

    #[test]
    fn test_is_trampoline_conditional_branch_not_trampoline() {
        let ssa = SsaFunctionBuilder::new(2, 0).build_with(|f| {
            f.block(0, |b| {
                let cond = b.const_true();
                b.branch(cond, 1, 1);
            });
            f.block(1, |b| b.ret());
        });

        // Conditional branch is not an unconditional transfer
        assert_eq!(ssa.block(0).unwrap().is_trampoline(), None);
    }
}
