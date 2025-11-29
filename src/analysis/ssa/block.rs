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

use std::fmt;

use crate::analysis::ssa::{PhiNode, SsaInstruction, SsaVarId};

/// An SSA basic block with phi nodes and instructions.
///
/// This represents a basic block in SSA form. It maintains a parallel structure
/// to the CFG blocks but with explicit variable information.
///
/// # Examples
///
/// ```rust,ignore
/// use dotscope::analysis::ssa::{SsaBlock, PhiNode, SsaInstruction, SsaVarId, VariableOrigin};
///
/// let mut block = SsaBlock::new(0);
///
/// // Add a phi node
/// let mut phi = PhiNode::new(SsaVarId::new(5), VariableOrigin::Local(0));
/// phi.set_operand(0, SsaVarId::new(1));
/// phi.set_operand(1, SsaVarId::new(2));
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

    /// Finds a phi node that defines the given variable.
    #[must_use]
    pub fn find_phi_defining(&self, var: SsaVarId) -> Option<&PhiNode> {
        self.phi_nodes.iter().find(|phi| phi.result() == var)
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
        let instr_uses = self
            .instructions
            .iter()
            .flat_map(|i| i.uses().iter().copied());
        phi_uses.chain(instr_uses)
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
    use crate::analysis::ssa::{PhiOperand, VariableOrigin};
    use crate::assembly::{FlowType, Instruction, InstructionCategory, Operand, StackBehavior};

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

        let mut phi = PhiNode::new(SsaVarId::new(5), VariableOrigin::Local(0));
        phi.add_operand(PhiOperand::new(SsaVarId::new(1), 0));
        phi.add_operand(PhiOperand::new(SsaVarId::new(2), 1));

        block.add_phi(phi);

        assert!(!block.has_no_phis());
        assert_eq!(block.phi_count(), 1);
        assert!(block.phi(0).is_some());
        assert_eq!(block.phi(0).unwrap().result(), SsaVarId::new(5));
    }

    #[test]
    fn test_ssa_block_add_instruction() {
        let mut block = SsaBlock::new(0);

        let cil = make_test_cil_instruction("add", 2, 1);
        let instr = SsaInstruction::new(
            cil,
            vec![SsaVarId::new(0), SsaVarId::new(1)],
            Some(SsaVarId::new(2)),
        );

        block.add_instruction(instr);

        assert!(!block.has_no_instructions());
        assert_eq!(block.instruction_count(), 1);
        assert!(block.instruction(0).is_some());
    }

    #[test]
    fn test_ssa_block_phi_access() {
        let mut block = SsaBlock::new(0);

        block.add_phi(PhiNode::new(SsaVarId::new(3), VariableOrigin::Local(0)));
        block.add_phi(PhiNode::new(SsaVarId::new(5), VariableOrigin::Local(1)));

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

        block.add_instruction(SsaInstruction::no_operands(cil1));
        block.add_instruction(SsaInstruction::no_operands(cil2));

        assert_eq!(block.instruction_count(), 2);
        assert!(block.instruction(0).is_some());
        assert!(block.instruction(1).is_some());
        assert!(block.instruction(2).is_none());
    }

    #[test]
    fn test_ssa_block_find_phi_defining() {
        let mut block = SsaBlock::new(0);

        block.add_phi(PhiNode::new(SsaVarId::new(3), VariableOrigin::Local(0)));
        block.add_phi(PhiNode::new(SsaVarId::new(7), VariableOrigin::Local(1)));

        assert!(block.find_phi_defining(SsaVarId::new(3)).is_some());
        assert!(block.find_phi_defining(SsaVarId::new(7)).is_some());
        assert!(block.find_phi_defining(SsaVarId::new(5)).is_none());
    }

    #[test]
    fn test_ssa_block_defined_variables() {
        let mut block = SsaBlock::new(0);

        // Add phi defining v5
        block.add_phi(PhiNode::new(SsaVarId::new(5), VariableOrigin::Local(0)));

        // Add instruction defining v10
        let cil = make_test_cil_instruction("add", 2, 1);
        let instr = SsaInstruction::new(
            cil,
            vec![SsaVarId::new(0), SsaVarId::new(1)],
            Some(SsaVarId::new(10)),
        );
        block.add_instruction(instr);

        // Add instruction with no def
        let cil2 = make_test_cil_instruction("pop", 1, 0);
        block.add_instruction(SsaInstruction::new(cil2, vec![SsaVarId::new(2)], None));

        let defs: Vec<_> = block.defined_variables().collect();
        assert_eq!(defs.len(), 2);
        assert!(defs.contains(&SsaVarId::new(5)));
        assert!(defs.contains(&SsaVarId::new(10)));
    }

    #[test]
    fn test_ssa_block_used_variables() {
        let mut block = SsaBlock::new(0);

        // Add phi using v1, v2
        let mut phi = PhiNode::new(SsaVarId::new(5), VariableOrigin::Local(0));
        phi.add_operand(PhiOperand::new(SsaVarId::new(1), 0));
        phi.add_operand(PhiOperand::new(SsaVarId::new(2), 1));
        block.add_phi(phi);

        // Add instruction using v3, v4
        let cil = make_test_cil_instruction("add", 2, 1);
        let instr = SsaInstruction::new(
            cil,
            vec![SsaVarId::new(3), SsaVarId::new(4)],
            Some(SsaVarId::new(10)),
        );
        block.add_instruction(instr);

        let uses: Vec<_> = block.used_variables().collect();
        assert_eq!(uses.len(), 4);
        assert!(uses.contains(&SsaVarId::new(1)));
        assert!(uses.contains(&SsaVarId::new(2)));
        assert!(uses.contains(&SsaVarId::new(3)));
        assert!(uses.contains(&SsaVarId::new(4)));
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
        let mut phi = PhiNode::new(SsaVarId::new(3), VariableOrigin::Local(0));
        phi.add_operand(PhiOperand::new(SsaVarId::new(1), 0));
        phi.add_operand(PhiOperand::new(SsaVarId::new(2), 2));
        block.add_phi(phi);

        // Add instruction
        let cil = make_test_cil_instruction("add", 2, 1);
        let instr = SsaInstruction::new(
            cil,
            vec![SsaVarId::new(3), SsaVarId::new(4)],
            Some(SsaVarId::new(5)),
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

        block.add_phi(PhiNode::new(SsaVarId::new(1), VariableOrigin::Local(0)));

        // Modify phi through mutable access
        if let Some(phi) = block.phi_mut(0) {
            phi.add_operand(PhiOperand::new(SsaVarId::new(5), 1));
        }

        assert_eq!(block.phi(0).unwrap().operand_count(), 1);
    }
}
