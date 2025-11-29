//! SSA function representation - a complete method in SSA form.
//!
//! An `SsaFunction` is the top-level container for a method's SSA representation.
//! It holds all SSA blocks, variables, and maintains the relationship to the
//! underlying control flow graph.
//!
//! # Structure
//!
//! ```text
//! SsaFunction
//! ├── blocks: Vec<SsaBlock>       // SSA blocks (1:1 with CFG blocks)
//! ├── variables: Vec<SsaVariable> // All SSA variables
//! ├── num_args: usize             // Number of method arguments
//! └── num_locals: usize           // Number of local variables
//! ```
//!
//! # Construction
//!
//! An `SsaFunction` is built by the `SsaBuilder` which:
//! 1. Simulates the stack to create explicit variables
//! 2. Places phi nodes at dominance frontiers
//! 3. Renames variables to achieve single-assignment form
//!
//! # Thread Safety
//!
//! `SsaFunction` is `Send` and `Sync` once constructed.

use std::fmt;

use crate::analysis::ssa::{
    PhiNode, SsaBlock, SsaInstruction, SsaVarId, SsaVariable, VariableOrigin,
};

/// A method in SSA (Static Single Assignment) form.
///
/// This is the complete SSA representation of a CIL method, containing:
/// - All basic blocks with phi nodes and SSA instructions
/// - All SSA variables with their metadata
/// - Method signature information (argument/local counts)
///
/// # Examples
///
/// ```rust,ignore
/// use dotscope::analysis::ssa::{SsaFunction, SsaBlock, SsaVarId};
///
/// // Create an SSA function with 2 args, 1 local, and 3 blocks
/// let mut func = SsaFunction::new(2, 1);
///
/// // Add blocks
/// func.add_block(SsaBlock::new(0));
/// func.add_block(SsaBlock::new(1));
/// func.add_block(SsaBlock::new(2));
///
/// // Query variables
/// for var in func.variables() {
///     println!("Variable: {}", var);
/// }
/// ```
#[derive(Debug, Clone)]
pub struct SsaFunction {
    /// SSA basic blocks, indexed by block ID.
    blocks: Vec<SsaBlock>,

    /// All SSA variables in this function.
    variables: Vec<SsaVariable>,

    /// Number of method arguments.
    num_args: usize,

    /// Number of local variables.
    num_locals: usize,
}

impl SsaFunction {
    /// Creates a new empty SSA function.
    ///
    /// # Arguments
    ///
    /// * `num_args` - Number of method arguments (including `this` for instance methods)
    /// * `num_locals` - Number of local variables declared in the method
    #[must_use]
    pub fn new(num_args: usize, num_locals: usize) -> Self {
        Self {
            blocks: Vec::new(),
            variables: Vec::new(),
            num_args,
            num_locals,
        }
    }

    /// Creates a new SSA function with pre-allocated capacity.
    ///
    /// # Arguments
    ///
    /// * `num_args` - Number of method arguments
    /// * `num_locals` - Number of local variables
    /// * `block_capacity` - Expected number of blocks
    /// * `var_capacity` - Expected number of SSA variables
    #[must_use]
    pub fn with_capacity(
        num_args: usize,
        num_locals: usize,
        block_capacity: usize,
        var_capacity: usize,
    ) -> Self {
        Self {
            blocks: Vec::with_capacity(block_capacity),
            variables: Vec::with_capacity(var_capacity),
            num_args,
            num_locals,
        }
    }

    /// Returns the SSA blocks.
    #[must_use]
    pub fn blocks(&self) -> &[SsaBlock] {
        &self.blocks
    }

    /// Returns a mutable reference to the blocks.
    pub fn blocks_mut(&mut self) -> &mut Vec<SsaBlock> {
        &mut self.blocks
    }

    /// Returns the SSA variables.
    #[must_use]
    pub fn variables(&self) -> &[SsaVariable] {
        &self.variables
    }

    /// Returns a mutable reference to the variables.
    pub fn variables_mut(&mut self) -> &mut Vec<SsaVariable> {
        &mut self.variables
    }

    /// Returns the number of method arguments.
    #[must_use]
    pub const fn num_args(&self) -> usize {
        self.num_args
    }

    /// Returns the number of local variables.
    #[must_use]
    pub const fn num_locals(&self) -> usize {
        self.num_locals
    }

    /// Returns the number of blocks.
    #[must_use]
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }

    /// Returns the number of variables.
    #[must_use]
    pub fn variable_count(&self) -> usize {
        self.variables.len()
    }

    /// Returns `true` if this function has no blocks.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    /// Gets a block by index.
    #[must_use]
    pub fn block(&self, index: usize) -> Option<&SsaBlock> {
        self.blocks.get(index)
    }

    /// Gets a mutable block by index.
    pub fn block_mut(&mut self, index: usize) -> Option<&mut SsaBlock> {
        self.blocks.get_mut(index)
    }

    /// Gets a variable by ID.
    #[must_use]
    pub fn variable(&self, id: SsaVarId) -> Option<&SsaVariable> {
        self.variables.get(id.index())
    }

    /// Gets a mutable variable by ID.
    pub fn variable_mut(&mut self, id: SsaVarId) -> Option<&mut SsaVariable> {
        self.variables.get_mut(id.index())
    }

    /// Adds a block to this function.
    pub fn add_block(&mut self, block: SsaBlock) {
        self.blocks.push(block);
    }

    /// Adds a variable to this function and returns its ID.
    pub fn add_variable(&mut self, variable: SsaVariable) -> SsaVarId {
        let id = SsaVarId::new(self.variables.len());
        self.variables.push(variable);
        id
    }

    /// Returns an iterator over argument variables (version 0).
    ///
    /// These are the initial SSA versions of arguments at method entry.
    pub fn argument_variables(&self) -> impl Iterator<Item = &SsaVariable> {
        self.variables
            .iter()
            .filter(|v| v.origin().is_argument() && v.version() == 0)
    }

    /// Returns an iterator over local variables (version 0).
    ///
    /// These are the initial SSA versions of locals at method entry.
    pub fn local_variables(&self) -> impl Iterator<Item = &SsaVariable> {
        self.variables
            .iter()
            .filter(|v| v.origin().is_local() && v.version() == 0)
    }

    /// Finds all variables originating from a specific argument.
    pub fn variables_from_argument(&self, arg_index: u16) -> impl Iterator<Item = &SsaVariable> {
        self.variables.iter().filter(
            move |v| matches!(v.origin(), VariableOrigin::Argument(idx) if idx == arg_index),
        )
    }

    /// Finds all variables originating from a specific local.
    pub fn variables_from_local(&self, local_index: u16) -> impl Iterator<Item = &SsaVariable> {
        self.variables
            .iter()
            .filter(move |v| matches!(v.origin(), VariableOrigin::Local(idx) if idx == local_index))
    }

    /// Returns the total number of phi nodes across all blocks.
    pub fn total_phi_count(&self) -> usize {
        self.blocks.iter().map(SsaBlock::phi_count).sum()
    }

    /// Returns the total number of instructions across all blocks.
    pub fn total_instruction_count(&self) -> usize {
        self.blocks.iter().map(SsaBlock::instruction_count).sum()
    }

    /// Returns an iterator over all phi nodes in the function.
    pub fn all_phi_nodes(&self) -> impl Iterator<Item = &PhiNode> {
        self.blocks.iter().flat_map(SsaBlock::phi_nodes)
    }

    /// Returns an iterator over all instructions in the function.
    pub fn all_instructions(&self) -> impl Iterator<Item = &SsaInstruction> {
        self.blocks.iter().flat_map(SsaBlock::instructions)
    }

    /// Finds dead variables (variables with no uses).
    pub fn dead_variables(&self) -> impl Iterator<Item = &SsaVariable> {
        self.variables.iter().filter(|v| v.is_dead())
    }

    /// Counts dead variables.
    #[must_use]
    pub fn dead_variable_count(&self) -> usize {
        self.variables.iter().filter(|v| v.is_dead()).count()
    }
}

impl fmt::Display for SsaFunction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "SSA Function ({} args, {} locals):",
            self.num_args, self.num_locals
        )?;
        writeln!(f, "  Variables: {}", self.variables.len())?;
        writeln!(f, "  Blocks: {}", self.blocks.len())?;
        writeln!(f)?;

        for block in &self.blocks {
            write!(f, "{block}")?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::ssa::{DefSite, PhiOperand, UseSite};
    use crate::assembly::{FlowType, Instruction, InstructionCategory, Operand, StackBehavior};

    fn make_test_cil_instruction(mnemonic: &'static str) -> Instruction {
        Instruction {
            rva: 0x1000,
            offset: 0,
            size: 1,
            opcode: 0x00,
            prefix: 0,
            mnemonic,
            category: InstructionCategory::Misc,
            flow_type: FlowType::Sequential,
            operand: Operand::None,
            stack_behavior: StackBehavior {
                pops: 0,
                pushes: 0,
                net_effect: 0,
            },
            branch_targets: vec![],
        }
    }

    #[test]
    fn test_ssa_function_creation() {
        let func = SsaFunction::new(2, 3);
        assert_eq!(func.num_args(), 2);
        assert_eq!(func.num_locals(), 3);
        assert!(func.is_empty());
        assert_eq!(func.block_count(), 0);
        assert_eq!(func.variable_count(), 0);
    }

    #[test]
    fn test_ssa_function_with_capacity() {
        let func = SsaFunction::with_capacity(2, 1, 10, 50);
        assert_eq!(func.num_args(), 2);
        assert_eq!(func.num_locals(), 1);
        assert!(func.is_empty());
    }

    #[test]
    fn test_ssa_function_add_block() {
        let mut func = SsaFunction::new(0, 0);

        func.add_block(SsaBlock::new(0));
        func.add_block(SsaBlock::new(1));

        assert!(!func.is_empty());
        assert_eq!(func.block_count(), 2);
        assert!(func.block(0).is_some());
        assert!(func.block(1).is_some());
        assert!(func.block(2).is_none());
    }

    #[test]
    fn test_ssa_function_add_variable() {
        let mut func = SsaFunction::new(1, 0);

        let var1 = SsaVariable::new(
            SsaVarId::new(0),
            VariableOrigin::Argument(0),
            0,
            DefSite::phi(0),
        );
        let id1 = func.add_variable(var1);
        assert_eq!(id1, SsaVarId::new(0));

        let var2 = SsaVariable::new(
            SsaVarId::new(1),
            VariableOrigin::Stack(0),
            0,
            DefSite::instruction(0, 0),
        );
        let id2 = func.add_variable(var2);
        assert_eq!(id2, SsaVarId::new(1));

        assert_eq!(func.variable_count(), 2);
    }

    #[test]
    fn test_ssa_function_variable_access() {
        let mut func = SsaFunction::new(1, 0);

        let var = SsaVariable::new(
            SsaVarId::new(0),
            VariableOrigin::Argument(0),
            0,
            DefSite::phi(0),
        );
        let id = func.add_variable(var);

        assert!(func.variable(id).is_some());
        assert_eq!(
            func.variable(id).unwrap().origin(),
            VariableOrigin::Argument(0)
        );
    }

    #[test]
    fn test_ssa_function_argument_variables() {
        let mut func = SsaFunction::new(2, 1);

        // Add arg0 version 0
        func.add_variable(SsaVariable::new(
            SsaVarId::new(0),
            VariableOrigin::Argument(0),
            0,
            DefSite::phi(0),
        ));

        // Add arg1 version 0
        func.add_variable(SsaVariable::new(
            SsaVarId::new(1),
            VariableOrigin::Argument(1),
            0,
            DefSite::phi(0),
        ));

        // Add arg0 version 1 (redefinition)
        func.add_variable(SsaVariable::new(
            SsaVarId::new(2),
            VariableOrigin::Argument(0),
            1,
            DefSite::instruction(1, 0),
        ));

        // Add local0 version 0
        func.add_variable(SsaVariable::new(
            SsaVarId::new(3),
            VariableOrigin::Local(0),
            0,
            DefSite::phi(0),
        ));

        let args: Vec<_> = func.argument_variables().collect();
        assert_eq!(args.len(), 2); // Only version 0 of each arg
    }

    #[test]
    fn test_ssa_function_local_variables() {
        let mut func = SsaFunction::new(0, 2);

        func.add_variable(SsaVariable::new(
            SsaVarId::new(0),
            VariableOrigin::Local(0),
            0,
            DefSite::phi(0),
        ));

        func.add_variable(SsaVariable::new(
            SsaVarId::new(1),
            VariableOrigin::Local(1),
            0,
            DefSite::phi(0),
        ));

        func.add_variable(SsaVariable::new(
            SsaVarId::new(2),
            VariableOrigin::Stack(0),
            0,
            DefSite::instruction(0, 0),
        ));

        let locals: Vec<_> = func.local_variables().collect();
        assert_eq!(locals.len(), 2);
    }

    #[test]
    fn test_ssa_function_variables_from_argument() {
        let mut func = SsaFunction::new(2, 0);

        func.add_variable(SsaVariable::new(
            SsaVarId::new(0),
            VariableOrigin::Argument(0),
            0,
            DefSite::phi(0),
        ));

        func.add_variable(SsaVariable::new(
            SsaVarId::new(1),
            VariableOrigin::Argument(0),
            1,
            DefSite::instruction(1, 0),
        ));

        func.add_variable(SsaVariable::new(
            SsaVarId::new(2),
            VariableOrigin::Argument(1),
            0,
            DefSite::phi(0),
        ));

        let arg0_vars: Vec<_> = func.variables_from_argument(0).collect();
        assert_eq!(arg0_vars.len(), 2);

        let arg1_vars: Vec<_> = func.variables_from_argument(1).collect();
        assert_eq!(arg1_vars.len(), 1);
    }

    #[test]
    fn test_ssa_function_total_phi_count() {
        let mut func = SsaFunction::new(0, 0);

        let mut block0 = SsaBlock::new(0);
        block0.add_phi(PhiNode::new(SsaVarId::new(0), VariableOrigin::Local(0)));
        block0.add_phi(PhiNode::new(SsaVarId::new(1), VariableOrigin::Local(1)));
        func.add_block(block0);

        let mut block1 = SsaBlock::new(1);
        block1.add_phi(PhiNode::new(SsaVarId::new(2), VariableOrigin::Local(0)));
        func.add_block(block1);

        func.add_block(SsaBlock::new(2)); // No phis

        assert_eq!(func.total_phi_count(), 3);
    }

    #[test]
    fn test_ssa_function_total_instruction_count() {
        let mut func = SsaFunction::new(0, 0);

        let mut block0 = SsaBlock::new(0);
        block0.add_instruction(SsaInstruction::no_operands(make_test_cil_instruction(
            "nop",
        )));
        block0.add_instruction(SsaInstruction::no_operands(make_test_cil_instruction(
            "nop",
        )));
        func.add_block(block0);

        let mut block1 = SsaBlock::new(1);
        block1.add_instruction(SsaInstruction::no_operands(make_test_cil_instruction(
            "ret",
        )));
        func.add_block(block1);

        assert_eq!(func.total_instruction_count(), 3);
    }

    #[test]
    fn test_ssa_function_all_phi_nodes() {
        let mut func = SsaFunction::new(0, 0);

        let mut block0 = SsaBlock::new(0);
        let mut phi = PhiNode::new(SsaVarId::new(0), VariableOrigin::Local(0));
        phi.add_operand(PhiOperand::new(SsaVarId::new(1), 1));
        block0.add_phi(phi);
        func.add_block(block0);

        let phis: Vec<_> = func.all_phi_nodes().collect();
        assert_eq!(phis.len(), 1);
        assert_eq!(phis[0].result(), SsaVarId::new(0));
    }

    #[test]
    fn test_ssa_function_dead_variables() {
        let mut func = SsaFunction::new(0, 0);

        // Variable with no uses (dead)
        func.add_variable(SsaVariable::new(
            SsaVarId::new(0),
            VariableOrigin::Stack(0),
            0,
            DefSite::instruction(0, 0),
        ));

        // Variable with uses (live)
        let mut live_var = SsaVariable::new(
            SsaVarId::new(1),
            VariableOrigin::Stack(1),
            0,
            DefSite::instruction(0, 1),
        );
        live_var.add_use(UseSite::instruction(0, 2));
        func.add_variable(live_var);

        let dead: Vec<_> = func.dead_variables().collect();
        assert_eq!(dead.len(), 1);
        assert_eq!(func.dead_variable_count(), 1);
    }

    #[test]
    fn test_ssa_function_display() {
        let mut func = SsaFunction::new(1, 1);
        func.add_block(SsaBlock::new(0));

        let display = format!("{func}");
        assert!(display.contains("SSA Function"));
        assert!(display.contains("1 args"));
        assert!(display.contains("1 locals"));
        assert!(display.contains("B0:"));
    }
}
