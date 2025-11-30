//! SSA construction algorithm (Cytron et al.).
//!
//! This module implements the classic SSA construction algorithm from:
//!
//! > Cytron et al., "Efficiently Computing Static Single Assignment Form and the
//! > Control Dependence Graph", ACM TOPLAS 1991
//!
//! # Algorithm Overview
//!
//! SSA construction proceeds in three phases:
//!
//! 1. **Stack Simulation**: Convert implicit CIL stack operations to explicit variables
//! 2. **Phi Placement**: Insert phi nodes at dominance frontiers for each variable
//! 3. **Variable Renaming**: Rename variables using dominator tree traversal
//!
//! # Usage
//!
//! ```rust,ignore
//! use dotscope::analysis::{ControlFlowGraph, ssa::SsaBuilder};
//! use dotscope::assembly::decode_blocks;
//!
//! // Build CFG from decoded blocks
//! let blocks = decode_blocks(data, offset, rva, Some(size))?;
//! let cfg = ControlFlowGraph::from_basic_blocks(blocks)?;
//!
//! // Construct SSA form
//! let ssa = SsaBuilder::build(&cfg, 2, 3)?; // 2 args, 3 locals
//!
//! // Analyze the SSA form
//! for block in ssa.blocks() {
//!     for phi in block.phi_nodes() {
//!         println!("{}", phi);
//!     }
//! }
//! ```

use std::collections::{HashMap, HashSet};

use crate::{
    analysis::{
        cfg::ControlFlowGraph,
        ssa::{
            decompose::decompose_instruction, DefSite, PhiNode, SimulationResult, SsaBlock,
            SsaFunction, SsaInstruction, SsaVarId, SsaVariable, StackSimulator, UseSite,
            VariableOrigin,
        },
    },
    assembly::{Immediate, Instruction, Operand},
    utils::graph::{algorithms::DominatorTree, NodeId},
    Error, Result,
};

mod opcodes {
    //! CIL opcode constants for SSA-relevant instructions.
    //!
    //! These are the opcodes that require special handling during SSA construction
    //! because they load/store arguments, locals, or duplicate stack values.

    pub const LDARG_0: u8 = 0x02;
    pub const LDARG_1: u8 = 0x03;
    pub const LDARG_2: u8 = 0x04;
    pub const LDARG_3: u8 = 0x05;
    pub const LDLOC_0: u8 = 0x06;
    pub const LDLOC_1: u8 = 0x07;
    pub const LDLOC_2: u8 = 0x08;
    pub const LDLOC_3: u8 = 0x09;
    pub const STLOC_0: u8 = 0x0A;
    pub const STLOC_1: u8 = 0x0B;
    pub const STLOC_2: u8 = 0x0C;
    pub const STLOC_3: u8 = 0x0D;
    pub const LDARG_S: u8 = 0x0E;
    pub const LDARGA_S: u8 = 0x0F;
    pub const STARG_S: u8 = 0x10;
    pub const LDLOC_S: u8 = 0x11;
    pub const LDLOCA_S: u8 = 0x12;
    pub const STLOC_S: u8 = 0x13;
    pub const DUP: u8 = 0x25;

    pub const FE_PREFIX: u8 = 0xFE;
    pub const FE_LDARG: u8 = 0x09;
    pub const FE_LDARGA: u8 = 0x0A;
    pub const FE_STARG: u8 = 0x0B;
    pub const FE_LDLOC: u8 = 0x0C;
    pub const FE_LDLOCA: u8 = 0x0D;
    pub const FE_STLOC: u8 = 0x0E;
}

/// A variable definition record during SSA construction.
#[derive(Debug, Clone)]
struct VarDef {
    /// The original variable (argument index, local index, or stack slot).
    origin: VariableOrigin,
    /// The block where this definition occurs.
    block: usize,
    /// Whether this is from a phi node (vs an instruction).
    is_phi: bool,
}

/// Builder for constructing SSA form from a control flow graph.
///
/// This implements the Cytron et al. algorithm with the following phases:
///
/// 1. Simulate the stack to identify variable definitions
/// 2. Compute dominance frontiers and place phi nodes
/// 3. Rename variables using dominator tree traversal
#[derive(Debug)]
pub struct SsaBuilder<'a, 'cfg> {
    /// The control flow graph being transformed.
    cfg: &'a ControlFlowGraph<'cfg>,

    /// Number of method arguments.
    num_args: usize,

    /// Number of local variables.
    num_locals: usize,

    /// The SSA function being built.
    function: SsaFunction,

    /// Definitions of each original variable (by origin) -> list of defining blocks.
    /// Used for phi placement.
    defs: HashMap<VariableOrigin, HashSet<usize>>,

    /// Current version stack for each variable during renaming.
    /// Maps origin -> stack of (version, `SsaVarId`).
    version_stacks: HashMap<VariableOrigin, Vec<(u32, SsaVarId)>>,

    /// Next version number for each variable origin.
    next_version: HashMap<VariableOrigin, u32>,

    /// Variables that have had their address taken.
    address_taken: HashSet<VariableOrigin>,
}

impl<'a, 'cfg> SsaBuilder<'a, 'cfg> {
    /// Converts a usize index to u16 with validation.
    ///
    /// Returns an error if the index exceeds `u16::MAX`.
    fn idx_to_u16(idx: usize) -> Result<u16> {
        u16::try_from(idx).map_err(|_| {
            Error::SsaError(format!(
                "Variable index {} exceeds maximum supported value of {}",
                idx,
                u16::MAX
            ))
        })
    }

    /// Builds SSA form from a control flow graph.
    ///
    /// # Arguments
    ///
    /// * `cfg` - The control flow graph to transform
    /// * `num_args` - Number of method arguments (including `this` for instance methods)
    /// * `num_locals` - Number of local variables
    ///
    /// # Returns
    ///
    /// The complete SSA representation, or an error if construction fails.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The CFG is empty
    /// - Stack simulation encounters inconsistencies
    /// - Internal invariants are violated
    pub fn build(
        cfg: &'a ControlFlowGraph<'cfg>,
        num_args: usize,
        num_locals: usize,
    ) -> Result<SsaFunction> {
        let block_count = cfg.block_count();
        if block_count == 0 {
            return Err(Error::SsaError(
                "Cannot build SSA from empty CFG".to_string(),
            ));
        }

        let mut builder = Self {
            cfg,
            num_args,
            num_locals,
            function: SsaFunction::with_capacity(num_args, num_locals, block_count, 0),
            defs: HashMap::new(),
            version_stacks: HashMap::new(),
            next_version: HashMap::new(),
            address_taken: HashSet::new(),
        };

        // Phase 1: Simulate stack and collect definitions
        builder.simulate_all_blocks()?;

        // Phase 2: Place phi nodes at dominance frontiers
        builder.place_phi_nodes();

        // Phase 3: Rename variables using dominator tree traversal
        builder.rename_variables()?;

        Ok(builder.function)
    }

    /// Phase 1: Simulates the stack for all blocks to identify variable definitions.
    fn simulate_all_blocks(&mut self) -> Result<()> {
        let rpo = self.cfg.reverse_postorder();

        for i in 0..self.cfg.block_count() {
            self.function.add_block(SsaBlock::new(i));
        }

        for i in 0..self.num_args {
            let origin = VariableOrigin::Argument(Self::idx_to_u16(i)?);
            self.defs.entry(origin).or_default().insert(0);
        }
        for i in 0..self.num_locals {
            let origin = VariableOrigin::Local(Self::idx_to_u16(i)?);
            self.defs.entry(origin).or_default().insert(0);
        }

        // First pass: compute stack depths at block exits
        let exit_depths = self.compute_stack_depths(&rpo)?;

        // Second pass: simulate with correct starting stack depths
        for &node_id in &rpo {
            let block_idx = node_id.index();
            let entry_depth = self.compute_entry_depth(block_idx, &exit_depths);
            self.simulate_block(block_idx, entry_depth)?;
        }

        Ok(())
    }

    /// Computes the stack depth at the exit of each block.
    ///
    /// This uses a lightweight simulation that only tracks stack depth changes,
    /// not actual variable values.
    fn compute_stack_depths(&self, rpo: &[NodeId]) -> Result<HashMap<usize, usize>> {
        let mut exit_depths: HashMap<usize, usize> = HashMap::new();

        for &node_id in rpo {
            let block_idx = node_id.index();
            let cfg_block = self
                .cfg
                .block(node_id)
                .ok_or_else(|| Error::SsaError(format!("Block {block_idx} not found in CFG")))?;

            // Compute entry depth from predecessors
            let entry_depth = self.compute_entry_depth(block_idx, &exit_depths);
            let mut depth = entry_depth;

            // Apply stack effects of each instruction
            for instr in &cfg_block.instructions {
                let net_effect = instr.stack_behavior.net_effect;
                // Apply effect, clamping to 0 if it would go negative (shouldn't happen in valid CIL)
                #[allow(clippy::cast_sign_loss)] // Sign checked in condition
                if net_effect < 0 {
                    depth = depth.saturating_sub(net_effect.unsigned_abs() as usize);
                } else {
                    depth += net_effect as usize;
                }
            }

            exit_depths.insert(block_idx, depth);
        }

        Ok(exit_depths)
    }

    /// Computes the stack depth at block entry based on predecessor exit depths.
    fn compute_entry_depth(&self, block_idx: usize, exit_depths: &HashMap<usize, usize>) -> usize {
        // Entry block always starts with empty stack
        if block_idx == self.cfg.entry().index() {
            return 0;
        }

        // Take the maximum of all predecessor exit depths
        // (In well-formed CIL, all predecessors should agree, but we use max for safety)
        let mut max_depth = 0;
        for pred_id in self.cfg.predecessors(NodeId::new(block_idx)) {
            if let Some(&pred_depth) = exit_depths.get(&pred_id.index()) {
                max_depth = max_depth.max(pred_depth);
            }
        }
        max_depth
    }

    /// Simulates a single block, converting CIL instructions to SSA.
    fn simulate_block(&mut self, block_idx: usize, entry_stack_depth: usize) -> Result<()> {
        let node_id = NodeId::new(block_idx);
        let cfg_block = self
            .cfg
            .block(node_id)
            .ok_or_else(|| Error::SsaError(format!("Block {block_idx} not found in CFG")))?;

        let mut simulator = StackSimulator::new(self.num_args, self.num_locals);

        // Initialize stack with placeholder values if block is entered with non-empty stack
        if entry_stack_depth > 0 {
            simulator.initialize_stack(entry_stack_depth);
        }

        for cil_instr in &cfg_block.instructions {
            let result = Self::simulate_instruction(&mut simulator, cil_instr)?;

            // Create SSA instruction with uses and def
            let mut ssa_instr =
                SsaInstruction::new(cil_instr.clone(), result.uses.clone(), result.def);

            // Try to decompose the CIL instruction into an SsaOp
            if let Some(op) = decompose_instruction(cil_instr, &result.uses, result.def) {
                ssa_instr.set_op(op);
            }

            if let Some(block) = self.function.block_mut(block_idx) {
                block.add_instruction(ssa_instr);
            }

            if let Some(origin) = Self::infer_origin(cil_instr)? {
                self.defs.entry(origin).or_default().insert(block_idx);
            }
        }

        for i in 0..self.num_args {
            if simulator.is_arg_address_taken(i) {
                self.address_taken
                    .insert(VariableOrigin::Argument(Self::idx_to_u16(i)?));
            }
        }
        for i in 0..self.num_locals {
            if simulator.is_local_address_taken(i) {
                self.address_taken
                    .insert(VariableOrigin::Local(Self::idx_to_u16(i)?));
            }
        }

        Ok(())
    }

    /// Simulates a single CIL instruction, returning the stack effects.
    ///
    /// All 257 CIL instructions are covered: specific handling for load/store instructions
    /// that affect SSA variables, and generic stack effect simulation for all others.
    fn simulate_instruction(
        simulator: &mut StackSimulator,
        instr: &Instruction,
    ) -> Result<SimulationResult> {
        let result = if instr.prefix == opcodes::FE_PREFIX {
            match instr.opcode {
                opcodes::FE_LDARG => Self::extract_index(&instr.operand)
                    .and_then(|idx| simulator.simulate_ldarg(idx)),
                opcodes::FE_LDARGA => Self::extract_index(&instr.operand)
                    .and_then(|idx| simulator.simulate_ldarga(idx)),
                opcodes::FE_STARG => Self::extract_index(&instr.operand)
                    .and_then(|idx| simulator.simulate_starg(idx)),
                opcodes::FE_LDLOC => Self::extract_index(&instr.operand)
                    .and_then(|idx| simulator.simulate_ldloc(idx)),
                opcodes::FE_LDLOCA => Self::extract_index(&instr.operand)
                    .and_then(|idx| simulator.simulate_ldloca(idx)),
                opcodes::FE_STLOC => Self::extract_index(&instr.operand)
                    .and_then(|idx| simulator.simulate_stloc(idx)),
                _ => simulator
                    .simulate_stack_effect(instr.stack_behavior.pops, instr.stack_behavior.pushes),
            }
        } else {
            match instr.opcode {
                opcodes::LDARG_0 => simulator.simulate_ldarg(0),
                opcodes::LDARG_1 => simulator.simulate_ldarg(1),
                opcodes::LDARG_2 => simulator.simulate_ldarg(2),
                opcodes::LDARG_3 => simulator.simulate_ldarg(3),
                opcodes::LDLOC_0 => simulator.simulate_ldloc(0),
                opcodes::LDLOC_1 => simulator.simulate_ldloc(1),
                opcodes::LDLOC_2 => simulator.simulate_ldloc(2),
                opcodes::LDLOC_3 => simulator.simulate_ldloc(3),
                opcodes::STLOC_0 => simulator.simulate_stloc(0),
                opcodes::STLOC_1 => simulator.simulate_stloc(1),
                opcodes::STLOC_2 => simulator.simulate_stloc(2),
                opcodes::STLOC_3 => simulator.simulate_stloc(3),
                opcodes::LDARG_S => Self::extract_index(&instr.operand)
                    .and_then(|idx| simulator.simulate_ldarg(idx)),
                opcodes::LDARGA_S => Self::extract_index(&instr.operand)
                    .and_then(|idx| simulator.simulate_ldarga(idx)),
                opcodes::STARG_S => Self::extract_index(&instr.operand)
                    .and_then(|idx| simulator.simulate_starg(idx)),
                opcodes::LDLOC_S => Self::extract_index(&instr.operand)
                    .and_then(|idx| simulator.simulate_ldloc(idx)),
                opcodes::LDLOCA_S => Self::extract_index(&instr.operand)
                    .and_then(|idx| simulator.simulate_ldloca(idx)),
                opcodes::STLOC_S => Self::extract_index(&instr.operand)
                    .and_then(|idx| simulator.simulate_stloc(idx)),
                opcodes::DUP => simulator.simulate_dup(),
                _ => simulator
                    .simulate_stack_effect(instr.stack_behavior.pops, instr.stack_behavior.pushes),
            }
        };

        result.ok_or_else(|| {
            Error::SsaError(format!(
                "Stack simulation failed for instruction: {}",
                instr.mnemonic
            ))
        })
    }

    /// Extracts an index from an operand.
    ///
    /// Handles both the typed operand forms (Argument, Local) and immediate values
    /// that are produced by the instruction assembler/decoder.
    fn extract_index(operand: &Operand) -> Option<usize> {
        match operand {
            Operand::Argument(idx) | Operand::Local(idx) => Some(*idx as usize),
            Operand::Immediate(imm) => match imm {
                Immediate::Int8(v) => usize::try_from(*v).ok(),
                Immediate::UInt8(v) => Some(*v as usize),
                Immediate::Int16(v) => usize::try_from(*v).ok(),
                Immediate::UInt16(v) => Some(*v as usize),
                Immediate::Int32(v) => usize::try_from(*v).ok(),
                Immediate::UInt32(v) => Some(*v as usize),
                _ => None,
            },
            _ => None,
        }
    }

    /// Infers the variable origin from an instruction.
    fn infer_origin(instr: &Instruction) -> Result<Option<VariableOrigin>> {
        if instr.prefix == opcodes::FE_PREFIX {
            match instr.opcode {
                opcodes::FE_STARG => match Self::extract_index(&instr.operand) {
                    Some(idx) => Ok(Some(VariableOrigin::Argument(Self::idx_to_u16(idx)?))),
                    None => Ok(None),
                },
                opcodes::FE_STLOC => match Self::extract_index(&instr.operand) {
                    Some(idx) => Ok(Some(VariableOrigin::Local(Self::idx_to_u16(idx)?))),
                    None => Ok(None),
                },
                _ => Ok(None),
            }
        } else {
            match instr.opcode {
                opcodes::STLOC_0 => Ok(Some(VariableOrigin::Local(0))),
                opcodes::STLOC_1 => Ok(Some(VariableOrigin::Local(1))),
                opcodes::STLOC_2 => Ok(Some(VariableOrigin::Local(2))),
                opcodes::STLOC_3 => Ok(Some(VariableOrigin::Local(3))),
                opcodes::STARG_S => match Self::extract_index(&instr.operand) {
                    Some(idx) => Ok(Some(VariableOrigin::Argument(Self::idx_to_u16(idx)?))),
                    None => Ok(None),
                },
                opcodes::STLOC_S => match Self::extract_index(&instr.operand) {
                    Some(idx) => Ok(Some(VariableOrigin::Local(Self::idx_to_u16(idx)?))),
                    None => Ok(None),
                },
                _ => Ok(None),
            }
        }
    }

    /// Phase 2: Places phi nodes at dominance frontiers.
    ///
    /// For each variable that has multiple definitions, we place phi nodes
    /// at the iterated dominance frontier of its definition sites.
    fn place_phi_nodes(&mut self) {
        let dominance_frontiers = self.cfg.dominance_frontiers();

        for (origin, def_blocks) in &self.defs {
            if self.address_taken.contains(origin) {
                continue;
            }

            // Compute iterated dominance frontier
            let mut phi_blocks: HashSet<usize> = HashSet::new();
            let mut worklist: Vec<usize> = def_blocks.iter().copied().collect();

            while let Some(block_idx) = worklist.pop() {
                let node_id = NodeId::new(block_idx);
                if node_id.index() < dominance_frontiers.len() {
                    for &frontier_node in &dominance_frontiers[node_id.index()] {
                        let frontier_idx = frontier_node.index();
                        if phi_blocks.insert(frontier_idx) {
                            worklist.push(frontier_idx);
                        }
                    }
                }
            }

            // Place phi nodes for this origin at each frontier block
            for &phi_block_idx in &phi_blocks {
                if let Some(block) = self.function.block_mut(phi_block_idx) {
                    let phi = PhiNode::new(SsaVarId::new(0), *origin);
                    block.add_phi(phi);
                }
            }
        }
    }

    /// Phase 3: Renames variables using dominator tree traversal.
    ///
    /// This assigns unique SSA versions to each variable definition and
    /// updates uses to reference the correct reaching definition.
    fn rename_variables(&mut self) -> Result<()> {
        // Initialize version stacks and create initial variables for args/locals
        for i in 0..self.num_args {
            let origin = VariableOrigin::Argument(Self::idx_to_u16(i)?);
            let initial_var = SsaVarId::new(self.function.variable_count());
            let var = SsaVariable::new(initial_var, origin, 0, DefSite::entry());
            self.function.add_variable(var);
            self.version_stacks.insert(origin, vec![(0, initial_var)]);
            self.next_version.insert(origin, 1);
        }
        for i in 0..self.num_locals {
            let origin = VariableOrigin::Local(Self::idx_to_u16(i)?);
            let initial_var = SsaVarId::new(self.function.variable_count());
            let var = SsaVariable::new(initial_var, origin, 0, DefSite::entry());
            self.function.add_variable(var);
            self.version_stacks.insert(origin, vec![(0, initial_var)]);
            self.next_version.insert(origin, 1);
        }

        // Start renaming from entry block
        let dom_tree = self.cfg.dominators();
        self.rename_block(self.cfg.entry().index(), dom_tree)?;

        Ok(())
    }

    /// Gets the current SSA variable for a given origin.
    fn current_def(&self, origin: VariableOrigin) -> Option<SsaVarId> {
        self.version_stacks
            .get(&origin)
            .and_then(|stack| stack.last())
            .map(|(_, var_id)| *var_id)
    }

    /// Creates a new SSA variable for a definition and pushes it on the stack.
    fn new_def(
        &mut self,
        origin: VariableOrigin,
        block_idx: usize,
        instr_idx: Option<usize>,
    ) -> SsaVarId {
        let version = *self.next_version.get(&origin).unwrap_or(&0);
        *self.next_version.entry(origin).or_insert(0) += 1;

        let var_id = SsaVarId::new(self.function.variable_count());
        let def_site = match instr_idx {
            Some(idx) => DefSite::instruction(block_idx, idx),
            None => DefSite::phi(block_idx),
        };
        let var = SsaVariable::new(var_id, origin, version, def_site);
        self.function.add_variable(var);

        self.version_stacks
            .entry(origin)
            .or_default()
            .push((version, var_id));
        var_id
    }

    /// Records a use of an SSA variable at the given site.
    fn record_use(&mut self, var_id: SsaVarId, use_site: UseSite) {
        if let Some(var) = self.function.variable_mut(var_id) {
            var.add_use(use_site);
        }
    }

    /// Recursively renames variables in a block and its dominated children.
    fn rename_block(&mut self, block_idx: usize, dom_tree: &DominatorTree) -> Result<()> {
        // Track how many definitions we push for each origin (for cleanup)
        let mut pushed_counts: HashMap<VariableOrigin, usize> = HashMap::new();

        // Step 1: Process phi nodes - they define new versions
        let phi_count = self
            .function
            .block(block_idx)
            .map_or(0, SsaBlock::phi_count);
        for phi_idx in 0..phi_count {
            if let Some(block) = self.function.block(block_idx) {
                if let Some(phi) = block.phi(phi_idx) {
                    let origin = phi.origin();
                    // Create new definition for this phi
                    let new_var = self.new_def(origin, block_idx, None);
                    *pushed_counts.entry(origin).or_insert(0) += 1;

                    // Update the phi's result
                    if let Some(block) = self.function.block_mut(block_idx) {
                        if let Some(phi) = block.phi_mut(phi_idx) {
                            phi.set_result(new_var);
                        }
                    }
                }
            }
        }

        // Step 2: Process instructions - update uses and create new defs
        let instr_count = self
            .function
            .block(block_idx)
            .map_or(0, SsaBlock::instruction_count);

        for instr_idx in 0..instr_count {
            // Get instruction info
            let instr_info = self.function.block(block_idx).and_then(|b| {
                b.instruction(instr_idx)
                    .map(|instr| (instr.original().clone(), instr.uses().to_vec(), instr.def()))
            });

            if let Some((cil_instr, uses, _old_def)) = instr_info {
                // Record uses for each operand
                // The uses are SsaVarIds that were assigned during stack simulation
                for &use_var in &uses {
                    let use_site = UseSite::instruction(block_idx, instr_idx);
                    self.record_use(use_var, use_site);
                }

                // Determine the origin this instruction defines (if any)
                let def_origin = Self::infer_origin(&cil_instr)?;

                // If this instruction defines a variable, create new version
                if let Some(origin) = def_origin {
                    let new_var = self.new_def(origin, block_idx, Some(instr_idx));
                    *pushed_counts.entry(origin).or_insert(0) += 1;

                    // Update the instruction's def
                    if let Some(block) = self.function.block_mut(block_idx) {
                        if let Some(instr) = block.instruction_mut(instr_idx) {
                            instr.set_def(Some(new_var));
                        }
                    }
                }
            }
        }

        // Step 3: Fill in phi operands in successor blocks and record uses
        let successors: Vec<usize> = self
            .cfg
            .successors(NodeId::new(block_idx))
            .map(NodeId::index)
            .collect();

        for succ_idx in successors {
            let succ_phi_count = self.function.block(succ_idx).map_or(0, SsaBlock::phi_count);

            for phi_idx in 0..succ_phi_count {
                // Get the origin for this phi
                let origin = self
                    .function
                    .block(succ_idx)
                    .and_then(|b| b.phi(phi_idx))
                    .map(PhiNode::origin);

                if let Some(origin) = origin {
                    // Get current reaching definition for this origin
                    let reaching_def = self.current_def(origin).unwrap_or(SsaVarId::new(0));

                    // Add operand to phi
                    if let Some(block) = self.function.block_mut(succ_idx) {
                        if let Some(phi) = block.phi_mut(phi_idx) {
                            phi.set_operand(block_idx, reaching_def);
                        }
                    }

                    // Record that reaching_def is used by this phi operand
                    let use_site = UseSite::phi_operand(succ_idx, phi_idx);
                    self.record_use(reaching_def, use_site);
                }
            }
        }

        // Step 4: Recursively process dominated children
        let children: Vec<_> = dom_tree
            .children(NodeId::new(block_idx))
            .into_iter()
            .collect();
        for child in children {
            self.rename_block(child.index(), dom_tree)?;
        }

        // Step 5: Pop pushed definitions from stacks
        for (origin, count) in pushed_counts {
            if let Some(stack) = self.version_stacks.get_mut(&origin) {
                for _ in 0..count {
                    stack.pop();
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assembly::{decode_blocks, InstructionAssembler};

    /// Helper to build a CFG from assembled bytecode.
    fn build_cfg(assembler: InstructionAssembler) -> ControlFlowGraph<'static> {
        let (bytecode, _max_stack) = assembler.finish().expect("Failed to assemble bytecode");
        let blocks =
            decode_blocks(&bytecode, 0, 0x1000, Some(bytecode.len())).expect("Failed to decode");
        ControlFlowGraph::from_basic_blocks(blocks).expect("Failed to build CFG")
    }

    #[test]
    fn test_simple_function() {
        // Simple method: return arg0 + arg1
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
        let ssa = SsaBuilder::build(&cfg, 2, 0).expect("SSA construction failed");

        // Should have 1 block
        assert_eq!(ssa.block_count(), 1);

        // Should have at least 2 variables (args)
        assert!(ssa.variable_count() >= 2);
    }

    #[test]
    fn test_local_variable() {
        // Method: local0 = arg0; return local0
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
        let ssa = SsaBuilder::build(&cfg, 1, 1).expect("SSA construction failed");

        // Should have 1 block
        assert_eq!(ssa.block_count(), 1);

        // Should have variables for arg and local
        assert!(ssa.variable_count() >= 2);
    }

    #[test]
    fn test_conditional_no_phi() {
        // if (arg0) { return 1; } return 0;
        // No phi needed because both paths return
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
        let ssa = SsaBuilder::build(&cfg, 1, 0).expect("SSA construction failed");

        // Should have 3 blocks: entry, then, else
        assert_eq!(ssa.block_count(), 3);

        // No phi nodes should be needed (no merge point)
        assert_eq!(ssa.total_phi_count(), 0);
    }

    #[test]
    fn test_diamond_with_merge() {
        // if (arg0) { x = 1; } else { x = 0; } return x;
        let mut asm = InstructionAssembler::new();
        asm.ldarg_0()
            .unwrap()
            .brfalse_s("else")
            .unwrap()
            .ldc_i4_1()
            .unwrap()
            .stloc_0()
            .unwrap()
            .br_s("merge")
            .unwrap()
            .label("else")
            .unwrap()
            .ldc_i4_0()
            .unwrap()
            .stloc_0()
            .unwrap()
            .label("merge")
            .unwrap()
            .ldloc_0()
            .unwrap()
            .ret()
            .unwrap();

        let cfg = build_cfg(asm);
        let ssa = SsaBuilder::build(&cfg, 1, 1).expect("SSA construction failed");

        // Should have 4 blocks: entry, then, else, merge
        assert_eq!(ssa.block_count(), 4);

        // Should have a phi node in the merge block
        // (local0 is defined in both then and else branches)
        assert!(ssa.total_phi_count() > 0);
    }

    #[test]
    fn test_loop_phi() {
        // i = 0; while (i < arg0) { i++; } return i;
        let mut asm = InstructionAssembler::new();
        asm.ldc_i4_0()
            .unwrap()
            .stloc_0()
            .unwrap() // i = 0
            .label("loop_header")
            .unwrap()
            .ldloc_0()
            .unwrap()
            .ldarg_0()
            .unwrap()
            .bge_s("loop_exit")
            .unwrap() // if (i >= arg0) exit
            .ldloc_0()
            .unwrap()
            .ldc_i4_1()
            .unwrap()
            .add()
            .unwrap()
            .stloc_0()
            .unwrap() // i++
            .br_s("loop_header")
            .unwrap()
            .label("loop_exit")
            .unwrap()
            .ldloc_0()
            .unwrap()
            .ret()
            .unwrap();

        let cfg = build_cfg(asm);
        let ssa = SsaBuilder::build(&cfg, 1, 1).expect("SSA construction failed");

        // Should have multiple blocks
        assert!(ssa.block_count() >= 2);

        // Should have phi node(s) for the loop variable
        // (i is modified in the loop body and merged at the header)
    }

    #[test]
    fn test_empty_cfg_error() {
        // Create an empty CFG manually would require internal access
        // For now, test that construction succeeds with minimal valid input
        let mut asm = InstructionAssembler::new();
        asm.ret().unwrap();

        let cfg = build_cfg(asm);
        let result = SsaBuilder::build(&cfg, 0, 0);
        assert!(result.is_ok());
    }

    // ============================================================
    // Variable Renaming Verification Tests
    // ============================================================

    #[test]
    fn test_variable_versions_increment_correctly() {
        // Test that multiple definitions of the same local create different versions
        // local0 = 1; local0 = 2; local0 = 3; return local0;
        let mut asm = InstructionAssembler::new();
        asm.ldc_i4_1()
            .unwrap()
            .stloc_0()
            .unwrap() // local0_0 = 1
            .ldc_i4_2()
            .unwrap()
            .stloc_0()
            .unwrap() // local0_1 = 2
            .ldc_i4_3()
            .unwrap()
            .stloc_0()
            .unwrap() // local0_2 = 3
            .ldloc_0()
            .unwrap()
            .ret()
            .unwrap();

        let cfg = build_cfg(asm);
        let ssa = SsaBuilder::build(&cfg, 0, 1).expect("SSA construction failed");

        // Collect all versions of local0
        let local0_vars: Vec<_> = ssa.variables_from_local(0).collect();

        // Should have multiple versions: initial (version 0) plus 3 definitions
        assert!(
            local0_vars.len() >= 3,
            "Expected at least 3 versions of local0, got {}",
            local0_vars.len()
        );

        // Verify each version is unique
        let mut versions: Vec<u32> = local0_vars.iter().map(|v| v.version()).collect();
        versions.sort();
        versions.dedup();
        assert_eq!(
            versions.len(),
            local0_vars.len(),
            "Not all versions are unique"
        );
    }

    #[test]
    fn test_phi_node_operands_from_correct_predecessors() {
        // Diamond control flow: local0 defined differently in each branch
        // if (arg0) { local0 = 1; } else { local0 = 2; }
        // return local0;
        let mut asm = InstructionAssembler::new();
        asm.ldarg_0()
            .unwrap()
            .brfalse_s("else")
            .unwrap()
            // then branch: local0 = 1
            .ldc_i4_1()
            .unwrap()
            .stloc_0()
            .unwrap()
            .br_s("merge")
            .unwrap()
            // else branch: local0 = 2
            .label("else")
            .unwrap()
            .ldc_i4_2()
            .unwrap()
            .stloc_0()
            .unwrap()
            // merge point
            .label("merge")
            .unwrap()
            .ldloc_0()
            .unwrap()
            .ret()
            .unwrap();

        let cfg = build_cfg(asm);
        let ssa = SsaBuilder::build(&cfg, 1, 1).expect("SSA construction failed");

        // Find the merge block (block 3 in 0-indexed: entry=0, then=1, else=2, merge=3)
        // There should be a phi node for local0 in the merge block
        assert!(
            ssa.total_phi_count() > 0,
            "Expected phi nodes in merge block"
        );

        // Get all phi nodes
        let phi_nodes: Vec<_> = ssa.all_phi_nodes().collect();
        assert!(!phi_nodes.is_empty(), "No phi nodes found");

        // Find phi node for local0
        let local0_phi = phi_nodes
            .iter()
            .find(|phi| phi.origin() == VariableOrigin::Local(0));
        assert!(
            local0_phi.is_some(),
            "No phi node found for local0 in merge block"
        );

        let phi = local0_phi.unwrap();

        // Phi should have 2 operands (one from each predecessor)
        assert_eq!(
            phi.operand_count(),
            2,
            "Phi node should have exactly 2 operands, got {}",
            phi.operand_count()
        );

        // Each operand should reference a different predecessor
        let predecessors: Vec<_> = phi.operands().iter().map(|op| op.predecessor()).collect();
        assert_ne!(
            predecessors[0], predecessors[1],
            "Phi operands should come from different predecessors"
        );
    }

    #[test]
    fn test_loop_variable_renaming() {
        // Loop with variable modified in body:
        // i = 0; while (i < 10) { i = i + 1; } return i;
        let mut asm = InstructionAssembler::new();
        asm.ldc_i4_0()
            .unwrap()
            .stloc_0()
            .unwrap() // i = 0
            .label("loop_header")
            .unwrap()
            .ldloc_0()
            .unwrap()
            .ldc_i4_s(10)
            .unwrap()
            .bge_s("exit")
            .unwrap() // if i >= 10 exit
            // loop body: i = i + 1
            .ldloc_0()
            .unwrap()
            .ldc_i4_1()
            .unwrap()
            .add()
            .unwrap()
            .stloc_0()
            .unwrap()
            .br_s("loop_header")
            .unwrap()
            .label("exit")
            .unwrap()
            .ldloc_0()
            .unwrap()
            .ret()
            .unwrap();

        let cfg = build_cfg(asm);
        let ssa = SsaBuilder::build(&cfg, 0, 1).expect("SSA construction failed");

        // Loop header should have a phi node for local0 (merges initial value and loop value)
        assert!(
            ssa.total_phi_count() > 0,
            "Expected phi node(s) for loop variable"
        );

        // Find phi node for local0
        let local0_phis: Vec<_> = ssa
            .all_phi_nodes()
            .filter(|phi| phi.origin() == VariableOrigin::Local(0))
            .collect();

        assert!(
            !local0_phis.is_empty(),
            "Expected phi node for loop variable local0"
        );

        // The phi in the loop header should have 2 operands:
        // one from entry block (initial value) and one from loop body (incremented value)
        for phi in &local0_phis {
            assert!(
                phi.operand_count() >= 2,
                "Loop phi should have at least 2 operands, got {}",
                phi.operand_count()
            );
        }

        // Verify we have multiple versions of local0
        let local0_versions: Vec<_> = ssa.variables_from_local(0).collect();
        assert!(
            local0_versions.len() >= 2,
            "Expected multiple versions of local0, got {}",
            local0_versions.len()
        );
    }

    #[test]
    fn test_unique_ssa_variable_ids() {
        // Test that all SSA variables have unique IDs
        let mut asm = InstructionAssembler::new();
        asm.ldarg_0()
            .unwrap()
            .ldarg_1()
            .unwrap()
            .add()
            .unwrap()
            .stloc_0()
            .unwrap()
            .ldloc_0()
            .unwrap()
            .ldarg_0()
            .unwrap()
            .mul()
            .unwrap()
            .stloc_0()
            .unwrap()
            .ldloc_0()
            .unwrap()
            .ret()
            .unwrap();

        let cfg = build_cfg(asm);
        let ssa = SsaBuilder::build(&cfg, 2, 1).expect("SSA construction failed");

        // All variable IDs should be unique
        let mut ids: Vec<_> = ssa.variables().iter().map(|v| v.id().index()).collect();
        let original_len = ids.len();
        ids.sort();
        ids.dedup();
        assert_eq!(
            ids.len(),
            original_len,
            "All SSA variable IDs should be unique"
        );
    }

    #[test]
    fn test_argument_variable_initial_version() {
        // Arguments should have version 0 at function entry
        let mut asm = InstructionAssembler::new();
        asm.ldarg_0()
            .unwrap()
            .ldarg_1()
            .unwrap()
            .ldarg_2()
            .unwrap()
            .add()
            .unwrap()
            .add()
            .unwrap()
            .ret()
            .unwrap();

        let cfg = build_cfg(asm);
        let ssa = SsaBuilder::build(&cfg, 3, 0).expect("SSA construction failed");

        // Check that we have argument variables
        let arg_vars: Vec<_> = ssa.argument_variables().collect();
        assert_eq!(
            arg_vars.len(),
            3,
            "Expected 3 argument variables (version 0), got {}",
            arg_vars.len()
        );

        // All should have version 0
        for var in arg_vars {
            assert_eq!(
                var.version(),
                0,
                "Initial argument should have version 0, got {}",
                var.version()
            );
        }
    }

    #[test]
    fn test_stack_variable_across_branch() {
        // Test that stack values flowing across branches are handled correctly
        // dup; brtrue skip; pop; skip: ret
        // This tests the stack depth propagation fix
        let mut asm = InstructionAssembler::new();
        asm.ldarg_0()
            .unwrap()
            .dup()
            .unwrap() // stack: [arg0, arg0]
            .brtrue_s("skip")
            .unwrap() // pops one, stack: [arg0] if false, [arg0] if true
            .pop()
            .unwrap() // stack: [] if we reach here
            .label("skip")
            .unwrap()
            .ret()
            .unwrap();

        let cfg = build_cfg(asm);
        let ssa = SsaBuilder::build(&cfg, 1, 0).expect("SSA construction failed");

        // Should succeed without error (this was failing before the stack depth fix)
        assert!(ssa.block_count() >= 2);
    }

    #[test]
    fn test_nested_conditionals_phi_placement() {
        // Nested conditionals to test phi node placement at correct join points
        // if (arg0) { if (arg1) { local0 = 1; } else { local0 = 2; } } else { local0 = 3; }
        // return local0;
        let mut asm = InstructionAssembler::new();
        asm.ldarg_0()
            .unwrap()
            .brfalse_s("outer_else")
            .unwrap()
            // outer then
            .ldarg_1()
            .unwrap()
            .brfalse_s("inner_else")
            .unwrap()
            // inner then: local0 = 1
            .ldc_i4_1()
            .unwrap()
            .stloc_0()
            .unwrap()
            .br_s("inner_merge")
            .unwrap()
            // inner else: local0 = 2
            .label("inner_else")
            .unwrap()
            .ldc_i4_2()
            .unwrap()
            .stloc_0()
            .unwrap()
            .label("inner_merge")
            .unwrap()
            .br_s("outer_merge")
            .unwrap()
            // outer else: local0 = 3
            .label("outer_else")
            .unwrap()
            .ldc_i4_3()
            .unwrap()
            .stloc_0()
            .unwrap()
            // final merge
            .label("outer_merge")
            .unwrap()
            .ldloc_0()
            .unwrap()
            .ret()
            .unwrap();

        let cfg = build_cfg(asm);
        let ssa = SsaBuilder::build(&cfg, 2, 1).expect("SSA construction failed");

        // Should have phi nodes at merge points
        assert!(
            ssa.total_phi_count() >= 1,
            "Expected phi nodes at merge points"
        );

        // Multiple versions of local0 should exist
        let local0_vars: Vec<_> = ssa.variables_from_local(0).collect();
        assert!(
            local0_vars.len() >= 3,
            "Expected at least 3 versions of local0 (one per definition path), got {}",
            local0_vars.len()
        );
    }

    #[test]
    fn test_argument_reassignment_creates_new_version() {
        // Test that storing to an argument creates a new version
        // starg.0 after using arg0 should create arg0_1
        let mut asm = InstructionAssembler::new();
        asm.ldarg_0()
            .unwrap() // load arg0_0
            .ldc_i4_1()
            .unwrap()
            .add()
            .unwrap()
            .starg_s(0)
            .unwrap() // arg0_1 = arg0_0 + 1
            .ldarg_0()
            .unwrap() // load arg0_1
            .ret()
            .unwrap();

        let cfg = build_cfg(asm);
        let ssa = SsaBuilder::build(&cfg, 1, 0).expect("SSA construction failed");

        // Should have multiple versions of arg0
        let arg0_vars: Vec<_> = ssa.variables_from_argument(0).collect();
        assert!(
            arg0_vars.len() >= 2,
            "Expected at least 2 versions of arg0, got {}",
            arg0_vars.len()
        );

        // Should have version 0 and version 1
        let versions: Vec<u32> = arg0_vars.iter().map(|v| v.version()).collect();
        assert!(versions.contains(&0), "Expected version 0 of arg0 to exist");
    }

    #[test]
    fn test_phi_operands_reference_existing_variables() {
        // Verify that phi node operands reference variables that actually exist
        let mut asm = InstructionAssembler::new();
        asm.ldarg_0()
            .unwrap()
            .brfalse_s("else")
            .unwrap()
            .ldc_i4_1()
            .unwrap()
            .stloc_0()
            .unwrap()
            .br_s("merge")
            .unwrap()
            .label("else")
            .unwrap()
            .ldc_i4_0()
            .unwrap()
            .stloc_0()
            .unwrap()
            .label("merge")
            .unwrap()
            .ldloc_0()
            .unwrap()
            .ret()
            .unwrap();

        let cfg = build_cfg(asm);
        let ssa = SsaBuilder::build(&cfg, 1, 1).expect("SSA construction failed");

        // For each phi node, verify all operand values reference valid variables
        let var_ids: std::collections::HashSet<_> =
            ssa.variables().iter().map(|v| v.id()).collect();

        for phi in ssa.all_phi_nodes() {
            for operand in phi.operands() {
                assert!(
                    var_ids.contains(&operand.value()),
                    "Phi operand references non-existent variable {}",
                    operand.value()
                );
            }
        }
    }

    #[test]
    fn test_def_site_correctness() {
        // Verify that def_site accurately reflects where variables are defined
        let mut asm = InstructionAssembler::new();
        asm.ldc_i4_0()
            .unwrap()
            .stloc_0()
            .unwrap() // local0 defined in block 0
            .ldloc_0()
            .unwrap()
            .ret()
            .unwrap();

        let cfg = build_cfg(asm);
        let ssa = SsaBuilder::build(&cfg, 0, 1).expect("SSA construction failed");

        // Find the non-initial version of local0 (the one from stloc)
        let local0_defs: Vec<_> = ssa
            .variables_from_local(0)
            .filter(|v| !v.def_site().is_phi()) // Skip phi/entry definitions
            .collect();

        // At least one should be defined by an instruction (not phi)
        for var in local0_defs {
            assert!(
                var.def_site().instruction.is_some(),
                "Non-phi variable should have instruction def site"
            );
            // def_site block should be valid
            assert!(
                var.def_site().block < ssa.block_count(),
                "Def site block out of range"
            );
        }
    }
}
