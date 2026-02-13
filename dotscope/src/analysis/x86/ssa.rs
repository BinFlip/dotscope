//! x86 to SSA translator.
//!
//! This module translates decoded x86 functions into SSA form, enabling
//! integration with the existing SSA optimization and codegen infrastructure.
//!
//! # Overview
//!
//! The translation pipeline:
//!
//! ```text
//! X86Function (CFG) → analyze dominance → place phi nodes → translate blocks → SsaFunction
//! ```
//!
//! # Register Versioning
//!
//! Each x86 register is tracked as a versioned SSA variable. When a register
//! is written, a new SSA variable is created. At control flow join points,
//! phi nodes merge the different versions.
//!
//! # Phi Node Placement
//!
//! Phi nodes are placed using the dominance frontier algorithm:
//! 1. Compute dominance frontiers for the CFG
//! 2. For each register defined in a block, place phi nodes at its dominance frontier
//! 3. Iterate until fixed point (phi nodes can themselves require more phi nodes)
//!
//! # Example
//!
//! ```rust,ignore
//! use dotscope::analysis::{x86_decode_all, X86Function, X86ToSsaTranslator};
//!
//! // Decode x86 code
//! let bytes = &[0x58, 0x83, 0xc0, 0x05, 0xc3]; // pop eax; add eax, 5; ret
//! let instructions = x86_decode_all(bytes, 32, 0)?;
//! let cfg = X86Function::new(&instructions, 32, 0);
//!
//! // Translate to SSA
//! let translator = X86ToSsaTranslator::new(&cfg);
//! let ssa_function = translator.translate()?;
//! ```

use crate::{
    analysis::{
        ssa::{
            CmpKind, ConstValue, DefSite, PhiNode, PhiOperand, SsaBlock, SsaFunction,
            SsaInstruction, SsaOp, SsaType, SsaVarId, SsaVariable, VariableOrigin,
        },
        x86::{
            cfg::X86Function,
            flags::{ArithmeticKind, ConditionEval, FlagState, FlagTestSource},
            types::{X86DecodedInstruction, X86Instruction, X86Memory, X86Operand, X86Register},
        },
    },
    utils::graph::NodeId,
    Error, Result,
};
use rustc_hash::{FxHashMap, FxHashSet};

/// Number of registers tracked (0-15 GPRs for x64, 16-21 segment registers).
const MAX_REGISTERS: usize = 22;

/// Tracks the current SSA variable for each x86 register.
///
/// This is the core of register versioning - each time a register is written,
/// we create a new SSA variable and update the mapping.
#[derive(Debug, Clone)]
struct RegisterState {
    /// Current SSA variable for each register (indexed by `X86Register::base_index()`).
    registers: [Option<SsaVarId>; MAX_REGISTERS],
    /// The bitness (32 or 64) - affects which registers are valid.
    bitness: u32,
}

impl RegisterState {
    /// Creates a new register state with all registers undefined.
    fn new(bitness: u32) -> Self {
        Self {
            registers: [None; MAX_REGISTERS],
            bitness,
        }
    }

    /// Gets the current SSA variable for a register.
    fn get(&self, reg: X86Register) -> Option<SsaVarId> {
        let idx = reg.base_index() as usize;
        if idx < MAX_REGISTERS {
            self.registers[idx]
        } else {
            None
        }
    }

    /// Sets the SSA variable for a register.
    fn set(&mut self, reg: X86Register, var: SsaVarId) {
        let idx = reg.base_index() as usize;
        if idx < MAX_REGISTERS {
            self.registers[idx] = Some(var);
        }
    }

    /// Returns an iterator over all defined registers and their SSA variables.
    fn defined_registers(&self) -> impl Iterator<Item = (usize, SsaVarId)> + '_ {
        self.registers
            .iter()
            .enumerate()
            .filter_map(|(idx, var)| var.map(|v| (idx, v)))
    }

    /// Returns the number of valid registers for this bitness.
    fn register_count(&self) -> usize {
        if self.bitness == 64 {
            16
        } else {
            8
        }
    }
}

/// Tracks phi nodes needed at each block for each register.
#[derive(Debug, Default)]
struct PhiPlacement {
    /// Maps block index → register index → phi node result variable.
    phis: FxHashMap<usize, FxHashMap<usize, SsaVarId>>,
}

impl PhiPlacement {
    fn new() -> Self {
        Self::default()
    }

    /// Returns the phi variable for a register at a block, if one exists.
    fn get(&self, block: usize, reg_idx: usize) -> Option<SsaVarId> {
        self.phis.get(&block).and_then(|m| m.get(&reg_idx).copied())
    }

    /// Sets the phi variable for a register at a block.
    fn set(&mut self, block: usize, reg_idx: usize, var: SsaVarId) {
        self.phis.entry(block).or_default().insert(reg_idx, var);
    }

    /// Returns true if a phi exists for the given block and register.
    fn has(&self, block: usize, reg_idx: usize) -> bool {
        self.phis
            .get(&block)
            .is_some_and(|m| m.contains_key(&reg_idx))
    }
}

/// Translates an x86 function to SSA form.
pub struct X86ToSsaTranslator<'a> {
    /// The x86 function to translate.
    func: &'a X86Function,
    /// Register state at the end of each block (for computing phi operands).
    block_exit_states: Vec<RegisterState>,
    /// Phi placement information.
    phi_placement: PhiPlacement,
    /// Blocks that define each register (for phi placement).
    reg_def_blocks: Vec<FxHashSet<usize>>,
    /// SSA variables created during translation.
    variables: Vec<SsaVariable>,
    /// Zero constant variable (lazily created).
    zero_const: Option<SsaVarId>,
}

impl<'a> X86ToSsaTranslator<'a> {
    /// Creates a new translator for the given x86 function.
    #[must_use]
    pub fn new(func: &'a X86Function) -> Self {
        let block_count = func.block_count();
        Self {
            func,
            block_exit_states: vec![RegisterState::new(func.bitness); block_count],
            phi_placement: PhiPlacement::new(),
            reg_def_blocks: vec![FxHashSet::default(); MAX_REGISTERS],
            variables: Vec::new(),
            zero_const: None,
        }
    }

    /// Translates the x86 function to SSA form.
    ///
    /// # Returns
    ///
    /// An `SsaFunction` representing the translated code, or an error if
    /// translation fails.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The function is empty
    /// - The CFG is irreducible
    /// - An unsupported instruction is encountered
    /// - A flag pattern cannot be translated
    pub fn translate(mut self) -> Result<SsaFunction> {
        if self.func.block_count() == 0 {
            return Err(Error::X86Error("Empty function".to_string()));
        }

        // Step 1: Analyze which blocks define which registers
        self.analyze_definitions();

        // Step 2: Place phi nodes using dominance frontiers
        self.place_phi_nodes();

        // Step 3: Translate blocks in dominator tree order
        let ssa_blocks = self.translate_blocks()?;

        // Step 4: Build the SSA function
        // DynCipher functions take one argument (the input value)
        let mut ssa_func = SsaFunction::new(1, 0);

        // Add blocks
        for block in ssa_blocks {
            ssa_func.add_block(block);
        }

        // Add variables
        for var in self.variables {
            ssa_func.add_variable(var);
        }

        Ok(ssa_func)
    }

    /// Analyzes which blocks define which registers.
    fn analyze_definitions(&mut self) {
        for node_id in self.func.node_ids() {
            let block_idx = node_id.index();
            if let Some(block) = self.func.block(block_idx) {
                for instr in &block.instructions {
                    if let Some(reg_idx) = get_defined_register(&instr.instruction) {
                        self.reg_def_blocks[reg_idx].insert(block_idx);
                    }
                }
            }
        }
    }

    /// Places phi nodes at dominance frontiers.
    fn place_phi_nodes(&mut self) {
        let doms = self.func.dominators();
        let block_count = self.func.block_count();
        let bitness = self.func.bitness;
        let register_count = self.block_exit_states[0].register_count();

        // For each register that is defined somewhere
        for reg_idx in 0..register_count {
            // Clone the def_blocks to avoid borrow issues
            let def_blocks: FxHashSet<usize> = self.reg_def_blocks[reg_idx].clone();
            if def_blocks.is_empty() {
                continue;
            }

            // Worklist of blocks where we might need phi nodes
            let mut worklist: Vec<usize> = def_blocks.iter().copied().collect();
            let mut phi_blocks: FxHashSet<usize> = FxHashSet::default();

            while let Some(def_block) = worklist.pop() {
                // For each block in the dominance frontier of def_block
                for block_idx in 0..block_count {
                    // Check if block_idx is in the dominance frontier of def_block
                    // DF(X) = {Y : ∃ pred of Y s.t. X dominates pred but X doesn't strictly dominate Y}
                    let node = NodeId::new(block_idx);
                    let def_node = NodeId::new(def_block);

                    let in_frontier = self.func.predecessors(node).any(|pred| {
                        doms.dominates(def_node, pred)
                            && (def_node == node || !doms.dominates(def_node, node))
                    });

                    if in_frontier && !phi_blocks.contains(&block_idx) {
                        phi_blocks.insert(block_idx);

                        // Create phi variable
                        let phi_var = self.create_variable(
                            VariableOrigin::Phi,
                            DefSite::phi(block_idx),
                            bitness,
                        );
                        self.phi_placement.set(block_idx, reg_idx, phi_var);

                        // Phi defines the register, so add to worklist
                        if !def_blocks.contains(&block_idx) {
                            worklist.push(block_idx);
                        }
                    }
                }
            }
        }
    }

    /// Translates all blocks to SSA form.
    fn translate_blocks(&mut self) -> Result<Vec<SsaBlock>> {
        let block_count = self.func.block_count();
        let mut ssa_blocks = Vec::with_capacity(block_count);

        // Initialize argument variable (first pop loads the argument)
        let arg_var = self.create_variable(
            VariableOrigin::Argument(0),
            DefSite::entry(),
            self.func.bitness,
        );

        // Process blocks in order
        for block_idx in 0..block_count {
            let ssa_block = self.translate_block(block_idx, arg_var)?;
            ssa_blocks.push(ssa_block);
        }

        // Fill in phi operands now that we know exit states
        self.fill_phi_operands(&mut ssa_blocks);

        Ok(ssa_blocks)
    }

    /// Translates a single block to SSA form.
    fn translate_block(&mut self, block_idx: usize, arg_var: SsaVarId) -> Result<SsaBlock> {
        let mut ssa_block = SsaBlock::new(block_idx);

        // Initialize register state from predecessors
        let mut reg_state = self.compute_entry_state(block_idx);

        // Initialize segment registers with constant 0 for the entry block
        // (segment registers are constant selectors in user-mode code)
        if block_idx == 0 {
            let seg_regs = [
                X86Register::Es,
                X86Register::Cs,
                X86Register::Ss,
                X86Register::Ds,
                X86Register::Fs,
                X86Register::Gs,
            ];
            for seg in seg_regs {
                if reg_state.get(seg).is_none() {
                    let seg_var = self.create_variable(
                        VariableOrigin::Stack(0),
                        DefSite::entry(),
                        self.func.bitness,
                    );
                    reg_state.set(seg, seg_var);
                }
            }
        }

        // Add phi nodes for this block
        if let Some(block_phis) = self.phi_placement.phis.get(&block_idx) {
            for (&reg_idx, &phi_var) in block_phis {
                let origin = VariableOrigin::Phi;
                let phi = PhiNode::new(phi_var, origin);
                ssa_block.add_phi(phi);

                // Phi defines this register at block entry
                if let Some(reg) = index_to_register(reg_idx, self.func.bitness) {
                    reg_state.set(reg, phi_var);
                }
            }
        }

        // Track flags for CMP/TEST + Jcc fusion
        let mut flags = FlagState::new();

        // Track if we've seen the first POP (which loads the argument)
        let mut first_pop = true;

        // Translate each instruction
        let block = self
            .func
            .block(block_idx)
            .ok_or_else(|| Error::X86Error(format!("Block {block_idx} not found")))?;

        for decoded in &block.instructions {
            let instrs = self.translate_instruction(
                decoded,
                &mut reg_state,
                &mut flags,
                arg_var,
                &mut first_pop,
                block_idx,
            )?;

            for instr in instrs {
                ssa_block.add_instruction(instr);
            }
        }

        // Save exit state for phi operand computation
        self.block_exit_states[block_idx] = reg_state;

        Ok(ssa_block)
    }

    /// Computes the register state at block entry from phi nodes and predecessors.
    fn compute_entry_state(&self, block_idx: usize) -> RegisterState {
        let mut state = RegisterState::new(self.func.bitness);

        // If this block has phi nodes, use them
        if let Some(block_phis) = self.phi_placement.phis.get(&block_idx) {
            for (&reg_idx, &phi_var) in block_phis {
                if let Some(reg) = index_to_register(reg_idx, self.func.bitness) {
                    state.set(reg, phi_var);
                }
            }
        }

        // For entry block, registers start undefined (will be set by instructions)
        if block_idx == 0 {
            return state;
        }

        // For non-entry blocks without phis, try to get value from single predecessor
        let node = NodeId::new(block_idx);
        let preds: Vec<_> = self.func.predecessors(node).collect();

        if preds.len() == 1 {
            let pred_idx = preds[0].index();
            // Copy predecessor's exit state for registers without phi nodes
            for reg_idx in 0..state.register_count() {
                if !self.phi_placement.has(block_idx, reg_idx) {
                    if let Some(var) = self.block_exit_states[pred_idx].registers[reg_idx] {
                        state.registers[reg_idx] = Some(var);
                    }
                }
            }
        }

        state
    }

    /// Fills in phi operands after all blocks have been translated.
    fn fill_phi_operands(&self, ssa_blocks: &mut [SsaBlock]) {
        for (block_idx, ssa_block) in ssa_blocks.iter_mut().enumerate() {
            let node = NodeId::new(block_idx);

            for phi in ssa_block.phi_nodes_mut() {
                // Find which register this phi is for
                let phi_var = phi.result();
                let reg_idx = self.find_phi_register(block_idx, phi_var);

                if let Some(reg_idx) = reg_idx {
                    // Add operand from each predecessor
                    for pred in self.func.predecessors(node) {
                        let pred_idx = pred.index();
                        if let Some(var) = self.block_exit_states[pred_idx].registers[reg_idx] {
                            phi.add_operand(PhiOperand::new(var, pred_idx));
                        }
                    }
                }
            }
        }
    }

    /// Finds which register index a phi variable is for.
    fn find_phi_register(&self, block_idx: usize, phi_var: SsaVarId) -> Option<usize> {
        if let Some(block_phis) = self.phi_placement.phis.get(&block_idx) {
            for (&reg_idx, &var) in block_phis {
                if var == phi_var {
                    return Some(reg_idx);
                }
            }
        }
        None
    }

    /// Translates a single x86 instruction to SSA operations.
    #[allow(clippy::too_many_arguments)]
    fn translate_instruction(
        &mut self,
        decoded: &X86DecodedInstruction,
        reg_state: &mut RegisterState,
        flags: &mut FlagState,
        arg_var: SsaVarId,
        first_pop: &mut bool,
        block_idx: usize,
    ) -> Result<Vec<SsaInstruction>> {
        let mut result = Vec::new();

        match &decoded.instruction {
            // Data movement
            X86Instruction::Mov { dst, src } => {
                let src_var = self.get_operand_value(src, reg_state, &mut result, block_idx)?;
                self.set_operand_value(dst, src_var, reg_state, &mut result, block_idx)?;
                flags.clear(); // MOV doesn't set flags
            }

            X86Instruction::Movzx { dst, src } | X86Instruction::Movsx { dst, src } => {
                let src_var = self.get_operand_value(src, reg_state, &mut result, block_idx)?;
                // For SSA purposes, we treat zero/sign extension as a simple move
                // The type system will handle the extension semantics
                self.set_operand_value(dst, src_var, reg_state, &mut result, block_idx)?;
                flags.clear();
            }

            X86Instruction::Lea { dst, src } => {
                // LEA computes an address without dereferencing
                let addr_var =
                    self.compute_memory_address(src, reg_state, &mut result, block_idx)?;
                reg_state.set(*dst, addr_var);
                flags.clear();
            }

            X86Instruction::Push { .. } => {
                // In our simplified model, we don't track stack explicitly
                // PUSH is used in prologues which we skip
                flags.clear();
            }

            X86Instruction::Pop { dst } => {
                // First POP in DynCipher code loads the argument
                if *first_pop {
                    *first_pop = false;
                    reg_state.set(*dst, arg_var);
                } else {
                    // Subsequent POPs restore saved registers (prologue handling)
                    // We create an undefined value
                    let var = self.create_variable(
                        VariableOrigin::Stack(0),
                        DefSite::instruction(block_idx, result.len()),
                        self.func.bitness,
                    );
                    reg_state.set(*dst, var);
                }
                flags.clear();
            }

            X86Instruction::Xchg { dst, src } => {
                let dst_var = self.get_operand_value(dst, reg_state, &mut result, block_idx)?;
                let src_var = self.get_operand_value(src, reg_state, &mut result, block_idx)?;
                self.set_operand_value(dst, src_var, reg_state, &mut result, block_idx)?;
                self.set_operand_value(src, dst_var, reg_state, &mut result, block_idx)?;
                flags.clear();
            }

            // Arithmetic
            X86Instruction::Add { dst, src } => {
                let dst_var = self.get_operand_value(dst, reg_state, &mut result, block_idx)?;
                let src_var = self.get_operand_value(src, reg_state, &mut result, block_idx)?;
                let res_var = self.create_variable(
                    VariableOrigin::Stack(0),
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::Add {
                    dest: res_var,
                    left: dst_var,
                    right: src_var,
                }));
                self.set_operand_value(dst, res_var, reg_state, &mut result, block_idx)?;
                flags.set_arithmetic(res_var, dst_var, src_var, ArithmeticKind::Add);
                // CF = (result < left) unsigned — unsigned overflow detection
                let cf = self.create_variable(
                    VariableOrigin::Stack(0),
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::Clt {
                    dest: cf,
                    left: res_var,
                    right: dst_var,
                    unsigned: true,
                }));
                flags.set_carry(cf);
            }

            X86Instruction::Sub { dst, src } => {
                let dst_var = self.get_operand_value(dst, reg_state, &mut result, block_idx)?;
                let src_var = self.get_operand_value(src, reg_state, &mut result, block_idx)?;
                let res_var = self.create_variable(
                    VariableOrigin::Stack(0),
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::Sub {
                    dest: res_var,
                    left: dst_var,
                    right: src_var,
                }));
                self.set_operand_value(dst, res_var, reg_state, &mut result, block_idx)?;
                flags.set_arithmetic(res_var, dst_var, src_var, ArithmeticKind::Sub);
                // CF = (left < right) unsigned — borrow detection
                let cf = self.create_variable(
                    VariableOrigin::Stack(0),
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::Clt {
                    dest: cf,
                    left: dst_var,
                    right: src_var,
                    unsigned: true,
                }));
                flags.set_carry(cf);
            }

            X86Instruction::Imul { dst, src, src2 } => {
                let src_var = self.get_operand_value(src, reg_state, &mut result, block_idx)?;
                let multiplier = if let Some(s2) = src2 {
                    self.get_operand_value(s2, reg_state, &mut result, block_idx)?
                } else {
                    // Two-operand form: dst = dst * src
                    Self::get_register_value(*dst, reg_state)?
                };
                let res_var = self.create_variable(
                    VariableOrigin::Stack(0),
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::Mul {
                    dest: res_var,
                    left: src_var,
                    right: multiplier,
                }));
                reg_state.set(*dst, res_var);
                flags.set_arithmetic(res_var, src_var, multiplier, ArithmeticKind::Other);
            }

            X86Instruction::Mul { src } => {
                // MUL: EDX:EAX = EAX * src (unsigned)
                // For simplicity, we only track EAX result
                let eax = Self::get_register_value(X86Register::Eax, reg_state)?;
                let src_var = self.get_operand_value(src, reg_state, &mut result, block_idx)?;
                let res_var = self.create_variable(
                    VariableOrigin::Stack(0),
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::Mul {
                    dest: res_var,
                    left: eax,
                    right: src_var,
                }));
                reg_state.set(X86Register::Eax, res_var);
                flags.set_arithmetic(res_var, eax, src_var, ArithmeticKind::Other);
            }

            X86Instruction::Neg { dst } => {
                let dst_var = self.get_operand_value(dst, reg_state, &mut result, block_idx)?;
                let res_var = self.create_variable(
                    VariableOrigin::Stack(0),
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::Neg {
                    dest: res_var,
                    operand: dst_var,
                }));
                self.set_operand_value(dst, res_var, reg_state, &mut result, block_idx)?;
                flags.set_arithmetic_unary(res_var);
                // NEG sets CF = (operand != 0)
                let zero = self.get_constant(0, &mut result, block_idx);
                let cf = self.create_variable(
                    VariableOrigin::Stack(0),
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::Ceq {
                    dest: cf,
                    left: dst_var,
                    right: zero,
                }));
                // Ceq gives 1 if equal, but CF = (operand != 0), so we need NOT of Ceq
                // CF = 1 - Ceq(operand, 0)  or equivalently CF = Cgt(operand, 0, unsigned)
                // Actually simpler: Ceq gives us (operand == 0), we need (operand != 0)
                // We can XOR with 1 to flip it
                let one = self.get_constant(1, &mut result, block_idx);
                let neg_cf = self.create_variable(
                    VariableOrigin::Stack(0),
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::Xor {
                    dest: neg_cf,
                    left: cf,
                    right: one,
                }));
                flags.set_carry(neg_cf);
            }

            X86Instruction::Inc { dst } => {
                let dst_var = self.get_operand_value(dst, reg_state, &mut result, block_idx)?;
                let one = self.get_constant(1, &mut result, block_idx);
                let res_var = self.create_variable(
                    VariableOrigin::Stack(0),
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::Add {
                    dest: res_var,
                    left: dst_var,
                    right: one,
                }));
                self.set_operand_value(dst, res_var, reg_state, &mut result, block_idx)?;
                // INC sets ZF/SF/OF but does NOT modify CF
                flags.set_arithmetic(res_var, dst_var, one, ArithmeticKind::Add);
            }

            X86Instruction::Dec { dst } => {
                let dst_var = self.get_operand_value(dst, reg_state, &mut result, block_idx)?;
                let one = self.get_constant(1, &mut result, block_idx);
                let res_var = self.create_variable(
                    VariableOrigin::Stack(0),
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::Sub {
                    dest: res_var,
                    left: dst_var,
                    right: one,
                }));
                self.set_operand_value(dst, res_var, reg_state, &mut result, block_idx)?;
                // DEC sets ZF/SF/OF but does NOT modify CF
                flags.set_arithmetic(res_var, dst_var, one, ArithmeticKind::Sub);
            }

            // Add with carry: dest = dst + src + CF
            X86Instruction::Adc { dst, src } => {
                let dst_var = self.get_operand_value(dst, reg_state, &mut result, block_idx)?;
                let src_var = self.get_operand_value(src, reg_state, &mut result, block_idx)?;
                // Get current carry flag (default to 0 if unknown)
                let cf_var = flags
                    .carry()
                    .unwrap_or_else(|| self.get_constant(0, &mut result, block_idx));
                // temp = dst + src
                let temp_var = self.create_variable(
                    VariableOrigin::Stack(0),
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::Add {
                    dest: temp_var,
                    left: dst_var,
                    right: src_var,
                }));
                // result = temp + CF
                let res_var = self.create_variable(
                    VariableOrigin::Stack(0),
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::Add {
                    dest: res_var,
                    left: temp_var,
                    right: cf_var,
                }));
                self.set_operand_value(dst, res_var, reg_state, &mut result, block_idx)?;
                flags.set_arithmetic(res_var, dst_var, src_var, ArithmeticKind::Add);
                // CF = (temp < dst) | (result < temp) — carry from either addition
                let cf1 = self.create_variable(
                    VariableOrigin::Stack(0),
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::Clt {
                    dest: cf1,
                    left: temp_var,
                    right: dst_var,
                    unsigned: true,
                }));
                let cf2 = self.create_variable(
                    VariableOrigin::Stack(0),
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::Clt {
                    dest: cf2,
                    left: res_var,
                    right: temp_var,
                    unsigned: true,
                }));
                let new_cf = self.create_variable(
                    VariableOrigin::Stack(0),
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::Or {
                    dest: new_cf,
                    left: cf1,
                    right: cf2,
                }));
                flags.set_carry(new_cf);
            }

            // Subtract with borrow: dest = dst - src - CF
            X86Instruction::Sbb { dst, src } => {
                let dst_var = self.get_operand_value(dst, reg_state, &mut result, block_idx)?;
                let src_var = self.get_operand_value(src, reg_state, &mut result, block_idx)?;
                // Get current carry flag (default to 0 if unknown)
                let cf_var = flags
                    .carry()
                    .unwrap_or_else(|| self.get_constant(0, &mut result, block_idx));
                // temp = dst - src
                let temp_var = self.create_variable(
                    VariableOrigin::Stack(0),
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::Sub {
                    dest: temp_var,
                    left: dst_var,
                    right: src_var,
                }));
                // result = temp - CF
                let res_var = self.create_variable(
                    VariableOrigin::Stack(0),
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::Sub {
                    dest: res_var,
                    left: temp_var,
                    right: cf_var,
                }));
                self.set_operand_value(dst, res_var, reg_state, &mut result, block_idx)?;
                flags.set_arithmetic(res_var, dst_var, src_var, ArithmeticKind::Sub);
                // CF = (dst < src) | (temp < CF) — borrow from either subtraction
                let cf1 = self.create_variable(
                    VariableOrigin::Stack(0),
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::Clt {
                    dest: cf1,
                    left: dst_var,
                    right: src_var,
                    unsigned: true,
                }));
                let cf2 = self.create_variable(
                    VariableOrigin::Stack(0),
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::Clt {
                    dest: cf2,
                    left: temp_var,
                    right: cf_var,
                    unsigned: true,
                }));
                let new_cf = self.create_variable(
                    VariableOrigin::Stack(0),
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::Or {
                    dest: new_cf,
                    left: cf1,
                    right: cf2,
                }));
                flags.set_carry(new_cf);
            }

            // Unsigned division: EDX:EAX / src
            X86Instruction::Div { src } => {
                let eax = Self::get_register_value(X86Register::Eax, reg_state)?;
                let src_var = self.get_operand_value(src, reg_state, &mut result, block_idx)?;
                // Quotient → EAX
                let quot_var = self.create_variable(
                    VariableOrigin::Stack(0),
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::Div {
                    dest: quot_var,
                    left: eax,
                    right: src_var,
                    unsigned: true,
                }));
                reg_state.set(X86Register::Eax, quot_var);
                // Remainder → EDX
                let rem_var = self.create_variable(
                    VariableOrigin::Stack(0),
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::Rem {
                    dest: rem_var,
                    left: eax,
                    right: src_var,
                    unsigned: true,
                }));
                reg_state.set(X86Register::Edx, rem_var);
                flags.set_arithmetic(quot_var, eax, src_var, ArithmeticKind::Other);
            }

            // Signed division: EDX:EAX / src
            X86Instruction::Idiv { src } => {
                let eax = Self::get_register_value(X86Register::Eax, reg_state)?;
                let src_var = self.get_operand_value(src, reg_state, &mut result, block_idx)?;
                // Quotient → EAX
                let quot_var = self.create_variable(
                    VariableOrigin::Stack(0),
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::Div {
                    dest: quot_var,
                    left: eax,
                    right: src_var,
                    unsigned: false,
                }));
                reg_state.set(X86Register::Eax, quot_var);
                // Remainder → EDX
                let rem_var = self.create_variable(
                    VariableOrigin::Stack(0),
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::Rem {
                    dest: rem_var,
                    left: eax,
                    right: src_var,
                    unsigned: false,
                }));
                reg_state.set(X86Register::Edx, rem_var);
                flags.set_arithmetic(quot_var, eax, src_var, ArithmeticKind::Other);
            }

            // Byte swap: reverse byte order using shifts and masks
            X86Instruction::Bswap { dst } => {
                let val = Self::get_register_value(*dst, reg_state)?;
                // bswap(x) = ((x >> 24) & 0xFF) | ((x >> 8) & 0xFF00)
                //          | ((x << 8) & 0xFF0000) | ((x << 24) & 0xFF000000)
                // For simplicity, emit as a chain of shift/mask/or operations
                let c8 = self.get_constant(8, &mut result, block_idx);
                let c24 = self.get_constant(24, &mut result, block_idx);
                let mask_ff = self.get_constant(0xFF, &mut result, block_idx);
                let mask_ff00 = self.get_constant(0xFF00, &mut result, block_idx);
                let mask_ff0000 = self.get_constant(0x00FF_0000, &mut result, block_idx);
                let mask_ff000000 =
                    self.get_constant(i64::from(0xFF00_0000_u32 as i32), &mut result, block_idx);

                // byte0 = (val >> 24) & 0xFF
                let shr24 = self.create_variable(
                    VariableOrigin::Stack(0),
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::Shr {
                    dest: shr24,
                    value: val,
                    amount: c24,
                    unsigned: true,
                }));
                let byte0 = self.create_variable(
                    VariableOrigin::Stack(0),
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::And {
                    dest: byte0,
                    left: shr24,
                    right: mask_ff,
                }));

                // byte1 = (val >> 8) & 0xFF00
                let shr8 = self.create_variable(
                    VariableOrigin::Stack(0),
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::Shr {
                    dest: shr8,
                    value: val,
                    amount: c8,
                    unsigned: true,
                }));
                let byte1 = self.create_variable(
                    VariableOrigin::Stack(0),
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::And {
                    dest: byte1,
                    left: shr8,
                    right: mask_ff00,
                }));

                // byte2 = (val << 8) & 0xFF0000
                let shl8 = self.create_variable(
                    VariableOrigin::Stack(0),
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::Shl {
                    dest: shl8,
                    value: val,
                    amount: c8,
                }));
                let byte2 = self.create_variable(
                    VariableOrigin::Stack(0),
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::And {
                    dest: byte2,
                    left: shl8,
                    right: mask_ff0000,
                }));

                // byte3 = (val << 24) & 0xFF000000
                let shl24 = self.create_variable(
                    VariableOrigin::Stack(0),
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::Shl {
                    dest: shl24,
                    value: val,
                    amount: c24,
                }));
                let byte3 = self.create_variable(
                    VariableOrigin::Stack(0),
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::And {
                    dest: byte3,
                    left: shl24,
                    right: mask_ff000000,
                }));

                // Combine: result = byte0 | byte1 | byte2 | byte3
                let or01 = self.create_variable(
                    VariableOrigin::Stack(0),
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::Or {
                    dest: or01,
                    left: byte0,
                    right: byte1,
                }));
                let or012 = self.create_variable(
                    VariableOrigin::Stack(0),
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::Or {
                    dest: or012,
                    left: or01,
                    right: byte2,
                }));
                let res_var = self.create_variable(
                    VariableOrigin::Stack(0),
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::Or {
                    dest: res_var,
                    left: or012,
                    right: byte3,
                }));

                reg_state.set(*dst, res_var);
                flags.clear();
            }

            // Conditional move: dst = condition ? src : dst
            X86Instruction::Cmovcc {
                condition,
                dst,
                src,
            } => {
                let src_var = self.get_operand_value(src, reg_state, &mut result, block_idx)?;
                let dst_var = Self::get_register_value(*dst, reg_state)?;

                // Evaluate condition to get a 0/1 value
                let cond_var =
                    self.evaluate_condition(*condition, flags, &mut result, block_idx)?;

                // Implement conditional move as: result = dst ^ (cond_mask & (src ^ dst))
                // where cond_mask = 0 - cond (produces 0 or 0xFFFFFFFF)
                let neg_cond = self.create_variable(
                    VariableOrigin::Stack(0),
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::Neg {
                    dest: neg_cond,
                    operand: cond_var,
                }));
                let xor_diff = self.create_variable(
                    VariableOrigin::Stack(0),
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::Xor {
                    dest: xor_diff,
                    left: src_var,
                    right: dst_var,
                }));
                let masked = self.create_variable(
                    VariableOrigin::Stack(0),
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::And {
                    dest: masked,
                    left: xor_diff,
                    right: neg_cond,
                }));
                let res_var = self.create_variable(
                    VariableOrigin::Stack(0),
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::Xor {
                    dest: res_var,
                    left: dst_var,
                    right: masked,
                }));
                reg_state.set(*dst, res_var);
                // Cmovcc doesn't modify flags
            }

            // Set byte on condition: dst = condition ? 1 : 0
            X86Instruction::Setcc { condition, dst } => {
                let cond_var =
                    self.evaluate_condition(*condition, flags, &mut result, block_idx)?;
                self.set_operand_value(dst, cond_var, reg_state, &mut result, block_idx)?;
                // Setcc doesn't modify flags
            }

            // Bit scan forward/reverse
            X86Instruction::Bsf { dst, src } | X86Instruction::Bsr { dst, src } => {
                let src_var = self.get_operand_value(src, reg_state, &mut result, block_idx)?;
                // Approximate: result is the source value (placeholder)
                reg_state.set(*dst, src_var);
                flags.clear();
            }

            // Bit test: sets CF based on the tested bit
            X86Instruction::Bt { src, bit } => {
                let src_var = self.get_operand_value(src, reg_state, &mut result, block_idx)?;
                let bit_var = self.get_operand_value(bit, reg_state, &mut result, block_idx)?;
                // BT only sets flags (specifically CF), doesn't modify operands
                flags.set_test(src_var, bit_var);
            }

            // Exchange and add: temp = dst; dst = dst + src; src = temp
            X86Instruction::Xadd { dst, src } => {
                let dst_var = self.get_operand_value(dst, reg_state, &mut result, block_idx)?;
                let src_var = self.get_operand_value(src, reg_state, &mut result, block_idx)?;
                let res_var = self.create_variable(
                    VariableOrigin::Stack(0),
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::Add {
                    dest: res_var,
                    left: dst_var,
                    right: src_var,
                }));
                self.set_operand_value(dst, res_var, reg_state, &mut result, block_idx)?;
                self.set_operand_value(src, dst_var, reg_state, &mut result, block_idx)?;
                flags.set_arithmetic(res_var, dst_var, src_var, ArithmeticKind::Add);
                // XADD sets CF like ADD: CF = (result < left) unsigned
                let cf = self.create_variable(
                    VariableOrigin::Stack(0),
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::Clt {
                    dest: cf,
                    left: res_var,
                    right: dst_var,
                    unsigned: true,
                }));
                flags.set_carry(cf);
            }

            // Bitwise
            X86Instruction::And { dst, src } => {
                let dst_var = self.get_operand_value(dst, reg_state, &mut result, block_idx)?;
                let src_var = self.get_operand_value(src, reg_state, &mut result, block_idx)?;
                let res_var = self.create_variable(
                    VariableOrigin::Stack(0),
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::And {
                    dest: res_var,
                    left: dst_var,
                    right: src_var,
                }));
                self.set_operand_value(dst, res_var, reg_state, &mut result, block_idx)?;
                flags.set_arithmetic(res_var, dst_var, src_var, ArithmeticKind::LogicalOp);
                // AND always clears CF
                let zero_cf = self.get_constant(0, &mut result, block_idx);
                flags.clear_carry(zero_cf);
            }

            X86Instruction::Or { dst, src } => {
                let dst_var = self.get_operand_value(dst, reg_state, &mut result, block_idx)?;
                let src_var = self.get_operand_value(src, reg_state, &mut result, block_idx)?;
                let res_var = self.create_variable(
                    VariableOrigin::Stack(0),
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::Or {
                    dest: res_var,
                    left: dst_var,
                    right: src_var,
                }));
                self.set_operand_value(dst, res_var, reg_state, &mut result, block_idx)?;
                flags.set_arithmetic(res_var, dst_var, src_var, ArithmeticKind::LogicalOp);
                // OR always clears CF
                let zero_cf = self.get_constant(0, &mut result, block_idx);
                flags.clear_carry(zero_cf);
            }

            X86Instruction::Xor { dst, src } => {
                let dst_var = self.get_operand_value(dst, reg_state, &mut result, block_idx)?;
                let src_var = self.get_operand_value(src, reg_state, &mut result, block_idx)?;
                let res_var = self.create_variable(
                    VariableOrigin::Stack(0),
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::Xor {
                    dest: res_var,
                    left: dst_var,
                    right: src_var,
                }));
                self.set_operand_value(dst, res_var, reg_state, &mut result, block_idx)?;
                flags.set_arithmetic(res_var, dst_var, src_var, ArithmeticKind::LogicalOp);
                // XOR always clears CF
                let zero_cf = self.get_constant(0, &mut result, block_idx);
                flags.clear_carry(zero_cf);
            }

            X86Instruction::Not { dst } => {
                let dst_var = self.get_operand_value(dst, reg_state, &mut result, block_idx)?;
                let res_var = self.create_variable(
                    VariableOrigin::Stack(0),
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::Not {
                    dest: res_var,
                    operand: dst_var,
                }));
                self.set_operand_value(dst, res_var, reg_state, &mut result, block_idx)?;
                // NOT doesn't affect flags (except in some specific cases)
            }

            X86Instruction::Shl { dst, count } => {
                let dst_var = self.get_operand_value(dst, reg_state, &mut result, block_idx)?;
                let count_var = self.get_operand_value(count, reg_state, &mut result, block_idx)?;
                let res_var = self.create_variable(
                    VariableOrigin::Stack(0),
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::Shl {
                    dest: res_var,
                    value: dst_var,
                    amount: count_var,
                }));
                self.set_operand_value(dst, res_var, reg_state, &mut result, block_idx)?;
                flags.set_arithmetic(res_var, dst_var, count_var, ArithmeticKind::Other);
            }

            X86Instruction::Shr { dst, count } => {
                let dst_var = self.get_operand_value(dst, reg_state, &mut result, block_idx)?;
                let count_var = self.get_operand_value(count, reg_state, &mut result, block_idx)?;
                let res_var = self.create_variable(
                    VariableOrigin::Stack(0),
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::Shr {
                    dest: res_var,
                    value: dst_var,
                    amount: count_var,
                    unsigned: true,
                }));
                self.set_operand_value(dst, res_var, reg_state, &mut result, block_idx)?;
                flags.set_arithmetic(res_var, dst_var, count_var, ArithmeticKind::Other);
            }

            X86Instruction::Sar { dst, count } => {
                let dst_var = self.get_operand_value(dst, reg_state, &mut result, block_idx)?;
                let count_var = self.get_operand_value(count, reg_state, &mut result, block_idx)?;
                let res_var = self.create_variable(
                    VariableOrigin::Stack(0),
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::Shr {
                    dest: res_var,
                    value: dst_var,
                    amount: count_var,
                    unsigned: false, // SAR is signed shift right
                }));
                self.set_operand_value(dst, res_var, reg_state, &mut result, block_idx)?;
                flags.set_arithmetic(res_var, dst_var, count_var, ArithmeticKind::Other);
            }

            X86Instruction::Rol { dst, count } | X86Instruction::Ror { dst, count } => {
                // Rotates are complex to express in SSA
                // For now, treat as unsupported or approximate
                let dst_var = self.get_operand_value(dst, reg_state, &mut result, block_idx)?;
                let _count_var =
                    self.get_operand_value(count, reg_state, &mut result, block_idx)?;
                // Keep the value unchanged (this is an approximation)
                self.set_operand_value(dst, dst_var, reg_state, &mut result, block_idx)?;
                flags.clear();
            }

            // Comparison
            X86Instruction::Cmp { left, right } => {
                let left_var = self.get_operand_value(left, reg_state, &mut result, block_idx)?;
                let right_var = self.get_operand_value(right, reg_state, &mut result, block_idx)?;
                flags.set_compare(left_var, right_var);
                // CMP sets CF = (left < right) unsigned (same as SUB)
                let cf = self.create_variable(
                    VariableOrigin::Stack(0),
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::Clt {
                    dest: cf,
                    left: left_var,
                    right: right_var,
                    unsigned: true,
                }));
                flags.set_carry(cf);
            }

            X86Instruction::Test { left, right } => {
                let left_var = self.get_operand_value(left, reg_state, &mut result, block_idx)?;
                let right_var = self.get_operand_value(right, reg_state, &mut result, block_idx)?;
                flags.set_test(left_var, right_var);
                // TEST always clears CF
                let zero_cf = self.get_constant(0, &mut result, block_idx);
                flags.clear_carry(zero_cf);
            }

            // Control flow
            X86Instruction::Jmp { target } => {
                let target_block = self.find_block_for_address(*target)?;
                result.push(SsaInstruction::synthetic(SsaOp::Jump {
                    target: target_block,
                }));
            }

            X86Instruction::Jcc { condition, target } => {
                let target_block = self.find_block_for_address(*target)?;
                let fallthrough_block = block_idx + 1; // Assumes sequential layout

                // Get comparison operands from flags
                if let Some((cmp, left, right, unsigned)) = flags.get_branch_operands(*condition) {
                    // Handle TEST special case
                    if matches!(
                        flags.producer(),
                        Some(crate::analysis::x86::flags::FlagProducer::Test { .. })
                    ) {
                        // For TEST + JE/JNE, we need to compare (left & right) with 0
                        let and_result = self.create_variable(
                            VariableOrigin::Stack(0),
                            DefSite::instruction(block_idx, result.len()),
                            self.func.bitness,
                        );
                        result.push(SsaInstruction::synthetic(SsaOp::And {
                            dest: and_result,
                            left,
                            right,
                        }));
                        let zero = self.get_zero_constant(&mut result, block_idx);
                        result.push(SsaInstruction::synthetic(SsaOp::BranchCmp {
                            left: and_result,
                            right: zero,
                            cmp,
                            unsigned: false,
                            true_target: target_block,
                            false_target: fallthrough_block,
                        }));
                    } else {
                        result.push(SsaInstruction::synthetic(SsaOp::BranchCmp {
                            left,
                            right,
                            cmp,
                            unsigned,
                            true_target: target_block,
                            false_target: fallthrough_block,
                        }));
                    }
                } else {
                    // Fall back to evaluate_condition for S/NS/O/NO/P/NP conditions
                    let cond_var =
                        self.evaluate_condition(*condition, flags, &mut result, block_idx)?;
                    let zero = self.get_zero_constant(&mut result, block_idx);
                    result.push(SsaInstruction::synthetic(SsaOp::BranchCmp {
                        left: cond_var,
                        right: zero,
                        cmp: CmpKind::Ne,
                        unsigned: false,
                        true_target: target_block,
                        false_target: fallthrough_block,
                    }));
                }
            }

            X86Instruction::Ret => {
                // Return the value in EAX/RAX
                let ret_reg = if self.func.bitness == 64 {
                    X86Register::Rax
                } else {
                    X86Register::Eax
                };
                let ret_val = reg_state.get(ret_reg);
                result.push(SsaInstruction::synthetic(SsaOp::Return { value: ret_val }));
            }

            X86Instruction::Call { target: _ } => {
                // Calls are not supported in DynCipher stubs
                return Err(Error::X86Error(format!(
                    "Unsupported CALL instruction at 0x{:x}",
                    decoded.offset
                )));
            }

            // Miscellaneous
            X86Instruction::Nop => {
                // No operation
            }

            X86Instruction::Cdq => {
                // Sign-extend EAX into EDX:EAX
                // In SSA, we just track that EDX becomes a function of EAX
                let eax = Self::get_register_value(X86Register::Eax, reg_state)?;
                // EDX gets sign bits of EAX (all 0s or all 1s)
                // For simplicity, create a new variable
                let edx_var = self.create_variable(
                    VariableOrigin::Stack(0),
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                // EDX = EAX >> 31 (arithmetic)
                let thirty_one = self.get_constant(31, &mut result, block_idx);
                result.push(SsaInstruction::synthetic(SsaOp::Shr {
                    dest: edx_var,
                    value: eax,
                    amount: thirty_one,
                    unsigned: false,
                }));
                reg_state.set(X86Register::Edx, edx_var);
            }

            X86Instruction::Cwde => {
                // Sign-extend AX into EAX
                // In SSA, this is effectively a no-op since we track 32-bit values
                flags.clear();
            }

            X86Instruction::Unsupported { offset, mnemonic } => {
                return Err(Error::X86Error(format!(
                    "Unsupported instruction '{mnemonic}' at 0x{offset:x}"
                )));
            }
        }

        Ok(result)
    }

    /// Gets the SSA variable for an operand value.
    fn get_operand_value(
        &mut self,
        operand: &X86Operand,
        reg_state: &RegisterState,
        instrs: &mut Vec<SsaInstruction>,
        block_idx: usize,
    ) -> Result<SsaVarId> {
        match operand {
            X86Operand::Register(reg) => Self::get_register_value(*reg, reg_state),
            X86Operand::Immediate(val) => Ok(self.get_constant(*val, instrs, block_idx)),
            X86Operand::Memory(mem) => self.load_from_memory(mem, reg_state, instrs, block_idx),
        }
    }

    /// Gets the SSA variable for a register.
    fn get_register_value(reg: X86Register, reg_state: &RegisterState) -> Result<SsaVarId> {
        reg_state
            .get(reg)
            .ok_or_else(|| Error::X86Error(format!("Register {reg:?} not defined")))
    }

    /// Sets the value of an operand.
    fn set_operand_value(
        &mut self,
        operand: &X86Operand,
        value: SsaVarId,
        reg_state: &mut RegisterState,
        instrs: &mut Vec<SsaInstruction>,
        block_idx: usize,
    ) -> Result<()> {
        match operand {
            X86Operand::Register(reg) => {
                reg_state.set(*reg, value);
                Ok(())
            }
            X86Operand::Memory(mem) => {
                self.store_to_memory(mem, value, reg_state, instrs, block_idx)
            }
            X86Operand::Immediate(_) => Err(Error::X86Error(
                "Cannot store to immediate operand".to_string(),
            )),
        }
    }

    /// Loads a value from memory.
    fn load_from_memory(
        &mut self,
        mem: &X86Memory,
        reg_state: &RegisterState,
        instrs: &mut Vec<SsaInstruction>,
        block_idx: usize,
    ) -> Result<SsaVarId> {
        let addr = self.compute_memory_address(mem, reg_state, instrs, block_idx)?;
        let result = self.create_variable(
            VariableOrigin::Stack(0),
            DefSite::instruction(block_idx, instrs.len()),
            self.func.bitness,
        );

        let value_type = match mem.size {
            1 => SsaType::I8,
            2 => SsaType::I16,
            8 => SsaType::I64,
            _ => SsaType::I32,
        };

        instrs.push(SsaInstruction::synthetic(SsaOp::LoadIndirect {
            dest: result,
            addr,
            value_type,
        }));

        Ok(result)
    }

    /// Stores a value to memory.
    fn store_to_memory(
        &mut self,
        mem: &X86Memory,
        value: SsaVarId,
        reg_state: &RegisterState,
        instrs: &mut Vec<SsaInstruction>,
        block_idx: usize,
    ) -> Result<()> {
        let addr = self.compute_memory_address(mem, reg_state, instrs, block_idx)?;

        let value_type = match mem.size {
            1 => SsaType::I8,
            2 => SsaType::I16,
            8 => SsaType::I64,
            _ => SsaType::I32,
        };

        instrs.push(SsaInstruction::synthetic(SsaOp::StoreIndirect {
            addr,
            value,
            value_type,
        }));

        Ok(())
    }

    /// Evaluates an x86 condition code into a 0/1 SSA variable.
    ///
    /// This is used by Cmovcc and Setcc to produce a value based on the
    /// current flag state. It emits the necessary comparison instructions
    /// and returns an SSA variable holding 0 (false) or 1 (true).
    fn evaluate_condition(
        &mut self,
        condition: crate::analysis::x86::types::X86Condition,
        flags: &FlagState,
        instrs: &mut Vec<SsaInstruction>,
        block_idx: usize,
    ) -> Result<SsaVarId> {
        let eval = flags.get_condition_operands(condition).ok_or_else(|| {
            Error::X86Error(format!(
                "Cannot evaluate condition {condition:?}: flags unknown or unsupported"
            ))
        })?;

        match eval {
            ConditionEval::Compare {
                cmp,
                left,
                right,
                unsigned,
            } => self.emit_comparison(cmp, left, right, unsigned, instrs, block_idx),
            ConditionEval::Test { cmp, left, right } => {
                // Compute AND first, then compare to zero
                let and_result = self.create_variable(
                    VariableOrigin::Stack(0),
                    DefSite::instruction(block_idx, instrs.len()),
                    self.func.bitness,
                );
                instrs.push(SsaInstruction::synthetic(SsaOp::And {
                    dest: and_result,
                    left,
                    right,
                }));
                let zero = self.get_zero_constant(instrs, block_idx);
                self.emit_comparison(cmp, and_result, zero, false, instrs, block_idx)
            }
            ConditionEval::ZeroTest { cmp, result } => {
                let zero = self.get_zero_constant(instrs, block_idx);
                self.emit_comparison(cmp, result, zero, false, instrs, block_idx)
            }
            ConditionEval::SignFlag { source, negated } => {
                self.emit_sign_flag(source, negated, instrs, block_idx)
            }
            ConditionEval::OverflowFlag {
                left,
                right,
                result,
                kind,
                negated,
            } => self.emit_overflow_flag(left, right, result, kind, negated, instrs, block_idx),
            ConditionEval::ParityFlag { source, negated } => {
                self.emit_parity_flag(source, negated, instrs, block_idx)
            }
        }
    }

    /// Emits a comparison SSA operation (Ceq/Clt/Cgt) and returns the result variable.
    fn emit_comparison(
        &mut self,
        cmp: crate::analysis::ssa::CmpKind,
        left: SsaVarId,
        right: SsaVarId,
        unsigned: bool,
        instrs: &mut Vec<SsaInstruction>,
        block_idx: usize,
    ) -> Result<SsaVarId> {
        use crate::analysis::ssa::CmpKind;

        let result = self.create_variable(
            VariableOrigin::Stack(0),
            DefSite::instruction(block_idx, instrs.len()),
            self.func.bitness,
        );

        match cmp {
            CmpKind::Eq => {
                instrs.push(SsaInstruction::synthetic(SsaOp::Ceq {
                    dest: result,
                    left,
                    right,
                }));
            }
            CmpKind::Ne => {
                // Ne = !Eq: compute Ceq then XOR with 1
                let eq_result = self.create_variable(
                    VariableOrigin::Stack(0),
                    DefSite::instruction(block_idx, instrs.len()),
                    self.func.bitness,
                );
                instrs.push(SsaInstruction::synthetic(SsaOp::Ceq {
                    dest: eq_result,
                    left,
                    right,
                }));
                let one = self.get_constant(1, instrs, block_idx);
                instrs.push(SsaInstruction::synthetic(SsaOp::Xor {
                    dest: result,
                    left: eq_result,
                    right: one,
                }));
            }
            CmpKind::Lt => {
                instrs.push(SsaInstruction::synthetic(SsaOp::Clt {
                    dest: result,
                    left,
                    right,
                    unsigned,
                }));
            }
            CmpKind::Gt => {
                instrs.push(SsaInstruction::synthetic(SsaOp::Cgt {
                    dest: result,
                    left,
                    right,
                    unsigned,
                }));
            }
            CmpKind::Le => {
                // Le = !Gt: compute Cgt then XOR with 1
                let gt_result = self.create_variable(
                    VariableOrigin::Stack(0),
                    DefSite::instruction(block_idx, instrs.len()),
                    self.func.bitness,
                );
                instrs.push(SsaInstruction::synthetic(SsaOp::Cgt {
                    dest: gt_result,
                    left,
                    right,
                    unsigned,
                }));
                let one = self.get_constant(1, instrs, block_idx);
                instrs.push(SsaInstruction::synthetic(SsaOp::Xor {
                    dest: result,
                    left: gt_result,
                    right: one,
                }));
            }
            CmpKind::Ge => {
                // Ge = !Lt: compute Clt then XOR with 1
                let lt_result = self.create_variable(
                    VariableOrigin::Stack(0),
                    DefSite::instruction(block_idx, instrs.len()),
                    self.func.bitness,
                );
                instrs.push(SsaInstruction::synthetic(SsaOp::Clt {
                    dest: lt_result,
                    left,
                    right,
                    unsigned,
                }));
                let one = self.get_constant(1, instrs, block_idx);
                instrs.push(SsaInstruction::synthetic(SsaOp::Xor {
                    dest: result,
                    left: lt_result,
                    right: one,
                }));
            }
        }

        Ok(result)
    }

    /// Resolves a `FlagTestSource` to an SSA variable, emitting Sub or And if needed.
    fn resolve_flag_test_source(
        &mut self,
        source: FlagTestSource,
        instrs: &mut Vec<SsaInstruction>,
        block_idx: usize,
    ) -> SsaVarId {
        match source {
            FlagTestSource::Direct(var) => var,
            FlagTestSource::Subtract { left, right } => {
                let result = self.create_variable(
                    VariableOrigin::Stack(0),
                    DefSite::instruction(block_idx, instrs.len()),
                    self.func.bitness,
                );
                instrs.push(SsaInstruction::synthetic(SsaOp::Sub {
                    dest: result,
                    left,
                    right,
                }));
                result
            }
            FlagTestSource::BitwiseAnd { left, right } => {
                let result = self.create_variable(
                    VariableOrigin::Stack(0),
                    DefSite::instruction(block_idx, instrs.len()),
                    self.func.bitness,
                );
                instrs.push(SsaInstruction::synthetic(SsaOp::And {
                    dest: result,
                    left,
                    right,
                }));
                result
            }
        }
    }

    /// Emits SSA instructions to compute the sign flag (SF) as a 0/1 value.
    ///
    /// SF = MSB of the value. Extracts it via `(value >> (bitwidth-1)) & 1`.
    fn emit_sign_flag(
        &mut self,
        source: FlagTestSource,
        negated: bool,
        instrs: &mut Vec<SsaInstruction>,
        block_idx: usize,
    ) -> Result<SsaVarId> {
        let value = self.resolve_flag_test_source(source, instrs, block_idx);
        let shift_amount = if self.func.bitness == 64 { 63 } else { 31 };
        let shift_const = self.get_constant(shift_amount, instrs, block_idx);

        // sign_shifted = value >> (bitwidth-1), unsigned shift
        let sign_shifted = self.create_variable(
            VariableOrigin::Stack(0),
            DefSite::instruction(block_idx, instrs.len()),
            self.func.bitness,
        );
        instrs.push(SsaInstruction::synthetic(SsaOp::Shr {
            dest: sign_shifted,
            value,
            amount: shift_const,
            unsigned: true,
        }));

        // sign_bit = sign_shifted & 1
        let one = self.get_constant(1, instrs, block_idx);
        let sign_bit = self.create_variable(
            VariableOrigin::Stack(0),
            DefSite::instruction(block_idx, instrs.len()),
            self.func.bitness,
        );
        instrs.push(SsaInstruction::synthetic(SsaOp::And {
            dest: sign_bit,
            left: sign_shifted,
            right: one,
        }));

        if negated {
            // NS: return !SF = sign_bit ^ 1
            let result = self.create_variable(
                VariableOrigin::Stack(0),
                DefSite::instruction(block_idx, instrs.len()),
                self.func.bitness,
            );
            let one2 = self.get_constant(1, instrs, block_idx);
            instrs.push(SsaInstruction::synthetic(SsaOp::Xor {
                dest: result,
                left: sign_bit,
                right: one2,
            }));
            Ok(result)
        } else {
            Ok(sign_bit)
        }
    }

    /// Emits SSA instructions to compute the overflow flag (OF) as a 0/1 value.
    ///
    /// The computation depends on the arithmetic operation that set the flags:
    /// - `LogicalOp`: OF is always 0 (TEST, AND, OR, XOR clear OF)
    /// - `Sub`/CMP: OF = ((left ^ right) & (left ^ result)) >> MSB
    /// - `Add`: OF = ((left ^ result) & (right ^ result)) >> MSB
    /// - `Neg`: OF = (result == INT_MIN)
    /// - `Other`: OF approximated as 0
    #[allow(clippy::too_many_arguments)]
    fn emit_overflow_flag(
        &mut self,
        left: SsaVarId,
        right: SsaVarId,
        result: Option<SsaVarId>,
        kind: ArithmeticKind,
        negated: bool,
        instrs: &mut Vec<SsaInstruction>,
        block_idx: usize,
    ) -> Result<SsaVarId> {
        let of = match kind {
            ArithmeticKind::LogicalOp | ArithmeticKind::Other => {
                // OF = 0 for logical operations and undefined/complex operations
                self.get_constant(0, instrs, block_idx)
            }
            ArithmeticKind::Sub => {
                // For CMP (result=None): compute sub_result = left - right
                // For SUB (result=Some): use existing result
                let sub_result = if let Some(r) = result {
                    r
                } else {
                    let r = self.create_variable(
                        VariableOrigin::Stack(0),
                        DefSite::instruction(block_idx, instrs.len()),
                        self.func.bitness,
                    );
                    instrs.push(SsaInstruction::synthetic(SsaOp::Sub {
                        dest: r,
                        left,
                        right,
                    }));
                    r
                };

                // OF = ((left ^ right) & (left ^ result)) >> (bitwidth-1)
                let xor_lr = self.create_variable(
                    VariableOrigin::Stack(0),
                    DefSite::instruction(block_idx, instrs.len()),
                    self.func.bitness,
                );
                instrs.push(SsaInstruction::synthetic(SsaOp::Xor {
                    dest: xor_lr,
                    left,
                    right,
                }));

                let xor_ls = self.create_variable(
                    VariableOrigin::Stack(0),
                    DefSite::instruction(block_idx, instrs.len()),
                    self.func.bitness,
                );
                instrs.push(SsaInstruction::synthetic(SsaOp::Xor {
                    dest: xor_ls,
                    left,
                    right: sub_result,
                }));

                let and_both = self.create_variable(
                    VariableOrigin::Stack(0),
                    DefSite::instruction(block_idx, instrs.len()),
                    self.func.bitness,
                );
                instrs.push(SsaInstruction::synthetic(SsaOp::And {
                    dest: and_both,
                    left: xor_lr,
                    right: xor_ls,
                }));

                let shift_amount = if self.func.bitness == 64 { 63 } else { 31 };
                let shift_const = self.get_constant(shift_amount, instrs, block_idx);
                let shifted = self.create_variable(
                    VariableOrigin::Stack(0),
                    DefSite::instruction(block_idx, instrs.len()),
                    self.func.bitness,
                );
                instrs.push(SsaInstruction::synthetic(SsaOp::Shr {
                    dest: shifted,
                    value: and_both,
                    amount: shift_const,
                    unsigned: true,
                }));

                let one = self.get_constant(1, instrs, block_idx);
                let of_bit = self.create_variable(
                    VariableOrigin::Stack(0),
                    DefSite::instruction(block_idx, instrs.len()),
                    self.func.bitness,
                );
                instrs.push(SsaInstruction::synthetic(SsaOp::And {
                    dest: of_bit,
                    left: shifted,
                    right: one,
                }));
                of_bit
            }
            ArithmeticKind::Add => {
                // OF = ((left ^ result) & (right ^ result)) >> (bitwidth-1)
                let add_result = result.unwrap_or(left); // Should always have result for Add

                let xor_lr = self.create_variable(
                    VariableOrigin::Stack(0),
                    DefSite::instruction(block_idx, instrs.len()),
                    self.func.bitness,
                );
                instrs.push(SsaInstruction::synthetic(SsaOp::Xor {
                    dest: xor_lr,
                    left,
                    right: add_result,
                }));

                let xor_rr = self.create_variable(
                    VariableOrigin::Stack(0),
                    DefSite::instruction(block_idx, instrs.len()),
                    self.func.bitness,
                );
                instrs.push(SsaInstruction::synthetic(SsaOp::Xor {
                    dest: xor_rr,
                    left: right,
                    right: add_result,
                }));

                let and_both = self.create_variable(
                    VariableOrigin::Stack(0),
                    DefSite::instruction(block_idx, instrs.len()),
                    self.func.bitness,
                );
                instrs.push(SsaInstruction::synthetic(SsaOp::And {
                    dest: and_both,
                    left: xor_lr,
                    right: xor_rr,
                }));

                let shift_amount = if self.func.bitness == 64 { 63 } else { 31 };
                let shift_const = self.get_constant(shift_amount, instrs, block_idx);
                let shifted = self.create_variable(
                    VariableOrigin::Stack(0),
                    DefSite::instruction(block_idx, instrs.len()),
                    self.func.bitness,
                );
                instrs.push(SsaInstruction::synthetic(SsaOp::Shr {
                    dest: shifted,
                    value: and_both,
                    amount: shift_const,
                    unsigned: true,
                }));

                let one = self.get_constant(1, instrs, block_idx);
                let of_bit = self.create_variable(
                    VariableOrigin::Stack(0),
                    DefSite::instruction(block_idx, instrs.len()),
                    self.func.bitness,
                );
                instrs.push(SsaInstruction::synthetic(SsaOp::And {
                    dest: of_bit,
                    left: shifted,
                    right: one,
                }));
                of_bit
            }
            ArithmeticKind::Neg => {
                // OF = (result == INT_MIN)
                let neg_result = result.unwrap_or(left);
                let int_min = if self.func.bitness == 64 {
                    self.get_constant(i64::MIN, instrs, block_idx)
                } else {
                    self.get_constant(i64::from(i32::MIN), instrs, block_idx)
                };
                let of_bit = self.create_variable(
                    VariableOrigin::Stack(0),
                    DefSite::instruction(block_idx, instrs.len()),
                    self.func.bitness,
                );
                instrs.push(SsaInstruction::synthetic(SsaOp::Ceq {
                    dest: of_bit,
                    left: neg_result,
                    right: int_min,
                }));
                of_bit
            }
        };

        if negated {
            // NO: return !OF = of ^ 1
            let result_var = self.create_variable(
                VariableOrigin::Stack(0),
                DefSite::instruction(block_idx, instrs.len()),
                self.func.bitness,
            );
            let one = self.get_constant(1, instrs, block_idx);
            instrs.push(SsaInstruction::synthetic(SsaOp::Xor {
                dest: result_var,
                left: of,
                right: one,
            }));
            Ok(result_var)
        } else {
            Ok(of)
        }
    }

    /// Emits SSA instructions to compute the parity flag (PF) as a 0/1 value.
    ///
    /// PF = 1 when the low byte of the value has even parity (even number of 1-bits).
    /// Computed by XOR-folding the low byte down to a single bit.
    fn emit_parity_flag(
        &mut self,
        source: FlagTestSource,
        negated: bool,
        instrs: &mut Vec<SsaInstruction>,
        block_idx: usize,
    ) -> Result<SsaVarId> {
        let value = self.resolve_flag_test_source(source, instrs, block_idx);

        // b = value & 0xFF (isolate low byte)
        let mask_ff = self.get_constant(0xFF, instrs, block_idx);
        let b = self.create_variable(
            VariableOrigin::Stack(0),
            DefSite::instruction(block_idx, instrs.len()),
            self.func.bitness,
        );
        instrs.push(SsaInstruction::synthetic(SsaOp::And {
            dest: b,
            left: value,
            right: mask_ff,
        }));

        // b ^= b >> 4
        let c4 = self.get_constant(4, instrs, block_idx);
        let shr4 = self.create_variable(
            VariableOrigin::Stack(0),
            DefSite::instruction(block_idx, instrs.len()),
            self.func.bitness,
        );
        instrs.push(SsaInstruction::synthetic(SsaOp::Shr {
            dest: shr4,
            value: b,
            amount: c4,
            unsigned: true,
        }));
        let b1 = self.create_variable(
            VariableOrigin::Stack(0),
            DefSite::instruction(block_idx, instrs.len()),
            self.func.bitness,
        );
        instrs.push(SsaInstruction::synthetic(SsaOp::Xor {
            dest: b1,
            left: b,
            right: shr4,
        }));

        // b ^= b >> 2
        let c2 = self.get_constant(2, instrs, block_idx);
        let shr2 = self.create_variable(
            VariableOrigin::Stack(0),
            DefSite::instruction(block_idx, instrs.len()),
            self.func.bitness,
        );
        instrs.push(SsaInstruction::synthetic(SsaOp::Shr {
            dest: shr2,
            value: b1,
            amount: c2,
            unsigned: true,
        }));
        let b2 = self.create_variable(
            VariableOrigin::Stack(0),
            DefSite::instruction(block_idx, instrs.len()),
            self.func.bitness,
        );
        instrs.push(SsaInstruction::synthetic(SsaOp::Xor {
            dest: b2,
            left: b1,
            right: shr2,
        }));

        // b ^= b >> 1
        let c1 = self.get_constant(1, instrs, block_idx);
        let shr1 = self.create_variable(
            VariableOrigin::Stack(0),
            DefSite::instruction(block_idx, instrs.len()),
            self.func.bitness,
        );
        instrs.push(SsaInstruction::synthetic(SsaOp::Shr {
            dest: shr1,
            value: b2,
            amount: c1,
            unsigned: true,
        }));
        let b3 = self.create_variable(
            VariableOrigin::Stack(0),
            DefSite::instruction(block_idx, instrs.len()),
            self.func.bitness,
        );
        instrs.push(SsaInstruction::synthetic(SsaOp::Xor {
            dest: b3,
            left: b2,
            right: shr1,
        }));

        // odd_parity = b3 & 1
        let one = self.get_constant(1, instrs, block_idx);
        let odd_parity = self.create_variable(
            VariableOrigin::Stack(0),
            DefSite::instruction(block_idx, instrs.len()),
            self.func.bitness,
        );
        instrs.push(SsaInstruction::synthetic(SsaOp::And {
            dest: odd_parity,
            left: b3,
            right: one,
        }));

        if negated {
            // NP (PF=0): return odd_parity (1 when odd number of bits)
            Ok(odd_parity)
        } else {
            // P (PF=1): return !odd_parity (1 when even number of bits)
            let result = self.create_variable(
                VariableOrigin::Stack(0),
                DefSite::instruction(block_idx, instrs.len()),
                self.func.bitness,
            );
            let one2 = self.get_constant(1, instrs, block_idx);
            instrs.push(SsaInstruction::synthetic(SsaOp::Xor {
                dest: result,
                left: odd_parity,
                right: one2,
            }));
            Ok(result)
        }
    }

    /// Computes the effective address for a memory operand.
    fn compute_memory_address(
        &mut self,
        mem: &X86Memory,
        reg_state: &RegisterState,
        instrs: &mut Vec<SsaInstruction>,
        block_idx: usize,
    ) -> Result<SsaVarId> {
        // Start with base or 0
        let mut addr = if let Some(base) = mem.base {
            Self::get_register_value(base, reg_state)?
        } else {
            self.get_zero_constant(instrs, block_idx)
        };

        // Add index * scale
        if let Some(index) = mem.index {
            let index_val = Self::get_register_value(index, reg_state)?;

            // Multiply by scale if not 1
            let scaled = if mem.scale == 1 {
                index_val
            } else {
                let scale_const = self.get_constant(i64::from(mem.scale), instrs, block_idx);
                let scaled_var = self.create_variable(
                    VariableOrigin::Stack(0),
                    DefSite::instruction(block_idx, instrs.len()),
                    self.func.bitness,
                );
                instrs.push(SsaInstruction::synthetic(SsaOp::Mul {
                    dest: scaled_var,
                    left: index_val,
                    right: scale_const,
                }));
                scaled_var
            };

            // Add to address
            let new_addr = self.create_variable(
                VariableOrigin::Stack(0),
                DefSite::instruction(block_idx, instrs.len()),
                self.func.bitness,
            );
            instrs.push(SsaInstruction::synthetic(SsaOp::Add {
                dest: new_addr,
                left: addr,
                right: scaled,
            }));
            addr = new_addr;
        }

        // Add displacement
        if mem.displacement != 0 {
            let disp_const = self.get_constant(mem.displacement, instrs, block_idx);
            let new_addr = self.create_variable(
                VariableOrigin::Stack(0),
                DefSite::instruction(block_idx, instrs.len()),
                self.func.bitness,
            );
            instrs.push(SsaInstruction::synthetic(SsaOp::Add {
                dest: new_addr,
                left: addr,
                right: disp_const,
            }));
            addr = new_addr;
        }

        Ok(addr)
    }

    /// Gets or creates an SSA variable for a constant value.
    fn get_constant(
        &mut self,
        value: i64,
        instrs: &mut Vec<SsaInstruction>,
        block_idx: usize,
    ) -> SsaVarId {
        let var = self.create_variable(
            VariableOrigin::Stack(0),
            DefSite::instruction(block_idx, instrs.len()),
            self.func.bitness,
        );

        let const_value = if self.func.bitness == 64 {
            ConstValue::I64(value)
        } else {
            // Safe: x86 32-bit constant intentionally truncated to i32
            #[allow(clippy::cast_possible_truncation)]
            let truncated = value as i32;
            ConstValue::I32(truncated)
        };

        instrs.push(SsaInstruction::synthetic(SsaOp::Const {
            dest: var,
            value: const_value,
        }));

        var
    }

    /// Gets or creates a zero constant.
    fn get_zero_constant(
        &mut self,
        instrs: &mut Vec<SsaInstruction>,
        block_idx: usize,
    ) -> SsaVarId {
        if let Some(zero) = self.zero_const {
            return zero;
        }

        let zero = self.get_constant(0, instrs, block_idx);
        self.zero_const = Some(zero);
        zero
    }

    /// Creates a new SSA variable.
    fn create_variable(
        &mut self,
        origin: VariableOrigin,
        def_site: DefSite,
        bitness: u32,
    ) -> SsaVarId {
        let var_type = if bitness == 64 {
            SsaType::I64
        } else {
            SsaType::I32
        };
        let var = SsaVariable::new_typed(origin, 0, def_site, var_type);
        let id = var.id();
        self.variables.push(var);
        id
    }

    /// Finds the block index for a given address.
    fn find_block_for_address(&self, addr: u64) -> Result<usize> {
        let offset = addr - self.func.base_address;

        for node_id in self.func.node_ids() {
            let idx = node_id.index();
            if let Some(block) = self.func.block(idx) {
                if block.start_offset == offset {
                    return Ok(idx);
                }
            }
        }

        Err(Error::X86Error(format!(
            "No block found for address 0x{addr:x}"
        )))
    }
}

/// Returns the register index defined by an instruction, if any.
fn get_defined_register(instr: &X86Instruction) -> Option<usize> {
    match instr {
        X86Instruction::Mov { dst, .. }
        | X86Instruction::Movzx { dst, .. }
        | X86Instruction::Movsx { dst, .. }
        | X86Instruction::Add { dst, .. }
        | X86Instruction::Sub { dst, .. }
        | X86Instruction::And { dst, .. }
        | X86Instruction::Or { dst, .. }
        | X86Instruction::Xor { dst, .. }
        | X86Instruction::Not { dst }
        | X86Instruction::Neg { dst }
        | X86Instruction::Inc { dst }
        | X86Instruction::Dec { dst }
        | X86Instruction::Shl { dst, .. }
        | X86Instruction::Shr { dst, .. }
        | X86Instruction::Sar { dst, .. }
        | X86Instruction::Rol { dst, .. }
        | X86Instruction::Ror { dst, .. }
        | X86Instruction::Adc { dst, .. }
        | X86Instruction::Sbb { dst, .. }
        | X86Instruction::Setcc { dst, .. }
        | X86Instruction::Xadd { dst, .. } => {
            if let X86Operand::Register(reg) = dst {
                Some(reg.base_index() as usize)
            } else {
                None
            }
        }
        X86Instruction::Lea { dst, .. }
        | X86Instruction::Imul { dst, .. }
        | X86Instruction::Bswap { dst }
        | X86Instruction::Cmovcc { dst, .. }
        | X86Instruction::Bsf { dst, .. }
        | X86Instruction::Bsr { dst, .. } => Some(dst.base_index() as usize),
        X86Instruction::Pop { dst } => Some(dst.base_index() as usize),
        X86Instruction::Mul { .. }
        | X86Instruction::Div { .. }
        | X86Instruction::Idiv { .. }
        | X86Instruction::Cdq => {
            // These define EAX/EDX
            Some(0) // EAX
        }
        X86Instruction::Xchg { dst, src } => {
            // Both operands are modified
            if let X86Operand::Register(reg) = dst {
                Some(reg.base_index() as usize)
            } else if let X86Operand::Register(reg) = src {
                Some(reg.base_index() as usize)
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Converts a register index back to a register.
fn index_to_register(index: usize, bitness: u32) -> Option<X86Register> {
    // Segment registers are the same regardless of bitness
    match index {
        16 => return Some(X86Register::Es),
        17 => return Some(X86Register::Cs),
        18 => return Some(X86Register::Ss),
        19 => return Some(X86Register::Ds),
        20 => return Some(X86Register::Fs),
        21 => return Some(X86Register::Gs),
        _ => {}
    }

    if bitness == 64 {
        match index {
            0 => Some(X86Register::Rax),
            1 => Some(X86Register::Rcx),
            2 => Some(X86Register::Rdx),
            3 => Some(X86Register::Rbx),
            4 => Some(X86Register::Rsp),
            5 => Some(X86Register::Rbp),
            6 => Some(X86Register::Rsi),
            7 => Some(X86Register::Rdi),
            8 => Some(X86Register::R8),
            9 => Some(X86Register::R9),
            10 => Some(X86Register::R10),
            11 => Some(X86Register::R11),
            12 => Some(X86Register::R12),
            13 => Some(X86Register::R13),
            14 => Some(X86Register::R14),
            15 => Some(X86Register::R15),
            _ => None,
        }
    } else {
        match index {
            0 => Some(X86Register::Eax),
            1 => Some(X86Register::Ecx),
            2 => Some(X86Register::Edx),
            3 => Some(X86Register::Ebx),
            4 => Some(X86Register::Esp),
            5 => Some(X86Register::Ebp),
            6 => Some(X86Register::Esi),
            7 => Some(X86Register::Edi),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::x86::decoder::x86_decode_all;

    #[test]
    fn test_translate_linear_code() {
        // pop eax; add eax, 5; ret
        let bytes = [0x58, 0x83, 0xc0, 0x05, 0xc3];
        let instructions = x86_decode_all(&bytes, 32, 0x1000).unwrap();
        let cfg = X86Function::new(&instructions, 32, 0x1000);

        let translator = X86ToSsaTranslator::new(&cfg);
        let ssa = translator.translate().unwrap();

        // Should have one block
        assert_eq!(ssa.block_count(), 1);

        // Should have instructions
        let block = ssa.block(0).unwrap();
        assert!(!block.instructions().is_empty());

        // Should end with return
        let last_instr = block.instructions().last().unwrap();
        assert!(matches!(last_instr.op(), SsaOp::Return { .. }));
    }

    #[test]
    fn test_translate_with_constant() {
        // mov eax, 0x12345678; ret
        let bytes = [0xb8, 0x78, 0x56, 0x34, 0x12, 0xc3];
        let instructions = x86_decode_all(&bytes, 32, 0x1000).unwrap();
        let cfg = X86Function::new(&instructions, 32, 0x1000);

        let translator = X86ToSsaTranslator::new(&cfg);
        let ssa = translator.translate().unwrap();

        assert_eq!(ssa.block_count(), 1);
    }

    #[test]
    fn test_translate_arithmetic() {
        // pop eax; xor eax, 0x1234; add eax, 5; sub eax, 2; ret
        let bytes = [
            0x58, // pop eax
            0x35, 0x34, 0x12, 0x00, 0x00, // xor eax, 0x1234
            0x83, 0xc0, 0x05, // add eax, 5
            0x83, 0xe8, 0x02, // sub eax, 2
            0xc3, // ret
        ];
        let instructions = x86_decode_all(&bytes, 32, 0x1000).unwrap();
        let cfg = X86Function::new(&instructions, 32, 0x1000);

        let translator = X86ToSsaTranslator::new(&cfg);
        let ssa = translator.translate().unwrap();

        // Should have one block with multiple operations
        let block = ssa.block(0).unwrap();
        let ops: Vec<_> = block.instructions().iter().map(|i| i.op()).collect();

        // Should have Xor, Add, Sub operations
        assert!(ops.iter().any(|op| matches!(op, SsaOp::Xor { .. })));
        assert!(ops.iter().any(|op| matches!(op, SsaOp::Add { .. })));
        assert!(ops.iter().any(|op| matches!(op, SsaOp::Sub { .. })));
    }

    #[test]
    fn test_translate_conditional() {
        // pop eax; cmp eax, 10; jl add_block; jmp skip
        // add_block: add eax, 5
        // skip: ret
        let bytes = [
            0x58, // pop eax
            0x83, 0xf8, 0x0a, // cmp eax, 10
            0x7c, 0x02, // jl +2 (to add)
            0xeb, 0x03, // jmp +3 (to ret)
            0x83, 0xc0, 0x05, // add eax, 5
            0xc3, // ret
        ];
        let instructions = x86_decode_all(&bytes, 32, 0x1000).unwrap();
        let cfg = X86Function::new(&instructions, 32, 0x1000);

        let translator = X86ToSsaTranslator::new(&cfg);
        let ssa = translator.translate().unwrap();

        // Should have multiple blocks
        assert!(ssa.block_count() > 1);

        // First block should have a BranchCmp
        let first_block = ssa.block(0).unwrap();
        let has_branch = first_block
            .instructions()
            .iter()
            .any(|i| matches!(i.op(), SsaOp::BranchCmp { .. }));
        assert!(has_branch);
    }

    #[test]
    fn test_register_state() {
        let mut state = RegisterState::new(32);

        let v1 = SsaVarId::new();
        state.set(X86Register::Eax, v1);
        assert_eq!(state.get(X86Register::Eax), Some(v1));

        // Different size registers map to same base
        assert_eq!(state.get(X86Register::Al), Some(v1));
        assert_eq!(state.get(X86Register::Ax), Some(v1));
    }

    #[test]
    fn test_empty_function() {
        let cfg = X86Function::new(&[], 32, 0);
        let translator = X86ToSsaTranslator::new(&cfg);
        let result = translator.translate();
        assert!(result.is_err());
    }

    #[test]
    fn test_translate_js_after_cmp() {
        // pop eax; cmp eax, 0; js +2; nop; nop; nop; ret
        // JS (0x78) jumps if SF=1 (result is negative)
        let bytes = [
            0x58, // pop eax
            0x83, 0xf8, 0x00, // cmp eax, 0
            0x78, 0x03, // js +3 (skip 3 nops to ret)
            0x90, // nop
            0x90, // nop
            0x90, // nop
            0xc3, // ret
        ];
        let instructions = x86_decode_all(&bytes, 32, 0x1000).unwrap();
        let cfg = X86Function::new(&instructions, 32, 0x1000);

        let translator = X86ToSsaTranslator::new(&cfg);
        let ssa = translator.translate().unwrap();

        // Should compile and produce multiple blocks with BranchCmp
        assert!(ssa.block_count() > 1);
        let first_block = ssa.block(0).unwrap();
        let has_branch = first_block
            .instructions()
            .iter()
            .any(|i| matches!(i.op(), SsaOp::BranchCmp { .. }));
        assert!(has_branch);
    }

    #[test]
    fn test_translate_jns_after_test() {
        // pop eax; test eax, eax; jns +3; nop; nop; nop; ret
        // JNS (0x79) jumps if SF=0 (non-negative)
        let bytes = [
            0x58, // pop eax
            0x85, 0xc0, // test eax, eax
            0x79, 0x03, // jns +3
            0x90, // nop
            0x90, // nop
            0x90, // nop
            0xc3, // ret
        ];
        let instructions = x86_decode_all(&bytes, 32, 0x1000).unwrap();
        let cfg = X86Function::new(&instructions, 32, 0x1000);

        let translator = X86ToSsaTranslator::new(&cfg);
        let ssa = translator.translate().unwrap();

        assert!(ssa.block_count() > 1);
        let first_block = ssa.block(0).unwrap();
        let has_branch = first_block
            .instructions()
            .iter()
            .any(|i| matches!(i.op(), SsaOp::BranchCmp { .. }));
        assert!(has_branch);
    }

    #[test]
    fn test_translate_jo_after_cmp() {
        // pop eax; cmp eax, 0x7FFFFFFF; jo +3; nop; nop; nop; ret
        // JO (0x70) jumps if OF=1 (signed overflow)
        let bytes = [
            0x58, // pop eax
            0x3d, 0xff, 0xff, 0xff, 0x7f, // cmp eax, 0x7FFFFFFF
            0x70, 0x03, // jo +3
            0x90, // nop
            0x90, // nop
            0x90, // nop
            0xc3, // ret
        ];
        let instructions = x86_decode_all(&bytes, 32, 0x1000).unwrap();
        let cfg = X86Function::new(&instructions, 32, 0x1000);

        let translator = X86ToSsaTranslator::new(&cfg);
        let ssa = translator.translate().unwrap();

        assert!(ssa.block_count() > 1);
        let first_block = ssa.block(0).unwrap();
        let has_branch = first_block
            .instructions()
            .iter()
            .any(|i| matches!(i.op(), SsaOp::BranchCmp { .. }));
        assert!(has_branch);
    }

    #[test]
    fn test_translate_jno_after_test() {
        // pop eax; test eax, eax; jno +3; nop; nop; nop; ret
        // JNO (0x71) jumps if OF=0 — always taken after TEST (TEST clears OF)
        let bytes = [
            0x58, // pop eax
            0x85, 0xc0, // test eax, eax
            0x71, 0x03, // jno +3
            0x90, // nop
            0x90, // nop
            0x90, // nop
            0xc3, // ret
        ];
        let instructions = x86_decode_all(&bytes, 32, 0x1000).unwrap();
        let cfg = X86Function::new(&instructions, 32, 0x1000);

        let translator = X86ToSsaTranslator::new(&cfg);
        let ssa = translator.translate().unwrap();

        assert!(ssa.block_count() > 1);
    }

    #[test]
    fn test_translate_jp_after_cmp() {
        // pop eax; cmp eax, 0; jp +3; nop; nop; nop; ret
        // JP (0x7A) jumps if PF=1 (even parity of low byte)
        let bytes = [
            0x58, // pop eax
            0x83, 0xf8, 0x00, // cmp eax, 0
            0x7a, 0x03, // jp +3
            0x90, // nop
            0x90, // nop
            0x90, // nop
            0xc3, // ret
        ];
        let instructions = x86_decode_all(&bytes, 32, 0x1000).unwrap();
        let cfg = X86Function::new(&instructions, 32, 0x1000);

        let translator = X86ToSsaTranslator::new(&cfg);
        let ssa = translator.translate().unwrap();

        assert!(ssa.block_count() > 1);
        let first_block = ssa.block(0).unwrap();
        let has_branch = first_block
            .instructions()
            .iter()
            .any(|i| matches!(i.op(), SsaOp::BranchCmp { .. }));
        assert!(has_branch);
    }

    #[test]
    fn test_translate_jnp_after_test() {
        // pop eax; test eax, eax; jnp +3; nop; nop; nop; ret
        // JNP (0x7B) jumps if PF=0 (odd parity)
        let bytes = [
            0x58, // pop eax
            0x85, 0xc0, // test eax, eax
            0x7b, 0x03, // jnp +3
            0x90, // nop
            0x90, // nop
            0x90, // nop
            0xc3, // ret
        ];
        let instructions = x86_decode_all(&bytes, 32, 0x1000).unwrap();
        let cfg = X86Function::new(&instructions, 32, 0x1000);

        let translator = X86ToSsaTranslator::new(&cfg);
        let ssa = translator.translate().unwrap();

        assert!(ssa.block_count() > 1);
    }

    #[test]
    fn test_translate_js_after_sub() {
        // pop eax; sub eax, 1; js +3; nop; nop; nop; ret
        // JS after SUB: jump if result is negative
        let bytes = [
            0x58, // pop eax
            0x83, 0xe8, 0x01, // sub eax, 1
            0x78, 0x03, // js +3
            0x90, // nop
            0x90, // nop
            0x90, // nop
            0xc3, // ret
        ];
        let instructions = x86_decode_all(&bytes, 32, 0x1000).unwrap();
        let cfg = X86Function::new(&instructions, 32, 0x1000);

        let translator = X86ToSsaTranslator::new(&cfg);
        let ssa = translator.translate().unwrap();

        assert!(ssa.block_count() > 1);
    }

    #[test]
    fn test_translate_jo_after_add() {
        // pop eax; add eax, 0x7FFFFFFF; jo +3; nop; nop; nop; ret
        // JO after ADD: signed overflow detection
        let bytes = [
            0x58, // pop eax
            0x05, 0xff, 0xff, 0xff, 0x7f, // add eax, 0x7FFFFFFF
            0x70, 0x03, // jo +3
            0x90, // nop
            0x90, // nop
            0x90, // nop
            0xc3, // ret
        ];
        let instructions = x86_decode_all(&bytes, 32, 0x1000).unwrap();
        let cfg = X86Function::new(&instructions, 32, 0x1000);

        let translator = X86ToSsaTranslator::new(&cfg);
        let ssa = translator.translate().unwrap();

        assert!(ssa.block_count() > 1);
    }

    #[test]
    fn test_translate_cmovs_after_cmp() {
        // pop eax; pop ecx; cmp eax, 0; cmovs eax, ecx; ret
        // CMOVS: conditional move if sign flag is set
        let bytes = [
            0x58, // pop eax
            0x59, // pop ecx
            0x83, 0xf8, 0x00, // cmp eax, 0
            0x0f, 0x48, 0xc1, // cmovs eax, ecx
            0xc3, // ret
        ];
        let instructions = x86_decode_all(&bytes, 32, 0x1000).unwrap();
        let cfg = X86Function::new(&instructions, 32, 0x1000);

        let translator = X86ToSsaTranslator::new(&cfg);
        let ssa = translator.translate().unwrap();

        // Should have one block with return
        let block = ssa.block(0).unwrap();
        let last = block.instructions().last().unwrap();
        assert!(matches!(last.op(), SsaOp::Return { .. }));
    }

    #[test]
    fn test_translate_seto_after_cmp() {
        // pop eax; cmp eax, 0x7FFFFFFF; seto al; ret
        // SETO: set byte if overflow
        let bytes = [
            0x58, // pop eax
            0x3d, 0xff, 0xff, 0xff, 0x7f, // cmp eax, 0x7FFFFFFF
            0x0f, 0x90, 0xc0, // seto al
            0xc3, // ret
        ];
        let instructions = x86_decode_all(&bytes, 32, 0x1000).unwrap();
        let cfg = X86Function::new(&instructions, 32, 0x1000);

        let translator = X86ToSsaTranslator::new(&cfg);
        let ssa = translator.translate().unwrap();

        // Should have one block with return
        let block = ssa.block(0).unwrap();
        let last = block.instructions().last().unwrap();
        assert!(matches!(last.op(), SsaOp::Return { .. }));
    }
}
