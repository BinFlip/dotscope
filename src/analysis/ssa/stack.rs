//! Stack simulator for converting CIL stack operations to SSA variables.
//!
//! CIL is a stack-based instruction set where operands are implicitly passed via
//! the evaluation stack. This module simulates the stack to convert implicit
//! stack operations into explicit SSA variable references.
//!
//! # Stack Simulation
//!
//! The simulator tracks:
//!
//! - **Stack slots**: Each stack position maps to an SSA variable
//! - **Arguments**: Method parameters tracked across versions
//! - **Locals**: Local variables tracked across versions
//! - **Address-taken variables**: Variables whose address is taken (via `ldarga`/`ldloca`)
//! - **Stack slot sources**: Tracks whether each slot value was defined in this block
//!   or inherited from block entry (placeholder)
//!
//! # Example
//!
//! Consider the CIL sequence:
//! ```text
//! ldarg.0     // Push arg0 onto stack
//! ldarg.1     // Push arg1 onto stack
//! add         // Pop two values, push sum
//! stloc.0     // Pop and store to local0
//! ```
//!
//! The simulator converts this to:
//! ```text
//! v0 = ldarg.0           // v0 is arg0
//! v1 = ldarg.1           // v1 is arg1
//! v2 = add v0, v1        // v2 = v0 + v1
//! stloc.0 v2             // local0 = v2
//! ```
//!
//! # Thread Safety
//!
//! The simulator is designed for single-threaded use during SSA construction.

use std::collections::HashMap;

use crate::analysis::ssa::{SsaVarId, VariableOrigin};

/// Tracks the source/origin of a stack slot value during simulation.
///
/// This is crucial for correct phi operand resolution in SSA construction:
/// - `Defined` values were computed by instructions in the current block
/// - `Inherited` values are placeholders from block entry (need phi resolution)
///
/// When filling phi operands, we distinguish between:
/// 1. Values actually computed in a predecessor (use them directly)
/// 2. Placeholders that flowed through unchanged (trace back to avoid self-refs)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StackSlotSource {
    /// Value was computed by an instruction in this block.
    ///
    /// The instruction index identifies which instruction defined this value.
    Defined {
        /// Index of the instruction that defined this value.
        instruction_idx: usize,
    },

    /// Value is a placeholder inherited from block entry.
    ///
    /// This happens when `reset_stack_to_depth` creates placeholder variables
    /// for values that flow into the block from predecessors. These placeholders
    /// need to be resolved to phi results or reaching definitions during rename.
    Inherited,
}

/// A stack slot with its value and source tracking.
#[derive(Debug, Clone, Copy)]
pub struct StackSlot {
    /// The SSA variable ID for this slot.
    pub var: SsaVarId,
    /// How this value was produced (defined vs inherited).
    pub source: StackSlotSource,
    /// If this value is an address (from ldloca/ldarga), what variable does it point to?
    ///
    /// This is used to track definitions through `initobj` and `stind` instructions,
    /// which write to memory through a pointer rather than directly via stloc/starg.
    pub address_target: Option<VariableOrigin>,
}

/// Result of simulating one instruction's stack effects.
///
/// Contains the SSA variables consumed (popped) and produced (pushed) by
/// the instruction, along with the variable defined (if any).
#[derive(Debug, Clone)]
pub struct SimulationResult {
    /// SSA variables popped from the stack (operands).
    /// Order: deepest stack element first.
    pub uses: Vec<SsaVarId>,

    /// SSA variable pushed to the stack (result), if any.
    pub def: Option<SsaVarId>,

    /// If this instruction writes through an address (initobj, stind),
    /// the variable origin that was written to.
    ///
    /// This is used by the converter to record indirect stores as definitions
    /// for proper phi node placement.
    pub store_target: Option<VariableOrigin>,
}

impl SimulationResult {
    /// Creates a result with no uses and no def.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            uses: Vec::new(),
            def: None,
            store_target: None,
        }
    }

    /// Creates a result with only a def (no uses).
    #[must_use]
    pub fn def_only(var: SsaVarId) -> Self {
        Self {
            uses: Vec::new(),
            def: Some(var),
            store_target: None,
        }
    }

    /// Creates a result with uses and a def.
    #[must_use]
    pub fn with_def(uses: Vec<SsaVarId>, def: SsaVarId) -> Self {
        Self {
            uses,
            def: Some(def),
            store_target: None,
        }
    }

    /// Creates a result with uses but no def.
    #[must_use]
    pub fn uses_only(uses: Vec<SsaVarId>) -> Self {
        Self {
            uses,
            def: None,
            store_target: None,
        }
    }

    /// Creates a result for an indirect store (initobj, stind).
    ///
    /// This indicates that the instruction writes to a variable through
    /// a pointer, rather than directly via stloc/starg.
    #[must_use]
    pub fn indirect_store(uses: Vec<SsaVarId>, target: VariableOrigin) -> Self {
        Self {
            uses,
            def: None,
            store_target: Some(target),
        }
    }
}

/// Information about a variable's current state during simulation.
#[derive(Debug, Clone)]
struct VariableState {
    /// Current SSA variable ID for this argument/local.
    current_var: SsaVarId,
    /// Current version number (for SSA renaming).
    version: u32,
    /// Whether this variable's address has been taken.
    address_taken: bool,
}

impl VariableState {
    fn new(initial_var: SsaVarId) -> Self {
        Self {
            current_var: initial_var,
            version: 0,
            address_taken: false,
        }
    }
}

/// Stack simulator for CIL to SSA conversion.
///
/// Tracks the evaluation stack state and converts implicit stack operations
/// into explicit SSA variable references.
///
/// # Usage
///
/// ```rust,ignore
/// use dotscope::analysis::StackSimulator;
///
/// let mut sim = StackSimulator::new(2, 3); // 2 args, 3 locals
///
/// // Simulate ldarg.0 (pushes 1)
/// let result = sim.simulate_push(VariableOrigin::Argument(0));
///
/// // Simulate add (pops 2, pushes 1)
/// let (uses, def) = sim.simulate_binary_op();
/// ```
#[derive(Debug)]
pub struct StackSimulator {
    /// The virtual evaluation stack, holding SSA variable IDs with source tracking.
    stack: Vec<StackSlot>,

    /// State for each argument variable.
    args: Vec<VariableState>,

    /// State for each local variable.
    locals: Vec<VariableState>,

    /// Counter for generating stack slot origin numbers.
    next_stack_slot: u32,

    /// Number of method arguments.
    num_args: usize,

    /// Number of local variables.
    num_locals: usize,

    /// Maps simulation variable IDs to their load origin (for ldloc/ldarg).
    ///
    /// When a variable is loaded via ldloc/ldarg, we record its origin here.
    /// During SSA rename, this allows us to resolve the variable to the
    /// correct reaching definition (phi result) instead of the stale
    /// simulation variable.
    load_origins: HashMap<SsaVarId, VariableOrigin>,

    /// Current instruction index within the block (for source tracking).
    current_instruction: usize,
}

impl StackSimulator {
    /// Creates a new stack simulator.
    ///
    /// # Arguments
    ///
    /// * `num_args` - Number of method arguments (including `this` for instance methods)
    /// * `num_locals` - Number of local variables
    #[must_use]
    pub fn new(num_args: usize, num_locals: usize) -> Self {
        let mut args = Vec::with_capacity(num_args);
        for _ in 0..num_args {
            args.push(VariableState::new(SsaVarId::new()));
        }

        let mut locals = Vec::with_capacity(num_locals);
        for _ in 0..num_locals {
            locals.push(VariableState::new(SsaVarId::new()));
        }

        Self {
            stack: Vec::with_capacity(16),
            args,
            locals,
            next_stack_slot: 0,
            num_args,
            num_locals,
            load_origins: HashMap::new(),
            current_instruction: 0,
        }
    }

    /// Sets the current instruction index for source tracking.
    ///
    /// Call this before simulating each instruction to ensure pushed values
    /// are correctly attributed to their defining instruction.
    pub fn set_instruction_index(&mut self, idx: usize) {
        self.current_instruction = idx;
    }

    /// Returns the current stack depth.
    #[must_use]
    pub fn stack_depth(&self) -> usize {
        self.stack.len()
    }

    /// Returns `true` if the stack is empty.
    #[must_use]
    pub fn is_stack_empty(&self) -> bool {
        self.stack.is_empty()
    }

    /// Initializes the stack with a given number of placeholder values.
    ///
    /// This is used when a block is entered with values already on the stack
    /// (e.g., due to `dup` before a conditional branch). Each slot gets a
    /// unique stack variable marked as `Inherited`.
    ///
    /// # Arguments
    ///
    /// * `depth` - Number of stack slots to initialize
    pub fn initialize_stack(&mut self, depth: usize) {
        self.stack.clear();
        self.current_instruction = 0;
        for _ in 0..depth {
            let (var, _origin) = self.alloc_stack_var();
            self.stack.push(StackSlot {
                var,
                source: StackSlotSource::Inherited,
                address_target: None,
            });
        }
    }

    /// Resets the stack to a specific depth for entering a new basic block.
    ///
    /// This is used when simulating multiple blocks with a shared simulator.
    /// In well-formed CIL, the stack depth at block entry is deterministic and
    /// must be consistent across all paths to that block.
    ///
    /// IMPORTANT: This method ALWAYS clears and rebuilds the stack with fresh
    /// placeholder variables marked as `Inherited`. This is necessary because
    /// blocks may not be simulated in predecessor-first order (e.g., due to
    /// RPO traversal), so the simulator's current stack state may contain stale
    /// variables from unrelated blocks. During the rename phase, these
    /// placeholders are mapped to the correct values (PHI results or reaching
    /// definitions).
    ///
    /// # Arguments
    ///
    /// * `depth` - The expected stack depth at block entry
    pub fn reset_stack_to_depth(&mut self, depth: usize) {
        // Always clear and rebuild with fresh placeholders
        // This ensures each block has its own entry stack variables that can be
        // properly mapped during the rename phase.
        self.stack.clear();
        self.current_instruction = 0;
        for _ in 0..depth {
            let (var, _origin) = self.alloc_stack_var();
            self.stack.push(StackSlot {
                var,
                source: StackSlotSource::Inherited,
                address_target: None,
            });
        }
    }

    /// Returns the number of method arguments.
    #[must_use]
    pub fn num_args(&self) -> usize {
        self.num_args
    }

    /// Returns the number of local variables.
    #[must_use]
    pub fn num_locals(&self) -> usize {
        self.num_locals
    }

    /// Returns `true` if the given argument has had its address taken.
    #[must_use]
    pub fn is_arg_address_taken(&self, index: usize) -> bool {
        self.args.get(index).is_some_and(|s| s.address_taken)
    }

    /// Returns `true` if the given local has had its address taken.
    #[must_use]
    pub fn is_local_address_taken(&self, index: usize) -> bool {
        self.locals.get(index).is_some_and(|s| s.address_taken)
    }

    /// Returns the load origins map for ldloc/ldarg simulation variables.
    ///
    /// This map records which simulation variables came from ldloc/ldarg instructions,
    /// mapping them to their respective Local(n) or Argument(n) origins.
    /// Used during SSA rename to resolve these variables to the correct reaching definition.
    #[must_use]
    pub fn load_origins(&self) -> &HashMap<SsaVarId, VariableOrigin> {
        &self.load_origins
    }

    /// Returns a snapshot of the current stack contents (variable IDs only).
    ///
    /// The returned vector contains the variables currently on the stack,
    /// from bottom to top (index 0 is bottom of stack).
    /// Used to track stack state at block exits for creating PHI nodes.
    ///
    /// For enhanced tracking with source information, use [`stack_snapshot_enhanced`].
    #[must_use]
    pub fn stack_snapshot(&self) -> Vec<SsaVarId> {
        self.stack.iter().map(|slot| slot.var).collect()
    }

    /// Returns an enhanced snapshot of the current stack with source tracking.
    ///
    /// The returned vector contains `StackSlot` values with both the variable ID
    /// and source information (Defined vs Inherited).
    ///
    /// This is used during SSA construction to properly resolve phi operands
    /// by distinguishing between values computed in this block vs placeholders.
    #[must_use]
    pub fn stack_snapshot_enhanced(&self) -> Vec<StackSlot> {
        self.stack.clone()
    }

    /// Allocates a new stack slot variable with a unique ID.
    fn alloc_stack_var(&mut self) -> (SsaVarId, VariableOrigin) {
        let var = SsaVarId::new();
        let origin = VariableOrigin::Stack(self.next_stack_slot);
        self.next_stack_slot += 1;
        (var, origin)
    }

    /// Gets the current SSA variable for an argument.
    ///
    /// Returns `None` if the index is out of bounds.
    #[must_use]
    pub fn get_arg_var(&self, index: usize) -> Option<SsaVarId> {
        self.args.get(index).map(|s| s.current_var)
    }

    /// Gets the current SSA variable for a local.
    ///
    /// Returns `None` if the index is out of bounds.
    #[must_use]
    pub fn get_local_var(&self, index: usize) -> Option<SsaVarId> {
        self.locals.get(index).map(|s| s.current_var)
    }

    /// Simulates loading an argument onto the stack (ldarg).
    ///
    /// This pushes the current SSA version of the argument onto the stack.
    /// It does NOT create a new definition - `ldarg` only reads an existing
    /// value that was defined by either the method entry or a prior `starg`.
    ///
    /// Records the load origin so that during SSA rename, the variable can be
    /// resolved to the correct reaching definition (from phi or version stack).
    ///
    /// Note: The pushed value is marked as `Defined` because the ldarg instruction
    /// is the defining point for this stack slot, even though it loads from an
    /// existing argument. This distinguishes it from inherited placeholders.
    ///
    /// # Arguments
    ///
    /// * `index` - The argument index
    ///
    /// # Returns
    ///
    /// The simulation result (no definition - just reading), or `None` if index is invalid.
    pub fn simulate_ldarg(&mut self, index: usize) -> Option<SimulationResult> {
        let var = self.get_arg_var(index)?;
        // Record that this variable should be resolved to Argument(index) during rename
        let origin = VariableOrigin::Argument(u16::try_from(index).unwrap_or(0));
        self.load_origins.insert(var, origin);
        self.stack.push(StackSlot {
            var,
            source: StackSlotSource::Defined {
                instruction_idx: self.current_instruction,
            },
            address_target: None, // ldarg loads value, not address
        });
        Some(SimulationResult::empty())
    }

    /// Simulates loading a local onto the stack (ldloc).
    ///
    /// This pushes the current SSA version of the local onto the stack.
    /// It does NOT create a new definition - `ldloc` only reads an existing
    /// value that was defined by a prior `stloc`.
    ///
    /// Records the load origin so that during SSA rename, the variable can be
    /// resolved to the correct reaching definition (from phi or version stack).
    ///
    /// Note: The pushed value is marked as `Defined` because the ldloc instruction
    /// is the defining point for this stack slot, even though it loads from an
    /// existing local. This distinguishes it from inherited placeholders.
    ///
    /// # Arguments
    ///
    /// * `index` - The local variable index
    ///
    /// # Returns
    ///
    /// The simulation result (no definition - just reading), or `None` if index is invalid.
    pub fn simulate_ldloc(&mut self, index: usize) -> Option<SimulationResult> {
        let var = self.get_local_var(index)?;
        // Record that this variable should be resolved to Local(index) during rename
        let origin = VariableOrigin::Local(u16::try_from(index).unwrap_or(0));
        self.load_origins.insert(var, origin);
        self.stack.push(StackSlot {
            var,
            source: StackSlotSource::Defined {
                instruction_idx: self.current_instruction,
            },
            address_target: None, // ldloc loads value, not address
        });
        Some(SimulationResult::empty())
    }

    /// Simulates storing to an argument (starg).
    ///
    /// Creates a new SSA version for the argument.
    ///
    /// # Arguments
    ///
    /// * `index` - The argument index
    ///
    /// # Returns
    ///
    /// The simulation result with the popped value as use and the new arg variable as def,
    /// or `None` if stack is empty or index invalid.
    pub fn simulate_starg(&mut self, index: usize) -> Option<SimulationResult> {
        let slot = self.stack.pop()?;

        if index >= self.args.len() {
            self.stack.push(slot);
            return None;
        }

        let new_var = SsaVarId::new();

        let state = &mut self.args[index];
        state.version += 1;
        state.current_var = new_var;

        // Return new_var as def to enable Copy op generation for constant propagation
        Some(SimulationResult::with_def(vec![slot.var], new_var))
    }

    /// Simulates storing to a local (stloc).
    ///
    /// Creates a new SSA version for the local.
    ///
    /// # Arguments
    ///
    /// * `index` - The local variable index
    ///
    /// # Returns
    ///
    /// The simulation result with the popped value as use and the new local variable as def,
    /// or `None` if stack is empty or index invalid.
    pub fn simulate_stloc(&mut self, index: usize) -> Option<SimulationResult> {
        let slot = self.stack.pop()?;
        if index >= self.locals.len() {
            self.stack.push(slot);
            return None;
        }

        let new_var = SsaVarId::new();
        let state = &mut self.locals[index];
        state.version += 1;
        state.current_var = new_var;

        // Return new_var as def to enable Copy op generation for constant propagation
        Some(SimulationResult::with_def(vec![slot.var], new_var))
    }

    /// Simulates loading the address of an argument (ldarga).
    ///
    /// Marks the argument as address-taken.
    ///
    /// # Arguments
    ///
    /// * `index` - The argument index
    ///
    /// # Returns
    ///
    /// The simulation result, or `None` if index is invalid.
    pub fn simulate_ldarga(&mut self, index: usize) -> Option<SimulationResult> {
        let state = self.args.get_mut(index)?;
        state.address_taken = true;

        let (var, _origin) = self.alloc_stack_var();
        // Track that this address points to an argument
        // Safe truncation: argument count is bounded by .NET limits (< 2^16)
        #[allow(clippy::cast_possible_truncation)]
        let address_target = Some(VariableOrigin::Argument(index as u16));
        self.stack.push(StackSlot {
            var,
            source: StackSlotSource::Defined {
                instruction_idx: self.current_instruction,
            },
            address_target,
        });
        Some(SimulationResult::def_only(var))
    }

    /// Simulates loading the address of a local (ldloca).
    ///
    /// Marks the local as address-taken.
    ///
    /// # Arguments
    ///
    /// * `index` - The local variable index
    ///
    /// # Returns
    ///
    /// The simulation result, or `None` if index is invalid.
    pub fn simulate_ldloca(&mut self, index: usize) -> Option<SimulationResult> {
        let state = self.locals.get_mut(index)?;
        state.address_taken = true;

        let (var, _origin) = self.alloc_stack_var();
        // Track that this address points to a local
        // Safe truncation: local count is bounded by .NET limits (< 2^16)
        #[allow(clippy::cast_possible_truncation)]
        let address_target = Some(VariableOrigin::Local(index as u16));
        self.stack.push(StackSlot {
            var,
            source: StackSlotSource::Defined {
                instruction_idx: self.current_instruction,
            },
            address_target,
        });
        Some(SimulationResult::def_only(var))
    }

    /// Simulates a generic push operation (e.g., ldc.i4, ldnull).
    ///
    /// Creates a new stack variable and pushes it, marked as `Defined`.
    ///
    /// # Returns
    ///
    /// The new variable ID and its origin.
    pub fn simulate_push(&mut self) -> (SsaVarId, VariableOrigin) {
        let (var, origin) = self.alloc_stack_var();
        self.stack.push(StackSlot {
            var,
            source: StackSlotSource::Defined {
                instruction_idx: self.current_instruction,
            },
            address_target: None,
        });
        (var, origin)
    }

    /// Simulates popping a value from the stack.
    ///
    /// # Returns
    ///
    /// The popped variable, or `None` if stack is empty.
    pub fn simulate_pop(&mut self) -> Option<SsaVarId> {
        self.stack.pop().map(|slot| slot.var)
    }

    /// Simulates popping a value from the stack and returns its address target.
    ///
    /// This is used by instructions like `initobj` and `stind` that write through
    /// a pointer. If the popped value was an address from `ldloca`/`ldarga`, the
    /// address target indicates which variable is being written to.
    ///
    /// # Returns
    ///
    /// A tuple of (variable, optional address target), or `None` if stack is empty.
    pub fn simulate_pop_with_address_target(
        &mut self,
    ) -> Option<(SsaVarId, Option<VariableOrigin>)> {
        self.stack.pop().map(|slot| (slot.var, slot.address_target))
    }

    /// Simulates popping multiple values from the stack.
    ///
    /// # Arguments
    ///
    /// * `count` - Number of values to pop
    ///
    /// # Returns
    ///
    /// A vector of popped variables (deepest first), or `None` if not enough values.
    pub fn simulate_pop_n(&mut self, count: usize) -> Option<Vec<SsaVarId>> {
        if self.stack.len() < count {
            return None;
        }

        let mut result = Vec::with_capacity(count);
        let start_idx = self.stack.len() - count;

        for i in start_idx..self.stack.len() {
            result.push(self.stack[i].var);
        }

        self.stack.truncate(start_idx);
        Some(result)
    }

    /// Simulates a binary operation (pops 2, pushes 1).
    ///
    /// Used for: add, sub, mul, div, rem, and, or, xor, shl, shr, etc.
    ///
    /// # Returns
    ///
    /// The simulation result, or `None` if stack underflow.
    pub fn simulate_binary_op(&mut self) -> Option<SimulationResult> {
        let uses = self.simulate_pop_n(2)?;
        let (def, _origin) = self.alloc_stack_var();
        self.stack.push(StackSlot {
            var: def,
            source: StackSlotSource::Defined {
                instruction_idx: self.current_instruction,
            },
            address_target: None,
        });
        Some(SimulationResult::with_def(uses, def))
    }

    /// Simulates a unary operation (pops 1, pushes 1).
    ///
    /// Used for: neg, not, conv.*, etc.
    ///
    /// # Returns
    ///
    /// The simulation result, or `None` if stack underflow.
    pub fn simulate_unary_op(&mut self) -> Option<SimulationResult> {
        let operand = self.simulate_pop()?;
        let (def, _origin) = self.alloc_stack_var();
        self.stack.push(StackSlot {
            var: def,
            source: StackSlotSource::Defined {
                instruction_idx: self.current_instruction,
            },
            address_target: None,
        });
        Some(SimulationResult::with_def(vec![operand], def))
    }

    /// Simulates a comparison operation (pops 2, pushes 1 boolean).
    ///
    /// Used for: ceq, cgt, clt, etc.
    ///
    /// # Returns
    ///
    /// The simulation result, or `None` if stack underflow.
    pub fn simulate_comparison(&mut self) -> Option<SimulationResult> {
        self.simulate_binary_op()
    }

    /// Simulates a dup instruction (duplicates top of stack).
    ///
    /// # Returns
    ///
    /// The simulation result, or `None` if stack is empty.
    pub fn simulate_dup(&mut self) -> Option<SimulationResult> {
        let top_slot = self.stack.last()?;
        let top = top_slot.var;
        // Propagate address_target through dup - if we're duplicating an address,
        // the duplicate also points to the same location
        let address_target = top_slot.address_target;
        let (new_var, _origin) = self.alloc_stack_var();
        self.stack.push(StackSlot {
            var: new_var,
            source: StackSlotSource::Defined {
                instruction_idx: self.current_instruction,
            },
            address_target,
        });
        Some(SimulationResult::with_def(vec![top], new_var))
    }

    /// Simulates an initobj instruction.
    ///
    /// `initobj` pops an address from the stack and initializes the memory
    /// location to zero/default. If the address was from `ldloca`/`ldarga`,
    /// this counts as a definition of that local/argument.
    ///
    /// # Returns
    ///
    /// The simulation result with the address as a use, and optionally
    /// the store_target indicating which variable was written to.
    pub fn simulate_initobj(&mut self) -> Option<SimulationResult> {
        let slot = self.stack.pop()?;
        let uses = vec![slot.var];

        // If this address points to a local/arg, record the store target
        if let Some(target) = slot.address_target {
            Some(SimulationResult::indirect_store(uses, target))
        } else {
            Some(SimulationResult::uses_only(uses))
        }
    }

    /// Simulates a stind (store indirect) instruction.
    ///
    /// `stind` pops a value and an address, then stores the value at the address.
    /// If the address was from `ldloca`/`ldarga`, this counts as a definition
    /// of that local/argument.
    ///
    /// # Returns
    ///
    /// The simulation result with both uses, and optionally the store_target
    /// indicating which variable was written to.
    pub fn simulate_stind(&mut self) -> Option<SimulationResult> {
        // Pop value first (top of stack)
        let value_slot = self.stack.pop()?;
        // Then pop address
        let addr_slot = self.stack.pop()?;
        let uses = vec![addr_slot.var, value_slot.var];

        // If this address points to a local/arg, record the store target
        if let Some(target) = addr_slot.address_target {
            Some(SimulationResult::indirect_store(uses, target))
        } else {
            Some(SimulationResult::uses_only(uses))
        }
    }

    /// Simulates a ret instruction.
    ///
    /// For non-void methods, pops the return value from the stack.
    /// For void methods (empty stack), returns empty uses.
    ///
    /// # Returns
    ///
    /// The simulation result with the return value (if any) as a use.
    #[must_use]
    pub fn simulate_ret(&mut self) -> SimulationResult {
        // Pop the return value if there's something on the stack
        let uses = if let Some(slot) = self.stack.pop() {
            vec![slot.var]
        } else {
            vec![]
        };

        SimulationResult {
            uses,
            def: None,
            store_target: None,
        }
    }

    /// Simulates generic stack effects based on pop/push counts.
    ///
    /// # Arguments
    ///
    /// * `pops` - Number of values to pop
    /// * `pushes` - Number of values to push
    ///
    /// # Returns
    ///
    /// The simulation result, or `None` if stack underflow.
    pub fn simulate_stack_effect(&mut self, pops: u8, pushes: u8) -> Option<SimulationResult> {
        let uses = if pops > 0 {
            self.simulate_pop_n(pops as usize)?
        } else {
            Vec::new()
        };

        let def = if pushes > 0 {
            let (var, _origin) = self.alloc_stack_var();
            self.stack.push(StackSlot {
                var,
                source: StackSlotSource::Defined {
                    instruction_idx: self.current_instruction,
                },
                address_target: None,
            });

            for _ in 1..pushes {
                let (extra_var, _) = self.alloc_stack_var();
                self.stack.push(StackSlot {
                    var: extra_var,
                    source: StackSlotSource::Defined {
                        instruction_idx: self.current_instruction,
                    },
                    address_target: None,
                });
            }

            Some(var)
        } else {
            None
        };

        Some(SimulationResult {
            uses,
            def,
            store_target: None,
        })
    }

    /// Clears the stack (e.g., at block boundaries or after control flow).
    pub fn clear_stack(&mut self) {
        self.stack.clear();
    }

    /// Simulates a `leave` or `leave.s` instruction.
    ///
    /// The leave instruction:
    /// 1. Clears the evaluation stack
    /// 2. Transfers control to a target outside the protected region
    ///
    /// This is used in structured exception handling to exit try blocks.
    pub fn simulate_leave(&mut self) -> SimulationResult {
        // Collect all variables currently on the stack as "uses" before clearing
        let uses: Vec<SsaVarId> = self.stack.iter().map(|slot| slot.var).collect();
        self.stack.clear();
        SimulationResult::uses_only(uses)
    }

    /// Sets the stack state from a vector of variables.
    ///
    /// Used for restoring state at block entry during SSA construction.
    /// All values are marked as `Inherited` since they come from outside this block.
    pub fn set_stack(&mut self, stack: Vec<SsaVarId>) {
        self.stack = stack
            .into_iter()
            .map(|var| StackSlot {
                var,
                source: StackSlotSource::Inherited,
                address_target: None,
            })
            .collect();
    }

    /// Sets the stack state from a vector of enhanced slots.
    ///
    /// Used when restoring state with preserved source information.
    pub fn set_stack_enhanced(&mut self, stack: Vec<StackSlot>) {
        self.stack = stack;
    }

    /// Updates the current variable for an argument (used during SSA renaming).
    ///
    /// # Arguments
    ///
    /// * `index` - The argument index
    /// * `var` - The new SSA variable ID
    ///
    /// # Returns
    ///
    /// `true` if successful, `false` if index is invalid.
    pub fn set_arg_var(&mut self, index: usize, var: SsaVarId) -> bool {
        if let Some(state) = self.args.get_mut(index) {
            state.current_var = var;
            true
        } else {
            false
        }
    }

    /// Updates the current variable for a local (used during SSA renaming).
    ///
    /// # Arguments
    ///
    /// * `index` - The local variable index
    /// * `var` - The new SSA variable ID
    ///
    /// # Returns
    ///
    /// `true` if successful, `false` if index is invalid.
    pub fn set_local_var(&mut self, index: usize, var: SsaVarId) -> bool {
        if let Some(state) = self.locals.get_mut(index) {
            state.current_var = var;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simulator_creation() {
        let sim = StackSimulator::new(2, 3);
        assert_eq!(sim.num_args(), 2);
        assert_eq!(sim.num_locals(), 3);
        assert!(sim.is_stack_empty());
        assert_eq!(sim.stack_depth(), 0);
    }

    #[test]
    fn test_initial_arg_vars() {
        let sim = StackSimulator::new(3, 0);
        // Args should exist and be distinct
        let arg0 = sim.get_arg_var(0);
        let arg1 = sim.get_arg_var(1);
        let arg2 = sim.get_arg_var(2);
        assert!(arg0.is_some());
        assert!(arg1.is_some());
        assert!(arg2.is_some());
        assert_ne!(arg0, arg1);
        assert_ne!(arg1, arg2);
        assert_ne!(arg0, arg2);
        assert_eq!(sim.get_arg_var(3), None);
    }

    #[test]
    fn test_initial_local_vars() {
        let sim = StackSimulator::new(2, 3);
        // Locals should exist and be distinct from args
        let arg0 = sim.get_arg_var(0).unwrap();
        let arg1 = sim.get_arg_var(1).unwrap();
        let loc0 = sim.get_local_var(0).unwrap();
        let loc1 = sim.get_local_var(1).unwrap();
        let loc2 = sim.get_local_var(2).unwrap();
        // All variables should be distinct
        let all_vars = [arg0, arg1, loc0, loc1, loc2];
        for i in 0..all_vars.len() {
            for j in (i + 1)..all_vars.len() {
                assert_ne!(
                    all_vars[i], all_vars[j],
                    "Variables at {} and {} should be distinct",
                    i, j
                );
            }
        }
        assert_eq!(sim.get_local_var(3), None);
    }

    #[test]
    fn test_simulate_ldarg() {
        let mut sim = StackSimulator::new(2, 0);

        let result = sim.simulate_ldarg(0).unwrap();
        assert!(result.uses.is_empty());
        assert_eq!(result.def, None); // No definition - just reading existing arg
        assert_eq!(sim.stack_depth(), 1);

        let result = sim.simulate_ldarg(1).unwrap();
        assert_eq!(result.def, None); // No definition - just reading existing arg
        assert_eq!(sim.stack_depth(), 2);
    }

    #[test]
    fn test_simulate_ldloc() {
        let mut sim = StackSimulator::new(1, 2);

        let result = sim.simulate_ldloc(0).unwrap();
        assert!(result.uses.is_empty());
        assert_eq!(result.def, None); // No definition - just reading existing local
        assert_eq!(sim.stack_depth(), 1);
    }

    #[test]
    fn test_simulate_starg() {
        let mut sim = StackSimulator::new(2, 0);
        let arg0 = sim.get_arg_var(0).unwrap();
        let initial_arg1 = sim.get_arg_var(1).unwrap();

        // Push a value first
        sim.simulate_ldarg(0);
        assert_eq!(sim.stack_depth(), 1);

        // Store to arg1
        let result = sim.simulate_starg(1).unwrap();
        assert_eq!(result.uses.len(), 1);
        assert_eq!(result.uses[0], arg0); // The value we pushed
        assert_eq!(sim.stack_depth(), 0);

        // arg1 should now have a new variable
        let new_var = sim.get_arg_var(1).unwrap();
        assert_ne!(new_var, initial_arg1); // Should be different from initial

        // def should be the new variable (for Copy op generation)
        assert_eq!(result.def, Some(new_var));
    }

    #[test]
    fn test_simulate_stloc() {
        let mut sim = StackSimulator::new(1, 1);
        let arg0 = sim.get_arg_var(0).unwrap();
        let initial_local0 = sim.get_local_var(0).unwrap();

        // Push a value first (ldarg.0)
        sim.simulate_ldarg(0);

        // Store to local0
        let result = sim.simulate_stloc(0).unwrap();
        assert_eq!(result.uses.len(), 1);
        assert_eq!(result.uses[0], arg0);

        // local0 should now have a new variable
        let new_var = sim.get_local_var(0).unwrap();
        assert_ne!(new_var, initial_local0); // Different from initial local0

        // def should be the new variable (for Copy op generation)
        assert_eq!(result.def, Some(new_var));
    }

    #[test]
    fn test_simulate_binary_op() {
        let mut sim = StackSimulator::new(2, 0);
        let arg0 = sim.get_arg_var(0).unwrap();
        let arg1 = sim.get_arg_var(1).unwrap();

        // ldarg.0, ldarg.1
        sim.simulate_ldarg(0);
        sim.simulate_ldarg(1);
        assert_eq!(sim.stack_depth(), 2);

        // add
        let result = sim.simulate_binary_op().unwrap();
        assert_eq!(result.uses.len(), 2);
        assert_eq!(result.uses[0], arg0); // Deepest first
        assert_eq!(result.uses[1], arg1);
        assert!(result.def.is_some());
        assert_eq!(sim.stack_depth(), 1);
    }

    #[test]
    fn test_simulate_unary_op() {
        let mut sim = StackSimulator::new(1, 0);
        let arg0 = sim.get_arg_var(0).unwrap();

        sim.simulate_ldarg(0);
        assert_eq!(sim.stack_depth(), 1);

        let result = sim.simulate_unary_op().unwrap();
        assert_eq!(result.uses.len(), 1);
        assert_eq!(result.uses[0], arg0);
        assert!(result.def.is_some());
        assert_eq!(sim.stack_depth(), 1);
    }

    #[test]
    fn test_simulate_dup() {
        let mut sim = StackSimulator::new(1, 0);

        sim.simulate_ldarg(0);
        assert_eq!(sim.stack_depth(), 1);

        let result = sim.simulate_dup().unwrap();
        assert_eq!(result.uses.len(), 1);
        assert!(result.def.is_some());
        assert_eq!(sim.stack_depth(), 2);
    }

    #[test]
    fn test_simulate_pop_n() {
        let mut sim = StackSimulator::new(3, 0);
        let arg1 = sim.get_arg_var(1).unwrap();
        let arg2 = sim.get_arg_var(2).unwrap();

        sim.simulate_ldarg(0);
        sim.simulate_ldarg(1);
        sim.simulate_ldarg(2);
        assert_eq!(sim.stack_depth(), 3);

        // Pop 2
        let popped = sim.simulate_pop_n(2).unwrap();
        assert_eq!(popped.len(), 2);
        assert_eq!(popped[0], arg1); // Deepest of the 2
        assert_eq!(popped[1], arg2); // Top
        assert_eq!(sim.stack_depth(), 1);
    }

    #[test]
    fn test_simulate_pop_n_underflow() {
        let mut sim = StackSimulator::new(1, 0);

        sim.simulate_ldarg(0);

        // Try to pop more than available
        assert!(sim.simulate_pop_n(2).is_none());
        assert_eq!(sim.stack_depth(), 1); // Stack unchanged
    }

    #[test]
    fn test_simulate_ldarga() {
        let mut sim = StackSimulator::new(2, 0);

        assert!(!sim.is_arg_address_taken(0));

        let result = sim.simulate_ldarga(0).unwrap();
        assert!(result.uses.is_empty());
        assert!(result.def.is_some());
        assert_eq!(sim.stack_depth(), 1);
        assert!(sim.is_arg_address_taken(0));
        assert!(!sim.is_arg_address_taken(1));
    }

    #[test]
    fn test_simulate_ldloca() {
        let mut sim = StackSimulator::new(0, 2);

        assert!(!sim.is_local_address_taken(0));

        let result = sim.simulate_ldloca(0).unwrap();
        assert!(result.uses.is_empty());
        assert!(result.def.is_some());
        assert_eq!(sim.stack_depth(), 1);
        assert!(sim.is_local_address_taken(0));
        assert!(!sim.is_local_address_taken(1));
    }

    #[test]
    fn test_simulate_stack_effect() {
        let mut sim = StackSimulator::new(3, 0);

        // Push 3 values
        sim.simulate_ldarg(0);
        sim.simulate_ldarg(1);
        sim.simulate_ldarg(2);
        assert_eq!(sim.stack_depth(), 3);

        // Simulate instruction that pops 2, pushes 1
        let result = sim.simulate_stack_effect(2, 1).unwrap();
        assert_eq!(result.uses.len(), 2);
        assert!(result.def.is_some());
        assert_eq!(sim.stack_depth(), 2);

        // Simulate instruction that pops 1, pushes 0
        let result = sim.simulate_stack_effect(1, 0).unwrap();
        assert_eq!(result.uses.len(), 1);
        assert!(result.def.is_none());
        assert_eq!(sim.stack_depth(), 1);
    }

    #[test]
    fn test_stack_snapshot_and_restore() {
        let mut sim = StackSimulator::new(2, 0);

        sim.simulate_ldarg(0);
        sim.simulate_ldarg(1);

        let snapshot = sim.stack_snapshot();
        assert_eq!(snapshot.len(), 2);

        sim.clear_stack();
        assert!(sim.is_stack_empty());

        sim.set_stack(snapshot.clone());
        assert_eq!(sim.stack_depth(), 2);
        assert_eq!(sim.stack_snapshot(), snapshot);
    }

    #[test]
    fn test_set_arg_var() {
        let mut sim = StackSimulator::new(2, 0);

        let v = SsaVarId::new();
        assert!(sim.set_arg_var(0, v));
        assert_eq!(sim.get_arg_var(0), Some(v));

        assert!(!sim.set_arg_var(5, v)); // Invalid index
    }

    #[test]
    fn test_set_local_var() {
        let mut sim = StackSimulator::new(0, 2);

        let v = SsaVarId::new();
        assert!(sim.set_local_var(0, v));
        assert_eq!(sim.get_local_var(0), Some(v));

        assert!(!sim.set_local_var(5, v)); // Invalid index
    }

    #[test]
    fn test_simulation_result_constructors() {
        let empty = SimulationResult::empty();
        assert!(empty.uses.is_empty());
        assert!(empty.def.is_none());

        let v5 = SsaVarId::new();
        let def_only = SimulationResult::def_only(v5);
        assert!(def_only.uses.is_empty());
        assert_eq!(def_only.def, Some(v5));

        let v1 = SsaVarId::new();
        let v2 = SsaVarId::new();
        let uses_only = SimulationResult::uses_only(vec![v1, v2]);
        assert_eq!(uses_only.uses.len(), 2);
        assert!(uses_only.def.is_none());

        let u1 = SsaVarId::new();
        let u2 = SsaVarId::new();
        let v3 = SsaVarId::new();
        let with_def = SimulationResult::with_def(vec![u1, u2], v3);
        assert_eq!(with_def.uses.len(), 2);
        assert_eq!(with_def.def, Some(v3));
    }

    #[test]
    fn test_complex_sequence() {
        // Simulate: local0 = arg0 + arg1
        let mut sim = StackSimulator::new(2, 1);
        let arg0 = sim.get_arg_var(0).unwrap();
        let arg1 = sim.get_arg_var(1).unwrap();

        // ldarg.0 - just pushes existing arg0 onto stack, no new definition
        let r1 = sim.simulate_ldarg(0).unwrap();
        assert_eq!(r1.def, None); // ldarg is not a definition

        // ldarg.1 - just pushes existing arg1 onto stack, no new definition
        let r2 = sim.simulate_ldarg(1).unwrap();
        assert_eq!(r2.def, None); // ldarg is not a definition

        // add - pops two values, creates new definition for the result
        let r3 = sim.simulate_binary_op().unwrap();
        assert_eq!(r3.uses, vec![arg0, arg1]);
        let add_result = r3.def.unwrap();

        // stloc.0 - pops result, creates new SSA version for local0
        let r4 = sim.simulate_stloc(0).unwrap();
        assert_eq!(r4.uses, vec![add_result]);

        assert!(sim.is_stack_empty());
    }
}
