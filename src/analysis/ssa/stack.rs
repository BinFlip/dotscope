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

use crate::analysis::ssa::{SsaVarId, VariableOrigin};

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
}

impl SimulationResult {
    /// Creates a result with no uses and no def.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            uses: Vec::new(),
            def: None,
        }
    }

    /// Creates a result with only a def (no uses).
    #[must_use]
    pub fn def_only(var: SsaVarId) -> Self {
        Self {
            uses: Vec::new(),
            def: Some(var),
        }
    }

    /// Creates a result with uses and a def.
    #[must_use]
    pub fn with_def(uses: Vec<SsaVarId>, def: SsaVarId) -> Self {
        Self {
            uses,
            def: Some(def),
        }
    }

    /// Creates a result with uses but no def.
    #[must_use]
    pub fn uses_only(uses: Vec<SsaVarId>) -> Self {
        Self { uses, def: None }
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
/// use dotscope::analysis::ssa::StackSimulator;
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
    /// The virtual evaluation stack, holding SSA variable IDs.
    stack: Vec<SsaVarId>,

    /// State for each argument variable.
    args: Vec<VariableState>,

    /// State for each local variable.
    locals: Vec<VariableState>,

    /// Counter for generating new stack slot variable IDs.
    /// Starts after args and locals are allocated.
    next_stack_slot: u32,

    /// Next SSA variable ID to allocate.
    next_var_id: usize,

    /// Number of method arguments.
    num_args: usize,

    /// Number of local variables.
    num_locals: usize,
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
        Self::with_var_offset(num_args, num_locals, num_args + num_locals)
    }

    /// Creates a new stack simulator with a specific starting variable ID.
    ///
    /// This is used when simulating multiple blocks to ensure unique
    /// variable IDs across the entire function.
    ///
    /// # Arguments
    ///
    /// * `num_args` - Number of method arguments (including `this` for instance methods)
    /// * `num_locals` - Number of local variables
    /// * `next_var_id` - The next variable ID to allocate (should be >= num_args + num_locals)
    #[must_use]
    pub fn with_var_offset(num_args: usize, num_locals: usize, next_var_id: usize) -> Self {
        let mut args = Vec::with_capacity(num_args);
        for i in 0..num_args {
            args.push(VariableState::new(SsaVarId::new(i)));
        }

        let mut locals = Vec::with_capacity(num_locals);
        for i in 0..num_locals {
            locals.push(VariableState::new(SsaVarId::new(num_args + i)));
        }

        Self {
            stack: Vec::with_capacity(16),
            args,
            locals,
            next_stack_slot: 0,
            next_var_id,
            num_args,
            num_locals,
        }
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
    /// unique stack variable.
    ///
    /// # Arguments
    ///
    /// * `depth` - Number of stack slots to initialize
    pub fn initialize_stack(&mut self, depth: usize) {
        self.stack.clear();
        for _ in 0..depth {
            let (var, _origin) = self.alloc_stack_var();
            self.stack.push(var);
        }
    }

    /// Resets the stack to a specific depth for entering a new basic block.
    ///
    /// This is used when simulating multiple blocks with a shared simulator.
    /// In well-formed CIL, the stack depth at block entry is deterministic and
    /// must be consistent across all paths to that block. This method adjusts
    /// the stack to match the expected entry depth:
    /// - If current depth > target: truncate the stack
    /// - If current depth < target: add placeholder variables
    ///
    /// # Arguments
    ///
    /// * `depth` - The expected stack depth at block entry
    pub fn reset_stack_to_depth(&mut self, depth: usize) {
        let current = self.stack.len();
        if current > depth {
            // Truncate to target depth
            self.stack.truncate(depth);
        } else if current < depth {
            // Add placeholder variables for missing slots
            for _ in current..depth {
                let (var, _origin) = self.alloc_stack_var();
                self.stack.push(var);
            }
        }
        // If current == depth, nothing to do
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

    /// Returns the total number of SSA variables allocated so far.
    #[must_use]
    pub fn variable_count(&self) -> usize {
        self.next_var_id
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

    /// Allocates a new SSA variable ID.
    fn alloc_var(&mut self) -> SsaVarId {
        let id = SsaVarId::new(self.next_var_id);
        self.next_var_id += 1;
        id
    }

    /// Allocates a new stack slot variable.
    fn alloc_stack_var(&mut self) -> (SsaVarId, VariableOrigin) {
        let var = self.alloc_var();
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
    /// # Arguments
    ///
    /// * `index` - The argument index
    ///
    /// # Returns
    ///
    /// The simulation result with the loaded variable, or `None` if index is invalid.
    pub fn simulate_ldarg(&mut self, index: usize) -> Option<SimulationResult> {
        let var = self.get_arg_var(index)?;
        self.stack.push(var);
        Some(SimulationResult::def_only(var))
    }

    /// Simulates loading a local onto the stack (ldloc).
    ///
    /// # Arguments
    ///
    /// * `index` - The local variable index
    ///
    /// # Returns
    ///
    /// The simulation result with the loaded variable, or `None` if index is invalid.
    pub fn simulate_ldloc(&mut self, index: usize) -> Option<SimulationResult> {
        let var = self.get_local_var(index)?;
        self.stack.push(var);
        Some(SimulationResult::def_only(var))
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
        let value = self.stack.pop()?;

        if index >= self.args.len() {
            self.stack.push(value);
            return None;
        }

        let new_var = self.alloc_var();

        let state = &mut self.args[index];
        state.version += 1;
        state.current_var = new_var;

        // Return new_var as def to enable Copy op generation for constant propagation
        Some(SimulationResult::with_def(vec![value], new_var))
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
        let value = self.stack.pop()?;
        if index >= self.locals.len() {
            self.stack.push(value);
            return None;
        }

        let new_var = self.alloc_var();
        let state = &mut self.locals[index];
        state.version += 1;
        state.current_var = new_var;

        // Return new_var as def to enable Copy op generation for constant propagation
        Some(SimulationResult::with_def(vec![value], new_var))
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
        self.stack.push(var);
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
        self.stack.push(var);
        Some(SimulationResult::def_only(var))
    }

    /// Simulates a generic push operation (e.g., ldc.i4, ldnull).
    ///
    /// Creates a new stack variable and pushes it.
    ///
    /// # Returns
    ///
    /// The new variable ID and its origin.
    pub fn simulate_push(&mut self) -> (SsaVarId, VariableOrigin) {
        let (var, origin) = self.alloc_stack_var();
        self.stack.push(var);
        (var, origin)
    }

    /// Simulates popping a value from the stack.
    ///
    /// # Returns
    ///
    /// The popped variable, or `None` if stack is empty.
    pub fn simulate_pop(&mut self) -> Option<SsaVarId> {
        self.stack.pop()
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
            result.push(self.stack[i]);
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
        self.stack.push(def);
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
        self.stack.push(def);
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
        let top = *self.stack.last()?;
        let (new_var, _origin) = self.alloc_stack_var();
        self.stack.push(new_var);
        Some(SimulationResult::with_def(vec![top], new_var))
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
        let uses = if let Some(ret_val) = self.stack.pop() {
            vec![ret_val]
        } else {
            vec![]
        };

        SimulationResult { uses, def: None }
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
            self.stack.push(var);

            for _ in 1..pushes {
                let (extra_var, _) = self.alloc_stack_var();
                self.stack.push(extra_var);
            }

            Some(var)
        } else {
            None
        };

        Some(SimulationResult { uses, def })
    }

    /// Clears the stack (e.g., at block boundaries or after control flow).
    pub fn clear_stack(&mut self) {
        self.stack.clear();
    }

    /// Sets the stack state from a vector of variables.
    ///
    /// Used for restoring state at block entry during SSA construction.
    pub fn set_stack(&mut self, stack: Vec<SsaVarId>) {
        self.stack = stack;
    }

    /// Returns a snapshot of the current stack state.
    #[must_use]
    pub fn stack_snapshot(&self) -> Vec<SsaVarId> {
        self.stack.clone()
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
        // Initial vars: 2 args + 3 locals = 5
        assert_eq!(sim.variable_count(), 5);
    }

    #[test]
    fn test_initial_arg_vars() {
        let sim = StackSimulator::new(3, 0);
        // Args should be v0, v1, v2
        assert_eq!(sim.get_arg_var(0), Some(SsaVarId::new(0)));
        assert_eq!(sim.get_arg_var(1), Some(SsaVarId::new(1)));
        assert_eq!(sim.get_arg_var(2), Some(SsaVarId::new(2)));
        assert_eq!(sim.get_arg_var(3), None);
    }

    #[test]
    fn test_initial_local_vars() {
        let sim = StackSimulator::new(2, 3);
        // Locals should be v2, v3, v4 (after 2 args)
        assert_eq!(sim.get_local_var(0), Some(SsaVarId::new(2)));
        assert_eq!(sim.get_local_var(1), Some(SsaVarId::new(3)));
        assert_eq!(sim.get_local_var(2), Some(SsaVarId::new(4)));
        assert_eq!(sim.get_local_var(3), None);
    }

    #[test]
    fn test_simulate_ldarg() {
        let mut sim = StackSimulator::new(2, 0);

        let result = sim.simulate_ldarg(0).unwrap();
        assert!(result.uses.is_empty());
        assert_eq!(result.def, Some(SsaVarId::new(0)));
        assert_eq!(sim.stack_depth(), 1);

        let result = sim.simulate_ldarg(1).unwrap();
        assert_eq!(result.def, Some(SsaVarId::new(1)));
        assert_eq!(sim.stack_depth(), 2);
    }

    #[test]
    fn test_simulate_ldloc() {
        let mut sim = StackSimulator::new(1, 2);

        let result = sim.simulate_ldloc(0).unwrap();
        assert!(result.uses.is_empty());
        assert_eq!(result.def, Some(SsaVarId::new(1))); // local0 = v1 (after 1 arg)
        assert_eq!(sim.stack_depth(), 1);
    }

    #[test]
    fn test_simulate_starg() {
        let mut sim = StackSimulator::new(2, 0);

        // Push a value first
        sim.simulate_ldarg(0);
        assert_eq!(sim.stack_depth(), 1);

        // Store to arg1
        let result = sim.simulate_starg(1).unwrap();
        assert_eq!(result.uses.len(), 1);
        assert_eq!(result.uses[0], SsaVarId::new(0)); // The value we pushed
        assert_eq!(sim.stack_depth(), 0);

        // arg1 should now have a new variable
        let new_var = sim.get_arg_var(1).unwrap();
        assert_ne!(new_var, SsaVarId::new(1)); // Should be different from initial

        // def should be the new variable (for Copy op generation)
        assert_eq!(result.def, Some(new_var));
    }

    #[test]
    fn test_simulate_stloc() {
        let mut sim = StackSimulator::new(1, 1);

        // Push a value first (ldarg.0)
        sim.simulate_ldarg(0);

        // Store to local0
        let result = sim.simulate_stloc(0).unwrap();
        assert_eq!(result.uses.len(), 1);
        assert_eq!(result.uses[0], SsaVarId::new(0)); // arg0

        // local0 should now have a new variable
        let new_var = sim.get_local_var(0).unwrap();
        assert_ne!(new_var, SsaVarId::new(1)); // Different from initial local0

        // def should be the new variable (for Copy op generation)
        assert_eq!(result.def, Some(new_var));
    }

    #[test]
    fn test_simulate_binary_op() {
        let mut sim = StackSimulator::new(2, 0);

        // ldarg.0, ldarg.1
        sim.simulate_ldarg(0);
        sim.simulate_ldarg(1);
        assert_eq!(sim.stack_depth(), 2);

        // add
        let result = sim.simulate_binary_op().unwrap();
        assert_eq!(result.uses.len(), 2);
        assert_eq!(result.uses[0], SsaVarId::new(0)); // Deepest first
        assert_eq!(result.uses[1], SsaVarId::new(1));
        assert!(result.def.is_some());
        assert_eq!(sim.stack_depth(), 1);
    }

    #[test]
    fn test_simulate_unary_op() {
        let mut sim = StackSimulator::new(1, 0);

        sim.simulate_ldarg(0);
        assert_eq!(sim.stack_depth(), 1);

        let result = sim.simulate_unary_op().unwrap();
        assert_eq!(result.uses.len(), 1);
        assert_eq!(result.uses[0], SsaVarId::new(0));
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

        sim.simulate_ldarg(0);
        sim.simulate_ldarg(1);
        sim.simulate_ldarg(2);
        assert_eq!(sim.stack_depth(), 3);

        // Pop 2
        let popped = sim.simulate_pop_n(2).unwrap();
        assert_eq!(popped.len(), 2);
        assert_eq!(popped[0], SsaVarId::new(1)); // Deepest of the 2
        assert_eq!(popped[1], SsaVarId::new(2)); // Top
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

        assert!(sim.set_arg_var(0, SsaVarId::new(100)));
        assert_eq!(sim.get_arg_var(0), Some(SsaVarId::new(100)));

        assert!(!sim.set_arg_var(5, SsaVarId::new(100))); // Invalid index
    }

    #[test]
    fn test_set_local_var() {
        let mut sim = StackSimulator::new(0, 2);

        assert!(sim.set_local_var(0, SsaVarId::new(100)));
        assert_eq!(sim.get_local_var(0), Some(SsaVarId::new(100)));

        assert!(!sim.set_local_var(5, SsaVarId::new(100))); // Invalid index
    }

    #[test]
    fn test_simulation_result_constructors() {
        let empty = SimulationResult::empty();
        assert!(empty.uses.is_empty());
        assert!(empty.def.is_none());

        let def_only = SimulationResult::def_only(SsaVarId::new(5));
        assert!(def_only.uses.is_empty());
        assert_eq!(def_only.def, Some(SsaVarId::new(5)));

        let uses_only = SimulationResult::uses_only(vec![SsaVarId::new(1), SsaVarId::new(2)]);
        assert_eq!(uses_only.uses.len(), 2);
        assert!(uses_only.def.is_none());

        let with_def =
            SimulationResult::with_def(vec![SsaVarId::new(1), SsaVarId::new(2)], SsaVarId::new(3));
        assert_eq!(with_def.uses.len(), 2);
        assert_eq!(with_def.def, Some(SsaVarId::new(3)));
    }

    #[test]
    fn test_complex_sequence() {
        // Simulate: local0 = arg0 + arg1
        let mut sim = StackSimulator::new(2, 1);

        // ldarg.0
        let r1 = sim.simulate_ldarg(0).unwrap();
        assert_eq!(r1.def, Some(SsaVarId::new(0)));

        // ldarg.1
        let r2 = sim.simulate_ldarg(1).unwrap();
        assert_eq!(r2.def, Some(SsaVarId::new(1)));

        // add
        let r3 = sim.simulate_binary_op().unwrap();
        assert_eq!(r3.uses, vec![SsaVarId::new(0), SsaVarId::new(1)]);
        let add_result = r3.def.unwrap();

        // stloc.0
        let r4 = sim.simulate_stloc(0).unwrap();
        assert_eq!(r4.uses, vec![add_result]);

        assert!(sim.is_stack_empty());
    }
}
