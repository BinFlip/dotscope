//! Read-only query methods for SSA functions.
//!
//! These methods analyze SSA functions without modifying them, providing
//! information about variables, control flow, return behavior, and purity.

use std::collections::BTreeMap;

use crate::{
    analysis::ssa::{
        ConstValue, PhiNode, SsaBlock, SsaFunction, SsaInstruction, SsaOp, SsaVarId, SsaVariable,
        VariableOrigin,
    },
    utils::BitSet,
};

/// What a method returns.
#[derive(Debug, Clone, PartialEq)]
pub enum ReturnInfo {
    /// Always returns this constant.
    Constant(ConstValue),

    /// Returns parameter N unchanged (pass-through).
    PassThrough(usize),

    /// Returns a pure computation of parameters (potentially foldable if params are known).
    PureComputation,

    /// Has varying return value (depends on state, input, etc.).
    Dynamic,

    /// Void method (no return value).
    Void,

    /// Return behavior is unknown.
    Unknown,
}

impl ReturnInfo {
    /// Checks if the return value is known at compile time.
    ///
    /// # Returns
    ///
    /// `true` if the return value is a constant or void.
    #[must_use]
    pub fn is_known(&self) -> bool {
        matches!(self, Self::Constant(_) | Self::Void)
    }

    /// Checks if the return value might be foldable with known inputs.
    ///
    /// # Returns
    ///
    /// `true` if the return could be computed at compile time given known inputs.
    #[must_use]
    pub fn is_potentially_foldable(&self) -> bool {
        matches!(
            self,
            Self::Constant(_) | Self::PassThrough(_) | Self::PureComputation
        )
    }
}

/// Purity classification of a method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MethodPurity {
    /// Method has no side effects - safe to inline, eliminate, or reorder.
    Pure,

    /// Method only reads fields but doesn't modify state.
    ReadOnly,

    /// Method modifies local state only (fields of `this` object).
    LocalMutation,

    /// Method has global side effects (I/O, static fields, exceptions, etc.).
    Impure,

    /// Purity is unknown (calls external methods, uses reflection, etc.).
    Unknown,
}

impl MethodPurity {
    /// Checks if the method can be safely eliminated if its result is unused.
    ///
    /// # Returns
    ///
    /// `true` if the method has no observable side effects.
    #[must_use]
    pub fn can_eliminate_if_unused(&self) -> bool {
        matches!(self, Self::Pure | Self::ReadOnly)
    }

    /// Checks if the method can be safely inlined.
    ///
    /// Pure and ReadOnly methods can always be inlined. LocalMutation can
    /// be inlined but requires care with the `this` reference.
    ///
    /// # Returns
    ///
    /// `true` if the method is safe to inline.
    #[must_use]
    pub fn can_inline(&self) -> bool {
        // Pure and ReadOnly methods can always be inlined
        // LocalMutation can be inlined but requires care with `this`
        matches!(self, Self::Pure | Self::ReadOnly | Self::LocalMutation)
    }

    /// Checks if calls to this method can be safely reordered.
    ///
    /// # Returns
    ///
    /// `true` if calls to this method can be reordered with respect to other calls.
    #[must_use]
    pub fn can_reorder(&self) -> bool {
        matches!(self, Self::Pure)
    }
}

impl SsaFunction {
    /// Returns an iterator over argument variables (version 0).
    ///
    /// These are the initial SSA versions of arguments at method entry.
    /// Uses the version registry for O(1) lookup per argument.
    ///
    /// # Returns
    ///
    /// An iterator over argument variables with version 0.
    pub fn argument_variables(&self) -> impl Iterator<Item = &SsaVariable> {
        (0..self.num_args() as u16).filter_map(|idx| {
            let origin = VariableOrigin::Argument(idx);
            self.versions_of(origin)
                .first()
                .and_then(|&id| self.variable(id))
                .filter(|v| v.version() == 0)
        })
    }

    /// Returns an iterator over local variables (version 0).
    ///
    /// These are the initial SSA versions of locals at method entry.
    /// Uses the version registry for O(1) lookup per local.
    ///
    /// # Returns
    ///
    /// An iterator over local variables with version 0.
    pub fn local_variables(&self) -> impl Iterator<Item = &SsaVariable> {
        (0..self.num_locals() as u16).filter_map(|idx| {
            let origin = VariableOrigin::Local(idx);
            self.versions_of(origin)
                .first()
                .and_then(|&id| self.variable(id))
                .filter(|v| v.version() == 0)
        })
    }

    /// Finds all variables originating from a specific argument.
    ///
    /// Uses the version registry for O(1) lookup.
    ///
    /// # Arguments
    ///
    /// * `arg_index` - The argument index to filter by
    ///
    /// # Returns
    ///
    /// An iterator over all SSA versions of the specified argument.
    pub fn variables_from_argument(&self, arg_index: u16) -> impl Iterator<Item = &SsaVariable> {
        let origin = VariableOrigin::Argument(arg_index);
        self.versions_of(origin)
            .iter()
            .filter_map(|&id| self.variable(id))
    }

    /// Finds all variables originating from a specific local.
    ///
    /// Uses the version registry for O(1) lookup.
    ///
    /// # Arguments
    ///
    /// * `local_index` - The local variable index to filter by
    ///
    /// # Returns
    ///
    /// An iterator over all SSA versions of the specified local variable.
    pub fn variables_from_local(&self, local_index: u16) -> impl Iterator<Item = &SsaVariable> {
        let origin = VariableOrigin::Local(local_index);
        self.versions_of(origin)
            .iter()
            .filter_map(|&id| self.variable(id))
    }

    /// Returns the total number of phi nodes across all blocks.
    ///
    /// # Returns
    ///
    /// The sum of phi node counts in all blocks.
    pub fn phi_count(&self) -> usize {
        self.blocks().iter().map(SsaBlock::phi_count).sum()
    }

    /// Returns the total number of instructions across all blocks.
    ///
    /// # Returns
    ///
    /// The sum of instruction counts in all blocks.
    pub fn instruction_count(&self) -> usize {
        self.blocks().iter().map(SsaBlock::instruction_count).sum()
    }

    /// Returns an iterator over all phi nodes in the function.
    ///
    /// # Returns
    ///
    /// An iterator yielding references to all [`PhiNode`]s across all blocks.
    pub fn all_phi_nodes(&self) -> impl Iterator<Item = &PhiNode> {
        self.blocks().iter().flat_map(SsaBlock::phi_nodes)
    }

    /// Returns an iterator over all instructions in the function.
    ///
    /// # Returns
    ///
    /// An iterator yielding references to all [`SsaInstruction`]s across all blocks.
    pub fn all_instructions(&self) -> impl Iterator<Item = &SsaInstruction> {
        self.blocks().iter().flat_map(SsaBlock::instructions)
    }

    /// Finds dead variables (variables with no uses).
    ///
    /// # Returns
    ///
    /// An iterator over variables that have no uses recorded.
    pub fn dead_variables(&self) -> impl Iterator<Item = &SsaVariable> {
        self.variables().iter().filter(|v| v.is_dead())
    }

    /// Counts dead variables.
    ///
    /// # Returns
    ///
    /// The number of variables with no uses.
    #[must_use]
    pub fn dead_variable_count(&self) -> usize {
        self.variables().iter().filter(|v| v.is_dead()).count()
    }

    /// Checks if a parameter at the given index is used in the function.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn is_parameter_used(&self, param_index: usize) -> bool {
        // Parameter indices > u16::MAX are not possible in practice
        self.variables_from_argument(param_index as u16)
            .any(|v| v.use_count() > 0)
    }

    /// Returns the use count for a parameter.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn parameter_use_count(&self, param_index: usize) -> usize {
        // Parameter indices > u16::MAX are not possible in practice
        self.variables_from_argument(param_index as u16)
            .map(SsaVariable::use_count)
            .sum()
    }

    /// Checks if the function has any XOR operations.
    #[must_use]
    pub fn has_xor_operations(&self) -> bool {
        self.all_instructions()
            .any(|instr| matches!(instr.op(), SsaOp::Xor { .. }))
    }

    /// Checks if the function has any array element access operations.
    #[must_use]
    pub fn has_array_element_access(&self) -> bool {
        self.all_instructions().any(|instr| {
            matches!(
                instr.op(),
                SsaOp::LoadElement { .. } | SsaOp::StoreElement { .. }
            )
        })
    }

    /// Checks if the function has any field store operations.
    #[must_use]
    pub fn has_field_stores(&self) -> bool {
        self.all_instructions().any(|instr| {
            matches!(
                instr.op(),
                SsaOp::StoreField { .. } | SsaOp::StoreStaticField { .. }
            )
        })
    }

    /// Checks if the function accesses any static fields.
    #[must_use]
    pub fn has_static_field_access(&self) -> bool {
        self.all_instructions().any(|instr| {
            matches!(
                instr.op(),
                SsaOp::LoadStaticField { .. }
                    | SsaOp::StoreStaticField { .. }
                    | SsaOp::LoadStaticFieldAddr { .. }
            )
        })
    }

    /// Checks if the function has any field load operations.
    #[must_use]
    pub fn has_field_loads(&self) -> bool {
        self.all_instructions().any(|instr| {
            matches!(
                instr.op(),
                SsaOp::LoadField { .. } | SsaOp::LoadStaticField { .. }
            )
        })
    }

    /// Returns the target count of the largest switch in the function, if any.
    #[must_use]
    pub fn largest_switch_target_count(&self) -> Option<usize> {
        self.all_instructions()
            .filter_map(|instr| {
                if let SsaOp::Switch { targets, .. } = instr.op() {
                    Some(targets.len())
                } else {
                    None
                }
            })
            .max()
    }

    /// Checks if the function returns void (no return value).
    #[must_use]
    pub fn is_void_return(&self) -> bool {
        self.all_instructions()
            .any(|instr| matches!(instr.op(), SsaOp::Return { value: None }))
    }

    /// Gets the instruction operation that defines a variable.
    ///
    /// Searches through all blocks and instructions to find where the given
    /// variable is defined (appears as a destination).
    ///
    /// **Note**: This only returns definitions from instructions, not phi nodes.
    /// For phi node definitions, use [`find_phi_defining()`](Self::find_phi_defining).
    ///
    /// # Arguments
    ///
    /// * `var` - The SSA variable to look up.
    ///
    /// # Returns
    ///
    /// The defining `SsaOp` if found in an instruction, or `None` if the variable
    /// is defined by a phi node or not found.
    #[must_use]
    pub fn get_definition(&self, var: SsaVarId) -> Option<&SsaOp> {
        // Fast path: O(1) via the variable's DefSite
        if let Some(variable) = self.variable(var) {
            let def = variable.def_site();
            if let Some(instr_idx) = def.instruction {
                if let Some(block) = self.block(def.block) {
                    if let Some(instr) = block.instructions().get(instr_idx) {
                        let op = instr.op();
                        if op.dest() == Some(var) {
                            return Some(op);
                        }
                    }
                }
            }
        }

        // Slow path: O(n) scan (DefSite may be stale after transforms or from builder)
        for block in self.blocks() {
            for instr in block.instructions() {
                let op = instr.op();
                if op.dest() == Some(var) {
                    return Some(op);
                }
            }
        }
        None
    }

    /// Gets the instruction that defines a variable.
    ///
    /// Like [`get_definition()`](Self::get_definition) but returns the full
    /// `SsaInstruction` instead of just the `SsaOp`. This is needed by codegen
    /// to access `instr.result_type()`.
    ///
    /// # Arguments
    ///
    /// * `var` - The SSA variable to look up.
    ///
    /// # Returns
    ///
    /// The defining `SsaInstruction` if found, or `None` if the variable
    /// is defined by a phi node or not found.
    #[must_use]
    pub fn get_definition_instruction(&self, var: SsaVarId) -> Option<&SsaInstruction> {
        // Fast path: O(1) via the variable's DefSite
        if let Some(variable) = self.variable(var) {
            let def = variable.def_site();
            if let Some(instr_idx) = def.instruction {
                if let Some(block) = self.block(def.block) {
                    if let Some(instr) = block.instructions().get(instr_idx) {
                        let op = instr.op();
                        if op.dest() == Some(var) {
                            return Some(instr);
                        }
                    }
                }
            }
        }

        // Slow path: O(n) scan (DefSite may be stale after transforms or from builder)
        for block in self.blocks() {
            for instr in block.instructions() {
                if instr.op().dest() == Some(var) {
                    return Some(instr);
                }
            }
        }
        None
    }

    /// Checks whether replacing `result` with `source` in all uses would
    /// create a self-referential instruction (i.e., `source = f(..., source, ...)`).
    ///
    /// This happens when `source` is defined by an instruction that uses `result`.
    /// In such cases, eliminating a trivial phi `result = phi(source, result)` by
    /// replacing `result → source` would create a self-referential cycle.
    ///
    /// # Arguments
    ///
    /// * `source` - The variable that would become the replacement.
    /// * `result` - The variable being replaced (e.g., a trivial phi result).
    ///
    /// # Returns
    ///
    /// `true` if the replacement would create a self-referential instruction.
    #[must_use]
    pub fn would_create_self_reference(&self, source: SsaVarId, result: SsaVarId) -> bool {
        self.get_definition(source)
            .is_some_and(|op| op.uses().contains(&result))
    }

    /// Like [`would_create_self_reference`](Self::would_create_self_reference), but only
    /// considers definitions in reachable blocks. Definitions in unreachable blocks will
    /// be cleared by DCE, so they don't create real self-referential cycles.
    ///
    /// # Arguments
    ///
    /// * `source` - The variable that would become the replacement.
    /// * `result` - The variable being replaced.
    /// * `var_def_block` - Map from variable to the block that defines it.
    /// * `reachable` - Set of reachable block indices.
    #[must_use]
    pub fn would_create_self_reference_reachable(
        &self,
        source: SsaVarId,
        result: SsaVarId,
        var_def_block: &BTreeMap<SsaVarId, usize>,
        reachable: &BitSet,
    ) -> bool {
        if let Some(&def_block) = var_def_block.get(&source) {
            if reachable.contains(def_block) {
                return self.would_create_self_reference(source, result);
            }
        }
        false
    }

    /// Checks if a variable is defined by a constant instruction.
    ///
    /// This is useful for analysis passes that need to identify compile-time
    /// constant values vs. runtime-computed values.
    ///
    /// # Arguments
    ///
    /// * `var` - The SSA variable to check.
    ///
    /// # Returns
    ///
    /// `true` if the variable is defined by a `Const` instruction.
    #[must_use]
    pub fn is_var_constant(&self, var: SsaVarId) -> bool {
        self.get_definition(var)
            .is_some_and(|op| matches!(op, SsaOp::Const { .. }))
    }

    /// Gets the constant value if a variable is defined by a constant instruction.
    ///
    /// # Arguments
    ///
    /// * `var` - The SSA variable to check.
    ///
    /// # Returns
    ///
    /// The constant value if the variable is defined by a `Const` instruction,
    /// `None` otherwise.
    #[must_use]
    pub fn get_var_constant(&self, var: SsaVarId) -> Option<&ConstValue> {
        match self.get_definition(var) {
            Some(SsaOp::Const { value, .. }) => Some(value),
            _ => None,
        }
    }

    /// Returns the constant value of a variable if it was defined by a `Const` operation.
    ///
    /// Uses the variable's [`DefSite`] for O(1) lookup without a fallback scan.
    /// Returns `None` for phi-defined variables or non-constant definitions.
    ///
    /// # Arguments
    ///
    /// * `var` - The SSA variable to check.
    ///
    /// # Returns
    ///
    /// The constant value if the variable is defined by a `Const` instruction,
    /// `None` otherwise.
    #[must_use]
    pub fn try_constant_value(&self, var: SsaVarId) -> Option<ConstValue> {
        let variable = self.variable(var)?;
        let def_site = variable.def_site();

        if def_site.is_phi() {
            return None;
        }

        let block = self.block(def_site.block)?;
        let instr = block.instruction(def_site.instruction?)?;

        match instr.op() {
            SsaOp::Const { value, .. } => Some(value.clone()),
            _ => None,
        }
    }

    /// Finds the PHI node that defines a variable.
    ///
    /// Uses O(1) lookup via the variable's definition site when available,
    /// falling back to O(n) scan across all blocks otherwise.
    ///
    /// # Arguments
    ///
    /// * `var` - The SSA variable ID to find the defining PHI for.
    ///
    /// # Returns
    ///
    /// `Some((block_idx, &PhiNode))` if the variable is defined by a PHI node,
    /// `None` if the variable is not defined by a PHI or doesn't exist.
    #[must_use]
    pub fn find_phi_defining(&self, var: SsaVarId) -> Option<(usize, &PhiNode)> {
        // Try O(1) lookup via the variable's definition site
        if let Some(variable) = self.variable(var) {
            let def_site = variable.def_site();
            if def_site.is_phi() {
                // Variable is defined by a phi - look in that block
                if let Some(block) = self.block(def_site.block) {
                    for phi in block.phi_nodes() {
                        if phi.result() == var {
                            return Some((def_site.block, phi));
                        }
                    }
                }
            }
            // Variable exists but is not defined by a phi
            return None;
        }

        // Fallback: O(n) scan if variable not defined by a phi in its block
        for (block_idx, block) in self.iter_blocks() {
            for phi in block.phi_nodes() {
                if phi.result() == var {
                    return Some((block_idx, phi));
                }
            }
        }

        None
    }

    /// Traces a variable backward through arithmetic operations to find a PHI source.
    ///
    /// This is useful for control flow unflattening where a switch variable may be
    /// computed from a state PHI through operations like `(state ^ key) % N`.
    ///
    /// The tracing follows these operations backward:
    /// - `Rem` (remainder): traces the left operand
    /// - `Xor`: tries both operands (XOR is commutative)
    /// - `And` (bitwise AND): traces the left operand
    /// - `Shr`/`Shl` (shifts): traces the value operand
    /// - `Copy`: traces the source
    ///
    /// # Arguments
    ///
    /// * `var` - The variable to trace backward from.
    /// * `target_block` - Optional block where the PHI should be defined.
    ///
    /// # Returns
    ///
    /// The PHI variable that is the ultimate source, or `None` if no PHI is found.
    #[must_use]
    pub fn trace_to_phi(&self, var: SsaVarId, target_block: Option<usize>) -> Option<SsaVarId> {
        self.trace_to_phi_impl(var, target_block, 0)
    }

    /// Internal implementation with depth limit to prevent infinite recursion.
    fn trace_to_phi_impl(
        &self,
        var: SsaVarId,
        target_block: Option<usize>,
        depth: usize,
    ) -> Option<SsaVarId> {
        // Prevent infinite recursion
        const MAX_DEPTH: usize = 20;
        if depth > MAX_DEPTH {
            return None;
        }

        // First check if this variable is directly defined by a phi node
        if let Some((phi_block, phi)) = self.find_phi_defining(var) {
            // If target_block specified, check if phi is in that block
            if target_block.is_none_or(|target| phi_block == target) {
                return Some(phi.result());
            }
            // If not in target block, still return it as a valid PHI
            return Some(phi.result());
        }

        // Get the definition of var
        let def = self.get_definition(var)?;

        match def {
            // If it's a phi node defined as instruction, use its dest
            SsaOp::Phi { dest, .. } => Some(*dest),

            // Remainder (state % N) or bitwise AND (state & mask): trace left operand
            SsaOp::Rem { left, .. } | SsaOp::And { left, .. } => {
                self.trace_to_phi_impl(*left, target_block, depth + 1)
            }

            // XOR operation (e.g., state ^ key): try both operands
            SsaOp::Xor { left, right, .. } => {
                // Try left first
                if let Some(phi) = self.trace_to_phi_impl(*left, target_block, depth + 1) {
                    return Some(phi);
                }
                // Then try right (XOR is commutative)
                self.trace_to_phi_impl(*right, target_block, depth + 1)
            }

            // Arithmetic operations (ConfuserEx uses mul/add/sub for state transformation)
            // e.g., new_state = (state * 529374418) ^ key
            SsaOp::Mul { left, right, .. }
            | SsaOp::Add { left, right, .. }
            | SsaOp::Sub { left, right, .. } => {
                // Try left first (usually where the state variable is)
                if let Some(phi) = self.trace_to_phi_impl(*left, target_block, depth + 1) {
                    return Some(phi);
                }
                // Then try right
                self.trace_to_phi_impl(*right, target_block, depth + 1)
            }

            // Shift operations: trace the value operand
            SsaOp::Shr { value, .. } | SsaOp::Shl { value, .. } => {
                self.trace_to_phi_impl(*value, target_block, depth + 1)
            }

            // Copy: trace through to source
            SsaOp::Copy { src, .. } => self.trace_to_phi_impl(*src, target_block, depth + 1),

            // For other operations (including constants), the variable cannot be traced to a PHI
            _ => None,
        }
    }

    /// Checks if a block has a specific successor in the control flow graph.
    ///
    /// This checks if control can flow from block `from_block` to block `to_block`
    /// through any terminator instruction (Jump, Branch, Switch, etc.).
    ///
    /// # Arguments
    ///
    /// * `from_block` - The source block index.
    /// * `to_block` - The target block index to check for.
    ///
    /// # Returns
    ///
    /// `true` if `to_block` is a successor of `from_block`.
    #[must_use]
    pub fn block_has_successor(&self, from_block: usize, to_block: usize) -> bool {
        let Some(block) = self.block(from_block) else {
            return false;
        };
        let Some(op) = block.terminator_op() else {
            return false;
        };

        op.successors().contains(&to_block)
    }

    /// Gets all predecessor blocks that can jump to the given block.
    ///
    /// This scans all blocks and returns those whose terminator instruction
    /// has `block_idx` as a successor.
    ///
    /// # Arguments
    ///
    /// * `block_idx` - The target block index.
    ///
    /// # Returns
    ///
    /// A vector of block indices that can transfer control to `block_idx`.
    #[must_use]
    pub fn block_predecessors(&self, block_idx: usize) -> Vec<usize> {
        let mut preds: Vec<usize> = self
            .iter_blocks()
            .filter(|&(idx, _)| idx != block_idx)
            .filter_map(|(idx, block)| {
                block
                    .terminator_op()
                    .filter(|op| op.successors().contains(&block_idx))
                    .map(|_| idx)
            })
            .collect();

        // Include synthetic exception handler edges: try_start -> handler_start.
        // This matches SsaCfg::from_ssa() which also adds these edges so that
        // handler blocks appear connected in the CFG.
        for handler in self.exception_handlers() {
            if handler.handler_start_block == Some(block_idx) {
                if let Some(try_start) = handler.try_start_block {
                    if try_start < self.blocks.len() && !preds.contains(&try_start) {
                        preds.push(try_start);
                    }
                }
            }
        }

        preds
    }

    /// Gets all successor blocks that a given block can jump to.
    ///
    /// # Arguments
    ///
    /// * `block_idx` - The source block index.
    ///
    /// # Returns
    ///
    /// A vector of block indices that `block_idx` can transfer control to.
    #[must_use]
    pub fn block_successors(&self, block_idx: usize) -> Vec<usize> {
        let Some(block) = self.block(block_idx) else {
            return Vec::new();
        };
        let Some(op) = block.terminator_op() else {
            return Vec::new();
        };

        let mut succs = op.successors();

        // Include synthetic exception handler edges: try_start -> handler_start.
        // This matches SsaCfg::from_ssa() which also adds these edges so that
        // handler blocks appear connected in the CFG.
        for handler in self.exception_handlers() {
            if handler.try_start_block == Some(block_idx) {
                if let Some(handler_start) = handler.handler_start_block {
                    if handler_start < self.blocks.len() && !succs.contains(&handler_start) {
                        succs.push(handler_start);
                    }
                }
            }
        }

        succs
    }

    /// Checks if one block can reach another through the CFG.
    ///
    /// Uses a simple BFS to determine reachability.
    ///
    /// # Arguments
    ///
    /// * `from` - The source block index.
    /// * `to` - The target block index.
    /// * `successor_map` - Precomputed successor map for efficiency.
    ///
    /// # Returns
    ///
    /// `true` if there is a path from `from` to `to`, `false` otherwise.
    fn block_reaches(from: usize, to: usize, successor_map: &BTreeMap<usize, Vec<usize>>) -> bool {
        if from == to {
            return true;
        }

        // Determine block count from successor map keys
        let block_count = successor_map.keys().copied().max().map_or(0, |m| m + 1);
        let block_count = block_count.max(from + 1).max(to + 1);
        let mut visited = BitSet::new(block_count);
        let mut worklist = vec![from];

        while let Some(block_idx) = worklist.pop() {
            if block_idx == to {
                return true;
            }
            if block_idx >= block_count || !visited.insert(block_idx) {
                continue;
            }
            if let Some(succs) = successor_map.get(&block_idx) {
                worklist.extend(succs.iter().copied());
            }
        }

        false
    }

    /// Checks if a variable is a parameter variable.
    ///
    /// In SSA form, parameters are typically mapped to specific variable ranges
    /// at the function entry. This method checks if the given variable ID
    /// corresponds to a parameter.
    ///
    /// # Arguments
    ///
    /// * `var` - The SSA variable to check.
    ///
    /// # Returns
    ///
    /// The parameter index if this is a parameter variable, `None` otherwise.
    #[must_use]
    pub fn is_parameter_variable(&self, var: SsaVarId) -> Option<usize> {
        let variable_count = self.var_id_capacity();
        self.is_parameter_variable_impl(var, &mut BitSet::new(variable_count), variable_count)
    }

    /// Internal implementation with visited set to prevent infinite recursion on cycles.
    fn is_parameter_variable_impl(
        &self,
        var: SsaVarId,
        visited: &mut BitSet,
        variable_count: usize,
    ) -> Option<usize> {
        // Prevent infinite recursion on cycles
        let idx = var.index();
        if idx >= variable_count || !visited.insert(idx) {
            return None;
        }

        // Parameters are typically assigned at function entry to the first N variables
        // where N is the parameter count. The exact mapping depends on SSA construction.

        // Check if this variable's definition is from a parameter load
        // or if it's in the initial argument range
        let idx = var.index();
        if idx < self.num_args() {
            return Some(idx);
        }

        // Also check if defined by argument loading
        for block in self.blocks() {
            for instr in block.instructions() {
                let op = instr.op();
                if op.dest() == Some(var) {
                    // Check if this is loading from an argument
                    if let SsaOp::Const { .. } = op {
                        // Not a parameter
                        return None;
                    }
                    // Check for patterns like copy from parameter variable
                    if let SsaOp::Copy { src, .. } = op {
                        // Recursively check if source is a parameter
                        return self.is_parameter_variable_impl(*src, visited, variable_count);
                    }
                }
            }
        }

        None
    }

    /// Counts how many times each variable is used across all blocks.
    ///
    /// This scans all phi node operands and instruction operands to build
    /// a map of variable use counts. This is useful for optimization passes
    /// that need to know whether a variable has multiple uses (e.g., for
    /// deciding whether to inline an expression).
    ///
    /// # Returns
    ///
    /// A map from each used variable ID to its use count.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let use_counts = ssa.count_uses();
    /// if use_counts.get(&var_id).copied().unwrap_or(0) == 1 {
    ///     // Variable has single use - safe to inline
    /// }
    /// ```
    #[must_use]
    pub fn count_uses(&self) -> BTreeMap<SsaVarId, usize> {
        let mut counts = BTreeMap::new();

        for block in self.blocks() {
            // Count phi node operands
            for phi in block.phi_nodes() {
                for operand in phi.operands() {
                    *counts.entry(operand.value()).or_insert(0) += 1;
                }
            }

            // Count instruction operands
            for instr in block.instructions() {
                for var in instr.op().uses() {
                    *counts.entry(var).or_insert(0) += 1;
                }
            }
        }

        counts
    }

    /// Finds all trampoline blocks in this SSA function.
    ///
    /// A trampoline block is one that has no phi nodes and contains only a single
    /// unconditional control transfer (`Jump` or `Leave`). These blocks can be
    /// bypassed by redirecting predecessors directly to their targets.
    ///
    /// # Arguments
    ///
    /// * `skip_entry` - If true, skips block 0 (entry block).
    ///
    /// # Returns
    ///
    /// A map from trampoline block index to its target block index.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let trampolines = ssa.find_trampoline_blocks(true);
    /// for (trampoline_idx, target_idx) in trampolines {
    ///     // trampoline_idx jumps unconditionally to target_idx
    /// }
    /// ```
    #[must_use]
    pub fn find_trampoline_blocks(&self, skip_entry: bool) -> BTreeMap<usize, usize> {
        self.iter_blocks()
            .filter(|&(block_idx, _)| !skip_entry || block_idx != 0)
            .filter_map(|(block_idx, block)| {
                block.is_trampoline().map(|target| (block_idx, target))
            })
            .collect()
    }

    /// Finds all constant definitions in this SSA function.
    ///
    /// Scans all blocks for `Const` instructions and returns a mapping from
    /// the destination variable to its constant value.
    ///
    /// # Returns
    ///
    /// A map from variable ID to its constant value.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let constants = ssa.find_constants();
    /// if let Some(value) = constants.get(&var_id) {
    ///     // var_id is defined as a constant with this value
    /// }
    /// ```
    #[must_use]
    pub fn find_constants(&self) -> BTreeMap<SsaVarId, ConstValue> {
        let mut constants = BTreeMap::new();

        for block in self.blocks() {
            for instr in block.instructions() {
                if let SsaOp::Const { dest, value } = instr.op() {
                    constants.insert(*dest, value.clone());
                }
            }
        }

        constants
    }

    /// Finds all blocks that use a given variable.
    ///
    /// Scans instructions and phi nodes across all blocks to find blocks
    /// that reference the specified variable.
    ///
    /// # Arguments
    ///
    /// * `var` - The variable ID to search for.
    /// * `exclude_block` - Optional block to exclude from results.
    ///
    /// # Returns
    ///
    /// A vector of block indices where the variable is used.
    #[must_use]
    pub fn find_var_user_blocks(&self, var: SsaVarId, exclude_block: Option<usize>) -> Vec<usize> {
        self.iter_blocks()
            .filter(|&(block_idx, _)| exclude_block != Some(block_idx))
            .filter(|(_, block)| {
                // Check instructions
                block.instructions().iter().any(|instr| instr.uses().contains(&var))
                    // Check phi operands
                    || block.phi_nodes().iter().any(|phi| {
                        phi.operands().iter().any(|op| op.value() == var)
                    })
            })
            .map(|(block_idx, _)| block_idx)
            .collect()
    }

    /// Analyzes what this method returns.
    ///
    /// Examines all return instructions in the SSA function to determine:
    /// - If returns a constant
    /// - If returns null
    /// - If returns "this" parameter
    /// - If returns a parameter directly
    /// - Otherwise Unknown
    #[must_use]
    pub fn return_info(&self) -> ReturnInfo {
        let mut return_values: Vec<Option<SsaVarId>> = Vec::new();

        for block in self.blocks() {
            for instr in block.instructions() {
                if let SsaOp::Return { value } = instr.op() {
                    return_values.push(*value);
                }
            }
        }

        // If no returns found, assume void
        if return_values.is_empty() {
            return ReturnInfo::Void;
        }

        // Check if all returns are void (None)
        if return_values.iter().all(Option::is_none) {
            return ReturnInfo::Void;
        }

        // If there's only one return with a value, trace what it is
        let non_void_returns: Vec<_> = return_values.iter().filter_map(|v| *v).collect();

        if non_void_returns.is_empty() {
            return ReturnInfo::Void;
        }

        // Try to determine what all returns have in common
        // Check if they all return the same constant
        let mut constants_found: Vec<Option<ConstValue>> = Vec::new();

        for &ret_var in &non_void_returns {
            // Find the definition of this variable
            let def = self.get_definition(ret_var);

            match def {
                Some(SsaOp::Const { value, .. }) => {
                    // Const includes null values (ConstValue::Null)
                    constants_found.push(Some(value.clone()));
                }
                _ => {
                    constants_found.push(None);
                }
            }
        }

        // If all returns are the same constant
        if constants_found.iter().all(Option::is_some) {
            let first = &constants_found[0];
            if constants_found.iter().all(|c| c == first) {
                if let Some(const_val) = first {
                    return ReturnInfo::Constant(const_val.clone());
                }
            }
        }

        // Check if returns a specific parameter (pass-through)
        for &ret_var in &non_void_returns {
            if let Some(param_idx) = self.is_parameter_variable(ret_var) {
                if non_void_returns.len() == 1 {
                    return ReturnInfo::PassThrough(param_idx);
                }
            }
        }

        // Check if all returns come from pure computations
        let all_pure = non_void_returns.iter().all(|&var| {
            if let Some(def) = self.get_definition(var) {
                def.is_pure()
            } else {
                false
            }
        });

        if all_pure {
            return ReturnInfo::PureComputation;
        }

        // Returns depend on state or have complex control flow
        ReturnInfo::Dynamic
    }

    /// Analyzes method purity (side effects).
    ///
    /// Examines the SSA function for various side effects:
    /// - Field stores (instance or static)
    /// - Indirect stores (via pointers)
    /// - Array element stores
    /// - Calls to potentially impure methods
    /// - Exception throwing
    ///
    /// Returns:
    /// - `Pure` if the method has no observable side effects
    /// - `ReadOnly` if the method only reads state, no writes
    /// - `Impure` if the method has definite side effects
    /// - `Unknown` if purity cannot be determined
    #[must_use]
    pub fn purity(&self) -> MethodPurity {
        let mut has_writes = false;
        let mut has_reads = false;
        let mut has_unknown_calls = false;
        let mut has_indirect_access = false;
        let mut has_throws = false;

        for block in self.blocks() {
            for instr in block.instructions() {
                match instr.op() {
                    // Definite writes - impure
                    SsaOp::StoreField { .. }
                    | SsaOp::StoreStaticField { .. }
                    | SsaOp::StoreElement { .. }
                    | SsaOp::StoreIndirect { .. }
                    | SsaOp::InitObj { .. }
                    | SsaOp::InitBlk { .. }
                    | SsaOp::CopyBlk { .. } => {
                        has_writes = true;
                    }

                    // Reads from external state
                    SsaOp::LoadField { .. }
                    | SsaOp::LoadStaticField { .. }
                    | SsaOp::LoadElement { .. }
                    | SsaOp::LoadIndirect { .. }
                    | SsaOp::LoadObj { .. } => {
                        has_reads = true;
                    }

                    // Address-of operations might lead to indirect access
                    SsaOp::LoadFieldAddr { .. }
                    | SsaOp::LoadStaticFieldAddr { .. }
                    | SsaOp::LoadElementAddr { .. } => {
                        has_indirect_access = true;
                    }

                    // Calls need deeper analysis - assume unknown
                    SsaOp::Call { .. }
                    | SsaOp::CallVirt { .. }
                    | SsaOp::CallIndirect { .. }
                    | SsaOp::NewObj { .. } => {
                        has_unknown_calls = true;
                    }

                    // Throws are a form of side effect (control flow)
                    SsaOp::Throw { .. } | SsaOp::Rethrow => {
                        has_throws = true;
                    }

                    // Everything else is either pure or doesn't affect state
                    _ => {}
                }
            }
        }

        // Determine purity level based on what we found
        if has_writes {
            return MethodPurity::Impure;
        }

        if has_unknown_calls {
            // Calls to unknown methods could be impure
            return MethodPurity::Unknown;
        }

        if has_throws {
            // Throwing exceptions is a side effect (abnormal control flow)
            return MethodPurity::Impure;
        }

        if has_indirect_access {
            // Address-of operations could enable writes we can't track
            return MethodPurity::Unknown;
        }

        if has_reads {
            return MethodPurity::ReadOnly;
        }

        MethodPurity::Pure
    }
}
