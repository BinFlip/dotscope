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
//! An `SsaFunction` is built by the `SsaConverter` which:
//! 1. Simulates the stack to create explicit variables
//! 2. Places phi nodes at dominance frontiers
//! 3. Renames variables to achieve single-assignment form
//!
//! # Thread Safety
//!
//! `SsaFunction` is `Send` and `Sync` once constructed.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    fmt,
};

use crate::{
    analysis::{
        cfg::{BlockSemantics, LoopSemantics, SemanticAnalyzer},
        ssa::{
            exception::SsaExceptionHandler, ConstValue, DefSite, PhiAnalyzer, PhiNode, PhiOperand,
            SsaBlock, SsaCfg, SsaInstruction, SsaOp, SsaType, SsaVarId, SsaVariable, UseSite,
            VariableOrigin,
        },
        LoopInfo,
    },
    metadata::signatures::{CustomModifiers, SignatureLocalVariable, SignatureLocalVariables},
    utils::graph::{
        algorithms::{compute_dominance_frontiers, compute_dominators},
        NodeId, RootedGraph,
    },
};

/// Immutable context for SSA variable renaming.
///
/// Bundles precomputed data structures needed during the rename phase of SSA
/// construction/rebuild. These are all immutable references that are passed
/// unchanged through recursive calls.
struct RenameContext<'a> {
    /// Maps variable IDs to their origins (Argument, Local, Stack, Phi)
    var_origins: &'a HashMap<SsaVarId, VariableOrigin>,
    /// Maps origins to their SSA types (for preserving type information)
    origin_types: &'a HashMap<VariableOrigin, SsaType>,
    /// CFG successor map for filling PHI operands
    successor_map: &'a HashMap<usize, Vec<usize>>,
    /// Dominator tree children for recursive traversal
    dom_children: &'a HashMap<usize, Vec<usize>>,
    /// Overridden origins for variables flowing to PHIs
    phi_operand_origins: &'a BTreeMap<SsaVarId, VariableOrigin>,
}

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

/// A method in SSA (Static Single Assignment) form.
///
/// This is the complete SSA representation of a CIL method, containing:
/// - All basic blocks with phi nodes and SSA instructions
/// - All SSA variables with their metadata
/// - Method signature information (argument/local counts)
/// - Exception handlers from the original method body
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::analysis::{SsaFunction, SsaBlock, SsaVarId};
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

    /// Maps variable IDs to their index in the variables Vec.
    /// Used for efficient reverse lookup in dataflow analysis.
    var_indices: HashMap<SsaVarId, usize>,

    /// Number of method arguments.
    num_args: usize,

    /// Number of local variables.
    num_locals: usize,

    /// Variables that control input-dependent control flow.
    /// Switches using these variables should not be simplified to jumps
    /// even if the value appears to be constant on some paths.
    preserved_dispatch_vars: HashSet<SsaVarId>,

    /// Original local variable types from the method signature.
    /// These are preserved during SSA construction so they can be used
    /// during code generation to maintain correct type information.
    original_local_types: Option<Vec<SignatureLocalVariable>>,

    /// Exception handlers from the original method body.
    /// These are preserved during SSA construction and remapped during
    /// code generation based on the new instruction layout.
    exception_handlers: Vec<SsaExceptionHandler>,
}

/// Finds kept predecessors of a removed block during canonicalization.
///
/// When a block is removed, we need to find the actual predecessor blocks
/// (that are being kept) which would flow into the removed block. This is
/// used to properly update PHI node predecessors.
///
/// The function follows predecessor chains through removed blocks until it
/// finds blocks that are being kept (have entries in `block_remap`).
fn find_kept_predecessors(
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
    /// Creates a new empty SSA function.
    ///
    /// # Arguments
    ///
    /// * `num_args` - Number of method arguments (including `this` for instance methods)
    /// * `num_locals` - Number of local variables declared in the method
    ///
    /// # Returns
    ///
    /// A new empty [`SsaFunction`] with no blocks or variables.
    #[must_use]
    pub fn new(num_args: usize, num_locals: usize) -> Self {
        Self {
            blocks: Vec::new(),
            variables: Vec::new(),
            var_indices: HashMap::new(),
            num_args,
            num_locals,
            preserved_dispatch_vars: HashSet::new(),
            original_local_types: None,
            exception_handlers: Vec::new(),
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
    ///
    /// # Returns
    ///
    /// A new empty [`SsaFunction`] with pre-allocated storage.
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
            var_indices: HashMap::with_capacity(var_capacity),
            num_args,
            num_locals,
            preserved_dispatch_vars: HashSet::new(),
            original_local_types: None,
            exception_handlers: Vec::new(),
        }
    }

    /// Returns the SSA blocks.
    ///
    /// # Returns
    ///
    /// A slice of all [`SsaBlock`]s in this function.
    #[must_use]
    pub fn blocks(&self) -> &[SsaBlock] {
        &self.blocks
    }

    /// Returns an iterator over blocks with their indices.
    ///
    /// This is a convenience method that pairs each block with its index,
    /// avoiding the common `for block_idx in 0..ssa.block_count()` pattern.
    ///
    /// # Example
    ///
    /// ```ignore
    /// for (block_idx, block) in ssa.iter_blocks() {
    ///     println!("Block {}: {} instructions", block_idx, block.instruction_count());
    /// }
    /// ```
    pub fn iter_blocks(&self) -> impl Iterator<Item = (usize, &SsaBlock)> {
        self.blocks.iter().enumerate()
    }

    /// Returns an iterator over all instructions with their block and instruction indices.
    ///
    /// This flattens the nested block/instruction structure into a single iterator,
    /// which is useful for passes that need to scan all instructions.
    ///
    /// # Example
    ///
    /// ```ignore
    /// for (block_idx, instr_idx, instr) in ssa.iter_instructions() {
    ///     { let op = instr.op();
    ///         // Process instruction at (block_idx, instr_idx)
    ///     }
    /// }
    /// ```
    pub fn iter_instructions(&self) -> impl Iterator<Item = (usize, usize, &SsaInstruction)> {
        self.blocks
            .iter()
            .enumerate()
            .flat_map(|(block_idx, block)| {
                block
                    .instructions()
                    .iter()
                    .enumerate()
                    .map(move |(instr_idx, instr)| (block_idx, instr_idx, instr))
            })
    }

    /// Returns a mutable iterator over all instructions with their block and instruction indices.
    ///
    /// This is the mutable counterpart to [`iter_instructions`], allowing passes to
    /// modify instructions while iterating. Note that structural changes (adding/removing
    /// instructions) require collecting the modifications and applying them separately.
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Replace all uses of old_var with new_var
    /// for (block_idx, instr_idx, instr) in ssa.iter_instructions_mut() {
    ///     instr.op_mut().replace_uses(old_var, new_var);
    /// }
    /// ```
    ///
    /// # Note
    ///
    /// For passes that need to add or remove instructions, use [`blocks_mut`] to access
    /// the blocks directly, as the iterator cannot handle structural modifications.
    ///
    /// [`iter_instructions`]: Self::iter_instructions
    /// [`blocks_mut`]: Self::blocks_mut
    pub fn iter_instructions_mut(
        &mut self,
    ) -> impl Iterator<Item = (usize, usize, &mut SsaInstruction)> {
        self.blocks
            .iter_mut()
            .enumerate()
            .flat_map(|(block_idx, block)| {
                block
                    .instructions_mut()
                    .iter_mut()
                    .enumerate()
                    .map(move |(instr_idx, instr)| (block_idx, instr_idx, instr))
            })
    }

    /// Returns an iterator over all phi nodes with their block and phi indices.
    ///
    /// This flattens the nested block/phi structure into a single iterator,
    /// which is useful for passes that need to analyze all phi nodes.
    ///
    /// # Example
    ///
    /// ```ignore
    /// for (block_idx, phi_idx, phi) in ssa.iter_phis() {
    ///     println!("Phi {} in block {} defines {}", phi_idx, block_idx, phi.result());
    /// }
    /// ```
    pub fn iter_phis(&self) -> impl Iterator<Item = (usize, usize, &PhiNode)> {
        self.blocks
            .iter()
            .enumerate()
            .flat_map(|(block_idx, block)| {
                block
                    .phi_nodes()
                    .iter()
                    .enumerate()
                    .map(move |(phi_idx, phi)| (block_idx, phi_idx, phi))
            })
    }

    /// Returns a mutable reference to the blocks.
    ///
    /// # Returns
    ///
    /// A mutable reference to the vector of [`SsaBlock`]s.
    pub fn blocks_mut(&mut self) -> &mut Vec<SsaBlock> {
        &mut self.blocks
    }

    /// Returns the SSA variables.
    ///
    /// # Returns
    ///
    /// A slice of all [`SsaVariable`]s in this function.
    #[must_use]
    pub fn variables(&self) -> &[SsaVariable] {
        &self.variables
    }

    /// Returns a mutable reference to the variables.
    ///
    /// # Returns
    ///
    /// A mutable reference to the vector of [`SsaVariable`]s.
    pub fn variables_mut(&mut self) -> &mut Vec<SsaVariable> {
        &mut self.variables
    }

    /// Returns the number of method arguments.
    ///
    /// # Returns
    ///
    /// The count of method arguments, including `this` for instance methods.
    #[must_use]
    pub const fn num_args(&self) -> usize {
        self.num_args
    }

    /// Returns the number of local variables.
    ///
    /// # Returns
    ///
    /// The count of local variables declared in the method.
    #[must_use]
    pub const fn num_locals(&self) -> usize {
        self.num_locals
    }

    /// Returns the number of blocks.
    ///
    /// # Returns
    ///
    /// The count of basic blocks in this function.
    #[must_use]
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }

    /// Returns the number of variables.
    ///
    /// # Returns
    ///
    /// The count of SSA variables in this function.
    #[must_use]
    pub fn variable_count(&self) -> usize {
        self.variables.len()
    }

    /// Gets the local index for a variable ID.
    ///
    /// This maps a global `SsaVarId` to its position in the variables Vec,
    /// which is used as a compact index for dataflow analysis.
    ///
    /// # Arguments
    ///
    /// * `id` - The variable ID to look up
    ///
    /// # Returns
    ///
    /// The local index (0-based), or `None` if the variable is not in this function.
    #[must_use]
    pub fn var_index(&self, id: SsaVarId) -> Option<usize> {
        self.var_indices.get(&id).copied()
    }

    /// Returns `true` if this function has no blocks.
    ///
    /// # Returns
    ///
    /// `true` if the function contains no blocks, `false` otherwise.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    /// Gets a block by index.
    ///
    /// # Arguments
    ///
    /// * `index` - The block index to retrieve
    ///
    /// # Returns
    ///
    /// A reference to the block, or `None` if the index is out of bounds.
    #[must_use]
    pub fn block(&self, index: usize) -> Option<&SsaBlock> {
        self.blocks.get(index)
    }

    /// Gets a mutable block by index.
    ///
    /// # Arguments
    ///
    /// * `index` - The block index to retrieve
    ///
    /// # Returns
    ///
    /// A mutable reference to the block, or `None` if the index is out of bounds.
    pub fn block_mut(&mut self, index: usize) -> Option<&mut SsaBlock> {
        self.blocks.get_mut(index)
    }

    /// Gets a variable by ID.
    ///
    /// # Arguments
    ///
    /// * `id` - The variable ID to look up
    ///
    /// # Returns
    ///
    /// A reference to the variable, or `None` if the ID is invalid.
    #[must_use]
    pub fn variable(&self, id: SsaVarId) -> Option<&SsaVariable> {
        self.var_indices
            .get(&id)
            .and_then(|&idx| self.variables.get(idx))
    }

    /// Gets a mutable variable by ID.
    ///
    /// # Arguments
    ///
    /// * `id` - The variable ID to look up
    ///
    /// # Returns
    ///
    /// A mutable reference to the variable, or `None` if the ID is invalid.
    pub fn variable_mut(&mut self, id: SsaVarId) -> Option<&mut SsaVariable> {
        self.var_indices
            .get(&id)
            .and_then(|&idx| self.variables.get_mut(idx))
    }

    /// Adds a block to this function.
    ///
    /// # Arguments
    ///
    /// * `block` - The block to add
    pub fn add_block(&mut self, block: SsaBlock) {
        self.blocks.push(block);
    }

    /// Adds a variable to this function and returns its ID.
    ///
    /// # Arguments
    ///
    /// * `variable` - The variable to add
    ///
    /// # Returns
    ///
    /// The [`SsaVarId`] assigned to the newly added variable.
    pub fn add_variable(&mut self, variable: SsaVariable) -> SsaVarId {
        let id = variable.id();
        let index = self.variables.len();
        self.var_indices.insert(id, index);
        self.variables.push(variable);
        id
    }

    /// Rebuilds the variable ID to index mapping.
    ///
    /// This must be called after removing variables from `self.variables` to ensure
    /// `var_indices` remains consistent. It's an O(n) operation.
    fn rebuild_var_indices(&mut self) {
        self.var_indices.clear();
        for (index, var) in self.variables.iter().enumerate() {
            self.var_indices.insert(var.id(), index);
        }
    }

    /// Marks a variable as a preserved dispatch variable.
    ///
    /// Preserved dispatch variables control input-dependent control flow
    /// (e.g., switches that depend on runtime input rather than constants).
    /// Optimization passes should not simplify switches using these variables
    /// even if the value appears constant on some paths.
    ///
    /// # Arguments
    ///
    /// * `var` - The variable ID to mark as preserved.
    pub fn mark_preserved_dispatch_var(&mut self, var: SsaVarId) {
        self.preserved_dispatch_vars.insert(var);
    }

    /// Checks if a variable is a preserved dispatch variable.
    ///
    /// # Arguments
    ///
    /// * `var` - The variable ID to check.
    ///
    /// # Returns
    ///
    /// `true` if this variable controls input-dependent control flow.
    #[must_use]
    pub fn is_preserved_dispatch_var(&self, var: SsaVarId) -> bool {
        self.preserved_dispatch_vars.contains(&var)
    }

    /// Checks if any preserved dispatch variables are set.
    ///
    /// # Returns
    ///
    /// `true` if there are any preserved dispatch variables.
    #[must_use]
    pub fn has_preserved_dispatch_vars(&self) -> bool {
        !self.preserved_dispatch_vars.is_empty()
    }

    /// Sets the original local variable types from the method signature.
    ///
    /// These types are preserved so they can be used during code generation
    /// to maintain correct type information in the output assembly.
    ///
    /// # Arguments
    ///
    /// * `types` - The original local variable types from the method signature.
    pub fn set_original_local_types(&mut self, types: Vec<SignatureLocalVariable>) {
        self.original_local_types = Some(types);
    }

    /// Returns the original local variable types if set.
    ///
    /// # Returns
    ///
    /// The original local types, or `None` if not set.
    #[must_use]
    pub fn original_local_types(&self) -> Option<&[SignatureLocalVariable]> {
        self.original_local_types.as_deref()
    }

    /// Sets the exception handlers for this function.
    ///
    /// These are preserved from the original method body and will be
    /// remapped during code generation based on the new instruction layout.
    ///
    /// # Arguments
    ///
    /// * `handlers` - The exception handlers from the original method body.
    pub fn set_exception_handlers(&mut self, handlers: Vec<SsaExceptionHandler>) {
        self.exception_handlers = handlers;
    }

    /// Returns the exception handlers for this function.
    ///
    /// # Returns
    ///
    /// A slice of exception handlers, or an empty slice if none are set.
    #[must_use]
    pub fn exception_handlers(&self) -> &[SsaExceptionHandler] {
        &self.exception_handlers
    }

    /// Returns whether this function has any exception handlers.
    ///
    /// # Returns
    ///
    /// `true` if the function has at least one exception handler.
    #[must_use]
    pub fn has_exception_handlers(&self) -> bool {
        !self.exception_handlers.is_empty()
    }

    /// Returns an iterator over argument variables (version 0).
    ///
    /// These are the initial SSA versions of arguments at method entry.
    ///
    /// # Returns
    ///
    /// An iterator over argument variables with version 0.
    pub fn argument_variables(&self) -> impl Iterator<Item = &SsaVariable> {
        self.variables
            .iter()
            .filter(|v| v.origin().is_argument() && v.version() == 0)
    }

    /// Returns an iterator over local variables (version 0).
    ///
    /// These are the initial SSA versions of locals at method entry.
    ///
    /// # Returns
    ///
    /// An iterator over local variables with version 0.
    pub fn local_variables(&self) -> impl Iterator<Item = &SsaVariable> {
        self.variables
            .iter()
            .filter(|v| v.origin().is_local() && v.version() == 0)
    }

    /// Finds all variables originating from a specific argument.
    ///
    /// # Arguments
    ///
    /// * `arg_index` - The argument index to filter by
    ///
    /// # Returns
    ///
    /// An iterator over all SSA versions of the specified argument.
    pub fn variables_from_argument(&self, arg_index: u16) -> impl Iterator<Item = &SsaVariable> {
        self.variables.iter().filter(
            move |v| matches!(v.origin(), VariableOrigin::Argument(idx) if idx == arg_index),
        )
    }

    /// Finds all variables originating from a specific local.
    ///
    /// # Arguments
    ///
    /// * `local_index` - The local variable index to filter by
    ///
    /// # Returns
    ///
    /// An iterator over all SSA versions of the specified local variable.
    pub fn variables_from_local(&self, local_index: u16) -> impl Iterator<Item = &SsaVariable> {
        self.variables
            .iter()
            .filter(move |v| matches!(v.origin(), VariableOrigin::Local(idx) if idx == local_index))
    }

    /// Returns the total number of phi nodes across all blocks.
    ///
    /// # Returns
    ///
    /// The sum of phi node counts in all blocks.
    pub fn total_phi_count(&self) -> usize {
        self.blocks.iter().map(SsaBlock::phi_count).sum()
    }

    /// Returns the total number of instructions across all blocks.
    ///
    /// # Returns
    ///
    /// The sum of instruction counts in all blocks.
    pub fn total_instruction_count(&self) -> usize {
        self.blocks.iter().map(SsaBlock::instruction_count).sum()
    }

    /// Returns an iterator over all phi nodes in the function.
    ///
    /// # Returns
    ///
    /// An iterator yielding references to all [`PhiNode`]s across all blocks.
    pub fn all_phi_nodes(&self) -> impl Iterator<Item = &PhiNode> {
        self.blocks.iter().flat_map(SsaBlock::phi_nodes)
    }

    /// Returns an iterator over all instructions in the function.
    ///
    /// # Returns
    ///
    /// An iterator yielding references to all [`SsaInstruction`]s across all blocks.
    pub fn all_instructions(&self) -> impl Iterator<Item = &SsaInstruction> {
        self.blocks.iter().flat_map(SsaBlock::instructions)
    }

    /// Finds dead variables (variables with no uses).
    ///
    /// # Returns
    ///
    /// An iterator over variables that have no uses recorded.
    pub fn dead_variables(&self) -> impl Iterator<Item = &SsaVariable> {
        self.variables.iter().filter(|v| v.is_dead())
    }

    /// Counts dead variables.
    ///
    /// # Returns
    ///
    /// The number of variables with no uses.
    #[must_use]
    pub fn dead_variable_count(&self) -> usize {
        self.variables.iter().filter(|v| v.is_dead()).count()
    }

    /// Returns the total instruction count across all blocks.
    #[must_use]
    pub fn instruction_count(&self) -> usize {
        self.total_instruction_count()
    }

    /// Returns the number of method parameters.
    #[must_use]
    pub fn parameter_count(&self) -> usize {
        self.num_args
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

    /// Checks if the function returns a string type (heuristic based on common patterns).
    /// Note: This is approximate since full type info requires metadata resolution.
    #[must_use]
    pub fn returns_string(&self) -> bool {
        // Check if there's a return with a value that comes from a string-related operation
        // This is a heuristic - full implementation would check return type from metadata
        false // Conservative default - override in specialized analysis
    }

    /// Checks if the function returns void (no return value).
    #[must_use]
    pub fn is_void_return(&self) -> bool {
        self.all_instructions()
            .any(|instr| matches!(instr.op(), SsaOp::Return { value: None }))
    }

    /// Returns None as return type info isn't stored in basic SsaFunction.
    /// Full type analysis requires metadata context.
    #[must_use]
    pub fn return_type(&self) -> Option<()> {
        // Return type would need method metadata - not available in pure SSA
        None
    }

    /// Gets the defining operation for an SSA variable.
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
        for block in &self.blocks {
            for instr in block.instructions() {
                {
                    let op = instr.op();
                    if op.dest() == Some(var) {
                        return Some(op);
                    }
                }
            }
        }
        None
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

        // Fallback: O(n) scan if variable not in var_indices
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
        self.iter_blocks()
            .filter(|&(idx, _)| idx != block_idx)
            .filter_map(|(idx, block)| {
                block
                    .terminator_op()
                    .filter(|op| op.successors().contains(&block_idx))
                    .map(|_| idx)
            })
            .collect()
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

        op.successors()
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
    fn block_reaches(from: usize, to: usize, successor_map: &HashMap<usize, Vec<usize>>) -> bool {
        if from == to {
            return true;
        }

        let mut visited: HashSet<usize> = HashSet::new();
        let mut worklist = vec![from];

        while let Some(block_idx) = worklist.pop() {
            if block_idx == to {
                return true;
            }
            if !visited.insert(block_idx) {
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
        self.is_parameter_variable_impl(var, &mut HashSet::new())
    }

    /// Internal implementation with visited set to prevent infinite recursion on cycles.
    fn is_parameter_variable_impl(
        &self,
        var: SsaVarId,
        visited: &mut HashSet<SsaVarId>,
    ) -> Option<usize> {
        // Prevent infinite recursion on cycles
        if !visited.insert(var) {
            return None;
        }

        // Parameters are typically assigned at function entry to the first N variables
        // where N is the parameter count. The exact mapping depends on SSA construction.

        // Check if this variable's definition is from a parameter load
        // or if it's in the initial argument range
        let idx = var.index();
        if idx < self.num_args {
            return Some(idx);
        }

        // Also check if defined by argument loading
        for block in &self.blocks {
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
                        return self.is_parameter_variable_impl(*src, visited);
                    }
                }
            }
        }

        None
    }

    /// Replaces all uses of `old_var` with `new_var` throughout the function.
    ///
    /// This is the core operation for copy propagation - when we know that
    /// `v1 = v0` (a copy), we can replace all uses of `v1` with `v0`.
    ///
    /// # Arguments
    ///
    /// * `old_var` - The variable whose uses should be replaced.
    /// * `new_var` - The variable to use instead.
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
        self.blocks
            .iter_mut()
            .map(|block| block.replace_uses(old_var, new_var))
            .sum()
    }

    /// Replaces all uses of `old_var` with `new_var`, including in PHI operands.
    ///
    /// Unlike [`replace_uses`](Self::replace_uses), this method also replaces uses
    /// in PHI node operands across all blocks. This is necessary for internal SSA
    /// operations that eliminate PHI nodes and need to forward their values through
    /// other PHIs.
    ///
    /// # Arguments
    ///
    /// * `old_var` - The variable ID to find and replace.
    /// * `new_var` - The variable ID to use as the replacement.
    ///
    /// # Returns
    ///
    /// The total number of uses replaced across all blocks.
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
        self.blocks
            .iter_mut()
            .map(|block| block.replace_uses_including_phis(old_var, new_var))
            .sum()
    }

    /// Replaces all uses of `old_var` with `new_var` within a specific block.
    ///
    /// This is a targeted version of `replace_uses` that only affects instructions
    /// within the specified block (not PHI operands).
    ///
    /// # Arguments
    ///
    /// * `block_idx` - The block to modify
    /// * `old_var` - The variable ID to find and replace
    /// * `new_var` - The variable ID to replace with
    ///
    /// # Returns
    ///
    /// The number of uses that were replaced.
    pub fn replace_uses_in_block(
        &mut self,
        block_idx: usize,
        old_var: SsaVarId,
        new_var: SsaVarId,
    ) -> usize {
        self.block_mut(block_idx)
            .map_or(0, |block| block.replace_uses(old_var, new_var))
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
    pub fn count_uses(&self) -> HashMap<SsaVarId, usize> {
        let mut counts = HashMap::new();

        for block in &self.blocks {
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
    pub fn find_trampoline_blocks(&self, skip_entry: bool) -> HashMap<usize, usize> {
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
    pub fn find_constants(&self) -> HashMap<SsaVarId, ConstValue> {
        let mut constants = HashMap::new();

        for block in &self.blocks {
            for instr in block.instructions() {
                if let SsaOp::Const { dest, value } = instr.op() {
                    constants.insert(*dest, value.clone());
                }
            }
        }

        constants
    }

    /// Recomputes all use information from scratch.
    ///
    /// This should be called after SSA transformations that may have invalidated
    /// the use tracking, such as instruction modifications, block restructuring,
    /// or phi node changes.
    ///
    /// The method:
    /// 1. Clears all existing use sites on all variables
    /// 2. Scans all instructions to record uses based on current operands
    /// 3. Scans all phi nodes to record uses based on current operands
    pub fn recompute_uses(&mut self) {
        // Step 1: Clear all existing uses
        for var in &mut self.variables {
            var.clear_uses();
        }

        // Step 2: Scan instructions to record uses
        for (block_idx, block) in self.blocks.iter().enumerate() {
            // Record uses from instructions
            for (instr_idx, instr) in block.instructions().iter().enumerate() {
                // Get all variable IDs used by this operation
                for use_var in instr.op().uses() {
                    if let Some(var) = self.var_indices.get(&use_var).copied() {
                        let use_site = UseSite::instruction(block_idx, instr_idx);
                        self.variables[var].add_use(use_site);
                    }
                }
            }

            // Record uses from phi nodes
            for (phi_idx, phi) in block.phi_nodes().iter().enumerate() {
                for operand in phi.operands() {
                    let use_var = operand.value();
                    if let Some(var) = self.var_indices.get(&use_var).copied() {
                        let use_site = UseSite::phi_operand(block_idx, phi_idx);
                        self.variables[var].add_use(use_site);
                    }
                }
            }
        }
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

    /// Replaces the operation of an instruction at a specific location.
    ///
    /// # Arguments
    ///
    /// * `block_idx` - The block containing the instruction.
    /// * `instr_idx` - The instruction index within the block.
    /// * `new_op` - The new operation to set.
    ///
    /// # Returns
    ///
    /// `true` if the replacement was successful, `false` if the location was invalid.
    pub fn replace_instruction_op(
        &mut self,
        block_idx: usize,
        instr_idx: usize,
        new_op: SsaOp,
    ) -> bool {
        if let Some(block) = self.blocks.get_mut(block_idx) {
            if let Some(instr) = block.instructions_mut().get_mut(instr_idx) {
                instr.set_op(new_op);
                return true;
            }
        }
        false
    }

    /// Removes an instruction by replacing it with a Nop.
    ///
    /// This maintains block structure while effectively removing the instruction.
    /// Dead code elimination can later compact the blocks if needed.
    ///
    /// # Arguments
    ///
    /// * `block_idx` - The block containing the instruction.
    /// * `instr_idx` - The instruction index within the block.
    ///
    /// # Returns
    ///
    /// `true` if the instruction was removed, `false` if the location was invalid.
    pub fn remove_instruction(&mut self, block_idx: usize, instr_idx: usize) -> bool {
        self.replace_instruction_op(block_idx, instr_idx, SsaOp::Nop)
    }

    /// Simplifies a phi node by converting it to a copy operation.
    ///
    /// When a phi node has all identical operands (excluding self-references),
    /// it can be converted to a simple copy operation: `phi_result = source`.
    ///
    /// # Arguments
    ///
    /// * `block_idx` - The block containing the phi node.
    /// * `phi_idx` - The phi node index within the block.
    /// * `source` - The single source variable all operands resolve to.
    ///
    /// # Returns
    ///
    /// `true` if the simplification was applied, `false` otherwise.
    pub fn simplify_phi_to_copy(
        &mut self,
        block_idx: usize,
        phi_idx: usize,
        source: SsaVarId,
    ) -> bool {
        let Some(block) = self.blocks.get_mut(block_idx) else {
            return false;
        };

        let Some(phi) = block.phi_nodes().get(phi_idx) else {
            return false;
        };

        let dest = phi.result();

        // Remove the phi node
        block.phi_nodes_mut().remove(phi_idx);

        // Add a copy instruction at the start of the block
        // Note: In pure SSA, the copy is implicit - we just need to
        // replace all uses of `dest` with `source`
        // We use replace_uses_including_phis here because we're eliminating a PHI
        // and need to forward its value through any other PHIs that use it.
        self.replace_uses_including_phis(dest, source);

        true
    }

    /// Removes a phi node by index without any validation.
    ///
    /// This is an unchecked removal - the caller is responsible for ensuring
    /// the phi node should be removed (e.g., it's unreachable, trivial, or
    /// fully self-referential).
    ///
    /// # Arguments
    ///
    /// * `block_idx` - The block containing the phi node.
    /// * `phi_idx` - The phi node index within the block.
    ///
    /// # Returns
    ///
    /// `true` if the phi was removed, `false` if indices were out of bounds.
    pub fn remove_phi_unchecked(&mut self, block_idx: usize, phi_idx: usize) -> bool {
        if let Some(block) = self.blocks.get_mut(block_idx) {
            if phi_idx < block.phi_nodes().len() {
                block.phi_nodes_mut().remove(phi_idx);
                return true;
            }
        }
        false
    }

    /// Folds a constant operation, replacing its uses with the computed value.
    ///
    /// When we can compute a constant result (e.g., `1 + 2 = 3`), we replace
    /// the operation with a `Const` instruction.
    ///
    /// # Arguments
    ///
    /// * `block_idx` - The block containing the instruction.
    /// * `instr_idx` - The instruction index within the block.
    /// * `value` - The constant value to fold to.
    ///
    /// # Returns
    ///
    /// `true` if folding was successful, `false` otherwise.
    pub fn fold_constant(&mut self, block_idx: usize, instr_idx: usize, value: ConstValue) -> bool {
        if let Some(block) = self.blocks.get_mut(block_idx) {
            if let Some(instr) = block.instructions_mut().get_mut(instr_idx) {
                if let Some(dest) = instr.op().dest() {
                    instr.set_op(SsaOp::Const { dest, value });
                    return true;
                }
            }
        }
        false
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
                // This handles the case where a block was removed but its PHI operand
                // value should still be included (e.g., initial loop values).
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
        // Exception handlers store block indices that must be updated when blocks are
        // renumbered or removed. Without this, code generation would use stale block
        // indices and produce incorrect exception handler offsets.
        for handler in &mut self.exception_handlers {
            handler.remap_block_indices(&block_remap);
        }

        // Phase 8: Ensure the method has a valid terminator.
        // After neutralization of protection code, a method might end up with only
        // Jumps leading to empty blocks (all code was protection infrastructure).
        // In this case, we need to ensure the entry block has a Return terminator.
        // This is especially important for module .cctor methods that become no-ops.
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

    /// Compacts the variable table by removing orphaned variables.
    ///
    /// After dead code elimination, some variables may no longer have active
    /// definitions (their defining instruction was replaced with `Nop` or their
    /// defining phi was removed). This method removes such orphaned variables
    /// from the variable table.
    ///
    /// A variable is considered orphaned if:
    /// - It's not defined by any instruction in any block
    /// - It's not defined by any phi node in any block
    ///
    /// # Returns
    ///
    /// The number of variables that were removed.
    ///
    /// # Note
    ///
    /// This should be called after dead code elimination to clean up the
    /// variable table. The method updates both the `variables` Vec and the
    /// `var_indices` HashMap to maintain consistency.
    pub fn compact_variables(&mut self) -> usize {
        // Phase 1: Collect all variables that still have active definitions
        let mut defined_vars: HashSet<SsaVarId> = HashSet::new();

        for block in &self.blocks {
            // From instructions
            for instr in block.instructions() {
                let op = instr.op();
                // Skip Nop instructions - they have no definition
                if matches!(op, SsaOp::Nop) {
                    continue;
                }
                if let Some(dest) = op.dest() {
                    defined_vars.insert(dest);
                }
            }

            // From phi nodes
            for phi in block.phi_nodes() {
                defined_vars.insert(phi.result());
            }
        }

        // Also keep argument and local variables at version 0 (entry definitions)
        // These are implicitly defined at function entry
        for var in &self.variables {
            if var.version() == 0 {
                match var.origin() {
                    VariableOrigin::Argument(_) | VariableOrigin::Local(_) => {
                        defined_vars.insert(var.id());
                    }
                    _ => {}
                }
            }
        }

        // Phase 2: Remove orphaned variables
        let original_count = self.variables.len();

        // Retain only defined variables
        self.variables.retain(|v| defined_vars.contains(&v.id()));

        // Phase 3: Rebuild var_indices
        self.var_indices.clear();
        for (idx, var) in self.variables.iter().enumerate() {
            self.var_indices.insert(var.id(), idx);
        }

        original_count - self.variables.len()
    }

    /// Optimizes local variables by removing unused ones and compacting indices.
    ///
    /// This method:
    /// 1. Identifies which local indices are actually used
    /// 2. Creates a compact remapping (old index -> new index)
    /// 3. Updates all `VariableOrigin::Local` references
    /// 4. Updates all `SsaOp::LoadLocalAddr` indices
    /// 5. Updates `num_locals` to the new count
    ///
    /// # Returns
    ///
    /// A vector where `result[old_index]` contains `Some(new_index)` for used locals,
    /// or `None` for unused locals. This can be used to create a new local variable
    /// signature with only the types that are actually needed.
    ///
    /// # Example
    ///
    /// If a method has 5 locals but only uses indices 1 and 3:
    /// - Returns: `[None, Some(0), None, Some(1), None]`
    /// - Updates `num_locals` to 2
    /// - All references to local 1 become local 0
    /// - All references to local 3 become local 1
    pub fn optimize_locals(&mut self) -> Vec<Option<u16>> {
        // Phase 1: Collect all used local indices
        let mut used_locals: HashSet<u16> = HashSet::new();

        // From variables
        for var in &self.variables {
            if let VariableOrigin::Local(idx) = var.origin() {
                used_locals.insert(idx);
            }
        }

        // From phi nodes
        for block in &self.blocks {
            for phi in block.phi_nodes() {
                if let VariableOrigin::Local(idx) = phi.origin() {
                    used_locals.insert(idx);
                }
            }
        }

        // From LoadLocalAddr instructions
        for block in &self.blocks {
            for instr in block.instructions() {
                if let SsaOp::LoadLocalAddr { local_index, .. } = instr.op() {
                    used_locals.insert(*local_index);
                }
            }
        }

        // If no optimization needed (all locals used or no locals), return identity mapping
        if used_locals.len() == self.num_locals || self.num_locals == 0 {
            #[allow(clippy::cast_possible_truncation)]
            return (0..self.num_locals as u16).map(Some).collect();
        }

        // Phase 2: Build remapping (old index -> new index)
        let mut remap: Vec<Option<u16>> = vec![None; self.num_locals];
        let mut sorted_used: Vec<u16> = used_locals.into_iter().collect();
        sorted_used.sort_unstable();

        for (new_idx, &old_idx) in sorted_used.iter().enumerate() {
            #[allow(clippy::cast_possible_truncation)]
            let new_idx_u16 = new_idx as u16;
            remap[old_idx as usize] = Some(new_idx_u16);
        }

        let new_num_locals = sorted_used.len();

        // Phase 3: Update all variable origins
        for var in &mut self.variables {
            if let VariableOrigin::Local(idx) = var.origin() {
                if let Some(new_idx) = remap[idx as usize] {
                    var.set_origin(VariableOrigin::Local(new_idx));
                }
            }
        }

        // Phase 4: Update phi nodes
        for block in &mut self.blocks {
            for phi in block.phi_nodes_mut() {
                if let VariableOrigin::Local(idx) = phi.origin() {
                    if let Some(new_idx) = remap[idx as usize] {
                        phi.set_origin(VariableOrigin::Local(new_idx));
                    }
                }
            }
        }

        // Phase 5: Update LoadLocalAddr instructions
        for block in &mut self.blocks {
            for instr in block.instructions_mut() {
                if let SsaOp::LoadLocalAddr { local_index, .. } = instr.op_mut() {
                    if let Some(new_idx) = remap[*local_index as usize] {
                        *local_index = new_idx;
                    }
                }
            }
        }

        // Phase 6: Update num_locals
        self.num_locals = new_num_locals;

        remap
    }

    /// Generates a local variable signature from the SSA variable types.
    ///
    /// This creates a signature based on the types of locals in the SSA, combining
    /// information from multiple sources in order of priority:
    ///
    /// 1. **Original types from CilObject** - If the SSA was built from a method that
    ///    had `set_original_local_types` called, those types are used for their
    ///    respective indices, preserving the exact encoding from the source assembly.
    ///
    /// 2. **Temporary types map** - For locals allocated by code generation (e.g.,
    ///    for PHI copy cycles), the `temporary_types` map provides explicit types.
    ///    This is critical for newly allocated locals that don't exist in the original
    ///    method or in SSA variables.
    ///
    /// 3. **SSA inference** - For locals not covered by the above, types are inferred
    ///    from SSA variables with `VariableOrigin::Local` or from PHI nodes.
    ///
    /// 4. **Default to I32** - For completely unknown locals (common in deobfuscated
    ///    code), defaults to `int32` which is the most common type for control flow
    ///    state variables.
    ///
    /// # Arguments
    ///
    /// * `override_count` - Optional override for the number of locals. If provided,
    ///   this count is used instead of `num_locals()`. This is useful when code
    ///   generation allocates additional temporary locals beyond the original count.
    ///
    /// * `temporary_types` - Optional map from local index to `SsaType` for any
    ///   temporaries allocated beyond the SSA's original locals (e.g., PHI cycle
    ///   temporaries). If `None`, an empty map is used.
    ///
    /// # Returns
    ///
    /// A `SignatureLocalVariables` containing the types for all locals,
    /// ordered by their local index (0, 1, 2, ...).
    #[must_use]
    pub fn generate_local_signature(
        &self,
        override_count: Option<u16>,
        temporary_types: Option<&HashMap<u16, SsaType>>,
    ) -> SignatureLocalVariables {
        // Use empty map if none provided
        let empty_temps = HashMap::new();
        let temp_types = temporary_types.unwrap_or(&empty_temps);

        // Use override count if provided, otherwise use the SSA's num_locals
        let local_count = override_count.map_or(self.num_locals, |c| c as usize);

        // If we have original local types (from CilObject), use them as the base
        if let Some(original_types) = &self.original_local_types {
            let mut locals: Vec<SignatureLocalVariable> = Vec::with_capacity(local_count);

            // Copy original types for existing locals, preserving CilObject encoding
            // We always use the original types when available - they're more accurate
            // than inference. Class types (Greeter, Calculator, etc.) need to be preserved
            // for correct runtime behavior.
            for (idx, orig) in original_types.iter().enumerate() {
                if idx >= local_count {
                    break;
                }
                locals.push(orig.clone());
            }

            // For any additional locals (temporaries allocated by codegen),
            // first check temporary_types map, then try SSA inference
            for idx in original_types.len()..local_count {
                #[allow(clippy::cast_possible_truncation)]
                let idx_u16 = idx as u16;
                let local_type = temp_types
                    .get(&idx_u16)
                    .cloned()
                    .unwrap_or_else(|| self.infer_local_type(idx));
                locals.push(SignatureLocalVariable {
                    modifiers: CustomModifiers::default(),
                    is_pinned: false,
                    is_byref: false,
                    base: local_type.to_type_signature(),
                });
            }

            return SignatureLocalVariables { locals };
        }

        // No original types - fall back to inference for all locals
        let mut local_types: Vec<Option<SsaType>> = vec![None; local_count];

        // First, populate with any provided temporary types (highest priority for temps)
        for (idx, typ) in temp_types {
            let idx = *idx as usize;
            if idx < local_types.len() {
                local_types[idx] = Some(typ.clone());
            }
        }

        // Get type from SSA variables with Local origin
        for var in &self.variables {
            if let VariableOrigin::Local(idx) = var.origin() {
                let idx = idx as usize;
                if idx < local_types.len() && local_types[idx].is_none() {
                    let var_type = var.var_type();
                    if !var_type.is_unknown() {
                        local_types[idx] = Some(var_type.clone());
                    }
                }
            }
        }

        // Also check phi nodes for type information
        for block in &self.blocks {
            for phi in block.phi_nodes() {
                if let VariableOrigin::Local(idx) = phi.origin() {
                    let idx = idx as usize;
                    if idx < local_types.len() && local_types[idx].is_none() {
                        if let Some(var) = self.variable(phi.result()) {
                            let var_type = var.var_type();
                            if !var_type.is_unknown() {
                                local_types[idx] = Some(var_type.clone());
                            }
                        }
                    }
                }
            }
        }

        // Build the signature locals - default to I32 (int32) for unknown types
        // since most locals in deobfuscated code are integer state variables
        let locals: Vec<SignatureLocalVariable> = local_types
            .into_iter()
            .map(|opt_type| {
                let base_type = opt_type.unwrap_or(SsaType::I32);
                SignatureLocalVariable {
                    modifiers: CustomModifiers::default(),
                    is_pinned: false,
                    is_byref: false,
                    base: base_type.to_type_signature(),
                }
            })
            .collect();

        SignatureLocalVariables { locals }
    }

    /// Infers the type for a local variable from SSA information.
    ///
    /// Searches through SSA variables and PHI nodes to find type information
    /// for the given local index. Returns I32 as the default type for unknown
    /// locals, which is appropriate for deobfuscated code.
    fn infer_local_type(&self, local_idx: usize) -> SsaType {
        // Try to find type from variables with this Local origin
        for var in &self.variables {
            if let VariableOrigin::Local(idx) = var.origin() {
                if idx as usize == local_idx {
                    let var_type = var.var_type();
                    if !var_type.is_unknown() {
                        return var_type.clone();
                    }
                }
            }
        }

        // Try phi nodes
        for block in &self.blocks {
            for phi in block.phi_nodes() {
                if let VariableOrigin::Local(idx) = phi.origin() {
                    if idx as usize == local_idx {
                        if let Some(var) = self.variable(phi.result()) {
                            let var_type = var.var_type();
                            if !var_type.is_unknown() {
                                return var_type.clone();
                            }
                        }
                    }
                }
            }
        }

        // Default to I32 for deobfuscated code (most common type for state vars)
        SsaType::I32
    }

    /// Analyzes the semantic role of a specific block.
    ///
    /// Uses the `SemanticAnalyzer` to determine what a block does:
    /// initialization, condition testing, loop body work, variable updates, etc.
    ///
    /// # Arguments
    ///
    /// * `block_idx` - The block index to analyze
    ///
    /// # Returns
    ///
    /// Semantic information about the block including its role and characteristics.
    #[must_use]
    pub fn analyze_block_semantics(&self, block_idx: usize) -> BlockSemantics {
        let mut analyzer = SemanticAnalyzer::new(self);
        analyzer.analyze_block(block_idx).clone()
    }

    /// Analyzes semantic roles of multiple blocks.
    ///
    /// # Arguments
    ///
    /// * `blocks` - The block indices to analyze
    ///
    /// # Returns
    ///
    /// A map of block index to semantic information.
    #[must_use]
    pub fn analyze_blocks_semantics(&self, blocks: &[usize]) -> HashMap<usize, BlockSemantics> {
        let mut analyzer = SemanticAnalyzer::new(self);
        let mut results = HashMap::new();

        for &block in blocks {
            results.insert(block, analyzer.analyze_block(block).clone());
        }

        results
    }

    /// Analyzes the semantic structure of a structural loop.
    ///
    /// Given a `LoopInfo` from dominance-based loop detection, this method
    /// classifies each block within the loop by its semantic role:
    /// init, condition, body, latch, exit.
    ///
    /// # Arguments
    ///
    /// * `loop_info` - Structural loop information from `LoopForest`
    ///
    /// # Returns
    ///
    /// Semantic loop information with classified blocks and execution order.
    #[must_use]
    pub fn analyze_loop_semantics(&self, loop_info: &LoopInfo) -> LoopSemantics {
        let mut analyzer = SemanticAnalyzer::new(self);
        analyzer.analyze_loop(loop_info)
    }

    /// Recovers loop semantics from flattened dispatcher case blocks.
    ///
    /// This is the key method for control flow unflattening. Given the target
    /// blocks from a switch dispatcher, it analyzes each block's semantic role
    /// to reconstruct the original loop structure.
    ///
    /// # Arguments
    ///
    /// * `case_blocks` - Block indices that are case targets of the dispatcher
    /// * `dispatcher_block` - Optional index of the dispatcher block to exclude
    ///
    /// # Returns
    ///
    /// Semantic loop structure with blocks classified and ordered correctly.
    ///
    /// # Example
    ///
    /// ```text
    /// // Flattened code has:
    /// // - Block 2: i = 0  (Init)
    /// // - Block 3: if (i < 5) goto case4 else goto case5  (Condition)
    /// // - Block 4: print(i)  (Body)
    /// // - Block 5: i++  (Latch)
    /// // - Block 6: return  (Exit)
    ///
    /// let semantics = ssa.recover_loop_from_cases(&[2, 3, 4, 5, 6], Some(1));
    /// // semantics.init_blocks = [2]
    /// // semantics.condition_blocks = [3]
    /// // semantics.body_blocks = [4]
    /// // semantics.latch_blocks = [5]
    /// // semantics.exit_blocks = [6]
    /// ```
    #[must_use]
    pub fn recover_loop_from_cases(
        &self,
        case_blocks: &[usize],
        dispatcher_block: Option<usize>,
    ) -> LoopSemantics {
        let mut analyzer = SemanticAnalyzer::new(self);

        // Mark dispatcher as known if provided
        if let Some(disp) = dispatcher_block {
            analyzer.mark_dispatcher(disp);
        }

        analyzer.recover_loop_from_cases(case_blocks)
    }

    /// Creates a semantic analyzer for this function.
    ///
    /// Use this when you need to perform multiple semantic analyses
    /// and want to benefit from caching.
    ///
    /// # Returns
    ///
    /// A new `SemanticAnalyzer` instance for this function.
    #[must_use]
    pub fn semantic_analyzer(&self) -> SemanticAnalyzer<'_> {
        SemanticAnalyzer::new(self)
    }

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
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let remap = func.allocate_fresh_variables_for_block(5)?;
    /// // remap: { v10 -> v100, v11 -> v101, v12 -> v102 }
    /// // where v10, v11, v12 were defined in block 5
    /// ```
    #[must_use]
    pub fn allocate_fresh_variables_for_block(
        &self,
        block_idx: usize,
    ) -> Option<HashMap<SsaVarId, SsaVarId>> {
        let block = self.block(block_idx)?;
        let mut mapping = HashMap::new();

        // Allocate fresh IDs for phi node results
        for phi in block.phi_nodes() {
            let old_id = phi.result();
            let new_id = SsaVarId::new();
            mapping.insert(old_id, new_id);
        }

        // Allocate fresh IDs for instruction defs
        for instr in block.instructions() {
            if let Some(dest) = instr.op().dest() {
                let new_id = SsaVarId::new();
                mapping.insert(dest, new_id);
            }
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
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let var_remap = func.allocate_fresh_variables_for_block(5)?;
    /// let pred_remap = HashMap::from([(2, 10), (3, 11)]); // remap predecessors too
    /// let cloned = func.clone_block_with_remap(5, 20, &var_remap, Some(&pred_remap))?;
    /// func.add_block(cloned);
    /// ```
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
        SsaInstruction::new(original, new_op)
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
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// // Duplicate block 5 for path splitting
    /// if let Some((new_idx, var_map)) = func.duplicate_block(5) {
    ///     println!("Created block {} as copy of block 5", new_idx);
    ///     println!("Variable mapping: {:?}", var_map);
    /// }
    /// ```
    pub fn duplicate_block(
        &mut self,
        block_idx: usize,
    ) -> Option<(usize, HashMap<SsaVarId, SsaVarId>)> {
        // Allocate fresh variables
        let var_remap = self.allocate_fresh_variables_for_block(block_idx)?;

        // Create SsaVariable entries for each new variable
        for (&old_id, &new_id) in &var_remap {
            if let Some(old_var) = self.variable(old_id) {
                let new_var = SsaVariable::new_with_id_typed(
                    new_id,
                    old_var.origin(),
                    old_var.version(),
                    old_var.def_site(),
                    old_var.var_type().clone(),
                );
                self.add_variable(new_var);
            }
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

    /// Rebuilds SSA form after CFG modifications (e.g., control flow unflattening).
    ///
    /// This method performs a complete SSA reconstruction using the standard
    /// Cytron et al. algorithm:
    ///
    /// 1. Build variable origin map
    /// 2. Compute reachability, dominators, and dominance frontiers
    /// 3. Collect definition sites for each variable origin
    /// 4. Clear existing PHI nodes
    /// 5. Place new PHI nodes at iterated dominance frontiers
    /// 6. Rename variables via dominator tree traversal
    ///
    /// This is necessary because after passes like control flow unflattening,
    /// the CFG structure changes significantly and PHI nodes may reference
    /// variables from removed blocks or have incorrect operands.
    pub fn rebuild_ssa(&mut self) {
        if self.blocks.is_empty() {
            return;
        }

        // Step 1: Build var_id -> origin map (needed for rename phase)
        // Also build origin -> type map to preserve types when creating new variables
        let mut var_origins: HashMap<SsaVarId, VariableOrigin> = self
            .variables
            .iter()
            .map(|v| (v.id(), v.origin()))
            .collect();

        // Track the best type for each origin (prefer non-unknown types)
        let mut origin_types: HashMap<VariableOrigin, SsaType> = HashMap::new();
        for var in &self.variables {
            let var_type = var.var_type();
            if !var_type.is_unknown() {
                origin_types.insert(var.origin(), var_type.clone());
            }
        }

        // Also collect variables from instructions that might not be in self.variables
        // (orphan variables created by passes). Give them Stack origin so they can be renamed.
        // This is critical: without this, orphan uses won't find their origin in var_origins,
        // so they won't be renamed, while their defs WILL be renamed - breaking def-use chains.
        //
        // CRITICAL: Process PHIs FIRST across ALL blocks to propagate origins to their
        // operands. This ensures that variables merging at a PHI get the same origin,
        // even if they're orphans. We must do this before processing instructions,
        // otherwise instruction defs would get unique orphan origins before we can
        // propagate the PHI's origin to them.
        #[allow(clippy::cast_possible_truncation)]
        let mut next_stack_idx = self.num_locals as u32;

        // First pass: propagate PHI origins to ALL operands
        // This ensures that phi operands use the same origin as the phi during rename,
        // so they end up on the same version stack and properly fill phi operands.
        // Without this, operands with different original origins would go on different
        // version stacks, causing "no reaching def" warnings during rename.
        for block in &self.blocks {
            for phi in block.phi_nodes() {
                let phi_origin = var_origins
                    .get(&phi.result())
                    .copied()
                    .unwrap_or_else(|| phi.origin());

                // Assign the PHI's origin to its result if orphan
                var_origins.entry(phi.result()).or_insert(phi_origin);

                // Assign the phi's origin to ORPHAN operands only.
                // This ensures orphan variables go on the same version stack as the phi.
                // IMPORTANT: Do NOT overwrite existing origins for non-orphan variables.
                // In particular, phi operands that are themselves phi results must keep
                // their original origins - otherwise we'd incorrectly merge different
                // local variables (e.g., marking Local(1) as Local(0) would cause
                // copy propagation to incorrectly merge distinct loop variables).
                for operand in phi.operands() {
                    let op_var = operand.value();
                    var_origins.entry(op_var).or_insert(phi_origin);
                }
            }
        }

        // Second pass: assign unique origins to remaining orphan variables
        for block in &self.blocks {
            for instr in block.instructions() {
                // Collect from instr.uses()
                for use_var in instr.uses().iter().copied() {
                    if let std::collections::hash_map::Entry::Vacant(e) = var_origins.entry(use_var)
                    {
                        e.insert(VariableOrigin::Stack(next_stack_idx));
                        next_stack_idx += 1;
                    }
                }
                if let Some(dest) = instr.def() {
                    if let std::collections::hash_map::Entry::Vacant(e) = var_origins.entry(dest) {
                        e.insert(VariableOrigin::Stack(next_stack_idx));
                        next_stack_idx += 1;
                    }
                }
            }
        }

        // Step 2: Compute reachability and CFG info
        // This must happen before clearing PHIs, but PHIs don't affect control flow edges
        let (dominance_frontiers, successor_map, dom_children, reachable) = {
            let cfg = SsaCfg::from_ssa(self);

            // Compute reachable blocks via BFS from entry
            let mut reachable: HashSet<usize> = HashSet::new();
            let mut worklist = vec![0usize];
            while let Some(block_idx) = worklist.pop() {
                if reachable.insert(block_idx) {
                    for succ in cfg.block_successors(block_idx) {
                        if succ < self.blocks.len() {
                            worklist.push(succ);
                        }
                    }
                }
            }

            // Also include exception handler entry blocks as roots.
            // Exception handlers are reachable via implicit exception edges,
            // not normal control flow, so they must be added separately.
            for handler in &self.exception_handlers {
                if let Some(handler_block) = handler.handler_start_block {
                    if handler_block < self.blocks.len() && !reachable.contains(&handler_block) {
                        worklist.push(handler_block);
                        while let Some(block_idx) = worklist.pop() {
                            if reachable.insert(block_idx) {
                                for succ in cfg.block_successors(block_idx) {
                                    if succ < self.blocks.len() {
                                        worklist.push(succ);
                                    }
                                }
                            }
                        }
                    }
                }
                // Also include filter blocks for FILTER handlers
                if let Some(filter_block) = handler.filter_start_block {
                    if filter_block < self.blocks.len() && !reachable.contains(&filter_block) {
                        worklist.push(filter_block);
                        while let Some(block_idx) = worklist.pop() {
                            if reachable.insert(block_idx) {
                                for succ in cfg.block_successors(block_idx) {
                                    if succ < self.blocks.len() {
                                        worklist.push(succ);
                                    }
                                }
                            }
                        }
                    }
                }
            }

            let dom_tree = compute_dominators(&cfg, cfg.entry());
            let df = compute_dominance_frontiers(&cfg, &dom_tree);

            // Extract successor map (only for reachable blocks)
            let mut succ_map: HashMap<usize, Vec<usize>> = HashMap::new();
            for &i in &reachable {
                succ_map.insert(i, cfg.block_successors(i));
            }

            // Extract dominator tree children (only for reachable blocks)
            let mut dom_ch: HashMap<usize, Vec<usize>> = HashMap::new();
            for &i in &reachable {
                dom_ch.insert(
                    i,
                    dom_tree
                        .children(NodeId::new(i))
                        .into_iter()
                        .filter(|n| n.index() < self.blocks.len() && reachable.contains(&n.index()))
                        .map(NodeId::index)
                        .collect(),
                );
            }

            (df, succ_map, dom_ch, reachable)
        };

        // Step 3: Collect definition sites from reachable blocks (before clearing PHIs)
        let mut defs: BTreeMap<VariableOrigin, BTreeSet<usize>> = BTreeMap::new();

        // Arguments and locals version 0 are defined at entry (block 0)
        for i in 0..self.num_args {
            #[allow(clippy::cast_possible_truncation)]
            let i_u16 = i as u16;
            defs.entry(VariableOrigin::Argument(i_u16))
                .or_default()
                .insert(0);
        }
        for i in 0..self.num_locals {
            #[allow(clippy::cast_possible_truncation)]
            let i_u16 = i as u16;
            defs.entry(VariableOrigin::Local(i_u16))
                .or_default()
                .insert(0);
        }

        // Build mapping from PHI operands to PHI origins.
        // This is critical: PHI operands may have different origins (e.g., Stack(8), Stack(9))
        // than the PHI itself (e.g., Stack(0)). When collecting defs, we need to use the PHI's
        // origin for its operands, otherwise the operand defs will be placed under different
        // origins and rebuild_ssa won't recognize they should merge at a PHI.
        let mut phi_operand_origins: BTreeMap<SsaVarId, VariableOrigin> = BTreeMap::new();

        // Collect defs from PHIs (before we clear them)
        for block in &self.blocks {
            let block_idx = block.id();
            if !reachable.contains(&block_idx) {
                continue;
            }
            for phi in block.phi_nodes() {
                let origin = phi.origin();
                if !matches!(origin, VariableOrigin::Phi) {
                    defs.entry(origin).or_default().insert(block_idx);

                    // Map all PHI operands to this PHI's origin
                    for operand in phi.operands() {
                        phi_operand_origins.insert(operand.value(), origin);
                    }
                }
            }
        }

        // Collect defs from instructions
        // If a variable is a PHI operand, use the PHI's origin so that its def
        // is grouped with other values merging at the same PHI.
        for block in &self.blocks {
            let block_idx = block.id();
            if !reachable.contains(&block_idx) {
                continue;
            }
            for instr in block.instructions() {
                if let Some(dest) = instr.def() {
                    // Prefer PHI operand origin (if this var flows to a PHI), else use var_origins
                    let origin = phi_operand_origins
                        .get(&dest)
                        .copied()
                        .or_else(|| var_origins.get(&dest).copied());

                    if let Some(origin) = origin {
                        if !matches!(origin, VariableOrigin::Phi) {
                            defs.entry(origin).or_default().insert(block_idx);
                        }
                    }
                }
            }
        }

        // Step 3b: Identify orphan USE variables (used but never defined).
        // These will need synthetic version 0 during rename, but we DON'T add them to `defs`
        // because that would cause PHI placement for these orphan origins, which is wrong.
        // Instead, we track them separately and handle them in rename_variables_for_rebuild.
        let mut orphan_stack_origins: HashSet<VariableOrigin> = HashSet::new();
        for &origin in var_origins.values() {
            if matches!(origin, VariableOrigin::Stack(_)) {
                // Check if this origin has any definition site
                if !defs.contains_key(&origin) {
                    // True orphan use with no def anywhere
                    orphan_stack_origins.insert(origin);
                }
            }
        }

        // Step 4: Clear all existing PHI nodes
        for block in &mut self.blocks {
            block.phi_nodes_mut().clear();
        }

        // Build predecessor map from successor map
        let mut predecessor_map: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
        for (&block_idx, succs) in &successor_map {
            for &succ in succs {
                predecessor_map.entry(succ).or_default().push(block_idx);
            }
        }

        // Step 5: Place PHI nodes
        // For Argument/Local origins: use iterated dominance frontiers (standard algorithm)
        // For Stack origins: use merge-point approach (PHI at blocks with multiple preds
        // where any predecessor has a definition) - this correctly handles cross-origin merges

        // Separate origins by type
        let mut arg_local_defs: BTreeMap<VariableOrigin, BTreeSet<usize>> = BTreeMap::new();
        let mut stack_defs: BTreeMap<VariableOrigin, BTreeSet<usize>> = BTreeMap::new();

        for (origin, def_blocks) in &defs {
            match origin {
                VariableOrigin::Argument(_) | VariableOrigin::Local(_) => {
                    arg_local_defs.insert(*origin, def_blocks.clone());
                }
                VariableOrigin::Stack(_) => {
                    stack_defs.insert(*origin, def_blocks.clone());
                }
                VariableOrigin::Phi => {}
            }
        }

        // 5a: Place PHIs for Argument/Local using dominance frontiers
        for (origin, def_blocks) in &arg_local_defs {
            // Skip origins that only have the implicit entry definition (block 0).
            // These don't need phis - the value flows directly from entry to all uses.
            if def_blocks.len() == 1 && def_blocks.contains(&0) {
                continue;
            }

            let mut phi_blocks: HashSet<usize> = HashSet::new();
            let mut worklist: Vec<usize> = def_blocks.iter().copied().collect();

            while let Some(block_idx) = worklist.pop() {
                let node_id = NodeId::new(block_idx);
                if node_id.index() < dominance_frontiers.len() {
                    for &frontier_node in &dominance_frontiers[node_id.index()] {
                        let frontier_idx = frontier_node.index();
                        // Only place PHIs in reachable blocks
                        if frontier_idx < self.blocks.len()
                            && reachable.contains(&frontier_idx)
                            && phi_blocks.insert(frontier_idx)
                        {
                            worklist.push(frontier_idx);
                        }
                    }
                }

                // For exception handler blocks (not in dominator tree), use Leave targets
                // as phi placement points. This handles the case where handler blocks
                // aren't represented in the dominance frontier computation.
                if let Some(block) = self.block(block_idx) {
                    if let Some(SsaOp::Leave { target }) = block.terminator_op() {
                        if *target < self.blocks.len()
                            && reachable.contains(target)
                            && phi_blocks.insert(*target)
                        {
                            worklist.push(*target);
                        }
                    }
                }
            }

            for &phi_block_idx in &phi_blocks {
                if let Some(block) = self.block_mut(phi_block_idx) {
                    let phi = PhiNode::new(SsaVarId::new(), *origin);
                    block.add_phi(phi);
                }
            }
        }

        // 5b: Place PHIs for Stack origins using merge-point approach
        // This is similar to converter's place_stack_phi_nodes: for each merge point
        // (block with 2+ predecessors), place a PHI for each Stack origin that has
        // a definition in any predecessor.
        for (origin, def_blocks) in &stack_defs {
            // For Stack origins, we need at least 2 definitions to need a PHI,
            // OR the definition must flow to a merge point
            if def_blocks.len() < 2 {
                // Single-def Stack origin: only needs PHI if it reaches a merge point
                // where another path doesn't define it. But this causes trivial PHIs.
                // Skip to avoid oscillation - the dominance frontier approach doesn't
                // work well for single-def Stack origins.
                continue;
            }

            // Find merge points where this origin might need a PHI
            for (&block_idx, preds) in &predecessor_map {
                if preds.len() < 2 || !reachable.contains(&block_idx) {
                    continue;
                }

                // Check if any predecessor has a definition of this origin
                // (either directly or via dominance - a def dominates the pred)
                let any_pred_has_def = preds.iter().any(|pred| {
                    // Check if this pred or any dominating block has a def
                    def_blocks.contains(pred)
                        || def_blocks.iter().any(|&def_block| {
                            // Simple reachability check: def_block reaches pred
                            Self::block_reaches(def_block, *pred, &successor_map)
                        })
                });

                if any_pred_has_def {
                    if let Some(block) = self.block_mut(block_idx) {
                        // Check if we already have a PHI for this origin
                        let has_phi = block.phi_nodes().iter().any(|p| p.origin() == *origin);
                        if !has_phi {
                            let phi = PhiNode::new(SsaVarId::new(), *origin);
                            block.add_phi(phi);
                        }
                    }
                }
            }
        }

        // Step 6: Rename variables via dominator tree traversal
        // IMPORTANT: Pass phi_operand_origins so that instruction defs that flow to PHIs
        // use the PHI's origin during rename, not their original origin. This ensures
        // the version stacks are populated correctly for filling PHI operands.
        self.rename_variables_for_rebuild(
            &var_origins,
            &origin_types,
            &successor_map,
            &dom_children,
            &reachable,
            &orphan_stack_origins,
            &phi_operand_origins,
        );

        // Step 7: Eliminate trivial PHIs created during rebuild.
        // A PHI is trivial if all its operands (excluding self-references) resolve to
        // the same value. This can happen when rebuild places PHIs conservatively at
        // merge points, but after renaming all operands end up being the same.
        // Eliminating these here prevents oscillation with DCE/copy-propagation.
        self.eliminate_trivial_phis();
    }

    /// Renames variables after PHI placement during SSA rebuild.
    ///
    /// This implements the standard SSA rename algorithm:
    /// - Walk dominator tree in preorder
    /// - For each block: process PHIs, then instructions, then fill successor PHI operands
    /// - Maintain version stacks to track reaching definitions
    ///
    /// Parameters are bundled into `RenameContext` for the recursive rename function.
    /// The setup parameters (`reachable`, `orphan_stack_origins`) are only used here.
    #[allow(clippy::too_many_arguments)]
    fn rename_variables_for_rebuild(
        &mut self,
        var_origins: &HashMap<SsaVarId, VariableOrigin>,
        origin_types: &HashMap<VariableOrigin, SsaType>,
        successor_map: &HashMap<usize, Vec<usize>>,
        dom_children: &HashMap<usize, Vec<usize>>,
        reachable: &HashSet<usize>,
        orphan_stack_origins: &HashSet<VariableOrigin>,
        phi_operand_origins: &BTreeMap<SsaVarId, VariableOrigin>,
    ) {
        // Bundle immutable references into a context struct for cleaner recursion
        let ctx = RenameContext {
            var_origins,
            origin_types,
            successor_map,
            dom_children,
            phi_operand_origins,
        };

        // Version stacks: for each origin, track the current reaching definition
        let mut version_stacks: HashMap<VariableOrigin, Vec<SsaVarId>> = HashMap::new();
        let mut next_version: HashMap<VariableOrigin, u32> = HashMap::new();

        // Initialize with arguments and locals version 0
        for var in &self.variables {
            match var.origin() {
                VariableOrigin::Argument(_) | VariableOrigin::Local(_) if var.version() == 0 => {
                    version_stacks
                        .entry(var.origin())
                        .or_default()
                        .push(var.id());
                    next_version.insert(var.origin(), 1);
                }
                _ => {}
            }
        }

        // Collect new variables to add (declared early so we can add orphan vars)
        let mut new_vars: Vec<SsaVariable> = Vec::new();

        // Initialize orphan Stack origins that are used but have no definition anywhere.
        // These need version 0 entries so uses can find a reaching definition.
        // This handles the case where deobfuscation passes leave orphan uses
        // (variables referenced in instructions but not in self.variables).
        //
        // IMPORTANT: Only create version 0 for true orphans (passed via orphan_stack_origins).
        // Normal Stack-origin variables are defined by instructions and should NOT
        // have a synthetic version 0 at entry - their definition creates the first version.
        //
        // Note: We only do this if there ARE orphan origins. For normal SSA without
        // orphans, this loop doesn't execute and has no effect.
        if !orphan_stack_origins.is_empty() {
            for &origin in orphan_stack_origins {
                if !version_stacks.contains_key(&origin) {
                    // True orphan use with no def anywhere - create synthetic version 0
                    let var = SsaVariable::new(origin, 0, DefSite::entry());
                    let new_var_id = var.id();
                    new_vars.push(var);
                    version_stacks.entry(origin).or_default().push(new_var_id);
                    next_version.insert(origin, 1);
                }
            }
        }

        // Track renames: old_var -> new_var
        let mut rename_map: HashMap<SsaVarId, SsaVarId> = HashMap::new();

        // Recursive rename using dominator tree order
        self.rename_block_recursive(
            0,
            &ctx,
            &mut version_stacks,
            &mut next_version,
            &mut rename_map,
            &mut new_vars,
        );

        // Also rename exception handler blocks that are not reachable via dominator tree.
        // Exception handlers are separate CFG regions and need their own rename pass.
        // We process them after the main CFG so they can see variable versions from entry.

        // Compute which blocks are actually reachable via dominator tree from entry.
        // This is the set of blocks that were already visited during the main rename.
        let mut dom_tree_reachable: HashSet<usize> = HashSet::new();
        let mut dom_stack = vec![0usize];
        while let Some(block_idx) = dom_stack.pop() {
            if dom_tree_reachable.insert(block_idx) {
                if let Some(children) = ctx.dom_children.get(&block_idx) {
                    dom_stack.extend(children.iter().copied());
                }
            }
        }

        for handler in self.exception_handlers.clone() {
            if let Some(handler_block) = handler.handler_start_block {
                // Only process if not already visited via dominator tree
                if !dom_tree_reachable.contains(&handler_block) {
                    self.rename_block_recursive(
                        handler_block,
                        &ctx,
                        &mut version_stacks,
                        &mut next_version,
                        &mut rename_map,
                        &mut new_vars,
                    );
                }
            }
            if let Some(filter_block) = handler.filter_start_block {
                // Only process if not already visited via dominator tree
                if !dom_tree_reachable.contains(&filter_block) {
                    self.rename_block_recursive(
                        filter_block,
                        &ctx,
                        &mut version_stacks,
                        &mut next_version,
                        &mut rename_map,
                        &mut new_vars,
                    );
                }
            }
        }

        // Process any remaining reachable blocks that weren't visited via dominator tree
        // or exception handlers. This can happen after CFF reconstruction creates blocks
        // that are reachable but not properly connected to the dominator tree.
        // Recompute dom_tree_reachable after exception handler processing
        dom_tree_reachable.clear();
        dom_stack.clear();
        dom_stack.push(0);
        while let Some(block_idx) = dom_stack.pop() {
            if dom_tree_reachable.insert(block_idx) {
                if let Some(children) = ctx.dom_children.get(&block_idx) {
                    dom_stack.extend(children.iter().copied());
                }
            }
        }
        // Add exception handler blocks
        for handler in &self.exception_handlers {
            if let Some(handler_block) = handler.handler_start_block {
                dom_tree_reachable.insert(handler_block);
            }
            if let Some(filter_block) = handler.filter_start_block {
                dom_tree_reachable.insert(filter_block);
            }
        }

        for &block_idx in reachable {
            if !dom_tree_reachable.contains(&block_idx) {
                self.rename_block_recursive(
                    block_idx,
                    &ctx,
                    &mut version_stacks,
                    &mut next_version,
                    &mut rename_map,
                    &mut new_vars,
                );
            }
        }

        // Add new variables
        for var in new_vars {
            self.add_variable(var);
        }

        // Apply renames to all variable uses
        self.apply_rename_map(&rename_map);

        // Final cleanup: Remove Pop instructions that use undefined variables.
        // After renaming, orphan variables that had no reaching definition will still
        // use their original IDs, which are not in self.variables. These Pops should
        // be removed to avoid emitting invalid ldloc instructions in codegen.
        {
            let defined_vars: HashSet<SsaVarId> =
                self.variables.iter().map(SsaVariable::id).collect();
            for block in &mut self.blocks {
                block.instructions_mut().retain(|instr| {
                    if let SsaOp::Pop { value } = instr.op() {
                        return defined_vars.contains(value);
                    }
                    true
                });
            }
        }

        // Eliminate trivial PHIs to avoid creating work for optimization passes.
        // A PHI is trivial if all its operands (excluding self-references) are identical.
        // This produces "pruned SSA" which is cleaner and doesn't require post-processing.
        self.eliminate_trivial_phis();
    }

    /// Eliminates trivial PHI nodes.
    ///
    /// A PHI is trivial if all its operands (excluding self-references) resolve to
    /// the same value. Such PHIs can be replaced with a simple copy.
    ///
    /// This is run at the end of SSA rebuild to produce cleaner SSA that doesn't
    /// require additional optimization passes to clean up.
    fn eliminate_trivial_phis(&mut self) {
        // Iterate until no more trivial PHIs are found (they can chain)
        loop {
            let mut trivial_phis: Vec<(SsaVarId, SsaVarId)> = Vec::new();

            // Find trivial PHIs using PhiAnalyzer
            {
                let analyzer = PhiAnalyzer::new(self);
                for block in &self.blocks {
                    for phi in block.phi_nodes() {
                        if let Some(source) = analyzer.is_trivial(phi) {
                            trivial_phis.push((phi.result(), source));
                        }
                    }
                }
            }

            if trivial_phis.is_empty() {
                break;
            }

            // Replace uses of trivial PHI results with their source
            // We use replace_uses_including_phis because we're eliminating PHIs
            // and need to forward their values through other PHIs that use them.
            for (phi_result, source) in &trivial_phis {
                self.replace_uses_including_phis(*phi_result, *source);
            }

            // Remove the trivial PHIs
            let trivial_set: HashSet<SsaVarId> =
                trivial_phis.iter().map(|(result, _)| *result).collect();
            for block in &mut self.blocks {
                block
                    .phi_nodes_mut()
                    .retain(|phi| !trivial_set.contains(&phi.result()));
            }

            // Remove variables for eliminated PHIs
            self.variables.retain(|v| !trivial_set.contains(&v.id()));
            self.rebuild_var_indices();
        }
    }

    /// Recursively renames variables in a block and its dominated children.
    fn rename_block_recursive(
        &mut self,
        block_idx: usize,
        ctx: &RenameContext<'_>,
        version_stacks: &mut HashMap<VariableOrigin, Vec<SsaVarId>>,
        next_version: &mut HashMap<VariableOrigin, u32>,
        rename_map: &mut HashMap<SsaVarId, SsaVarId>,
        new_vars: &mut Vec<SsaVariable>,
    ) {
        let mut pushed_counts: HashMap<VariableOrigin, usize> = HashMap::new();

        // Step 1: Process PHI nodes - collect info first
        let phi_info: Vec<(VariableOrigin, SsaVarId)> = self
            .block(block_idx)
            .map(|b| {
                b.phi_nodes()
                    .iter()
                    .map(|phi| (phi.origin(), phi.result()))
                    .collect()
            })
            .unwrap_or_default();

        // Update phis and track renames
        for (i, (origin, old_result)) in phi_info.iter().enumerate() {
            let version = *next_version.get(origin).unwrap_or(&0);
            *next_version.entry(*origin).or_insert(0) += 1;

            // Create variable with preserved type if available
            let mut new_var = SsaVariable::new(*origin, version, DefSite::phi(block_idx));
            if let Some(var_type) = ctx.origin_types.get(origin) {
                new_var.set_type(var_type.clone());
            }
            let new_var_id = new_var.id();

            if let Some(block) = self.block_mut(block_idx) {
                if let Some(phi) = block.phi_nodes_mut().get_mut(i) {
                    phi.set_result(new_var_id);
                }
            }

            new_vars.push(new_var);
            version_stacks.entry(*origin).or_default().push(new_var_id);
            *pushed_counts.entry(*origin).or_insert(0) += 1;

            if *old_result != new_var_id {
                rename_map.insert(*old_result, new_var_id);
            }
        }

        // Step 2: Process instructions - collect info first
        // IMPORTANT: Collect uses from BOTH instr.uses() AND op.uses() in case they're out of sync
        let instr_info: Vec<(usize, Vec<SsaVarId>, Option<SsaVarId>)> = self
            .block(block_idx)
            .map(|b| {
                b.instructions()
                    .iter()
                    .enumerate()
                    .map(|(i, instr)| (i, instr.uses(), instr.def()))
                    .collect()
            })
            .unwrap_or_default();

        for (instr_idx, old_uses, opt_def) in &instr_info {
            // Apply use renames DIRECTLY to the instruction instead of putting them
            // in rename_map. This is critical: if the same variable ID appears as a
            // use in one instruction and a def in another (which can happen with
            // orphan variables after CFF reconstruction), putting both in rename_map
            // causes the def rename to overwrite the use rename, creating cycles.
            //
            // By applying use renames immediately, we ensure they're applied with
            // the correct reaching definition at the time of processing.
            let mut use_renames: Vec<(SsaVarId, SsaVarId)> = Vec::new();
            for &old_use in old_uses {
                if let Some(&origin) = ctx.var_origins.get(&old_use) {
                    if let Some(reaching_def) = version_stacks
                        .get(&origin)
                        .and_then(|stack| stack.last().copied())
                    {
                        if reaching_def != old_use {
                            use_renames.push((old_use, reaching_def));
                        }
                    }
                }
            }

            // Apply use renames directly to this instruction
            if !use_renames.is_empty() {
                if let Some(block) = self.block_mut(block_idx) {
                    if let Some(instr) = block.instructions_mut().get_mut(*instr_idx) {
                        let op = instr.op_mut();
                        for (old_use, new_use) in &use_renames {
                            op.replace_uses(*old_use, *new_use);
                        }
                    }
                }
            }

            // Handle definition - create NEW variable like we do for PHIs
            if let Some(old_dest) = opt_def {
                // IMPORTANT: Use phi_operand_origins first, then fall back to var_origins.
                // This is critical for maintaining consistency with def collection in rebuild_ssa:
                // if an instruction's def flows to a PHI, its origin during rename must match
                // the origin used when placing definitions (phi's origin), not the original origin.
                let origin = ctx
                    .phi_operand_origins
                    .get(old_dest)
                    .copied()
                    .or_else(|| ctx.var_origins.get(old_dest).copied());
                if let Some(origin) = origin {
                    if !matches!(origin, VariableOrigin::Phi) {
                        let version = *next_version.get(&origin).unwrap_or(&0);
                        *next_version.entry(origin).or_insert(0) += 1;

                        // Create variable with preserved type if available
                        let mut new_var = SsaVariable::new(
                            origin,
                            version,
                            DefSite::instruction(block_idx, *instr_idx),
                        );
                        if let Some(var_type) = ctx.origin_types.get(&origin) {
                            new_var.set_type(var_type.clone());
                        }
                        let new_var_id = new_var.id();

                        // Update instruction's dest in the op
                        if let Some(block) = self.block_mut(block_idx) {
                            if let Some(instr) = block.instructions_mut().get_mut(*instr_idx) {
                                instr.op_mut().set_dest(new_var_id);
                            }
                        }

                        new_vars.push(new_var);
                        version_stacks.entry(origin).or_default().push(new_var_id);
                        *pushed_counts.entry(origin).or_insert(0) += 1;

                        if *old_dest != new_var_id {
                            rename_map.insert(*old_dest, new_var_id);
                        }
                    }
                }
            }
        }

        // Step 3: Fill in PHI operands for successors
        let successors = ctx
            .successor_map
            .get(&block_idx)
            .cloned()
            .unwrap_or_default();
        for succ_idx in successors {
            let phi_updates: Vec<(usize, VariableOrigin)> = self
                .block(succ_idx)
                .map(|b| {
                    b.phi_nodes()
                        .iter()
                        .enumerate()
                        .map(|(i, phi)| (i, phi.origin()))
                        .collect()
                })
                .unwrap_or_default();

            for (phi_idx, origin) in phi_updates {
                if let Some(reaching_def) = version_stacks
                    .get(&origin)
                    .and_then(|stack| stack.last().copied())
                {
                    if let Some(succ_block) = self.block_mut(succ_idx) {
                        if let Some(phi) = succ_block.phi_nodes_mut().get_mut(phi_idx) {
                            phi.set_operand(block_idx, reaching_def);
                        }
                    }
                }
            }
        }

        // Step 4: Recurse into dominated children
        let children = ctx
            .dom_children
            .get(&block_idx)
            .cloned()
            .unwrap_or_default();
        for child in children {
            self.rename_block_recursive(
                child,
                ctx,
                version_stacks,
                next_version,
                rename_map,
                new_vars,
            );
        }

        // Step 5: Pop definitions from version stacks
        for (origin, count) in pushed_counts {
            if let Some(stack) = version_stacks.get_mut(&origin) {
                for _ in 0..count {
                    stack.pop();
                }
            }
        }
    }

    /// Applies the rename map to all variable uses in the function.
    fn apply_rename_map(&mut self, rename_map: &HashMap<SsaVarId, SsaVarId>) {
        if rename_map.is_empty() {
            return;
        }

        // Build a local copy for the resolve closure
        let map = rename_map.clone();

        // Helper to resolve through chains
        let resolve = |var: SsaVarId| -> SsaVarId {
            let mut current = var;
            let mut visited = HashSet::new();
            while let Some(&new_var) = map.get(&current) {
                if !visited.insert(current) {
                    break;
                }
                current = new_var;
            }
            current
        };

        // Collect all phi operand updates first
        let mut phi_updates: Vec<(usize, usize, usize, SsaVarId)> = Vec::new();
        for block in &self.blocks {
            let block_idx = block.id();
            for (phi_idx, phi) in block.phi_nodes().iter().enumerate() {
                for op in phi.operands() {
                    let old_val = op.value();
                    let new_val = resolve(old_val);
                    if new_val != old_val {
                        phi_updates.push((block_idx, phi_idx, op.predecessor(), new_val));
                    }
                }
            }
        }

        // Apply phi operand updates
        for (block_idx, phi_idx, pred, new_val) in phi_updates {
            if let Some(block) = self.block_mut(block_idx) {
                if let Some(phi) = block.phi_nodes_mut().get_mut(phi_idx) {
                    phi.set_operand(pred, new_val);
                }
            }
        }

        // Collect all instruction use updates
        // Check BOTH instr.uses() AND op.uses() since they may be out of sync
        let mut instr_updates: Vec<(usize, usize, SsaVarId, SsaVarId)> = Vec::new();
        for block in &self.blocks {
            let block_idx = block.id();
            for (instr_idx, instr) in block.instructions().iter().enumerate() {
                let mut seen = std::collections::HashSet::new();
                for &old_use in &instr.uses() {
                    if seen.insert(old_use) {
                        let new_use = resolve(old_use);
                        if new_use != old_use {
                            instr_updates.push((block_idx, instr_idx, old_use, new_use));
                        }
                    }
                }
            }
        }

        // Apply instruction use updates
        for (block_idx, instr_idx, old_var, new_var) in instr_updates {
            if let Some(block) = self.block_mut(block_idx) {
                if let Some(instr) = block.instructions_mut().get_mut(instr_idx) {
                    instr.op_mut().replace_uses(old_var, new_var);
                }
            }
        }

        // Sort instructions in topological order within each block.
        // This fixes ordering issues that may arise during SSA transformations.
        self.sort_all_blocks_topologically();
    }

    /// Sorts instructions in all blocks in topological order.
    ///
    /// This ensures that within each block, if instruction A uses a value defined
    /// by instruction B, then B appears before A.
    ///
    /// This is called automatically by [`rebuild_ssa`](Self::rebuild_ssa) but can
    /// also be called manually after passes that may have disrupted instruction order.
    ///
    /// # Returns
    ///
    /// `true` if all blocks were successfully sorted, `false` if any block has
    /// cyclic dependencies (which indicates invalid SSA).
    pub fn sort_all_blocks_topologically(&mut self) -> bool {
        let mut all_sorted = true;
        for block in &mut self.blocks {
            if !block.sort_instructions_topologically() {
                all_sorted = false;
            }
        }
        all_sorted
    }

    /// Validates that the SSA function is well-formed.
    ///
    /// This checks several SSA invariants:
    ///
    /// 1. **No cyclic dependencies within a block** - Operations must have a valid
    ///    topological order. If operation A uses the result of operation B, then B
    ///    must come before A in the instruction list.
    ///
    /// 2. **Single definition** - Each variable should be defined at most once
    ///    (the defining property of SSA form).
    ///
    /// 3. **Phi nodes at block start** - Phi nodes should only appear at the
    ///    beginning of blocks, not mixed with regular instructions.
    ///
    /// # Errors
    ///
    /// Returns `Err` with a description of the problem if any SSA invariant is violated,
    /// such as cyclic dependencies, duplicate definitions, or misplaced terminators.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let ssa = build_ssa_from_method(&method)?;
    /// ssa.validate()?; // Returns error if SSA is malformed
    ///
    /// // After running a pass
    /// some_pass.run(&mut ssa);
    /// ssa.validate()?; // Check the pass didn't break SSA invariants
    /// ```
    pub fn validate(&self) -> Result<(), String> {
        // Check each block independently
        for (block_idx, block) in self.blocks.iter().enumerate() {
            Self::validate_block(block_idx, block)?;
        }

        // Check single-definition property
        self.validate_single_definition()?;

        Ok(())
    }

    /// Validates a single block for internal consistency.
    fn validate_block(block_idx: usize, block: &SsaBlock) -> Result<(), String> {
        // Track which variables are defined within this block
        let mut defined_in_block: HashSet<SsaVarId> = HashSet::new();

        // Add phi node results to defined set
        for phi in block.phi_nodes() {
            defined_in_block.insert(phi.result());
        }

        // Build a map of variable -> instruction index for operations that define variables
        let mut def_indices: HashMap<SsaVarId, usize> = HashMap::new();
        for (instr_idx, instr) in block.instructions().iter().enumerate() {
            {
                let op = instr.op();
                if let Some(dest) = op.dest() {
                    def_indices.insert(dest, instr_idx);
                    defined_in_block.insert(dest);
                }
            }
        }

        // Check for cyclic dependencies within the block.
        // For each instruction, verify that all its operands that are defined
        // in this block are defined BEFORE this instruction.
        for (instr_idx, instr) in block.instructions().iter().enumerate() {
            let op = instr.op();
            for used_var in op.uses() {
                // Only check variables defined in THIS block
                if let Some(&def_idx) = def_indices.get(&used_var) {
                    if def_idx >= instr_idx {
                        // The definition comes at or after the use - this is either:
                        // 1. A cyclic dependency (def_idx > instr_idx but uses this result)
                        // 2. Self-reference (def_idx == instr_idx, instruction uses its own result)
                        return Err(format!(
                            "Block {block_idx}: Instruction {instr_idx} ({op:?}) uses {used_var:?} which is defined \
                                at instruction {def_idx} - invalid order (possible cycle)"
                        ));
                    }
                }
            }
        }

        // Check for terminators in the middle of the block.
        // A terminator (Jump, Branch, Return, etc.) must be the last instruction.
        // Having instructions after a terminator indicates malformed SSA.
        let instr_count = block.instruction_count();
        for (instr_idx, instr) in block.instructions().iter().enumerate() {
            let op = instr.op();
            if op.is_terminator() && instr_idx < instr_count - 1 {
                return Err(format!(
                    "Block {}: Terminator {:?} at position {}/{} is not the last instruction - \
                        {} instructions follow the terminator",
                    block_idx,
                    op,
                    instr_idx,
                    instr_count,
                    instr_count - instr_idx - 1
                ));
            }
        }

        Ok(())
    }

    /// Validates the single-definition property of SSA.
    fn validate_single_definition(&self) -> Result<(), String> {
        let mut definitions: HashMap<SsaVarId, (usize, &str)> = HashMap::new();

        for (block_idx, block) in self.blocks.iter().enumerate() {
            // Check phi nodes
            for phi in block.phi_nodes() {
                let var = phi.result();
                if let Some((prev_block, prev_kind)) = definitions.get(&var) {
                    return Err(format!(
                        "Variable {var:?} defined multiple times: first as {prev_kind} in block {prev_block}, \
                         then as phi in block {block_idx}"
                    ));
                }
                definitions.insert(var, (block_idx, "phi"));
            }

            // Check instructions
            for instr in block.instructions() {
                let op = instr.op();
                if let Some(dest) = op.dest() {
                    if let Some((prev_block, prev_kind)) = definitions.get(&dest) {
                        return Err(format!(
                            "Variable {dest:?} defined multiple times: first as {prev_kind} in block {prev_block}, \
                                then as {op:?} in block {block_idx}"
                        ));
                    }
                    definitions.insert(dest, (block_idx, "instruction"));
                }
            }
        }

        Ok(())
    }

    /// Checks if the SSA function is valid without returning detailed errors.
    ///
    /// This is a convenience method that returns `true` if [`validate`](Self::validate)
    /// would return `Ok(())`.
    ///
    /// # Returns
    ///
    /// `true` if the SSA is well-formed, `false` otherwise.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.validate().is_ok()
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
    use crate::{
        analysis::{
            ssa::{DefSite, PhiOperand, UseSite},
            SsaFunctionBuilder,
        },
        assembly::{FlowType, Instruction, InstructionCategory, Operand, StackBehavior},
    };

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

        let var1 = SsaVariable::new(VariableOrigin::Argument(0), 0, DefSite::phi(0));
        let id1 = func.add_variable(var1);

        let var2 = SsaVariable::new(VariableOrigin::Stack(0), 0, DefSite::instruction(0, 0));
        let id2 = func.add_variable(var2);

        // IDs should be different
        assert_ne!(id1, id2);
        assert_eq!(func.variable_count(), 2);
    }

    #[test]
    fn test_ssa_function_variable_access() {
        let mut func = SsaFunction::new(1, 0);

        let var = SsaVariable::new(VariableOrigin::Argument(0), 0, DefSite::phi(0));
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
            VariableOrigin::Argument(0),
            0,
            DefSite::phi(0),
        ));

        // Add arg1 version 0
        func.add_variable(SsaVariable::new(
            VariableOrigin::Argument(1),
            0,
            DefSite::phi(0),
        ));

        // Add arg0 version 1 (redefinition)
        func.add_variable(SsaVariable::new(
            VariableOrigin::Argument(0),
            1,
            DefSite::instruction(1, 0),
        ));

        // Add local0 version 0
        func.add_variable(SsaVariable::new(
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
            VariableOrigin::Local(0),
            0,
            DefSite::phi(0),
        ));

        func.add_variable(SsaVariable::new(
            VariableOrigin::Local(1),
            0,
            DefSite::phi(0),
        ));

        func.add_variable(SsaVariable::new(
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
            VariableOrigin::Argument(0),
            0,
            DefSite::phi(0),
        ));

        func.add_variable(SsaVariable::new(
            VariableOrigin::Argument(0),
            1,
            DefSite::instruction(1, 0),
        ));

        func.add_variable(SsaVariable::new(
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
        block0.add_phi(PhiNode::new(SsaVarId::new(), VariableOrigin::Local(0)));
        block0.add_phi(PhiNode::new(SsaVarId::new(), VariableOrigin::Local(1)));
        func.add_block(block0);

        let mut block1 = SsaBlock::new(1);
        block1.add_phi(PhiNode::new(SsaVarId::new(), VariableOrigin::Local(0)));
        func.add_block(block1);

        func.add_block(SsaBlock::new(2)); // No phis

        assert_eq!(func.total_phi_count(), 3);
    }

    #[test]
    fn test_ssa_function_total_instruction_count() {
        let mut func = SsaFunction::new(0, 0);

        let mut block0 = SsaBlock::new(0);
        block0.add_instruction(SsaInstruction::new(
            make_test_cil_instruction("nop"),
            SsaOp::Nop,
        ));
        block0.add_instruction(SsaInstruction::new(
            make_test_cil_instruction("nop"),
            SsaOp::Nop,
        ));
        func.add_block(block0);

        let mut block1 = SsaBlock::new(1);
        block1.add_instruction(SsaInstruction::new(
            make_test_cil_instruction("ret"),
            SsaOp::Return { value: None },
        ));
        func.add_block(block1);

        assert_eq!(func.total_instruction_count(), 3);
    }

    #[test]
    fn test_ssa_function_all_phi_nodes() {
        let mut func = SsaFunction::new(0, 0);

        let phi_result = SsaVarId::new();
        let phi_operand = SsaVarId::new();
        let mut block0 = SsaBlock::new(0);
        let mut phi = PhiNode::new(phi_result, VariableOrigin::Local(0));
        phi.add_operand(PhiOperand::new(phi_operand, 1));
        block0.add_phi(phi);
        func.add_block(block0);

        let phis: Vec<_> = func.all_phi_nodes().collect();
        assert_eq!(phis.len(), 1);
        assert_eq!(phis[0].result(), phi_result);
    }

    #[test]
    fn test_ssa_function_dead_variables() {
        let mut func = SsaFunction::new(0, 0);

        // Variable with no uses (dead)
        func.add_variable(SsaVariable::new(
            VariableOrigin::Stack(0),
            0,
            DefSite::instruction(0, 0),
        ));

        // Variable with uses (live)
        let mut live_var =
            SsaVariable::new(VariableOrigin::Stack(1), 0, DefSite::instruction(0, 1));
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

    #[test]
    fn test_compact_variables_removes_orphaned() {
        let mut func = SsaFunction::new(0, 0);

        // Add a block with an instruction that defines a variable
        let mut block = SsaBlock::new(0);
        let defined_var = SsaVariable::new(VariableOrigin::Stack(0), 0, DefSite::instruction(0, 0));
        let defined_id = defined_var.id();
        func.add_variable(defined_var);

        // Add the instruction that defines it
        let instr = SsaInstruction::new(
            make_test_cil_instruction("nop"),
            SsaOp::Const {
                dest: defined_id,
                value: ConstValue::I32(42),
            },
        );
        block.add_instruction(instr);

        // Add return
        let ret = SsaInstruction::new(
            make_test_cil_instruction("ret"),
            SsaOp::Return { value: None },
        );
        block.add_instruction(ret);
        func.add_block(block);

        // Add an orphaned variable (not defined by any instruction)
        let orphaned_var =
            SsaVariable::new(VariableOrigin::Stack(1), 0, DefSite::instruction(0, 99));
        func.add_variable(orphaned_var);

        assert_eq!(func.variable_count(), 2);

        // Compact should remove the orphaned variable
        let removed = func.compact_variables();
        assert_eq!(removed, 1);
        assert_eq!(func.variable_count(), 1);

        // The remaining variable should be the defined one
        assert!(func.variable(defined_id).is_some());
    }

    #[test]
    fn test_compact_variables_preserves_entry_vars() {
        let mut func = SsaFunction::new(1, 1);

        // Add arg0 version 0 (entry definition - should be preserved even without instruction)
        let arg_var = SsaVariable::new(VariableOrigin::Argument(0), 0, DefSite::entry());
        let arg_id = arg_var.id();
        func.add_variable(arg_var);

        // Add local0 version 0 (entry definition - should be preserved)
        let local_var = SsaVariable::new(VariableOrigin::Local(0), 0, DefSite::entry());
        let local_id = local_var.id();
        func.add_variable(local_var);

        // Add an orphaned stack variable
        let orphaned = SsaVariable::new(VariableOrigin::Stack(0), 0, DefSite::instruction(0, 99));
        func.add_variable(orphaned);

        // Add an empty block
        let mut block = SsaBlock::new(0);
        let ret = SsaInstruction::new(
            make_test_cil_instruction("ret"),
            SsaOp::Return { value: None },
        );
        block.add_instruction(ret);
        func.add_block(block);

        assert_eq!(func.variable_count(), 3);

        // Compact should preserve arg and local (entry definitions) but remove orphaned
        let removed = func.compact_variables();
        assert_eq!(removed, 1);
        assert_eq!(func.variable_count(), 2);

        // Arg and local should remain
        assert!(func.variable(arg_id).is_some());
        assert!(func.variable(local_id).is_some());
    }

    #[test]
    fn test_find_constants_collects_all_const_instructions() {
        let ssa = SsaFunctionBuilder::new(1, 0).build_with(|f| {
            f.block(0, |b| {
                let c1 = b.const_i32(42);
                let c2 = b.const_i32(100);
                let _ = b.add(c1, c2);
                b.ret();
            });
        });

        let constants = ssa.find_constants();
        assert_eq!(constants.len(), 2);

        // Verify we can look up constants by their variable IDs
        let values: Vec<_> = constants.values().collect();
        assert!(values.iter().any(|v| **v == ConstValue::I32(42)));
        assert!(values.iter().any(|v| **v == ConstValue::I32(100)));
    }

    #[test]
    fn test_find_constants_across_multiple_blocks() {
        let ssa = SsaFunctionBuilder::new(2, 0).build_with(|f| {
            f.block(0, |b| {
                let _ = b.const_i32(1);
                b.jump(1);
            });
            f.block(1, |b| {
                let _ = b.const_i32(2);
                let _ = b.const_i32(3);
                b.ret();
            });
        });

        let constants = ssa.find_constants();
        assert_eq!(constants.len(), 3);
    }

    #[test]
    fn test_find_constants_empty_when_no_constants() {
        let ssa = SsaFunctionBuilder::new(1, 0).build_with(|f| {
            f.block(0, |b| {
                b.ret();
            });
        });

        let constants = ssa.find_constants();
        assert!(constants.is_empty());
    }

    #[test]
    fn test_find_trampoline_blocks_in_chain() {
        let ssa = SsaFunctionBuilder::new(4, 0).build_with(|f| {
            f.block(0, |b| b.jump(1)); // trampoline -> 1
            f.block(1, |b| b.jump(2)); // trampoline -> 2
            f.block(2, |b| b.jump(3)); // trampoline -> 3
            f.block(3, |b| b.ret()); // not a trampoline
        });

        // With skip_entry = true, block 0 is excluded
        let trampolines = ssa.find_trampoline_blocks(true);
        assert_eq!(trampolines.len(), 2);
        assert_eq!(trampolines.get(&1), Some(&2));
        assert_eq!(trampolines.get(&2), Some(&3));
        assert!(!trampolines.contains_key(&0));

        // With skip_entry = false, block 0 is included
        let trampolines = ssa.find_trampoline_blocks(false);
        assert_eq!(trampolines.len(), 3);
        assert_eq!(trampolines.get(&0), Some(&1));
        assert_eq!(trampolines.get(&1), Some(&2));
        assert_eq!(trampolines.get(&2), Some(&3));
    }

    #[test]
    fn test_find_trampoline_blocks_mixed_control_flow() {
        let ssa = SsaFunctionBuilder::new(4, 0).build_with(|f| {
            f.block(0, |b| {
                let cond = b.const_true();
                b.branch(cond, 1, 2); // conditional - not a trampoline
            });
            f.block(1, |b| b.jump(3)); // trampoline -> 3
            f.block(2, |b| {
                let _ = b.const_i32(42);
                b.jump(3); // has extra instruction - not a trampoline
            });
            f.block(3, |b| b.ret());
        });

        let trampolines = ssa.find_trampoline_blocks(false);
        assert_eq!(trampolines.len(), 1);
        assert_eq!(trampolines.get(&1), Some(&3));
    }

    #[test]
    fn test_find_trampoline_blocks_empty_result() {
        let ssa = SsaFunctionBuilder::new(2, 0).build_with(|f| {
            f.block(0, |b| {
                let _ = b.const_i32(1);
                b.ret();
            });
            f.block(1, |b| b.ret());
        });

        // No trampolines in this function
        let trampolines = ssa.find_trampoline_blocks(false);
        assert!(trampolines.is_empty());
    }

    #[test]
    fn test_iter_instructions_mut() {
        let mut ssa = SsaFunctionBuilder::new(1, 0).build_with(|f| {
            f.block(0, |b| {
                let c1 = b.const_i32(10);
                let c2 = b.const_i32(20);
                let _ = b.add(c1, c2);
                b.ret();
            });
        });

        // Count total instructions
        let count = ssa.iter_instructions().count();
        assert_eq!(count, 4); // 2 consts + 1 add + 1 ret

        // Use iter_instructions_mut to count and verify positions
        let mut positions: Vec<(usize, usize)> = Vec::new();
        for (block_idx, instr_idx, _instr) in ssa.iter_instructions_mut() {
            positions.push((block_idx, instr_idx));
        }

        // All instructions should be in block 0
        assert_eq!(positions.len(), 4);
        assert_eq!(positions[0], (0, 0));
        assert_eq!(positions[1], (0, 1));
        assert_eq!(positions[2], (0, 2));
        assert_eq!(positions[3], (0, 3));
    }

    #[test]
    fn test_iter_instructions_mut_across_blocks() {
        let mut ssa = SsaFunctionBuilder::new(2, 0).build_with(|f| {
            f.block(0, |b| {
                let _ = b.const_i32(1);
                b.jump(1);
            });
            f.block(1, |b| {
                let _ = b.const_i32(2);
                b.ret();
            });
        });

        let positions: Vec<(usize, usize)> = ssa
            .iter_instructions_mut()
            .map(|(b, i, _)| (b, i))
            .collect();

        assert_eq!(positions.len(), 4);
        // Block 0: const, jump
        assert_eq!(positions[0], (0, 0));
        assert_eq!(positions[1], (0, 1));
        // Block 1: const, ret
        assert_eq!(positions[2], (1, 0));
        assert_eq!(positions[3], (1, 1));
    }
}
