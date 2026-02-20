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

mod canonical;
mod duplication;
mod queries;
mod rebuild;
mod repair;
mod semantics;
mod transforms;

pub use queries::{MethodPurity, ReturnInfo};
pub use transforms::TrivialPhiOptions;

use std::{
    collections::{HashMap, HashSet},
    fmt,
};

use crate::{
    analysis::ssa::{
        exception::SsaExceptionHandler,
        verifier::{SsaVerifier, VerifyLevel},
        DefSite, FunctionVarAllocator, PhiNode, PhiOperand, SsaBlock, SsaInstruction, SsaOp,
        SsaType, SsaVarId, SsaVariable, VariableOrigin,
    },
    metadata::signatures::SignatureLocalVariable,
};

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

    /// All SSA variables in this function, densely indexed by `SsaVarId`.
    ///
    /// Invariant: `variables[i].id().index() == i` for all valid indices.
    /// This is maintained by `add_variable()` (which assigns dense IDs) and
    /// `compact_variables()` (which re-establishes density after removals).
    variables: Vec<SsaVariable>,

    /// Per-function allocator for dense variable IDs.
    var_allocator: FunctionVarAllocator,

    /// Maps each origin to its variable IDs, ordered by version.
    ///
    /// This enables O(1) lookup of all versions of a given origin
    /// (e.g., "all versions of Local(3)") without scanning all variables.
    origin_versions: HashMap<VariableOrigin, Vec<SsaVarId>>,

    /// Maps each variable origin to its canonical type.
    ///
    /// Populated during SSA construction from method signatures and instruction
    /// type inference. Used by [`create_variable_for_origin()`](Self::create_variable_for_origin)
    /// to ensure new variable versions always get proper types.
    origin_types: HashMap<VariableOrigin, SsaType>,

    /// Number of method arguments.
    num_args: usize,

    /// Number of local variables.
    num_locals: usize,

    /// Number of locals from the original method signature.
    original_num_locals: usize,

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

    /// Rename group for each variable, indexed by `SsaVarId::index()`.
    ///
    /// During SSA construction and rebuild, variables that share the same
    /// "version stack" for phi placement and renaming are assigned the same
    /// group ID. This separates the rename-grouping concern from
    /// `VariableOrigin`, which tracks provenance only.
    ///
    /// Group assignment (by converter/rebuild):
    /// - `Argument(i)` → group `i`
    /// - `Local(i)` → group `num_args + i`
    /// - Stack temp at depth D → group `num_args + num_locals + D`
    /// - Orphan/pass-created → auto-incrementing from max group + 1
    rename_groups: Vec<u32>,
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
            var_allocator: FunctionVarAllocator::new(),
            origin_versions: HashMap::new(),
            origin_types: HashMap::new(),
            num_args,
            num_locals,
            original_num_locals: num_locals,
            preserved_dispatch_vars: HashSet::new(),
            original_local_types: None,
            exception_handlers: Vec::new(),
            rename_groups: Vec::new(),
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
            var_allocator: FunctionVarAllocator::new(),
            origin_versions: HashMap::new(),
            origin_types: HashMap::new(),
            num_args,
            num_locals,
            original_num_locals: num_locals,
            preserved_dispatch_vars: HashSet::new(),
            original_local_types: None,
            exception_handlers: Vec::new(),
            rename_groups: Vec::with_capacity(var_capacity),
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

    /// Returns the number of locals from the original method signature.
    ///
    /// With the group-based rename system, this is always equal to `num_locals`
    /// since stack temporaries use `Phi` origin instead of inflated local indices.
    #[must_use]
    pub const fn original_num_locals(&self) -> usize {
        self.original_num_locals
    }

    /// Sets the total number of local variables.
    pub(crate) fn set_num_locals(&mut self, num_locals: usize, original_num_locals: usize) {
        self.num_locals = num_locals;
        self.original_num_locals = original_num_locals;
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

    /// Returns all variable IDs for a given origin, ordered by creation.
    ///
    /// This is O(1) via the version registry. For example,
    /// `versions_of(VariableOrigin::Local(3))` returns all SSA versions
    /// of local variable 3.
    #[must_use]
    pub fn versions_of(&self, origin: VariableOrigin) -> &[SsaVarId] {
        self.origin_versions
            .get(&origin)
            .map_or(&[], |v| v.as_slice())
    }

    /// Returns the most recently created variable ID for a given origin.
    #[must_use]
    pub fn latest_version(&self, origin: VariableOrigin) -> Option<SsaVarId> {
        self.origin_versions
            .get(&origin)
            .and_then(|v| v.last().copied())
    }

    /// Gets the local index for a variable ID.
    ///
    /// With dense IDs, this is always O(1) — the index equals `id.index()`.
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
        let idx = id.index();
        if idx < self.variables.len() {
            Some(idx)
        } else {
            None
        }
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

    /// Gets a variable by ID. O(1) via dense indexing.
    ///
    /// # Arguments
    ///
    /// * `id` - The variable ID to look up
    ///
    /// # Returns
    ///
    /// A reference to the variable, or `None` if the ID is out of bounds.
    #[must_use]
    pub fn variable(&self, id: SsaVarId) -> Option<&SsaVariable> {
        self.variables.get(id.index())
    }

    /// Gets a mutable variable by ID. O(1) via dense indexing.
    ///
    /// # Arguments
    ///
    /// * `id` - The variable ID to look up
    ///
    /// # Returns
    ///
    /// A mutable reference to the variable, or `None` if the ID is out of bounds.
    pub fn variable_mut(&mut self, id: SsaVarId) -> Option<&mut SsaVariable> {
        self.variables.get_mut(id.index())
    }

    /// Adds a block to this function.
    ///
    /// # Arguments
    ///
    /// * `block` - The block to add
    pub fn add_block(&mut self, block: SsaBlock) {
        self.blocks.push(block);
    }

    /// Creates a new variable with a dense ID allocated by this function.
    ///
    /// This is the **only** way to create variables. The ID is guaranteed to be
    /// dense (equal to the variable's index in the variables Vec), enabling
    /// O(1) lookup via direct indexing.
    ///
    /// If `var_type` is not `Unknown`, it is automatically registered in the
    /// origin type registry for future lookups.
    pub fn create_variable(
        &mut self,
        origin: VariableOrigin,
        version: u32,
        def_site: DefSite,
        var_type: SsaType,
    ) -> SsaVarId {
        let id = self.var_allocator.alloc();
        let var = SsaVariable::new(id, origin, version, def_site, var_type.clone());
        debug_assert_eq!(id.index(), self.variables.len());
        self.origin_versions.entry(origin).or_default().push(id);
        // Register origin type if known (first concrete type wins)
        if !var_type.is_unknown() && !self.origin_types.contains_key(&origin) {
            self.origin_types.insert(origin, var_type);
        }
        self.variables.push(var);
        // Extend rename_groups to keep it in sync (default u32::MAX = no group)
        if self.rename_groups.len() <= id.index() {
            self.rename_groups.resize(id.index() + 1, u32::MAX);
        }
        id
    }

    /// Creates a new variable, inferring its type from the origin type registry.
    ///
    /// This is a convenience method for creating new versions of variables
    /// whose origin type was previously registered. If no type is registered
    /// for the origin, the variable gets `SsaType::Unknown`.
    pub fn create_variable_for_origin(
        &mut self,
        origin: VariableOrigin,
        version: u32,
        def_site: DefSite,
    ) -> SsaVarId {
        let var_type = self.origin_type(origin);
        self.create_variable(origin, version, def_site, var_type)
    }

    /// Registers the canonical type for a variable origin.
    ///
    /// Only registers if the type is not `Unknown`. If a type is already
    /// registered for this origin, it is not overwritten (first wins).
    pub fn register_origin_type(&mut self, origin: VariableOrigin, var_type: SsaType) {
        if !var_type.is_unknown() && !self.origin_types.contains_key(&origin) {
            self.origin_types.insert(origin, var_type);
        }
    }

    /// Returns the registered type for a variable origin, or `SsaType::Unknown`.
    #[must_use]
    pub fn origin_type(&self, origin: VariableOrigin) -> SsaType {
        self.origin_types
            .get(&origin)
            .cloned()
            .unwrap_or(SsaType::Unknown)
    }

    /// Returns the origin type registry.
    #[must_use]
    pub fn origin_types(&self) -> &HashMap<VariableOrigin, SsaType> {
        &self.origin_types
    }

    /// Rebuilds the origin_versions registry from the current variables list.
    ///
    /// Called after operations that modify the variables list (compact, reindex).
    fn rebuild_origin_versions(&mut self) {
        self.origin_versions.clear();
        for var in &self.variables {
            self.origin_versions
                .entry(var.origin())
                .or_default()
                .push(var.id());
        }
    }

    /// Reassigns dense variable IDs after variable removal.
    ///
    /// This must be called after removing variables from `self.variables` to restore
    /// the dense indexing invariant (`variables[i].id().index() == i`).
    ///
    /// Returns a mapping from old IDs to new IDs for updating references.
    fn reassign_dense_ids(&mut self) -> HashMap<SsaVarId, SsaVarId> {
        let mut remap = HashMap::new();
        let old_groups = std::mem::take(&mut self.rename_groups);
        self.var_allocator = FunctionVarAllocator::starting_from(self.variables.len());
        let mut new_groups = vec![u32::MAX; self.variables.len()];
        for (index, var) in self.variables.iter_mut().enumerate() {
            let old_id = var.id();
            let new_id = SsaVarId::from_index(index);
            // Carry over the rename group from the old position
            if old_id.index() < old_groups.len() {
                new_groups[index] = old_groups[old_id.index()];
            }
            if old_id != new_id {
                remap.insert(old_id, new_id);
                var.set_id(new_id);
            }
        }
        self.rename_groups = new_groups;
        remap
    }

    /// Remaps all variable ID references in blocks (instructions, phi nodes, terminators)
    /// using the given old-to-new ID mapping.
    fn remap_var_ids_in_blocks(&mut self, remap: &HashMap<SsaVarId, SsaVarId>) {
        if remap.is_empty() {
            return;
        }
        let lookup = |id: SsaVarId| -> Option<SsaVarId> { remap.get(&id).copied() };
        let resolve = |id: SsaVarId| -> SsaVarId { remap.get(&id).copied().unwrap_or(id) };

        for block in &mut self.blocks {
            // Remap phi nodes
            for phi in block.phi_nodes_mut() {
                let old_result = phi.result();
                phi.set_result(resolve(old_result));
                for operand in phi.operands_mut() {
                    let old_value = operand.value();
                    *operand = PhiOperand::new(resolve(old_value), operand.predecessor());
                }
            }
            // Remap instructions using existing remap_variables
            for instr in block.instructions_mut() {
                let new_op = instr.op().remap_variables(lookup);
                instr.set_op(new_op);
            }
        }
        // Remap preserved_dispatch_vars
        let remapped_dispatch: HashSet<SsaVarId> = self
            .preserved_dispatch_vars
            .iter()
            .map(|id| resolve(*id))
            .collect();
        self.preserved_dispatch_vars = remapped_dispatch;
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

    /// Returns the rename group for a variable.
    ///
    /// Returns `u32::MAX` if no group has been assigned (the variable was
    /// created without a rename group, e.g. by a compiler pass).
    #[must_use]
    pub(crate) fn rename_group(&self, var_id: SsaVarId) -> u32 {
        self.rename_groups
            .get(var_id.index())
            .copied()
            .unwrap_or(u32::MAX)
    }

    /// Sets the rename group for a variable.
    ///
    /// Extends the `rename_groups` vector with `u32::MAX` if needed.
    pub(crate) fn set_rename_group(&mut self, var_id: SsaVarId, group: u32) {
        let idx = var_id.index();
        if idx >= self.rename_groups.len() {
            self.rename_groups.resize(idx + 1, u32::MAX);
        }
        self.rename_groups[idx] = group;
    }

    /// Rebuilds SSA form after CFG modifications (e.g., control flow unflattening).
    ///
    /// This method performs a complete SSA reconstruction using the standard
    /// Cytron et al. algorithm. See [`rebuild::SsaRebuilder`] for the
    /// individual phases.
    ///
    /// This is necessary because after passes like control flow unflattening,
    /// the CFG structure changes significantly and PHI nodes may reference
    /// variables from removed blocks or have incorrect operands.
    pub fn rebuild_ssa(&mut self) -> crate::Result<()> {
        if self.blocks.is_empty() {
            return Ok(());
        }
        rebuild::SsaRebuilder::new(self).rebuild()
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

    /// Validates that no meaningfully-used variable has `SsaType::Unknown`.
    ///
    /// This ensures that all variables whose values are actually consumed have a
    /// concrete type. Variables are considered NOT meaningfully used if:
    /// - They have no uses at all (dead variables, stripped by DCE)
    /// - Their only uses are in `Pop` instructions (value is discarded)
    /// - Their only uses are as phi operands where the phi result is also unused
    ///
    /// # Errors
    ///
    /// Returns `Err` with a description listing the first Unknown-typed
    /// variable that has meaningful uses.
    pub fn validate_types(&self) -> Result<(), String> {
        for var in &self.variables {
            if !var.var_type().is_unknown() || var.uses().is_empty() {
                continue;
            }

            // Check if all uses are in Pop instructions (value is discarded)
            let has_meaningful_use = var.uses().iter().any(|use_site| {
                if use_site.is_phi_operand {
                    // Phi operand — meaningful if the phi result is typed
                    return true;
                }
                if let Some(block) = self.block(use_site.block) {
                    if let Some(instr) = block.instruction(use_site.instruction) {
                        return !matches!(instr.op(), SsaOp::Pop { .. });
                    }
                }
                true // Conservative: assume meaningful if we can't check
            });

            if has_meaningful_use {
                return Err(format!(
                    "Variable {} (origin={:?}) has Unknown type but is used ({} uses)",
                    var.id(),
                    var.origin(),
                    var.uses().len()
                ));
            }
        }
        Ok(())
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
        let errors = SsaVerifier::new(self).verify(VerifyLevel::Standard);
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors
                .iter()
                .map(|e| e.to_string())
                .collect::<Vec<_>>()
                .join("; "))
        }
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
            ssa::{
                ConstValue, DefSite, PhiNode, PhiOperand, SsaBlock, SsaInstruction, SsaOp, SsaType,
                SsaVarId, UseSite, VariableOrigin,
            },
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

        let id1 = func.create_variable(
            VariableOrigin::Argument(0),
            0,
            DefSite::phi(0),
            SsaType::Unknown,
        );

        let id2 = func.create_variable(
            VariableOrigin::Local(0),
            0,
            DefSite::instruction(0, 0),
            SsaType::Unknown,
        );

        // IDs should be different
        assert_ne!(id1, id2);
        assert_eq!(func.variable_count(), 2);
    }

    #[test]
    fn test_ssa_function_variable_access() {
        let mut func = SsaFunction::new(1, 0);

        let id = func.create_variable(
            VariableOrigin::Argument(0),
            0,
            DefSite::phi(0),
            SsaType::Unknown,
        );

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
        func.create_variable(
            VariableOrigin::Argument(0),
            0,
            DefSite::phi(0),
            SsaType::Unknown,
        );

        // Add arg1 version 0
        func.create_variable(
            VariableOrigin::Argument(1),
            0,
            DefSite::phi(0),
            SsaType::Unknown,
        );

        // Add arg0 version 1 (redefinition)
        func.create_variable(
            VariableOrigin::Argument(0),
            1,
            DefSite::instruction(1, 0),
            SsaType::Unknown,
        );

        // Add local0 version 0
        func.create_variable(
            VariableOrigin::Local(0),
            0,
            DefSite::phi(0),
            SsaType::Unknown,
        );

        let args: Vec<_> = func.argument_variables().collect();
        assert_eq!(args.len(), 2); // Only version 0 of each arg
    }

    #[test]
    fn test_ssa_function_local_variables() {
        let mut func = SsaFunction::new(0, 2);

        func.create_variable(
            VariableOrigin::Local(0),
            0,
            DefSite::phi(0),
            SsaType::Unknown,
        );

        func.create_variable(
            VariableOrigin::Local(1),
            0,
            DefSite::phi(0),
            SsaType::Unknown,
        );

        // Add a non-local variable (phi origin) - should not be counted
        func.create_variable(VariableOrigin::Phi, 0, DefSite::phi(0), SsaType::Unknown);

        let locals: Vec<_> = func.local_variables().collect();
        assert_eq!(locals.len(), 2);
    }

    #[test]
    fn test_ssa_function_variables_from_argument() {
        let mut func = SsaFunction::new(2, 0);

        func.create_variable(
            VariableOrigin::Argument(0),
            0,
            DefSite::phi(0),
            SsaType::Unknown,
        );

        func.create_variable(
            VariableOrigin::Argument(0),
            1,
            DefSite::instruction(1, 0),
            SsaType::Unknown,
        );

        func.create_variable(
            VariableOrigin::Argument(1),
            0,
            DefSite::phi(0),
            SsaType::Unknown,
        );

        let arg0_vars: Vec<_> = func.variables_from_argument(0).collect();
        assert_eq!(arg0_vars.len(), 2);

        let arg1_vars: Vec<_> = func.variables_from_argument(1).collect();
        assert_eq!(arg1_vars.len(), 1);
    }

    #[test]
    fn test_ssa_function_total_phi_count() {
        let mut func = SsaFunction::new(0, 0);

        let mut block0 = SsaBlock::new(0);
        block0.add_phi(PhiNode::new(
            SsaVarId::from_index(0),
            VariableOrigin::Local(0),
        ));
        block0.add_phi(PhiNode::new(
            SsaVarId::from_index(1),
            VariableOrigin::Local(1),
        ));
        func.add_block(block0);

        let mut block1 = SsaBlock::new(1);
        block1.add_phi(PhiNode::new(
            SsaVarId::from_index(2),
            VariableOrigin::Local(0),
        ));
        func.add_block(block1);

        func.add_block(SsaBlock::new(2)); // No phis

        assert_eq!(func.phi_count(), 3);
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

        assert_eq!(func.instruction_count(), 3);
    }

    #[test]
    fn test_ssa_function_all_phi_nodes() {
        let mut func = SsaFunction::new(0, 0);

        let phi_result = SsaVarId::from_index(0);
        let phi_operand = SsaVarId::from_index(1);
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
        func.create_variable(
            VariableOrigin::Local(0),
            0,
            DefSite::instruction(0, 0),
            SsaType::Unknown,
        );

        // Variable with uses (live)
        let live_id = func.create_variable(
            VariableOrigin::Local(1),
            0,
            DefSite::instruction(0, 1),
            SsaType::Unknown,
        );
        func.variable_mut(live_id)
            .unwrap()
            .add_use(UseSite::instruction(0, 2));

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

        // Create a variable via create_variable (dense ID 0)
        let defined_id = func.create_variable(
            VariableOrigin::Local(0),
            0,
            DefSite::instruction(0, 0),
            SsaType::Unknown,
        );

        // Add a block with an instruction that defines the variable
        let mut block = SsaBlock::new(0);
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

        // Add an orphaned variable (not defined by any instruction, version > 0 so not entry)
        func.create_variable(
            VariableOrigin::Local(1),
            1,
            DefSite::instruction(0, 99),
            SsaType::Unknown,
        );

        assert_eq!(func.variable_count(), 2);

        // Compact should remove the orphaned variable
        let removed = func.compact_variables();
        assert_eq!(removed, 1);
        assert_eq!(func.variable_count(), 1);

        // The remaining variable should be the defined one (may have been remapped to index 0)
        assert!(func.variable(SsaVarId::from_index(0)).is_some());
    }

    #[test]
    fn test_compact_variables_preserves_entry_vars() {
        let mut func = SsaFunction::new(1, 1);

        // Add arg0 version 0 (entry definition - should be preserved even without instruction)
        let arg_id = func.create_variable(
            VariableOrigin::Argument(0),
            0,
            DefSite::entry(),
            SsaType::Unknown,
        );

        // Add local0 version 0 (entry definition - should be preserved)
        let local_id = func.create_variable(
            VariableOrigin::Local(0),
            0,
            DefSite::entry(),
            SsaType::Unknown,
        );

        // Add an orphaned variable (version > 0, not defined by any instruction)
        func.create_variable(
            VariableOrigin::Local(2),
            1,
            DefSite::instruction(0, 99),
            SsaType::Unknown,
        );

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

        // After compaction, dense IDs are reassigned: arg_id=0, local_id=1
        // arg_id was originally 0 and local_id was originally 1, so they stay the same
        assert!(func.variable(arg_id).is_some());
        assert!(func.variable(local_id).is_some());
    }

    #[test]
    fn test_find_constants_collects_all_const_instructions() {
        let ssa = SsaFunctionBuilder::new(1, 0)
            .build_with(|f| {
                f.block(0, |b| {
                    let c1 = b.const_i32(42);
                    let c2 = b.const_i32(100);
                    let _ = b.add(c1, c2);
                    b.ret();
                });
            })
            .unwrap();

        let constants = ssa.find_constants();
        assert_eq!(constants.len(), 2);

        // Verify we can look up constants by their variable IDs
        let values: Vec<_> = constants.values().collect();
        assert!(values.iter().any(|v| **v == ConstValue::I32(42)));
        assert!(values.iter().any(|v| **v == ConstValue::I32(100)));
    }

    #[test]
    fn test_find_constants_across_multiple_blocks() {
        let ssa = SsaFunctionBuilder::new(2, 0)
            .build_with(|f| {
                f.block(0, |b| {
                    let _ = b.const_i32(1);
                    b.jump(1);
                });
                f.block(1, |b| {
                    let _ = b.const_i32(2);
                    let _ = b.const_i32(3);
                    b.ret();
                });
            })
            .unwrap();

        let constants = ssa.find_constants();
        assert_eq!(constants.len(), 3);
    }

    #[test]
    fn test_find_constants_empty_when_no_constants() {
        let ssa = SsaFunctionBuilder::new(1, 0)
            .build_with(|f| {
                f.block(0, |b| {
                    b.ret();
                });
            })
            .unwrap();

        let constants = ssa.find_constants();
        assert!(constants.is_empty());
    }

    #[test]
    fn test_find_trampoline_blocks_in_chain() {
        let ssa = SsaFunctionBuilder::new(4, 0)
            .build_with(|f| {
                f.block(0, |b| b.jump(1)); // trampoline -> 1
                f.block(1, |b| b.jump(2)); // trampoline -> 2
                f.block(2, |b| b.jump(3)); // trampoline -> 3
                f.block(3, |b| b.ret()); // not a trampoline
            })
            .unwrap();

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
        let ssa = SsaFunctionBuilder::new(4, 0)
            .build_with(|f| {
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
            })
            .unwrap();

        let trampolines = ssa.find_trampoline_blocks(false);
        assert_eq!(trampolines.len(), 1);
        assert_eq!(trampolines.get(&1), Some(&3));
    }

    #[test]
    fn test_find_trampoline_blocks_empty_result() {
        let ssa = SsaFunctionBuilder::new(2, 0)
            .build_with(|f| {
                f.block(0, |b| {
                    let _ = b.const_i32(1);
                    b.ret();
                });
                f.block(1, |b| b.ret());
            })
            .unwrap();

        // No trampolines in this function
        let trampolines = ssa.find_trampoline_blocks(false);
        assert!(trampolines.is_empty());
    }

    #[test]
    fn test_iter_instructions_mut() {
        let mut ssa = SsaFunctionBuilder::new(1, 0)
            .build_with(|f| {
                f.block(0, |b| {
                    let c1 = b.const_i32(10);
                    let c2 = b.const_i32(20);
                    let _ = b.add(c1, c2);
                    b.ret();
                });
            })
            .unwrap();

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
        let mut ssa = SsaFunctionBuilder::new(2, 0)
            .build_with(|f| {
                f.block(0, |b| {
                    let _ = b.const_i32(1);
                    b.jump(1);
                });
                f.block(1, |b| {
                    let _ = b.const_i32(2);
                    b.ret();
                });
            })
            .unwrap();

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
