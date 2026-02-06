//! Def-Use Index for efficient SSA variable lookup.
//!
//! This module provides [`DefUseIndex`], a shared index structure that enables
//! efficient queries about variable definitions and uses across an SSA function.
//!
//! # Purpose
//!
//! While each `SsaVariable` tracks its own definition site and use sites, this
//! index provides additional views:
//!
//! - **Definitions by location**: What variables are defined in block B at instruction I?
//! - **Uses by location**: What variables are used in block B at instruction I?
//! - **All definitions in block**: All variables defined in block B
//! - **Unused variables**: Variables with no uses (candidates for elimination)
//! - **Defining operations**: What operation defines variable V? (with `build_with_ops`)
//!
//! # Basic Usage
//!
//! ```rust,ignore
//! use dotscope::analysis::{DefUseIndex, SsaFunction};
//!
//! let ssa: SsaFunction = /* ... */;
//! let index = DefUseIndex::build(&ssa);
//!
//! // Find all uses of variable v0
//! if let Some(uses) = index.uses_of(v0) {
//!     for use_site in uses {
//!         println!("v0 used at block {}, instr {}", use_site.block, use_site.instruction);
//!     }
//! }
//!
//! // Find variables defined at a specific instruction
//! for var_id in index.defs_at(block_idx, instr_idx) {
//!     println!("Variable {} defined here", var_id);
//! }
//!
//! // Check if a variable is dead (unused)
//! if index.is_unused(var_id) {
//!     println!("Variable {} can be eliminated", var_id);
//! }
//! ```
//!
//! # Building with Operations
//!
//! For passes that need to analyze the defining operation (e.g., constant folding,
//! pattern matching), use [`DefUseIndex::build_with_ops`]:
//!
//! ```rust,ignore
//! let index = DefUseIndex::build_with_ops(&ssa);
//!
//! // Get the defining operation for a variable
//! if let Some(op) = index.def_op(var_id) {
//!     match op {
//!         SsaOp::Add { left, right, .. } => { /* analyze operands */ }
//!         SsaOp::Const { value, .. } => { /* it's a constant */ }
//!         _ => {}
//!     }
//! }
//!
//! // Or get everything at once: (block, instruction, operation)
//! if let Some((block, instr, op)) = index.full_definition(var_id) {
//!     println!("Defined at B{}:{} by {:?}", block, instr, op);
//! }
//! ```

use std::collections::{HashMap, HashSet};

use crate::analysis::ssa::{DefSite, SsaFunction, SsaOp, SsaVarId, UseSite};

/// Location in the SSA function (block + instruction).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Location {
    /// Block index.
    pub block: usize,
    /// Instruction index within the block.
    pub instruction: usize,
}

impl Location {
    /// Creates a new location.
    #[must_use]
    pub const fn new(block: usize, instruction: usize) -> Self {
        Self { block, instruction }
    }
}

/// Index for efficient def-use queries on an SSA function.
///
/// This structure is built once from an `SsaFunction` and provides O(1) or O(k)
/// access to various def-use relationships (where k is the result size).
///
/// # Building with Operations
///
/// Use [`build_with_ops`](Self::build_with_ops) to also index the defining operations,
/// enabling efficient lookups via [`def_op`](Self::def_op) and
/// [`full_definition`](Self::full_definition).
///
/// ```rust,ignore
/// let index = DefUseIndex::build_with_ops(&ssa);
///
/// // Get block, instruction, and operation in one call
/// if let Some((block, instr, op)) = index.full_definition(var_id) {
///     println!("Defined at B{}:{} by {:?}", block, instr, op);
/// }
/// ```
#[derive(Debug, Clone, Default)]
pub struct DefUseIndex {
    /// Map from variable ID to its definition site.
    definitions: HashMap<SsaVarId, DefSite>,

    /// Map from variable ID to its use sites.
    uses: HashMap<SsaVarId, Vec<UseSite>>,

    /// Map from location to variables defined there.
    /// Key: (block_idx, instr_idx), Value: variables defined at that instruction.
    defs_at_location: HashMap<Location, Vec<SsaVarId>>,

    /// Map from location to variables used there.
    /// Key: (block_idx, instr_idx), Value: variables used at that instruction.
    uses_at_location: HashMap<Location, Vec<SsaVarId>>,

    /// Variables defined in each block (including phi nodes).
    defs_in_block: HashMap<usize, Vec<SsaVarId>>,

    /// Variables defined by phi nodes.
    phi_defs: HashSet<SsaVarId>,

    /// Variables with no uses (dead variables).
    unused_vars: HashSet<SsaVarId>,

    /// Total variable count.
    var_count: usize,

    /// Optional: defining operations for each variable.
    /// Populated when built with [`build_with_ops`](Self::build_with_ops).
    def_ops: Option<HashMap<SsaVarId, SsaOp>>,
}

impl DefUseIndex {
    /// Builds a def-use index from an SSA function.
    ///
    /// This is an O(n) operation where n is the total number of instructions
    /// and phi nodes in the function.
    ///
    /// # Arguments
    ///
    /// * `ssa` - The SSA function to index.
    ///
    /// # Returns
    ///
    /// A new `DefUseIndex` with all relationships computed.
    #[must_use]
    pub fn build(ssa: &SsaFunction) -> Self {
        let mut definitions = HashMap::new();
        let mut uses: HashMap<SsaVarId, Vec<UseSite>> = HashMap::new();
        let mut defs_at_location: HashMap<Location, Vec<SsaVarId>> = HashMap::new();
        let mut uses_at_location: HashMap<Location, Vec<SsaVarId>> = HashMap::new();
        let mut defs_in_block: HashMap<usize, Vec<SsaVarId>> = HashMap::new();
        let mut phi_defs = HashSet::new();

        // Collect from SsaVariables (the authoritative source)
        for var in ssa.variables() {
            let var_id = var.id();
            let def_site = var.def_site();

            definitions.insert(var_id, def_site);

            // Track phi definitions
            if def_site.is_phi() {
                phi_defs.insert(var_id);
            }

            // Track definitions by location
            if let Some(instr_idx) = def_site.instruction {
                let loc = Location::new(def_site.block, instr_idx);
                defs_at_location.entry(loc).or_default().push(var_id);
            }
            defs_in_block
                .entry(def_site.block)
                .or_default()
                .push(var_id);

            // Collect uses from the variable
            let var_uses: Vec<UseSite> = var.uses().to_vec();
            for use_site in &var_uses {
                let loc = Location::new(use_site.block, use_site.instruction);
                uses_at_location.entry(loc).or_default().push(var_id);
            }
            uses.insert(var_id, var_uses);
        }

        // Identify unused variables
        let unused_vars: HashSet<SsaVarId> = uses
            .iter()
            .filter(|(_, use_sites)| use_sites.is_empty())
            .map(|(var_id, _)| *var_id)
            .collect();

        Self {
            definitions,
            uses,
            defs_at_location,
            uses_at_location,
            defs_in_block,
            phi_defs,
            unused_vars,
            var_count: ssa.variable_count(),
            def_ops: None,
        }
    }

    /// Builds a def-use index with defining operations stored internally.
    ///
    /// This version indexes the defining operation for each variable, enabling
    /// efficient lookups via [`def_op`](Self::def_op) and
    /// [`full_definition`](Self::full_definition).
    ///
    /// Use this when passes need to analyze the defining operation alongside
    /// the definition site.
    ///
    /// # Arguments
    ///
    /// * `ssa` - The SSA function to index.
    ///
    /// # Returns
    ///
    /// A `DefUseIndex` with operations indexed.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let index = DefUseIndex::build_with_ops(&ssa);
    ///
    /// // Get the defining operation
    /// if let Some(op) = index.def_op(var_id) {
    ///     match op {
    ///         SsaOp::Add { left, right, .. } => { /* analyze add */ }
    ///         _ => {}
    ///     }
    /// }
    ///
    /// // Or get everything at once
    /// if let Some((block, instr, op)) = index.full_definition(var_id) {
    ///     println!("B{}:{} {:?}", block, instr, op);
    /// }
    /// ```
    #[must_use]
    pub fn build_with_ops(ssa: &SsaFunction) -> Self {
        let mut index = Self::build(ssa);

        // Collect defining operations
        let mut def_ops = HashMap::new();
        for (_block_idx, _instr_idx, instr) in ssa.iter_instructions() {
            let op = instr.op();
            if let Some(dest) = op.dest() {
                def_ops.insert(dest, op.clone());
            }
        }
        index.def_ops = Some(def_ops);

        index
    }

    /// Builds a def-use index with operations, also returning a separate map.
    ///
    /// This is a compatibility method for code that needs both the index
    /// and a separate operation map. Prefer [`build_with_ops`](Self::build_with_ops)
    /// for new code.
    ///
    /// # Arguments
    ///
    /// * `ssa` - The SSA function to index.
    ///
    /// # Returns
    ///
    /// A tuple of (`DefUseIndex`, operation map).
    #[must_use]
    pub fn build_with_ops_map(ssa: &SsaFunction) -> (Self, HashMap<SsaVarId, SsaOp>) {
        let index = Self::build_with_ops(ssa);
        let ops = index.def_ops.clone().unwrap_or_default();
        (index, ops)
    }

    /// Returns whether this index has operation information.
    ///
    /// Returns `true` if built with [`build_with_ops`](Self::build_with_ops).
    #[must_use]
    pub fn has_ops(&self) -> bool {
        self.def_ops.is_some()
    }

    /// Returns the defining operation for a variable.
    ///
    /// This method requires the index to be built with
    /// [`build_with_ops`](Self::build_with_ops).
    ///
    /// # Arguments
    ///
    /// * `var` - The variable ID to look up.
    ///
    /// # Returns
    ///
    /// The defining operation, or `None` if:
    /// - The variable is unknown
    /// - The variable is defined by a phi node (no operation)
    /// - The index was not built with operations
    #[must_use]
    pub fn def_op(&self, var: SsaVarId) -> Option<&SsaOp> {
        self.def_ops.as_ref()?.get(&var)
    }

    /// Returns full definition information: block, instruction index, and operation.
    ///
    /// This is a convenience method for passes that need all three pieces of
    /// information together. Requires the index to be built with
    /// [`build_with_ops`](Self::build_with_ops).
    ///
    /// # Arguments
    ///
    /// * `var` - The variable ID to look up.
    ///
    /// # Returns
    ///
    /// A tuple of `(block_index, instruction_index, operation)`, or `None` if:
    /// - The variable is unknown
    /// - The variable is defined by a phi node (no instruction index)
    /// - The index was not built with operations
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let index = DefUseIndex::build_with_ops(&ssa);
    ///
    /// if let Some((block, instr, op)) = index.full_definition(var_id) {
    ///     // Check if this is an add of two constants
    ///     if let SsaOp::Add { left, right, .. } = op {
    ///         let left_const = index.def_op(*left);
    ///         let right_const = index.def_op(*right);
    ///         // ...
    ///     }
    /// }
    /// ```
    #[must_use]
    pub fn full_definition(&self, var: SsaVarId) -> Option<(usize, usize, &SsaOp)> {
        let site = self.def_site(var)?;
        let instr = site.instruction?; // None for phi nodes
        let op = self.def_op(var)?;
        Some((site.block, instr, op))
    }

    /// Returns the definition site for a variable.
    ///
    /// # Arguments
    ///
    /// * `var` - The variable ID to look up.
    ///
    /// # Returns
    ///
    /// The definition site, or `None` if the variable is unknown.
    #[must_use]
    pub fn def_site(&self, var: SsaVarId) -> Option<DefSite> {
        self.definitions.get(&var).copied()
    }

    /// Returns all use sites for a variable.
    ///
    /// # Arguments
    ///
    /// * `var` - The variable ID to look up.
    ///
    /// # Returns
    ///
    /// A slice of use sites, or `None` if the variable is unknown.
    #[must_use]
    pub fn uses_of(&self, var: SsaVarId) -> Option<&[UseSite]> {
        self.uses.get(&var).map(Vec::as_slice)
    }

    /// Returns the number of uses for a variable.
    ///
    /// # Arguments
    ///
    /// * `var` - The variable ID to count uses for.
    ///
    /// # Returns
    ///
    /// The use count, or 0 if the variable is unknown.
    #[must_use]
    pub fn use_count(&self, var: SsaVarId) -> usize {
        self.uses.get(&var).map_or(0, Vec::len)
    }

    /// Checks if a variable has any uses.
    ///
    /// # Arguments
    ///
    /// * `var` - The variable ID to check.
    ///
    /// # Returns
    ///
    /// `true` if the variable has at least one use.
    #[must_use]
    pub fn has_uses(&self, var: SsaVarId) -> bool {
        self.uses.get(&var).is_some_and(|u| !u.is_empty())
    }

    /// Checks if a variable is unused (dead).
    ///
    /// # Arguments
    ///
    /// * `var` - The variable ID to check.
    ///
    /// # Returns
    ///
    /// `true` if the variable has no uses.
    #[must_use]
    pub fn is_unused(&self, var: SsaVarId) -> bool {
        self.unused_vars.contains(&var)
    }

    /// Checks if a variable is defined by a phi node.
    ///
    /// # Arguments
    ///
    /// * `var` - The variable ID to check.
    ///
    /// # Returns
    ///
    /// `true` if the variable is defined by a phi node.
    #[must_use]
    pub fn is_phi_def(&self, var: SsaVarId) -> bool {
        self.phi_defs.contains(&var)
    }

    /// Returns variables defined at a specific location.
    ///
    /// # Arguments
    ///
    /// * `block` - The block index.
    /// * `instruction` - The instruction index within the block.
    ///
    /// # Returns
    ///
    /// A slice of variable IDs defined at that location.
    #[must_use]
    pub fn defs_at(&self, block: usize, instruction: usize) -> &[SsaVarId] {
        let loc = Location::new(block, instruction);
        self.defs_at_location.get(&loc).map_or(&[], Vec::as_slice)
    }

    /// Returns variables used at a specific location.
    ///
    /// # Arguments
    ///
    /// * `block` - The block index.
    /// * `instruction` - The instruction index within the block.
    ///
    /// # Returns
    ///
    /// A slice of variable IDs used at that location.
    #[must_use]
    pub fn uses_at(&self, block: usize, instruction: usize) -> &[SsaVarId] {
        let loc = Location::new(block, instruction);
        self.uses_at_location.get(&loc).map_or(&[], Vec::as_slice)
    }

    /// Returns all variables defined in a block.
    ///
    /// This includes both phi node definitions and instruction definitions.
    ///
    /// # Arguments
    ///
    /// * `block` - The block index.
    ///
    /// # Returns
    ///
    /// A slice of variable IDs defined in the block.
    #[must_use]
    pub fn defs_in_block(&self, block: usize) -> &[SsaVarId] {
        self.defs_in_block.get(&block).map_or(&[], Vec::as_slice)
    }

    /// Returns all unused (dead) variables.
    ///
    /// These are candidates for dead code elimination.
    ///
    /// # Returns
    ///
    /// A reference to the set of unused variable IDs.
    #[must_use]
    pub fn unused_variables(&self) -> &HashSet<SsaVarId> {
        &self.unused_vars
    }

    /// Returns all phi-defined variables.
    ///
    /// # Returns
    ///
    /// A reference to the set of phi-defined variable IDs.
    #[must_use]
    pub fn phi_definitions(&self) -> &HashSet<SsaVarId> {
        &self.phi_defs
    }

    /// Returns the total number of variables indexed.
    #[must_use]
    pub fn variable_count(&self) -> usize {
        self.var_count
    }

    /// Returns the number of unused variables.
    #[must_use]
    pub fn unused_count(&self) -> usize {
        self.unused_vars.len()
    }

    /// Checks if a variable has a single use.
    ///
    /// Single-use variables are good candidates for inlining.
    ///
    /// # Arguments
    ///
    /// * `var` - The variable ID to check.
    ///
    /// # Returns
    ///
    /// `true` if the variable has exactly one use.
    #[must_use]
    pub fn is_single_use(&self, var: SsaVarId) -> bool {
        self.use_count(var) == 1
    }

    /// Checks if a variable is only used in phi nodes.
    ///
    /// # Arguments
    ///
    /// * `var` - The variable ID to check.
    ///
    /// # Returns
    ///
    /// `true` if all uses are phi node operands.
    #[must_use]
    pub fn only_used_in_phis(&self, var: SsaVarId) -> bool {
        self.uses
            .get(&var)
            .is_some_and(|uses| !uses.is_empty() && uses.iter().all(|u| u.is_phi_operand))
    }

    /// Returns all variables used in a block.
    ///
    /// This is computed by scanning all use locations in the block.
    ///
    /// # Arguments
    ///
    /// * `block` - The block index.
    ///
    /// # Returns
    ///
    /// A set of variable IDs used anywhere in the block.
    #[must_use]
    pub fn uses_in_block(&self, block: usize) -> HashSet<SsaVarId> {
        let mut result = HashSet::new();
        for (loc, vars) in &self.uses_at_location {
            if loc.block == block {
                result.extend(vars.iter().copied());
            }
        }
        result
    }

    /// Finds the unique use site if a variable has exactly one use.
    ///
    /// # Arguments
    ///
    /// * `var` - The variable ID to check.
    ///
    /// # Returns
    ///
    /// The single use site, or `None` if the variable has zero or multiple uses.
    #[must_use]
    pub fn single_use_site(&self, var: SsaVarId) -> Option<UseSite> {
        self.uses
            .get(&var)
            .and_then(|uses| if uses.len() == 1 { Some(uses[0]) } else { None })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::ssa::{
        ConstValue, SsaBlock, SsaFunction, SsaInstruction, SsaOp, SsaVarId, SsaVariable,
        VariableOrigin,
    };

    /// Helper to create test SSA and return variable IDs for assertions
    fn make_test_ssa() -> (SsaFunction, SsaVarId, SsaVarId) {
        // Create a simple SSA function:
        // Block 0:
        //   v0 = const 42
        //   v1 = add v0, v0
        //   ret v1
        let mut ssa = SsaFunction::new(0, 0);

        // Create variables first to get their IDs
        let mut v0 = SsaVariable::new(VariableOrigin::Stack(0), 0, DefSite::instruction(0, 0));
        let id0 = v0.id();
        v0.add_use(UseSite::instruction(0, 1));
        v0.add_use(UseSite::instruction(0, 1)); // Used twice in add
        ssa.variables_mut().push(v0);

        let mut v1 = SsaVariable::new(VariableOrigin::Stack(1), 0, DefSite::instruction(0, 1));
        let id1 = v1.id();
        v1.add_use(UseSite::instruction(0, 2));
        ssa.variables_mut().push(v1);

        // Now create block with instructions using the auto-allocated IDs
        let mut block = SsaBlock::new(0);

        // v0 = const 42
        block.add_instruction(SsaInstruction::synthetic(SsaOp::Const {
            dest: id0,
            value: ConstValue::I32(42),
        }));

        // v1 = add v0, v0
        block.add_instruction(SsaInstruction::synthetic(SsaOp::Add {
            dest: id1,
            left: id0,
            right: id0,
        }));

        // ret v1
        block.add_instruction(SsaInstruction::synthetic(SsaOp::Return {
            value: Some(id1),
        }));

        ssa.add_block(block);

        (ssa, id0, id1)
    }

    #[test]
    fn test_build_index() {
        let (ssa, _id0, _id1) = make_test_ssa();
        let index = DefUseIndex::build(&ssa);

        assert_eq!(index.variable_count(), 2);
    }

    #[test]
    fn test_def_site_lookup() {
        let (ssa, id0, id1) = make_test_ssa();
        let index = DefUseIndex::build(&ssa);

        let def0 = index.def_site(id0).unwrap();
        assert_eq!(def0.block, 0);
        assert_eq!(def0.instruction, Some(0));

        let def1 = index.def_site(id1).unwrap();
        assert_eq!(def1.block, 0);
        assert_eq!(def1.instruction, Some(1));
    }

    #[test]
    fn test_uses_of() {
        let (ssa, id0, id1) = make_test_ssa();
        let index = DefUseIndex::build(&ssa);

        // v0 is used twice
        let uses0 = index.uses_of(id0).unwrap();
        assert_eq!(uses0.len(), 2);

        // v1 is used once
        let uses1 = index.uses_of(id1).unwrap();
        assert_eq!(uses1.len(), 1);
    }

    #[test]
    fn test_use_count() {
        let (ssa, id0, id1) = make_test_ssa();
        let index = DefUseIndex::build(&ssa);

        assert_eq!(index.use_count(id0), 2);
        assert_eq!(index.use_count(id1), 1);
        assert_eq!(index.use_count(SsaVarId::from_index(999999)), 0); // Unknown var
    }

    #[test]
    fn test_defs_at_location() {
        let (ssa, id0, id1) = make_test_ssa();
        let index = DefUseIndex::build(&ssa);

        let defs_0_0 = index.defs_at(0, 0);
        assert_eq!(defs_0_0.len(), 1);
        assert!(defs_0_0.contains(&id0));

        let defs_0_1 = index.defs_at(0, 1);
        assert_eq!(defs_0_1.len(), 1);
        assert!(defs_0_1.contains(&id1));

        // No defs at ret instruction
        let defs_0_2 = index.defs_at(0, 2);
        assert!(defs_0_2.is_empty());
    }

    #[test]
    fn test_uses_at_location() {
        let (ssa, id0, id1) = make_test_ssa();
        let index = DefUseIndex::build(&ssa);

        // v0 used at instruction 1
        let uses_0_1 = index.uses_at(0, 1);
        assert!(uses_0_1.contains(&id0));

        // v1 used at instruction 2
        let uses_0_2 = index.uses_at(0, 2);
        assert!(uses_0_2.contains(&id1));
    }

    #[test]
    fn test_defs_in_block() {
        let (ssa, id0, id1) = make_test_ssa();
        let index = DefUseIndex::build(&ssa);

        let defs = index.defs_in_block(0);
        assert_eq!(defs.len(), 2);
        assert!(defs.contains(&id0));
        assert!(defs.contains(&id1));
    }

    #[test]
    fn test_unused_variables() {
        // Create SSA with an unused variable
        let mut ssa = SsaFunction::new(0, 0);
        let mut block = SsaBlock::new(0);

        let dest0 = SsaVarId::new();
        let dest1 = SsaVarId::new();
        block.add_instruction(SsaInstruction::synthetic(SsaOp::Const {
            dest: dest0,
            value: ConstValue::I32(42),
        }));
        block.add_instruction(SsaInstruction::synthetic(SsaOp::Const {
            dest: dest1,
            value: ConstValue::I32(0),
        }));
        block.add_instruction(SsaInstruction::synthetic(SsaOp::Return {
            value: Some(dest1),
        }));

        ssa.add_block(block);

        // v0: defined but never used
        let v0 = SsaVariable::new(VariableOrigin::Stack(0), 0, DefSite::instruction(0, 0));
        let v0_id = v0.id();
        ssa.variables_mut().push(v0);

        // v1: defined and used
        let mut v1 = SsaVariable::new(VariableOrigin::Stack(1), 0, DefSite::instruction(0, 1));
        let v1_id = v1.id();
        v1.add_use(UseSite::instruction(0, 2));
        ssa.variables_mut().push(v1);

        let index = DefUseIndex::build(&ssa);

        assert!(index.is_unused(v0_id));
        assert!(!index.is_unused(v1_id));
        assert_eq!(index.unused_count(), 1);
        assert!(index.unused_variables().contains(&v0_id));
    }

    #[test]
    fn test_single_use() {
        let (ssa, v0_id, v1_id) = make_test_ssa();
        let index = DefUseIndex::build(&ssa);

        // v0 has 2 uses -> not single use
        assert!(!index.is_single_use(v0_id));

        // v1 has 1 use -> single use
        assert!(index.is_single_use(v1_id));

        // Get the single use site
        let use_site = index.single_use_site(v1_id).unwrap();
        assert_eq!(use_site.block, 0);
        assert_eq!(use_site.instruction, 2);

        // v0 doesn't have single use site
        assert!(index.single_use_site(v0_id).is_none());
    }

    #[test]
    fn test_phi_definitions() {
        let mut ssa = SsaFunction::new(0, 0);
        let block = SsaBlock::new(0);
        ssa.add_block(block);

        // v0: phi definition
        let v0 = SsaVariable::new(VariableOrigin::Phi, 0, DefSite::phi(0));
        let v0_id = v0.id();
        ssa.variables_mut().push(v0);

        // v1: instruction definition
        let v1 = SsaVariable::new(VariableOrigin::Stack(0), 0, DefSite::instruction(0, 0));
        let v1_id = v1.id();
        ssa.variables_mut().push(v1);

        let index = DefUseIndex::build(&ssa);

        assert!(index.is_phi_def(v0_id));
        assert!(!index.is_phi_def(v1_id));
        assert!(index.phi_definitions().contains(&v0_id));
    }

    #[test]
    fn test_uses_in_block() {
        let (ssa, v0_id, v1_id) = make_test_ssa();
        let index = DefUseIndex::build(&ssa);

        let uses = index.uses_in_block(0);
        assert!(uses.contains(&v0_id));
        assert!(uses.contains(&v1_id));
    }

    #[test]
    fn test_default() {
        let index = DefUseIndex::default();
        assert_eq!(index.variable_count(), 0);
        assert_eq!(index.unused_count(), 0);
    }

    #[test]
    fn test_build_without_ops() {
        let (ssa, id0, _id1) = make_test_ssa();
        let index = DefUseIndex::build(&ssa);

        // Index built without ops should not have operations
        assert!(!index.has_ops());
        assert!(index.def_op(id0).is_none());
        assert!(index.full_definition(id0).is_none());
    }

    #[test]
    fn test_build_with_ops() {
        let (ssa, id0, id1) = make_test_ssa();
        let index = DefUseIndex::build_with_ops(&ssa);

        // Index built with ops should have operations
        assert!(index.has_ops());

        // Check v0's defining operation (const 42)
        let op0 = index.def_op(id0).unwrap();
        assert!(matches!(op0, SsaOp::Const { value, .. } if value.as_i32() == Some(42)));

        // Check v1's defining operation (add)
        let op1 = index.def_op(id1).unwrap();
        assert!(matches!(op1, SsaOp::Add { .. }));
    }

    #[test]
    fn test_full_definition() {
        let (ssa, id0, id1) = make_test_ssa();
        let index = DefUseIndex::build_with_ops(&ssa);

        // v0 = const 42 at block 0, instruction 0
        let (block0, instr0, op0) = index.full_definition(id0).unwrap();
        assert_eq!(block0, 0);
        assert_eq!(instr0, 0);
        assert!(matches!(op0, SsaOp::Const { .. }));

        // v1 = add at block 0, instruction 1
        let (block1, instr1, op1) = index.full_definition(id1).unwrap();
        assert_eq!(block1, 0);
        assert_eq!(instr1, 1);
        assert!(matches!(op1, SsaOp::Add { .. }));
    }

    #[test]
    fn test_full_definition_phi_returns_none() {
        let mut ssa = SsaFunction::new(0, 0);
        let block = SsaBlock::new(0);
        ssa.add_block(block);

        // v0: phi definition (no instruction index)
        let v0 = SsaVariable::new(VariableOrigin::Phi, 0, DefSite::phi(0));
        let v0_id = v0.id();
        ssa.variables_mut().push(v0);

        let index = DefUseIndex::build_with_ops(&ssa);

        // Phi definitions should return None from full_definition
        // (because there's no instruction index)
        assert!(index.full_definition(v0_id).is_none());

        // But def_site still works
        let site = index.def_site(v0_id).unwrap();
        assert_eq!(site.block, 0);
        assert!(site.instruction.is_none());
    }

    #[test]
    fn test_build_with_ops_map_compatibility() {
        let (ssa, id0, id1) = make_test_ssa();
        let (index, ops) = DefUseIndex::build_with_ops_map(&ssa);

        // The index should have ops internally
        assert!(index.has_ops());

        // The returned map should have the same ops
        assert!(ops.contains_key(&id0));
        assert!(ops.contains_key(&id1));

        // Both should match
        let op0_from_index = index.def_op(id0).unwrap();
        let op0_from_map = ops.get(&id0).unwrap();
        assert!(matches!(op0_from_index, SsaOp::Const { .. }));
        assert!(matches!(op0_from_map, SsaOp::Const { .. }));
    }
}
