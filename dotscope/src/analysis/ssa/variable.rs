//! SSA variable representation and identifiers.
//!
//! This module defines the core types for representing variables in SSA form.
//! Each SSA variable has a unique identifier and is assigned exactly once,
//! enabling precise tracking of data flow through the program.
//!
//! # Design Rationale
//!
//! ## Variable Identification
//!
//! SSA variables are identified by a simple index ([`SsaVarId`]) into a variable
//! table. This provides O(1) lookup and minimal memory overhead. The ID encodes
//! no semantic information - all variable metadata is stored in [`SsaVariable`].
//!
//! ## Variable Origins
//!
//! CIL has three primary sources of values that become SSA variables:
//!
//! 1. **Arguments** - Method parameters passed by the caller
//! 2. **Locals** - Local variables declared in the method
//! 3. **Stack temporaries** - Values pushed/popped during evaluation
//!
//! Additionally, phi nodes at control flow merge points create new variables.
//!
//! ## Address-Taken Variables
//!
//! Variables whose address is taken (`ldarga`, `ldloca`) are marked specially.
//! These variables may be modified through pointers and thus cannot participate
//! in certain SSA optimizations. We track this conservatively.
//!
//! # Thread Safety
//!
//! All types in this module are `Send` and `Sync` when their generic parameters
//! (if any) are also `Send` and `Sync`.

use std::fmt;

use crate::analysis::ssa::SsaType;

/// Unique identifier for an SSA variable.
///
/// This is a lightweight handle into the variable table, providing O(1) access
/// to variable metadata. Variable IDs are dense and sequential within each
/// [`SsaFunction`](crate::analysis::SsaFunction) (0, 1, 2, ...), enabling
/// direct indexing into the variables vector.
///
/// # Memory Layout
///
/// Uses `usize` internally to match native indexing, avoiding conversions
/// when accessing variable tables.
///
/// # Construction
///
/// Variable IDs are allocated by [`FunctionVarAllocator`] through
/// [`SsaFunction::create_variable()`](crate::analysis::SsaFunction::create_variable).
/// Use [`SsaVarId::from_index()`] only to reconstruct IDs from stored indices.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct SsaVarId(usize);

impl SsaVarId {
    /// A sentinel value representing an uninitialized or placeholder variable ID.
    ///
    /// This is used during phi placement and other construction phases where a
    /// real variable ID hasn't been assigned yet. Placeholder IDs must be replaced
    /// with real IDs before the SSA function is finalized.
    pub const PLACEHOLDER: Self = Self(usize::MAX);

    /// Returns `true` if this is the placeholder sentinel value.
    #[must_use]
    pub const fn is_placeholder(self) -> bool {
        self.0 == usize::MAX
    }

    /// Creates an `SsaVarId` from an index value.
    ///
    /// This is the primary way to construct variable IDs. In production code,
    /// IDs are allocated by [`FunctionVarAllocator`] to ensure dense, sequential
    /// numbering within each function. This method is also used to reconstruct
    /// IDs from stored indices (e.g., in BitSets).
    ///
    /// # Arguments
    ///
    /// * `index` - The index value for this variable ID
    #[must_use]
    pub const fn from_index(index: usize) -> Self {
        Self(index)
    }

    /// Returns the underlying index.
    ///
    /// In production code, this index is dense and contiguous within a function
    /// (0, 1, 2, ...), enabling O(1) lookup via `variables[id.index()]`.
    #[must_use]
    pub const fn index(self) -> usize {
        self.0
    }
}

impl fmt::Debug for SsaVarId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "v{}", self.0)
    }
}

impl fmt::Display for SsaVarId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "v{}", self.0)
    }
}

/// The origin of an SSA variable - where it came from in the original CIL.
///
/// This enum tracks the semantic source of each SSA variable, which is useful
/// for debugging, optimization decisions, and mapping back to source code.
///
/// # CIL Variable Mapping
///
/// | CIL Instruction | Variable Origin |
/// |-----------------|-----------------|
/// | `ldarg.N`, `ldarg.s`, `ldarg` | `Argument(N)` |
/// | `ldloc.N`, `ldloc.s`, `ldloc` | `Local(N)` |
/// | Stack operations (add, call, etc.) | `Local(num_locals + K)` |
/// | Phi node result | `Phi` |
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::analysis::VariableOrigin;
///
/// let arg_origin = VariableOrigin::Argument(0);  // First method argument
/// let local_origin = VariableOrigin::Local(2);   // Third local variable
/// let phi_origin = VariableOrigin::Phi;          // From phi node
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum VariableOrigin {
    /// Method argument (parameter).
    ///
    /// The index corresponds to the argument's position in the method signature.
    /// For instance methods, argument 0 is `this`.
    Argument(u16),

    /// Local variable declared in the method.
    ///
    /// The index corresponds to the local's position in the local variable
    /// signature (accessed via `ldloc`/`stloc`). `Local(idx)` always refers
    /// to a real CIL local. Stack temporaries and other synthetics use
    /// `Phi` origin instead.
    Local(u16),

    /// Result of a phi node at a control flow merge.
    ///
    /// Phi nodes are synthetic - they don't correspond to any CIL instruction
    /// but rather represent the merging of values from different control flow paths.
    Phi,
}

impl VariableOrigin {
    /// Returns `true` if this is an argument origin.
    #[must_use]
    pub const fn is_argument(&self) -> bool {
        matches!(self, Self::Argument(_))
    }

    /// Returns `true` if this is a local variable origin.
    #[must_use]
    pub const fn is_local(&self) -> bool {
        matches!(self, Self::Local(_))
    }

    /// Returns `true` if this is a phi node result.
    #[must_use]
    pub const fn is_phi(&self) -> bool {
        matches!(self, Self::Phi)
    }

    /// Returns the argument index if this is an argument origin.
    #[must_use]
    pub const fn argument_index(&self) -> Option<u16> {
        match self {
            Self::Argument(idx) => Some(*idx),
            _ => None,
        }
    }

    /// Returns the local index if this is a local variable origin.
    #[must_use]
    pub const fn local_index(&self) -> Option<u16> {
        match self {
            Self::Local(idx) => Some(*idx),
            _ => None,
        }
    }
}

impl fmt::Display for VariableOrigin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Argument(idx) => write!(f, "arg{idx}"),
            Self::Local(idx) => write!(f, "loc{idx}"),
            Self::Phi => write!(f, "phi"),
        }
    }
}

/// Per-function allocator for dense, contiguous SSA variable IDs.
///
/// Unlike the global `SsaVarId::from_index(0)` counter, this allocator produces IDs
/// starting from 0 that are contiguous within a single function. This enables
/// O(1) variable lookup via direct vector indexing: `variables[id.index()]`.
///
/// # Usage
///
/// ```rust,ignore
/// let mut alloc = FunctionVarAllocator::new();
/// let id0 = alloc.alloc(); // SsaVarId(0)
/// let id1 = alloc.alloc(); // SsaVarId(1)
/// assert_eq!(alloc.count(), 2);
/// ```
#[derive(Debug, Clone)]
pub struct FunctionVarAllocator {
    next_id: usize,
}

impl FunctionVarAllocator {
    /// Creates a new allocator starting from ID 0.
    #[must_use]
    pub fn new() -> Self {
        Self { next_id: 0 }
    }

    /// Creates a new allocator starting from a specific ID.
    ///
    /// Used when resuming allocation after compaction or when
    /// variables already exist with IDs 0..start_id.
    #[must_use]
    pub fn starting_from(start_id: usize) -> Self {
        Self { next_id: start_id }
    }

    /// Allocates the next dense variable ID.
    pub fn alloc(&mut self) -> SsaVarId {
        let id = SsaVarId::from_index(self.next_id);
        self.next_id = self.next_id.saturating_add(1);
        id
    }

    /// Returns the number of IDs allocated so far.
    #[must_use]
    pub fn count(&self) -> usize {
        self.next_id
    }
}

impl Default for FunctionVarAllocator {
    fn default() -> Self {
        Self::new()
    }
}

/// Definition site of an SSA variable.
///
/// Records where in the program a variable is defined. For most variables,
/// this is a specific instruction within a block. For phi nodes, the definition
/// is at the block entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DefSite {
    /// The block where this variable is defined.
    pub block: usize,
    /// The instruction index within the block, or `None` for phi nodes.
    ///
    /// Phi nodes are considered to be defined at the "top" of the block,
    /// before any real instructions execute.
    pub instruction: Option<usize>,
}

impl DefSite {
    /// Creates a definition site for a regular instruction.
    #[must_use]
    pub const fn instruction(block: usize, instr_idx: usize) -> Self {
        Self {
            block,
            instruction: Some(instr_idx),
        }
    }

    /// Creates a definition site for a phi node (at block entry).
    #[must_use]
    pub const fn phi(block: usize) -> Self {
        Self {
            block,
            instruction: None,
        }
    }

    /// Creates a definition site for function entry (arguments and initialized locals).
    ///
    /// These are defined at the entry block (block 0) before any instructions.
    #[must_use]
    pub const fn entry() -> Self {
        Self {
            block: 0,
            instruction: None,
        }
    }

    /// Returns `true` if this is a phi node definition.
    #[must_use]
    pub const fn is_phi(&self) -> bool {
        self.instruction.is_none()
    }
}

/// Use site of an SSA variable.
///
/// Records where in the program a variable is used (read).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UseSite {
    /// The block where this variable is used.
    pub block: usize,
    /// The instruction index within the block.
    ///
    /// For phi node operands, this refers to the phi node's index in the
    /// block's phi node list (not the instruction list).
    pub instruction: usize,
    /// Whether this use is in a phi node operand.
    pub is_phi_operand: bool,
}

impl UseSite {
    /// Creates a use site for a regular instruction.
    #[must_use]
    pub const fn instruction(block: usize, instr_idx: usize) -> Self {
        Self {
            block,
            instruction: instr_idx,
            is_phi_operand: false,
        }
    }

    /// Creates a use site for a phi node operand.
    #[must_use]
    pub const fn phi_operand(block: usize, phi_idx: usize) -> Self {
        Self {
            block,
            instruction: phi_idx,
            is_phi_operand: true,
        }
    }
}

/// Complete metadata for an SSA variable.
///
/// Each SSA variable has exactly one definition point and zero or more use
/// points. This structure tracks all the metadata needed for analysis and
/// optimization.
///
/// # Construction
///
/// Variables are created exclusively through [`SsaFunction::create_variable()`](crate::analysis::SsaFunction::create_variable),
/// which ensures dense ID allocation and proper type assignment.
#[derive(Debug, Clone)]
pub struct SsaVariable {
    /// Unique identifier for this variable.
    id: SsaVarId,

    /// Where this variable originated in the CIL.
    origin: VariableOrigin,

    /// SSA version number for this variable.
    ///
    /// For arguments and locals, multiple versions exist (one per assignment).
    /// The version number distinguishes between them. Version 0 is typically
    /// the initial value at method entry.
    version: u32,

    /// Where this variable is defined.
    def_site: DefSite,

    /// The type of this variable.
    ///
    /// This is inferred from the operation that defines the variable.
    /// Initially `SsaType::Unknown` if type inference hasn't been performed.
    var_type: SsaType,

    /// All places where this variable is used.
    ///
    /// This is computed during SSA construction and enables dead code
    /// elimination and other use-based analyses.
    uses: Vec<UseSite>,

    /// Whether this variable's address has been taken.
    ///
    /// If `true`, this variable may be modified through a pointer and
    /// cannot participate in certain optimizations. Set when `ldarga`
    /// or `ldloca` is encountered for the corresponding argument/local.
    address_taken: bool,
}

impl SsaVariable {
    /// Creates a new SSA variable with a pre-allocated ID and type.
    ///
    /// This is `pub(crate)` because variables should only be created through
    /// [`SsaFunction::create_variable()`](crate::analysis::SsaFunction::create_variable)
    /// which ensures dense ID allocation via [`FunctionVarAllocator`].
    ///
    /// # Arguments
    ///
    /// * `id` - The dense variable ID from [`FunctionVarAllocator`]
    /// * `origin` - Where this variable came from in the CIL
    /// * `version` - SSA version number
    /// * `def_site` - Where this variable is defined
    /// * `var_type` - The type of this variable
    #[must_use]
    pub(crate) fn new(
        id: SsaVarId,
        origin: VariableOrigin,
        version: u32,
        def_site: DefSite,
        var_type: SsaType,
    ) -> Self {
        Self {
            id,
            origin,
            version,
            def_site,
            var_type,
            uses: Vec::new(),
            address_taken: false,
        }
    }

    /// Returns the variable's unique identifier.
    #[must_use]
    pub const fn id(&self) -> SsaVarId {
        self.id
    }

    /// Returns where this variable originated in the CIL.
    #[must_use]
    pub const fn origin(&self) -> VariableOrigin {
        self.origin
    }

    /// Returns the SSA version number.
    #[must_use]
    pub const fn version(&self) -> u32 {
        self.version
    }

    /// Returns where this variable is defined.
    #[must_use]
    pub const fn def_site(&self) -> DefSite {
        self.def_site
    }

    /// Returns the type of this variable.
    ///
    /// Returns `SsaType::Unknown` if type inference hasn't been performed.
    #[must_use]
    pub fn var_type(&self) -> &SsaType {
        &self.var_type
    }

    /// Updates where this variable is defined.
    pub fn set_def_site(&mut self, site: DefSite) {
        self.def_site = site;
    }

    /// Sets the type of this variable.
    ///
    /// This is typically called during type inference or when resolving
    /// phi node types.
    pub fn set_type(&mut self, var_type: SsaType) {
        self.var_type = var_type;
    }

    /// Returns `true` if the variable's type is known (not Unknown).
    #[must_use]
    pub fn has_known_type(&self) -> bool {
        !matches!(self.var_type, SsaType::Unknown)
    }

    /// Returns all use sites for this variable.
    #[must_use]
    pub fn uses(&self) -> &[UseSite] {
        &self.uses
    }

    /// Returns `true` if this variable's address has been taken.
    #[must_use]
    pub const fn is_address_taken(&self) -> bool {
        self.address_taken
    }

    /// Returns `true` if this variable has no uses (dead).
    #[must_use]
    pub fn is_dead(&self) -> bool {
        self.uses.is_empty()
    }

    /// Returns the number of uses for this variable.
    #[must_use]
    pub fn use_count(&self) -> usize {
        self.uses.len()
    }

    /// Adds a use site for this variable.
    pub fn add_use(&mut self, use_site: UseSite) {
        self.uses.push(use_site);
    }

    /// Clears all use sites for this variable.
    ///
    /// This is used when recomputing use information after SSA transformations
    /// that may have invalidated the use tracking.
    pub fn clear_uses(&mut self) {
        self.uses.clear();
    }

    /// Marks this variable as having its address taken.
    pub fn set_address_taken(&mut self) {
        self.address_taken = true;
    }

    /// Sets the origin of this variable.
    ///
    /// This is used during local variable optimization to update indices
    /// after unused locals are removed.
    pub fn set_origin(&mut self, origin: VariableOrigin) {
        self.origin = origin;
    }

    /// Sets the variable's ID.
    ///
    /// Used during variable compaction to reassign dense IDs.
    pub fn set_id(&mut self, id: SsaVarId) {
        self.id = id;
    }
}

impl fmt::Display for SsaVariable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}_{}", self.origin, self.version)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::analysis::ssa::SsaType;

    #[test]
    fn test_ssa_var_id_creation() {
        let id = SsaVarId::from_index(42);
        assert_eq!(id.index(), 42);
    }

    #[test]
    fn test_ssa_var_id_display() {
        let id = SsaVarId::from_index(0);
        let expected = format!("v{}", id.index());
        assert_eq!(format!("{id}"), expected);
        assert_eq!(format!("{id:?}"), expected);
    }

    #[test]
    fn test_ssa_var_id_equality() {
        let id1 = SsaVarId::from_index(10);
        let id2 = SsaVarId::from_index(10);
        let id3 = SsaVarId::from_index(20);

        assert_eq!(id1, id2);
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_variable_origin_argument() {
        let origin = VariableOrigin::Argument(0);
        assert!(origin.is_argument());
        assert!(!origin.is_local());
        assert!(!origin.is_phi());
        assert_eq!(origin.argument_index(), Some(0));
        assert_eq!(origin.local_index(), None);
        assert_eq!(format!("{origin}"), "arg0");
    }

    #[test]
    fn test_variable_origin_local() {
        let origin = VariableOrigin::Local(3);
        assert!(!origin.is_argument());
        assert!(origin.is_local());
        assert!(!origin.is_phi());
        assert_eq!(origin.argument_index(), None);
        assert_eq!(origin.local_index(), Some(3));
        assert_eq!(format!("{origin}"), "loc3");
    }

    #[test]
    fn test_variable_origin_phi() {
        let origin = VariableOrigin::Phi;
        assert!(!origin.is_argument());
        assert!(!origin.is_local());
        assert!(origin.is_phi());
        assert_eq!(format!("{origin}"), "phi");
    }

    #[test]
    fn test_def_site_instruction() {
        let site = DefSite::instruction(2, 5);
        assert_eq!(site.block, 2);
        assert_eq!(site.instruction, Some(5));
        assert!(!site.is_phi());
    }

    #[test]
    fn test_def_site_phi() {
        let site = DefSite::phi(3);
        assert_eq!(site.block, 3);
        assert_eq!(site.instruction, None);
        assert!(site.is_phi());
    }

    #[test]
    fn test_use_site_instruction() {
        let site = UseSite::instruction(1, 4);
        assert_eq!(site.block, 1);
        assert_eq!(site.instruction, 4);
        assert!(!site.is_phi_operand);
    }

    #[test]
    fn test_use_site_phi_operand() {
        let site = UseSite::phi_operand(2, 0);
        assert_eq!(site.block, 2);
        assert_eq!(site.instruction, 0);
        assert!(site.is_phi_operand);
    }

    #[test]
    fn test_ssa_variable_creation() {
        let var = SsaVariable::new(
            SsaVarId::from_index(0),
            VariableOrigin::Argument(0),
            0,
            DefSite::phi(0),
            SsaType::Unknown,
        );

        // ID is now auto-allocated
        assert_eq!(var.origin(), VariableOrigin::Argument(0));
        assert_eq!(var.version(), 0);
        assert!(var.def_site().is_phi());
        assert!(var.uses().is_empty());
        assert!(!var.is_address_taken());
        assert!(var.is_dead());
    }

    #[test]
    fn test_ssa_variable_add_use() {
        let mut var = SsaVariable::new(
            SsaVarId::from_index(0),
            VariableOrigin::Local(0),
            1,
            DefSite::instruction(0, 0),
            SsaType::Unknown,
        );

        assert!(var.is_dead());

        var.add_use(UseSite::instruction(0, 5));
        var.add_use(UseSite::instruction(1, 2));

        assert!(!var.is_dead());
        assert_eq!(var.uses().len(), 2);
    }

    #[test]
    fn test_ssa_variable_address_taken() {
        let mut var = SsaVariable::new(
            SsaVarId::from_index(0),
            VariableOrigin::Local(1),
            0,
            DefSite::phi(0),
            SsaType::Unknown,
        );

        assert!(!var.is_address_taken());
        var.set_address_taken();
        assert!(var.is_address_taken());
    }

    #[test]
    fn test_ssa_variable_display() {
        let var = SsaVariable::new(
            SsaVarId::from_index(0),
            VariableOrigin::Argument(2),
            3,
            DefSite::phi(0),
            SsaType::Unknown,
        );
        assert_eq!(format!("{var}"), "arg2_3");

        let var2 = SsaVariable::new(
            SsaVarId::from_index(1),
            VariableOrigin::Local(0),
            1,
            DefSite::instruction(1, 2),
            SsaType::Unknown,
        );
        assert_eq!(format!("{var2}"), "loc0_1");
    }
}
