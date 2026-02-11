//! Memory SSA (MSSA) for tracking versioned memory locations.
//!
//! This module extends SSA to track state stored in fields, arrays, and heap locations.
//! Memory SSA is essential for precise analysis of obfuscated code that stores state
//! in memory rather than local variables.
//!
//! # Architecture
//!
//! Memory SSA builds on top of traditional SSA by:
//!
//! 1. **Memory Locations**: Abstract representation of memory (fields, arrays, pointers)
//! 2. **Memory Versioning**: Each store creates a new version, each load reads a version
//! 3. **Memory Phi Nodes**: At control flow merges, memory versions are merged
//!
//! ```text
//! Traditional SSA:           Memory SSA:
//!
//!   v1 = x                     v1 = x
//!   obj.field = v1             mem[obj.field]₁ = v1
//!   ...                        ...
//!   v2 = obj.field             v2 = mem[obj.field]₁
//! ```
//!
//! # Memory Location Hierarchy
//!
//! Memory locations form a hierarchy for alias analysis:
//!
//! ```text
//! Unknown (may alias anything)
//!   ├── StaticField(token)      - Specific static field
//!   ├── InstanceField(obj, token) - Specific instance field
//!   ├── ArrayElement(arr, idx)   - Specific array element
//!   │     ├── ArrayElement(arr, Constant(i)) - Known index
//!   │     └── ArrayElement(arr, Variable(v)) - Unknown index (may alias)
//!   └── Indirect(addr)          - Pointer dereference
//! ```
//!
//! # Usage
//!
//! ```rust,ignore
//! use dotscope::analysis::{MemorySsa, SsaFunction, SsaCfg};
//!
//! let cfg = SsaCfg::from_ssa(&ssa);
//! let mem_ssa = MemorySsa::build(&ssa, &cfg);
//!
//! // Query memory version at a specific point
//! let loc = MemoryLocation::StaticField(field_token);
//! if let Some(version) = mem_ssa.version_at_block(&loc, block_idx) {
//!     println!("Memory version: {}", version);
//! }
//! ```
//!
//! # References
//!
//! - Chow et al., "Effective Representation of Aliases and Indirect Memory
//!   Operations in SSA Form", CC 1996

use std::collections::{HashMap, HashSet, VecDeque};

use crate::analysis::ssa::{FieldRef, SsaCfg, SsaFunction, SsaOp, SsaVarId};
use crate::utils::graph::{
    algorithms::{compute_dominance_frontiers, compute_dominators},
    GraphBase, NodeId, RootedGraph, Successors,
};

/// Represents an abstract memory location.
///
/// Memory locations are used to track which memory is being accessed by
/// load/store operations. The granularity varies by location type:
///
/// - Static fields are precise (one location per field)
/// - Instance fields depend on object identity (may alias if objects may alias)
/// - Array elements depend on both array identity and index
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum MemoryLocation {
    /// Instance field access: `object.field`
    ///
    /// The `SsaVarId` identifies the object, and `FieldRef` identifies the field.
    /// Two instance field locations may alias if the objects may alias.
    InstanceField(SsaVarId, FieldRef),

    /// Static field access: `ClassName.field`
    ///
    /// Static fields are uniquely identified by their token. Two static field
    /// locations alias iff they have the same token.
    StaticField(FieldRef),

    /// Array element access: `array[index]`
    ///
    /// The `SsaVarId` identifies the array, and `ArrayIndex` identifies the index.
    /// Array element locations may alias based on array identity and index overlap.
    ArrayElement(SsaVarId, ArrayIndex),

    /// Indirect memory access through a pointer: `*ptr`
    ///
    /// The `SsaVarId` is the pointer variable. Indirect accesses are the most
    /// conservative - they may alias anything the pointer could point to.
    Indirect(SsaVarId),

    /// Unknown/escaped memory.
    ///
    /// Used when we can't determine the exact location (e.g., after a call
    /// that may modify memory, or for volatile accesses).
    Unknown,
}

impl MemoryLocation {
    /// Returns the base object variable, if any.
    ///
    /// For instance fields and arrays, this is the object/array variable.
    /// For static fields and unknown locations, returns `None`.
    #[must_use]
    pub fn base_object(&self) -> Option<SsaVarId> {
        match self {
            Self::InstanceField(obj, _) => Some(*obj),
            Self::ArrayElement(arr, _) => Some(*arr),
            Self::Indirect(ptr) => Some(*ptr),
            Self::StaticField(_) | Self::Unknown => None,
        }
    }

    /// Returns `true` if this location may alias the other location.
    ///
    /// This is a conservative analysis - if we can't prove non-aliasing,
    /// we assume aliasing is possible.
    #[must_use]
    pub fn may_alias(&self, other: &Self) -> bool {
        match (self, other) {
            // Unknown aliases everything; Indirect may alias any concrete location
            (Self::Unknown, _)
            | (_, Self::Unknown)
            | (
                Self::Indirect(_),
                Self::InstanceField(..) | Self::ArrayElement(..) | Self::StaticField(_),
            )
            | (
                Self::InstanceField(..) | Self::ArrayElement(..) | Self::StaticField(_),
                Self::Indirect(_),
            ) => true,

            // Static fields alias iff same field
            (Self::StaticField(f1), Self::StaticField(f2)) => f1 == f2,

            // Static fields don't alias instance fields or arrays;
            // Instance fields don't alias array elements (different memory types)
            (Self::StaticField(_), Self::InstanceField(..) | Self::ArrayElement(..))
            | (Self::InstanceField(..) | Self::ArrayElement(..), Self::StaticField(_))
            | (Self::InstanceField(..), Self::ArrayElement(..))
            | (Self::ArrayElement(..), Self::InstanceField(..)) => false,

            // Instance fields alias if same object AND same field
            // Conservative: different objects assumed to not alias
            (Self::InstanceField(obj1, f1), Self::InstanceField(obj2, f2)) => {
                obj1 == obj2 && f1 == f2
            }

            // Array elements alias if same array AND indices may overlap
            (Self::ArrayElement(arr1, idx1), Self::ArrayElement(arr2, idx2)) => {
                arr1 == arr2 && idx1.may_overlap(idx2)
            }

            // Indirect access may alias anything with same pointer
            (Self::Indirect(p1), Self::Indirect(p2)) => p1 == p2,
        }
    }

    /// Returns `true` if this location must alias the other location.
    ///
    /// This is a more precise analysis - returns `true` only if we can
    /// prove the locations definitely refer to the same memory.
    #[must_use]
    pub fn must_alias(&self, other: &Self) -> bool {
        match (self, other) {
            // Static fields must-alias iff same field
            (Self::StaticField(f1), Self::StaticField(f2)) => f1 == f2,

            // Instance fields must-alias iff same object AND same field
            (Self::InstanceField(obj1, f1), Self::InstanceField(obj2, f2)) => {
                obj1 == obj2 && f1 == f2
            }

            // Array elements must-alias iff same array AND same constant index
            (Self::ArrayElement(arr1, idx1), Self::ArrayElement(arr2, idx2)) => {
                arr1 == arr2 && idx1.must_equal(idx2)
            }

            // Indirect must-alias iff same pointer
            (Self::Indirect(p1), Self::Indirect(p2)) => p1 == p2,

            // Unknown never must-aliases (not precise enough)
            _ => false,
        }
    }
}

/// Represents an array index for array element locations.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum ArrayIndex {
    /// A constant index value.
    Constant(i64),
    /// A variable index.
    Variable(SsaVarId),
    /// Unknown index (could be any value).
    Unknown,
}

impl ArrayIndex {
    /// Returns `true` if these indices may refer to the same element.
    #[must_use]
    pub fn may_overlap(&self, other: &Self) -> bool {
        match (self, other) {
            // Unknown overlaps everything; Variable indices may overlap (conservative)
            (Self::Unknown | Self::Variable(_), _) | (_, Self::Unknown | Self::Variable(_)) => true,
            // Constants overlap iff equal
            (Self::Constant(i1), Self::Constant(i2)) => i1 == i2,
        }
    }

    /// Returns `true` if these indices must refer to the same element.
    #[must_use]
    pub fn must_equal(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Constant(i1), Self::Constant(i2)) => i1 == i2,
            (Self::Variable(v1), Self::Variable(v2)) => v1 == v2,
            _ => false,
        }
    }
}

/// A memory operation (load or store).
#[derive(Debug, Clone)]
pub enum MemoryOp {
    /// A memory load operation.
    Load {
        /// The memory location being loaded.
        location: MemoryLocation,
        /// The SSA variable receiving the loaded value.
        dest: SsaVarId,
        /// Block containing this operation.
        block: usize,
        /// Instruction index within the block.
        instr: usize,
    },
    /// A memory store operation.
    Store {
        /// The memory location being stored to.
        location: MemoryLocation,
        /// The SSA variable being stored.
        value: SsaVarId,
        /// Block containing this operation.
        block: usize,
        /// Instruction index within the block.
        instr: usize,
    },
}

impl MemoryOp {
    /// Returns the memory location accessed by this operation.
    #[must_use]
    pub fn location(&self) -> &MemoryLocation {
        match self {
            Self::Load { location, .. } | Self::Store { location, .. } => location,
        }
    }

    /// Returns the block index containing this operation.
    #[must_use]
    pub fn block(&self) -> usize {
        match self {
            Self::Load { block, .. } | Self::Store { block, .. } => *block,
        }
    }

    /// Returns the instruction index within the block.
    #[must_use]
    pub fn instr(&self) -> usize {
        match self {
            Self::Load { instr, .. } | Self::Store { instr, .. } => *instr,
        }
    }

    /// Returns `true` if this is a store operation.
    #[must_use]
    pub fn is_store(&self) -> bool {
        matches!(self, Self::Store { .. })
    }

    /// Returns `true` if this is a load operation.
    #[must_use]
    pub fn is_load(&self) -> bool {
        matches!(self, Self::Load { .. })
    }
}

/// A phi node for memory locations.
///
/// Memory phi nodes are placed at control flow merge points where different
/// memory versions from different predecessors need to be merged.
#[derive(Debug, Clone)]
pub struct MemoryPhi {
    /// The memory location this phi node is for.
    pub location: MemoryLocation,
    /// The result version number produced by this phi.
    pub result_version: u32,
    /// The operands from each predecessor.
    pub operands: Vec<MemoryPhiOperand>,
}

impl MemoryPhi {
    /// Creates a new memory phi node.
    #[must_use]
    pub fn new(location: MemoryLocation, result_version: u32) -> Self {
        Self {
            location,
            result_version,
            operands: Vec::new(),
        }
    }

    /// Adds an operand from a predecessor block.
    pub fn add_operand(&mut self, predecessor: usize, version: u32) {
        self.operands.push(MemoryPhiOperand {
            predecessor,
            version,
        });
    }

    /// Returns the operand from a specific predecessor, if present.
    #[must_use]
    pub fn operand_from(&self, predecessor: usize) -> Option<&MemoryPhiOperand> {
        self.operands
            .iter()
            .find(|op| op.predecessor == predecessor)
    }
}

/// An operand of a memory phi node.
#[derive(Debug, Clone)]
pub struct MemoryPhiOperand {
    /// The predecessor block this operand comes from.
    pub predecessor: usize,
    /// The memory version from that predecessor.
    pub version: u32,
}

/// Memory version identifier.
///
/// Combines a memory location with a version number to uniquely identify
/// a specific "value" of that memory location.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct MemoryVersion {
    /// The memory location.
    pub location: MemoryLocation,
    /// The version number.
    pub version: u32,
}

impl MemoryVersion {
    /// Creates a new memory version.
    #[must_use]
    pub fn new(location: MemoryLocation, version: u32) -> Self {
        Self { location, version }
    }
}

/// Definition site for a memory version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryDefSite {
    /// Defined at entry (initial version).
    Entry,
    /// Defined by a store instruction.
    Store {
        /// The block containing the store.
        block: usize,
        /// The instruction index within the block.
        instr: usize,
    },
    /// Defined by a memory phi node.
    Phi {
        /// The block containing the phi node.
        block: usize,
    },
}

/// Memory SSA representation.
///
/// This structure tracks versioned memory locations throughout a function,
/// enabling precise tracking of memory state for analysis.
#[derive(Debug)]
pub struct MemorySsa {
    /// Next version number for each memory location.
    next_version: HashMap<MemoryLocation, u32>,

    /// Memory phi nodes at each block.
    /// Key is block index, value is list of memory phi nodes.
    memory_phis: HashMap<usize, Vec<MemoryPhi>>,

    /// Definition sites for each memory version.
    definitions: HashMap<MemoryVersion, MemoryDefSite>,

    /// Memory version at block entry for each location.
    /// Key is (location, block), value is version.
    entry_versions: HashMap<(MemoryLocation, usize), u32>,

    /// Memory version at block exit for each location.
    /// Key is (location, block), value is version.
    exit_versions: HashMap<(MemoryLocation, usize), u32>,

    /// All identified memory operations.
    operations: Vec<MemoryOp>,

    /// All unique memory locations in the function.
    locations: HashSet<MemoryLocation>,
}

impl MemorySsa {
    /// Creates an empty Memory SSA structure.
    #[must_use]
    pub fn new() -> Self {
        Self {
            next_version: HashMap::new(),
            memory_phis: HashMap::new(),
            definitions: HashMap::new(),
            entry_versions: HashMap::new(),
            exit_versions: HashMap::new(),
            operations: Vec::new(),
            locations: HashSet::new(),
        }
    }

    /// Builds Memory SSA from an SSA function.
    ///
    /// This performs the full Memory SSA construction:
    /// 1. Identify all memory operations
    /// 2. Place memory phi nodes at dominance frontiers
    /// 3. Rename memory versions using dominator tree traversal
    ///
    /// # Arguments
    ///
    /// * `ssa` - The SSA function to analyze.
    /// * `cfg` - The control flow graph of the function.
    ///
    /// # Returns
    ///
    /// A complete Memory SSA representation.
    #[must_use]
    pub fn build(ssa: &SsaFunction, cfg: &SsaCfg<'_>) -> Self {
        let mut mem_ssa = Self::new();

        // Phase 1: Identify all memory operations
        mem_ssa.identify_memory_operations(ssa);

        // Phase 2: Place memory phi nodes
        mem_ssa.place_memory_phis(cfg);

        // Phase 3: Rename memory versions
        mem_ssa.rename_memory_versions(ssa, cfg);

        mem_ssa
    }

    /// Returns the memory phi nodes at a block.
    #[must_use]
    pub fn memory_phis(&self, block: usize) -> &[MemoryPhi] {
        self.memory_phis.get(&block).map_or(&[], Vec::as_slice)
    }

    /// Returns all memory operations.
    #[must_use]
    pub fn operations(&self) -> &[MemoryOp] {
        &self.operations
    }

    /// Returns all unique memory locations.
    #[must_use]
    pub fn locations(&self) -> &HashSet<MemoryLocation> {
        &self.locations
    }

    /// Returns the memory version at block entry for a location.
    #[must_use]
    pub fn version_at_entry(&self, location: &MemoryLocation, block: usize) -> Option<u32> {
        self.entry_versions.get(&(location.clone(), block)).copied()
    }

    /// Returns the memory version at block exit for a location.
    #[must_use]
    pub fn version_at_exit(&self, location: &MemoryLocation, block: usize) -> Option<u32> {
        self.exit_versions.get(&(location.clone(), block)).copied()
    }

    /// Returns the definition site for a memory version.
    #[must_use]
    pub fn definition(&self, version: &MemoryVersion) -> Option<MemoryDefSite> {
        self.definitions.get(version).copied()
    }

    /// Returns the next version number for a location (and increments it).
    fn allocate_version(&mut self, location: &MemoryLocation) -> u32 {
        let version = self.next_version.entry(location.clone()).or_insert(0);
        let result = *version;
        *version += 1;
        result
    }

    /// Returns the current version number for a location without incrementing.
    fn current_version(&self, location: &MemoryLocation) -> u32 {
        self.next_version
            .get(location)
            .copied()
            .unwrap_or(0)
            .saturating_sub(1)
    }

    /// Phase 1: Identify all memory operations in the SSA function.
    fn identify_memory_operations(&mut self, ssa: &SsaFunction) {
        for (block_idx, instr_idx, instr) in ssa.iter_instructions() {
            if let Some(mem_op) = Self::classify_memory_operation(instr.op(), block_idx, instr_idx)
            {
                self.locations.insert(mem_op.location().clone());
                self.operations.push(mem_op);
            }
        }
    }

    /// Classifies an SSA operation as a memory operation, if applicable.
    fn classify_memory_operation(op: &SsaOp, block: usize, instr: usize) -> Option<MemoryOp> {
        match op {
            SsaOp::LoadField {
                dest,
                object,
                field,
            } => {
                let location = MemoryLocation::InstanceField(*object, *field);
                Some(MemoryOp::Load {
                    location,
                    dest: *dest,
                    block,
                    instr,
                })
            }
            SsaOp::StoreField {
                object,
                field,
                value,
            } => {
                let location = MemoryLocation::InstanceField(*object, *field);
                Some(MemoryOp::Store {
                    location,
                    value: *value,
                    block,
                    instr,
                })
            }
            SsaOp::LoadStaticField { dest, field } => {
                let location = MemoryLocation::StaticField(*field);
                Some(MemoryOp::Load {
                    location,
                    dest: *dest,
                    block,
                    instr,
                })
            }
            SsaOp::StoreStaticField { field, value } => {
                let location = MemoryLocation::StaticField(*field);
                Some(MemoryOp::Store {
                    location,
                    value: *value,
                    block,
                    instr,
                })
            }
            SsaOp::LoadElement {
                dest, array, index, ..
            } => {
                let idx = Self::resolve_array_index(*index);
                let location = MemoryLocation::ArrayElement(*array, idx);
                Some(MemoryOp::Load {
                    location,
                    dest: *dest,
                    block,
                    instr,
                })
            }
            SsaOp::StoreElement {
                array,
                index,
                value,
                ..
            } => {
                let idx = Self::resolve_array_index(*index);
                let location = MemoryLocation::ArrayElement(*array, idx);
                Some(MemoryOp::Store {
                    location,
                    value: *value,
                    block,
                    instr,
                })
            }
            SsaOp::LoadIndirect { dest, addr, .. } => {
                let location = MemoryLocation::Indirect(*addr);
                Some(MemoryOp::Load {
                    location,
                    dest: *dest,
                    block,
                    instr,
                })
            }
            SsaOp::StoreIndirect { addr, value, .. } => {
                let location = MemoryLocation::Indirect(*addr);
                Some(MemoryOp::Store {
                    location,
                    value: *value,
                    block,
                    instr,
                })
            }
            _ => None,
        }
    }

    /// Resolves an array index to an `ArrayIndex` abstraction.
    fn resolve_array_index(index_var: SsaVarId) -> ArrayIndex {
        // For now, treat all variable indices as unknown
        // Could be improved with constant propagation
        ArrayIndex::Variable(index_var)
    }

    /// Phase 2: Place memory phi nodes at dominance frontiers.
    fn place_memory_phis(&mut self, cfg: &SsaCfg<'_>) {
        let block_count = cfg.node_count();
        if block_count == 0 {
            return;
        }

        // Compute dominators and dominance frontiers
        let dom_tree = compute_dominators(cfg, cfg.entry());
        let frontiers = compute_dominance_frontiers(cfg, &dom_tree);

        // For each memory location, find blocks that define it (stores)
        let mut def_blocks: HashMap<MemoryLocation, HashSet<usize>> = HashMap::new();
        for op in &self.operations {
            if op.is_store() {
                def_blocks
                    .entry(op.location().clone())
                    .or_default()
                    .insert(op.block());
            }
        }

        // Standard phi placement algorithm (iterated dominance frontier)
        for (location, defs) in def_blocks {
            let mut phi_blocks: HashSet<usize> = HashSet::new();
            let mut worklist: VecDeque<usize> = defs.iter().copied().collect();
            let mut processed: HashSet<usize> = HashSet::new();

            while let Some(block) = worklist.pop_front() {
                if !processed.insert(block) {
                    continue;
                }

                let node_id = NodeId::new(block);
                if node_id.index() >= frontiers.len() {
                    continue;
                }

                for &frontier_node in &frontiers[node_id.index()] {
                    let frontier_block = frontier_node.index();
                    if phi_blocks.insert(frontier_block) {
                        // Add phi at frontier
                        let version = self.allocate_version(&location);
                        let phi = MemoryPhi::new(location.clone(), version);
                        self.memory_phis
                            .entry(frontier_block)
                            .or_default()
                            .push(phi);
                        self.definitions.insert(
                            MemoryVersion::new(location.clone(), version),
                            MemoryDefSite::Phi {
                                block: frontier_block,
                            },
                        );
                        worklist.push_back(frontier_block);
                    }
                }
            }
        }
    }

    /// Phase 3: Rename memory versions using dominator tree traversal.
    fn rename_memory_versions(&mut self, ssa: &SsaFunction, cfg: &SsaCfg<'_>) {
        let block_count = cfg.node_count();
        if block_count == 0 {
            return;
        }

        // Compute dominators for traversal order
        let dom_tree = compute_dominators(cfg, cfg.entry());

        // Stack of versions for each location
        let mut version_stacks: HashMap<MemoryLocation, Vec<u32>> = HashMap::new();

        // Initialize all locations with version 0 (entry version)
        let locations: Vec<_> = self.locations.iter().cloned().collect();
        for location in locations {
            let entry_version = self.allocate_version(&location);
            version_stacks
                .entry(location.clone())
                .or_default()
                .push(entry_version);
            self.definitions.insert(
                MemoryVersion::new(location, entry_version),
                MemoryDefSite::Entry,
            );
        }

        // Rename in dominator tree order (preorder)
        let mut visited = vec![false; block_count];
        let mut worklist = vec![cfg.entry().index()];

        while let Some(block_idx) = worklist.pop() {
            if visited[block_idx] {
                continue;
            }
            visited[block_idx] = true;

            self.rename_block(block_idx, ssa, cfg, &mut version_stacks);

            // Add dominated blocks to worklist
            for child in dom_tree.children(NodeId::new(block_idx)) {
                if !visited[child.index()] {
                    worklist.push(child.index());
                }
            }
        }
    }

    /// Renames memory versions within a single block.
    fn rename_block(
        &mut self,
        block_idx: usize,
        ssa: &SsaFunction,
        cfg: &SsaCfg<'_>,
        version_stacks: &mut HashMap<MemoryLocation, Vec<u32>>,
    ) {
        // Record entry versions
        for location in self.locations.clone() {
            if let Some(&version) = version_stacks.get(&location).and_then(|s| s.last()) {
                self.entry_versions
                    .insert((location.clone(), block_idx), version);
            }
        }

        // Process memory phi nodes - they define new versions
        if let Some(phis) = self.memory_phis.get(&block_idx).cloned() {
            for phi in phis {
                version_stacks
                    .entry(phi.location.clone())
                    .or_default()
                    .push(phi.result_version);
            }
        }

        // Process instructions in the block
        let Some(block) = ssa.block(block_idx) else {
            return;
        };

        for (instr_idx, instr) in block.instructions().iter().enumerate() {
            // Handle stores - create new version
            if let Some(mem_op) = Self::classify_memory_operation(instr.op(), block_idx, instr_idx)
            {
                if mem_op.is_store() {
                    let location = mem_op.location().clone();
                    let new_version = self.allocate_version(&location);
                    version_stacks
                        .entry(location.clone())
                        .or_default()
                        .push(new_version);
                    self.definitions.insert(
                        MemoryVersion::new(location, new_version),
                        MemoryDefSite::Store {
                            block: block_idx,
                            instr: instr_idx,
                        },
                    );
                }
            }
        }

        // Record exit versions
        for location in self.locations.clone() {
            if let Some(&version) = version_stacks.get(&location).and_then(|s| s.last()) {
                self.exit_versions
                    .insert((location.clone(), block_idx), version);
            }
        }

        // Fill in phi operands for successors
        for succ_id in cfg.successors(NodeId::new(block_idx)) {
            let succ_idx = succ_id.index();
            if let Some(phis) = self.memory_phis.get_mut(&succ_idx) {
                for phi in phis {
                    if let Some(&version) = version_stacks.get(&phi.location).and_then(|s| s.last())
                    {
                        phi.add_operand(block_idx, version);
                    }
                }
            }
        }
    }

    /// Returns statistics about the Memory SSA.
    #[must_use]
    pub fn stats(&self) -> MemorySsaStats {
        let total_phis = self.memory_phis.values().map(Vec::len).sum();
        let store_count = self.operations.iter().filter(|op| op.is_store()).count();
        let load_count = self.operations.iter().filter(|op| op.is_load()).count();

        MemorySsaStats {
            location_count: self.locations.len(),
            memory_phi_count: total_phis,
            store_count,
            load_count,
            version_count: self.definitions.len(),
        }
    }
}

impl Default for MemorySsa {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics about Memory SSA.
#[derive(Debug, Clone, Copy)]
pub struct MemorySsaStats {
    /// Number of unique memory locations tracked.
    pub location_count: usize,
    /// Number of memory phi nodes placed.
    pub memory_phi_count: usize,
    /// Number of store operations.
    pub store_count: usize,
    /// Number of load operations.
    pub load_count: usize,
    /// Total number of memory versions.
    pub version_count: usize,
}

/// Memory state tracker for path-aware evaluation.
///
/// This tracks the memory values along a specific execution path, enabling
/// precise tracking of memory contents during symbolic or concrete evaluation.
#[derive(Debug, Clone)]
pub struct MemoryState {
    /// Current memory values: location -> (version, value as SSA variable).
    values: HashMap<MemoryLocation, (u32, SsaVarId)>,
    /// Reference to the Memory SSA for version lookups.
    mem_ssa: Option<std::sync::Arc<MemorySsa>>,
}

impl MemoryState {
    /// Creates a new empty memory state.
    #[must_use]
    pub fn new() -> Self {
        Self {
            values: HashMap::new(),
            mem_ssa: None,
        }
    }

    /// Creates a memory state with a reference to Memory SSA.
    #[must_use]
    pub fn with_mem_ssa(mem_ssa: std::sync::Arc<MemorySsa>) -> Self {
        Self {
            values: HashMap::new(),
            mem_ssa: Some(mem_ssa),
        }
    }

    /// Records a memory store.
    pub fn store(&mut self, location: MemoryLocation, value: SsaVarId, version: u32) {
        self.values.insert(location, (version, value));
    }

    /// Loads from a memory location.
    ///
    /// Returns the SSA variable holding the value, if known.
    #[must_use]
    pub fn load(&self, location: &MemoryLocation) -> Option<SsaVarId> {
        // Direct match
        if let Some((_, value)) = self.values.get(location) {
            return Some(*value);
        }

        // Check for aliasing locations
        for (loc, (_, value)) in &self.values {
            if location.must_alias(loc) {
                return Some(*value);
            }
        }

        None
    }

    /// Returns the current version for a location, if known.
    #[must_use]
    pub fn version(&self, location: &MemoryLocation) -> Option<u32> {
        self.values.get(location).map(|(v, _)| *v)
    }

    /// Checks if any stored location may alias the given location.
    #[must_use]
    pub fn has_may_alias(&self, location: &MemoryLocation) -> bool {
        self.values.keys().any(|loc| loc.may_alias(location))
    }

    /// Clears all memory state.
    pub fn clear(&mut self) {
        self.values.clear();
    }

    /// Returns the number of tracked locations.
    #[must_use]
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Returns `true` if no memory is being tracked.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}

impl Default for MemoryState {
    fn default() -> Self {
        Self::new()
    }
}

/// Alias analysis result for a pair of memory locations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AliasResult {
    /// The locations definitely do not alias.
    NoAlias,
    /// The locations may alias (conservative).
    MayAlias,
    /// The locations definitely alias (same memory).
    MustAlias,
}

/// Performs alias analysis between two memory locations.
#[must_use]
pub fn analyze_alias(loc1: &MemoryLocation, loc2: &MemoryLocation) -> AliasResult {
    if loc1.must_alias(loc2) {
        AliasResult::MustAlias
    } else if loc1.may_alias(loc2) {
        AliasResult::MayAlias
    } else {
        AliasResult::NoAlias
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_location_static_field_alias() {
        let field1 = FieldRef::new(crate::metadata::token::Token::new(0x04000001));
        let field2 = FieldRef::new(crate::metadata::token::Token::new(0x04000002));

        let loc1 = MemoryLocation::StaticField(field1);
        let loc2 = MemoryLocation::StaticField(field1);
        let loc3 = MemoryLocation::StaticField(field2);

        assert!(loc1.must_alias(&loc2));
        assert!(loc1.may_alias(&loc2));
        assert!(!loc1.may_alias(&loc3));
    }

    #[test]
    fn test_memory_location_instance_field_alias() {
        let field = FieldRef::new(crate::metadata::token::Token::new(0x04000001));
        let obj1 = SsaVarId::new();
        let obj2 = SsaVarId::new();

        let loc1 = MemoryLocation::InstanceField(obj1, field);
        let loc2 = MemoryLocation::InstanceField(obj1, field);
        let loc3 = MemoryLocation::InstanceField(obj2, field);

        assert!(loc1.must_alias(&loc2));
        assert!(loc1.may_alias(&loc2));
        assert!(!loc1.may_alias(&loc3)); // Different objects
    }

    #[test]
    fn test_array_index_overlap() {
        let idx1 = ArrayIndex::Constant(5);
        let idx2 = ArrayIndex::Constant(5);
        let idx3 = ArrayIndex::Constant(10);
        let idx4 = ArrayIndex::Unknown;

        assert!(idx1.may_overlap(&idx2));
        assert!(idx1.must_equal(&idx2));
        assert!(!idx1.may_overlap(&idx3));
        assert!(idx1.may_overlap(&idx4)); // Unknown overlaps everything
    }

    #[test]
    fn test_memory_location_array_element_alias() {
        let arr = SsaVarId::new();
        let idx1 = ArrayIndex::Constant(5);
        let idx2 = ArrayIndex::Constant(5);
        let idx3 = ArrayIndex::Constant(10);

        let loc1 = MemoryLocation::ArrayElement(arr, idx1);
        let loc2 = MemoryLocation::ArrayElement(arr, idx2);
        let loc3 = MemoryLocation::ArrayElement(arr, idx3);

        assert!(loc1.must_alias(&loc2));
        assert!(!loc1.may_alias(&loc3));
    }

    #[test]
    fn test_memory_location_unknown_alias() {
        let field = FieldRef::new(crate::metadata::token::Token::new(0x04000001));
        let loc1 = MemoryLocation::Unknown;
        let loc2 = MemoryLocation::StaticField(field);

        assert!(loc1.may_alias(&loc2)); // Unknown aliases everything
        assert!(!loc1.must_alias(&loc2)); // But doesn't must-alias
    }

    #[test]
    fn test_alias_result() {
        let field = FieldRef::new(crate::metadata::token::Token::new(0x04000001));
        let loc1 = MemoryLocation::StaticField(field);
        let loc2 = MemoryLocation::StaticField(field);

        assert_eq!(analyze_alias(&loc1, &loc2), AliasResult::MustAlias);

        let arr1 = SsaVarId::new();
        let arr2 = SsaVarId::new();
        let loc3 = MemoryLocation::ArrayElement(arr1, ArrayIndex::Constant(0));
        let loc4 = MemoryLocation::ArrayElement(arr2, ArrayIndex::Constant(0));

        assert_eq!(analyze_alias(&loc3, &loc4), AliasResult::NoAlias);
    }

    #[test]
    fn test_memory_state() {
        let mut state = MemoryState::new();
        let field = FieldRef::new(crate::metadata::token::Token::new(0x04000001));
        let loc = MemoryLocation::StaticField(field);
        let value = SsaVarId::new();

        state.store(loc.clone(), value, 1);
        assert_eq!(state.load(&loc), Some(value));
        assert_eq!(state.version(&loc), Some(1));
        assert_eq!(state.len(), 1);

        state.clear();
        assert!(state.is_empty());
    }

    #[test]
    fn test_memory_phi() {
        let field = FieldRef::new(crate::metadata::token::Token::new(0x04000001));
        let loc = MemoryLocation::StaticField(field);

        let mut phi = MemoryPhi::new(loc.clone(), 2);
        phi.add_operand(0, 0);
        phi.add_operand(1, 1);

        assert_eq!(phi.result_version, 2);
        assert_eq!(phi.operands.len(), 2);
        assert_eq!(phi.operand_from(0).unwrap().version, 0);
        assert_eq!(phi.operand_from(1).unwrap().version, 1);
        assert!(phi.operand_from(2).is_none());
    }

    #[test]
    fn test_memory_op() {
        let field = FieldRef::new(crate::metadata::token::Token::new(0x04000001));
        let loc = MemoryLocation::StaticField(field);
        let dest = SsaVarId::new();
        let value = SsaVarId::new();

        let load = MemoryOp::Load {
            location: loc.clone(),
            dest,
            block: 0,
            instr: 5,
        };
        assert!(load.is_load());
        assert!(!load.is_store());
        assert_eq!(load.block(), 0);
        assert_eq!(load.instr(), 5);

        let store = MemoryOp::Store {
            location: loc,
            value,
            block: 1,
            instr: 3,
        };
        assert!(!store.is_load());
        assert!(store.is_store());
    }
}
