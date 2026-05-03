//! Local variable coalescing for SSA code generation.
//!
//! This module implements register allocation for SSA variables, allowing
//! non-interfering variables (those never live at the same program point)
//! to share the same local slot, reducing code size.
//!
//! # Algorithms
//!
//! Two allocation algorithms are available, selected automatically based on
//! the number of variables:
//!
//! ## Graph Coloring (for small SSAs, ≤500 variables)
//! - **Optimal results**: Minimizes the number of local slots
//! - **O(n²) complexity**: Builds full interference graph
//! - Used by GCC, LLVM for ahead-of-time compilation
//!
//! ## Linear Scan (for large SSAs, >500 variables)
//! - **Near-optimal results**: Within 5-10% of graph coloring
//! - **O(n log n) complexity**: Uses live intervals instead of interference graph
//! - Used by HotSpot JVM, V8, .NET RyuJIT for JIT compilation
//!
//! # Type Compatibility
//!
//! Variables can only share slots if their types are compatible:
//! - Same type: always compatible
//! - All reference types: share object slots
//! - Integer types of same size: compatible (I32/U32, I64/U64)

use std::{
    cmp::Reverse,
    collections::{BTreeMap, BinaryHeap},
};

use rayon::prelude::*;

use crate::{
    analysis::{
        AnalysisResults, DataFlowSolver, LiveVariables, LivenessResult, SsaCfg, SsaFunction, SsaOp,
        SsaType, SsaVarId, VariableOrigin,
    },
    utils::BitSet,
    Error, Result,
};

/// Interference graph for register allocation.
///
/// Tracks which variables interfere (are live simultaneously) and thus
/// cannot share the same local slot.
pub struct InterferenceGraph {
    /// Adjacency list: var_id -> bitset of interfering var_ids (indexed by SsaVarId::index())
    edges: BTreeMap<SsaVarId, BitSet>,
    /// Type of each variable (for compatibility checking)
    var_types: BTreeMap<SsaVarId, SsaType>,
    /// Number of variables (capacity for BitSets)
    var_count: usize,
}

impl InterferenceGraph {
    /// Creates a new empty interference graph with the given variable capacity.
    fn new(var_count: usize) -> Self {
        Self {
            edges: BTreeMap::new(),
            var_types: BTreeMap::new(),
            var_count,
        }
    }

    /// Adds an interference edge between two variables.
    fn add_edge(&mut self, a: SsaVarId, b: SsaVarId) {
        if a != b {
            let var_count = self.var_count;
            self.edges
                .entry(a)
                .or_insert_with(|| BitSet::new(var_count))
                .insert(b.index());
            self.edges
                .entry(b)
                .or_insert_with(|| BitSet::new(var_count))
                .insert(a.index());
        }
    }

    /// Records the type of a variable.
    fn set_type(&mut self, var: SsaVarId, ty: SsaType) {
        self.var_types.insert(var, ty);
    }

    /// Returns the neighbors (interfering variables) of a variable.
    fn neighbors(&self, var: SsaVarId) -> impl Iterator<Item = SsaVarId> + '_ {
        self.edges
            .get(&var)
            .into_iter()
            .flat_map(|set| set.iter().map(SsaVarId::from_index))
    }

    /// Returns the degree (number of interferences) of a variable.
    fn degree(&self, var: SsaVarId) -> usize {
        self.edges.get(&var).map_or(0, |s| s.count())
    }
}

/// Result of local allocation.
pub struct LocalAllocation {
    /// Map SSA var -> allocated local slot
    pub var_to_local: BTreeMap<SsaVarId, u16>,
    /// Number of locals needed
    pub num_locals: u16,
    /// Map original local index -> compacted local index (for signature generation)
    pub original_to_compacted: BTreeMap<u16, u16>,
}

/// Live interval for a variable (used by linear scan).
///
/// Represents the range [start, end) where a variable is live.
#[derive(Debug, Clone)]
struct LiveInterval {
    start: usize,
    end: usize,
}

impl LiveInterval {
    fn new(pos: usize) -> Self {
        Self {
            start: pos,
            end: pos + 1,
        }
    }

    fn extend_start(&mut self, pos: usize) {
        self.start = self.start.min(pos);
    }

    fn extend_end(&mut self, pos: usize) {
        self.end = self.end.max(pos);
    }
}

/// Local variable coalescer for SSA code generation.
///
/// Automatically selects between graph coloring (optimal, O(n²)) and
/// linear scan (near-optimal, O(n log n)) based on the number of variables.
pub struct LocalCoalescer {
    /// Interference graph (used by graph coloring algorithm)
    interference: InterferenceGraph,
    /// Variables that need allocation (Stack and Phi origins only)
    coalescable_vars: Vec<SsaVarId>,
    /// Pre-computed allocation from linear scan (if used)
    precomputed: Option<LocalAllocation>,
}

/// Threshold for switching from graph coloring to linear scan.
///
/// Graph coloring has O(n²) complexity for building the interference graph.
/// For SSAs with more variables than this threshold, we use linear scan
/// which has O(n log n) complexity and produces near-optimal results.
const LINEAR_SCAN_THRESHOLD: usize = 500;

impl LocalCoalescer {
    /// Builds a coalescer from the SSA function.
    ///
    /// Automatically selects the appropriate algorithm:
    /// - **Graph coloring** for small SSAs (≤500 variables): Optimal results, O(n²)
    /// - **Linear scan** for large SSAs (>500 variables): Near-optimal, O(n log n)
    pub fn build(ssa: &SsaFunction) -> Self {
        if ssa.variable_count() > LINEAR_SCAN_THRESHOLD {
            return Self::build_linear_scan(ssa);
        }
        Self::build_graph_coloring(ssa)
    }

    /// Builds using graph coloring algorithm.
    ///
    /// Uses liveness analysis to determine which variables are live at each
    /// program point, then builds edges between variables that are live
    /// simultaneously. Produces optimal slot allocation.
    ///
    /// Complexity: O(n²) for n variables
    fn build_graph_coloring(ssa: &SsaFunction) -> Self {
        let var_count = ssa.var_id_capacity();
        let mut interference = InterferenceGraph::new(var_count);

        // Record types for all variables
        for var in ssa.variables() {
            interference.set_type(var.id(), var.var_type().clone());
        }

        // Build CFG for dataflow analysis
        let cfg = SsaCfg::from_ssa(ssa);

        // Run liveness analysis
        let analysis = LiveVariables::new(ssa);
        let solver = DataFlowSolver::new(analysis);
        let results = solver.solve(ssa, &cfg);

        // Collect block IDs for parallel processing
        let block_ids: Vec<usize> = (0..ssa.block_count()).collect();

        // Phase 1: Collect boundary edges in parallel
        // Each block independently computes its interference edges
        let boundary_edges: Vec<(SsaVarId, SsaVarId)> = block_ids
            .par_iter()
            .flat_map(|&block_id| {
                let mut edges = Vec::new();

                // Edges from live_out
                if let Some(live_out) = results.out_state(block_id) {
                    let live_vars: Vec<SsaVarId> = live_out.variables().collect();
                    for (i, &var1) in live_vars.iter().enumerate() {
                        for &var2 in &live_vars[i + 1..] {
                            edges.push((var1, var2));
                        }
                    }
                }

                // Edges from live_in
                if let Some(live_in) = results.in_state(block_id) {
                    let live_vars: Vec<SsaVarId> = live_in.variables().collect();
                    for (i, &var1) in live_vars.iter().enumerate() {
                        for &var2 in &live_vars[i + 1..] {
                            edges.push((var1, var2));
                        }
                    }
                }

                edges
            })
            .collect();

        // Phase 2: Collect intra-block edges in parallel
        let intra_block_edges: Vec<(SsaVarId, SsaVarId)> = block_ids
            .par_iter()
            .flat_map(|&block_id| Self::collect_intra_block_edges(ssa, &results, block_id))
            .collect();

        // Phase 3: Collect PHI edge interference
        // PHI operands from the same predecessor edge are all live at that edge,
        // so they must interfere. This is critical for correct parallel copy semantics.
        let phi_edge_edges: Vec<(SsaVarId, SsaVarId)> = ssa
            .blocks()
            .par_iter()
            .flat_map(|block| {
                let mut edges = Vec::new();

                // Group PHI operands by predecessor
                let mut operands_by_pred: BTreeMap<usize, Vec<SsaVarId>> = BTreeMap::new();
                for phi in block.phi_nodes() {
                    for operand in phi.operands() {
                        operands_by_pred
                            .entry(operand.predecessor())
                            .or_default()
                            .push(operand.value());
                    }
                }

                // All operands from the same predecessor interfere with each other
                for (_, operands) in operands_by_pred {
                    for (i, &var1) in operands.iter().enumerate() {
                        for &var2 in &operands[i + 1..] {
                            edges.push((var1, var2));
                        }
                    }
                }

                edges
            })
            .collect();

        // Phase 4: Collect cross-subtree interference edges
        //
        // The codegen's dependency-driven scheduler processes root instructions
        // (terminators, side-effect ops, dead computations) by generating their
        // complete dependency subtrees in sequence. This can reorder operations
        // relative to the original SSA instruction order. Variables from different
        // root subtrees must interfere to prevent the scheduler from causing
        // slot conflicts when it interleaves subtrees.
        let cross_subtree_edges: Vec<(SsaVarId, SsaVarId)> = block_ids
            .par_iter()
            .flat_map(|&block_id| Self::collect_cross_subtree_edges(ssa, block_id))
            .collect();

        // Phase 5: Merge all edges into the interference graph
        for (a, b) in boundary_edges {
            interference.add_edge(a, b);
        }
        for (a, b) in intra_block_edges {
            interference.add_edge(a, b);
        }
        for (a, b) in phi_edge_edges {
            interference.add_edge(a, b);
        }
        for (a, b) in cross_subtree_edges {
            interference.add_edge(a, b);
        }

        // Collect variables that need allocation (Phi-origin variables are freely
        // coalescable, while original locals and arguments keep their fixed slots).
        let coalescable_vars: Vec<SsaVarId> = ssa
            .variables()
            .iter()
            .filter_map(|v| match v.origin() {
                VariableOrigin::Phi => Some(v.id()),
                VariableOrigin::Argument(_) | VariableOrigin::Local(_) => None,
            })
            .collect();

        Self {
            interference,
            coalescable_vars,
            precomputed: None,
        }
    }

    /// Builds using linear scan algorithm.
    ///
    /// Computes live intervals for each variable and allocates slots in a single
    /// pass. Produces near-optimal results (within 5-10% of graph coloring) with
    /// much better performance for large SSAs.
    ///
    /// Complexity: O(n log n) for n variables
    fn build_linear_scan(ssa: &SsaFunction) -> Self {
        // Collect variable types for compatibility checking
        let mut var_types: BTreeMap<SsaVarId, SsaType> = BTreeMap::new();
        for var in ssa.variables() {
            var_types.insert(var.id(), var.var_type().clone());
        }

        // Compute live intervals for each variable
        let intervals = Self::compute_live_intervals(ssa);

        // Pre-assign fixed slots for arguments and used original locals.
        // Collect Local-origin variables that have live intervals (are actually used).
        // Phi-origin variables go through linear scan allocation separately.
        let mut used_local_vars: Vec<(SsaVarId, u16)> = ssa
            .variables()
            .iter()
            .filter_map(|v| {
                if let VariableOrigin::Local(idx) = v.origin() {
                    if intervals.contains_key(&v.id()) {
                        return Some((v.id(), idx));
                    }
                }
                None
            })
            .collect();
        // Sort by original index for deterministic ordering
        used_local_vars.sort_by_key(|(_, idx)| *idx);

        let PreAssignment {
            mut var_to_local,
            reserved_slots,
            original_to_new,
            mut next_local,
        } = pre_assign_locals(ssa, &used_local_vars);

        // Sort intervals by start position, with (origin, version) as tiebreaker for determinism.
        // The secondary key ensures stable ordering when multiple variables share the same
        // start position.
        let mut sorted_intervals: Vec<_> = intervals.into_iter().collect();
        sorted_intervals.sort_by(|(var_id_a, interval_a), (var_id_b, interval_b)| {
            interval_a
                .start
                .cmp(&interval_b.start)
                .then_with(|| var_sort_key(ssa, *var_id_a).cmp(&var_sort_key(ssa, *var_id_b)))
        });

        // Active list: heap sorted by end position (earliest end first).
        // Heap payload is just `(end, slot)` — we look up the slot's exact
        // type in `slot_types` below when we need it (SsaType isn't `Ord`).
        let mut active: BinaryHeap<Reverse<(usize, u16)>> = BinaryHeap::new();
        // Per-slot exact type (indexed by slot id), used to tag free slots
        // with the precise type they last held so reuse obeys the CIL
        // exact-type-match rule for Reference-class locals.
        let mut slot_type: BTreeMap<u16, SsaType> = BTreeMap::new();

        // Free slots available for reuse, tagged with the exact type they last
        // held. We key this pool by exact type (not just `TypeClass`) so we
        // never recycle e.g. a `bool&` slot for a `string` or `object` value;
        // `is_compatible_for_storage` then governs which types may share.
        // A plain Vec is fine here — allocation count is bounded by live
        // variables, so the linear search on pop stays small in practice.
        let mut free_slots: Vec<(SsaType, u16)> = Vec::new();

        // Linear scan allocation
        for (var_id, interval) in sorted_intervals {
            // Skip if already allocated (arguments, original locals)
            // BUT add them to the active list so their slots aren't reused!
            if var_to_local.contains_key(&var_id) {
                // If this is a Local-origin variable that was pre-assigned,
                // add it to the active list so its slot isn't reused while live
                if let Some(slot) = var_to_local.get(&var_id) {
                    let ty = var_types.get(&var_id).cloned().unwrap_or(SsaType::Unknown);
                    slot_type.insert(*slot, ty);
                    active.push(Reverse((interval.end, *slot)));
                }
                continue;
            }

            // Expire old intervals - return their slots to free pool
            // BUT don't return reserved Local-origin slots to the pool
            while let Some(Reverse((end, _slot))) = active.peek() {
                if *end > interval.start {
                    break;
                }
                let Reverse((_, slot)) = active.pop().unwrap();
                // Only add to free pool if not a reserved slot
                if !reserved_slots.contains(slot as usize) {
                    let ty = slot_type.get(&slot).cloned().unwrap_or(SsaType::Unknown);
                    free_slots.push((ty, slot));
                }
            }

            // Pick this variable's type
            let var_type = var_types.get(&var_id).cloned().unwrap_or(SsaType::Unknown);

            // Try to reuse a free slot whose stored type is compatible with
            // the requesting variable's type. Linear scan is acceptable since
            // the free pool is bounded by concurrently-live variables.
            let slot = {
                let pick = free_slots
                    .iter()
                    .position(|(ty, _)| ty.is_compatible_for_storage(&var_type));
                pick.map(|i| free_slots.swap_remove(i).1)
            };

            let slot = slot.unwrap_or_else(|| {
                let s = next_local;
                next_local += 1;
                s
            });

            var_to_local.insert(var_id, slot);
            slot_type.insert(slot, var_type.clone());

            // Add to active list
            active.push(Reverse((interval.end, slot)));
        }

        let allocation = LocalAllocation {
            var_to_local,
            num_locals: next_local,
            original_to_compacted: original_to_new,
        };

        Self {
            interference: InterferenceGraph::new(0),
            coalescable_vars: Vec::new(),
            precomputed: Some(allocation),
        }
    }

    /// Computes live intervals for all variables in the SSA.
    ///
    /// A live interval is the range [start, end) where a variable is live.
    /// We use instruction indices within a linearized view of the CFG.
    fn compute_live_intervals(ssa: &SsaFunction) -> BTreeMap<SsaVarId, LiveInterval> {
        let mut intervals: BTreeMap<SsaVarId, LiveInterval> = BTreeMap::new();

        // Phase 1: Build a map of block → end instruction index.
        // PHI operands are semantically used at the END of the predecessor
        // block (not at the PHI's block), so we need to know each block's
        // end position to correctly extend operand intervals.
        let mut block_end_idx: Vec<usize> = Vec::with_capacity(ssa.block_count());
        {
            let mut idx = 0usize;
            for block_id in 0..ssa.block_count() {
                if let Some(block) = ssa.block(block_id) {
                    idx += block.instructions().len();
                }
                block_end_idx.push(idx);
            }
        }

        // Phase 2: Assign instruction indices by walking blocks in order
        let mut instr_idx = 0usize;

        for block_id in 0..ssa.block_count() {
            let Some(block) = ssa.block(block_id) else {
                continue;
            };

            // Phi nodes define at block entry
            for phi in block.phi_nodes() {
                let def = phi.result();
                intervals
                    .entry(def)
                    .or_insert_with(|| LiveInterval::new(instr_idx))
                    .extend_start(instr_idx);

                // PHI operands are used at the END of their predecessor block.
                // A variable v in `v<-B_pred` must be live from its definition
                // through the end of B_pred. If B_pred comes AFTER the PHI's
                // block in the linearized layout, extending only to the PHI
                // position would leave a gap where the local slot can be reused.
                for operand in phi.operands() {
                    let pred = operand.predecessor();
                    let pred_end = if pred < block_end_idx.len() {
                        block_end_idx[pred]
                    } else {
                        instr_idx + 1
                    };
                    // Use the later of: PHI position or predecessor end
                    let use_point = pred_end.max(instr_idx + 1);
                    intervals
                        .entry(operand.value())
                        .or_insert_with(|| LiveInterval::new(instr_idx))
                        .extend_end(use_point);
                }
            }

            // Process instructions
            for instr in block.instructions() {
                // Uses extend the interval
                for &use_var in &instr.uses() {
                    intervals
                        .entry(use_var)
                        .or_insert_with(|| LiveInterval::new(instr_idx))
                        .extend_end(instr_idx + 1);
                }

                // Definitions start the interval
                if let Some(def) = instr.def() {
                    intervals
                        .entry(def)
                        .or_insert_with(|| LiveInterval::new(instr_idx))
                        .extend_start(instr_idx);
                }

                instr_idx += 1;
            }
        }

        intervals
    }

    /// Collects interference edges from intra-block liveness for a single block.
    ///
    /// Returns a vector of edge pairs that can be merged later.
    fn collect_intra_block_edges(
        ssa: &SsaFunction,
        results: &AnalysisResults<LivenessResult>,
        block_id: usize,
    ) -> Vec<(SsaVarId, SsaVarId)> {
        let mut edges = Vec::new();
        let var_count = ssa.var_id_capacity();

        let Some(block) = ssa.block(block_id) else {
            return edges;
        };

        // Start with live_out from this block
        let mut live = BitSet::new(var_count);
        if let Some(live_out) = results.out_state(block_id) {
            for var in live_out.variables() {
                live.insert(var.index());
            }
        }

        // Walk instructions backwards
        for instr in block.instructions().iter().rev() {
            // If this instruction defines a variable, it interferes with all live vars
            if let Some(def) = instr.def() {
                for live_idx in live.iter() {
                    let live_var = SsaVarId::from_index(live_idx);
                    if live_var != def {
                        edges.push((def, live_var));
                    }
                }
                // The defined variable is no longer live before this point
                live.remove(def.index());
            }

            // Uses make variables live
            for &use_var in &instr.uses() {
                live.insert(use_var.index());
            }
        }

        // Handle phi nodes (they define at block entry)
        for phi in block.phi_nodes() {
            let def = phi.result();
            for live_idx in live.iter() {
                let live_var = SsaVarId::from_index(live_idx);
                if live_var != def {
                    edges.push((def, live_var));
                }
            }
        }

        edges
    }

    /// Collects interference edges between variables from different root subtrees.
    ///
    /// The codegen's dependency-driven scheduler processes root instructions by
    /// generating their complete dependency subtrees in sequence. Since subtrees
    /// can be executed in any relative order, variables from different subtrees
    /// must be treated as potentially simultaneously live.
    ///
    /// For each block with multiple roots, this function:
    /// 1. Identifies root instructions (those not consumed by other in-block ops)
    /// 2. Assigns each instruction to the first root subtree that claims it (via DFS)
    /// 3. Adds interference edges between all variable pairs from different subtrees
    fn collect_cross_subtree_edges(
        ssa: &SsaFunction,
        block_id: usize,
    ) -> Vec<(SsaVarId, SsaVarId)> {
        let Some(block) = ssa.block(block_id) else {
            return Vec::new();
        };

        let instructions = block.instructions();
        if instructions.len() <= 1 {
            return Vec::new();
        }

        // Build def_map: variable -> instruction index within this block
        let mut def_map: BTreeMap<SsaVarId, usize> = BTreeMap::new();
        for (idx, instr) in instructions.iter().enumerate() {
            if let Some(dest) = instr.def() {
                def_map.insert(dest, idx);
            }
        }

        // Identify which variables are used as operands within this block
        let var_count = ssa.var_id_capacity();
        let mut used_in_block = BitSet::new(var_count);
        for instr in instructions {
            for use_var in instr.uses() {
                used_in_block.insert(use_var.index());
            }
        }

        // Find root instructions: those whose results are NOT used by other ops
        // in this block, or that have no result (side-effect only / terminators)
        let roots: Vec<usize> = instructions
            .iter()
            .enumerate()
            .filter_map(|(idx, instr)| {
                let is_root = match instr.def() {
                    Some(dest) => {
                        !used_in_block.contains(dest.index())
                            || matches!(
                                instr.op(),
                                SsaOp::Jump { .. }
                                    | SsaOp::Branch { .. }
                                    | SsaOp::BranchCmp { .. }
                                    | SsaOp::Switch { .. }
                                    | SsaOp::Return { .. }
                                    | SsaOp::Throw { .. }
                                    | SsaOp::Rethrow
                                    | SsaOp::Leave { .. }
                                    | SsaOp::EndFinally
                                    | SsaOp::EndFilter { .. }
                            )
                    }
                    None => true,
                };
                if is_root {
                    Some(idx)
                } else {
                    None
                }
            })
            .collect();

        if roots.len() <= 1 {
            return Vec::new();
        }

        // Assign each instruction to a root subtree via DFS.
        // The first subtree (in root order) to reach an instruction claims it.
        // This models the scheduler: subtrees processed first claim shared deps.
        let mut instr_to_subtree: Vec<Option<usize>> = vec![None; instructions.len()];
        for (subtree_id, &root_idx) in roots.iter().enumerate() {
            let mut stack = vec![root_idx];
            while let Some(idx) = stack.pop() {
                if instr_to_subtree[idx].is_some() {
                    continue;
                }
                instr_to_subtree[idx] = Some(subtree_id);

                // Follow dependency edges: operands defined in this block
                for use_var in instructions[idx].uses() {
                    if let Some(&dep_idx) = def_map.get(&use_var) {
                        if instr_to_subtree[dep_idx].is_none() {
                            stack.push(dep_idx);
                        }
                    }
                }
            }
        }

        // Group defined variables by their subtree
        let num_subtrees = roots.len();
        let mut subtree_vars: Vec<Vec<SsaVarId>> = vec![Vec::new(); num_subtrees];
        for (idx, instr) in instructions.iter().enumerate() {
            if let (Some(dest), Some(subtree_id)) = (instr.def(), instr_to_subtree[idx]) {
                subtree_vars[subtree_id].push(dest);
            }
        }

        // Add interference edges between all variable pairs from different subtrees
        let mut edges = Vec::new();
        for i in 0..num_subtrees {
            for j in (i + 1)..num_subtrees {
                for &var_a in &subtree_vars[i] {
                    for &var_b in &subtree_vars[j] {
                        edges.push((var_a, var_b));
                    }
                }
            }
        }

        edges
    }

    /// Allocates local slots for SSA variables.
    ///
    /// Returns a mapping from SSA variables to local slots, minimizing the
    /// total number of locals needed. Uses the result from whatever algorithm
    /// was selected during `build()`.
    pub fn allocate(&self, ssa: &SsaFunction) -> Result<LocalAllocation> {
        // If we used linear scan, the allocation is already computed
        if let Some(precomputed) = &self.precomputed {
            return Ok(LocalAllocation {
                var_to_local: precomputed.var_to_local.clone(),
                num_locals: precomputed.num_locals,
                original_to_compacted: precomputed.original_to_compacted.clone(),
            });
        }

        // Otherwise use graph coloring allocation
        self.allocate_graph_coloring(ssa)
    }

    /// Allocates local slots using greedy graph coloring.
    fn allocate_graph_coloring(&self, ssa: &SsaFunction) -> Result<LocalAllocation> {
        let var_count = ssa.variable_count();

        // First, collect which Local-origin variables are actually USED.
        // Phi-origin variables go through graph coloring allocation separately.
        let slot_capacity = var_count.max(self.coalescable_vars.len() + 1).max(64);
        let mut used_local_var_ids = BitSet::new(slot_capacity);
        for block in ssa.blocks() {
            for phi in block.phi_nodes() {
                // Check phi result
                if let Some(var) = ssa.variable(phi.result()) {
                    if matches!(var.origin(), VariableOrigin::Local(_)) {
                        used_local_var_ids.insert(phi.result().index());
                    }
                }
                // Check phi operands
                for operand in phi.operands() {
                    if let Some(var) = ssa.variable(operand.value()) {
                        if matches!(var.origin(), VariableOrigin::Local(_)) {
                            used_local_var_ids.insert(operand.value().index());
                        }
                    }
                }
            }
            for instr in block.instructions() {
                let op = instr.op();
                // Check destination
                if let Some(dest) = op.dest() {
                    if let Some(var) = ssa.variable(dest) {
                        if matches!(var.origin(), VariableOrigin::Local(_)) {
                            used_local_var_ids.insert(dest.index());
                        }
                    }
                }
                // Check uses
                for use_var in op.uses() {
                    if let Some(var) = ssa.variable(use_var) {
                        if matches!(var.origin(), VariableOrigin::Local(_)) {
                            used_local_var_ids.insert(use_var.index());
                        }
                    }
                }
            }
        }

        // Collect Local-origin variables sorted by original index for deterministic ordering
        let mut local_vars: Vec<(SsaVarId, u16)> = ssa
            .variables()
            .iter()
            .filter_map(|v| {
                if let VariableOrigin::Local(idx) = v.origin() {
                    if used_local_var_ids.contains(v.id().index()) {
                        return Some((v.id(), idx));
                    }
                }
                None
            })
            .collect();
        local_vars.sort_by_key(|(_, idx)| *idx);

        let PreAssignment {
            mut var_to_local,
            reserved_slots,
            original_to_new,
            mut next_local,
        } = pre_assign_locals(ssa, &local_vars);

        // Sort coalescable variables by degree (most constrained first)
        // This is a simple heuristic that often produces good colorings.
        // Use (origin, version) as secondary key for deterministic ordering when degrees are equal.
        let mut sorted_vars = self.coalescable_vars.clone();
        sorted_vars.sort_by(|a, b| {
            let deg_a = self.interference.degree(*a);
            let deg_b = self.interference.degree(*b);
            deg_b
                .cmp(&deg_a)
                .then_with(|| var_sort_key(ssa, *a).cmp(&var_sort_key(ssa, *b)))
        });

        // Greedy coloring with type compatibility
        for var in sorted_vars {
            // Find slots used by interfering neighbors
            let mut used_slots = BitSet::new(slot_capacity);
            for neighbor in self.interference.neighbors(var) {
                if let Some(&slot) = var_to_local.get(&neighbor) {
                    used_slots.insert(slot as usize);
                }
            }

            // Get this variable's type for compatibility checking
            let var_type = self.interference.var_types.get(&var);

            // Find first available slot that is type-compatible
            // Skip reserved slots (those belonging to Local-origin variables)
            // Safe: will always find a slot since u16 range exceeds possible variable count
            #[allow(clippy::maybe_infinite_iter)]
            let slot = (0u16..)
                .find(|&s| {
                    // Skip reserved slots - they belong to Local-origin variables
                    if reserved_slots.contains(s as usize) {
                        return false;
                    }

                    // Slot must not be used by an interfering variable
                    if used_slots.contains(s as usize) {
                        return false;
                    }

                    // Check type compatibility with any variable already using this slot
                    for (&other_var, &other_slot) in &var_to_local {
                        if other_slot == s {
                            let other_type = self.interference.var_types.get(&other_var);
                            if !types_compatible(var_type, other_type) {
                                return false;
                            }
                        }
                    }

                    true
                })
                .ok_or_else(|| Error::CodegenFailed("Should always find a valid slot".into()))?;

            var_to_local.insert(var, slot);
            next_local = next_local.max(slot + 1);
        }

        Ok(LocalAllocation {
            var_to_local,
            num_locals: next_local,
            original_to_compacted: original_to_new,
        })
    }
}

/// Pre-assignment result for local variables.
///
/// Contains the initial slot assignments for Local-origin and LoadLocal-referenced
/// variables, along with tracking state for the allocation phase.
struct PreAssignment {
    /// Map from SSA variable ID to assigned local slot.
    var_to_local: BTreeMap<SsaVarId, u16>,
    /// Slots reserved for Local-origin variables (must not be reused).
    reserved_slots: BitSet,
    /// Map from original local index to compacted index.
    original_to_new: BTreeMap<u16, u16>,
    /// Next available local slot index.
    next_local: u16,
}

/// Pre-assigns local slots for Local-origin and LoadLocal-referenced variables.
///
/// This shared logic is used by both graph coloring and linear scan algorithms.
/// It assigns consecutive slots to used Local-origin variables (deduplicating
/// SSA versions of the same original local) and ensures LoadLocal/LoadLocalAddr-
/// referenced locals also get compacted entries.
///
/// `used_local_vars` must be a pre-filtered, sorted list of `(var_id, original_local_index)`
/// pairs representing Local-origin variables that are actually used.
fn pre_assign_locals(ssa: &SsaFunction, used_local_vars: &[(SsaVarId, u16)]) -> PreAssignment {
    let var_count = ssa.variable_count();
    let slot_capacity = var_count.max(64);
    let mut var_to_local: BTreeMap<SsaVarId, u16> = BTreeMap::new();
    let mut reserved_slots = BitSet::new(slot_capacity);
    let mut original_to_new: BTreeMap<u16, u16> = BTreeMap::new();
    let mut next_local: u16 = 0;

    // Assign consecutive slots to USED Local-origin variables.
    // All SSA versions of the same original local share the same physical slot.
    for &(var_id, original_idx) in used_local_vars {
        let new_slot = *original_to_new.entry(original_idx).or_insert_with(|| {
            let slot = next_local;
            next_local += 1;
            slot
        });
        var_to_local.insert(var_id, new_slot);
        reserved_slots.insert(new_slot as usize);
    }

    // Ensure LoadLocal/LoadLocalAddr-referenced locals also get compacted entries.
    // These reference locals by index (not SSA variable), so the coalescer's
    // liveness analysis doesn't see them.
    let mut load_referenced_locals = BitSet::new(slot_capacity);
    for block in ssa.blocks() {
        for instr in block.instructions() {
            match instr.op() {
                SsaOp::LoadLocal { local_index, .. } | SsaOp::LoadLocalAddr { local_index, .. } => {
                    load_referenced_locals.insert(*local_index as usize);
                }
                _ => {}
            }
        }
    }
    let mut sorted_load_refs: Vec<u16> = load_referenced_locals.iter().map(|i| i as u16).collect();
    sorted_load_refs.sort_unstable();
    for original_idx in sorted_load_refs {
        original_to_new.entry(original_idx).or_insert_with(|| {
            let slot = next_local;
            next_local += 1;
            reserved_slots.insert(slot as usize);
            slot
        });
    }

    PreAssignment {
        var_to_local,
        reserved_slots,
        original_to_new,
        next_local,
    }
}

/// Builds a stable sort key for an SSA variable.
///
/// Returns `(origin, version)` which is deterministic within a method,
/// unlike `SsaVarId` which depends on global allocation order.
fn var_sort_key(ssa: &SsaFunction, var_id: SsaVarId) -> (VariableOrigin, u32) {
    ssa.variable(var_id)
        .map_or((VariableOrigin::Phi, u32::MAX), |v| {
            (v.origin(), v.version())
        })
}

/// Checks if two types can share the same local slot.
///
/// Types are compatible if they have the same size and alignment requirements.
fn types_compatible(t1: Option<&SsaType>, t2: Option<&SsaType>) -> bool {
    match (t1, t2) {
        (None, _) | (_, None) => true, // Unknown types are conservatively compatible
        (Some(a), Some(b)) => a.is_compatible_for_storage(b),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeSet;

    use crate::analysis::{SsaFunctionBuilder, SsaType, SsaVarId};

    /// Helper to create N unique SsaVarIds
    fn make_vars(n: usize) -> Vec<SsaVarId> {
        (0..n).map(SsaVarId::from_index).collect()
    }

    #[test]
    fn test_interference_graph_add_edge() {
        let mut graph = InterferenceGraph::new(10);
        let vars = make_vars(3);
        let (var_a, var_b, var_c) = (vars[0], vars[1], vars[2]);

        // Adding edge creates bidirectional interference
        graph.add_edge(var_a, var_b);
        assert_eq!(graph.degree(var_a), 1);
        assert_eq!(graph.degree(var_b), 1);
        assert_eq!(graph.degree(var_c), 0);

        // Neighbors are correct
        let neighbors_a: Vec<_> = graph.neighbors(var_a).collect();
        assert_eq!(neighbors_a, vec![var_b]);

        let neighbors_b: Vec<_> = graph.neighbors(var_b).collect();
        assert_eq!(neighbors_b, vec![var_a]);

        // Adding same edge again doesn't increase degree
        graph.add_edge(var_a, var_b);
        assert_eq!(graph.degree(var_a), 1);

        // Self-edges are ignored
        graph.add_edge(var_a, var_a);
        assert_eq!(graph.degree(var_a), 1);
    }

    #[test]
    fn test_interference_graph_multiple_edges() {
        let mut graph = InterferenceGraph::new(10);
        let vars = make_vars(5);

        // Create a clique of 3 variables (all interfere with each other)
        graph.add_edge(vars[0], vars[1]);
        graph.add_edge(vars[0], vars[2]);
        graph.add_edge(vars[1], vars[2]);

        // Each has degree 2
        assert_eq!(graph.degree(vars[0]), 2);
        assert_eq!(graph.degree(vars[1]), 2);
        assert_eq!(graph.degree(vars[2]), 2);

        // vars[3] and vars[4] are isolated
        assert_eq!(graph.degree(vars[3]), 0);
        assert_eq!(graph.degree(vars[4]), 0);
    }

    #[test]
    fn test_type_compatibility_same_class() {
        // Same types are compatible
        assert!(types_compatible(Some(&SsaType::I32), Some(&SsaType::I32)));

        // 32-bit integers are compatible with each other
        assert!(types_compatible(Some(&SsaType::I32), Some(&SsaType::U32)));
        assert!(types_compatible(Some(&SsaType::I32), Some(&SsaType::Bool)));
        assert!(types_compatible(Some(&SsaType::Bool), Some(&SsaType::Char)));

        // 64-bit integers are compatible
        assert!(types_compatible(Some(&SsaType::I64), Some(&SsaType::U64)));

        // Different reference types are NOT compatible (CIL verifier requires
        // exact type match on stloc/ldloc for reference types)
        assert!(!types_compatible(
            Some(&SsaType::Object),
            Some(&SsaType::String)
        ));

        // Same reference types ARE compatible
        assert!(types_compatible(
            Some(&SsaType::String),
            Some(&SsaType::String)
        ));
    }

    #[test]
    fn test_type_compatibility_different_class() {
        // Different size integers are not compatible
        assert!(!types_compatible(Some(&SsaType::I32), Some(&SsaType::I64)));

        // Integer and reference are not compatible
        assert!(!types_compatible(
            Some(&SsaType::I32),
            Some(&SsaType::Object)
        ));

        // Different float sizes are not compatible
        assert!(!types_compatible(Some(&SsaType::F32), Some(&SsaType::F64)));

        // Integer and float are not compatible
        assert!(!types_compatible(Some(&SsaType::I32), Some(&SsaType::F32)));
    }

    #[test]
    fn test_type_compatibility_with_none() {
        // None (unknown) is conservatively compatible with anything
        assert!(types_compatible(None, Some(&SsaType::I32)));
        assert!(types_compatible(Some(&SsaType::I32), None));
        assert!(types_compatible(None, None));
    }

    #[test]
    fn test_greedy_coloring_non_interfering_same_slot() {
        // When variables don't interfere, they should share the same slot
        let mut graph = InterferenceGraph::new(10);
        let vars = make_vars(2);
        let (var_a, var_b) = (vars[0], vars[1]);

        // Both have compatible types but no interference edge
        graph.set_type(var_a, SsaType::I32);
        graph.set_type(var_b, SsaType::I32);
        // Note: no add_edge call - they don't interfere

        let coalescer = LocalCoalescer {
            interference: graph,
            coalescable_vars: vec![var_a, var_b],
            precomputed: None,
        };

        // Create a minimal SSA function for allocation
        let ssa = create_minimal_ssa_function();
        let allocation = coalescer.allocate(&ssa).unwrap();

        // Non-interfering variables with compatible types should share slot 0
        assert_eq!(allocation.var_to_local.get(&var_a), Some(&0));
        assert_eq!(allocation.var_to_local.get(&var_b), Some(&0));
        assert_eq!(allocation.num_locals, 1);
    }

    #[test]
    fn test_greedy_coloring_interfering_different_slots() {
        // When variables interfere, they must get different slots
        let mut graph = InterferenceGraph::new(10);
        let vars = make_vars(2);
        let (var_a, var_b) = (vars[0], vars[1]);

        graph.set_type(var_a, SsaType::I32);
        graph.set_type(var_b, SsaType::I32);
        graph.add_edge(var_a, var_b); // They interfere!

        let coalescer = LocalCoalescer {
            interference: graph,
            coalescable_vars: vec![var_a, var_b],
            precomputed: None,
        };

        let ssa = create_minimal_ssa_function();
        let allocation = coalescer.allocate(&ssa).unwrap();

        // Interfering variables must have different slots
        let slot_a = allocation.var_to_local.get(&var_a).unwrap();
        let slot_b = allocation.var_to_local.get(&var_b).unwrap();
        assert_ne!(slot_a, slot_b);
        assert_eq!(allocation.num_locals, 2);
    }

    #[test]
    fn test_greedy_coloring_type_incompatible_different_slots() {
        // Even non-interfering variables need different slots if types are incompatible
        let mut graph = InterferenceGraph::new(10);
        let vars = make_vars(2);
        let (var_a, var_b) = (vars[0], vars[1]);

        graph.set_type(var_a, SsaType::I32);
        graph.set_type(var_b, SsaType::I64); // Different type class!
                                             // No interference edge - they're not live at the same time

        let coalescer = LocalCoalescer {
            interference: graph,
            coalescable_vars: vec![var_a, var_b],
            precomputed: None,
        };

        let ssa = create_minimal_ssa_function();
        let allocation = coalescer.allocate(&ssa).unwrap();

        // Type-incompatible variables must have different slots
        let slot_a = allocation.var_to_local.get(&var_a).unwrap();
        let slot_b = allocation.var_to_local.get(&var_b).unwrap();
        assert_ne!(slot_a, slot_b);
        assert_eq!(allocation.num_locals, 2);
    }

    #[test]
    fn test_greedy_coloring_clique_needs_n_colors() {
        // A clique of n nodes needs n colors (slots)
        let mut graph = InterferenceGraph::new(10);
        let vars = make_vars(4);

        // Create a clique - all 4 variables interfere with each other
        for i in 0..4 {
            graph.set_type(vars[i], SsaType::I32);
            for j in (i + 1)..4 {
                graph.add_edge(vars[i], vars[j]);
            }
        }

        let coalescer = LocalCoalescer {
            interference: graph,
            coalescable_vars: vars.clone(),
            precomputed: None,
        };

        let ssa = create_minimal_ssa_function();
        let allocation = coalescer.allocate(&ssa).unwrap();

        // All 4 must have unique slots
        let slots: BTreeSet<_> = vars
            .iter()
            .filter_map(|v| allocation.var_to_local.get(v).copied())
            .collect();
        assert_eq!(slots.len(), 4);
        assert_eq!(allocation.num_locals, 4);
    }

    #[test]
    fn test_greedy_coloring_chain_needs_2_colors() {
        // A chain graph (v0-v1-v2-v3) is 2-colorable
        let mut graph = InterferenceGraph::new(10);
        let vars = make_vars(4);

        // Chain: 0-1-2-3
        for var in &vars {
            graph.set_type(*var, SsaType::I32);
        }
        graph.add_edge(vars[0], vars[1]);
        graph.add_edge(vars[1], vars[2]);
        graph.add_edge(vars[2], vars[3]);

        let coalescer = LocalCoalescer {
            interference: graph,
            coalescable_vars: vars.clone(),
            precomputed: None,
        };

        let ssa = create_minimal_ssa_function();
        let allocation = coalescer.allocate(&ssa).unwrap();

        // Adjacent variables must have different slots
        for i in 0..3 {
            let slot_i = allocation.var_to_local.get(&vars[i]).unwrap();
            let slot_j = allocation.var_to_local.get(&vars[i + 1]).unwrap();
            assert_ne!(
                slot_i,
                slot_j,
                "Adjacent vars {} and {} share slot",
                i,
                i + 1
            );
        }

        // Chain is 2-colorable, so at most 2 slots needed
        assert!(allocation.num_locals <= 2);
    }

    #[test]
    fn test_mixed_types_coalesce_within_class() {
        // Variables of compatible types that don't interfere should share slots
        let mut graph = InterferenceGraph::new(10);
        let vars = make_vars(5);
        let (var_i32, var_u32, var_bool, var_i64, var_u64) =
            (vars[0], vars[1], vars[2], vars[3], vars[4]);

        // All Int32-class types (should share one slot)
        graph.set_type(var_i32, SsaType::I32);
        graph.set_type(var_u32, SsaType::U32);
        graph.set_type(var_bool, SsaType::Bool);
        // All Int64-class types (should share another slot)
        graph.set_type(var_i64, SsaType::I64);
        graph.set_type(var_u64, SsaType::U64);

        // No interference edges

        let coalescer = LocalCoalescer {
            interference: graph,
            coalescable_vars: vec![var_i32, var_u32, var_bool, var_i64, var_u64],
            precomputed: None,
        };

        let ssa = create_minimal_ssa_function();
        let allocation = coalescer.allocate(&ssa).unwrap();

        // All Int32-class should share slot 0
        assert_eq!(allocation.var_to_local.get(&var_i32), Some(&0));
        assert_eq!(allocation.var_to_local.get(&var_u32), Some(&0));
        assert_eq!(allocation.var_to_local.get(&var_bool), Some(&0));

        // All Int64-class should share slot 1
        assert_eq!(allocation.var_to_local.get(&var_i64), Some(&1));
        assert_eq!(allocation.var_to_local.get(&var_u64), Some(&1));

        assert_eq!(allocation.num_locals, 2);
    }

    /// Creates a minimal SSA function for testing allocation.
    fn create_minimal_ssa_function() -> SsaFunction {
        SsaFunctionBuilder::new(0, 0)
            .build_with(|ctx| {
                ctx.block(0, |b| {
                    b.ret();
                });
            })
            .unwrap()
    }
}
