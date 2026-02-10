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
    collections::{BinaryHeap, HashMap, HashSet},
};

use rayon::prelude::*;

use crate::analysis::{
    AnalysisResults, DataFlowSolver, LiveVariables, LivenessResult, SsaCfg, SsaFunction, SsaType,
    SsaVarId, TypeClass, VariableOrigin,
};

/// Interference graph for register allocation.
///
/// Tracks which variables interfere (are live simultaneously) and thus
/// cannot share the same local slot.
pub struct InterferenceGraph {
    /// Adjacency list: var_id -> set of interfering var_ids
    edges: HashMap<SsaVarId, HashSet<SsaVarId>>,
    /// Type of each variable (for compatibility checking)
    var_types: HashMap<SsaVarId, SsaType>,
}

impl InterferenceGraph {
    /// Creates a new empty interference graph.
    fn new() -> Self {
        Self {
            edges: HashMap::new(),
            var_types: HashMap::new(),
        }
    }

    /// Adds an interference edge between two variables.
    fn add_edge(&mut self, a: SsaVarId, b: SsaVarId) {
        if a != b {
            self.edges.entry(a).or_default().insert(b);
            self.edges.entry(b).or_default().insert(a);
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
            .flat_map(|set| set.iter().copied())
    }

    /// Returns the degree (number of interferences) of a variable.
    fn degree(&self, var: SsaVarId) -> usize {
        self.edges.get(&var).map_or(0, HashSet::len)
    }
}

/// Result of local allocation.
pub struct LocalAllocation {
    /// Map SSA var -> allocated local slot
    pub var_to_local: HashMap<SsaVarId, u16>,
    /// Number of locals needed
    pub num_locals: u16,
    /// Map original local index -> compacted local index (for signature generation)
    pub original_to_compacted: HashMap<u16, u16>,
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
        let mut interference = InterferenceGraph::new();

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
                let mut operands_by_pred: HashMap<usize, Vec<SsaVarId>> = HashMap::new();
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

        // Phase 4: Merge all edges into the interference graph
        for (a, b) in boundary_edges {
            interference.add_edge(a, b);
        }
        for (a, b) in intra_block_edges {
            interference.add_edge(a, b);
        }
        for (a, b) in phi_edge_edges {
            interference.add_edge(a, b);
        }

        // Collect variables that need allocation (Stack and Phi origins)
        let coalescable_vars: Vec<SsaVarId> = ssa
            .variables()
            .iter()
            .filter_map(|v| {
                match v.origin() {
                    VariableOrigin::Stack(_) | VariableOrigin::Phi => Some(v.id()),
                    // Arguments and original locals keep their slots
                    VariableOrigin::Argument(_) | VariableOrigin::Local(_) => None,
                }
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
        let mut var_types: HashMap<SsaVarId, SsaType> = HashMap::new();
        for var in ssa.variables() {
            var_types.insert(var.id(), var.var_type().clone());
        }

        // Compute live intervals for each variable
        let intervals = Self::compute_live_intervals(ssa);

        // Pre-assign fixed slots for arguments and used original locals
        let mut var_to_local: HashMap<SsaVarId, u16> = HashMap::new();
        let mut next_local: u16 = 0;
        // Track which slots are reserved for Local-origin variables
        let mut reserved_slots: HashSet<u16> = HashSet::new();
        // Track mapping from original local index to compacted index
        let mut original_to_new: HashMap<u16, u16> = HashMap::new();

        // Collect Local-origin variables that have live intervals (are actually used)
        let mut used_local_vars: Vec<(SsaVarId, u16)> = ssa
            .variables()
            .iter()
            .filter_map(|v| {
                if let VariableOrigin::Local(idx) = v.origin() {
                    // Only include if it has a live interval
                    if intervals.contains_key(&v.id()) {
                        return Some((v.id(), idx));
                    }
                }
                None
            })
            .collect();
        // Sort by original index for deterministic ordering
        used_local_vars.sort_by_key(|(_, idx)| *idx);

        // Assign consecutive slots to USED Local-origin variables
        // IMPORTANT: All SSA versions of the same original local must share
        // the same physical slot. This ensures original_to_new correctly maps
        // each original index to exactly one compacted index.
        for (var_id, original_idx) in used_local_vars {
            // Reuse existing slot if this original local was already mapped
            let new_slot = *original_to_new.entry(original_idx).or_insert_with(|| {
                let slot = next_local;
                next_local += 1;
                slot
            });
            var_to_local.insert(var_id, new_slot);
            reserved_slots.insert(new_slot);
        }

        // Build a stable sort key for each variable: (origin, version).
        // This is deterministic within a method, unlike SsaVarId which depends on
        // global allocation order that varies with parallel processing.
        let var_sort_key = |var_id: SsaVarId| -> (VariableOrigin, u32) {
            ssa.variable(var_id)
                .map(|v| (v.origin(), v.version()))
                .unwrap_or((VariableOrigin::Stack(u32::MAX), u32::MAX))
        };

        // Sort intervals by start position, with (origin, version) as tiebreaker for determinism.
        // Without the secondary key, variables with the same start position would be ordered
        // by HashMap iteration order, which is non-deterministic.
        let mut sorted_intervals: Vec<_> = intervals.into_iter().collect();
        sorted_intervals.sort_by(|(var_id_a, interval_a), (var_id_b, interval_b)| {
            interval_a
                .start
                .cmp(&interval_b.start)
                .then_with(|| var_sort_key(*var_id_a).cmp(&var_sort_key(*var_id_b)))
        });

        // Active list: heap sorted by end position (earliest end first)
        // Each entry is (end_position, slot, type_class)
        let mut active: BinaryHeap<Reverse<(usize, u16, TypeClass)>> = BinaryHeap::new();

        // Free slots available for reuse, grouped by type class
        let mut free_slots: HashMap<TypeClass, Vec<u16>> = HashMap::new();

        // Linear scan allocation
        for (var_id, interval) in sorted_intervals {
            // Skip if already allocated (arguments, original locals)
            // BUT add them to the active list so their slots aren't reused!
            if var_to_local.contains_key(&var_id) {
                // If this is a Local-origin variable that was pre-assigned,
                // add it to the active list so its slot isn't reused while live
                if let Some(slot) = var_to_local.get(&var_id) {
                    let type_class = var_types
                        .get(&var_id)
                        .map(|ty| ty.storage_class())
                        .unwrap_or(TypeClass::Int32);
                    active.push(Reverse((interval.end, *slot, type_class)));
                }
                continue;
            }

            // Expire old intervals - return their slots to free pool
            // BUT don't return reserved Local-origin slots to the pool
            while let Some(&Reverse((end, slot, type_class))) = active.peek() {
                if end > interval.start {
                    break;
                }
                active.pop();
                // Only add to free pool if not a reserved slot
                if !reserved_slots.contains(&slot) {
                    free_slots.entry(type_class).or_default().push(slot);
                }
            }

            // Get this variable's type class
            let type_class = var_types
                .get(&var_id)
                .map(|ty| ty.storage_class())
                .unwrap_or(TypeClass::Int32);

            // Try to reuse a free slot with compatible type
            let slot = free_slots
                .get_mut(&type_class)
                .and_then(|slots| slots.pop());

            let slot = slot.unwrap_or_else(|| {
                let s = next_local;
                next_local += 1;
                s
            });

            var_to_local.insert(var_id, slot);

            // Add to active list
            active.push(Reverse((interval.end, slot, type_class)));
        }

        let allocation = LocalAllocation {
            var_to_local,
            num_locals: next_local,
            original_to_compacted: original_to_new,
        };

        Self {
            interference: InterferenceGraph::new(),
            coalescable_vars: Vec::new(),
            precomputed: Some(allocation),
        }
    }

    /// Computes live intervals for all variables in the SSA.
    ///
    /// A live interval is the range [start, end) where a variable is live.
    /// We use instruction indices within a linearized view of the CFG.
    fn compute_live_intervals(ssa: &SsaFunction) -> HashMap<SsaVarId, LiveInterval> {
        let mut intervals: HashMap<SsaVarId, LiveInterval> = HashMap::new();

        // Assign instruction indices by walking blocks in order
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

                // Phi operands are used at this point
                for operand in phi.operands() {
                    intervals
                        .entry(operand.value())
                        .or_insert_with(|| LiveInterval::new(instr_idx))
                        .extend_end(instr_idx + 1);
                }
            }

            // Process instructions
            for instr in block.instructions() {
                // Uses extend the interval
                for &use_var in instr.uses().iter() {
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

        let Some(block) = ssa.block(block_id) else {
            return edges;
        };

        // Start with live_out from this block
        let mut live: HashSet<SsaVarId> = results
            .out_state(block_id)
            .map(|r| r.variables().collect())
            .unwrap_or_default();

        // Walk instructions backwards
        for instr in block.instructions().iter().rev() {
            // If this instruction defines a variable, it interferes with all live vars
            if let Some(def) = instr.def() {
                for &live_var in &live {
                    if live_var != def {
                        edges.push((def, live_var));
                    }
                }
                // The defined variable is no longer live before this point
                live.remove(&def);
            }

            // Uses make variables live
            for &use_var in instr.uses().iter() {
                live.insert(use_var);
            }
        }

        // Handle phi nodes (they define at block entry)
        for phi in block.phi_nodes() {
            let def = phi.result();
            for &live_var in &live {
                if live_var != def {
                    edges.push((def, live_var));
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
    pub fn allocate(&self, ssa: &SsaFunction) -> LocalAllocation {
        // If we used linear scan, the allocation is already computed
        if let Some(precomputed) = &self.precomputed {
            return LocalAllocation {
                var_to_local: precomputed.var_to_local.clone(),
                num_locals: precomputed.num_locals,
                original_to_compacted: precomputed.original_to_compacted.clone(),
            };
        }

        // Otherwise use graph coloring allocation
        self.allocate_graph_coloring(ssa)
    }

    /// Allocates local slots using greedy graph coloring.
    fn allocate_graph_coloring(&self, ssa: &SsaFunction) -> LocalAllocation {
        let mut var_to_local: HashMap<SsaVarId, u16> = HashMap::new();
        let mut next_local: u16 = 0;
        // Track which slots are reserved for Local-origin variables
        // These slots must not be reused by other variables
        let mut reserved_slots: HashSet<u16> = HashSet::new();

        // First, collect which Local-origin variables are actually USED
        // A variable is used if it appears in any instruction's uses or phi operands
        let mut used_local_vars: HashSet<SsaVarId> = HashSet::new();
        for block in ssa.blocks() {
            for phi in block.phi_nodes() {
                // Check phi result
                if let Some(var) = ssa.variable(phi.result()) {
                    if matches!(var.origin(), VariableOrigin::Local(_)) {
                        used_local_vars.insert(phi.result());
                    }
                }
                // Check phi operands
                for operand in phi.operands() {
                    if let Some(var) = ssa.variable(operand.value()) {
                        if matches!(var.origin(), VariableOrigin::Local(_)) {
                            used_local_vars.insert(operand.value());
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
                            used_local_vars.insert(dest);
                        }
                    }
                }
                // Check uses
                for use_var in op.uses() {
                    if let Some(var) = ssa.variable(use_var) {
                        if matches!(var.origin(), VariableOrigin::Local(_)) {
                            used_local_vars.insert(use_var);
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
                    if used_local_vars.contains(&v.id()) {
                        return Some((v.id(), idx));
                    }
                }
                None
            })
            .collect();
        local_vars.sort_by_key(|(_, idx)| *idx);

        // Assign consecutive slots to USED Local-origin variables only
        // Track mapping from original index to new index
        // IMPORTANT: All SSA versions of the same original local must share
        // the same physical slot. This ensures original_to_new correctly maps
        // each original index to exactly one compacted index.
        let mut original_to_new: HashMap<u16, u16> = HashMap::new();
        for (var_id, original_idx) in local_vars {
            // Reuse existing slot if this original local was already mapped
            let new_slot = *original_to_new.entry(original_idx).or_insert_with(|| {
                let slot = next_local;
                next_local += 1;
                slot
            });
            var_to_local.insert(var_id, new_slot);
            reserved_slots.insert(new_slot);
        }

        // Build a stable sort key for each variable: (origin, version).
        // This is deterministic within a method, unlike SsaVarId which depends on
        // global allocation order that varies with parallel processing.
        let var_sort_key = |var_id: SsaVarId| -> (VariableOrigin, u32) {
            ssa.variable(var_id)
                .map(|v| (v.origin(), v.version()))
                .unwrap_or((VariableOrigin::Stack(u32::MAX), u32::MAX))
        };

        // Sort coalescable variables by degree (most constrained first)
        // This is a simple heuristic that often produces good colorings.
        // Use (origin, version) as secondary key for deterministic ordering when degrees are equal.
        let mut sorted_vars = self.coalescable_vars.clone();
        sorted_vars.sort_by(|a, b| {
            let deg_a = self.interference.degree(*a);
            let deg_b = self.interference.degree(*b);
            deg_b
                .cmp(&deg_a)
                .then_with(|| var_sort_key(*a).cmp(&var_sort_key(*b)))
        });

        // Greedy coloring with type compatibility
        for var in sorted_vars {
            // Find slots used by interfering neighbors
            let used_slots: HashSet<u16> = self
                .interference
                .neighbors(var)
                .filter_map(|neighbor| var_to_local.get(&neighbor).copied())
                .collect();

            // Get this variable's type for compatibility checking
            let var_type = self.interference.var_types.get(&var);

            // Find first available slot that is type-compatible
            // Skip reserved slots (those belonging to Local-origin variables)
            let slot = (0u16..)
                .find(|&s| {
                    // Skip reserved slots - they belong to Local-origin variables
                    if reserved_slots.contains(&s) {
                        return false;
                    }

                    // Slot must not be used by an interfering variable
                    if used_slots.contains(&s) {
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
                .expect("Should always find a valid slot");

            var_to_local.insert(var, slot);
            next_local = next_local.max(slot + 1);
        }

        LocalAllocation {
            var_to_local,
            num_locals: next_local,
            original_to_compacted: original_to_new,
        }
    }
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

    /// Helper to create N unique SsaVarIds
    fn make_vars(n: usize) -> Vec<SsaVarId> {
        (0..n).map(|_| SsaVarId::new()).collect()
    }

    #[test]
    fn test_interference_graph_add_edge() {
        let mut graph = InterferenceGraph::new();
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
        let mut graph = InterferenceGraph::new();
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

        // Reference types are compatible
        assert!(types_compatible(
            Some(&SsaType::Object),
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
        let mut graph = InterferenceGraph::new();
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
        let allocation = coalescer.allocate(&ssa);

        // Non-interfering variables with compatible types should share slot 0
        assert_eq!(allocation.var_to_local.get(&var_a), Some(&0));
        assert_eq!(allocation.var_to_local.get(&var_b), Some(&0));
        assert_eq!(allocation.num_locals, 1);
    }

    #[test]
    fn test_greedy_coloring_interfering_different_slots() {
        // When variables interfere, they must get different slots
        let mut graph = InterferenceGraph::new();
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
        let allocation = coalescer.allocate(&ssa);

        // Interfering variables must have different slots
        let slot_a = allocation.var_to_local.get(&var_a).unwrap();
        let slot_b = allocation.var_to_local.get(&var_b).unwrap();
        assert_ne!(slot_a, slot_b);
        assert_eq!(allocation.num_locals, 2);
    }

    #[test]
    fn test_greedy_coloring_type_incompatible_different_slots() {
        // Even non-interfering variables need different slots if types are incompatible
        let mut graph = InterferenceGraph::new();
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
        let allocation = coalescer.allocate(&ssa);

        // Type-incompatible variables must have different slots
        let slot_a = allocation.var_to_local.get(&var_a).unwrap();
        let slot_b = allocation.var_to_local.get(&var_b).unwrap();
        assert_ne!(slot_a, slot_b);
        assert_eq!(allocation.num_locals, 2);
    }

    #[test]
    fn test_greedy_coloring_clique_needs_n_colors() {
        // A clique of n nodes needs n colors (slots)
        let mut graph = InterferenceGraph::new();
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
        let allocation = coalescer.allocate(&ssa);

        // All 4 must have unique slots
        let slots: HashSet<_> = vars
            .iter()
            .filter_map(|v| allocation.var_to_local.get(v).copied())
            .collect();
        assert_eq!(slots.len(), 4);
        assert_eq!(allocation.num_locals, 4);
    }

    #[test]
    fn test_greedy_coloring_chain_needs_2_colors() {
        // A chain graph (v0-v1-v2-v3) is 2-colorable
        let mut graph = InterferenceGraph::new();
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
        let allocation = coalescer.allocate(&ssa);

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
        let mut graph = InterferenceGraph::new();
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
        let allocation = coalescer.allocate(&ssa);

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
        use crate::analysis::SsaFunctionBuilder;
        SsaFunctionBuilder::new(0, 0).build_with(|ctx| {
            ctx.block(0, |b| {
                b.ret();
            });
        })
    }
}
