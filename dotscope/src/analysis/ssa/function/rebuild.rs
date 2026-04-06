//! SSA rebuild: reconstructs SSA form after CFG modifications.
//!
//! After passes like control flow unflattening modify the CFG, PHI nodes may
//! reference variables from removed blocks or have incorrect operands. This
//! module provides a structured rebuilder that performs a complete SSA
//! reconstruction using the standard Cytron et al. algorithm.
//!
//! The rebuild is split into named phases, each operating on explicit
//! intermediate state stored in `SsaRebuilder`. This makes the pipeline
//! individually testable and easier to debug.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use crate::{
    analysis::ssa::{
        liveness,
        phis::place_pruned_phis,
        verifier::{SsaVerifier, VerifierError, VerifyLevel},
        DefSite, PhiOperand, SsaBlock, SsaCfg, SsaFunction, SsaOp, SsaType, SsaVarId,
        TrivialPhiOptions, VariableOrigin,
    },
    utils::{
        graph::{
            algorithms::{compute_dominance_frontiers, compute_dominators, DominatorTree},
            NodeId, RootedGraph,
        },
        BitSet,
    },
    Error, Result,
};

/// Immutable context for SSA variable renaming.
///
/// Bundles precomputed data structures needed during the rename phase of SSA
/// construction/rebuild. These are all immutable references that are passed
/// unchanged through recursive calls.
struct RenameContext<'a> {
    /// Maps variable IDs to their origins (Argument, Local, Phi)
    var_origins: &'a BTreeMap<SsaVarId, VariableOrigin>,
    /// Maps group IDs to their SSA types (for preserving type information)
    group_types: &'a BTreeMap<u32, SsaType>,
    /// Maps group IDs to their VariableOrigin (for creating variables)
    group_origins: &'a BTreeMap<u32, VariableOrigin>,
    /// Maps variable IDs to their types (per-variable, for stack-derived locals
    /// where different variables at the same origin can have different types)
    var_types: &'a BTreeMap<SsaVarId, SsaType>,
    /// CFG successor map for filling PHI operands
    successor_map: &'a BTreeMap<usize, Vec<usize>>,
    /// Dominator tree children for recursive traversal
    dom_children: &'a BTreeMap<usize, Vec<usize>>,
    /// Maps block index to ordered list of rename groups for its phi nodes.
    /// Built from `place_pruned_phis` return values so rename can associate
    /// each phi with its group (needed when multiple groups share `Phi` origin).
    phi_groups: &'a BTreeMap<usize, Vec<u32>>,
    /// Number of method arguments (for group ID computation)
    num_args: usize,
}

/// Structured SSA rebuilder.
///
/// Each phase of SSA reconstruction is a named method that reads from
/// and writes to explicit fields. This replaces the former 935-line
/// monolithic `rebuild_ssa()` function.
pub(crate) struct SsaRebuilder<'a> {
    ssa: &'a mut SsaFunction,

    // Phase 1 output: variable origins and types
    var_origins: BTreeMap<SsaVarId, VariableOrigin>,
    /// Maps group ID to SSA type (for preserving type information)
    group_types: BTreeMap<u32, SsaType>,
    /// Maps group ID to its VariableOrigin (for creating phi nodes)
    group_origins: BTreeMap<u32, VariableOrigin>,
    /// Per-variable types: preserves the exact type of each variable across rebuild.
    /// This is needed because stack-derived locals at the same origin can have different
    /// types at different definition points.
    var_types: BTreeMap<SsaVarId, SsaType>,

    // Phase 2 output: CFG analysis
    reachable: BitSet,
    dominance_frontiers: Vec<BitSet>,
    successor_map: BTreeMap<usize, Vec<usize>>,
    dom_children: BTreeMap<usize, Vec<usize>>,

    // Phase 3 output: definition sites (keyed by group ID)
    defs: BTreeMap<u32, BTreeSet<usize>>,

    // Phase 3b output: liveness (keyed by group ID)
    live_in: BTreeMap<u32, BitSet>,

    // Phase 4 output: per-block phi group mapping
    /// Maps block index to ordered list of rename groups for its phi nodes.
    phi_groups: BTreeMap<usize, Vec<u32>>,

    /// Next auto-incrementing group ID for orphans
    next_group: u32,
}

impl<'a> SsaRebuilder<'a> {
    pub fn new(ssa: &'a mut SsaFunction) -> Self {
        let next_group = ssa.num_args as u32 + ssa.num_locals as u32;
        let block_count = ssa.blocks.len();
        Self {
            ssa,
            var_origins: BTreeMap::new(),
            group_types: BTreeMap::new(),
            group_origins: BTreeMap::new(),
            var_types: BTreeMap::new(),
            reachable: BitSet::new(block_count),
            dominance_frontiers: Vec::new(),
            successor_map: BTreeMap::new(),
            dom_children: BTreeMap::new(),
            defs: BTreeMap::new(),
            live_in: BTreeMap::new(),
            phi_groups: BTreeMap::new(),
            next_group,
        }
    }

    /// Computes the set of reachable block indices via BFS from entry + exception handler roots.
    fn compute_reachable_blocks(ssa: &SsaFunction, cfg: &SsaCfg<'_>) -> BitSet {
        let block_count = ssa.blocks.len();
        let mut reachable = BitSet::new(block_count);
        let mut worklist = vec![0usize];
        while let Some(block_idx) = worklist.pop() {
            if reachable.insert(block_idx) {
                for &succ in cfg.block_successors(block_idx) {
                    if succ < block_count {
                        worklist.push(succ);
                    }
                }
            }
        }

        // Include exception handler entries as roots
        for handler in &ssa.exception_handlers {
            for block in [handler.handler_start_block, handler.filter_start_block]
                .into_iter()
                .flatten()
            {
                if block < block_count && !reachable.contains(block) {
                    worklist.push(block);
                    while let Some(b) = worklist.pop() {
                        if reachable.insert(b) {
                            for &succ in cfg.block_successors(b) {
                                if succ < block_count {
                                    worklist.push(succ);
                                }
                            }
                        }
                    }
                }
            }
        }

        reachable
    }

    /// Runs the full SSA rebuild pipeline.
    pub fn rebuild(&mut self) -> Result<()> {
        // Stage 1: Pre-clean
        self.pre_clean_unreachable(); // Phase 1
        self.recompute_groups_from_connectivity(); // Phase 2

        // Stage 2: Type & origin collection
        self.collect_origins(); // Phase 3
        self.propagate_types(); // Phase 4
        self.propagate_instruction_types(); // Phase 5
        self.assign_orphan_origins(); // Phase 6

        // Stage 3: CFG analysis
        self.compute_cfg(); // Phase 7
        self.collect_defs(); // Phase 8
        self.collect_uses_and_liveness(); // Phase 9

        // Stage 4: Phi placement & rename
        self.clear_all_phis(); // Phase 10
        self.place_phis(); // Phase 11
        self.rename(); // Phase 12

        // Stage 5: Cleanup & compaction
        self.eliminate_trivial_phis(); // Phase 13
        self.ssa.strip_nops(); // Phase 14
        self.ssa.compact_variables(); // Phase 15
        self.remove_orphan_pops(); // Phase 16
        self.ssa.reindex_variables(); // Phase 17
                                      // reindex can cause stale phi operand refs to collide with new IDs
        self.eliminate_trivial_phis(); // Phase 18
        self.ssa.shrink_num_locals(); // Phase 19

        // Verification
        self.verify()
    }

    /// Validates the rebuilt SSA, filtering to reachable blocks only.
    ///
    /// Unreachable blocks (e.g., dead CFF dispatcher remnants) may contain stale
    /// variable references that weren't processed by the rename phase.
    fn verify(&self) -> Result<()> {
        let errors = SsaVerifier::new(self.ssa).verify(VerifyLevel::Standard);
        let reachable_errors: Vec<&VerifierError> = errors
            .iter()
            .filter(|e| {
                let block = match e {
                    VerifierError::UndefinedUse { block, .. }
                    | VerifierError::MissingPhiOperand { block, .. }
                    | VerifierError::ExtraPhiOperand { block, .. }
                    | VerifierError::MissingTerminator { block }
                    | VerifierError::PhiInEntryBlock { block, .. }
                    | VerifierError::TerminatorNotLast { block, .. }
                    | VerifierError::IntraBlockCycle { block, .. }
                    | VerifierError::PlaceholderVariable { block, .. }
                    | VerifierError::SelfReferentialInstruction { block, .. } => Some(*block),
                    VerifierError::DominanceViolation { use_block, .. } => Some(*use_block),
                    VerifierError::DuplicateDefinition { .. }
                    | VerifierError::UnregisteredVariable { .. } => None,
                    // OrphanVariable is cosmetic — the variable exists without a
                    // definition but isn't harmful. Typically caused by v0 entry
                    // variables from stack temp groups that survive compaction.
                    VerifierError::OrphanVariable { .. } => return false,
                };
                // Keep errors for reachable blocks (or block-independent errors)
                block.is_none_or(|b| self.reachable.contains(b))
            })
            .collect();

        if !reachable_errors.is_empty() {
            let msg = reachable_errors
                .iter()
                .map(|e| e.to_string())
                .collect::<Vec<_>>()
                .join("; ");
            return Err(Error::SsaError(format!(
                "SSA rebuild validation failed ({} blocks, {} vars): {}",
                self.ssa.blocks().len(),
                self.ssa.variables.len(),
                msg
            )));
        }

        Ok(())
    }

    /// Removes unreachable blocks and simplifies stale phi operands.
    ///
    /// Must run BEFORE `recompute_groups_from_connectivity` so that stale phi
    /// operands from unreachable predecessors don't create false disconnected
    /// components in the union-find. Without this, passes like anti-debug
    /// removal that make blocks unreachable (but don't clean up phis in
    /// successor blocks) cause phi results to be split from their operands,
    /// leading to orphan groups with no definitions after phi clearing.
    fn pre_clean_unreachable(&mut self) {
        let cfg = SsaCfg::from_ssa(self.ssa);
        let reachable = Self::compute_reachable_blocks(self.ssa, &cfg);

        // Clear unreachable blocks
        for block_idx in 0..self.ssa.blocks.len() {
            if !reachable.contains(block_idx) {
                self.ssa.blocks[block_idx].instructions_mut().clear();
                self.ssa.blocks[block_idx].phi_nodes_mut().clear();
            }
        }

        // Remove phi operands from unreachable predecessors and collect
        // trivial phi replacements (phi with 0 or 1 unique operand)
        let mut replacements: Vec<(SsaVarId, SsaVarId)> = Vec::new();
        for block_idx in 0..self.ssa.blocks.len() {
            if !reachable.contains(block_idx) {
                continue;
            }
            let block = &mut self.ssa.blocks[block_idx];

            // Remove operands from unreachable predecessors
            for phi in block.phi_nodes_mut().iter_mut() {
                phi.retain_operands(|pred| reachable.contains(pred));
            }

            // Inline trivial phis (0 or 1 unique operand value)
            block.phi_nodes_mut().retain(|phi| {
                let operands = phi.operands();
                if operands.is_empty() {
                    return false; // Remove empty phi
                }
                // Check if all operands resolve to the same value
                let first = operands[0].value();
                if operands
                    .iter()
                    .all(|op| op.value() == first || op.value() == phi.result())
                {
                    replacements.push((phi.result(), first));
                    return false;
                }
                true
            });
        }

        // Apply replacements: substitute phi result uses with the single operand
        if !replacements.is_empty() {
            let replacement_map: BTreeMap<SsaVarId, SsaVarId> = replacements.into_iter().collect();
            for block in &mut self.ssa.blocks {
                for instr in block.instructions_mut() {
                    for (&old_var, &new_var) in &replacement_map {
                        instr.op_mut().replace_uses(old_var, new_var);
                    }
                }
                for phi in block.phi_nodes_mut() {
                    for (&old_var, &new_var) in &replacement_map {
                        for op in phi.operands_mut() {
                            if op.value() == old_var {
                                *op = PhiOperand::new(new_var, op.predecessor());
                            }
                        }
                    }
                }
            }
        }
    }

    /// Splits stale rename groups that contain disconnected components.
    ///
    /// After CFG modifications (e.g., CFF unflattening), stale rename groups may
    /// cause unrelated variables to share the same group. For example, CFF stores
    /// different values (Calculator instance, format string) in the same local slot
    /// across different switch cases. After unflattening removes the dispatcher phi
    /// that merged them, they should be in separate groups — but the original groups
    /// from SSA construction still link them.
    ///
    /// This method conservatively splits only groups that have multiple disconnected
    /// components (based on phi/copy/load connectivity). Groups that are already
    /// a single connected component are left unchanged. This avoids the regression
    /// of splitting groups that are legitimately connected through the dominator tree
    /// but lack explicit phi/copy edges.
    fn recompute_groups_from_connectivity(&mut self) {
        let num_vars = self.ssa.variables.len();
        if num_vars == 0 {
            return;
        }

        // Union-find structure (parent array, initially each variable is its own root)
        let mut parent: Vec<usize> = (0..num_vars).collect();
        let mut rank: Vec<u8> = vec![0; num_vars];

        let find = |parent: &mut Vec<usize>, mut x: usize| -> usize {
            while parent[x] != x {
                parent[x] = parent[parent[x]]; // path halving
                x = parent[x];
            }
            x
        };

        let union = |parent: &mut Vec<usize>, rank: &mut Vec<u8>, a: usize, b: usize| {
            let ra = find(parent, a);
            let rb = find(parent, b);
            if ra == rb {
                return;
            }
            if rank[ra] < rank[rb] {
                parent[ra] = rb;
            } else if rank[ra] > rank[rb] {
                parent[rb] = ra;
            } else {
                parent[rb] = ra;
                rank[ra] += 1;
            }
        };

        // Build a mapping from SsaVarId to index in the variables array
        let mut var_to_idx: BTreeMap<SsaVarId, usize> = BTreeMap::new();
        for (idx, var) in self.ssa.variables.iter().enumerate() {
            var_to_idx.insert(var.id(), idx);
        }

        // Union phi operands with their phi result to maintain group connectivity.
        //
        // We only process phis in REACHABLE blocks — unreachable blocks were
        // cleaned in pre_clean_unreachable (Phase 1), so any remaining phis
        // are genuine. This is critical: block-merging's trampoline elimination
        // updates phi operands to reference new predecessors, but the new
        // operand variables may be in different rename groups than the phi
        // result. Without unconditional union here, the group splits, causing
        // phi placement to skip the entry-only group → switch phis collapse
        // → CFF dispatchers are incorrectly constant-folded.
        //
        // The original same-group restriction was added to avoid false
        // connectivity from stale phis. Phase 1's unreachable block cleanup
        // eliminates stale phis, making the restriction unnecessary for
        // reachable blocks.
        let cfg_for_reach = SsaCfg::from_ssa(self.ssa);
        let reachable_here = Self::compute_reachable_blocks(self.ssa, &cfg_for_reach);
        for block in &self.ssa.blocks {
            let block_idx = block.id();
            if !reachable_here.contains(block_idx) {
                continue;
            }
            for phi in block.phi_nodes() {
                let phi_result = phi.result();
                if self.ssa.rename_group(phi_result) == u32::MAX {
                    continue;
                }
                if let Some(&result_idx) = var_to_idx.get(&phi_result) {
                    for operand in phi.operands() {
                        if let Some(&operand_idx) = var_to_idx.get(&operand.value()) {
                            union(&mut parent, &mut rank, result_idx, operand_idx);
                        }
                    }
                }
            }
        }

        // Union copy sources with their destinations
        for block in &self.ssa.blocks {
            for instr in block.instructions() {
                if let SsaOp::Copy { dest, src } = instr.op() {
                    if let (Some(&dest_idx), Some(&src_idx)) =
                        (var_to_idx.get(dest), var_to_idx.get(src))
                    {
                        union(&mut parent, &mut rank, dest_idx, src_idx);
                    }
                }
            }
        }

        // Union LoadLocal/LoadArg destinations with their respective arg/local
        // group representatives, so loads from the same slot stay connected.
        let num_args = self.ssa.num_args;
        let mut arg_local_reps: BTreeMap<u32, usize> = BTreeMap::new();
        for (idx, var) in self.ssa.variables.iter().enumerate() {
            match var.origin() {
                VariableOrigin::Argument(ai) => {
                    let group = ai as u32;
                    arg_local_reps.entry(group).or_insert(idx);
                }
                VariableOrigin::Local(li) => {
                    let group = num_args as u32 + li as u32;
                    arg_local_reps.entry(group).or_insert(idx);
                }
                _ => {}
            }
        }
        for block in &self.ssa.blocks {
            for instr in block.instructions() {
                match instr.op() {
                    SsaOp::LoadLocal { dest, local_index } => {
                        let group = num_args as u32 + *local_index as u32;
                        if let (Some(&dest_idx), Some(&rep_idx)) =
                            (var_to_idx.get(dest), arg_local_reps.get(&group))
                        {
                            union(&mut parent, &mut rank, dest_idx, rep_idx);
                        }
                    }
                    SsaOp::LoadArg { dest, arg_index } => {
                        let group = *arg_index as u32;
                        if let (Some(&dest_idx), Some(&rep_idx)) =
                            (var_to_idx.get(dest), arg_local_reps.get(&group))
                        {
                            union(&mut parent, &mut rank, dest_idx, rep_idx);
                        }
                    }
                    _ => {}
                }
            }
        }

        // Collect variables by their CURRENT rename group
        let mut group_members: BTreeMap<u32, Vec<usize>> = BTreeMap::new();
        for (idx, var) in self.ssa.variables.iter().enumerate() {
            let group = self.ssa.rename_group(var.id());
            if group != u32::MAX {
                group_members.entry(group).or_default().push(idx);
            }
        }

        // For each existing group, check if it has multiple disconnected components.
        // Only split groups that actually have disconnected components.
        let max_existing = self.ssa.rename_groups.iter().copied().max().unwrap_or(0);
        let mut next_new_group = if max_existing == u32::MAX {
            num_args as u32 + self.ssa.num_locals as u32
        } else {
            max_existing + 1
        };

        let mut updates: Vec<(SsaVarId, u32)> = Vec::new();

        let real_local_limit = num_args as u32 + self.ssa.num_locals as u32;

        for (&original_group, members) in &group_members {
            if members.len() <= 1 {
                continue; // Single-variable groups can't have disconnected components
            }

            // Find the distinct connected components within this group
            let mut component_roots: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
            for &idx in members {
                let root = find(&mut parent, idx);
                component_roots.entry(root).or_default().push(idx);
            }

            if component_roots.len() <= 1 {
                continue; // Single component — group is fine as-is
            }

            // Multiple components detected — split this group.
            // Keep the original group ID for the component that contains a variable
            // with Argument/Local origin (the canonical component). Assign new group
            // IDs to the other components.
            let mut canonical_root: Option<usize> = None;
            for (&root, component_members) in &component_roots {
                for &idx in component_members {
                    let var = &self.ssa.variables[idx];
                    match var.origin() {
                        VariableOrigin::Argument(_) | VariableOrigin::Local(_) => {
                            canonical_root = Some(root);
                            break;
                        }
                        _ => {}
                    }
                }
                if canonical_root.is_some() {
                    break;
                }
            }

            // If no canonical root found, pick the largest component.
            // Break ties deterministically by the smallest variable index
            // within each component to avoid nondeterministic grouping.
            let canonical_root = canonical_root.unwrap_or_else(|| {
                *component_roots
                    .iter()
                    .max_by(|(_, members_a), (_, members_b)| {
                        members_a.len().cmp(&members_b.len()).then_with(|| {
                            let min_a = members_a.iter().copied().min().unwrap_or(usize::MAX);
                            let min_b = members_b.iter().copied().min().unwrap_or(usize::MAX);
                            min_b.cmp(&min_a)
                        })
                    })
                    .map(|(root, _)| root)
                    .unwrap()
            });

            // Decide which components to keep vs. split.
            //
            // Two tiers:
            //
            // 1. When the canonical component has Argument/Local-origin
            //    variables, keep only components that share an (origin, type)
            //    pair.  This handles the CFF case where different if/else
            //    branches assign to the same local with the same type, while
            //    still splitting when CFF reuses a local slot for different
            //    types (e.g., Calculator Object vs format String).
            //
            // 2. When ALL variables in the group are Phi-origin (common after
            //    a previous rebuild) AND the group represents a real CIL
            //    local/argument (group ID < num_args + num_locals), fall back
            //    to type-only comparison: same-type components stay together,
            //    different-type components are split.  Stack temp groups
            //    (group >= num_args + num_locals) always split.
            let canonical_origin_types: HashSet<(VariableOrigin, SsaType)> = component_roots
                .get(&canonical_root)
                .into_iter()
                .flat_map(|members| members.iter())
                .filter_map(|&idx| {
                    let var = &self.ssa.variables[idx];
                    match var.origin() {
                        VariableOrigin::Argument(_) | VariableOrigin::Local(_) => {
                            Some((var.origin(), var.var_type().clone()))
                        }
                        _ => None,
                    }
                })
                .collect();

            let has_canonical_origin = !canonical_origin_types.is_empty();

            // Precompute the canonical component's type for type-based
            // split decisions (Tier 2 and stack temp groups).
            let canonical_type: Option<SsaType> = if !has_canonical_origin {
                component_roots
                    .get(&canonical_root)
                    .into_iter()
                    .flat_map(|members| members.iter())
                    .filter_map(|&idx| {
                        let t = self.ssa.variables[idx].var_type();
                        if t.is_unknown() {
                            None
                        } else {
                            Some(t.clone())
                        }
                    })
                    .next()
            } else {
                None
            };

            for (&root, component_members) in &component_roots {
                if root == canonical_root {
                    continue; // Keep original group ID
                }

                let keep = if has_canonical_origin {
                    // Tier 1: origin + type matching
                    component_members.iter().any(|&idx| {
                        let var = &self.ssa.variables[idx];
                        match var.origin() {
                            VariableOrigin::Argument(_) | VariableOrigin::Local(_) => {
                                canonical_origin_types
                                    .contains(&(var.origin(), var.var_type().clone()))
                            }
                            _ => false,
                        }
                    })
                } else if original_group < real_local_limit {
                    // Tier 2: type-only matching for real local/argument groups
                    // where all variables are Phi-origin (from a previous
                    // rebuild's rename phase).
                    let comp_type: Option<SsaType> = component_members
                        .iter()
                        .filter_map(|&idx| {
                            let t = self.ssa.variables[idx].var_type();
                            if t.is_unknown() {
                                None
                            } else {
                                Some(t.clone())
                            }
                        })
                        .next();

                    match (&comp_type, &canonical_type) {
                        (Some(ct), Some(cano_t)) => ct == cano_t,
                        _ => true, // Unknown types: keep together (conservative)
                    }
                } else {
                    false // Stack temp group — always split to avoid aliasing
                };

                if keep {
                    continue; // Same origin+type or same type — keep in canonical group
                }

                let new_group = next_new_group;
                next_new_group += 1;
                for &idx in component_members {
                    let var_id = self.ssa.variables[idx].id();
                    updates.push((var_id, new_group));
                }
            }
        }

        for (var_id, new_group) in updates {
            self.ssa.set_rename_group(var_id, new_group);
        }
    }

    /// Builds var_id → origin map, group → type map, and var_id → type map.
    fn collect_origins(&mut self) {
        self.var_origins = self
            .ssa
            .variables
            .iter()
            .map(|v| (v.id(), v.origin()))
            .collect();

        // Build group_origins from existing rename_groups.
        // Prefer Local/Argument origins over Phi — after CFF reconstruction
        // clears dispatcher phis, the union-find may group Local-origin and
        // Phi-origin variables together. The group must retain the Local origin
        // so the codegen allocates a CIL local slot instead of a stack temporary.
        for var in &self.ssa.variables {
            let group = self.ssa.rename_group(var.id());
            if group != u32::MAX {
                self.group_origins
                    .entry(group)
                    .and_modify(|existing| {
                        if matches!(existing, VariableOrigin::Phi)
                            && matches!(
                                var.origin(),
                                VariableOrigin::Local(_) | VariableOrigin::Argument(_)
                            )
                        {
                            *existing = var.origin();
                        }
                    })
                    .or_insert(var.origin());
            }
        }

        // Also register arg/local groups
        for i in 0..self.ssa.num_args {
            let group = i as u32;
            self.group_origins
                .entry(group)
                .or_insert(VariableOrigin::Argument(i as u16));
        }
        for i in 0..self.ssa.num_locals {
            let group = self.ssa.num_args as u32 + i as u32;
            self.group_origins
                .entry(group)
                .or_insert(VariableOrigin::Local(i as u16));
        }

        // Track the best type for each group (prefer non-unknown types)
        // and per-variable types
        for var in &self.ssa.variables {
            let var_type = var.var_type();
            if !var_type.is_unknown() {
                let group = self.ssa.rename_group(var.id());
                if group != u32::MAX {
                    self.group_types.entry(group).or_insert(var_type.clone());
                }
                self.var_types.insert(var.id(), var_type.clone());
            }
        }

        // Update next_group to be above all existing groups
        let max_existing = self.ssa.rename_groups.iter().copied().max().unwrap_or(0);
        if max_existing != u32::MAX {
            self.next_group = self.next_group.max(max_existing + 1);
        }
    }

    /// Propagates types from LoadLocal/LoadArg to their dest's group.
    fn propagate_types(&mut self) {
        for block in &self.ssa.blocks {
            for instr in block.instructions() {
                match instr.op() {
                    SsaOp::LoadLocal { dest, local_index } => {
                        let dest_group = self.ssa.rename_group(*dest);
                        if dest_group != u32::MAX && !self.group_types.contains_key(&dest_group) {
                            let local_group = self.ssa.num_args as u32 + *local_index as u32;
                            if let Some(local_type) = self.group_types.get(&local_group).cloned() {
                                self.group_types.insert(dest_group, local_type);
                            }
                        }
                    }
                    SsaOp::LoadArg { dest, arg_index } => {
                        let dest_group = self.ssa.rename_group(*dest);
                        if dest_group != u32::MAX && !self.group_types.contains_key(&dest_group) {
                            let arg_group = *arg_index as u32;
                            if let Some(arg_type) = self.group_types.get(&arg_group).cloned() {
                                self.group_types.insert(dest_group, arg_type);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    /// Infers types for instructions whose destination variable has no type in `group_types`.
    ///
    /// Runs after `propagate_types()` and before `assign_orphan_origins()`. For each
    /// instruction with a destination variable, if the variable's origin has no entry
    /// in `group_types`, checks the instruction's `result_type` first (set during SSA
    /// construction with full TypeContext), then falls back to `SsaOp::infer_result_type()`.
    fn propagate_instruction_types(&mut self) {
        for block in &self.ssa.blocks {
            for instr in block.instructions() {
                if let Some(dest) = instr.op().dest() {
                    let group = self.ssa.rename_group(dest);
                    if group != u32::MAX && !self.group_types.contains_key(&group) {
                        // Priority: instruction result_type (from converter with TypeContext)
                        // > op structural inference
                        if let Some(rt) = instr.result_type() {
                            if !rt.is_unknown() {
                                self.group_types.insert(group, rt.clone());
                                continue;
                            }
                        }
                        if let Some(inferred) = instr.op().infer_result_type() {
                            self.group_types.insert(group, inferred);
                        }
                    }
                }
            }
        }
    }

    /// Assigns origins and groups to orphan variables not in self.variables.
    ///
    /// Orphan variables are created by passes. They need origins and groups so they
    /// can be renamed. PHI origins/groups are propagated first, then remaining orphans
    /// get `Phi` origin with unique group IDs.
    fn assign_orphan_origins(&mut self) {
        // First pass: propagate PHI origins/groups to ALL operands.
        // This ensures that phi operands use the same origin as the phi during rename,
        // so they end up on the same version stack and properly fill phi operands.
        // Collect group propagations first to avoid borrow conflicts.
        let mut group_propagations: Vec<(SsaVarId, u32)> = Vec::new();
        for block in &self.ssa.blocks {
            for phi in block.phi_nodes() {
                let phi_origin = self
                    .var_origins
                    .get(&phi.result())
                    .copied()
                    .unwrap_or_else(|| phi.origin());

                let phi_group = self.ssa.rename_group(phi.result());

                // Assign the PHI's origin to its result if orphan
                self.var_origins.entry(phi.result()).or_insert(phi_origin);

                // Assign the phi's origin and group to ORPHAN operands only.
                // IMPORTANT: Do NOT overwrite existing origins for non-orphan variables.
                for operand in phi.operands() {
                    let op_var = operand.value();
                    self.var_origins.entry(op_var).or_insert(phi_origin);
                    // Propagate the phi's group to orphan operands
                    if phi_group != u32::MAX && self.ssa.rename_group(op_var) == u32::MAX {
                        group_propagations.push((op_var, phi_group));
                    }
                }
            }
        }
        for (var_id, group) in group_propagations {
            self.ssa.set_rename_group(var_id, group);
        }

        // Second pass: assign Phi origin and unique group IDs to remaining orphan
        // variables. Orphans must participate in rename (with version stacks) so that
        // their defs and uses get proper new IDs. Each orphan variable gets its own
        // group, mirroring the old behavior where orphans got unique Local(next_idx)
        // origins.
        // Collect orphan var IDs first to avoid borrow conflicts.
        let mut orphan_vars: Vec<(SsaVarId, Option<SsaType>)> = Vec::new();
        for block in &self.ssa.blocks {
            for instr in block.instructions() {
                for use_var in instr.uses().iter().copied() {
                    if !self.var_origins.contains_key(&use_var) {
                        orphan_vars.push((use_var, None));
                    }
                }
                if let Some(dest) = instr.def() {
                    if !self.var_origins.contains_key(&dest) {
                        // Prefer instruction result_type (from converter), fall back
                        // to structural inference
                        let inferred_type = instr
                            .result_type()
                            .filter(|rt| !rt.is_unknown())
                            .cloned()
                            .or_else(|| instr.op().infer_result_type());
                        orphan_vars.push((dest, inferred_type));
                    }
                }
            }
        }

        for (var_id, inferred_type) in orphan_vars {
            self.var_origins
                .entry(var_id)
                .or_insert(VariableOrigin::Phi);
            if self.ssa.rename_group(var_id) == u32::MAX {
                let group = self.next_group;
                self.next_group += 1;
                self.ssa.set_rename_group(var_id, group);
                self.group_origins.insert(group, VariableOrigin::Phi);
                if let Some(inferred) = inferred_type {
                    self.group_types.entry(group).or_insert(inferred);
                }
            }
        }

        // No num_locals inflation — orphans use Phi origin
    }

    /// Computes reachability, dominators, dominance frontiers, and successor/children maps.
    fn compute_cfg(&mut self) {
        // First pass: compute reachability from the raw SSA
        {
            let cfg = SsaCfg::from_ssa(self.ssa);
            self.reachable = Self::compute_reachable_blocks(self.ssa, &cfg);
        }

        // Clear unreachable blocks to remove phantom CFG edges.
        // Without this, unreachable blocks (e.g., dead crash code after anti-debug
        // removal) keep outgoing edges that pollute the predecessor graph. This
        // causes incorrect dominator computation and stale variable references
        // during rename.
        for block_idx in 0..self.ssa.blocks.len() {
            if !self.reachable.contains(block_idx) {
                self.ssa.blocks[block_idx].instructions_mut().clear();
                self.ssa.blocks[block_idx].phi_nodes_mut().clear();
            }
        }

        // Second pass: rebuild CFG from cleaned-up SSA (no phantom edges).
        // The cfg borrow of self.ssa must end before merge_handler_dom_trees
        // borrows &mut self, so we scope it in a block.
        let (dom_tree, entry_node) = {
            let cfg = SsaCfg::from_ssa(self.ssa);
            let dom_tree = compute_dominators(&cfg, cfg.entry());
            self.dominance_frontiers = compute_dominance_frontiers(&cfg, &dom_tree);

            // Extract successor map (only for reachable blocks)
            for i in self.reachable.iter() {
                self.successor_map
                    .insert(i, cfg.block_successors(i).to_vec());
            }

            // Extract dominator tree children (only for reachable blocks)
            let entry_node = cfg.entry();
            for i in self.reachable.iter() {
                self.dom_children.insert(
                    i,
                    dom_tree
                        .children(NodeId::new(i))
                        .iter()
                        .filter(|n| {
                            n.index() < self.ssa.blocks.len() && self.reachable.contains(n.index())
                        })
                        .map(|n| n.index())
                        .collect(),
                );
            }

            (dom_tree, entry_node)
        };

        self.merge_handler_dom_trees(&dom_tree, entry_node);
    }

    /// Merges local dominator trees for exception handler roots into the main structures.
    ///
    /// Handler/filter entries not dominated by the entry block are reachable via
    /// exception flow but not via the normal dominator tree. This computes local
    /// dom trees for each handler root and merges their `dom_children` and
    /// `dominance_frontiers` into the main structures so that rename covers all blocks.
    fn merge_handler_dom_trees(&mut self, dom_tree: &DominatorTree, entry: NodeId) {
        let cfg = SsaCfg::from_ssa(self.ssa);
        // IMPORTANT: The handler BFS must NOT cross into blocks already in the
        // main dom tree. If it did, the handler's local dom tree could create
        // parent→child relationships that conflict with the main tree, introducing
        // cycles in dom_children and causing rename_block_recursive to loop forever.
        let block_count = self.ssa.blocks.len();
        let mut main_dom_blocks = BitSet::new(block_count);
        for b in self.reachable.iter() {
            if dom_tree.dominates(entry, NodeId::new(b)) {
                main_dom_blocks.insert(b);
            }
        }

        let mut handler_roots: Vec<usize> = Vec::new();
        for handler in &self.ssa.exception_handlers {
            for block in [handler.handler_start_block, handler.filter_start_block]
                .into_iter()
                .flatten()
            {
                if block < block_count
                    && self.reachable.contains(block)
                    && !main_dom_blocks.contains(block)
                {
                    handler_roots.push(block);
                }
            }
        }

        for &root in &handler_roots {
            let local_dom = compute_dominators(&cfg, NodeId::new(root));
            let local_df = compute_dominance_frontiers(&cfg, &local_dom);

            // Collect handler-reachable blocks via BFS from root, stopping at
            // blocks already in the main dom tree to prevent cycle creation.
            let mut handler_reachable = BitSet::new(block_count);
            let mut wl = vec![root];
            while let Some(b) = wl.pop() {
                if handler_reachable.insert(b) {
                    for &succ in cfg.block_successors(b) {
                        if succ < block_count
                            && self.reachable.contains(succ)
                            && !main_dom_blocks.contains(succ)
                        {
                            wl.push(succ);
                        }
                    }
                }
            }

            // Merge dom_children (only for handler-reachable blocks)
            for b in handler_reachable.iter() {
                let children: Vec<usize> = local_dom
                    .children(NodeId::new(b))
                    .iter()
                    .filter(|n| n.index() < block_count && handler_reachable.contains(n.index()))
                    .map(|n| n.index())
                    .collect();
                if !children.is_empty() {
                    self.dom_children.entry(b).or_default().extend(children);
                }
            }

            // Merge dominance frontiers
            for b in handler_reachable.iter() {
                if b < local_df.len() {
                    if b >= self.dominance_frontiers.len() {
                        self.dominance_frontiers
                            .resize(b + 1, BitSet::new(block_count));
                    }
                    self.dominance_frontiers[b].union_with(&local_df[b]);
                }
            }
        }
    }

    /// Collects definition sites from reachable blocks (before clearing PHIs).
    fn collect_defs(&mut self) {
        // Arguments are always defined at entry (block 0) — they have values from the caller.
        for i in 0..self.ssa.num_args {
            let group = i as u32;
            self.defs.entry(group).or_default().insert(0);
        }
        // Only ORIGINAL .NET locals have default-initialization at entry.
        // `num_locals == original_num_locals` always now (no inflation).
        for i in 0..self.ssa.num_locals {
            let group = self.ssa.num_args as u32 + i as u32;
            self.defs.entry(group).or_default().insert(0);
        }

        // Collect defs from instructions using group IDs.
        for block in &self.ssa.blocks {
            let block_idx = block.id();
            if !self.reachable.contains(block_idx) {
                continue;
            }
            for instr in block.instructions() {
                if let Some(dest) = instr.def() {
                    let group = self.ssa.rename_group(dest);
                    if group != u32::MAX {
                        self.defs.entry(group).or_default().insert(block_idx);
                    }
                }
            }
        }
    }

    /// Collects use sites and computes liveness for pruned SSA phi placement.
    fn collect_uses_and_liveness(&mut self) {
        let block_count = self.ssa.blocks.len();
        let variable_count = self.ssa.var_id_capacity();

        // Pre-compute which variables are consumed by non-Nop instructions.
        let mut consumed_vars = BitSet::new(variable_count);
        for block in &self.ssa.blocks {
            if !self.reachable.contains(block.id()) {
                continue;
            }
            for instr in block.instructions() {
                if !matches!(instr.op(), SsaOp::Nop) {
                    for &use_var in instr.uses().iter() {
                        consumed_vars.insert(use_var.index());
                    }
                }
            }
        }

        let mut use_sites: BTreeMap<u32, BitSet> = BTreeMap::new();
        for block in &self.ssa.blocks {
            let block_idx = block.id();
            if !self.reachable.contains(block_idx) {
                continue;
            }
            for instr in block.instructions() {
                for use_var in instr.uses().iter().copied() {
                    let group = self.ssa.rename_group(use_var);
                    if group != u32::MAX {
                        use_sites
                            .entry(group)
                            .or_insert_with(|| BitSet::new(block_count))
                            .insert(block_idx);
                    }
                }
                // Track implicit uses from LoadLocal/LoadArg
                match instr.op() {
                    SsaOp::LoadLocal { dest, local_index } => {
                        if consumed_vars.contains(dest.index()) {
                            let group = self.ssa.num_args as u32 + *local_index as u32;
                            use_sites
                                .entry(group)
                                .or_insert_with(|| BitSet::new(block_count))
                                .insert(block_idx);
                        }
                    }
                    SsaOp::LoadArg { dest, arg_index } => {
                        if consumed_vars.contains(dest.index()) {
                            let group = *arg_index as u32;
                            use_sites
                                .entry(group)
                                .or_insert_with(|| BitSet::new(block_count))
                                .insert(block_idx);
                        }
                    }
                    _ => {}
                }
            }
        }

        // Build successors list for liveness analysis
        let successors_list: Vec<Vec<usize>> = (0..block_count)
            .map(|i| self.successor_map.get(&i).cloned().unwrap_or_default())
            .collect();

        // Convert defs to BTreeMap<u32, BitSet> for liveness
        let defs_for_liveness: BTreeMap<u32, BitSet> = self
            .defs
            .iter()
            .map(|(group, blocks)| {
                let mut bs = BitSet::new(block_count);
                for &b in blocks {
                    bs.insert(b);
                }
                (*group, bs)
            })
            .collect();

        self.live_in = liveness::compute_live_in_blocks(
            &defs_for_liveness,
            &use_sites,
            &successors_list,
            block_count,
        );
    }

    /// Clears all phi nodes from all blocks before fresh placement.
    fn clear_all_phis(&mut self) {
        for block in &mut self.ssa.blocks {
            block.phi_nodes_mut().clear();
        }
    }

    /// Places PHI nodes for all groups using iterated dominance frontiers.
    fn place_phis(&mut self) {
        // Leave target resolver for exception handler phi placement
        let leave_target_fn = |block_idx: usize, blocks: &[SsaBlock]| -> Option<usize> {
            blocks
                .get(block_idx)
                .and_then(|block| match block.terminator_op() {
                    Some(SsaOp::Leave { target }) => Some(*target),
                    _ => None,
                })
        };

        let block_count = self.ssa.blocks.len();

        // Convert defs to BTreeMap<u32, BitSet> and filter to skip single-entry-only groups
        let filtered_defs: BTreeMap<u32, BitSet> = self
            .defs
            .iter()
            .filter(|(_, def_blocks)| !(def_blocks.len() == 1 && def_blocks.contains(&0)))
            .map(|(k, v)| {
                let mut bs = BitSet::new(block_count);
                for &b in v {
                    bs.insert(b);
                }
                (*k, bs)
            })
            .collect();

        let group_origins = self.group_origins.clone();
        let num_args = self.ssa.num_args;

        let placements = place_pruned_phis(
            &mut self.ssa.blocks,
            &filtered_defs,
            &self.live_in,
            &self.dominance_frontiers,
            Some(&self.reachable),
            &|_| true, // Process all groups
            &|group| {
                group_origins
                    .get(&group)
                    .copied()
                    .unwrap_or(if (group as usize) < num_args {
                        VariableOrigin::Argument(group as u16)
                    } else {
                        VariableOrigin::Phi
                    })
            },
            Some(&leave_target_fn),
        );

        // Build per-block phi group mapping from placement info
        for (block_idx, group) in placements {
            self.phi_groups.entry(block_idx).or_default().push(group);
        }
    }

    /// Renames variables after PHI placement during SSA rebuild.
    fn rename(&mut self) {
        let ctx = RenameContext {
            var_origins: &self.var_origins,
            group_types: &self.group_types,
            group_origins: &self.group_origins,
            var_types: &self.var_types,
            successor_map: &self.successor_map,
            dom_children: &self.dom_children,
            phi_groups: &self.phi_groups,
            num_args: self.ssa.num_args,
        };

        // Version stacks: for each group, track the current reaching definition
        let mut version_stacks: BTreeMap<u32, Vec<SsaVarId>> = BTreeMap::new();
        let mut next_version: BTreeMap<u32, u32> = BTreeMap::new();

        // Initialize with arguments and locals version 0 from existing variables.
        // Only use version-0 variables that have an entry-point def_site (no specific
        // instruction). Variables with instruction-specific def_sites are actual
        // definitions in specific blocks and must NOT be used as the initial reaching
        // definition for the entry block, as that would create use-before-def when the
        // entry block references a variable defined in a later block.
        for var in &self.ssa.variables {
            let group = self.ssa.rename_group(var.id());
            if group != u32::MAX {
                match var.origin() {
                    VariableOrigin::Argument(_) | VariableOrigin::Local(_)
                        if var.version() == 0 && var.def_site().instruction.is_none() =>
                    {
                        version_stacks.entry(group).or_default().push(var.id());
                        next_version.insert(group, 1);
                    }
                    _ => {}
                }
            }
        }

        // Ensure all groups that have definitions get a version 0 entry.
        // Without version 0 entries, the rename step will leave stale
        // references when the version stack is empty (which causes
        // apply_rename_map to create use-before-def errors).
        for &group in self.defs.keys() {
            if !version_stacks.contains_key(&group) {
                let origin = self
                    .group_origins
                    .get(&group)
                    .copied()
                    .unwrap_or(VariableOrigin::Phi);
                let var_type = self
                    .group_types
                    .get(&group)
                    .cloned()
                    .unwrap_or(SsaType::Unknown);
                let id = self
                    .ssa
                    .create_variable(origin, 0, DefSite::entry(), var_type);
                self.ssa.set_rename_group(id, group);
                version_stacks.entry(group).or_default().push(id);
                next_version.insert(group, 1);
            }
        }

        let mut rename_map: BTreeMap<SsaVarId, SsaVarId> = BTreeMap::new();

        // Rename from entry block — the dom tree now covers handler blocks
        // via local dom trees computed in compute_cfg().
        Self::rename_block_recursive(
            self.ssa,
            0,
            &ctx,
            &mut version_stacks,
            &mut next_version,
            &mut rename_map,
        );

        // Rename handler roots that are not reachable from the entry's dom tree.
        // With the augmented dom tree, handler body blocks are dom_children of their
        // handler root, so rename_block_recursive from the root covers them.
        let block_count = self.ssa.blocks.len();
        let mut dom_tree_reachable = BitSet::new(block_count);
        let mut dom_stack = vec![0usize];
        while let Some(block_idx) = dom_stack.pop() {
            if dom_tree_reachable.insert(block_idx) {
                if let Some(children) = ctx.dom_children.get(&block_idx) {
                    dom_stack.extend(children.iter().copied());
                }
            }
        }

        for handler in self.ssa.exception_handlers.clone() {
            for block in [handler.handler_start_block, handler.filter_start_block]
                .into_iter()
                .flatten()
            {
                if self.reachable.contains(block) && !dom_tree_reachable.contains(block) {
                    Self::rename_block_recursive(
                        self.ssa,
                        block,
                        &ctx,
                        &mut version_stacks,
                        &mut next_version,
                        &mut rename_map,
                    );
                    // Mark this subtree as reachable so we don't re-visit
                    let mut sub_stack = vec![block];
                    while let Some(b) = sub_stack.pop() {
                        if dom_tree_reachable.insert(b) {
                            if let Some(children) = ctx.dom_children.get(&b) {
                                sub_stack.extend(children.iter().copied());
                            }
                        }
                    }
                }
            }
        }

        // Apply renames to all variable uses
        Self::apply_rename_map(self.ssa, &rename_map);

        // Fill missing phi operands: if rename didn't provide an operand for a
        // predecessor (e.g., the predecessor was not visited or the version stack
        // was empty), fill it with the version 0 entry variable for that origin.
        {
            // Collect all needed fixups first (to avoid borrow conflicts)
            let fixups: Vec<(usize, usize, usize, SsaVarId)> = {
                let cfg = SsaCfg::from_ssa(self.ssa);
                let mut fixes = Vec::new();
                for block_idx in 0..self.ssa.blocks.len() {
                    let preds: Vec<usize> = cfg.block_predecessors(block_idx).to_vec();
                    if preds.is_empty() {
                        continue;
                    }
                    if let Some(block) = self.ssa.block(block_idx) {
                        for (phi_idx, phi) in block.phi_nodes().iter().enumerate() {
                            let mut existing = BitSet::new(block_count);
                            for op in phi.operands() {
                                existing.insert(op.predecessor());
                            }
                            let group = self.ssa.rename_group(phi.result());
                            for &pred in &preds {
                                if !existing.contains(pred) {
                                    if let Some(&v0) =
                                        version_stacks.get(&group).and_then(|stack| stack.first())
                                    {
                                        fixes.push((block_idx, phi_idx, pred, v0));
                                    }
                                }
                            }
                        }
                    }
                }
                fixes
            };

            // Apply fixups
            for (block_idx, phi_idx, pred, v0) in fixups {
                if let Some(block) = self.ssa.block_mut(block_idx) {
                    if let Some(phi) = block.phi_nodes_mut().get_mut(phi_idx) {
                        phi.set_operand(pred, v0);
                    }
                }
            }
        }

        // Final cleanup: Remove Pop instructions that use undefined variables
        {
            let variable_count = self.ssa.var_id_capacity();
            let mut defined_vars = BitSet::new(variable_count);
            for v in &self.ssa.variables {
                let idx = v.id().index();
                if idx < variable_count {
                    defined_vars.insert(idx);
                }
            }
            for block in &mut self.ssa.blocks {
                block.instructions_mut().retain(|instr| {
                    if let SsaOp::Pop { value } = instr.op() {
                        let idx = value.index();
                        return idx < variable_count && defined_vars.contains(idx);
                    }
                    true
                });
            }
        }

        // Eliminate trivial PHIs from rename
        self.eliminate_trivial_phis();
    }

    /// Eliminates trivial PHI nodes (all operands resolve to the same value).
    ///
    /// This also handles phis that become trivial when only considering operands
    /// from reachable predecessors. Unreachable predecessors may provide stale
    /// version-0 operands that make a phi look non-trivial when it's actually
    /// trivial for the reachable control flow. Without this, DCE would have to
    /// prune unreachable operands on every iteration, causing a ping-pong cycle.
    fn eliminate_trivial_phis(&mut self) {
        self.ssa.eliminate_trivial_phis(&TrivialPhiOptions {
            reachable: Some(&self.reachable),
        });

        // Also eliminate dead phis: phis whose result is never used.
        // This prevents oscillation with DCE: rebuild places phis for all
        // variables with multiple defs, but some may have no consumers.
        self.ssa.eliminate_dead_phis();
    }

    /// Removes Pop instructions that reference variables removed by
    /// `eliminate_trivial_phis` or `compact_variables`.
    fn remove_orphan_pops(&mut self) {
        let variable_count = self.ssa.var_id_capacity();
        let defined_vars: BitSet = {
            let mut d = BitSet::new(variable_count);
            for b in self.ssa.blocks() {
                for phi in b.phi_nodes() {
                    let idx = phi.result().index();
                    if idx < variable_count {
                        d.insert(idx);
                    }
                }
                for instr in b.instructions() {
                    if let Some(dest) = instr.op().dest() {
                        let idx = dest.index();
                        if idx < variable_count {
                            d.insert(idx);
                        }
                    }
                }
            }
            d
        };

        // Collect exception/filter handler entry blocks — their Pop instructions
        // consume the runtime-pushed exception object which has no SSA definition.
        let block_count = self.ssa.blocks.len();
        let mut handler_entry_blocks = BitSet::new(block_count);
        for h in &self.ssa.exception_handlers {
            if let Some(b) = h.handler_start_block {
                if b < block_count {
                    handler_entry_blocks.insert(b);
                }
            }
            if let Some(b) = h.filter_start_block {
                if b < block_count {
                    handler_entry_blocks.insert(b);
                }
            }
        }

        for block in &mut self.ssa.blocks {
            let is_handler_entry = handler_entry_blocks.contains(block.id());
            block.instructions_mut().retain(|instr| {
                if let SsaOp::Pop { value } = instr.op() {
                    // Preserve Pops in handler entry blocks — the exception object
                    // is pushed by the runtime and has no SSA definition.
                    if is_handler_entry {
                        return true;
                    }
                    let idx = value.index();
                    return idx < variable_count && defined_vars.contains(idx);
                }
                true
            });
        }
    }

    /// Iteratively renames variables in a block and its dominated children.
    fn rename_block_recursive(
        ssa: &mut SsaFunction,
        entry_block_idx: usize,
        ctx: &RenameContext<'_>,
        version_stacks: &mut BTreeMap<u32, Vec<SsaVarId>>,
        next_version: &mut BTreeMap<u32, u32>,
        rename_map: &mut BTreeMap<SsaVarId, SsaVarId>,
    ) {
        enum RenameAction {
            Enter(usize),
            Exit(BTreeMap<u32, usize>),
        }

        let mut work_stack = vec![RenameAction::Enter(entry_block_idx)];
        let mut visited = BitSet::new(ssa.blocks.len());

        while let Some(action) = work_stack.pop() {
            match action {
                RenameAction::Exit(pushed_counts) => {
                    for (group, count) in pushed_counts {
                        if let Some(stack) = version_stacks.get_mut(&group) {
                            for _ in 0..count {
                                stack.pop();
                            }
                        }
                    }
                }
                RenameAction::Enter(block_idx) => {
                    // Guard against cycles in dom_children (can occur when
                    // multiple exception handlers share blocks outside the
                    // main dominator tree).
                    if !visited.insert(block_idx) {
                        continue;
                    }

                    let pushed_counts = Self::rename_block_process(
                        ssa,
                        block_idx,
                        ctx,
                        version_stacks,
                        next_version,
                        rename_map,
                    );

                    let children = ctx
                        .dom_children
                        .get(&block_idx)
                        .cloned()
                        .unwrap_or_default();

                    work_stack.push(RenameAction::Exit(pushed_counts));

                    for child in children.into_iter().rev() {
                        work_stack.push(RenameAction::Enter(child));
                    }
                }
            }
        }
    }

    /// Processes a single block during rebuild rename.
    fn rename_block_process(
        ssa: &mut SsaFunction,
        block_idx: usize,
        ctx: &RenameContext<'_>,
        version_stacks: &mut BTreeMap<u32, Vec<SsaVarId>>,
        next_version: &mut BTreeMap<u32, u32>,
        rename_map: &mut BTreeMap<SsaVarId, SsaVarId>,
    ) -> BTreeMap<u32, usize> {
        let mut pushed_counts: BTreeMap<u32, usize> = BTreeMap::new();

        Self::rename_phis(
            ssa,
            block_idx,
            ctx,
            version_stacks,
            next_version,
            rename_map,
            &mut pushed_counts,
        );
        Self::rename_instructions(
            ssa,
            block_idx,
            ctx,
            version_stacks,
            next_version,
            rename_map,
            &mut pushed_counts,
        );
        Self::fill_successor_phi_operands(ssa, block_idx, ctx, version_stacks);

        pushed_counts
    }

    /// Renames PHI node results in a block during rebuild rename.
    fn rename_phis(
        ssa: &mut SsaFunction,
        block_idx: usize,
        ctx: &RenameContext<'_>,
        version_stacks: &mut BTreeMap<u32, Vec<SsaVarId>>,
        next_version: &mut BTreeMap<u32, u32>,
        rename_map: &mut BTreeMap<SsaVarId, SsaVarId>,
        pushed_counts: &mut BTreeMap<u32, usize>,
    ) {
        // Look up the group for each phi from the phi_groups mapping built during placement.
        let phi_info: Vec<(u32, VariableOrigin, SsaVarId)> = {
            let block_phi_groups = ctx.phi_groups.get(&block_idx);
            ssa.block(block_idx)
                .map(|b| {
                    b.phi_nodes()
                        .iter()
                        .enumerate()
                        .map(|(i, phi)| {
                            let origin = phi.origin();
                            let group = block_phi_groups
                                .and_then(|groups| groups.get(i).copied())
                                .unwrap_or_else(|| {
                                    // Fallback: derive group from origin for Argument/Local
                                    match origin {
                                        VariableOrigin::Argument(idx) => idx as u32,
                                        VariableOrigin::Local(idx) => {
                                            ctx.num_args as u32 + idx as u32
                                        }
                                        VariableOrigin::Phi => u32::MAX,
                                    }
                                });
                            (group, origin, phi.result())
                        })
                        .collect()
                })
                .unwrap_or_default()
        };

        for (i, (group, origin, old_result)) in phi_info.iter().enumerate() {
            let version = *next_version.get(group).unwrap_or(&0);
            *next_version.entry(*group).or_insert(0) += 1;

            let var_type = ctx
                .group_types
                .get(group)
                .cloned()
                .unwrap_or(SsaType::Unknown);
            let new_var_id =
                ssa.create_variable(*origin, version, DefSite::phi(block_idx), var_type);
            ssa.set_rename_group(new_var_id, *group);

            if let Some(block) = ssa.block_mut(block_idx) {
                if let Some(phi) = block.phi_nodes_mut().get_mut(i) {
                    phi.set_result(new_var_id);
                }
            }

            version_stacks.entry(*group).or_default().push(new_var_id);
            *pushed_counts.entry(*group).or_insert(0) += 1;

            if *old_result != new_var_id {
                rename_map.insert(*old_result, new_var_id);
            }
        }
    }

    /// Renames instruction uses and definitions in a block during rebuild rename.
    fn rename_instructions(
        ssa: &mut SsaFunction,
        block_idx: usize,
        ctx: &RenameContext<'_>,
        version_stacks: &mut BTreeMap<u32, Vec<SsaVarId>>,
        next_version: &mut BTreeMap<u32, u32>,
        rename_map: &mut BTreeMap<SsaVarId, SsaVarId>,
        pushed_counts: &mut BTreeMap<u32, usize>,
    ) {
        // Collect instruction info including load targets for LoadArg/LoadLocal.
        // A load_target of Some(group) means the instruction is a LoadArg/LoadLocal
        // that reads from the given arg/local group. During rename, these are
        // resolved to the current reaching definition instead of creating new versions,
        // ensuring multiple loads of the same arg/local produce the same SSA variable.
        type InstrRenameInfo = (usize, Vec<SsaVarId>, Option<SsaVarId>, Option<u32>);
        let instr_info: Vec<InstrRenameInfo> = ssa
            .block(block_idx)
            .map(|b| {
                b.instructions()
                    .iter()
                    .enumerate()
                    .map(|(i, instr)| {
                        let load_target_group = match instr.op() {
                            SsaOp::LoadArg { arg_index, .. } => Some(*arg_index as u32),
                            SsaOp::LoadLocal { local_index, .. } => {
                                Some(ctx.num_args as u32 + *local_index as u32)
                            }
                            _ => None,
                        };
                        (i, instr.uses(), instr.def(), load_target_group)
                    })
                    .collect()
            })
            .unwrap_or_default();

        for (instr_idx, old_uses, opt_def, load_target_group) in &instr_info {
            // Apply use renames directly to the instruction
            let mut use_renames: Vec<(SsaVarId, SsaVarId)> = Vec::new();
            for &old_use in old_uses {
                let group = ssa.rename_group(old_use);
                if group != u32::MAX {
                    if let Some(reaching_def) = version_stacks
                        .get(&group)
                        .and_then(|stack| stack.last().copied())
                    {
                        if reaching_def != old_use {
                            use_renames.push((old_use, reaching_def));
                        }
                    }
                }
            }

            if !use_renames.is_empty() {
                if let Some(block) = ssa.block_mut(block_idx) {
                    if let Some(instr) = block.instructions_mut().get_mut(*instr_idx) {
                        let op = instr.op_mut();
                        for (old_use, new_use) in &use_renames {
                            op.replace_uses(*old_use, *new_use);
                        }
                    }
                }
            }

            if let Some(old_dest) = opt_def {
                // LoadArg/LoadLocal: resolve dest to the current reaching definition
                // for the arg/local instead of creating a new version. This ensures
                // that multiple loads of the same arg/local produce the same SSA
                // variable, enabling patterns like `x - x = 0` to be recognized.
                if let Some(target_group) = load_target_group {
                    if let Some(reaching_def) = version_stacks
                        .get(target_group)
                        .and_then(|stack| stack.last().copied())
                    {
                        rename_map.insert(*old_dest, reaching_def);
                        // Also push the reaching def onto the dest's group stack
                        // so that within-block uses (which resolve via version_stacks, not
                        // rename_map) also see the correct reaching definition.
                        let dest_group = ssa.rename_group(*old_dest);
                        if dest_group != u32::MAX {
                            version_stacks
                                .entry(dest_group)
                                .or_default()
                                .push(reaching_def);
                            *pushed_counts.entry(dest_group).or_insert(0) += 1;
                        }
                        // Convert to Nop since the value is the reaching definition
                        if let Some(block) = ssa.block_mut(block_idx) {
                            if let Some(instr) = block.instructions_mut().get_mut(*instr_idx) {
                                instr.set_op(SsaOp::Nop);
                            }
                        }
                        continue;
                    }
                }

                let group = ssa.rename_group(*old_dest);
                let origin = ctx.var_origins.get(old_dest).copied();
                if group != u32::MAX {
                    if let Some(origin) = origin {
                        let version = *next_version.get(&group).unwrap_or(&0);
                        *next_version.entry(group).or_insert(0) += 1;

                        // Use per-variable type first (preserves stack-derived local types),
                        // fall back to per-group type
                        let var_type = ctx
                            .var_types
                            .get(old_dest)
                            .or_else(|| ctx.group_types.get(&group))
                            .cloned()
                            .unwrap_or(SsaType::Unknown);
                        let new_var_id = ssa.create_variable(
                            origin,
                            version,
                            DefSite::instruction(block_idx, *instr_idx),
                            var_type,
                        );
                        ssa.set_rename_group(new_var_id, group);

                        if let Some(block) = ssa.block_mut(block_idx) {
                            if let Some(instr) = block.instructions_mut().get_mut(*instr_idx) {
                                instr.op_mut().set_dest(new_var_id);
                            }
                        }

                        version_stacks.entry(group).or_default().push(new_var_id);
                        *pushed_counts.entry(group).or_insert(0) += 1;

                        if *old_dest != new_var_id {
                            rename_map.insert(*old_dest, new_var_id);
                        }
                    }
                }
            }
        }
    }

    /// Fills PHI operands in successor blocks with current reaching definitions.
    fn fill_successor_phi_operands(
        ssa: &mut SsaFunction,
        block_idx: usize,
        ctx: &RenameContext<'_>,
        version_stacks: &mut BTreeMap<u32, Vec<SsaVarId>>,
    ) {
        let successors = ctx
            .successor_map
            .get(&block_idx)
            .cloned()
            .unwrap_or_default();
        for succ_idx in successors {
            // Collect each successor phi's group from the phi_groups mapping
            let phi_updates: Vec<(usize, u32)> = {
                let succ_phi_groups = ctx.phi_groups.get(&succ_idx);
                ssa.block(succ_idx)
                    .map(|b| {
                        b.phi_nodes()
                            .iter()
                            .enumerate()
                            .map(|(i, phi)| {
                                let group = succ_phi_groups
                                    .and_then(|groups| groups.get(i).copied())
                                    .unwrap_or_else(|| {
                                        // Fallback for phis created outside place_pruned_phis
                                        // (e.g., by rename itself). Use the phi result's group.
                                        let result = phi.result();
                                        if result.index() < ssa.rename_groups.len() {
                                            ssa.rename_group(result)
                                        } else {
                                            match phi.origin() {
                                                VariableOrigin::Argument(idx) => idx as u32,
                                                VariableOrigin::Local(idx) => {
                                                    ctx.num_args as u32 + idx as u32
                                                }
                                                VariableOrigin::Phi => u32::MAX,
                                            }
                                        }
                                    });
                                (i, group)
                            })
                            .collect()
                    })
                    .unwrap_or_default()
            };

            for (phi_idx, group) in phi_updates {
                if group == u32::MAX {
                    continue;
                }
                if let Some(reaching_def) = version_stacks
                    .get(&group)
                    .and_then(|stack| stack.last().copied())
                {
                    if let Some(succ_block) = ssa.block_mut(succ_idx) {
                        if let Some(phi) = succ_block.phi_nodes_mut().get_mut(phi_idx) {
                            phi.set_operand(block_idx, reaching_def);
                        }
                    }
                }
            }
        }
    }

    /// Applies the rename map to all variable uses in the function.
    fn apply_rename_map(ssa: &mut SsaFunction, rename_map: &BTreeMap<SsaVarId, SsaVarId>) {
        if rename_map.is_empty() {
            return;
        }

        let resolve = |var: SsaVarId| -> SsaVarId {
            let mut current = var;
            let mut visited = BTreeSet::new();
            while let Some(&new_var) = rename_map.get(&current) {
                if !visited.insert(current) {
                    break;
                }
                current = new_var;
            }
            current
        };

        // Collect all phi operand updates first
        let mut phi_updates: Vec<(usize, usize, usize, SsaVarId)> = Vec::new();
        for block in &ssa.blocks {
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

        for (block_idx, phi_idx, pred, new_val) in phi_updates {
            if let Some(block) = ssa.block_mut(block_idx) {
                if let Some(phi) = block.phi_nodes_mut().get_mut(phi_idx) {
                    phi.set_operand(pred, new_val);
                }
            }
        }

        // Collect all instruction use updates
        let mut instr_updates: Vec<(usize, usize, SsaVarId, SsaVarId)> = Vec::new();
        for block in &ssa.blocks {
            let block_idx = block.id();
            for (instr_idx, instr) in block.instructions().iter().enumerate() {
                let mut seen = std::collections::BTreeSet::new();
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

        for (block_idx, instr_idx, old_var, new_var) in instr_updates {
            if let Some(block) = ssa.block_mut(block_idx) {
                if let Some(instr) = block.instructions_mut().get_mut(instr_idx) {
                    instr.op_mut().replace_uses(old_var, new_var);
                }
            }
        }

        // NOTE: We intentionally do NOT sort instructions topologically here.
        // The rename phase processes instructions in their current order and
        // produces definitions before their uses within each block, so the
        // result is already in valid topological order.
        //
        // Sorting here would reorder pure instructions (like Const) earlier
        // than their original program position. When rebuild_ssa() is called
        // again (e.g., after normalization passes), the rename phase would
        // then process the sorted order, causing incorrect reaching-definition
        // assignments for variables sharing the same origin (stack slot).
    }
}
