//! Mutation/transform methods for SSA functions.
//!
//! These methods modify SSA functions: replacing uses, simplifying phis,
//! folding constants, compacting variables, optimizing locals, and
//! generating local signatures.
//!
//! # `replace_uses` Architecture
//!
//! The SSA function provides two variable-replacement primitives with different
//! safety characteristics:
//!
//! - **`replace_uses(old, new)`** — replaces uses in instructions only, leaving
//!   phi operands unchanged. This is the safe default for compiler passes because
//!   it avoids creating cross-origin phi operand references (where a variable
//!   defined at one phi origin appears as an operand of a phi with a different
//!   origin). Cross-origin references can break `rebuild_ssa`'s assumption that
//!   each variable flows to at most one phi origin.
//!
//! - **`replace_uses_including_phis(old, new)`** — also replaces uses in phi
//!   operands. This is `pub(crate)` and intended only for SSA infrastructure
//!   operations like trivial phi elimination, where the phi being eliminated
//!   and its forwarding target share the same origin context.
//!
//! ## The Self-Referential Guard
//!
//! Both methods skip replacements where the instruction's destination equals
//! `new_var`, preventing the creation of self-referential instructions like
//! `v0 = add(v0, v1)`. This guard is necessary because replacing `v1 → v0`
//! in `v0 = add(v1, v2)` would make `v0` both the definition and a use, which
//! is invalid in SSA form.
//!
//! The [`ReplaceResult`] type makes this guard transparent: `replaced` counts
//! successful substitutions, `skipped` counts uses that were left unchanged.
//! Callers use `result.is_complete()` to determine whether all uses were
//! handled, eliminating the need for post-hoc scanning.
//!
//! ## High-Level Operations
//!
//! Compiler passes should prefer the high-level operations that encapsulate
//! the replace-and-check pattern:
//!
//! - **`propagate_copies(copies)`** — batch copy propagation. Takes a
//!   dest→src map, replaces uses via `replace_uses` (not including phis),
//!   and reports which copies were fully vs. partially propagated.
//!
//! - **`eliminate_trivial_phis(options)`** — finds and removes trivial phi
//!   nodes (all non-self operands are the same value). Replaces uses via
//!   `replace_uses_including_phis` and iterates to fixpoint.
//!
//! - **`prune_phi_operands(reachable)`** — removes stale phi operands from
//!   unreachable predecessors after CFG changes.

use std::collections::{BTreeMap, BTreeSet};

use crate::{
    analysis::ssa::{
        ConstValue, DefSite, ReplaceResult, SsaFunction, SsaOp, SsaType, SsaVarId, UseSite,
        VariableOrigin,
    },
    metadata::signatures::{CustomModifiers, SignatureLocalVariable, SignatureLocalVariables},
    utils::BitSet,
    Error,
};

/// Options for trivial phi elimination.
pub struct TrivialPhiOptions<'a> {
    /// If set, only consider phis in reachable blocks and use reachability-aware
    /// self-referential checks. Unreachable predecessor operands are filtered out
    /// as a second-pass check. All trivial phis are removed unconditionally.
    ///
    /// If `None`, all blocks are considered. Chain resolution is applied, and only
    /// fully propagated phis (no skipped uses from the self-ref guard) are removed.
    pub reachable: Option<&'a BitSet>,
}

/// Result of batch copy propagation.
pub struct CopyPropagationResult {
    /// Total number of uses replaced across all copies.
    pub total_replaced: usize,
    /// Set of copy destinations that were fully propagated (all uses replaced).
    /// These copies can safely be Nop'd by the caller.
    /// Stored as a BitSet indexed by `SsaVarId::index()`.
    pub fully_propagated: BitSet,
    /// Set of copy destinations that still have remaining instruction uses
    /// (due to self-referential guard). These copies must be kept alive.
    /// Stored as a BitSet indexed by `SsaVarId::index()`.
    pub partially_propagated: BitSet,
}

impl SsaFunction {
    /// Replaces all uses of `old_var` with `new_var` throughout the function.
    ///
    /// This is the core operation for copy propagation - when we know that
    /// `v1 = v0` (a copy), we can replace all uses of `v1` with `v0`.
    ///
    /// # Note
    ///
    /// This method only replaces uses in instructions, not in PHI operands.
    /// For internal operations that need to also replace PHI operands, use
    /// `replace_uses_including_phis`.
    pub fn replace_uses(&mut self, old_var: SsaVarId, new_var: SsaVarId) -> ReplaceResult {
        self.blocks
            .iter_mut()
            .map(|block| block.replace_uses(old_var, new_var))
            .fold(ReplaceResult::default(), |acc, r| ReplaceResult {
                replaced: acc.replaced.saturating_add(r.replaced),
                skipped: acc.skipped.saturating_add(r.skipped),
            })
    }

    /// Replaces all uses of `old_var` with `new_var`, including in PHI operands.
    ///
    /// Unlike [`replace_uses`](Self::replace_uses), this method also replaces uses
    /// in PHI node operands across all blocks. This is necessary for internal SSA
    /// operations that eliminate PHI nodes and need to forward their values through
    /// other PHIs.
    ///
    /// # Safety
    ///
    /// This method is `pub(crate)` because it can create cross-origin PHI operand
    /// references if misused.
    ///
    /// # When to Use
    ///
    /// Only use this method for:
    /// - **Trivial PHI elimination**: When removing a PHI like `v10 = phi(v5, v5)`,
    ///   we need to replace uses of `v10` with `v5` everywhere, including in other
    ///   PHI operands.
    /// - **Copy propagation within PHIs**: When a copy's destination is a PHI result
    ///   and we're eliminating that PHI.
    pub(crate) fn replace_uses_including_phis(
        &mut self,
        old_var: SsaVarId,
        new_var: SsaVarId,
    ) -> ReplaceResult {
        self.blocks
            .iter_mut()
            .map(|block| block.replace_uses_including_phis(old_var, new_var))
            .fold(ReplaceResult::default(), |acc, r| ReplaceResult {
                replaced: acc.replaced.saturating_add(r.replaced),
                skipped: acc.skipped.saturating_add(r.skipped),
            })
    }

    /// Replaces all uses of `old_var` with `new_var` within a specific block.
    ///
    /// This is a targeted version of `replace_uses` that only affects instructions
    /// within the specified block (not PHI operands).
    pub fn replace_uses_in_block(
        &mut self,
        block_idx: usize,
        old_var: SsaVarId,
        new_var: SsaVarId,
    ) -> ReplaceResult {
        self.block_mut(block_idx)
            .map_or(ReplaceResult::default(), |block| {
                block.replace_uses(old_var, new_var)
            })
    }

    /// Propagates a batch of copy mappings (dest → src) through all instructions.
    ///
    /// For each mapping, replaces all uses of `dest` with `src` in instructions
    /// (NOT in phi operands — this is the safe default that avoids cross-origin
    /// phi references). Reports which copies were fully propagated vs. which
    /// still have remaining uses due to the self-referential guard.
    ///
    /// # Usage
    ///
    /// ```rust,ignore
    /// let result = ssa.propagate_copies(&resolved_copies);
    /// // Nop only the fully propagated copies:
    /// for dest in &result.fully_propagated {
    ///     ssa.nop_copy_defining(*dest);
    /// }
    /// ```
    pub fn propagate_copies(
        &mut self,
        copies: &BTreeMap<SsaVarId, SsaVarId>,
    ) -> CopyPropagationResult {
        let variable_count = self.var_id_capacity();
        let mut total_replaced: usize = 0;
        let mut fully_propagated = BitSet::new(variable_count);
        let mut partially_propagated = BitSet::new(variable_count);

        for (dest, src) in copies {
            if dest == src {
                continue;
            }

            let result = self.replace_uses(*dest, *src);

            if result.replaced > 0 {
                if result.is_complete() {
                    fully_propagated.insert(dest.index());
                } else {
                    partially_propagated.insert(dest.index());
                }
                total_replaced = total_replaced.saturating_add(result.replaced);
            }
        }

        CopyPropagationResult {
            total_replaced,
            fully_propagated,
            partially_propagated,
        }
    }

    /// Neutralizes Copy instructions that define the given variable by
    /// replacing them with Nop.
    ///
    /// This is used after copy propagation to eliminate dead copy instructions
    /// whose destination has been fully propagated to all use sites. Without
    /// this, rebuild_ssa's rename would re-create versions for the Copy's origin,
    /// shadowing the source variable and undoing the propagation.
    pub fn nop_copy_defining(&mut self, dest: SsaVarId) {
        for block in &mut self.blocks {
            for instr in block.instructions_mut() {
                if let SsaOp::Copy { dest: d, .. } = instr.op() {
                    if *d == dest {
                        instr.set_op(SsaOp::Nop);
                        return;
                    }
                }
            }
        }
    }

    /// Prunes phi operands from non-existent or unreachable predecessors.
    ///
    /// After block removal or CFG changes, phi nodes may reference predecessors
    /// that no longer exist or are unreachable. This method removes those stale
    /// operands, ensuring phi nodes only reference valid predecessors with
    /// defined values.
    ///
    /// Returns the number of operands pruned.
    pub fn prune_phi_operands(&mut self, reachable: &BitSet) -> usize {
        let variable_count = self.var_id_capacity();

        // Build a set of all defined variables in reachable blocks
        let mut defined_vars = BitSet::new(variable_count);

        for block_idx in reachable.iter() {
            if let Some(block) = self.block(block_idx) {
                for phi in block.phi_nodes() {
                    let idx = phi.result().index();
                    if idx < variable_count {
                        defined_vars.insert(idx);
                    }
                }
                for instr in block.instructions() {
                    if let Some(def) = instr.def() {
                        let idx = def.index();
                        if idx < variable_count {
                            defined_vars.insert(idx);
                        }
                    }
                }
            }
        }

        // Include argument variables (implicitly defined at function entry)
        for var in &self.variables {
            if var.origin().is_argument() {
                let idx = var.id().index();
                if idx < variable_count {
                    defined_vars.insert(idx);
                }
            }
        }

        // Compute actual predecessors from the CFG
        let block_count = self.blocks.len();
        let mut actual_predecessors: BTreeMap<usize, BitSet> = BTreeMap::new();
        for block_idx in reachable.iter() {
            if let Some(block) = self.block(block_idx) {
                for successor in block.successors() {
                    actual_predecessors
                        .entry(successor)
                        .or_insert_with(|| BitSet::new(block_count))
                        .insert(block_idx);
                }
            }
        }

        let mut pruned: usize = 0;

        for block_idx in reachable.iter() {
            if let Some(block) = self.block_mut(block_idx) {
                let preds = actual_predecessors.get(&block_idx);

                for phi in block.phi_nodes_mut() {
                    let operands = phi.operands_mut();
                    let original_len = operands.len();

                    if original_len == 0 {
                        continue;
                    }

                    let to_keep: Vec<bool> = operands
                        .iter()
                        .map(|op| {
                            let pred = op.predecessor();
                            let value = op.value();
                            let pred_ok =
                                pred < block_count && preds.is_some_and(|p| p.contains(pred));
                            let val_ok = value.index() < variable_count
                                && defined_vars.contains(value.index());
                            pred_ok && val_ok
                        })
                        .collect();

                    // Never leave a PHI completely empty
                    let keep_count = to_keep.iter().filter(|&&k| k).count();
                    if keep_count == 0 {
                        continue;
                    }

                    let mut keep_iter = to_keep.iter();
                    operands.retain(|_| *keep_iter.next().unwrap_or(&true));

                    pruned = pruned.saturating_add(original_len.saturating_sub(operands.len()));
                }
            }
        }

        pruned
    }

    /// Recomputes all use information from scratch.
    ///
    /// This should be called after SSA transformations that may have invalidated
    /// the use tracking.
    pub fn recompute_uses(&mut self) {
        // Step 1: Clear all existing uses
        for var in &mut self.variables {
            var.clear_uses();
        }

        // Step 2: Scan instructions to record uses
        for (block_idx, block) in self.blocks.iter().enumerate() {
            // Record uses from instructions
            for (instr_idx, instr) in block.instructions().iter().enumerate() {
                for use_var in instr.op().uses() {
                    if let Some(var) = self.var_index(use_var) {
                        let use_site = UseSite::instruction(block_idx, instr_idx);
                        if let Some(slot) = self.variables.get_mut(var) {
                            slot.add_use(use_site);
                        }
                    }
                }
            }

            // Record uses from phi nodes
            for (phi_idx, phi) in block.phi_nodes().iter().enumerate() {
                for operand in phi.operands() {
                    if let Some(var) = self.var_index(operand.value()) {
                        let use_site = UseSite::phi_operand(block_idx, phi_idx);
                        if let Some(slot) = self.variables.get_mut(var) {
                            slot.add_use(use_site);
                        }
                    }
                }
            }
        }
    }

    /// Replaces the operation of an instruction at a specific location.
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
    pub fn remove_instruction(&mut self, block_idx: usize, instr_idx: usize) -> bool {
        self.replace_instruction_op(block_idx, instr_idx, SsaOp::Nop)
    }

    /// Simplifies a phi node by converting it to a copy operation.
    ///
    /// When a phi node has all identical operands (excluding self-references),
    /// it can be converted to a simple copy operation: `phi_result = source`.
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

        // Replace all uses of `dest` with `source`
        self.replace_uses_including_phis(dest, source);

        true
    }

    /// Removes a phi node by index without any validation.
    pub fn remove_phi_unchecked(&mut self, block_idx: usize, phi_idx: usize) -> bool {
        if let Some(block) = self.blocks.get_mut(block_idx) {
            if phi_idx < block.phi_nodes().len() {
                block.phi_nodes_mut().remove(phi_idx);
                return true;
            }
        }
        false
    }

    /// Eliminates trivial phi nodes where all non-self operands resolve to a
    /// single value. Iterates to fixpoint (cascading simplification).
    ///
    /// A phi is trivial when, excluding self-references, all operands provide
    /// the same value. The phi result is replaced by that value everywhere
    /// (including other phi operands).
    ///
    /// # Modes
    ///
    /// When `options.reachable` is `Some`:
    /// - Uses reachability-aware self-referential checks (definitions in unreachable
    ///   blocks don't count as creating cycles).
    /// - Performs a second-pass check filtering operands from unreachable predecessors.
    /// - All trivial phis are removed unconditionally (suitable for rebuild_ssa).
    ///
    /// When `options.reachable` is `None`:
    /// - Uses basic self-referential checks.
    /// - Resolves chains among trivial phis to avoid stale references.
    /// - Only fully propagated phis (no skipped uses) are removed (suitable for repair_ssa).
    ///
    /// # Returns
    ///
    /// The number of phis eliminated.
    pub fn eliminate_trivial_phis(&mut self, options: &TrivialPhiOptions) -> usize {
        let mut total_eliminated: usize = 0;
        let block_count = self.blocks.len();

        // Precompute reachability data if in reachable mode
        let reachable_preds: Option<BTreeMap<usize, BitSet>> = options.reachable.map(|reachable| {
            let mut map = BTreeMap::new();
            for block in &self.blocks {
                let block_idx = block.id();
                if !reachable.contains(block_idx) {
                    continue;
                }
                let mut preds = BitSet::new(block_count);
                for p in self.block_predecessors(block_idx) {
                    if reachable.contains(p) {
                        preds.insert(p);
                    }
                }
                map.insert(block_idx, preds);
            }
            map
        });

        let var_def_block: Option<BTreeMap<SsaVarId, usize>> = options.reachable.map(|_| {
            let mut map = BTreeMap::new();
            for block in &self.blocks {
                let block_idx = block.id();
                for instr in block.instructions() {
                    if let Some(dest) = instr.op().dest() {
                        map.insert(dest, block_idx);
                    }
                }
            }
            map
        });

        loop {
            let mut trivial_phis: Vec<(SsaVarId, SsaVarId)> = Vec::new();

            for block in &self.blocks {
                let block_idx = block.id();
                let block_reachable_preds =
                    reachable_preds.as_ref().and_then(|rp| rp.get(&block_idx));

                for phi in block.phi_nodes() {
                    let result = phi.result();

                    // Collect unique non-self operands
                    let unique_sources: BTreeSet<SsaVarId> = phi
                        .operands()
                        .iter()
                        .map(|op| op.value())
                        .filter(|&v| v != result)
                        .collect();

                    if let Some(&source) = unique_sources
                        .iter()
                        .next()
                        .filter(|_| unique_sources.len() == 1)
                    {
                        let is_self_ref = match (&var_def_block, options.reachable) {
                            (Some(vdb), Some(reachable)) => self
                                .would_create_self_reference_reachable(
                                    source, result, vdb, reachable,
                                ),
                            _ => self.would_create_self_reference(source, result),
                        };

                        if !is_self_ref {
                            trivial_phis.push((result, source));
                            continue;
                        }
                    } else if unique_sources.is_empty() && !phi.operands().is_empty() {
                        // Fully self-referential phi
                        trivial_phis.push((result, result));
                        continue;
                    }

                    // Reachable-only second pass: filter out operands from
                    // unreachable predecessors and check triviality again
                    if unique_sources.len() > 1 {
                        if let Some(rpreds) = block_reachable_preds {
                            let unique_reachable: BTreeSet<SsaVarId> = phi
                                .operands()
                                .iter()
                                .filter(|op| {
                                    let pred = op.predecessor();
                                    pred < block_count && rpreds.contains(pred)
                                })
                                .map(|op| op.value())
                                .filter(|&v| v != result)
                                .collect();

                            if let Some(&source) = unique_reachable
                                .iter()
                                .next()
                                .filter(|_| unique_reachable.len() == 1)
                            {
                                let is_self_ref = match (&var_def_block, options.reachable) {
                                    (Some(vdb), Some(reachable)) => self
                                        .would_create_self_reference_reachable(
                                            source, result, vdb, reachable,
                                        ),
                                    _ => self.would_create_self_reference(source, result),
                                };
                                if !is_self_ref {
                                    trivial_phis.push((result, source));
                                }
                            } else if unique_reachable.is_empty()
                                && phi.operands().iter().any(|op| {
                                    let pred = op.predecessor();
                                    pred < block_count && rpreds.contains(pred)
                                })
                            {
                                trivial_phis.push((result, result));
                            }
                        }
                    }
                }
            }

            if trivial_phis.is_empty() {
                break;
            }

            let variable_count = self.var_id_capacity();

            if options.reachable.is_none() {
                // Repair mode: resolve chains among trivial phis.
                let trivial_map: BTreeMap<SsaVarId, SsaVarId> =
                    trivial_phis.iter().copied().collect();
                for entry in &mut trivial_phis {
                    if entry.0 == entry.1 {
                        continue;
                    }
                    let mut current = entry.1;
                    let mut visited = BTreeSet::new();
                    while let Some(&next) = trivial_map.get(&current) {
                        if next == current || !visited.insert(current) {
                            break;
                        }
                        current = next;
                    }
                    entry.1 = current;
                }

                // Replace uses and track which phis were fully propagated.
                let mut trivial_set = BitSet::new(variable_count);
                for (phi_result, source) in &trivial_phis {
                    if *phi_result != *source {
                        let result = self.replace_uses_including_phis(*phi_result, *source);
                        if result.is_complete() {
                            trivial_set.insert(phi_result.index());
                        }
                    } else {
                        trivial_set.insert(phi_result.index());
                    }
                }
                if trivial_set.is_empty() {
                    break;
                }

                total_eliminated = total_eliminated.saturating_add(trivial_set.count());
                for block in &mut self.blocks {
                    block.phi_nodes_mut().retain(|phi| {
                        let idx = phi.result().index();
                        idx >= variable_count || !trivial_set.contains(idx)
                    });
                }
                self.variables.retain(|v| {
                    let idx = v.id().index();
                    idx >= variable_count || !trivial_set.contains(idx)
                });
            } else {
                // Rebuild mode: replace uses and remove unconditionally.
                for (phi_result, source) in &trivial_phis {
                    if *phi_result != *source {
                        self.replace_uses_including_phis(*phi_result, *source);
                    }
                }

                let mut trivial_set = BitSet::new(variable_count);
                for (result, _) in &trivial_phis {
                    trivial_set.insert(result.index());
                }
                total_eliminated = total_eliminated.saturating_add(trivial_set.count());
                for block in &mut self.blocks {
                    block.phi_nodes_mut().retain(|phi| {
                        let idx = phi.result().index();
                        idx >= variable_count || !trivial_set.contains(idx)
                    });
                }
                self.variables.retain(|v| {
                    let idx = v.id().index();
                    idx >= variable_count || !trivial_set.contains(idx)
                });
            }
        }

        total_eliminated
    }

    /// Folds a constant operation, replacing its uses with the computed value.
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

    /// Compacts the variable table by removing orphaned variables.
    ///
    /// A variable is considered orphaned if:
    /// - It's not defined by any instruction in any block
    /// - It's not defined by any phi node in any block
    ///
    /// # Returns
    ///
    /// The number of variables that were removed.
    pub fn compact_variables(&mut self) -> usize {
        let variable_count = self.var_id_capacity();

        // Phase 1: Collect all variables that still have active definitions
        let mut defined_vars = BitSet::new(variable_count);

        for block in &self.blocks {
            // From instructions
            for instr in block.instructions() {
                let op = instr.op();
                // Skip Nop instructions - they have no definition
                if matches!(op, SsaOp::Nop) {
                    continue;
                }
                if let Some(dest) = op.dest() {
                    let idx = dest.index();
                    if idx < variable_count {
                        defined_vars.insert(idx);
                    }
                }
            }

            // From phi nodes
            for phi in block.phi_nodes() {
                let idx = phi.result().index();
                if idx < variable_count {
                    defined_vars.insert(idx);
                }
            }
        }

        // Also keep version-0 entry-point variables. These have no instruction
        // def but are implicitly defined at function entry:
        // - Argument/Local v0: method parameters and default-initialized locals
        // - Phi v0 with entry def_site: placeholder reaching defs for stack temp
        //   groups created during SSA rebuild
        for var in &self.variables {
            if var.version() == 0 && var.def_site().instruction.is_none() {
                let idx = var.id().index();
                if idx < variable_count {
                    defined_vars.insert(idx);
                }
            }
        }

        // Also keep variables that are still referenced by non-Nop instructions.
        // This can happen when replace_uses skips replacements due to the
        // self-referential guard (dest == new_var), leaving uses behind after
        // the definition was Nop'd or eliminated.
        for block in &self.blocks {
            for instr in block.instructions() {
                if matches!(instr.op(), SsaOp::Nop) {
                    continue;
                }
                for u in instr.uses() {
                    let idx = u.index();
                    if idx < variable_count {
                        defined_vars.insert(idx);
                    }
                }
            }

            // Also keep variables referenced by phi operands. A phi may
            // reference a variable whose defining instruction was Nop'd by
            // an optimization pass — without this, compact would remove the
            // variable and the phi operand would become a dangling reference.
            for phi in block.phi_nodes() {
                for op in phi.operands() {
                    let idx = op.value().index();
                    if idx < variable_count {
                        defined_vars.insert(idx);
                    }
                }
            }
        }

        // Phase 2: Remove orphaned variables
        let original_count = self.variables.len();
        self.variables.retain(|v| {
            let idx = v.id().index();
            idx < variable_count && defined_vars.contains(idx)
        });
        // Reassign dense IDs and rebuild registries
        let remap = self.reassign_dense_ids();
        self.remap_var_ids_in_blocks(&remap);
        self.rebuild_origin_versions();
        original_count.saturating_sub(self.variables.len())
    }

    /// Reassigns all variable IDs to dense contiguous indices (0..N-1) and
    /// remaps all references in blocks.
    ///
    /// **Warning**: This invalidates any externally-held `SsaVarId` references.
    pub fn reindex_variables(&mut self) -> usize {
        let remap = self.reassign_dense_ids();
        let remapped = remap.len();
        self.remap_var_ids_in_blocks(&remap);
        self.rebuild_origin_versions();
        remapped
    }

    /// Strips Nop instructions from all blocks and reindexes variable DefSites.
    ///
    /// This is the shared implementation used by both `repair_ssa` and
    /// `rebuild_ssa`. After stripping Nops:
    ///
    /// 1. Non-Nop instructions that shifted get their DefSites remapped
    /// 2. Variables whose defining instruction was a Nop get reset to entry DefSite
    /// 3. Any remaining out-of-bounds DefSites are reset to entry DefSite
    pub fn strip_nops(&mut self) {
        let mut remap: BTreeMap<(usize, usize), usize> = BTreeMap::new();
        let mut nop_sites: BTreeSet<(usize, usize)> = BTreeSet::new();

        for (block_idx, block) in self.blocks.iter_mut().enumerate() {
            let instructions = block.instructions_mut();

            if !instructions.iter().any(|i| matches!(i.op(), SsaOp::Nop)) {
                continue;
            }

            let mut new_idx = 0usize;
            for (old_idx, instr) in instructions.iter().enumerate() {
                if matches!(instr.op(), SsaOp::Nop) {
                    nop_sites.insert((block_idx, old_idx));
                } else {
                    if old_idx != new_idx {
                        remap.insert((block_idx, old_idx), new_idx);
                    }
                    new_idx = new_idx.saturating_add(1);
                }
            }

            instructions.retain(|instr| !matches!(instr.op(), SsaOp::Nop));
        }

        // Update variable DefSites to reflect new instruction positions.
        // Variables whose defining instruction was a Nop get reset to entry.
        if !remap.is_empty() || !nop_sites.is_empty() {
            for var in &mut self.variables {
                let site = var.def_site();
                if let Some(old_instr) = site.instruction {
                    if nop_sites.contains(&(site.block, old_instr)) {
                        var.set_def_site(DefSite::entry());
                    } else if let Some(&new_instr) = remap.get(&(site.block, old_instr)) {
                        var.set_def_site(DefSite::instruction(site.block, new_instr));
                    }
                }
            }
        }

        // Validate remaining DefSites are in-bounds. Catches stale DefSites
        // that existed before strip_nops was called (e.g., from passes that
        // modified instructions without updating DefSites).
        let block_instr_counts: Vec<usize> =
            self.blocks.iter().map(|b| b.instructions().len()).collect();

        for var in &mut self.variables {
            let site = var.def_site();
            if let Some(instr_idx) = site.instruction {
                let out_of_bounds = match block_instr_counts.get(site.block) {
                    Some(&count) => instr_idx >= count,
                    None => true,
                };
                if out_of_bounds {
                    var.set_def_site(DefSite::entry());
                }
            }
        }
    }

    /// Eliminates dead phi nodes whose result is never used.
    ///
    /// A phi is dead if its result variable has no consumers (no instruction
    /// or other phi uses it). Handles dead phi cycles (A uses B, B uses A,
    /// neither used elsewhere) via liveness propagation.
    ///
    /// Also bridges implicit uses from `LoadLocal`/`LoadArg` instructions
    /// to the corresponding phi nodes for that local/arg origin, ensuring
    /// phis that are read by index-based loads are not incorrectly eliminated.
    pub fn eliminate_dead_phis(&mut self) {
        let variable_count = self.var_id_capacity();
        let mut all_phi_results = BitSet::new(variable_count);
        for block in &self.blocks {
            for phi in block.phi_nodes() {
                let idx = phi.result().index();
                if idx < variable_count {
                    all_phi_results.insert(idx);
                }
            }
        }

        if all_phi_results.is_empty() {
            return;
        }

        // Build map from phi origin to phi result IDs for LoadLocal/LoadArg bridging.
        let mut origin_to_phi_results: BTreeMap<VariableOrigin, Vec<SsaVarId>> = BTreeMap::new();
        for block in &self.blocks {
            for phi in block.phi_nodes() {
                origin_to_phi_results
                    .entry(phi.origin())
                    .or_default()
                    .push(phi.result());
            }
        }

        // Phase 1: Mark phis as live if used by any non-phi instruction
        let mut live_phis = BitSet::new(variable_count);
        for block in &self.blocks {
            for instr in block.instructions() {
                // Direct SSA uses
                for u in instr.uses() {
                    let idx = u.index();
                    if idx < variable_count && all_phi_results.contains(idx) {
                        live_phis.insert(idx);
                    }
                }

                // Implicit uses via LoadLocal/LoadArg (index-based reads).
                // These don't appear in uses() but create a dependency on
                // the corresponding PHI node for that local/arg origin.
                match instr.op() {
                    SsaOp::LoadLocal { local_index, .. } => {
                        let origin = VariableOrigin::Local(*local_index);
                        if let Some(phi_results) = origin_to_phi_results.get(&origin) {
                            for &phi_result in phi_results {
                                let idx = phi_result.index();
                                if idx < variable_count {
                                    live_phis.insert(idx);
                                }
                            }
                        }
                    }
                    SsaOp::LoadArg { arg_index, .. } => {
                        let origin = VariableOrigin::Argument(*arg_index);
                        if let Some(phi_results) = origin_to_phi_results.get(&origin) {
                            for &phi_result in phi_results {
                                let idx = phi_result.index();
                                if idx < variable_count {
                                    live_phis.insert(idx);
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        // Phase 2: Propagate liveness through phi operands
        let mut changed = true;
        while changed {
            changed = false;
            for block in &self.blocks {
                for phi in block.phi_nodes() {
                    let result_idx = phi.result().index();
                    if result_idx < variable_count && live_phis.contains(result_idx) {
                        for op in phi.operands() {
                            let val_idx = op.value().index();
                            if val_idx < variable_count
                                && all_phi_results.contains(val_idx)
                                && live_phis.insert(val_idx)
                            {
                                changed = true;
                            }
                        }
                    }
                }
            }
        }

        // Phase 3: Remove dead phis (all_phi_results - live_phis)
        let mut dead_phis = all_phi_results.clone();
        dead_phis.difference_with(&live_phis);

        if dead_phis.is_empty() {
            return;
        }

        for block in &mut self.blocks {
            block.phi_nodes_mut().retain(|phi| {
                let idx = phi.result().index();
                idx >= variable_count || !dead_phis.contains(idx)
            });
        }

        self.variables.retain(|v| {
            let idx = v.id().index();
            idx >= variable_count || !dead_phis.contains(idx)
        });
    }

    /// Optimizes local variables by removing unused ones and compacting indices.
    ///
    /// This method:
    /// 1. Identifies which local indices are actually used
    /// 2. Creates a compact remapping (old index -> new index)
    /// 3. Updates all `VariableOrigin::Local` references
    /// 4. Updates all `SsaOp::LoadLocal` and `SsaOp::LoadLocalAddr` indices
    /// 5. Updates `num_locals` to the new count
    ///
    /// # Returns
    ///
    /// A vector where `result[old_index]` contains `Some(new_index)` for used locals,
    /// or `None` for unused locals.
    pub fn optimize_locals(&mut self) -> Vec<Option<u16>> {
        // Phase 1: Collect all used local indices
        let mut used_locals: BTreeSet<u16> = BTreeSet::new();

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

        // From LoadLocal and LoadLocalAddr instructions
        for block in &self.blocks {
            for instr in block.instructions() {
                match instr.op() {
                    SsaOp::LoadLocal { local_index, .. }
                    | SsaOp::LoadLocalAddr { local_index, .. } => {
                        used_locals.insert(*local_index);
                    }
                    _ => {}
                }
            }
        }

        // Determine the actual range of local indices (may exceed num_locals
        // when stack-originated locals have indices >= original num_locals)
        let max_local_idx =
            (used_locals.iter().copied().max().unwrap_or(0) as usize).saturating_add(1);
        let remap_size = max_local_idx.max(self.num_locals);

        // If no optimization needed (all locals used or no locals), return identity mapping
        if used_locals.len() == remap_size || remap_size == 0 {
            #[allow(clippy::cast_possible_truncation)]
            return (0..remap_size as u16).map(Some).collect();
        }

        // Phase 2: Build remapping (old index -> new index)
        let mut remap: Vec<Option<u16>> = vec![None; remap_size];
        let mut sorted_used: Vec<u16> = used_locals.into_iter().collect();
        sorted_used.sort_unstable();

        for (new_idx, &old_idx) in sorted_used.iter().enumerate() {
            #[allow(clippy::cast_possible_truncation)]
            let new_idx_u16 = new_idx as u16;
            if let Some(slot) = remap.get_mut(old_idx as usize) {
                *slot = Some(new_idx_u16);
            }
        }

        let new_num_locals = sorted_used.len();

        // Phase 3: Update all variable origins
        for var in &mut self.variables {
            if let VariableOrigin::Local(idx) = var.origin() {
                if let Some(Some(new_idx)) = remap.get(idx as usize).copied() {
                    var.set_origin(VariableOrigin::Local(new_idx));
                }
            }
        }

        // Phase 4: Update phi nodes
        for block in &mut self.blocks {
            for phi in block.phi_nodes_mut() {
                if let VariableOrigin::Local(idx) = phi.origin() {
                    if let Some(Some(new_idx)) = remap.get(idx as usize).copied() {
                        phi.set_origin(VariableOrigin::Local(new_idx));
                    }
                }
            }
        }

        // Phase 5: Update LoadLocal and LoadLocalAddr instructions
        for block in &mut self.blocks {
            for instr in block.instructions_mut() {
                match instr.op_mut() {
                    SsaOp::LoadLocal { local_index, .. }
                    | SsaOp::LoadLocalAddr { local_index, .. } => {
                        if let Some(Some(new_idx)) = remap.get(*local_index as usize).copied() {
                            *local_index = new_idx;
                        }
                    }
                    _ => {}
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
    /// 1. **Original types from CilObject** - preserved from source assembly
    /// 2. **Temporary types map** - for codegen-allocated locals
    /// 3. **SSA inference** - from SSA variables with `VariableOrigin::Local`
    ///
    /// # Errors
    ///
    /// Returns an error if type information is missing for any local variable.
    pub fn generate_local_signature(
        &self,
        override_count: Option<u16>,
        temporary_types: Option<&BTreeMap<u16, SsaType>>,
    ) -> crate::Result<SignatureLocalVariables> {
        // Use empty map if none provided
        let empty_temps = BTreeMap::new();
        let temp_types = temporary_types.unwrap_or(&empty_temps);

        // Use override count if provided, otherwise use the SSA's num_locals
        let local_count = override_count.map_or(self.num_locals, |c| c as usize);

        // If we have original local types (from CilObject), use them as the base
        if let Some(original_types) = &self.original_local_types {
            let mut locals: Vec<SignatureLocalVariable> = Vec::with_capacity(local_count);

            for (idx, orig) in original_types.iter().enumerate() {
                if idx >= local_count {
                    break;
                }
                locals.push(orig.clone());
            }

            // For any additional locals (temporaries allocated by codegen)
            for idx in original_types.len()..local_count {
                #[allow(clippy::cast_possible_truncation)]
                let idx_u16 = idx as u16;
                let local_type = temp_types
                    .get(&idx_u16)
                    .cloned()
                    .or_else(|| self.infer_local_type(idx))
                    .ok_or_else(|| {
                        Error::CodegenFailed(format!(
                            "no type information for local {idx} \
                             (original_num_locals={}, num_locals={})",
                            self.original_num_locals, self.num_locals,
                        ))
                    })?;
                locals.push(SignatureLocalVariable {
                    modifiers: CustomModifiers::default(),
                    is_pinned: false,
                    is_byref: false,
                    base: local_type.to_type_signature(),
                });
            }

            return Ok(SignatureLocalVariables { locals });
        }

        // No original types - fall back to inference for all locals
        let mut local_types: Vec<Option<SsaType>> = vec![None; local_count];

        // First, populate with any provided temporary types (highest priority for temps)
        for (idx, typ) in temp_types {
            let idx = *idx as usize;
            if let Some(slot) = local_types.get_mut(idx) {
                *slot = Some(typ.clone());
            }
        }

        // Get type from SSA variables with Local origin
        for var in &self.variables {
            if let VariableOrigin::Local(idx) = var.origin() {
                let idx = idx as usize;
                if let Some(slot) = local_types.get_mut(idx) {
                    if slot.is_none() {
                        let var_type = var.var_type();
                        if !var_type.is_unknown() {
                            *slot = Some(var_type.clone());
                        }
                    }
                }
            }
        }

        // Also check phi nodes for type information
        for block in &self.blocks {
            for phi in block.phi_nodes() {
                if let VariableOrigin::Local(idx) = phi.origin() {
                    let idx = idx as usize;
                    if let Some(slot) = local_types.get_mut(idx) {
                        if slot.is_none() {
                            if let Some(var) = self.variable(phi.result()) {
                                let var_type = var.var_type();
                                if !var_type.is_unknown() {
                                    *slot = Some(var_type.clone());
                                }
                            }
                        }
                    }
                }
            }
        }

        // Build the signature locals
        let mut locals: Vec<SignatureLocalVariable> = Vec::with_capacity(local_types.len());
        for (idx, opt_type) in local_types.into_iter().enumerate() {
            let base_type = opt_type.ok_or_else(|| {
                Error::CodegenFailed(format!(
                    "no type information for local {idx} \
                     (original_num_locals={}, num_locals={})",
                    self.original_num_locals, self.num_locals,
                ))
            })?;
            locals.push(SignatureLocalVariable {
                modifiers: CustomModifiers::default(),
                is_pinned: false,
                is_byref: false,
                base: base_type.to_type_signature(),
            });
        }

        Ok(SignatureLocalVariables { locals })
    }

    /// Infers the type for a local variable from SSA information.
    ///
    /// Returns `None` if no type information is available for the given local index.
    fn infer_local_type(&self, local_idx: usize) -> Option<SsaType> {
        // Try to find type from variables with this Local origin
        for var in &self.variables {
            if let VariableOrigin::Local(idx) = var.origin() {
                if idx as usize == local_idx {
                    let var_type = var.var_type();
                    if !var_type.is_unknown() {
                        return Some(var_type.clone());
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
                                return Some(var_type.clone());
                            }
                        }
                    }
                }
            }
        }

        None
    }

    /// Shrinks `num_locals` to the actual maximum local index in use.
    ///
    /// After `compact_variables()` removes unused variables, `num_locals` may
    /// exceed the actual maximum local index referenced. This scans all
    /// `VariableOrigin::Local(idx)` references (variables, phi nodes, and
    /// `LoadLocal`/`LoadLocalAddr` instructions) to find the true maximum, then
    /// sets `num_locals = max(max_used + 1, original_num_locals)`.
    ///
    /// The `original_num_locals` floor ensures we never drop below the method's
    /// declared local count (those locals have default-initialization semantics).
    pub fn shrink_num_locals(&mut self) {
        let mut max_local_idx: Option<u16> = None;

        // From variables
        for var in &self.variables {
            if let VariableOrigin::Local(idx) = var.origin() {
                max_local_idx = Some(max_local_idx.map_or(idx, |cur| cur.max(idx)));
            }
        }

        // From phi nodes
        for block in &self.blocks {
            for phi in block.phi_nodes() {
                if let VariableOrigin::Local(idx) = phi.origin() {
                    max_local_idx = Some(max_local_idx.map_or(idx, |cur| cur.max(idx)));
                }
            }
        }

        // From LoadLocal and LoadLocalAddr instructions
        for block in &self.blocks {
            for instr in block.instructions() {
                match instr.op() {
                    SsaOp::LoadLocal { local_index, .. }
                    | SsaOp::LoadLocalAddr { local_index, .. } => {
                        max_local_idx =
                            Some(max_local_idx.map_or(*local_index, |cur| cur.max(*local_index)));
                    }
                    _ => {}
                }
            }
        }

        let needed = max_local_idx.map_or(0, |idx| (idx as usize).saturating_add(1));
        self.num_locals = needed.max(self.original_num_locals);
    }
}
