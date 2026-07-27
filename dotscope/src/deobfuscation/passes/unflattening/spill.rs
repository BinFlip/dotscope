//! Giving cross-block values a storage location before the CFG is rewired.
//!
//! # Why this exists
//!
//! Unflattening restructures control flow: case blocks are redirected past the
//! dispatcher, merge blocks are cloned, and dead dispatch machinery is removed.
//! The resulting CFG has edges that did not exist before, so the SSA form has to
//! be reconstructed afterwards by [`SsaFunction::rebuild_ssa`].
//!
//! Reconstruction is a reaching-definition problem, and it can only be solved
//! for values that have an identity independent of the control flow — a storage
//! location. Arguments and locals have one: a slot index. Rebuild re-derives
//! their versions and phi placement from the definitions that reach each slot,
//! whatever shape the CFG has taken.
//!
//! Stack temporaries do not. A temporary produced in one block and consumed in
//! another exists only as an SSA name, and the fact that two names in different
//! blocks denote the same value is recorded *solely* in the phi node that merges
//! them. Rewiring the CFG invalidates exactly that record: a phi describing a
//! merge that no longer exists is discarded, and with it the only evidence of
//! what the value was. Rebuild is then asked to find a reaching definition for a
//! value it has no way to track, and the result is a use with no definition —
//! reported as an undefined-variable failure in whichever block the value was
//! needed.
//!
//! No amount of phi bookkeeping during patching fixes this, because the
//! information is missing before patching starts: for an edge the patch
//! *creates*, no phi ever recorded what flows along it.
//!
//! # What this does
//!
//! Every value that crosses a block boundary is promoted to a local slot before
//! the CFG is touched. This is the classical "spill temporaries before
//! restructuring" step. Afterwards every cross-block value has a storage
//! location, so rebuild can reconstruct versions and phis for all of them by the
//! ordinary reaching-definition algorithm, and the transformation is correct for
//! any CFG rewiring rather than only the shapes whose phis happen to survive.
//!
//! Only values that genuinely cross a boundary are promoted. Temporaries used
//! within the block that defines them keep their `Phi` origin, so the local
//! count grows by the number of values live across edges — for a flattened
//! method, the values carried through the dispatcher, which is precisely the set
//! that has to survive unflattening.

use std::collections::{BTreeMap, BTreeSet};

use crate::analysis::{SsaFunction, SsaVarId, VariableOrigin};

/// Narrows a variable id to the union-find key space.
///
/// Ids beyond `u32::MAX` cannot occur — the variable table is indexed by `usize`
/// but allocated densely from zero — so saturating is unreachable in practice.
fn var_key(var: SsaVarId) -> u32 {
    u32::try_from(var.index()).unwrap_or(u32::MAX)
}

/// Union-find over SSA variable ids, used to group names that a phi proves
/// denote the same value.
struct ValueClasses {
    parent: Vec<u32>,
}

impl ValueClasses {
    fn new(capacity: usize) -> Self {
        let parent = (0..u32::try_from(capacity).unwrap_or(u32::MAX)).collect();
        Self { parent }
    }

    fn find(&mut self, var: u32) -> u32 {
        let mut root = var;
        while let Some(&parent) = self.parent.get(root as usize) {
            if parent == root {
                break;
            }
            root = parent;
        }
        // Path compression.
        let mut current = var;
        while let Some(&parent) = self.parent.get(current as usize) {
            if parent == root {
                break;
            }
            if let Some(slot) = self.parent.get_mut(current as usize) {
                *slot = root;
            }
            current = parent;
        }
        root
    }

    fn union(&mut self, a: u32, b: u32) {
        let (ra, rb) = (self.find(a), self.find(b));
        if ra != rb {
            if let Some(slot) = self.parent.get_mut(rb as usize) {
                *slot = ra;
            }
        }
    }
}

/// Promotes every value that crosses a block boundary to a local slot.
///
/// Must be called on the function that is about to be patched, before any
/// terminator is rewired — the phi graph it reads is the record of which names
/// denote the same value, and patching destroys it.
///
/// Returns the number of new local slots allocated.
pub fn promote_cross_block_values(ssa: &mut SsaFunction) -> usize {
    let capacity = ssa.var_id_capacity();
    if capacity == 0 {
        return 0;
    }

    // Where each variable is defined, and whether it is ever referenced from a
    // block other than that one.
    let mut def_block: BTreeMap<SsaVarId, usize> = BTreeMap::new();
    for block in ssa.blocks() {
        let id = block.id();
        for phi in block.phi_nodes() {
            def_block.insert(phi.result(), id);
        }
        for instr in block.instructions() {
            if let Some(dest) = instr.def() {
                def_block.insert(dest, id);
            }
        }
    }

    let mut crosses: BTreeSet<SsaVarId> = BTreeSet::new();
    let mut classes = ValueClasses::new(capacity);

    for block in ssa.blocks() {
        let id = block.id();

        for phi in block.phi_nodes() {
            // A phi is the statement that its result and operands are the same
            // value observed on different paths, so the whole set is one class
            // and every member of it crosses an edge.
            let result = phi.result();
            crosses.insert(result);
            for operand in phi.operands() {
                let value = operand.value();
                crosses.insert(value);
                classes.union(var_key(result), var_key(value));
            }
        }

        for instr in block.instructions() {
            for used in instr.uses() {
                if def_block.get(&used).is_some_and(|&def| def != id) {
                    crosses.insert(used);
                }
            }
        }
    }

    if crosses.is_empty() {
        return 0;
    }

    // Group the crossing values, and record which classes already have a
    // storage location. A class containing an argument or a local is already
    // reconstructible — rebuild treats that slot as canonical — so promoting it
    // would only rename something that already works.
    let mut members: BTreeMap<u32, Vec<SsaVarId>> = BTreeMap::new();
    let mut anchored: BTreeSet<u32> = BTreeSet::new();
    for &var in &crosses {
        let root = classes.find(var_key(var));
        members.entry(root).or_default().push(var);
        if let Some(variable) = ssa.variable(var) {
            if matches!(
                variable.origin(),
                VariableOrigin::Argument(_) | VariableOrigin::Local(_)
            ) {
                anchored.insert(root);
            }
        }
    }

    let mut next_local = u16::try_from(ssa.num_locals()).unwrap_or(u16::MAX);
    let mut promotions: Vec<(SsaVarId, u16)> = Vec::new();
    for (root, vars) in members {
        if anchored.contains(&root) {
            continue;
        }
        if next_local == u16::MAX {
            // Local indices are u16 in CIL; a method needing more than that is
            // beyond what we can represent, so leave the rest alone rather than
            // aliasing two values onto one slot.
            break;
        }
        let slot = next_local;
        next_local = next_local.saturating_add(1);
        for var in vars {
            promotions.push((var, slot));
        }
    }

    if promotions.is_empty() {
        return 0;
    }

    // Origin and rename group must move together. `rebuild_ssa` decides which
    // names denote the same value from the rename group, while its
    // argument/local representative map is keyed on the origin; if the two
    // disagree the value is silently split and ends up with no reaching
    // definition. The group for a local is `num_args + index`, as documented on
    // `SsaFunction::rename_groups`.
    let num_args = u32::try_from(ssa.num_args()).unwrap_or(0);
    for (var, slot) in &promotions {
        if let Some(variable) = ssa.variable_mut(*var) {
            variable.set_origin(VariableOrigin::Local(*slot));
        }
        ssa.set_rename_group(*var, num_args.saturating_add(u32::from(*slot)));
    }

    let added = usize::from(next_local).saturating_sub(ssa.num_locals());
    ssa.set_num_locals(usize::from(next_local), ssa.original_num_locals());
    added
}
