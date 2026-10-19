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
//! for values that have an identity independent of the control flow - a storage
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
//! value it has no way to track, and the result is a use with no definition -
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
//! count grows by the number of values live across edges - for a flattened
//! method, the values carried through the dispatcher, which is precisely the set
//! that has to survive unflattening.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::analysis::{
    DefSite, PhiOperand, SsaFunction, SsaInstruction, SsaOp, SsaType, SsaVarId, VariableOrigin,
};

/// Narrows a variable id to the union-find key space.
///
/// Ids beyond `u32::MAX` cannot occur - the variable table is indexed by `usize`
/// but allocated densely from zero - so saturating is unreachable in practice.
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
/// terminator is rewired - the phi graph it reads is the record of which names
/// denote the same value, and patching destroys it.
///
/// Returns the number of new local slots allocated.
pub fn promote_cross_block_values(ssa: &mut SsaFunction, dispatchers: &BTreeSet<usize>) -> usize {
    isolate_phi_operands(ssa, dispatchers);
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

    // Group the crossing values, and note which storage locations each class
    // already contains.
    //
    // A class is one value under several names, and relabeling is the whole
    // mechanism here: rebuild relates two names only when they share a rename
    // group, so a class is reconstructible exactly when *all* of it carries one
    // storage location. Finding an argument or a local in a class and skipping
    // the class on that basis - which is what this did - leaves the stack
    // temporaries that carry the same value across the dispatcher on their own
    // groups. The local is then reconstructible and they are not, so the merge
    // at the join block has no record and rebuild produces no phi for it. In
    // `DemoIfElse` that is the `result` of the if/else chain: every arm's string
    // becomes unread, dead-code elimination removes it, and the method prints
    // the local's initial `null`.
    let mut members: BTreeMap<u32, Vec<SsaVarId>> = BTreeMap::new();
    let mut anchors: BTreeMap<u32, BTreeSet<VariableOrigin>> = BTreeMap::new();
    for &var in &crosses {
        let root = classes.find(var_key(var));
        members.entry(root).or_default().push(var);
        if let Some(variable) = ssa.variable(var) {
            let origin = variable.origin();
            if matches!(
                origin,
                VariableOrigin::Argument(_) | VariableOrigin::Local(_)
            ) {
                anchors.entry(root).or_default().insert(origin);
            }
        }
    }

    let mut next_local = u16::try_from(ssa.num_locals()).unwrap_or(u16::MAX);
    let mut promotions: Vec<(SsaVarId, VariableOrigin)> = Vec::new();
    // Classes that need a slot written by explicit copies rather than by
    // relabeling, as `(class root, slot)`.
    let mut copied: Vec<(u32, u16)> = Vec::new();
    for (root, vars) in &members {
        let (root, vars) = (*root, vars);
        let origin = match anchors.get(&root).map(BTreeSet::len) {
            // The class already names one storage location, so that is the one
            // every member has to carry.
            Some(1) => match anchors.get(&root).and_then(|set| set.iter().next()) {
                Some(origin) => *origin,
                None => continue,
            },
            // Two distinct slots merged into one value, which relabeling
            // cannot say. Moving one slot's versions onto the other's group
            // would change which definition reaches every *other* reader of
            // the slot that lost, and an argument cannot be relabeled at all
            // since its slot is where the caller put it. These classes get a
            // slot of their own, written explicitly - see `merges_to_copy`.
            Some(_) => {
                if next_local == u16::MAX {
                    break;
                }
                let slot = next_local;
                next_local = next_local.saturating_add(1);
                copied.push((root, slot));
                continue;
            }
            None => {
                if next_local == u16::MAX {
                    // Local indices are u16 in CIL; a method needing more than
                    // that is beyond what we can represent, so leave the rest
                    // alone rather than aliasing two values onto one slot.
                    break;
                }
                let slot = next_local;
                next_local = next_local.saturating_add(1);
                VariableOrigin::Local(slot)
            }
        };
        for var in vars {
            promotions.push((*var, origin));
        }
    }

    if promotions.is_empty() && copied.is_empty() {
        return 0;
    }

    // Origin and rename group must move together. `rebuild_ssa` decides which
    // names denote the same value from the rename group, while its
    // argument/local representative map is keyed on the origin; if the two
    // disagree the value is silently split and ends up with no reaching
    // definition. An argument's group is its index and a local's is
    // `num_args + index`, as documented on `SsaFunction::rename_groups`.
    let num_args = u32::try_from(ssa.num_args()).unwrap_or(0);
    for (var, origin) in &promotions {
        let group = match origin {
            VariableOrigin::Argument(index) => u32::from(*index),
            VariableOrigin::Local(index) => num_args.saturating_add(u32::from(*index)),
            // `promotions` only ever carries the two storage origins above.
            _ => continue,
        };
        if let Some(variable) = ssa.variable_mut(*var) {
            variable.set_origin(*origin);
        }
        ssa.set_rename_group(*var, group);
    }

    // The slot count has to cover the copy slots before any variable is created
    // against one of them.
    let added = usize::from(next_local).saturating_sub(ssa.num_locals());
    ssa.set_num_locals(usize::from(next_local), ssa.original_num_locals());

    for (root, slot) in copied {
        write_merge_to_slot(ssa, &mut classes, root, slot, num_args);
    }

    added
}

/// The classes phi webs put values in: a phi, its non-exceptional operands,
/// and theirs, transitively.
struct PhiClasses {
    parent: HashMap<SsaVarId, SsaVarId>,
}

impl PhiClasses {
    fn of(ssa: &SsaFunction) -> Self {
        let mut classes = Self {
            parent: HashMap::new(),
        };
        for block in ssa.blocks() {
            for phi in block.phi_nodes() {
                for operand in phi.operands() {
                    if !operand.is_exceptional() {
                        classes.union(phi.result(), operand.value());
                    }
                }
            }
        }
        classes
    }

    fn find(&mut self, mut var: SsaVarId) -> SsaVarId {
        // Path halving: each step points the node at its grandparent, so
        // chains flatten as they are walked.
        while let Some(&parent) = self.parent.get(&var) {
            match self.parent.get(&parent).copied() {
                Some(grandparent) => {
                    self.parent.insert(var, grandparent);
                    var = grandparent;
                }
                None => return parent,
            }
        }
        var
    }

    fn union(&mut self, a: SsaVarId, b: SsaVarId) {
        let (a, b) = (self.find(a), self.find(b));
        if a != b {
            self.parent.insert(a, b);
        }
    }
}

/// Gives the phi operands of a block at risk a name of their own, written at
/// the end of their predecessor.
///
/// The classes below put a phi and its operands in one storage location, which
/// is sound only when those values are never live at once. After copy
/// propagation they can be: a loop that updates `a = b; b = a + b` reaches its
/// head with `a`'s phi reading `b` - the other phi - on the back edge, so `a`,
/// `b` and `a + b` become one class, one slot, and `a + b` reads `b` twice.
/// A fresh copy of an operand, written just before the edge is taken, is live
/// only there, so the class holds nothing else that is live.
///
/// Copying one operand is not enough: the copy reads its source at the end of
/// the predecessor, which keeps the source live past whatever else the
/// predecessor defines in the source's own class - `b` past `a + b`. So a block
/// at risk has every operand of every phi copied, all read before any is
/// written, which is also what keeps a swap a swap. A block is at risk when it
/// is a dispatcher - where flattening merges the values the cases pass each
/// other - or when two of its phis fall into one class: both are live as the
/// block is entered, and one slot cannot hold them. A phi reading another phi
/// of its block is the plain case; the same happens through phis of other
/// blocks, as when the loop head's `a` reads the dispatcher's `b` and the
/// dispatcher's `b` is in the class of the loop head's own `b`. The rest keep
/// their names, since copying every operand of a large function multiplies
/// its variables for no case this covers.
///
/// An operand for a throw is left as it is: it describes a point inside its
/// block, where no copy can be placed.
///
/// # Arguments
///
/// * `ssa` - The function about to be patched.
/// * `dispatchers` - The dispatcher blocks being rewired.
fn isolate_phi_operands(ssa: &mut SsaFunction, dispatchers: &BTreeSet<usize>) {
    let mut classes = PhiClasses::of(ssa);

    // Per predecessor, the operands its edges carry: `(block, phi, operand, value)`.
    let mut by_predecessor: BTreeMap<usize, Vec<(usize, usize, usize, SsaVarId)>> = BTreeMap::new();
    for block in ssa.blocks() {
        let id = block.id();
        let mut seen = BTreeSet::new();
        let at_risk = dispatchers.contains(&id)
            || block
                .phi_nodes()
                .iter()
                .any(|phi| !seen.insert(classes.find(phi.result())));
        if !at_risk {
            continue;
        }
        for (phi_idx, phi) in block.phi_nodes().iter().enumerate() {
            for (operand_idx, operand) in phi.operands().iter().enumerate() {
                // A phi's own result on an edge is the value going round
                // unchanged, which its own slot already holds.
                if operand.is_exceptional() || operand.value() == phi.result() {
                    continue;
                }
                by_predecessor
                    .entry(operand.predecessor())
                    .or_default()
                    .push((id, phi_idx, operand_idx, operand.value()));
            }
        }
    }

    for (predecessor, operands) in by_predecessor {
        let Some(index) = copy_insertion_point(ssa, predecessor) else {
            continue;
        };
        let mut reads: Vec<SsaInstruction> = Vec::with_capacity(operands.len());
        let mut writes: Vec<SsaInstruction> = Vec::with_capacity(operands.len());
        let mut renamed: Vec<(usize, usize, usize, SsaVarId)> = Vec::with_capacity(operands.len());
        for (block, phi_idx, operand_idx, value) in operands {
            let value_type = ssa
                .variable(value)
                .map_or(SsaType::Unknown, |variable| variable.var_type().clone());
            let result_type = ssa
                .block(block)
                .and_then(|b| b.phi_nodes().get(phi_idx))
                .and_then(|phi| ssa.variable(phi.result()))
                .map_or(SsaType::Unknown, |variable| variable.var_type().clone());
            let read = ssa.create_variable(
                VariableOrigin::Phi,
                0,
                DefSite::instruction(predecessor, index),
                value_type,
            );
            let written = ssa.create_variable(
                VariableOrigin::Phi,
                0,
                DefSite::instruction(predecessor, index),
                result_type,
            );
            reads.push(SsaInstruction::synthetic(SsaOp::Copy {
                dest: read,
                src: value,
            }));
            writes.push(SsaInstruction::synthetic(SsaOp::Copy {
                dest: written,
                src: read,
            }));
            renamed.push((block, phi_idx, operand_idx, written));
        }
        if let Some(block) = ssa.block_mut(predecessor) {
            let instructions = block.instructions_mut();
            for (offset, instruction) in reads.into_iter().chain(writes).enumerate() {
                instructions.insert(index.saturating_add(offset), instruction);
            }
        }
        for (block, phi_idx, operand_idx, written) in renamed {
            if let Some(operand) = ssa
                .block_mut(block)
                .and_then(|b| b.phi_nodes_mut().get_mut(phi_idx))
                .and_then(|phi| phi.operands_mut().get_mut(operand_idx))
            {
                *operand = PhiOperand::new(written, predecessor);
            }
        }
    }
}

/// A phi of the class: its result, the result's type, and each operand as
/// `(predecessor, value)`.
type PhiMerge = (SsaVarId, SsaType, Vec<(usize, SsaVarId)>);

/// Gives one merge its own slot, written by an explicit copy on each incoming
/// edge.
///
/// The class this serves is a value that arrives from two different storage
/// locations, so it cannot borrow either one's slot: the versions of a slot are
/// read by whatever else uses that slot, and moving one of them elsewhere
/// changes which definition reaches those readers. What it can have is a slot
/// of its own, and a definition on every path that reaches the merge.
///
/// That definition is what the phi already says implicitly. Writing it out -
/// `slot = <operand>` at the end of each predecessor, with the phi's result
/// relabeled to the slot - turns the merge into ordinary reaching definitions,
/// which is the one form `rebuild_ssa` can re-derive after the edges move.
/// The phi nodes themselves are left alone; reconstruction discards them and
/// places new ones from the copies.
///
/// # Arguments
///
/// * `ssa` - The function being prepared for rewiring.
/// * `classes` - The value classes, to test membership of each phi result.
/// * `root` - The class whose merges are being written out.
/// * `slot` - The local slot allocated to this class.
/// * `num_args` - Argument count, for deriving the rename group of `slot`.
fn write_merge_to_slot(
    ssa: &mut SsaFunction,
    classes: &mut ValueClasses,
    root: u32,
    slot: u16,
    num_args: u32,
) {
    let group = num_args.saturating_add(u32::from(slot));
    let origin = VariableOrigin::Local(slot);

    // Which phi results belong to the class, and what each operand contributes,
    // read out before the function is borrowed mutably.
    let mut merges: Vec<PhiMerge> = Vec::new();
    for block in ssa.blocks() {
        for phi in block.phi_nodes() {
            let result = phi.result();
            if classes.find(var_key(result)) != root {
                continue;
            }
            let result_type = ssa
                .variable(result)
                .map_or(SsaType::Unknown, |variable| variable.var_type().clone());
            let operands = phi
                .operands()
                .iter()
                .map(|operand| (operand.predecessor(), operand.value()))
                .collect();
            merges.push((result, result_type, operands));
        }
    }

    for (result, result_type, operands) in merges {
        for (predecessor, value) in operands {
            let Some(index) = copy_insertion_point(ssa, predecessor) else {
                continue;
            };
            let dest = ssa.create_variable(
                origin,
                0,
                DefSite::instruction(predecessor, index),
                result_type.clone(),
            );
            ssa.set_rename_group(dest, group);
            if let Some(block) = ssa.block_mut(predecessor) {
                block.instructions_mut().insert(
                    index,
                    SsaInstruction::synthetic(SsaOp::Copy { dest, src: value }),
                );
            }
        }

        if let Some(variable) = ssa.variable_mut(result) {
            variable.set_origin(origin);
        }
        ssa.set_rename_group(result, group);
    }
}

/// Where a copy goes in `block`: after its last real instruction, before the
/// terminator that leaves it.
///
/// `None` when the block does not exist, which leaves that edge without a
/// definition rather than putting one after the jump.
///
/// # Arguments
///
/// * `ssa` - The function being prepared for rewiring.
/// * `block` - The predecessor to insert into.
fn copy_insertion_point(ssa: &SsaFunction, block: usize) -> Option<usize> {
    let instructions = ssa.block(block)?.instructions();
    Some(
        instructions
            .iter()
            .position(SsaInstruction::is_terminator)
            .unwrap_or(instructions.len()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::{ConstValue, PhiNode, SsaBlock};

    /// `B0: jump B1` / `B1: a = phi(0, b); b = phi(1, a + b); branch` /
    /// `B2: s = a + b; jump B1` / `B3: ret b` - a Fibonacci step, `a` taking
    /// `b` on the back edge while `b` is still live. `a` and `b` are two
    /// values, and they have to stay two locations.
    #[test]
    fn a_phi_reading_a_live_value_keeps_its_own_slot() {
        let mut ssa = SsaFunction::new(1, 0);
        let var = |ssa: &mut SsaFunction, site| {
            ssa.create_variable(VariableOrigin::Phi, 0, site, SsaType::I32)
        };
        let cond = ssa.create_variable(
            VariableOrigin::Argument(0),
            0,
            DefSite::entry(),
            SsaType::I32,
        );
        let a0 = var(&mut ssa, DefSite::instruction(0, 0));
        let b0 = var(&mut ssa, DefSite::instruction(0, 1));
        let a = var(&mut ssa, DefSite::phi(1));
        let b = var(&mut ssa, DefSite::phi(1));
        let sum = var(&mut ssa, DefSite::instruction(2, 0));

        let mut b0_block = SsaBlock::new(0);
        b0_block.add_instruction(SsaInstruction::synthetic(SsaOp::Const {
            dest: a0,
            value: ConstValue::I32(0),
        }));
        b0_block.add_instruction(SsaInstruction::synthetic(SsaOp::Const {
            dest: b0,
            value: ConstValue::I32(1),
        }));
        b0_block.add_instruction(SsaInstruction::synthetic(SsaOp::Jump { target: 1 }));
        ssa.add_block(b0_block);

        let mut head = SsaBlock::new(1);
        let mut phi_a = PhiNode::new(a, VariableOrigin::Phi);
        phi_a.add_operand(PhiOperand::new(a0, 0));
        phi_a.add_operand(PhiOperand::new(b, 2));
        head.add_phi(phi_a);
        let mut phi_b = PhiNode::new(b, VariableOrigin::Phi);
        phi_b.add_operand(PhiOperand::new(b0, 0));
        phi_b.add_operand(PhiOperand::new(sum, 2));
        head.add_phi(phi_b);
        head.add_instruction(SsaInstruction::synthetic(SsaOp::Branch {
            condition: cond,
            true_target: 2,
            false_target: 3,
        }));
        ssa.add_block(head);

        let mut body = SsaBlock::new(2);
        body.add_instruction(SsaInstruction::synthetic(SsaOp::Add {
            dest: sum,
            left: a,
            right: b,
            flags: None,
        }));
        body.add_instruction(SsaInstruction::synthetic(SsaOp::Jump { target: 1 }));
        ssa.add_block(body);

        let mut exit = SsaBlock::new(3);
        exit.add_instruction(SsaInstruction::synthetic(SsaOp::Return { value: Some(b) }));
        ssa.add_block(exit);
        ssa.recompute_uses();

        promote_cross_block_values(&mut ssa, &BTreeSet::new());

        let slot = |var: SsaVarId| ssa.variable(var).map(|v| v.origin());
        assert!(matches!(slot(a), Some(VariableOrigin::Local(_))), "{ssa}");
        assert!(matches!(slot(b), Some(VariableOrigin::Local(_))), "{ssa}");
        assert_ne!(slot(a), slot(b), "{ssa}");
        assert_ne!(ssa.rename_group(a), ssa.rename_group(b));
    }

    /// `B0: jump B1` / `B1: p = phi(0, s); q = phi(1, r); jump B2` /
    /// `B2: r = phi(p); s = r + q; branch B1, B3` / `B3: ret q` - the swap of
    /// the step above, with `q` reading `p` through a phi of another block.
    /// That phi puts `p` and `q` in one class all the same, and the loop head
    /// has to keep them two locations: one slot for both made `s` read one
    /// value twice, which is how `Fibonacci(10)` came out 0.
    #[test]
    fn a_swap_through_another_blocks_phi_keeps_two_slots() {
        let mut ssa = SsaFunction::new(1, 0);
        let var = |ssa: &mut SsaFunction, site| {
            ssa.create_variable(VariableOrigin::Phi, 0, site, SsaType::I32)
        };
        let cond = ssa.create_variable(
            VariableOrigin::Argument(0),
            0,
            DefSite::entry(),
            SsaType::I32,
        );
        let c0 = var(&mut ssa, DefSite::instruction(0, 0));
        let c1 = var(&mut ssa, DefSite::instruction(0, 1));
        let p = var(&mut ssa, DefSite::phi(1));
        let q = var(&mut ssa, DefSite::phi(1));
        let r = var(&mut ssa, DefSite::phi(2));
        let sum = var(&mut ssa, DefSite::instruction(2, 0));

        let mut entry = SsaBlock::new(0);
        entry.add_instruction(SsaInstruction::synthetic(SsaOp::Const {
            dest: c0,
            value: ConstValue::I32(0),
        }));
        entry.add_instruction(SsaInstruction::synthetic(SsaOp::Const {
            dest: c1,
            value: ConstValue::I32(1),
        }));
        entry.add_instruction(SsaInstruction::synthetic(SsaOp::Jump { target: 1 }));
        ssa.add_block(entry);

        let mut head = SsaBlock::new(1);
        let mut phi_p = PhiNode::new(p, VariableOrigin::Phi);
        phi_p.add_operand(PhiOperand::new(c0, 0));
        phi_p.add_operand(PhiOperand::new(sum, 2));
        head.add_phi(phi_p);
        let mut phi_q = PhiNode::new(q, VariableOrigin::Phi);
        phi_q.add_operand(PhiOperand::new(c1, 0));
        phi_q.add_operand(PhiOperand::new(r, 2));
        head.add_phi(phi_q);
        head.add_instruction(SsaInstruction::synthetic(SsaOp::Jump { target: 2 }));
        ssa.add_block(head);

        let mut body = SsaBlock::new(2);
        let mut phi_r = PhiNode::new(r, VariableOrigin::Phi);
        phi_r.add_operand(PhiOperand::new(p, 1));
        body.add_phi(phi_r);
        body.add_instruction(SsaInstruction::synthetic(SsaOp::Add {
            dest: sum,
            left: r,
            right: q,
            flags: None,
        }));
        body.add_instruction(SsaInstruction::synthetic(SsaOp::Branch {
            condition: cond,
            true_target: 1,
            false_target: 3,
        }));
        ssa.add_block(body);

        let mut exit = SsaBlock::new(3);
        exit.add_instruction(SsaInstruction::synthetic(SsaOp::Return { value: Some(q) }));
        ssa.add_block(exit);
        ssa.recompute_uses();

        promote_cross_block_values(&mut ssa, &BTreeSet::new());

        assert_ne!(ssa.rename_group(p), ssa.rename_group(q), "{ssa}");
    }
}
