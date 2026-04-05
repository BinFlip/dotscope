//! Liveness analysis for pruned SSA phi placement.
//!
//! Computes live-in blocks for each variable group using backward dataflow.
//! A variable is live-in to block B if:
//! - B contains a use of the variable, OR
//! - B has a successor where the variable is live-in AND B does not define it
//!
//! This information is used to prune phi placement: phi nodes are only placed
//! at dominance frontier blocks where the variable is actually live, avoiding
//! dead-on-arrival phi nodes that DCE would need to clean up.
//!
//! Based on LLVM's mem2reg `ComputeLiveInBlocks()` approach.

use std::collections::BTreeMap;

use crate::utils::BitSet;

/// Computes live-in blocks for each variable group.
///
/// Given the definition sites and use sites for each group ID, computes which
/// blocks each variable is live-in to using backward dataflow.
///
/// # Arguments
/// * `defs` - For each group ID, the set of blocks that contain a definition
/// * `uses` - For each group ID, the set of blocks that contain a use
/// * `successors` - CFG successors for each block index
/// * `block_count` - Total number of blocks in the CFG
///
/// # Returns
/// For each group ID, the set of blocks where the variable is live-in.
pub fn compute_live_in_blocks(
    defs: &BTreeMap<u32, BitSet>,
    uses: &BTreeMap<u32, BitSet>,
    successors: &[Vec<usize>],
    block_count: usize,
) -> BTreeMap<u32, BitSet> {
    let mut live_in: BTreeMap<u32, BitSet> = BTreeMap::new();

    // Pre-compute predecessors from successors (avoids recomputation per group)
    let mut predecessors: Vec<Vec<usize>> = vec![Vec::new(); block_count];
    for (block_idx, succs) in successors.iter().enumerate() {
        for &succ in succs {
            if succ < block_count {
                predecessors[succ].push(block_idx);
            }
        }
    }

    // For each group that has both defs and uses, compute liveness
    for (group, def_blocks) in defs {
        let use_blocks = match uses.get(group) {
            Some(blocks) => blocks,
            None => continue, // No uses → variable is dead everywhere → no phis needed
        };

        // Backward dataflow: start from use blocks, propagate backward
        let mut live_in_set = BitSet::new(block_count);
        let mut worklist: Vec<usize> = Vec::new();

        // Seed: blocks that contain a use and don't define the variable before the use.
        // For simplicity (and matching LLVM's approach), we treat a block as a use block
        // if it contains any use, regardless of whether it also defines the variable.
        // The key insight: if a block both defines and uses a variable, the use might
        // refer to a previous definition from outside the block.
        //
        // Conservative approach: if a block uses the variable but also defines it,
        // it's only live-in if the use comes before the def. Since we don't track
        // instruction ordering here, we conservatively mark use-only blocks as live-in
        // and blocks that both use and define as live-in (slightly over-approximate
        // but safe — may place a few extra phis that trivial phi elimination removes).
        for use_block in use_blocks.iter() {
            if live_in_set.insert(use_block) {
                worklist.push(use_block);
            }
        }

        // Propagate backward: variable is live-in to predecessor if it's live-in to
        // a successor and the predecessor doesn't define it (or it's live-in to the
        // predecessor due to a direct use).
        while let Some(block_idx) = worklist.pop() {
            for &pred in &predecessors[block_idx] {
                // If predecessor defines the variable, liveness doesn't propagate further
                // (the definition satisfies the use). But the predecessor itself is NOT
                // live-in for this variable (the def originates here).
                if def_blocks.contains(pred) {
                    continue;
                }
                if live_in_set.insert(pred) {
                    worklist.push(pred);
                }
            }
        }

        live_in.insert(*group, live_in_set);
    }

    live_in
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::utils::BitSet;

    use super::compute_live_in_blocks;

    fn bitset_from(cap: usize, indices: &[usize]) -> BitSet {
        let mut bs = BitSet::new(cap);
        for &i in indices {
            bs.insert(i);
        }
        bs
    }

    /// Diamond CFG:
    ///   0 → 1, 2
    ///   1 → 3
    ///   2 → 3
    ///
    /// def at 0, use at 3 → live through 1 and 2
    #[test]
    fn test_diamond_liveness() {
        let mut defs = BTreeMap::new();
        let mut uses = BTreeMap::new();
        let group: u32 = 0;

        defs.insert(group, bitset_from(4, &[0]));
        uses.insert(group, bitset_from(4, &[3]));

        let successors = vec![
            vec![1, 2], // block 0
            vec![3],    // block 1
            vec![3],    // block 2
            vec![],     // block 3
        ];

        let live_in = compute_live_in_blocks(&defs, &uses, &successors, 4);

        let live = live_in.get(&group).unwrap();
        assert!(live.contains(3), "use block should be live-in");
        assert!(live.contains(1), "path block 1 should be live-in");
        assert!(live.contains(2), "path block 2 should be live-in");
        assert!(!live.contains(0), "def block should NOT be live-in");
    }

    /// Loop CFG:
    ///   0 → 1
    ///   1 → 2, 3
    ///   2 → 1
    ///   3 (exit)
    ///
    /// def at 0 and 2, use at 1 → live in 1 and 2
    #[test]
    fn test_loop_liveness() {
        let mut defs = BTreeMap::new();
        let mut uses = BTreeMap::new();
        let group: u32 = 0;

        defs.insert(group, bitset_from(4, &[0, 2]));
        uses.insert(group, bitset_from(4, &[1]));

        let successors = vec![
            vec![1],    // block 0
            vec![2, 3], // block 1 (loop header)
            vec![1],    // block 2 (loop body)
            vec![],     // block 3 (exit)
        ];

        let live_in = compute_live_in_blocks(&defs, &uses, &successors, 4);

        let live = live_in.get(&group).unwrap();
        assert!(live.contains(1), "use/header block should be live-in");
        assert!(!live.contains(0), "def block 0 should NOT be live-in");
        assert!(!live.contains(2), "def block 2 should NOT be live-in");
    }

    /// No uses → no liveness entry at all
    #[test]
    fn test_no_uses() {
        let mut defs = BTreeMap::new();
        let uses = BTreeMap::new();
        let group: u32 = 0;

        defs.insert(group, bitset_from(2, &[0]));

        let successors = vec![vec![1], vec![]];

        let live_in = compute_live_in_blocks(&defs, &uses, &successors, 2);

        assert!(
            !live_in.contains_key(&group),
            "no uses means no liveness entry"
        );
    }

    /// Nested if-else:
    ///   0 → 1, 2
    ///   1 → 3, 4
    ///   2 → 5
    ///   3 → 5
    ///   4 → 5
    ///
    /// def at 1 and 2, use at 5
    #[test]
    fn test_nested_if_liveness() {
        let mut defs = BTreeMap::new();
        let mut uses = BTreeMap::new();
        let group: u32 = 0;

        defs.insert(group, bitset_from(6, &[1, 2]));
        uses.insert(group, bitset_from(6, &[5]));

        let successors = vec![
            vec![1, 2], // block 0
            vec![3, 4], // block 1
            vec![5],    // block 2
            vec![5],    // block 3
            vec![5],    // block 4
            vec![],     // block 5
        ];

        let live_in = compute_live_in_blocks(&defs, &uses, &successors, 6);

        let live = live_in.get(&group).unwrap();
        assert!(live.contains(5), "use block should be live-in");
        assert!(
            live.contains(3),
            "block 3 should be live-in (no def, on path)"
        );
        assert!(
            live.contains(4),
            "block 4 should be live-in (no def, on path)"
        );
        assert!(!live.contains(1), "def block 1 should NOT be live-in");
        assert!(!live.contains(2), "def block 2 should NOT be live-in");
    }
}
