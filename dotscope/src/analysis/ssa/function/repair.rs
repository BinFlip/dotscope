//! Lightweight SSA repair for non-CFG-modifying passes.
//!
//! After passes that only modify instructions (e.g., constant propagation,
//! copy propagation, DCE, algebraic simplification), SSA form may need minor
//! cleanup but does NOT need full reconstruction. The CFG topology, dominator
//! tree, and phi placement are all still valid — only instruction-level
//! artifacts need attention.
//!
//! `repair_ssa` is the lightweight alternative to `rebuild_ssa` for passes
//! classified as `ModificationScope::InstructionsOnly` or `UsesOnly`. It
//! performs:
//!
//! 1. **Nop stripping** — removes Nop instructions and reindexes DefSites
//! 2. **Trivial phi elimination** — phis where all operands resolve to one value
//! 3. **Dead phi elimination** — phis whose result has no consumers
//! 4. **Variable compaction** — removes orphaned variables and reindexes IDs
//!
//! What it does NOT do (saving significant overhead):
//! - Recompute dominators or dominance frontiers
//! - Recompute liveness
//! - Re-place phi nodes
//! - Full variable renaming
//! - Orphan origin assignment

use crate::analysis::ssa::{SsaFunction, TrivialPhiOptions};

impl SsaFunction {
    /// Lightweight SSA repair for passes that don't modify CFG structure.
    ///
    /// This is the fast path alternative to [`rebuild_ssa`](Self::rebuild_ssa)
    /// for passes classified as `InstructionsOnly` or `UsesOnly`. It assumes
    /// the CFG topology is unchanged and only cleans up instruction-level
    /// artifacts.
    ///
    /// # What this does
    ///
    /// 1. Strips Nop instructions and reindexes variable DefSites
    /// 2. Eliminates trivial phi nodes (all operands resolve to one value)
    /// 3. Eliminates dead phi nodes (result never used)
    /// 4. Compacts orphaned variables and reindexes IDs
    ///
    /// # When to use
    ///
    /// Use this instead of `rebuild_ssa` when the pass only:
    /// - Replaces instruction opcodes/operands
    /// - Converts instructions to Nops (for DCE)
    /// - Substitutes variable uses (copy propagation, GVN)
    ///
    /// Do NOT use this if the pass:
    /// - Adds, removes, or reorders blocks
    /// - Changes branch targets (changes predecessor lists)
    /// - Converts branches to jumps (changes CFG edges)
    pub fn repair_ssa(&mut self) {
        if self.blocks.is_empty() {
            return;
        }

        self.strip_nops();
        self.eliminate_trivial_phis(&TrivialPhiOptions { reachable: None });
        self.eliminate_dead_phis();
        self.compact_variables();
        self.reindex_variables();
    }
}

#[cfg(test)]
mod tests {
    use crate::analysis::{ssa::SsaOp, SsaFunctionBuilder};

    #[test]
    fn test_repair_strips_nops() {
        let mut ssa = SsaFunctionBuilder::new(1, 0)
            .build_with(|f| {
                f.block(0, |b| {
                    let c1 = b.const_i32(42);
                    b.nop();
                    b.nop();
                    let c2 = b.const_i32(100);
                    let _ = b.add(c1, c2);
                    b.ret();
                });
            })
            .unwrap();

        let pre_count = ssa.blocks()[0].instructions().len();
        ssa.repair_ssa();
        let post_count = ssa.blocks()[0].instructions().len();

        // Should have removed the 2 nops
        assert_eq!(pre_count - post_count, 2);
        assert!(ssa.validate().is_ok());
    }

    #[test]
    fn test_repair_eliminates_trivial_phis() {
        let mut ssa = SsaFunctionBuilder::new(2, 1)
            .build_with(|f| {
                f.block(0, |b| {
                    let _ = b.const_i32(42);
                    b.jump(1);
                });
                f.block(1, |b| {
                    b.ret();
                });
            })
            .unwrap();

        // repair_ssa should handle trivial phi elimination without panicking
        // and preserve valid SSA.
        ssa.repair_ssa();
        assert!(ssa.validate().is_ok());
    }

    #[test]
    fn test_repair_strips_nops_and_compacts() {
        let mut ssa = SsaFunctionBuilder::new(1, 0)
            .build_with(|f| {
                f.block(0, |b| {
                    let c1 = b.const_i32(42);
                    let c2 = b.const_i32(100);
                    let _ = b.add(c1, c2);
                    b.ret();
                });
            })
            .unwrap();

        // Nop out one instruction — the Nop should be stripped and the
        // result should still be valid SSA (the add will have a dangling
        // use but compact handles that).
        let pre_instr_count = ssa.blocks()[0].instructions().len();
        if let Some(block) = ssa.block_mut(0) {
            if let Some(instr) = block.instructions_mut().get_mut(1) {
                instr.set_op(SsaOp::Nop);
            }
        }

        ssa.repair_ssa();

        // The Nop should be removed
        let post_instr_count = ssa.blocks()[0].instructions().len();
        assert_eq!(pre_instr_count - post_instr_count, 1);
    }

    #[test]
    fn test_repair_preserves_valid_ssa() {
        let mut ssa = SsaFunctionBuilder::new(3, 1)
            .build_with(|f| {
                f.block(0, |b| {
                    let c = b.const_true();
                    b.branch(c, 1, 2);
                });
                f.block(1, |b| {
                    let _ = b.const_i32(10);
                    b.jump(2);
                });
                f.block(2, |b| {
                    b.ret();
                });
            })
            .unwrap();

        // repair_ssa should maintain valid SSA form
        ssa.repair_ssa();
        assert!(ssa.validate().is_ok());
    }

    #[test]
    fn test_repair_is_idempotent() {
        let mut ssa = SsaFunctionBuilder::new(2, 0)
            .build_with(|f| {
                f.block(0, |b| {
                    let c1 = b.const_i32(1);
                    let c2 = b.const_i32(2);
                    let _ = b.add(c1, c2);
                    b.jump(1);
                });
                f.block(1, |b| {
                    b.ret();
                });
            })
            .unwrap();

        // Running repair twice should produce the same result
        ssa.repair_ssa();
        let vars_after_first = ssa.variable_count();
        let blocks_after_first = ssa.block_count();

        ssa.repair_ssa();
        assert_eq!(ssa.variable_count(), vars_after_first);
        assert_eq!(ssa.block_count(), blocks_after_first);
    }
}
