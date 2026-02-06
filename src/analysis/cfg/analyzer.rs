//! Loop analyzer for computing comprehensive loop information from SSA.
//!
//! This module provides the [`LoopAnalyzer`] which computes full [`LoopInfo`]
//! structures from an SSA function, including preheaders, latches, exits,
//! and loop type classification.

use crate::{
    analysis::{
        cfg::{detect_loops, LoopForest},
        SsaCfg, SsaFunction,
    },
    utils::graph::{algorithms, RootedGraph},
};

/// Analyzes loops in an SSA function.
///
/// The analyzer computes:
/// - Natural loops using dominance-based back edge detection
/// - Preheader identification for each loop
/// - Latch (back edge source) identification
/// - Exit edge detection
/// - Loop type classification
/// - Loop nesting relationships
///
/// This is a thin wrapper around the generic [`detect_loops`] function,
/// providing a convenient SSA-specific interface.
pub struct LoopAnalyzer<'a> {
    cfg: SsaCfg<'a>,
}

impl<'a> LoopAnalyzer<'a> {
    /// Creates a new loop analyzer for the given SSA function.
    #[must_use]
    pub fn new(ssa: &'a SsaFunction) -> Self {
        let cfg = SsaCfg::from_ssa(ssa);
        Self { cfg }
    }

    /// Analyzes all loops and returns a [`LoopForest`].
    ///
    /// Uses the shared [`detect_loops`] function which implements dominance-based
    /// back edge detection and computes preheaders, exits, loop types, and nesting.
    #[must_use]
    pub fn analyze(&self) -> LoopForest {
        let dominators = algorithms::compute_dominators(&self.cfg, self.cfg.entry());
        detect_loops(&self.cfg, &dominators)
    }
}

/// Extension trait for SSA functions to easily access loop analysis.
pub trait SsaLoopAnalysis {
    /// Analyzes loops in this function.
    fn analyze_loops(&self) -> LoopForest;
}

impl SsaLoopAnalysis for SsaFunction {
    fn analyze_loops(&self) -> LoopForest {
        LoopAnalyzer::new(self).analyze()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        analysis::{cfg::LoopType, SsaFunctionBuilder, SsaVarId},
        utils::graph::NodeId,
    };

    #[test]
    fn test_find_condition_in_body() {
        // Create a simple loop with a condition inside:
        // B0 (entry) -> B1 (header)
        // B1: jump to B2
        // B2 (condition): branch cond, B3, B4
        // B3 (body): jump to B1 (back edge)
        // B4 (exit): ret

        let ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
            // B0: entry, jump to header
            f.block(0, |b| b.jump(1));
            // B1: header (dispatcher-like), jump to condition
            f.block(1, |b| b.jump(2));
            // B2: condition block with branch
            f.block(2, |b| {
                let cond = b.const_true();
                b.branch(cond, 3, 4);
            });
            // B3: body, jump back to header (back edge to B1)
            f.block(3, |b| b.jump(1));
            // B4: exit
            f.block(4, |b| b.ret());
        });

        let forest = ssa.analyze_loops();

        assert_eq!(forest.len(), 1, "Should have one loop");

        let loop_info = &forest.loops()[0];
        assert_eq!(loop_info.header, NodeId::new(1), "Header should be B1");

        // The condition block should be B2 (the one with Branch)
        let condition = loop_info.find_condition_in_body(&ssa);
        assert_eq!(
            condition,
            Some(NodeId::new(2)),
            "Condition block should be B2"
        );
    }

    #[test]
    fn test_find_all_conditions_in_body() {
        // Create a loop with multiple conditional branches
        // B0 -> B1 (header)
        // B1: jump to B2
        // B2: branch cond1, B3, B4
        // B3: branch cond2, B5, B1 (early exit or continue)
        // B4: branch cond3, B1, B5 (back edge or exit)
        // B5: ret

        let ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
            f.block(0, |b| b.jump(1));
            f.block(1, |b| b.jump(2));
            f.block(2, |b| {
                let cond = b.const_true();
                b.branch(cond, 3, 4);
            });
            f.block(3, |b| {
                let cond = b.const_true();
                b.branch(cond, 5, 1);
            });
            f.block(4, |b| {
                let cond = b.const_true();
                b.branch(cond, 1, 5);
            });
            f.block(5, |b| b.ret());
        });

        let forest = ssa.analyze_loops();
        assert!(!forest.is_empty(), "Should have at least one loop");

        let loop_info = &forest.loops()[0];
        let conditions = loop_info.find_all_conditions_in_body(&ssa);

        // Should find multiple condition blocks in the loop body
        assert!(
            !conditions.is_empty(),
            "Should find at least one condition block"
        );
    }

    #[test]
    fn test_simple_while_loop() {
        // Create a simple while loop:
        // B0 (entry) -> B1 (header)
        // B1: branch cond, B2, B3
        // B2 (body) -> B1 (back edge)
        // B3 (exit)

        let ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
            // B0: entry, jump to header
            f.block(0, |b| b.jump(1));
            // B1: header with conditional branch
            f.block(1, |b| {
                let cond = b.const_true();
                b.branch(cond, 2, 3);
            });
            // B2: body, jump back to header
            f.block(2, |b| b.jump(1));
            // B3: exit
            f.block(3, |b| b.ret());
        });

        let forest = ssa.analyze_loops();

        assert_eq!(forest.len(), 1);

        let loop_info = &forest.loops()[0];
        assert_eq!(loop_info.header, NodeId::new(1));
        assert!(loop_info.contains(NodeId::new(1)));
        assert!(loop_info.contains(NodeId::new(2)));
        assert!(!loop_info.contains(NodeId::new(0)));
        assert!(!loop_info.contains(NodeId::new(3)));

        // Should have single latch
        assert!(loop_info.has_single_latch());
        assert_eq!(loop_info.single_latch(), Some(NodeId::new(2)));

        // Should have preheader (B0)
        assert!(loop_info.has_preheader());
        assert_eq!(loop_info.preheader, Some(NodeId::new(0)));

        // Should be pre-tested (exit from header)
        assert_eq!(loop_info.loop_type, LoopType::PreTested);
        assert!(loop_info.is_canonical());
    }

    #[test]
    fn test_do_while_loop() {
        // Create a do-while loop:
        // B0 (entry) -> B1 (header/body)
        // B1: branch cond, B1, B2 (back edge is latch with exit)
        // B2 (exit)

        let ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
            // B0: entry, jump to header
            f.block(0, |b| b.jump(1));
            // B1: header/body with conditional back edge
            f.block(1, |b| {
                let cond = b.const_true();
                b.branch(cond, 1, 2); // back edge to 1, exit to 2
            });
            // B2: exit
            f.block(2, |b| b.ret());
        });

        let forest = ssa.analyze_loops();

        assert_eq!(forest.len(), 1);

        let loop_info = &forest.loops()[0];
        assert_eq!(loop_info.header, NodeId::new(1));

        // Latch is the header itself (self-loop)
        assert!(loop_info.has_single_latch());
        assert_eq!(loop_info.single_latch(), Some(NodeId::new(1)));

        // Exit is from latch, so this is post-tested
        assert_eq!(loop_info.loop_type, LoopType::PostTested);
    }

    #[test]
    fn test_nested_loops() {
        // Create nested loops:
        // B0 -> B1 (outer header)
        // B1 -> B2 (inner header)
        // B2 -> B2 (inner back edge), B3
        // B3 -> B1 (outer back edge), B4
        // B4 (exit)

        let ssa = {
            let mut cond_out = SsaVarId::new();
            SsaFunctionBuilder::new(0, 0).build_with(|f| {
                // B0: entry
                f.block(0, |b| b.jump(1));
                // B1: outer header
                f.block(1, |b| b.jump(2));
                // B2: inner header with self-loop
                f.block(2, |b| {
                    let c = b.const_true();
                    cond_out = c;
                    b.branch(c, 2, 3); // inner back edge to 2, exit to 3
                });
                // B3: between inner and outer, branches back to outer header or exits
                f.block(3, |b| b.branch(cond_out, 1, 4)); // outer back edge to 1, exit to 4
                                                          // B4: exit
                f.block(4, |b| b.ret());
            })
        };

        let forest = ssa.analyze_loops();

        assert_eq!(forest.len(), 2);

        // Find inner and outer loops
        let inner = forest.loop_for_header(NodeId::new(2)).unwrap();
        let outer = forest.loop_for_header(NodeId::new(1)).unwrap();

        // Inner loop should be nested in outer
        assert_eq!(inner.parent, Some(NodeId::new(1)));
        assert!(outer.children.contains(&NodeId::new(2)));

        // Depths
        assert_eq!(outer.depth, 0);
        assert_eq!(inner.depth, 1);

        // Block 2 should be in inner loop
        assert_eq!(forest.loop_depth(NodeId::new(2)), 2);
    }

    #[test]
    fn test_induction_variable_api() {
        // Test that the induction variable detection API works correctly.
        // We use an existing loop structure and verify the method can be called.

        let ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
            // B0: entry, jump to header
            f.block(0, |b| b.jump(1));
            // B1: header with conditional branch
            f.block(1, |b| {
                let cond = b.const_true();
                b.branch(cond, 2, 3);
            });
            // B2: body, jump back to header
            f.block(2, |b| b.jump(1));
            // B3: exit
            f.block(3, |b| b.ret());
        });

        let forest = ssa.analyze_loops();

        assert_eq!(forest.len(), 1, "Should have one loop");

        let loop_info = &forest.loops()[0];

        // Call the induction variable detection method
        // (may return empty since our simple test loop has no phi nodes)
        let induction_vars = loop_info.find_induction_vars(&ssa);

        // This simple loop has no phi nodes at the header, so no induction vars
        // The test verifies the API works without panicking
        assert!(
            induction_vars.is_empty(),
            "Simple loop without phi should have no induction vars"
        );
    }
}
