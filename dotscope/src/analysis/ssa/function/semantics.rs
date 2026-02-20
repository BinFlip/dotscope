//! Block and loop semantic analysis for SSA functions.
//!
//! These methods delegate to the `SemanticAnalyzer` to classify blocks
//! by their role: initialization, condition, body, latch, exit, etc.

use std::collections::HashMap;

use crate::analysis::{
    cfg::{BlockSemantics, LoopSemantics, SemanticAnalyzer},
    ssa::SsaFunction,
    LoopInfo,
};

impl SsaFunction {
    /// Analyzes the semantic role of a specific block.
    ///
    /// Uses the `SemanticAnalyzer` to determine what a block does:
    /// initialization, condition testing, loop body work, variable updates, etc.
    ///
    /// # Arguments
    ///
    /// * `block_idx` - The block index to analyze
    ///
    /// # Returns
    ///
    /// Semantic information about the block including its role and characteristics.
    #[must_use]
    pub fn analyze_block_semantics(&self, block_idx: usize) -> BlockSemantics {
        let mut analyzer = SemanticAnalyzer::new(self);
        analyzer.analyze_block(block_idx).clone()
    }

    /// Analyzes semantic roles of multiple blocks.
    ///
    /// # Arguments
    ///
    /// * `blocks` - The block indices to analyze
    ///
    /// # Returns
    ///
    /// A map of block index to semantic information.
    #[must_use]
    pub fn analyze_blocks_semantics(&self, blocks: &[usize]) -> HashMap<usize, BlockSemantics> {
        let mut analyzer = SemanticAnalyzer::new(self);
        let mut results = HashMap::new();

        for &block in blocks {
            results.insert(block, analyzer.analyze_block(block).clone());
        }

        results
    }

    /// Analyzes the semantic structure of a structural loop.
    ///
    /// Given a `LoopInfo` from dominance-based loop detection, this method
    /// classifies each block within the loop by its semantic role:
    /// init, condition, body, latch, exit.
    ///
    /// # Arguments
    ///
    /// * `loop_info` - Structural loop information from `LoopForest`
    ///
    /// # Returns
    ///
    /// Semantic loop information with classified blocks and execution order.
    #[must_use]
    pub fn analyze_loop_semantics(&self, loop_info: &LoopInfo) -> LoopSemantics {
        let mut analyzer = SemanticAnalyzer::new(self);
        analyzer.analyze_loop(loop_info)
    }

    /// Recovers loop semantics from flattened dispatcher case blocks.
    ///
    /// This is the key method for control flow unflattening. Given the target
    /// blocks from a switch dispatcher, it analyzes each block's semantic role
    /// to reconstruct the original loop structure.
    ///
    /// # Arguments
    ///
    /// * `case_blocks` - Block indices that are case targets of the dispatcher
    /// * `dispatcher_block` - Optional index of the dispatcher block to exclude
    ///
    /// # Returns
    ///
    /// Semantic loop structure with blocks classified and ordered correctly.
    #[must_use]
    pub fn recover_loop_from_cases(
        &self,
        case_blocks: &[usize],
        dispatcher_block: Option<usize>,
    ) -> LoopSemantics {
        let mut analyzer = SemanticAnalyzer::new(self);

        // Mark dispatcher as known if provided
        if let Some(disp) = dispatcher_block {
            analyzer.mark_dispatcher(disp);
        }

        analyzer.recover_loop_from_cases(case_blocks)
    }

    /// Creates a semantic analyzer for this function.
    ///
    /// Use this when you need to perform multiple semantic analyses
    /// and want to benefit from caching.
    ///
    /// # Returns
    ///
    /// A new `SemanticAnalyzer` instance for this function.
    #[must_use]
    pub fn semantic_analyzer(&self) -> SemanticAnalyzer<'_> {
        SemanticAnalyzer::new(self)
    }
}
