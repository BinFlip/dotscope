//! PHI node analysis utilities.
//!
//! This module provides utilities for analyzing PHI nodes in SSA form.
//! The [`PhiAnalyzer`] helps identify patterns like trivial PHIs (single unique source),
//! uniform constants (all operands resolve to the same value), and finding PHI definitions.
//!
//! # Example
//!
//! ```rust,ignore
//! use dotscope::analysis::{PhiAnalyzer, ConstEvaluator, SsaFunction};
//!
//! let analyzer = PhiAnalyzer::new(&ssa);
//!
//! // Check if a PHI is trivial (has single unique non-self source)
//! if let Some(source) = analyzer.is_trivial(phi) {
//!     println!("PHI can be replaced with copy from {:?}", source);
//! }
//!
//! // Check if all PHI operands resolve to the same constant
//! let mut evaluator = ConstEvaluator::new(&ssa);
//! if let Some(value) = analyzer.uniform_constant(phi, &mut evaluator) {
//!     println!("PHI always produces: {:?}", value);
//! }
//! ```

use std::collections::{HashMap, HashSet};

use crate::analysis::ssa::{
    ConstEvaluator, ConstValue, PhiNode, PhiOperand, SsaFunction, SsaOp, SsaVarId,
};

/// Analyzes PHI nodes for various patterns.
///
/// This struct provides methods for common PHI node analysis tasks:
/// - Detecting trivial PHIs that can be replaced with copies
/// - Finding PHIs where all operands resolve to the same constant
/// - Looking up PHI operands by predecessor block
/// - Finding the PHI node that defines a variable
pub struct PhiAnalyzer<'a> {
    /// Reference to the SSA function being analyzed.
    ssa: &'a SsaFunction,
}

impl<'a> PhiAnalyzer<'a> {
    /// Creates a new PHI analyzer for the given SSA function.
    ///
    /// # Arguments
    ///
    /// * `ssa` - The SSA function to analyze.
    #[must_use]
    pub fn new(ssa: &'a SsaFunction) -> Self {
        Self { ssa }
    }

    /// Returns a reference to the SSA function being analyzed.
    #[must_use]
    pub fn ssa(&self) -> &SsaFunction {
        self.ssa
    }

    /// Checks if a PHI is trivial (has a single unique non-self source).
    ///
    /// A trivial PHI can be replaced with a simple copy operation.
    /// This occurs when all non-self-referential operands point to the
    /// same source variable.
    ///
    /// # Arguments
    ///
    /// * `phi` - The PHI node to analyze.
    ///
    /// # Returns
    ///
    /// `Some(source)` if the PHI has exactly one unique non-self source,
    /// `None` otherwise.
    ///
    /// # Examples
    ///
    /// ```text
    /// // Trivial PHI (can be replaced with: result = v1)
    /// result = phi(v1, v1, result)  // Returns Some(v1)
    ///
    /// // Non-trivial PHI (multiple different sources)
    /// result = phi(v1, v2)  // Returns None
    ///
    /// // Non-trivial PHI (only self-references, unreachable)
    /// result = phi(result, result)  // Returns None
    /// ```
    #[must_use]
    pub fn is_trivial(&self, phi: &PhiNode) -> Option<SsaVarId> {
        let result = phi.result();

        // Collect non-self-referential operands
        let unique_sources: HashSet<SsaVarId> = phi
            .operands()
            .iter()
            .map(PhiOperand::value)
            .filter(|&v| v != result)
            .collect();

        // Trivial if exactly one unique non-self source
        if unique_sources.len() == 1 {
            let source = unique_sources.into_iter().next()?;

            // Check if replacing result with source would create a self-referential instruction.
            // This happens when source is defined by an instruction that uses result.
            // In such cases, the phi is NOT trivial - it's carrying a loop value.
            if let Some(op) = self.ssa.get_definition(source) {
                if op.uses().contains(&result) {
                    // source is defined as: source = f(..., result, ...)
                    // Replacing result with source would create: source = f(..., source, ...)
                    // This is a self-referential instruction, so phi is NOT trivial.
                    return None;
                }
            }

            Some(source)
        } else {
            None
        }
    }

    /// Checks if a PHI is fully self-referential (all operands reference the PHI's result).
    ///
    /// A fully self-referential PHI indicates unreachable code or undefined behavior,
    /// since there's no external value entering the PHI. Such PHIs can be safely removed.
    ///
    /// # Arguments
    ///
    /// * `phi` - The PHI node to analyze.
    ///
    /// # Returns
    ///
    /// `true` if all operands reference the PHI's own result variable, `false` otherwise.
    ///
    /// # Examples
    ///
    /// ```text
    /// // Fully self-referential (returns true)
    /// result = phi(result, result)
    ///
    /// // Not fully self-referential (returns false)
    /// result = phi(v1, result)
    /// result = phi(v1, v2)
    /// ```
    #[must_use]
    pub fn is_fully_self_referential(&self, phi: &PhiNode) -> bool {
        let result = phi.result();
        !phi.operands().is_empty() && phi.operands().iter().all(|op| op.value() == result)
    }

    /// Analyzes a PHI to determine its trivial status.
    ///
    /// This is the comprehensive analysis method that distinguishes between:
    /// - Trivial PHIs with a single replacement value
    /// - Fully self-referential PHIs that should be removed
    /// - Non-trivial PHIs that must be kept
    ///
    /// # Arguments
    ///
    /// * `phi` - The PHI node to analyze.
    ///
    /// # Returns
    ///
    /// - `Some(Some(var))` - PHI is trivial, can be replaced with `var`
    /// - `Some(None)` - PHI is fully self-referential, can be removed
    /// - `None` - PHI is not trivial, must be kept
    #[must_use]
    pub fn analyze_trivial(&self, phi: &PhiNode) -> Option<Option<SsaVarId>> {
        // Check if trivial with a replacement value
        if let Some(source) = self.is_trivial(phi) {
            return Some(Some(source));
        }

        // Check if fully self-referential (can be removed)
        if self.is_fully_self_referential(phi) {
            return Some(None);
        }

        // Not trivial
        None
    }

    /// Finds all trivial PHI nodes in the SSA function.
    ///
    /// Scans all reachable blocks for PHI nodes that are either:
    /// - Trivial with a single replacement value
    /// - Fully self-referential and can be removed
    ///
    /// # Arguments
    ///
    /// * `reachable` - Set of reachable block indices to scan.
    ///
    /// # Returns
    ///
    /// A vector of `(block_idx, phi_idx, replacement)` tuples where:
    /// - `replacement = Some(var)` - PHI can be replaced with `var`
    /// - `replacement = None` - PHI is fully self-referential and can be removed
    #[must_use]
    pub fn find_all_trivial(
        &self,
        reachable: &HashSet<usize>,
    ) -> Vec<(usize, usize, Option<SsaVarId>)> {
        let mut trivial = Vec::new();

        for &block_idx in reachable {
            if let Some(block) = self.ssa.block(block_idx) {
                for (phi_idx, phi) in block.phi_nodes().iter().enumerate() {
                    if let Some(replacement) = self.analyze_trivial(phi) {
                        trivial.push((block_idx, phi_idx, replacement));
                    }
                }
            }
        }

        trivial
    }

    /// Collects all copy-like operations in the SSA function.
    ///
    /// This method identifies all operations that are effectively copies:
    /// - Explicit `Copy` instructions: `dest = copy src`
    /// - Trivial phi nodes: `dest = phi(src, src, ...)` where all non-self operands are identical
    ///
    /// This is the unified entry point for copy detection, used by copy propagation
    /// and other optimizations that need to identify copy relationships.
    ///
    /// # Returns
    ///
    /// A map from each copy destination to its immediate source.
    ///
    /// # Example
    ///
    /// ```text
    /// // Given:
    /// v1 = copy v0           // Explicit copy
    /// v2 = phi(v0, v0)       // Trivial phi (all same source)
    /// v3 = phi(v0, v3)       // Trivial phi (self-ref excluded)
    /// v4 = phi(v0, v1)       // Non-trivial (different sources)
    ///
    /// // Returns: {v1 → v0, v2 → v0, v3 → v0}
    /// ```
    #[must_use]
    pub fn collect_all_copies(&self) -> HashMap<SsaVarId, SsaVarId> {
        let mut copies = HashMap::new();

        for block in self.ssa.blocks() {
            // Collect explicit copy instructions
            for instr in block.instructions() {
                if let SsaOp::Copy { dest, src } = instr.op() {
                    copies.insert(*dest, *src);
                }
            }

            // Collect trivial phi nodes (effectively copies)
            for phi in block.phi_nodes() {
                if let Some(source) = self.is_trivial(phi) {
                    copies.insert(phi.result(), source);
                }
            }
        }

        copies
    }

    /// Checks if all PHI operands resolve to the same constant.
    ///
    /// This is useful for detecting PHIs that always produce the same value,
    /// which can be replaced with a constant assignment.
    ///
    /// # Arguments
    ///
    /// * `phi` - The PHI node to analyze.
    /// * `evaluator` - A constant evaluator for resolving operand values.
    ///
    /// # Returns
    ///
    /// `Some(value)` if all operands evaluate to the same constant,
    /// `None` if operands differ, cannot be evaluated, or PHI is empty.
    ///
    /// # Examples
    ///
    /// ```text
    /// // Given: v1 = 42, v2 = 42
    /// result = phi(v1, v2)  // Returns Some(42)
    ///
    /// // Given: v1 = 42, v2 = 99
    /// result = phi(v1, v2)  // Returns None (values differ)
    ///
    /// // Given: v1 = 42, v2 = unknown
    /// result = phi(v1, v2)  // Returns None (v2 not constant)
    /// ```
    pub fn uniform_constant(
        &self,
        phi: &PhiNode,
        evaluator: &mut ConstEvaluator,
    ) -> Option<ConstValue> {
        let operands = phi.operands();

        // Empty PHI has no uniform value
        if operands.is_empty() {
            return None;
        }

        // Get the first operand's constant value
        let first_value = evaluator.evaluate_var(operands[0].value())?;

        // Check that all other operands have the same value
        for operand in operands.iter().skip(1) {
            let value = evaluator.evaluate_var(operand.value())?;
            if value != first_value {
                return None;
            }
        }

        Some(first_value)
    }

    /// Finds the PHI node that defines a variable.
    ///
    /// This delegates to [`SsaFunction::find_phi_defining`] for the actual lookup,
    /// which uses O(1) lookup via the variable's definition site when available.
    ///
    /// # Arguments
    ///
    /// * `var` - The SSA variable ID to find the defining PHI for.
    ///
    /// # Returns
    ///
    /// `Some((block_idx, &PhiNode))` if the variable is defined by a PHI node,
    /// `None` if the variable is not defined by a PHI or doesn't exist.
    #[must_use]
    pub fn find_phi_defining(&self, var: SsaVarId) -> Option<(usize, &PhiNode)> {
        self.ssa.find_phi_defining(var)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use crate::analysis::ssa::{
        ConstEvaluator, ConstValue, DefSite, PhiAnalyzer, PhiNode, PhiOperand, SsaBlock,
        SsaFunction, SsaInstruction, SsaOp, SsaVarId, SsaVariable, VariableOrigin,
    };

    #[test]
    fn test_phi_analyzer_creation() {
        let ssa = SsaFunction::new(0, 0);
        let analyzer = PhiAnalyzer::new(&ssa);

        // Basic sanity check
        assert_eq!(analyzer.ssa().num_args(), 0);
        assert_eq!(analyzer.ssa().num_locals(), 0);
    }

    #[test]
    fn test_is_trivial_single_source() {
        let ssa = SsaFunction::new(0, 0);
        let analyzer = PhiAnalyzer::new(&ssa);

        let result = SsaVarId::new();
        let source = SsaVarId::new();

        // phi(v1, v1) - trivial, single unique source
        let mut phi = PhiNode::new(result, VariableOrigin::Local(0));
        phi.add_operand(PhiOperand::new(source, 0));
        phi.add_operand(PhiOperand::new(source, 1));

        assert_eq!(analyzer.is_trivial(&phi), Some(source));
    }

    #[test]
    fn test_is_trivial_with_self_reference() {
        let ssa = SsaFunction::new(0, 0);
        let analyzer = PhiAnalyzer::new(&ssa);

        let result = SsaVarId::new();
        let source = SsaVarId::new();

        // phi(v1, result, v1) - trivial, self-references are ignored
        let mut phi = PhiNode::new(result, VariableOrigin::Local(0));
        phi.add_operand(PhiOperand::new(source, 0));
        phi.add_operand(PhiOperand::new(result, 1)); // self-reference
        phi.add_operand(PhiOperand::new(source, 2));

        assert_eq!(analyzer.is_trivial(&phi), Some(source));
    }

    #[test]
    fn test_is_trivial_multiple_sources() {
        let ssa = SsaFunction::new(0, 0);
        let analyzer = PhiAnalyzer::new(&ssa);

        let result = SsaVarId::new();
        let source1 = SsaVarId::new();
        let source2 = SsaVarId::new();

        // phi(v1, v2) - not trivial, multiple different sources
        let mut phi = PhiNode::new(result, VariableOrigin::Local(0));
        phi.add_operand(PhiOperand::new(source1, 0));
        phi.add_operand(PhiOperand::new(source2, 1));

        assert_eq!(analyzer.is_trivial(&phi), None);
    }

    #[test]
    fn test_is_trivial_only_self_references() {
        let ssa = SsaFunction::new(0, 0);
        let analyzer = PhiAnalyzer::new(&ssa);

        let result = SsaVarId::new();

        // phi(result, result) - not trivial, only self-references (unreachable)
        let mut phi = PhiNode::new(result, VariableOrigin::Local(0));
        phi.add_operand(PhiOperand::new(result, 0));
        phi.add_operand(PhiOperand::new(result, 1));

        assert_eq!(analyzer.is_trivial(&phi), None);
    }

    #[test]
    fn test_uniform_constant_same_values() {
        let mut ssa = SsaFunction::new(0, 0);
        let mut block = SsaBlock::new(0);

        // v1 = 42
        let v1 = SsaVariable::new(VariableOrigin::Stack(0), 0, DefSite::instruction(0, 0));
        let v1_id = v1.id();
        ssa.add_variable(v1);

        // v2 = 42
        let v2 = SsaVariable::new(VariableOrigin::Stack(1), 0, DefSite::instruction(0, 1));
        let v2_id = v2.id();
        ssa.add_variable(v2);

        block.add_instruction(SsaInstruction::synthetic(SsaOp::Const {
            dest: v1_id,
            value: ConstValue::I32(42),
        }));
        block.add_instruction(SsaInstruction::synthetic(SsaOp::Const {
            dest: v2_id,
            value: ConstValue::I32(42),
        }));
        block.add_instruction(SsaInstruction::synthetic(SsaOp::Return { value: None }));
        ssa.add_block(block);

        let analyzer = PhiAnalyzer::new(&ssa);
        let mut evaluator = ConstEvaluator::new(&ssa);

        // phi(v1, v2) where both are 42
        let phi_result = SsaVarId::new();
        let mut phi = PhiNode::new(phi_result, VariableOrigin::Local(0));
        phi.add_operand(PhiOperand::new(v1_id, 0));
        phi.add_operand(PhiOperand::new(v2_id, 1));

        assert_eq!(
            analyzer.uniform_constant(&phi, &mut evaluator),
            Some(ConstValue::I32(42))
        );
    }

    #[test]
    fn test_uniform_constant_different_values() {
        let mut ssa = SsaFunction::new(0, 0);
        let mut block = SsaBlock::new(0);

        // v1 = 42
        let v1 = SsaVariable::new(VariableOrigin::Stack(0), 0, DefSite::instruction(0, 0));
        let v1_id = v1.id();
        ssa.add_variable(v1);

        // v2 = 99
        let v2 = SsaVariable::new(VariableOrigin::Stack(1), 0, DefSite::instruction(0, 1));
        let v2_id = v2.id();
        ssa.add_variable(v2);

        block.add_instruction(SsaInstruction::synthetic(SsaOp::Const {
            dest: v1_id,
            value: ConstValue::I32(42),
        }));
        block.add_instruction(SsaInstruction::synthetic(SsaOp::Const {
            dest: v2_id,
            value: ConstValue::I32(99),
        }));
        block.add_instruction(SsaInstruction::synthetic(SsaOp::Return { value: None }));
        ssa.add_block(block);

        let analyzer = PhiAnalyzer::new(&ssa);
        let mut evaluator = ConstEvaluator::new(&ssa);

        // phi(v1, v2) where v1=42 and v2=99
        let phi_result = SsaVarId::new();
        let mut phi = PhiNode::new(phi_result, VariableOrigin::Local(0));
        phi.add_operand(PhiOperand::new(v1_id, 0));
        phi.add_operand(PhiOperand::new(v2_id, 1));

        assert_eq!(analyzer.uniform_constant(&phi, &mut evaluator), None);
    }

    #[test]
    fn test_uniform_constant_empty_phi() {
        let ssa = SsaFunction::new(0, 0);
        let analyzer = PhiAnalyzer::new(&ssa);
        let mut evaluator = ConstEvaluator::new(&ssa);

        // Empty PHI
        let phi_result = SsaVarId::new();
        let phi = PhiNode::new(phi_result, VariableOrigin::Local(0));

        assert_eq!(analyzer.uniform_constant(&phi, &mut evaluator), None);
    }

    #[test]
    fn test_uniform_constant_non_constant_operand() {
        let ssa = SsaFunction::new(0, 0);
        let analyzer = PhiAnalyzer::new(&ssa);
        let mut evaluator = ConstEvaluator::new(&ssa);

        // phi(v1, v2) where neither is defined (not constant)
        let phi_result = SsaVarId::new();
        let v1_id = SsaVarId::new();
        let v2_id = SsaVarId::new();

        let mut phi = PhiNode::new(phi_result, VariableOrigin::Local(0));
        phi.add_operand(PhiOperand::new(v1_id, 0));
        phi.add_operand(PhiOperand::new(v2_id, 1));

        assert_eq!(analyzer.uniform_constant(&phi, &mut evaluator), None);
    }

    #[test]
    fn test_find_defining_phi() {
        let mut ssa = SsaFunction::new(0, 0);

        // Create a variable defined by a PHI
        let phi_result = SsaVariable::new(VariableOrigin::Local(0), 0, DefSite::phi(0));
        let phi_result_id = phi_result.id();
        ssa.add_variable(phi_result);

        // Create block with PHI node
        let mut block = SsaBlock::new(0);
        let mut phi = PhiNode::new(phi_result_id, VariableOrigin::Local(0));
        let operand_id = SsaVarId::new();
        phi.add_operand(PhiOperand::new(operand_id, 1));
        block.add_phi(phi);
        block.add_instruction(SsaInstruction::synthetic(SsaOp::Return { value: None }));
        ssa.add_block(block);

        let analyzer = PhiAnalyzer::new(&ssa);

        // Should find the PHI
        let result = analyzer.find_phi_defining(phi_result_id);
        assert!(result.is_some());
        let (block_idx, found_phi) = result.unwrap();
        assert_eq!(block_idx, 0);
        assert_eq!(found_phi.result(), phi_result_id);
    }

    #[test]
    fn test_find_defining_not_phi() {
        let mut ssa = SsaFunction::new(0, 0);
        let mut block = SsaBlock::new(0);

        // Create a variable defined by a regular instruction (not PHI)
        let var = SsaVariable::new(VariableOrigin::Stack(0), 0, DefSite::instruction(0, 0));
        let var_id = var.id();
        ssa.add_variable(var);

        block.add_instruction(SsaInstruction::synthetic(SsaOp::Const {
            dest: var_id,
            value: ConstValue::I32(42),
        }));
        block.add_instruction(SsaInstruction::synthetic(SsaOp::Return { value: None }));
        ssa.add_block(block);

        let analyzer = PhiAnalyzer::new(&ssa);

        // Should not find a PHI (variable is defined by Const, not PHI)
        assert!(analyzer.find_phi_defining(var_id).is_none());
    }

    #[test]
    fn test_is_fully_self_referential_true() {
        let ssa = SsaFunction::new(0, 0);
        let analyzer = PhiAnalyzer::new(&ssa);

        let result = SsaVarId::new();

        // phi(result, result) - fully self-referential
        let mut phi = PhiNode::new(result, VariableOrigin::Local(0));
        phi.add_operand(PhiOperand::new(result, 0));
        phi.add_operand(PhiOperand::new(result, 1));

        assert!(analyzer.is_fully_self_referential(&phi));
    }

    #[test]
    fn test_is_fully_self_referential_false() {
        let ssa = SsaFunction::new(0, 0);
        let analyzer = PhiAnalyzer::new(&ssa);

        let result = SsaVarId::new();
        let source = SsaVarId::new();

        // phi(source, result) - not fully self-referential
        let mut phi = PhiNode::new(result, VariableOrigin::Local(0));
        phi.add_operand(PhiOperand::new(source, 0));
        phi.add_operand(PhiOperand::new(result, 1));

        assert!(!analyzer.is_fully_self_referential(&phi));
    }

    #[test]
    fn test_is_fully_self_referential_empty() {
        let ssa = SsaFunction::new(0, 0);
        let analyzer = PhiAnalyzer::new(&ssa);

        let result = SsaVarId::new();

        // Empty phi - not fully self-referential
        let phi = PhiNode::new(result, VariableOrigin::Local(0));

        assert!(!analyzer.is_fully_self_referential(&phi));
    }

    #[test]
    fn test_analyze_trivial_with_replacement() {
        let ssa = SsaFunction::new(0, 0);
        let analyzer = PhiAnalyzer::new(&ssa);

        let result = SsaVarId::new();
        let source = SsaVarId::new();

        // phi(source, source) - trivial with replacement
        let mut phi = PhiNode::new(result, VariableOrigin::Local(0));
        phi.add_operand(PhiOperand::new(source, 0));
        phi.add_operand(PhiOperand::new(source, 1));

        assert_eq!(analyzer.analyze_trivial(&phi), Some(Some(source)));
    }

    #[test]
    fn test_analyze_trivial_self_referential_removal() {
        let ssa = SsaFunction::new(0, 0);
        let analyzer = PhiAnalyzer::new(&ssa);

        let result = SsaVarId::new();

        // phi(result, result) - fully self-referential, should be removed
        let mut phi = PhiNode::new(result, VariableOrigin::Local(0));
        phi.add_operand(PhiOperand::new(result, 0));
        phi.add_operand(PhiOperand::new(result, 1));

        assert_eq!(analyzer.analyze_trivial(&phi), Some(None));
    }

    #[test]
    fn test_analyze_trivial_not_trivial() {
        let ssa = SsaFunction::new(0, 0);
        let analyzer = PhiAnalyzer::new(&ssa);

        let result = SsaVarId::new();
        let source1 = SsaVarId::new();
        let source2 = SsaVarId::new();

        // phi(source1, source2) - not trivial (different sources)
        let mut phi = PhiNode::new(result, VariableOrigin::Local(0));
        phi.add_operand(PhiOperand::new(source1, 0));
        phi.add_operand(PhiOperand::new(source2, 1));

        assert_eq!(analyzer.analyze_trivial(&phi), None);
    }

    #[test]
    fn test_find_all_trivial() {
        let mut ssa = SsaFunction::new(0, 0);

        // Block 0: entry with trivial phi
        let mut block0 = SsaBlock::new(0);
        let phi_result1 = SsaVarId::new();
        let source1 = SsaVarId::new();
        let mut phi1 = PhiNode::new(phi_result1, VariableOrigin::Local(0));
        phi1.add_operand(PhiOperand::new(source1, 1)); // trivial: single source
        block0.add_phi(phi1);
        block0.add_instruction(SsaInstruction::synthetic(SsaOp::Jump { target: 1 }));
        ssa.add_block(block0);

        // Block 1: self-referential phi
        let mut block1 = SsaBlock::new(1);
        let phi_result2 = SsaVarId::new();
        let mut phi2 = PhiNode::new(phi_result2, VariableOrigin::Local(1));
        phi2.add_operand(PhiOperand::new(phi_result2, 0)); // self-referential
        phi2.add_operand(PhiOperand::new(phi_result2, 1));
        block1.add_phi(phi2);
        block1.add_instruction(SsaInstruction::synthetic(SsaOp::Return { value: None }));
        ssa.add_block(block1);

        let analyzer = PhiAnalyzer::new(&ssa);
        let reachable: HashSet<usize> = [0, 1].iter().copied().collect();

        let trivial = analyzer.find_all_trivial(&reachable);

        // Should find 2 trivial PHIs
        assert_eq!(trivial.len(), 2);

        // Block 0, phi 0: trivial with replacement source1
        assert!(trivial.contains(&(0, 0, Some(source1))));

        // Block 1, phi 0: self-referential, no replacement
        assert!(trivial.contains(&(1, 0, None)));
    }
}
