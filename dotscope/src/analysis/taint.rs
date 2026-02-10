//! Generic taint analysis for SSA functions.
//!
//! This module provides a reusable taint analysis framework that can propagate
//! taint information through SSA variables and instructions. It supports:
//!
//! - **Forward propagation**: If an instruction uses a tainted variable, its
//!   output becomes tainted (the result depends on tainted data).
//! - **Backward propagation**: If an instruction's output is tainted, its
//!   inputs become tainted (they contribute to tainted data).
//! - **PHI handling**: Configurable modes for how taint flows through PHI nodes.
//!
//! # Use Cases
//!
//! - **CFF Unflattening**: Track state variables to identify dispatcher machinery
//! - **Cleanup Neutralization**: Identify instructions dependent on removed tokens
//! - **Security Analysis**: Track data flow from untrusted sources
//!
//! # Example
//!
//! ```rust,ignore
//! use dotscope::analysis::{TaintAnalysis, TaintConfig, PhiTaintMode, SsaFunction};
//!
//! let ssa: SsaFunction = /* ... */;
//!
//! let config = TaintConfig {
//!     forward: true,
//!     backward: true,
//!     phi_mode: PhiTaintMode::TaintAllOperands,
//!     max_iterations: 100,
//! };
//!
//! let mut taint = TaintAnalysis::new(config);
//! taint.add_tainted_var(some_var_id);
//! taint.propagate(&ssa);
//!
//! // Check what's tainted
//! if taint.is_var_tainted(other_var_id) {
//!     println!("Variable is tainted!");
//! }
//! ```

use std::collections::HashSet;

use crate::analysis::ssa::{SsaFunction, SsaOp, SsaVarId, VariableOrigin};

/// How to handle PHI nodes during taint propagation.
///
/// PHI nodes are control flow merge points where values from different
/// predecessors come together. The taint mode determines how taint
/// flows through these merge points.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PhiTaintMode {
    /// If the PHI result is tainted, all operands become tainted.
    ///
    /// Use this for backward analysis where you need to find all sources
    /// that could contribute to a tainted value.
    TaintAllOperands,

    /// If any operand is tainted, the PHI result becomes tainted.
    ///
    /// Use this for forward analysis where taint should flow from any
    /// predecessor path.
    TaintIfAnyOperand,

    /// Only taint operands from specific predecessor blocks.
    ///
    /// Use this for path-sensitive analysis where only certain control
    /// flow paths should propagate taint.
    TaintFromPredecessors(HashSet<usize>),

    /// Selective backward taint through PHI chains for CFF analysis.
    ///
    /// This mode is specifically designed for control flow flattening (CFF)
    /// analysis where we need to trace state values back through PHI chains.
    ///
    /// When a PHI result is tainted:
    /// - Check if the PHI's origin matches (if origin filter is Some)
    /// - Only taint operands from predecessors in the set
    /// - Recursively trace through intermediate PHIs with the same origin
    SelectivePhi {
        /// Set of predecessor blocks whose operands should be tainted.
        /// For CFF, this is typically the set of blocks that jump to the dispatcher.
        predecessors: HashSet<usize>,
        /// Optional `VariableOrigin` to filter PHI chains.
        /// Only PHIs with matching origin will be traversed.
        origin_filter: Option<VariableOrigin>,
    },

    /// Don't propagate taint through PHI nodes.
    ///
    /// Use this when PHIs represent control flow merge points that
    /// should act as taint barriers.
    NoPropagation,
}

/// Configuration for taint analysis.
///
/// Controls how taint propagates through the SSA graph.
#[derive(Debug, Clone)]
pub struct TaintConfig {
    /// Propagate forward (input tainted → output tainted).
    ///
    /// When enabled, if an instruction uses a tainted variable, its
    /// defined variable (if any) becomes tainted.
    pub forward: bool,

    /// Propagate backward (output tainted → inputs tainted).
    ///
    /// When enabled, if an instruction's defined variable is tainted,
    /// all variables it uses become tainted.
    pub backward: bool,

    /// How to handle PHI nodes.
    pub phi_mode: PhiTaintMode,

    /// Maximum iterations for fixpoint computation.
    ///
    /// Prevents infinite loops in pathological cases.
    pub max_iterations: usize,
}

impl Default for TaintConfig {
    fn default() -> Self {
        Self {
            forward: true,
            backward: false,
            phi_mode: PhiTaintMode::TaintIfAnyOperand,
            max_iterations: 100,
        }
    }
}

impl TaintConfig {
    /// Creates a config for forward-only propagation.
    ///
    /// Suitable for tracking what variables depend on a taint source.
    #[must_use]
    pub fn forward_only() -> Self {
        Self {
            forward: true,
            backward: false,
            phi_mode: PhiTaintMode::TaintIfAnyOperand,
            max_iterations: 100,
        }
    }

    /// Creates a config for bidirectional propagation.
    ///
    /// Suitable for cleanup neutralization where we need to find all
    /// instructions connected to removed tokens.
    #[must_use]
    pub fn bidirectional() -> Self {
        Self {
            forward: true,
            backward: true,
            phi_mode: PhiTaintMode::TaintAllOperands,
            max_iterations: 100,
        }
    }
}

/// Statistics about taint analysis execution.
#[derive(Debug, Clone, Default)]
pub struct TaintStats {
    /// Number of iterations to reach fixpoint.
    pub iterations: usize,
    /// Number of tainted variables.
    pub tainted_vars: usize,
    /// Number of tainted instructions.
    pub tainted_instrs: usize,
    /// Number of tainted PHI nodes.
    pub tainted_phis: usize,
}

/// Generic taint analysis for SSA functions.
///
/// This struct tracks which variables and instructions are "tainted" - meaning
/// they are connected to some set of taint sources through data flow.
///
/// The analysis runs to a fixpoint, propagating taint through the SSA graph
/// according to the configuration.
#[derive(Debug, Clone)]
pub struct TaintAnalysis {
    /// Tainted SSA variables.
    tainted_vars: HashSet<SsaVarId>,

    /// Tainted instructions: (block_idx, instr_idx).
    tainted_instrs: HashSet<(usize, usize)>,

    /// Tainted PHI nodes: (block_idx, phi_idx).
    tainted_phis: HashSet<(usize, usize)>,

    /// Configuration.
    config: TaintConfig,

    /// Statistics from the last propagation.
    stats: TaintStats,
}

impl TaintAnalysis {
    /// Creates a new taint analysis with the given configuration.
    ///
    /// # Arguments
    ///
    /// * `config` - Configuration controlling propagation behavior.
    ///
    /// # Returns
    ///
    /// A new `TaintAnalysis` with empty taint sets.
    #[must_use]
    pub fn new(config: TaintConfig) -> Self {
        Self {
            tainted_vars: HashSet::new(),
            tainted_instrs: HashSet::new(),
            tainted_phis: HashSet::new(),
            config,
            stats: TaintStats::default(),
        }
    }

    /// Creates a taint analysis with default forward-only configuration.
    #[must_use]
    pub fn forward_only() -> Self {
        Self::new(TaintConfig::forward_only())
    }

    /// Creates a taint analysis with bidirectional configuration.
    #[must_use]
    pub fn bidirectional() -> Self {
        Self::new(TaintConfig::bidirectional())
    }

    /// Adds a variable as a taint source.
    ///
    /// # Arguments
    ///
    /// * `var` - The variable ID to mark as tainted.
    pub fn add_tainted_var(&mut self, var: SsaVarId) {
        self.tainted_vars.insert(var);
    }

    /// Adds multiple variables as taint sources.
    ///
    /// # Arguments
    ///
    /// * `vars` - Iterator of variable IDs to mark as tainted.
    pub fn add_tainted_vars(&mut self, vars: impl IntoIterator<Item = SsaVarId>) {
        self.tainted_vars.extend(vars);
    }

    /// Adds an instruction as a taint source.
    ///
    /// Also taints the instruction's defined variable (if any) and its uses
    /// (for backward propagation from instructions without defs like stores).
    ///
    /// # Arguments
    ///
    /// * `block` - Block index containing the instruction.
    /// * `instr` - Instruction index within the block.
    /// * `ssa` - The SSA function for looking up the instruction's def/uses.
    pub fn add_tainted_instr(&mut self, block: usize, instr: usize, ssa: &SsaFunction) {
        self.tainted_instrs.insert((block, instr));

        if let Some(block_data) = ssa.block(block) {
            if let Some(instruction) = block_data.instructions().get(instr) {
                // Taint the instruction's defined variable (for forward propagation)
                if let Some(def) = instruction.def() {
                    self.tainted_vars.insert(def);
                }

                // Also taint the instruction's uses (for backward propagation).
                // This is critical for instructions like StoreStaticField that have
                // no def - we need to taint what feeds into them.
                if self.config.backward {
                    for use_var in instruction.uses() {
                        self.tainted_vars.insert(use_var);
                    }
                }
            }
        }
    }

    /// Adds a PHI node as a taint source.
    ///
    /// Also taints the PHI's result variable.
    ///
    /// # Arguments
    ///
    /// * `block` - Block index containing the PHI.
    /// * `phi_idx` - PHI index within the block.
    /// * `ssa` - The SSA function for looking up the PHI's result.
    pub fn add_tainted_phi(&mut self, block: usize, phi_idx: usize, ssa: &SsaFunction) {
        self.tainted_phis.insert((block, phi_idx));

        // Also taint the PHI's result variable
        if let Some(block_data) = ssa.block(block) {
            if let Some(phi) = block_data.phi_nodes().get(phi_idx) {
                self.tainted_vars.insert(phi.result());
            }
        }
    }

    /// Runs taint propagation to fixpoint.
    ///
    /// Iteratively propagates taint through the SSA graph until no more
    /// changes occur or the iteration limit is reached.
    ///
    /// # Arguments
    ///
    /// * `ssa` - The SSA function to analyze.
    pub fn propagate(&mut self, ssa: &SsaFunction) {
        let mut iterations = 0;

        loop {
            if iterations >= self.config.max_iterations {
                break;
            }
            iterations += 1;

            let mut changed = false;

            // Process PHI nodes first
            changed |= self.propagate_phis(ssa);

            // Process instructions
            changed |= self.propagate_instructions(ssa);

            if !changed {
                break;
            }
        }

        // Update statistics
        self.stats = TaintStats {
            iterations,
            tainted_vars: self.tainted_vars.len(),
            tainted_instrs: self.tainted_instrs.len(),
            tainted_phis: self.tainted_phis.len(),
        };
    }

    /// Propagates taint through PHI nodes.
    ///
    /// Returns `true` if any changes were made.
    fn propagate_phis(&mut self, ssa: &SsaFunction) -> bool {
        let mut changed = false;

        for (block_idx, block) in ssa.blocks().iter().enumerate() {
            for (phi_idx, phi) in block.phi_nodes().iter().enumerate() {
                let result = phi.result();
                let result_tainted = self.tainted_vars.contains(&result);

                match &self.config.phi_mode {
                    PhiTaintMode::TaintAllOperands => {
                        // If result is tainted, all operands become tainted
                        if result_tainted {
                            for operand in phi.operands() {
                                if self.tainted_vars.insert(operand.value()) {
                                    changed = true;
                                }
                            }
                            if self.tainted_phis.insert((block_idx, phi_idx)) {
                                changed = true;
                            }
                        }
                    }
                    PhiTaintMode::TaintIfAnyOperand => {
                        // If any operand is tainted, result becomes tainted
                        let any_operand_tainted = phi
                            .operands()
                            .iter()
                            .any(|op| self.tainted_vars.contains(&op.value()));

                        if any_operand_tainted {
                            if self.tainted_vars.insert(result) {
                                changed = true;
                            }
                            if self.tainted_phis.insert((block_idx, phi_idx)) {
                                changed = true;
                            }
                        }
                    }
                    PhiTaintMode::TaintFromPredecessors(preds) => {
                        // Only taint operands from specific predecessors
                        if result_tainted {
                            for operand in phi.operands() {
                                if preds.contains(&operand.predecessor())
                                    && self.tainted_vars.insert(operand.value())
                                {
                                    changed = true;
                                }
                            }
                            if self.tainted_phis.insert((block_idx, phi_idx)) {
                                changed = true;
                            }
                        }
                    }
                    PhiTaintMode::SelectivePhi {
                        predecessors,
                        origin_filter,
                    } => {
                        // Selective backward taint for CFF analysis
                        if result_tainted {
                            // Check if this PHI's origin matches the filter
                            let should_follow = origin_filter
                                .as_ref()
                                .is_none_or(|filter| phi.origin() == *filter);

                            if should_follow {
                                for operand in phi.operands() {
                                    if predecessors.contains(&operand.predecessor())
                                        && self.tainted_vars.insert(operand.value())
                                    {
                                        changed = true;
                                    }
                                }
                                if self.tainted_phis.insert((block_idx, phi_idx)) {
                                    changed = true;
                                }
                            }
                        }
                    }
                    PhiTaintMode::NoPropagation => {
                        // Don't propagate through PHIs
                    }
                }
            }
        }

        changed
    }

    /// Propagates taint through instructions.
    ///
    /// Returns `true` if any changes were made.
    fn propagate_instructions(&mut self, ssa: &SsaFunction) -> bool {
        let mut changed = false;

        for (block_idx, instr_idx, instr) in ssa.iter_instructions() {
            let def = instr.def();
            let uses = instr.uses();

            // Forward propagation: if any USE is tainted, DEF becomes tainted
            if self.config.forward {
                if let Some(def_var) = def {
                    let uses_tainted = uses.iter().any(|u| self.tainted_vars.contains(u));
                    if uses_tainted {
                        if self.tainted_vars.insert(def_var) {
                            changed = true;
                        }
                        if self.tainted_instrs.insert((block_idx, instr_idx)) {
                            changed = true;
                        }
                    }
                }
            }

            // Backward propagation: if DEF is tainted, all USEs become tainted
            if self.config.backward {
                let def_tainted = def.is_some_and(|d| self.tainted_vars.contains(&d));
                if def_tainted {
                    for use_var in &uses {
                        if self.tainted_vars.insert(*use_var) {
                            changed = true;
                        }
                    }
                    if self.tainted_instrs.insert((block_idx, instr_idx)) {
                        changed = true;
                    }
                }
            }

            // Array-aware propagation: if an array is tainted, all StoreElement
            // operations to that array are also tainted (they're preparing dead data).
            // This is critical for cleanup neutralization where protection code fills
            // arrays that are passed to removed methods.
            if self.config.backward {
                if let SsaOp::StoreElement { array, .. } = instr.op() {
                    if self.tainted_vars.contains(array)
                        && self.tainted_instrs.insert((block_idx, instr_idx))
                    {
                        changed = true;
                        // Also taint the value and index being stored - they feed into dead code
                        for use_var in &uses {
                            if self.tainted_vars.insert(*use_var) {
                                changed = true;
                            }
                        }
                    }
                }
            }

            // Mark instruction as tainted if it uses tainted vars (even without def)
            let uses_tainted = uses.iter().any(|u| self.tainted_vars.contains(u));
            if uses_tainted && self.tainted_instrs.insert((block_idx, instr_idx)) {
                changed = true;
            }
        }

        changed
    }

    /// Checks if a variable is tainted.
    ///
    /// # Arguments
    ///
    /// * `var` - The variable ID to check.
    ///
    /// # Returns
    ///
    /// `true` if the variable is tainted.
    #[must_use]
    pub fn is_var_tainted(&self, var: SsaVarId) -> bool {
        self.tainted_vars.contains(&var)
    }

    /// Checks if an instruction is tainted.
    ///
    /// # Arguments
    ///
    /// * `block` - Block index.
    /// * `instr` - Instruction index within the block.
    ///
    /// # Returns
    ///
    /// `true` if the instruction is tainted.
    #[must_use]
    pub fn is_instr_tainted(&self, block: usize, instr: usize) -> bool {
        self.tainted_instrs.contains(&(block, instr))
    }

    /// Checks if a PHI node is tainted.
    ///
    /// # Arguments
    ///
    /// * `block` - Block index.
    /// * `phi_idx` - PHI index within the block.
    ///
    /// # Returns
    ///
    /// `true` if the PHI is tainted.
    #[must_use]
    pub fn is_phi_tainted(&self, block: usize, phi_idx: usize) -> bool {
        self.tainted_phis.contains(&(block, phi_idx))
    }

    /// Returns all tainted variables.
    #[must_use]
    pub fn tainted_variables(&self) -> &HashSet<SsaVarId> {
        &self.tainted_vars
    }

    /// Returns all tainted instructions.
    #[must_use]
    pub fn tainted_instructions(&self) -> &HashSet<(usize, usize)> {
        &self.tainted_instrs
    }

    /// Returns all tainted PHI nodes.
    #[must_use]
    pub fn tainted_phis(&self) -> &HashSet<(usize, usize)> {
        &self.tainted_phis
    }

    /// Returns statistics from the last propagation.
    #[must_use]
    pub fn stats(&self) -> &TaintStats {
        &self.stats
    }

    /// Returns the number of tainted variables.
    #[must_use]
    pub fn tainted_var_count(&self) -> usize {
        self.tainted_vars.len()
    }

    /// Returns the number of tainted instructions.
    #[must_use]
    pub fn tainted_instr_count(&self) -> usize {
        self.tainted_instrs.len()
    }

    /// Clears all taint information.
    pub fn clear(&mut self) {
        self.tainted_vars.clear();
        self.tainted_instrs.clear();
        self.tainted_phis.clear();
        self.stats = TaintStats::default();
    }
}

/// Finds all blocks that have a direct jump/branch to the target block.
///
/// This is useful for CFF analysis where we need to identify which blocks
/// set the state variable (those that jump back to the dispatcher).
///
/// # Arguments
///
/// * `ssa` - The SSA function to analyze.
/// * `target` - The target block index to find jumpers to.
///
/// # Returns
///
/// A set of block indices that have a control flow edge to `target`.
#[must_use]
pub fn find_blocks_jumping_to(ssa: &SsaFunction, target: usize) -> HashSet<usize> {
    let mut jumpers = HashSet::new();

    for block in ssa.blocks() {
        if let Some(terminator) = block.instructions().last() {
            let jumps_to_target = match terminator.op() {
                SsaOp::Jump { target: t } | SsaOp::Leave { target: t } => *t == target,
                SsaOp::Branch {
                    true_target,
                    false_target,
                    ..
                } => *true_target == target || *false_target == target,
                SsaOp::BranchCmp {
                    true_target,
                    false_target,
                    ..
                } => *true_target == target || *false_target == target,
                SsaOp::Switch {
                    targets, default, ..
                } => *default == target || targets.contains(&target),
                _ => false,
            };

            if jumps_to_target {
                jumpers.insert(block.id());
            }
        }
    }

    jumpers
}

/// Creates a CFF-specific taint configuration for state variable analysis.
///
/// This configuration is designed for control flow flattening analysis where:
/// - Forward propagation is enabled (derived values from state are tainted)
/// - Backward propagation is disabled (too aggressive, taints loop counters)
/// - PHI taint uses selective mode (only from blocks jumping to dispatcher)
///
/// # Arguments
///
/// * `ssa` - The SSA function being analyzed.
/// * `dispatcher_block` - The block index of the CFF dispatcher.
/// * `state_origin` - Optional `VariableOrigin` to filter PHI chains.
///
/// # Returns
///
/// A `TaintConfig` configured for CFF state tracking.
#[must_use]
pub fn cff_taint_config(
    ssa: &SsaFunction,
    dispatcher_block: usize,
    state_origin: Option<VariableOrigin>,
) -> TaintConfig {
    let predecessors = find_blocks_jumping_to(ssa, dispatcher_block);

    TaintConfig {
        forward: true,
        backward: false,
        phi_mode: PhiTaintMode::SelectivePhi {
            predecessors,
            origin_filter: state_origin,
        },
        max_iterations: 100,
    }
}

/// Builder for taint analysis that finds instructions referencing specific tokens.
///
/// This is a convenience builder for the common pattern of finding all instructions
/// that reference a set of tokens (methods, types, fields) and then propagating
/// taint from those instructions.
#[derive(Debug)]
pub struct TokenTaintBuilder {
    /// Tokens to find references to.
    target_tokens: HashSet<crate::metadata::token::Token>,
    /// Configuration for the taint analysis.
    config: TaintConfig,
}

impl TokenTaintBuilder {
    /// Creates a new token taint builder.
    ///
    /// # Arguments
    ///
    /// * `tokens` - Tokens to find references to.
    #[must_use]
    pub fn new(tokens: impl IntoIterator<Item = crate::metadata::token::Token>) -> Self {
        Self {
            target_tokens: tokens.into_iter().collect(),
            config: TaintConfig::bidirectional(),
        }
    }

    /// Sets the taint configuration.
    #[must_use]
    pub fn with_config(mut self, config: TaintConfig) -> Self {
        self.config = config;
        self
    }

    /// Builds and runs the taint analysis on the given SSA function.
    ///
    /// Finds all instructions that reference the target tokens, marks them
    /// as taint sources, and propagates to fixpoint.
    ///
    /// # Arguments
    ///
    /// * `ssa` - The SSA function to analyze.
    ///
    /// # Returns
    ///
    /// The completed taint analysis.
    #[must_use]
    pub fn analyze(self, ssa: &SsaFunction) -> TaintAnalysis {
        let mut taint = TaintAnalysis::new(self.config);

        // Find instructions that reference target tokens
        for (block_idx, instr_idx, instr) in ssa.iter_instructions() {
            if let Some(token) = instr.op().referenced_token() {
                if self.target_tokens.contains(&token) {
                    taint.add_tainted_instr(block_idx, instr_idx, ssa);
                }
            }
        }

        // Propagate taint
        taint.propagate(ssa);

        taint
    }
}

/// Convenience function to find instructions referencing removed tokens.
///
/// This is the main entry point for cleanup neutralization. It finds all
/// instructions that reference the given tokens and propagates taint to
/// find all dependent instructions.
///
/// # Arguments
///
/// * `ssa` - The SSA function to analyze.
/// * `removed_tokens` - Tokens that will be removed.
///
/// # Returns
///
/// A taint analysis with all dependent instructions marked.
#[must_use]
pub fn find_token_dependencies(
    ssa: &SsaFunction,
    removed_tokens: impl IntoIterator<Item = crate::metadata::token::Token>,
) -> TaintAnalysis {
    TokenTaintBuilder::new(removed_tokens).analyze(ssa)
}

#[cfg(test)]
mod tests {
    use crate::analysis::{
        ConstValue, PhiNode, PhiOperand, SsaBlock, SsaFunction, SsaInstruction, SsaOp, SsaVarId,
        VariableOrigin,
    };

    use super::*;

    /// Creates a simple SSA function for testing.
    ///
    /// ```text
    /// Block 0:
    ///   v0 = const 42
    ///   v1 = const 10
    ///   v2 = add v0, v1
    ///   jump block 1
    ///
    /// Block 1:
    ///   v3 = mul v2, v0
    ///   ret v3
    /// ```
    fn create_simple_ssa() -> (SsaFunction, SsaVarId, SsaVarId, SsaVarId, SsaVarId) {
        let mut ssa = SsaFunction::new(0, 0);

        let v0 = SsaVarId::new();
        let v1 = SsaVarId::new();
        let v2 = SsaVarId::new();
        let v3 = SsaVarId::new();

        // Block 0
        let mut b0 = SsaBlock::new(0);
        b0.add_instruction(SsaInstruction::synthetic(SsaOp::Const {
            dest: v0,
            value: ConstValue::I32(42),
        }));
        b0.add_instruction(SsaInstruction::synthetic(SsaOp::Const {
            dest: v1,
            value: ConstValue::I32(10),
        }));
        b0.add_instruction(SsaInstruction::synthetic(SsaOp::Add {
            dest: v2,
            left: v0,
            right: v1,
        }));
        b0.add_instruction(SsaInstruction::synthetic(SsaOp::Jump { target: 1 }));
        ssa.add_block(b0);

        // Block 1
        let mut b1 = SsaBlock::new(1);
        b1.add_instruction(SsaInstruction::synthetic(SsaOp::Mul {
            dest: v3,
            left: v2,
            right: v0,
        }));
        b1.add_instruction(SsaInstruction::synthetic(SsaOp::Return { value: Some(v3) }));
        ssa.add_block(b1);

        (ssa, v0, v1, v2, v3)
    }

    /// Creates an SSA function with a PHI node for testing.
    ///
    /// ```text
    /// Block 0:
    ///   v0 = const 1
    ///   jump block 2
    ///
    /// Block 1:
    ///   v1 = const 2
    ///   jump block 2
    ///
    /// Block 2:
    ///   v2 = phi(v0 from 0, v1 from 1)
    ///   ret v2
    /// ```
    fn create_phi_ssa() -> (SsaFunction, SsaVarId, SsaVarId, SsaVarId) {
        let mut ssa = SsaFunction::new(0, 0);

        let v0 = SsaVarId::new();
        let v1 = SsaVarId::new();
        let v2 = SsaVarId::new();

        // Block 0
        let mut b0 = SsaBlock::new(0);
        b0.add_instruction(SsaInstruction::synthetic(SsaOp::Const {
            dest: v0,
            value: ConstValue::I32(1),
        }));
        b0.add_instruction(SsaInstruction::synthetic(SsaOp::Jump { target: 2 }));
        ssa.add_block(b0);

        // Block 1
        let mut b1 = SsaBlock::new(1);
        b1.add_instruction(SsaInstruction::synthetic(SsaOp::Const {
            dest: v1,
            value: ConstValue::I32(2),
        }));
        b1.add_instruction(SsaInstruction::synthetic(SsaOp::Jump { target: 2 }));
        ssa.add_block(b1);

        // Block 2 with PHI
        let mut b2 = SsaBlock::new(2);
        let mut phi = PhiNode::new(v2, VariableOrigin::Stack(0));
        phi.add_operand(PhiOperand::new(v0, 0));
        phi.add_operand(PhiOperand::new(v1, 1));
        b2.add_phi(phi);
        b2.add_instruction(SsaInstruction::synthetic(SsaOp::Return { value: Some(v2) }));
        ssa.add_block(b2);

        (ssa, v0, v1, v2)
    }

    #[test]
    fn test_forward_propagation() {
        let (ssa, v0, v1, v2, v3) = create_simple_ssa();

        let mut taint = TaintAnalysis::forward_only();
        taint.add_tainted_var(v0);
        taint.propagate(&ssa);

        // v0 is the source
        assert!(taint.is_var_tainted(v0));
        // v1 is not tainted (independent constant)
        assert!(!taint.is_var_tainted(v1));
        // v2 uses v0, so it's tainted
        assert!(taint.is_var_tainted(v2));
        // v3 uses v2 and v0, so it's tainted
        assert!(taint.is_var_tainted(v3));

        // Instructions using tainted vars should be tainted
        assert!(taint.is_instr_tainted(0, 2)); // add v0, v1
        assert!(taint.is_instr_tainted(1, 0)); // mul v2, v0
    }

    #[test]
    fn test_backward_propagation() {
        let (ssa, v0, v1, v2, v3) = create_simple_ssa();

        let mut taint = TaintAnalysis::bidirectional();
        taint.add_tainted_var(v3);
        taint.propagate(&ssa);

        // v3 is the source
        assert!(taint.is_var_tainted(v3));
        // v2 is used to compute v3, so backward taint
        assert!(taint.is_var_tainted(v2));
        // v0 is used to compute v3 and v2, so backward taint
        assert!(taint.is_var_tainted(v0));
        // v1 is used to compute v2, so backward taint
        assert!(taint.is_var_tainted(v1));
    }

    #[test]
    fn test_phi_taint_if_any_operand() {
        let (ssa, v0, v1, v2) = create_phi_ssa();

        let config = TaintConfig {
            forward: true,
            backward: false,
            phi_mode: PhiTaintMode::TaintIfAnyOperand,
            max_iterations: 100,
        };

        let mut taint = TaintAnalysis::new(config);
        taint.add_tainted_var(v0);
        taint.propagate(&ssa);

        // v0 is tainted
        assert!(taint.is_var_tainted(v0));
        // v1 is not tainted
        assert!(!taint.is_var_tainted(v1));
        // v2 should be tainted because v0 (one of its operands) is tainted
        assert!(taint.is_var_tainted(v2));
        // The PHI should be marked as tainted
        assert!(taint.is_phi_tainted(2, 0));
    }

    #[test]
    fn test_phi_taint_all_operands() {
        let (ssa, v0, v1, v2) = create_phi_ssa();

        let config = TaintConfig {
            forward: false,
            backward: true,
            phi_mode: PhiTaintMode::TaintAllOperands,
            max_iterations: 100,
        };

        let mut taint = TaintAnalysis::new(config);
        taint.add_tainted_var(v2);
        taint.propagate(&ssa);

        // v2 is the source
        assert!(taint.is_var_tainted(v2));
        // Both v0 and v1 should be tainted (backward through PHI)
        assert!(taint.is_var_tainted(v0));
        assert!(taint.is_var_tainted(v1));
    }

    #[test]
    fn test_phi_no_propagation() {
        let (ssa, v0, _v1, v2) = create_phi_ssa();

        let config = TaintConfig {
            forward: true,
            backward: false,
            phi_mode: PhiTaintMode::NoPropagation,
            max_iterations: 100,
        };

        let mut taint = TaintAnalysis::new(config);
        taint.add_tainted_var(v0);
        taint.propagate(&ssa);

        // v0 is tainted
        assert!(taint.is_var_tainted(v0));
        // v2 should NOT be tainted because PHI propagation is disabled
        assert!(!taint.is_var_tainted(v2));
    }

    #[test]
    fn test_phi_from_specific_predecessors() {
        let (ssa, v0, v1, v2) = create_phi_ssa();

        // Only allow propagation from predecessor 0
        let mut preds = HashSet::new();
        preds.insert(0);

        let config = TaintConfig {
            forward: false,
            backward: true,
            phi_mode: PhiTaintMode::TaintFromPredecessors(preds),
            max_iterations: 100,
        };

        let mut taint = TaintAnalysis::new(config);
        taint.add_tainted_var(v2);
        taint.propagate(&ssa);

        // v2 is the source
        assert!(taint.is_var_tainted(v2));
        // v0 should be tainted (from predecessor 0)
        assert!(taint.is_var_tainted(v0));
        // v1 should NOT be tainted (from predecessor 1, not in the set)
        assert!(!taint.is_var_tainted(v1));
    }

    #[test]
    fn test_instruction_taint_source() {
        let (ssa, v0, v1, v2, v3) = create_simple_ssa();

        let mut taint = TaintAnalysis::forward_only();
        // Mark the add instruction as a taint source
        taint.add_tainted_instr(0, 2, &ssa);
        taint.propagate(&ssa);

        // The add's result (v2) should be tainted
        assert!(taint.is_var_tainted(v2));
        // v3 uses v2, so it should be tainted
        assert!(taint.is_var_tainted(v3));
        // v0 and v1 should NOT be tainted (they're inputs, not outputs)
        assert!(!taint.is_var_tainted(v0));
        assert!(!taint.is_var_tainted(v1));
    }

    #[test]
    fn test_stats() {
        let (ssa, v0, _, _, _) = create_simple_ssa();

        let mut taint = TaintAnalysis::forward_only();
        taint.add_tainted_var(v0);
        taint.propagate(&ssa);

        let stats = taint.stats();
        assert!(stats.iterations > 0);
        assert!(stats.tainted_vars > 0);
    }

    #[test]
    fn test_clear() {
        let (ssa, v0, _, _, _) = create_simple_ssa();

        let mut taint = TaintAnalysis::forward_only();
        taint.add_tainted_var(v0);
        taint.propagate(&ssa);

        assert!(taint.tainted_var_count() > 0);

        taint.clear();

        assert_eq!(taint.tainted_var_count(), 0);
        assert_eq!(taint.tainted_instr_count(), 0);
    }
}
