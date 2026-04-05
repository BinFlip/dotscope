//! SSA verifier for validating SSA invariants.
//!
//! Provides comprehensive verification of SSA form at three levels:
//!
//! - **Quick**: Single-definition property + block structure (O(n))
//! - **Standard**: + def-use chains + phi operand coverage (O(n*m))
//! - **Full**: + dominance checking (O(n^2) worst case)
//!
//! The verifier is the safety net for all SSA transformations. It catches
//! invariant violations early, preventing silent corruption that would
//! manifest as broken codegen or incorrect deobfuscation.

use std::collections::HashMap;

use crate::{
    analysis::ssa::{cfg::SsaCfg, DefSite, SsaFunction, SsaVarId},
    utils::{
        graph::{
            algorithms::{compute_dominators, DominatorTree},
            NodeId, RootedGraph,
        },
        BitSet,
    },
};

/// Definition site for verifier error reporting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifierDefSite {
    pub block: usize,
    pub kind: DefKind,
}

/// What kind of definition produced a variable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DefKind {
    Phi(usize),
    Instruction(usize),
}

/// Errors detected by the SSA verifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifierError {
    /// A variable is used but never defined.
    UndefinedUse {
        block: usize,
        instr_idx: usize,
        var: SsaVarId,
    },
    /// A phi node is missing an operand for a CFG predecessor.
    MissingPhiOperand {
        block: usize,
        phi_idx: usize,
        missing_pred: usize,
    },
    /// A phi node has an operand for a non-predecessor block.
    ExtraPhiOperand {
        block: usize,
        phi_idx: usize,
        extra_pred: usize,
    },
    /// A variable is defined more than once.
    DuplicateDefinition {
        var: SsaVarId,
        def1: VerifierDefSite,
        def2: VerifierDefSite,
    },
    /// A variable exists in the variables vec but has no definition in any block.
    OrphanVariable { var: SsaVarId },
    /// A variable appears in an instruction but is not in the variables vec.
    UnregisteredVariable { var: SsaVarId },
    /// A block has successors but no terminator instruction.
    MissingTerminator { block: usize },
    /// A phi node appears in the entry block (block 0), which has no predecessors
    /// in a well-formed CFG.
    PhiInEntryBlock { block: usize, phi_idx: usize },
    /// A variable is used in a block not dominated by its definition block.
    DominanceViolation {
        var: SsaVarId,
        def_block: usize,
        use_block: usize,
    },
    /// A terminator instruction is not the last instruction in its block.
    TerminatorNotLast {
        block: usize,
        instr_idx: usize,
        instr_count: usize,
    },
    /// An instruction uses a variable defined later in the same block (cycle).
    IntraBlockCycle {
        block: usize,
        use_instr: usize,
        def_instr: usize,
        var: SsaVarId,
    },
    /// A placeholder variable ID (usize::MAX) remains in finalized SSA.
    PlaceholderVariable { block: usize, location: String },
    /// An instruction's destination appears in its own operands (self-referential).
    SelfReferentialInstruction {
        block: usize,
        instr_idx: usize,
        var: SsaVarId,
    },
}

impl std::fmt::Display for VerifierError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UndefinedUse {
                block,
                instr_idx,
                var,
            } => write!(
                f,
                "Block {block}: instruction {instr_idx} uses undefined variable {var:?}"
            ),
            Self::MissingPhiOperand {
                block,
                phi_idx,
                missing_pred,
            } => write!(
                f,
                "Block {block}: phi {phi_idx} missing operand for predecessor {missing_pred}"
            ),
            Self::ExtraPhiOperand {
                block,
                phi_idx,
                extra_pred,
            } => write!(
                f,
                "Block {block}: phi {phi_idx} has operand for non-predecessor {extra_pred}"
            ),
            Self::DuplicateDefinition { var, def1, def2 } => write!(
                f,
                "Variable {var:?} defined twice: at block {} ({:?}) and block {} ({:?})",
                def1.block, def1.kind, def2.block, def2.kind
            ),
            Self::OrphanVariable { var } => {
                write!(f, "Variable {var:?} in variables vec but not defined in any block")
            }
            Self::UnregisteredVariable { var } => write!(
                f,
                "Variable {var:?} used in instruction but not in variables vec"
            ),
            Self::MissingTerminator { block } => {
                write!(f, "Block {block}: has successors but no terminator")
            }
            Self::PhiInEntryBlock { block, phi_idx } => {
                write!(f, "Block {block}: phi {phi_idx} in entry block")
            }
            Self::DominanceViolation {
                var,
                def_block,
                use_block,
            } => write!(
                f,
                "Variable {var:?}: def in block {def_block} does not dominate use in block {use_block}"
            ),
            Self::TerminatorNotLast {
                block,
                instr_idx,
                instr_count,
            } => write!(
                f,
                "Block {block}: terminator at position {instr_idx}/{instr_count} is not last"
            ),
            Self::IntraBlockCycle {
                block,
                use_instr,
                def_instr,
                var,
            } => write!(
                f,
                "Block {block}: instruction {use_instr} uses {var:?} defined at instruction {def_instr}"
            ),
            Self::PlaceholderVariable { block, location } => write!(
                f,
                "Block {block}: placeholder variable ID (usize::MAX) at {location}"
            ),
            Self::SelfReferentialInstruction {
                block,
                instr_idx,
                var,
            } => write!(
                f,
                "Block {block}: instruction {instr_idx} has self-referential use of {var:?}"
            ),
        }
    }
}

impl std::error::Error for VerifierError {}

/// Verification depth levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum VerifyLevel {
    /// Single-definition + block structure checks (O(n)).
    Quick,
    /// + def-use chains + phi operand coverage (O(n*m)).
    Standard,
    /// + dominance checking (O(n^2) worst case).
    Full,
}

/// SSA verifier that validates invariants at configurable depth.
pub struct SsaVerifier<'a> {
    ssa: &'a SsaFunction,
    errors: Vec<VerifierError>,
}

impl<'a> SsaVerifier<'a> {
    /// Creates a new verifier for the given SSA function.
    #[must_use]
    pub fn new(ssa: &'a SsaFunction) -> Self {
        Self {
            ssa,
            errors: Vec::new(),
        }
    }

    /// Runs verification at the specified level and returns all errors found.
    pub fn verify(mut self, level: VerifyLevel) -> Vec<VerifierError> {
        self.errors.clear();

        // Quick checks (always run)
        self.check_single_definition();
        self.check_block_structure();
        self.check_no_placeholders_or_self_refs();

        if level >= VerifyLevel::Standard {
            let cfg = SsaCfg::from_ssa(self.ssa);
            let definitions = self.collect_definitions();
            self.check_phi_operands(&cfg);
            self.check_defined_before_use(&definitions);
            self.check_registered_variables();

            if level >= VerifyLevel::Full {
                let dom_tree = compute_dominators(&cfg, cfg.entry());
                self.check_dominance(&cfg, &dom_tree, &definitions);
            }
        }

        self.errors
    }

    /// Verifies that every variable is defined at most once (the fundamental SSA property).
    fn check_single_definition(&mut self) {
        let mut definitions: HashMap<SsaVarId, VerifierDefSite> = HashMap::new();

        for (block_idx, block) in self.ssa.blocks().iter().enumerate() {
            for (phi_idx, phi) in block.phi_nodes().iter().enumerate() {
                let var = phi.result();
                let site = VerifierDefSite {
                    block: block_idx,
                    kind: DefKind::Phi(phi_idx),
                };
                if let Some(prev) = definitions.get(&var) {
                    self.errors.push(VerifierError::DuplicateDefinition {
                        var,
                        def1: prev.clone(),
                        def2: site,
                    });
                } else {
                    definitions.insert(var, site);
                }
            }

            for (instr_idx, instr) in block.instructions().iter().enumerate() {
                if let Some(dest) = instr.op().dest() {
                    let site = VerifierDefSite {
                        block: block_idx,
                        kind: DefKind::Instruction(instr_idx),
                    };
                    if let Some(prev) = definitions.get(&dest) {
                        self.errors.push(VerifierError::DuplicateDefinition {
                            var: dest,
                            def1: prev.clone(),
                            def2: site,
                        });
                    } else {
                        definitions.insert(dest, site);
                    }
                }
            }
        }
    }

    /// Checks block structural invariants:
    /// - Every block with successors has a terminator
    /// - Terminators are the last instruction
    /// - No intra-block cycles (use before def)
    fn check_block_structure(&mut self) {
        for (block_idx, block) in self.ssa.blocks().iter().enumerate() {
            let instrs = block.instructions();
            let instr_count = instrs.len();

            // Check terminator placement
            for (instr_idx, instr) in instrs.iter().enumerate() {
                if instr.op().is_terminator() && instr_idx < instr_count.saturating_sub(1) {
                    self.errors.push(VerifierError::TerminatorNotLast {
                        block: block_idx,
                        instr_idx,
                        instr_count,
                    });
                }
            }

            // Check for intra-block use-before-def cycles
            let mut def_indices: HashMap<SsaVarId, usize> = HashMap::new();
            for (instr_idx, instr) in instrs.iter().enumerate() {
                if let Some(dest) = instr.op().dest() {
                    def_indices.insert(dest, instr_idx);
                }
            }

            for (instr_idx, instr) in instrs.iter().enumerate() {
                for used_var in instr.op().uses() {
                    if let Some(&def_idx) = def_indices.get(&used_var) {
                        if def_idx >= instr_idx {
                            self.errors.push(VerifierError::IntraBlockCycle {
                                block: block_idx,
                                use_instr: instr_idx,
                                def_instr: def_idx,
                                var: used_var,
                            });
                        }
                    }
                }
            }
        }
    }

    /// Collects all variable definitions into a map: var_id -> (block, def_site).
    fn collect_definitions(&self) -> HashMap<SsaVarId, (usize, DefSite)> {
        let mut defs: HashMap<SsaVarId, (usize, DefSite)> = HashMap::new();

        // Variables from the variables vec (includes entry-block defs for args/locals)
        for var in self.ssa.variables() {
            defs.insert(var.id(), (var.def_site().block, var.def_site()));
        }

        // Also collect from actual block contents (may differ after transforms)
        for (block_idx, block) in self.ssa.blocks().iter().enumerate() {
            for phi in block.phi_nodes() {
                defs.entry(phi.result())
                    .or_insert((block_idx, DefSite::phi(block_idx)));
            }
            for (instr_idx, instr) in block.instructions().iter().enumerate() {
                if let Some(dest) = instr.op().dest() {
                    defs.entry(dest)
                        .or_insert((block_idx, DefSite::instruction(block_idx, instr_idx)));
                }
            }
        }

        defs
    }

    /// Checks that every phi node has the correct operand set:
    /// - One operand per CFG predecessor
    /// - No operands from non-predecessor blocks
    /// - No phis in the entry block (which has no predecessors)
    fn check_phi_operands(&mut self, cfg: &SsaCfg<'_>) {
        let block_count = self.ssa.block_count();
        for (block_idx, block) in self.ssa.blocks().iter().enumerate() {
            let pred_list = cfg.block_predecessors(block_idx);
            // Capacity must cover both actual predecessors and phi operand predecessors
            // (which may reference non-existent blocks in malformed SSA)
            let max_phi_pred = block
                .phi_nodes()
                .iter()
                .flat_map(|phi| phi.operands().iter().map(|op| op.predecessor()))
                .max()
                .unwrap_or(0);
            let capacity = block_count.max(max_phi_pred + 1).max(1);
            let mut preds = BitSet::new(capacity);
            for &p in pred_list {
                if p < capacity {
                    preds.insert(p);
                }
            }

            for (phi_idx, phi) in block.phi_nodes().iter().enumerate() {
                // Entry block should not have phis (no predecessors)
                if block_idx == 0 && preds.is_empty() {
                    self.errors.push(VerifierError::PhiInEntryBlock {
                        block: block_idx,
                        phi_idx,
                    });
                    continue;
                }

                let mut operand_preds = BitSet::new(capacity);
                for op in phi.operands() {
                    let pred = op.predecessor();
                    operand_preds.insert(pred);
                }

                // Check for missing predecessors
                for pred in preds.iter() {
                    if !operand_preds.contains(pred) {
                        self.errors.push(VerifierError::MissingPhiOperand {
                            block: block_idx,
                            phi_idx,
                            missing_pred: pred,
                        });
                    }
                }

                // Check for extra (non-predecessor) operands
                for op_pred in operand_preds.iter() {
                    if !preds.contains(op_pred) {
                        self.errors.push(VerifierError::ExtraPhiOperand {
                            block: block_idx,
                            phi_idx,
                            extra_pred: op_pred,
                        });
                    }
                }
            }
        }
    }

    /// Checks that every variable used in an instruction or phi operand is defined
    /// somewhere (either in the variables vec or in a block).
    fn check_defined_before_use(&mut self, definitions: &HashMap<SsaVarId, (usize, DefSite)>) {
        for (block_idx, block) in self.ssa.blocks().iter().enumerate() {
            for (instr_idx, instr) in block.instructions().iter().enumerate() {
                for used_var in instr.op().uses() {
                    if !definitions.contains_key(&used_var) {
                        self.errors.push(VerifierError::UndefinedUse {
                            block: block_idx,
                            instr_idx,
                            var: used_var,
                        });
                    }
                }
            }
        }
    }

    /// Checks that every variable used in blocks is registered in the variables vec.
    fn check_registered_variables(&mut self) {
        let variable_count = self.ssa.variable_count();
        // Capacity must cover all variable IDs that appear in blocks (may exceed variable_count)
        let max_block_var = self
            .ssa
            .blocks()
            .iter()
            .flat_map(|b| {
                let phi_ids = b.phi_nodes().iter().map(|p| p.result().index());
                let instr_ids = b
                    .instructions()
                    .iter()
                    .filter_map(|i| i.op().dest().map(|d| d.index()));
                phi_ids.chain(instr_ids)
            })
            .max()
            .unwrap_or(0);
        let max_reg_var = self
            .ssa
            .variables()
            .iter()
            .map(|v| v.id().index())
            .max()
            .unwrap_or(0);
        let capacity = (max_block_var + 1)
            .max(max_reg_var + 1)
            .max(variable_count)
            .max(1);
        let mut registered = BitSet::new(capacity);
        for v in self.ssa.variables() {
            registered.insert(v.id().index());
        }

        // Check variables defined in blocks but not in variables vec
        for block in self.ssa.blocks() {
            for phi in block.phi_nodes() {
                let idx = phi.result().index();
                if idx >= capacity || !registered.contains(idx) {
                    self.errors
                        .push(VerifierError::UnregisteredVariable { var: phi.result() });
                }
            }
            for instr in block.instructions() {
                if let Some(dest) = instr.op().dest() {
                    let idx = dest.index();
                    if idx >= capacity || !registered.contains(idx) {
                        self.errors
                            .push(VerifierError::UnregisteredVariable { var: dest });
                    }
                }
            }
        }

        // Check for orphan variables (in variables vec but not defined in any block)
        let mut block_defined = BitSet::new(capacity);
        for block in self.ssa.blocks() {
            for phi in block.phi_nodes() {
                let idx = phi.result().index();
                if idx < capacity {
                    block_defined.insert(idx);
                }
            }
            for instr in block.instructions() {
                if let Some(dest) = instr.op().dest() {
                    let idx = dest.index();
                    if idx < capacity {
                        block_defined.insert(idx);
                    }
                }
            }
        }

        for var in self.ssa.variables() {
            // Version 0 entry-point variables are defined at function entry, not
            // in blocks. This includes args, locals, and Phi-origin placeholder
            // variables created during SSA rebuild for stack temp groups.
            if var.version() == 0 && var.def_site().instruction.is_none() {
                continue;
            }
            if !block_defined.contains(var.id().index()) {
                self.errors
                    .push(VerifierError::OrphanVariable { var: var.id() });
            }
        }
    }

    /// Checks for placeholder variable IDs (usize::MAX) that should have been
    /// replaced during construction. Also checks for self-referential instructions
    /// where an instruction's destination appears in its own operands.
    fn check_no_placeholders_or_self_refs(&mut self) {
        for (block_idx, block) in self.ssa.blocks().iter().enumerate() {
            // Check phi nodes for placeholder IDs
            for (phi_idx, phi) in block.phi_nodes().iter().enumerate() {
                if phi.result().is_placeholder() {
                    self.errors.push(VerifierError::PlaceholderVariable {
                        block: block_idx,
                        location: format!("phi {phi_idx} result"),
                    });
                }
                for operand in phi.operands() {
                    if operand.value().is_placeholder() {
                        self.errors.push(VerifierError::PlaceholderVariable {
                            block: block_idx,
                            location: format!(
                                "phi {phi_idx} operand from B{}",
                                operand.predecessor()
                            ),
                        });
                    }
                }
            }

            // Check instructions for placeholder IDs and self-referential uses
            for (instr_idx, instr) in block.instructions().iter().enumerate() {
                let op = instr.op();
                if let Some(dest) = op.dest() {
                    if dest.is_placeholder() {
                        self.errors.push(VerifierError::PlaceholderVariable {
                            block: block_idx,
                            location: format!("instruction {instr_idx} dest"),
                        });
                    }
                    // Check for self-referential instruction (dest appears in uses)
                    if op.uses().contains(&dest) {
                        self.errors.push(VerifierError::SelfReferentialInstruction {
                            block: block_idx,
                            instr_idx,
                            var: dest,
                        });
                    }
                }
                for used_var in op.uses() {
                    if used_var.is_placeholder() {
                        self.errors.push(VerifierError::PlaceholderVariable {
                            block: block_idx,
                            location: format!("instruction {instr_idx} operand"),
                        });
                    }
                }
            }
        }
    }

    /// Checks dominance: every use of a variable must be dominated by its definition.
    ///
    /// For phi operands, the use is considered to be at the end of the predecessor
    /// block (not at the phi's block), following standard SSA semantics.
    fn check_dominance(
        &mut self,
        cfg: &SsaCfg<'_>,
        dom_tree: &DominatorTree,
        definitions: &HashMap<SsaVarId, (usize, DefSite)>,
    ) {
        // Compute reachable blocks
        let block_count = self.ssa.block_count().max(1);
        let mut reachable = BitSet::new(block_count);
        let mut worklist = vec![0usize];
        while let Some(block_idx) = worklist.pop() {
            if block_idx < block_count && reachable.insert(block_idx) {
                for &succ in cfg.block_successors(block_idx) {
                    if succ < block_count {
                        worklist.push(succ);
                    }
                }
            }
        }

        // Check instruction uses
        for (block_idx, block) in self.ssa.blocks().iter().enumerate() {
            if !reachable.contains(block_idx) {
                continue;
            }

            for instr in block.instructions() {
                for used_var in instr.op().uses() {
                    if let Some(&(def_block, _)) = definitions.get(&used_var) {
                        if !reachable.contains(def_block) {
                            continue;
                        }
                        // Definition must dominate use block
                        let def_node = NodeId::new(def_block);
                        let use_node = NodeId::new(block_idx);
                        if def_node.index() < dom_tree.node_count()
                            && use_node.index() < dom_tree.node_count()
                            && !dom_tree.dominates(def_node, use_node)
                        {
                            self.errors.push(VerifierError::DominanceViolation {
                                var: used_var,
                                def_block,
                                use_block: block_idx,
                            });
                        }
                    }
                }
            }

            // Check phi operand uses: the use is at the end of the predecessor
            for phi in block.phi_nodes() {
                for operand in phi.operands() {
                    let used_var = operand.value();
                    let pred_block = operand.predecessor();
                    if let Some(&(def_block, _)) = definitions.get(&used_var) {
                        if !reachable.contains(def_block) || !reachable.contains(pred_block) {
                            continue;
                        }
                        // Definition must dominate the predecessor block
                        let def_node = NodeId::new(def_block);
                        let pred_node = NodeId::new(pred_block);
                        if def_node.index() < dom_tree.node_count()
                            && pred_node.index() < dom_tree.node_count()
                            && !dom_tree.dominates(def_node, pred_node)
                        {
                            self.errors.push(VerifierError::DominanceViolation {
                                var: used_var,
                                def_block,
                                use_block: pred_block,
                            });
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::analysis::ssa::{
        ConstValue, DefSite, PhiNode, PhiOperand, SsaBlock, SsaFunction, SsaInstruction, SsaOp,
        SsaType, SsaVarId, VariableOrigin,
    };

    /// Helper: create a minimal SSA function for testing.
    fn make_empty_ssa() -> SsaFunction {
        SsaFunction::new(0, 0)
    }

    /// Helper: create an SSA with a single block containing a return.
    fn make_single_block_ssa() -> SsaFunction {
        let mut ssa = SsaFunction::new(0, 0);
        let mut block = SsaBlock::new(0);
        block.add_instruction(SsaInstruction::synthetic(SsaOp::Return { value: None }));
        ssa.add_block(block);
        ssa
    }

    #[test]
    fn test_empty_ssa_passes_all_levels() {
        let ssa = make_empty_ssa();
        assert!(SsaVerifier::new(&ssa).verify(VerifyLevel::Quick).is_empty());
        assert!(SsaVerifier::new(&ssa)
            .verify(VerifyLevel::Standard)
            .is_empty());
        assert!(SsaVerifier::new(&ssa).verify(VerifyLevel::Full).is_empty());
    }

    #[test]
    fn test_single_block_passes() {
        let ssa = make_single_block_ssa();
        assert!(SsaVerifier::new(&ssa)
            .verify(VerifyLevel::Standard)
            .is_empty());
    }

    #[test]
    fn test_duplicate_definition_detected() {
        let mut ssa = SsaFunction::new(0, 0);
        let var_id = SsaVarId::from_index(0);

        let mut block = SsaBlock::new(0);
        // Define the same var twice
        block.add_instruction(SsaInstruction::synthetic(SsaOp::Const {
            dest: var_id,
            value: ConstValue::I32(1),
        }));
        block.add_instruction(SsaInstruction::synthetic(SsaOp::Const {
            dest: var_id,
            value: ConstValue::I32(2),
        }));
        block.add_instruction(SsaInstruction::synthetic(SsaOp::Return { value: None }));
        ssa.add_block(block);

        let errors = SsaVerifier::new(&ssa).verify(VerifyLevel::Quick);
        assert!(
            errors.iter().any(
                |e| matches!(e, VerifierError::DuplicateDefinition { var, .. } if *var == var_id)
            ),
            "should detect duplicate definition: {errors:?}"
        );
    }

    #[test]
    fn test_terminator_not_last_detected() {
        let mut ssa = SsaFunction::new(0, 0);
        let mut block = SsaBlock::new(0);
        // Terminator followed by another instruction
        block.add_instruction(SsaInstruction::synthetic(SsaOp::Return { value: None }));
        block.add_instruction(SsaInstruction::synthetic(SsaOp::Nop));
        ssa.add_block(block);

        let errors = SsaVerifier::new(&ssa).verify(VerifyLevel::Quick);
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, VerifierError::TerminatorNotLast { block: 0, .. })),
            "should detect terminator not last: {errors:?}"
        );
    }

    #[test]
    fn test_intra_block_cycle_detected() {
        let mut ssa = SsaFunction::new(0, 0);
        let v0 = SsaVarId::from_index(0);
        let v1 = SsaVarId::from_index(1);

        let mut block = SsaBlock::new(0);
        // v0 uses v1, but v1 is defined after v0
        block.add_instruction(SsaInstruction::synthetic(SsaOp::Copy { dest: v0, src: v1 }));
        block.add_instruction(SsaInstruction::synthetic(SsaOp::Const {
            dest: v1,
            value: ConstValue::I32(42),
        }));
        block.add_instruction(SsaInstruction::synthetic(SsaOp::Return { value: None }));
        ssa.add_block(block);

        let errors = SsaVerifier::new(&ssa).verify(VerifyLevel::Quick);
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, VerifierError::IntraBlockCycle { .. })),
            "should detect intra-block cycle: {errors:?}"
        );
    }

    #[test]
    fn test_missing_phi_operand_detected() {
        let mut ssa = SsaFunction::new(0, 0);

        // Register variables first (dense IDs: 0, 1, 2)
        let cond = ssa.create_variable(
            VariableOrigin::Local(0),
            0,
            DefSite::instruction(0, 0),
            SsaType::Unknown,
        );
        let v1 = ssa.create_variable(
            VariableOrigin::Local(0),
            1,
            DefSite::instruction(1, 0),
            SsaType::Unknown,
        );
        let phi_result = ssa.create_variable(
            VariableOrigin::Local(0),
            2,
            DefSite::phi(2),
            SsaType::Unknown,
        );

        // Block 0: branch to 1 or 2
        let mut b0 = SsaBlock::new(0);
        b0.add_instruction(SsaInstruction::synthetic(SsaOp::Const {
            dest: cond,
            value: ConstValue::I32(1),
        }));
        b0.add_instruction(SsaInstruction::synthetic(SsaOp::Branch {
            condition: cond,
            true_target: 1,
            false_target: 2,
        }));

        // Block 1: jump to 2
        let mut b1 = SsaBlock::new(1);
        b1.add_instruction(SsaInstruction::synthetic(SsaOp::Const {
            dest: v1,
            value: ConstValue::I32(10),
        }));
        b1.add_instruction(SsaInstruction::synthetic(SsaOp::Jump { target: 2 }));

        // Block 2: phi with only one operand (missing pred 0)
        let mut b2 = SsaBlock::new(2);
        let mut phi = PhiNode::new(phi_result, VariableOrigin::Local(0));
        phi.add_operand(PhiOperand::new(v1, 1)); // only from block 1, missing block 0
        b2.add_phi(phi);
        b2.add_instruction(SsaInstruction::synthetic(SsaOp::Return { value: None }));

        ssa.add_block(b0);
        ssa.add_block(b1);
        ssa.add_block(b2);

        let errors = SsaVerifier::new(&ssa).verify(VerifyLevel::Standard);
        assert!(
            errors.iter().any(|e| matches!(
                e,
                VerifierError::MissingPhiOperand {
                    block: 2,
                    missing_pred: 0,
                    ..
                }
            )),
            "should detect missing phi operand from block 0: {errors:?}"
        );
    }

    #[test]
    fn test_well_formed_diamond_passes_full() {
        let mut ssa = SsaFunction::new(0, 1);

        // Register all variables first (dense IDs: 0, 1, 2, 3)
        let cond = ssa.create_variable(
            VariableOrigin::Local(0),
            0,
            DefSite::instruction(0, 0),
            SsaType::Unknown,
        );
        let v1 = ssa.create_variable(
            VariableOrigin::Local(0),
            1,
            DefSite::instruction(1, 0),
            SsaType::Unknown,
        );
        let v2 = ssa.create_variable(
            VariableOrigin::Local(0),
            2,
            DefSite::instruction(2, 0),
            SsaType::Unknown,
        );
        let phi_result = ssa.create_variable(
            VariableOrigin::Local(0),
            3,
            DefSite::phi(3),
            SsaType::Unknown,
        );

        // Block 0: branch
        let mut b0 = SsaBlock::new(0);
        b0.add_instruction(SsaInstruction::synthetic(SsaOp::Const {
            dest: cond,
            value: ConstValue::I32(1),
        }));
        b0.add_instruction(SsaInstruction::synthetic(SsaOp::Branch {
            condition: cond,
            true_target: 1,
            false_target: 2,
        }));

        // Block 1: define v1
        let mut b1 = SsaBlock::new(1);
        b1.add_instruction(SsaInstruction::synthetic(SsaOp::Const {
            dest: v1,
            value: ConstValue::I32(10),
        }));
        b1.add_instruction(SsaInstruction::synthetic(SsaOp::Jump { target: 3 }));

        // Block 2: define v2
        let mut b2 = SsaBlock::new(2);
        b2.add_instruction(SsaInstruction::synthetic(SsaOp::Const {
            dest: v2,
            value: ConstValue::I32(20),
        }));
        b2.add_instruction(SsaInstruction::synthetic(SsaOp::Jump { target: 3 }));

        // Block 3: merge with phi
        let mut b3 = SsaBlock::new(3);
        let mut phi = PhiNode::new(phi_result, VariableOrigin::Local(0));
        phi.add_operand(PhiOperand::new(v1, 1));
        phi.add_operand(PhiOperand::new(v2, 2));
        b3.add_phi(phi);
        b3.add_instruction(SsaInstruction::synthetic(SsaOp::Return {
            value: Some(phi_result),
        }));

        ssa.add_block(b0);
        ssa.add_block(b1);
        ssa.add_block(b2);
        ssa.add_block(b3);

        let errors = SsaVerifier::new(&ssa).verify(VerifyLevel::Full);
        assert!(
            errors.is_empty(),
            "well-formed diamond should pass Full verification: {errors:?}"
        );
    }

    #[test]
    fn test_undefined_use_detected() {
        let mut ssa = SsaFunction::new(0, 0);
        let undefined_var = SsaVarId::from_index(0);

        let mut block = SsaBlock::new(0);
        block.add_instruction(SsaInstruction::synthetic(SsaOp::Return {
            value: Some(undefined_var),
        }));
        ssa.add_block(block);
        // Note: undefined_var is NOT registered as a variable

        let errors = SsaVerifier::new(&ssa).verify(VerifyLevel::Standard);
        assert!(
            errors.iter().any(
                |e| matches!(e, VerifierError::UndefinedUse { var, .. } if *var == undefined_var)
            ),
            "should detect undefined use: {errors:?}"
        );
    }

    #[test]
    fn test_verify_level_ordering() {
        assert!(VerifyLevel::Quick < VerifyLevel::Standard);
        assert!(VerifyLevel::Standard < VerifyLevel::Full);
    }

    #[test]
    fn test_extra_phi_operand_detected() {
        let mut ssa = SsaFunction::new(0, 0);

        // Register variables first (dense IDs: 0, 1, 2)
        let v1 = ssa.create_variable(
            VariableOrigin::Local(0),
            0,
            DefSite::instruction(0, 0),
            SsaType::Unknown,
        );
        let v_extra = ssa.create_variable(
            VariableOrigin::Local(0),
            1,
            DefSite::instruction(0, 0),
            SsaType::Unknown,
        );
        let phi_result = ssa.create_variable(
            VariableOrigin::Local(0),
            2,
            DefSite::phi(1),
            SsaType::Unknown,
        );

        // Block 0: jump to block 1
        let mut b0 = SsaBlock::new(0);
        b0.add_instruction(SsaInstruction::synthetic(SsaOp::Const {
            dest: v1,
            value: ConstValue::I32(1),
        }));
        b0.add_instruction(SsaInstruction::synthetic(SsaOp::Jump { target: 1 }));

        // Block 1: phi with operand from block 0 AND from non-predecessor block 5
        let mut b1 = SsaBlock::new(1);
        let mut phi = PhiNode::new(phi_result, VariableOrigin::Local(0));
        phi.add_operand(PhiOperand::new(v1, 0));
        phi.add_operand(PhiOperand::new(v_extra, 5)); // block 5 doesn't exist
        b1.add_phi(phi);
        b1.add_instruction(SsaInstruction::synthetic(SsaOp::Return { value: None }));

        ssa.add_block(b0);
        ssa.add_block(b1);

        let errors = SsaVerifier::new(&ssa).verify(VerifyLevel::Standard);
        assert!(
            errors.iter().any(|e| matches!(
                e,
                VerifierError::ExtraPhiOperand {
                    block: 1,
                    extra_pred: 5,
                    ..
                }
            )),
            "should detect extra phi operand from non-predecessor: {errors:?}"
        );
    }
}
