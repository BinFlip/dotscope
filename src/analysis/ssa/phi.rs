//! Phi node representation for SSA form.
//!
//! Phi nodes are the cornerstone of SSA form - they represent the merging of
//! values at control flow join points. When multiple control flow paths converge,
//! a phi node selects which value to use based on which path was taken.
//!
//! # Semantics
//!
//! A phi node `v3 = phi(v1 from B1, v2 from B2)` means:
//! - If control came from block B1, use value v1
//! - If control came from block B2, use value v2
//!
//! Phi nodes are not real instructions - they are evaluated "instantaneously"
//! at the entry of a basic block, before any real instructions execute.
//!
//! # Placement
//!
//! Phi nodes are placed at dominance frontiers during SSA construction.
//! A block B needs a phi node for variable V if:
//! 1. B is in the dominance frontier of some block that defines V
//! 2. V is live at the entry of B
//!
//! # Thread Safety
//!
//! All types in this module are `Send` and `Sync`.

use std::fmt;

use crate::analysis::ssa::{SsaVarId, VariableOrigin};

/// An operand of a phi node - a value coming from a specific predecessor block.
///
/// Each phi operand represents one possible value that could be selected,
/// associated with the predecessor block from which that value comes.
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::analysis::{PhiOperand, SsaVarId};
///
/// // Value coming from block 1
/// let var = SsaVarId::new();
/// let operand = PhiOperand::new(var, 1);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PhiOperand {
    /// The SSA variable providing the value.
    value: SsaVarId,
    /// The predecessor block from which this value comes.
    predecessor: usize,
}

impl PhiOperand {
    /// Creates a new phi operand.
    ///
    /// # Arguments
    ///
    /// * `value` - The SSA variable providing the value
    /// * `predecessor` - The block index from which this value comes
    #[must_use]
    pub const fn new(value: SsaVarId, predecessor: usize) -> Self {
        Self { value, predecessor }
    }

    /// Returns the SSA variable providing the value.
    #[must_use]
    pub const fn value(&self) -> SsaVarId {
        self.value
    }

    /// Returns the predecessor block index.
    #[must_use]
    pub const fn predecessor(&self) -> usize {
        self.predecessor
    }
}

impl fmt::Display for PhiOperand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} from B{}", self.value, self.predecessor)
    }
}

/// A phi node that merges values at a control flow join point.
///
/// Phi nodes are placed at the beginning of basic blocks where control flow
/// from multiple predecessors converges. They select which value to use based
/// on which predecessor block was executed.
///
/// # Invariants
///
/// - Each phi node has exactly one operand for each predecessor of its block
/// - All operands must have the same type (enforced by SSA construction)
/// - The result variable is defined by this phi node
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::analysis::{PhiNode, PhiOperand, SsaVarId, VariableOrigin};
///
/// // Create phi: result = phi(v1 from B1, v2 from B2)
/// let v1 = SsaVarId::new();
/// let v2 = SsaVarId::new();
/// let result = SsaVarId::new();
/// let mut phi = PhiNode::new(result, VariableOrigin::Local(0));
/// phi.add_operand(PhiOperand::new(v1, 1));
/// phi.add_operand(PhiOperand::new(v2, 2));
/// ```
#[derive(Debug, Clone)]
pub struct PhiNode {
    /// The SSA variable defined by this phi node.
    result: SsaVarId,
    /// The original variable this phi merges (Argument or Local index).
    origin: VariableOrigin,
    /// Operands from each predecessor block.
    operands: Vec<PhiOperand>,
}

impl PhiNode {
    /// Creates a new phi node for the given variable origin.
    ///
    /// The phi node is created with no operands - they must be added
    /// during SSA construction as predecessor blocks are processed.
    ///
    /// # Arguments
    ///
    /// * `result` - The SSA variable that this phi node defines
    /// * `origin` - The original variable (Argument or Local) this phi merges
    #[must_use]
    pub fn new(result: SsaVarId, origin: VariableOrigin) -> Self {
        Self {
            result,
            origin,
            operands: Vec::new(),
        }
    }

    /// Creates a new phi node with pre-allocated operand capacity.
    ///
    /// Use this when the number of predecessors is known in advance
    /// to avoid reallocations.
    ///
    /// # Arguments
    ///
    /// * `result` - The SSA variable that this phi node defines
    /// * `origin` - The original variable this phi merges
    /// * `predecessor_count` - Expected number of predecessor blocks
    #[must_use]
    pub fn with_capacity(
        result: SsaVarId,
        origin: VariableOrigin,
        predecessor_count: usize,
    ) -> Self {
        Self {
            result,
            origin,
            operands: Vec::with_capacity(predecessor_count),
        }
    }

    /// Returns the SSA variable defined by this phi node.
    #[must_use]
    pub const fn result(&self) -> SsaVarId {
        self.result
    }

    /// Returns the original variable origin this phi merges.
    #[must_use]
    pub const fn origin(&self) -> VariableOrigin {
        self.origin
    }

    /// Sets the SSA variable defined by this phi node.
    ///
    /// Used during SSA construction when renaming variables.
    pub fn set_result(&mut self, var: SsaVarId) {
        self.result = var;
    }

    /// Returns the operands of this phi node.
    #[must_use]
    pub fn operands(&self) -> &[PhiOperand] {
        &self.operands
    }

    /// Returns a mutable reference to the operands.
    pub fn operands_mut(&mut self) -> &mut Vec<PhiOperand> {
        &mut self.operands
    }

    /// Adds an operand to this phi node.
    ///
    /// # Arguments
    ///
    /// * `operand` - The phi operand to add
    pub fn add_operand(&mut self, operand: PhiOperand) {
        self.operands.push(operand);
    }

    /// Returns the number of operands.
    #[must_use]
    pub fn operand_count(&self) -> usize {
        self.operands.len()
    }

    /// Returns `true` if this phi node has no operands.
    ///
    /// A phi node with no operands is incomplete and should not appear
    /// in a fully-constructed SSA form.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.operands.is_empty()
    }

    /// Finds the operand coming from the specified predecessor block.
    ///
    /// # Arguments
    ///
    /// * `predecessor` - The block index to look up
    ///
    /// # Returns
    ///
    /// The phi operand if found, or `None` if no operand comes from that predecessor.
    #[must_use]
    pub fn operand_from(&self, predecessor: usize) -> Option<&PhiOperand> {
        self.operands
            .iter()
            .find(|op| op.predecessor == predecessor)
    }

    /// Returns all the SSA variables used by this phi node.
    ///
    /// This is useful for building def-use chains and liveness analysis.
    pub fn used_variables(&self) -> impl Iterator<Item = SsaVarId> + '_ {
        self.operands.iter().map(|op| op.value)
    }

    /// Sets the origin of this phi node.
    ///
    /// This is used during local variable optimization to update indices
    /// after unused locals are removed.
    pub fn set_origin(&mut self, origin: VariableOrigin) {
        self.origin = origin;
    }

    /// Sets the operand value for a specific predecessor.
    ///
    /// If an operand from that predecessor already exists, it is updated.
    /// Otherwise, a new operand is added.
    ///
    /// # Arguments
    ///
    /// * `predecessor` - The predecessor block index
    /// * `value` - The SSA variable value from that predecessor
    pub fn set_operand(&mut self, predecessor: usize, value: SsaVarId) {
        if let Some(existing) = self
            .operands
            .iter_mut()
            .find(|op| op.predecessor == predecessor)
        {
            existing.value = value;
        } else {
            self.operands.push(PhiOperand::new(value, predecessor));
        }
    }
}

impl fmt::Display for PhiNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} = phi(", self.result)?;
        for (i, operand) in self.operands.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{operand}")?;
        }
        write!(f, ")")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_phi_operand_creation() {
        let v = SsaVarId::new();
        let operand = PhiOperand::new(v, 2);
        assert_eq!(operand.value(), v);
        assert_eq!(operand.predecessor(), 2);
    }

    #[test]
    fn test_phi_operand_display() {
        let operand = PhiOperand::new(SsaVarId::from_index(3), 1);
        assert_eq!(format!("{operand}"), "v3 from B1");
    }

    #[test]
    fn test_phi_node_creation() {
        let result = SsaVarId::new();
        let phi = PhiNode::new(result, VariableOrigin::Local(0));
        assert_eq!(phi.result(), result);
        assert_eq!(phi.origin(), VariableOrigin::Local(0));
        assert!(phi.is_empty());
        assert_eq!(phi.operand_count(), 0);
    }

    #[test]
    fn test_phi_node_with_capacity() {
        let result = SsaVarId::new();
        let phi = PhiNode::with_capacity(result, VariableOrigin::Argument(1), 3);
        assert_eq!(phi.result(), result);
        assert_eq!(phi.origin(), VariableOrigin::Argument(1));
        assert!(phi.is_empty());
    }

    #[test]
    fn test_phi_node_add_operands() {
        let result = SsaVarId::new();
        let v1 = SsaVarId::new();
        let v2 = SsaVarId::new();
        let mut phi = PhiNode::new(result, VariableOrigin::Local(0));

        phi.add_operand(PhiOperand::new(v1, 0));
        phi.add_operand(PhiOperand::new(v2, 1));

        assert!(!phi.is_empty());
        assert_eq!(phi.operand_count(), 2);

        let ops = phi.operands();
        assert_eq!(ops[0].value(), v1);
        assert_eq!(ops[0].predecessor(), 0);
        assert_eq!(ops[1].value(), v2);
        assert_eq!(ops[1].predecessor(), 1);
    }

    #[test]
    fn test_phi_node_operand_from() {
        let result = SsaVarId::new();
        let v1 = SsaVarId::new();
        let v3 = SsaVarId::new();
        let mut phi = PhiNode::new(result, VariableOrigin::Local(0));
        phi.add_operand(PhiOperand::new(v1, 2));
        phi.add_operand(PhiOperand::new(v3, 4));

        assert!(phi.operand_from(2).is_some());
        assert_eq!(phi.operand_from(2).unwrap().value(), v1);

        assert!(phi.operand_from(4).is_some());
        assert_eq!(phi.operand_from(4).unwrap().value(), v3);

        assert!(phi.operand_from(0).is_none());
        assert!(phi.operand_from(99).is_none());
    }

    #[test]
    fn test_phi_node_set_operand_new() {
        let result = SsaVarId::new();
        let v10 = SsaVarId::new();
        let mut phi = PhiNode::new(result, VariableOrigin::Local(0));

        phi.set_operand(1, v10);
        assert_eq!(phi.operand_count(), 1);
        assert_eq!(phi.operand_from(1).unwrap().value(), v10);
    }

    #[test]
    fn test_phi_node_set_operand_update() {
        let result = SsaVarId::new();
        let v10 = SsaVarId::new();
        let v20 = SsaVarId::new();
        let mut phi = PhiNode::new(result, VariableOrigin::Local(0));

        phi.set_operand(1, v10);
        phi.set_operand(1, v20); // Update existing

        assert_eq!(phi.operand_count(), 1);
        assert_eq!(phi.operand_from(1).unwrap().value(), v20);
    }

    #[test]
    fn test_phi_node_used_variables() {
        let result = SsaVarId::new();
        let v1 = SsaVarId::new();
        let v2 = SsaVarId::new();
        let v3 = SsaVarId::new();
        let mut phi = PhiNode::new(result, VariableOrigin::Local(0));
        phi.add_operand(PhiOperand::new(v1, 0));
        phi.add_operand(PhiOperand::new(v2, 1));
        phi.add_operand(PhiOperand::new(v3, 2));

        let used: Vec<_> = phi.used_variables().collect();
        assert_eq!(used.len(), 3);
        assert!(used.contains(&v1));
        assert!(used.contains(&v2));
        assert!(used.contains(&v3));
    }

    #[test]
    fn test_phi_node_display() {
        let mut phi = PhiNode::new(SsaVarId::from_index(5), VariableOrigin::Local(0));
        phi.add_operand(PhiOperand::new(SsaVarId::from_index(1), 0));
        phi.add_operand(PhiOperand::new(SsaVarId::from_index(2), 1));

        let display = format!("{phi}");
        assert_eq!(display, "v5 = phi(v1 from B0, v2 from B1)");
    }

    #[test]
    fn test_phi_node_display_empty() {
        let phi = PhiNode::new(SsaVarId::from_index(3), VariableOrigin::Local(0));
        assert_eq!(format!("{phi}"), "v3 = phi()");
    }

    #[test]
    fn test_phi_node_display_single_operand() {
        let mut phi = PhiNode::new(SsaVarId::from_index(7), VariableOrigin::Local(0));
        phi.add_operand(PhiOperand::new(SsaVarId::from_index(4), 2));
        assert_eq!(format!("{phi}"), "v7 = phi(v4 from B2)");
    }
}
