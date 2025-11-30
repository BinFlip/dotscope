//! Live variable analysis.
//!
//! A variable is *live* at a program point if there exists a path from that
//! point to a use of the variable that doesn't pass through a definition of
//! the variable. In SSA form, since each variable is defined exactly once,
//! this simplifies to: a variable is live if it will be used on some path
//! from this point.
//!
//! # Uses
//!
//! Live variable analysis is essential for:
//! - **Dead code elimination**: If a definition's result is never live, it's dead
//! - **Register allocation**: Variables live at the same time need different registers
//! - **Debugging**: Determine which variables can be inspected at a breakpoint
//!
//! # Algorithm
//!
//! This is a backward data flow analysis:
//!
//! - `USE[B]` = variables used in B before any definition
//! - `DEF[B]` = variables defined in B
//! - `OUT[B]` = ∪{IN[S] | S is a successor of B}
//! - `IN[B]` = USE[B] ∪ (OUT[B] - DEF[B])
//!
//! In SSA form, DEF[B] kills only the variables defined in B (which have
//! unique definitions anyway), so the analysis tracks which uses are live.

use crate::{
    analysis::{
        dataflow::{
            framework::{DataFlowAnalysis, Direction},
            lattice::MeetSemiLattice,
        },
        SsaBlock, SsaFunction, SsaVarId,
    },
    utils::BitSet,
};

/// Live variable analysis.
///
/// Computes which variables are live at each program point.
/// A variable is live if its value may be used on some path from
/// that point forward.
///
/// # Example
///
/// ```rust,ignore
/// use dotscope::analysis::dataflow::{LiveVariables, DataFlowSolver};
///
/// let analysis = LiveVariables::new(&ssa);
/// let mut solver = DataFlowSolver::new(analysis);
/// let results = solver.solve(&ssa, &cfg);
///
/// // Check which variables are live at block exit
/// if let Some(live) = results.out_state(block_id) {
///     for var_id in live.variables() {
///         println!("Variable {} is live at exit of block {}", var_id, block_id);
///     }
/// }
/// ```
pub struct LiveVariables {
    /// Number of variables in the function.
    num_vars: usize,
    /// USE sets for each block (variables used before definition).
    use_sets: Vec<BitSet>,
    /// DEF sets for each block (variables defined).
    def_sets: Vec<BitSet>,
}

impl LiveVariables {
    /// Creates a new live variables analysis for the given SSA function.
    #[must_use]
    pub fn new(ssa: &SsaFunction) -> Self {
        let num_vars = ssa.variable_count();
        let num_blocks = ssa.block_count();

        let mut use_sets = Vec::with_capacity(num_blocks);
        let mut def_sets = Vec::with_capacity(num_blocks);

        for block in ssa.blocks() {
            let mut uses = BitSet::new(num_vars);
            let mut defs = BitSet::new(num_vars);

            // Process phi nodes: they define variables and use operands
            for phi in block.phi_nodes() {
                // Phi defines its result
                let def_idx = phi.result().index();
                if def_idx < num_vars {
                    defs.insert(def_idx);
                }

                // Phi uses its operands (these come from predecessors,
                // but we track them as uses in this block for simplicity)
                for op in phi.operands() {
                    let var_idx = op.value().index();
                    // Only count as USE if not already defined in this block
                    if var_idx < num_vars && !defs.contains(var_idx) {
                        uses.insert(var_idx);
                    }
                }
            }

            // Process instructions in forward order
            for instr in block.instructions() {
                // Uses first (before def, since this is the "USE before DEF" set)
                for &use_var in instr.uses() {
                    let var_idx = use_var.index();
                    if var_idx < num_vars && !defs.contains(var_idx) {
                        uses.insert(var_idx);
                    }
                }

                // Then definition
                if let Some(def) = instr.def() {
                    let def_idx = def.index();
                    if def_idx < num_vars {
                        defs.insert(def_idx);
                    }
                }
            }

            use_sets.push(uses);
            def_sets.push(defs);
        }

        Self {
            num_vars,
            use_sets,
            def_sets,
        }
    }

    /// Returns the number of variables being tracked.
    #[must_use]
    pub const fn num_variables(&self) -> usize {
        self.num_vars
    }

    /// Returns the USE set for a block.
    #[must_use]
    pub fn use_set(&self, block: usize) -> Option<&BitSet> {
        self.use_sets.get(block)
    }

    /// Returns the DEF set for a block.
    #[must_use]
    pub fn def_set(&self, block: usize) -> Option<&BitSet> {
        self.def_sets.get(block)
    }
}

impl DataFlowAnalysis for LiveVariables {
    type Lattice = LivenessResult;
    const DIRECTION: Direction = Direction::Backward;

    fn boundary(&self, _ssa: &SsaFunction) -> Self::Lattice {
        // At function exit, no variables are live
        // (unless we're tracking return values, which we could add)
        LivenessResult {
            live: BitSet::new(self.num_vars),
        }
    }

    fn initial(&self, _ssa: &SsaFunction) -> Self::Lattice {
        // Initially, no variables are live
        LivenessResult {
            live: BitSet::new(self.num_vars),
        }
    }

    fn transfer(
        &self,
        block_id: usize,
        _block: &SsaBlock,
        output: &Self::Lattice,
        _ssa: &SsaFunction,
    ) -> Self::Lattice {
        // For backward analysis: IN = USE ∪ (OUT - DEF)
        let mut result = output.live.clone();

        // Remove definitions (OUT - DEF)
        result.difference_with(&self.def_sets[block_id]);

        // Add uses (USE ∪ ...)
        result.union_with(&self.use_sets[block_id]);

        LivenessResult { live: result }
    }
}

/// Result of live variable analysis for a single program point.
#[derive(Debug, Clone, PartialEq)]
pub struct LivenessResult {
    /// Bit vector of live variables (indexed by `SsaVarId`).
    live: BitSet,
}

impl LivenessResult {
    /// Creates a new empty result.
    #[must_use]
    pub fn new(num_vars: usize) -> Self {
        Self {
            live: BitSet::new(num_vars),
        }
    }

    /// Returns `true` if the given variable is live at this point.
    #[must_use]
    pub fn is_live(&self, var: SsaVarId) -> bool {
        let idx = var.index();
        idx < self.live.len() && self.live.contains(idx)
    }

    /// Returns an iterator over all live variables.
    pub fn variables(&self) -> impl Iterator<Item = SsaVarId> + '_ {
        self.live.iter().map(SsaVarId::new)
    }

    /// Returns the number of live variables.
    #[must_use]
    pub fn count(&self) -> usize {
        self.live.count()
    }

    /// Returns `true` if no variables are live.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.live.is_empty()
    }

    /// Marks a variable as live.
    pub fn add(&mut self, var: SsaVarId) {
        let idx = var.index();
        if idx < self.live.len() {
            self.live.insert(idx);
        }
    }

    /// Marks a variable as not live.
    pub fn remove(&mut self, var: SsaVarId) {
        let idx = var.index();
        if idx < self.live.len() {
            self.live.remove(idx);
        }
    }

    /// Returns the underlying bit set.
    #[must_use]
    pub const fn as_bitset(&self) -> &BitSet {
        &self.live
    }
}

impl MeetSemiLattice for LivenessResult {
    /// Meet is union (a variable is live if it's live on ANY successor path).
    fn meet(&self, other: &Self) -> Self {
        let mut result = self.live.clone();
        result.union_with(&other.live);
        Self { live: result }
    }

    fn is_bottom(&self) -> bool {
        // Bottom is when all variables are live (full set)
        self.live.count() == self.live.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_liveness_result() {
        let mut result = LivenessResult::new(10);
        assert!(result.is_empty());

        result.add(SsaVarId::new(0));
        result.add(SsaVarId::new(5));

        assert!(!result.is_empty());
        assert_eq!(result.count(), 2);
        assert!(result.is_live(SsaVarId::new(0)));
        assert!(result.is_live(SsaVarId::new(5)));
        assert!(!result.is_live(SsaVarId::new(1)));

        result.remove(SsaVarId::new(0));
        assert!(!result.is_live(SsaVarId::new(0)));
        assert_eq!(result.count(), 1);
    }

    #[test]
    fn test_liveness_meet() {
        let mut a = LivenessResult::new(10);
        let mut b = LivenessResult::new(10);

        a.add(SsaVarId::new(0));
        a.add(SsaVarId::new(1));
        b.add(SsaVarId::new(1));
        b.add(SsaVarId::new(2));

        let result = a.meet(&b);
        assert!(result.is_live(SsaVarId::new(0)));
        assert!(result.is_live(SsaVarId::new(1)));
        assert!(result.is_live(SsaVarId::new(2)));
        assert_eq!(result.count(), 3);
    }

    #[test]
    fn test_liveness_iterator() {
        let mut result = LivenessResult::new(100);
        result.add(SsaVarId::new(5));
        result.add(SsaVarId::new(42));
        result.add(SsaVarId::new(99));

        let vars: Vec<_> = result.variables().collect();
        assert_eq!(vars.len(), 3);
        assert!(vars.contains(&SsaVarId::new(5)));
        assert!(vars.contains(&SsaVarId::new(42)));
        assert!(vars.contains(&SsaVarId::new(99)));
    }
}
