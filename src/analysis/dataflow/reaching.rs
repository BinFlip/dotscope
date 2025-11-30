//! Reaching definitions analysis.
//!
//! Reaching definitions computes, for each program point, which variable
//! definitions may reach that point without being killed by an intervening
//! definition of the same variable.
//!
//! # SSA Form
//!
//! In SSA form, each variable is defined exactly once, so reaching definitions
//! is simplified: a definition reaches a use if and only if there's a path
//! from the definition to the use. This is always true in well-formed SSA.
//!
//! However, this analysis is still useful for:
//! - Validating SSA construction
//! - Computing def-use chains
//! - Detecting dead definitions
//!
//! # Algorithm
//!
//! For each block B:
//! - `GEN[B]` = definitions created in B
//! - `KILL[B]` = definitions killed in B (in SSA: none, since each var is defined once)
//! - `IN[B]` = ∪{OUT[P] | P is a predecessor of B}
//! - `OUT[B]` = GEN[B] ∪ (IN[B] - KILL[B])
//!
//! Since SSA has no kills, this simplifies to:
//! - `OUT[B]` = GEN[B] ∪ IN[B]

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

/// Reaching definitions analysis.
///
/// Computes which variable definitions may reach each block.
///
/// # Example
///
/// ```rust,ignore
/// use dotscope::analysis::dataflow::{ReachingDefinitions, DataFlowSolver};
///
/// let analysis = ReachingDefinitions::new(&ssa);
/// let mut solver = DataFlowSolver::new(analysis);
/// let results = solver.solve(&ssa, &cfg);
///
/// // Check which definitions reach a block
/// if let Some(reaching) = results.in_state(block_id) {
///     for var_id in reaching.definitions() {
///         println!("Definition {} reaches block {}", var_id, block_id);
///     }
/// }
/// ```
pub struct ReachingDefinitions {
    /// Number of variables in the function.
    num_vars: usize,
    /// GEN sets for each block (definitions created in the block).
    gen_sets: Vec<BitSet>,
}

impl ReachingDefinitions {
    /// Creates a new reaching definitions analysis for the given SSA function.
    #[must_use]
    pub fn new(ssa: &SsaFunction) -> Self {
        let num_vars = ssa.variable_count();
        let num_blocks = ssa.block_count();

        // Compute GEN sets
        let mut gen_sets = Vec::with_capacity(num_blocks);

        for block in ssa.blocks() {
            let mut gen = BitSet::new(num_vars);

            // Phi nodes define variables
            for phi in block.phi_nodes() {
                let idx = phi.result().index();
                if idx < num_vars {
                    gen.insert(idx);
                }
            }

            // Instructions may define variables
            for instr in block.instructions() {
                if let Some(def) = instr.def() {
                    let idx = def.index();
                    if idx < num_vars {
                        gen.insert(idx);
                    }
                }
            }

            gen_sets.push(gen);
        }

        Self { num_vars, gen_sets }
    }

    /// Returns the number of variables being tracked.
    #[must_use]
    pub const fn num_variables(&self) -> usize {
        self.num_vars
    }
}

impl DataFlowAnalysis for ReachingDefinitions {
    type Lattice = ReachingDefsResult;
    const DIRECTION: Direction = Direction::Forward;

    fn boundary(&self, ssa: &SsaFunction) -> Self::Lattice {
        // At function entry, the initial definitions of arguments and locals reach
        let mut defs = BitSet::new(self.num_vars);

        // Arguments and locals have initial definitions (version 0)
        for var in ssa.variables() {
            if var.version() == 0 && (var.origin().is_argument() || var.origin().is_local()) {
                defs.insert(var.id().index());
            }
        }

        ReachingDefsResult { defs }
    }

    fn initial(&self, _ssa: &SsaFunction) -> Self::Lattice {
        // Initially, no definitions reach interior blocks
        ReachingDefsResult {
            defs: BitSet::new(self.num_vars),
        }
    }

    fn transfer(
        &self,
        block_id: usize,
        _block: &SsaBlock,
        input: &Self::Lattice,
        _ssa: &SsaFunction,
    ) -> Self::Lattice {
        // OUT = GEN ∪ IN (no KILL in SSA since each variable is defined once)
        let mut result = input.defs.clone();
        result.union_with(&self.gen_sets[block_id]);
        ReachingDefsResult { defs: result }
    }
}

/// Result of reaching definitions analysis for a single program point.
#[derive(Debug, Clone, PartialEq)]
pub struct ReachingDefsResult {
    /// Bit vector of reaching definitions (indexed by `SsaVarId`).
    defs: BitSet,
}

impl ReachingDefsResult {
    /// Creates a new empty result.
    #[must_use]
    pub fn new(num_vars: usize) -> Self {
        Self {
            defs: BitSet::new(num_vars),
        }
    }

    /// Returns `true` if the given variable's definition reaches this point.
    #[must_use]
    pub fn reaches(&self, var: SsaVarId) -> bool {
        let idx = var.index();
        idx < self.defs.len() && self.defs.contains(idx)
    }

    /// Returns an iterator over all reaching definitions.
    pub fn definitions(&self) -> impl Iterator<Item = SsaVarId> + '_ {
        self.defs.iter().map(SsaVarId::new)
    }

    /// Returns the number of reaching definitions.
    #[must_use]
    pub fn count(&self) -> usize {
        self.defs.count()
    }

    /// Returns `true` if no definitions reach this point.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.defs.is_empty()
    }

    /// Adds a definition to the reaching set.
    pub fn add(&mut self, var: SsaVarId) {
        let idx = var.index();
        if idx < self.defs.len() {
            self.defs.insert(idx);
        }
    }

    /// Removes a definition from the reaching set.
    pub fn remove(&mut self, var: SsaVarId) {
        let idx = var.index();
        if idx < self.defs.len() {
            self.defs.remove(idx);
        }
    }
}

impl MeetSemiLattice for ReachingDefsResult {
    /// Meet is union (may analysis: a definition reaches if it reaches from ANY predecessor).
    fn meet(&self, other: &Self) -> Self {
        let mut result = self.defs.clone();
        result.union_with(&other.defs);
        Self { defs: result }
    }

    fn is_bottom(&self) -> bool {
        // Bottom is when all definitions reach (full set)
        self.defs.count() == self.defs.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reaching_defs_result() {
        let mut result = ReachingDefsResult::new(10);
        assert!(result.is_empty());

        result.add(SsaVarId::new(0));
        result.add(SsaVarId::new(5));

        assert!(!result.is_empty());
        assert_eq!(result.count(), 2);
        assert!(result.reaches(SsaVarId::new(0)));
        assert!(result.reaches(SsaVarId::new(5)));
        assert!(!result.reaches(SsaVarId::new(1)));

        result.remove(SsaVarId::new(0));
        assert!(!result.reaches(SsaVarId::new(0)));
        assert_eq!(result.count(), 1);
    }

    #[test]
    fn test_reaching_defs_meet() {
        let mut a = ReachingDefsResult::new(10);
        let mut b = ReachingDefsResult::new(10);

        a.add(SsaVarId::new(0));
        a.add(SsaVarId::new(1));
        b.add(SsaVarId::new(1));
        b.add(SsaVarId::new(2));

        let result = a.meet(&b);
        assert!(result.reaches(SsaVarId::new(0)));
        assert!(result.reaches(SsaVarId::new(1)));
        assert!(result.reaches(SsaVarId::new(2)));
        assert_eq!(result.count(), 3);
    }

    #[test]
    fn test_reaching_defs_iterator() {
        let mut result = ReachingDefsResult::new(100);
        result.add(SsaVarId::new(5));
        result.add(SsaVarId::new(42));
        result.add(SsaVarId::new(99));

        let defs: Vec<_> = result.definitions().collect();
        assert_eq!(defs.len(), 3);
        assert!(defs.contains(&SsaVarId::new(5)));
        assert!(defs.contains(&SsaVarId::new(42)));
        assert!(defs.contains(&SsaVarId::new(99)));
    }
}
