//! Expected analysis properties for test verification.
//!
//! This module defines the expectation types that describe what analysis
//! results we expect for each test case.

/// Expected properties of a Control Flow Graph.
#[derive(Debug, Clone, Default)]
pub struct CfgExpectation {
    /// Minimum number of basic blocks.
    pub min_blocks: usize,
    /// Maximum number of basic blocks (compilers may vary).
    pub max_blocks: usize,
    /// Whether the CFG should contain loops.
    pub has_loops: bool,
    /// Minimum number of exit blocks.
    pub min_exits: usize,
    /// Maximum number of exit blocks.
    pub max_exits: usize,
}

impl CfgExpectation {
    /// Creates a new expectation for a sequential (single-block) method.
    #[must_use]
    pub const fn sequential() -> Self {
        Self {
            min_blocks: 1,
            max_blocks: 1,
            has_loops: false,
            min_exits: 1,
            max_exits: 1,
        }
    }

    /// Creates a new expectation for a method with conditionals.
    #[must_use]
    pub const fn conditional(min_blocks: usize, max_blocks: usize) -> Self {
        Self {
            min_blocks,
            max_blocks,
            has_loops: false,
            min_exits: 1,
            max_exits: 2,
        }
    }

    /// Creates a new expectation for a method with loops.
    #[must_use]
    pub const fn with_loops(min_blocks: usize, max_blocks: usize) -> Self {
        Self {
            min_blocks,
            max_blocks,
            has_loops: true,
            min_exits: 1,
            max_exits: 1,
        }
    }
}

/// Expected properties of SSA form.
#[derive(Debug, Clone, Default)]
pub struct SsaExpectation {
    /// Number of method arguments.
    pub num_args: usize,
    /// Minimum number of local variables (debug builds may add extra).
    pub min_locals: usize,
    /// Maximum number of local variables.
    pub max_locals: usize,
    /// Whether phi nodes should be present.
    pub has_phi_nodes: bool,
    /// Minimum number of phi nodes.
    pub min_phi_count: usize,
    /// Maximum number of phi nodes (compilers may vary).
    pub max_phi_count: usize,
}

impl SsaExpectation {
    /// Creates a new expectation for a method without phi nodes.
    /// Allows +1 local for debug builds (return value slot).
    #[must_use]
    pub const fn no_phi(num_args: usize, num_locals: usize) -> Self {
        Self {
            num_args,
            min_locals: num_locals,
            max_locals: num_locals + 1, // Debug builds add return value local
            has_phi_nodes: false,
            min_phi_count: 0,
            max_phi_count: 0,
        }
    }

    /// Creates a new expectation for a method with phi nodes.
    /// Allows +1 local for debug builds (return value slot).
    #[must_use]
    pub const fn with_phi(
        num_args: usize,
        num_locals: usize,
        min_phi: usize,
        max_phi: usize,
    ) -> Self {
        Self {
            num_args,
            min_locals: num_locals,
            max_locals: num_locals + 1, // Debug builds add return value local
            has_phi_nodes: true,
            min_phi_count: min_phi,
            max_phi_count: max_phi,
        }
    }
}

/// Expected properties of call graph nodes.
#[derive(Debug, Clone, Default)]
pub struct CallGraphExpectation {
    /// Minimum number of call sites in the method.
    pub min_call_sites: usize,
    /// Maximum number of call sites.
    pub max_call_sites: usize,
    /// Whether this method is recursive (direct or mutual).
    pub is_recursive: bool,
    /// Whether this method is a leaf (no outgoing calls).
    pub is_leaf: bool,
}

impl CallGraphExpectation {
    /// Creates an expectation for a leaf method (no calls).
    #[must_use]
    pub const fn leaf() -> Self {
        Self {
            min_call_sites: 0,
            max_call_sites: 0,
            is_recursive: false,
            is_leaf: true,
        }
    }

    /// Creates an expectation for a method with calls.
    #[must_use]
    pub const fn with_calls(min_calls: usize, max_calls: usize) -> Self {
        Self {
            min_call_sites: min_calls,
            max_call_sites: max_calls,
            is_recursive: false,
            is_leaf: false,
        }
    }

    /// Creates an expectation for a recursive method.
    #[must_use]
    pub const fn recursive() -> Self {
        Self {
            min_call_sites: 1,
            max_call_sites: 1,
            is_recursive: true,
            is_leaf: false,
        }
    }
}

/// Expected properties of data flow analysis results.
#[derive(Debug, Clone, Default)]
pub struct DataFlowExpectation {
    /// Whether constant propagation should find constants.
    pub has_constants: bool,
    /// Whether there should be dead code.
    pub has_dead_code: bool,
    /// Whether all blocks should be reachable.
    pub all_blocks_reachable: bool,
}

impl DataFlowExpectation {
    /// Creates an expectation where all code is live.
    #[must_use]
    pub const fn all_live() -> Self {
        Self {
            has_constants: false,
            has_dead_code: false,
            all_blocks_reachable: true,
        }
    }

    /// Creates an expectation with constants.
    #[must_use]
    pub const fn with_constants() -> Self {
        Self {
            has_constants: true,
            has_dead_code: false,
            all_blocks_reachable: true,
        }
    }

    /// Creates an expectation with dead code.
    #[must_use]
    pub const fn with_dead_code() -> Self {
        Self {
            has_constants: true,
            has_dead_code: true,
            all_blocks_reachable: false,
        }
    }
}
