//! Data types for trace-based CFF analysis.
//!
//! All types in this module are part of the tracer's public API — they are
//! re-exported from [`super`] and consumed by the
//! [`reconstruction`](crate::deobfuscation::passes::unflattening::reconstruction)
//! module to build patch plans.
//!
//! The central type is [`TraceTree`], which contains a root [`TraceNode`] and
//! optional handler traces. Each node represents a segment of linear execution,
//! terminated by one of the [`TraceTerminator`] variants (state transition, user
//! branch, exit, loop, or stop).

use std::collections::BTreeMap;

use crate::analysis::{SsaInstruction, SsaVarId};
use crate::utils::BitSet;

/// Information about the dispatcher found during tracing.
#[derive(Debug, Clone)]
pub struct TracedDispatcher {
    /// Block index of the dispatcher.
    pub block: usize,

    /// The switch value variable.
    pub switch_var: SsaVarId,

    /// Switch targets (case blocks).
    pub targets: Vec<usize>,

    /// Default target.
    pub default: usize,

    /// The state variable (phi at dispatcher that receives state from case blocks).
    pub state_var: Option<SsaVarId>,

    /// Initial state value captured during detection (before optimization may
    /// remove the defining `ldc.i4; stloc` sequence).
    pub initial_state: Option<i64>,
}

/// Why tracing stopped.
#[derive(Debug, Clone)]
pub enum StopReason {
    /// Hit a return/throw instruction.
    Terminator,

    /// Exceeded maximum block visits.
    MaxVisitsExceeded,

    /// Couldn't determine next block (unknown branch/switch value).
    UnknownControlFlow { block: usize },

    /// Visited same block too many times (likely infinite loop).
    InfiniteLoop { block: usize },
}

/// An instruction together with the concrete values it used at this trace step.
#[derive(Debug, Clone)]
pub struct InstructionWithValues {
    /// The SSA instruction that was executed.
    pub instruction: SsaInstruction,

    /// Block index where this instruction lives.
    pub block_idx: usize,

    /// Concrete values of input variables at this point.
    pub input_values: BTreeMap<SsaVarId, i64>,

    /// Concrete value of output variable (if instruction defines one).
    pub output_value: Option<i64>,
}

/// A trace of an exception handler entry block.
///
/// When CFF exists inside exception handler blocks (catch/finally/filter),
/// the normal trace from block 0 won't reach them because handlers are only
/// reachable via runtime exceptions. This struct holds a separate trace
/// starting from a handler entry block.
#[derive(Debug, Clone)]
pub struct HandlerTrace {
    /// The handler's entry block index.
    pub handler_start_block: usize,

    /// The root node of the handler's trace tree.
    pub root: TraceNode,
}

/// A trace tree represents all execution paths through a CFF-protected method.
///
/// Unlike the linear `MethodTrace`, this structure forks at user branches
/// (conditions that don't depend on state) to capture all possible paths.
#[derive(Debug, Clone)]
pub struct TraceTree {
    /// The root node of the trace tree.
    pub root: TraceNode,

    /// Traces of exception handler entry blocks that were not reached by the main trace.
    pub handler_traces: Vec<HandlerTrace>,

    /// Dispatcher information (detected during tracing).
    pub dispatcher: Option<TracedDispatcher>,

    /// Variables that are tainted by state (CFF machinery).
    pub state_tainted: BitSet,

    /// Statistics about the trace.
    pub stats: TraceStats,
}

/// Statistics about a trace tree.
#[derive(Debug, Clone, Default)]
pub struct TraceStats {
    /// Total number of nodes in the tree.
    pub node_count: usize,

    /// Number of user branches encountered.
    pub user_branch_count: usize,

    /// Number of state transitions (dispatcher visits).
    pub state_transition_count: usize,

    /// Maximum depth of the tree.
    pub max_depth: usize,

    /// Number of exit points (ret/throw).
    pub exit_count: usize,
}

/// A node in the trace tree representing a segment of execution.
#[derive(Debug, Clone)]
pub struct TraceNode {
    /// Unique identifier for this node.
    pub id: usize,

    /// The block index where this segment starts.
    pub start_block: usize,

    /// Linear sequence of instructions in this segment.
    pub instructions: Vec<InstructionWithValues>,

    /// Blocks visited in this segment (in order).
    pub blocks_visited: Vec<usize>,

    /// How this segment ends.
    pub terminator: TraceTerminator,
}

/// How a trace segment terminates.
#[derive(Debug, Clone)]
pub enum TraceTerminator {
    /// Reached method exit (ret/throw).
    Exit {
        /// The exit block.
        block: usize,
    },

    /// State-driven transition through dispatcher (deterministic).
    /// We follow this automatically - it's CFF machinery.
    StateTransition {
        /// The state value that led here.
        from_state: i64,
        /// The next state value.
        to_state: i64,
        /// The case block we're transitioning to.
        target_block: usize,
        /// Continuation of the trace.
        continues: Box<TraceNode>,
    },

    /// Internal sentinel: state transition that needs iterative continuation.
    /// Only used transiently during `trace_from_block` — never appears in
    /// the final trace tree.
    PendingStateTransition {
        from_state: i64,
        target_block: usize,
    },

    /// User branch - the condition doesn't depend on state.
    /// This represents original program logic that was flattened.
    UserBranch {
        /// The block containing the branch.
        block: usize,
        /// The condition variable.
        condition: SsaVarId,
        /// True branch continuation.
        true_branch: Box<TraceNode>,
        /// False branch continuation.
        false_branch: Box<TraceNode>,
    },

    /// User switch - value doesn't depend on state.
    UserSwitch {
        /// The block containing the switch.
        block: usize,
        /// The switch value variable.
        value: SsaVarId,
        /// Case continuations: (case_value, node).
        cases: Vec<(i64, Box<TraceNode>)>,
        /// Default continuation.
        default: Box<TraceNode>,
    },

    /// Trace stopped due to a limit or error.
    Stopped { reason: StopReason },

    /// Loop detected - this path rejoins an earlier point.
    /// We don't expand further to avoid infinite trees.
    LoopBack {
        /// The block we're looping back to.
        target_block: usize,
        /// The state when reaching this point.
        state: i64,
    },
}

impl TraceTree {
    /// Creates a new trace tree with a root node.
    ///
    /// The `variable_count` parameter is the number of SSA variables, used to
    /// size the `state_tainted` bit set.
    #[must_use]
    pub fn new(root: TraceNode, variable_count: usize) -> Self {
        Self {
            root,
            handler_traces: Vec::new(),
            dispatcher: None,
            state_tainted: BitSet::new(variable_count),
            stats: TraceStats::default(),
        }
    }

    /// Checks if a variable is state-tainted.
    #[must_use]
    pub fn is_state_tainted(&self, var: SsaVarId) -> bool {
        self.state_tainted.contains(var.index())
    }

    /// Marks a variable as state-tainted.
    pub fn mark_tainted(&mut self, var: SsaVarId) {
        self.state_tainted.insert(var.index());
    }
}

impl TraceNode {
    /// Creates a new trace node.
    pub fn new(id: usize, start_block: usize) -> Self {
        Self {
            id,
            start_block,
            instructions: Vec::new(),
            blocks_visited: vec![start_block],
            terminator: TraceTerminator::Stopped {
                reason: StopReason::UnknownControlFlow { block: start_block },
            },
        }
    }

    /// Adds an instruction to this node.
    pub fn add_instruction(&mut self, instr: InstructionWithValues) {
        self.instructions.push(instr);
    }

    /// Records visiting a block.
    pub fn visit_block(&mut self, block: usize) {
        self.blocks_visited.push(block);
    }

    /// Marks this node as needing a state transition continuation.
    pub fn set_pending_state_transition(&mut self, from_state: i64, target_block: usize) {
        self.terminator = TraceTerminator::PendingStateTransition {
            from_state,
            target_block,
        };
    }

    /// Returns pending state transition info if this node needs continuation.
    pub fn pending_state_transition(&self) -> Option<(i64, usize)> {
        match &self.terminator {
            TraceTerminator::PendingStateTransition {
                from_state,
                target_block,
            } => Some((*from_state, *target_block)),
            _ => None,
        }
    }

    /// Sets the terminator.
    pub fn set_terminator(&mut self, terminator: TraceTerminator) {
        self.terminator = terminator;
    }

    /// Returns true if this node ends at an exit.
    pub fn is_exit(&self) -> bool {
        matches!(self.terminator, TraceTerminator::Exit { .. })
    }

    /// Returns true if this node has a user branch.
    pub fn is_user_branch(&self) -> bool {
        matches!(
            self.terminator,
            TraceTerminator::UserBranch { .. } | TraceTerminator::UserSwitch { .. }
        )
    }
}
