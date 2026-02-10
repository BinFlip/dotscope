//! Control flow edge types for the CFG.
//!
//! This module defines the edge representations used in the control flow graph,
//! providing semantic information about how control flows between basic blocks.

use crate::metadata::token::Token;

/// The kind of control flow represented by an edge.
///
/// This enum classifies edges by their control flow semantics, which is essential
/// for analyses like loop detection, path condition computation, and SSA construction.
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::analysis::CfgEdgeKind;
///
/// let edge_kind = CfgEdgeKind::ConditionalTrue;
/// assert!(edge_kind.is_conditional());
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CfgEdgeKind {
    /// Unconditional control flow (direct jump or fall-through).
    ///
    /// This includes:
    /// - Unconditional branch instructions (`br`, `br.s`)
    /// - Fall-through from one block to the next
    /// - The single successor of a non-branching block
    Unconditional,

    /// The "true" branch of a conditional.
    ///
    /// Taken when the condition evaluates to true (non-zero).
    /// Used by `brtrue`, `brtrue.s`, and comparison branches like `beq`, `blt`, etc.
    ConditionalTrue,

    /// The "false" branch of a conditional (fall-through).
    ///
    /// Taken when the condition evaluates to false (zero).
    /// This is typically the fall-through path after a conditional branch.
    ConditionalFalse,

    /// A switch case edge.
    ///
    /// Contains the case value (if known) or `None` for the default case.
    Switch {
        /// The case value that triggers this edge, or `None` for the default case.
        case_value: Option<i32>,
    },

    /// Edge to an exception handler.
    ///
    /// These edges represent potential control flow to catch, filter, or finally blocks.
    ExceptionHandler {
        /// The type of exception caught, if this is a typed catch handler.
        /// `None` for finally blocks or catch-all handlers.
        exception_type: Option<Token>,
    },

    /// Edge from a `leave` instruction exiting a protected region.
    ///
    /// Leave instructions exit try/catch/finally blocks and jump to a target
    /// outside the protected region.
    Leave,

    /// Edge from an `endfinally` instruction.
    ///
    /// Represents the implicit control flow when a finally block completes.
    /// The actual target depends on how the finally block was entered.
    EndFinally,
}

impl CfgEdgeKind {
    /// Returns `true` if this is a conditional branch edge.
    ///
    /// # Returns
    ///
    /// `true` for [`ConditionalTrue`](Self::ConditionalTrue) and
    /// [`ConditionalFalse`](Self::ConditionalFalse), `false` otherwise.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::analysis::CfgEdgeKind;
    ///
    /// assert!(CfgEdgeKind::ConditionalTrue.is_conditional());
    /// assert!(CfgEdgeKind::ConditionalFalse.is_conditional());
    /// assert!(!CfgEdgeKind::Unconditional.is_conditional());
    /// ```
    #[must_use]
    pub const fn is_conditional(&self) -> bool {
        matches!(self, Self::ConditionalTrue | Self::ConditionalFalse)
    }

    /// Returns `true` if this is an exception-related edge.
    ///
    /// # Returns
    ///
    /// `true` for [`ExceptionHandler`](Self::ExceptionHandler), [`Leave`](Self::Leave),
    /// and [`EndFinally`](Self::EndFinally), `false` otherwise.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::analysis::CfgEdgeKind;
    ///
    /// assert!(CfgEdgeKind::ExceptionHandler { exception_type: None }.is_exceptional());
    /// assert!(CfgEdgeKind::Leave.is_exceptional());
    /// assert!(CfgEdgeKind::EndFinally.is_exceptional());
    /// ```
    #[must_use]
    pub const fn is_exceptional(&self) -> bool {
        matches!(
            self,
            Self::ExceptionHandler { .. } | Self::Leave | Self::EndFinally
        )
    }

    /// Returns `true` if this is a switch case edge.
    ///
    /// # Returns
    ///
    /// `true` for [`Switch`](Self::Switch) edges, `false` otherwise.
    #[must_use]
    pub const fn is_switch(&self) -> bool {
        matches!(self, Self::Switch { .. })
    }
}

/// An edge in the control flow graph.
///
/// Each edge connects a source block to a target block and carries semantic
/// information about the type of control flow.
///
/// # Examples
///
/// ```rust
/// use dotscope::analysis::{CfgEdge, CfgEdgeKind};
///
/// let edge = CfgEdge::new(1, CfgEdgeKind::Unconditional);
/// assert_eq!(edge.target(), 1);
/// assert!(!edge.kind().is_conditional());
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CfgEdge {
    /// The target block of this edge.
    target: usize,
    /// The kind of control flow this edge represents.
    kind: CfgEdgeKind,
}

impl CfgEdge {
    /// Creates a new CFG edge.
    ///
    /// # Arguments
    ///
    /// * `target` - The target block index
    /// * `kind` - The kind of control flow
    ///
    /// # Returns
    ///
    /// A new `CfgEdge` instance.
    #[must_use]
    pub const fn new(target: usize, kind: CfgEdgeKind) -> Self {
        Self { target, kind }
    }

    /// Returns the target block index of this edge.
    ///
    /// # Returns
    ///
    /// The index of the target basic block.
    #[must_use]
    pub const fn target(&self) -> usize {
        self.target
    }

    /// Returns the kind of control flow this edge represents.
    ///
    /// # Returns
    ///
    /// A reference to the [`CfgEdgeKind`] for this edge.
    #[must_use]
    pub const fn kind(&self) -> &CfgEdgeKind {
        &self.kind
    }

    /// Creates an unconditional edge to the target block.
    ///
    /// # Arguments
    ///
    /// * `target` - The target block index
    ///
    /// # Returns
    ///
    /// A new [`CfgEdge`] with [`CfgEdgeKind::Unconditional`] kind.
    #[must_use]
    pub const fn unconditional(target: usize) -> Self {
        Self::new(target, CfgEdgeKind::Unconditional)
    }

    /// Creates a conditional true edge to the target block.
    ///
    /// # Arguments
    ///
    /// * `target` - The target block index
    ///
    /// # Returns
    ///
    /// A new [`CfgEdge`] with [`CfgEdgeKind::ConditionalTrue`] kind.
    #[must_use]
    pub const fn conditional_true(target: usize) -> Self {
        Self::new(target, CfgEdgeKind::ConditionalTrue)
    }

    /// Creates a conditional false edge to the target block.
    ///
    /// # Arguments
    ///
    /// * `target` - The target block index
    ///
    /// # Returns
    ///
    /// A new [`CfgEdge`] with [`CfgEdgeKind::ConditionalFalse`] kind.
    #[must_use]
    pub const fn conditional_false(target: usize) -> Self {
        Self::new(target, CfgEdgeKind::ConditionalFalse)
    }

    /// Creates a switch case edge to the target block.
    ///
    /// # Arguments
    ///
    /// * `target` - The target block index
    /// * `case_value` - The case value, or `None` for the default case
    ///
    /// # Returns
    ///
    /// A new [`CfgEdge`] with [`CfgEdgeKind::Switch`] kind.
    #[must_use]
    pub const fn switch_case(target: usize, case_value: Option<i32>) -> Self {
        Self::new(target, CfgEdgeKind::Switch { case_value })
    }

    /// Creates an exception handler edge to the target block.
    ///
    /// # Arguments
    ///
    /// * `target` - The target block index
    /// * `exception_type` - The caught exception type token, or `None` for catch-all
    ///
    /// # Returns
    ///
    /// A new [`CfgEdge`] with [`CfgEdgeKind::ExceptionHandler`] kind.
    #[must_use]
    pub const fn exception_handler(target: usize, exception_type: Option<Token>) -> Self {
        Self::new(target, CfgEdgeKind::ExceptionHandler { exception_type })
    }

    /// Creates a leave edge to the target block.
    ///
    /// # Arguments
    ///
    /// * `target` - The target block index
    ///
    /// # Returns
    ///
    /// A new [`CfgEdge`] with [`CfgEdgeKind::Leave`] kind.
    #[must_use]
    pub const fn leave(target: usize) -> Self {
        Self::new(target, CfgEdgeKind::Leave)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_edge_kind_is_conditional() {
        assert!(!CfgEdgeKind::Unconditional.is_conditional());
        assert!(CfgEdgeKind::ConditionalTrue.is_conditional());
        assert!(CfgEdgeKind::ConditionalFalse.is_conditional());
        assert!(!CfgEdgeKind::Switch {
            case_value: Some(0)
        }
        .is_conditional());
        assert!(!CfgEdgeKind::ExceptionHandler {
            exception_type: None
        }
        .is_conditional());
        assert!(!CfgEdgeKind::Leave.is_conditional());
        assert!(!CfgEdgeKind::EndFinally.is_conditional());
    }

    #[test]
    fn test_edge_kind_is_exceptional() {
        assert!(!CfgEdgeKind::Unconditional.is_exceptional());
        assert!(!CfgEdgeKind::ConditionalTrue.is_exceptional());
        assert!(!CfgEdgeKind::ConditionalFalse.is_exceptional());
        assert!(!CfgEdgeKind::Switch {
            case_value: Some(0)
        }
        .is_exceptional());
        assert!(CfgEdgeKind::ExceptionHandler {
            exception_type: None
        }
        .is_exceptional());
        assert!(CfgEdgeKind::Leave.is_exceptional());
        assert!(CfgEdgeKind::EndFinally.is_exceptional());
    }

    #[test]
    fn test_edge_kind_is_switch() {
        assert!(!CfgEdgeKind::Unconditional.is_switch());
        assert!(CfgEdgeKind::Switch {
            case_value: Some(0)
        }
        .is_switch());
        assert!(CfgEdgeKind::Switch { case_value: None }.is_switch());
    }

    #[test]
    fn test_cfg_edge_creation() {
        let edge = CfgEdge::new(5, CfgEdgeKind::Unconditional);
        assert_eq!(edge.target(), 5);
        assert_eq!(*edge.kind(), CfgEdgeKind::Unconditional);
    }

    #[test]
    fn test_cfg_edge_factory_methods() {
        let unconditional = CfgEdge::unconditional(1);
        assert_eq!(unconditional.target(), 1);
        assert_eq!(*unconditional.kind(), CfgEdgeKind::Unconditional);

        let cond_true = CfgEdge::conditional_true(2);
        assert_eq!(cond_true.target(), 2);
        assert_eq!(*cond_true.kind(), CfgEdgeKind::ConditionalTrue);

        let cond_false = CfgEdge::conditional_false(3);
        assert_eq!(cond_false.target(), 3);
        assert_eq!(*cond_false.kind(), CfgEdgeKind::ConditionalFalse);

        let switch = CfgEdge::switch_case(4, Some(42));
        assert_eq!(switch.target(), 4);
        assert_eq!(
            *switch.kind(),
            CfgEdgeKind::Switch {
                case_value: Some(42)
            }
        );

        let exception = CfgEdge::exception_handler(5, None);
        assert_eq!(exception.target(), 5);
        assert_eq!(
            *exception.kind(),
            CfgEdgeKind::ExceptionHandler {
                exception_type: None
            }
        );

        let leave = CfgEdge::leave(6);
        assert_eq!(leave.target(), 6);
        assert_eq!(*leave.kind(), CfgEdgeKind::Leave);
    }
}
