//! Lattice traits for data flow analysis.
//!
//! A lattice is a mathematical structure that defines how abstract values
//! combine at control flow join points. This module provides the fundamental
//! traits that analysis domains must implement.
//!
//! # Lattice Theory Background
//!
//! For data flow analysis, we use lattices with the following properties:
//!
//! - **Partial Order**: Elements can be compared (≤)
//! - **Meet (∧)**: Greatest lower bound of two elements
//! - **Join (∨)**: Least upper bound of two elements
//! - **Top (⊤)**: Greatest element (no information)
//! - **Bottom (⊥)**: Least element (conflicting/all information)
//!
//! # Forward vs Backward Analysis
//!
//! - **Forward analysis** (e.g., reaching definitions): Uses meet at join points
//! - **Backward analysis** (e.g., liveness): Uses join at split points
//!
//! The solver automatically selects the appropriate operation based on
//! analysis direction.

use std::fmt::Debug;

use crate::utils::BitSet;

/// A meet semi-lattice with a meet (greatest lower bound) operation.
///
/// The meet operation combines information from multiple control flow paths.
/// It must satisfy:
///
/// - **Idempotent**: `x.meet(x) = x`
/// - **Commutative**: `x.meet(y) = y.meet(x)`
/// - **Associative**: `x.meet(y.meet(z)) = (x.meet(y)).meet(z)`
///
/// # Examples
///
/// ```rust,ignore
/// use dotscope::analysis::dataflow::MeetSemiLattice;
///
/// impl MeetSemiLattice for ConstantLattice {
///     fn meet(&self, other: &Self) -> Self {
///         match (self, other) {
///             (Self::Top, x) | (x, Self::Top) => x.clone(),
///             (Self::Const(a), Self::Const(b)) if a == b => Self::Const(*a),
///             _ => Self::Bottom,
///         }
///     }
/// }
/// ```
pub trait MeetSemiLattice: Clone + Debug + PartialEq {
    /// Computes the meet (greatest lower bound) of two lattice elements.
    ///
    /// The meet represents combining information from two paths that merge.
    #[must_use]
    fn meet(&self, other: &Self) -> Self;

    /// Returns `true` if this is the bottom element.
    ///
    /// The bottom element represents "all information" or "conflict".
    /// Once bottom is reached, further meets cannot change the value.
    fn is_bottom(&self) -> bool;
}

/// A join semi-lattice with a join (least upper bound) operation.
///
/// The join operation combines information when paths split (for backward analysis)
/// or when we want to widen the approximation.
///
/// It must satisfy:
///
/// - **Idempotent**: `x.join(x) = x`
/// - **Commutative**: `x.join(y) = y.join(x)`
/// - **Associative**: `x.join(y.join(z)) = (x.join(y)).join(z)`
pub trait JoinSemiLattice: Clone + Debug + PartialEq {
    /// Computes the join (least upper bound) of two lattice elements.
    ///
    /// The join represents the least specific value that covers both inputs.
    #[must_use]
    fn join(&self, other: &Self) -> Self;

    /// Returns `true` if this is the top element.
    ///
    /// The top element represents "no information" or "unknown".
    /// It is the identity for meet: `x.meet(top) = x`.
    fn is_top(&self) -> bool;
}

/// A complete lattice with both meet and join operations.
///
/// Most data flow analyses operate over complete lattices, which have
/// both a greatest and least element, plus meet and join operations.
///
/// # Required Properties
///
/// - All properties of `MeetSemiLattice` and `JoinSemiLattice`
/// - **Absorption**: `x.meet(x.join(y)) = x` and `x.join(x.meet(y)) = x`
pub trait Lattice: MeetSemiLattice + JoinSemiLattice {
    /// Returns the top (⊤) element of the lattice.
    ///
    /// Top represents "no information" and is the identity for meet.
    fn top() -> Self;

    /// Returns the bottom (⊥) element of the lattice.
    ///
    /// Bottom represents "all information" or "conflict".
    fn bottom() -> Self;
}

// Lattice trait implementations for BitSet (defined in crate::utils::bitset)

impl MeetSemiLattice for BitSet {
    /// Meet is union for reaching definitions (may analysis).
    fn meet(&self, other: &Self) -> Self {
        let mut result = self.clone();
        result.union_with(other);
        result
    }

    fn is_bottom(&self) -> bool {
        // For may analysis, bottom is full set
        self.count() == self.len()
    }
}

impl JoinSemiLattice for BitSet {
    /// Join is intersection for reaching definitions.
    fn join(&self, other: &Self) -> Self {
        let mut result = self.clone();
        result.intersect_with(other);
        result
    }

    fn is_top(&self) -> bool {
        self.is_empty()
    }
}
