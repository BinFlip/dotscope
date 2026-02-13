//! Value range analysis for SSA variables.
//!
//! This module provides interval-based range analysis for tracking the possible
//! values of integer variables. It supports:
//!
//! - **Constant ranges**: `[5, 5]` — exact value known
//! - **Bounded ranges**: `[0, 255]` — value within bounds
//! - **Half-open ranges**: `[0, +∞)` — non-negative values
//! - **Union ranges**: `[0, 10] ∪ [20, 30]` — disjoint intervals
//!
//! # Lattice Structure
//!
//! The `ValueRange` forms a lattice for dataflow analysis:
//!
//! ```text
//!           Top (all values)
//!              |
//!     [MIN, MAX] full range
//!        /    \
//!   [a, b]    [c, d]  bounded ranges
//!        \    /
//!         [x, x]  constant (singleton)
//!           |
//!        Bottom (no values - unreachable)
//! ```
//!
//! # Usage
//!
//! ```rust,no_run
//! use dotscope::analysis::ValueRange;
//!
//! // Create ranges
//! let constant = ValueRange::constant(42);
//! let non_negative = ValueRange::non_negative();
//! let byte_range = ValueRange::bounded(0, 255);
//!
//! // Query ranges
//! assert!(constant.is_constant());
//! assert!(non_negative.is_always_non_negative());
//! assert!(byte_range.always_less_than(256) == Some(true));
//!
//! // Range arithmetic
//! let sum = byte_range.add(&ValueRange::constant(1));
//! assert_eq!(sum.min(), Some(1));
//! assert_eq!(sum.max(), Some(256));
//! ```

use std::cmp::{max, min};
use std::fmt;

/// A range of possible integer values for analysis.
///
/// Represents the set of values a variable might hold at runtime.
/// Used for opaque predicate detection, bounds check elimination,
/// and general range-based optimization.
#[derive(Clone, PartialEq, Eq, Hash, Default)]
pub enum ValueRange {
    /// No possible values (unreachable code).
    Bottom,

    /// A single contiguous interval `[min, max]`.
    Interval(IntervalRange),

    /// A union of disjoint intervals (for precision).
    /// Intervals are sorted by min value and non-overlapping.
    Union(Vec<IntervalRange>),

    /// All values possible (no information).
    #[default]
    Top,
}

/// A single contiguous interval `[min, max]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IntervalRange {
    /// Minimum value (inclusive). `None` means negative infinity.
    pub min: Option<i64>,
    /// Maximum value (inclusive). `None` means positive infinity.
    pub max: Option<i64>,
}

impl IntervalRange {
    /// Creates a new interval range.
    #[must_use]
    pub const fn new(min: Option<i64>, max: Option<i64>) -> Self {
        Self { min, max }
    }

    /// Creates a constant (singleton) interval.
    #[must_use]
    pub const fn constant(value: i64) -> Self {
        Self {
            min: Some(value),
            max: Some(value),
        }
    }

    /// Creates a bounded interval `[min, max]`.
    #[must_use]
    pub const fn bounded(min: i64, max: i64) -> Self {
        Self {
            min: Some(min),
            max: Some(max),
        }
    }

    /// Creates a non-negative interval `[0, +∞)`.
    #[must_use]
    pub const fn non_negative() -> Self {
        Self {
            min: Some(0),
            max: None,
        }
    }

    /// Creates an interval from min to infinity `[min, +∞)`.
    #[must_use]
    pub const fn at_least(min: i64) -> Self {
        Self {
            min: Some(min),
            max: None,
        }
    }

    /// Creates an interval from negative infinity to max `(-∞, max]`.
    #[must_use]
    pub const fn at_most(max: i64) -> Self {
        Self {
            min: None,
            max: Some(max),
        }
    }

    /// Creates a full interval `(-∞, +∞)`.
    #[must_use]
    pub const fn full() -> Self {
        Self {
            min: None,
            max: None,
        }
    }

    /// Returns `true` if this is a constant (singleton) range.
    #[must_use]
    pub fn is_constant(&self) -> bool {
        matches!((self.min, self.max), (Some(a), Some(b)) if a == b)
    }

    /// Returns the constant value if this is a singleton.
    #[must_use]
    pub fn as_constant(&self) -> Option<i64> {
        match (self.min, self.max) {
            (Some(a), Some(b)) if a == b => Some(a),
            _ => None,
        }
    }

    /// Returns `true` if all values in this range are non-negative.
    #[must_use]
    pub fn is_always_non_negative(&self) -> bool {
        self.min.is_some_and(|m| m >= 0)
    }

    /// Returns `true` if all values in this range are positive.
    #[must_use]
    pub fn is_always_positive(&self) -> bool {
        self.min.is_some_and(|m| m > 0)
    }

    /// Returns `true` if all values in this range are negative.
    #[must_use]
    pub fn is_always_negative(&self) -> bool {
        self.max.is_some_and(|m| m < 0)
    }

    /// Returns `true` if all values in this range are non-positive.
    #[must_use]
    pub fn is_always_non_positive(&self) -> bool {
        self.max.is_some_and(|m| m <= 0)
    }

    /// Checks if all values in this range are less than `value`.
    #[must_use]
    pub fn always_less_than(&self, value: i64) -> Option<bool> {
        if let Some(max_val) = self.max {
            if max_val < value {
                return Some(true);
            }
            // If max >= value, then at least one value (max) is NOT < value
            return Some(false);
        }
        if let Some(min_val) = self.min {
            if min_val >= value {
                return Some(false);
            }
        }
        None
    }

    /// Checks if all values in this range are greater than `value`.
    #[must_use]
    pub fn always_greater_than(&self, value: i64) -> Option<bool> {
        if let Some(min_val) = self.min {
            if min_val > value {
                return Some(true);
            }
            // If min <= value, then at least one value (min) is NOT > value
            return Some(false);
        }
        if let Some(max_val) = self.max {
            if max_val <= value {
                return Some(false);
            }
        }
        None
    }

    /// Checks if all values in this range are less than or equal to `value`.
    #[must_use]
    pub fn always_less_equal(&self, value: i64) -> Option<bool> {
        if let Some(max_val) = self.max {
            if max_val <= value {
                return Some(true);
            }
        }
        if let Some(min_val) = self.min {
            if min_val > value {
                return Some(false);
            }
        }
        None
    }

    /// Checks if all values in this range are greater than or equal to `value`.
    #[must_use]
    pub fn always_greater_equal(&self, value: i64) -> Option<bool> {
        if let Some(min_val) = self.min {
            if min_val >= value {
                return Some(true);
            }
        }
        if let Some(max_val) = self.max {
            if max_val < value {
                return Some(false);
            }
        }
        None
    }

    /// Checks if all values in this range equal `value`.
    #[must_use]
    pub fn always_equal_to(&self, value: i64) -> Option<bool> {
        match (self.min, self.max) {
            (Some(min_val), Some(max_val)) => {
                if min_val == max_val && min_val == value {
                    Some(true)
                } else if value < min_val || value > max_val {
                    Some(false)
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// Checks if this range can possibly contain `value`.
    #[must_use]
    pub fn may_contain(&self, value: i64) -> bool {
        let above_min = self.min.is_none_or(|m| value >= m);
        let below_max = self.max.is_none_or(|m| value <= m);
        above_min && below_max
    }

    /// Returns `true` if this interval overlaps with another.
    #[must_use]
    pub fn overlaps(&self, other: &Self) -> bool {
        // Check if intervals are disjoint
        let self_below_other = match (self.max, other.min) {
            (Some(self_max), Some(other_min)) => self_max < other_min,
            _ => false,
        };
        let other_below_self = match (other.max, self.min) {
            (Some(other_max), Some(self_min)) => other_max < self_min,
            _ => false,
        };
        !self_below_other && !other_below_self
    }

    /// Returns `true` if this interval is adjacent to another (can be merged).
    #[must_use]
    pub fn adjacent(&self, other: &Self) -> bool {
        // Check if max + 1 == other.min or other.max + 1 == self.min
        if let (Some(self_max), Some(other_min)) = (self.max, other.min) {
            if self_max.checked_add(1) == Some(other_min) {
                return true;
            }
        }
        if let (Some(other_max), Some(self_min)) = (other.max, self.min) {
            if other_max.checked_add(1) == Some(self_min) {
                return true;
            }
        }
        false
    }

    /// Meet operation: intersection of ranges.
    #[must_use]
    pub fn meet(&self, other: &Self) -> Option<Self> {
        let new_min = match (self.min, other.min) {
            (Some(a), Some(b)) => Some(max(a, b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        };

        let new_max = match (self.max, other.max) {
            (Some(a), Some(b)) => Some(min(a, b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        };

        // Check if result is empty
        if let (Some(min_val), Some(max_val)) = (new_min, new_max) {
            if min_val > max_val {
                return None; // Empty intersection
            }
        }

        Some(Self {
            min: new_min,
            max: new_max,
        })
    }

    /// Join operation: union/hull of ranges (may lose precision).
    #[must_use]
    pub fn join(&self, other: &Self) -> Self {
        let new_min = match (self.min, other.min) {
            (Some(a), Some(b)) => Some(min(a, b)),
            _ => None, // Either unbounded -> result unbounded
        };

        let new_max = match (self.max, other.max) {
            (Some(a), Some(b)) => Some(max(a, b)),
            _ => None, // Either unbounded -> result unbounded
        };

        Self {
            min: new_min,
            max: new_max,
        }
    }

    /// Widen operation for loop fixpoint computation.
    ///
    /// If the bound is growing, extend to infinity.
    #[must_use]
    pub fn widen(&self, other: &Self) -> Self {
        let new_min = match (self.min, other.min) {
            (Some(a), Some(b)) if b < a => None, // Growing down -> -∞
            (min_val, _) => min_val,             // Keep current
        };

        let new_max = match (self.max, other.max) {
            (Some(a), Some(b)) if b > a => None, // Growing up -> +∞
            (max_val, _) => max_val,             // Keep current
        };

        Self {
            min: new_min,
            max: new_max,
        }
    }

    /// Addition of two ranges.
    #[must_use]
    pub fn add(&self, other: &Self) -> Self {
        let new_min = match (self.min, other.min) {
            (Some(a), Some(b)) => a.checked_add(b),
            _ => None,
        };

        let new_max = match (self.max, other.max) {
            (Some(a), Some(b)) => a.checked_add(b),
            _ => None,
        };

        Self {
            min: new_min,
            max: new_max,
        }
    }

    /// Subtraction of two ranges.
    #[must_use]
    pub fn sub(&self, other: &Self) -> Self {
        // [a, b] - [c, d] = [a - d, b - c]
        let new_min = match (self.min, other.max) {
            (Some(a), Some(d)) => a.checked_sub(d),
            _ => None,
        };

        let new_max = match (self.max, other.min) {
            (Some(b), Some(c)) => b.checked_sub(c),
            _ => None,
        };

        Self {
            min: new_min,
            max: new_max,
        }
    }

    /// Multiplication of two ranges.
    #[must_use]
    pub fn mul(&self, other: &Self) -> Self {
        // For multiplication, we need to consider all corner combinations
        // because signs matter
        match (self.min, self.max, other.min, other.max) {
            (Some(a), Some(b), Some(c), Some(d)) => {
                // Compute all four products
                let products = [
                    a.checked_mul(c),
                    a.checked_mul(d),
                    b.checked_mul(c),
                    b.checked_mul(d),
                ];

                // If any overflowed, return unbounded
                if products.iter().any(std::option::Option::is_none) {
                    return Self::full();
                }

                let products: Vec<i64> = products.iter().filter_map(|&p| p).collect();
                let new_min = products.iter().copied().min();
                let new_max = products.iter().copied().max();

                Self {
                    min: new_min,
                    max: new_max,
                }
            }
            _ => Self::full(),
        }
    }

    /// Bitwise AND with constant mask.
    #[must_use]
    pub fn and_constant(&self, mask: i64) -> Self {
        if mask >= 0 {
            // AND with non-negative mask always produces [0, mask]
            Self::bounded(0, mask)
        } else {
            Self::full()
        }
    }

    /// Bitwise OR with constant.
    #[must_use]
    pub fn or_constant(&self, value: i64) -> Self {
        // Hard to compute precisely, be conservative
        if self.is_always_non_negative() && value >= 0 {
            // Both non-negative: result >= max(self.min, value)
            let new_min = max(self.min.unwrap_or(0), value);
            Self {
                min: Some(new_min),
                max: None,
            }
        } else {
            Self::full()
        }
    }
}

impl Default for IntervalRange {
    fn default() -> Self {
        Self::full()
    }
}

impl fmt::Display for IntervalRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.min, self.max) {
            (Some(a), Some(b)) if a == b => write!(f, "{a}"),
            (Some(a), Some(b)) => write!(f, "[{a}, {b}]"),
            (Some(a), None) => write!(f, "[{a}, +∞)"),
            (None, Some(b)) => write!(f, "(-∞, {b}]"),
            (None, None) => write!(f, "(-∞, +∞)"),
        }
    }
}

impl ValueRange {
    /// Creates the bottom element (empty set, unreachable).
    #[must_use]
    pub const fn bottom() -> Self {
        Self::Bottom
    }

    /// Creates the top element (all values, no information).
    #[must_use]
    pub const fn top() -> Self {
        Self::Top
    }

    /// Creates a constant (singleton) range.
    #[must_use]
    pub fn constant(value: i64) -> Self {
        Self::Interval(IntervalRange::constant(value))
    }

    /// Creates a bounded interval `[min, max]`.
    #[must_use]
    pub fn bounded(min_val: i64, max_val: i64) -> Self {
        if min_val > max_val {
            Self::Bottom
        } else {
            Self::Interval(IntervalRange::bounded(min_val, max_val))
        }
    }

    /// Creates a non-negative interval `[0, +∞)`.
    #[must_use]
    pub fn non_negative() -> Self {
        Self::Interval(IntervalRange::non_negative())
    }

    /// Creates an interval from min to infinity `[min, +∞)`.
    #[must_use]
    pub fn at_least(min_val: i64) -> Self {
        Self::Interval(IntervalRange::at_least(min_val))
    }

    /// Creates an interval from negative infinity to max `(-∞, max]`.
    #[must_use]
    pub fn at_most(max_val: i64) -> Self {
        Self::Interval(IntervalRange::at_most(max_val))
    }

    /// Creates a range for non-null references.
    ///
    /// This is semantically different from numeric ranges — it indicates
    /// that a reference is known to be non-null.
    #[must_use]
    pub fn non_null() -> Self {
        // For references, we use a special marker value
        // In practice, non-null is tracked separately, but we can use Top
        // to indicate "some reference value exists"
        Self::Top
    }

    /// Creates a union of two ranges.
    ///
    /// If the ranges overlap or are adjacent, they are merged.
    #[must_use]
    pub fn union(a: Self, b: Self) -> Self {
        match (a, b) {
            (Self::Bottom, other) | (other, Self::Bottom) => other,
            (Self::Top, _) | (_, Self::Top) => Self::Top,
            (Self::Interval(ia), Self::Interval(ib)) => {
                if ia.overlaps(&ib) || ia.adjacent(&ib) {
                    Self::Interval(ia.join(&ib))
                } else {
                    // Sort intervals
                    let (first, second) = if ia.min <= ib.min { (ia, ib) } else { (ib, ia) };
                    Self::Union(vec![first, second])
                }
            }
            (Self::Union(mut intervals), Self::Interval(i))
            | (Self::Interval(i), Self::Union(mut intervals)) => {
                intervals.push(i);
                Self::normalize_union(intervals)
            }
            (Self::Union(mut a_intervals), Self::Union(b_intervals)) => {
                a_intervals.extend(b_intervals);
                Self::normalize_union(a_intervals)
            }
        }
    }

    /// Normalizes a union of intervals (sorts, merges overlapping/adjacent).
    fn normalize_union(mut intervals: Vec<IntervalRange>) -> Self {
        if intervals.is_empty() {
            return Self::Bottom;
        }
        if intervals.len() == 1 {
            return Self::Interval(intervals.remove(0));
        }

        // Sort by min value
        intervals.sort_by(|a, b| match (a.min, b.min) {
            (Some(a_min), Some(b_min)) => a_min.cmp(&b_min),
            (None, Some(_)) => std::cmp::Ordering::Less,
            (Some(_), None) => std::cmp::Ordering::Greater,
            (None, None) => std::cmp::Ordering::Equal,
        });

        // Merge overlapping/adjacent intervals
        let mut merged: Vec<IntervalRange> = Vec::new();
        for interval in intervals {
            if let Some(last) = merged.last_mut() {
                if last.overlaps(&interval) || last.adjacent(&interval) {
                    *last = last.join(&interval);
                    continue;
                }
            }
            merged.push(interval);
        }

        if merged.len() == 1 {
            Self::Interval(merged.remove(0))
        } else {
            Self::Union(merged)
        }
    }

    /// Returns `true` if this is the bottom element (empty set).
    #[must_use]
    pub const fn is_bottom(&self) -> bool {
        matches!(self, Self::Bottom)
    }

    /// Returns `true` if this is the top element (all values).
    #[must_use]
    pub const fn is_top(&self) -> bool {
        matches!(self, Self::Top)
    }

    /// Returns `true` if this is a constant (singleton) range.
    #[must_use]
    pub fn is_constant(&self) -> bool {
        match self {
            Self::Interval(i) => i.is_constant(),
            _ => false,
        }
    }

    /// Returns the constant value if this is a singleton.
    #[must_use]
    pub fn as_constant(&self) -> Option<i64> {
        match self {
            Self::Interval(i) => i.as_constant(),
            _ => None,
        }
    }

    /// Returns the minimum value if bounded below.
    #[must_use]
    pub fn min(&self) -> Option<i64> {
        match self {
            Self::Bottom | Self::Top => None,
            Self::Interval(i) => i.min,
            Self::Union(intervals) => intervals.first().and_then(|i| i.min),
        }
    }

    /// Returns the maximum value if bounded above.
    #[must_use]
    pub fn max(&self) -> Option<i64> {
        match self {
            Self::Bottom | Self::Top => None,
            Self::Interval(i) => i.max,
            Self::Union(intervals) => intervals.last().and_then(|i| i.max),
        }
    }

    /// Returns `true` if all values are non-negative.
    #[must_use]
    pub fn is_always_non_negative(&self) -> bool {
        match self {
            Self::Bottom => true, // Vacuously true
            Self::Top => false,
            Self::Interval(i) => i.is_always_non_negative(),
            Self::Union(intervals) => intervals.iter().all(IntervalRange::is_always_non_negative),
        }
    }

    /// Returns `true` if all values are positive.
    #[must_use]
    pub fn is_always_positive(&self) -> bool {
        match self {
            Self::Bottom => true,
            Self::Top => false,
            Self::Interval(i) => i.is_always_positive(),
            Self::Union(intervals) => intervals.iter().all(IntervalRange::is_always_positive),
        }
    }

    /// Checks if all values are less than `value`.
    #[must_use]
    pub fn always_less_than(&self, value: i64) -> Option<bool> {
        match self {
            Self::Bottom => Some(true), // Vacuously true
            Self::Top => None,
            Self::Interval(i) => i.always_less_than(value),
            Self::Union(intervals) => {
                // All intervals must satisfy
                let results: Vec<_> = intervals
                    .iter()
                    .map(|i| i.always_less_than(value))
                    .collect();
                if results.iter().all(|r| *r == Some(true)) {
                    Some(true)
                } else if results.contains(&Some(false)) {
                    Some(false)
                } else {
                    None
                }
            }
        }
    }

    /// Checks if all values are greater than `value`.
    #[must_use]
    pub fn always_greater_than(&self, value: i64) -> Option<bool> {
        match self {
            Self::Bottom => Some(true),
            Self::Top => None,
            Self::Interval(i) => i.always_greater_than(value),
            Self::Union(intervals) => {
                let results: Vec<_> = intervals
                    .iter()
                    .map(|i| i.always_greater_than(value))
                    .collect();
                if results.iter().all(|r| *r == Some(true)) {
                    Some(true)
                } else if results.contains(&Some(false)) {
                    Some(false)
                } else {
                    None
                }
            }
        }
    }

    /// Checks if all values equal `value`.
    #[must_use]
    pub fn always_equal_to(&self, value: i64) -> Option<bool> {
        match self {
            Self::Bottom => Some(true), // Vacuously true
            Self::Interval(i) => i.always_equal_to(value),
            // Top represents all possible values, Union has multiple disjoint intervals
            Self::Top | Self::Union(_) => None,
        }
    }

    /// Checks if value might be contained in this range.
    #[must_use]
    pub fn may_contain(&self, value: i64) -> bool {
        match self {
            Self::Bottom => false,
            Self::Top => true,
            Self::Interval(i) => i.may_contain(value),
            Self::Union(intervals) => intervals.iter().any(|i| i.may_contain(value)),
        }
    }

    /// Meet operation (intersection) — greatest lower bound.
    ///
    /// Returns the range of values that are in both `self` and `other`.
    #[must_use]
    pub fn meet(&self, other: &Self) -> Self {
        match (self, other) {
            // Bottom absorbs
            (Self::Bottom, _) | (_, Self::Bottom) => Self::Bottom,

            // Top is identity
            (Self::Top, x) | (x, Self::Top) => x.clone(),

            // Interval meet
            (Self::Interval(a), Self::Interval(b)) => match a.meet(b) {
                Some(result) => Self::Interval(result),
                None => Self::Bottom,
            },

            // Union meet: intersect each pair
            (Self::Union(intervals), Self::Interval(i))
            | (Self::Interval(i), Self::Union(intervals)) => {
                let results: Vec<_> = intervals.iter().filter_map(|ui| ui.meet(i)).collect();
                Self::from_intervals(results)
            }

            (Self::Union(a), Self::Union(b)) => {
                let mut results = Vec::new();
                for ai in a {
                    for bi in b {
                        if let Some(r) = ai.meet(bi) {
                            results.push(r);
                        }
                    }
                }
                Self::from_intervals(results)
            }
        }
    }

    /// Join operation (union hull) — least upper bound.
    ///
    /// Returns a range containing all values from both `self` and `other`.
    /// May lose precision (the hull may contain values not in either input).
    #[must_use]
    pub fn join(&self, other: &Self) -> Self {
        match (self, other) {
            // Bottom is identity
            (Self::Bottom, x) | (x, Self::Bottom) => x.clone(),

            // Top absorbs
            (Self::Top, _) | (_, Self::Top) => Self::Top,

            // Interval join: take hull
            (Self::Interval(a), Self::Interval(b)) => Self::Interval(a.join(b)),

            // Union join
            (Self::Union(intervals), Self::Interval(i))
            | (Self::Interval(i), Self::Union(intervals)) => {
                let mut all = intervals.clone();
                all.push(*i);
                Self::normalize_union(all)
            }

            (Self::Union(a), Self::Union(b)) => {
                let mut all = a.clone();
                all.extend(b.iter().copied());
                Self::normalize_union(all)
            }
        }
    }

    /// Widen operation for loop fixpoint computation.
    ///
    /// If bounds are growing, extends to infinity to ensure termination.
    #[must_use]
    pub fn widen(&self, other: &Self) -> Self {
        match (self, other) {
            (Self::Bottom, x) | (x, Self::Bottom) => x.clone(),
            (Self::Top, _) | (_, Self::Top) => Self::Top,
            (Self::Interval(a), Self::Interval(b)) => Self::Interval(a.widen(b)),
            // For unions, widen the hull
            _ => {
                let self_hull = self.hull();
                let other_hull = other.hull();
                match (self_hull, other_hull) {
                    (Self::Interval(a), Self::Interval(b)) => Self::Interval(a.widen(&b)),
                    _ => Self::Top,
                }
            }
        }
    }

    /// Returns the convex hull (single interval containing all values).
    #[must_use]
    pub fn hull(&self) -> Self {
        match self {
            Self::Bottom => Self::Bottom,
            Self::Top => Self::Top,
            Self::Interval(_) => self.clone(),
            Self::Union(intervals) => {
                if intervals.is_empty() {
                    Self::Bottom
                } else {
                    let min_val = intervals.first().and_then(|i| i.min);
                    let max_val = intervals.last().and_then(|i| i.max);
                    Self::Interval(IntervalRange::new(min_val, max_val))
                }
            }
        }
    }

    /// Addition of two ranges.
    #[must_use]
    pub fn add(&self, other: &Self) -> Self {
        self.binary_op(other, IntervalRange::add)
    }

    /// Subtraction of two ranges.
    #[must_use]
    pub fn sub(&self, other: &Self) -> Self {
        self.binary_op(other, IntervalRange::sub)
    }

    /// Multiplication of two ranges.
    #[must_use]
    pub fn mul(&self, other: &Self) -> Self {
        self.binary_op(other, IntervalRange::mul)
    }

    /// Bitwise AND with a constant mask.
    #[must_use]
    pub fn and_constant(&self, mask: i64) -> Self {
        match self {
            Self::Bottom => Self::Bottom,
            Self::Top | Self::Interval(_) | Self::Union(_) => {
                if mask >= 0 {
                    Self::bounded(0, mask)
                } else {
                    Self::Top
                }
            }
        }
    }

    /// Helper for binary operations on ranges.
    fn binary_op<F>(&self, other: &Self, op: F) -> Self
    where
        F: Fn(&IntervalRange, &IntervalRange) -> IntervalRange,
    {
        match (self, other) {
            (Self::Bottom, _) | (_, Self::Bottom) => Self::Bottom,
            (Self::Top, _) | (_, Self::Top) => Self::Top,
            (Self::Interval(a), Self::Interval(b)) => Self::Interval(op(a, b)),
            // For unions, operate on hulls (loses precision but correct)
            _ => {
                let a_hull = self.hull();
                let b_hull = other.hull();
                match (a_hull, b_hull) {
                    (Self::Interval(a), Self::Interval(b)) => Self::Interval(op(&a, &b)),
                    _ => Self::Top,
                }
            }
        }
    }

    /// Creates a range from a list of intervals.
    fn from_intervals(intervals: Vec<IntervalRange>) -> Self {
        if intervals.is_empty() {
            Self::Bottom
        } else {
            Self::normalize_union(intervals)
        }
    }
}

impl fmt::Debug for ValueRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bottom => write!(f, "⊥"),
            Self::Top => write!(f, "⊤"),
            Self::Interval(i) => write!(f, "{i}"),
            Self::Union(intervals) => {
                write!(f, "(")?;
                for (i, interval) in intervals.iter().enumerate() {
                    if i > 0 {
                        write!(f, " ∪ ")?;
                    }
                    write!(f, "{interval}")?;
                }
                write!(f, ")")
            }
        }
    }
}

impl fmt::Display for ValueRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interval_constant() {
        let r = IntervalRange::constant(42);
        assert!(r.is_constant());
        assert_eq!(r.as_constant(), Some(42));
        assert_eq!(r.min, Some(42));
        assert_eq!(r.max, Some(42));
    }

    #[test]
    fn test_interval_bounded() {
        let r = IntervalRange::bounded(0, 255);
        assert!(!r.is_constant());
        assert_eq!(r.as_constant(), None);
        assert!(r.is_always_non_negative());
        assert!(!r.is_always_positive());
        assert!(r.may_contain(0));
        assert!(r.may_contain(255));
        assert!(!r.may_contain(256));
        assert!(!r.may_contain(-1));
    }

    #[test]
    fn test_interval_non_negative() {
        let r = IntervalRange::non_negative();
        assert!(r.is_always_non_negative());
        assert!(!r.is_always_positive());
        assert_eq!(r.always_less_than(0), Some(false));
        assert_eq!(r.always_greater_equal(0), Some(true));
    }

    #[test]
    fn test_interval_comparisons() {
        let r = IntervalRange::bounded(5, 10);

        // always_less_than: "are ALL values in range < X?"
        assert_eq!(r.always_less_than(11), Some(true)); // All of [5,10] < 11
        assert_eq!(r.always_less_than(10), Some(false)); // 10 is not < 10
        assert_eq!(r.always_less_than(5), Some(false)); // 5,6,7,8,9,10 are not all < 5
        assert_eq!(r.always_less_than(8), Some(false)); // 8,9,10 are not < 8

        // always_greater_than: "are ALL values in range > X?"
        assert_eq!(r.always_greater_than(4), Some(true)); // All of [5,10] > 4
        assert_eq!(r.always_greater_than(5), Some(false)); // 5 is not > 5
        assert_eq!(r.always_greater_than(10), Some(false)); // 5,6,7,8,9 are not > 10
        assert_eq!(r.always_greater_than(7), Some(false)); // 5,6,7 are not > 7

        // always_equal_to
        let c = IntervalRange::constant(5);
        assert_eq!(c.always_equal_to(5), Some(true));
        assert_eq!(c.always_equal_to(6), Some(false));
        assert_eq!(r.always_equal_to(5), None); // Range [5,10] might equal 5 (but not always)

        // Unbounded ranges
        let unbounded = IntervalRange::full();
        assert_eq!(unbounded.always_less_than(0), None); // Cannot determine
        assert_eq!(unbounded.always_greater_than(0), None);
    }

    #[test]
    fn test_interval_meet() {
        let a = IntervalRange::bounded(0, 10);
        let b = IntervalRange::bounded(5, 15);
        let meet = a.meet(&b).unwrap();
        assert_eq!(meet.min, Some(5));
        assert_eq!(meet.max, Some(10));

        // Disjoint intervals
        let c = IntervalRange::bounded(0, 5);
        let d = IntervalRange::bounded(10, 15);
        assert!(c.meet(&d).is_none());
    }

    #[test]
    fn test_interval_join() {
        let a = IntervalRange::bounded(0, 10);
        let b = IntervalRange::bounded(5, 15);
        let join = a.join(&b);
        assert_eq!(join.min, Some(0));
        assert_eq!(join.max, Some(15));
    }

    #[test]
    fn test_interval_widen() {
        let a = IntervalRange::bounded(0, 10);
        let b = IntervalRange::bounded(0, 20); // Growing up
        let widen = a.widen(&b);
        assert_eq!(widen.min, Some(0));
        assert_eq!(widen.max, None); // Widened to +∞

        let c = IntervalRange::bounded(5, 10);
        let d = IntervalRange::bounded(0, 10); // Growing down
        let widen2 = c.widen(&d);
        assert_eq!(widen2.min, None); // Widened to -∞
        assert_eq!(widen2.max, Some(10));
    }

    #[test]
    fn test_interval_arithmetic() {
        let a = IntervalRange::bounded(1, 5);
        let b = IntervalRange::bounded(2, 3);

        // Add: [1,5] + [2,3] = [3,8]
        let sum = a.add(&b);
        assert_eq!(sum.min, Some(3));
        assert_eq!(sum.max, Some(8));

        // Sub: [1,5] - [2,3] = [1-3, 5-2] = [-2, 3]
        let diff = a.sub(&b);
        assert_eq!(diff.min, Some(-2));
        assert_eq!(diff.max, Some(3));

        // Mul: [1,5] * [2,3] = [2, 15]
        let prod = a.mul(&b);
        assert_eq!(prod.min, Some(2));
        assert_eq!(prod.max, Some(15));
    }

    #[test]
    fn test_interval_mul_with_negatives() {
        let a = IntervalRange::bounded(-2, 3);
        let b = IntervalRange::bounded(-1, 4);

        // Products: (-2)*(-1)=2, (-2)*4=-8, 3*(-1)=-3, 3*4=12
        // Range: [-8, 12]
        let prod = a.mul(&b);
        assert_eq!(prod.min, Some(-8));
        assert_eq!(prod.max, Some(12));
    }

    #[test]
    fn test_interval_and_constant() {
        let r = IntervalRange::bounded(0, 1000);
        let masked = r.and_constant(0xFF);
        assert_eq!(masked.min, Some(0));
        assert_eq!(masked.max, Some(255));
    }

    #[test]
    fn test_range_constant() {
        let r = ValueRange::constant(42);
        assert!(r.is_constant());
        assert_eq!(r.as_constant(), Some(42));
        assert!(!r.is_bottom());
        assert!(!r.is_top());
    }

    #[test]
    fn test_range_bounded() {
        let r = ValueRange::bounded(0, 255);
        assert!(!r.is_constant());
        assert!(r.is_always_non_negative());
        assert_eq!(r.min(), Some(0));
        assert_eq!(r.max(), Some(255));
    }

    #[test]
    fn test_range_invalid_bounded() {
        let r = ValueRange::bounded(10, 5); // min > max
        assert!(r.is_bottom());
    }

    #[test]
    fn test_range_lattice_meet() {
        // Top is identity
        let a = ValueRange::bounded(0, 10);
        assert_eq!(a.meet(&ValueRange::top()), a);
        assert_eq!(ValueRange::top().meet(&a), a);

        // Bottom absorbs
        assert!(a.meet(&ValueRange::bottom()).is_bottom());
        assert!(ValueRange::bottom().meet(&a).is_bottom());

        // Interval intersection
        let b = ValueRange::bounded(5, 15);
        let meet = a.meet(&b);
        assert_eq!(meet.min(), Some(5));
        assert_eq!(meet.max(), Some(10));

        // Disjoint -> bottom
        let c = ValueRange::bounded(20, 30);
        assert!(a.meet(&c).is_bottom());
    }

    #[test]
    fn test_range_lattice_join() {
        // Bottom is identity
        let a = ValueRange::bounded(0, 10);
        assert_eq!(a.join(&ValueRange::bottom()), a);
        assert_eq!(ValueRange::bottom().join(&a), a);

        // Top absorbs
        assert!(a.join(&ValueRange::top()).is_top());
        assert!(ValueRange::top().join(&a).is_top());

        // Interval hull
        let b = ValueRange::bounded(5, 15);
        let join = a.join(&b);
        assert_eq!(join.min(), Some(0));
        assert_eq!(join.max(), Some(15));
    }

    #[test]
    fn test_range_union() {
        let a = ValueRange::bounded(0, 5);
        let b = ValueRange::bounded(10, 15);
        let union = ValueRange::union(a, b);

        // Should be a union, not merged
        assert!(matches!(union, ValueRange::Union(_)));
        assert!(union.may_contain(3));
        assert!(union.may_contain(12));
        assert!(!union.may_contain(7)); // Gap

        // Adjacent ranges merge
        let c = ValueRange::bounded(0, 5);
        let d = ValueRange::bounded(6, 10);
        let merged = ValueRange::union(c, d);
        assert!(matches!(merged, ValueRange::Interval(_)));
        assert_eq!(merged.min(), Some(0));
        assert_eq!(merged.max(), Some(10));

        // Overlapping ranges merge
        let e = ValueRange::bounded(0, 7);
        let f = ValueRange::bounded(5, 10);
        let merged2 = ValueRange::union(e, f);
        assert!(matches!(merged2, ValueRange::Interval(_)));
        assert_eq!(merged2.min(), Some(0));
        assert_eq!(merged2.max(), Some(10));
    }

    #[test]
    fn test_range_widen() {
        let a = ValueRange::bounded(0, 10);
        let b = ValueRange::bounded(0, 20); // Growing up
        let widen = a.widen(&b);
        assert_eq!(widen.min(), Some(0));
        assert_eq!(widen.max(), None); // Widened to +∞

        let c = ValueRange::bounded(5, 10);
        let d = ValueRange::bounded(0, 10); // Growing down
        let widen2 = c.widen(&d);
        assert_eq!(widen2.min(), None); // Widened to -∞
        assert_eq!(widen2.max(), Some(10));
    }

    #[test]
    fn test_range_arithmetic() {
        let a = ValueRange::bounded(1, 5);
        let b = ValueRange::bounded(2, 3);

        let sum = a.add(&b);
        assert_eq!(sum.min(), Some(3));
        assert_eq!(sum.max(), Some(8));

        let diff = a.sub(&b);
        assert_eq!(diff.min(), Some(-2));
        assert_eq!(diff.max(), Some(3));

        let prod = a.mul(&b);
        assert_eq!(prod.min(), Some(2));
        assert_eq!(prod.max(), Some(15));
    }

    #[test]
    fn test_range_and_constant_mask() {
        let r = ValueRange::bounded(0, 1000);
        let masked = r.and_constant(0xFF);
        assert_eq!(masked.min(), Some(0));
        assert_eq!(masked.max(), Some(255));

        // Top with mask
        let top_masked = ValueRange::top().and_constant(0x0F);
        assert_eq!(top_masked.min(), Some(0));
        assert_eq!(top_masked.max(), Some(15));
    }

    #[test]
    fn test_range_comparison_queries() {
        let r = ValueRange::bounded(5, 10);

        // always_less_than: "are ALL values in range < X?"
        assert_eq!(r.always_less_than(11), Some(true)); // All of [5,10] < 11
        assert_eq!(r.always_less_than(5), Some(false)); // 5..10 are not all < 5
        assert_eq!(r.always_less_than(8), Some(false)); // 8,9,10 are not < 8

        // always_greater_than: "are ALL values in range > X?"
        assert_eq!(r.always_greater_than(4), Some(true)); // All of [5,10] > 4
        assert_eq!(r.always_greater_than(10), Some(false)); // 5..10 are not all > 10
        assert_eq!(r.always_greater_than(7), Some(false)); // 5,6,7 are not > 7
    }

    #[test]
    fn test_range_always_non_negative() {
        assert!(ValueRange::non_negative().is_always_non_negative());
        assert!(ValueRange::bounded(0, 100).is_always_non_negative());
        assert!(ValueRange::at_least(5).is_always_non_negative());
        assert!(!ValueRange::bounded(-5, 100).is_always_non_negative());
        assert!(!ValueRange::top().is_always_non_negative());
        assert!(ValueRange::bottom().is_always_non_negative()); // Vacuously true
    }

    #[test]
    fn test_range_display() {
        assert_eq!(format!("{}", ValueRange::bottom()), "⊥");
        assert_eq!(format!("{}", ValueRange::top()), "⊤");
        assert_eq!(format!("{}", ValueRange::constant(42)), "42");
        assert_eq!(format!("{}", ValueRange::bounded(0, 10)), "[0, 10]");
        assert_eq!(format!("{}", ValueRange::non_negative()), "[0, +∞)");
        assert_eq!(format!("{}", ValueRange::at_most(10)), "(-∞, 10]");
    }

    #[test]
    fn test_range_union_display() {
        let union = ValueRange::union(ValueRange::bounded(0, 5), ValueRange::bounded(10, 15));
        let s = format!("{union}");
        assert!(s.contains("∪"));
        assert!(s.contains("[0, 5]"));
        assert!(s.contains("[10, 15]"));
    }
}
