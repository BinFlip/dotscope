//! A bit vector for efficient set operations.
//!
//! This module provides a compact bit set implementation optimized for
//! set operations commonly used in data flow analysis and other algorithms
//! that track sets of entities identified by small integers.
//!
//! # Features
//!
//! - Efficient storage: 64 elements per word
//! - Set operations: union, intersection, difference
//! - Iteration over set elements
//! - Clone-on-write friendly design
//!
//! # Example
//!
//! ```rust,ignore
//! use dotscope::utils::BitSet;
//!
//! let mut set = BitSet::new(100);
//! set.insert(0);
//! set.insert(50);
//! set.insert(99);
//!
//! assert!(set.contains(50));
//! assert_eq!(set.count(), 3);
//!
//! for idx in set.iter() {
//!     println!("Set contains: {}", idx);
//! }
//! ```

/// A bit vector for efficient set operations.
///
/// This is commonly used for analyses that track sets of definitions,
/// variables, or other entities identified by small integers.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct BitSet {
    /// The bits, stored as a vector of words.
    words: Vec<u64>,
    /// The number of bits in the set.
    len: usize,
}

impl BitSet {
    /// Creates a new empty bit set with the given capacity.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        let num_words = capacity.div_ceil(64);
        Self {
            words: vec![0; num_words],
            len: capacity,
        }
    }

    /// Creates a new bit set with all bits set.
    #[must_use]
    pub fn full(capacity: usize) -> Self {
        let num_words = capacity.div_ceil(64);
        let mut words = vec![u64::MAX; num_words];

        // Clear the excess bits in the last word
        if !capacity.is_multiple_of(64) {
            if let Some(last) = words.last_mut() {
                *last = (1u64 << (capacity % 64)) - 1;
            }
        }

        Self {
            words,
            len: capacity,
        }
    }

    /// Returns the capacity of this bit set.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` if the bit set has no bits set.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.words.iter().all(|&w| w == 0)
    }

    /// Sets the bit at the given index.
    ///
    /// # Panics
    ///
    /// Panics if `index >= self.len()`.
    pub fn insert(&mut self, index: usize) {
        assert!(index < self.len, "index out of bounds");
        let word = index / 64;
        let bit = index % 64;
        self.words[word] |= 1u64 << bit;
    }

    /// Clears the bit at the given index.
    ///
    /// # Panics
    ///
    /// Panics if `index >= self.len()`.
    pub fn remove(&mut self, index: usize) {
        assert!(index < self.len, "index out of bounds");
        let word = index / 64;
        let bit = index % 64;
        self.words[word] &= !(1u64 << bit);
    }

    /// Returns `true` if the bit at the given index is set.
    ///
    /// # Panics
    ///
    /// Panics if `index >= self.len()`.
    #[must_use]
    pub fn contains(&self, index: usize) -> bool {
        assert!(index < self.len, "index out of bounds");
        let word = index / 64;
        let bit = index % 64;
        (self.words[word] & (1u64 << bit)) != 0
    }

    /// Returns the number of bits set.
    #[must_use]
    pub fn count(&self) -> usize {
        self.words.iter().map(|w| w.count_ones() as usize).sum()
    }

    /// Clears all bits.
    pub fn clear(&mut self) {
        for word in &mut self.words {
            *word = 0;
        }
    }

    /// Sets all bits.
    pub fn fill(&mut self) {
        for word in &mut self.words {
            *word = u64::MAX;
        }
        // Clear excess bits in last word
        if !self.len.is_multiple_of(64) {
            if let Some(last) = self.words.last_mut() {
                *last = (1u64 << (self.len % 64)) - 1;
            }
        }
    }

    /// Computes the union with another bit set (in place).
    ///
    /// Returns `true` if `self` changed.
    pub fn union_with(&mut self, other: &Self) -> bool {
        assert_eq!(self.len, other.len, "bit sets must have same length");
        let mut changed = false;
        for (a, b) in self.words.iter_mut().zip(other.words.iter()) {
            let old = *a;
            *a |= *b;
            changed |= old != *a;
        }
        changed
    }

    /// Computes the intersection with another bit set (in place).
    ///
    /// Returns `true` if `self` changed.
    pub fn intersect_with(&mut self, other: &Self) -> bool {
        assert_eq!(self.len, other.len, "bit sets must have same length");
        let mut changed = false;
        for (a, b) in self.words.iter_mut().zip(other.words.iter()) {
            let old = *a;
            *a &= *b;
            changed |= old != *a;
        }
        changed
    }

    /// Computes the difference with another bit set (in place).
    ///
    /// Removes all bits that are set in `other` from `self`.
    /// Returns `true` if `self` changed.
    pub fn difference_with(&mut self, other: &Self) -> bool {
        assert_eq!(self.len, other.len, "bit sets must have same length");
        let mut changed = false;
        for (a, b) in self.words.iter_mut().zip(other.words.iter()) {
            let old = *a;
            *a &= !*b;
            changed |= old != *a;
        }
        changed
    }

    /// Returns an iterator over the indices of set bits.
    pub fn iter(&self) -> BitSetIter<'_> {
        BitSetIter {
            set: self,
            word_idx: 0,
            bit_idx: 0,
        }
    }
}

impl std::fmt::Debug for BitSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{{")?;
        let mut first = true;
        for i in self.iter() {
            if !first {
                write!(f, ", ")?;
            }
            write!(f, "{i}")?;
            first = false;
        }
        write!(f, "}}")
    }
}

/// Iterator over the set bits in a `BitSet`.
pub struct BitSetIter<'a> {
    set: &'a BitSet,
    word_idx: usize,
    bit_idx: usize,
}

impl Iterator for BitSetIter<'_> {
    type Item = usize;

    fn next(&mut self) -> Option<Self::Item> {
        while self.word_idx < self.set.words.len() {
            let word = self.set.words[self.word_idx];
            while self.bit_idx < 64 {
                let idx = self.word_idx * 64 + self.bit_idx;
                if idx >= self.set.len {
                    return None;
                }
                self.bit_idx += 1;
                if (word & (1u64 << (self.bit_idx - 1))) != 0 {
                    return Some(idx);
                }
            }
            self.word_idx += 1;
            self.bit_idx = 0;
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bitset_basic() {
        let mut bs = BitSet::new(100);
        assert!(bs.is_empty());
        assert_eq!(bs.count(), 0);

        bs.insert(0);
        bs.insert(50);
        bs.insert(99);

        assert!(!bs.is_empty());
        assert_eq!(bs.count(), 3);
        assert!(bs.contains(0));
        assert!(bs.contains(50));
        assert!(bs.contains(99));
        assert!(!bs.contains(1));
    }

    #[test]
    fn test_bitset_remove() {
        let mut bs = BitSet::new(100);
        bs.insert(42);
        assert!(bs.contains(42));

        bs.remove(42);
        assert!(!bs.contains(42));
    }

    #[test]
    fn test_bitset_full() {
        let bs = BitSet::full(100);
        assert_eq!(bs.count(), 100);
        for i in 0..100 {
            assert!(bs.contains(i), "bit {i} should be set");
        }
    }

    #[test]
    fn test_bitset_union() {
        let mut a = BitSet::new(100);
        let mut b = BitSet::new(100);

        a.insert(0);
        a.insert(1);
        b.insert(1);
        b.insert(2);

        let changed = a.union_with(&b);
        assert!(changed);
        assert!(a.contains(0));
        assert!(a.contains(1));
        assert!(a.contains(2));
        assert_eq!(a.count(), 3);
    }

    #[test]
    fn test_bitset_intersect() {
        let mut a = BitSet::new(100);
        let mut b = BitSet::new(100);

        a.insert(0);
        a.insert(1);
        a.insert(2);
        b.insert(1);
        b.insert(2);
        b.insert(3);

        let changed = a.intersect_with(&b);
        assert!(changed);
        assert!(!a.contains(0));
        assert!(a.contains(1));
        assert!(a.contains(2));
        assert!(!a.contains(3));
        assert_eq!(a.count(), 2);
    }

    #[test]
    fn test_bitset_difference() {
        let mut a = BitSet::new(100);
        let mut b = BitSet::new(100);

        a.insert(0);
        a.insert(1);
        a.insert(2);
        b.insert(1);

        let changed = a.difference_with(&b);
        assert!(changed);
        assert!(a.contains(0));
        assert!(!a.contains(1));
        assert!(a.contains(2));
        assert_eq!(a.count(), 2);
    }

    #[test]
    fn test_bitset_iter() {
        let mut bs = BitSet::new(100);
        bs.insert(5);
        bs.insert(42);
        bs.insert(99);

        let bits: Vec<_> = bs.iter().collect();
        assert_eq!(bits, vec![5, 42, 99]);
    }

    #[test]
    fn test_bitset_clear_fill() {
        let mut bs = BitSet::new(100);
        bs.insert(50);
        assert_eq!(bs.count(), 1);

        bs.clear();
        assert!(bs.is_empty());

        bs.fill();
        assert_eq!(bs.count(), 100);
    }
}
