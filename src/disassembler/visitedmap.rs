//! Bitfield map for tracking visited bytes during disassembly and analysis.
//!
//! This module provides a thread-safe, memory-efficient mechanism for tracking which bytes
//! or regions of a file have been processed during disassembly operations. The implementation
//! uses compact bitfield storage with atomic operations to enable concurrent analysis while
//! preventing redundant processing and identifying unanalyzed regions.
//!
//! # Architecture
//!
//! The module centers around the [`crate::disassembler::visitedmap::VisitedMap`] struct, which
//! implements a thread-safe bitfield where each bit represents the visited state of one byte.
//! The underlying storage uses atomic operations on `usize` chunks for efficient concurrent
//! access while maintaining an 8:1 compression ratio compared to byte-per-byte tracking.
//!
//! # Key Components
//!
//! - [`crate::disassembler::visitedmap::VisitedMap`] - Main bitfield structure for tracking visited state
//! - [`crate::disassembler::visitedmap::VisitedMap::new`] - Constructor for creating tracking maps
//! - [`crate::disassembler::visitedmap::VisitedMap::get`] - Query visited state of individual bytes
//! - [`crate::disassembler::visitedmap::VisitedMap::set`] - Mark individual bytes as visited/unvisited
//! - [`crate::disassembler::visitedmap::VisitedMap::set_range`] - Efficiently mark byte ranges
//!
//! # Usage Examples
//!
//! ```rust,ignore
//! use std::sync::Arc;
//! use dotscope::disassembler::VisitedMap;
//!
//! // Create a visited map for tracking 1024 bytes
//! let visited = Arc::new(VisitedMap::new(1024));
//!
//! // Mark byte 100 as visited
//! visited.set(100, true);
//!
//! // Check if byte 100 has been visited
//! assert!(visited.get(100));
//!
//! // Mark a range of bytes as visited
//! visited.set_range(200, true, 10);
//!
//! // Find unvisited regions
//! let unvisited_count = visited.get_range(0);
//! println!("Found {} consecutive unvisited bytes", unvisited_count);
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Thread Safety
//!
//! All operations are thread-safe and can be performed concurrently across multiple threads.
//! The implementation uses atomic operations with appropriate memory ordering to ensure
//! data consistency without requiring external synchronization.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::disassembler::decoder`] - Uses visited maps to coordinate parallel disassembly
//! - [`crate::disassembler::block`] - Tracks which instruction regions have been processed

use std::sync::atomic::{AtomicUsize, Ordering};

/// Thread-safe bitfield for tracking visited bytes during disassembly operations.
///
/// This structure efficiently tracks which bytes of a file have been processed during analysis,
/// helping to avoid duplicate processing and identify unanalyzed regions. It uses a compact
/// bitfield representation where each bit corresponds to one byte in the target data.
///
/// # Thread Safety
///
/// The [`crate::disassembler::visitedmap::VisitedMap`] is thread-safe and can be shared across multiple threads for parallel
/// disassembly operations. It uses atomic operations for thread-safe access to the bitfield data,
/// making it suitable for concurrent analysis scenarios.
///
/// # Examples
///
/// ```rust,ignore
/// use std::sync::Arc;
/// use dotscope::disassembler::VisitedMap;
///
/// // Create a visited map for tracking 1024 bytes
/// let visited = Arc::new(VisitedMap::new(1024));
///
/// // Mark byte 100 as visited
/// visited.set(100, true);
///
/// // Check if byte 100 has been visited
/// assert!(visited.get(100));
///
/// // Check if byte 101 has been visited
/// assert!(!visited.get(101));
/// # Ok::<(), dotscope::Error>(())
/// ```
pub struct VisitedMap {
    /// Atomic bitfield data storing visit status
    data: Vec<AtomicUsize>,
    /// Number of byte positions that can be tracked
    elements: usize,
    /// Size of each bitfield element in bits
    bitfield_size: usize,
}

impl VisitedMap {
    /// Creates a new [`crate::disassembler::visitedmap::VisitedMap`] for tracking the specified number of bytes.
    ///
    /// Allocates and initializes a bitfield capable of tracking `elements` number of bytes.
    /// All bytes are initially marked as unvisited.
    ///
    /// # Arguments
    ///
    /// * `elements` - The number of bytes to track (must be > 0 for useful operation)
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::disassembler::VisitedMap;
    ///
    /// // Create a map for tracking 8192 bytes
    /// let visited_map = VisitedMap::new(8192);
    /// assert_eq!(visited_map.len(), 8192);
    /// assert!(!visited_map.get(0)); // Initially unvisited
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn new(elements: usize) -> VisitedMap {
        let bitfield_size = std::mem::size_of::<usize>() * 8;
        let num_bitfields = elements.div_ceil(bitfield_size);

        let mut data = Vec::with_capacity(num_bitfields);
        for _ in 0..num_bitfields {
            data.push(AtomicUsize::new(0));
        }

        VisitedMap {
            data,
            elements,
            bitfield_size,
        }
    }

    /// Returns the maximum number of elements this instance can track.
    ///
    /// This value was set during construction and represents the total number
    /// of bytes that can be tracked by this visited map.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::disassembler::VisitedMap;
    ///
    /// let visited_map = VisitedMap::new(1024);
    /// assert_eq!(visited_map.len(), 1024);
    /// ```
    pub fn len(&self) -> usize {
        self.elements
    }

    /// Checks if the visited map is empty (has no trackable elements).
    ///
    /// Returns `true` if this map was created to track zero elements,
    /// making it effectively unusable for tracking purposes.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::disassembler::VisitedMap;
    ///
    /// let empty_map = VisitedMap::new(0);
    /// assert!(empty_map.is_empty());
    ///
    /// let normal_map = VisitedMap::new(100);
    /// assert!(!normal_map.is_empty());
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn is_empty(&self) -> bool {
        self.elements == 0
    }

    /// Checks if a specific byte has been marked as visited.
    ///
    /// Returns `true` if the byte at the specified index has been marked as visited,
    /// `false` otherwise. For indices beyond the trackable range, returns `false`.
    ///
    /// # Arguments
    ///
    /// * `element` - The byte index to check (0-based)
    ///
    /// # Returns
    ///
    /// `true` if the byte has been visited, `false` if unvisited or out of bounds.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::disassembler::VisitedMap;
    ///
    /// let visited_map = VisitedMap::new(100);
    ///
    /// // Initially unvisited
    /// assert!(!visited_map.get(50));
    ///
    /// // Mark as visited
    /// visited_map.set(50, true);
    /// assert!(visited_map.get(50));
    ///
    /// // Out of bounds returns false
    /// assert!(!visited_map.get(200));
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn get(&self, element: usize) -> bool {
        if element > self.elements {
            return false;
        }

        if let Some(bitfield) = self.data.get(element / self.bitfield_size) {
            let shift_amount = u32::try_from(element % self.bitfield_size).unwrap_or(0);
            let current_value = bitfield.load(Ordering::Acquire);
            return (current_value.wrapping_shr(shift_amount) & 1_usize) != 0;
        }

        false
    }

    /// Returns the number of consecutive unvisited elements starting from the specified position.
    ///
    /// Counts how many consecutive bytes starting from `element` are marked as unvisited.
    /// This is useful for finding the size of unanalyzed regions in a file.
    ///
    /// # Arguments
    ///
    /// * `element` - The starting byte index to begin counting from (0-based)
    ///
    /// # Returns
    ///
    /// The number of consecutive unvisited bytes starting from the specified element.
    /// Returns 0 if the starting element is out of bounds or already visited.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::disassembler::VisitedMap;
    ///
    /// let visited_map = VisitedMap::new(100);
    ///
    /// // Mark some bytes as visited
    /// visited_map.set(10, true);
    /// visited_map.set(11, true);
    ///
    /// // Check unvisited range from start
    /// let unvisited_count = visited_map.get_range(0);
    /// assert_eq!(unvisited_count, 10); // Bytes 0-9 are unvisited
    ///
    /// // Check from a visited position
    /// assert_eq!(visited_map.get_range(10), 0); // Position 10 is visited
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn get_range(&self, element: usize) -> usize {
        if element > self.elements {
            return 0;
        }

        let mut counter = 0;

        while let Some(bitfield) = self.data.get((element + counter) / self.bitfield_size) {
            let current_value = bitfield.load(Ordering::Acquire);
            if current_value == usize::MAX {
                counter += self.bitfield_size;
            } else {
                let shift_amount =
                    u32::try_from((element + counter) % self.bitfield_size).unwrap_or(0);
                if (current_value.wrapping_shr(shift_amount) & 1_usize) == 0 {
                    counter += 1;
                } else {
                    break;
                }
            }
        }

        counter
    }

    /// Finds the first byte that matches the specified visited state.
    ///
    /// Searches through the visited map to find the first byte that is either
    /// visited or unvisited, depending on the `visited` parameter. This is useful
    /// for finding the next region to analyze or the first processed region.
    ///
    /// # Arguments
    ///
    /// * `visited` - If `true`, searches for the first visited byte; if `false`, searches for the first unvisited byte
    ///
    /// # Returns
    ///
    /// The index of the first byte matching the requested state, or 0 if no matching byte is found.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::disassembler::VisitedMap;
    ///
    /// let visited_map = VisitedMap::new(100);
    ///
    /// // Initially, first unvisited byte is at index 0
    /// assert_eq!(visited_map.get_first(false), 0);
    ///
    /// // Mark first few bytes as visited
    /// visited_map.set_range(0, true, 5);
    ///
    /// // Now first unvisited byte is at index 5
    /// assert_eq!(visited_map.get_first(false), 5);
    ///
    /// // First visited byte is at index 0
    /// assert_eq!(visited_map.get_first(true), 0);
    /// ```
    pub fn get_first(&self, visited: bool) -> usize {
        let mut counter = 0;

        while let Some(bitfield) = self.data.get(counter / self.bitfield_size) {
            let current_value = bitfield.load(Ordering::Acquire);
            if visited {
                if current_value == usize::MAX {
                    return counter;
                } else if current_value == 0 {
                    counter += self.bitfield_size;
                } else {
                    let shift_amount = u32::try_from(counter % self.bitfield_size).unwrap_or(0);
                    if (current_value.wrapping_shr(shift_amount) & 1_usize) == 0 {
                        counter += 1;
                    } else {
                        return counter;
                    }
                }
            } else if current_value == 0 {
                return counter;
            } else if current_value == usize::MAX {
                counter += self.bitfield_size;
            } else if (current_value
                .wrapping_shr(u32::try_from(counter % self.bitfield_size).unwrap_or(0))
                & 1_usize)
                != 0
            {
                counter += 1;
            } else {
                return counter;
            }
        }

        0
    }

    /// Sets the visited state of a specific byte.
    ///
    /// Marks a single byte at the specified index as either visited or unvisited.
    /// This is a convenience method that calls [`set_range`](Self::set_range) with a length of 1.
    ///
    /// # Arguments
    ///
    /// * `element` - The byte index to modify (0-based)
    /// * `visited` - `true` to mark as visited, `false` to mark as unvisited
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::disassembler::VisitedMap;
    ///
    /// let visited_map = VisitedMap::new(100);
    ///
    /// // Mark byte 42 as visited
    /// visited_map.set(42, true);
    /// assert!(visited_map.get(42));
    ///
    /// // Mark it as unvisited again
    /// visited_map.set(42, false);
    /// assert!(!visited_map.get(42));
    /// ```
    pub fn set(&self, element: usize, visited: bool) {
        self.set_range(element, visited, 1);
    }

    /// Sets the visited state for a range of consecutive bytes.
    ///
    /// Marks multiple consecutive bytes starting from the specified index as either
    /// visited or unvisited. This is more efficient than calling [`set`](Self::set) multiple times
    /// for contiguous regions.
    ///
    /// # Arguments
    ///
    /// * `element` - The starting byte index (0-based)
    /// * `state` - `true` to mark as visited, `false` to mark as unvisited
    /// * `len` - The number of consecutive bytes to modify
    ///
    /// # Panics
    ///
    /// Panics in debug builds if the range extends beyond the trackable elements.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::disassembler::VisitedMap;
    ///
    /// let visited_map = VisitedMap::new(100);
    ///
    /// // Mark bytes 10-14 as visited (5 bytes total)
    /// visited_map.set_range(10, true, 5);
    ///
    /// // Verify the range was set
    /// for i in 10..15 {
    ///     assert!(visited_map.get(i));
    /// }
    ///
    /// // Bytes outside the range remain unvisited
    /// assert!(!visited_map.get(9));
    /// assert!(!visited_map.get(15));
    /// ```
    pub fn set_range(&self, element: usize, state: bool, len: usize) {
        if element > self.elements || (element + len) > self.elements {
            debug_assert!(false, "Invalid element!");
            return;
        }

        let mut counter = 0;
        while counter < len {
            if let Some(bitfield) = self.data.get((element + counter) / self.bitfield_size) {
                if len - counter > self.bitfield_size {
                    if state {
                        bitfield.store(usize::MAX, Ordering::Release);
                    } else {
                        bitfield.store(0, Ordering::Release);
                    }
                    counter += self.bitfield_size;
                } else {
                    let shift_amount =
                        u32::try_from((element + counter) % self.bitfield_size).unwrap_or(0);
                    let bit_mask = 1_usize.wrapping_shl(shift_amount);

                    if state {
                        bitfield.fetch_or(bit_mask, Ordering::AcqRel);
                    } else {
                        bitfield.fetch_and(!bit_mask, Ordering::AcqRel);
                    }

                    counter += 1;
                }
            } else {
                debug_assert!(false);
                return;
            }
        }
    }

    /// Marks a specific byte as unvisited.
    ///
    /// This is a convenience method equivalent to calling `set(element, false)`.
    /// Useful for clearing the visited state of a single byte.
    ///
    /// # Arguments
    ///
    /// * `element` - The byte index to mark as unvisited (0-based)
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::disassembler::VisitedMap;
    ///
    /// let visited_map = VisitedMap::new(100);
    ///
    /// // Mark a byte as visited
    /// visited_map.set(25, true);
    /// assert!(visited_map.get(25));
    ///
    /// // Clear it back to unvisited
    /// visited_map.clear(25);
    /// assert!(!visited_map.get(25));
    /// ```
    pub fn clear(&self, element: usize) {
        self.set(element, false);
    }

    /// Marks all bytes in the map as unvisited.
    ///
    /// Resets the entire visited map to its initial state where all bytes
    /// are marked as unvisited. This is equivalent to calling
    /// `set_range(0, false, self.len())` but more explicit in intent.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::disassembler::VisitedMap;
    ///
    /// let visited_map = VisitedMap::new(100);
    ///
    /// // Mark some bytes as visited
    /// visited_map.set_range(0, true, 50);
    ///
    /// // Clear everything
    /// visited_map.clear_all();
    ///
    /// // Verify all bytes are now unvisited
    /// for i in 0..100 {
    ///     assert!(!visited_map.get(i));
    /// }
    /// ```
    pub fn clear_all(&self) {
        self.set_range(0, false, self.elements);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_small() {
        let elements = 4096;
        let map = VisitedMap::new(elements);

        assert_eq!(map.len(), elements);
    }

    #[test]
    fn create_big() {
        let elements = 4 * 1024 * 1024;
        let map = VisitedMap::new(elements);

        assert_eq!(map.len(), elements);
    }

    #[test]
    fn use_one() {
        let map = VisitedMap::new(4096);

        map.set(1, true);
        assert!(map.get(1));

        map.set(1, false);
        assert!(!map.get(1));

        assert!(!map.get(2));
    }

    #[test]
    fn use_many() {
        let map = VisitedMap::new(4096);

        map.set(0, true);
        map.set(2, true);
        map.set(4, true);
        map.set(8, true);
        map.set(100, true);
        map.set(101, true);
        map.set(102, true);
        map.set(104, true);
        map.set(103, true);

        assert!(map.get(0));
        assert!(map.get(4));
        assert!(map.get(8));
        assert!(map.get(100));
        assert!(map.get(101));
        assert!(map.get(102));
        assert!(map.get(104));
        assert!(map.get(103));
    }

    #[test]
    fn clear_one() {
        let map = VisitedMap::new(4096);

        map.set(4, true);
        assert!(map.get(4));

        map.clear(4);
        assert!(!map.get(4));
    }

    #[test]
    fn clear_many() {
        let map = VisitedMap::new(4096);

        map.set(0, true);
        map.set(4, true);
        map.set(8, true);
        map.set(100, true);
        map.set(101, true);
        map.set(102, true);
        map.set(104, true);
        map.set(103, true);

        assert!(map.get(0));
        assert!(map.get(4));
        assert!(map.get(8));
        assert!(map.get(100));
        assert!(map.get(101));
        assert!(map.get(102));
        assert!(map.get(104));
        assert!(map.get(103));

        map.clear_all();

        assert!(!map.get(0));
        assert!(!map.get(4));
        assert!(!map.get(8));
        assert!(!map.get(100));
        assert!(!map.get(101));
        assert!(!map.get(102));
        assert!(!map.get(104));
        assert!(!map.get(103));
    }

    #[test]
    fn get_range() {
        let map = VisitedMap::new(4096);

        map.set(0, true);
        map.set(1, true);
        map.set(2, true);
        map.set(3, true);
        map.set(10, true);
        map.set(11, true);
        map.set(12, true);

        assert_eq!(map.get_range(4), 6);
    }

    #[test]
    fn set_range_long() {
        let map = VisitedMap::new(4096);

        map.set_range(0, true, 1001);

        assert!(map.get(0));
        assert!(map.get(4));
        assert!(map.get(8));
        assert!(map.get(100));
        assert!(map.get(101));
        assert!(map.get(444));
        assert!(map.get(666));
        assert!(map.get(1000));
        assert!(!map.get(1001));
    }

    #[test]
    fn set_range_small() {
        let map = VisitedMap::new(4096);

        map.set_range(0, true, 32);

        assert!(map.get(0));
        assert!(map.get(4));
        assert!(map.get(8));
        assert!(map.get(24));
        assert!(!map.get(35));
        assert!(!map.get(33));
    }

    #[test]
    fn get_first_true() {
        let map = VisitedMap::new(4096);

        map.clear_all();

        map.set_range(0, true, 64);
        assert_eq!(map.get_first(true), 0);
        assert_eq!(map.get_first(false), 64);

        map.clear_all();

        map.set_range(1, true, 64);
        assert_eq!(map.get_first(true), 1);
        assert_eq!(map.get_first(false), 0);
    }

    #[test]
    fn bitfield_boundary() {
        let bitfield_size = std::mem::size_of::<usize>() * 8;
        for offset in 1..8 {
            let elements = bitfield_size + offset;
            let map = VisitedMap::new(elements);

            for i in 0..elements {
                map.set(i, true);
                assert!(map.get(i), "Element {i} should be set to true");
            }

            let last_element = elements - 1;
            map.set(last_element, false);
            assert!(
                !map.get(last_element),
                "Last element should be set to false"
            );
            map.set(last_element, true);
            assert!(
                map.get(last_element),
                "Last element should be set to true again"
            );
        }
    }

    #[test]
    fn bitfield_boundary_exact() {
        let bitfield_size = std::mem::size_of::<usize>() * 8;
        let map = VisitedMap::new(bitfield_size);

        for i in 0..bitfield_size {
            map.set(i, true);
            assert!(map.get(i));
        }
    }
}
