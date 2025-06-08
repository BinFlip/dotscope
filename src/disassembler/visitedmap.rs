//! Bitfield map for tracking visited bytes during disassembly and analysis.
//!
//! The [`VisitedMap`] struct efficiently tracks which bytes or regions of a file have been
//! processed, enabling fast detection of unvisited regions and preventing redundant analysis.
//! Used internally by the disassembler for control flow and block analysis.

/// This structure tracks the bytes of the file that is being analysed, in order to avoid double
/// processing of the same locations. But also to focus scans on remaining locations that have not
/// been analysed before
pub struct VisitedMap {
    data: Vec<usize>,
    elements: usize,
    bitfield_size: usize,
}

impl VisitedMap {
    /// Create a new instance of the `VisitedMap`
    ///
    /// ## Arguments
    /// * 'elements' - The amount of bytes to track
    pub fn new(elements: usize) -> VisitedMap {
        let bitfield_size = std::mem::size_of::<usize>() * 8;

        VisitedMap {
            data: vec![0_usize; elements.div_ceil(bitfield_size)],
            elements,
            bitfield_size,
        }
    }

    /// Returns the max amount of elements this instance can track
    pub fn len(&self) -> usize {
        self.elements
    }

    /// Check if the visited map is empty (has no trackable elements)
    pub fn is_empty(&self) -> bool {
        self.elements == 0
    }

    /// Check if a certain element / byte has already been visited
    ///
    /// # Arguments
    /// * 'element' - The element or byte that should be looked up
    pub fn get(&self, element: usize) -> bool {
        if element > self.elements {
            return false;
        }

        if let Some(bitfield) = self.data.get(element / self.bitfield_size) {
            let shift_amount = u32::try_from(element % self.bitfield_size).unwrap_or(0);
            return (bitfield.wrapping_shr(shift_amount) & 1_usize) != 0;
        }

        false
    }

    /// Returns the number of unvisited elements from the provided starting element
    ///
    /// # Arguments
    /// * 'element' - The element or byte that should be looked up
    pub fn get_range(&self, element: usize) -> usize {
        if element > self.elements {
            return 0;
        }

        let mut counter = 0;

        while let Some(bitfield) = self.data.get((element + counter) / self.bitfield_size) {
            if *bitfield == usize::MAX {
                counter += self.bitfield_size;
            } else {
                let shift_amount =
                    u32::try_from((element + counter) % self.bitfield_size).unwrap_or(0);
                if (bitfield.wrapping_shr(shift_amount) & 1_usize) == 0 {
                    counter += 1;
                } else {
                    break;
                }
            }
        }

        counter
    }

    /// Get the first byte which matches the requested state
    ///
    /// # Arguments
    /// * 'visited' - Specify which kind of first entry you're looking for
    pub fn get_first(&self, visited: bool) -> usize {
        let mut counter = 0;

        while let Some(bitfield) = self.data.get(counter / self.bitfield_size) {
            if visited {
                if *bitfield == usize::MAX {
                    return counter;
                } else if *bitfield == 0 {
                    counter += self.bitfield_size;
                } else {
                    let shift_amount = u32::try_from(counter % self.bitfield_size).unwrap_or(0);
                    if (bitfield.wrapping_shr(shift_amount) & 1_usize) == 0 {
                        counter += 1;
                    } else {
                        return counter;
                    }
                }
            } else if *bitfield == 0 {
                return counter;
            } else if *bitfield == usize::MAX {
                counter += self.bitfield_size;
            } else if (bitfield
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

    /// Set a specific element / byte to either visited or un-visited
    ///
    /// # Arguments
    /// * 'element' - The element / byte which is going to be set
    /// * 'visited' - The state that should be applied to the specified element
    pub fn set(&mut self, element: usize, visited: bool) {
        self.set_range(element, visited, 1);
    }

    /// Set a specific element / byte to either visited or un-visited
    ///
    /// # Arguments
    /// * 'element' - The first element which is going to be set
    /// * 'state'   - The state that should be applied to the specified element
    /// * 'len'     - The count of elements that should receive the new state
    pub fn set_range(&mut self, element: usize, state: bool, len: usize) {
        if element > self.elements || (element + len) > self.elements {
            debug_assert!(false, "Invalid element!");
            return;
        }

        let mut counter = 0;
        while counter < len {
            if let Some(bitfield) = self.data.get_mut((element + counter) / self.bitfield_size) {
                if len - counter > self.bitfield_size {
                    if state {
                        *bitfield = usize::MAX;
                    } else {
                        *bitfield = 0;
                    }

                    counter += self.bitfield_size;
                } else {
                    if state {
                        *bitfield |= 1_usize.wrapping_shl(
                            u32::try_from((element + counter) % self.bitfield_size).unwrap_or(0),
                        );
                    } else {
                        *bitfield &= !(1_usize.wrapping_shl(
                            u32::try_from((element + counter) % self.bitfield_size).unwrap_or(0),
                        ));
                    }

                    counter += 1;
                }
            } else {
                debug_assert!(false);
                return;
            }
        }
    }

    /// Clear a specific element to be not visited
    /// # Arguments
    /// * 'element' - The element that will be cleared
    pub fn clear(&mut self, element: usize) {
        self.set(element, false);
    }

    /// Clears the whole structure back to not visited
    pub fn clear_all(&mut self) {
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
        let mut map = VisitedMap::new(4096);

        map.set(1, true);
        assert!(map.get(1));

        map.set(1, false);
        assert!(!map.get(1));

        assert!(!map.get(2));
    }

    #[test]
    fn use_many() {
        let mut map = VisitedMap::new(4096);

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
        let mut map = VisitedMap::new(4096);

        map.set(4, true);
        assert!(map.get(4));

        map.clear(4);
        assert!(!map.get(4));
    }

    #[test]
    fn clear_many() {
        let mut map = VisitedMap::new(4096);

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
        let mut map = VisitedMap::new(4096);

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
        let mut map = VisitedMap::new(4096);

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
        let mut map = VisitedMap::new(4096);

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
        let mut map = VisitedMap::new(4096);

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
            let mut map = VisitedMap::new(elements);

            for i in 0..elements {
                map.set(i, true);
                assert!(map.get(i), "Element {} should be set to true", i);
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
        let mut map = VisitedMap::new(bitfield_size);

        for i in 0..bitfield_size {
            map.set(i, true);
            assert!(map.get(i));
        }
    }
}
