use super::Backend;
use crate::{Error::OutOfBounds, Result};

/// Input file backed by Memory
#[derive(Debug)]
pub struct Memory {
    data: Vec<u8>,
}

impl Memory {
    /// Create a new memory backend
    ///
    /// ## Arguments
    /// * 'data' - The data buffer to consume
    pub fn new(data: Vec<u8>) -> Memory {
        Memory { data }
    }
}

impl Backend for Memory {
    fn data_slice(&self, offset: usize, len: usize) -> Result<&[u8]> {
        let Some(offset_end) = offset.checked_add(len) else {
            return Err(OutOfBounds);
        };

        if offset_end > self.data.len() {
            return Err(OutOfBounds);
        }

        Ok(&self.data[offset..offset_end])
    }

    fn data(&self) -> &[u8] {
        self.data.as_slice()
    }

    fn len(&self) -> usize {
        self.data.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory() {
        let mut data = vec![0xCC_u8; 1048];
        data[10] = 0xBB;
        data[11] = 0xBB;
        data[12] = 0xBB;
        data[13] = 0xBB;
        data[14] = 0xBB;

        let memory = Memory::new(data);

        assert_eq!(memory.len(), 1048);
        assert_eq!(memory.data()[0], 0xCC);
        assert_eq!(memory.data()[42], 0xCC);
        assert_eq!(
            memory.data_slice(10, 5).unwrap(),
            &[0xBB, 0xBB, 0xBB, 0xBB, 0xBB]
        );

        if memory
            .data_slice(u32::MAX as usize, u32::MAX as usize)
            .is_ok()
        {
            panic!("This should not work!")
        }

        if memory.data_slice(0, 2048).is_ok() {
            panic!("This should not work!")
        }
    }

    #[test]
    fn test_memory_empty_buffer() {
        let memory = Memory::new(vec![]);

        assert_eq!(memory.len(), 0);
        assert_eq!(memory.data().len(), 0);

        // Test edge cases with empty buffer
        assert!(memory.data_slice(0, 1).is_err());
        assert!(memory.data_slice(1, 0).is_err());
        let empty_slice: &[u8] = &[];
        assert_eq!(memory.data_slice(0, 0).unwrap(), empty_slice);
    }

    #[test]
    fn test_memory_single_byte() {
        let memory = Memory::new(vec![0x42]);

        assert_eq!(memory.len(), 1);
        assert_eq!(memory.data()[0], 0x42);

        // Test boundary conditions
        assert_eq!(memory.data_slice(0, 1).unwrap(), &[0x42]);
        assert!(memory.data_slice(0, 2).is_err());
        assert!(memory.data_slice(1, 1).is_err());
        let empty_slice: &[u8] = &[];
        assert_eq!(memory.data_slice(1, 0).unwrap(), empty_slice);
    }

    #[test]
    fn test_memory_offset_overflow() {
        let memory = Memory::new(vec![0x00; 100]);

        // Test offset + len overflow
        let result = memory.data_slice(usize::MAX, 1);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), OutOfBounds));

        // Test offset exactly at length
        let result = memory.data_slice(100, 1);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), OutOfBounds));

        // Test offset + len exceeds length by 1
        let result = memory.data_slice(99, 2);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), OutOfBounds));
    }

    #[test]
    fn test_memory_large_buffer() {
        let size = 10_000;
        let mut data = vec![0x00; size];
        data[size - 1] = 0xFF;

        let memory = Memory::new(data);
        assert_eq!(memory.len(), size);

        // Test reading at the end
        assert_eq!(memory.data_slice(size - 1, 1).unwrap(), &[0xFF]);

        // Test reading entire buffer
        let full_data = memory.data_slice(0, size).unwrap();
        assert_eq!(full_data.len(), size);
        assert_eq!(full_data[size - 1], 0xFF);
    }
}
