use super::Backend;
use crate::{Error::OutOfBounds, Result};

/// Input file backed by Memory
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
}
