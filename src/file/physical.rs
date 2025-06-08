use super::Backend;
use crate::{
    Error::{Error, FileError, OutOfBounds},
    Result,
};

use memmap2::Mmap;
use std::{fs, path::Path};

/// Input file backed by a physical file on disk
pub struct Physical {
    data: Mmap,
}

impl Physical {
    /// Create a new physical backend
    ///
    /// ## Arguments
    /// * 'path' - The file path to use
    pub fn new(path: &Path) -> Result<Physical> {
        let file = match fs::File::open(path) {
            Ok(file) => file,
            Err(error) => return Err(FileError(error)),
        };

        let mmap = match unsafe { Mmap::map(&file) } {
            Ok(mmap) => mmap,
            Err(error) => return Err(Error(error.to_string())),
        };

        Ok(Physical { data: mmap })
    }
}

impl Backend for Physical {
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
        self.data.as_ref()
    }

    fn len(&self) -> usize {
        self.data.len()
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn physical() {
        let physical = Physical::new(
            &PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll"),
        )
        .unwrap();

        assert_eq!(physical.len(), 2255024);
        assert_eq!(physical.data()[0], 0x4D);
        assert_eq!(physical.data()[1], 0x5A);
        assert_eq!(
            physical.data_slice(12, 5).unwrap(),
            &[0xFF, 0xFF, 0x00, 0x00, 0xB8]
        );

        if physical
            .data_slice(u32::MAX as usize, u32::MAX as usize)
            .is_ok()
        {
            panic!("This should not work!")
        }

        if physical.data_slice(0, 4 * 1024 * 1024).is_ok() {
            panic!("This should not work!")
        }
    }
}
