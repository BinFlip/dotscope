use super::Backend;
use crate::{
    Error::{Error, FileError, OutOfBounds},
    Result,
};

use memmap2::Mmap;
use std::{fs, path::Path};

/// Input file backed by a physical file on disk
#[derive(Debug)]
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

    #[test]
    fn test_physical_invalid_file_path() {
        let result = Physical::new(&PathBuf::from("/nonexistent/path/to/file.dll"));
        assert!(result.is_err());
        match result.unwrap_err() {
            FileError(io_error) => {
                assert_eq!(io_error.kind(), std::io::ErrorKind::NotFound);
            }
            _ => panic!("Expected FileError"),
        }
    }

    #[test]
    fn test_physical_empty_file() {
        // Create a temporary empty file to test with
        let temp_dir = std::env::temp_dir();
        let temp_path = temp_dir.join("empty_test_file.bin");
        std::fs::write(&temp_path, b"").unwrap();
        
        let physical = Physical::new(&temp_path).unwrap();
        assert_eq!(physical.len(), 0);
        assert_eq!(physical.data().len(), 0);
        
        // Test edge cases with empty file
        assert!(physical.data_slice(0, 1).is_err());
        assert!(physical.data_slice(1, 0).is_err());
        let empty_slice: &[u8] = &[];
        assert_eq!(physical.data_slice(0, 0).unwrap(), empty_slice);
        
        // Cleanup
        std::fs::remove_file(&temp_path).unwrap();
    }

    #[test] 
    fn test_physical_large_offset_overflow() {
        let physical = Physical::new(
            &PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll"),
        )
        .unwrap();

        // Test offset + len overflow
        let result = physical.data_slice(usize::MAX, 1);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), OutOfBounds));

        // Test offset exactly at length
        let len = physical.len();
        let result = physical.data_slice(len, 1);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), OutOfBounds));

        // Test offset + len exceeds length by 1
        let result = physical.data_slice(len - 1, 2);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), OutOfBounds));
    }

    #[test]
    fn test_physical_boundary_conditions() {
        let physical = Physical::new(
            &PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll"),
        )
        .unwrap();

        let len = physical.len();
        
        // Test reading exactly at the boundary (should work)
        let result = physical.data_slice(len - 1, 1);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 1);

        // Test reading the entire file
        let result = physical.data_slice(0, len);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), len);

        // Test zero-length read at end
        let result = physical.data_slice(len, 0);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 0);
    }
}
