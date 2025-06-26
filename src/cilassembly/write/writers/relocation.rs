//! Base relocation table handling for PE files.
//!
//! This module provides comprehensive base relocation table management for mixed-mode assemblies
//! and position-dependent code scenarios. It handles parsing, updating, and writing base
//! relocation tables according to the PE/COFF specification when assembly sections move
//! to different virtual addresses.
//!
//! # Base Relocation Format
//!
//! Base relocations are stored in the .reloc section and consist of:
//! - **Relocation blocks**: Each covering a 4KB page of virtual memory
//! - **Block header**: Virtual address and total block size
//! - **Relocation entries**: Type and offset within the page
//!
//! # Relocation Types
//!
//! Common relocation types include:
//! - `IMAGE_REL_BASED_ABSOLUTE` (0): No operation, used for padding
//! - `IMAGE_REL_BASED_HIGH` (1): High 16 bits of 32-bit address
//! - `IMAGE_REL_BASED_LOW` (2): Low 16 bits of 32-bit address  
//! - `IMAGE_REL_BASED_HIGHLOW` (3): Full 32-bit address
//! - `IMAGE_REL_BASED_DIR64` (10): Full 64-bit address
//!
//! # Usage
//!
//! ```rust,ignore
//! use crate::cilassembly::write::writers::relocation::RelocationWriter;
//!
//! let mut writer = RelocationWriter::new(output, section_moves);
//! writer.parse_relocation_table()?;
//! writer.update_relocations()?;
//! writer.write_relocation_table()?;
//! ```

use crate::{
    cilassembly::write::output::Output, cilassembly::CilAssembly, file::io::read_le, Error, Result,
};
use std::collections::HashMap;

/// Information about a section that has moved to a different virtual address.
#[derive(Debug, Clone)]
pub struct SectionMove {
    /// Original virtual address of the section.
    pub old_virtual_address: u32,
    /// New virtual address of the section.
    pub new_virtual_address: u32,
    /// Virtual size of the section.
    pub virtual_size: u32,
}

/// Relocation type constants from PE/COFF specification.
#[allow(dead_code, non_snake_case)]
pub mod RelocationTypes {
    /// No operation, used for padding to align blocks to 4-byte boundaries.
    pub const IMAGE_REL_BASED_ABSOLUTE: u8 = 0;
    /// High 16 bits of a 32-bit address.
    pub const IMAGE_REL_BASED_HIGH: u8 = 1;
    /// Low 16 bits of a 32-bit address.
    pub const IMAGE_REL_BASED_LOW: u8 = 2;
    /// Full 32-bit address (most common for 32-bit executables).
    pub const IMAGE_REL_BASED_HIGHLOW: u8 = 3;
    /// High 16 bits of a 32-bit address, adjusted for sign extension.
    pub const IMAGE_REL_BASED_HIGHADJ: u8 = 4;
    /// Full 64-bit address (used in 64-bit executables).
    pub const IMAGE_REL_BASED_DIR64: u8 = 10;
}

/// A single relocation entry within a relocation block.
///
/// Each entry describes one memory location that needs to be adjusted
/// when the image is loaded at a different base address than originally intended.
#[derive(Debug, Clone, PartialEq)]
pub struct RelocationEntry {
    /// Offset from the block's virtual address (12 bits).
    pub offset: u16,
    /// Type of relocation (4 bits) - see `relocation_types` module.
    pub relocation_type: u8,
}

impl RelocationEntry {
    /// Creates a new relocation entry from a raw 16-bit value.
    ///
    /// The raw format packs both type (high 4 bits) and offset (low 12 bits).
    pub fn from_raw(raw: u16) -> Self {
        Self {
            offset: raw & 0x0FFF,
            relocation_type: ((raw >> 12) & 0x0F) as u8,
        }
    }

    /// Converts the relocation entry to its raw 16-bit representation.
    pub fn to_raw(&self) -> u16 {
        ((self.relocation_type as u16) << 12) | (self.offset & 0x0FFF)
    }

    /// Gets the size in bytes for this relocation type.
    pub fn size_bytes(&self) -> usize {
        match self.relocation_type {
            RelocationTypes::IMAGE_REL_BASED_ABSOLUTE => 0,
            RelocationTypes::IMAGE_REL_BASED_HIGH => 2,
            RelocationTypes::IMAGE_REL_BASED_LOW => 2,
            RelocationTypes::IMAGE_REL_BASED_HIGHLOW => 4,
            RelocationTypes::IMAGE_REL_BASED_HIGHADJ => 4,
            RelocationTypes::IMAGE_REL_BASED_DIR64 => 8,
            _ => 0, // Unknown type, assume no size
        }
    }
}

/// A relocation block covering one 4KB page of virtual memory.
///
/// Each block contains a header with the virtual address and size,
/// followed by an array of relocation entries for addresses within that page.
#[derive(Debug, Clone)]
pub struct RelocationBlock {
    /// Virtual address of the start of this 4KB page.
    pub virtual_address: u32,
    /// Total size of this block including header and entries.
    pub size_of_block: u32,
    /// Array of relocation entries within this page.
    pub entries: Vec<RelocationEntry>,
}

impl RelocationBlock {
    /// Creates a new empty relocation block.
    pub fn new(virtual_address: u32) -> Self {
        Self {
            virtual_address,
            size_of_block: 8, // Minimum size: header only
            entries: Vec::new(),
        }
    }

    /// Adds a relocation entry to this block.
    pub fn add_entry(&mut self, entry: RelocationEntry) {
        self.entries.push(entry);
        self.size_of_block += 2; // Each entry is 2 bytes
    }

    /// Ensures the block size is aligned to 4-byte boundary with padding entries.
    pub fn align_block(&mut self) {
        while (self.size_of_block % 4) != 0 {
            self.add_entry(RelocationEntry {
                offset: 0,
                relocation_type: RelocationTypes::IMAGE_REL_BASED_ABSOLUTE,
            });
        }
    }

    /// Parses a relocation block from binary data.
    pub fn parse(data: &[u8], offset: &mut usize) -> Result<Self> {
        if data.len() < *offset + 8 {
            return Err(malformed_error!(
                "Insufficient data for relocation block header"
            ));
        }

        let virtual_address = read_le::<u32>(&data[*offset..*offset + 4])?;
        let size_of_block = read_le::<u32>(&data[*offset + 4..*offset + 8])?;
        *offset += 8;

        if size_of_block < 8 {
            return Err(malformed_error!("Invalid relocation block size"));
        }

        let entries_size = (size_of_block - 8) as usize;
        if data.len() < *offset + entries_size {
            return Err(malformed_error!("Insufficient data for relocation entries"));
        }

        let mut entries = Vec::new();
        let entries_end = *offset + entries_size;

        while *offset < entries_end {
            if data.len() < *offset + 2 {
                break; // Not enough data for another entry
            }

            let raw_entry = read_le::<u16>(&data[*offset..*offset + 2])?;
            *offset += 2;

            let entry = RelocationEntry::from_raw(raw_entry);

            // Skip absolute (padding) entries
            if entry.relocation_type != RelocationTypes::IMAGE_REL_BASED_ABSOLUTE {
                entries.push(entry);
            }
        }

        Ok(Self {
            virtual_address,
            size_of_block,
            entries,
        })
    }

    /// Writes the relocation block to a buffer.
    pub fn write_to_buffer(&self, buffer: &mut Vec<u8>) {
        buffer.extend_from_slice(&self.virtual_address.to_le_bytes());
        buffer.extend_from_slice(&self.size_of_block.to_le_bytes());

        for entry in &self.entries {
            buffer.extend_from_slice(&entry.to_raw().to_le_bytes());
        }
    }
}

/// Writer for managing base relocation tables during assembly modification.
///
/// Handles parsing existing relocation tables, updating relocations when sections move,
/// and writing updated tables back to the assembly output.
pub struct RelocationWriter<'a> {
    output: &'a mut Output,
    section_moves: &'a [SectionMove],
    assembly: Option<&'a CilAssembly>,
    relocation_blocks: Vec<RelocationBlock>,
    reloc_section_offset: Option<usize>,
    reloc_section_size: Option<usize>,
}

impl<'a> RelocationWriter<'a> {
    /// Creates a new RelocationWriter.
    pub fn new(output: &'a mut Output, section_moves: &'a [SectionMove]) -> Self {
        Self {
            output,
            section_moves,
            assembly: None,
            relocation_blocks: Vec::new(),
            reloc_section_offset: None,
            reloc_section_size: None,
        }
    }

    /// Creates a new RelocationWriter with assembly context for PE parsing.
    pub fn with_assembly(
        output: &'a mut Output,
        section_moves: &'a [SectionMove],
        assembly: &'a CilAssembly,
    ) -> Self {
        Self {
            output,
            section_moves,
            assembly: Some(assembly),
            relocation_blocks: Vec::new(),
            reloc_section_offset: None,
            reloc_section_size: None,
        }
    }

    /// Parses the existing base relocation table from the .reloc section.
    ///
    /// Locates the .reloc section in the PE file and parses all relocation blocks
    /// and their entries according to the PE/COFF specification.
    pub fn parse_relocation_table(&mut self) -> Result<()> {
        let (section_offset, section_size) = self.find_reloc_section()?;

        self.reloc_section_offset = Some(section_offset);
        self.reloc_section_size = Some(section_size);

        if section_size == 0 {
            return Ok(());
        }

        let reloc_data = self.output.get_mut_slice(section_offset, section_size)?;

        let mut offset = 0;
        self.relocation_blocks.clear();

        while offset < section_size {
            if offset + 8 > section_size {
                break;
            }

            match RelocationBlock::parse(reloc_data, &mut offset) {
                Ok(block) => {
                    if block.virtual_address == 0 && block.size_of_block == 0 {
                        break;
                    }
                    self.relocation_blocks.push(block);
                }
                Err(_e) => {}
            }

            if offset >= section_size {
                break;
            }
        }

        Ok(())
    }

    /// Updates relocation entries based on section movements.
    ///
    /// Adjusts relocation targets when sections move to different virtual addresses,
    /// ensuring that relocated addresses point to the correct locations.
    pub fn update_relocations(&mut self) -> Result<()> {
        if self.section_moves.is_empty() || self.relocation_blocks.is_empty() {
            return Ok(());
        }

        let address_mapping = self.create_address_mapping();
        for i in 0..self.relocation_blocks.len() {
            self.update_block_relocations(i, &address_mapping)?;
        }

        Ok(())
    }

    /// Writes the updated relocation table back to the output.
    pub fn write_relocation_table(&mut self) -> Result<()> {
        if self.relocation_blocks.is_empty() {
            return Ok(());
        }

        let section_offset =
            self.reloc_section_offset
                .ok_or_else(|| Error::ModificationInvalidOperation {
                    details: "Relocation section offset not set".to_string(),
                })?;

        let mut buffer = Vec::new();
        for block in &mut self.relocation_blocks {
            block.align_block();
            block.write_to_buffer(&mut buffer);
        }

        self.output.write_at(section_offset as u64, &buffer)?;

        Ok(())
    }

    /// Finds the .reloc section in the PE file using PE data directories.
    fn find_reloc_section(&self) -> Result<(usize, usize)> {
        let assembly = self
            .assembly
            .ok_or_else(|| Error::ModificationInvalidOperation {
                details: "Assembly context required for relocation section lookup".to_string(),
            })?;

        let view = assembly.view();
        let file = view.file();

        let optional_header =
            file.header_optional()
                .as_ref()
                .ok_or_else(|| Error::WriteLayoutFailed {
                    message: "Missing optional header in PE file".to_string(),
                })?;

        let base_reloc_dir = optional_header.data_directories.get_base_relocation_table();

        match base_reloc_dir {
            Some(dir) => {
                if dir.size == 0 {
                    return Ok((0, 0));
                }

                let file_offset = file.rva_to_offset(dir.virtual_address as usize)?;
                Ok((file_offset, dir.size as usize))
            }
            None => Ok((0, 0)),
        }
    }

    /// Creates a mapping from old virtual addresses to new addresses.
    fn create_address_mapping(&self) -> HashMap<(u32, u32), u32> {
        let mut mapping = HashMap::new();

        for section_move in self.section_moves {
            let old_start = section_move.old_virtual_address;
            let old_end = old_start + section_move.virtual_size;
            let new_start = section_move.new_virtual_address;

            mapping.insert((old_start, old_end), new_start);
        }

        mapping
    }

    /// Updates relocations within a single block.
    fn update_block_relocations(
        &mut self,
        block_index: usize,
        address_mapping: &HashMap<(u32, u32), u32>,
    ) -> Result<()> {
        // We need to work backwards through entries since we might remove some
        let block = &self.relocation_blocks[block_index];
        let block_va = block.virtual_address;
        let entry_count = block.entries.len();

        for entry_index in (0..entry_count).rev() {
            let entry = &self.relocation_blocks[block_index].entries[entry_index];
            let current_target_rva = block_va + u32::from(entry.offset);

            for ((old_start, old_end), new_start) in address_mapping {
                if current_target_rva >= *old_start && current_target_rva < *old_end {
                    let offset_in_section = current_target_rva - old_start;
                    let new_target_rva = new_start + offset_in_section;

                    if new_target_rva != current_target_rva {
                        self.update_relocation_entry(block_index, entry_index, new_target_rva)?;
                    }
                    break;
                }
            }
        }

        Ok(())
    }

    /// Updates a relocation entry when the target address has moved.
    ///
    /// This updates the relocation table entry itself, NOT the binary data.
    /// The Windows loader will apply the actual relocations at runtime.
    fn update_relocation_entry(
        &mut self,
        block_index: usize,
        entry_index: usize,
        new_target_rva: u32,
    ) -> Result<()> {
        let new_page_base = new_target_rva & !0xFFF; // Clear lower 12 bits
        let new_offset = new_target_rva & 0xFFF; // Keep lower 12 bits

        let current_block_va = self.relocation_blocks[block_index].virtual_address;
        if new_page_base != current_block_va {
            let entry_to_move = self.relocation_blocks[block_index].entries[entry_index].clone();
            let target_block_index = self.find_or_create_relocation_block(new_page_base)?;
            let relocated_entry = RelocationEntry {
                offset: new_offset as u16,
                relocation_type: entry_to_move.relocation_type,
            };

            self.relocation_blocks[target_block_index].add_entry(relocated_entry);

            self.relocation_blocks[block_index]
                .entries
                .remove(entry_index);
            self.relocation_blocks[block_index].size_of_block -= 2;
        } else {
            self.relocation_blocks[block_index].entries[entry_index].offset = new_offset as u16;
        }

        Ok(())
    }

    /// Finds an existing relocation block for the given page or creates a new one.
    fn find_or_create_relocation_block(&mut self, page_base: u32) -> Result<usize> {
        for (index, block) in self.relocation_blocks.iter().enumerate() {
            if block.virtual_address == page_base {
                return Ok(index);
            }
        }

        let new_block = RelocationBlock::new(page_base);
        self.relocation_blocks.push(new_block);
        Ok(self.relocation_blocks.len() - 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cilassembly::write::output::Output;
    use tempfile::NamedTempFile;

    #[test]
    fn test_relocation_entry_round_trip() {
        let entry = RelocationEntry {
            offset: 0x123,
            relocation_type: RelocationTypes::IMAGE_REL_BASED_HIGHLOW,
        };

        let raw = entry.to_raw();
        let parsed = RelocationEntry::from_raw(raw);

        assert_eq!(entry, parsed);
    }

    #[test]
    fn test_relocation_entry_size_bytes() {
        assert_eq!(
            RelocationEntry {
                offset: 0,
                relocation_type: RelocationTypes::IMAGE_REL_BASED_ABSOLUTE,
            }
            .size_bytes(),
            0
        );

        assert_eq!(
            RelocationEntry {
                offset: 0,
                relocation_type: RelocationTypes::IMAGE_REL_BASED_HIGH,
            }
            .size_bytes(),
            2
        );

        assert_eq!(
            RelocationEntry {
                offset: 0,
                relocation_type: RelocationTypes::IMAGE_REL_BASED_LOW,
            }
            .size_bytes(),
            2
        );

        assert_eq!(
            RelocationEntry {
                offset: 0,
                relocation_type: RelocationTypes::IMAGE_REL_BASED_HIGHLOW,
            }
            .size_bytes(),
            4
        );

        assert_eq!(
            RelocationEntry {
                offset: 0,
                relocation_type: RelocationTypes::IMAGE_REL_BASED_DIR64,
            }
            .size_bytes(),
            8
        );
    }

    #[test]
    fn test_relocation_block_creation() {
        let mut block = RelocationBlock::new(0x1000);

        block.add_entry(RelocationEntry {
            offset: 0x100,
            relocation_type: RelocationTypes::IMAGE_REL_BASED_HIGHLOW,
        });

        assert_eq!(block.virtual_address, 0x1000);
        assert_eq!(block.entries.len(), 1);
        assert_eq!(block.size_of_block, 10); // 8 byte header + 2 byte entry
    }

    #[test]
    fn test_relocation_block_alignment() {
        let mut block = RelocationBlock::new(0x1000);

        // Add one entry (2 bytes) - total size will be 10 bytes (not aligned)
        block.add_entry(RelocationEntry {
            offset: 0x100,
            relocation_type: RelocationTypes::IMAGE_REL_BASED_HIGHLOW,
        });

        assert_eq!(block.size_of_block, 10);

        // Align the block
        block.align_block();

        // Should now be 12 bytes (aligned to 4) with one padding entry added
        assert_eq!(block.size_of_block, 12);
        assert_eq!(block.entries.len(), 2);
        assert_eq!(
            block.entries[1].relocation_type,
            RelocationTypes::IMAGE_REL_BASED_ABSOLUTE
        );
    }

    #[test]
    fn test_relocation_block_parsing() {
        // Create a test relocation block with known data
        let mut original_block = RelocationBlock::new(0x2000);
        original_block.add_entry(RelocationEntry {
            offset: 0x123,
            relocation_type: RelocationTypes::IMAGE_REL_BASED_HIGHLOW,
        });
        original_block.add_entry(RelocationEntry {
            offset: 0x456,
            relocation_type: RelocationTypes::IMAGE_REL_BASED_DIR64,
        });
        original_block.align_block();

        // Serialize to binary data
        let mut buffer = Vec::new();
        original_block.write_to_buffer(&mut buffer);

        // Parse it back
        let mut offset = 0;
        let parsed_block =
            RelocationBlock::parse(&buffer, &mut offset).expect("Failed to parse block");

        // Verify the parsed block matches the original
        assert_eq!(parsed_block.virtual_address, original_block.virtual_address);
        assert_eq!(parsed_block.entries.len(), 2); // Excluding padding entries
        assert_eq!(parsed_block.entries[0].offset, 0x123);
        assert_eq!(
            parsed_block.entries[0].relocation_type,
            RelocationTypes::IMAGE_REL_BASED_HIGHLOW
        );
        assert_eq!(parsed_block.entries[1].offset, 0x456);
        assert_eq!(
            parsed_block.entries[1].relocation_type,
            RelocationTypes::IMAGE_REL_BASED_DIR64
        );
    }

    #[test]
    fn test_section_move_address_mapping() {
        let section_moves = vec![
            SectionMove {
                old_virtual_address: 0x1000,
                new_virtual_address: 0x2000,
                virtual_size: 0x1000,
            },
            SectionMove {
                old_virtual_address: 0x3000,
                new_virtual_address: 0x5000,
                virtual_size: 0x800,
            },
        ];

        // Create a temporary file and output for testing
        let temp_file = NamedTempFile::new().expect("Failed to create temporary file");
        let mut output = Output::create(temp_file.path(), 4096).expect("Failed to create output");
        let writer = RelocationWriter::new(&mut output, &section_moves);
        let mapping = writer.create_address_mapping();

        // Check that the mapping contains the expected entries
        assert_eq!(mapping.get(&(0x1000, 0x2000)), Some(&0x2000));
        assert_eq!(mapping.get(&(0x3000, 0x3800)), Some(&0x5000));
        assert_eq!(mapping.len(), 2);
    }

    #[test]
    fn test_page_boundary_calculations() {
        // Test 4KB page boundary calculations
        assert_eq!(0x1234 & !0xFFF, 0x1000); // Page base
        assert_eq!(0x1234 & 0xFFF, 0x234); // Offset within page

        assert_eq!(0x2FFF & !0xFFF, 0x2000);
        assert_eq!(0x2FFF & 0xFFF, 0xFFF);

        assert_eq!(0x3000 & !0xFFF, 0x3000);
        assert_eq!(0x3000 & 0xFFF, 0x0);
    }

    #[test]
    fn test_find_or_create_relocation_block() {
        let section_moves = vec![];
        let temp_file = NamedTempFile::new().expect("Failed to create temporary file");
        let mut output = Output::create(temp_file.path(), 4096).expect("Failed to create output");
        let mut writer = RelocationWriter::new(&mut output, &section_moves);

        // Initially no blocks
        assert_eq!(writer.relocation_blocks.len(), 0);

        // Create first block
        let index1 = writer
            .find_or_create_relocation_block(0x1000)
            .expect("Failed to create block");
        assert_eq!(index1, 0);
        assert_eq!(writer.relocation_blocks.len(), 1);
        assert_eq!(writer.relocation_blocks[0].virtual_address, 0x1000);

        // Find existing block
        let index2 = writer
            .find_or_create_relocation_block(0x1000)
            .expect("Failed to find block");
        assert_eq!(index2, 0);
        assert_eq!(writer.relocation_blocks.len(), 1);

        // Create second block
        let index3 = writer
            .find_or_create_relocation_block(0x2000)
            .expect("Failed to create block");
        assert_eq!(index3, 1);
        assert_eq!(writer.relocation_blocks.len(), 2);
        assert_eq!(writer.relocation_blocks[1].virtual_address, 0x2000);
    }

    #[test]
    fn test_relocation_entry_update_same_page() {
        let section_moves = vec![SectionMove {
            old_virtual_address: 0x1000,
            new_virtual_address: 0x1100,
            virtual_size: 0x1000,
        }];
        let temp_file = NamedTempFile::new().expect("Failed to create temporary file");
        let mut output = Output::create(temp_file.path(), 4096).expect("Failed to create output");
        let mut writer = RelocationWriter::new(&mut output, &section_moves);

        // Create a relocation block with an entry
        let mut block = RelocationBlock::new(0x1000);
        block.add_entry(RelocationEntry {
            offset: 0x200,
            relocation_type: RelocationTypes::IMAGE_REL_BASED_HIGHLOW,
        });
        writer.relocation_blocks.push(block);

        // Target is at 0x1200, should move to 0x1300 (same page: 0x1000)
        let new_target_rva = 0x1300;
        writer
            .update_relocation_entry(0, 0, new_target_rva)
            .expect("Failed to update entry");

        // Entry should be updated within the same block
        assert_eq!(writer.relocation_blocks.len(), 1);
        assert_eq!(writer.relocation_blocks[0].entries.len(), 1);
        assert_eq!(writer.relocation_blocks[0].entries[0].offset, 0x300);
    }

    #[test]
    fn test_relocation_entry_update_different_page() {
        let section_moves = vec![SectionMove {
            old_virtual_address: 0x1000,
            new_virtual_address: 0x3000,
            virtual_size: 0x1000,
        }];
        let temp_file = NamedTempFile::new().expect("Failed to create temporary file");
        let mut output = Output::create(temp_file.path(), 4096).expect("Failed to create output");
        let mut writer = RelocationWriter::new(&mut output, &section_moves);

        // Create a relocation block with an entry
        let mut block = RelocationBlock::new(0x1000);
        block.add_entry(RelocationEntry {
            offset: 0x200,
            relocation_type: RelocationTypes::IMAGE_REL_BASED_HIGHLOW,
        });
        writer.relocation_blocks.push(block);

        // Target moves from 0x1200 to 0x3200 (different page: 0x1000 -> 0x3000)
        let new_target_rva = 0x3200;
        writer
            .update_relocation_entry(0, 0, new_target_rva)
            .expect("Failed to update entry");

        // Should have 2 blocks now: original (empty) and new (with entry)
        assert_eq!(writer.relocation_blocks.len(), 2);
        assert_eq!(writer.relocation_blocks[0].entries.len(), 0); // Original block now empty
        assert_eq!(writer.relocation_blocks[1].virtual_address, 0x3000); // New block
        assert_eq!(writer.relocation_blocks[1].entries.len(), 1);
        assert_eq!(writer.relocation_blocks[1].entries[0].offset, 0x200); // Same offset within page
    }
}
