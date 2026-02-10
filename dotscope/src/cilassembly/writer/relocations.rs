//! PE base relocation support for assembly writing.
//!
//! This module provides relocation generation logic for .NET assemblies to ensure
//! compliance with CoreCLR requirements. It handles the nuances of when relocations
//! are required vs. when the `IMAGE_FILE_RELOCS_STRIPPED` flag should be set.
//!
//! # Background
//!
//! When dotscope regenerates a .NET assembly, it completely rebuilds the .text section.
//! This invalidates all original relocations pointing to .text. The handling differs
//! based on the assembly type:
//!
//! - **x64 IL-only EXE**: RIP-relative entry stub, no relocations needed. Set RELOCS_STRIPPED.
//! - **x86 IL-only EXE**: Absolute VA in entry stub needs one relocation.
//! - **DLL (any arch)**: CoreCLR requires relocations to be present for DLLs.
//! - **Mixed-mode**: Preserve non-.text relocations from original.
//!
//! # CoreCLR Validation
//!
//! From CoreCLR's `CheckILOnlyBaseRelocations()` in pedecoder.cpp:
//!
//! ```text
//! if (!HasDirectoryEntry(IMAGE_DIRECTORY_ENTRY_BASERELOC))
//! {
//!     CHECK(!IsDll());  // DLLs MUST have relocations
//!     CHECK((Characteristics & IMAGE_FILE_RELOCS_STRIPPED) != 0);  // EXEs must set flag
//! }
//! ```

/// Relocation type: Absolute - no relocation performed (padding).
pub const IMAGE_REL_BASED_ABSOLUTE: u16 = 0;

/// Relocation type: HIGHLOW - 32-bit absolute address (x86).
pub const IMAGE_REL_BASED_HIGHLOW: u16 = 3;

/// Relocation type: DIR64 - 64-bit absolute address (x64).
#[allow(dead_code)]
pub const IMAGE_REL_BASED_DIR64: u16 = 10;

/// Configuration for relocation generation.
///
/// Contains all the information needed to determine how to handle
/// relocations for a regenerated .NET assembly.
#[derive(Debug, Clone)]
pub struct RelocationConfig {
    /// Whether this is a DLL (IMAGE_FILE_DLL flag set).
    pub is_dll: bool,

    /// Whether this is PE32+ (x64) vs PE32 (x86).
    pub is_pe32_plus: bool,

    /// Whether the assembly is IL-only (COMIMAGE_FLAGS_ILONLY).
    pub is_il_only: bool,

    /// RVA of the native entry point stub (jmp instruction).
    /// For x86, the absolute VA is at stub_rva + 2.
    pub entry_stub_rva: Option<u32>,
}

/// Result of relocation processing.
///
/// Contains the serialized relocation data (if any) and whether
/// the RELOCS_STRIPPED flag should be set.
#[derive(Debug, Clone)]
pub struct RelocationResult {
    /// Serialized .reloc section data. Empty if no relocations needed.
    pub data: Vec<u8>,

    /// Whether IMAGE_FILE_RELOCS_STRIPPED should be set in COFF characteristics.
    /// True for x64 IL-only EXEs that need no relocations.
    pub strip_relocations: bool,
}

/// Generates relocation data for .NET assemblies.
///
/// This function determines the appropriate relocation handling based on the
/// assembly type and generates the minimal correct relocation section.
///
/// # Arguments
///
/// * `config` - Configuration describing the assembly type and entry point
/// * `existing_reloc_data` - Original .reloc section data (for mixed-mode)
/// * `text_rva_range` - RVA range of .text section (start, end) to filter out
///
/// # Returns
///
/// A `RelocationResult` containing the relocation data and strip flag.
///
/// # Decision Matrix
///
/// | Scenario | Relocations | RELOCS_STRIPPED |
/// |----------|-------------|-----------------|
/// | x64 IL-only EXE | None | SET |
/// | x86 IL-only EXE | Entry stub reloc | CLEAR |
/// | DLL (any arch) | Minimal or existing | CLEAR |
/// | Mixed-mode | Filtered existing | CLEAR |
pub fn generate_relocations(
    config: &RelocationConfig,
    existing_reloc_data: Option<&[u8]>,
    text_rva_range: (u32, u32),
) -> RelocationResult {
    // DLLs always need relocations per CoreCLR requirements
    if config.is_dll {
        return generate_dll_relocations(config, existing_reloc_data, text_rva_range);
    }

    // EXE logic depends on architecture and IL-only status
    if config.is_pe32_plus && config.is_il_only {
        // x64 IL-only EXE: RIP-relative entry stub, no relocations needed
        return RelocationResult {
            data: Vec::new(),
            strip_relocations: true,
        };
    }

    if !config.is_pe32_plus && config.is_il_only {
        // x86 IL-only EXE: need one relocation for entry stub VA
        if let Some(stub_rva) = config.entry_stub_rva {
            // The entry stub is: FF 25 [VA32]
            // VA is at offset +2 from the stub start
            let reloc_rva = stub_rva.saturating_add(2);
            return RelocationResult {
                data: generate_single_reloc_block(reloc_rva, IMAGE_REL_BASED_HIGHLOW),
                strip_relocations: false,
            };
        }
    }

    // Mixed-mode or unusual case: filter existing relocations
    if let Some(data) = existing_reloc_data {
        let filtered = filter_relocation_blocks(data, text_rva_range);
        if filtered.is_empty() {
            // All relocations were in .text, treat as stripped
            return RelocationResult {
                data: Vec::new(),
                strip_relocations: true,
            };
        }
        return RelocationResult {
            data: filtered,
            strip_relocations: false,
        };
    }

    // No existing data and not x86 IL-only - strip relocations
    RelocationResult {
        data: Vec::new(),
        strip_relocations: true,
    }
}

/// Generates relocations for a DLL.
///
/// DLLs must always have a .reloc section per CoreCLR requirements.
/// For IL-only x64 DLLs, we generate a minimal valid reloc block.
fn generate_dll_relocations(
    config: &RelocationConfig,
    existing_reloc_data: Option<&[u8]>,
    text_rva_range: (u32, u32),
) -> RelocationResult {
    // First try to filter existing relocations
    if let Some(data) = existing_reloc_data {
        let filtered = filter_relocation_blocks(data, text_rva_range);
        if !filtered.is_empty() {
            return RelocationResult {
                data: filtered,
                strip_relocations: false,
            };
        }
    }

    // x86 DLL with entry stub: generate real relocation
    if !config.is_pe32_plus {
        if let Some(stub_rva) = config.entry_stub_rva {
            let reloc_rva = stub_rva.saturating_add(2);
            return RelocationResult {
                data: generate_single_reloc_block(reloc_rva, IMAGE_REL_BASED_HIGHLOW),
                strip_relocations: false,
            };
        }
    }

    // For x64 DLLs or when no entry stub, generate minimal dummy block
    // This satisfies CoreCLR's requirement that DLLs have a .reloc section
    RelocationResult {
        data: generate_minimal_reloc_block(),
        strip_relocations: false,
    }
}

/// Generates a minimal valid relocation block.
///
/// Creates a 12-byte relocation block with just padding entries.
/// This satisfies CoreCLR's requirement that DLLs have relocations
/// without actually relocating anything.
///
/// Block format:
/// - VirtualAddress (4 bytes): 0x1000 (arbitrary valid page)
/// - SizeOfBlock (4 bytes): 12
/// - Entries (4 bytes): Two IMAGE_REL_BASED_ABSOLUTE entries for padding
fn generate_minimal_reloc_block() -> Vec<u8> {
    let mut data = Vec::with_capacity(12);

    // VirtualAddress - use a valid-looking page RVA
    // We use 0x1000 which is typically before .text section
    data.extend_from_slice(&0x1000u32.to_le_bytes());

    // SizeOfBlock - header (8) + 2 entries (4) = 12 bytes
    data.extend_from_slice(&12u32.to_le_bytes());

    // Two padding entries (IMAGE_REL_BASED_ABSOLUTE)
    // Each entry: type (4 bits) | offset (12 bits) = 0x0000
    data.extend_from_slice(&0u16.to_le_bytes());
    data.extend_from_slice(&0u16.to_le_bytes());

    data
}

/// Generates a single relocation block for the given RVA.
///
/// Creates a 12-byte relocation block with one real entry and one padding entry.
///
/// # Arguments
///
/// * `rva` - The RVA that needs relocation
/// * `reloc_type` - The relocation type (e.g., IMAGE_REL_BASED_HIGHLOW)
///
/// # Returns
///
/// A 12-byte relocation block containing the single relocation.
fn generate_single_reloc_block(rva: u32, reloc_type: u16) -> Vec<u8> {
    let mut data = Vec::with_capacity(12);

    // Calculate page RVA and offset within page
    let page_rva = rva & !0xFFF; // Align to 4KB page
    let offset_in_page = (rva & 0xFFF) as u16;

    // VirtualAddress - page-aligned RVA
    data.extend_from_slice(&page_rva.to_le_bytes());

    // SizeOfBlock - header (8) + 2 entries (4) = 12 bytes
    data.extend_from_slice(&12u32.to_le_bytes());

    // Entry 1: type (high 4 bits) | offset (low 12 bits)
    let entry = (reloc_type << 12) | offset_in_page;
    data.extend_from_slice(&entry.to_le_bytes());

    // Entry 2: padding (IMAGE_REL_BASED_ABSOLUTE)
    data.extend_from_slice(&0u16.to_le_bytes());

    data
}

/// Filters relocation blocks, removing those pointing to .text section.
///
/// Parses the relocation block format and keeps only blocks that don't
/// point to the specified RVA range.
///
/// # Arguments
///
/// * `reloc_data` - Original .reloc section data
/// * `text_rva_range` - (start_rva, end_rva) of .text section to filter out
///
/// # Returns
///
/// Filtered relocation data with .text blocks removed.
fn filter_relocation_blocks(reloc_data: &[u8], text_rva_range: (u32, u32)) -> Vec<u8> {
    let mut result = Vec::new();
    let mut offset = 0;
    let (text_start, text_end) = text_rva_range;

    while offset + 8 <= reloc_data.len() {
        // Read block header
        let block_va = u32::from_le_bytes([
            reloc_data[offset],
            reloc_data[offset + 1],
            reloc_data[offset + 2],
            reloc_data[offset + 3],
        ]);
        let block_size = u32::from_le_bytes([
            reloc_data[offset + 4],
            reloc_data[offset + 5],
            reloc_data[offset + 6],
            reloc_data[offset + 7],
        ]) as usize;

        // Validate block size
        if block_size < 8 || offset + block_size > reloc_data.len() {
            break;
        }

        // Keep blocks that don't point to .text
        let points_to_text = block_va >= text_start && block_va < text_end;
        if !points_to_text {
            result.extend_from_slice(&reloc_data[offset..offset + block_size]);
        }

        offset += block_size;
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_x64_il_only_exe_strips_relocations() {
        let config = RelocationConfig {
            is_dll: false,
            is_pe32_plus: true,
            is_il_only: true,
            entry_stub_rva: Some(0x2050),
        };
        let result = generate_relocations(&config, None, (0x2000, 0x4000));

        assert!(result.strip_relocations);
        assert!(result.data.is_empty());
    }

    #[test]
    fn test_x86_il_only_exe_has_entry_reloc() {
        let config = RelocationConfig {
            is_dll: false,
            is_pe32_plus: false,
            is_il_only: true,
            entry_stub_rva: Some(0x2050),
        };
        let result = generate_relocations(&config, None, (0x2000, 0x4000));

        assert!(!result.strip_relocations);
        assert_eq!(result.data.len(), 12); // One block

        // Verify block structure
        let page_rva = u32::from_le_bytes([
            result.data[0],
            result.data[1],
            result.data[2],
            result.data[3],
        ]);
        let block_size = u32::from_le_bytes([
            result.data[4],
            result.data[5],
            result.data[6],
            result.data[7],
        ]);
        let entry = u16::from_le_bytes([result.data[8], result.data[9]]);

        // Entry stub RVA 0x2050 + 2 = 0x2052
        // Page RVA: 0x2000, offset: 0x052
        assert_eq!(page_rva, 0x2000);
        assert_eq!(block_size, 12);
        // Entry: HIGHLOW (3) << 12 | 0x052 = 0x3052
        assert_eq!(entry, 0x3052);
    }

    #[test]
    fn test_x64_dll_always_has_relocations() {
        let config = RelocationConfig {
            is_dll: true,
            is_pe32_plus: true,
            is_il_only: true,
            entry_stub_rva: Some(0x2050),
        };
        let result = generate_relocations(&config, None, (0x2000, 0x4000));

        assert!(!result.strip_relocations);
        assert!(!result.data.is_empty());
        assert_eq!(result.data.len(), 12); // Minimal block
    }

    #[test]
    fn test_x86_dll_has_entry_reloc() {
        let config = RelocationConfig {
            is_dll: true,
            is_pe32_plus: false,
            is_il_only: true,
            entry_stub_rva: Some(0x2050),
        };
        let result = generate_relocations(&config, None, (0x2000, 0x4000));

        assert!(!result.strip_relocations);
        assert_eq!(result.data.len(), 12);

        // Should have real HIGHLOW relocation
        let entry = u16::from_le_bytes([result.data[8], result.data[9]]);
        assert_eq!(entry, 0x3052); // HIGHLOW at offset 0x052
    }

    #[test]
    fn test_minimal_reloc_block_structure() {
        let block = generate_minimal_reloc_block();

        assert_eq!(block.len(), 12);

        let page_rva = u32::from_le_bytes([block[0], block[1], block[2], block[3]]);
        let block_size = u32::from_le_bytes([block[4], block[5], block[6], block[7]]);
        let entry1 = u16::from_le_bytes([block[8], block[9]]);
        let entry2 = u16::from_le_bytes([block[10], block[11]]);

        assert_eq!(page_rva, 0x1000);
        assert_eq!(block_size, 12);
        assert_eq!(entry1, 0); // ABSOLUTE padding
        assert_eq!(entry2, 0); // ABSOLUTE padding
    }

    #[test]
    fn test_filter_removes_text_blocks() {
        // Create a mock reloc section with two blocks
        let mut reloc_data = Vec::new();

        // Block 1: in .text (0x2000-0x4000) - should be filtered
        reloc_data.extend_from_slice(&0x2000u32.to_le_bytes()); // VA
        reloc_data.extend_from_slice(&12u32.to_le_bytes()); // Size
        reloc_data.extend_from_slice(&0x3050u16.to_le_bytes()); // Entry
        reloc_data.extend_from_slice(&0u16.to_le_bytes()); // Padding

        // Block 2: in .rsrc (0x6000) - should be kept
        reloc_data.extend_from_slice(&0x6000u32.to_le_bytes()); // VA
        reloc_data.extend_from_slice(&12u32.to_le_bytes()); // Size
        reloc_data.extend_from_slice(&0x3100u16.to_le_bytes()); // Entry
        reloc_data.extend_from_slice(&0u16.to_le_bytes()); // Padding

        let filtered = filter_relocation_blocks(&reloc_data, (0x2000, 0x4000));

        // Should only have the second block
        assert_eq!(filtered.len(), 12);
        let page_rva = u32::from_le_bytes([filtered[0], filtered[1], filtered[2], filtered[3]]);
        assert_eq!(page_rva, 0x6000);
    }

    #[test]
    fn test_mixed_mode_preserves_non_text_relocs() {
        // Create mock existing relocs outside .text
        let mut reloc_data = Vec::new();
        reloc_data.extend_from_slice(&0x8000u32.to_le_bytes()); // VA outside .text
        reloc_data.extend_from_slice(&12u32.to_le_bytes()); // Size
        reloc_data.extend_from_slice(&0x3050u16.to_le_bytes()); // Entry
        reloc_data.extend_from_slice(&0u16.to_le_bytes()); // Padding

        let config = RelocationConfig {
            is_dll: false,
            is_pe32_plus: false,
            is_il_only: false, // Mixed-mode
            entry_stub_rva: Some(0x2050),
        };
        let result = generate_relocations(&config, Some(&reloc_data), (0x2000, 0x4000));

        assert!(!result.strip_relocations);
        assert_eq!(result.data.len(), 12);
    }
}
