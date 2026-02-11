//! PE file generator for the assembly writer.
//!
//! This module provides the [`PeGenerator`] that orchestrates complete PE file generation
//! from a [`CilAssembly`]. The generator uses a streaming approach where content is written
//! sequentially and forward-referenced values are patched via fixups at the end.
//!
//! # Generation Process
//!
//! The generator follows this sequence:
//!
//! 1. **Initialize**: Create WriteContext with estimated file size
//! 2. **Write**: Stream all content sequentially:
//!    - PE Headers (DOS, PE signature, COFF, Optional, Section Table)
//!    - .text Section (IAT, COR20 header, method bodies, metadata)
//!    - Import/Export Data
//!    - Additional Sections (.rsrc, .reloc)
//! 3. **Fixup**: Patch headers with final values (sizes, RVAs, checksum)
//! 4. **Truncate**: Remove over-allocated space
//!
//! # Architecture
//!
//! The key insight is that we don't need to pre-calculate everything. Instead:
//!
//! - **Streaming writes**: Write content as we go, tracking positions
//! - **Fixups**: Headers that need forward-referenced values get patched at the end
//! - **Context carries state**: WriteContext holds all positions and values we need
//!
//! # References
//!
//! - ECMA-335 §II.25 - File format extensions to PE
//! - [PE Format Specification](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)

use crate::{
    cilassembly::{
        changes::{AssemblyChanges, ChangeRef},
        writer::{
            context::{SectionWriteInfo, WriteContext, FILE_ALIGNMENT_DEFAULT},
            fields::{resolve_field_data_rva, write_field_data},
            fixups::{apply_all_fixups, fixup_metadata_stream_headers},
            heaps::{
                patch_row_heap_refs, precompute_heap_offsets, stream_blob_heap, stream_guid_heap,
                stream_strings_heap, stream_userstring_heap,
            },
            methods::remap_method_body_tokens,
            output::Output,
            relocations::{generate_relocations, RelocationConfig},
            remapper::{RemapReferences, RidRemapper},
        },
        CilAssembly, Operation, TableModifications,
    },
    dispatch_table_type,
    file::pe::{relocate_resource_section, DataDirectoryType, DosHeader, SectionTable},
    metadata::{
        exports::NativeExports,
        imports::NativeImports,
        method::MethodBody,
        root::Root,
        streams::{Blob, Guid, StreamHeader, Strings, UserStrings},
        tablefields::get_heap_fields,
        tables::{
            MethodDefRaw, RowWritable, StandAloneSigRaw, TableDataOwned, TableId, TableInfoRef,
        },
        token::Token,
    },
    utils::{align_to, calculate_table_row_size},
    Error, Result,
};
use std::{
    collections::{HashMap, HashSet},
    io::Write,
    path::Path,
    sync::Arc,
};
use strum::IntoEnumIterator;

/// IAT (Import Address Table) size for .NET executables (8 bytes).
const IAT_SIZE: u64 = 8;

/// Configuration options for PE file generation.
///
/// Controls assembly writing behavior:
/// - **Section exclusion**: Removes specified PE sections from output
/// - **Method body handling**: Controls whether original bodies are preserved
///
/// Note: Heap deduplication and table compaction are always enabled for
/// optimal output. Tables are always rebuilt fresh to ensure consistency.
#[derive(Debug, Clone, Default)]
pub struct GeneratorConfig {
    /// PE sections to exclude from the output.
    ///
    /// Section names in this set will be skipped during PE generation.
    /// This is useful for removing artifact sections from deobfuscated assemblies,
    /// such as encrypted data sections created by obfuscators.
    ///
    /// Note: Standard sections like .text, .rsrc, and .reloc have special handling
    /// and cannot be excluded via this mechanism.
    ///
    /// Default: empty (no sections excluded)
    pub excluded_sections: HashSet<String>,

    /// Skip copying original method bodies from source assembly.
    ///
    /// When enabled, the generator will not copy the original method body region
    /// from the source PE file. This is useful for deobfuscation where all method
    /// bodies have been regenerated and the original (potentially encrypted)
    /// bodies should be discarded.
    ///
    /// When disabled (default), original method bodies are preserved and new
    /// bodies are appended after them.
    ///
    /// Default: `false`
    pub skip_original_method_bodies: bool,
}

impl GeneratorConfig {
    /// Creates a new configuration with default settings.
    ///
    /// # Returns
    ///
    /// A new `GeneratorConfig` with:
    /// - `excluded_sections`: empty
    /// - `skip_original_method_bodies`: `false`
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the PE sections to exclude from the output.
    ///
    /// Section names in this set will be skipped during PE generation.
    /// This is useful for removing artifact sections from deobfuscated assemblies.
    ///
    /// # Arguments
    ///
    /// * `sections` - Set of section names to exclude
    ///
    /// # Returns
    ///
    /// The modified configuration for method chaining.
    #[must_use]
    pub fn with_excluded_sections(mut self, sections: HashSet<String>) -> Self {
        self.excluded_sections = sections;
        self
    }

    /// Enables or disables skipping original method bodies.
    ///
    /// When enabled, the generator will not copy the original method body region
    /// from the source PE file. This is essential for deobfuscation where all
    /// method bodies have been regenerated and the original (encrypted/obfuscated)
    /// bodies should be discarded.
    ///
    /// # Arguments
    ///
    /// * `enabled` - Whether to skip copying original method bodies
    ///
    /// # Returns
    ///
    /// The modified configuration for method chaining.
    #[must_use]
    pub fn with_skip_original_method_bodies(mut self, enabled: bool) -> Self {
        self.skip_original_method_bodies = enabled;
        self
    }
}

/// PE file generator that orchestrates complete file generation.
///
/// The `PeGenerator` takes a `CilAssembly` and generates a complete, valid PE file
/// using a streaming write approach with fixups applied at the end.
///
/// # Configuration
///
/// The generator supports configuration options via [`GeneratorConfig`]:
///
/// ```rust,ignore
/// let generator = PeGenerator::new(&assembly)
///     .with_config(GeneratorConfig::default());
/// ```
///
/// Or using the builder pattern:
///
/// ```rust,ignore
/// let generator = PeGenerator::with_config(
///     &assembly,
///     GeneratorConfig::new()
///         .with_skip_original_method_bodies(true)
/// );
/// ```
pub struct PeGenerator<'a> {
    assembly: &'a CilAssembly,
    config: GeneratorConfig,
}

impl<'a> PeGenerator<'a> {
    /// Creates a new PE generator for the given assembly with default configuration.
    ///
    /// # Arguments
    ///
    /// * `assembly` - The assembly to generate a PE file from
    ///
    /// # Returns
    ///
    /// A new `PeGenerator` with default configuration:
    /// - Heap deduplication: enabled
    /// - Dead reference elimination: disabled
    pub fn new(assembly: &'a CilAssembly) -> Self {
        Self {
            assembly,
            config: GeneratorConfig::default(),
        }
    }

    /// Creates a new PE generator with the specified configuration.
    ///
    /// # Arguments
    ///
    /// * `assembly` - The assembly to generate a PE file from
    /// * `config` - Configuration options controlling generation behavior
    ///
    /// # Returns
    ///
    /// A new `PeGenerator` with the specified configuration.
    pub fn with_config(assembly: &'a CilAssembly, config: GeneratorConfig) -> Self {
        Self { assembly, config }
    }

    /// Returns the current generator configuration.
    ///
    /// # Returns
    ///
    /// A reference to the current [`GeneratorConfig`].
    pub fn config(&self) -> &GeneratorConfig {
        &self.config
    }

    /// Sets the generator configuration.
    ///
    /// # Arguments
    ///
    /// * `config` - The new configuration to use for generation
    pub fn set_config(&mut self, config: GeneratorConfig) {
        self.config = config;
    }

    /// Generates a complete PE file to the specified path.
    ///
    /// This is the main entry point for PE file generation. It performs the complete
    /// generation process including:
    ///
    /// 1. Writing PE headers (DOS, COFF, Optional, Section Table)
    /// 2. Writing the .text section (IAT, COR20 header, method bodies, metadata)
    /// 3. Copying preserved sections (.rsrc, .reloc)
    /// 4. Applying fixups to headers with final values
    /// 5. Calculating and writing the PE checksum
    ///
    /// # Arguments
    ///
    /// * `path` - The file path where the PE file will be written
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on successful generation.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The output file cannot be created or written
    /// - Memory mapping operations fail
    /// - The assembly contains invalid metadata
    /// - Layout calculation fails due to size constraints
    pub fn to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        // Estimate file size for initial allocation (we'll truncate at the end)
        let estimated_size = self.estimate_file_size()?;

        // Create file-backed output
        let output = Output::create(&path, estimated_size)?;

        // Generate using internal method
        let ctx = self.generate(output)?;

        // Finalize file (truncate to actual size)
        ctx.output.finalize(Some(ctx.bytes_written))
    }

    /// Generates a complete PE file to memory.
    ///
    /// This method generates the PE file entirely in memory without writing to disk,
    /// returning the raw bytes. This is useful for:
    ///
    /// - In-memory assembly manipulation pipelines
    /// - Testing and validation without file I/O
    /// - Streaming assembly modifications to network or other outputs
    ///
    /// # Returns
    ///
    /// Returns `Ok(Vec<u8>)` containing the complete PE file bytes on success.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Memory allocation fails
    /// - The assembly contains invalid metadata
    /// - Layout calculation fails due to size constraints
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use dotscope::cilassembly::{CilAssembly, PeGenerator};
    ///
    /// let assembly = CilAssembly::new(view);
    /// // ... modify assembly ...
    ///
    /// let generator = PeGenerator::new(&assembly);
    /// let pe_bytes = generator.generate_to_memory()?;
    ///
    /// // Use pe_bytes for further processing
    /// ```
    pub fn to_memory(&self) -> Result<Vec<u8>> {
        // Estimate file size for initial allocation
        let estimated_size = self.estimate_file_size()?;

        // Create in-memory output
        let output = Output::create_in_memory(estimated_size)?;

        // Generate using internal method
        let ctx = self.generate(output)?;

        // Extract the bytes
        ctx.output.into_vec(Some(ctx.bytes_written))
    }

    /// Internal generation method that performs the actual PE writing.
    ///
    /// This is the core generation logic shared by both `generate_to_file` and
    /// `generate_to_memory`. It takes an already-created `Output` and performs
    /// all the generation steps.
    ///
    /// # Arguments
    ///
    /// * `output` - The output target (file-backed or in-memory)
    ///
    /// # Returns
    ///
    /// Returns the `WriteContext` after generation, allowing the caller to
    /// finalize the output appropriately.
    fn generate(&self, output: Output) -> Result<WriteContext<'_>> {
        let changes = self.assembly.changes();

        // Create write context
        let mut ctx = WriteContext::new(self.assembly, changes, output)?;

        // Phase 1: Write PE headers (positions tracked in ctx)
        self.write_dos_header(&mut ctx)?;
        self.write_pe_signature(&mut ctx)?;
        self.write_coff_header(&mut ctx)?;
        self.write_optional_header(&mut ctx)?;
        self.write_section_table(&mut ctx)?;

        // Align to file alignment for .text section
        ctx.align_to_file()?;
        ctx.text_section_offset = ctx.pos();

        // Phase 2: Write .text section content
        // Only write IAT for assemblies that need native imports (e.g., mscoree.dll).
        // .NET Core PE32+ assemblies typically have no IAT, no import table, and no
        // native entry point. Adding these unconditionally triggers CoreCLR's
        // CheckILOnly validation which requires matching base relocations, causing
        // BadImageFormatException for assemblies that originally lacked them.
        if self.needs_native_imports() {
            self.write_iat(&mut ctx)?;
        }
        self.write_cor20_header(&mut ctx)?;

        // Pre-compute heap offsets early - needed for method bodies that reference
        // newly added userstrings (ldstr instructions) and other heap entries.
        // This resolves ChangeRefs to their final heap offsets.
        precompute_heap_offsets(self.assembly.view(), &mut ctx, changes)?;

        // Resolve table ChangeRefs early - needed for method bodies that reference
        // newly added StandAloneSig entries (local variable signatures)
        Self::resolve_table_change_refs(changes);

        // Build RID remapper early - needed to patch IL tokens when rows are deleted.
        // When TypeDef/MethodDef/etc rows are removed, subsequent rows shift down
        // and IL tokens must be updated accordingly.
        if let Some(tables) = self.assembly.view().tables() {
            let mut original_counts: HashMap<TableId, u32> = HashMap::new();
            for table_id in TableId::iter() {
                let count = tables.table_row_count(table_id);
                if count > 0 {
                    original_counts.insert(table_id, count);
                }
            }

            let remapper = RidRemapper::from_changes(changes, &original_counts);
            if !remapper.is_empty() {
                ctx.token_remapping = remapper.build_token_remapping();
                // Store TypeDef RID remapping for signature blob processing
                // Note: typedef_remap() filters out deleted TypeDefs so signatures
                // referencing deleted types won't be corrupted by remapping to other types
                if let Some(typedef_remap) = remapper.typedef_remap() {
                    ctx.typedef_rid_remap = typedef_remap;
                }
                // Store TypeRef RID remapping for signature blob processing
                // When orphaned TypeRefs are removed, signature blobs must also be updated
                if let Some(typeref_remap) = remapper.typeref_remap() {
                    ctx.typeref_rid_remap = typeref_remap;
                }
            }

            // Build StandAloneSig deduplication mapping
            self.build_standalonesig_dedup(&mut ctx, changes);
        }

        // Write method bodies
        ctx.align_to_4();
        ctx.method_bodies_offset = ctx.pos();
        self.write_method_bodies(&mut ctx, changes)?;
        ctx.method_bodies_size = ctx.pos() - ctx.method_bodies_offset;

        // Write field initialization data (FieldRVA entries)
        write_field_data(&mut ctx)?;

        // Write CLR resources section (pointed to by COR20.resource_rva/resource_size)
        ctx.align_to_4();
        self.write_resource_data(&mut ctx, changes)?;

        // Write metadata (heaps first, then tables)
        ctx.align_to_4();
        ctx.metadata_offset = ctx.pos();
        self.write_metadata(&mut ctx, changes)?;
        ctx.metadata_size = ctx.pos() - ctx.metadata_offset;

        // Write import/export data (if present)
        if self.needs_native_imports() {
            Self::write_import_data(&mut ctx)?;
        }
        self.write_export_data(&mut ctx)?;

        // Write embedded PE resources if the original assembly had Win32 resources
        // in .text (no .rsrc section). These must be carried over to the new .text.
        self.write_embedded_pe_resources(&mut ctx)?;

        // Calculate .text section size and update sections vector
        ctx.text_section_size = ctx.pos() - ctx.text_section_offset;
        let text_size_u32 = u32::try_from(ctx.text_section_size).unwrap_or(u32::MAX);
        if let Some(idx) = ctx.find_section_index(".text") {
            ctx.update_section(
                idx,
                ctx.text_section_offset,
                ctx.text_section_rva,
                text_size_u32,
            );
        }

        // Align to file alignment for next section
        ctx.align_to_file()?;

        // Phase 3: Write additional sections (in order they appear in section table)
        self.write_other_sections(&mut ctx)?;

        // Phase 4: Apply fixups (patch headers with final values)
        apply_all_fixups(&mut ctx)?;

        Ok(ctx)
    }

    /// Estimates the total file size for initial allocation.
    ///
    /// This provides a conservative over-estimate. The actual file will be
    /// truncated to the correct size at the end.
    ///
    /// # Returns
    ///
    /// The estimated file size in bytes, aligned to file alignment.
    ///
    /// # Errors
    ///
    /// Returns an error if method body size calculation fails.
    fn estimate_file_size(&self) -> Result<u64> {
        let view = self.assembly.view();
        let file = view.file();

        // Get original file size as base estimate
        let original_size = file.data().len() as u64;

        // Add room for modifications (new methods, new heap entries, field data, etc.)
        let changes = self.assembly.changes();
        let method_bodies_expansion = u64::from(changes.method_bodies_total_size()?);
        let field_data_expansion = u64::from(changes.field_data_total_size()?);

        // Estimate heap expansion
        let heap_expansion = self.estimate_heap_expansion();

        // Estimate original FieldRVA data that will be relocated
        // (this may duplicate data already in original_size, but we're being conservative)
        let fieldrva_expansion = self.estimate_fieldrva_data_size();

        // Add 20% buffer for safety
        let estimated = original_size
            + method_bodies_expansion
            + field_data_expansion
            + heap_expansion
            + fieldrva_expansion;
        let with_buffer = (estimated * 120) / 100;

        // Align to file alignment
        Ok(align_to(with_buffer, u64::from(FILE_ALIGNMENT_DEFAULT)))
    }

    /// Estimates the size of original FieldRVA data that will be relocated.
    fn estimate_fieldrva_data_size(&self) -> u64 {
        let view = self.assembly.view();
        let Some(tables) = view.tables() else {
            return 0;
        };
        let Some(fieldrva_table) = tables.table::<MethodDefRaw>().map(|_| {
            // Use FieldRvaRaw if available
            tables.table_row_count(TableId::FieldRVA)
        }) else {
            return 0;
        };

        // Conservative estimate: assume average 64 bytes per FieldRVA entry
        // (typical for small arrays, struct data, etc.)
        u64::from(fieldrva_table) * 64
    }

    /// Estimates additional heap space needed for modifications.
    ///
    /// Calculates the total bytes needed for all appended heap entries including
    /// strings, blobs, GUIDs, and user strings.
    ///
    /// # Returns
    ///
    /// The estimated additional heap space in bytes.
    fn estimate_heap_expansion(&self) -> u64 {
        let changes = self.assembly.changes();
        let mut expansion = 0u64;

        // Add space for appended strings
        for (data, _) in changes.string_heap_changes.appended_iter() {
            expansion += data.len() as u64 + 1; // +1 for null terminator
        }

        // Add space for appended blobs
        for (data, _) in changes.blob_heap_changes.appended_iter() {
            expansion += data.len() as u64 + 5; // +5 for max compressed length prefix
        }

        // Add space for appended GUIDs
        expansion += (changes.guid_heap_changes.appended_iter().count() * 16) as u64;

        // Add space for appended user strings
        for (data, _) in changes.userstring_heap_changes.appended_iter() {
            expansion += data.len() as u64 + 5; // +5 for max compressed length prefix
        }

        expansion
    }

    /// Writes the DOS header with standard stub.
    ///
    /// Copies the original DOS header from the source assembly, preserving any
    /// custom DOS stub. The `e_lfanew` field at offset 0x3C is fixed up later.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The write context tracking positions and output
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success.
    ///
    /// # Errors
    ///
    /// Returns an error if reading from the source or writing fails.
    fn write_dos_header(&self, ctx: &mut WriteContext) -> Result<()> {
        ctx.dos_header_offset = ctx.pos();

        let view = self.assembly.view();
        let file = view.file();

        // Copy original DOS header (preserves any custom DOS stub)
        let dos_size = DosHeader::STANDARD_SIZE;
        let original_dos = file.data_slice(0, dos_size)?;
        ctx.write(original_dos)?;

        // e_lfanew at offset 0x3C will be fixed up later

        Ok(())
    }

    /// Writes the PE signature ("PE\0\0").
    ///
    /// # Arguments
    ///
    /// * `ctx` - The write context tracking positions and output
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success.
    ///
    /// # Errors
    ///
    /// Returns an error if writing fails.
    fn write_pe_signature(&self, ctx: &mut WriteContext) -> Result<()> {
        let _ = self; // Method signature kept for consistency
        ctx.pe_signature_offset = ctx.pos();
        ctx.write(b"PE\0\0")?;
        Ok(())
    }

    /// Writes the COFF header.
    ///
    /// Clones the original COFF header and patches fields that may change:
    /// - number_of_sections (if we add/remove sections)
    /// - size_of_optional_header (format-dependent)
    ///
    /// # Arguments
    ///
    /// * `ctx` - The write context tracking positions and output
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success.
    ///
    /// # Errors
    ///
    /// Returns an error if writing fails.
    fn write_coff_header(&self, ctx: &mut WriteContext) -> Result<()> {
        ctx.coff_header_offset = ctx.pos();

        let view = self.assembly.view();
        let pe = view.file().pe();

        // Clone and modify the COFF header
        let mut coff_header = pe.coff_header.clone();
        coff_header.number_of_sections = ctx.section_count;
        coff_header.size_of_optional_header =
            u16::try_from(ctx.optional_header_size()).map_err(|_| {
                Error::LayoutFailed(format!(
                    "Optional header size {} exceeds u16 range",
                    ctx.optional_header_size()
                ))
            })?;

        // Write using the struct's write_to method
        coff_header.write_to(ctx)?;

        Ok(())
    }

    /// Writes the optional header.
    ///
    /// Clones the original optional header and zeroes invalid data directories:
    /// - CertificateTable: Signature is invalidated by any modification
    /// - Debug: Debug info becomes stale (IL offsets change, PDB correlation breaks)
    ///
    /// Original directory locations are stored in ctx for zeroing actual data regions.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The write context tracking positions and output
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success.
    ///
    /// # Errors
    ///
    /// Returns an error if the PE has no optional header or writing fails.
    fn write_optional_header(&self, ctx: &mut WriteContext) -> Result<()> {
        ctx.optional_header_offset = ctx.pos();

        let view = self.assembly.view();
        let pe = view.file().pe();

        // Clone and modify the optional header
        let mut optional_header = pe
            .optional_header
            .clone()
            .ok_or_else(|| Error::LayoutFailed("No optional header in PE file".to_string()))?;

        // Store original debug directory location for zeroing the data region later
        if let Some(debug_dir) = pe.get_data_directory(DataDirectoryType::Debug) {
            if debug_dir.virtual_address != 0 && debug_dir.size != 0 {
                ctx.original_debug_dir = Some((debug_dir.virtual_address, debug_dir.size));
            }
        }

        // Store original certificate directory location for zeroing the data region later
        // Note: Certificate table uses file offset (not RVA) in the virtual_address field
        if let Some(cert_dir) = pe.get_data_directory(DataDirectoryType::CertificateTable) {
            if cert_dir.virtual_address != 0 && cert_dir.size != 0 {
                ctx.original_certificate_dir = Some((cert_dir.virtual_address, cert_dir.size));
            }
        }

        // Zero out CertificateTable - signature is invalid after modification
        optional_header
            .data_directories
            .update_entry(DataDirectoryType::CertificateTable, 0, 0);

        // Zero out Debug directory - debug info becomes invalid after modification
        optional_header
            .data_directories
            .update_entry(DataDirectoryType::Debug, 0, 0);

        // Write using the struct's write_to method
        optional_header.write_to(ctx)?;

        Ok(())
    }

    /// Writes the section table.
    ///
    /// Writes all section headers. Fields that change (VirtualAddress,
    /// SizeOfRawData, PointerToRawData) are fixed up later in apply_fixups.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The write context tracking positions and output
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success.
    ///
    /// # Errors
    ///
    /// Returns an error if writing fails.
    fn write_section_table(&self, ctx: &mut WriteContext) -> Result<()> {
        ctx.section_table_offset = ctx.pos();

        let view = self.assembly.view();
        let pe = view.file().pe();

        // Write each section header and track its position
        for section in &pe.sections {
            let header_offset = ctx.pos();

            // Write the section header
            section.write_to(ctx)?;

            // Record section info for later fixup
            ctx.sections.push(SectionWriteInfo {
                name: section.name.clone(),
                characteristics: section.characteristics,
                header_offset,
                data_offset: None,
                rva: None,
                data_size: None,
                removed: false,
            });
        }

        Ok(())
    }

    /// Writes the IAT (Import Address Table) at the start of .text section.
    ///
    /// Builds the complete import list (mscoree.dll first, then any native imports)
    /// and writes the IAT content directly. The IAT is placed at the very start of
    /// .text section as required by .NET PE format.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The write context tracking positions and output
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success.
    ///
    /// # Errors
    ///
    /// Returns an error if building imports or writing fails.
    fn write_iat(&self, ctx: &mut WriteContext) -> Result<()> {
        ctx.iat_offset = ctx.pos();

        // Build complete import list: mscoree.dll first, then preserved + new imports
        let imports = self.build_import_list(ctx)?;

        // Calculate IAT size
        let iat_size = imports.iat_byte_size(ctx.is_pe32_plus);

        if iat_size == 0 {
            // No imports - write minimal placeholder (shouldn't happen for .NET)
            let zeros = [0u8; 8];
            ctx.write(&zeros)?;
            ctx.iat_size = 8;
        } else {
            // Calculate where import table will be written (needed for string RVA calculation)
            // This is a forward reference - we'll write the import table after metadata
            // For now, use a placeholder RVA that will be corrected when we know the final position
            // The IAT content depends on import_table_rva for hint/name string references
            //
            // Since we don't know import_table_rva yet, we store the imports and build IAT
            // later as part of write_import_data, then patch the IAT offset.
            //
            // Alternative: write zeros now, then patch in fixup phase
            let zeros = vec![0u8; iat_size];
            ctx.write(&zeros)?;
            ctx.iat_size = iat_size as u64;
        }

        // Store imports for use in write_import_data
        ctx.pending_imports = Some(imports);

        Ok(())
    }

    /// Builds the complete import list for the assembly.
    ///
    /// The import list is built by merging:
    /// 1. mscoree.dll with _CorExeMain/_CorDllMain (always first)
    /// 2. Original imports from the source PE (excluding mscoree.dll)
    /// 3. User-added imports from assembly changes
    ///
    /// # Arguments
    ///
    /// * `ctx` - The write context (used for PE format detection)
    ///
    /// # Returns
    ///
    /// A `NativeImports` containing all imports with mscoree.dll first.
    fn build_import_list(&self, ctx: &WriteContext) -> Result<NativeImports> {
        let view = self.assembly.view();

        // Collect non-mscoree imports from original PE
        let mut other_imports = NativeImports::new();
        other_imports.set_pe_format(ctx.is_pe32_plus);

        if let Some(pe_imports) = view.file().imports() {
            let original = NativeImports::from_pe_imports(pe_imports, ctx.is_pe32_plus)?;
            for desc in original.descriptors() {
                // Skip mscoree.dll - we'll add it correctly as first import
                if desc.dll_name.eq_ignore_ascii_case("mscoree.dll") {
                    continue;
                }
                if other_imports.add_dll(&desc.dll_name).is_ok() {
                    for func in &desc.functions {
                        if let Some(ref name) = func.name {
                            let _ = other_imports.add_function(&desc.dll_name, name);
                        } else if let Some(ordinal) = func.ordinal {
                            let _ = other_imports.add_function_by_ordinal(&desc.dll_name, ordinal);
                        }
                    }
                }
            }
        }

        // Add user-specified imports from changes
        let new_imports = self.assembly.changes().native_imports().native();
        for desc in new_imports.descriptors() {
            // Skip mscoree.dll - protected
            if desc.dll_name.eq_ignore_ascii_case("mscoree.dll") {
                continue;
            }
            // Add or merge with existing
            if !other_imports.has_dll(&desc.dll_name) {
                let _ = other_imports.add_dll(&desc.dll_name);
            }
            for func in &desc.functions {
                if let Some(ref name) = func.name {
                    let _ = other_imports.add_function(&desc.dll_name, name);
                } else if let Some(ordinal) = func.ordinal {
                    let _ = other_imports.add_function_by_ordinal(&desc.dll_name, ordinal);
                }
            }
        }

        // Build final import list with mscoree.dll FIRST
        let mut final_imports = NativeImports::new();
        final_imports.set_pe_format(ctx.is_pe32_plus);

        // Determine entry point function based on PE characteristics
        // IMAGE_FILE_DLL = 0x2000
        let is_dll = view.file().header().characteristics & 0x2000 != 0;
        let entry_fn = if is_dll { "_CorDllMain" } else { "_CorExeMain" };

        // Add mscoree.dll first (required for .NET)
        final_imports.add_dll("mscoree.dll")?;
        final_imports.add_function("mscoree.dll", entry_fn)?;

        // Add all other imports after mscoree.dll
        for desc in other_imports.descriptors() {
            final_imports.add_dll(&desc.dll_name)?;
            for func in &desc.functions {
                if let Some(ref name) = func.name {
                    let _ = final_imports.add_function(&desc.dll_name, name);
                } else if let Some(ordinal) = func.ordinal {
                    let _ = final_imports.add_function_by_ordinal(&desc.dll_name, ordinal);
                }
            }
        }

        Ok(final_imports)
    }

    /// Checks if this assembly is IL-only (no native code).
    ///
    /// Examines the COMIMAGE_FLAGS_ILONLY flag in the COR20 header.
    ///
    /// # Returns
    ///
    /// `true` if the assembly contains only managed IL code, `false` if it has native code.
    fn is_il_only(&self) -> bool {
        const COMIMAGE_FLAGS_ILONLY: u32 = 0x0000_0001;
        let cor20 = self.assembly.view().cor20header();
        (cor20.flags & COMIMAGE_FLAGS_ILONLY) != 0
    }

    /// Checks if this is a DLL (not an EXE).
    ///
    /// Examines the IMAGE_FILE_DLL flag in the COFF characteristics.
    ///
    /// # Returns
    ///
    /// `true` if the assembly is a DLL, `false` if it's an EXE.
    fn is_dll(&self) -> bool {
        const IMAGE_FILE_DLL: u16 = 0x2000;
        let characteristics = self.assembly.view().file().header().characteristics;
        (characteristics & IMAGE_FILE_DLL) != 0
    }

    /// Checks if this assembly needs native import table entries.
    ///
    /// Returns `true` if the original PE had native imports (e.g., mscoree.dll)
    /// or if the user has added new native imports. .NET Core assemblies compiled
    /// for x64 typically have no IAT, no import table, and no native entry point;
    /// adding these unconditionally triggers CoreCLR's `CheckILOnly` validation
    /// which requires matching base relocations.
    fn needs_native_imports(&self) -> bool {
        let view = self.assembly.view();

        // Check if original PE had any imports
        if view.file().imports().is_some() {
            return true;
        }

        // Check if user has added any native imports
        let user_imports = self.assembly.changes().native_imports().native();
        if !user_imports.is_empty() {
            return true;
        }

        false
    }

    /// Writes the COR20 (CLR) header.
    ///
    /// Clones the original COR20 header and zeroes the strong name signature
    /// (invalidated by modifications). MetaData RVA/Size are fixed up later.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The write context tracking positions and output
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success.
    ///
    /// # Errors
    ///
    /// Returns an error if writing fails.
    fn write_cor20_header(&self, ctx: &mut WriteContext) -> Result<()> {
        ctx.cor20_header_offset = ctx.pos();

        let view = self.assembly.view();

        // Clone and modify the COR20 header
        let mut cor20_header = *view.cor20header();

        // Zero strong name signature - invalidated by modifications
        cor20_header.strong_name_signature_rva = 0;
        cor20_header.strong_name_signature_size = 0;

        // Write using the struct's write_to method
        // MetaData RVA and Size will be fixed up later in apply_fixups
        // Entry point token remapping is also handled in fixups (after token_remapping is built)
        cor20_header.write_to(ctx)?;

        Ok(())
    }

    /// Writes method bodies to the output.
    ///
    /// Copies original method bodies and appends new method bodies from changes.
    /// Handles IL token patching for userstring remapping and metadata token updates.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The write context tracking positions and output
    /// * `changes` - The assembly changes containing new method bodies
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success.
    ///
    /// # Errors
    ///
    /// Returns an error if reading source data or writing fails.
    fn write_method_bodies(&self, ctx: &mut WriteContext, changes: &AssemblyChanges) -> Result<()> {
        let view = self.assembly.view();
        let file = view.file();

        // Copy original method bodies individually (unless configured to skip them)
        // This explicitly copies ONLY method bodies, not FieldRVA data or other content
        // that might be interspersed in the same region.
        if !self.config.skip_original_method_bodies {
            if let Some(tables) = view.tables() {
                if let Some(method_table) = tables.table::<MethodDefRaw>() {
                    // Check if we need to patch IL tokens
                    let has_userstring_changes = !ctx.heap_remapping.userstrings.is_empty();
                    let has_token_changes = !ctx.token_remapping.is_empty();

                    let deleted_method_rids: HashSet<u32> = changes
                        .get_table_modifications(TableId::MethodDef)
                        .map(|mods| mods.deleted_rids().collect())
                        .unwrap_or_default();

                    // Track RVAs we've already written to avoid duplicates.
                    // Multiple MethodDef entries can share the same RVA if they have
                    // identical IL bodies - we only need to write each unique body once.
                    let mut written_rvas: HashSet<u32> = HashSet::new();

                    for row in method_table {
                        if deleted_method_rids.contains(&row.rid) {
                            continue;
                        }

                        let original_rva = row.rva;
                        if original_rva == 0 {
                            continue; // Abstract/external method, no body
                        }

                        // Skip placeholder RVAs - these method bodies are stored in
                        // changes.method_bodies() and will be written separately below.
                        // This happens when cleanup patches a method body and stores it
                        // with a placeholder RVA.
                        if ChangeRef::is_placeholder(original_rva) {
                            continue;
                        }

                        // Skip if we've already written a body at this RVA.
                        // The RVA mapping was already recorded on first write.
                        if written_rvas.contains(&original_rva) {
                            continue;
                        }
                        written_rvas.insert(original_rva);

                        // Read method body at original RVA
                        let offset = file.rva_to_offset(original_rva as usize)?;
                        let available_data = file.data_slice(offset, file.data().len() - offset)?;

                        // Parse method body to get its size
                        let method_body = MethodBody::from(available_data).map_err(|e| {
                            Error::ModificationInvalid(format!(
                                "Cannot parse method body at RVA 0x{original_rva:08x}: {e}"
                            ))
                        })?;
                        let body_size = method_body.size();

                        // Read just the method body bytes
                        let body_data = file.data_slice(offset, body_size)?;

                        // Fat method headers require 4-byte alignment (ECMA-335 §II.25.4.2)
                        // Tiny headers have no alignment requirement
                        if method_body.is_fat {
                            ctx.align_to_4_with_padding()?;
                        }

                        // Track new RVA for this method
                        let new_rva = ctx.current_rva();
                        ctx.method_body_rva_map.insert(original_rva, new_rva);

                        // Apply token patching if needed
                        if has_userstring_changes || has_token_changes {
                            let mut patched_body = body_data.to_vec();
                            remap_method_body_tokens(
                                &mut patched_body,
                                &ctx.token_remapping,
                                &ctx.heap_remapping.userstrings,
                                None, // No changes for original methods
                            )?;
                            ctx.write(&patched_body)?;
                        } else {
                            ctx.write(body_data)?;
                        }
                    }
                }
            }
        }

        // Write new method bodies (sorted by placeholder RVA)
        let mut bodies: Vec<_> = changes.method_bodies().collect();
        bodies.sort_by_key(|(placeholder, _)| *placeholder);

        for (placeholder_rva, body_bytes) in bodies {
            // Fat method headers require 4-byte alignment (ECMA-335 §II.25.4.2)
            // Check first byte: (byte & 0x3) == 0x3 means fat header
            let is_fat = !body_bytes.is_empty() && (body_bytes[0] & 0x3) == 0x3;
            if is_fat {
                ctx.align_to_4_with_padding()?;
            }

            // Calculate actual RVA for this method body
            let actual_rva = ctx.current_rva();
            ctx.method_body_rva_map.insert(placeholder_rva, actual_rva);

            // Remap tokens in the method body in place.
            // This handles both placeholder resolution and token remapping for row deletions.
            let mut resolved_body = body_bytes.clone();
            remap_method_body_tokens(
                &mut resolved_body,
                &ctx.token_remapping,
                &HashMap::new(), // No userstring remapping for new bodies
                Some(changes),
            )?;

            ctx.write(&resolved_body)?;
        }

        Ok(())
    }

    /// Writes the CLR resources section.
    ///
    /// This section contains embedded managed resources accessed via
    /// `Assembly.GetManifestResourceStream()`. The section is pointed to by the
    /// COR20 header's resource_rva/resource_size fields.
    ///
    /// Each resource entry is stored as:
    /// - 4-byte little-endian length prefix
    /// - Actual resource data bytes
    ///
    /// The ManifestResource table's offset_field contains offsets relative to the
    /// start of this section.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The write context tracking positions and output
    /// * `changes` - The assembly changes containing new resource data
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success.
    ///
    /// # Errors
    ///
    /// Returns an error if reading source data or writing fails.
    fn write_resource_data(&self, ctx: &mut WriteContext, changes: &AssemblyChanges) -> Result<()> {
        let view = self.assembly.view();
        let file = view.file();
        let cor20 = view.cor20header();

        // Track the start of the resources section
        ctx.resource_data_offset = ctx.pos();

        // Copy original resources (if any exist)
        if cor20.resource_rva != 0 && cor20.resource_size != 0 {
            let resource_offset = file.rva_to_offset(cor20.resource_rva as usize)?;
            let original_data = file.data_slice(resource_offset, cor20.resource_size as usize)?;
            ctx.write(original_data)?;
        }

        // Append new resources from changes
        // Note: The offsets in ManifestResource.offset_field are calculated based on
        // the position where resources are stored in changes.resource_data, which
        // accounts for original resource size via store_resource_data's offset calculation.
        // However, for newly added resources, we need to adjust offsets based on the
        // original resource size. This is handled by the offset calculation in
        // AssemblyChanges::store_resource_data - the offset returned is relative to
        // the START of the new resource data section, so we need to add the original
        // resource size when writing the table.
        if changes.has_resource_data() {
            ctx.write(changes.resource_data_bytes())?;
        }

        // Calculate total size
        ctx.resource_data_size = ctx.pos() - ctx.resource_data_offset;

        Ok(())
    }

    /// Writes the complete metadata section.
    ///
    /// The metadata section layout is:
    /// 1. Metadata root header (signature, version, stream count)
    /// 2. Stream headers (offsets and sizes, all relative to metadata root)
    /// 3. #~ stream (tables)
    /// 4. #Strings heap
    /// 5. #US heap
    /// 6. #GUID heap
    /// 7. #Blob heap
    ///
    /// Headers have fixed structure - we write them with placeholders first,
    /// then write content, then fixup the header fields with actual values.
    ///
    /// The key insight: heaps produce offset remapping during streaming writes.
    /// Tables contain heap references that need patching. So we:
    /// 1. Write metadata root header (with placeholder stream offsets/sizes)
    /// 2. Write tables stream (table data written sequentially)
    /// 3. Write heaps → get remapping
    /// 4. Patch table rows in-place with new heap offsets
    /// 5. Fixup metadata root header with final stream offsets/sizes
    ///
    /// # Arguments
    ///
    /// * `ctx` - The write context tracking positions and output
    /// * `changes` - The assembly changes containing modifications
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success.
    ///
    /// # Errors
    ///
    /// Returns an error if any phase of metadata writing fails.
    fn write_metadata(&self, ctx: &mut WriteContext, changes: &AssemblyChanges) -> Result<()> {
        let view = self.assembly.view();
        let root = view.metadata_root();

        // Note: precompute_heap_offsets is called earlier (before method bodies)
        // so that ChangeRefs are resolved for IL placeholder patching.

        // PHASE 1: Write metadata root header with placeholder stream headers
        let metadata_root_offset = ctx.pos();
        // We'll track where stream headers start so we can patch them later
        let stream_headers_offset = self.write_metadata_root_header(ctx, root)?;

        // PHASE 2: Write tables stream (ChangeRefs are now resolved!)
        ctx.align_to_4();
        ctx.tables_stream_offset = ctx.pos();
        self.write_tables_stream(ctx, changes)?;

        // PHASE 3: Write heaps - this populates ctx.heap_remapping
        // Note: ChangeRefs are already resolved, so this just writes the data
        self.write_heaps(ctx, changes)?;

        // PHASE 4: Patch table rows after heaps are written
        // This handles old→new heap offset remapping (from deduplication)
        // ChangeRef resolution is no longer needed here since we pre-computed offsets
        self.patch_tables_after_heaps(ctx, changes)?;

        // PHASE 5: Fixup metadata root header with final stream offsets/sizes
        fixup_metadata_stream_headers(ctx, metadata_root_offset, stream_headers_offset)?;

        // Update metadata size
        ctx.metadata_size = ctx.pos() - metadata_root_offset;

        // Note: Table ChangeRefs are resolved earlier (before method bodies)
        // to support methods with local variable signatures

        Ok(())
    }

    /// Writes the metadata root header with placeholder stream headers.
    ///
    /// Creates a modified root header with 5 standard stream headers containing
    /// placeholder values (offset=0, size=0). These are patched later by
    /// `fixup_metadata_stream_headers` after all streams are written.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The write context tracking positions and output
    /// * `root` - The original metadata root to clone
    ///
    /// # Returns
    ///
    /// The file offset where stream headers start (for later fixup).
    ///
    /// # Errors
    ///
    /// Returns an error if writing fails.
    fn write_metadata_root_header(&self, ctx: &mut WriteContext, root: &Root) -> Result<u64> {
        let _ = self; // Method signature kept for consistency
                      // Create a modified root with placeholder stream headers
        let placeholder_streams: Vec<StreamHeader> = ["#~", "#Strings", "#US", "#GUID", "#Blob"]
            .iter()
            .map(|name| StreamHeader {
                offset: 0, // Placeholder - will be patched later
                size: 0,   // Placeholder - will be patched later
                name: (*name).to_string(),
            })
            .collect();

        let version_padded_len = (root.version.len() + 3) & !3;
        let version_len_u32 = u32::try_from(version_padded_len).map_err(|_| {
            Error::LayoutFailed(format!(
                "Version length {version_padded_len} exceeds u32 range"
            ))
        })?;
        let modified_root = Root {
            signature: root.signature,
            major_version: root.major_version,
            minor_version: root.minor_version,
            reserved: root.reserved,
            length: version_len_u32,
            version: root.version.clone(),
            flags: root.flags,
            stream_number: 5, // We always have 5 streams
            stream_headers: placeholder_streams,
        };

        // Calculate where stream headers will start (after fixed root header)
        // sig(4) + major(2) + minor(2) + reserved(4) + length(4) + version(padded) + flags(2) + count(2)
        let fixed_header_size = 4 + 2 + 2 + 4 + 4 + version_padded_len + 2 + 2;
        let stream_headers_offset = ctx.pos() + fixed_header_size as u64;

        // Write the full root header using its write_to method
        modified_root.write_to(ctx)?;

        Ok(stream_headers_offset)
    }

    /// Patches table rows in-place after heaps are written.
    ///
    /// This handles two types of patching:
    /// 1. Old→new heap offset remapping (from streaming heap deduplication)
    /// 2. ChangeRef placeholder resolution (for newly added heap entries)
    ///
    /// # Arguments
    ///
    /// * `ctx` - The write context with heap remapping data
    /// * `changes` - The assembly changes for ChangeRef lookup
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success.
    ///
    /// # Errors
    ///
    /// Returns an error if the assembly has no tables or read/write operations fail.
    fn patch_tables_after_heaps(
        &self,
        ctx: &mut WriteContext,
        changes: &AssemblyChanges,
    ) -> Result<()> {
        let view = self.assembly.view();
        let tables = view
            .tables()
            .ok_or_else(|| Error::LayoutFailed("No tables found".to_string()))?;

        // Calculate new row counts for each table (needed for output table info)
        let mut new_row_counts: HashMap<TableId, u32> = HashMap::new();
        let mut valid = tables.valid;

        for table_id in TableId::iter() {
            let original_count = tables.table_row_count(table_id);
            if let Some(table_mod) = changes.get_table_modifications(table_id) {
                let mut new_count = self.calculate_table_row_count(table_id, table_mod)?;
                // Subtract deduplicated StandAloneSig entries
                if table_id == TableId::StandAloneSig {
                    #[allow(clippy::cast_possible_truncation)]
                    let skip_len = ctx.standalonesig_skip.len() as u32;
                    new_count = new_count.saturating_sub(skip_len);
                }
                new_row_counts.insert(table_id, new_count);
                if new_count > 0 {
                    valid |= 1u64 << (table_id as u64);
                } else {
                    valid &= !(1u64 << (table_id as u64));
                }
            } else if original_count > 0 {
                // Unmodified table - keep original count (minus dedup for StandAloneSig)
                let mut count = original_count;
                if table_id == TableId::StandAloneSig {
                    #[allow(clippy::cast_possible_truncation)]
                    let skip_len = ctx.standalonesig_skip.len() as u32;
                    count = count.saturating_sub(skip_len);
                }
                new_row_counts.insert(table_id, count);
            }
        }

        // Create output table info with new row counts (same as in write_tables_stream)
        // This ensures we use the correct row sizes for reading the output
        let output_table_info = Arc::new(
            tables
                .info
                .with_modified_row_counts(new_row_counts.iter().map(|(k, v)| (*k, *v))),
        );

        // Calculate where table data starts (after tables stream header)
        let header_size = 24 + (valid.count_ones() as usize * 4);
        let mut table_data_offset = ctx.tables_stream_offset + header_size as u64;

        // Clone remapping to avoid borrow issues
        let strings_remap = ctx.heap_remapping.strings.clone();
        let blobs_remap = ctx.heap_remapping.blobs.clone();
        let guids_remap = ctx.heap_remapping.guids.clone();

        for table_id in TableId::iter() {
            if valid & (1u64 << (table_id as u64)) == 0 {
                continue;
            }

            // Get the output row count
            let output_row_count = new_row_counts.get(&table_id).copied().unwrap_or(0);

            // Use output table info row size since we're reading from output
            let row_size = calculate_table_row_size(table_id, &output_table_info) as usize;

            // Patch each row in the output table
            for output_idx in 0..output_row_count as usize {
                let row_offset = table_data_offset + (output_idx as u64 * row_size as u64);
                let mut row_buffer = vec![0u8; row_size];
                ctx.output.read_at(row_offset, &mut row_buffer)?;

                // First: resolve ChangeRef placeholders (for newly added heap entries)
                // These are heap references that were written before heaps existed
                Self::patch_row_change_ref_placeholders(
                    &mut row_buffer,
                    table_id,
                    &output_table_info,
                    changes,
                );

                // Second: apply old→new heap offset remapping (from deduplication)
                // This applies to ALL rows, including updated ones. ChangeRef placeholders
                // resolve to NEW heap offsets, which won't appear in the remapping (since
                // remapping only contains old->new mappings for deduplicated entries).
                // Updated rows may still have original heap offsets in fields that weren't
                // modified (e.g., a MethodDef update that only changes RVA but not name).
                if ctx.heap_remapping.has_changes() {
                    patch_row_heap_refs(
                        table_id,
                        &mut row_buffer,
                        &output_table_info,
                        &strings_remap,
                        &blobs_remap,
                        &guids_remap,
                    );
                }

                ctx.write_at(row_offset, &row_buffer)?;
            }

            table_data_offset += u64::from(output_row_count) * (row_size as u64);
        }

        Ok(())
    }

    /// Patches ChangeRef placeholders in a table row buffer.
    ///
    /// When tables are written before heaps, heap references for newly added entries
    /// contain ChangeRef placeholder values. After heaps are written and ChangeRefs
    /// are resolved, this function patches those placeholders to actual offsets.
    ///
    /// # Arguments
    ///
    /// * `row_buffer` - The raw bytes of the table row to patch
    /// * `table_id` - The table type (determines which fields are heap references)
    /// * `table_info` - Table size information for field offset calculation
    /// * `changes` - The assembly changes for ChangeRef lookup
    fn patch_row_change_ref_placeholders(
        row_buffer: &mut [u8],
        table_id: TableId,
        table_info: &TableInfoRef,
        changes: &AssemblyChanges,
    ) {
        // Get heap field positions using the centralized schema
        let heap_fields = get_heap_fields(table_id, table_info);

        for field in heap_fields {
            if field.offset + field.size > row_buffer.len() {
                continue;
            }

            // Read the field value
            let value = if field.size == 4 {
                u32::from_le_bytes([
                    row_buffer[field.offset],
                    row_buffer[field.offset + 1],
                    row_buffer[field.offset + 2],
                    row_buffer[field.offset + 3],
                ])
            } else {
                u32::from(u16::from_le_bytes([
                    row_buffer[field.offset],
                    row_buffer[field.offset + 1],
                ]))
            };

            // Check if it's a placeholder
            if ChangeRef::is_placeholder(value) {
                if let Some(change_ref) = changes.lookup_by_placeholder(value) {
                    if let Some(resolved) = change_ref.offset() {
                        // Write the resolved value back
                        if field.size == 4 {
                            row_buffer[field.offset..field.offset + 4]
                                .copy_from_slice(&resolved.to_le_bytes());
                        } else {
                            // Truncate to u16 - this is safe because heap offsets in small
                            // metadata files fit in u16. Overflow would indicate a corrupted state.
                            #[allow(clippy::cast_possible_truncation)]
                            let small_value =
                                u16::try_from(resolved).unwrap_or((resolved & 0xFFFF) as u16);
                            row_buffer[field.offset..field.offset + 2]
                                .copy_from_slice(&small_value.to_le_bytes());
                        }
                    }
                }
            }
        }
    }

    /// Estimates the size of the metadata root header.
    ///
    /// Calculates the approximate size needed for the metadata root header including
    /// the version string (aligned to 4 bytes) and stream headers.
    ///
    /// # Returns
    ///
    /// The estimated header size in bytes.
    fn estimate_metadata_header_size(&self) -> usize {
        let view = self.assembly.view();
        let root = view.metadata_root();

        // Base header: signature (4) + major (2) + minor (2) + reserved (4) + version_length (4)
        let base_size = 16;
        // Version string aligned to 4 bytes
        let version_len = root.version.len();
        // Safe cast: version_len is a string length which is always small
        let aligned_version =
            usize::try_from(align_to(version_len as u64, 4)).unwrap_or(version_len + 4);
        // Flags (2) + stream count (2)
        let flags_and_count = 4;
        // Stream headers: each is offset (4) + size (4) + name (variable, 4-byte aligned)
        // Estimate 5 streams max with ~12 bytes each for names
        let stream_headers = 5 * (8 + 12);

        base_size + aligned_version + flags_and_count + stream_headers
    }

    /// Writes all heaps using streaming writers.
    ///
    /// Writes the four metadata heaps in order: #Strings, #US, #GUID, #Blob.
    /// Each heap is aligned to 4 bytes and uses streaming deduplication.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The write context tracking positions and heap mappings
    /// * `changes` - The assembly changes containing heap modifications
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success.
    ///
    /// # Errors
    ///
    /// Returns an error if heap streaming fails.
    fn write_heaps(&self, ctx: &mut WriteContext, changes: &AssemblyChanges) -> Result<()> {
        let view = self.assembly.view();

        // Default empty heap data
        let empty_strings: &[u8] = &[0u8];
        let empty_blob: &[u8] = &[0u8];
        let empty_guid: &[u8] = &[];
        let empty_us: &[u8] = &[0u8];

        // Get source heap data
        let strings_data: &[u8] = changes
            .string_heap_changes
            .replacement_heap()
            .map(Vec::as_slice)
            .or_else(|| view.strings().map(Strings::data))
            .unwrap_or(empty_strings);

        let blob_data: &[u8] = changes
            .blob_heap_changes
            .replacement_heap()
            .map(Vec::as_slice)
            .or_else(|| view.blobs().map(Blob::data))
            .unwrap_or(empty_blob);

        let guid_data: &[u8] = changes
            .guid_heap_changes
            .replacement_heap()
            .map(Vec::as_slice)
            .or_else(|| view.guids().map(Guid::data))
            .unwrap_or(empty_guid);

        let us_data: &[u8] = changes
            .userstring_heap_changes
            .replacement_heap()
            .map(Vec::as_slice)
            .or_else(|| view.userstrings().map(UserStrings::data))
            .unwrap_or(empty_us);

        // Write #Strings heap
        ctx.align_to_4();
        ctx.strings_heap_offset = ctx.pos();
        let strings_result = stream_strings_heap(
            &mut ctx.output,
            ctx.strings_heap_offset,
            strings_data,
            &changes.string_heap_changes,
            &changes.referenced_string_offsets,
        )?;
        ctx.strings_heap_size = strings_result.bytes_written;
        ctx.heap_remapping.strings = strings_result.remapping;
        ctx.advance(ctx.strings_heap_size);

        // Write #US heap
        ctx.align_to_4();
        ctx.us_heap_offset = ctx.pos();
        let us_result = stream_userstring_heap(
            &mut ctx.output,
            ctx.us_heap_offset,
            us_data,
            &changes.userstring_heap_changes,
        )?;
        ctx.us_heap_size = us_result.bytes_written;
        ctx.heap_remapping.userstrings = us_result.remapping;
        ctx.advance(ctx.us_heap_size);

        // Write #GUID heap
        ctx.align_to_4();
        ctx.guid_heap_offset = ctx.pos();
        let guid_result = stream_guid_heap(
            &mut ctx.output,
            ctx.guid_heap_offset,
            guid_data,
            &changes.guid_heap_changes,
        )?;
        ctx.guid_heap_size = guid_result.bytes_written;
        ctx.heap_remapping.guids = guid_result.remapping;
        ctx.advance(ctx.guid_heap_size);

        // Write #Blob heap (with signature token remapping if TypeDefs/TypeRefs were deleted)
        ctx.align_to_4();
        ctx.blob_heap_offset = ctx.pos();
        let blob_result = stream_blob_heap(
            &mut ctx.output,
            ctx.blob_heap_offset,
            blob_data,
            &changes.blob_heap_changes,
            &ctx.typedef_rid_remap,
            &ctx.typeref_rid_remap,
        )?;
        ctx.blob_heap_size = blob_result.bytes_written;
        ctx.heap_remapping.blobs = blob_result.remapping;
        ctx.advance(ctx.blob_heap_size);

        // Align final position to 4 bytes for proper metadata section end
        ctx.align_to_4();

        Ok(())
    }

    /// Resolves all table row ChangeRefs to their actual metadata tokens.
    ///
    /// Iterates through all table ChangeRefs and resolves unresolved ones to their
    /// final metadata token values (combining table ID and RID).
    ///
    /// # Arguments
    ///
    /// * `changes` - The assembly changes containing table ChangeRefs
    fn resolve_table_change_refs(changes: &AssemblyChanges) {
        for (table_id, rid, change_ref) in changes.all_table_change_refs() {
            if !change_ref.is_resolved() {
                let token = Token::from_parts(table_id, *rid);
                change_ref.resolve_to_token(token);
            }
        }
    }

    /// Writes the tables stream (#~).
    ///
    /// Writes the tables stream header followed by all table data. This writes tables
    /// with original heap references; heap patching happens AFTER heaps are written
    /// via `patch_tables_after_heaps`.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The write context tracking positions and output
    /// * `changes` - The assembly changes containing table modifications
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success.
    ///
    /// # Errors
    ///
    /// Returns an error if the assembly has no tables or writing fails.
    fn write_tables_stream(&self, ctx: &mut WriteContext, changes: &AssemblyChanges) -> Result<()> {
        let view = self.assembly.view();

        let tables = view
            .tables()
            .ok_or_else(|| Error::LayoutFailed("No tables found in assembly".to_string()))?;

        // Build original row counts map for RID remapping
        let mut original_counts: HashMap<TableId, u32> = HashMap::new();
        for table_id in TableId::iter() {
            let count = tables.table_row_count(table_id);
            if count > 0 {
                original_counts.insert(table_id, count);
            }
        }

        // Build RID remapper for handling row deletions
        let remapper = RidRemapper::from_changes(changes, &original_counts);

        // Calculate new row counts for all tables and build valid bitvector
        let mut valid = tables.valid;
        let mut new_row_counts: HashMap<TableId, u32> = HashMap::new();

        for table_id in TableId::iter() {
            let original_count = tables.table_row_count(table_id);
            if let Some(table_mod) = changes.get_table_modifications(table_id) {
                let mut new_count = self.calculate_table_row_count(table_id, table_mod)?;
                // Subtract deduplicated StandAloneSig entries
                if table_id == TableId::StandAloneSig {
                    #[allow(clippy::cast_possible_truncation)]
                    let skip_len = ctx.standalonesig_skip.len() as u32;
                    new_count = new_count.saturating_sub(skip_len);
                }
                new_row_counts.insert(table_id, new_count);
                if new_count > 0 {
                    valid |= 1u64 << (table_id as u64);
                } else {
                    // Clear bit if table is now empty
                    valid &= !(1u64 << (table_id as u64));
                }
            } else if original_count > 0 {
                // Unmodified table - keep original count (minus dedup for StandAloneSig)
                let mut count = original_count;
                if table_id == TableId::StandAloneSig {
                    #[allow(clippy::cast_possible_truncation)]
                    let skip_len = ctx.standalonesig_skip.len() as u32;
                    count = count.saturating_sub(skip_len);
                }
                new_row_counts.insert(table_id, count);
            }
        }

        // Create output table info with new row counts
        // This recalculates coded index sizes based on new row counts
        let output_table_info = Arc::new(
            tables
                .info
                .with_modified_row_counts(new_row_counts.iter().map(|(k, v)| (*k, *v))),
        );

        // Write tables stream header using OUTPUT table info
        let mut header_buffer = Vec::new();

        // Reserved (4 bytes)
        header_buffer.write_all(&[0u8; 4])?;
        // Major version
        header_buffer.write_all(&[tables.major_version])?;
        // Minor version
        header_buffer.write_all(&[tables.minor_version])?;
        // HeapSizes
        header_buffer.write_all(&[output_table_info.heap_sizes()])?;
        // Reserved (1 byte, must be 1)
        header_buffer.write_all(&[0x01])?;
        // Valid bitvector
        header_buffer.write_all(&valid.to_le_bytes())?;
        // Sorted bitvector
        header_buffer.write_all(&tables.sorted.to_le_bytes())?;

        // Row counts for each present table
        for table_id in TableId::iter() {
            if valid & (1u64 << (table_id as u64)) != 0 {
                let row_count = new_row_counts.get(&table_id).copied().unwrap_or(0);
                header_buffer.write_all(&row_count.to_le_bytes())?;
            }
        }

        ctx.write(&header_buffer)?;

        // Write table data using unified approach
        for table_id in TableId::iter() {
            if valid & (1u64 << (table_id as u64)) == 0 {
                continue;
            }

            self.write_table_data(ctx, table_id, &output_table_info, changes, &remapper)?;
        }

        ctx.tables_stream_size = ctx.pos() - ctx.tables_stream_offset;

        Ok(())
    }

    /// Calculates the row count for a table after modifications.
    ///
    /// Computes the final row count by starting with the original count and
    /// adjusting for inserted and deleted rows.
    ///
    /// # Arguments
    ///
    /// * `table_id` - The table to calculate the count for
    /// * `table_mod` - The modifications applied to the table
    ///
    /// # Returns
    ///
    /// The final row count after applying modifications.
    ///
    /// # Errors
    ///
    /// Returns an error if the assembly has no tables.
    fn calculate_table_row_count(
        &self,
        table_id: TableId,
        table_mod: &TableModifications,
    ) -> Result<u32> {
        let view = self.assembly.view();
        let tables = view
            .tables()
            .ok_or_else(|| Error::LayoutFailed("No tables found".to_string()))?;
        let original_count = tables.table_row_count(table_id);

        match table_mod {
            TableModifications::Replaced(rows) => u32::try_from(rows.len()).map_err(|_| {
                Error::LayoutFailed(format!(
                    "Table {:?} row count {} exceeds u32::MAX",
                    table_id,
                    rows.len()
                ))
            }),
            TableModifications::Sparse { operations, .. } => {
                let added_count = operations
                    .iter()
                    .filter(|op| matches!(op.operation, Operation::Insert(_, _)))
                    .count();
                let deleted_count = operations
                    .iter()
                    .filter(|op| matches!(op.operation, Operation::Delete(_)))
                    .count();
                let added = u32::try_from(added_count).map_err(|_| {
                    Error::LayoutFailed(format!(
                        "Table {table_id:?} added count {added_count} exceeds u32::MAX"
                    ))
                })?;
                let deleted = u32::try_from(deleted_count).map_err(|_| {
                    Error::LayoutFailed(format!(
                        "Table {table_id:?} deleted count {deleted_count} exceeds u32::MAX"
                    ))
                })?;
                Ok(original_count + added - deleted)
            }
        }
    }

    /// Writes table data with unified handling for all cases.
    ///
    /// This function handles:
    /// - Tables with no modifications (simple iteration)
    /// - Tables with Replaced modifications (full replacement)
    /// - Tables with Sparse modifications (updates, deletes, inserts)
    ///
    /// All rows are read from parsed table data and written with the output format.
    /// RID remapping is applied to all cross-table references.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The write context
    /// * `table_id` - The table being written
    /// * `output_table_info` - Table size information for output assembly
    /// * `changes` - Assembly changes for modifications and placeholder resolution
    /// * `remapper` - RID remapper for handling row deletions
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success.
    ///
    /// # Errors
    ///
    /// Returns an error if row serialization or writing fails.
    fn write_table_data(
        &self,
        ctx: &mut WriteContext,
        table_id: TableId,
        output_table_info: &TableInfoRef,
        changes: &AssemblyChanges,
        remapper: &RidRemapper,
    ) -> Result<()> {
        // Compute row size from table info
        let output_row_size = calculate_table_row_size(table_id, output_table_info) as usize;

        // Clone to avoid borrow issues with ctx
        let method_body_rva_map = ctx.method_body_rva_map.clone();
        let field_data_rva_map = ctx.field_data_rva_map.clone();
        let original_rva_delta = ctx.original_method_rva_delta;
        let needs_remapping = remapper.needs_remapping(table_id);

        // Get table modification info (if any)
        let table_mod = changes.get_table_modifications(table_id);

        // Handle fully replaced tables
        if let Some(TableModifications::Replaced(rows)) = table_mod {
            let mut buffer = vec![0u8; output_row_size];
            for (idx, row) in rows.iter().enumerate() {
                let rid = u32::try_from(idx + 1).map_err(|_| {
                    Error::LayoutFailed(format!("Row index {} exceeds u32 range", idx + 1))
                })?;

                let mut resolved_row = row.clone();
                resolved_row.resolve_placeholders(changes);
                if needs_remapping {
                    resolved_row.remap_references(remapper);
                }

                let mut buf_offset = 0;
                resolved_row.row_write(&mut buffer, &mut buf_offset, rid, output_table_info)?;
                Self::apply_rva_fixups(
                    &mut buffer,
                    table_id,
                    &method_body_rva_map,
                    &field_data_rva_map,
                    original_rva_delta,
                );
                ctx.write(&buffer)?;
            }
            return Ok(());
        }

        // Extract sparse modification info (deletions, updates, inserts)
        let (deleted_rows, updates, inserts) = match table_mod {
            Some(TableModifications::Sparse {
                operations,
                deleted_rows,
                ..
            }) => {
                // Build update map for O(1) lookup
                let updates: HashMap<u32, &TableDataOwned> = operations
                    .iter()
                    .filter_map(|op| {
                        if let Operation::Update(rid, data) = &op.operation {
                            Some((*rid, data))
                        } else {
                            None
                        }
                    })
                    .collect();

                // Collect inserts sorted by RID
                let mut inserts: Vec<_> = operations
                    .iter()
                    .filter_map(|op| {
                        if let Operation::Insert(rid, data) = &op.operation {
                            Some((*rid, data))
                        } else {
                            None
                        }
                    })
                    .collect();
                inserts.sort_by_key(|(rid, _)| *rid);

                (deleted_rows.clone(), updates, inserts)
            }
            _ => (
                HashSet::<u32>::new(),
                HashMap::<u32, &TableDataOwned>::new(),
                Vec::<(u32, &TableDataOwned)>::new(),
            ),
        };

        // Get the parsed tables for reading original rows
        let tables = self
            .assembly
            .view
            .tables()
            .ok_or_else(|| Error::LayoutFailed("No tables stream".to_string()))?;
        let original_row_count = tables.table_row_count(table_id);

        // Write original rows (using parsed table data)
        let mut buffer = vec![0u8; output_row_size];
        dispatch_table_type!(table_id, |RawType| {
            if let Some(table) = tables.table::<RawType>() {
                for rid in 1..=original_row_count {
                    // Skip deleted rows
                    if deleted_rows.contains(&rid) {
                        continue;
                    }

                    // Skip StandAloneSig duplicates (deduplication)
                    if table_id == TableId::StandAloneSig && ctx.standalonesig_skip.contains(&rid) {
                        continue;
                    }

                    // Check for updated row data
                    if let Some(row_data) = updates.get(&rid) {
                        let mut resolved_row = (*row_data).clone();
                        resolved_row.resolve_placeholders(changes);
                        if needs_remapping {
                            resolved_row.remap_references(remapper);
                        }
                        let mut buf_offset = 0;
                        resolved_row.row_write(
                            &mut buffer,
                            &mut buf_offset,
                            rid,
                            output_table_info,
                        )?;
                    } else if let Some(mut row) = table.get(rid) {
                        // Use parsed original row
                        if needs_remapping {
                            row.remap_references(remapper);
                        }
                        let mut buf_offset = 0;
                        row.row_write(&mut buffer, &mut buf_offset, rid, output_table_info)?;
                    } else {
                        continue; // Row not found (shouldn't happen)
                    }

                    Self::apply_rva_fixups(
                        &mut buffer,
                        table_id,
                        &method_body_rva_map,
                        &field_data_rva_map,
                        original_rva_delta,
                    );
                    ctx.write(&buffer)?;
                }
            }
        });

        // Append inserted rows
        for (rid, insert_data) in &inserts {
            // Check if insert was subsequently updated
            let final_data = updates.get(rid).unwrap_or(insert_data);

            let mut resolved_row = (*final_data).clone();
            resolved_row.resolve_placeholders(changes);
            if needs_remapping {
                resolved_row.remap_references(remapper);
            }

            let mut buf_offset = 0;
            resolved_row.row_write(&mut buffer, &mut buf_offset, *rid, output_table_info)?;
            Self::apply_rva_fixups(
                &mut buffer,
                table_id,
                &method_body_rva_map,
                &field_data_rva_map,
                original_rva_delta,
            );
            ctx.write(&buffer)?;
        }

        Ok(())
    }

    /// Applies RVA fixups to a row buffer for MethodDef and FieldRVA tables.
    fn apply_rva_fixups(
        buffer: &mut [u8],
        table_id: TableId,
        method_body_rva_map: &HashMap<u32, u32>,
        field_data_rva_map: &HashMap<u32, u32>,
        original_rva_delta: i32,
    ) {
        if table_id == TableId::MethodDef {
            Self::resolve_method_def_rva(buffer, method_body_rva_map, original_rva_delta);
        } else if table_id == TableId::FieldRVA {
            resolve_field_data_rva(buffer, field_data_rva_map);
        }
    }

    /// Resolves method RVAs in MethodDef row buffers.
    ///
    /// Updates RVA values to point to new method body locations. This handles:
    /// - Placeholder RVAs (>= 0xF000_0000) from new methods via changes API
    /// - Original RVAs from copied method bodies
    ///
    /// The first 4 bytes of a MethodDef row contain the RVA field.
    ///
    /// # Arguments
    ///
    /// * `buffer` - The raw MethodDef row bytes
    /// * `method_body_rva_map` - Mapping from original/placeholder RVAs to actual RVAs
    /// * `original_rva_delta` - Fallback delta for RVAs not in the map
    fn resolve_method_def_rva(
        buffer: &mut [u8],
        method_body_rva_map: &HashMap<u32, u32>,
        original_rva_delta: i32,
    ) {
        if buffer.len() < 4 {
            return;
        }

        let rva = u32::from_le_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);

        // RVA 0 means abstract/extern method with no body
        if rva == 0 {
            return;
        }

        // First check the map - this handles both placeholder RVAs and individually
        // copied original method bodies
        let new_rva = if let Some(&mapped_rva) = method_body_rva_map.get(&rva) {
            mapped_rva
        } else if rva < 0xF000_0000 {
            // Original RVA not in map - apply delta as fallback
            // (used when method bodies region was copied as a whole)
            (rva.cast_signed() + original_rva_delta).cast_unsigned()
        } else {
            // Unmapped placeholder - keep as is (shouldn't happen in valid code)
            rva
        };

        let new_bytes = new_rva.to_le_bytes();
        buffer[0] = new_bytes[0];
        buffer[1] = new_bytes[1];
        buffer[2] = new_bytes[2];
        buffer[3] = new_bytes[3];
    }

    /// Builds StandAloneSig deduplication mapping.
    ///
    /// Scans the StandAloneSig table and identifies entries with identical blob content.
    /// For each group of duplicates, keeps one canonical entry and maps others to it.
    /// Updates `ctx.standalonesig_skip` with RIDs to skip during table writing,
    /// and adds token remappings to `ctx.token_remapping` including RID shifts.
    fn build_standalonesig_dedup(&self, ctx: &mut WriteContext, changes: &AssemblyChanges) {
        let view = self.assembly.view();
        let Some(tables) = view.tables() else {
            return;
        };
        let Some(sig_table) = tables.table::<StandAloneSigRaw>() else {
            return;
        };
        let Some(blob_heap) = view.blobs() else {
            return;
        };

        // Get deleted RIDs from changes
        let deleted_rids: HashSet<u32> =
            if let Some(TableModifications::Sparse { deleted_rows, .. }) =
                changes.get_table_modifications(TableId::StandAloneSig)
            {
                deleted_rows.clone()
            } else {
                HashSet::new()
            };

        // Phase 1: Identify duplicates and canonical entries
        // Maps blob content -> canonical RID (first occurrence)
        let mut blob_to_canonical: HashMap<Vec<u8>, u32> = HashMap::new();
        // Maps duplicate RID -> canonical RID
        let mut dup_to_canonical: HashMap<u32, u32> = HashMap::new();

        for sig in sig_table {
            if deleted_rids.contains(&sig.rid) {
                continue;
            }
            let Ok(blob_bytes) = blob_heap.get(sig.signature as usize) else {
                continue;
            };
            if let Some(&canonical_rid) = blob_to_canonical.get(blob_bytes) {
                dup_to_canonical.insert(sig.rid, canonical_rid);
                ctx.standalonesig_skip.insert(sig.rid);
            } else {
                blob_to_canonical.insert(blob_bytes.to_vec(), sig.rid);
            }
        }

        // Phase 2: Compute output RIDs and build complete token remapping
        // Output RID = original RID - (deleted before) - (skipped before)
        let mut output_rid = 0u32;
        let mut rid_to_output: HashMap<u32, u32> = HashMap::new();

        for sig in sig_table {
            if deleted_rids.contains(&sig.rid) || ctx.standalonesig_skip.contains(&sig.rid) {
                continue;
            }
            output_rid += 1;
            rid_to_output.insert(sig.rid, output_rid);
        }

        // Phase 3: Build token remapping
        for sig in sig_table {
            if deleted_rids.contains(&sig.rid) {
                continue;
            }

            let old_token = Token::from_parts(TableId::StandAloneSig, sig.rid).value();

            if let Some(&canonical_rid) = dup_to_canonical.get(&sig.rid) {
                // Duplicate: map to canonical's output RID
                if let Some(&canon_output) = rid_to_output.get(&canonical_rid) {
                    let new_token = Token::from_parts(TableId::StandAloneSig, canon_output).value();
                    ctx.token_remapping.insert(old_token, new_token);
                }
            } else if let Some(&new_rid) = rid_to_output.get(&sig.rid) {
                // Non-duplicate: map to shifted output RID if different
                if sig.rid != new_rid {
                    let new_token = Token::from_parts(TableId::StandAloneSig, new_rid).value();
                    ctx.token_remapping.insert(old_token, new_token);
                }
            }
        }
    }

    /// Writes import data (descriptors + ILT + strings) and patches the IAT.
    ///
    /// Uses the imports built during `write_iat()` to generate the import table.
    /// The import table is written after metadata, and the IAT at the start of
    /// .text section is patched with the correct thunk RVAs.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The write context tracking positions and output
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success (including when there are no imports).
    ///
    /// # Errors
    ///
    /// Returns an error if import table generation or writing fails.
    fn write_import_data(ctx: &mut WriteContext) -> Result<()> {
        // Take pending imports built during write_iat()
        let Some(imports) = ctx.pending_imports.take() else {
            // No imports were built - this shouldn't happen for .NET assemblies
            // but handle gracefully
            return Ok(());
        };

        if imports.is_empty() {
            return Ok(());
        }

        ctx.align_to_4();
        let import_table_rva = ctx.current_rva();

        // Generate import table data (descriptors + ILT + strings)
        // FirstThunk fields will point to IAT at ctx.text_section_rva
        let import_table_bytes = imports.build_import_table(
            ctx.is_pe32_plus,
            ctx.text_section_rva, // IAT is at start of .text
            import_table_rva,     // Where we're writing the import table
        )?;

        if import_table_bytes.is_empty() {
            return Ok(());
        }

        // Now generate and patch the IAT content
        // The IAT was written as zeros in write_iat(), now we know the import_table_rva
        let iat_bytes = imports.build_iat_bytes(ctx.is_pe32_plus, import_table_rva)?;

        // Patch the IAT at the start of .text section
        if !iat_bytes.is_empty() {
            ctx.write_at(ctx.iat_offset, &iat_bytes)?;
        }

        // Write import table data
        ctx.import_data_offset = Some(ctx.pos());
        ctx.import_data_rva = Some(import_table_rva);
        ctx.import_data_size = Some(u32::try_from(import_table_bytes.len()).map_err(|_| {
            Error::LayoutFailed(format!(
                "Import data size {} exceeds u32 range",
                import_table_bytes.len()
            ))
        })?);
        ctx.write(&import_table_bytes)?;

        // Write native entry point stub after import table
        Self::write_native_entry_stub(ctx)?;

        Ok(())
    }

    /// Writes the native entry point stub for .NET PE files.
    ///
    /// This writes a small native code stub that performs an indirect jump through
    /// the IAT to _CorExeMain (for EXEs) or _CorDllMain (for DLLs). The Windows
    /// loader jumps to this entry point, which then transfers control to the CLR.
    ///
    /// The stub format is:
    /// - For PE32: `ff 25 xx xx xx xx` (jmp dword ptr [VA]) - 6 bytes
    /// - For PE32+: `ff 25 00 00 00 00` (jmp qword ptr [rip+0]) followed by 8-byte address
    ///
    /// # Arguments
    ///
    /// * `ctx` - The write context tracking positions and output
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success.
    ///
    /// # Errors
    ///
    /// Returns an error if writing fails.
    fn write_native_entry_stub(ctx: &mut WriteContext) -> Result<()> {
        // Align to 4 bytes for entry point
        ctx.align_to_4_with_padding()?;

        // Calculate entry point RVA
        let entry_rva = ctx.current_rva();
        ctx.native_entry_rva = Some(entry_rva);

        // The IAT entry for _CorExeMain/_CorDllMain is at the start of .text section
        // We need the absolute VA (image base + RVA)
        let iat_rva = ctx.text_section_rva;
        let image_base = ctx.image_base;

        if ctx.is_pe32_plus {
            // PE32+ (x64): Use RIP-relative addressing
            // ff 25 00 00 00 00 = jmp qword ptr [rip+0]
            // followed by 8-byte absolute address
            // But for .NET, the stub is simpler: jmp qword ptr [IAT]
            // The offset from RIP (after instruction) to IAT
            let stub_end_rva = entry_rva + 6; // instruction is 6 bytes
            let rel_offset = iat_rva.wrapping_sub(stub_end_rva);
            let stub: [u8; 6] = [
                0xff,
                0x25, // jmp qword ptr [rip+offset]
                (rel_offset & 0xff) as u8,
                ((rel_offset >> 8) & 0xff) as u8,
                ((rel_offset >> 16) & 0xff) as u8,
                ((rel_offset >> 24) & 0xff) as u8,
            ];
            ctx.write(&stub)?;
        } else {
            // PE32 (x86): Use absolute addressing
            // ff 25 xx xx xx xx = jmp dword ptr [VA]
            let iat_va = image_base + u64::from(iat_rva);
            let stub: [u8; 6] = [
                0xff,
                0x25, // jmp dword ptr [abs]
                (iat_va & 0xff) as u8,
                ((iat_va >> 8) & 0xff) as u8,
                ((iat_va >> 16) & 0xff) as u8,
                ((iat_va >> 24) & 0xff) as u8,
            ];
            ctx.write(&stub)?;
        }

        Ok(())
    }

    /// Writes export data.
    ///
    /// Merges original exports from the assembly with any new exports from changes
    /// and writes the combined export table.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The write context tracking positions and output
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success (including when there are no exports).
    ///
    /// # Errors
    ///
    /// Returns an error if export table serialization or writing fails.
    fn write_export_data(&self, ctx: &mut WriteContext) -> Result<()> {
        let view = self.assembly.view();

        // Get original exports from the PE file
        let original_exports = if let Some(pe_exports) = view.file().exports() {
            NativeExports::from_pe_exports(pe_exports)?
        } else {
            NativeExports::new("")
        };

        let new_exports = self.assembly.changes().native_exports().native();

        // Skip if no exports at all
        if original_exports.is_empty() && new_exports.is_empty() {
            return Ok(());
        }

        // Clone original exports and merge in new ones
        let mut merged = if !original_exports.is_empty() {
            let mut merged = NativeExports::new(original_exports.dll_name());

            // Copy original functions
            for func in original_exports.functions() {
                if let Some(ref name) = func.name {
                    let _ = merged.add_function(name, func.ordinal, func.address);
                } else {
                    let _ = merged.add_function_by_ordinal(func.ordinal, func.address);
                }
            }

            // Copy original forwarders
            for fwd in original_exports.forwarders() {
                if let Some(ref name) = fwd.name {
                    let _ = merged.add_forwarder(name, fwd.ordinal, &fwd.target);
                }
            }
            merged
        } else if !new_exports.is_empty() {
            NativeExports::new(new_exports.dll_name())
        } else {
            return Ok(());
        };

        // Add new exports from changes
        for func in new_exports.functions() {
            if let Some(ref name) = func.name {
                if !merged.has_function(name) {
                    let _ = merged.add_function(name, func.ordinal, func.address);
                }
            } else {
                let _ = merged.add_function_by_ordinal(func.ordinal, func.address);
            }
        }
        for fwd in new_exports.forwarders() {
            if let Some(ref name) = fwd.name {
                let _ = merged.add_forwarder(name, fwd.ordinal, &fwd.target);
            }
        }

        if merged.is_empty() {
            return Ok(());
        }

        ctx.align_to_4();
        let export_data_offset = ctx.pos();
        let export_data_rva = ctx.current_rva();

        // Serialize export table data
        let export_data_bytes = merged.get_export_table_data_with_base_rva(export_data_rva)?;

        if !export_data_bytes.is_empty() {
            ctx.export_data_offset = Some(export_data_offset);
            ctx.export_data_rva = Some(export_data_rva);
            ctx.export_data_size = Some(u32::try_from(export_data_bytes.len()).map_err(|_| {
                Error::LayoutFailed(format!(
                    "Export data size {} exceeds u32 range",
                    export_data_bytes.len()
                ))
            })?);
            ctx.export_table_bytes = Some(export_data_bytes.clone());
            ctx.write(&export_data_bytes)?;
        }

        Ok(())
    }

    /// Writes embedded PE resources into the .text section if applicable.
    ///
    /// Some assemblies (e.g., WindowsBase.dll) embed Win32 PE resources directly
    /// in the .text section rather than in a separate .rsrc section. The PE data
    /// directory index 2 (ResourceTable) points into .text in these cases.
    ///
    /// Since the writer completely rewrites .text, these resources would be lost
    /// unless explicitly carried over. This method detects the case and copies
    /// the resource data into the new .text section, adjusting internal RVAs
    /// via `relocate_resource_section()`.
    fn write_embedded_pe_resources(&self, ctx: &mut WriteContext) -> Result<()> {
        let view = self.assembly.view();
        let file = view.file();

        // Check if the original PE has a resource directory
        let (res_rva, res_size) = match file.get_data_directory(DataDirectoryType::ResourceTable) {
            Some((rva, size)) if rva != 0 && size != 0 => (rva, size),
            _ => return Ok(()),
        };

        // Check if there's a .rsrc section — if so, resources are handled there
        let has_rsrc_section = file.sections().iter().any(|s| s.name.starts_with(".rsrc"));
        if has_rsrc_section {
            return Ok(());
        }

        // Resources are embedded in .text — read from original file
        let Ok(offset) = file.rva_to_offset(res_rva as usize) else {
            return Ok(()); // Can't resolve, skip
        };

        let Some(data) = file.data().get(offset..offset + res_size as usize) else {
            return Ok(()); // Out of bounds, skip
        };

        // Write at aligned position in new .text
        ctx.align_to_4();
        let write_offset = ctx.pos();
        let new_rva = ctx.current_rva();

        // Clone and relocate the resource directory entries if RVA changed
        if res_rva == new_rva {
            ctx.write(data)?;
        } else {
            let mut rsrc_data = data.to_vec();
            relocate_resource_section(&mut rsrc_data, res_rva, new_rva)?;
            ctx.write(&rsrc_data)?;
        }

        ctx.pe_resource_offset = write_offset;
        ctx.pe_resource_size = res_size;

        Ok(())
    }

    /// Writes all sections except .text (which is handled separately).
    ///
    /// Iterates through sections in order, writing each one at the next aligned
    /// position. Handles special cases:
    /// - `.rsrc`: Relocates resource directory entries if RVA changed
    /// - `.reloc`: Filters out entries pointing to .text, may be removed entirely
    /// - Other sections: Copied as-is from original
    ///
    /// Updates the sections vector with write info for each section.
    fn write_other_sections(&self, ctx: &mut WriteContext) -> Result<()> {
        let view = self.assembly.view();
        let file = view.file();

        // Track current end RVA for calculating next section's RVA
        let mut current_end_rva = u64::from(ctx.text_section_rva) + ctx.text_section_size;

        // Get original section info for reloc processing
        let original_text_rva = file
            .sections()
            .iter()
            .find(|s| s.name.starts_with(".text"))
            .map_or(0, |s| s.virtual_address);
        let original_text_size = file
            .sections()
            .iter()
            .find(|s| s.name.starts_with(".text"))
            .map_or(0, |s| s.virtual_size);
        let original_text_end = original_text_rva.saturating_add(original_text_size);

        // Iterate through sections in order
        for section_idx in 0..ctx.sections.len() {
            let section_name = ctx.sections[section_idx].name.clone();

            // Skip .text - already handled
            if section_name.starts_with(".text") {
                continue;
            }

            // Skip excluded sections
            if self.config.excluded_sections.contains(&section_name) {
                ctx.mark_section_removed(section_idx);
                continue;
            }

            // Find original section data
            let original_section = file.sections().iter().find(|s| s.name == section_name);

            let Some(original_section) = original_section else {
                continue; // Section not found in original, skip
            };

            // Calculate new RVA for this section
            let section_rva =
                u32::try_from(align_to(current_end_rva, u64::from(ctx.section_alignment)))
                    .map_err(|_| {
                        Error::LayoutFailed(format!("Section {section_name} RVA exceeds u32 range"))
                    })?;

            // Handle each section type
            if section_name.starts_with(".rsrc") {
                // Write resource section with relocation
                let data_offset = ctx.pos();
                let data_size = self.write_rsrc_data(ctx, original_section, section_rva)?;

                if data_size > 0 {
                    ctx.update_section(section_idx, data_offset, section_rva, data_size);
                    current_end_rva = u64::from(section_rva) + u64::from(data_size);
                }
            } else if section_name.starts_with(".reloc") {
                // Write reloc section with filtering
                let data_offset = ctx.pos();
                let result = self.write_reloc_data(
                    ctx,
                    original_section,
                    original_text_rva,
                    original_text_end,
                )?;

                if let Some(data_size) = result {
                    ctx.update_section(section_idx, data_offset, section_rva, data_size);
                    current_end_rva = u64::from(section_rva) + u64::from(data_size);
                } else {
                    // Reloc section was filtered out entirely
                    ctx.mark_section_removed(section_idx);
                }
            } else {
                // Copy other sections as-is
                let data_offset = ctx.pos();
                let data_size = self.write_generic_section(ctx, original_section)?;

                if data_size > 0 {
                    ctx.update_section(section_idx, data_offset, section_rva, data_size);
                    current_end_rva = u64::from(section_rva) + u64::from(data_size);
                }
            }

            // Align to file alignment. This padding is required because PE spec
            // mandates SizeOfRawData be a multiple of FileAlignment, and the file
            // must contain those bytes.
            ctx.align_to_file()?;
        }

        Ok(())
    }

    /// Writes resource section data with relocation handling.
    ///
    /// Returns the size of data written, or 0 if no data.
    fn write_rsrc_data(
        &self,
        ctx: &mut WriteContext,
        section: &SectionTable,
        new_rva: u32,
    ) -> Result<u32> {
        let view = self.assembly.view();
        let file = view.file();

        let Some(data) = file.data().get(
            section.pointer_to_raw_data as usize
                ..(section.pointer_to_raw_data + section.size_of_raw_data) as usize,
        ) else {
            return Ok(0);
        };

        // Relocate if RVA changed
        if section.virtual_address == new_rva {
            ctx.write(data)?;
        } else {
            let mut rsrc_data = data.to_vec();
            relocate_resource_section(&mut rsrc_data, section.virtual_address, new_rva)?;
            ctx.write(&rsrc_data)?;
        }

        Ok(section.virtual_size)
    }

    /// Writes reloc section data with proper CoreCLR compliance.
    ///
    /// Handles relocations based on assembly type:
    /// - x64 IL-only EXE: Remove .reloc, set RELOCS_STRIPPED flag
    /// - x86 IL-only EXE: Generate entry stub relocation
    /// - DLLs: Always generate relocations (CoreCLR requirement)
    /// - Mixed-mode: Filter existing relocations
    ///
    /// Returns Some(size) if data was written, None if section should be removed.
    fn write_reloc_data(
        &self,
        ctx: &mut WriteContext,
        section: &SectionTable,
        original_text_rva: u32,
        original_text_end: u32,
    ) -> Result<Option<u32>> {
        let view = self.assembly.view();
        let file = view.file();

        // Get original reloc data if present
        let existing_data = file.data().get(
            section.pointer_to_raw_data as usize
                ..(section.pointer_to_raw_data + section.size_of_raw_data) as usize,
        );

        // Build relocation configuration
        let config = RelocationConfig {
            is_dll: self.is_dll(),
            is_pe32_plus: ctx.is_pe32_plus,
            is_il_only: self.is_il_only(),
            entry_stub_rva: ctx.native_entry_rva,
        };

        // Generate relocations using the new module
        let result = generate_relocations(
            &config,
            existing_data,
            (original_text_rva, original_text_end),
        );

        // Store the strip flag for later fixup
        ctx.relocs_stripped = result.strip_relocations;

        if result.data.is_empty() {
            return Ok(None);
        }

        let size = u32::try_from(result.data.len()).unwrap_or(0);
        ctx.write(&result.data)?;

        Ok(Some(size))
    }

    /// Writes a generic section by copying data as-is.
    ///
    /// Returns the size of data written, or 0 if no data.
    fn write_generic_section(&self, ctx: &mut WriteContext, section: &SectionTable) -> Result<u32> {
        let view = self.assembly.view();
        let file = view.file();

        // Skip sections with no data
        if section.size_of_raw_data == 0 {
            return Ok(0);
        }

        let Some(data) = file.data().get(
            section.pointer_to_raw_data as usize
                ..(section.pointer_to_raw_data + section.size_of_raw_data) as usize,
        ) else {
            return Ok(0);
        };

        ctx.write(data)?;

        Ok(section.virtual_size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cilassembly::CilAssembly, metadata::signatures::TypeSignature, CilAssemblyView,
        MethodBuilder,
    };
    use tempfile::NamedTempFile;

    #[test]
    fn test_pe_generator_basic() {
        let view = CilAssemblyView::from_path(std::path::Path::new("tests/samples/crafted_2.exe"))
            .expect("Failed to load test assembly");
        let assembly = view.to_owned();

        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let generator = PeGenerator::new(&assembly);
        let result = generator.to_file(temp_file.path());

        assert!(
            result.is_ok(),
            "PE generation should succeed: {:?}",
            result.err()
        );

        // Verify the generated file can be loaded
        let reloaded = CilAssemblyView::from_path(temp_file.path());
        assert!(
            reloaded.is_ok(),
            "Generated PE should be loadable: {:?}",
            reloaded.err()
        );
    }

    #[test]
    fn test_pe_generator_with_modifications() {
        let view = CilAssemblyView::from_path(std::path::Path::new("tests/samples/crafted_2.exe"))
            .expect("Failed to load test assembly");

        let original_method_count = view
            .tables()
            .map(|t| t.table_row_count(TableId::MethodDef))
            .unwrap_or(0);

        let mut assembly = CilAssembly::new(view);

        let _method_token = MethodBuilder::new("TestGeneratorMethod")
            .public()
            .static_method()
            .parameter("a", TypeSignature::I4)
            .parameter("b", TypeSignature::I4)
            .returns(TypeSignature::I4)
            .implementation(|body| {
                body.implementation(|asm| {
                    asm.ldarg_0()?.ldarg_1()?.add()?.ret()?;
                    Ok(())
                })
            })
            .build(&mut assembly)
            .expect("Failed to build method");

        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        assembly.to_file(temp_file.path()).expect("Write failed");

        let reloaded =
            CilAssemblyView::from_path(temp_file.path()).expect("Failed to reload generated PE");

        let new_method_count = reloaded
            .tables()
            .map(|t| t.table_row_count(TableId::MethodDef))
            .unwrap_or(0);

        assert!(
            new_method_count > original_method_count,
            "Method count should have increased: {} -> {}",
            original_method_count,
            new_method_count
        );
    }

    #[test]
    fn test_pe_generator_to_memory() {
        let view = CilAssemblyView::from_path(std::path::Path::new("tests/samples/crafted_2.exe"))
            .expect("Failed to load test assembly");
        let assembly = view.to_owned();

        let generator = PeGenerator::new(&assembly);
        let result = generator.to_memory();

        assert!(
            result.is_ok(),
            "In-memory PE generation should succeed: {:?}",
            result.err()
        );

        let pe_bytes = result.unwrap();

        // Verify basic PE structure
        assert!(
            pe_bytes.len() > 512,
            "Generated PE should be larger than 512 bytes"
        );
        assert_eq!(&pe_bytes[0..2], b"MZ", "PE should start with MZ signature");

        // Get e_lfanew offset (at 0x3C)
        let e_lfanew = u32::from_le_bytes([
            pe_bytes[0x3C],
            pe_bytes[0x3D],
            pe_bytes[0x3E],
            pe_bytes[0x3F],
        ]) as usize;

        // Verify PE signature at e_lfanew
        assert_eq!(
            &pe_bytes[e_lfanew..e_lfanew + 4],
            b"PE\0\0",
            "PE signature should be at e_lfanew offset"
        );
    }

    #[test]
    fn test_pe_generator_to_memory_can_reload() {
        let view = CilAssemblyView::from_path(std::path::Path::new("tests/samples/crafted_2.exe"))
            .expect("Failed to load test assembly");
        let assembly = view.to_owned();

        let generator = PeGenerator::new(&assembly);
        let pe_bytes = generator.to_memory().expect("Generation should succeed");

        // Verify the in-memory bytes can be loaded as an assembly
        let reloaded = CilAssemblyView::from_mem(pe_bytes);
        assert!(
            reloaded.is_ok(),
            "Generated PE bytes should be loadable: {:?}",
            reloaded.err()
        );
    }

    #[test]
    fn test_pe_generator_to_memory_with_modifications() {
        let view = CilAssemblyView::from_path(std::path::Path::new("tests/samples/crafted_2.exe"))
            .expect("Failed to load test assembly");

        let original_method_count = view
            .tables()
            .map(|t| t.table_row_count(TableId::MethodDef))
            .unwrap_or(0);

        let mut assembly = CilAssembly::new(view);

        let _method_token = MethodBuilder::new("TestMemoryMethod")
            .public()
            .static_method()
            .parameter("x", TypeSignature::I4)
            .returns(TypeSignature::I4)
            .implementation(|body| {
                body.implementation(|asm| {
                    asm.ldarg_0()?.ret()?;
                    Ok(())
                })
            })
            .build(&mut assembly)
            .expect("Failed to build method");

        // Generate to memory instead of file
        let generator = PeGenerator::new(&assembly);
        let pe_bytes = generator
            .to_memory()
            .expect("In-memory generation should succeed");

        // Load from bytes
        let reloaded = CilAssemblyView::from_mem(pe_bytes).expect("Failed to reload from bytes");

        let new_method_count = reloaded
            .tables()
            .map(|t| t.table_row_count(TableId::MethodDef))
            .unwrap_or(0);

        assert!(
            new_method_count > original_method_count,
            "Method count should have increased: {} -> {}",
            original_method_count,
            new_method_count
        );
    }

    #[test]
    fn test_pe_generator_file_and_memory_produce_same_result() {
        let view = CilAssemblyView::from_path(std::path::Path::new("tests/samples/crafted_2.exe"))
            .expect("Failed to load test assembly");
        let assembly = view.to_owned();

        // Generate to file
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let generator = PeGenerator::new(&assembly);
        generator
            .to_file(temp_file.path())
            .expect("File generation failed");

        // Read the file back
        let file_bytes = std::fs::read(temp_file.path()).expect("Failed to read generated file");

        // Generate to memory
        let memory_bytes = generator.to_memory().expect("Memory generation failed");

        // Compare the two
        assert_eq!(
            file_bytes.len(),
            memory_bytes.len(),
            "File and memory generation should produce same size: file={}, memory={}",
            file_bytes.len(),
            memory_bytes.len()
        );
        assert_eq!(
            file_bytes, memory_bytes,
            "File and memory generation should produce identical bytes"
        );
    }
}
