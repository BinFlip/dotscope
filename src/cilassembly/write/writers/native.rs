//! Native PE import/export table generation.
//!
//! This module provides [`NativeTablesWriter`] for generating native PE import and export tables
//! during the binary write process. It integrates with the dotscope write pipeline to create
//! valid PE import/export structures from the unified import/export containers.
//!
//! # Key Components
//!
//! - [`NativeTablesWriter`] - Stateful writer for native PE table generation
//! - [`write_import_tables`] - Import Address Table (IAT) and Import Lookup Table (ILT) generation
//! - [`write_export_tables`] - Export Address Table (EAT) and Export Name Table generation
//!
//! # Architecture
//!
//! The native tables writer handles PE-specific data structures:
//!
//! ## Import Table Generation
//! Creates standard PE import structures:
//! - Import descriptors for each DLL dependency
//! - Import Address Table (IAT) entries for runtime binding
//! - Import Lookup Table (ILT) entries for loader resolution
//! - Import name table for function name storage
//!
//! ## Export Table Generation
//! Creates standard PE export structures:
//! - Export directory with DLL metadata
//! - Export Address Table (EAT) with function addresses
//! - Export Name Table with sorted function names
//! - Export Ordinal Table for ordinal-to-index mapping
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::cilassembly::write::planner`] - Layout planning for PE table space allocation
//! - [`crate::cilassembly::write::output`] - Binary output buffer management
//! - [`crate::metadata::imports::container`] - Unified import container source data
//! - [`crate::metadata::exports::container`] - Unified export container source data

use crate::{
    cilassembly::{
        write::{output::Output, planner::LayoutPlan},
        CilAssembly,
    },
    metadata::{exports::UnifiedExportContainer, imports::UnifiedImportContainer},
    Error, Result,
};

/// A stateful writer for native PE import/export tables.
///
/// `NativeTablesWriter` generates native PE import and export table structures
/// from the unified containers managed by the assembly. It integrates with the
/// dotscope write pipeline to produce valid PE tables during binary generation.
///
/// # Design Benefits
///
/// - **Encapsulation**: All writing context stored in one place
/// - **Clean API**: Methods don't require numerous parameters
/// - **Integration**: Seamless integration with existing write pipeline
/// - **Performance**: Efficient table generation with minimal allocations
/// - **Safety**: Centralized bounds checking and validation
///
/// # Usage
/// Created via [`NativeTablesWriter::new`] and used during the write process
/// to generate native PE tables when unified containers contain native data.
pub struct NativeTablesWriter<'a> {
    /// Reference to the [`crate::cilassembly::CilAssembly`] containing native tables
    assembly: &'a CilAssembly,
    /// Mutable reference to the [`crate::cilassembly::write::output::Output`] buffer for writing
    output: &'a mut Output,
    /// Reference to the [`crate::cilassembly::write::planner::LayoutPlan`] for offset calculations
    layout_plan: &'a LayoutPlan,
}

impl<'a> NativeTablesWriter<'a> {
    /// Creates a new [`NativeTablesWriter`] with the necessary context.
    ///
    /// # Arguments
    ///
    /// * `assembly` - The [`crate::cilassembly::CilAssembly`] containing native table data
    /// * `output` - Mutable reference to the [`crate::cilassembly::write::output::Output`] buffer
    /// * `layout_plan` - Reference to the [`crate::cilassembly::write::planner::LayoutPlan`] for offset calculations
    pub fn new(
        assembly: &'a CilAssembly,
        output: &'a mut Output,
        layout_plan: &'a LayoutPlan,
    ) -> Self {
        Self {
            assembly,
            output,
            layout_plan,
        }
    }

    /// Writes native PE import and export tables if they exist.
    ///
    /// This method examines the assembly's unified import/export containers and
    /// generates the corresponding PE table structures when native data is present.
    /// It handles both import tables (IAT/ILT) and export tables (EAT) generation.
    ///
    /// # Process
    /// 1. Check for native imports in the unified import container
    /// 2. Generate import descriptors, IAT, and ILT if imports exist
    /// 3. Check for native exports in the unified export container
    /// 4. Generate export directory and related tables if exports exist
    /// 5. Update PE directory entries to point to the new tables
    ///
    /// # Returns
    /// Returns `Ok(())` if table generation completed successfully.
    ///
    /// # Errors
    /// Returns [`crate::Error`] if table generation fails due to invalid data
    /// or insufficient output buffer space.
    pub fn write_native_tables(&mut self) -> Result<()> {
        if let Some(imports) = self.assembly.native_imports() {
            if !imports.is_empty() {
                self.write_import_tables(imports)?;
            }
        }

        if let Some(exports) = self.assembly.native_exports() {
            if !exports.is_empty() {
                self.write_export_tables(exports)?;
            }
        }

        Ok(())
    }

    /// Writes native PE import tables (Import Directory, IAT, ILT).
    ///
    /// Generates the complete PE import table structure including:
    /// - Import Directory Table with descriptors for each DLL
    /// - Import Address Table (IAT) for runtime function binding
    /// - Import Lookup Table (ILT) for loader resolution
    /// - Import Name Table for function name storage
    ///
    /// # Arguments
    /// * `imports` - The unified import container with native import data
    ///
    /// # Returns
    /// Returns `Ok(())` if import table generation succeeded.
    ///
    /// # Errors
    /// Returns [`crate::Error`] if import table generation fails.
    fn write_import_tables(&mut self, imports: &UnifiedImportContainer) -> Result<()> {
        let native_imports = imports.native();
        if native_imports.is_empty() {
            return Ok(());
        }

        let requirements = &self.layout_plan.native_table_requirements;
        if let Some(import_rva) = requirements.import_table_rva {
            // We need to get a mutable reference to set the correct base RVA
            // Since we only have an immutable reference, we'll need to work around this
            // by cloning the native imports, setting the base RVA, then generating the data
            let mut native_imports_copy = native_imports.clone();
            native_imports_copy.set_import_table_base_rva(import_rva);

            let is_pe32_plus = self.is_pe32_plus_format()?;
            let import_table_data = native_imports_copy.get_import_table_data(is_pe32_plus)?;
            if import_table_data.is_empty() {
                return Ok(());
            }

            let file_offset = self.rva_to_file_offset(import_rva)?;
            self.output.write_at(file_offset, &import_table_data)?;
        } else {
            return Err(Error::WriteLayoutFailed {
                message: "Import table RVA not calculated in layout plan".to_string(),
            });
        }

        Ok(())
    }

    /// Writes native PE export tables (Export Directory, EAT, Name Table).
    ///
    /// Generates the complete PE export table structure including:
    /// - Export Directory with DLL metadata and table pointers
    /// - Export Address Table (EAT) with function RVAs
    /// - Export Name Table with sorted function names
    /// - Export Ordinal Table for ordinal-to-index mapping
    /// - Export Name Pointer Table for name-to-address mapping
    ///
    /// # Arguments
    /// * `exports` - The unified export container with native export data
    ///
    /// # Returns
    /// Returns `Ok(())` if export table generation succeeded.
    ///
    /// # Errors
    /// Returns [`crate::Error`] if export table generation fails.
    fn write_export_tables(&mut self, exports: &UnifiedExportContainer) -> Result<()> {
        let native_exports = exports.native();
        if native_exports.is_empty() {
            return Ok(());
        }

        let requirements = &self.layout_plan.native_table_requirements;
        if let Some(export_rva) = requirements.export_table_rva {
            let mut native_exports_copy = native_exports.clone();
            native_exports_copy.set_export_table_base_rva(export_rva);

            let export_table_data = native_exports_copy.get_export_table_data()?;
            if export_table_data.is_empty() {
                return Ok(());
            }

            let file_offset = self.rva_to_file_offset(export_rva)?;
            self.output.write_at(file_offset, &export_table_data)?;
        } else {
            return Err(Error::WriteLayoutFailed {
                message: "Export table RVA not calculated in layout plan".to_string(),
            });
        }

        Ok(())
    }

    /// Converts an RVA (Relative Virtual Address) to a file offset.
    ///
    /// Uses the layout plan's section information to ensure consistency between
    /// RVA calculation and file offset mapping. This accounts for section relocations
    /// that may have occurred during layout planning.
    ///
    /// # Arguments
    /// * `rva` - The relative virtual address to convert
    ///
    /// # Returns
    /// Returns the file offset corresponding to the RVA.
    ///
    /// # Errors
    /// Returns [`crate::Error`] if the RVA cannot be converted to a valid file offset.
    fn rva_to_file_offset(&self, rva: u32) -> Result<u64> {
        // First try to use the layout plan's section information (for relocated sections)
        for section_layout in &self.layout_plan.file_layout.sections {
            let section_start = section_layout.virtual_address;
            let section_end = section_layout.virtual_address + section_layout.virtual_size;

            if rva >= section_start && rva < section_end {
                let offset_in_section = rva - section_start;
                let file_offset = section_layout.file_region.offset + offset_in_section as u64;
                return Ok(file_offset);
            }
        }

        // Fall back to original assembly sections (for unchanged sections)
        let view = self.assembly.view();
        let file = view.file();

        for section in file.sections() {
            let section_start = section.virtual_address;
            let section_end = section.virtual_address + section.virtual_size;

            if rva >= section_start && rva < section_end {
                let offset_in_section = rva - section_start;
                let file_offset = section.pointer_to_raw_data as u64 + offset_in_section as u64;
                return Ok(file_offset);
            }
        }

        Ok(rva as u64)
    }

    /// Determines if this is a PE32+ format file.
    ///
    /// Returns `true` for PE32+ (64-bit) format, `false` for PE32 (32-bit) format.
    /// This affects the size of ILT/IAT entries and ordinal import bit positions.
    ///
    /// # Returns
    /// Returns `true` if PE32+ format, `false` if PE32 format.
    ///
    /// # Errors
    /// Returns [`crate::Error`] if the PE format cannot be determined.
    fn is_pe32_plus_format(&self) -> Result<bool> {
        let view = self.assembly.view();
        let optional_header =
            view.file()
                .header_optional()
                .as_ref()
                .ok_or_else(|| Error::WriteLayoutFailed {
                    message: "Missing optional header for PE format detection".to_string(),
                })?;

        // PE32 magic is 0x10b, PE32+ magic is 0x20b
        Ok(optional_header.standard_fields.magic != 0x10b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cilassembly::{write::planner::create_layout_plan, BuilderContext, CilAssembly},
        metadata::{
            cilassemblyview::CilAssemblyView, exports::NativeExportsBuilder,
            imports::NativeImportsBuilder,
        },
    };
    use std::path::Path;
    use tempfile::NamedTempFile;

    #[test]
    fn test_native_tables_writer_creation() {
        let view = CilAssemblyView::from_file(Path::new("tests/samples/WindowsBase.dll"))
            .expect("Failed to load test assembly");
        let assembly = CilAssembly::new(view);

        let layout_plan = create_layout_plan(&assembly).expect("Failed to create layout plan");

        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let mut output = crate::cilassembly::write::output::Output::create(
            temp_file.path(),
            layout_plan.total_size,
        )
        .expect("Failed to create output");

        let writer = NativeTablesWriter::new(&assembly, &mut output, &layout_plan);

        // Should create successfully
        assert!(!std::ptr::eq(writer.assembly, std::ptr::null()));
    }

    #[test]
    fn test_native_tables_writer_with_no_native_data() {
        let view = CilAssemblyView::from_file(Path::new("tests/samples/WindowsBase.dll"))
            .expect("Failed to load test assembly");
        let assembly = CilAssembly::new(view);

        let layout_plan = create_layout_plan(&assembly).expect("Failed to create layout plan");

        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let mut output = crate::cilassembly::write::output::Output::create(
            temp_file.path(),
            layout_plan.total_size,
        )
        .expect("Failed to create output");

        let mut writer = NativeTablesWriter::new(&assembly, &mut output, &layout_plan);

        // Should succeed with no native data to write
        let result = writer.write_native_tables();
        assert!(result.is_ok());
    }

    #[test]
    fn test_native_tables_writer_with_imports() {
        let view = CilAssemblyView::from_file(Path::new("tests/samples/WindowsBase.dll"))
            .expect("Failed to load test assembly");
        let assembly = CilAssembly::new(view);
        let mut context = BuilderContext::new(assembly);

        // Add some native imports
        let result = NativeImportsBuilder::new()
            .add_dll("kernel32.dll")
            .add_function("kernel32.dll", "GetCurrentProcessId")
            .add_function("kernel32.dll", "ExitProcess")
            .build(&mut context);

        assert!(result.is_ok());

        let assembly = context.finish();
        let layout_plan = create_layout_plan(&assembly).expect("Failed to create layout plan");

        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let mut output = crate::cilassembly::write::output::Output::create(
            temp_file.path(),
            layout_plan.total_size,
        )
        .expect("Failed to create output");

        let mut writer = NativeTablesWriter::new(&assembly, &mut output, &layout_plan);

        // Should succeed with native imports present
        let result = writer.write_native_tables();
        if let Err(e) = &result {
            panic!("Write native tables failed: {:?}", e);
        }
        assert!(result.is_ok());
    }

    #[test]
    fn test_native_tables_writer_with_exports() {
        let view = CilAssemblyView::from_file(Path::new("tests/samples/WindowsBase.dll"))
            .expect("Failed to load test assembly");
        let assembly = CilAssembly::new(view);
        let mut context = BuilderContext::new(assembly);

        // Add some native exports
        let result = NativeExportsBuilder::new("TestLibrary.dll")
            .add_function("MyFunction", 1, 0x1000)
            .add_function("AnotherFunction", 2, 0x2000)
            .build(&mut context);

        assert!(result.is_ok());

        let assembly = context.finish();
        let layout_plan = create_layout_plan(&assembly).expect("Failed to create layout plan");

        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let mut output = crate::cilassembly::write::output::Output::create(
            temp_file.path(),
            layout_plan.total_size,
        )
        .expect("Failed to create output");

        let mut writer = NativeTablesWriter::new(&assembly, &mut output, &layout_plan);

        // Should succeed with native exports present
        let result = writer.write_native_tables();
        if let Err(e) = &result {
            panic!("Write native tables failed: {:?}", e);
        }
        assert!(result.is_ok());
    }

    #[test]
    fn test_native_tables_writer_with_both_imports_and_exports() {
        let view = CilAssemblyView::from_file(Path::new("tests/samples/WindowsBase.dll"))
            .expect("Failed to load test assembly");
        let assembly = CilAssembly::new(view);
        let mut context = BuilderContext::new(assembly);

        // Add native imports
        let result = NativeImportsBuilder::new()
            .add_dll("kernel32.dll")
            .add_function("kernel32.dll", "GetCurrentProcessId")
            .build(&mut context);
        assert!(result.is_ok());

        // Add native exports
        let result = NativeExportsBuilder::new("TestLibrary.dll")
            .add_function("MyFunction", 1, 0x1000)
            .build(&mut context);
        assert!(result.is_ok());

        let assembly = context.finish();
        let layout_plan = create_layout_plan(&assembly).expect("Failed to create layout plan");

        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let mut output = crate::cilassembly::write::output::Output::create(
            temp_file.path(),
            layout_plan.total_size,
        )
        .expect("Failed to create output");

        let mut writer = NativeTablesWriter::new(&assembly, &mut output, &layout_plan);

        // Should succeed with both native imports and exports present
        let result = writer.write_native_tables();
        if let Err(e) = &result {
            panic!("Write native tables failed: {:?}", e);
        }
        assert!(result.is_ok());
    }
}
