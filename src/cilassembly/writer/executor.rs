//! Mechanical execution engine for the simplified assembly writer pipeline.
//!
//! This module implements the pure execution stage that takes a complete [`crate::cilassembly::writer::WriteLayout`]
//! and mechanically executes all planned operations. The executor contains zero conditional logic
//! or decision-making - it simply performs operations that were pre-calculated during planning.
//!
//! # Architecture
//!
//! The executor follows a "mechanical execution" design philosophy:
//!
//! ```text
//! ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
//! │   WriteLayout   │───▶│  WriteExecutor  │───▶│   Output File   │
//! │  (Complete)     │    │  .execute()     │    │  (Complete)     │
//! └─────────────────┘    └─────────────────┘    └─────────────────┘
//!          │                       │                       │
//!          ▼                       ▼                       ▼
//! ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
//! │ Pre-calculated  │    │   Mechanical    │    │  Valid PE File  │
//! │   Operations    │    │   Execution     │    │ + .NET Assembly │
//! └─────────────────┘    └─────────────────┘    └─────────────────┘
//! ```
//!
//! **Core Principles:**
//!
//! - **No Decisions**: All decisions were made during layout planning
//! - **Pure Operations**: Only copy/zero/write operations in sequence
//! - **Error Recovery**: Clear error reporting with operation context
//! - **Safety**: Bounds checking and validation at each step
//! - **Deterministic**: Same layout always produces identical output
//!
//! # Key Components
//!
//! - [`crate::cilassembly::writer::WriteExecutor`] - Main execution engine (stateless)
//! - [`crate::cilassembly::writer::operations::CopyOperation`] - Data copying from original file
//! - [`crate::cilassembly::writer::operations::ZeroOperation`] - Memory clearing operations
//! - [`crate::cilassembly::writer::operations::WriteOperation`] - New data writing operations
//! - [`crate::cilassembly::writer::output::Output`] - Memory-mapped output file interface
//!
//! # Usage Examples
//!
//! ## Basic Execution
//!
//! ```rust,ignore
//! use dotscope::cilassembly::writer::{WriteLayout, WriteExecutor};
//! use dotscope::cilassembly::writer::output::Output;
//! use dotscope::prelude::*;
//! use std::path::Path;
//!
//! # let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))?;
//! # let assembly = view.to_owned();
//! # let output_path = Path::new("output.dll");
//! let layout = WriteLayout::plan(&assembly)?;
//! let mut output = Output::create(output_path, layout.total_file_size)?;
//!
//! WriteExecutor::execute(&layout, &mut output, &assembly)?;
//! output.finalize()?;
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## With Progress Monitoring
//!
//! ```rust,ignore
//! use dotscope::cilassembly::writer::{WriteLayout, WriteExecutor};
//! use dotscope::cilassembly::writer::output::Output;
//! use dotscope::prelude::*;
//! use std::path::Path;
//!
//! # let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))?;
//! # let assembly = view.to_owned();
//! # let output_path = Path::new("output.dll");
//! let layout = WriteLayout::plan(&assembly)?;
//! println!("Executing {} operations", layout.operation_count());
//!
//! let mut output = Output::create(output_path, layout.total_file_size)?;
//! WriteExecutor::execute(&layout, &mut output, &assembly)?;
//!
//! println!("Execution completed successfully");
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Error Handling
//!
//! The executor provides comprehensive error handling:
//!
//! - [`crate::Error::WriteLayoutFailed`] - When operation validation fails or I/O errors occur
//! - [`crate::Error::WriteFailed`] - When file writing operations encounter system errors
//! - [`crate::Error::MemoryMappingFailed`] - When memory-mapped file operations fail
//!
//! All errors include:
//! - Specific operation that failed (with index and description)
//! - Root cause of the failure
//! - Progress information (how many operations completed successfully)
//! - Detailed context for debugging
//!
//! # Thread Safety
//!
//! - [`crate::cilassembly::writer::WriteExecutor`] is stateless and fully [`Send`] + [`Sync`]
//! - Individual execution calls are thread-safe when using different output files
//! - The same [`crate::cilassembly::writer::WriteLayout`] can be executed concurrently by multiple threads
//! - [`crate::cilassembly::writer::output::Output`] is not [`Sync`] due to memory-mapped file access
//!
//! # Integration
//!
//! This module integrates with:
//!
//! - [`crate::cilassembly::writer::layout`] - Receives complete layout plans with all operations
//! - [`crate::cilassembly::writer::operations`] - Executes copy/zero/write operations
//! - [`crate::cilassembly::writer::output`] - Writes to memory-mapped output files
//! - [`crate::cilassembly::CilAssembly`] - Reads source data during copy operations
//! - [`crate::metadata::imports`] - Generates native PE import tables
//! - [`crate::metadata::exports`] - Generates native PE export tables

use crate::{
    cilassembly::{
        writer::{
            layout::WriteLayout,
            operations::{CopyOperation, WriteOperation, ZeroOperation},
            output::Output,
        },
        CilAssembly,
    },
    metadata::{exports::UnifiedExportContainer, imports::UnifiedImportContainer},
    Error, Result,
};

/// Mechanical execution engine for [`crate::cilassembly::writer::WriteLayout`] operations.
///
/// The [`WriteExecutor`] is a stateless engine that takes a complete layout plan and
/// executes all planned operations mechanically. It provides no decision-making logic,
/// focusing purely on reliable execution with comprehensive error reporting.
///
/// # Design Philosophy
///
/// The executor operates on the principle of **mechanical execution**:
///
/// 1. **Pre-calculated Operations**: All operations are fully specified in the layout
/// 2. **No Runtime Decisions**: No conditional logic or branching based on data
/// 3. **Atomic Execution**: Either all operations succeed or none are applied
/// 4. **Comprehensive Validation**: Bounds checking and consistency verification
/// 5. **Rich Error Context**: Detailed failure information for debugging
///
/// # Execution Process
///
/// The executor performs operations in this precise order:
///
/// 1. **Validation**: Verify layout and output compatibility
/// 2. **Copy Operations**: Transfer existing data to new locations
/// 3. **Zero Operations**: Clear old locations that are no longer needed
/// 4. **Write Operations**: Place newly generated data
/// 5. **Native Tables**: Generate PE import/export tables if needed
/// 6. **PE Updates**: Update data directories and clear invalid entries
///
/// # Thread Safety
///
/// [`WriteExecutor`] is completely stateless and thread-safe. Multiple threads can
/// execute different layouts concurrently without synchronization.
///
/// # Examples
///
/// ## Basic Usage
///
/// ```rust,ignore
/// use dotscope::cilassembly::writer::{WriteLayout, WriteExecutor};
/// use dotscope::cilassembly::writer::output::Output;
/// use dotscope::prelude::*;
/// use std::path::Path;
///
/// # let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))?;
/// # let assembly = view.to_owned();
/// # let output_path = Path::new("output.dll");
/// let layout = WriteLayout::plan(&assembly)?;
/// let mut output = Output::create(output_path, layout.total_file_size)?;
///
/// WriteExecutor::execute(&layout, &mut output, &assembly)?;
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// ## Error Handling
///
/// ```rust,ignore
/// use dotscope::cilassembly::writer::{WriteLayout, WriteExecutor};
/// use dotscope::cilassembly::writer::output::Output;
/// use dotscope::prelude::*;
/// use dotscope::Error;
/// use std::path::Path;
///
/// # let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))?;
/// # let assembly = view.to_owned();
/// # let output_path = Path::new("output.dll");
/// # let layout = WriteLayout::plan(&assembly)?;
/// # let mut output = Output::create(output_path, layout.total_file_size)?;
/// match WriteExecutor::execute(&layout, &mut output, &assembly) {
///     Ok(()) => println!("Execution completed successfully"),
///     Err(Error::WriteLayoutFailed { message }) => {
///         eprintln!("Operation failed: {}", message);
///     },
///     Err(e) => eprintln!("Other error: {}", e),
/// }
/// # Ok::<(), dotscope::Error>(())
/// ```
pub struct WriteExecutor;

impl WriteExecutor {
    /// Executes all operations in the [`crate::cilassembly::writer::WriteLayout`] mechanically.
    ///
    /// This is the main entry point for mechanical execution. It performs all copy, zero,
    /// and write operations in the correct sequence to generate a complete output file.
    /// The function is completely deterministic - the same layout will always produce
    /// identical output.
    ///
    /// # Arguments
    ///
    /// * `layout` - The complete [`crate::cilassembly::writer::WriteLayout`] with all operations pre-calculated
    /// * `output` - The [`crate::cilassembly::writer::output::Output`] buffer to write to (must match layout size)
    /// * `assembly` - The source [`crate::cilassembly::CilAssembly`] for reading original data during copy operations
    ///
    /// # Returns
    ///
    /// Returns [`crate::Result<()>`] on successful execution. The output file will contain
    /// a complete, valid .NET assembly with all modifications applied.
    ///
    /// # Errors
    ///
    /// This function returns [`crate::Error`] in the following cases:
    ///
    /// - [`crate::Error::WriteLayoutFailed`] - When operation validation fails, bounds checking fails, or I/O errors occur
    /// - [`crate::Error::WriteFailed`] - When file writing operations encounter system-level errors
    /// - [`crate::Error::MemoryMappingFailed`] - When memory-mapped file operations fail
    ///
    /// All errors include detailed context about which operation failed and why.
    ///
    /// # Execution Order
    ///
    /// Operations are executed in this precise order for correctness:
    ///
    /// 1. **Compatibility Validation**: Verify layout matches output file size
    /// 2. **Copy Operations**: Move existing data to new positions (preserves PE headers, method bodies)
    /// 3. **Zero Operations**: Clear old metadata locations
    /// 4. **Write Operations**: Place new metadata, heaps, and tables
    /// 5. **Native Table Generation**: Create PE import/export tables if needed
    /// 6. **PE Data Directory Updates**: Update pointers to native tables
    /// 7. **Certificate Table Clearing**: Prevent corruption from invalid certificate pointers
    ///
    /// # Examples
    ///
    /// ## Complete Execution Flow
    ///
    /// ```rust,ignore
    /// use dotscope::cilassembly::writer::{WriteLayout, WriteExecutor};
    /// use dotscope::cilassembly::writer::output::Output;
    /// use dotscope::prelude::*;
    /// use std::path::Path;
    ///
    /// # let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))?;
    /// # let assembly = view.to_owned();
    /// # let output_path = Path::new("output.dll");
    /// let layout = WriteLayout::plan(&assembly)?;
    /// let mut output = Output::create(output_path, layout.total_file_size)?;
    ///
    /// WriteExecutor::execute(&layout, &mut output, &assembly)?;
    /// output.finalize()?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// ## With Progress Monitoring
    ///
    /// ```rust,ignore
    /// use dotscope::cilassembly::writer::{WriteLayout, WriteExecutor};
    /// use dotscope::cilassembly::writer::output::Output;
    /// use dotscope::prelude::*;
    /// use std::path::Path;
    ///
    /// # let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))?;
    /// # let assembly = view.to_owned();
    /// # let output_path = Path::new("output.dll");
    /// let layout = WriteLayout::plan(&assembly)?;
    /// println!("Executing {} operations...", layout.operation_count());
    ///
    /// let mut output = Output::create(output_path, layout.total_file_size)?;
    /// WriteExecutor::execute(&layout, &mut output, &assembly)?;
    ///
    /// println!("Execution completed successfully");
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Thread Safety
    ///
    /// This function is thread-safe and can be called concurrently with different
    /// layouts and output files. The same layout can be executed by multiple threads
    /// simultaneously as long as they use different output files.
    pub fn execute(
        layout: &WriteLayout,
        output: &mut Output,
        assembly: &CilAssembly,
    ) -> Result<()> {
        Self::validate_execution_compatibility(layout, output)?;

        Self::execute_copy_operations(&layout.operations.copy, output, assembly)?;
        Self::execute_zero_operations(&layout.operations.zero, output)?;
        Self::execute_write_operations(&layout.operations.write, output)?;

        Self::execute_native_table_operations(layout, output, assembly)?;

        Self::update_native_data_directories(layout, output, assembly)?;

        Self::clear_certificate_table(layout, output, assembly)?;

        Ok(())
    }

    /// Executes all copy operations to preserve existing data in new locations.
    ///
    /// Copy operations transfer content from the original assembly file to new positions
    /// in the output file. This preserves PE headers, section content, method bodies,
    /// and other data that doesn't require modification.
    ///
    /// # Arguments
    ///
    /// * `operations` - Array of [`crate::cilassembly::writer::operations::CopyOperation`] to execute
    /// * `output` - Target [`crate::cilassembly::writer::output::Output`] for writing data
    /// * `assembly` - Source [`crate::cilassembly::CilAssembly`] for reading original data
    ///
    /// # Returns
    ///
    /// Returns [`crate::Result<()>`] on success, or detailed error information if any
    /// copy operation fails.
    ///
    /// # Errors
    ///
    /// - [`crate::Error::WriteLayoutFailed`] - When source data cannot be read or target cannot be written
    ///
    /// Each error includes the operation index and description for debugging.
    fn execute_copy_operations(
        operations: &[CopyOperation],
        output: &mut Output,
        assembly: &CilAssembly,
    ) -> Result<()> {
        for (index, operation) in operations.iter().enumerate() {
            Self::execute_copy_operation(operation, output, assembly).map_err(|e| {
                Self::wrap_operation_error(&e, "copy", index, &operation.description)
            })?;
        }
        Ok(())
    }

    /// Executes a single copy operation with bounds validation.
    ///
    /// Reads data from the source assembly at the specified offset and writes it
    /// to the target location in the output file. Includes comprehensive bounds
    /// checking and error reporting.
    ///
    /// # Arguments
    ///
    /// * `operation` - The [`crate::cilassembly::writer::operations::CopyOperation`] to execute
    /// * `output` - Target [`crate::cilassembly::writer::output::Output`] for writing
    /// * `assembly` - Source [`crate::cilassembly::CilAssembly`] for reading
    ///
    /// # Returns
    ///
    /// Returns [`crate::Result<()>`] on success or detailed error on failure.
    fn execute_copy_operation(
        operation: &CopyOperation,
        output: &mut Output,
        assembly: &CilAssembly,
    ) -> Result<()> {
        if operation.size == 0 {
            return Ok(());
        }

        let source_data = assembly
            .file()
            .data_slice(
                usize::try_from(operation.source_offset).map_err(|_| Error::WriteLayoutFailed {
                    message: format!(
                        "Source offset {} exceeds usize range",
                        operation.source_offset
                    ),
                })?,
                usize::try_from(operation.size).map_err(|_| Error::WriteLayoutFailed {
                    message: format!("Size {} exceeds usize range", operation.size),
                })?,
            )
            .map_err(|e| Error::WriteLayoutFailed {
                message: format!(
                    "Failed to read source data: {size} bytes from 0x{offset:X}: {e}",
                    size = operation.size,
                    offset = operation.source_offset
                ),
            })?;

        output
            .write_at(operation.target_offset, source_data)
            .map_err(|e| Error::WriteLayoutFailed {
                message: format!(
                    "Copy operation failed: {size} bytes from 0x{source_offset:X} to 0x{target_offset:X}: {e}",
                    size = operation.size,
                    source_offset = operation.source_offset,
                    target_offset = operation.target_offset
                ),
            })
    }

    /// Executes all zero operations to clear old locations.
    ///
    /// Zero operations clear old metadata locations after content has been relocated
    /// to the new .meta section. This ensures clean separation between old and new
    /// layouts and prevents tools from reading stale metadata.
    ///
    /// # Arguments
    ///
    /// * `operations` - Array of [`crate::cilassembly::writer::operations::ZeroOperation`] to execute
    /// * `output` - Target [`crate::cilassembly::writer::output::Output`] for clearing memory
    ///
    /// # Returns
    ///
    /// Returns [`crate::Result<()>`] on success or error information if clearing fails.
    fn execute_zero_operations(operations: &[ZeroOperation], output: &mut Output) -> Result<()> {
        for (index, operation) in operations.iter().enumerate() {
            Self::execute_zero_operation(operation, output)
                .map_err(|e| Self::wrap_operation_error(&e, "zero", index, &operation.reason))?;
        }
        Ok(())
    }

    /// Executes a single zero operation with validation.
    ///
    /// Clears a range of memory in the output file by writing zeros. Used to
    /// clear old metadata locations and ensure clean file layout.
    ///
    /// # Arguments
    ///
    /// * `operation` - The [`crate::cilassembly::writer::operations::ZeroOperation`] to execute
    /// * `output` - Target [`crate::cilassembly::writer::output::Output`] for memory clearing
    ///
    /// # Returns
    ///
    /// Returns [`crate::Result<()>`] on success or detailed error on failure.
    fn execute_zero_operation(operation: &ZeroOperation, output: &mut Output) -> Result<()> {
        if operation.size == 0 {
            return Ok(());
        }

        output
            .zero_range(operation.offset, operation.size)
            .map_err(|e| Error::WriteLayoutFailed {
                message: format!(
                    "Zero operation failed: {size} bytes at 0x{offset:X}: {e}",
                    size = operation.size,
                    offset = operation.offset
                ),
            })
    }

    /// Executes all write operations to place new data.
    ///
    /// Write operations place newly generated content including reconstructed
    /// metadata heaps, updated tables, method bodies, and PE structure updates.
    /// This is the final stage that creates the new assembly content.
    ///
    /// # Arguments
    ///
    /// * `operations` - Array of [`crate::cilassembly::writer::operations::WriteOperation`] to execute
    /// * `output` - Target [`crate::cilassembly::writer::output::Output`] for writing new data
    ///
    /// # Returns
    ///
    /// Returns [`crate::Result<()>`] on success or error information if writing fails.
    fn execute_write_operations(operations: &[WriteOperation], output: &mut Output) -> Result<()> {
        for (index, operation) in operations.iter().enumerate() {
            Self::execute_write_operation(operation, output).map_err(|e| {
                Self::wrap_operation_error(&e, "write", index, &operation.component)
            })?;
        }
        Ok(())
    }

    /// Executes a single write operation with validation.
    ///
    /// Writes new data to the specified location in the output file. Used for
    /// placing reconstructed metadata heaps, updated tables, and other generated content.
    ///
    /// # Arguments
    ///
    /// * `operation` - The [`crate::cilassembly::writer::operations::WriteOperation`] to execute
    /// * `output` - Target [`crate::cilassembly::writer::output::Output`] for writing
    ///
    /// # Returns
    ///
    /// Returns [`crate::Result<()>`] on success or detailed error on failure.
    fn execute_write_operation(operation: &WriteOperation, output: &mut Output) -> Result<()> {
        if operation.data.is_empty() {
            return Ok(());
        }

        output
            .write_at(operation.offset, &operation.data)
            .map_err(|e| Error::WriteLayoutFailed {
                message: format!(
                    "Write operation failed: {} bytes at 0x{:X}: {}",
                    operation.data.len(),
                    operation.offset,
                    e
                ),
            })
    }

    /// Validates that the layout and output are compatible for execution.
    ///
    /// Performs comprehensive validation to ensure the layout can be executed
    /// successfully against the given output file. This prevents runtime failures
    /// by catching incompatibilities early.
    ///
    /// # Arguments
    ///
    /// * `layout` - The [`crate::cilassembly::writer::WriteLayout`] to validate
    /// * `output` - The [`crate::cilassembly::writer::output::Output`] to validate against
    ///
    /// # Returns
    ///
    /// Returns [`crate::Result<()>`] if compatible, or detailed error describing the incompatibility.
    ///
    /// # Validations Performed
    ///
    /// - Output file size matches layout expectations
    /// - All copy operations target valid file ranges
    /// - All zero operations target valid file ranges  
    /// - All write operations target valid file ranges
    /// - No operations extend beyond file boundaries
    fn validate_execution_compatibility(layout: &WriteLayout, output: &Output) -> Result<()> {
        let output_size = output.size();
        if output_size != layout.total_file_size {
            return Err(Error::WriteLayoutFailed {
                message: format!(
                    "Output size mismatch: layout expects {} bytes, output has {} bytes",
                    layout.total_file_size, output_size
                ),
            });
        }

        for operation in &layout.operations.copy {
            let end_offset = operation.target_offset + operation.size;
            if end_offset > layout.total_file_size {
                return Err(Error::WriteLayoutFailed {
                    message: format!(
                        "Copy operation extends beyond file: {} > {}",
                        end_offset, layout.total_file_size
                    ),
                });
            }
        }

        for operation in &layout.operations.zero {
            let end_offset = operation.offset + operation.size;
            if end_offset > layout.total_file_size {
                return Err(Error::WriteLayoutFailed {
                    message: format!(
                        "Zero operation extends beyond file: {} > {}",
                        end_offset, layout.total_file_size
                    ),
                });
            }
        }

        for operation in &layout.operations.write {
            let end_offset = operation.offset + operation.data.len() as u64;
            if end_offset > layout.total_file_size {
                return Err(Error::WriteLayoutFailed {
                    message: format!(
                        "Write operation extends beyond file: {} > {}",
                        end_offset, layout.total_file_size
                    ),
                });
            }
        }

        Ok(())
    }

    /// Executes native table operations (import/export tables) if needed.
    ///
    /// Generates and writes native PE import and export tables based on the
    /// requirements calculated during layout planning. These tables enable
    /// interoperability between managed and native code.
    ///
    /// # Arguments
    ///
    /// * `layout` - The [`crate::cilassembly::writer::WriteLayout`] containing native table requirements
    /// * `output` - Target [`crate::cilassembly::writer::output::Output`] for writing tables
    /// * `assembly` - Source [`crate::cilassembly::CilAssembly`] containing import/export definitions
    ///
    /// # Returns
    ///
    /// Returns [`crate::Result<()>`] on success or error if table generation fails.
    ///
    /// # Native Table Types
    ///
    /// - **Import Tables**: Allow managed code to call native DLL functions
    /// - **Export Tables**: Allow native code to call managed functions
    ///
    /// Tables are only generated if the layout indicates they are needed and
    /// RVA space has been allocated for them.
    fn execute_native_table_operations(
        layout: &WriteLayout,
        output: &mut Output,
        assembly: &CilAssembly,
    ) -> Result<()> {
        let requirements = &layout.native_table_requirements;

        if requirements.needs_import_tables {
            if let Some(import_rva) = requirements.import_table_rva {
                let unified_imports = assembly.native_imports();
                if !unified_imports.is_empty() {
                    Self::write_import_tables(
                        output,
                        layout,
                        assembly,
                        import_rva,
                        unified_imports,
                    )?;
                }
            }
        }

        if requirements.needs_export_tables {
            if let Some(export_rva) = requirements.export_table_rva {
                let unified_exports = assembly.native_exports();
                if !unified_exports.is_empty() {
                    Self::write_export_tables(
                        output,
                        layout,
                        assembly,
                        export_rva,
                        unified_exports,
                    )?;
                }
            }
        }

        Ok(())
    }

    /// Writes import tables to the output at the specified RVA.
    ///
    /// Generates and writes the complete native import table data including Import
    /// Directory Table, Import Lookup Tables, and Import Address Tables. These
    /// structures enable managed code to call functions in native DLLs.
    ///
    /// # Arguments
    ///
    /// * `output` - Target [`crate::cilassembly::writer::output::Output`] for writing import table data
    /// * `layout` - Layout information for RVA-to-offset conversion
    /// * `assembly` - Assembly to determine PE format (PE32 vs PE32+)
    /// * `import_rva` - RVA where import table should be positioned
    /// * `imports` - [`crate::metadata::imports::UnifiedImportContainer`] with native import data
    ///
    /// # Returns
    ///
    /// Returns [`crate::Result<()>`] on success or error if table generation fails.
    ///
    /// # PE Import Table Structure
    ///
    /// The import table consists of these components:
    ///
    /// 1. **Import Directory Table**: Array of IMAGE_IMPORT_DESCRIPTOR structures
    /// 2. **Import Lookup Tables (ILT)**: Function names/ordinals for each DLL
    /// 3. **Import Address Tables (IAT)**: Runtime addresses filled by loader
    /// 4. **String Data**: DLL names and function names as null-terminated strings
    ///
    /// # PE Format Considerations
    ///
    /// The import table format differs between PE32 and PE32+ for pointer sizes,
    /// which is handled automatically based on the assembly's PE format.
    fn write_import_tables(
        output: &mut Output,
        layout: &WriteLayout,
        assembly: &CilAssembly,
        import_rva: u32,
        imports: &UnifiedImportContainer,
    ) -> Result<()> {
        let mut native_imports_copy = imports.native().clone();
        native_imports_copy.set_import_table_base_rva(import_rva);

        let is_pe32_plus = assembly.file().is_pe32_plus_format()?;
        let import_table_data = native_imports_copy.get_import_table_data(is_pe32_plus)?;

        if !import_table_data.is_empty() {
            let file_offset = Self::rva_to_file_offset_with_layout(layout, import_rva);
            output.write_at(file_offset, &import_table_data)?;
        }

        Ok(())
    }

    /// Writes export tables to the output at the specified RVA.
    ///
    /// Generates and writes the complete native export table data including Export
    /// Directory Table, Address Table, Name Pointer Table, and Ordinal Table.
    /// These structures enable native code to call managed functions.
    ///
    /// # Arguments
    ///
    /// * `output` - Target [`crate::cilassembly::writer::output::Output`] for writing export table data
    /// * `layout` - Layout information for RVA-to-offset conversion
    /// * `_assembly` - Assembly reference (currently unused, reserved for future enhancements)
    /// * `export_rva` - RVA where export table should be positioned
    /// * `exports` - [`crate::metadata::exports::UnifiedExportContainer`] with native export data
    ///
    /// # Returns
    ///
    /// Returns [`crate::Result<()>`] on success or error if table generation fails.
    ///
    /// # PE Export Table Structure
    ///
    /// The export table consists of these components:
    ///
    /// 1. **Export Directory Table**: IMAGE_EXPORT_DIRECTORY structure
    /// 2. **Export Address Table**: RVAs of exported functions
    /// 3. **Name Pointer Table**: RVAs of exported function names
    /// 4. **Ordinal Table**: Ordinals for name-based exports
    /// 5. **String Data**: Function names as null-terminated strings
    fn write_export_tables(
        output: &mut Output,
        layout: &WriteLayout,
        _assembly: &crate::cilassembly::CilAssembly,
        export_rva: u32,
        exports: &UnifiedExportContainer,
    ) -> Result<()> {
        let mut native_exports_copy = exports.native().clone();
        native_exports_copy.set_export_table_base_rva(export_rva);

        let export_table_data = native_exports_copy.get_export_table_data()?;

        if !export_table_data.is_empty() {
            let file_offset = Self::rva_to_file_offset_with_layout(layout, export_rva);
            output.write_at(file_offset, &export_table_data)?;
        }

        Ok(())
    }

    /// Converts an RVA to a file offset using the assembly's original section information.
    ///
    /// This function uses the original assembly's section table to convert a Relative
    /// Virtual Address (RVA) to a file offset. It searches through all sections to
    /// find which section contains the given RVA and calculates the corresponding
    /// file position.
    ///
    /// # Arguments
    ///
    /// * `assembly` - Source [`crate::cilassembly::CilAssembly`] containing original section information
    /// * `rva` - Relative Virtual Address to convert
    ///
    /// # Returns
    ///
    /// The file offset corresponding to the given RVA, or the RVA itself as fallback
    /// if no matching section is found.
    ///
    /// # Algorithm
    ///
    /// 1. Iterate through all sections in the assembly
    /// 2. Check if RVA falls within section's virtual address range
    /// 3. Calculate offset within section: `rva - section.virtual_address`
    /// 4. Add section's file position: `section.pointer_to_raw_data + offset`
    ///
    /// This function is used for RVAs that should map to the original file layout.
    fn rva_to_file_offset(assembly: &CilAssembly, rva: u32) -> u64 {
        let view = assembly.view();
        let file = view.file();

        for section in file.sections() {
            let section_start = section.virtual_address;
            let section_end = section.virtual_address + section.virtual_size;

            if rva >= section_start && rva < section_end {
                let offset_in_section = rva - section_start;
                let file_offset =
                    u64::from(section.pointer_to_raw_data) + u64::from(offset_in_section);
                return file_offset;
            }
        }

        u64::from(rva)
    }

    /// Converts an RVA to a file offset using the layout's updated section information.
    ///
    /// This function uses the layout's updated section information (which includes the
    /// new .meta section) to convert RVAs to file offsets. This is essential for
    /// native import/export tables positioned within the new layout structure.
    ///
    /// # Arguments
    ///
    /// * `layout` - [`crate::cilassembly::writer::WriteLayout`] containing updated section information
    /// * `rva` - Relative Virtual Address to convert
    ///
    /// # Returns
    ///
    /// The file offset in the new layout corresponding to the given RVA.
    ///
    /// # Why This Function Exists
    ///
    /// The original assembly's section table doesn't include the new .meta section,
    /// so native tables positioned there need the updated layout information for
    /// correct RVA-to-offset conversion. This function provides that capability.
    ///
    /// # Usage
    ///
    /// Used specifically for converting RVAs of native import/export tables that
    /// are positioned within the new .meta section structure.
    fn rva_to_file_offset_with_layout(layout: &WriteLayout, rva: u32) -> u64 {
        for section in &layout.file_structure.sections {
            let section_start = section.virtual_address;
            let section_end = section.virtual_address + section.virtual_size;

            if rva >= section_start && rva < section_end {
                let offset_in_section = rva - section_start;
                let file_offset = section.file_region.offset + u64::from(offset_in_section);
                return file_offset;
            }
        }

        u64::from(rva)
    }

    /// Updates PE data directories to point to native import/export tables.
    ///
    /// Updates the PE Optional Header's data directory entries to point to the
    /// newly generated native import and export tables. This enables the Windows
    /// loader to find and process these tables correctly.
    ///
    /// # Arguments
    ///
    /// * `layout` - Layout containing native table requirements and locations
    /// * `output` - Target output for writing data directory updates
    /// * `assembly` - Assembly for locating PE data directory
    ///
    /// # Returns
    ///
    /// Returns [`crate::Result<()>`] on success or error if directory updates fail.
    ///
    /// # Data Directory Entries Updated
    ///
    /// - **Entry 0**: Export Table (RVA + Size)
    /// - **Entry 1**: Import Table (RVA + Size)
    ///
    /// Each entry is 8 bytes (4-byte RVA + 4-byte Size).
    fn update_native_data_directories(
        layout: &WriteLayout,
        output: &mut Output,
        assembly: &CilAssembly,
    ) -> Result<()> {
        let requirements = &layout.native_table_requirements;

        let data_directory_offset = Self::find_data_directory_offset(layout, assembly)?;

        if requirements.needs_import_tables {
            if let Some(import_rva) = requirements.import_table_rva {
                let import_entry_offset = data_directory_offset + 8;
                output.write_u32_le_at(import_entry_offset, import_rva)?;
                output.write_u32_le_at(
                    import_entry_offset + 4,
                    u32::try_from(requirements.import_table_size).map_err(|_| {
                        Error::WriteLayoutFailed {
                            message: "Import table size exceeds u32 range".to_string(),
                        }
                    })?,
                )?;
            }
        }

        if requirements.needs_export_tables {
            if let Some(export_rva) = requirements.export_table_rva {
                let export_entry_offset = data_directory_offset;
                output.write_u32_le_at(export_entry_offset, export_rva)?;
                output.write_u32_le_at(
                    export_entry_offset + 4,
                    u32::try_from(requirements.export_table_size).map_err(|_| {
                        Error::WriteLayoutFailed {
                            message: "Export table size exceeds u32 range".to_string(),
                        }
                    })?,
                )?;
            }
        }

        Ok(())
    }

    /// Clears the PE certificate table directory entry to prevent corruption.
    ///
    /// When we modify a PE file and change its size, any existing certificate table
    /// entry may become invalid and point beyond the end of the file. This function
    /// safely clears the certificate table entry (directory entry 4) to prevent
    /// file corruption and parsing errors.
    ///
    /// # Arguments
    ///
    /// * `layout` - Layout for locating PE data directory
    /// * `output` - Target output for writing directory clear operation
    /// * `assembly` - Assembly for PE format information
    ///
    /// # Returns
    ///
    /// Returns [`crate::Result<()>`] on success. This function is designed to be safe
    /// and will only return an error if critical operations fail.
    ///
    /// # Certificate Table Structure
    ///
    /// The certificate table (directory entry 4) contains:
    /// - RVA: Pointer to certificate data (4 bytes)
    /// - Size: Size of certificate data (4 bytes)
    ///
    /// Both fields are cleared to zero to indicate no certificate table.
    fn clear_certificate_table(
        layout: &WriteLayout,
        output: &mut Output,
        assembly: &CilAssembly,
    ) -> Result<()> {
        let data_directory_offset = Self::find_data_directory_offset(layout, assembly)?;

        let certificate_entry_offset = data_directory_offset + (4 * 8);

        output.write_u32_le_at(certificate_entry_offset, 0)?;
        output.write_u32_le_at(certificate_entry_offset + 4, 0)?;

        Ok(())
    }

    /// Finds the offset of the PE data directory within the file.
    ///
    /// The data directory is a crucial part of the PE Optional Header that contains
    /// RVA/Size pairs pointing to various PE structures like import/export tables,
    /// resources, and other components. Its location depends on the PE format.
    ///
    /// # Arguments
    ///
    /// * `layout` - [`crate::cilassembly::writer::WriteLayout`] containing PE headers region information
    /// * `assembly` - [`crate::cilassembly::CilAssembly`] to determine PE format (PE32 vs PE32+)
    ///
    /// # Returns
    ///
    /// File offset where the data directory starts, or [`crate::Error`] if PE headers are invalid.
    ///
    /// # PE Data Directory Layout
    ///
    /// The data directory location varies by PE format:
    /// - **PE32**: 96 bytes from start of optional header
    /// - **PE32+**: 112 bytes from start of optional header
    ///
    /// # Data Directory Entries
    ///
    /// Each entry is 8 bytes (RVA + Size):
    /// - Entry 0: Export Table
    /// - Entry 1: Import Table  
    /// - Entry 2: Resource Table
    /// - Entry 3: Exception Table
    /// - Entry 4: Certificate Table
    /// - Entry 5: Base Relocation Table
    /// - Entry 6: Debug
    /// - Entry 7: Architecture
    /// - Entry 8: Global Ptr
    /// - Entry 9: TLS Table
    /// - Entry 10: Load Config Table
    /// - Entry 11: Bound Import
    /// - Entry 12: Import Address Table
    /// - Entry 13: Delay Import Descriptor
    /// - Entry 14: COM+ Runtime Header
    /// - Entry 15: Reserved
    ///
    /// # Algorithm
    ///
    /// 1. Get PE Optional Header to determine format (PE32 vs PE32+)
    /// 2. Calculate optional header start: PE headers + 24 bytes (PE signature + COFF header)
    /// 3. Add data directory offset based on PE format
    /// 4. Validate the calculated offset is within PE headers region
    fn find_data_directory_offset(layout: &WriteLayout, assembly: &CilAssembly) -> Result<u64> {
        let view = assembly.view();
        let pe_headers_region = &layout.file_structure.pe_headers;

        let optional_header =
            view.file()
                .header_optional()
                .as_ref()
                .ok_or_else(|| Error::WriteLayoutFailed {
                    message: "Missing optional header for PE data directory location".to_string(),
                })?;
        let is_pe32_plus = optional_header.standard_fields.magic != 0x10b;

        let optional_header_start = pe_headers_region.offset + 24;

        let data_directory_offset = if is_pe32_plus {
            optional_header_start + 112
        } else {
            optional_header_start + 96
        };

        if data_directory_offset + 128 > pe_headers_region.offset + pe_headers_region.size {
            return Err(Error::WriteLayoutFailed {
                message: "PE data directory extends beyond PE headers region".to_string(),
            });
        }

        Ok(data_directory_offset)
    }

    /// Wraps operation errors with additional context for debugging.
    ///
    /// Enhances operation errors with context about which specific operation failed,
    /// its index in the operation sequence, and its description. This provides
    /// comprehensive debugging information when execution fails.
    ///
    /// # Arguments
    ///
    /// * `error` - The original [`crate::Error`] that occurred
    /// * `operation_type` - Type of operation ("copy", "zero", "write")
    /// * `operation_index` - Index of the operation in its sequence
    /// * `description` - Human-readable description of the operation
    ///
    /// # Returns
    ///
    /// Enhanced [`crate::Error`] with additional context for debugging.
    fn wrap_operation_error(
        error: &Error,
        operation_type: &str,
        operation_index: usize,
        description: &str,
    ) -> Error {
        Error::WriteLayoutFailed {
            message: format!(
                "{operation_type} operation #{operation_index} failed ({description}): {error}"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use tempfile::NamedTempFile;

    use crate::{cilassembly::writer::layout::WriteLayout, CilAssemblyView};

    use super::*;

    #[test]
    fn test_write_executor_with_basic_layout() {
        let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))
            .expect("Failed to load test assembly");
        let assembly = view.to_owned();

        let layout = WriteLayout::plan(&assembly).expect("Layout planning should succeed");

        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let mut output = Output::create(temp_file.path(), layout.total_file_size)
            .expect("Failed to create output");

        let result = WriteExecutor::execute(&layout, &mut output, &assembly);
        assert!(result.is_ok(), "Execution should succeed");
    }
}
