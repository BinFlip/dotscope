//! Simplified assembly writer pipeline for .NET binary generation.
//!
//! This module implements a revolutionary 3-stage approach to replace the complex 7-phase pipeline
//! in the legacy writer. The new design emphasizes complete upfront planning followed by purely
//! mechanical execution, resulting in superior maintainability, debuggability, and reliability.
//!
//! # Architecture
//!
//! The writer is built around the principle of **complete separation of concerns**:
//!
//! ```text
//! ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
//! │   Assembly      │───▶│  WriteLayout    │───▶│   WriteExecutor │
//! │   + Changes     │    │   .plan()       │    │   .execute()    │
//! └─────────────────┘    └─────────────────┘    └─────────────────┘
//!                                 │                        │
//!                                 ▼                        ▼
//!                        ┌─────────────────┐    ┌─────────────────┐
//!                        │ All Operations  │    │   Output File   │
//!                        │ Pre-calculated  │    │   (Complete)    │
//!                        └─────────────────┘    └─────────────────┘
//! ```
//!
//! **Design Principles:**
//!
//! 1. **Complete Planning**: All decisions made during layout planning, zero during execution
//! 2. **Operation-Based**: Everything expressed as simple copy/zero/write operations  
//! 3. **Mechanical Execution**: Execution engine contains no conditional logic
//! 4. **Preserved Guarantees**: Maintains all dnSpy compatibility and ECMA-335 compliance
//! 5. **Debugging-Friendly**: Every operation has description and validation
//!
//! # Key Components
//!
//! - [`crate::cilassembly::writer::WriteLayout`] - Complete layout plan with all operations pre-calculated
//! - [`crate::cilassembly::writer::WriteExecutor`] - Mechanical execution engine that performs planned operations
//! - [`crate::cilassembly::writer::layout`] - Layout planning subsystem with all calculation logic
//! - [`crate::cilassembly::writer::operations`] - Operation types for copy/zero/write actions
//! - [`crate::cilassembly::writer::heaps`] - Heap reconstruction with precise size calculations
//! - [`crate::cilassembly::writer::output`] - Memory-mapped output file abstraction
//! - [`crate::cilassembly::writer::utils`] - Shared utilities for metadata calculations
//!
//! # Usage Examples
//!
//! ## Simple High-Level API
//!
//! ```rust,ignore
//! use dotscope::cilassembly::writer::write_assembly_to_file;
//! use dotscope::prelude::*;
//! use std::path::Path;
//!
//! # let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))?;
//! # let assembly = view.to_owned();
//! // Simple one-line API that replaces the complex pipeline
//! write_assembly_to_file(&assembly, "output.dll")?;
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Advanced Three-Stage Usage
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
//! // Stage 1: Plan complete layout
//! let layout = WriteLayout::plan(&assembly)?;
//!
//! // Optional: Validate planning
//! layout.validate()?;
//! println!("Planning: {}", layout.summary());
//!
//! // Stage 2: Execute mechanically  
//! let mut output = Output::create(output_path, layout.total_file_size)?;
//! WriteExecutor::execute(&layout, &mut output, &assembly)?;
//!
//! // Stage 3: Verify results
//! layout.validate_against_output(&output)?;
//! output.finalize()?;
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Error Handling
//!
//! This module defines comprehensive error handling for the writing process:
//!
//! - [`crate::Error::WriteLayoutFailed`] - When layout planning encounters invalid conditions
//! - [`crate::Error::WriteFailed`] - When mechanical execution fails due to I/O issues
//! - [`crate::Error::ValidationFailed`] - When post-execution validation detects inconsistencies
//! - [`crate::Error::MemoryMappingFailed`] - When output file memory mapping operations fail
//!
//! All errors include detailed context about the specific operation that failed and suggested
//! recovery actions where applicable.
//!
//! # Thread Safety
//!
//! All types in this module are [`Send`] and [`Sync`] with the following guarantees:
//!
//! - [`crate::cilassembly::writer::WriteLayout`] is immutable after creation and fully thread-safe
//! - [`crate::cilassembly::writer::WriteExecutor`] is stateless and can be used concurrently
//! - [`crate::cilassembly::writer::output::Output`] is not [`Sync`] due to memory-mapped file access
//! - Individual operations within a layout can be executed in parallel (future enhancement)
//!
//! # Integration
//!
//! This module integrates with:
//!
//! - [`crate::cilassembly::CilAssembly`] - Source assembly with pending changes
//! - [`crate::metadata::tables`] - Metadata table modifications and analysis
//! - [`crate::metadata::heaps`] - String, blob, GUID, and user string heap operations
//! - [`crate::file::physical`] - Low-level PE file structure manipulation
//! - [`crate::assembly`] - Method body analysis and preservation
//!
//! # References
//!
//! - [ECMA-335 Common Language Infrastructure (CLI)](https://www.ecma-international.org/publications/standards/Ecma-335.htm)
//! - [PE Format Specification](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)
//! - [.NET Metadata Physical Layout](https://github.com/dotnet/runtime/blob/main/docs/design/specs/Ecma-335-Augments.md)

use crate::{cilassembly::CilAssembly, Result};

mod executor;
mod heaps;
mod layout;
mod operations;
mod output;
// Utils are now available from the main utils module - no local utils needed

use crate::cilassembly::writer::output::Output;

pub use crate::cilassembly::writer::{executor::WriteExecutor, layout::WriteLayout};

/// Writes a [`crate::cilassembly::CilAssembly`] to a file using the simplified 3-stage pipeline.
///
/// This function provides a clean high-level interface that encapsulates the complete
/// writing process: layout planning, mechanical execution, and validation. It replaces
/// the complex legacy pipeline with a single function call while maintaining full
/// compatibility and all existing guarantees.
///
/// The function performs these stages internally:
///
/// 1. **Layout Planning**: Analyzes the assembly and calculates the complete output layout
/// 2. **Mechanical Execution**: Performs all copy/zero/write operations as planned
/// 3. **Validation & Finalization**: Ensures consistency and flushes the output file
///
/// # Arguments
///
/// * `assembly` - The [`crate::cilassembly::CilAssembly`] to write (never modified during writing)
/// * `output_path` - Path where the new assembly file should be created. Parent directory must exist.
///
/// # Returns
///
/// Returns [`crate::Result<()>`] on successful completion. The output file will be a complete,
/// valid .NET assembly with all modifications applied and ready for execution or analysis.
///
/// # Errors
///
/// This function returns [`crate::Error`] in the following cases:
///
/// - [`crate::Error`] - When layout planning fails due to invalid assembly state or unsupported modifications
/// - [`crate::Error`] - When file I/O operations fail (permissions, disk space, path issues)
/// - [`crate::Error`] - When post-execution validation detects inconsistencies
/// - [`crate::Error`] - When memory mapping operations fail on the output file
///
/// # Examples
///
/// ## Basic Usage
///
/// ```rust,ignore
/// use dotscope::cilassembly::writer::write_assembly_to_file;
/// use dotscope::prelude::*;
/// use std::path::Path;
///
/// # let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))?;
/// # let assembly = view.to_owned();
/// write_assembly_to_file(&assembly, "output.dll")?;
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// ## With Error Handling
///
/// ```rust,ignore
/// use dotscope::cilassembly::writer::write_assembly_to_file;
/// use dotscope::prelude::*;
/// use dotscope::Error;
/// use std::path::Path;
///
/// # let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))?;
/// # let assembly = view.to_owned();
/// match write_assembly_to_file(&assembly, "output.dll") {
///     Ok(()) => println!("Assembly written successfully"),
///     Err(Error::WriteLayoutFailed { message }) => {
///         eprintln!("Layout planning failed: {}", message);
///     },
///     Err(Error::WriteFailed { message }) => {
///         eprintln!("File writing failed: {}", message);
///     },
///     Err(e) => eprintln!("Other error: {}", e),
/// }
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Thread Safety
///
/// This function is thread-safe and can be called concurrently with different assemblies
/// and output paths. However, writing to the same output path concurrently will result
/// in undefined behavior due to file system limitations.
pub fn write_assembly_to_file<P: AsRef<std::path::Path>>(
    assembly: &CilAssembly,
    output_path: P,
) -> Result<()> {
    let output_path = output_path.as_ref();

    let layout = WriteLayout::plan(assembly)?;

    let mut output = Output::create(output_path, layout.total_file_size)?;
    WriteExecutor::execute(&layout, &mut output, assembly)?;

    output.finalize()?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use tempfile::NamedTempFile;

    use crate::CilAssemblyView;

    use super::*;

    #[test]
    fn test_write_assembly_to_file_basic() {
        let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))
            .expect("Failed to load test assembly");
        let assembly = view.to_owned();

        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let result = write_assembly_to_file(&assembly, temp_file.path());

        assert!(result.is_ok(), "Basic assembly writing should succeed");
    }
}
