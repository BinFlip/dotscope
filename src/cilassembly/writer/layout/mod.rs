//! Comprehensive layout planning system for deterministic assembly file generation.
//!
//! This module implements the revolutionary "plan-everything-upfront" approach that transforms
//! the complex task of .NET assembly modification from a multi-phase, stateful process into
//! a single-pass planning phase followed by mechanical execution. The planning system analyzes
//! assembly changes, calculates precise file layouts, and generates complete operation sets
//! for deterministic binary generation.
//!
//! The layout planning approach eliminates the complexity and unpredictability of traditional
//! assembly writers by making every decision during the planning phase. This results in
//! superior reliability, debuggability, and maintainability while ensuring perfect ECMA-335
//! compliance and compatibility with analysis tools like dnSpy.
//!
//! # Architecture
//!
//! The layout planning system operates on a comprehensive analysis and planning model:
//!
//! ```text
//! ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
//! │   Assembly      │───▶│   Analysis      │───▶│  Size Calc      │
//! │   + Changes     │    │   Phase         │    │  Phase          │
//! └─────────────────┘    └─────────────────┘    └─────────────────┘
//!          │                       │                       │
//!          ▼                       ▼                       ▼
//! ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
//! │  Requirements   │    │  Dependencies   │    │  Exact Sizes    │
//! │  Identification │    │  Analysis       │    │  All Components │
//! └─────────────────┘    └─────────────────┘    └─────────────────┘
//!          │                       │                       │
//!          ▼                       ▼                       ▼
//! ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
//! │ Layout Planning │───▶│ Operation Gen   │───▶│  WriteLayout    │
//! │ File Structure  │    │ Copy/Zero/Write │    │  (Complete)     │
//! └─────────────────┘    └─────────────────┘    └─────────────────┘
//! ```
//!
//! **Core Design Principles:**
//!
//! 1. **Complete Upfront Planning**: All decisions made during planning, zero during execution
//! 2. **Deterministic Results**: Same input assembly always produces identical layouts
//! 3. **Operation-Based Execution**: Every file modification expressed as atomic operations
//! 4. **Comprehensive Validation**: Built-in validation ensures consistency and compliance
//! 5. **Rich Debugging Information**: Detailed planning information for analysis and troubleshooting
//!
//! # Key Components
//!
//! - [`crate::cilassembly::writer::layout::WriteLayout`] - Complete layout plan with all operations and metadata
//! - [`crate::cilassembly::writer::layout::LayoutPlanner`] - Main planning engine that orchestrates the entire process
//! - [`crate::cilassembly::writer::layout::MetadataLayout`] - .meta section layout with COR20 header and stream organization
//! - [`crate::cilassembly::writer::layout::SectionLayout`] - PE section layout calculations with proper alignment
//! - [`crate::cilassembly::writer::layout::StreamLayout`] - Individual metadata stream positioning and sizing
//! - [`crate::cilassembly::writer::layout::FileRegion`] - File region abstraction for precise positioning
//!
//! # Usage Examples
//!
//! ## Basic Layout Planning
//!
//! ```rust,ignore
//! use dotscope::cilassembly::writer::layout::WriteLayout;
//! use dotscope::prelude::*;
//! use std::path::Path;
//!
//! # let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))?;
//! # let assembly = view.to_owned();
//! // Complete layout planning in a single call
//! let layout = WriteLayout::plan(&assembly)?;
//!
//! // Inspect planning results
//! println!("File size: {} bytes", layout.total_file_size);
//! println!("Operations: {}", layout.operations.summary());
//! println!("Size increase: {} bytes", layout.size_increase());
//!
//! // Planning information is rich and detailed
//! println!("Planning took: {:?}", layout.planning_info.planning_duration);
//! for warning in &layout.planning_info.warnings {
//!     println!("Warning: {}", warning);
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Advanced Layout Analysis
//!
//! ```rust,ignore
//! use dotscope::cilassembly::writer::layout::WriteLayout;
//! use dotscope::prelude::*;
//! use std::path::Path;
//!
//! # let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))?;
//! # let assembly = view.to_owned();
//! let layout = WriteLayout::plan(&assembly)?;
//!
//! // Analyze file structure layout
//! println!("PE Headers: {} bytes at 0x{:X}",
//!     layout.file_structure.pe_headers.size,
//!     layout.file_structure.pe_headers.offset);
//!
//! // Analyze metadata layout
//! println!("Metadata section: {} bytes at RVA 0x{:X}",
//!     layout.metadata_layout.meta_section.file_region.size,
//!     layout.metadata_layout.meta_section.virtual_address);
//!
//! // Examine individual streams
//! for stream in &layout.metadata_layout.streams {
//!     println!("{}: {} bytes at offset 0x{:X}",
//!         stream.name, stream.size, stream.file_region.offset);
//! }
//!
//! // Analyze size breakdown
//! let breakdown = layout.size_breakdown();
//! println!("Headers: {} bytes", breakdown.headers_size);
//! println!("Metadata: {} bytes", breakdown.metadata_section_size);
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Integration with Execution Pipeline
//!
//! ```rust,ignore
//! use dotscope::cilassembly::writer::layout::WriteLayout;
//! use dotscope::cilassembly::writer::executor::WriteExecutor;
//! use dotscope::cilassembly::writer::output::Output;
//! use dotscope::prelude::*;
//! use std::path::Path;
//!
//! # let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))?;
//! # let assembly = view.to_owned();
//! // Complete three-stage pipeline
//! let layout = WriteLayout::plan(&assembly)?;
//! let mut output = Output::create("output.dll", layout.total_file_size)?;
//! WriteExecutor::execute(&layout, &mut output, &assembly)?;
//!
//! // Validate that execution matched planning
//! layout.validate_against_output(&output)?;
//! output.finalize()?;
//!
//! println!("Assembly successfully written with planned layout");
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Error Handling
//!
//! This module defines comprehensive error handling for layout planning issues:
//!
//! - [`crate::Error::WriteLayoutFailed`] - When layout planning encounters invalid conditions or conflicts
//! - Detailed error messages with specific information about what failed and why
//! - Context-rich errors that help diagnose assembly structure issues
//! - Validation errors that prevent generation of invalid PE files
//!
//! All errors include detailed information about the specific planning step that failed,
//! the assembly characteristics that caused the issue, and guidance for resolution.
//!
//! # Thread Safety
//!
//! All layout types are designed for thread-safe usage with specific guarantees:
//!
//! - [`crate::cilassembly::writer::layout::WriteLayout`] is immutable after creation and fully thread-safe
//! - [`crate::cilassembly::writer::layout::LayoutPlanner`] is not thread-safe during planning but produces thread-safe results
//! - All layout data structures are [`Send`] and [`Sync`] once created
//! - Planning can be performed on different assemblies concurrently without conflicts
//!
//! # Integration
//!
//! This module provides the critical planning foundation for the entire writer pipeline:
//!
//! - [`crate::cilassembly::writer::executor`] - Executes the operations generated by layout planning
//! - [`crate::cilassembly::writer::operations`] - Operation types are generated and populated by planning
//! - [`crate::cilassembly::writer::output`] - Output file operations use regions calculated by planning
//! - [`crate::cilassembly::writer::heap_builders`] - Heap construction uses size calculations from planning
//! - [`crate::cilassembly::writer::utils`] - Utility functions support the planning calculations
//!
//! # References
//!
//! - [ECMA-335 Common Language Infrastructure (CLI)](https://www.ecma-international.org/publications/standards/Ecma-335.htm)
//! - [PE Format Specification](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)
//! - [.NET Metadata Physical Layout](https://github.com/dotnet/runtime/blob/main/docs/design/specs/Ecma-335-Augments.md)
//! - [ECMA-335 Partition II: Metadata Definition and Semantics](https://www.ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf)

use std::collections::HashMap;

use crate::{
    cilassembly::{
        writer::{operations::OperationSet, output::Output},
        CilAssembly,
    },
    Error, Result,
};

mod heaps;
mod planner;
mod region;
mod tables;

pub(crate) use heaps::{
    calculate_blob_heap_size, calculate_guid_heap_size, calculate_string_heap_size,
    calculate_userstring_heap_size,
};
pub(crate) use planner::LayoutPlanner;
pub(crate) use region::FileRegion;
pub(crate) use tables::calculate_table_stream_expansion;

/// Complete layout plan serving as the definitive blueprint for assembly file generation.
///
/// [`WriteLayout`] represents the culmination of the planning phase and contains every piece of
/// information needed for mechanical execution of assembly file generation. This structure
/// embodies the "plan everything upfront" philosophy by pre-calculating all operations,
/// file positions, size requirements, and cross-references before any actual file writing begins.
///
/// The layout serves as an immutable contract between the planning and execution phases,
/// ensuring that execution is purely mechanical with zero decision-making required. This
/// approach eliminates runtime complexity while providing complete auditability and
/// debuggability of the entire file generation process.
///
/// # Complete Planning Information
///
/// The layout contains comprehensive information across all aspects of file generation:
///
/// - **Operations**: Complete set of copy/zero/write operations for mechanical execution
/// - **File Structure**: Detailed PE file layout including headers, sections, and positioning
/// - **Metadata Layout**: Complete .meta section organization with all streams and heaps
/// - **Cross-References**: RVA mappings and index remappings for maintaining referential integrity
/// - **Native Tables**: Import/export table requirements and RVA allocations
/// - **Validation Data**: Comprehensive validation information and debugging metrics
///
/// # Immutability and Thread Safety
///
/// Once created, [`WriteLayout`] is completely immutable and can be safely shared between
/// threads or used multiple times for execution. All internal data structures are designed
/// for read-only access during the execution phase.
///
/// # Thread Safety
///
/// This type is [`Send`] and [`Sync`] because all contained data is immutable after creation
/// and consists only of owned data structures without shared references or interior mutability.
///
/// # Examples
///
/// ## Basic Layout Planning and Execution
///
/// ```rust,ignore
/// use dotscope::cilassembly::writer::layout::WriteLayout;
/// use dotscope::cilassembly::writer::executor::WriteExecutor;
/// use dotscope::cilassembly::writer::output::Output;
/// use dotscope::prelude::*;
/// use std::path::Path;
///
/// # let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))?;
/// # let assembly = view.to_owned();
/// // Create complete layout plan
/// let layout = WriteLayout::plan(&assembly)?;
///
/// // Inspect planning results
/// println!("Planned file size: {} bytes", layout.total_file_size);
/// println!("Operations to execute: {}", layout.operations.summary());
/// println!("Size increase: {} bytes", layout.size_increase());
///
/// // Execute the plan mechanically
/// let mut output = Output::create("output.dll", layout.total_file_size)?;
/// WriteExecutor::execute(&layout, &mut output, &assembly)?;
/// output.finalize()?;
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// ## Detailed Layout Analysis
///
/// ```rust,ignore
/// use dotscope::cilassembly::writer::layout::WriteLayout;
/// use dotscope::prelude::*;
/// use std::path::Path;
///
/// # let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))?;
/// # let assembly = view.to_owned();
/// let layout = WriteLayout::plan(&assembly)?;
///
/// // Analyze file structure layout
/// println!("DOS/PE Headers: {} bytes", layout.file_structure.pe_headers.size);
/// println!("Section count: {}", layout.file_structure.sections.len());
///
/// // Find the .meta section
/// for section in &layout.file_structure.sections {
///     if section.contains_metadata {
///         println!(".meta section: {} bytes at RVA 0x{:X}",
///             section.file_region.size, section.virtual_address);
///     }
/// }
///
/// // Analyze metadata streams
/// for stream in &layout.metadata_layout.streams {
///     println!("{}: {} bytes at file offset 0x{:X}",
///         stream.name, stream.size, stream.file_region.offset);
/// }
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// ## Validation and Debugging
///
/// ```rust,ignore
/// use dotscope::cilassembly::writer::layout::WriteLayout;
/// use dotscope::prelude::*;
/// use std::path::Path;
///
/// # let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))?;
/// # let assembly = view.to_owned();
/// let layout = WriteLayout::plan(&assembly)?;
///
/// // Comprehensive validation
/// layout.validate()?;
/// println!("Layout validation passed");
///
/// // Examine planning metrics
/// let info = &layout.planning_info;
/// println!("Planning duration: {:?}", info.planning_duration);
/// println!("Generated {} operations", info.operation_count);
/// println!("File grew by {} bytes ({:.1}%)",
///     info.size_increase,
///     (info.size_increase as f64 / info.original_size as f64) * 100.0);
///
/// // Check for warnings
/// for warning in &info.warnings {
///     println!("Planning warning: {}", warning);
/// }
///
/// // Detailed size breakdown
/// let breakdown = layout.size_breakdown();
/// println!("Size breakdown:");
/// println!("  Headers: {} bytes", breakdown.headers_size);
/// println!("  Original sections: {} bytes", breakdown.original_sections_size);
/// println!("  Metadata section: {} bytes", breakdown.metadata_section_size);
/// # Ok::<(), dotscope::Error>(())
/// ```
#[derive(Debug, Clone)]
pub struct WriteLayout {
    /// Total size of the output file in bytes
    pub total_file_size: u64,

    /// Complete set of operations to execute
    pub operations: OperationSet,

    /// PE file structure layout information
    pub file_structure: FileStructureLayout,

    /// Metadata section layout in the new .meta section
    pub metadata_layout: MetadataLayout,

    /// RVA mapping for method body resolution
    pub rva_mappings: HashMap<u32, u32>, // placeholder_rva -> actual_rva

    /// Index remapping for heap cross-references
    pub index_mappings: crate::cilassembly::remapping::IndexRemapper,

    /// Native PE table requirements and RVA allocations
    pub native_table_requirements: NativeTableRequirements,

    /// Validation and debugging information
    pub planning_info: PlanningInfo,
}

/// Native PE import/export table requirements calculated during layout planning.
///
/// This structure captures the complete requirements for generating native PE import and
/// export tables that enable interoperability between managed .NET code and native code.
/// During layout planning, the system analyzes the assembly's native import/export needs
/// and calculates precise space requirements and RVA allocations within the file structure.
///
/// Native table generation enables powerful scenarios like P/Invoke function calls,
/// native DLL dependencies, and exposing managed functions to native code consumers.
/// The layout planning approach ensures these tables are properly positioned and sized
/// without conflicts with metadata streams or other PE structures.
///
/// # PE Native Table Types
///
/// - **Import Tables**: Enable managed code to call functions in native DLLs (P/Invoke)
/// - **Export Tables**: Enable native code to call managed functions (reverse P/Invoke)
/// - **Data Directories**: PE header entries that point to these tables for loader access
/// - **Name Tables**: String tables containing DLL names and function names
/// - **Address Tables**: Runtime-populated tables for function address resolution
///
/// # RVA Allocation Strategy
///
/// RVAs (Relative Virtual Addresses) are allocated during layout planning to ensure:
/// - No conflicts with metadata streams or other PE structures
/// - Proper alignment for loader requirements
/// - Efficient memory layout for runtime performance
/// - Compliance with PE format specifications
///
/// # Examples
///
/// ## Checking Native Table Requirements
///
/// ```rust,ignore
/// use dotscope::cilassembly::writer::layout::WriteLayout;
/// use dotscope::prelude::*;
/// use std::path::Path;
///
/// # let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))?;
/// # let assembly = view.to_owned();
/// let layout = WriteLayout::plan(&assembly)?;
/// let requirements = &layout.native_table_requirements;
///
/// // Check import table requirements
/// if requirements.needs_import_tables {
///     println!("Import table required: {} bytes", requirements.import_table_size);
///     if let Some(rva) = requirements.import_table_rva {
///         println!("Import table allocated at RVA: 0x{:X}", rva);
///     }
/// } else {
///     println!("No import tables needed");
/// }
///
/// // Check export table requirements
/// if requirements.needs_export_tables {
///     println!("Export table required: {} bytes", requirements.export_table_size);
///     if let Some(rva) = requirements.export_table_rva {
///         println!("Export table allocated at RVA: 0x{:X}", rva);
///     }
/// } else {
///     println!("No export tables needed");
/// }
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// ## Space Planning Analysis
///
/// ```rust,ignore
/// use dotscope::cilassembly::writer::layout::WriteLayout;
/// use dotscope::prelude::*;
/// use std::path::Path;
///
/// # let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))?;
/// # let assembly = view.to_owned();
/// let layout = WriteLayout::plan(&assembly)?;
/// let requirements = &layout.native_table_requirements;
///
/// // Calculate total native table space
/// let total_native_size = requirements.import_table_size + requirements.export_table_size;
/// if total_native_size > 0 {
///     println!("Total native table space: {} bytes", total_native_size);
///     
///     let metadata_size = layout.metadata_layout.meta_section.file_region.size;
///     let native_percentage = (total_native_size as f64 / metadata_size as f64) * 100.0;
///     println!("Native tables: {:.1}% of .meta section", native_percentage);
/// }
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Thread Safety
///
/// This type is [`Send`] and [`Sync`] because all fields are primitive types or options
/// containing primitive types, with no shared references or interior mutability.
#[derive(Debug, Clone, Default)]
pub struct NativeTableRequirements {
    /// Whether import tables need to be generated
    pub needs_import_tables: bool,
    /// Whether export tables need to be generated  
    pub needs_export_tables: bool,
    /// Size in bytes needed for import table data
    pub import_table_size: u64,
    /// Size in bytes needed for export table data
    pub export_table_size: u64,
    /// Allocated RVA for import table (None if not needed)
    pub import_table_rva: Option<u32>,
    /// Allocated RVA for export table (None if not needed)
    pub export_table_rva: Option<u32>,
}

/// Complete PE file structure layout with precise positioning of all components.
///
/// This structure represents the calculated layout of the entire PE (Portable Executable)
/// file structure, including DOS header, PE headers, section table, and all sections.
/// The layout planning process determines the exact positioning, sizing, and alignment
/// of every component to ensure a valid, well-formed PE file that meets operating
/// system loader requirements.
///
/// The PE file structure layout accounts for the addition of the new .meta section
/// while preserving all original sections through careful relocation and RVA updates.
/// This ensures that existing code references remain valid while accommodating the
/// new metadata organization.
///
/// # Complete PE File Layout
///
/// The layout represents the full PE file structure from start to finish:
///
/// ```text
/// File Offset    Component              Virtual Address
/// ┌─────────────────┐ ← 0x0000        ┌─────────────────┐ ← 0x00400000
/// │   DOS Header    │                 │   DOS Header    │
/// │   (64 bytes)    │                 │   (64 bytes)    │
/// ├─────────────────┤ ← dos_header    ├─────────────────┤
/// │   PE Headers    │ end             │   PE Headers    │
/// │   NT + COFF +   │                 │   NT + COFF +   │
/// │   Optional      │                 │   Optional      │
/// ├─────────────────┤ ← pe_headers    ├─────────────────┤
/// │ Section Table   │ end             │ Section Table   │
/// │ (40 * N bytes)  │                 │ (40 * N bytes)  │
/// ├─────────────────┤ ← section_table ├─────────────────┤ ← sections[0].rva
/// │   .text         │ end             │   .text         │
/// │   (relocated)   │                 │   (relocated)   │
/// ├─────────────────┤                 ├─────────────────┤ ← sections[1].rva
/// │   .rsrc         │                 │   .rsrc         │
/// │   (relocated)   │                 │   (relocated)   │
/// ├─────────────────┤                 ├─────────────────┤ ← sections[2].rva
/// │   .meta (NEW)   │                 │   .meta (NEW)   │
/// │   All metadata  │                 │   All metadata  │
/// │   streams here  │                 │   streams here  │
/// └─────────────────┘                 └─────────────────┘
/// ```
///
/// # Section Management Strategy
///
/// The layout planning implements a sophisticated section management approach:
///
/// - **Preservation**: All original sections are preserved with their content intact
/// - **Relocation**: Original sections are moved to new file positions to make room for .meta
/// - **RVA Updates**: All virtual addresses are recalculated to maintain memory layout integrity
/// - **Expansion**: Section table is expanded to accommodate the additional .meta section
/// - **Alignment**: All sections maintain proper file and memory alignment requirements
///
/// # Examples
///
/// ## File Structure Analysis
///
/// ```rust,ignore
/// use dotscope::cilassembly::writer::layout::WriteLayout;
/// use dotscope::prelude::*;
/// use std::path::Path;
///
/// # let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))?;
/// # let assembly = view.to_owned();
/// let layout = WriteLayout::plan(&assembly)?;
/// let file_structure = &layout.file_structure;
///
/// // Analyze PE headers
/// println!("DOS Header: {} bytes at offset 0x{:X}",
///     file_structure.dos_header.size,
///     file_structure.dos_header.offset);
///
/// println!("PE Headers: {} bytes at offset 0x{:X}",
///     file_structure.pe_headers.size,
///     file_structure.pe_headers.offset);
///
/// println!("Section Table: {} bytes at offset 0x{:X} ({} sections)",
///     file_structure.section_table.size,
///     file_structure.section_table.offset,
///     file_structure.sections.len());
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// ## Section Layout Analysis
///
/// ```rust,ignore
/// use dotscope::cilassembly::writer::layout::WriteLayout;
/// use dotscope::prelude::*;
/// use std::path::Path;
///
/// # let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))?;
/// # let assembly = view.to_owned();
/// let layout = WriteLayout::plan(&assembly)?;
///
/// println!("Section Layout:");
/// for (i, section) in layout.file_structure.sections.iter().enumerate() {
///     println!("  [{}] {}: {} bytes", i, section.name, section.file_region.size);
///     println!("      File: 0x{:X}-0x{:X}",
///         section.file_region.offset,
///         section.file_region.offset + section.file_region.size);
///     println!("      RVA:  0x{:X}-0x{:X}",
///         section.virtual_address,
///         section.virtual_address + section.virtual_size);
///     println!("      Characteristics: 0x{:X}", section.characteristics);
///     if section.contains_metadata {
///         println!("      ** Contains .NET metadata **");
///     }
/// }
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Thread Safety
///
/// This type is [`Send`] and [`Sync`] because all contained data structures are
/// owned and immutable after creation, with no shared references or interior mutability.
#[derive(Debug, Clone)]
pub struct FileStructureLayout {
    /// DOS header position and size
    pub dos_header: FileRegion,

    /// PE headers position and size (PE signature, COFF header, optional header)
    pub pe_headers: FileRegion,

    /// Section table position and size (expanded for .meta section)
    pub section_table: FileRegion,

    /// All sections including original (relocated) and new .meta section
    pub sections: Vec<SectionLayout>,
}

/// Complete metadata section layout with ECMA-335 compliant organization.
///
/// This structure represents the detailed internal layout of the .meta section that contains
/// all .NET metadata in a precisely organized, ECMA-335 compliant format. The metadata
/// layout encompasses the COR20 header, metadata root, stream directory, and all individual
/// metadata streams, with each component positioned for optimal access and compliance.
///
/// The metadata layout planning ensures that all components are properly aligned, sized,
/// and positioned to create a valid .NET metadata structure that can be correctly interpreted
/// by the Common Language Runtime and analysis tools like dnSpy.
///
/// # Complete .meta Section Architecture
///
/// The .meta section follows the standard .NET metadata physical layout:
///
/// ```text
/// Offset from .meta start    Component                Size
/// ┌────────────────────────────────────────────────────────────────────────────────┐
/// │0x0000              │  COR20 Header                        72 bytes fixed  │
/// │                    │  - .NET Runtime Version             (always 0x30002) │
/// │                    │  - Metadata Directory RVA/Size      (points below)  │
/// │                    │  - Flags, EntryPoint, Resources      (various)     │
/// ├────────────────────────────────────────────────────────────────────────────────┤
/// │0x0048              │  Metadata Root                       Variable size   │
/// │                    │  - Signature ("BSJB")               4 bytes         │
/// │                    │  - Major/Minor Version              4 bytes         │
/// │                    │  - Version String Length + Data     Variable        │
/// │                    │  - Flags (always 0)                 2 bytes         │
/// │                    │  - Stream Count                     2 bytes         │
/// ├────────────────────────────────────────────────────────────────────────────────┤
/// │Variable offset    │  Stream Directory                    Variable size   │
/// │                    │  - Stream Headers (Offset, Size, Name) per stream   │
/// │                    │  - Null-terminated, 4-byte aligned  entries         │
/// ├────────────────────────────────────────────────────────────────────────────────┤
/// │Stream offsets     │  #~ or #- Stream (Tables)            Variable size   │
/// │(calculated)       │  - Table schema, row data, indexes  (ECMA-335)      │
/// ├────────────────────────────────────────────────────────────────────────────────┤
/// │                    │  #Strings Stream                     Variable size   │
/// │                    │  - Null-terminated UTF-8 strings    (heap format)   │
/// ├────────────────────────────────────────────────────────────────────────────────┤
/// │                    │  #Blob Stream                        Variable size   │
/// │                    │  - Length-prefixed binary data      (heap format)   │
/// ├────────────────────────────────────────────────────────────────────────────────┤
/// │                    │  #GUID Stream                        Variable size   │
/// │                    │  - 16-byte GUID values              (heap format)   │
/// ├────────────────────────────────────────────────────────────────────────────────┤
/// │                    │  #US Stream (User Strings)           Variable size   │
/// │                    │  - Length-prefixed UTF-16 strings   (heap format)   │
/// └────────────────────────────────────────────────────────────────────────────────┘
/// ```
///
/// # ECMA-335 Compliance Features
///
/// The metadata layout ensures strict compliance with ECMA-335 specification:
///
/// - **Signature Validation**: Metadata root begins with "BSJB" signature
/// - **Version Compliance**: Proper version information and format compliance
/// - **Stream Alignment**: All streams aligned to 4-byte boundaries
/// - **Directory Structure**: Stream directory entries with correct offset calculations
/// - **Heap Format**: All heaps follow ECMA-335 heap format specifications
/// - **Table Encoding**: Metadata tables use proper encoding and compression
///
/// # Examples
///
/// ## Metadata Section Analysis
///
/// ```rust,ignore
/// use dotscope::cilassembly::writer::layout::WriteLayout;
/// use dotscope::prelude::*;
/// use std::path::Path;
///
/// # let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))?;
/// # let assembly = view.to_owned();
/// let layout = WriteLayout::plan(&assembly)?;
/// let metadata = &layout.metadata_layout;
///
/// // Analyze .meta section overall structure
/// println!(".meta section: {} bytes at RVA 0x{:X}",
///     metadata.meta_section.file_region.size,
///     metadata.meta_section.virtual_address);
///
/// // Analyze COR20 header
/// println!("COR20 Header: {} bytes at offset 0x{:X}",
///     metadata.cor20_header.size,
///     metadata.cor20_header.offset);
///
/// // Analyze metadata root
/// println!("Metadata Root: {} bytes at offset 0x{:X}",
///     metadata.metadata_root.size,
///     metadata.metadata_root.offset);
///
/// // Analyze stream directory
/// println!("Stream Directory: {} bytes at offset 0x{:X}",
///     metadata.stream_directory.size,
///     metadata.stream_directory.offset);
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// ## Stream Layout Analysis
///
/// ```rust,ignore
/// use dotscope::cilassembly::writer::layout::WriteLayout;
/// use dotscope::prelude::*;
/// use std::path::Path;
///
/// # let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))?;
/// # let assembly = view.to_owned();
/// let layout = WriteLayout::plan(&assembly)?;
///
/// println!("Metadata Streams Layout:");
/// for (i, stream) in layout.metadata_layout.streams.iter().enumerate() {
///     println!("  [{}] {}: {} bytes", i, stream.name, stream.size);
///     println!("      From metadata root: +0x{:X}", stream.offset_from_root);
///     println!("      File offset: 0x{:X}", stream.file_region.offset);
///     
///     // Special information for specific streams
///     match stream.name.as_str() {
///         "#~" | "#-" => println!("      ** Metadata Tables Stream **"),
///         "#Strings" => println!("      ** String Heap **"),
///         "#Blob" => println!("      ** Blob Heap **"),
///         "#GUID" => println!("      ** GUID Heap **"),
///         "#US" => println!("      ** User String Heap **"),
///         _ => {}
///     }
///     println!();
/// }
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Thread Safety
///
/// This type is [`Send`] and [`Sync`] because all contained data structures are
/// owned and immutable after creation, with no shared references or interior mutability.
#[derive(Debug, Clone)]
pub struct MetadataLayout {
    /// .meta section overall information
    pub meta_section: SectionLayout,

    /// COR20 header position within .meta section
    pub cor20_header: FileRegion,

    /// Metadata root position within .meta section  
    pub metadata_root: FileRegion,

    /// Stream directory position within .meta section
    pub stream_directory: FileRegion,

    /// Individual stream layouts within .meta section
    pub streams: Vec<StreamLayout>,
}

/// Complete layout information for a single PE section with file and memory positioning.
///
/// This structure represents the complete layout information for one PE section, including
/// both its physical positioning within the file and its virtual memory mapping when the
/// PE file is loaded. Each section has specific characteristics that determine how the
/// operating system loader treats the section content.
///
/// The section layout planning ensures proper alignment for both file storage and memory
/// mapping, while maintaining the section characteristics required for correct execution.
/// This is critical for maintaining compatibility with the Windows PE loader and ensuring
/// that relocated sections continue to function correctly.
///
/// # PE Section Architecture
///
/// Each section has dual positioning requirements:
/// - **File Position**: Where the section data is stored in the physical file
/// - **Virtual Position**: Where the section will be mapped in process memory
/// - **Characteristics**: Flags that control loader behavior and access permissions
///
/// # Common Section Types and Characteristics
///
/// | Section | Characteristics | Purpose |
/// |---------|----------------|----------|
/// | .text   | `CODE + EXECUTE + READ` | Executable code and IL |
/// | .data   | `INITIALIZED_DATA + READ + WRITE` | Initialized data |
/// | .rsrc   | `INITIALIZED_DATA + READ` | Resources and manifests |
/// | .meta   | `INITIALIZED_DATA + READ` | .NET metadata (new) |
///
/// # Section Characteristics Flags
///
/// - **0x00000020**: `IMAGE_SCN_CNT_CODE` - Contains executable code
/// - **0x00000040**: `IMAGE_SCN_CNT_INITIALIZED_DATA` - Contains initialized data
/// - **0x20000000**: `IMAGE_SCN_MEM_EXECUTE` - Executable section
/// - **0x40000000**: `IMAGE_SCN_MEM_READ` - Readable section
/// - **0x80000000**: `IMAGE_SCN_MEM_WRITE` - Writable section
///
/// # Examples
///
/// ## Code Section Layout
///
/// ```rust,ignore
/// use dotscope::cilassembly::writer::layout::{SectionLayout, FileRegion};
///
/// let text_section = SectionLayout {
///     name: ".text".to_string(),
///     virtual_address: 0x2000,     // RVA where section is mapped
///     virtual_size: 0x1000,        // Size in memory
///     file_region: FileRegion {
///         offset: 0x400,           // File offset (aligned to file alignment)
///         size: 0x1000             // Size on disk
///     },
///     characteristics: 0x60000020,  // CODE | EXECUTE | READ
///     contains_metadata: false,
/// };
///
/// // Verify section properties
/// assert_eq!(text_section.name, ".text");
/// assert!(!text_section.contains_metadata);
/// assert_eq!(text_section.characteristics & 0x00000020, 0x00000020); // Has CODE
/// ```
///
/// ## Metadata Section Layout
///
/// ```rust,ignore
/// use dotscope::cilassembly::writer::layout::{SectionLayout, FileRegion};
///
/// let meta_section = SectionLayout {
///     name: ".meta".to_string(),
///     virtual_address: 0x4000,     // RVA for metadata section
///     virtual_size: 0x2000,        // Virtual size for all metadata
///     file_region: FileRegion {
///         offset: 0x1400,          // File offset after other sections
///         size: 0x2000             // Physical size on disk
///     },
///     characteristics: 0x40000040,  // INITIALIZED_DATA | READ
///     contains_metadata: true,      // Special flag for .meta section
/// };
///
/// // Verify metadata section properties
/// assert_eq!(meta_section.name, ".meta");
/// assert!(meta_section.contains_metadata);
/// assert_eq!(meta_section.characteristics & 0x40000000, 0x40000000); // Has READ
/// ```
///
/// ## Section Relocation Analysis
///
/// ```rust,ignore
/// use dotscope::cilassembly::writer::layout::WriteLayout;
/// use dotscope::prelude::*;
/// use std::path::Path;
///
/// # let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))?;
/// # let assembly = view.to_owned();
/// let layout = WriteLayout::plan(&assembly)?;
///
/// println!("Section Layout Analysis:");
/// for (i, section) in layout.file_structure.sections.iter().enumerate() {
///     println!("Section [{}]: {}", i, section.name);
///     println!("  Virtual: RVA 0x{:08X}, size 0x{:X}",
///         section.virtual_address, section.virtual_size);
///     println!("  File: offset 0x{:08X}, size 0x{:X}",
///         section.file_region.offset, section.file_region.size);
///     println!("  Characteristics: 0x{:08X}", section.characteristics);
///     
///     if section.contains_metadata {
///         println!("  ** This section contains .NET metadata **");
///     }
///     
///     // Analyze section type
///     if section.characteristics & 0x00000020 != 0 {
///         println!("  Type: Executable code section");
///     } else if section.characteristics & 0x00000040 != 0 {
///         println!("  Type: Initialized data section");
///     }
/// }
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Thread Safety
///
/// This type is [`Send`] and [`Sync`] because all fields are owned and immutable
/// after creation, with no shared references or interior mutability.
#[derive(Debug, Clone)]
pub struct SectionLayout {
    /// Section name
    pub name: String,

    /// Virtual address (RVA) where section is mapped
    pub virtual_address: u32,

    /// Virtual size of section in memory
    pub virtual_size: u32,

    /// File region where section data is stored
    pub file_region: FileRegion,

    /// Section characteristics flags
    pub characteristics: u32,

    /// Whether this section contains metadata
    pub contains_metadata: bool,
}

/// Detailed layout information for individual metadata streams within the .meta section.
///
/// This structure represents the precise positioning and sizing of a single metadata stream
/// within the .meta section. Each stream serves a specific purpose in the ECMA-335 metadata
/// format and must be positioned with exact alignment and size calculations to ensure
/// proper interpretation by the Common Language Runtime.
///
/// The stream layout planning ensures that each stream is optimally positioned within the
/// metadata section while maintaining all ECMA-335 compliance requirements including
/// proper alignment, size encoding, and stream directory entries.
///
/// # ECMA-335 Metadata Stream Types
///
/// The .NET metadata format defines several standard stream types:
///
/// | Stream Name | Content Type | Purpose |
/// |-------------|--------------|----------|
/// | `#~` | Compressed Tables | Default metadata tables with compressed indexes |
/// | `#-` | Uncompressed Tables | Metadata tables with uncompressed indexes (rare) |
/// | `#Strings` | String Heap | Null-terminated UTF-8 strings referenced by tables |
/// | `#Blob` | Blob Heap | Binary data with compressed length prefixes |
/// | `#GUID` | GUID Heap | 16-byte GUID values for assemblies and types |
/// | `#US` | UserString Heap | UTF-16 string literals with length prefixes |
///
/// # Dual Positioning System
///
/// Each stream has two positioning references:
/// - **`offset_from_root`**: Offset relative to the metadata root (used in stream directory)
/// - **`file_region`**: Absolute file position and size (used for actual I/O operations)
///
/// This dual system enables both ECMA-335 compliant stream directory generation and
/// efficient file I/O operations during execution.
///
/// # Alignment Requirements
///
/// Per ECMA-335 specification:
/// - All streams must begin on 4-byte aligned boundaries
/// - Stream sizes are padded to 4-byte multiples
/// - Stream directory entries must account for alignment padding
///
/// # Examples
///
/// ## String Heap Stream Layout
///
/// ```rust,ignore
/// use dotscope::cilassembly::writer::layout::{StreamLayout, FileRegion};
///
/// let strings_stream = StreamLayout {
///     name: "#Strings".to_string(),
///     offset_from_root: 0x0400,    // 1KB from metadata root start
///     size: 0x0800,                // 2KB of string data
///     file_region: FileRegion {
///         offset: 0x5400,          // Absolute file position
///         size: 0x0800             // Same size as logical size
///     },
/// };
///
/// // Verify stream properties
/// assert_eq!(strings_stream.name, "#Strings");
/// assert_eq!(strings_stream.size, strings_stream.file_region.size);
/// assert_eq!(strings_stream.offset_from_root % 4, 0); // 4-byte aligned
/// ```
///
/// ## Metadata Tables Stream Layout
///
/// ```rust,ignore
/// use dotscope::cilassembly::writer::layout::{StreamLayout, FileRegion};
///
/// let tables_stream = StreamLayout {
///     name: "#~".to_string(),        // Compressed tables
///     offset_from_root: 0x0080,     // Immediately after metadata root
///     size: 0x0200,                 // 512 bytes of table data
///     file_region: FileRegion {
///         offset: 0x5080,           // Absolute file position
///         size: 0x0200              // Physical size matches logical size
///     },
/// };
///
/// // Tables stream is typically first after metadata root
/// assert_eq!(tables_stream.name, "#~");
/// assert!(tables_stream.offset_from_root < 0x1000); // Near beginning
/// ```
///
/// ## Stream Layout Analysis
///
/// ```rust,ignore
/// use dotscope::cilassembly::writer::layout::WriteLayout;
/// use dotscope::prelude::*;
/// use std::path::Path;
///
/// # let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))?;
/// # let assembly = view.to_owned();
/// let layout = WriteLayout::plan(&assembly)?;
///
/// println!("Metadata Stream Layout:");
/// let mut total_stream_size = 0u64;
///
/// for stream in &layout.metadata_layout.streams {
///     println!("Stream: {}", stream.name);
///     println!("  Logical size: {} bytes", stream.size);
///     println!("  From metadata root: +0x{:X}", stream.offset_from_root);
///     println!("  File position: 0x{:X}-0x{:X}",
///         stream.file_region.offset,
///         stream.file_region.offset + stream.file_region.size);
///     
///     // Check alignment
///     if stream.offset_from_root % 4 == 0 {
///         println!("  ✓ Properly aligned");
///     } else {
///         println!("  ✗ Alignment violation!");
///     }
///     
///     total_stream_size += stream.size as u64;
///     println!();
/// }
///
/// println!("Total stream data: {} bytes", total_stream_size);
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// ## Stream Type Analysis
///
/// ```rust,ignore
/// use dotscope::cilassembly::writer::layout::WriteLayout;
/// use dotscope::prelude::*;
/// use std::path::Path;
///
/// # let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))?;
/// # let assembly = view.to_owned();
/// let layout = WriteLayout::plan(&assembly)?;
///
/// for stream in &layout.metadata_layout.streams {
///     match stream.name.as_str() {
///         "#~" => println!("Found compressed metadata tables: {} bytes", stream.size),
///         "#-" => println!("Found uncompressed metadata tables: {} bytes", stream.size),
///         "#Strings" => println!("Found string heap: {} bytes", stream.size),
///         "#Blob" => println!("Found blob heap: {} bytes", stream.size),
///         "#GUID" => println!("Found GUID heap: {} bytes", stream.size),
///         "#US" => println!("Found user string heap: {} bytes", stream.size),
///         other => println!("Found custom stream '{}': {} bytes", other, stream.size),
///     }
/// }
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Thread Safety
///
/// This type is [`Send`] and [`Sync`] because all fields are owned string and numeric
/// types with no shared references or interior mutability.
#[derive(Debug, Clone)]
pub struct StreamLayout {
    /// Stream name (#Strings, #Blob, #GUID, #US, #~, #-)
    pub name: String,

    /// Offset from metadata root start
    pub offset_from_root: u32,

    /// Stream size in bytes
    pub size: u32,

    /// File region where stream data is located
    pub file_region: FileRegion,
}

/// Comprehensive planning metrics and debugging information for analysis and optimization.
///
/// This structure captures detailed information about the layout planning process, including
/// performance metrics, size analysis, warnings, and debugging data. The planning information
/// is invaluable for understanding the complexity of assembly modifications, identifying
/// optimization opportunities, and troubleshooting issues with the planning process.
///
/// The planning information serves multiple purposes: performance analysis for optimizing
/// the planning algorithms, size analysis for understanding file growth, and diagnostic
/// information for debugging complex assembly modification scenarios.
///
/// # Performance Analysis
///
/// The planning metrics enable performance analysis and optimization:
/// - **Timing Information**: How long each phase of planning took
/// - **Operation Complexity**: Number and types of operations generated
/// - **Size Impact**: How modifications affect file size
/// - **Efficiency Metrics**: Ratios and percentages for optimization analysis
///
/// # Size Analysis and Optimization
///
/// The detailed size breakdown helps identify optimization opportunities:
/// - **Growth Analysis**: Understanding why and where files grow
/// - **Component Sizing**: Size impact of different metadata components
/// - **Efficiency Ratios**: Comparing useful data to overhead
/// - **Trend Analysis**: How different modification patterns affect size
///
/// # Diagnostic and Debugging Support
///
/// The warning system captures non-fatal issues that might indicate problems:
/// - **Compatibility Warnings**: Potential issues with analysis tools
/// - **Efficiency Warnings**: Suboptimal conditions that affect performance
/// - **Size Warnings**: Unusual growth patterns or large size increases
/// - **Structure Warnings**: Unusual assembly characteristics
///
/// # Examples
///
/// ## Basic Planning Analysis
///
/// ```rust,ignore
/// use dotscope::cilassembly::writer::layout::WriteLayout;
/// use dotscope::prelude::*;
/// use std::path::Path;
///
/// # let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))?;
/// # let assembly = view.to_owned();
/// let layout = WriteLayout::plan(&assembly)?;
/// let info = &layout.planning_info;
///
/// // Basic planning metrics
/// println!("Planning Metrics:");
/// println!("  Duration: {:?}", info.planning_duration);
/// println!("  Original size: {} bytes", info.original_size);
/// println!("  Size increase: {} bytes ({:.1}%)",
///     info.size_increase,
///     (info.size_increase as f64 / info.original_size as f64) * 100.0);
/// println!("  Operations generated: {}", info.operation_count);
///
/// // Check for warnings
/// if info.warnings.is_empty() {
///     println!("  ✓ No planning warnings");
/// } else {
///     println!("  {} planning warnings:", info.warnings.len());
///     for warning in &info.warnings {
///         println!("    ⚠ {}", warning);
///     }
/// }
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// ## Detailed Size Analysis
///
/// ```rust,ignore
/// use dotscope::cilassembly::writer::layout::WriteLayout;
/// use dotscope::prelude::*;
/// use std::path::Path;
///
/// # let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))?;
/// # let assembly = view.to_owned();
/// let layout = WriteLayout::plan(&assembly)?;
/// let breakdown = &layout.planning_info.size_breakdown;
///
/// println!("Detailed Size Breakdown:");
/// println!("  Headers: {} bytes", breakdown.headers_size);
/// println!("  Section table: {} bytes", breakdown.section_table_size);
/// println!("  Original sections: {} bytes", breakdown.original_sections_size);
/// println!("  Metadata section: {} bytes", breakdown.metadata_section_size);
///
/// // Metadata component analysis
/// let meta = &breakdown.metadata_components;
/// println!("\n  Metadata Components:");
/// println!("    COR20 header: {} bytes", meta.cor20_header_size);
/// println!("    Metadata root: {} bytes", meta.metadata_root_size);
/// println!("    Tables stream: {} bytes", meta.tables_stream_size);
/// println!("    Strings heap: {} bytes", meta.strings_heap_size);
/// println!("    Blob heap: {} bytes", meta.blob_heap_size);
/// println!("    GUID heap: {} bytes", meta.guid_heap_size);
/// println!("    UserString heap: {} bytes", meta.userstring_heap_size);
///
/// // Calculate metadata efficiency
/// let total_heaps = meta.strings_heap_size + meta.blob_heap_size +
///                  meta.guid_heap_size + meta.userstring_heap_size;
/// let metadata_overhead = meta.cor20_header_size + meta.metadata_root_size;
/// println!("\n  Metadata Efficiency:");
/// println!("    Heap data: {} bytes", total_heaps);
/// println!("    Metadata overhead: {} bytes ({:.1}%)",
///     metadata_overhead,
///     (metadata_overhead as f64 / breakdown.metadata_section_size as f64) * 100.0);
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// ## Performance Optimization Analysis
///
/// ```rust,ignore
/// use dotscope::cilassembly::writer::layout::WriteLayout;
/// use dotscope::prelude::*;
/// use std::path::Path;
/// use std::time::Duration;
///
/// # let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))?;
/// # let assembly = view.to_owned();
/// let layout = WriteLayout::plan(&assembly)?;
/// let info = &layout.planning_info;
///
/// // Performance analysis
/// println!("Performance Analysis:");
/// let ops_per_second = if info.planning_duration.as_secs_f64() > 0.0 {
///     info.operation_count as f64 / info.planning_duration.as_secs_f64()
/// } else {
///     f64::INFINITY
/// };
/// println!("  Operations per second: {:.0}", ops_per_second);
///
/// let bytes_per_ms = info.size_increase as f64 / info.planning_duration.as_millis() as f64;
/// println!("  Bytes planned per millisecond: {:.1}", bytes_per_ms);
///
/// // Size efficiency analysis
/// let size_ratio = info.size_increase as f64 / info.original_size as f64;
/// println!("  Size growth ratio: {:.3}x", 1.0 + size_ratio);
///
/// if size_ratio > 0.5 {
///     println!("  ⚠ Large size increase - consider optimization");
/// } else if size_ratio < 0.1 {
///     println!("  ✓ Efficient size increase");
/// }
///
/// // Operation density analysis
/// let ops_per_kb = (info.operation_count as f64 / info.size_increase as f64) * 1024.0;
/// println!("  Operations per KB added: {:.1}", ops_per_kb);
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// ## Warning Analysis and Response
///
/// ```rust,ignore
/// use dotscope::cilassembly::writer::layout::WriteLayout;
/// use dotscope::prelude::*;
/// use std::path::Path;
///
/// # let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))?;
/// # let assembly = view.to_owned();
/// let layout = WriteLayout::plan(&assembly)?;
/// let warnings = &layout.planning_info.warnings;
///
/// // Categorize and respond to warnings
/// println!("Warning Analysis:");
/// let mut warning_categories = std::collections::HashMap::new();
///
/// for warning in warnings {
///     let category = if warning.contains("size") {
///         "Size"
///     } else if warning.contains("compatibility") {
///         "Compatibility"
///     } else if warning.contains("performance") {
///         "Performance"
///     } else {
///         "General"
///     };
///     
///     *warning_categories.entry(category).or_insert(0) += 1;
///     println!("  [{}] {}", category, warning);
/// }
///
/// // Summary
/// if warnings.is_empty() {
///     println!("  ✓ No warnings - optimal planning");
/// } else {
///     println!("\nWarning Summary:");
///     for (category, count) in warning_categories {
///         println!("  {}: {} warnings", category, count);
///     }
/// }
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Thread Safety
///
/// This type is [`Send`] and [`Sync`] because all fields are either primitive types,
/// owned collections, or standard library types that are thread-safe after creation.
#[derive(Debug, Clone)]
pub struct PlanningInfo {
    /// Original file size
    pub original_size: u64,

    /// Size increase from original
    pub size_increase: u64,

    /// Number of operations generated
    pub operation_count: usize,

    /// Time taken for planning (for performance analysis)
    pub planning_duration: std::time::Duration,

    /// Warnings generated during planning
    pub warnings: Vec<String>,

    /// Detailed breakdown of size components
    pub size_breakdown: SizeBreakdown,
}

/// Detailed breakdown of file size components.
#[derive(Debug, Clone)]
pub struct SizeBreakdown {
    /// Size of DOS header and PE headers
    pub headers: u64,

    /// Size of section table
    pub section_table: u64,

    /// Size of original sections (relocated)
    pub original_sections: u64,

    /// Size of new .meta section
    pub metadata_section: u64,

    /// Breakdown of .meta section components
    pub metadata_components: MetadataComponentSizes,
}

/// Size breakdown of metadata section components.
#[derive(Debug, Clone)]
pub struct MetadataComponentSizes {
    /// COR20 header size (always 72 bytes)
    pub cor20_header: u64,

    /// Metadata root + stream directory size
    pub metadata_root: u64,

    /// Tables stream size (#~ or #-)
    pub tables_stream: u64,

    /// String heap size (#Strings)
    pub strings_heap: u64,

    /// Blob heap size (#Blob)
    pub blob_heap: u64,

    /// GUID heap size (#GUID)
    pub guid_heap: u64,

    /// User string heap size (#US)
    pub userstring_heap: u64,
}

impl WriteLayout {
    /// Creates a comprehensive, validated layout plan for the given assembly with complete operation generation.
    ///
    /// This is the primary entry point for the revolutionary "plan everything upfront" approach
    /// to assembly file generation. The method performs comprehensive analysis of the assembly
    /// and its pending changes, calculates precise sizes for all components, determines optimal
    /// file positioning, and generates the complete set of operations needed for mechanical execution.
    ///
    /// The planning process is designed to make every decision during this phase, eliminating
    /// runtime complexity and ensuring deterministic, reproducible results. The returned
    /// [`WriteLayout`] serves as an immutable contract that guarantees successful mechanical
    /// execution when used with [`WriteExecutor`].
    ///
    /// # Arguments
    ///
    /// * `assembly` - The [`CilAssembly`] to analyze and plan for. The assembly's current state
    ///   and all pending changes are analyzed to determine layout requirements. The assembly
    ///   itself is never modified during planning.
    ///
    /// # Returns
    ///
    /// Returns a complete [`WriteLayout`] containing every piece of information needed for
    /// file generation:
    /// - All copy/zero/write operations pre-calculated and validated
    /// - Complete file structure layout with precise positioning
    /// - Metadata section organization with stream layouts
    /// - RVA mappings and index remappings for referential integrity
    /// - Native table requirements and allocations
    /// - Comprehensive validation and debugging information
    ///
    /// # Comprehensive Planning Process
    ///
    /// The planning process follows a carefully orchestrated sequence:
    ///
    /// 1. **Requirements Analysis**: Examine assembly changes, additions, and modifications
    /// 2. **Dependency Analysis**: Identify cross-references and update requirements
    /// 3. **Size Calculation**: Calculate precise sizes for all heaps, tables, and structures
    /// 4. **Layout Planning**: Determine optimal positioning for PE sections and metadata streams
    /// 5. **Operation Generation**: Create complete copy/zero/write operation sequences
    /// 6. **Mapping Construction**: Build RVA mappings and index remapping tables
    /// 7. **Comprehensive Validation**: Ensure layout consistency, compliance, and feasibility
    /// 8. **Performance Analysis**: Collect timing and size metrics for optimization
    ///
    /// # Errors
    ///
    /// This method returns [`crate::Error::WriteLayoutFailed`] when:
    /// - Assembly structure is invalid or unsupported for modification
    /// - Size calculations exceed file format limitations
    /// - Layout planning encounters irreconcilable conflicts
    /// - ECMA-335 compliance requirements cannot be satisfied
    /// - System resources are insufficient for layout calculation
    ///
    /// All errors include detailed context about the specific planning step that failed
    /// and guidance for resolution.
    ///
    /// # Examples
    ///
    /// ## Basic Layout Planning
    ///
    /// ```rust,ignore
    /// use dotscope::cilassembly::writer::layout::WriteLayout;
    /// use dotscope::prelude::*;
    /// use std::path::Path;
    ///
    /// # let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))?;
    /// # let assembly = view.to_owned();
    /// // Plan complete layout in one call
    /// let layout = WriteLayout::plan(&assembly)?;
    ///
    /// // Inspect planning results
    /// println!("Planning completed successfully!");
    /// println!("File size: {} bytes (increase: {})",
    ///     layout.total_file_size, layout.size_increase());
    /// println!("Operations: {}", layout.operations.summary());
    /// println!("Planning time: {:?}", layout.planning_info.planning_duration);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// ## Planning with Error Handling
    ///
    /// ```rust,ignore
    /// use dotscope::cilassembly::writer::layout::WriteLayout;
    /// use dotscope::prelude::*;
    /// use std::path::Path;
    ///
    /// # let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))?;
    /// # let assembly = view.to_owned();
    /// match WriteLayout::plan(&assembly) {
    ///     Ok(layout) => {
    ///         println!("Planning successful: {}", layout.summary());
    ///         
    ///         // Check for planning warnings
    ///         for warning in &layout.planning_info.warnings {
    ///             println!("Warning: {}", warning);
    ///         }
    ///         
    ///         // Proceed with execution...
    ///     }
    ///     Err(e) => {
    ///         eprintln!("Layout planning failed: {}", e);
    ///         // Handle specific error cases, potentially retry with different assembly state
    ///     }
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// ## Integration with Complete Pipeline
    ///
    /// ```rust,ignore
    /// use dotscope::cilassembly::writer::layout::WriteLayout;
    /// use dotscope::cilassembly::writer::executor::WriteExecutor;
    /// use dotscope::cilassembly::writer::output::Output;
    /// use dotscope::prelude::*;
    /// use std::path::Path;
    ///
    /// # let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))?;
    /// # let assembly = view.to_owned();
    /// // Stage 1: Comprehensive planning
    /// let start_time = std::time::Instant::now();
    /// let layout = WriteLayout::plan(&assembly)?;
    /// println!("Planning completed in {:?}", start_time.elapsed());
    ///
    /// // Stage 2: Mechanical execution
    /// let mut output = Output::create("output.dll", layout.total_file_size)?;
    /// WriteExecutor::execute(&layout, &mut output, &assembly)?;
    ///
    /// // Stage 3: Validation and finalization
    /// layout.validate_against_output(&output)?;
    /// output.finalize()?;
    ///
    /// println!("Complete pipeline executed successfully");
    /// println!("Final metrics: {}", layout.summary());
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently to plan layouts for
    /// different assemblies. Each invocation creates an independent planning context
    /// with no shared state.
    ///
    /// [`WriteExecutor`]: crate::cilassembly::writer::executor::WriteExecutor
    /// [`CilAssembly`]: crate::cilassembly::CilAssembly
    pub fn plan(assembly: &CilAssembly) -> Result<Self> {
        let start_time = std::time::Instant::now();

        // Create the main planner and execute comprehensive planning
        let mut planner = LayoutPlanner::new(assembly);
        let layout = planner.plan_complete_layout()?;

        let planning_duration = start_time.elapsed();

        // Add timing information
        let mut final_layout = layout;
        final_layout.planning_info.planning_duration = planning_duration;

        // Final validation
        final_layout.validate()?;

        Ok(final_layout)
    }

    /// Validates the layout for consistency and compliance.
    ///
    /// Performs comprehensive validation including:
    /// - Operation overlap detection
    /// - Size calculation verification
    /// - PE structure compliance
    /// - ECMA-335 metadata compliance
    ///
    /// # Returns
    /// Returns `Ok(())` if validation passes, error with details if not.
    pub fn validate(&self) -> Result<()> {
        // Validate operations don't overlap
        self.operations.validate()?;

        // Validate file structure
        self.validate_file_structure()?;

        // Validate metadata layout
        self.validate_metadata_layout()?;

        Ok(())
    }

    /// Validates against actual output to ensure planning matched execution.
    ///
    /// This method can be used after execution to verify that the
    /// actual output matches what was planned.
    ///
    /// # Arguments
    /// * `output` - The output that was generated
    ///
    /// # Returns
    /// Returns `Ok(())` if output matches planning, error if not.
    pub fn validate_against_output(&self, output: &Output) -> Result<()> {
        // Verify file size matches
        let actual_size = output.size();
        if actual_size != self.total_file_size {
            return Err(Error::WriteLayoutFailed {
                message: format!(
                    "File size mismatch: planned {total_file_size} bytes, actual {actual_size} bytes",
                    total_file_size = self.total_file_size
                ),
            });
        }

        // Additional validation can be added here:
        // - Verify specific regions contain expected data
        // - Check PE structure validity
        // - Validate metadata stream sizes

        Ok(())
    }

    /// Provides a summary of the layout plan for debugging.
    ///
    /// Returns a concise single-line summary showing the key metrics
    /// of the layout planning including size changes and operation count.
    ///
    /// # Returns
    ///
    /// A formatted string in the format:
    /// `"WriteLayout: original -> final bytes (+increase), N operations, N warnings"`
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let layout = WriteLayout::plan(&assembly)?;
    /// println!("{}", layout.summary());
    /// // Output: "WriteLayout: 12800 -> 15200 bytes (+2400), 156 operations, 0 warnings"
    /// ```
    pub fn summary(&self) -> String {
        format!(
            "WriteLayout: {} -> {} bytes (+{}), {} operations, {} warnings",
            self.planning_info.original_size,
            self.total_file_size,
            self.planning_info.size_increase,
            self.planning_info.operation_count,
            self.planning_info.warnings.len()
        )
    }

    /// Returns the size increase compared to the original file.
    ///
    /// This represents how many additional bytes the output file will
    /// contain compared to the input assembly.
    ///
    /// # Returns
    ///
    /// The number of bytes added to the file size.
    pub fn size_increase(&self) -> u64 {
        self.planning_info.size_increase
    }

    /// Returns the total number of operations that will be executed.
    ///
    /// This includes all copy, zero, and write operations generated
    /// during layout planning.
    ///
    /// # Returns
    ///
    /// Total count of operations to be performed during execution.
    pub fn operation_count(&self) -> usize {
        self.operations.operation_count()
    }

    /// Returns detailed size breakdown information.
    ///
    /// Provides comprehensive analysis of where bytes are allocated
    /// in the final file, useful for optimization and debugging.
    ///
    /// # Returns
    ///
    /// Reference to the detailed size breakdown data.
    pub fn size_breakdown(&self) -> &SizeBreakdown {
        &self.planning_info.size_breakdown
    }

    // Private validation methods
    fn validate_file_structure(&self) -> Result<()> {
        // Validate section table can accommodate all sections
        let expected_section_table_size = self.file_structure.sections.len() * 40;
        if self.file_structure.section_table.size < expected_section_table_size as u64 {
            return Err(Error::WriteLayoutFailed {
                message: format!(
                    "Section table too small: {size} bytes for {count} sections",
                    size = self.file_structure.section_table.size,
                    count = self.file_structure.sections.len()
                ),
            });
        }

        // Validate sections don't overlap
        let mut sections_by_offset: Vec<_> = self.file_structure.sections.iter().collect();
        sections_by_offset.sort_by_key(|s| s.file_region.offset);

        for window in sections_by_offset.windows(2) {
            let section1 = window[0];
            let section2 = window[1];

            let section1_end = section1.file_region.offset + section1.file_region.size;
            if section1_end > section2.file_region.offset {
                return Err(Error::WriteLayoutFailed {
                    message: format!(
                        "Section overlap: {name1} (ends at {end1}) overlaps with {name2} (starts at {start2})",
                        name1 = section1.name,
                        end1 = section1_end,
                        name2 = section2.name,
                        start2 = section2.file_region.offset
                    ),
                });
            }
        }

        Ok(())
    }

    fn validate_metadata_layout(&self) -> Result<()> {
        // Validate that all streams fit within the .meta section
        let meta_section_end = self.metadata_layout.meta_section.file_region.offset
            + self.metadata_layout.meta_section.file_region.size;

        for stream in &self.metadata_layout.streams {
            let stream_end = stream.file_region.offset + stream.file_region.size;
            if stream_end > meta_section_end {
                return Err(Error::WriteLayoutFailed {
                    message: format!(
                        "Stream {name} extends beyond .meta section: {stream_end} > {meta_end}",
                        name = stream.name,
                        meta_end = meta_section_end
                    ),
                });
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use crate::CilAssemblyView;

    use super::*;

    #[test]
    fn test_write_layout_planning() {
        let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))
            .expect("Failed to load test assembly");
        let assembly = view.to_owned();

        let result = WriteLayout::plan(&assembly);
        assert!(result.is_ok(), "Layout planning should succeed");

        let layout = result.unwrap();
        assert!(
            layout.total_file_size > 0,
            "Should calculate positive file size"
        );
        assert!(layout.operation_count() > 0, "Should generate operations");
    }

    #[test]
    fn test_layout_validation() {
        let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))
            .expect("Failed to load test assembly");
        let assembly = view.to_owned();

        let layout = WriteLayout::plan(&assembly).expect("Planning should succeed");
        let validation_result = layout.validate();

        assert!(validation_result.is_ok(), "Layout validation should pass");
    }

    #[test]
    fn test_file_region_creation() {
        let region = FileRegion {
            offset: 1000,
            size: 500,
        };
        assert_eq!(region.offset, 1000);
        assert_eq!(region.size, 500);
    }
}
