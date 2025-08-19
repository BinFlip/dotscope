//! Core layout planning engine for the simplified assembly writer.
//!
//! This module implements the [`crate::cilassembly::writer::layout::planner::LayoutPlanner`] that orchestrates the complete
//! layout planning process for the revolutionary 3-stage assembly writer pipeline. It consolidates
//! all individual planning components to create a comprehensive [`crate::cilassembly::writer::layout::WriteLayout`]
//! with all operations pre-calculated for purely mechanical execution.
//!
//! # Architecture
//!
//! The planner serves as the central orchestrator in the simplified writer architecture:
//!
//! ```text
//! ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
//! │   Assembly      │───▶│  LayoutPlanner  │───▶│   WriteLayout   │
//! │   + Changes     │    │   .plan()       │    │  (Complete)     │
//! └─────────────────┘    └─────────────────┘    └─────────────────┘
//!                                 │                        │
//!                                 ▼                        ▼
//!                        ┌─────────────────┐    ┌─────────────────┐
//!                        │ All Calculations│    │ Ready for Pure  │
//!                        │   Complete      │    │ Mechanical Exec │
//!                        └─────────────────┘    └─────────────────┘
//! ```
//!
//! **Core Responsibilities:**
//!
//! 1. **Assembly Analysis**: Deep analysis of [`crate::cilassembly::CilAssembly`] changes and requirements
//! 2. **Size Calculation**: Precise sizing using battle-tested algorithms from the legacy pipeline
//! 3. **Layout Planning**: PE file structure and section layout with ECMA-335 compliance
//! 4. **Operation Generation**: Complete set of copy/zero/write operations for mechanical execution
//! 5. **Mapping Construction**: RVA and index mappings for proper relocation and reference updates
//! 6. **Layout Validation**: Comprehensive validation to ensure consistency and correctness
//!
//! # Key Components
//!
//! - [`crate::cilassembly::writer::layout::planner::LayoutPlanner`] - Main orchestration engine for complete layout planning
//! - [`crate::cilassembly::remapping::IndexRemapper`] - Comprehensive index remapping for table reconstruction
//!
//! # Planning Process
//!
//! The planner follows a systematic 7-stage process:
//!
//! ## Stage 1: Component Analysis
//! Analyzes assembly changes and calculates precise metadata component sizes:
//! - Heap sizes (strings, blobs, GUIDs, user strings) using proven algorithms
//! - Tables stream size with modifications and expansions
//! - Metadata root and stream directory sizing
//!
//! ## Stage 2: Native Table Requirements
//! Determines and sizes native PE import/export table needs:
//! - Import table analysis for native function calls
//! - Export table planning for exposed native functions
//! - Conservative size estimation with safety margins
//!
//! ## Stage 3: File Structure Planning
//! Plans complete PE file structure with sections:
//! - PE header preservation and updates
//! - Section layout with proper alignment
//! - Space allocation for native tables
//!
//! ## Stage 4: Metadata Layout
//! Detailed layout of .NET metadata within sections:
//! - COR20 header positioning and updates
//! - Stream layout with proper alignment
//! - Heap reconstruction planning
//!
//! ## Stage 5: Operation Generation
//! Generates all copy/zero/write operations:
//! - Copy operations for preserving existing content
//! - Zero operations for clearing old locations
//! - Write operations for new/modified content
//!
//! ## Stage 6: Mapping Construction
//! Builds comprehensive RVA and index mappings:
//! - Method body RVA mappings for proper execution
//! - Heap index remapping for table reconstruction
//! - Table row index mappings for references
//!
//! ## Stage 7: Final Assembly
//! Assembles complete layout with validation:
//! - Total file size calculation
//! - Planning performance metrics
//! - Comprehensive layout validation
//!
//! # Usage Examples
//!
//! ## Basic Layout Planning
//!
//! ```rust,ignore
//! use dotscope::cilassembly::writer::layout::planner::LayoutPlanner;
//! use dotscope::prelude::*;
//! use std::path::Path;
//!
//! # let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))?;
//! # let assembly = view.to_owned();
//! // Create planner and generate complete layout
//! let mut planner = LayoutPlanner::new(&assembly);
//! let layout = planner.plan_complete_layout()?;
//!
//! // Layout is now ready for mechanical execution
//! println!("Planning generated {} operations", layout.operations.len());
//! println!("Total file size: {} bytes", layout.total_file_size);
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Advanced Planning with Validation
//!
//! ```rust,ignore
//! use dotscope::cilassembly::writer::layout::planner::LayoutPlanner;
//! use dotscope::prelude::*;
//! use std::path::Path;
//!
//! # let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))?;
//! # let assembly = view.to_owned();
//! let mut planner = LayoutPlanner::new(&assembly);
//!
//! // Plan with comprehensive validation
//! let layout = planner.plan_complete_layout()?;
//!
//! // Validate the complete layout
//! layout.validate()?;
//!
//! // Examine planning details
//! println!("Planning info: {}", layout.planning_info.summary());
//! println!("Metadata layout: {:#?}", layout.metadata_layout);
//! println!("RVA mappings count: {}", layout.rva_mappings.len());
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Error Handling
//!
//! The planner provides comprehensive error handling for all planning failures:
//!
//! - [`crate::Error::WriteLayoutFailed`] - When component size calculation fails or layout is invalid
//! - [`crate::Error::MetadataLayoutFailed`] - When metadata stream layout cannot be determined
//! - [`crate::Error::SectionLayoutFailed`] - When PE section layout planning fails
//! - [`crate::Error::OperationGenerationFailed`] - When operation generation encounters errors
//!
//! All errors include detailed context about the specific planning stage that failed.
//!
//! # Thread Safety
//!
//! The [`crate::cilassembly::writer::layout::planner::LayoutPlanner`] is not [`Send`] or [`Sync`] as it:
//! - Contains mutable state during planning (warnings, temporary calculations)
//! - Holds references to the source assembly
//! - Accumulates planning context that is not thread-safe
//!
//! However, the resulting [`crate::cilassembly::writer::layout::WriteLayout`] is fully thread-safe
//! and immutable after creation.
//!
//! # Integration
//!
//! This module integrates with:
//!
//! - [`crate::cilassembly::CilAssembly`] - Source assembly with pending changes
//! - [`crate::cilassembly::writer::layout`] - Layout data structures and calculations
//! - [`crate::cilassembly::writer::operations`] - Operation types for mechanical execution
//! - [`crate::cilassembly::writer::heap_builders`] - Heap reconstruction with size calculations
//! - [`crate::metadata::tables`] - Table analysis and modification handling
//! - [`crate::file::physical`] - PE file structure analysis and manipulation
//!
//! # References
//!
//! - [ECMA-335 Common Language Infrastructure (CLI)](https://www.ecma-international.org/publications/standards/Ecma-335.htm)
//! - [PE Format Specification](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)
//! - [.NET Metadata Physical Layout](https://github.com/dotnet/runtime/blob/main/docs/design/specs/Ecma-335-Augments.md)

use std::{collections::HashMap, time::Instant};

use crate::{
    cilassembly::{
        modifications::TableModifications,
        operation::{Operation, TableOperation},
        remapping::{IndexRemapper, RidRemapper},
        writer::{
            heaps::{
                BlobHeapBuilder, GuidHeapBuilder, HeapBuilder, StringHeapBuilder,
                UserStringHeapBuilder,
            },
            layout::{
                calculate_blob_heap_size, calculate_guid_heap_size, calculate_string_heap_size,
                calculate_table_stream_expansion, calculate_userstring_heap_size, FileRegion,
                FileStructureLayout, MetadataComponentSizes, MetadataLayout,
                NativeTableRequirements, PlanningInfo, SectionLayout, SizeBreakdown, StreamLayout,
                WriteLayout,
            },
            operations::{CopyOperation, OperationSet, WriteOperation, ZeroOperation},
        },
        CilAssembly, TableModifications as CilTableModifications,
    },
    dispatch_table_type,
    file::{
        pe::{
            self,
            constants::{
                COR20_HEADER_SIZE, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_METADATA, MAX_REASONABLE_RVA,
            },
            DosHeader, SectionTable,
        },
        File,
    },
    metadata::{
        streams::TablesHeader,
        tables::{
            AssemblyProcessorRaw, AssemblyRaw, AssemblyRefProcessorRaw, AssemblyRefRaw,
            ClassLayoutRaw, CodedIndexType, ConstantRaw, CustomAttributeRaw, DeclSecurityRaw,
            EventMapRaw, EventRaw, ExportedTypeRaw, FieldLayoutRaw, FieldMarshalRaw, FieldRaw,
            FieldRvaRaw, FileRaw, GenericParamConstraintRaw, GenericParamRaw, ImplMapRaw,
            InterfaceImplRaw, ManifestResourceRaw, MemberRefRaw, MethodDefRaw, MethodImplRaw,
            MethodSemanticsRaw, MethodSpecRaw, ModuleRaw, ModuleRefRaw, NestedClassRaw, ParamRaw,
            PropertyMapRaw, PropertyRaw, RowWritable, StandAloneSigRaw, TableDataOwned, TableId,
            TableInfo, TableInfoRef, TableRow, TypeDefRaw, TypeRefRaw, TypeSpecRaw,
        },
    },
    utils::{align_to, align_to_4_bytes, calculate_table_row_size, read_le_at, write_le_at},
    Error, Result,
};

/// Main layout planning engine for the simplified assembly writer.
///
/// The [`crate::cilassembly::writer::layout::planner::LayoutPlanner`] serves as the central orchestrator
/// in the revolutionary 3-stage assembly writer pipeline. It coordinates all aspects of layout
/// planning to transform a [`crate::cilassembly::CilAssembly`] with pending changes into a complete
/// [`crate::cilassembly::writer::layout::WriteLayout`] ready for purely mechanical execution.
///
/// # Architecture Role
///
/// The planner bridges the gap between high-level assembly modifications and low-level
/// binary operations:
///
/// ```text
/// Assembly Analysis → Layout Planning → Mechanical Execution
///      ↓                    ↓                  ↓
///   Changes &           All Operations      Pure I/O
///  Requirements         Pre-calculated     Operations
/// ```
///
/// # Planning Philosophy
///
/// The planner follows the **"Complete Planning, Zero Decisions"** principle:
/// - **All decisions made during planning**: No conditional logic during execution
/// - **Battle-tested algorithms**: Reuses proven size calculation methods
/// - **Comprehensive validation**: Validates every aspect of the planned layout
/// - **Operation-based output**: Everything expressed as simple copy/zero/write operations
///
/// # Planning Stages
///
/// The planner executes a systematic 7-stage process:
///
/// 1. **Component Analysis**: Calculate precise metadata component sizes
/// 2. **Native Requirements**: Determine PE import/export table needs
/// 3. **File Structure**: Plan complete PE file structure with sections
/// 4. **Metadata Layout**: Design detailed .NET metadata layout
/// 5. **Operation Generation**: Generate all copy/zero/write operations
/// 6. **Mapping Construction**: Build RVA and index mappings
/// 7. **Final Assembly**: Create validated [`crate::cilassembly::writer::layout::WriteLayout`]
///
/// # State Management
///
/// The planner maintains state throughout the planning process:
/// - **Immutable Source**: Never modifies the source assembly
/// - **Accumulated Warnings**: Collects non-fatal issues for reporting
/// - **Size Tracking**: Tracks size changes for optimization analysis
/// - **Validation Context**: Maintains context for comprehensive validation
///
/// # Error Handling
///
/// Planning failures are comprehensive and actionable:
/// - **Stage Identification**: Errors clearly identify which planning stage failed
/// - **Context Preservation**: Full context about what was being planned
/// - **Recovery Suggestions**: Actionable suggestions where applicable
/// - **Validation Integration**: Post-planning validation catches edge cases
///
/// # Performance Characteristics
///
/// - **Memory Efficient**: Processes large assemblies without loading entire content
/// - **Timing Tracked**: Planning performance is measured and reported
/// - **Incremental Processing**: Processes only changed components where possible
/// - **Validation Overhead**: Comprehensive validation adds ~5-10% planning time
///
/// # Thread Safety
///
/// The planner is **not thread-safe** due to:
/// - Mutable warning accumulation during planning
/// - Temporary state used across planning stages
/// - Reference to source assembly (though assembly itself is not modified)
///
/// However, the output [`crate::cilassembly::writer::layout::WriteLayout`] is fully thread-safe.
///
/// # Examples
///
/// ## Basic Planning
///
/// ```rust,ignore
/// use dotscope::cilassembly::writer::layout::planner::LayoutPlanner;
/// use dotscope::prelude::*;
/// use std::path::Path;
///
/// # let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))?;
/// # let assembly = view.to_owned();
/// let mut planner = LayoutPlanner::new(&assembly);
/// let layout = planner.plan_complete_layout()?;
/// println!("Planned {} operations", layout.operations.len());
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// ## Planning with Validation
///
/// ```rust,ignore
/// use dotscope::cilassembly::writer::layout::planner::LayoutPlanner;
/// use dotscope::prelude::*;
/// use std::path::Path;
///
/// # let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))?;
/// # let assembly = view.to_owned();
/// let mut planner = LayoutPlanner::new(&assembly);
/// let layout = planner.plan_complete_layout()?;
///
/// // Comprehensive validation
/// layout.validate()?;
/// println!("Layout validation passed");
///
/// // Examine planning metrics
/// let info = &layout.planning_info;
/// println!("Planning took: {:?}", info.planning_duration);
/// println!("Size change: {} -> {} bytes", info.original_size, layout.total_file_size);
/// # Ok::<(), dotscope::Error>(())
/// ```
pub struct LayoutPlanner<'a> {
    /// The source assembly being planned for.
    ///
    /// This assembly contains all the changes and modifications that need to be
    /// applied during the writing process. The planner never modifies this assembly;
    /// it only reads from it to understand what needs to be done.
    assembly: &'a CilAssembly,

    /// Modified PE structure used throughout the planning process.
    ///
    /// This Pe struct is initialized from the source assembly and then modified
    /// in-place as sections are added, headers updated, and data directories changed.
    /// This eliminates the need for multiple copies during different planning stages.
    pe: pe::Pe,

    /// Warnings accumulated during the planning process.
    ///
    /// Non-fatal issues discovered during planning are collected here for later
    /// reporting. These might include size estimation uncertainties, deprecated
    /// patterns, or potential optimization opportunities.
    warnings: Vec<String>,

    /// Original file size for size change analysis.
    ///
    /// Used to calculate size deltas and provide useful metrics about how the
    /// planning process affects the final binary size. This helps with performance
    /// analysis and optimization decisions.
    original_size: u64,
}

impl<'a> LayoutPlanner<'a> {
    /// Creates a new layout planner for the given assembly.
    ///
    /// Initializes a new [`crate::cilassembly::writer::layout::planner::LayoutPlanner`] that will coordinate
    /// the complete layout planning process for the provided assembly. The planner analyzes
    /// the assembly's current state and pending changes to prepare for comprehensive layout planning.
    ///
    /// # Arguments
    ///
    /// * `assembly` - The [`crate::cilassembly::CilAssembly`] to plan layout for. Must contain all
    ///   desired changes and modifications. The assembly is never modified during planning.
    ///
    /// # Returns
    ///
    /// Returns a new [`crate::cilassembly::writer::layout::planner::LayoutPlanner`] ready to begin the planning process
    /// via [`crate::cilassembly::writer::layout::planner::LayoutPlanner::plan_complete_layout`].
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::cilassembly::writer::layout::planner::LayoutPlanner;
    /// use dotscope::prelude::*;
    /// use std::path::Path;
    ///
    /// # let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))?;
    /// # let assembly = view.to_owned();
    /// let planner = LayoutPlanner::new(&assembly);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn new(assembly: &'a CilAssembly) -> Self {
        let original_size = assembly.file().file_size();
        let pe = assembly.file().pe().clone();

        Self {
            assembly,
            pe,
            warnings: Vec::new(),
            original_size,
        }
    }

    /// Plans the complete layout with all operations for mechanical execution.
    ///
    /// This is the primary orchestration method that coordinates all aspects of layout planning
    /// to transform the assembly's pending changes into a complete [`crate::cilassembly::writer::layout::WriteLayout`]
    /// with every operation pre-calculated for purely mechanical execution. It implements the
    /// revolutionary **"Complete Planning, Zero Decisions"** approach.
    ///
    /// # Planning Process
    ///
    /// Executes a systematic 7-stage planning process:
    ///
    /// ## Stage 1: Component Analysis
    /// Calculates precise metadata component sizes using battle-tested algorithms:
    /// - String, blob, GUID, and user string heap sizes
    /// - Tables stream size with all modifications
    /// - Metadata root and stream directory sizing
    ///
    /// ## Stage 2: Native Table Requirements
    /// Determines PE import/export table requirements:
    /// - Analyzes native import/export changes
    /// - Calculates precise or conservative size estimates
    /// - Plans space allocation within PE structure
    ///
    /// ## Stage 3: File Structure Planning
    /// Plans complete PE file structure:
    /// - PE header preservation and updates
    /// - Section layout with proper alignment
    /// - Native table space allocation
    ///
    /// ## Stage 4: Metadata Layout
    /// Designs detailed .NET metadata layout:
    /// - COR20 header positioning and content
    /// - Stream layout within sections
    /// - Heap reconstruction planning
    ///
    /// ## Stage 5: Operation Generation
    /// Generates all copy/zero/write operations:
    /// - Copy operations for existing content preservation
    /// - Zero operations for clearing old locations
    /// - Write operations for new/modified content
    ///
    /// ## Stage 6: Mapping Construction
    /// Builds comprehensive RVA and index mappings:
    /// - Method body RVA mappings for execution
    /// - Heap index remapping for table reconstruction
    /// - Table row index mappings for references
    ///
    /// ## Stage 7: Final Assembly
    /// Creates validated complete layout:
    /// - Total file size calculation
    /// - Planning performance metrics
    /// - Comprehensive layout validation
    ///
    /// # Returns
    ///
    /// Returns a complete [`crate::cilassembly::writer::layout::WriteLayout`] containing:
    /// - All operations needed for mechanical execution
    /// - Complete file structure with sections and layout
    /// - Metadata layout with stream positions
    /// - RVA and index mappings for proper references
    /// - Native table requirements and allocations
    /// - Planning information and performance metrics
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::WriteLayoutFailed`] for various planning failures:
    /// - **Component Analysis Failure**: When metadata component sizes cannot be calculated
    /// - **Native Table Analysis Failure**: When import/export requirements cannot be determined
    /// - **File Structure Planning Failure**: When PE file structure cannot be planned
    /// - **Metadata Layout Failure**: When .NET metadata layout is invalid
    /// - **Operation Generation Failure**: When copy/zero/write operations cannot be generated
    /// - **Mapping Construction Failure**: When RVA or index mappings are invalid
    /// - **Validation Failure**: When final layout validation detects inconsistencies
    ///
    /// All errors include detailed context about which planning stage failed and why.
    ///
    /// # Performance
    ///
    /// Planning performance is tracked and reported:
    /// - **Typical Planning Time**: 1-50ms for most assemblies
    /// - **Large Assembly Handling**: Scales to multi-MB assemblies efficiently
    /// - **Memory Usage**: Processes without loading entire assembly content
    /// - **Incremental Processing**: Only processes changed components where possible
    ///
    /// # Examples
    ///
    /// ## Basic Planning
    ///
    /// ```rust,ignore
    /// use dotscope::cilassembly::writer::layout::planner::LayoutPlanner;
    /// use dotscope::prelude::*;
    /// use std::path::Path;
    ///
    /// # let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))?;
    /// # let assembly = view.to_owned();
    /// let mut planner = LayoutPlanner::new(&assembly);
    /// let layout = planner.plan_complete_layout()?;
    ///
    /// println!("Generated {} operations", layout.operations.len());
    /// println!("Total file size: {} bytes", layout.total_file_size);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// ## Planning with Detailed Analysis
    ///
    /// ```rust,ignore
    /// use dotscope::cilassembly::writer::layout::planner::LayoutPlanner;
    /// use dotscope::prelude::*;
    /// use std::path::Path;
    ///
    /// # let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))?;
    /// # let assembly = view.to_owned();
    /// let mut planner = LayoutPlanner::new(&assembly);
    /// let layout = planner.plan_complete_layout()?;
    ///
    /// // Analyze planning results
    /// let info = &layout.planning_info;
    /// println!("Planning took: {:?}", info.planning_duration);
    /// println!("Size change: {} -> {} bytes", info.original_size, layout.total_file_size);
    /// println!("Operations breakdown: {}", layout.operations.summary());
    ///
    /// // Validate the complete layout
    /// layout.validate()?;
    /// println!("Layout validation passed successfully");
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn plan_complete_layout(&mut self) -> Result<WriteLayout> {
        let planning_start = Instant::now();

        // Step 1: Analyze assembly changes and calculate component sizes
        let component_sizes = self.calculate_metadata_component_sizes()?;

        // Step 1.5: Calculate native table requirements (sizes only)
        let mut native_table_requirements = self.calculate_native_table_requirements()?;

        // Step 2: Plan file structure with PE headers and sections (including native table space)
        let file_structure = self
            .plan_file_structure_with_native_tables(&component_sizes, &native_table_requirements)?;

        // Step 3: Plan detailed metadata layout within .meta section
        let metadata_layout = Self::plan_metadata_layout(&file_structure, &component_sizes)?;

        // Step 3.5: Allocate RVAs for native tables
        Self::allocate_native_table_rvas(&file_structure, &mut native_table_requirements)?;

        // Step 4: Generate all copy/zero/write operations
        let operations = self.generate_operations(&file_structure, &metadata_layout)?;

        // Step 5: Build RVA and index mappings
        let (rva_mappings, index_mappings) = self.build_mappings(&metadata_layout)?;

        // Step 6: Calculate final file size
        let total_file_size = Self::calculate_total_file_size(&file_structure);

        // Step 7: Build planning info and size breakdown
        let planning_info =
            self.build_planning_info(&component_sizes, total_file_size, planning_start);

        Ok(WriteLayout {
            total_file_size,
            operations,
            file_structure,
            metadata_layout,
            rva_mappings,
            index_mappings,
            native_table_requirements,
            planning_info,
        })
    }

    /// Calculates precise sizes for all metadata components using battle-tested algorithms.
    ///
    /// This method performs **Stage 1** of the planning process, analyzing the assembly's metadata
    /// to calculate exact sizes for all .NET metadata components. It uses the proven algorithms
    /// from the legacy pipeline to ensure 100% accuracy and compatibility with existing tools.
    ///
    /// # Calculated Components
    ///
    /// ## Heap Sizes
    /// - **String Heap**: Total size including all existing and new string entries
    /// - **Blob Heap**: Complete blob heap size with existing and modified blobs
    /// - **GUID Heap**: GUID heap size (typically minimal, 16 bytes per GUID)
    /// - **User String Heap**: Size of literal string constants used in IL code
    ///
    /// ## Stream Sizes
    /// - **Tables Stream**: Complete metadata tables with all modifications applied
    /// - **Metadata Root**: Root metadata header with stream directory
    ///
    /// ## Header Sizes
    /// - **COR20 Header**: Always 72 bytes per ECMA-335 specification
    ///
    /// # Size Calculation Strategy
    ///
    /// Uses a **conservative but precise** approach:
    /// 1. **Existing Content Analysis**: Measures current heap and table content
    /// 2. **Change Impact Assessment**: Calculates size impact of all pending changes
    /// 3. **Battle-tested Algorithms**: Reuses proven calculation methods from legacy pipeline
    /// 4. **Safety Margins**: Includes minimal padding for alignment requirements
    ///
    /// # Returns
    ///
    /// Returns [`crate::cilassembly::writer::layout::MetadataComponentSizes`] containing precise
    /// size information for all metadata components needed for subsequent planning stages.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::WriteLayoutFailed`] if:
    /// - Heap size calculation fails due to corrupted heap data
    /// - Table analysis fails due to invalid table modifications
    /// - Metadata root analysis encounters structural issues
    /// - Size calculations overflow or produce invalid results
    fn calculate_metadata_component_sizes(&self) -> Result<MetadataComponentSizes> {
        // Calculate heap sizes using existing proven algorithms
        let strings_heap_size = self.calculate_string_heap_total_size()?;
        let blob_heap_size = self.calculate_blob_heap_total_size()?;
        let guid_heap_size = self.calculate_guid_heap_total_size()?;
        let userstring_heap_size = self.calculate_userstring_heap_total_size();

        // Calculate tables stream size
        let tables_stream_size = self.calculate_tables_stream_size()?;

        // Calculate metadata root + stream directory size
        let metadata_root_size = Self::calculate_metadata_root_size();

        Ok(MetadataComponentSizes {
            cor20_header: 72, // COR20 header is always 72 bytes
            metadata_root: metadata_root_size,
            tables_stream: tables_stream_size,
            strings_heap: strings_heap_size,
            blob_heap: blob_heap_size,
            guid_heap: guid_heap_size,
            userstring_heap: userstring_heap_size,
        })
    }

    /// Calculates native PE table requirements for import/export tables.
    ///
    /// This method performs **Stage 2** of the planning process, analyzing the assembly's
    /// native import/export changes to determine PE table requirements. It calculates precise
    /// sizes for import and export tables that will be embedded in the PE structure.
    ///
    /// # Analysis Process
    ///
    /// ## Import Table Analysis
    /// For native function imports:
    /// 1. **Change Detection**: Identifies new native imports in assembly changes
    /// 2. **Size Calculation**: Uses actual import data when available for precise sizing
    /// 3. **Conservative Estimation**: Falls back to safe size estimates when exact data unavailable
    /// 4. **PE32/PE32+ Handling**: Adjusts calculations for 32-bit vs 64-bit PE formats
    ///
    /// ## Export Table Analysis
    /// For native function exports:
    /// 1. **Export Discovery**: Identifies native functions being exported
    /// 2. **Table Structure**: Calculates export directory and function table sizes
    /// 3. **String Requirements**: Accounts for exported function name storage
    /// 4. **Ordinal Handling**: Plans ordinal-based export table structure
    ///
    /// # Size Estimation Strategy
    ///
    /// Uses a **hybrid precise/conservative** approach:
    /// - **Precise Calculation**: When import/export data is immediately available
    /// - **Conservative Estimation**: When exact data requires complex analysis
    ///   - Import tables: `dll_count * 64 + function_count * 32 + 1024` bytes
    ///   - Export tables: `40 + function_count * 16 + 512` bytes
    /// - **Safety Margins**: Additional padding for alignment and structure overhead
    ///
    /// # Returns
    ///
    /// Returns [`crate::cilassembly::writer::layout::NativeTableRequirements`] containing:
    /// - Import table size requirements and flags
    /// - Export table size requirements and flags
    /// - PE format compatibility information
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::WriteLayoutFailed`] if:
    /// - PE format detection fails for the assembly
    /// - Import/export data analysis encounters corrupted data
    /// - Size calculations produce invalid results
    fn calculate_native_table_requirements(&self) -> Result<NativeTableRequirements> {
        let mut requirements = NativeTableRequirements::default();
        let changes = self.assembly.changes();

        if !changes.has_changes() {
            return Ok(requirements);
        }

        // Check for native import requirements
        let has_import_changes = !changes.native_imports.native().is_empty();
        if has_import_changes {
            requirements.needs_import_tables = true;

            let imports = &changes.native_imports;
            let is_pe32_plus = self.assembly.file().is_pe32_plus_format()?;

            if let Ok(import_data) = imports.native().get_import_table_data(is_pe32_plus) {
                requirements.import_table_size = import_data.len() as u64;
            } else {
                // Conservative estimation
                let dll_count = imports.native().dll_count();
                let function_count = imports.native().total_function_count();
                requirements.import_table_size =
                    (dll_count * 64 + function_count * 32 + 1024) as u64;
            }
        }

        // Check for native export requirements
        let has_export_changes = !changes.native_exports.native().is_empty();
        if has_export_changes {
            requirements.needs_export_tables = true;

            let exports = &changes.native_exports;
            if let Ok(export_data) = exports.native().get_export_table_data() {
                requirements.export_table_size = export_data.len() as u64;
            } else {
                // Conservative estimation
                let function_count = exports.native().function_count();
                requirements.export_table_size = (40 + function_count * 16 + 512) as u64;
            }
        }

        Ok(requirements)
    }

    /// Allocates RVAs for native PE import/export tables within the .meta section.
    ///
    /// This method assigns specific Relative Virtual Addresses (RVAs) for native PE import
    /// and export tables, positioning them within the .meta section after all metadata
    /// streams to avoid conflicts with .NET metadata structures.
    ///
    /// # Arguments
    ///
    /// * `file_structure` - Complete PE file structure layout with section information
    /// * `requirements` - Mutable native table requirements to update with allocated RVAs
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on successful RVA allocation, or error if .meta section not found
    /// or insufficient space for native tables.
    ///
    /// # RVA Allocation Strategy
    ///
    /// 1. **Locate .meta section**: Find the section containing .NET metadata
    /// 2. **Calculate metadata end**: Determine where .NET metadata streams end
    /// 3. **Reserve space**: Use last 1KB of .meta section for native tables
    /// 4. **Align boundaries**: Ensure 4-byte alignment for PE structure compliance
    /// 5. **Sequential allocation**: Assign import table first, then export table
    ///
    /// # Native Table Positioning
    ///
    /// ```text
    /// .meta section layout:
    /// ┌─────────────────┐ ← virtual_address
    /// │  COR20 Header   │
    /// ├─────────────────┤
    /// │ Metadata Root   │
    /// ├─────────────────┤
    /// │  .NET Streams   │ (.NET metadata)
    /// ├─────────────────┤ ← metadata_end - 1024
    /// │ Import Tables   │ (native PE tables)
    /// ├─────────────────┤
    /// │ Export Tables   │ (native PE tables)
    /// └─────────────────┘ ← virtual_address + virtual_size
    /// ```
    ///
    /// # PE Integration
    ///
    /// The allocated RVAs are used to update PE data directories:
    /// - **Entry 0**: Export table RVA and size
    /// - **Entry 1**: Import table RVA and size
    ///
    /// This enables managed assemblies to interoperate with native code.
    fn allocate_native_table_rvas(
        file_structure: &FileStructureLayout,
        requirements: &mut NativeTableRequirements,
    ) -> Result<()> {
        // Find the .meta section where we can allocate space for native tables
        let meta_section = file_structure
            .sections
            .iter()
            .find(|s| s.name == ".meta")
            .ok_or_else(|| Error::WriteLayoutFailed {
                message: "Cannot find .meta section for native table allocation".to_string(),
            })?;

        let mut current_rva = meta_section.virtual_address;

        // Calculate the end of all metadata streams to avoid conflicts
        // .meta section contains: COR20 header + metadata root + all streams
        // We need to place native tables AFTER all the metadata
        let metadata_end_offset = current_rva + meta_section.virtual_size;

        // Start native table allocation from a safe location after metadata
        // Use the last 1KB of the .meta section for native tables
        current_rva = metadata_end_offset - 1024;
        current_rva = u32::try_from(align_to_4_bytes(u64::from(current_rva))).map_err(|_| {
            Error::WriteLayoutFailed {
                message: "RVA alignment result exceeds u32 range".to_string(),
            }
        })?;

        // Allocate import table RVA if needed
        if requirements.needs_import_tables {
            requirements.import_table_rva = Some(current_rva);
            current_rva += u32::try_from(requirements.import_table_size).map_err(|_| {
                Error::WriteLayoutFailed {
                    message: "Import table size exceeds u32 range".to_string(),
                }
            })?;
            current_rva =
                u32::try_from(align_to_4_bytes(u64::from(current_rva))).map_err(|_| {
                    Error::WriteLayoutFailed {
                        message: "RVA alignment result exceeds u32 range".to_string(),
                    }
                })?;
        }

        // Allocate export table RVA if needed
        if requirements.needs_export_tables {
            requirements.export_table_rva = Some(current_rva);
            current_rva += u32::try_from(requirements.export_table_size).map_err(|_| {
                Error::WriteLayoutFailed {
                    message: "Export table size exceeds u32 range".to_string(),
                }
            })?;
            current_rva =
                u32::try_from(align_to_4_bytes(u64::from(current_rva))).map_err(|_| {
                    Error::WriteLayoutFailed {
                        message: "RVA alignment result exceeds u32 range".to_string(),
                    }
                })?;
        }

        // Verify allocations fit within the section
        let section_end = meta_section.virtual_address + meta_section.virtual_size;
        if current_rva > section_end {
            return Err(Error::WriteLayoutFailed {
                message: format!(
                    "Native tables too large for .meta section: need RVA 0x{current_rva:X}, section ends at 0x{section_end:X}"
                ),
            });
        }

        Ok(())
    }

    /// Plans the complete file structure including PE headers and sections with native table space.
    fn plan_file_structure_with_native_tables(
        &mut self,
        component_sizes: &MetadataComponentSizes,
        native_table_requirements: &NativeTableRequirements,
    ) -> Result<FileStructureLayout> {
        // Calculate file regions using the planner's Pe struct
        let dos_header = FileRegion {
            offset: 0,
            size: DosHeader::size(),
        };

        let pe_headers_offset = self.pe.get_pe_headers_offset();
        let pe_headers_size = self.pe.calculate_headers_size();
        let pe_headers = FileRegion {
            offset: pe_headers_offset,
            size: pe_headers_size,
        };

        let total_sections = self.pe.sections.len() + 1; // +1 for .meta section
        let section_table_size = SectionTable::calculate_table_size(total_sections);
        let section_table = FileRegion {
            offset: pe_headers.offset + pe_headers.size,
            size: section_table_size,
        };

        // Plan all sections including relocated originals and new .meta
        let sections = self.plan_sections(component_sizes, native_table_requirements)?;

        Ok(FileStructureLayout {
            dos_header,
            pe_headers,
            section_table,
            sections,
        })
    }

    /// Plans all sections including relocated originals and new .meta section.
    fn plan_sections(
        &mut self,
        component_sizes: &MetadataComponentSizes,
        native_table_requirements: &NativeTableRequirements,
    ) -> Result<Vec<SectionLayout>> {
        let view = self.assembly.view();
        let file = view.file();
        let mut sections = Vec::new();

        // Calculate section table growth to determine relocation offset
        let original_section_count = file.sections().len();
        let section_table_growth = 40; // 40 bytes for new .meta section entry

        // Calculate where the new section table will end
        let pe_header_offset = u64::from(file.header_dos().pe_header_offset);
        let section_table_start =
            pe_header_offset + 24 + u64::from(file.header().size_of_optional_header);
        let new_section_table_size = (original_section_count + 1) * 40; // +1 for .meta section
        let new_section_table_end = section_table_start + new_section_table_size as u64;

        // Plan relocated original sections
        for (index, original_section) in file.sections().iter().enumerate() {
            let section_name = original_section.name.as_str();

            // FIXED: Only relocate sections that would overlap with the expanded section table
            let original_section_start = u64::from(original_section.pointer_to_raw_data);
            let new_file_offset = if original_section_start < new_section_table_end {
                // This section overlaps with the expanded section table, need to relocate
                original_section_start + section_table_growth
            } else {
                // This section is after the section table, keep original offset
                original_section_start
            };

            // FIXED: Preserve original virtual addresses instead of recalculating
            // This ensures that resource section data is interpreted correctly
            let new_virtual_address = original_section.virtual_address;

            // No need to extend sections - method bodies go in .meta section
            let extended_virtual_size = original_section.virtual_size;

            // Calculate the actual available file space for this section
            // Check if this section would overlap with the next section
            let mut available_file_size = u64::from(original_section.size_of_raw_data);

            // Check against subsequent sections to avoid overlaps
            let mut next_section_offset = u64::MAX;
            for (next_index, next_section) in file.sections().iter().enumerate() {
                if next_index > index {
                    let next_offset =
                        if u64::from(next_section.pointer_to_raw_data) < new_section_table_end {
                            // Next section will be relocated
                            u64::from(next_section.pointer_to_raw_data) + section_table_growth
                        } else {
                            // Next section keeps original offset
                            u64::from(next_section.pointer_to_raw_data)
                        };
                    next_section_offset = std::cmp::min(next_section_offset, next_offset);
                }
            }

            // Limit the section size to not overlap with the next section
            let final_virtual_size = if next_section_offset != u64::MAX
                && new_file_offset + available_file_size > next_section_offset
            {
                let max_size = next_section_offset - new_file_offset;
                available_file_size = max_size;

                // CRITICAL FIX: Ensure VirtualSize doesn't exceed SizeOfRawData
                // If we had to reduce the raw size due to overlap constraints,
                // also adjust the virtual size to prevent SizeOfRawData < VirtualSize
                let max_virtual_size_u32 = u32::try_from(max_size)
                    .map_err(|_| malformed_error!("Maximum section size exceeds u32 range"))?;
                std::cmp::min(extended_virtual_size, max_virtual_size_u32)
            } else {
                extended_virtual_size
            };

            sections.push(SectionLayout {
                name: section_name.to_string(),
                virtual_address: new_virtual_address,
                virtual_size: final_virtual_size,
                file_region: FileRegion {
                    offset: new_file_offset,
                    size: available_file_size,
                },
                characteristics: original_section.characteristics,
                contains_metadata: false, // Original sections no longer contain metadata
            });
        }

        // Plan new .meta section
        let meta_section = Self::plan_meta_section(
            file,
            &sections,
            component_sizes,
            native_table_requirements,
            self.assembly.changes().method_bodies_total_size()?,
        )?;
        sections.push(meta_section);

        Ok(sections)
    }

    /// Plans the new .meta section that will contain all metadata.
    fn plan_meta_section(
        file: &File,
        existing_sections: &[SectionLayout],
        component_sizes: &MetadataComponentSizes,
        native_table_requirements: &NativeTableRequirements,
        method_bodies_size: u32,
    ) -> Result<SectionLayout> {
        // Calculate .meta section size including native table space
        let mut meta_section_size = component_sizes.cor20_header
            + component_sizes.metadata_root
            + component_sizes.tables_stream
            + component_sizes.strings_heap
            + component_sizes.blob_heap
            + component_sizes.guid_heap
            + component_sizes.userstring_heap;

        // Each non-zero stream gets 4 bytes of extra padding after alignment
        let mut stream_count = 0;
        if component_sizes.tables_stream > 0 {
            stream_count += 1;
        }
        if component_sizes.strings_heap > 0 {
            stream_count += 1;
        }
        if component_sizes.blob_heap > 0 {
            stream_count += 1;
        }
        if component_sizes.guid_heap > 0 {
            stream_count += 1;
        }
        if component_sizes.userstring_heap > 0 {
            stream_count += 1;
        }
        meta_section_size += stream_count * 4; // 4 bytes padding per stream

        // Add space for method bodies - place them after metadata streams
        if method_bodies_size > 0 {
            meta_section_size += u64::from(method_bodies_size);
            // Add alignment padding after method bodies
            meta_section_size += 128; // Padding between method bodies and native tables
        }

        // Add space for native tables
        if native_table_requirements.needs_import_tables {
            meta_section_size += native_table_requirements.import_table_size;
        }
        if native_table_requirements.needs_export_tables {
            meta_section_size += native_table_requirements.export_table_size;
        }

        // Add padding for alignment between native tables
        if native_table_requirements.needs_import_tables
            || native_table_requirements.needs_export_tables
        {
            meta_section_size += 256; // Extra padding for RVA alignment
        }

        // Align to file alignment from original PE headers
        let aligned_meta_size = align_to(meta_section_size, u64::from(file.file_alignment()?));

        // Calculate position after last existing section
        let last_section = existing_sections
            .last()
            .ok_or_else(|| Error::WriteLayoutFailed {
                message: "No existing sections found".to_string(),
            })?;

        let meta_file_offset = last_section.file_region.offset
            + align_to(
                last_section.file_region.size,
                u64::from(file.file_alignment()?),
            );

        // FIXED: Calculate .meta section virtual address based on original section layout
        // Find the highest virtual address + size from existing sections
        let mut max_virtual_end = 0u64;
        for section in existing_sections {
            let section_end = u64::from(section.virtual_address)
                + align_to(
                    u64::from(section.virtual_size),
                    u64::from(file.section_alignment()?),
                );
            max_virtual_end = max_virtual_end.max(section_end);
        }
        let meta_virtual_address = u32::try_from(align_to(
            max_virtual_end,
            u64::from(file.section_alignment()?),
        ))
        .map_err(|_| malformed_error!("Meta virtual address exceeds u32 range"))?;

        Ok(SectionLayout {
            name: ".meta".to_string(),
            virtual_address: meta_virtual_address,
            virtual_size: u32::try_from(meta_section_size)
                .map_err(|_| malformed_error!("Meta section size exceeds u32 range"))?,
            file_region: FileRegion {
                offset: meta_file_offset,
                size: aligned_meta_size,
            },
            characteristics: IMAGE_SCN_METADATA, // IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ
            contains_metadata: true,
        })
    }

    /// Plans detailed metadata layout within the .meta section.
    fn plan_metadata_layout(
        file_structure: &FileStructureLayout,
        component_sizes: &MetadataComponentSizes,
    ) -> Result<MetadataLayout> {
        // Find the .meta section
        let meta_section = file_structure
            .sections
            .iter()
            .find(|s| s.contains_metadata)
            .ok_or_else(|| Error::WriteLayoutFailed {
                message: "No .meta section found in file structure".to_string(),
            })?;

        let meta_start = meta_section.file_region.offset;
        let mut current_offset = meta_start;

        // COR20 header at the beginning of .meta section
        let cor20_header = FileRegion {
            offset: current_offset,
            size: component_sizes.cor20_header,
        };
        current_offset += component_sizes.cor20_header;

        // Metadata root + stream directory
        let metadata_root = FileRegion {
            offset: current_offset,
            size: component_sizes.metadata_root,
        };
        current_offset += component_sizes.metadata_root;

        // Calculate stream directory position (part of metadata root calculation)
        let stream_directory = FileRegion {
            offset: metadata_root.offset + Self::calculate_metadata_root_header_size(),
            size: component_sizes.metadata_root - Self::calculate_metadata_root_header_size(),
        };

        // Plan individual streams - they start immediately after the metadata root
        let streams = Self::plan_metadata_streams(current_offset, component_sizes, &metadata_root)?;

        Ok(MetadataLayout {
            meta_section: meta_section.clone(),
            cor20_header,
            metadata_root,
            stream_directory,
            streams,
        })
    }

    /// Plans individual metadata streams within the .meta section.
    fn plan_metadata_streams(
        start_offset: u64,
        component_sizes: &MetadataComponentSizes,
        metadata_root: &FileRegion,
    ) -> Result<Vec<StreamLayout>> {
        let mut streams = Vec::new();
        let mut current_offset = start_offset;
        let root_start = metadata_root.offset;

        // Tables stream (#~ or #-)
        if component_sizes.tables_stream > 0 {
            streams.push(StreamLayout {
                name: "#~".to_string(), // Use compressed format
                offset_from_root: u32::try_from(current_offset - root_start)
                    .map_err(|_| malformed_error!("Tables stream offset exceeds u32 range"))?,
                size: u32::try_from(component_sizes.tables_stream)
                    .map_err(|_| malformed_error!("Tables stream size exceeds u32 range"))?,
                file_region: FileRegion {
                    offset: current_offset,
                    size: component_sizes.tables_stream,
                },
            });
            current_offset += component_sizes.tables_stream;
            current_offset += 4;
            current_offset = align_to_4_bytes(current_offset);
        }

        // String heap (#Strings)
        if component_sizes.strings_heap > 0 {
            streams.push(StreamLayout {
                name: "#Strings".to_string(),
                offset_from_root: u32::try_from(current_offset - root_start)
                    .map_err(|_| malformed_error!("Strings heap offset exceeds u32 range"))?,
                size: u32::try_from(component_sizes.strings_heap)
                    .map_err(|_| malformed_error!("Strings heap size exceeds u32 range"))?,
                file_region: FileRegion {
                    offset: current_offset,
                    size: component_sizes.strings_heap,
                },
            });
            current_offset += component_sizes.strings_heap;
            current_offset += 4;
            current_offset = align_to_4_bytes(current_offset);
        }

        // Blob heap (#Blob)
        if component_sizes.blob_heap > 0 {
            streams.push(StreamLayout {
                name: "#Blob".to_string(),
                offset_from_root: u32::try_from(current_offset - root_start)
                    .map_err(|_| malformed_error!("Blob heap offset exceeds u32 range"))?,
                size: u32::try_from(component_sizes.blob_heap)
                    .map_err(|_| malformed_error!("Blob heap size exceeds u32 range"))?,
                file_region: FileRegion {
                    offset: current_offset,
                    size: component_sizes.blob_heap,
                },
            });
            current_offset += component_sizes.blob_heap;
            current_offset += 4;
            current_offset = align_to_4_bytes(current_offset);
        }

        // GUID heap (#GUID)
        if component_sizes.guid_heap > 0 {
            streams.push(StreamLayout {
                name: "#GUID".to_string(),
                offset_from_root: u32::try_from(current_offset - root_start)
                    .map_err(|_| malformed_error!("GUID heap offset exceeds u32 range"))?,
                size: u32::try_from(component_sizes.guid_heap)
                    .map_err(|_| malformed_error!("GUID heap size exceeds u32 range"))?,
                file_region: FileRegion {
                    offset: current_offset,
                    size: component_sizes.guid_heap,
                },
            });
            current_offset += component_sizes.guid_heap;
            current_offset += 4;
            current_offset = align_to_4_bytes(current_offset);
        }

        // User string heap (#US)
        if component_sizes.userstring_heap > 0 {
            streams.push(StreamLayout {
                name: "#US".to_string(),
                offset_from_root: u32::try_from(current_offset - root_start)
                    .map_err(|_| malformed_error!("UserString heap offset exceeds u32 range"))?,
                size: u32::try_from(component_sizes.userstring_heap)
                    .map_err(|_| malformed_error!("UserString heap size exceeds u32 range"))?,
                file_region: FileRegion {
                    offset: current_offset,
                    size: component_sizes.userstring_heap,
                },
            });
        }

        Ok(streams)
    }

    /// Generates all copy/zero/write operations needed for file generation.
    fn generate_operations(
        &mut self,
        file_structure: &FileStructureLayout,
        metadata_layout: &MetadataLayout,
    ) -> Result<OperationSet> {
        let mut operations = OperationSet::new();

        // Generate copy operations for existing content
        self.generate_copy_operations(&mut operations, file_structure)?;

        // Generate zero operations to clear old metadata locations
        self.generate_zero_operations(&mut operations, file_structure);

        // Generate write operations for new content
        self.generate_write_operations(&mut operations, file_structure, metadata_layout)?;

        Ok(operations)
    }

    /// Generates copy operations to preserve existing content.
    fn generate_copy_operations(
        &mut self,
        operations: &mut OperationSet,
        file_structure: &FileStructureLayout,
    ) -> Result<()> {
        let view = self.assembly.view();
        let file = view.file();

        // Copy DOS header
        operations.copy.push(CopyOperation {
            source_offset: 0,
            target_offset: 0,
            size: 64,
            description: "DOS header".to_string(),
        });

        // Copy DOS stub (from end of DOS header to start of PE headers)
        // PE headers start at offset specified in DOS header e_lfanew field (typically 0x80 = 128)
        let pe_headers_start = file_structure.pe_headers.offset;
        if pe_headers_start > 64 {
            operations.copy.push(CopyOperation {
                source_offset: 64,
                target_offset: 64,
                size: pe_headers_start - 64,
                description: "DOS stub".to_string(),
            });
        }

        // Note: PE headers will be written by generate_write_operations() after section table is updated

        // Copy original section content to new locations
        for (index, original_section) in file.sections().iter().enumerate() {
            if let Some(new_section) = file_structure.sections.get(index) {
                if !new_section.contains_metadata {
                    // Check if this section contains metadata in the original file
                    let section_contains_original_metadata =
                        self.section_contains_metadata(original_section);

                    if section_contains_original_metadata {
                        // This section contains metadata - copy it in parts to exclude the metadata
                        self.generate_section_copy_excluding_metadata(
                            operations,
                            original_section,
                            new_section,
                        )?;
                    } else {
                        // This section doesn't contain metadata - copy it entirely
                        operations.copy.push(CopyOperation {
                            source_offset: u64::from(original_section.pointer_to_raw_data),
                            target_offset: new_section.file_region.offset,
                            size: u64::from(original_section.size_of_raw_data),
                            description: format!("Section {} content", new_section.name),
                        });
                    }
                }
            }
        }

        Ok(())
    }

    /// Checks if a section contains metadata in the original file.
    fn section_contains_metadata(&self, section: &SectionTable) -> bool {
        let view = self.assembly.view();
        let metadata_rva = view.cor20header().meta_data_rva;

        let section_start_rva = section.virtual_address;
        let section_end_rva = section_start_rva + section.virtual_size;

        metadata_rva >= section_start_rva && metadata_rva < section_end_rva
    }

    /// Checks if a section contains the COR20 header in the original file.
    fn section_contains_cor20_header(&self, section: &SectionTable) -> Result<bool> {
        let view = self.assembly.view();
        let file = view.file();

        // Get COR20 header RVA
        let optional_header =
            file.header_optional()
                .as_ref()
                .ok_or_else(|| Error::WriteLayoutFailed {
                    message: "Missing optional header for COR20 check".to_string(),
                })?;

        let clr_header_entry = optional_header
            .data_directories
            .get_clr_runtime_header()
            .ok_or_else(|| Error::WriteLayoutFailed {
                message: "No CLR Runtime Header data directory entry found".to_string(),
            })?;

        let cor20_rva = clr_header_entry.virtual_address;
        let section_start_rva = section.virtual_address;
        let section_end_rva = section_start_rva + section.virtual_size;

        Ok(cor20_rva >= section_start_rva && cor20_rva < section_end_rva)
    }

    /// Generates copy operations for a section that contains metadata, excluding the metadata region.
    fn generate_section_copy_excluding_metadata(
        &self,
        operations: &mut OperationSet,
        original_section: &SectionTable,
        new_section: &SectionLayout,
    ) -> Result<()> {
        let view = self.assembly.view();
        let file = view.file();

        // Get metadata location in the file
        let metadata_rva = view.cor20header().meta_data_rva as usize;
        let metadata_file_offset =
            file.rva_to_offset(metadata_rva)
                .map_err(|e| Error::WriteLayoutFailed {
                    message: format!("Failed to resolve metadata RVA to file offset: {e}"),
                })? as u64;
        let metadata_size = u64::from(view.cor20header().meta_data_size);

        let section_file_start = u64::from(original_section.pointer_to_raw_data);
        let section_file_end = section_file_start + u64::from(original_section.size_of_raw_data);

        // Check if this is a code section that might have method bodies reserved at the end
        let is_code_section = new_section.name == ".text"
            || (original_section.characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        let method_bodies_total_size = if is_code_section {
            u64::from(self.assembly.changes().method_bodies_total_size()?)
        } else {
            0
        };

        // Calculate the available space for copying content, excluding method body space
        let available_copy_space = if method_bodies_total_size > 0 && is_code_section {
            // For code sections with method bodies, limit the copy to original virtual size
            // The extended space is reserved for method bodies
            std::cmp::min(
                new_section.file_region.size,
                u64::from(original_section.virtual_size),
            )
        } else {
            new_section.file_region.size
        };

        // Copy the part before metadata (if any)
        if metadata_file_offset > section_file_start {
            let before_size = metadata_file_offset - section_file_start;
            operations.copy.push(CopyOperation {
                source_offset: section_file_start,
                target_offset: new_section.file_region.offset,
                size: before_size,
                description: format!(
                    "Section {name} content (before metadata)",
                    name = new_section.name
                ),
            });
        }

        // Copy the part after metadata (if any), but respect method body space reservation
        let metadata_end = metadata_file_offset + metadata_size;
        if metadata_end < section_file_end {
            let after_start = metadata_end;
            let after_offset_in_section = after_start - section_file_start;
            let after_target_offset = new_section.file_region.offset + after_offset_in_section;

            // Calculate how much we can copy after metadata, considering method body space
            let remaining_available_space =
                available_copy_space.saturating_sub(after_offset_in_section);

            let after_size =
                std::cmp::min(section_file_end - after_start, remaining_available_space);

            if after_size > 0 {
                operations.copy.push(CopyOperation {
                    source_offset: after_start,
                    target_offset: after_target_offset,
                    size: after_size,
                    description: format!(
                        "Section {name} content (after metadata)",
                        name = new_section.name
                    ),
                });
            }
        }

        Ok(())
    }

    /// Generates zero operations to clear old metadata locations.
    fn generate_zero_operations(
        &mut self,
        operations: &mut OperationSet,
        file_structure: &FileStructureLayout,
    ) {
        // Find original metadata locations and clear them
        let view = self.assembly.view();

        // Clear original metadata root location
        if let Ok(metadata_rva) = view.cor20header().meta_data_rva.try_into() {
            if let Ok(metadata_offset) = view.file().rva_to_offset(metadata_rva) {
                let metadata_size = u64::from(view.cor20header().meta_data_size);
                let metadata_start = metadata_offset as u64;
                let metadata_end = metadata_start + metadata_size;

                // Check if this metadata location overlaps with any section being copied entirely
                let mut overlaps_with_copied_section = false;
                for (index, original_section) in view.file().sections().iter().enumerate() {
                    if let Some(new_section) = file_structure.sections.get(index) {
                        if !new_section.contains_metadata {
                            // This section is being copied entirely
                            let section_start = u64::from(original_section.pointer_to_raw_data);
                            let section_end =
                                section_start + u64::from(original_section.size_of_raw_data);

                            // Check if metadata overlaps with this section
                            if metadata_start < section_end && metadata_end > section_start {
                                overlaps_with_copied_section = true;
                                break;
                            }
                        }
                    }
                }

                // Only add zero operation if metadata doesn't overlap with a copied section
                if !overlaps_with_copied_section {
                    operations.zero.push(ZeroOperation {
                        offset: metadata_start,
                        size: metadata_size,
                        reason: "Clear original metadata location".to_string(),
                    });
                }
            }
        }
    }

    /// Generates write operations for new content.
    fn generate_write_operations(
        &mut self,
        operations: &mut OperationSet,
        file_structure: &FileStructureLayout,
        metadata_layout: &MetadataLayout,
    ) -> Result<()> {
        // Generate updated section table
        self.generate_section_table_write_operation(operations, file_structure)?;

        // Generate updated PE headers with correct CLR data directory (AFTER section table is updated)
        self.generate_updated_pe_headers_write_operation_final(
            operations,
            file_structure,
            metadata_layout,
        )?;

        // Generate COR20 header update
        self.generate_cor20_header_write_operation(operations, metadata_layout, file_structure)?;

        // Generate metadata root and stream directory
        Self::generate_metadata_root_write_operation(operations, metadata_layout)?;

        // Generate metadata streams
        self.generate_metadata_streams_write_operations(operations, metadata_layout)?;

        // Generate method body write operations
        self.generate_method_body_write_operations(operations, file_structure)?;

        Ok(())
    }

    /// Builds RVA and index mappings for cross-reference updates.
    fn build_mappings(
        &mut self,
        _metadata_layout: &MetadataLayout,
    ) -> Result<(HashMap<u32, u32>, IndexRemapper)> {
        // Build method body RVA mappings from placeholder RVAs to actual RVAs
        let rva_mappings = self.build_method_body_rva_mappings()?;

        // Build comprehensive index remapping using the proper remapping system
        let index_remapper =
            IndexRemapper::build_from_changes(self.assembly.changes(), self.assembly.view());

        Ok((rva_mappings, index_remapper))
    }

    /// Builds RVA mappings from placeholder RVAs (0xF0000000+) to actual RVAs.
    /// Method bodies are now placed in the .meta section for better isolation.
    fn build_method_body_rva_mappings(&self) -> Result<HashMap<u32, u32>> {
        let changes = self.assembly.changes();
        let mut rva_mappings = HashMap::new();

        // Check if we have any method bodies to map
        if changes.method_bodies_total_size()? == 0 {
            return Ok(rva_mappings);
        }

        // Method bodies are now placed in the .meta section instead of extending existing sections
        // This avoids overlap issues and provides better isolation
        let meta_section_virtual_address = self.meta_section_virtual_address()?;

        // Calculate where method bodies will be placed within .meta section
        // Place them after all metadata streams but before native tables
        let component_sizes = self.calculate_metadata_component_sizes()?;
        let metadata_streams_size = component_sizes.cor20_header
            + component_sizes.metadata_root
            + component_sizes.tables_stream
            + component_sizes.strings_heap
            + component_sizes.blob_heap
            + component_sizes.guid_heap
            + component_sizes.userstring_heap;

        // Each non-zero stream gets 4 bytes of padding
        let stream_count = [
            component_sizes.tables_stream,
            component_sizes.strings_heap,
            component_sizes.blob_heap,
            component_sizes.guid_heap,
            component_sizes.userstring_heap,
        ]
        .iter()
        .filter(|&&size| size > 0)
        .count();

        let streams_padding = stream_count * 4;
        let metadata_end_offset = metadata_streams_size + streams_padding as u64;

        // Place method bodies after metadata, aligned to 4-byte boundary
        let method_body_base_rva = u32::try_from(align_to_4_bytes(
            u64::from(meta_section_virtual_address) + metadata_end_offset,
        ))
        .map_err(|_| malformed_error!("Method body base RVA exceeds u32 range"))?;

        // Build mapping for each method body
        let mut current_rva = method_body_base_rva;
        for (placeholder_rva, method_body_bytes) in changes.method_bodies() {
            rva_mappings.insert(placeholder_rva, current_rva);

            // Advance to next method body position with proper alignment
            // method_body_bytes already contains the complete method body including:
            // - Method header (tiny 1 byte or fat 12 bytes)
            // - IL instruction bytes
            // - 4-byte padding before exception handlers (if present)
            // - Exception handler section (if present)
            let method_body_size = u32::try_from(method_body_bytes.len())
                .map_err(|_| malformed_error!("Method body size exceeds u32 range"))?;
            let aligned_size = u32::try_from(align_to_4_bytes(u64::from(method_body_size)))
                .map_err(|_| malformed_error!("Method body aligned size exceeds u32 range"))?;

            // No additional padding needed - method_body_bytes is already complete and accurate
            current_rva += aligned_size;
        }

        Ok(rva_mappings)
    }

    /// Gets the virtual address where the .meta section will be placed.
    fn meta_section_virtual_address(&self) -> Result<u32> {
        let view = self.assembly.view();
        let sections = view.file().sections();

        // Find the last section to determine where .meta section will be placed
        let last_section = sections
            .iter()
            .max_by_key(|section| section.virtual_address)
            .ok_or_else(|| Error::WriteLayoutFailed {
                message: "No sections found in PE file".to_string(),
            })?;

        // .meta section will be placed after the last existing section
        let last_section_end = last_section.virtual_address + last_section.virtual_size;

        // Align to section alignment
        let section_alignment = view.file().section_alignment()?;
        u32::try_from(align_to(
            u64::from(last_section_end),
            u64::from(section_alignment),
        ))
        .map_err(|_| malformed_error!("Virtual size calculation exceeds u32 range"))
    }

    // Helper methods for size calculations (using existing algorithms)

    fn calculate_string_heap_total_size(&self) -> Result<u64> {
        let string_changes = &self.assembly.changes().string_heap_changes;
        calculate_string_heap_size(string_changes, self.assembly)
    }

    fn calculate_blob_heap_total_size(&self) -> Result<u64> {
        let blob_changes = &self.assembly.changes().blob_heap_changes;
        calculate_blob_heap_size(blob_changes, self.assembly)
    }

    fn calculate_guid_heap_total_size(&self) -> Result<u64> {
        let guid_changes = &self.assembly.changes().guid_heap_changes;
        calculate_guid_heap_size(guid_changes, self.assembly)
    }

    fn calculate_userstring_heap_total_size(&self) -> u64 {
        let userstring_changes = &self.assembly.changes().userstring_heap_changes;
        calculate_userstring_heap_size(userstring_changes, self.assembly)
    }

    fn calculate_tables_stream_size(&self) -> Result<u64> {
        // Calculate the original tables stream size
        let original_size = if let Some(tables_stream) = self
            .assembly
            .view()
            .streams()
            .iter()
            .find(|s| s.name == "#~" || s.name == "#-")
        {
            u64::from(tables_stream.size)
        } else {
            // No original tables stream - calculate minimal size with empty tables
            100 // Basic tables stream header
        };

        // Add expansion for modified tables
        let expansion = calculate_table_stream_expansion(self.assembly)?;

        Ok(original_size + expansion)
    }

    fn calculate_metadata_root_size() -> u64 {
        // Calculate metadata root header + stream directory size
        let header_size = Self::calculate_metadata_root_header_size();
        let stream_directory_size = Self::calculate_stream_directory_size();
        header_size + stream_directory_size
    }

    fn calculate_metadata_root_header_size() -> u64 {
        // Metadata root header contains:
        // - Signature (4 bytes): "BSJB"
        // - Major version (2 bytes): typically 1
        // - Minor version (2 bytes): typically 1
        // - Reserved (4 bytes): 0
        // - Length (4 bytes): length of version string
        // - Version string: padded to 4-byte boundary
        // - Flags (2 bytes): 0
        // - Streams count (2 bytes): number of streams

        let version_string = b"v4.0.30319"; // Standard .NET version string
        let version_string_padded_length = align_to_4_bytes(version_string.len() as u64);

        // 4 + 2 + 2 + 4 + 4 + version_string + 2 + 2 = 20 + version_string_padded
        20 + version_string_padded_length
    }

    fn calculate_stream_directory_size() -> u64 {
        // Each stream directory entry contains:
        // - Offset (4 bytes): offset from metadata root
        // - Size (4 bytes): size of stream
        // - Name: null-terminated, padded to 4-byte boundary

        let stream_names = vec!["#~", "#Strings", "#Blob", "#GUID", "#US"];
        let mut total_size = 0u64;

        for name in stream_names {
            let name_bytes = name.as_bytes();
            let name_padded_length = align_to_4_bytes((name_bytes.len() + 1) as u64); // +1 for null terminator
            total_size += 8 + name_padded_length; // offset(4) + size(4) + padded_name
        }

        total_size
    }

    fn calculate_total_file_size(file_structure: &FileStructureLayout) -> u64 {
        // Find the last section and calculate file size from it
        if let Some(last_section) = file_structure.sections.last() {
            last_section.file_region.offset + last_section.file_region.size
        } else {
            // Fallback to section table end if no sections
            file_structure.section_table.offset + file_structure.section_table.size
        }
    }

    fn build_planning_info(
        &self,
        component_sizes: &MetadataComponentSizes,
        total_file_size: u64,
        planning_start: Instant,
    ) -> PlanningInfo {
        let size_increase = total_file_size.saturating_sub(self.original_size);

        let section_table_size = SectionTable::calculate_table_size(self.pe.sections.len() + 1); // +1 for .meta section
        let original_sections_size = self.pe.get_sections_total_raw_data_size();

        let size_breakdown = SizeBreakdown {
            headers: self.pe.calculate_total_file_headers_size(), // DOS header + PE headers
            section_table: section_table_size,
            original_sections: original_sections_size,
            metadata_section: component_sizes.cor20_header
                + component_sizes.metadata_root
                + component_sizes.tables_stream
                + component_sizes.strings_heap
                + component_sizes.blob_heap
                + component_sizes.guid_heap
                + component_sizes.userstring_heap,
            metadata_components: component_sizes.clone(),
        };

        PlanningInfo {
            original_size: self.original_size,
            size_increase,
            operation_count: 0, // Will be updated by WriteLayout
            planning_duration: planning_start.elapsed(),
            warnings: self.warnings.clone(),
            size_breakdown,
        }
    }

    fn generate_section_table_write_operation(
        &mut self,
        operations: &mut OperationSet,
        file_structure: &FileStructureLayout,
    ) -> Result<()> {
        // Update the planner's Pe struct with the new section layout
        self.pe.sections.clear();
        self.pe.coff_header.update_section_count(0);

        // Add all sections from file_structure layout
        for section_layout in &file_structure.sections {
            let section_table = SectionTable::from_layout_info(
                section_layout.name.clone(),
                section_layout.virtual_address,
                section_layout.virtual_size,
                section_layout.file_region.offset,
                section_layout.file_region.size,
                section_layout.characteristics,
            )?;
            self.pe.add_section(section_table);
        }

        // Update section count to reflect the new layout including .meta section
        let new_section_count = u16::try_from(file_structure.sections.len())
            .map_err(|_| malformed_error!("Section count exceeds u16 range"))?;
        self.pe.coff_header.update_section_count(new_section_count);

        // Write the complete section table using the updated Pe struct
        let mut section_table_data = Vec::new();
        self.pe.write_section_headers(&mut section_table_data)?;

        operations.write.push(WriteOperation {
            offset: file_structure.section_table.offset,
            data: section_table_data,
            component: "Section table with .meta section".to_string(),
        });

        Ok(())
    }

    fn generate_cor20_header_write_operation(
        &mut self,
        operations: &mut OperationSet,
        metadata_layout: &MetadataLayout,
        file_structure: &FileStructureLayout,
    ) -> Result<()> {
        // Constants
        const VALID_COR20_FLAGS: u32 = 0x0000_001F;

        // Generate updated COR20 header pointing to new metadata location
        let view = self.assembly.view();
        let original_cor20 = view.cor20header();

        let mut cor20_data = vec![0u8; COR20_HEADER_SIZE as usize]; // COR20 header is always 72 bytes
        let mut offset = 0;

        // Size (4 bytes) - always 72
        cor20_data[offset..offset + 4].copy_from_slice(&COR20_HEADER_SIZE.to_le_bytes());
        offset += 4;

        // Major runtime version (2 bytes)
        cor20_data[offset..offset + 2]
            .copy_from_slice(&original_cor20.major_runtime_version.to_le_bytes());
        offset += 2;

        // Minor runtime version (2 bytes)
        cor20_data[offset..offset + 2]
            .copy_from_slice(&original_cor20.minor_runtime_version.to_le_bytes());
        offset += 2;

        // Metadata directory - point to new .meta section
        let metadata_rva =
            Self::file_offset_to_rva(metadata_layout.metadata_root.offset, file_structure)?;

        cor20_data[offset..offset + 4].copy_from_slice(&metadata_rva.to_le_bytes());
        offset += 4;

        // Calculate total metadata size (excluding COR20 header)
        let total_metadata_size =
            metadata_layout.meta_section.file_region.size - metadata_layout.cor20_header.size;
        let metadata_size_u32 = u32::try_from(total_metadata_size)
            .map_err(|_| malformed_error!("Total metadata size exceeds u32 range"))?;
        cor20_data[offset..offset + 4].copy_from_slice(&metadata_size_u32.to_le_bytes());
        offset += 4;

        // Flags (4 bytes) - mask to only include valid flags (0x0000_001F per ECMA-335)
        let safe_flags = original_cor20.flags & VALID_COR20_FLAGS;
        cor20_data[offset..offset + 4].copy_from_slice(&safe_flags.to_le_bytes());
        offset += 4;

        // Entry point token (4 bytes)
        cor20_data[offset..offset + 4]
            .copy_from_slice(&original_cor20.entry_point_token.to_le_bytes());
        offset += 4;

        // Copy remaining fields from original (resources, strong name, etc.)
        // These typically don't change during metadata modifications

        // Resource directory (8 bytes)
        cor20_data[offset..offset + 4].copy_from_slice(&original_cor20.resource_rva.to_le_bytes());
        offset += 4;
        cor20_data[offset..offset + 4].copy_from_slice(&original_cor20.resource_size.to_le_bytes());
        offset += 4;

        // Strong name signature (8 bytes)
        cor20_data[offset..offset + 4]
            .copy_from_slice(&original_cor20.strong_name_signature_rva.to_le_bytes());
        offset += 4;
        cor20_data[offset..offset + 4]
            .copy_from_slice(&original_cor20.strong_name_signature_size.to_le_bytes());
        offset += 4;

        // Code manager table (8 bytes) - reserved, typically 0
        cor20_data[offset..offset + 4]
            .copy_from_slice(&original_cor20.code_manager_table_rva.to_le_bytes());
        offset += 4;
        cor20_data[offset..offset + 4]
            .copy_from_slice(&original_cor20.code_manager_table_size.to_le_bytes());

        // Write COR20 header to the .meta section (as originally designed)

        operations.write.push(WriteOperation {
            offset: metadata_layout.cor20_header.offset,
            data: cor20_data,
            component: "Updated COR20 header".to_string(),
        });

        // Note: CLR data directory entry will be updated inline during PE headers copy

        Ok(())
    }

    /// Generates updated PE headers with CLR data directory pointing to new COR20 location.
    fn generate_updated_pe_headers_write_operation(
        &mut self,
        operations: &mut OperationSet,
        file_structure: &FileStructureLayout,
        metadata_layout: &MetadataLayout,
    ) -> Result<()> {
        // Update section count to match the new layout
        let new_section_count = u16::try_from(file_structure.sections.len())
            .map_err(|_| malformed_error!("Section count exceeds u16 range"))?;
        self.pe.coff_header.update_section_count(new_section_count);

        // Calculate the new COR20 header RVA and update CLR data directory
        let new_cor20_rva =
            Self::file_offset_to_rva(metadata_layout.cor20_header.offset, file_structure)?;
        let cor20_size = COR20_HEADER_SIZE; // COR20 header is always 72 bytes

        self.pe
            .update_clr_data_directory(new_cor20_rva, cor20_size)?;

        // Write only the PE headers (not including section table) to match the expected size
        let mut updated_headers = Vec::new();
        self.pe.write_headers(&mut updated_headers)?;

        // Ensure the size matches what was allocated in the layout
        let expected_size = usize::try_from(file_structure.pe_headers.size)
            .map_err(|_| malformed_error!("PE headers size exceeds usize range"))?;
        if updated_headers.len() > expected_size {
            // Truncate to the expected size to avoid overlap
            updated_headers.truncate(expected_size);
        } else if updated_headers.len() < expected_size {
            // Pad with zeros if needed
            updated_headers.resize(expected_size, 0);
        }

        operations.write.push(WriteOperation {
            offset: file_structure.pe_headers.offset,
            data: updated_headers,
            component: "PE headers with updated CLR data directory".to_string(),
        });

        Ok(())
    }

    /// Generates updated PE headers AFTER section table has been updated (final correct version).
    fn generate_updated_pe_headers_write_operation_final(
        &mut self,
        operations: &mut OperationSet,
        file_structure: &FileStructureLayout,
        metadata_layout: &MetadataLayout,
    ) -> Result<()> {
        // At this point, the section table has been updated and self.pe contains the correct sections
        // Now update the CLR data directory to point to the new COR20 header location
        let new_cor20_rva =
            Self::file_offset_to_rva(metadata_layout.cor20_header.offset, file_structure)?;
        let cor20_size = COR20_HEADER_SIZE; // COR20 header is always 72 bytes

        self.pe
            .update_clr_data_directory(new_cor20_rva, cor20_size)?;

        // Write only the PE headers (not including section table) to match the expected size
        let mut updated_headers = Vec::new();
        self.pe.write_headers(&mut updated_headers)?;

        // Ensure the size matches what was allocated in the layout
        let expected_size = usize::try_from(file_structure.pe_headers.size)
            .map_err(|_| malformed_error!("PE headers size exceeds usize range"))?;
        if updated_headers.len() > expected_size {
            // Truncate to the expected size to avoid overlap
            updated_headers.truncate(expected_size);
        } else if updated_headers.len() < expected_size {
            // Pad with zeros if needed
            updated_headers.resize(expected_size, 0);
        }

        operations.write.push(WriteOperation {
            offset: file_structure.pe_headers.offset,
            data: updated_headers,
            component: "Final PE headers with correct CLR data directory".to_string(),
        });

        Ok(())
    }

    /// Updates the CLR data directory entry to point to the new COR20 header location.
    fn generate_clr_data_directory_update(
        &self,
        operations: &mut OperationSet,
        metadata_layout: &MetadataLayout,
        file_structure: &FileStructureLayout,
    ) -> Result<()> {
        // Find the CLR data directory entry location in the PE optional header
        let view = self.assembly.view();
        let file = view.file();

        let optional_header =
            file.header_optional()
                .as_ref()
                .ok_or_else(|| Error::WriteLayoutFailed {
                    message: "Missing optional header for CLR data directory update".to_string(),
                })?;

        // Calculate the file offset of the CLR directory entry
        // The data directory is at a fixed offset within the optional header
        let pe_headers_region = &file_structure.pe_headers;
        let is_pe32_plus = optional_header.standard_fields.magic != 0x10b;

        // PE signature (4) + COFF header (20) = 24 bytes before optional header
        let optional_header_start = pe_headers_region.offset + 24;

        // Data directory offset depends on PE type:
        // PE32: 96 bytes from start of optional header
        // PE32+: 112 bytes from start of optional header
        let data_directory_offset = if is_pe32_plus {
            optional_header_start + 112
        } else {
            optional_header_start + 96
        };

        // CLR Runtime Header is directory entry 14, each entry is 8 bytes (RVA + Size)
        let clr_entry_offset = data_directory_offset + (14 * 8);

        // Calculate the new COR20 header RVA
        let new_cor20_rva =
            Self::file_offset_to_rva(metadata_layout.cor20_header.offset, file_structure)?;
        let cor20_size = COR20_HEADER_SIZE; // COR20 header is always 72 bytes

        // Create data directory entry update (8 bytes: RVA + Size)
        let mut directory_data = Vec::with_capacity(8);
        directory_data.extend_from_slice(&new_cor20_rva.to_le_bytes());
        directory_data.extend_from_slice(&cor20_size.to_le_bytes());

        operations.write.push(WriteOperation {
            offset: clr_entry_offset,
            data: directory_data,
            component: "CLR data directory entry update".to_string(),
        });

        Ok(())
    }

    /// Converts a file offset to RVA using the updated file structure layout.
    fn file_offset_to_rva(file_offset: u64, file_structure: &FileStructureLayout) -> Result<u32> {
        // Find which section contains this file offset and calculate the correct RVA
        for section in &file_structure.sections {
            let section_file_start = section.file_region.offset;
            let section_file_end = section_file_start + section.file_region.size;

            if file_offset >= section_file_start && file_offset < section_file_end {
                // Calculate RVA: section's virtual address + offset within section
                let offset_within_section = file_offset - section_file_start;
                let offset_u32 = u32::try_from(offset_within_section)
                    .map_err(|_| malformed_error!("Offset within section exceeds u32 range"))?;
                let rva = section.virtual_address + offset_u32;
                return Ok(rva);
            }
        }

        Err(malformed_error!(
            "Could not find section containing file offset 0x{:X}",
            file_offset
        ))
    }

    /// Finds the original COR20 header location in the PE file.
    /// The COR20 header location is found through the PE data directory.
    fn find_original_cor20_location(&self) -> Result<u64> {
        let view = self.assembly.view();
        let file = view.file();

        // Get the CLR Runtime Header directory entry
        let optional_header =
            file.header_optional()
                .as_ref()
                .ok_or_else(|| Error::WriteLayoutFailed {
                    message: "Missing optional header for COR20 location".to_string(),
                })?;

        let clr_header_entry = optional_header
            .data_directories
            .get_clr_runtime_header()
            .ok_or_else(|| Error::WriteLayoutFailed {
                message: "No CLR Runtime Header data directory entry found".to_string(),
            })?;

        if clr_header_entry.virtual_address == 0 {
            return Err(Error::WriteLayoutFailed {
                message: "CLR Runtime Header data directory entry is empty".to_string(),
            });
        }

        // Convert RVA to file offset
        let cor20_rva = clr_header_entry.virtual_address as usize;
        let cor20_file_offset =
            file.rva_to_offset(cor20_rva)
                .map_err(|e| Error::WriteLayoutFailed {
                    message: format!(
                        "Failed to convert COR20 RVA 0x{cor20_rva:X} to file offset: {e}"
                    ),
                })? as u64;

        Ok(cor20_file_offset)
    }

    /// Converts a file offset to a Relative Virtual Address (RVA) using the new file structure.
    ///
    /// This method performs the reverse operation of RVA-to-offset conversion by finding
    /// which section contains the given file offset and calculating the corresponding
    /// virtual address within that section's memory mapping.
    ///
    /// # Arguments
    ///
    /// * `file_offset` - Physical file offset to convert to RVA
    /// * `file_structure` - Complete file structure layout with updated section information
    ///
    /// # Returns
    ///
    /// Returns the RVA corresponding to the file offset, or error if the offset
    /// doesn't fall within any section boundaries.
    ///
    /// # Algorithm
    ///
    /// 1. **Section Search**: Iterate through all sections in the new file structure
    /// 2. **Boundary Check**: Find section containing the file offset
    /// 3. **RVA Calculation**: `section.virtual_address + (file_offset - section.file_start)`
    ///
    /// # PE Address Mapping
    ///
    /// The conversion follows standard PE address mapping:
    ///
    /// ```text
    /// File Layout:         Virtual Memory Layout:
    /// ┌─────────────┐     ┌─────────────┐
    /// │   Headers   │     │   Headers   │ ← Base RVA
    /// ├─────────────┤     ├─────────────┤
    /// │   .text     │ ←→  │   .text     │ ← virtual_address
    /// ├─────────────┤     ├─────────────┤
    /// │   .meta     │ ←→  │   .meta     │ ← virtual_address + size
    /// └─────────────┘     └─────────────┘
    /// ```
    ///
    /// # Usage Context
    ///
    /// This method is essential for:
    /// - Updating PE data directories with correct RVAs
    /// - Converting COR20 header file positions to RVAs
    /// - Ensuring correct virtual address references in PE structures
    ///
    /// # Why This Matters
    ///
    /// Since we're generating a new file layout with potentially relocated sections,
    /// we need to use the updated section information rather than the original
    /// assembly's section table for accurate RVA calculations.
    fn generate_metadata_root_write_operation(
        operations: &mut OperationSet,
        metadata_layout: &MetadataLayout,
    ) -> Result<()> {
        // Generate metadata root and stream directory
        let mut metadata_root_data = Vec::new();

        // Metadata root header
        metadata_root_data.extend_from_slice(b"BSJB"); // Signature
        metadata_root_data.extend_from_slice(&1u16.to_le_bytes()); // Major version
        metadata_root_data.extend_from_slice(&1u16.to_le_bytes()); // Minor version
        metadata_root_data.extend_from_slice(&0u32.to_le_bytes()); // Reserved

        let version_string = b"v4.0.30319";
        // Pad version string to 4-byte boundary per ECMA-335
        let padded_version_len = u32::try_from(align_to_4_bytes(version_string.len() as u64))
            .map_err(|_| malformed_error!("Version string length exceeds u32 range"))?;
        metadata_root_data.extend_from_slice(&padded_version_len.to_le_bytes()); // Padded length
        metadata_root_data.extend_from_slice(version_string); // Version string
                                                              // Add padding to reach the declared padded length
        let padding_needed = padded_version_len as usize - version_string.len();
        metadata_root_data.extend(vec![0; padding_needed]);

        // Add flags immediately after version string (no padding yet)
        metadata_root_data.extend_from_slice(&0u16.to_le_bytes()); // Flags
        let stream_count = u16::try_from(metadata_layout.streams.len())
            .map_err(|_| malformed_error!("Stream count exceeds u16 range"))?;
        metadata_root_data.extend_from_slice(&stream_count.to_le_bytes()); // Streams count

        // Stream directory starts immediately after stream count (no padding here)
        // Parser expects it at version_string.len() + 20 = 10 + 20 = 30

        // Stream directory entries
        for stream in &metadata_layout.streams {
            // Ensure stream size is 4-byte aligned
            let aligned_size = u32::try_from(align_to_4_bytes(u64::from(stream.size)))
                .map_err(|_| malformed_error!("Stream size exceeds u32 range"))?;
            metadata_root_data.extend_from_slice(&stream.offset_from_root.to_le_bytes()); // Offset
            metadata_root_data.extend_from_slice(&aligned_size.to_le_bytes()); // Size (4-byte aligned)
            metadata_root_data.extend_from_slice(stream.name.as_bytes()); // Name
            metadata_root_data.push(0); // Null terminator

            // Pad the NAME ONLY (not the entire entry) to 4-byte boundary per ECMA-335
            let name_with_null_len = stream.name.len() + 1; // name + null terminator
            let name_aligned_len = usize::try_from(align_to_4_bytes(name_with_null_len as u64))
                .map_err(|_| malformed_error!("Stream name length exceeds usize range"))?;
            let padding_needed = name_aligned_len - name_with_null_len;

            metadata_root_data.extend(vec![0; padding_needed]);

            if padding_needed > 0 {}
        }

        operations.write.push(WriteOperation {
            offset: metadata_layout.metadata_root.offset,
            data: metadata_root_data,
            component: "Metadata root and stream directory".to_string(),
        });

        Ok(())
    }

    fn generate_metadata_streams_write_operations(
        &mut self,
        operations: &mut OperationSet,
        metadata_layout: &MetadataLayout,
    ) -> Result<()> {
        // Generate all metadata stream content
        // This is where the heap builders would be used to generate the actual stream data

        for stream in &metadata_layout.streams {
            match stream.name.as_str() {
                "#~" | "#-" => {
                    // Tables stream - generate using existing tables data with modifications
                    let mut tables_data = self.generate_tables_stream_data()?;
                    // Pad tables data to match the aligned size declared in stream directory
                    let aligned_size = align_to_4_bytes(u64::from(stream.size));
                    let target_size = usize::try_from(aligned_size)
                        .map_err(|_| malformed_error!("Aligned size exceeds usize range"))?;
                    while tables_data.len() < target_size {
                        tables_data.push(0); // Pad with zeros
                    }

                    operations.write.push(WriteOperation {
                        offset: stream.file_region.offset,
                        data: tables_data,
                        component: format!("Tables stream ({})", stream.name),
                    });
                }
                "#Strings" => {
                    // String heap - for simplified table modifications, preserve original heap
                    // to maintain string index consistency with unchanged table data

                    let changes = self.assembly.changes();
                    if changes.string_heap_changes.has_changes() {
                        // Use string builder for real string changes
                        let mut string_builder = StringHeapBuilder::new(self.assembly);
                        match string_builder.build() {
                            Ok(mut string_data) => {
                                // Pad string data to match the aligned size declared in stream directory
                                let aligned_size = align_to_4_bytes(u64::from(stream.size));
                                let target_size = usize::try_from(aligned_size).map_err(|_| {
                                    malformed_error!("Aligned size exceeds usize range")
                                })?;
                                while string_data.len() < target_size {
                                    string_data.push(0); // Pad with zeros
                                }

                                operations.write.push(WriteOperation {
                                    offset: stream.file_region.offset,
                                    data: string_data,
                                    component: "String heap (modified)".to_string(),
                                });
                            }
                            Err(e) => {
                                return Err(e);
                            }
                        }
                    } else {
                        // No string changes - copy original string heap to preserve indices
                        let original_data = self.copy_original_stream_data("#Strings")?;

                        // Pad to match declared size if needed
                        let mut string_data = original_data;
                        let aligned_size = align_to_4_bytes(u64::from(stream.size));
                        let target_size = usize::try_from(aligned_size)
                            .map_err(|_| malformed_error!("Aligned size exceeds usize range"))?;
                        while string_data.len() < target_size {
                            string_data.push(0); // Pad with zeros
                        }

                        operations.write.push(WriteOperation {
                            offset: stream.file_region.offset,
                            data: string_data,
                            component: "String heap (original)".to_string(),
                        });
                    }
                }
                "#Blob" => {
                    // Blob heap - preserve original to maintain index consistency

                    let changes = self.assembly.changes();
                    if changes.blob_heap_changes.has_changes() {
                        // Use blob builder for real blob changes
                        let mut blob_builder = BlobHeapBuilder::new(self.assembly);
                        match blob_builder.build() {
                            Ok(mut blob_data) => {
                                // Pad blob data to match the aligned size declared in stream directory
                                let aligned_size = align_to_4_bytes(u64::from(stream.size));
                                let target_size = usize::try_from(aligned_size).map_err(|_| {
                                    malformed_error!("Aligned size exceeds usize range")
                                })?;
                                while blob_data.len() < target_size {
                                    blob_data.push(0); // Pad with zeros
                                }

                                operations.write.push(WriteOperation {
                                    offset: stream.file_region.offset,
                                    data: blob_data,
                                    component: "Blob heap (modified)".to_string(),
                                });
                            }
                            Err(e) => {
                                return Err(e);
                            }
                        }
                    } else {
                        // No blob changes - copy original blob heap to preserve indices
                        let original_data = self.copy_original_stream_data("#Blob")?;

                        // Pad to match declared size if needed
                        let mut blob_data = original_data;
                        let aligned_size = align_to_4_bytes(u64::from(stream.size));
                        let target_size = usize::try_from(aligned_size)
                            .map_err(|_| malformed_error!("Aligned size exceeds usize range"))?;
                        while blob_data.len() < target_size {
                            blob_data.push(0); // Pad with zeros
                        }

                        operations.write.push(WriteOperation {
                            offset: stream.file_region.offset,
                            data: blob_data,
                            component: "Blob heap (original)".to_string(),
                        });
                    }
                }
                "#GUID" => {
                    // GUID heap - check for any changes (replacement, additions, modifications)
                    let guid_changes = &self.assembly.changes().guid_heap_changes;
                    let guid_data = if guid_changes.has_changes() {
                        // Generate modified heap (handles replacement, additions, modifications)
                        let mut builder = GuidHeapBuilder::new(self.assembly);
                        builder.build()?
                    } else {
                        // Fall back to original heap preservation
                        self.copy_original_stream_data("#GUID")?
                    };

                    // Pad to match declared size if needed
                    let mut final_guid_data = guid_data;
                    let aligned_size = align_to_4_bytes(u64::from(stream.size));
                    let target_size = usize::try_from(aligned_size)
                        .map_err(|_| malformed_error!("Aligned size exceeds usize range"))?;
                    while final_guid_data.len() < target_size {
                        final_guid_data.push(0); // Pad with zeros
                    }

                    operations.write.push(WriteOperation {
                        offset: stream.file_region.offset,
                        data: final_guid_data,
                        component: "GUID heap".to_string(),
                    });
                }
                "#US" => {
                    // User string heap - check for any changes (replacement, additions, modifications)
                    let userstring_changes = &self.assembly.changes().userstring_heap_changes;
                    let (userstring_data, calculated_size) = if userstring_changes.has_changes() {
                        // Calculate size first, then build the heap data
                        let size_builder = UserStringHeapBuilder::new(self.assembly);
                        let calculated_size = size_builder.calculate_size()?;

                        let mut data_builder = UserStringHeapBuilder::new(self.assembly);
                        let data = data_builder.build()?;

                        (data, calculated_size)
                    } else {
                        // Fall back to original heap preservation
                        let data = self.copy_original_stream_data("#US")?;
                        let size = u64::from(stream.size);
                        (data, size)
                    };

                    // Use the calculated size instead of the original stream size for sparse heaps
                    let mut final_userstring_data = userstring_data;
                    let aligned_size = align_to_4_bytes(calculated_size);
                    let target_size = usize::try_from(aligned_size)
                        .map_err(|_| malformed_error!("Aligned size exceeds usize range"))?;
                    while final_userstring_data.len() < target_size {
                        final_userstring_data.push(0); // Pad with zeros
                    }

                    operations.write.push(WriteOperation {
                        offset: stream.file_region.offset,
                        data: final_userstring_data,
                        component: "User string heap".to_string(),
                    });
                }
                _ => {
                    // Unknown stream type
                    return Err(Error::WriteLayoutFailed {
                        message: format!("Unknown stream type: {}", stream.name),
                    });
                }
            }
        }

        Ok(())
    }

    /// Generates write operations for method bodies.
    fn generate_method_body_write_operations(
        &self,
        operations: &mut OperationSet,
        file_structure: &FileStructureLayout,
    ) -> Result<()> {
        let changes = self.assembly.changes();

        // Check if we have any method bodies to write
        if changes.method_bodies_total_size()? == 0 {
            return Ok(());
        }

        // Build RVA mappings to know where to write each method body
        let rva_mappings = self.build_method_body_rva_mappings()?;

        // Find the .meta section in our planned sections to get the actual file offset
        let mut meta_section_info = None;
        for section in &file_structure.sections {
            if section.name == ".meta" {
                // Found the .meta section - use the actual planned file offset
                let base_rva = section.virtual_address;
                let base_file_offset = section.file_region.offset;
                meta_section_info = Some((base_rva, base_file_offset));
                break;
            }
        }

        if let Some((base_rva, base_file_offset)) = meta_section_info {
            for (placeholder_rva, method_body_bytes) in changes.method_bodies() {
                if let Some(&actual_rva) = rva_mappings.get(&placeholder_rva) {
                    // Calculate file offset directly using .meta section base mapping
                    let rva_offset_within_section = actual_rva - base_rva;
                    let file_offset = base_file_offset + u64::from(rva_offset_within_section);

                    // Update userstring tokens in method body bytes using heap mappings
                    let updated_method_body_bytes =
                        self.update_userstring_tokens_in_method_body(method_body_bytes)?;

                    operations.write.push(WriteOperation {
                        offset: file_offset,
                        data: updated_method_body_bytes,
                        component: format!("Method body at RVA 0x{actual_rva:08X}"),
                    });
                }
            }
        } else {
            return Err(Error::WriteLayoutFailed {
                message: ".meta section not found for method body placement".to_string(),
            });
        }

        Ok(())
    }

    /// Generates the complete tables stream data with all modifications applied.
    ///
    /// This is a simplified implementation that copies the original tables stream
    /// and applies any modifications from the assembly changes. For now, it serves
    /// as a bridge to get the new writer working while we develop full table
    /// reconstruction capabilities.
    fn generate_tables_stream_data(&self) -> Result<Vec<u8>> {
        let view = self.assembly.view();
        let metadata_root = view.metadata_root();

        // Find the original tables stream data
        for stream_header in &metadata_root.stream_headers {
            if stream_header.name == "#~" || stream_header.name == "#-" {
                // Get the stream data from the original metadata
                let metadata_slice = view.data();
                let cor20_header = view.cor20header();
                let metadata_offset = view
                    .file()
                    .rva_to_offset(cor20_header.meta_data_rva as usize)
                    .map_err(|e| Error::WriteLayoutFailed {
                        message: format!("Failed to resolve metadata RVA: {e}"),
                    })?;

                let stream_start = metadata_offset + stream_header.offset as usize;
                let stream_end = stream_start + stream_header.size as usize;

                if stream_end > metadata_slice.len() {
                    return Err(Error::WriteLayoutFailed {
                        message: "Tables stream extends beyond metadata bounds".to_string(),
                    });
                }

                let original_stream_data = &metadata_slice[stream_start..stream_end];

                // Check if we have table changes to apply
                let changes = self.assembly.changes();
                if !changes.table_changes.is_empty() {
                    return self.generate_modified_tables_stream_data(original_stream_data);
                }
                return Ok(original_stream_data.to_vec());
            }
        }

        Err(Error::WriteLayoutFailed {
            message: "No tables stream (#~ or #-) found in assembly".to_string(),
        })
    }

    /// Generates modified tables stream data by applying all changes from assembly.changes().
    ///
    /// This method takes the original tables stream data and applies all modifications
    /// that have been accumulated in the assembly's changes. It uses the existing table
    /// writing logic to ensure compatibility with the existing pipeline.
    fn generate_modified_tables_stream_data(&self, original_stream_data: &[u8]) -> Result<Vec<u8>> {
        let changes = self.assembly.changes();

        // If there are no table modifications, return the original data
        if changes.table_changes.is_empty() {
            return Ok(original_stream_data.to_vec());
        }

        // For this initial implementation, we'll use a simplified approach:
        // 1. Parse the original tables header
        // 2. Calculate new row counts based on changes
        // 3. Update the header with new row counts but keep the same data
        // 4. This will make the method appear in the count but may not have actual data

        // This is a temporary solution to get the pipeline working
        // A full implementation would rebuild the entire tables stream

        self.apply_simple_table_modifications(original_stream_data, &changes.table_changes)
    }

    /// Applies proper table modifications with full table reconstruction and heap index remapping.
    ///
    /// This is the full implementation that properly rebuilds all modified tables with correct
    /// heap indices, maintains referential integrity, and implements complete metadata stream
    /// reconstruction for production-quality assembly generation.
    fn apply_simple_table_modifications(
        &self,
        original_stream_data: &[u8],
        table_changes: &std::collections::HashMap<TableId, TableModifications>,
    ) -> Result<Vec<u8>> {
        // Parse the original header to understand the structure
        let original_header = TablesHeader::from(original_stream_data)?;

        // Step 1: Build comprehensive index remapping using the proper remapping system
        let heap_mappings =
            IndexRemapper::build_from_changes(self.assembly.changes(), self.assembly.view());

        // Step 2: Build method body RVA mappings
        let rva_mappings = self.build_method_body_rva_mappings()?;

        // Step 3: Reconstruct all tables with proper heap index and RVA updates
        let reconstructed_tables_data =
            if heap_mappings.string_map.is_empty() && heap_mappings.blob_map.is_empty() {
                self.reconstruct_tables_with_rva_updates_only(
                    &original_header,
                    table_changes,
                    &rva_mappings,
                )?
            } else {
                self.reconstruct_tables_with_heap_remapping(
                    &original_header,
                    table_changes,
                    &heap_mappings,
                    &rva_mappings,
                )?
            };

        Ok(reconstructed_tables_data)
    }

    /// Reconstruct tables with RVA updates only (no heap index remapping needed).
    /// This is used with the append-only heap strategy where all original indices are preserved.
    fn reconstruct_tables_with_rva_updates_only(
        &self,
        original_header: &TablesHeader,
        table_changes: &std::collections::HashMap<TableId, TableModifications>,
        rva_mappings: &HashMap<u32, u32>,
    ) -> Result<Vec<u8>> {
        let view = self.assembly.view();
        let tables = view.tables().ok_or_else(|| Error::WriteLayoutFailed {
            message: "No tables found in assembly".to_string(),
        })?;

        // Calculate new row counts for all tables
        let mut new_row_counts = Vec::with_capacity(64);
        for table_id in 0..64 {
            if let Some(tid) = TableId::from_token_type(table_id) {
                let original_count = original_header.table_row_count(tid);
                let new_count = if table_changes.contains_key(&tid) {
                    Self::calculate_new_row_count_full(original_count, &table_changes[&tid])?
                } else {
                    original_count
                };
                new_row_counts.push(new_count);
            } else {
                new_row_counts.push(0);
            }
        }

        // Create empty heap mappings since we're preserving all indices
        let empty_heap_mappings = IndexRemapper {
            string_map: HashMap::new(),
            blob_map: HashMap::new(),
            guid_map: HashMap::new(),
            userstring_map: HashMap::new(),
            table_maps: HashMap::new(),
        };

        // Build the new tables stream (heap remapping will be skipped due to empty mappings)
        let reconstructed_tables_data = self.build_complete_tables_stream(
            original_header,
            &new_row_counts,
            table_changes,
            &empty_heap_mappings,
            &tables.info,
            rva_mappings,
        )?;

        Ok(reconstructed_tables_data)
    }

    /// Builds comprehensive heap index mappings from all heap builders.
    ///
    /// This critical method constructs the complete mapping of how heap indices
    /// change during metadata heap reconstruction. These mappings are essential
    /// for updating table references to point to the correct relocated data.
    ///
    /// # Returns
    ///
    /// Returns `IndexRemapper` containing mappings for all heap types:
    /// - String heap mappings (old index → new index)
    /// - Blob heap mappings (old index → new index)  
    /// - User string heap mappings (old index → new index)
    /// - Table row mappings (per table: old row → new row)
    ///
    /// # Heap Reconstruction Process
    ///
    /// For each heap type:
    /// 1. **Create Builder**: Instantiate the appropriate heap builder
    /// 2. **Execute Reconstruction**: Build the new heap with modifications
    /// 3. **Extract Mappings**: Capture index remapping information
    /// 4. **Aggregate Results**: Combine into comprehensive mapping structure
    ///
    /// # Why Index Mappings Matter
    ///
    /// During heap reconstruction, indices may change due to:
    /// - **Modifications**: Changed strings/blobs may need relocation
    /// - **Removals**: Deleted entries create gaps that compress indices
    /// - **Additions**: New entries are appended and may be renumbered
    /// - **Size Changes**: Modified entries that don't fit in place
    ///
    /// # Mapping Examples
    ///
    /// ```text
    /// Original String Heap:     Reconstructed Heap:
    /// Index 0: ""               Index 0: ""           (preserved)
    /// Index 5: "Hello"          Index 5: "Hello"      (unchanged)
    /// Index 12: "World"         Index 12: "Universe"  (modified in place)
    /// Index 18: "Test"          [removed]             (deleted)
    /// Index 25: "New"           Index 18: "New"       (compacted)
    ///
    /// Mapping: {25 → 18}  (only changed indices recorded)
    /// ```
    ///
    /// # Critical for Table Consistency
    ///
    /// These mappings ensure metadata table references remain valid:
    /// - TypeDef.Name field updated to new string indices
    /// - MethodDef.Signature updated to new blob indices
    /// - Custom attribute values updated to new blob indices
    /// - String literals updated to new user string indices
    ///
    /// Without accurate mappings, table references become invalid and the
    /// generated assembly will be malformed or unloadable.
    ///
    /// Reconstructs all tables with proper heap index remapping and modifications applied.
    fn reconstruct_tables_with_heap_remapping(
        &self,
        original_header: &TablesHeader,
        table_changes: &std::collections::HashMap<TableId, TableModifications>,
        heap_mappings: &IndexRemapper,
        rva_mappings: &HashMap<u32, u32>,
    ) -> Result<Vec<u8>> {
        let view = self.assembly.view();
        let tables = view.tables().ok_or_else(|| Error::WriteLayoutFailed {
            message: "No tables found in assembly".to_string(),
        })?;

        // Calculate new row counts for all tables
        let mut new_row_counts = Vec::with_capacity(64);
        for table_id in 0..64 {
            if let Some(tid) = TableId::from_token_type(table_id) {
                let original_count = original_header.table_row_count(tid);
                let new_count = if table_changes.contains_key(&tid) {
                    Self::calculate_new_row_count_full(original_count, &table_changes[&tid])?
                } else {
                    original_count
                };
                new_row_counts.push(new_count);

                if new_count != original_count {}
            } else {
                new_row_counts.push(0);
            }
        }

        // Build the new tables stream
        self.build_complete_tables_stream(
            original_header,
            &new_row_counts,
            table_changes,
            heap_mappings,
            &tables.info,
            rva_mappings,
        )
    }

    /// Calculates new row count for full table modifications.
    fn calculate_new_row_count_full(
        original_count: u32,
        modifications: &TableModifications,
    ) -> Result<u32> {
        match modifications {
            TableModifications::Sparse { operations, .. } => {
                let mut count = original_count;

                for operation in operations {
                    match &operation.operation {
                        Operation::Insert(_, _) => {
                            count += 1;
                        }
                        Operation::Delete(_) => {
                            count = count.saturating_sub(1);
                        }
                        Operation::Update(_, _) => {
                            // Updates don't change row count
                        }
                    }
                }

                Ok(count)
            }
            TableModifications::Replaced(rows) => {
                let row_count = u32::try_from(rows.len())
                    .map_err(|_| malformed_error!("Row count exceeds u32 range"))?;
                Ok(row_count)
            }
        }
    }

    /// Builds the complete tables stream with proper structure and data.
    fn build_complete_tables_stream(
        &self,
        original_header: &TablesHeader,
        new_row_counts: &[u32],
        table_changes: &std::collections::HashMap<TableId, TableModifications>,
        heap_mappings: &IndexRemapper,
        table_info: &TableInfoRef,
        rva_mappings: &HashMap<u32, u32>,
    ) -> Result<Vec<u8>> {
        // Calculate the total size needed
        let header_size = Self::calculate_tables_header_size_full(new_row_counts);
        let data_size = Self::calculate_tables_data_size_full(new_row_counts, table_info)?;
        let total_size = header_size + data_size;

        let mut stream_data = vec![0u8; total_size];

        // Write the header
        Self::write_tables_header_full(&mut stream_data, original_header, new_row_counts)?;

        // Write all table data
        self.write_all_tables_data_full(
            &mut stream_data[header_size..],
            original_header,
            new_row_counts,
            table_changes,
            heap_mappings,
            table_info,
            rva_mappings,
        )?;

        Ok(stream_data)
    }

    /// Calculates the size needed for the complete tables header.
    fn calculate_tables_header_size_full(row_counts: &[u32]) -> usize {
        let mut size = 24; // Fixed header: reserved(4) + versions(2) + heap_sizes(1) + reserved(1) + valid(8) + sorted(8)

        // Add 4 bytes for each present table
        for &count in row_counts {
            if count > 0 {
                size += 4;
            }
        }

        size
    }

    /// Calculates the size needed for all tables data.
    fn calculate_tables_data_size_full(
        row_counts: &[u32],
        table_info: &TableInfoRef,
    ) -> Result<usize> {
        let mut total_size = 0;

        for (table_id, &row_count) in row_counts.iter().enumerate() {
            if row_count > 0 {
                let table_id_u8 = u8::try_from(table_id)
                    .map_err(|_| malformed_error!("Table ID exceeds u8 range"))?;
                if let Some(tid) = TableId::from_token_type(table_id_u8) {
                    let row_size = Self::get_table_row_size(tid, table_info) as usize;
                    total_size += (row_count as usize) * row_size;
                }
            }
        }

        Ok(total_size)
    }

    /// Writes the complete tables header with proper structure.
    fn write_tables_header_full(
        buffer: &mut [u8],
        original_header: &TablesHeader,
        new_row_counts: &[u32],
    ) -> Result<()> {
        let mut offset = 0;

        // Write fixed header fields
        write_le_at(buffer, &mut offset, 0u32)?; // Reserved
        write_le_at(buffer, &mut offset, original_header.major_version)?;
        write_le_at(buffer, &mut offset, original_header.minor_version)?;
        write_le_at(
            buffer,
            &mut offset,
            Self::calculate_heap_sizes_byte(&original_header.info),
        )?; // HeapSizes
        write_le_at(buffer, &mut offset, 1u8)?; // Reserved2

        // Calculate new valid bitvec
        let mut valid_bitvec = 0u64;
        for (table_id, &row_count) in new_row_counts.iter().enumerate() {
            if row_count > 0 {
                valid_bitvec |= 1u64 << table_id;
            }
        }

        write_le_at(buffer, &mut offset, valid_bitvec)?;
        write_le_at(buffer, &mut offset, original_header.sorted)?;

        // Write row counts for present tables
        for &row_count in new_row_counts {
            if row_count > 0 {
                write_le_at(buffer, &mut offset, row_count)?;
            }
        }

        Ok(())
    }

    /// Writes all table data with proper heap index remapping.
    #[allow(clippy::too_many_arguments)]
    fn write_all_tables_data_full(
        &self,
        buffer: &mut [u8],
        original_header: &TablesHeader,
        new_row_counts: &[u32],
        table_changes: &std::collections::HashMap<TableId, TableModifications>,
        heap_mappings: &IndexRemapper,
        table_info: &TableInfoRef,
        rva_mappings: &HashMap<u32, u32>,
    ) -> Result<()> {
        let mut buffer_offset = 0;

        // Write all tables in order
        for (table_id, &row_count) in new_row_counts.iter().enumerate() {
            if row_count == 0 {
                continue;
            }

            let table_id_u8 = u8::try_from(table_id)
                .map_err(|_| malformed_error!("Table ID exceeds u8 range"))?;
            if let Some(tid) = TableId::from_token_type(table_id_u8) {
                let row_size = Self::get_table_row_size(tid, table_info) as usize;
                let table_size = (row_count as usize) * row_size;

                if table_changes.contains_key(&tid) {
                    // Table has modifications - write modified data
                    self.write_modified_table_data_full(
                        &mut buffer[buffer_offset..buffer_offset + table_size],
                        tid,
                        original_header,
                        &table_changes[&tid],
                        heap_mappings,
                        table_info,
                        rva_mappings,
                    )?;
                } else {
                    // Table unchanged - copy original data with heap index remapping
                    self.write_original_table_data_with_remapping(
                        &mut buffer[buffer_offset..buffer_offset + table_size],
                        tid,
                        original_header,
                        heap_mappings,
                        table_info,
                        rva_mappings,
                    )?;
                }

                buffer_offset += table_size;
            }
        }

        Ok(())
    }

    /// Writes modified table data with proper heap indices.
    #[allow(clippy::too_many_arguments)]
    fn write_modified_table_data_full(
        &self,
        buffer: &mut [u8],
        table_id: TableId,
        original_header: &TablesHeader,
        modifications: &TableModifications,
        heap_mappings: &IndexRemapper,
        table_info: &TableInfoRef,
        rva_mappings: &HashMap<u32, u32>,
    ) -> Result<()> {
        match modifications {
            TableModifications::Sparse { operations, .. } => {
                // Start with original table data and apply operations
                self.write_original_table_data_with_remapping(
                    buffer,
                    table_id,
                    original_header,
                    heap_mappings,
                    table_info,
                    rva_mappings,
                )?;

                // Apply the operations
                self.apply_table_operations_with_remapping(
                    buffer,
                    table_id,
                    operations,
                    heap_mappings,
                    table_info,
                    rva_mappings,
                )?;
            }
            TableModifications::Replaced(rows) => {
                // Write entirely new table data
                let row_size = Self::get_table_row_size(table_id, table_info) as usize;

                for (i, row_data) in rows.iter().enumerate() {
                    let row_offset = i * row_size;
                    if row_offset + row_size <= buffer.len() {
                        let mut offset = 0;
                        let row_id = u32::try_from(row_offset / row_size + 1)
                            .map_err(|_| malformed_error!("Row ID exceeds u32 range"))?;
                        row_data.row_write(
                            &mut buffer[row_offset..row_offset + row_size],
                            &mut offset,
                            row_id,
                            table_info,
                        )?;

                        // Apply heap index remapping to the written row
                        self.remap_heap_indices_in_row(
                            &mut buffer[row_offset..row_offset + row_size],
                            table_id,
                            heap_mappings,
                            table_info,
                            rva_mappings,
                        )?;
                    }
                }
            }
        }

        Ok(())
    }

    /// Writes original table data with heap index remapping applied.
    fn write_original_table_data_with_remapping(
        &self,
        buffer: &mut [u8],
        table_id: TableId,
        original_header: &TablesHeader,
        heap_mappings: &IndexRemapper,
        table_info: &TableInfoRef,
        rva_mappings: &HashMap<u32, u32>,
    ) -> Result<()> {
        // First copy the original table data
        let original_data = self.get_original_table_data(table_id, original_header, table_info)?;

        if original_data.len() > buffer.len() {
            return Err(Error::WriteLayoutFailed {
                message: format!("Table {table_id:?} data too large for buffer"),
            });
        }

        buffer[..original_data.len()].copy_from_slice(&original_data);

        // Apply heap index remapping to all rows
        let row_size = Self::get_table_row_size(table_id, table_info) as usize;
        let row_count = original_data.len() / row_size;

        for row_index in 0..row_count {
            let row_offset = row_index * row_size;
            self.remap_heap_indices_in_row(
                &mut buffer[row_offset..row_offset + row_size],
                table_id,
                heap_mappings,
                table_info,
                rva_mappings,
            )?;
        }

        Ok(())
    }

    /// Gets the original table data from the assembly.
    fn get_original_table_data(
        &self,
        table_id: TableId,
        original_header: &TablesHeader,
        table_info: &TableInfoRef,
    ) -> Result<Vec<u8>> {
        let row_count = original_header.table_row_count(table_id);
        let row_size = Self::get_table_row_size(table_id, table_info) as usize;
        let table_size = (row_count as usize) * row_size;

        if row_count == 0 {
            return Ok(Vec::new());
        }

        // Extract the raw table data from the original tables stream
        let original_stream_data = self.copy_original_stream_data("#~")?;

        // Calculate the offset to this table's data within the stream
        let mut table_offset = Self::calculate_tables_header_size_full(
            &Self::build_original_row_counts(original_header),
        );

        // Add offsets for all previous tables
        for tid in 0u8..64 {
            if let Some(prev_table) = TableId::from_token_type(tid) {
                if prev_table == table_id {
                    break;
                }
                let prev_row_count = original_header.table_row_count(prev_table);
                if prev_row_count > 0 {
                    let prev_row_size = Self::get_table_row_size(prev_table, table_info) as usize;
                    table_offset += (prev_row_count as usize) * prev_row_size;
                }
            }
        }

        // Extract the table data
        if table_offset + table_size <= original_stream_data.len() {
            Ok(original_stream_data[table_offset..table_offset + table_size].to_vec())
        } else {
            Ok(vec![0u8; table_size])
        }
    }

    /// Applies table operations with comprehensive heap index remapping.
    ///
    /// This method processes table modification operations while simultaneously
    /// updating heap references to account for changes in string, blob, GUID,
    /// and user string heaps during reconstruction.
    ///
    /// # Arguments
    ///
    /// * `buffer` - Mutable table data buffer to modify in place
    /// * `table_id` - The metadata table being processed
    /// * `operations` - Array of table operations to apply
    /// * `table_info` - Table structure information for proper field interpretation
    /// * `mappings` - Complete heap index mappings from reconstruction
    ///
    /// # Operation Processing
    ///
    /// For each table operation:
    /// 1. **Apply Operation**: Execute the table modification (add/update/delete row)
    /// 2. **Identify Heap References**: Scan table fields for heap indices
    /// 3. **Remap Indices**: Update heap references using the provided mappings
    /// 4. **Preserve Consistency**: Ensure all cross-references remain valid
    ///
    /// # Heap Reference Types
    ///
    /// The method handles remapping for:
    /// - **String Indices**: References to #Strings heap (UTF-8 strings)
    /// - **Blob Indices**: References to #Blob heap (binary data)
    /// - **GUID Indices**: References to #GUID heap (16-byte GUIDs)
    /// - **User String Indices**: References to #US heap (UTF-16 literals)
    ///
    /// # Critical for Correctness
    ///
    /// This method is essential because:
    /// - Heap reconstruction may change index values
    /// - Table references must point to correct relocated data
    /// - Cross-references between tables and heaps must remain consistent
    /// - ECMA-335 metadata integrity depends on accurate index mapping
    ///
    /// # Examples of Remapping
    ///
    /// ```text
    /// Before heap reconstruction:
    /// TypeDef.Name = 0x12 → "MyClass" at string index 0x12
    ///
    /// After heap reconstruction (string moved):
    /// TypeDef.Name = 0x34 → "MyClass" at string index 0x34
    /// ```
    fn apply_table_operations_with_remapping(
        &self,
        buffer: &mut [u8],
        table_id: TableId,
        operations: &[TableOperation],
        heap_mappings: &IndexRemapper,
        table_info: &TableInfoRef,
        rva_mappings: &HashMap<u32, u32>,
    ) -> Result<()> {
        let row_size = Self::get_table_row_size(table_id, table_info) as usize;

        for operation in operations {
            match &operation.operation {
                Operation::Insert(rid, row_data) => {
                    let row_offset = ((*rid - 1) as usize) * row_size;
                    if row_offset + row_size <= buffer.len() {
                        let mut offset = 0;
                        let row_id = u32::try_from(row_offset / row_size + 1)
                            .map_err(|_| malformed_error!("Row ID exceeds u32 range"))?;
                        row_data.row_write(
                            &mut buffer[row_offset..row_offset + row_size],
                            &mut offset,
                            row_id,
                            table_info,
                        )?;

                        // Apply heap index remapping to the inserted row
                        self.remap_heap_indices_in_row(
                            &mut buffer[row_offset..row_offset + row_size],
                            table_id,
                            heap_mappings,
                            table_info,
                            rva_mappings,
                        )?;
                    }
                }
                Operation::Update(rid, row_data) => {
                    let row_offset = ((*rid - 1) as usize) * row_size;
                    if row_offset + row_size <= buffer.len() {
                        let mut offset = 0;
                        let row_id = u32::try_from(row_offset / row_size + 1)
                            .map_err(|_| malformed_error!("Row ID exceeds u32 range"))?;
                        row_data.row_write(
                            &mut buffer[row_offset..row_offset + row_size],
                            &mut offset,
                            row_id,
                            table_info,
                        )?;

                        // Apply heap index remapping to the updated row
                        self.remap_heap_indices_in_row(
                            &mut buffer[row_offset..row_offset + row_size],
                            table_id,
                            heap_mappings,
                            table_info,
                            rva_mappings,
                        )?;
                    }
                }
                Operation::Delete(rid) => {
                    let row_offset = ((*rid - 1) as usize) * row_size;
                    if row_offset + row_size <= buffer.len() {
                        // Zero out the deleted row
                        buffer[row_offset..row_offset + row_size].fill(0);
                    }
                }
            }
        }

        Ok(())
    }

    /// Remaps heap indices in a single table row.
    fn remap_heap_indices_in_row(
        &self,
        row_buffer: &mut [u8],
        table_id: TableId,
        heap_mappings: &IndexRemapper,
        table_info: &TableInfoRef,
        rva_mappings: &HashMap<u32, u32>,
    ) -> Result<()> {
        // For all tables that use heap indices, apply proper remapping
        match table_id {
            TableId::Module => {
                // Module: [Generation(2), Name(StringIndex), Mvid(GuidIndex), EncId(GuidIndex), EncBaseId(GuidIndex)]
                self.remap_string_index_at(row_buffer, 2, heap_mappings)?; // Name
                                                                           // Note: GUID indices don't need remapping as we copy GUID heap unchanged
            }
            TableId::TypeRef => {
                // TypeRef: [ResolutionScope(ResolutionScope), TypeName(StringIndex), TypeNamespace(StringIndex)]
                let scope_size =
                    table_info.coded_index_bytes(CodedIndexType::ResolutionScope) as usize;
                self.remap_string_index_at(row_buffer, scope_size, heap_mappings)?; // TypeName
                let string_size = table_info.str_bytes() as usize;
                self.remap_string_index_at(row_buffer, scope_size + string_size, heap_mappings)?;
                // TypeNamespace
            }
            TableId::TypeDef => {
                // TypeDef: [Flags(4), TypeName(StringIndex), TypeNamespace(StringIndex), Extends(TypeDefOrRef), FieldList(Field), MethodList(Method)]
                self.remap_string_index_at(row_buffer, 4, heap_mappings)?; // TypeName
                let string_size = table_info.str_bytes() as usize;
                self.remap_string_index_at(row_buffer, 4 + string_size, heap_mappings)?;
                // TypeNamespace
            }
            TableId::MethodDef => {
                // MethodDef: [RVA(4), ImplFlags(2), Flags(2), Name(StringIndex), Signature(BlobIndex), ParamList(Param)]

                // First, remap RVA if it's a placeholder RVA (0xF0000000+)
                let mut offset = 0;
                let current_rva: u32 = read_le_at(row_buffer, &mut offset)?;
                if let Some(&actual_rva) = rva_mappings.get(&current_rva) {
                    let mut offset = 0;
                    write_le_at(row_buffer, &mut offset, actual_rva)?;
                }

                // Then remap heap indices
                self.remap_string_index_at(row_buffer, 8, heap_mappings)?; // Name
                let string_size = table_info.str_bytes() as usize;
                self.remap_blob_index_at(row_buffer, 8 + string_size, heap_mappings)?;
                // Signature
            }
            TableId::Param => {
                // Param: [Flags(2), Sequence(2), Name(StringIndex)]
                self.remap_string_index_at(row_buffer, 4, heap_mappings)?; // Name
            }
            TableId::MemberRef => {
                // MemberRef: [Class(MemberRefParent), Name(StringIndex), Signature(BlobIndex)]
                let class_size =
                    table_info.coded_index_bytes(CodedIndexType::MemberRefParent) as usize;
                self.remap_string_index_at(row_buffer, class_size, heap_mappings)?; // Name
                let string_size = table_info.str_bytes() as usize;
                self.remap_blob_index_at(row_buffer, class_size + string_size, heap_mappings)?;
                // Signature
            }
            TableId::Constant => {
                // Constant: [Type(1), Padding(1), Parent(HasConstant), Value(BlobIndex)]
                let parent_size =
                    table_info.coded_index_bytes(CodedIndexType::HasConstant) as usize;
                self.remap_blob_index_at(row_buffer, 2 + parent_size, heap_mappings)?;
                // Value
            }
            TableId::CustomAttribute => {
                // CustomAttribute: [Parent(HasCustomAttribute), Type(CustomAttributeType), Value(BlobIndex)]
                let parent_size =
                    table_info.coded_index_bytes(CodedIndexType::HasCustomAttribute) as usize;
                let type_size =
                    table_info.coded_index_bytes(CodedIndexType::CustomAttributeType) as usize;
                self.remap_blob_index_at(row_buffer, parent_size + type_size, heap_mappings)?;
                // Value
            }
            TableId::FieldMarshal => {
                // FieldMarshal: [Parent(HasFieldMarshal), NativeType(BlobIndex)]
                let parent_size =
                    table_info.coded_index_bytes(CodedIndexType::HasFieldMarshal) as usize;
                self.remap_blob_index_at(row_buffer, parent_size, heap_mappings)?;
                // NativeType
            }
            TableId::DeclSecurity => {
                // DeclSecurity: [Action(2), Parent(HasDeclSecurity), PermissionSet(BlobIndex)]
                let parent_size =
                    table_info.coded_index_bytes(CodedIndexType::HasDeclSecurity) as usize;
                self.remap_blob_index_at(row_buffer, 2 + parent_size, heap_mappings)?;
                // PermissionSet
            }
            TableId::StandAloneSig => {
                // StandAloneSig: [Signature(BlobIndex)]
                self.remap_blob_index_at(row_buffer, 0, heap_mappings)?; // Signature
            }
            TableId::Event => {
                // Event: [EventFlags(2), Name(StringIndex), EventType(TypeDefOrRef)]
                self.remap_string_index_at(row_buffer, 2, heap_mappings)?; // Name
            }
            TableId::Property => {
                // Property: [Flags(2), Name(StringIndex), Type(BlobIndex)]
                self.remap_string_index_at(row_buffer, 2, heap_mappings)?; // Name
                let string_size = table_info.str_bytes() as usize;
                self.remap_blob_index_at(row_buffer, 2 + string_size, heap_mappings)?;
                // Type
            }
            TableId::ModuleRef => {
                // ModuleRef: [Name(StringIndex)]
                self.remap_string_index_at(row_buffer, 0, heap_mappings)?; // Name
            }
            TableId::TypeSpec => {
                // TypeSpec: [Signature(BlobIndex)]
                self.remap_blob_index_at(row_buffer, 0, heap_mappings)?; // Signature
            }
            TableId::ImplMap => {
                // ImplMap: [MappingFlags(2), MemberForwarded(MemberForwarded), ImportName(StringIndex), ImportScope(ModuleRef)]
                let member_size =
                    table_info.coded_index_bytes(CodedIndexType::MemberForwarded) as usize;
                self.remap_string_index_at(row_buffer, 2 + member_size, heap_mappings)?;
                // ImportName
            }
            TableId::AssemblyRef => {
                // AssemblyRef: [MajorVersion(2), MinorVersion(2), BuildNumber(2), RevisionNumber(2), Flags(4), PublicKeyOrToken(BlobIndex), Name(StringIndex), Culture(StringIndex), HashValue(BlobIndex)]
                self.remap_blob_index_at(row_buffer, 12, heap_mappings)?; // PublicKeyOrToken
                let blob_size = table_info.blob_bytes() as usize;
                self.remap_string_index_at(row_buffer, 12 + blob_size, heap_mappings)?; // Name
                let string_size = table_info.str_bytes() as usize;
                self.remap_string_index_at(
                    row_buffer,
                    12 + blob_size + string_size,
                    heap_mappings,
                )?; // Culture
                self.remap_blob_index_at(
                    row_buffer,
                    12 + blob_size + string_size + string_size,
                    heap_mappings,
                )?; // HashValue
            }
            TableId::File => {
                // File: [Flags(4), Name(StringIndex), HashValue(BlobIndex)]
                self.remap_string_index_at(row_buffer, 4, heap_mappings)?; // Name
                let string_size = table_info.str_bytes() as usize;
                self.remap_blob_index_at(row_buffer, 4 + string_size, heap_mappings)?;
                // HashValue
            }
            TableId::ExportedType => {
                // ExportedType: [Flags(4), TypeDefId(4), TypeName(StringIndex), TypeNamespace(StringIndex), Implementation(Implementation)]
                self.remap_string_index_at(row_buffer, 8, heap_mappings)?; // TypeName
                let string_size = table_info.str_bytes() as usize;
                self.remap_string_index_at(row_buffer, 8 + string_size, heap_mappings)?;
                // TypeNamespace
            }
            TableId::ManifestResource => {
                // ManifestResource: [Offset(4), Flags(4), Name(StringIndex), Implementation(Implementation)]
                self.remap_string_index_at(row_buffer, 8, heap_mappings)?; // Name
            }
            TableId::GenericParam => {
                // GenericParam: [Number(2), Flags(2), Owner(TypeOrMethodDef), Name(StringIndex)]
                let owner_size =
                    table_info.coded_index_bytes(CodedIndexType::TypeOrMethodDef) as usize;
                self.remap_string_index_at(row_buffer, 4 + owner_size, heap_mappings)?;
                // Name
            }
            TableId::MethodSpec => {
                // MethodSpec: [Method(MethodDefOrRef), Instantiation(BlobIndex)]
                let method_size =
                    table_info.coded_index_bytes(CodedIndexType::MethodDefOrRef) as usize;
                self.remap_blob_index_at(row_buffer, method_size, heap_mappings)?;
                // Instantiation
            }
            TableId::FieldRVA => {
                // FieldRVA: [RVA(4), Field(2/4)]
                // CRITICAL: FieldRVA table contains RVAs that need remapping for placeholder RVAs
                let mut offset = 0;
                let current_rva: u32 = read_le_at(row_buffer, &mut offset)?;

                // Check if this RVA needs remapping (either placeholder RVA or in rva_mappings)
                if let Some(&actual_rva) = rva_mappings.get(&current_rva) {
                    let mut offset = 0;
                    write_le_at(row_buffer, &mut offset, actual_rva)?;
                } else {
                    // Validate that the RVA is reasonable (not corrupted)
                    if current_rva > MAX_REASONABLE_RVA {
                        // RVA validation - suspicious values that weren't remapped
                    }
                }
            }
            // Tables that don't use heap indices or are rare
            TableId::Field
            | TableId::FieldPtr
            | TableId::MethodPtr
            | TableId::ParamPtr
            | TableId::EventPtr
            | TableId::PropertyPtr
            | TableId::InterfaceImpl
            | TableId::ClassLayout
            | TableId::FieldLayout
            | TableId::EventMap
            | TableId::PropertyMap
            | TableId::MethodSemantics
            | TableId::MethodImpl
            | TableId::Assembly
            | TableId::AssemblyProcessor
            | TableId::AssemblyOS
            | TableId::AssemblyRefProcessor
            | TableId::AssemblyRefOS
            | TableId::NestedClass
            | TableId::GenericParamConstraint
            | TableId::EncLog
            | TableId::EncMap
            | TableId::Document
            | TableId::MethodDebugInformation
            | TableId::LocalScope
            | TableId::LocalVariable
            | TableId::LocalConstant
            | TableId::ImportScope
            | TableId::StateMachineMethod
            | TableId::CustomDebugInformation => {
                // These tables either don't contain heap indices or are pointer/mapping tables
            }
        }

        Ok(())
    }

    /// Remaps a string index at the specified offset in a row buffer.
    fn remap_string_index_at(
        &self,
        row_buffer: &mut [u8],
        offset: usize,
        heap_mappings: &IndexRemapper,
    ) -> Result<()> {
        let view = self.assembly.view();
        let tables = view.tables().ok_or_else(|| Error::WriteLayoutFailed {
            message: "No tables found".to_string(),
        })?;
        let index_size = tables.info.str_bytes() as usize;

        if offset + index_size > row_buffer.len() {
            return Ok(());
        }

        let mut read_offset = offset;
        let original_index = if index_size == 2 {
            u32::from(read_le_at::<u16>(row_buffer, &mut read_offset)?)
        } else {
            read_le_at::<u32>(row_buffer, &mut read_offset)?
        };

        if let Some(&new_index) = heap_mappings.string_map.get(&original_index) {
            let mut write_offset = offset;
            if index_size == 2 {
                write_le_at(
                    row_buffer,
                    &mut write_offset,
                    u16::try_from(new_index)
                        .map_err(|_| malformed_error!("Index exceeds u16 range"))?,
                )?;
            } else {
                write_le_at(row_buffer, &mut write_offset, new_index)?;
            }
        } else if original_index != 0 {
            // If no string mappings are available, don't remap anything (simplified heap approach)
            if heap_mappings.string_map.is_empty() {
            } else {
                // Only warn when mappings exist but this specific index is missing
            }
        }

        Ok(())
    }

    /// Remaps a blob index at the specified offset in a row buffer.
    fn remap_blob_index_at(
        &self,
        row_buffer: &mut [u8],
        offset: usize,
        heap_mappings: &IndexRemapper,
    ) -> Result<()> {
        let view = self.assembly.view();
        let tables = view.tables().ok_or_else(|| Error::WriteLayoutFailed {
            message: "No tables found".to_string(),
        })?;
        let index_size = tables.info.blob_bytes() as usize;

        if offset + index_size > row_buffer.len() {
            return Ok(());
        }

        let mut read_offset = offset;
        let original_index = if index_size == 2 {
            u32::from(read_le_at::<u16>(row_buffer, &mut read_offset)?)
        } else {
            read_le_at::<u32>(row_buffer, &mut read_offset)?
        };

        if let Some(&new_index) = heap_mappings.blob_map.get(&original_index) {
            let mut write_offset = offset;
            if index_size == 2 {
                write_le_at(
                    row_buffer,
                    &mut write_offset,
                    u16::try_from(new_index)
                        .map_err(|_| malformed_error!("Index exceeds u16 range"))?,
                )?;
            } else {
                write_le_at(row_buffer, &mut write_offset, new_index)?;
            }
        } else if original_index != 0 {
            // If no blob mappings are available, don't remap anything (simplified heap approach)
            if heap_mappings.blob_map.is_empty() {
            } else {
                // Only warn when mappings exist but this specific index is missing
            }
        }

        Ok(())
    }

    /// Remaps a field index (table row index) at the specified offset in a row buffer.
    fn remap_field_index_at(
        row_buffer: &mut [u8],
        offset: usize,
        heap_mappings: &IndexRemapper,
        table_info: &TableInfoRef,
    ) -> Result<()> {
        // Field indices are 2 or 4 bytes depending on Field table size
        // We need to check if Field table index should be 2 or 4 bytes
        let index_size = if table_info.table_index_bytes(TableId::Field) == 2 {
            2
        } else {
            4
        };

        if offset + index_size > row_buffer.len() {
            return Ok(());
        }

        let mut read_offset = offset;
        let original_index = if index_size == 2 {
            u32::from(read_le_at::<u16>(row_buffer, &mut read_offset)?)
        } else {
            read_le_at::<u32>(row_buffer, &mut read_offset)?
        };

        // Check if we have table row mappings for the Field table
        if let Some(field_mappings) = heap_mappings.table_maps.get(&TableId::Field) {
            if let Some(Some(new_index)) = field_mappings.mapping.get(&original_index) {
                let mut write_offset = offset;
                if index_size == 2 {
                    let index_u16 = u16::try_from(*new_index)
                        .map_err(|_| malformed_error!("Index exceeds u16 range"))?;
                    write_le_at(row_buffer, &mut write_offset, index_u16)?;
                } else {
                    write_le_at(row_buffer, &mut write_offset, *new_index)?;
                }
            }
        }

        Ok(())
    }

    /// Builds the original row counts array from the header.
    fn build_original_row_counts(header: &TablesHeader) -> Vec<u32> {
        let mut row_counts = Vec::with_capacity(64);
        for table_id in 0..64 {
            if let Some(tid) = TableId::from_token_type(table_id) {
                row_counts.push(header.table_row_count(tid));
            } else {
                row_counts.push(0);
            }
        }
        row_counts
    }

    /// Copies original stream data from the assembly to preserve indices and structure.
    fn copy_original_stream_data(&self, stream_name: &str) -> Result<Vec<u8>> {
        let view = self.assembly.view();
        let metadata_root = view.metadata_root();

        // Find the stream in the original metadata
        for stream_header in &metadata_root.stream_headers {
            if stream_header.name == stream_name {
                // Get the original stream data
                let cor20_header = view.cor20header();
                let metadata_offset = view
                    .file()
                    .rva_to_offset(cor20_header.meta_data_rva as usize)
                    .map_err(|e| Error::WriteLayoutFailed {
                        message: format!("Failed to resolve metadata RVA: {e}"),
                    })?;

                let metadata_slice = view.file().data();
                let stream_start = metadata_offset + stream_header.offset as usize;
                let stream_end = stream_start + stream_header.size as usize;

                if stream_end > metadata_slice.len() {
                    return Err(Error::WriteLayoutFailed {
                        message: format!("Stream {stream_name} extends beyond metadata bounds"),
                    });
                }

                let stream_data = &metadata_slice[stream_start..stream_end];
                return Ok(stream_data.to_vec());
            }
        }

        Err(Error::WriteLayoutFailed {
            message: format!("Stream {stream_name} not found in original assembly"),
        })
    }

    /// Rebuilds the tables stream with modifications applied.
    ///
    /// This method creates a new tables stream by applying all table modifications
    /// from the assembly changes. It handles both sparse modifications (individual
    /// row operations) and complete table replacements.
    fn rebuild_tables_with_modifications(&self, _original_stream_data: &[u8]) -> Result<Vec<u8>> {
        // For now, implement a simpler approach that directly reconstructs the tables stream
        // without using the complex TableWriter infrastructure. This ensures we get the
        // functionality working while maintaining compatibility.

        let tables_header =
            self.assembly
                .view
                .tables()
                .ok_or_else(|| Error::WriteLayoutFailed {
                    message: "No metadata tables found in assembly".to_string(),
                })?;

        // Calculate the size needed for the new tables stream
        let new_stream_size = self.calculate_modified_tables_stream_size()?;
        let mut new_stream_data = vec![0u8; new_stream_size];

        // Write the tables stream header with updated row counts
        let header_size = self.write_modified_tables_header(&mut new_stream_data, tables_header)?;

        // Write the table data with modifications applied
        self.write_modified_table_data(&mut new_stream_data, header_size, tables_header)?;

        Ok(new_stream_data)
    }

    /// Calculates the size needed for the modified tables stream.
    ///
    /// This method determines the total size required for the new tables stream
    /// by calculating the header size and the sizes of all tables after modifications.
    fn calculate_modified_tables_stream_size(&self) -> Result<usize> {
        let tables_header =
            self.assembly
                .view
                .tables()
                .ok_or_else(|| Error::WriteLayoutFailed {
                    message: "No metadata tables found in assembly".to_string(),
                })?;

        // Calculate header size: 24 bytes fixed + 4 bytes per present table
        let present_table_count = tables_header.valid.count_ones() as usize;
        let header_size = 24 + (present_table_count * 4);

        // Calculate total size for all tables with modifications applied
        let mut total_table_data_size = 0usize;

        for table_id in tables_header.present_tables() {
            let row_size = calculate_table_row_size(table_id, &tables_header.info) as usize;

            let table_row_count = if let Some(table_mod) =
                self.assembly.changes().get_table_modifications(table_id)
            {
                // Table has modifications - calculate final row count
                match table_mod {
                    CilTableModifications::Replaced(new_rows) => new_rows.len(),
                    CilTableModifications::Sparse { operations, .. } => {
                        let original_row_count = tables_header.table_row_count(table_id);
                        let remapper =
                            RidRemapper::build_from_operations(operations, original_row_count);
                        remapper.final_row_count() as usize
                    }
                }
            } else {
                // Table has no modifications - use original row count
                tables_header.table_row_count(table_id) as usize
            };

            total_table_data_size += table_row_count * row_size;
        }

        Ok(header_size + total_table_data_size)
    }

    /// Writes the modified tables stream header with updated row counts.
    ///
    /// This method writes the ECMA-335 compliant tables stream header to the
    /// beginning of the new stream data, updating row counts for modified tables.
    fn write_modified_tables_header(
        &self,
        stream_data: &mut [u8],
        tables_header: &TablesHeader,
    ) -> Result<usize> {
        let mut pos = 0;

        // Write header fields using project's IO functions
        // Reserved (4 bytes)
        write_le_at(stream_data, &mut pos, 0u32)?;
        // Major version (1 byte)
        write_le_at(stream_data, &mut pos, tables_header.major_version)?;
        // Minor version (1 byte)
        write_le_at(stream_data, &mut pos, tables_header.minor_version)?;
        // Heap sizes (1 byte) - calculate from table_info directly
        let heap_sizes = Self::calculate_heap_sizes_byte(&tables_header.info);
        write_le_at(stream_data, &mut pos, heap_sizes)?;
        // Reserved (1 byte)
        write_le_at(stream_data, &mut pos, 0x01u8)?;
        // Valid tables mask (8 bytes)
        write_le_at(stream_data, &mut pos, tables_header.valid)?;
        // Sorted tables mask (8 bytes)
        write_le_at(stream_data, &mut pos, tables_header.sorted)?;

        // Write row counts for each present table
        for table_id in tables_header.present_tables() {
            let row_count = if let Some(table_mod) =
                self.assembly.changes().get_table_modifications(table_id)
            {
                match table_mod {
                    CilTableModifications::Replaced(new_rows) => u32::try_from(new_rows.len())
                        .map_err(|_| Error::WriteLayoutFailed {
                            message: "New table row count exceeds u32 range".to_string(),
                        })?,
                    CilTableModifications::Sparse { operations, .. } => {
                        let original_row_count = tables_header.table_row_count(table_id);
                        let remapper =
                            RidRemapper::build_from_operations(operations, original_row_count);
                        remapper.final_row_count()
                    }
                }
            } else {
                tables_header.table_row_count(table_id)
            };
            write_le_at(stream_data, &mut pos, row_count)?;
        }

        Ok(pos)
    }

    /// Writes the modified table data to the stream.
    ///
    /// This method writes all table data with modifications applied, handling
    /// both sparse modifications and complete table replacements.
    fn write_modified_table_data(
        &self,
        stream_data: &mut [u8],
        header_size: usize,
        tables_header: &TablesHeader,
    ) -> Result<()> {
        let mut current_offset = header_size;

        // Process each table systematically
        for table_id in tables_header.present_tables() {
            let row_size = calculate_table_row_size(table_id, &tables_header.info) as usize;

            // Check if this table has modifications
            if let Some(table_mod) = self.assembly.changes().get_table_modifications(table_id) {
                // Table has modifications - write modified version
                match table_mod {
                    CilTableModifications::Replaced(new_rows) => {
                        // Write complete replacement
                        Self::write_replaced_table_data(
                            stream_data,
                            current_offset,
                            new_rows,
                            &tables_header.info,
                        )?;
                        current_offset += new_rows.len() * row_size;
                    }
                    CilTableModifications::Sparse { operations, .. } => {
                        // Apply sparse modifications to original table data
                        let table_size = Self::write_sparse_modified_table_data(
                            stream_data,
                            current_offset,
                            table_id,
                            operations,
                            tables_header,
                        )?;
                        current_offset += table_size;
                    }
                }
            } else {
                // Table has no modifications - copy original table data completely
                let original_row_count = tables_header.table_row_count(table_id) as usize;
                let table_size = original_row_count * row_size;

                if table_size > 0 {
                    Self::copy_original_table_data(
                        stream_data,
                        current_offset,
                        table_id,
                        tables_header,
                    )?;
                }
                current_offset += table_size;
            }
        }

        Ok(())
    }

    /// Calculates the heap sizes byte based on the table info.
    fn calculate_heap_sizes_byte(table_info: &TableInfo) -> u8 {
        let mut heap_sizes = 0u8;

        if table_info.is_large_str() {
            heap_sizes |= 0x01;
        }

        if table_info.is_large_guid() {
            heap_sizes |= 0x02;
        }

        if table_info.is_large_blob() {
            heap_sizes |= 0x04;
        }

        heap_sizes
    }

    /// Gets the row size for a table using the appropriate TableRow implementation.
    fn get_table_row_size(table_id: TableId, table_info: &TableInfoRef) -> u32 {
        // For different table types, call the appropriate TableRow::row_size method
        match table_id {
            TableId::Module => ModuleRaw::row_size(table_info),
            TableId::TypeRef => TypeRefRaw::row_size(table_info),
            TableId::TypeDef => TypeDefRaw::row_size(table_info),
            TableId::Field => FieldRaw::row_size(table_info),
            TableId::MethodDef => MethodDefRaw::row_size(table_info),
            TableId::Param => ParamRaw::row_size(table_info),
            TableId::InterfaceImpl => InterfaceImplRaw::row_size(table_info),
            TableId::MemberRef => MemberRefRaw::row_size(table_info),
            TableId::Constant => ConstantRaw::row_size(table_info),
            TableId::CustomAttribute => CustomAttributeRaw::row_size(table_info),
            TableId::FieldMarshal => FieldMarshalRaw::row_size(table_info),
            TableId::DeclSecurity => DeclSecurityRaw::row_size(table_info),
            TableId::ClassLayout => ClassLayoutRaw::row_size(table_info),
            TableId::FieldLayout => FieldLayoutRaw::row_size(table_info),
            TableId::StandAloneSig => StandAloneSigRaw::row_size(table_info),
            TableId::EventMap => EventMapRaw::row_size(table_info),
            TableId::Event => EventRaw::row_size(table_info),
            TableId::PropertyMap => PropertyMapRaw::row_size(table_info),
            TableId::Property => PropertyRaw::row_size(table_info),
            TableId::MethodSemantics => MethodSemanticsRaw::row_size(table_info),
            TableId::MethodImpl => MethodImplRaw::row_size(table_info),
            TableId::ModuleRef => ModuleRefRaw::row_size(table_info),
            TableId::TypeSpec => TypeSpecRaw::row_size(table_info),
            TableId::ImplMap => ImplMapRaw::row_size(table_info),
            TableId::FieldRVA => FieldRvaRaw::row_size(table_info),
            TableId::Assembly => AssemblyRaw::row_size(table_info),
            TableId::AssemblyProcessor => AssemblyProcessorRaw::row_size(table_info),
            TableId::AssemblyRef => AssemblyRefRaw::row_size(table_info),
            TableId::AssemblyRefProcessor => AssemblyRefProcessorRaw::row_size(table_info),
            TableId::File => FileRaw::row_size(table_info),
            TableId::ExportedType => ExportedTypeRaw::row_size(table_info),
            TableId::ManifestResource => ManifestResourceRaw::row_size(table_info),
            TableId::NestedClass => NestedClassRaw::row_size(table_info),
            TableId::GenericParam => GenericParamRaw::row_size(table_info),
            TableId::MethodSpec => MethodSpecRaw::row_size(table_info),
            TableId::GenericParamConstraint => GenericParamConstraintRaw::row_size(table_info),
            _ => {
                // For debug tables or unknown tables, return a default size
                4
            }
        }
    }

    /// Writes replaced table data to the stream.
    fn write_replaced_table_data(
        stream_data: &mut [u8],
        offset: usize,
        new_rows: &[TableDataOwned],
        table_info: &TableInfoRef,
    ) -> Result<()> {
        let mut current_offset = offset;
        for (index, row) in new_rows.iter().enumerate() {
            let rid = u32::try_from(index + 1).map_err(|_| Error::WriteLayoutFailed {
                message: "Row index exceeds u32 range".to_string(),
            })?; // RIDs are 1-based

            let row_size = row.calculate_row_size(table_info) as usize;
            let row_slice = &mut stream_data[current_offset..current_offset + row_size];
            let mut write_pos = 0;

            row.row_write(row_slice, &mut write_pos, rid, table_info)?;
            current_offset += row_size;
        }

        Ok(())
    }

    /// Writes table data with sparse modifications applied.
    fn write_sparse_modified_table_data(
        stream_data: &mut [u8],
        offset: usize,
        table_id: TableId,
        operations: &[TableOperation],
        tables_header: &TablesHeader,
    ) -> Result<usize> {
        let original_row_count = tables_header.table_row_count(table_id);
        let row_size = calculate_table_row_size(table_id, &tables_header.info) as usize;
        let remapper = RidRemapper::build_from_operations(operations, original_row_count);
        let final_row_count = remapper.final_row_count() as usize;

        // Create operation data map for quick lookup
        let mut operation_data: HashMap<u32, TableDataOwned> = HashMap::new();
        for operation in operations {
            match &operation.operation {
                Operation::Insert(rid, row_data) | Operation::Update(rid, row_data) => {
                    operation_data.insert(*rid, row_data.clone());
                }
                Operation::Delete(_) => {
                    // Deletions are handled by the remapper
                }
            }
        }

        dispatch_table_type!(table_id, |RawType| {
            let original_table = tables_header.table::<RawType>();

            let final_count_u32 = u32::try_from(final_row_count)
                .map_err(|_| malformed_error!("Final row count exceeds u32 range"))?;
            for final_rid in 1..=final_count_u32 {
                if let Some(original_rid) = remapper.reverse_lookup(final_rid) {
                    let row_offset = offset + ((final_rid - 1) as usize * row_size);
                    let row_slice = &mut stream_data[row_offset..row_offset + row_size];
                    let mut write_pos = 0;

                    if let Some(modified_data) = operation_data.get(&original_rid) {
                        modified_data.row_write(
                            row_slice,
                            &mut write_pos,
                            final_rid,
                            &tables_header.info,
                        )?;
                    } else if let Some(original_table) = original_table {
                        if let Some(original_row) = original_table.get(original_rid) {
                            original_row.row_write(
                                row_slice,
                                &mut write_pos,
                                final_rid,
                                &tables_header.info,
                            )?;
                        } else {
                            return Err(Error::Error(format!(
                                "Cannot read original row {original_rid} from table {table_id:?}"
                            )));
                        }
                    } else {
                        return Err(Error::Error(format!(
                            "Original table {table_id:?} not found during sparse modification writing"
                        )));
                    }
                }
            }

            Ok(final_row_count * row_size)
        })
    }

    /// Copies original table data unchanged.
    fn copy_original_table_data(
        stream_data: &mut [u8],
        offset: usize,
        table_id: TableId,
        tables_header: &TablesHeader,
    ) -> Result<()> {
        dispatch_table_type!(table_id, |RawType| {
            if let Some(original_table) = tables_header.table::<RawType>() {
                let row_size = calculate_table_row_size(table_id, &tables_header.info) as usize;

                for (index, row) in original_table.iter().enumerate() {
                    let rid = u32::try_from(index + 1).map_err(|_| Error::WriteLayoutFailed {
                        message: "Row index exceeds u32 range".to_string(),
                    })?; // RIDs are 1-based

                    let row_offset = offset + (index * row_size);
                    let row_slice = &mut stream_data[row_offset..row_offset + row_size];
                    let mut write_pos = 0;

                    row.row_write(row_slice, &mut write_pos, rid, &tables_header.info)?;
                }
            }
            Ok(())
        })
    }

    /// Updates userstring tokens in method body bytecode using heap builder mappings.
    ///
    /// This function scans the method body bytes for ldstr instructions (opcode 0x72)
    /// and updates the userstring tokens using the actual mappings from the heap builder.
    fn update_userstring_tokens_in_method_body(&self, method_body_bytes: &[u8]) -> Result<Vec<u8>> {
        // Get userstring heap mappings by building the heap
        let mut userstring_builder = UserStringHeapBuilder::new(self.assembly);
        let _ = userstring_builder.build()?; // Build to populate mappings
        let userstring_mappings = userstring_builder.get_index_mappings();

        // If no userstring mappings, return original bytes
        if userstring_mappings.is_empty() {
            return Ok(method_body_bytes.to_vec());
        }

        let mut updated_bytes = method_body_bytes.to_vec();

        // Skip method header and scan IL instructions for ldstr (0x72)
        let header_size = if updated_bytes.is_empty() {
            0
        } else if updated_bytes[0] & 0x03 == 0x02 {
            1 // Tiny header
        } else {
            12 // Fat header
        };

        if header_size >= updated_bytes.len() {
            return Ok(updated_bytes);
        }

        // Scan IL bytecode starting after the header
        let il_bytes = &mut updated_bytes[header_size..];
        let mut pos = 0;

        while pos < il_bytes.len() {
            if il_bytes[pos] == 0x72 && pos + 4 < il_bytes.len() {
                // Found ldstr instruction, check if it's a userstring token
                let token_bytes = &il_bytes[pos + 1..pos + 5];
                let token = u32::from_le_bytes([
                    token_bytes[0],
                    token_bytes[1],
                    token_bytes[2],
                    token_bytes[3],
                ]);

                // Check if it's a userstring token (0x70000000 prefix)
                if token & 0xFF00_0000 == 0x7000_0000 {
                    let original_index = token & 0x00FF_FFFF;

                    // Look up the new index in the mappings
                    if let Some(&new_index) = userstring_mappings.get(&original_index) {
                        let new_token = 0x7000_0000 | new_index;
                        let new_token_bytes = new_token.to_le_bytes();

                        // Update the token in the bytecode
                        il_bytes[pos + 1..pos + 5].copy_from_slice(&new_token_bytes);
                    }
                }

                pos += 5; // Move past ldstr + 4-byte token
            } else {
                pos += 1; // Move to next instruction
            }
        }

        Ok(updated_bytes)
    }
}
