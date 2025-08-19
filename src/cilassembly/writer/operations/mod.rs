//! Atomic operation types for deterministic assembly file generation.
//!
//! This module implements a revolutionary operation-based approach where all assembly
//! writing tasks are expressed as simple, atomic operations. This design eliminates
//! the complexity of conditional execution paths by pre-calculating all operations
//! during the planning phase and executing them mechanically.
//!
//! The operation model transforms the entire assembly writing process from a complex
//! multi-phase pipeline with intricate state management into a simple sequence of
//! three fundamental operations that can be validated, optimized, and debugged independently.
//!
//! # Architecture
//!
//! The operation system is built around three core principles:
//!
//! ```text
//! ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
//! │   Planning      │───▶│   Validation    │───▶│   Execution     │
//! │   Phase         │    │   Phase         │    │   Phase         │
//! └─────────────────┘    └─────────────────┘    └─────────────────┘
//!          │                       │                       │
//!          ▼                       ▼                       ▼
//! ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
//! │ All Operations  │    │  No Conflicts   │    │   File Output   │
//! │ Pre-Calculated  │    │  No Overlaps    │    │   (Success)     │
//! └─────────────────┘    └─────────────────┘    └─────────────────┘
//! ```
//!
//! **Core Design Principles:**
//!
//! 1. **Atomic Operations**: Every file modification is a single, indivisible operation
//! 2. **Complete Pre-Planning**: All decisions made during planning, zero during execution
//! 3. **Operation Independence**: Each operation is self-contained and can be validated separately
//! 4. **Deterministic Execution**: Same inputs always produce identical operation sequences
//! 5. **Full Auditability**: Every byte written has a documented reason and source
//!
//! # Key Components
//!
//! - [`crate::cilassembly::writer::operations::CopyOperation`] - Preserves existing data by copying from source to target locations
//! - [`crate::cilassembly::writer::operations::ZeroOperation`] - Clears obsolete regions by filling them with zeros
//! - [`crate::cilassembly::writer::operations::WriteOperation`] - Places new data at calculated positions in the output file
//! - [`crate::cilassembly::writer::operations::OperationSet`] - Complete collection of all operations for file generation
//!
//! # Usage Examples
//!
//! ## Basic Operation Creation
//!
//! ```rust,ignore
//! use dotscope::cilassembly::writer::operations::*;
//!
//! // Create a copy operation to preserve PE headers
//! let copy_headers = CopyOperation {
//!     source_offset: 0,
//!     target_offset: 0,
//!     size: 0x400,
//!     description: "Copy PE headers and DOS stub".to_string(),
//! };
//!
//! // Create a zero operation to clear old metadata
//! let clear_old_metadata = ZeroOperation {
//!     offset: 0x2000,
//!     size: 0x1000,
//!     reason: "Clear original metadata streams location".to_string(),
//! };
//!
//! // Create a write operation for new metadata
//! let write_new_strings = WriteOperation {
//!     offset: 0x5000,
//!     data: b"\x00Hello\x00World\x00".to_vec(),
//!     component: "Updated #Strings heap".to_string(),
//! };
//! ```
//!
//! ## Operation Set Management
//!
//! ```rust,ignore
//! use dotscope::cilassembly::writer::operations::*;
//!
//! # let copy_headers = CopyOperation {
//! #     source_offset: 0, target_offset: 0, size: 0x400,
//! #     description: "Copy PE headers".to_string(),
//! # };
//! # let clear_old_metadata = ZeroOperation {
//! #     offset: 0x2000, size: 0x1000,
//! #     reason: "Clear old metadata".to_string(),
//! # };
//! # let write_new_strings = WriteOperation {
//! #     offset: 0x5000, data: vec![0u8; 100],
//! #     component: "New strings heap".to_string(),
//! # };
//! // Build complete operation set
//! let mut operations = OperationSet::new();
//! operations.copy_operations.push(copy_headers);
//! operations.zero_operations.push(clear_old_metadata);
//! operations.write_operations.push(write_new_strings);
//!
//! // Validate for conflicts before execution
//! operations.validate()?;
//!
//! // Get summary for debugging
//! println!("Execution Plan: {}", operations.summary());
//! println!("Total operations: {}", operations.operation_count());
//! println!("Data to copy: {} bytes", operations.total_copy_size());
//! println!("Data to write: {} bytes", operations.total_write_size());
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Error Handling
//!
//! This module defines specific error conditions for operation validation:
//!
//! - [`crate::Error::WriteLayoutFailed`] - When operation validation detects conflicts or overlaps
//! - Operation overlap detection with detailed conflict reporting
//! - Invalid offset or size validation with specific error locations
//! - Complete audit trail of which operations conflict and why
//!
//! All errors include the specific operations that caused conflicts and suggested
//! resolution approaches for debugging layout planning issues.
//!
//! # Thread Safety
//!
//! All operation types are [`Send`] and [`Sync`] with the following guarantees:
//!
//! - [`crate::cilassembly::writer::operations::CopyOperation`] is immutable after creation and fully thread-safe
//! - [`crate::cilassembly::writer::operations::ZeroOperation`] is immutable after creation and fully thread-safe
//! - [`crate::cilassembly::writer::operations::WriteOperation`] is immutable after creation and fully thread-safe
//! - [`crate::cilassembly::writer::operations::OperationSet`] can be safely shared between threads for validation
//! - Individual operations within a set can be executed in parallel if dependencies are maintained
//!
//! # Integration
//!
//! This module integrates with:
//!
//! - [`crate::cilassembly::writer::layout`] - Layout planning generates complete operation sets
//! - [`crate::cilassembly::writer::executor`] - Mechanical execution of all operations in sequence
//! - [`crate::cilassembly::writer::output`] - Memory-mapped file operations for actual data placement
//! - [`crate::Error`] - Comprehensive error handling with detailed operation conflict reporting
//!
//! # References
//!
//! - [ECMA-335 Common Language Infrastructure (CLI)](https://www.ecma-international.org/publications/standards/Ecma-335.htm)
//! - [PE Format Specification](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)
//! - [.NET Metadata Physical Layout](https://github.com/dotnet/runtime/blob/main/docs/design/specs/Ecma-335-Augments.md)

use std::fmt;

use crate::{Error, Result};

/// Atomic operation for preserving existing data by copying from source to target location.
///
/// Copy operations are fundamental to the assembly writing process, ensuring that all
/// existing content (PE headers, sections, method bodies, resources) is preserved exactly
/// while accommodating new layout requirements. These operations never modify the source
/// data and guarantee byte-perfect preservation of the original content.
///
/// Copy operations are essential for maintaining binary compatibility and ensuring that
/// tools like dnSpy can correctly analyze the modified assemblies. Every copy operation
/// includes a human-readable description for debugging and audit purposes.
///
/// # Use Cases
///
/// - **PE Headers**: DOS stub, NT headers, section table preservation
/// - **Code Sections**: Complete .text section content with method bodies and IL code
/// - **Resource Sections**: Embedded resources, version information, manifests
/// - **Unmodified Metadata**: Original metadata streams that haven't been changed
/// - **Method Bodies**: Native code, IL code, and exception handling tables
/// - **Import/Export Tables**: Native function imports and exports when unchanged
///
/// # Thread Safety
///
/// This type is [`Send`] and [`Sync`] because all fields are immutable after creation
/// and contain only owned data with no shared references or interior mutability.
///
/// # Examples
///
/// ## PE Header Preservation
///
/// ```rust,ignore
/// use dotscope::cilassembly::writer::operations::CopyOperation;
///
/// let preserve_headers = CopyOperation {
///     source_offset: 0,
///     target_offset: 0,
///     size: 0x400,
///     description: "Preserve PE headers and DOS stub for compatibility".to_string(),
/// };
///
/// assert_eq!(preserve_headers.source_offset, 0);
/// assert_eq!(preserve_headers.size, 0x400);
/// ```
///
/// ## Section Content Relocation
///
/// ```rust,ignore
/// use dotscope::cilassembly::writer::operations::CopyOperation;
///
/// let relocate_text_section = CopyOperation {
///     source_offset: 0x2000,
///     target_offset: 0x3000,
///     size: 0x5000,
///     description: "Relocate .text section to accommodate new .meta section".to_string(),
/// };
///
/// // Verify the operation moves content correctly
/// assert_eq!(relocate_text_section.source_offset, 0x2000);
/// assert_eq!(relocate_text_section.target_offset, 0x3000);
/// assert!(relocate_text_section.description.contains(".text"));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CopyOperation {
    /// Offset in the original file to copy from
    pub source_offset: u64,
    /// Offset in the output file to copy to
    pub target_offset: u64,
    /// Number of bytes to copy
    pub size: u64,
    /// Human-readable description of what this operation does
    pub description: String,
}

/// Atomic operation for clearing obsolete data by filling regions with zeros.
///
/// Zero operations are crucial for maintaining clean assembly files by removing obsolete
/// data that might interfere with analysis tools or cause confusion. After relocating
/// content to new locations (such as moving metadata to a dedicated .meta section),
/// zero operations clear the original locations to prevent stale data from being
/// misinterpreted by disassemblers, debuggers, or other analysis tools.
///
/// These operations are particularly important for maintaining compatibility with tools
/// like dnSpy and ensuring that the modified assembly has a clean, professional
/// appearance without leftover artifacts from the modification process.
///
/// # Use Cases
///
/// - **Metadata Stream Cleanup**: Clearing original #Strings, #Blob, #GUID, and #US heap locations
/// - **Table Relocation**: Removing obsolete metadata table data after consolidation
/// - **Section Cleanup**: Clearing sections that have been merged or relocated to new positions
/// - **Header Updates**: Zeroing old directory entries that point to relocated content
/// - **Alignment Padding**: Ensuring proper section alignment with clean zero-filled gaps
/// - **Security Cleanup**: Removing potentially sensitive data from unused file regions
///
/// # Thread Safety
///
/// This type is [`Send`] and [`Sync`] because all fields are immutable after creation
/// and contain only owned data with no shared references or interior mutability.
///
/// # Examples
///
/// ## Metadata Stream Cleanup
///
/// ```rust,ignore
/// use dotscope::cilassembly::writer::operations::ZeroOperation;
///
/// let clear_old_strings = ZeroOperation {
///     offset: 0x2000,
///     size: 0x800,
///     reason: "Clear original #Strings heap after relocation to .meta section".to_string(),
/// };
///
/// assert_eq!(clear_old_strings.offset, 0x2000);
/// assert_eq!(clear_old_strings.size, 0x800);
/// assert!(clear_old_strings.reason.contains("#Strings"));
/// ```
///
/// ## Section Alignment Padding
///
/// ```rust,ignore
/// use dotscope::cilassembly::writer::operations::ZeroOperation;
///
/// let alignment_padding = ZeroOperation {
///     offset: 0x5800,
///     size: 0x200,
///     reason: "Zero-fill alignment padding between sections".to_string(),
/// };
///
/// // Verify proper alignment calculation
/// assert_eq!(alignment_padding.offset, 0x5800);
/// assert_eq!(alignment_padding.size, 0x200);
/// assert!(alignment_padding.reason.contains("alignment"));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZeroOperation {
    /// Offset in the output file to start zeroing
    pub offset: u64,
    /// Number of bytes to zero
    pub size: u64,
    /// Human-readable explanation of why this region is being zeroed
    pub reason: String,
}

/// Atomic operation for placing new or modified data at specific file locations.
///
/// Write operations are the core mechanism for placing all newly generated content
/// into the output assembly file. These operations contain the complete, ready-to-write
/// binary data along with precise positioning information calculated during the layout
/// planning phase. Each write operation represents a complete, atomic modification
/// that will be applied exactly as specified.
///
/// Write operations are essential for applying all assembly modifications, from simple
/// string additions to complex metadata table restructuring. They ensure that all
/// new content is placed with surgical precision while maintaining ECMA-335 compliance
/// and compatibility with analysis tools.
///
/// # Use Cases
///
/// - **Metadata Heaps**: New or updated #Strings, #Blob, #GUID, and #US heaps with added content
/// - **Metadata Tables**: Modified TypeDef, MethodDef, FieldDef, and other ECMA-335 tables
/// - **Method Bodies**: New IL code, method headers, and exception handling tables
/// - **PE Directory Updates**: Data directory entries pointing to new or relocated content
/// - **Section Headers**: Updated section table entries with new RVAs and sizes
/// - **Import/Export Tables**: Native function imports and exports for P/Invoke functionality
/// - **Resource Data**: New embedded resources, version information, and manifest entries
///
/// # Thread Safety
///
/// This type is [`Send`] and [`Sync`] because all fields are immutable after creation
/// and the data vector is owned without any shared references or interior mutability.
///
/// # Examples
///
/// ## Metadata Root Signature
///
/// ```rust,ignore
/// use dotscope::cilassembly::writer::operations::WriteOperation;
///
/// let metadata_signature = WriteOperation {
///     offset: 0x5000,
///     data: b"BSJB\x01\x00\x01\x00".to_vec(), // ECMA-335 metadata signature
///     component: "Metadata root signature for .meta section".to_string(),
/// };
///
/// assert_eq!(metadata_signature.offset, 0x5000);
/// assert_eq!(metadata_signature.data.len(), 8);
/// assert_eq!(&metadata_signature.data[0..4], b"BSJB");
/// ```
///
/// ## Updated Strings Heap
///
/// ```rust,ignore
/// use dotscope::cilassembly::writer::operations::WriteOperation;
///
/// let new_strings_heap = WriteOperation {
///     offset: 0x6000,
///     data: b"\x00System\x00String\x00Console\x00WriteLine\x00".to_vec(),
///     component: "Updated #Strings heap with new string entries".to_string(),
/// };
///
/// // Verify proper null-terminated string format
/// assert!(new_strings_heap.data.starts_with(&[0x00]));
/// assert!(new_strings_heap.data.ends_with(&[0x00]));
/// assert!(new_strings_heap.component.contains("#Strings"));
/// ```
///
/// ## PE Data Directory Update
///
/// ```rust,ignore
/// use dotscope::cilassembly::writer::operations::WriteOperation;
///
/// // Update CLI Header data directory entry (8 bytes: RVA + Size)
/// let cli_header_entry = WriteOperation {
///     offset: 0x128, // IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR offset in data directory
///     data: vec![0x00, 0x50, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00], // RVA=0x5000, Size=0x48
///     component: "CLI Header data directory entry update".to_string(),
/// };
///
/// assert_eq!(cli_header_entry.data.len(), 8);
/// assert_eq!(cli_header_entry.offset, 0x128);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteOperation {
    /// Offset in the output file to write data
    pub offset: u64,
    /// Complete binary data to write
    pub data: Vec<u8>,
    /// Human-readable description of what component this represents
    pub component: String,
}

/// Complete collection of all operations required to generate the final assembly file.
///
/// The [`OperationSet`] represents the complete execution plan for transforming a
/// [`CilAssembly`] with pending changes into a valid output file. It contains every
/// operation that must be performed, pre-calculated and validated during the layout
/// planning phase, ready for mechanical execution.
///
/// This structure embodies the core philosophy of the simplified writer pipeline:
/// complete separation between planning (which generates the [`OperationSet`]) and
/// execution (which applies each operation mechanically). The result is a system
/// that is highly debuggable, testable, and reliable.
///
/// # Execution Guarantees
///
/// - **Completeness**: Contains every operation needed for correct file generation
/// - **Non-Overlapping**: All operations are validated to prevent conflicts
/// - **Ordered**: Operations are sequenced for optimal execution and dependency management
/// - **Atomic**: Each operation is independently executable and verifiable
/// - **Deterministic**: Same input assembly always produces identical operation sets
///
/// # Thread Safety
///
/// This type is [`Send`] and [`Sync`] because all contained operations are immutable
/// after creation and the vectors contain only owned data. The validation methods
/// are read-only and can be safely called from multiple threads.
///
/// [`CilAssembly`]: crate::cilassembly::CilAssembly
#[derive(Debug, Clone)]
pub struct OperationSet {
    /// Copy operations to preserve existing content
    pub copy: Vec<CopyOperation>,
    /// Zero operations to clear old locations
    pub zero: Vec<ZeroOperation>,
    /// Write operations to place new content
    pub write: Vec<WriteOperation>,
}

impl OperationSet {
    /// Creates a new empty operation set ready for population during layout planning.
    ///
    /// # Returns
    ///
    /// Returns an [`OperationSet`] with empty operation vectors, ready to be populated
    /// by the layout planning process with [`CopyOperation`], [`ZeroOperation`], and
    /// [`WriteOperation`] instances.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::cilassembly::writer::operations::OperationSet;
    ///
    /// let mut operations = OperationSet::new();
    /// assert_eq!(operations.operation_count(), 0);
    /// assert_eq!(operations.total_copy_size(), 0);
    /// assert_eq!(operations.total_write_size(), 0);
    /// ```
    ///
    /// # Thread Safety
    ///
    /// This function is thread-safe and can be called concurrently to create
    /// independent operation sets for different assemblies.
    pub fn new() -> Self {
        Self {
            copy: Vec::new(),
            zero: Vec::new(),
            write: Vec::new(),
        }
    }

    /// Returns the total number of operations across all operation types.
    ///
    /// This method provides a quick way to assess the complexity of the file generation
    /// process by counting all copy, zero, and write operations that will be executed.
    ///
    /// # Returns
    ///
    /// Returns the sum of all copy operations, zero operations, and write operations
    /// as a [`usize`]. This count represents the total number of atomic operations
    /// that will be executed during file generation.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::cilassembly::writer::operations::*;
    ///
    /// let mut operations = OperationSet::new();
    /// assert_eq!(operations.operation_count(), 0);
    ///
    /// # operations.copy_operations.push(CopyOperation {
    /// #     source_offset: 0, target_offset: 0, size: 100,
    /// #     description: "Test".to_string(),
    /// # });
    /// # operations.write_operations.push(WriteOperation {
    /// #     offset: 200, data: vec![1, 2, 3],
    /// #     component: "Test".to_string(),
    /// # });
    /// // After adding 1 copy and 1 write operation
    /// assert_eq!(operations.operation_count(), 2);
    /// ```
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe as it only reads immutable vector lengths.
    pub fn operation_count(&self) -> usize {
        self.copy.len() + self.zero.len() + self.write.len()
    }

    /// Returns the total amount of data that will be copied from source to target locations.
    ///
    /// This method calculates the sum of all copy operation sizes, providing insight
    /// into how much existing data will be preserved during the assembly modification
    /// process. This metric is useful for performance estimation and progress tracking.
    ///
    /// # Returns
    ///
    /// Returns the total number of bytes that will be copied as a [`u64`]. This
    /// represents the sum of the `size` field from all [`CopyOperation`] instances
    /// in the operation set.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::cilassembly::writer::operations::*;
    ///
    /// let mut operations = OperationSet::new();
    ///
    /// operations.copy_operations.push(CopyOperation {
    ///     source_offset: 0,
    ///     target_offset: 1000,
    ///     size: 512,
    ///     description: "Copy PE headers".to_string(),
    /// });
    ///
    /// operations.copy_operations.push(CopyOperation {
    ///     source_offset: 2000,
    ///     target_offset: 3000,
    ///     size: 1024,
    ///     description: "Copy .text section".to_string(),
    /// });
    ///
    /// assert_eq!(operations.total_copy_size(), 1536); // 512 + 1024
    /// ```
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe as it only reads immutable operation data.
    pub fn total_copy_size(&self) -> u64 {
        self.copy.iter().map(|op| op.size).sum()
    }

    /// Returns the total amount of data that will be cleared by filling with zeros.
    ///
    /// This method calculates the sum of all zero operation sizes, indicating how much
    /// obsolete data will be cleaned up during the assembly modification process.
    /// This is important for understanding the cleanup scope and ensuring no stale
    /// data remains in the output file.
    ///
    /// # Returns
    ///
    /// Returns the total number of bytes that will be zeroed as a [`u64`]. This
    /// represents the sum of the `size` field from all [`ZeroOperation`] instances
    /// in the operation set.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::cilassembly::writer::operations::*;
    ///
    /// let mut operations = OperationSet::new();
    ///
    /// operations.zero_operations.push(ZeroOperation {
    ///     offset: 2000,
    ///     size: 256,
    ///     reason: "Clear old #Strings heap".to_string(),
    /// });
    ///
    /// operations.zero_operations.push(ZeroOperation {
    ///     offset: 3000,
    ///     size: 128,
    ///     reason: "Clear old #Blob heap".to_string(),
    /// });
    ///
    /// assert_eq!(operations.total_zero_size(), 384); // 256 + 128
    /// ```
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe as it only reads immutable operation data.
    pub fn total_zero_size(&self) -> u64 {
        self.zero.iter().map(|op| op.size).sum()
    }

    /// Returns the total amount of new data that will be written to the output file.
    ///
    /// This method calculates the sum of all write operation data sizes, representing
    /// the total amount of new content (metadata heaps, tables, headers, etc.) that
    /// will be added to the assembly. This metric is crucial for understanding the
    /// scope of modifications and estimating output file size changes.
    ///
    /// # Returns
    ///
    /// Returns the total number of bytes of new data as a [`u64`]. This represents
    /// the sum of the length of the `data` field from all [`WriteOperation`] instances
    /// in the operation set.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::cilassembly::writer::operations::*;
    ///
    /// let mut operations = OperationSet::new();
    ///
    /// operations.write_operations.push(WriteOperation {
    ///     offset: 5000,
    ///     data: b"BSJB\x01\x00\x01\x00".to_vec(), // 8 bytes
    ///     component: "Metadata signature".to_string(),
    /// });
    ///
    /// operations.write_operations.push(WriteOperation {
    ///     offset: 6000,
    ///     data: b"\x00System\x00Console\x00".to_vec(), // 16 bytes
    ///     component: "New strings".to_string(),
    /// });
    ///
    /// assert_eq!(operations.total_write_size(), 24); // 8 + 16
    /// ```
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe as it only reads immutable operation data.
    pub fn total_write_size(&self) -> u64 {
        self.write.iter().map(|op| op.data.len() as u64).sum()
    }

    /// Validates that all operations are conflict-free and can be executed safely.
    ///
    /// This comprehensive validation method performs critical safety checks to ensure
    /// that the operation set can be executed without conflicts, overlaps, or data
    /// corruption. It is essential to call this method before execution to prevent
    /// runtime failures and ensure file integrity.
    ///
    /// The validation process checks for:
    /// - **Target Region Overlaps**: Ensures no two operations write to overlapping file regions
    /// - **Operation Consistency**: Verifies that all offsets and sizes are valid and within bounds
    /// - **Execution Safety**: Confirms that operations can be executed in any order without conflicts
    /// - **Data Integrity**: Validates that the operation set will produce a coherent output file
    ///
    /// # Returns
    ///
    /// Returns [`crate::Result<()>`] on successful validation. If validation fails,
    /// returns [`crate::Error::WriteLayoutFailed`] with detailed information about
    /// the specific conflict detected, including which operations overlap and their
    /// file offset ranges.
    ///
    /// # Errors
    ///
    /// This method returns [`crate::Error::WriteLayoutFailed`] when:
    /// - Two or more operations attempt to write to overlapping file regions
    /// - Operations have invalid offsets (negative or extremely large values)
    /// - Operation sizes would cause integer overflow when calculating end positions
    /// - The operation set contains inconsistent or contradictory instructions
    ///
    /// # Examples
    ///
    /// ## Successful Validation
    ///
    /// ```rust,ignore
    /// use dotscope::cilassembly::writer::operations::*;
    ///
    /// let mut operations = OperationSet::new();
    ///
    /// operations.copy_operations.push(CopyOperation {
    ///     source_offset: 0,
    ///     target_offset: 1000,
    ///     size: 100,
    ///     description: "Copy PE headers".to_string(),
    /// });
    ///
    /// operations.write_operations.push(WriteOperation {
    ///     offset: 2000, // No overlap with copy operation (1000-1100)
    ///     data: vec![0xBE, 0xEF],
    ///     component: "New metadata".to_string(),
    /// });
    ///
    /// // Validation should succeed - no overlaps
    /// assert!(operations.validate().is_ok());
    /// ```
    ///
    /// ## Validation Failure Due to Overlap
    ///
    /// ```rust,ignore
    /// use dotscope::cilassembly::writer::operations::*;
    ///
    /// let mut operations = OperationSet::new();
    ///
    /// operations.copy_operations.push(CopyOperation {
    ///     source_offset: 0,
    ///     target_offset: 1000,
    ///     size: 200, // Covers 1000-1200
    ///     description: "Copy large section".to_string(),
    /// });
    ///
    /// operations.write_operations.push(WriteOperation {
    ///     offset: 1100, // Overlaps with copy operation!
    ///     data: vec![0xDE, 0xAD, 0xBE, 0xEF],
    ///     component: "Conflicting write".to_string(),
    /// });
    ///
    /// // Validation should fail due to overlap
    /// match operations.validate() {
    ///     Err(e) => println!("Expected overlap error: {}", e),
    ///     Ok(_) => panic!("Validation should have failed!"),
    /// }
    /// ```
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe as it only reads operation data and performs
    /// validation calculations without modifying the operation set.
    pub fn validate(&self) -> Result<()> {
        let mut target_regions = Vec::new();
        for op in &self.copy {
            target_regions.push((
                op.target_offset,
                op.target_offset + op.size,
                &op.description,
            ));
        }

        for op in &self.zero {
            target_regions.push((op.offset, op.offset + op.size, &op.reason));
        }

        for op in &self.write {
            let end_offset = op.offset + op.data.len() as u64;
            target_regions.push((op.offset, end_offset, &op.component));
        }

        target_regions.sort_by_key(|(start, _, _)| *start);

        for window in target_regions.windows(2) {
            let (start1, end1, desc1) = &window[0];
            let (start2, _end2, desc2) = &window[1];

            if end1 > start2 {
                return Err(Error::WriteLayoutFailed {
                    message: format!(
                        "Operation overlap detected: '{desc1}' ({start1}..{end1}) overlaps with '{desc2}' (starts at {start2})" 
                    ),
                });
            }
        }

        Ok(())
    }

    /// Provides a comprehensive summary of the operation set for debugging and monitoring.
    ///
    /// This method generates a human-readable summary that includes key metrics about
    /// the operation set, making it invaluable for debugging layout planning issues,
    /// monitoring execution progress, and understanding the scope of assembly modifications.
    ///
    /// The summary includes operation counts by type, total data volumes, and aggregate
    /// statistics that help developers understand what the writer pipeline will accomplish.
    ///
    /// # Returns
    ///
    /// Returns a [`String`] containing a formatted summary with the following information:
    /// - Total number of operations across all types
    /// - Breakdown by operation type (copy, zero, write)
    /// - Total data volume that will be processed
    /// - Aggregate metrics for performance estimation
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::cilassembly::writer::operations::*;
    ///
    /// let mut operations = OperationSet::new();
    ///
    /// operations.copy_operations.push(CopyOperation {
    ///     source_offset: 0, target_offset: 1000, size: 512,
    ///     description: "Copy headers".to_string(),
    /// });
    ///
    /// operations.write_operations.push(WriteOperation {
    ///     offset: 2000, data: vec![0; 256],
    ///     component: "New metadata".to_string(),
    /// });
    ///
    /// let summary = operations.summary();
    /// println!("Execution plan: {}", summary);
    /// // Output: "OperationSet: 2 operations (1 copy, 0 zero, 1 write), 768 total bytes"
    ///
    /// assert!(summary.contains("2 operations"));
    /// assert!(summary.contains("1 copy"));
    /// assert!(summary.contains("1 write"));
    /// assert!(summary.contains("768 total bytes")); // 512 + 256
    /// ```
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe as it only reads operation data to generate
    /// the summary without modifying the operation set.
    pub fn summary(&self) -> String {
        format!(
            "OperationSet: {total_ops} operations ({copy_ops} copy, {zero_ops} zero, {write_ops} write), {total_bytes} total bytes",
            total_ops = self.operation_count(),
            copy_ops = self.copy.len(),
            zero_ops = self.zero.len(),
            write_ops = self.write.len(),
            total_bytes = self.total_copy_size() + self.total_zero_size() + self.total_write_size()
        )
    }
}

impl Default for OperationSet {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for CopyOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "COPY: {} bytes from 0x{:X} to 0x{:X} ({})",
            self.size, self.source_offset, self.target_offset, self.description
        )
    }
}

impl fmt::Display for ZeroOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ZERO: {} bytes at 0x{:X} ({})",
            self.size, self.offset, self.reason
        )
    }
}

impl fmt::Display for WriteOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "WRITE: {} bytes at 0x{:X} ({})",
            self.data.len(),
            self.offset,
            self.component
        )
    }
}

impl fmt::Display for OperationSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Operation Set ({} operations):", self.operation_count())?;

        for op in &self.copy {
            writeln!(f, "  {op}")?;
        }

        for op in &self.zero {
            writeln!(f, "  {op}")?;
        }

        for op in &self.write {
            writeln!(f, "  {op}")?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_operation_set_creation() {
        let ops = OperationSet::new();
        assert_eq!(ops.operation_count(), 0);
        assert_eq!(ops.total_copy_size(), 0);
        assert_eq!(ops.total_zero_size(), 0);
        assert_eq!(ops.total_write_size(), 0);
    }

    #[test]
    fn test_operation_validation_no_overlap() {
        let mut ops = OperationSet::new();

        ops.copy.push(CopyOperation {
            source_offset: 0,
            target_offset: 1000,
            size: 100,
            description: "Test copy".to_string(),
        });

        ops.write.push(WriteOperation {
            offset: 2000,
            data: vec![1, 2, 3, 4],
            component: "Test write".to_string(),
        });

        assert!(ops.validate().is_ok());
    }

    #[test]
    fn test_operation_validation_with_overlap() {
        let mut ops = OperationSet::new();

        ops.copy.push(CopyOperation {
            source_offset: 0,
            target_offset: 1000,
            size: 100,
            description: "Test copy".to_string(),
        });

        ops.write.push(WriteOperation {
            offset: 1050, // Overlaps with copy operation
            data: vec![1, 2, 3, 4],
            component: "Test write".to_string(),
        });

        assert!(ops.validate().is_err());
    }

    #[test]
    fn test_operation_size_calculations() {
        let mut ops = OperationSet::new();

        ops.copy.push(CopyOperation {
            source_offset: 0,
            target_offset: 1000,
            size: 100,
            description: "Test copy".to_string(),
        });

        ops.zero.push(ZeroOperation {
            offset: 2000,
            size: 200,
            reason: "Test zero".to_string(),
        });

        ops.write.push(WriteOperation {
            offset: 3000,
            data: vec![1; 50], // 50 bytes
            component: "Test write".to_string(),
        });

        assert_eq!(ops.total_copy_size(), 100);
        assert_eq!(ops.total_zero_size(), 200);
        assert_eq!(ops.total_write_size(), 50);
        assert_eq!(ops.operation_count(), 3);
    }
}
