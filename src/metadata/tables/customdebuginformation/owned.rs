//! Owned `CustomDebugInformation` table representation for Portable PDB format.
//!
//! This module provides the [`crate::metadata::tables::customdebuginformation::CustomDebugInformation`] struct that represents
//! a fully resolved `CustomDebugInformation` table entry with all indices converted
//! to actual data for immediate use in debugging scenarios. The owned representation
//! enables direct access to custom debug information without requiring additional
//! heap lookups or index resolution.
//!
//! # Key Components
//!
//! - [`crate::metadata::tables::customdebuginformation::CustomDebugInformation`] - Main struct representing resolved custom debug information
//!
//! # Thread Safety
//!
//! All types in this module are [`Send`] and [`Clone`], enabling safe sharing
//! across threads and efficient copying when needed.

use crate::metadata::{
    customdebuginformation::CustomDebugInfo, token::Token, typesystem::CilTypeReference,
};
use uguid::Guid;

/// Owned representation of a `CustomDebugInformation` table entry
///
/// This structure contains the processed `CustomDebugInformation` data with all heap indices
/// resolved to their actual data. Custom debug information provides extensibility for
/// debugging scenarios beyond the standard Portable PDB tables, allowing compilers
/// and tools to store implementation-specific debugging metadata.
///
/// # Custom Debug Information Types
///
/// The Kind field contains a GUID that identifies the specific type of custom debug
/// information. Microsoft compilers define several well-known types:
///
/// ## State Machine Information
/// - **`{6DA9A61E-F8C7-4874-BE62-68BC5630DF71}`**: State Machine Hoisted Local Scopes
///   Associates variables hoisted to state machine fields with their scope information.
///
/// - **`{755F52A8-91C5-45BE-B4B8-209571E552BD}`**: Edit and Continue Local Slot Map
///   Maps local variables to their syntax positions for edit-and-continue debugging.
///
/// - **`{A643004C-0240-496F-A783-30D64F4979DE}`**: Edit and Continue Lambda and Closure Map
///   Maps lambdas and closures to their implementing methods and syntax positions.
///
/// ## Dynamic and Source Information
/// - **`{83C563C4-B4F3-47D5-B824-BA5441477EA8}`**: Dynamic Local Variables (C#)
///   Tracks which System.Object types were originally declared as `dynamic` in source code.
///
/// - **`{58b2eab6-209f-4e4e-a22c-b2d0f910c782}`**: Default Namespace (VB)
///   Stores the default namespace for VB.NET projects/modules.
///
/// - **`{0E8A571B-6926-466E-B4AD-8AB04611F5FE}`**: Embedded Source
///   Contains source code embedded directly in the PDB file.
///
/// - **`{CC110556-A091-4D38-9FEC-25AB9A351A6A}`**: Source Link
///   JSON configuration for retrieving source files from version control systems.
///
/// # Parent Element
///
/// The Parent field identifies which metadata element this custom debug information
/// is associated with. It can reference methods, types, fields, parameters, and many
/// other metadata elements through the `HasCustomDebugInformation` coded index.
///
/// # Usage Examples
///
/// ```rust,ignore
/// use dotscope::metadata::tables::CustomDebugInformation;
/// use dotscope::metadata::customdebuginformation::types::CustomDebugInfo;
///
/// # fn process_custom_debug(custom_debug: &CustomDebugInformation) -> crate::Result<()> {
/// // Example: Processing different types of custom debug information
/// match &custom_debug.value {
///     CustomDebugInfo::SourceLink { document } => {
///         println!("Source Link JSON: {}", document);
///         // Parse JSON to get source server mappings
///     }
///     CustomDebugInfo::EmbeddedSource { filename, content } => {
///         println!("Embedded source file: {}", filename);
///         println!("Content: {} characters", content.len());
///     }
///     CustomDebugInfo::CompilationMetadata { metadata } => {
///         println!("Compilation metadata: {}", metadata);
///     }
///     CustomDebugInfo::Unknown { kind, data } => {
///         println!("Unknown debug info type: {:?}", kind);
///         println!("Raw data: {} bytes", data.len());
///         // Handle custom or unsupported debug information types
///     }
/// }
/// # Ok(())
/// # }
/// ```
///
/// # References
///
/// - [Portable PDB Format - CustomDebugInformation Table](https://github.com/dotnet/corefx/blob/master/src/System.Reflection.Metadata/specs/PortablePdb-Metadata.md#customdebuginformation-table-0x37)
/// - [Custom Debug Information Records](https://github.com/dotnet/corefx/blob/master/src/System.Reflection.Metadata/specs/PortablePdb-Metadata.md#language-specific-custom-debug-information-records)
#[derive(Clone)]
pub struct CustomDebugInformation {
    /// Row identifier (1-based index in the table)
    pub rid: u32,

    /// Metadata token for this `CustomDebugInformation` entry
    pub token: Token,

    /// Byte offset of this row in the original metadata stream
    pub offset: usize,

    /// Reference to the metadata element this custom debug information is associated with
    ///
    /// This field contains a resolved reference to the metadata element that this
    /// custom debug information is associated with. The reference can point to any
    /// type of metadata element that supports custom debug information.
    ///
    /// Common parent types include:
    /// - `MethodDef`: Method-specific debug information (most common)
    /// - Document: Document-specific information (embedded source, etc.)
    /// - Module: Module/assembly-wide information (default namespace, source link)
    /// - `LocalVariable`/`LocalConstant`: Variable-specific information (dynamic flags)
    /// - `TypeDef`: Type-specific debug information
    pub parent: CilTypeReference,

    /// GUID identifying the type of custom debug information
    ///
    /// This GUID determines how to interpret the Value data. Well-known GUIDs
    /// are defined by Microsoft compilers, but tools can define their own
    /// custom types by using unique GUIDs.
    ///
    /// The GUID serves as both a type identifier and a versioning mechanism -
    /// if a format needs to change, a new GUID should be defined rather than
    /// modifying an existing format.
    pub kind: Guid,

    /// Parsed custom debug information data
    ///
    /// This field contains the structured representation of the custom debug information
    /// blob, parsed according to the Kind GUID. Instead of raw bytes, this provides
    /// direct access to the meaningful data structures such as:
    /// - Source Link JSON documents for source server mappings
    /// - Embedded source file content with filenames
    /// - Compilation metadata and options as structured text
    /// - Unknown formats preserved as raw data for future processing
    ///
    /// The parsing is performed automatically during the conversion from raw to owned
    /// representation, providing immediate access to the debug information without
    /// requiring additional parsing steps.
    pub value: CustomDebugInfo,
}
