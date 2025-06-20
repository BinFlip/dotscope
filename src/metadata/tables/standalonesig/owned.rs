//! # `StandAloneSig` Owned Implementation
//!
//! This module provides the owned variant of `StandAloneSig` table entries with resolved
//! references and complete metadata context for application use.

use crate::metadata::{customattributes::CustomAttributeValueList, token::Token};

/// Owned representation of a `StandAloneSig` table entry with complete metadata context.
///
/// This structure represents a fully processed entry from the `StandAloneSig` metadata table
/// (ID 0x11), which contains standalone signatures that are not directly associated with
/// specific methods, fields, or properties. It contains resolved signature data and
/// complete contextual information for signature analysis and usage.
///
/// ## Purpose
///
/// The `StandAloneSig` table serves multiple signature scenarios:
/// - **Method Signatures**: Standalone method pointer and delegate signatures
/// - **Local Variable Signatures**: Method local variable type declarations
/// - **Dynamic Signatures**: Runtime signature generation and manipulation
/// - **CIL Instruction Support**: Signatures referenced by CIL instructions
///
/// ## Owned vs Raw
///
/// This owned variant provides:
/// - Resolved signature blob data with parsed type information
/// - Complete custom attribute collections with resolved values
/// - Validated signature structure and type references
/// - Integration with the broader metadata resolution system
/// - High-level access methods for signature analysis operations
///
/// ## Signature Types
///
/// `StandAloneSig` entries can contain various signature types:
/// - **Method Signatures**: Function pointer signatures with calling conventions
/// - **Local Variable Signatures**: Local variable type declarations
/// - **Field Signatures**: Standalone field type specifications
/// - **Generic Signatures**: Generic type and method instantiation signatures
///
/// ## See Also
///
/// - [`StandAloneSigRaw`](crate::metadata::tables::StandAloneSigRaw) - Raw unresolved variant
/// - [ECMA-335 §II.22.39](https://www.ecma-international.org/publications-and-standards/standards/ecma-335/) - `StandAloneSig` table specification
pub struct StandAloneSig {
    /// The 1-based row identifier within the `StandAloneSig` table.
    ///
    /// This value corresponds to the logical position of the standalone signature entry
    /// within the `StandAloneSig` table and is used to construct the metadata token.
    pub rid: u32,

    /// The metadata token for this `StandAloneSig` entry.
    ///
    /// Constructed as `0x11000000 | rid`, this token uniquely identifies
    /// the standalone signature entry within the metadata system and enables
    /// efficient signature reference operations.
    pub token: Token,

    /// The byte offset of this entry within the metadata stream.
    ///
    /// Indicates the physical location of the standalone signature entry in the
    /// original metadata stream, useful for debugging and low-level metadata analysis.
    pub offset: usize,

    /// Index into the Blob heap containing the signature data.
    ///
    /// This field points to the signature blob that contains the actual signature
    /// information including calling conventions, parameter types, return types,
    /// and other signature-specific data. The blob format depends on the signature type.
    pub signature: u32,

    /// Custom attributes applied to this standalone signature.
    ///
    /// Contains a collection of custom attributes that provide additional metadata
    /// and annotations for the standalone signature. These attributes can include
    /// compiler-generated information, security attributes, and other metadata
    /// relevant to signature usage and interpretation.
    pub custom_attributes: CustomAttributeValueList,
}
