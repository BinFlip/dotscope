//! # `StandAloneSig` Owned Implementation
//!
//! This module provides the owned variant of `StandAloneSig` table entries with resolved
//! references and complete metadata context for application use.

use crate::metadata::{
    customattributes::CustomAttributeValueList,
    signatures::{SignatureField, SignatureLocalVariables, SignatureMethod},
    token::Token,
};

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

    /// The parsed signature data.
    ///
    /// Contains the fully parsed signature from the blob heap. The signature type
    /// is determined by the first byte of the blob data and can be one of:
    /// - Local variable signature (0x07)
    /// - Method signature (calling conventions 0x00-0x05, with optional flags)
    /// - Field signature (0x06)
    pub parsed_signature: StandAloneSignature,
}

/// Represents the different types of signatures that can appear in a `StandAloneSig` entry.
///
/// According to ECMA-335, standalone signatures can contain:
/// - **Local Variable Signatures**: Used by method bodies to declare local variables
/// - **Method Signatures**: Used for `calli` instructions and function pointers
/// - **Field Signatures**: Standalone field type specifications (rare)
///
/// The signature type is determined by examining the first byte of the signature blob.
#[derive(Debug, Clone, PartialEq)]
pub enum StandAloneSignature {
    /// A local variable signature (header byte 0x07).
    ///
    /// Contains the types and modifiers for all local variables in a method body.
    /// This is the most common use of `StandAloneSig` entries.
    LocalVariables(SignatureLocalVariables),

    /// A standalone method signature.
    ///
    /// Used for `calli` instructions and function pointer types. Contains calling
    /// convention, return type, and parameter types.
    Method(SignatureMethod),

    /// A standalone field signature (header byte 0x06).
    ///
    /// Contains a single field type with optional custom modifiers. This is rare
    /// in practice but supported by the ECMA-335 specification.
    Field(SignatureField),
}

impl Default for StandAloneSignature {
    fn default() -> Self {
        Self::LocalVariables(SignatureLocalVariables::default())
    }
}
