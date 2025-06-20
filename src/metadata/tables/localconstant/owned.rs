//! Owned `LocalConstant` table representation
//!
//! This module provides the [`LocalConstant`] struct that represents
//! the high-level, resolved form of `LocalConstant` table entries with
//! all heap references resolved to actual string and binary data.

use crate::metadata::{signatures::SignatureField, token::Token};

/// High-level representation of a `LocalConstant` table entry
///
/// This structure provides the resolved form of `LocalConstant` table data
/// with all heap indices resolved to their actual values. The name field
/// contains the resolved string data from the #Strings heap, and the
/// signature field contains the parsed type signature from the #Blob heap.
///
/// # Usage Examples
///
/// ```rust,ignore
/// use dotscope::metadata::tables::LocalConstant;
/// use dotscope::metadata::signatures::TypeSignature;
///
/// // Access constant information with parsed signature
/// println!("Constant '{}' with type: {:?}", constant.name, constant.signature.base);
///
/// // Check the constant's type
/// match &constant.signature.base {
///     TypeSignature::I4 => println!("Integer constant"),
///     TypeSignature::String => println!("String constant"),
///     TypeSignature::R8 => println!("Double constant"),
///     _ => println!("Other type constant"),
/// }
///
/// // Check for custom modifiers
/// if !constant.signature.modifiers.is_empty() {
///     println!("Constant has {} custom modifiers", constant.signature.modifiers.len());
/// }
/// ```
#[derive(Debug, Clone)]
pub struct LocalConstant {
    /// Row identifier (1-based index in the table)
    pub rid: u32,

    /// Metadata token for this `LocalConstant` entry
    pub token: Token,

    /// Byte offset of this row in the original metadata stream
    pub offset: usize,

    /// Constant name resolved from #Strings heap
    ///
    /// The actual name string for this local constant. May be empty for
    /// anonymous or compiler-generated constants where no name was specified.
    pub name: String,

    /// Parsed constant signature describing the constant's type
    ///
    /// The structured representation of the constant's type signature, parsed from
    /// the #Blob heap. This provides immediate access to the constant's type information
    /// including the base type and any custom modifiers, without requiring additional
    /// parsing steps.
    ///
    /// The signature describes:
    /// - **Base Type**: The fundamental type of the constant (int, string, etc.)
    /// - **Custom Modifiers**: Optional type annotations for advanced scenarios
    /// - **Type Constraints**: Generic type parameters and their constraints
    ///
    /// Parsing is performed automatically during the conversion from raw to owned
    /// representation, providing structured access to type information.
    pub signature: SignatureField,
}
