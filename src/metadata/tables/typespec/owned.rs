//! # `TypeSpec` Table - Owned Implementation
//!
//! This module provides the owned [`TypeSpec`] struct representing parsed entries from
//! the `TypeSpec` metadata table with resolved references and owned data.
//!
//! ## `TypeSpec` Table Overview
//!
//! The `TypeSpec` table (0x1B) defines type specifications through signatures. This table
//! provides type definitions that describe types in their most general form, allowing
//! for generic type instantiation and complex type composition.
//!
//! | Offset | Name      | Type      | Description |
//! |--------|-----------|-----------|-------------|
//! | 0      | Signature | Blob Idx  | Index into blob heap for type signature |
//!
//! ## Key Features
//!
//! - **Type Signatures**: Fully parsed type specification signatures
//! - **Token Access**: Direct token reference for table entry identification
//! - **Owned Data**: Contains resolved and owned signature data
//! - **Metadata Resolution**: Supports type system metadata operations
//!
//! ## References
//!
//! - [ECMA-335 §II.22.39 - TypeSpec Table](https://www.ecma-international.org/publications-and-standards/standards/ecma-335/)
//! - [`crate::metadata::tables::typespec`] - `TypeSpec` table module
//! - [`crate::metadata::signatures::SignatureTypeSpec`] - Type specification signatures

use crate::metadata::{signatures::SignatureTypeSpec, token::Token};

/// Represents an owned `TypeSpec` table entry with resolved references and parsed signatures.
///
/// The `TypeSpec` table defines type specifications through signatures, providing the foundation
/// for complex type definitions including generic types, arrays, pointers, and type modifiers.
/// This struct contains fully resolved and owned data from the raw table entries.
///
/// ## Fields Overview
///
/// - `rid`: The 1-based row identifier within the `TypeSpec` table
/// - `token`: The metadata token for this `TypeSpec` entry
/// - `offset`: Byte offset of the signature within the blob heap
/// - `signature`: Fully parsed type specification signature
///
/// ## Type Specifications
///
/// `TypeSpec` entries define types through their signatures and are used for:
/// - Generic type instantiations (e.g., `List<T>`)
/// - Array types with specific dimensions
/// - Pointer and reference types
/// - Modified types (e.g., `const`, `volatile`)
///
/// ## Usage in Metadata
///
/// `TypeSpec` entries are referenced by:
/// - [`crate::metadata::tables::MethodDefRaw`] - Method signatures
/// - [`crate::metadata::tables::Field`] - Field type specifications
/// - [`crate::metadata::tables::MemberRef`] - Member references
/// - Other tables requiring complex type definitions
///
pub struct TypeSpec {
    /// The 1-based row identifier within the `TypeSpec` table.
    ///
    /// This identifier uniquely identifies the `TypeSpec` entry within the table
    /// and is used for cross-references from other metadata tables.
    pub rid: u32,

    /// The metadata token for this `TypeSpec` entry.
    ///
    /// Tokens provide a consistent way to reference metadata entries across
    /// different contexts and are used in IL instructions and other metadata.
    pub token: Token,

    /// Byte offset of the type signature within the blob heap.
    ///
    /// This offset points to the location in the blob heap where the type
    /// specification signature is stored in its binary encoded form.
    pub offset: usize,

    /// The fully parsed type specification signature.
    ///
    /// Contains the complete type definition including generic parameters,
    /// array dimensions, pointer levels, and type modifiers. This signature
    /// defines the exact type being specified.
    pub signature: SignatureTypeSpec,
}
