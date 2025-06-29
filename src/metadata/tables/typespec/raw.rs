//! # TypeSpec Table - Raw Implementation
//!
//! This module provides the raw [`TypeSpecRaw`] struct representing unresolved entries from
//! the TypeSpec metadata table with direct binary data access.
//!
//! ## Table Overview
//!
//! The TypeSpec table (0x1B) defines type specifications through signatures stored in the blob heap.
//! This table provides type definitions that describe types in their most general form, enabling
//! generic type instantiation, array definitions, pointer types, and complex type composition.
//!
//! | Offset | Name      | Type      | Description |
//! |--------|-----------|-----------|-------------|
//! | 0      | Signature | Blob Idx  | Index into blob heap for type signature |
//!
//! ## Raw vs Owned
//!
//! This raw implementation provides:
//! - **Direct Binary Access**: Unresolved blob heap indexes
//! - **Memory Efficiency**: Minimal allocation for metadata tables
//! - **Lazy Resolution**: Signature parsing deferred until needed
//! - **Table Operations**: Row-level access and iteration
//!
//! ## Type Specification Signatures
//!
//! TypeSpec signatures define complex types including:
//! - **Generic Instantiations**: `List<T>`, `Dictionary<K,V>`
//! - **Array Types**: Single and multi-dimensional arrays
//! - **Pointer Types**: Managed and unmanaged pointers
//! - **Modified Types**: `const`, `volatile`, and other modifiers
//!
//! ## References
//!
//! - [ECMA-335 §II.22.39 - TypeSpec Table](https://www.ecma-international.org/publications-and-standards/standards/ecma-335/)
//! - [`crate::metadata::tables::typespec`] - TypeSpec table module
//! - [`crate::metadata::signatures::parse_type_spec_signature`] - Signature parsing

use std::sync::Arc;

use crate::{
    file::io::read_le_at_dyn,
    metadata::{
        signatures::parse_type_spec_signature,
        streams::Blob,
        tables::{RowDefinition, TableInfoRef, TypeSpec, TypeSpecRc},
        token::Token,
    },
    Result,
};

#[derive(Clone, Debug)]
/// Represents a raw TypeSpec table entry with unresolved blob heap references.
///
/// The TypeSpec table stores type specifications through signatures in the blob heap.
/// This raw representation provides direct access to the binary data without resolving
/// references, enabling efficient table operations and lazy parsing of complex signatures.
///
/// ## Table Structure (0x1B)
///
/// The TypeSpec table contains a single column pointing to signature data:
/// - **Signature**: Index into the blob heap containing the type specification
///
/// ## Type Specifications
///
/// TypeSpec entries define complex types through their signatures:
/// - **Generic Types**: `List<T>`, `Dictionary<K,V>`, custom generic instantiations
/// - **Array Types**: Single-dimensional arrays, multi-dimensional arrays with bounds
/// - **Pointer Types**: Managed pointers, unmanaged pointers, reference types
/// - **Modified Types**: Types with `const`, `volatile`, and other modifiers
/// - **Constructed Types**: Complex compositions of primitive and defined types
///
/// ## Usage in .NET Metadata
///
/// TypeSpec entries are referenced by:
/// - Method signatures requiring complex type definitions
/// - Field declarations with constructed types
/// - Local variable declarations in method bodies
/// - Custom attribute constructor arguments
///
/// ## Raw vs Owned Conversion
///
/// Use [`to_owned`](TypeSpecRaw::to_owned) to convert this raw entry into a fully-resolved
/// [`TypeSpec`] with parsed signature data. This conversion requires access to the blob heap
/// and performs signature parsing which may fail for malformed data.
pub struct TypeSpecRaw {
    /// The 1-based row identifier within the TypeSpec table.
    ///
    /// This identifier uniquely identifies the TypeSpec entry within the table
    /// and is used for cross-references from other metadata tables and IL instructions.
    pub rid: u32,

    /// The metadata token for this TypeSpec entry.
    ///
    /// TypeSpec tokens have the format 0x1B000000 + RID, where 0x1B identifies
    /// the TypeSpec table. These tokens are used in IL instructions and other
    /// metadata contexts to reference type specifications.
    pub token: Token,

    /// Byte offset of this entry within the TypeSpec table data.
    ///
    /// This offset can be used for debugging, diagnostic purposes, or when
    /// implementing custom table parsers that need to track data positions.
    pub offset: usize,

    /// Index into the blob heap containing the type specification signature.
    ///
    /// This index points to a compressed signature in the blob heap that defines
    /// the complete type specification. The signature format follows ECMA-335
    /// standards and includes type modifiers, generic arguments, and array bounds.
    pub signature: u32,
}

impl TypeSpecRaw {
    /// Converts this raw TypeSpec entry into a fully-resolved owned representation.
    ///
    /// This method resolves the blob heap reference and parses the type specification
    /// signature to create a [`TypeSpec`] instance with owned, parsed data. The conversion
    /// performs signature parsing and validation according to ECMA-335 standards.
    ///
    /// ## Supported Type Specifications
    ///
    /// - **Generic Instantiations**: `List<T>`, `Dictionary<TKey, TValue>`
    /// - **Array Types**: `T[]`, `T[,]`, `T[0..10]` with bounds
    /// - **Pointer Types**: `T*`, `T&`, managed and unmanaged pointers
    /// - **Modified Types**: `const T`, `volatile T`, custom modifiers
    /// - **Function Pointers**: Method signatures as type specifications
    ///
    /// ## Arguments
    ///
    /// * `blob` - The blob heap containing the signature data
    ///
    /// ## Returns
    ///
    /// Returns an [`Arc<TypeSpec>`] containing the fully-resolved type specification
    /// with parsed signature data.
    ///
    /// ## Errors
    ///
    /// - The blob heap index is invalid or out of bounds
    /// - The signature data is malformed or truncated
    /// - Type references within the signature cannot be resolved
    /// - The signature format doesn't conform to ECMA-335 standards
    pub fn to_owned(&self, blob: &Blob) -> Result<TypeSpecRc> {
        let signature_data = blob.get(self.signature as usize)?;
        let signature = parse_type_spec_signature(signature_data)?;

        Ok(Arc::new(TypeSpec {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            signature,
        }))
    }

    /// Applies this raw TypeSpec entry to maintain metadata consistency.
    ///
    /// TypeSpec entries define standalone type specifications and don't require
    /// modifications to other metadata tables during the resolution process.
    /// This method is part of the metadata resolution framework but always
    /// succeeds for TypeSpec entries since they are self-contained.
    ///
    /// ## Metadata Resolution Framework
    ///
    /// While other metadata tables may require cross-table updates during resolution,
    /// TypeSpec entries serve as type definitions that are referenced by other tables
    /// but don't themselves modify other metadata structures.
    ///
    /// ## Returns
    ///
    /// Always returns `Ok(())` as TypeSpec entries don't require metadata updates.
    ///
    /// ## Errors
    ///
    /// This method currently never returns an error, but maintains the [`Result`]
    /// return type for consistency with the metadata resolution framework.
    pub fn apply(&self) -> Result<()> {
        Ok(())
    }
}

impl<'a> RowDefinition<'a> for TypeSpecRaw {
    /// Calculates the byte size of a single TypeSpec table row.
    ///
    /// The TypeSpec table contains a single column:
    /// - **Signature**: Blob heap index (2 or 4 bytes depending on heap size)
    ///
    /// ## Arguments
    ///
    /// * `sizes` - Table size information including blob heap size thresholds
    ///
    /// ## Returns
    ///
    /// The total byte size for one TypeSpec table row.
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* signature */ sizes.blob_bytes()
        )
    }

    /// Reads a single TypeSpec table row from binary data.
    ///
    /// Parses the binary representation of a TypeSpec table entry, extracting
    /// the signature blob index and constructing the appropriate metadata token.
    /// The token format is 0x1B000000 + RID where 0x1B identifies the TypeSpec table.
    ///
    /// ## Arguments
    ///
    /// * `data` - The raw table data to read from
    /// * `offset` - Current reading position, updated after reading
    /// * `rid` - The 1-based row identifier for this entry
    /// * `sizes` - Table size information for determining field sizes
    ///
    /// ## Returns
    ///
    /// A fully constructed [`TypeSpecRaw`] instance with all fields populated.
    ///
    /// ## Errors
    ///
    /// May return an error if:
    /// - The data buffer is too short for a complete table entry
    /// - Invalid data structure encountered during parsing
    fn read_row(
        data: &'a [u8],
        offset: &mut usize,
        rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<Self> {
        Ok(TypeSpecRaw {
            rid,
            token: Token::new(0x1B00_0000 + rid),
            offset: *offset,
            signature: read_le_at_dyn(data, offset, sizes.is_large_blob())?,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::metadata::tables::{MetadataTable, TableId, TableInfo};

    #[test]
    fn crafted_short() {
        let data = vec![
            0x01, 0x01, // signature
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::TypeSpec, 1)],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<TypeSpecRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: TypeSpecRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x1B000001);
            assert_eq!(row.signature, 0x0101);
        };

        {
            for row in table.iter() {
                eval(row);
            }
        }

        {
            let row = table.get(1).unwrap();
            eval(row);
        }
    }

    #[test]
    fn crafted_long() {
        let data = vec![
            0x01, 0x01, 0x01, 0x01, // signature
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::TypeSpec, 1)],
            true,
            true,
            true,
        ));
        let table = MetadataTable::<TypeSpecRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: TypeSpecRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x1B000001);
            assert_eq!(row.signature, 0x01010101);
        };

        {
            for row in table.iter() {
                eval(row);
            }
        }

        {
            let row = table.get(1).unwrap();
            eval(row);
        }
    }
}
