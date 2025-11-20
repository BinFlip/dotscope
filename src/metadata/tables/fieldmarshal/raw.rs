//! Raw `FieldMarshal` structures for the `FieldMarshal` metadata table.
//!
//! This module provides the [`crate::metadata::tables::fieldmarshal::raw::FieldMarshalRaw`] struct for reading field marshal data
//! directly from metadata tables before index resolution. The `FieldMarshal` table specifies
//! marshalling behavior for fields and parameters when crossing managed/unmanaged boundaries.
//!
//! # Table Structure
//! The `FieldMarshal` table (`TableId` = 0x0D) contains these columns:
//! - `Parent`: `HasFieldMarshal` coded index (Field or Param reference)
//! - `NativeType`: Blob heap index containing marshalling signature
//!
//! # Coded Index Types
//! The Parent field uses the `HasFieldMarshal` coded index which can reference:
//! - **Field table entries**: For field marshalling specifications
//! - **Param table entries**: For parameter marshalling specifications
//!
//! # Marshalling Context
//! `FieldMarshal` entries are essential for interop scenarios:
//! - **P/Invoke calls**: Parameter conversion for native function calls
//! - **COM interop**: Field and parameter handling for COM objects
//! - **Custom marshalling**: User-defined conversion behavior
//! - **Array handling**: Element type and size specifications
//! - **String processing**: Character encoding and memory management
//!
//! # ECMA-335 Reference
//! See ECMA-335, Partition II, §22.17 for the `FieldMarshal` table specification.

use std::sync::Arc;

use crate::{
    metadata::{
        marshalling::parse_marshalling_descriptor,
        streams::Blob,
        tables::{
            CodedIndex, CodedIndexType, FieldMap, FieldMarshal, FieldMarshalRc, ParamMap, TableId,
            TableInfoRef, TableRow,
        },
        token::Token,
        typesystem::CilTypeReference,
    },
    Result,
};

/// Raw field marshal data read directly from the `FieldMarshal` metadata table.
///
/// This structure represents a field marshal entry before index resolution and blob
/// parsing. Field marshals specify how fields and parameters should be converted
/// when crossing managed/unmanaged boundaries during interop operations.
///
/// # Binary Format
/// Each row in the `FieldMarshal` table has this layout:
/// ```text
/// Offset | Size | Field      | Description
/// -------|------|------------|----------------------------------
/// 0      | 2/4  | Parent     | HasFieldMarshal coded index
/// 2/4    | 2/4  | NativeType | Blob heap index
/// ```
///
/// The field sizes depend on the coded index size and blob heap size.
///
/// # Marshalling Context
/// `FieldMarshal` entries define conversion rules for:
/// - **P/Invoke parameters**: Method parameter conversion for native calls
/// - **Interop fields**: Struct field marshalling for COM/native interop
/// - **Custom marshallers**: User-defined conversion classes
/// - **Array marshalling**: Element type and size information
/// - **String marshalling**: Character encoding and memory strategies
///
/// # Parent Entity Types
/// The `HasFieldMarshal` coded index can reference:
/// - **Field entities**: For field marshalling in interop structures
/// - **Parameter entities**: For parameter marshalling in P/Invoke methods
///
/// # ECMA-335 Reference
/// See ECMA-335, Partition II, §22.17 for the complete `FieldMarshal` table specification.
#[derive(Clone, Debug)]
pub struct FieldMarshalRaw {
    /// The row identifier in the `FieldMarshal` table.
    ///
    /// This 1-based index uniquely identifies this field marshal within the `FieldMarshal` table.
    pub rid: u32,

    /// The metadata token for this field marshal.
    ///
    /// A [`crate::metadata::token::Token`] that uniquely identifies this field marshal across the entire assembly.
    /// The token value is calculated as `0x0D000000 + rid`.
    pub token: Token,

    /// The byte offset of this field marshal in the metadata tables stream.
    ///
    /// This offset points to the start of this marshal's row data within the
    /// metadata tables stream, used for binary parsing and navigation.
    pub offset: usize,

    /// `HasFieldMarshal` coded index referencing the target entity.
    ///
    /// A [`crate::metadata::tables::CodedIndex`] that can reference either a Field or Param table entry.
    /// This determines which entity the marshalling specification applies to.
    ///
    /// # Coded Index Encoding
    /// - **Tag 0 (Field)**: References Field table entries
    /// - **Tag 1 (Param)**: References Param table entries
    pub parent: CodedIndex,

    /// Index into the Blob heap containing the marshalling signature.
    ///
    /// This index points to a binary marshalling descriptor in the Blob heap
    /// that specifies the native type and conversion rules according to
    /// ECMA-335 marshalling signature format.
    pub native_type: u32,
}

impl FieldMarshalRaw {
    /// Apply this field marshal to the referenced entity during metadata loading.
    ///
    /// This method applies the marshalling specification to the target field or parameter
    /// by looking up the entity in the provided maps and setting its marshal information.
    /// This is used during the raw metadata processing phase before full structure resolution.
    ///
    /// # Arguments
    /// * `blob` - The blob heap for marshalling signature parsing
    /// * `params` - Map of all parsed Param entries indexed by token
    /// * `fields` - Map of all parsed Field entries indexed by token
    ///
    /// # Returns
    /// Returns `Ok(())` on successful application, or an error if:
    /// - Blob lookup or marshalling descriptor parsing fails
    /// - Entity lookup in the appropriate map fails
    /// - Marshal information is already set on the target entity
    /// - Invalid parent entity type is encountered
    ///
    /// # Errors
    /// - **Parsing Error**: Invalid marshalling descriptor in blob heap
    /// - **Lookup Error**: Entity token not found in field/param map
    /// - **Duplicate Marshal**: Entity already has marshal information assigned
    /// - **Invalid Parent**: Unsupported parent entity type
    pub fn apply(&self, blob: &Blob, params: &ParamMap, fields: &FieldMap) -> Result<()> {
        let marshal = parse_marshalling_descriptor(blob.get(self.native_type as usize)?)?;

        match self.parent.tag {
            TableId::Field => match fields.get(&self.parent.token) {
                Some(field) => field
                    .value()
                    .marshal
                    .set(marshal)
                    .map_err(|_| malformed_error!("Marshal info already set for field")),
                None => Err(malformed_error!(
                    "Failed to resolve field token - {}",
                    self.parent.token.value()
                )),
            },
            TableId::Param => match params.get(&self.parent.token) {
                Some(param) => param
                    .value()
                    .marshal
                    .set(marshal)
                    .map_err(|_| malformed_error!("Marshal info already set for param")),
                None => Err(malformed_error!(
                    "Failed to resolve param token - {}",
                    self.parent.token.value()
                )),
            },
            _ => Err(malformed_error!(
                "Invalid parent token - {}",
                self.parent.token.value()
            )),
        }
    }

    /// Convert this raw field marshal to an owned [`crate::metadata::tables::fieldmarshal::owned::FieldMarshal`] with resolved indexes.
    ///
    /// This method resolves the coded index reference to an actual entity reference
    /// and parses the marshalling signature from the blob heap to create an owned
    /// structure with all dependencies resolved.
    ///
    /// # Arguments
    /// * `get_ref` - Function to resolve coded indexes to entity references
    /// * `blob` - The blob heap for marshalling signature parsing
    ///
    /// # Returns
    /// Returns an [`crate::metadata::tables::fieldmarshal::FieldMarshalRc`] with resolved entity reference and parsed marshalling data.
    ///
    /// # Errors
    /// - Parent reference resolution fails (returns None)
    /// - Blob lookup or marshalling descriptor parsing fails
    /// - Memory allocation fails during structure creation
    /// - Invalid marshalling signature is encountered
    pub fn to_owned<F>(&self, get_ref: F, blob: &Blob) -> Result<FieldMarshalRc>
    where
        F: Fn(&CodedIndex) -> CilTypeReference,
    {
        let parent = get_ref(&self.parent);
        if matches!(parent, CilTypeReference::None) {
            return Err(malformed_error!(
                "Failed to resolve parent token - {}",
                self.parent.token.value()
            ));
        }

        Ok(Arc::new(FieldMarshal {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            parent,
            native_type: Arc::new(parse_marshalling_descriptor(
                blob.get(self.native_type as usize)?,
            )?),
        }))
    }
}

impl TableRow for FieldMarshalRaw {
    /// Calculate the binary size of one `FieldMarshal` table row
    ///
    /// Returns the total byte size of a single `FieldMarshal` table row based on the table
    /// configuration. The size varies depending on the size of coded indexes and heap indexes.
    ///
    /// # Size Breakdown
    /// - `parent`: Variable bytes (`HasFieldMarshal` coded index)
    /// - `native_type`: Variable bytes (Blob heap index)
    ///
    /// Total: Variable size depending on coded index and heap size configuration
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* parent */      sizes.coded_index_bytes(CodedIndexType::HasFieldMarshal) +
            /* native_type */ sizes.blob_bytes()
        )
    }
}
