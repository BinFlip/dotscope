//! Owned `FieldMarshal` structures for the `FieldMarshal` metadata table.
//!
//! This module provides the [`crate::metadata::tables::fieldmarshal::owned::FieldMarshal`] struct which represents marshalling
//! specifications with resolved references and owned data. Field marshals define
//! how fields and parameters should be converted when crossing managed/unmanaged
//! boundaries during interop operations.
//!
//! # Purpose
//! The `FieldMarshal` table is critical for interop scenarios:
//! - **P/Invoke marshalling**: Converting parameters for native function calls
//! - **COM interop**: Field and parameter handling for COM objects
//! - **Custom marshalling**: User-defined conversion behavior
//! - **Array marshalling**: Element type and size specifications
//! - **String marshalling**: Character encoding and memory management
//!
//! # Marshalling Scenarios
//! - **Parameter marshalling**: Method parameter conversion for native calls
//! - **Field marshalling**: Struct field layout for interop types
//! - **Return value marshalling**: Converting return values from native code
//! - **Callback marshalling**: Delegate parameter conversion
//! - **Structure marshalling**: Complex type layout preservation
//!
//! # ECMA-335 Reference
//! See ECMA-335, Partition II, §22.17 for the `FieldMarshal` table specification.

use std::sync::Arc;

use crate::{
    metadata::{marshalling::MarshallingInfo, token::Token, typesystem::CilTypeReference},
    Result,
};

/// Represents a field marshal specification with resolved references and owned data.
///
/// A field marshal defines how a specific field or parameter should be marshalled
/// when crossing managed/unmanaged boundaries. This includes type conversion rules,
/// memory management strategies, and platform-specific handling requirements.
///
/// # Marshalling Context
/// Field marshals are applied in various interop scenarios:
/// - **P/Invoke calls**: Converting managed parameters to native representations
/// - **COM interop**: Handling COM interface parameters and fields
/// - **Callback functions**: Converting delegate parameters for native callbacks
/// - **Structure layouts**: Ensuring proper field alignment in interop types
/// - **Array handling**: Managing array element marshalling and size information
///
/// # Parent Types
/// The marshal specification can apply to:
/// - **Fields**: Instance or static fields requiring specific marshalling
/// - **Parameters**: Method parameters for P/Invoke or COM calls
///
/// # ECMA-335 Reference
/// See ECMA-335, Partition II, §22.17 for the complete `FieldMarshal` table specification.
pub struct FieldMarshal {
    /// The row identifier in the `FieldMarshal` table.
    ///
    /// This 1-based index uniquely identifies this field marshal within the `FieldMarshal` table.
    /// Combined with the table type, it forms the marshal entry's unique identity.
    pub rid: u32,

    /// The metadata token for this field marshal.
    ///
    /// A [`crate::metadata::token::Token`] that uniquely identifies this field marshal across the entire assembly.
    /// The token encodes both the table type (`FieldMarshal`) and the row ID.
    pub token: Token,

    /// The byte offset of this field marshal in the metadata tables stream.
    ///
    /// This offset points to the start of this marshal's row data within the
    /// metadata tables stream, used for binary parsing and navigation.
    pub offset: usize,

    /// Reference to the entity that this marshalling rule applies to.
    ///
    /// A [`crate::metadata::typesystem::CilTypeReference`] that can point to either a Field or Parameter entry.
    /// This is resolved from the `HasFieldMarshal` coded index in the raw table data.
    ///
    /// # Valid Parent Types
    /// - **Field**: For field marshalling in interop structures
    /// - **Param**: For parameter marshalling in P/Invoke or COM methods
    pub parent: CilTypeReference,

    /// The marshalling specification for this field or parameter.
    ///
    /// A reference-counted [`crate::metadata::marshalling::MarshallingInfo`] structure containing the detailed
    /// marshalling rules, including native type, size information, custom marshaller
    /// details, and platform-specific conversion requirements.
    ///
    /// # Marshalling Information
    /// - **Native type**: Target native type (BOOL, LPSTR, etc.)
    /// - **Size information**: Array sizes, string lengths
    /// - **Custom marshaller**: User-defined marshaller class
    /// - **Encoding**: Character encoding for strings
    /// - **Memory management**: Allocation and cleanup strategies
    pub native_type: Arc<MarshallingInfo>,
}

impl FieldMarshal {
    /// Apply this field marshal to the referenced entity.
    ///
    /// This method applies the marshalling specification to the target field or parameter,
    /// updating the entity's marshal information. Since this is the owned structure, all
    /// references are already resolved, enabling efficient entity updates.
    ///
    /// # Returns
    /// Returns `Ok(())` on successful application, or an error if:
    /// - Marshal information is already set on the target entity
    /// - Parent entity type is invalid or unsupported
    /// - Memory allocation fails during the assignment
    /// - Thread safety constraints are violated
    ///
    /// # Errors
    /// - **Duplicate Marshal**: If the entity already has marshal information assigned
    /// - **Invalid Parent**: If the parent reference is not a Field or Param
    /// - **Type Mismatch**: If the entity type doesn't support marshalling
    /// - **Memory Error**: If allocation fails during assignment
    pub fn apply(&self) -> Result<()> {
        match &self.parent {
            CilTypeReference::Field(field) => field
                .marshal
                .set(self.native_type.as_ref().clone())
                .map_err(|_| malformed_error!("Marshal info already set for field")),
            CilTypeReference::Param(param) => param
                .marshal
                .set(self.native_type.as_ref().clone())
                .map_err(|_| malformed_error!("Marshal info already set for param")),
            _ => Err(malformed_error!(
                "Invalid parent type for field marshal - {}",
                self.token.value()
            )),
        }
    }
}
