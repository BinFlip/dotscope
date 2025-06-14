use std::sync::Arc;

use crate::{
    metadata::{marshalling::MarshallingInfo, token::Token, typesystem::CilTypeReference},
    Result,
};

/// The `FieldMarshal` table specifies marshaling information for fields and parameters. Similar to `FieldMarshalRaw` but
/// with resolved indexes and owned data
pub struct FieldMarshal {
    /// `RowID`
    pub rid: u32,
    /// Token
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// an index into Field or Param table; more precisely, a `HasFieldMarshal` (§II.24.2.6) coded index
    pub parent: CilTypeReference,
    /// The `MarshallingDescriptor` for a specific field
    pub native_type: Arc<MarshallingInfo>,
}

impl FieldMarshal {
    /// Apply a `FieldMarshal` to set the marshalling information on the parent entity (field or parameter)
    ///
    /// Since this is the owned structure, all references are already resolved, so we can
    /// efficiently update the parent without re-resolving anything.
    ///
    /// # Errors
    /// Returns an error if the marshal information is already set for the parent entity
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
