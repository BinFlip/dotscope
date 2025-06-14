use std::sync::{Arc, OnceLock};

use crate::{
    metadata::{
        customattributes::CustomAttributeValueList,
        token::Token,
        typesystem::{CilTypeRefList, CilTypeReference},
    },
    Result,
};

/// The `GenericParam` table defines generic parameters for generic types and methods. Similar to `GenericParamRaw` but
/// with resolved indexes and owned data
pub struct GenericParam {
    /// `RowID`
    pub rid: u32,
    /// Token
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// a 2-byte index of the generic parameter, numbered left-to-right, from zero
    pub number: u32,
    /// a 2-byte bitmask of type `GenericParamAttributes`, §II.23.1.7
    pub flags: u32,
    /// The owner of this `GenericParam`
    pub owner: OnceLock<CilTypeReference>,
    /// The contrained type that applies to this `GenericParam`
    pub constraints: CilTypeRefList,
    /// Name of the generic parameter
    pub name: String,
    /// Custom attributes applied to this `GenericParam`
    pub custom_attributes: CustomAttributeValueList,
}

impl GenericParam {
    /// Apply an `GenericParam` - The owner will be updated with the new `GenericParam` entry
    ///
    /// # Errors
    /// Returns an error if the owner type reference is invalid or not set
    pub fn apply(self: &Arc<Self>) -> Result<()> {
        match self.owner.get() {
            Some(owner) => match owner {
                CilTypeReference::TypeDef(cil_type) => {
                    if let Some(generic_params) = cil_type.generic_params() {
                        generic_params.push(self.clone());
                    }

                    Ok(())
                }
                CilTypeReference::MethodDef(method) => {
                    if let Some(method) = method.upgrade() {
                        method.generic_params.push(self.clone());
                    }

                    Ok(())
                }
                _ => Err(malformed_error!("Invalid owner type reference")),
            },
            None => Err(malformed_error!("No owner type reference")),
        }
    }
}
