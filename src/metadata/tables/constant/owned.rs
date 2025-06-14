use std::sync::Arc;

use crate::{
    metadata::{
        token::Token,
        typesystem::{CilPrimitive, CilTypeReference},
    },
    Result,
};

/// The Constant table stores constant values for fields, parameters, and properties. Similar to `ConstantRaw` but
/// with resolved indexes and owned data
pub struct Constant {
    /// `RowID`
    pub rid: u32,
    /// Token
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// a 1-byte constant, followed by a 1-byte padding zero); see §II.23.1.16. The encoding of Type for the
    /// nullref value for `FieldInit` in ilasm (§II.16.2) is `ELEMENT_TYPE_CLASS` with a Value of a 4-byte zero.
    /// Unlike uses of `ELEMENT_TYPE_CLASS` in signatures, this one is not followed by a type toke
    pub c_type: u8,
    /// an index into the `Param`, `Field`, or `Property` table; more precisely, a `HasConstant` (§II.24.2.6) coded index
    pub parent: CilTypeReference,
    /// The const value
    pub value: Arc<CilPrimitive>,
}

impl Constant {
    /// Apply a `Constant` to set the default value on the parent entity (field, parameter, or property)
    ///
    /// # Errors
    /// Returns an error if the default value is already set for the parent entity,
    /// or if the constant value is not compatible with the target type
    pub fn apply(&self) -> Result<()> {
        match &self.parent {
            CilTypeReference::Field(field) => {
                if !field.signature.base.accepts_constant(&self.value) {
                    return Err(malformed_error!(
                        "Constant type {:?} is not compatible with field type: {:?} (token: {})",
                        self.value.kind,
                        field.signature.base,
                        self.token.value()
                    ));
                }

                field
                    .default
                    .set(self.value.as_ref().clone())
                    .map_err(|_| malformed_error!("Default value already set for field"))
            }
            CilTypeReference::Param(param) => {
                if let Some(param_type) = param.base.get() {
                    if let Some(param_type_strong) = param_type.upgrade() {
                        if !param_type_strong.accepts_constant(&self.value) {
                            return Err(malformed_error!(
                                "Constant type {:?} is not compatible with parameter type {} (token: {})",
                                self.value.kind,
                                param_type_strong.fullname(),
                                self.token.value()
                            ));
                        }
                    }
                }

                param
                    .default
                    .set(self.value.as_ref().clone())
                    .map_err(|_| malformed_error!("Default value already set for param"))
            }
            CilTypeReference::Property(property) => {
                if !property.signature.base.accepts_constant(&self.value) {
                    return Err(malformed_error!(
                        "Constant type {:?} is not compatible with property type: {:?} (token: {})",
                        self.value.kind,
                        property.signature.base,
                        self.token.value()
                    ));
                }

                property
                    .default
                    .set(self.value.as_ref().clone())
                    .map_err(|_| malformed_error!("Default value already set for property"))
            }
            _ => Err(malformed_error!(
                "Invalid parent type for constant - {}",
                self.token.value()
            )),
        }
    }
}
