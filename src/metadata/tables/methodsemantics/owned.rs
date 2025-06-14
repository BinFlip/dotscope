use crate::{
    metadata::{
        method::MethodRc, tables::MethodSemanticsAttributes, token::Token,
        typesystem::CilTypeReference,
    },
    Result,
};

/// The `MethodSemantics` table specifies the relationship between methods and events or properties.
/// It defines which methods are getters, setters, adders, removers, etc. Similar to `ConstantRaw` but
/// with resolved indexes and owned data
pub struct MethodSemantics {
    /// `RowID`
    pub rid: u32,
    /// Token
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// a 2-byte bitmask of type `MethodSemanticsAttributes`, §II.23.1.12
    pub semantics: u32,
    /// an index into the `MethodDef` table
    pub method: MethodRc,
    /// a `HasSemantics` coded index
    pub association: CilTypeReference,
}

impl MethodSemantics {
    /// Apply a `MethodSemantics` entry - The associated type fill be updated to have it's getter/setter set
    ///
    /// # Errors
    /// Returns an error if the semantics attributes are invalid or if the property/event
    /// assignment fails.
    pub fn apply(&self) -> Result<()> {
        match &self.association {
            CilTypeReference::Property(property) => match self.semantics {
                MethodSemanticsAttributes::SETTER => property
                    .fn_setter
                    .set(self.method.clone().into())
                    .map_err(|_| malformed_error!("Property setter already set".to_string())),
                MethodSemanticsAttributes::GETTER => property
                    .fn_getter
                    .set(self.method.clone().into())
                    .map_err(|_| malformed_error!("Property getter already set".to_string())),
                MethodSemanticsAttributes::OTHER => property
                    .fn_other
                    .set(self.method.clone().into())
                    .map_err(|_| malformed_error!("Property other already set".to_string())),
                _ => Err(malformed_error!("Invalid property semantics".to_string())),
            },
            CilTypeReference::Event(event) => match self.semantics {
                MethodSemanticsAttributes::ADD_ON => event
                    .fn_on_add
                    .set(self.method.clone().into())
                    .map_err(|_| malformed_error!("Event add method already set".to_string())),
                MethodSemanticsAttributes::REMOVE_ON => event
                    .fn_on_remove
                    .set(self.method.clone().into())
                    .map_err(|_| malformed_error!("Event remove method already set".to_string())),
                MethodSemanticsAttributes::FIRE => event
                    .fn_on_raise
                    .set(self.method.clone().into())
                    .map_err(|_| malformed_error!("Event raise method already set".to_string())),
                MethodSemanticsAttributes::OTHER => event
                    .fn_on_other
                    .set(self.method.clone().into())
                    .map_err(|_| malformed_error!("Event other method already set".to_string())),
                _ => Err(malformed_error!("Invalid event semantics".to_string())),
            },
            _ => Err(malformed_error!("Invalid association".to_string())),
        }
    }
}
