use std::sync::Arc;

use crate::{
    metadata::{
        customattributes::CustomAttributeValue, token::Token, typesystem::CilTypeReference,
    },
    Result,
};

/// The `CustomAttribute` table associates attributes with elements in various metadata tables. Similar to `CustomAttributeRaw` but
/// with resolved indexes and owned data
pub struct CustomAttribute {
    /// `RowID`
    pub rid: u32,
    /// Token
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// Resolved parent object that has this custom attribute attached
    pub parent: CilTypeReference,
    /// Resolved constructor (`MethodDef` or `MemberRef`) for this custom attribute
    pub constructor: CilTypeReference,
    /// Parsed custom attribute value
    pub value: CustomAttributeValue,
}

impl CustomAttribute {
    /// Apply a `CustomAttribute` to attach it to its parent metadata element
    ///
    /// This method attaches the custom attribute value to its resolved parent object by adding it
    /// to the parent's custom attribute collection. The custom attribute value is stored as an
    /// `Arc<CustomAttributeValue>` for efficient memory usage and sharing.
    ///
    /// # Errors
    /// Returns an error if the parent type is not supported for custom attributes
    /// or if custom attribute storage is not implemented for the parent type.
    pub fn apply(&self) -> Result<()> {
        let attribute_value = Arc::new(self.value.clone());

        match &self.parent {
            CilTypeReference::TypeDef(entry)
            | CilTypeReference::TypeSpec(entry)
            | CilTypeReference::TypeRef(entry) => {
                if let Some(type_ref) = entry.upgrade() {
                    type_ref.custom_attributes.push(attribute_value);
                    Ok(())
                } else {
                    Err(malformed_error!("Type reference is no longer valid"))
                }
            }
            CilTypeReference::MethodDef(entry) => {
                if let Some(method) = entry.upgrade() {
                    method.custom_attributes.push(attribute_value);
                    Ok(())
                } else {
                    Err(malformed_error!("Method reference is no longer valid"))
                }
            }
            CilTypeReference::Field(entry) => {
                entry.custom_attributes.push(attribute_value);
                Ok(())
            }
            CilTypeReference::Param(entry) => {
                entry.custom_attributes.push(attribute_value);
                Ok(())
            }
            CilTypeReference::Property(entry) => {
                entry.custom_attributes.push(attribute_value);
                Ok(())
            }
            CilTypeReference::Event(entry) => {
                entry.custom_attributes.push(attribute_value);
                Ok(())
            }
            CilTypeReference::Assembly(entry) => {
                entry.custom_attributes.push(attribute_value);
                Ok(())
            }
            CilTypeReference::Module(entry) => {
                entry.custom_attributes.push(attribute_value);
                Ok(())
            }
            CilTypeReference::InterfaceImpl(entry) => {
                entry.custom_attributes.push(attribute_value);
                Ok(())
            }
            CilTypeReference::MemberRef(entry) => {
                entry.custom_attributes.push(attribute_value);
                Ok(())
            }
            CilTypeReference::DeclSecurity(entry) => {
                entry.custom_attributes.push(attribute_value);
                Ok(())
            }
            CilTypeReference::StandAloneSig(entry) => {
                entry.custom_attributes.push(attribute_value);
                Ok(())
            }
            CilTypeReference::ModuleRef(entry) => {
                entry.custom_attributes.push(attribute_value);
                Ok(())
            }
            CilTypeReference::AssemblyRef(entry) => {
                entry.custom_attributes.push(attribute_value);
                Ok(())
            }
            CilTypeReference::File(entry) => {
                entry.custom_attributes.push(attribute_value);
                Ok(())
            }
            CilTypeReference::ExportedType(entry) => {
                entry.custom_attributes.push(attribute_value);
                Ok(())
            }
            CilTypeReference::GenericParam(entry) => {
                entry.custom_attributes.push(attribute_value);
                Ok(())
            }
            CilTypeReference::GenericParamConstraint(entry) => {
                entry.custom_attributes.push(attribute_value);
                Ok(())
            }
            CilTypeReference::MethodSpec(entry) => {
                entry.custom_attributes.push(attribute_value);
                Ok(())
            }
            //CilTypeReference::ManifestResource(entry) => {},
            CilTypeReference::None => {
                // For now, just return Ok() for unsupported parent types
                Ok(())
            }
        }
    }
}
