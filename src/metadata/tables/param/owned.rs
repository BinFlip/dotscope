use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, OnceLock,
};

use crate::{
    metadata::{
        customattributes::CustomAttributeValueList,
        marshalling::MarshallingInfo,
        signatures::SignatureParameter,
        token::Token,
        typesystem::{CilPrimitive, CilTypeRef, CilTypeRefList, TypeRegistry, TypeResolver},
    },
    Result,
};

/// The `Param` table defines parameters for methods in the `MethodDef` table. Similar to `ParamRaw` but
/// with resolved indexes and owned data.
pub struct Param {
    /// `RowID`
    pub rid: u32,
    /// Token
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// bitmask of `ParamAttributes`, §II.23.1.13
    pub flags: u32,
    /// The sequence number (0 for return value)
    pub sequence: u32,
    /// The parameter name
    pub name: Option<String>,
    /// `flags.HAS_DEFAULT` -> This is the default value of this parameter
    pub default: OnceLock<CilPrimitive>,
    /// `flags.HAS_MARSHAL` -> The marshal instructions for `PInvoke`
    pub marshal: OnceLock<MarshallingInfo>,
    /// Custom modifiers that are applied to this `Param`
    pub modifiers: CilTypeRefList,
    /// The underlaying type of this `Param`
    pub base: OnceLock<CilTypeRef>,
    /// Is the parameter passed by reference
    pub is_by_ref: AtomicBool,
    /// Custom attributes applied to this parameter
    pub custom_attributes: CustomAttributeValueList,
}

impl Param {
    /// Apply a signature to this parameter, will cause update with type information
    ///
    /// # Errors
    ///
    /// Returns an error if type resolution fails, if modifier types cannot be resolved,
    /// if the base type has already been set for this parameter, or if sequence validation fails.
    ///
    /// ## Arguments
    /// * 'signature'   - The signature to apply to this parameter
    /// * 'types'       - The type registry for lookup and generation of types
    /// * `method_param_count` - Total number of parameters in the method signature (for validation)
    pub fn apply_signature(
        &self,
        signature: &SignatureParameter,
        types: Arc<TypeRegistry>,
        method_param_count: Option<usize>,
    ) -> Result<()> {
        if let Some(param_count) = method_param_count {
            #[allow(clippy::cast_possible_truncation)]
            if self.sequence > param_count as u32 {
                return Err(malformed_error!(
                    "Parameter sequence {} exceeds method parameter count {} for parameter token {}",
                    self.sequence,
                    param_count,
                    self.token.value()
                ));
            }
        }
        self.is_by_ref.store(signature.by_ref, Ordering::Relaxed);

        for modifier in &signature.modifiers {
            match types.get(modifier) {
                Some(new_mod) => {
                    self.modifiers.push(new_mod.into());
                }
                None => {
                    return Err(malformed_error!(
                        "Failed to resolve modifier type - {}",
                        modifier.value()
                    ))
                }
            }
        }

        let mut resolver = TypeResolver::new(types);
        let resolved_type = resolver.resolve(&signature.base)?;

        // Handle the case where multiple methods share the same parameter
        // This is valid in .NET metadata and happens when methods have identical signatures
        if self.base.set(resolved_type.clone().into()).is_err() {
            if let Some(existing_type_ref) = self.base.get() {
                let existing_type = existing_type_ref.upgrade().ok_or_else(|| {
                    malformed_error!(
                        "Invalid type reference: existing parameter type has been dropped"
                    )
                })?;

                if !resolved_type.is_compatible_with(&existing_type) {
                    return Err(malformed_error!(
                        "Type compatibility error: parameter {} cannot be shared between methods with incompatible types",
                        self.token.value()
                    ));
                }
            }
        }
        Ok(())
    }
}
