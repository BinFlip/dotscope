use crate::{
    metadata::{
        token::Token,
        typesystem::{CilTypeRc, CilTypeReference},
    },
    Result,
};

/// The `MethodImpl` table specifies which methods implement which methods for a class. Similar to `MethodImplRaw` but
/// with resolved indexes and owned data
pub struct MethodImpl {
    /// `RowID`
    pub rid: u32,
    /// Token
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// The `CilType` which implements the Interface
    pub class: CilTypeRc,
    /// The `Method` owned by 'class' that is implementing the interface functionality
    pub method_body: CilTypeReference,
    /// The 'Interface' definition
    pub method_declaration: CilTypeReference,
}

impl MethodImpl {
    /// Apply a `MethodImpl` to update the class with interface implementation information.
    ///
    /// Since this is the owned structure, all references are already resolved, so we can
    /// efficiently update the class without re-resolving anything. This establishes the
    /// bidirectional relationship between interface methods and their implementations.
    ///
    /// # Errors
    /// Returns an error if updating the class overwrite information fails.
    pub fn apply(&self) -> Result<()> {
        self.class.overwrites.push(self.method_body.clone());

        if let CilTypeReference::MethodDef(method_ref) = &self.method_declaration {
            if let Some(method) = method_ref.upgrade() {
                if let CilTypeReference::MethodDef(body_method_ref) = &self.method_body {
                    method.interface_impls.push(body_method_ref.clone());
                }
            }
        }

        Ok(())
    }
}
