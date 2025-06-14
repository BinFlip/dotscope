use std::sync::Arc;

use crate::{
    metadata::{
        customattributes::CustomAttributeValueList,
        security::{PermissionSet, Security, SecurityAction},
        token::Token,
        typesystem::CilTypeReference,
    },
    Result,
};

/// The `DeclSecurity` table holds security declarations for types, methods, and assemblies. Similar to `DeclSecurityRaw` but
/// with resolved indexes and owned data
///
/// # .NET Security Declarations
///
/// Security declarations in .NET are applied at three levels:
///
/// 1. **Assembly Level**: Applied to the entire assembly, often to request minimum permissions
/// 2. **Type Level**: Applied to a class or interface, affecting all its members
/// 3. **Method Level**: Applied to a specific method
///
/// # Common Use Cases
///
/// Security declarations are commonly used for:
///
/// - Specifying that code requires specific permissions to run
/// - Preventing less-trusted code from calling sensitive methods
/// - Asserting permissions to allow operations that callers might not have permission for
/// - Preventing code from using certain permissions even if granted
///
/// # Fields
///
/// - `action`: Specifies how the permission is enforced (e.g., Demand, Assert, Deny)
/// - `parent`: References the target entity (type, method, or assembly)
/// - `permission_set`: Contains the actual permissions being declared
pub struct DeclSecurity {
    /// `RowID`
    pub rid: u32,
    /// Token
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// a 2-byte value representing the security action
    pub action: SecurityAction,
    /// an index into the `TypeDef`, `MethodDef`, or Assembly table; more precisely, a `HasDeclSecurity` (§II.24.2.6) coded index
    pub parent: CilTypeReference,
    /// The parsed permission set containing the security permissions
    pub permission_set: Arc<PermissionSet>,
    /// Custom attributes applied to this security declaration
    pub custom_attributes: CustomAttributeValueList,
}

impl DeclSecurity {
    /// Check if this is a demand security declaration
    #[must_use]
    pub fn is_demand(&self) -> bool {
        matches!(self.action, SecurityAction::Demand)
    }

    /// Check if this is an assert security declaration
    #[must_use]
    pub fn is_assert(&self) -> bool {
        matches!(self.action, SecurityAction::Assert)
    }

    /// Check if this is a deny security declaration
    #[must_use]
    pub fn is_deny(&self) -> bool {
        matches!(self.action, SecurityAction::Deny)
    }

    /// Check if this is a link demand security declaration
    #[must_use]
    pub fn is_link_demand(&self) -> bool {
        matches!(self.action, SecurityAction::LinkDemand)
    }

    /// Check if this is an inheritance demand security declaration
    #[must_use]
    pub fn is_inheritance_demand(&self) -> bool {
        matches!(self.action, SecurityAction::InheritanceDemand)
    }

    /// Check if this declaration grants unrestricted permissions
    #[must_use]
    pub fn is_unrestricted(&self) -> bool {
        self.permission_set.is_unrestricted()
    }

    /// Check if this declaration includes file IO permissions
    #[must_use]
    pub fn has_file_io(&self) -> bool {
        self.permission_set.has_file_io()
    }

    /// Check if this declaration includes registry permissions
    #[must_use]
    pub fn has_registry(&self) -> bool {
        self.permission_set.has_registry()
    }

    /// Check if this declaration includes reflection permissions
    #[must_use]
    pub fn has_reflection(&self) -> bool {
        self.permission_set.has_reflection()
    }

    /// Apply an `DeclSecurity` to the relevant entries of types (e.g. fields, methods and parameters)
    ///
    /// This method processes a raw security declaration and applies it to the appropriate
    /// entity (type, method, or assembly) by parsing the permission set and setting up the
    /// security context.
    ///
    /// # Errors
    /// Returns an error if the target entity has already been assigned security permissions
    /// or if there are issues applying the security declarations to the target entity.
    pub fn apply(&self) -> Result<()> {
        match &self.parent {
            CilTypeReference::TypeDef(typedef) => {
                if let Some(strong_ref) = typedef.upgrade() {
                    strong_ref
                        .security
                        .set(Security {
                            action: self.action,
                            permission_set: self.permission_set.clone(),
                        })
                        .ok();
                }
                Ok(())
            }
            CilTypeReference::MethodDef(method) => {
                if let Some(method) = method.upgrade() {
                    method
                        .security
                        .set(Security {
                            action: self.action,
                            permission_set: self.permission_set.clone(),
                        })
                        .ok();
                }

                Ok(())
            }
            CilTypeReference::Assembly(assembly) => {
                assembly
                    .security
                    .set(Security {
                        action: self.action,
                        permission_set: self.permission_set.clone(),
                    })
                    .ok();

                Ok(())
            }
            _ => Err(malformed_error!(
                "Invalid parent for {0}",
                self.token.value()
            )),
        }
    }
}
