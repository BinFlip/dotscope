//! Owned `InterfaceImpl` table structure with resolved type references.
//!
//! This module provides the [`crate::metadata::tables::interfaceimpl::owned::InterfaceImpl`] struct, which represents interface implementation
//! entries with all type references resolved and data owned. Unlike [`crate::metadata::tables::interfaceimpl::raw::InterfaceImplRaw`], this
//! structure contains resolved type references for both implementing classes and implemented interfaces.

use crate::{
    metadata::{
        customattributes::CustomAttributeValueList, tables::TypeAttributes, token::Token,
        typesystem::CilTypeRc,
    },
    Result,
};

/// Owned `InterfaceImpl` table entry with resolved type references and owned data.
///
/// This structure represents an interface implementation relationship with all coded indexes
/// resolved to their target type structures. It defines which types implement which interfaces,
/// forming the foundation of .NET's interface-based inheritance system.
///
/// # Interface Implementation Types
/// The structure handles two distinct relationship patterns:
/// - **Class implements interface**: Standard interface implementation by concrete types
/// - **Interface extends interface**: Interface inheritance (incorrectly placed in `InterfaceImpl` by compiler)
pub struct InterfaceImpl {
    /// Row identifier within the `InterfaceImpl` table.
    ///
    /// Unique identifier for this interface implementation entry, used for internal
    /// table management and cross-references.
    pub rid: u32,

    /// Metadata token identifying this `InterfaceImpl` entry.
    ///
    /// The token enables efficient lookup and reference to this interface implementation
    /// from other metadata structures and runtime systems.
    pub token: Token,

    /// Byte offset of this entry within the raw table data.
    ///
    /// Used for efficient table navigation and binary metadata processing.
    pub offset: usize,

    /// Resolved reference to the type that implements the interface.
    ///
    /// Points to the class or interface that declares implementation of the target interface.
    /// In cases of interface inheritance, this may also be an interface type.
    pub class: CilTypeRc,

    /// Resolved reference to the interface being implemented.
    ///
    /// Points to the interface type that is being implemented or extended. This may be
    /// a generic interface instantiation for parameterized interface implementations.
    pub interface: CilTypeRc,

    /// Custom attributes applied to this interface implementation.
    ///
    /// Collection of custom attributes that provide additional metadata about the
    /// interface implementation relationship, such as explicit implementation attributes.
    pub custom_attributes: CustomAttributeValueList,
}

impl InterfaceImpl {
    /// Applies the interface implementation relationship to the type system.
    ///
    /// This method establishes the interface implementation relationship by updating the
    /// implementing type's interface list or base type. It handles both standard interface
    /// implementation and interface inheritance patterns.
    ///
    /// # Returns
    /// * `Ok(())` - Interface implementation applied successfully
    /// * `Err(_)` - Reserved for future error conditions (currently infallible)
    /// # Errors
    ///
    /// This function never returns an error; it always returns `Ok(())`.
    pub fn apply(&self) -> Result<()> {
        // Check if this is interface inheritance (both class and interface are interfaces)
        // The .NET compiler incorrectly puts interface inheritance in `InterfaceImpl` table
        let class_is_interface = self.class.flags & TypeAttributes::INTERFACE != 0;
        let interface_is_interface = self.interface.flags & TypeAttributes::INTERFACE != 0;

        if class_is_interface && interface_is_interface {
            if self.class.base().is_none() {
                let _ = self.class.set_base(self.interface.clone().into());
            }
        } else {
            self.class.interfaces.push(self.interface.clone().into());
        }
        Ok(())
    }
}
