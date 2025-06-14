use crate::{
    metadata::{
        customattributes::CustomAttributeValueList, tables::TypeAttributes, token::Token,
        typesystem::CilTypeRc,
    },
    Result,
};

/// The `InterfaceImpl` table defines interface implementations for types in the `TypeDef` table. Similar to `InterfaceImpl` but
/// with resolved indexes and owned data
pub struct InterfaceImpl {
    /// `RowID`
    pub rid: u32,
    /// Token
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// The class that implements this interface
    pub class: CilTypeRc,
    /// The interface base type
    pub interface: CilTypeRc,
    /// Custom attributes applied to this interface implementation
    pub custom_attributes: CustomAttributeValueList,
}

impl InterfaceImpl {
    /// Apply an `InterfaceImpl` - Updates the class to point to the right interface method
    ///
    /// # Errors
    /// Returns an error if the interface cannot be added to the class.
    pub fn apply(&self) -> Result<()> {
        // Check if this is interface inheritance (both class and interface are interfaces)
        // The .NET compiler incorrectly puts interface inheritance in InterfaceImpl table
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
