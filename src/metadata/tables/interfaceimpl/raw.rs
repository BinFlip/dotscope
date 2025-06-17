//! Raw InterfaceImpl table structure with unresolved coded indexes.
//!
//! This module provides the [`crate::metadata::tables::InterfaceImplRaw`] struct, which represents interface implementation
//! entries as stored in the metadata stream. The structure contains unresolved coded indexes
//! and table references that require processing to become usable type relationships.
//!
//! # Purpose
//! [`crate::metadata::tables::InterfaceImplRaw`] serves as the direct representation of InterfaceImpl table entries from
//! the binary metadata stream, before type resolution and relationship establishment. This
//! raw format is processed during metadata loading to create [`crate::metadata::tables::InterfaceImpl`] instances
//! with resolved type references and applied relationships.
//!
//! [`InterfaceImpl`]: crate::metadata::tables::InterfaceImpl

use std::sync::Arc;

use crate::{
    file::io::read_le_at_dyn,
    metadata::{
        tables::{
            CodedIndex, CodedIndexType, InterfaceImpl, InterfaceImplRc, RowDefinition, TableId,
            TableInfoRef, TypeAttributes,
        },
        token::Token,
        typesystem::TypeRegistry,
    },
    Result,
};

/// Raw InterfaceImpl table entry with unresolved indexes and type references.
///
/// This structure represents an interface implementation entry as stored directly
/// in the metadata stream. All references are unresolved table indexes that require
/// processing during metadata loading to establish type system relationships.
///
/// # Table Structure (ECMA-335 §22.23)
/// | Column | Size | Description |
/// |--------|------|-------------|
/// | Class | TypeDef index | Type that implements the interface |
/// | Interface | TypeDefOrRef coded index | Interface being implemented |
///
/// # Coded Index Resolution
/// The `interface` field uses the TypeDefOrRef coded index encoding:
/// - **Tag 0**: TypeDef table (interfaces in current assembly)
/// - **Tag 1**: TypeRef table (interfaces from other assemblies)
/// - **Tag 2**: TypeSpec table (generic interface instantiations)
///
/// # Compiler Quirks
/// The .NET compiler incorrectly places interface inheritance relationships in the
/// InterfaceImpl table instead of using proper base type relationships. This requires
/// special handling during processing to distinguish between true interface implementation
/// and interface-to-interface inheritance.
#[derive(Clone, Debug)]
pub struct InterfaceImplRaw {
    /// Row identifier within the InterfaceImpl table.
    ///
    /// Unique identifier for this interface implementation entry, used for internal
    /// table management and token generation.
    pub rid: u32,

    /// Metadata token for this InterfaceImpl entry (TableId 0x09).
    ///
    /// Computed as `0x09000000 | rid` to create the full token value
    /// for referencing this interface implementation from other metadata structures.
    pub token: Token,

    /// Byte offset of this entry within the raw table data.
    ///
    /// Used for efficient table navigation and binary metadata processing.
    pub offset: usize,

    /// TypeDef table index for the implementing type.
    ///
    /// References the type (class or interface) that implements or extends the target interface.
    /// Requires token construction (`class | 0x02000000`) and TypeDef lookup during processing.
    pub class: u32,

    /// TypeDefOrRef coded index for the implemented interface.
    ///
    /// Points to the interface being implemented or extended. Uses coded index encoding
    /// to reference TypeDef, TypeRef, or TypeSpec tables for different interface sources.
    /// Requires coded index resolution during processing to obtain the actual interface type.
    pub interface: CodedIndex,
}

impl InterfaceImplRaw {
    /// Applies interface implementation directly to the type system.
    ///
    /// This method resolves type references and immediately establishes the interface
    /// implementation relationship in the type system. It's an alternative to the
    /// two-step process of conversion to owned structure followed by application.
    ///
    /// # Arguments
    /// * `types` - Type registry containing all resolved type definitions
    ///
    /// # Returns
    /// * `Ok(())` - Interface implementation applied successfully
    /// * `Err(_)` - Type reference resolution failed
    ///
    /// # Errors
    /// - Invalid class token or type not found in registry
    /// - Invalid interface coded index or type resolution failure
    pub fn apply(&self, types: &TypeRegistry) -> Result<()> {
        let Some(interface) = types.get(&self.interface.token) else {
            return Err(malformed_error!(
                "Failed to resolve interface token - {}",
                self.interface.token.value()
            ));
        };

        match types.get(&Token::new(self.class | 0x0200_0000)) {
            Some(class) => {
                // Check if this is interface inheritance (both class and interface are interfaces)
                // The .NET compiler incorrectly puts interface inheritance in InterfaceImpl table
                let class_is_interface = class.flags & TypeAttributes::INTERFACE != 0;
                let interface_is_interface = interface.flags & TypeAttributes::INTERFACE != 0;

                if class_is_interface && interface_is_interface {
                    if class.base().is_none() {
                        let _ = class.set_base(interface.clone().into());
                    }
                } else {
                    class.interfaces.push(interface.into());
                }
                Ok(())
            }
            None => Err(malformed_error!(
                "Failed to resolve class token - {}",
                self.class | 0x0200_0000
            )),
        }
    }

    /// Converts raw InterfaceImpl entry to owned structure with resolved type references.
    ///
    /// This method processes the raw table entry by resolving all type references,
    /// creating an [`crate::metadata::tables::interfaceimpl::owned::InterfaceImpl`] instance with owned data suitable for runtime
    /// use and further processing.
    ///
    /// # Arguments
    /// * `types` - Type registry containing all resolved type definitions
    ///
    /// # Returns
    /// * `Ok(InterfaceImplRc)` - Successfully converted owned InterfaceImpl structure
    /// * `Err(_)` - Type reference resolution failed
    ///
    /// # Errors
    /// - Invalid class token or type not found in registry
    /// - Invalid interface coded index or type resolution failure
    ///
    /// [`InterfaceImpl`]: crate::metadata::tables::InterfaceImpl
    pub fn to_owned(&self, types: &TypeRegistry) -> Result<InterfaceImplRc> {
        Ok(Arc::new(InterfaceImpl {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            class: match types.get(&Token::new(self.class | 0x0200_0000)) {
                Some(class) => class,
                None => {
                    return Err(malformed_error!(
                        "Failed to resolve class token - {}",
                        self.class | 0x0200_0000
                    ))
                }
            },
            interface: match types.get(&self.interface.token) {
                Some(interface) => interface,
                None => {
                    return Err(malformed_error!(
                        "Failed to resolve interface token - {}",
                        self.interface.token.value()
                    ))
                }
            },
            custom_attributes: Arc::new(boxcar::Vec::new()),
        }))
    }
}

impl<'a> RowDefinition<'a> for InterfaceImplRaw {
    /// Calculates the byte size of an InterfaceImpl table row based on table sizing information.
    ///
    /// The row size depends on the size of table indexes and coded indexes,
    /// which vary based on the total number of entries in referenced tables.
    ///
    /// # Row Layout
    /// - class: Variable size TypeDef table index (2 or 4 bytes)
    /// - interface: Variable size TypeDefOrRef coded index
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* class */        sizes.table_index_bytes(TableId::TypeDef) +
            /* interface */    sizes.coded_index_bytes(CodedIndexType::TypeDefOrRef)
        )
    }

    /// Reads a single InterfaceImpl table row from binary metadata stream.
    ///
    /// Parses the binary representation of an InterfaceImpl entry, reading fields
    /// in the order specified by ECMA-335 and handling variable-size indexes
    /// based on table sizing information.
    ///
    /// # Arguments
    /// * `data` - Binary data containing the table row
    /// * `offset` - Current read position, updated after reading
    /// * `rid` - Row identifier for this entry
    /// * `sizes` - Table sizing information for variable-width fields
    ///
    /// # Returns
    /// * `Ok(InterfaceImplRaw)` - Successfully parsed table row
    /// * `Err(_)` - Binary data reading or parsing error
    fn read_row(
        data: &'a [u8],
        offset: &mut usize,
        rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<Self> {
        Ok(InterfaceImplRaw {
            rid,
            token: Token::new(0x0900_0000 + rid),
            offset: *offset,
            class: read_le_at_dyn(data, offset, sizes.is_large(TableId::TypeDef))?,
            interface: CodedIndex::read(data, offset, sizes, CodedIndexType::TypeDefOrRef)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::metadata::tables::{MetadataTable, TableInfo};

    use super::*;

    #[test]
    fn crafted_short() {
        let data = vec![
            0x01, 0x01, // class
            0x02, 0x02, // interface
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::InterfaceImpl, 1)],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<InterfaceImplRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: InterfaceImplRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x09000001);
            assert_eq!(row.class, 0x0101);
            assert_eq!(
                row.interface,
                CodedIndex {
                    tag: TableId::TypeSpec,
                    row: 0x80,
                    token: Token::new(0x80 | 0x1B000000),
                }
            );
        };

        {
            for row in table.iter() {
                eval(row);
            }
        }

        {
            let row = table.get(1).unwrap();
            eval(row);
        }
    }

    #[test]
    fn crafted_long() {
        let data = vec![
            0x01, 0x01, 0x01, 0x01, // class
            0x02, 0x02, 0x02, 0x02, // interface
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::TypeDef, u16::MAX as u32 + 2)],
            true,
            true,
            true,
        ));
        let table =
            MetadataTable::<InterfaceImplRaw>::new(&data, u16::MAX as u32 + 2, sizes).unwrap();

        let eval = |row: InterfaceImplRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x09000001);
            assert_eq!(row.class, 0x01010101);
            assert_eq!(
                row.interface,
                CodedIndex {
                    tag: TableId::TypeSpec,
                    row: 0x808080,
                    token: Token::new(0x808080 | 0x1B000000),
                }
            );
        };

        {
            let row = table.get(1).unwrap();
            eval(row);
        }
    }
}
