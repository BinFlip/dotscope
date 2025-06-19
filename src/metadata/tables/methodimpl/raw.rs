//! Raw `MethodImpl` table structure with unresolved coded indexes.
//!
//! This module provides the [`MethodImplRaw`] struct, which represents method implementation
//! mappings as stored in the metadata stream. The structure contains unresolved coded indexes
//! that require processing to establish complete implementation mapping information.
//!
//! # Purpose
//! [`MethodImplRaw`] serves as the direct representation of `MethodImpl` table entries from the
//! binary metadata stream, before reference resolution and type system integration. This raw
//! format is processed during metadata loading to create [`MethodImpl`] instances with resolved
//! references and complete implementation mapping information.
//!
//! [`MethodImpl`]: crate::metadata::tables::MethodImpl

use std::sync::Arc;

use crate::{
    file::io::read_le_at_dyn,
    metadata::{
        method::MethodMap,
        tables::{
            CodedIndex, CodedIndexType, MemberRefMap, MethodImpl, MethodImplRc, RowDefinition,
            TableId, TableInfoRef,
        },
        token::Token,
        typesystem::{CilTypeReference, TypeRegistry},
    },
    Result,
};

/// Raw `MethodImpl` table entry with unresolved indexes and coded references.
///
/// This structure represents a method implementation mapping as stored directly in the metadata
/// stream. All references are unresolved indexes or coded indexes that require processing during
/// metadata loading to establish complete implementation mapping information.
///
/// # Table Structure (ECMA-335 §22.27)
/// | Column | Size | Description |
/// |--------|------|-------------|
/// | Class | `TypeDef` index | Type containing the implementation mapping |
/// | `MethodBody` | `MethodDefOrRef` coded index | Concrete method implementation |
/// | `MethodDeclaration` | `MethodDefOrRef` coded index | Method declaration being implemented |
///
/// # Coded Index Resolution
/// Both `method_body` and `method_declaration` use `MethodDefOrRef` coded index encoding:
/// - **Tag 0**: `MethodDef` table (methods defined in current assembly)
/// - **Tag 1**: `MemberRef` table (methods referenced from external assemblies)
///
/// # Implementation Mapping Logic
/// The mapping establishes the relationship:
/// - **Class**: Contains the concrete implementation method
/// - **`MethodBody`**: The actual implementation that provides the behavior
/// - **`MethodDeclaration`**: The interface or virtual method being implemented
#[derive(Clone, Debug)]
pub struct MethodImplRaw {
    /// Row identifier within the `MethodImpl` table.
    ///
    /// Unique identifier for this method implementation mapping entry, used for internal
    /// table management and token generation.
    pub rid: u32,

    /// Metadata token for this `MethodImpl` entry (`TableId` 0x19).
    ///
    /// Computed as `0x19000000 | rid` to create the full token value
    /// for referencing this implementation mapping from other metadata structures.
    pub token: Token,

    /// Byte offset of this entry within the raw table data.
    ///
    /// Used for efficient table navigation and binary metadata processing.
    pub offset: usize,

    /// `TypeDef` table index for the class containing the implementation mapping.
    ///
    /// References the type that provides the concrete implementation for the method
    /// declaration. The class contains the method body that implements the interface
    /// contract or overrides the virtual method.
    pub class: u32,

    /// `MethodDefOrRef` coded index for the concrete method implementation.
    ///
    /// Points to `MethodDef` or `MemberRef` tables to specify the actual method that
    /// provides the implementation behavior. This method belongs to the class and
    /// contains the IL code or native implementation.
    pub method_body: CodedIndex,

    /// `MethodDefOrRef` coded index for the method declaration being implemented.
    ///
    /// Points to `MethodDef` or `MemberRef` tables to specify the interface method,
    /// abstract method, or virtual method declaration that is being implemented.
    /// This establishes the contract that the implementation must fulfill.
    pub method_declaration: CodedIndex,
}

impl MethodImplRaw {
    /// Applies a `MethodImplRaw` entry to update type system implementation relationships.
    ///
    /// This method establishes bidirectional relationships between method declarations
    /// and their implementations by updating type system collections. It resolves
    /// coded indexes to concrete method references and updates both the implementing
    /// class and the declared method with cross-reference information.
    ///
    /// # Arguments
    /// * `types` - Type registry containing all parsed `CilType` entries for class resolution
    /// * `memberrefs` - Collection of all `MemberRef` entries for external method resolution
    /// * `methods` - Collection of all `MethodDef` entries for local method resolution
    ///
    /// # Returns
    /// * `Ok(())` - If the implementation mapping was applied successfully
    /// * `Err(_)` - If class resolution, method resolution, or system updates fail
    ///
    /// # Errors
    ///
    /// Returns an error if class resolution, method resolution, or system updates fail.
    pub fn apply(
        &self,
        types: &TypeRegistry,
        memberrefs: &MemberRefMap,
        methods: &MethodMap,
    ) -> Result<()> {
        // ToDo: Implement resolving of MemberRefs, accross multiple binaries (if present and loaded)
        let interface_implementation = match self.method_body.tag {
            TableId::MethodDef => match methods.get(&self.method_body.token) {
                Some(parent) => CilTypeReference::MethodDef(parent.value().clone().into()),
                None => {
                    return Err(malformed_error!(
                        "Failed to resolve methoddef method_body token - {}",
                        self.method_body.token.value()
                    ))
                }
            },
            TableId::MemberRef => match memberrefs.get(&self.method_body.token) {
                Some(parent) => CilTypeReference::MemberRef(parent.value().clone()),
                None => {
                    return Err(malformed_error!(
                        "Failed to resolve memberref method_body token - {}",
                        self.method_body.token.value()
                    ))
                }
            },
            _ => {
                return Err(malformed_error!(
                    "Invalid method_body token - {}",
                    self.method_body.token.value()
                ))
            }
        };

        match types.get(&Token::new(self.class | 0x0200_0000)) {
            Some(cil_type) => {
                cil_type.overwrites.push(interface_implementation.clone());

                match self.method_declaration.tag {
                    TableId::MethodDef => match methods.get(&self.method_declaration.token) {
                        Some(parent) => {
                            if let CilTypeReference::MethodDef(method_ref) =
                                &interface_implementation
                            {
                                parent.value().interface_impls.push(method_ref.clone());
                            }
                        }
                        None => {
                            return Err(malformed_error!(
                                "Failed to resolve methoddef method_declaration token - {}",
                                self.method_declaration.token.value()
                            ))
                        }
                    },
                    TableId::MemberRef => match memberrefs.get(&self.method_declaration.token) {
                        Some(_parent) => {
                            // ToDo: Handle MemberRef interface declarations
                            // MemberRef declarations need special handling for cross-assembly references
                            // For now, we only track bidirectional relationships for MethodDef declarations
                        }
                        None => {
                            return Err(malformed_error!(
                                "Failed to resolve memberref method_declaration token - {}",
                                self.method_declaration.token.value()
                            ))
                        }
                    },
                    _ => {
                        return Err(malformed_error!(
                            "Invalid method_declaration token - {}",
                            self.method_declaration.token.value()
                        ))
                    }
                }

                Ok(())
            }
            None => Err(malformed_error!(
                "Failed to resolve class type token - {}",
                self.class | 0x0200_0000
            )),
        }
    }

    /// Converts a `MethodImplRaw` entry into a `MethodImpl` with resolved references and implementation mappings.
    ///
    /// This method performs complete implementation mapping resolution, including class type resolution,
    /// method reference resolution through coded indexes, and creation of the owned structure with
    /// all references established. The resulting structure provides direct access to implementation
    /// mapping information for method resolution and virtual dispatch operations.
    ///
    /// # Arguments
    /// * `types` - Type registry containing all parsed `CilType` entries for class resolution
    ///
    /// # Errors
    ///
    /// Returns an error if type or method reference resolution fails.
    pub fn to_owned<F>(&self, get_ref: F, types: &TypeRegistry) -> Result<MethodImplRc>
    where
        F: Fn(&CodedIndex) -> CilTypeReference,
    {
        Ok(Arc::new(MethodImpl {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            class: match types.get(&Token::new(self.class | 0x0200_0000)) {
                Some(cil_type) => cil_type.clone(),
                None => {
                    return Err(malformed_error!(
                        "Failed to resolve class type token - {}",
                        self.class | 0x0200_0000
                    ))
                }
            },
            method_body: {
                let result = get_ref(&self.method_body);
                if matches!(result, CilTypeReference::None) {
                    return Err(malformed_error!(
                        "Failed to resolve method_body token - {}",
                        self.method_body.token.value()
                    ));
                }
                result
            },
            method_declaration: {
                let result = get_ref(&self.method_declaration);
                if matches!(result, CilTypeReference::None) {
                    return Err(malformed_error!(
                        "Failed to resolve method_declaration token - {}",
                        self.method_declaration.token.value()
                    ));
                }
                result
            },
        }))
    }
}

impl<'a> RowDefinition<'a> for MethodImplRaw {
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* class */               sizes.table_index_bytes(TableId::TypeDef) +
            /* method_body */         sizes.coded_index_bytes(CodedIndexType::MethodDefOrRef) +
            /* method_declaration */  sizes.coded_index_bytes(CodedIndexType::MethodDefOrRef)
        )
    }

    fn row_read(
        data: &'a [u8],
        offset: &mut usize,
        rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<Self> {
        Ok(MethodImplRaw {
            rid,
            token: Token::new(0x1900_0000 + rid),
            offset: *offset,
            class: read_le_at_dyn(data, offset, sizes.is_large(TableId::TypeDef))?,
            method_body: CodedIndex::read(data, offset, sizes, CodedIndexType::MethodDefOrRef)?,
            method_declaration: CodedIndex::read(
                data,
                offset,
                sizes,
                CodedIndexType::MethodDefOrRef,
            )?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::tables::{MetadataTable, TableId, TableInfo};

    #[test]
    fn crafted_short() {
        let data = vec![
            0x01, 0x01, // class
            0x02, 0x00, // method_body (tag 0 = MethodDef, index = 1)
            0x02, 0x00, // method_declaration (tag 0 = MethodDef, index = 1)
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::MethodImpl, 1),
                (TableId::TypeDef, 10),
                (TableId::MethodDef, 10),
                (TableId::MemberRef, 10),
            ],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<MethodImplRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: MethodImplRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x19000001);
            assert_eq!(row.class, 0x0101);
            assert_eq!(
                row.method_body,
                CodedIndex {
                    tag: TableId::MethodDef,
                    row: 1,
                    token: Token::new(1 | 0x06000000),
                }
            );
            assert_eq!(
                row.method_declaration,
                CodedIndex {
                    tag: TableId::MethodDef,
                    row: 1,
                    token: Token::new(1 | 0x06000000),
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
            0x02, 0x00, 0x00, 0x00, // method_body (tag 0 = MethodDef, index = 1)
            0x02, 0x00, 0x00, 0x00, // method_declaration (tag 0 = MethodDef, index = 1)
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::MethodImpl, u16::MAX as u32 + 3),
                (TableId::TypeDef, u16::MAX as u32 + 3),
                (TableId::MethodDef, u16::MAX as u32 + 3),
                (TableId::MemberRef, u16::MAX as u32 + 3),
            ],
            true,
            true,
            true,
        ));
        let table = MetadataTable::<MethodImplRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: MethodImplRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x19000001);
            assert_eq!(row.class, 0x01010101);
            assert_eq!(
                row.method_body,
                CodedIndex {
                    tag: TableId::MethodDef,
                    row: 1,
                    token: Token::new(1 | 0x06000000),
                }
            );
            assert_eq!(
                row.method_declaration,
                CodedIndex {
                    tag: TableId::MethodDef,
                    row: 1,
                    token: Token::new(1 | 0x06000000),
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
}
