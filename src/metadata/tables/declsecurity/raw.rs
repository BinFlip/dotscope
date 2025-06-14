use std::sync::Arc;

use crate::{
    file::io::{read_le_at, read_le_at_dyn},
    metadata::{
        security::{PermissionSet, Security, SecurityAction},
        streams::Blob,
        tables::{
            CodedIndex, CodedIndexType, DeclSecurity, DeclSecurityRc, RowDefinition, TableInfoRef,
        },
        token::Token,
        typesystem::CilTypeReference,
    },
    Result,
};

#[derive(Clone, Debug)]
/// The `DeclSecurity` table holds security declarations for types, methods, and assemblies. `TableId` = 0x0E
///
/// # Raw Metadata Representation
///
/// This struct represents the raw data from the `DeclSecurity` metadata table before it's
/// been processed into a more usable form. It contains the unresolved indices and references
/// that will later be resolved into actual type references.
///
/// # Fields
///
/// - `action`: The security action code (links to `SecurityAction` enum)
/// - `parent`: Coded index to the target entity (`TypeDef`, `MethodDef`, or Assembly)
/// - `permission_set`: Index into the Blob heap containing the serialized permission set
pub struct DeclSecurityRaw {
    /// `RowID`
    pub rid: u32,
    /// Token
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// a 2-byte value
    pub action: u16,
    /// an index into the `TypeDef`, `MethodDef`, or Assembly table; more precisely, a `HasDeclSecurity` (§II.24.2.6) coded index
    pub parent: CodedIndex,
    /// an index into the Blob heap
    pub permission_set: u32,
}

impl DeclSecurityRaw {
    /// Apply an `DeclSecurityRaw` to the relevant entries of types (e.g. fields, methods and parameters)
    ///
    /// This method processes a raw security declaration and applies it to the appropriate
    /// entity (type, method, or assembly) by parsing the permission set and setting up the
    /// security context.
    ///
    /// ## Arguments
    /// * `get_ref` - A closure that resolves coded indices to `CilTypeReference`
    /// * 'blob'    - The #Blob heap
    ///
    /// # Errors
    /// Returns an error if:
    /// - The blob heap lookup fails for the permission set
    /// - The permission set cannot be parsed from the blob data
    /// - The parent reference cannot be resolved to a valid type reference
    /// - The target entity has already been assigned security permissions
    pub fn apply<F>(&self, get_ref: F, blob: &Blob) -> Result<()>
    where
        F: Fn(&CodedIndex) -> CilTypeReference,
    {
        let blob_data = blob.get(self.permission_set as usize)?;
        let permission_set = Arc::new(PermissionSet::new(blob_data)?);
        let action = SecurityAction::from(self.action);
        let parent = get_ref(&self.parent);

        match parent {
            CilTypeReference::TypeDef(typedef) => {
                if let Some(strong_ref) = typedef.upgrade() {
                    strong_ref
                        .security
                        .set(Security {
                            action,
                            permission_set,
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
                            action,
                            permission_set,
                        })
                        .ok();
                }
                Ok(())
            }
            CilTypeReference::Assembly(assembly) => {
                assembly
                    .security
                    .set(Security {
                        action,
                        permission_set,
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

    /// Convert an `DeclSecurityRaw`, into a `DeclSecurity` which has indexes resolved and owns the referenced data
    ///
    /// ## Arguments
    /// * `get_ref` - A closure that resolves coded indices to `CilTypeReference`
    /// * 'blob'    - The #Blob heap
    ///
    /// # Errors
    /// Returns an error if:
    /// - The blob heap lookup fails for the permission set
    /// - The permission set cannot be parsed from the blob data
    /// - The parent reference cannot be resolved to a valid type reference
    pub fn to_owned<F>(&self, get_ref: F, blob: &Blob) -> Result<DeclSecurityRc>
    where
        F: Fn(&CodedIndex) -> CilTypeReference,
    {
        let blob_data = blob.get(self.permission_set as usize)?;
        let permission_set = Arc::new(PermissionSet::new(blob_data)?);
        let action = SecurityAction::from(self.action);

        let parent = get_ref(&self.parent);
        if matches!(parent, CilTypeReference::None) {
            return Err(malformed_error!(
                "Failed to resolve parent token - {}",
                self.parent.token.value()
            ));
        }

        Ok(Arc::new(DeclSecurity {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            action,
            parent,
            permission_set,
            custom_attributes: Arc::new(boxcar::Vec::new()),
        }))
    }
}

impl<'a> RowDefinition<'a> for DeclSecurityRaw {
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* action */            2 +
            /* parent */            sizes.coded_index_bytes(CodedIndexType::HasDeclSecurity) +
            /* permission_set */    sizes.blob_bytes()
        )
    }

    fn read_row(
        data: &'a [u8],
        offset: &mut usize,
        rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<Self> {
        let offset_org = *offset;

        let action = read_le_at::<u16>(data, offset)?;

        Ok(DeclSecurityRaw {
            rid,
            token: Token::new(0x0E00_0000 + rid),
            offset: offset_org,
            action,
            parent: CodedIndex::read(data, offset, sizes, CodedIndexType::HasDeclSecurity)?,
            permission_set: read_le_at_dyn(data, offset, sizes.is_large_blob())?,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::metadata::tables::{MetadataTable, TableId, TableInfo};

    use super::*;

    #[test]
    fn crafted_short() {
        let data = vec![
            0x01, 0x01, // action
            0x02, 0x02, // parent
            0x03, 0x03, // permission_set
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::TypeDef, 1),
                (TableId::MethodDef, 1),
                (TableId::Assembly, 1),
            ],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<DeclSecurityRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: DeclSecurityRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x0E000001);
            assert_eq!(row.action, 0x0101);
            assert_eq!(
                row.parent,
                CodedIndex {
                    tag: TableId::Assembly,
                    row: 128,
                    token: Token::new(128 | 0x20000000),
                }
            );
            assert_eq!(row.permission_set, 0x303);
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
            0x01, 0x01, // action
            0x02, 0x02, 0x02, 0x02, // parent
            0x03, 0x03, 0x03, 0x03, // permission_set
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::TypeDef, u16::MAX as u32 + 3),
                (TableId::MethodDef, u16::MAX as u32 + 3),
                (TableId::Assembly, u16::MAX as u32 + 3),
            ],
            true,
            true,
            true,
        ));
        let table =
            MetadataTable::<DeclSecurityRaw>::new(&data, u16::MAX as u32 + 3, sizes).unwrap();

        let eval = |row: DeclSecurityRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x0E000001);
            assert_eq!(row.action, 0x0101);
            assert_eq!(
                row.parent,
                CodedIndex {
                    tag: TableId::Assembly,
                    row: 0x808080,
                    token: Token::new(0x808080 | 0x20000000)
                }
            );
            assert_eq!(row.permission_set, 0x3030303);
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
