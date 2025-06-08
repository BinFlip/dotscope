use std::sync::{Arc, OnceLock};

use crossbeam_skiplist::SkipMap;

use crate::{
    file::io::{read_le_at, read_le_at_dyn},
    metadata::{
        method::MethodMap,
        security::{PermissionSet, Security, SecurityAction},
        streams::{
            AssemblyRc, Blob, CodedIndex, CodedIndexType, RowDefinition, TableId, TableInfoRef,
        },
        token::Token,
        typesystem::{CilTypeReference, TypeRegistry},
    },
    Result,
};

/// A map that holds the mapping of Token to parsed `DeclSecurity`
pub type DeclSecurityMap = SkipMap<Token, DeclSecurityRc>;
/// A vector that holds a list of `DeclSecurity`
pub type DeclSecurityList = Arc<boxcar::Vec<DeclSecurityRc>>;
/// A reference to a `DeclSecurity`
pub type DeclSecurityRc = Arc<DeclSecurity>;
pub struct DeclSecurityLoader;

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
    /// * 'blob'        - The #Blob heap
    /// * 'types'       - All parsed `CilType` entries
    /// * 'methods'     - All parsed `MethodDef` entries
    /// * 'assembly'    - The parsed `Assembly` entry
    ///
    /// # Errors
    /// Returns an error if:
    /// - The blob heap lookup fails for the permission set
    /// - The permission set cannot be parsed from the blob data
    /// - The parent reference points to a non-existent entry in the respective table
    pub fn apply(
        &self,
        blob: &Blob,
        types: &TypeRegistry,
        methods: &MethodMap,
        assembly: &Arc<OnceLock<AssemblyRc>>,
    ) -> Result<()> {
        let blob_data = blob.get(self.permission_set as usize)?;
        let permission_set = Arc::new(PermissionSet::new(blob_data)?);
        let action = SecurityAction::from(self.action);

        match self.parent.tag {
            TableId::TypeDef => match types.get(&self.parent.token) {
                Some(cil_type) => {
                    cil_type
                        .security
                        .set(Security {
                            action,
                            permission_set,
                        })
                        .ok();

                    Ok(())
                }
                None => Err(malformed_error!(
                    "Failed to resolve typedef token - {}",
                    self.parent.token.value()
                )),
            },
            TableId::MethodDef => match methods.get(&self.parent.token) {
                Some(method) => {
                    method
                        .value()
                        .security
                        .set(Security {
                            action,
                            permission_set,
                        })
                        .ok();
                    Ok(())
                }
                None => Err(malformed_error!(
                    "Failed to resolve methoddef token - {}",
                    self.parent.token.value()
                )),
            },
            TableId::Assembly => match assembly.get() {
                Some(assembly_ref) => {
                    assembly_ref
                        .security
                        .set(Security {
                            action,
                            permission_set,
                        })
                        .ok();
                    Ok(())
                }
                None => Err(malformed_error!(
                    "Failed to resolve assembly token - {}",
                    self.parent.token.value()
                )),
            },
            _ => Err(malformed_error!(
                "Invalid parent token - {}",
                self.parent.token.value()
            )),
        }
    }

    /// Convert an `DeclSecurityRaw`, into a `DeclSecurity` which has indexes resolved and owns the referenced data
    ///
    /// ## Arguments
    /// * 'blob'        - The #Blob heap
    /// * 'types'       - All parsed `CilType` entries
    /// * 'methods'     - All parsed `MethodDef` entries
    /// * 'assemblies'  - All parsed `Assembly` entries
    ///
    /// # Errors
    /// Returns an error if:
    /// - The blob heap lookup fails for the permission set
    /// - The permission set cannot be parsed from the blob data
    /// - The parent reference cannot be resolved to a valid type reference
    pub fn to_owned(
        &self,
        blob: &Blob,
        types: &TypeRegistry,
        methods: &MethodMap,
        assembly: &Arc<OnceLock<AssemblyRc>>,
    ) -> Result<DeclSecurityRc> {
        let blob_data = blob.get(self.permission_set as usize)?;
        let permission_set = Arc::new(PermissionSet::new(blob_data)?);
        let action = SecurityAction::from(self.action);

        let parent = match self.parent.tag {
            TableId::TypeDef => match types.get(&self.parent.token) {
                Some(typedef) => CilTypeReference::TypeDef(typedef.clone().into()),
                None => {
                    return Err(malformed_error!(
                        "Failed to resolve typedef token - {}",
                        self.parent.token.value()
                    ))
                }
            },
            TableId::MethodDef => match methods.get(&self.parent.token) {
                Some(methoddef) => CilTypeReference::MethodDef(methoddef.value().clone().into()),
                None => {
                    return Err(malformed_error!(
                        "Failed to resolve methoddef token - {}",
                        self.parent.token.value()
                    ))
                }
            },
            TableId::Assembly => match assembly.get() {
                Some(assembly_ref) => CilTypeReference::Assembly(assembly_ref.clone()),
                None => {
                    return Err(malformed_error!(
                        "Failed to resolve assembly token - {}",
                        self.parent.token.value()
                    ))
                }
            },
            _ => {
                return Err(malformed_error!(
                    "Invalid parent token - {}",
                    self.parent.token.value()
                ))
            }
        };

        Ok(Arc::new(DeclSecurity {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            action,
            parent,
            permission_set,
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
    use crate::metadata::streams::tables::types::{MetadataTable, TableId, TableInfo};

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
