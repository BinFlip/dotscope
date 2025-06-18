//! Raw `ImplMap` table structure with unresolved coded indexes.
//!
//! This module provides the [`ImplMapRaw`] struct, which represents Platform Invoke (P/Invoke)
//! mapping entries as stored in the metadata stream. The structure contains unresolved
//! coded indexes and string heap references that require processing to become usable.
//!
//! # Purpose
//! [`ImplMapRaw`] serves as the direct representation of `ImplMap` table entries from
//! the binary metadata stream, before reference resolution and string lookup. This
//! raw format is processed during metadata loading to create [`ImplMap`] instances
//! with resolved references and owned data.
//!
//! [`ImplMap`]: crate::metadata::tables::ImplMap

use std::sync::{atomic::Ordering, Arc};

use crate::{
    file::io::{read_le_at, read_le_at_dyn},
    metadata::{
        imports::Imports,
        method::MethodMap,
        streams::Strings,
        tables::{
            CodedIndex, CodedIndexType, ImplMap, ImplMapRc, ModuleRefMap, RowDefinition, TableId,
            TableInfoRef,
        },
        token::Token,
        typesystem::CilTypeReference,
    },
    Result,
};

/// Raw `ImplMap` table entry with unresolved coded indexes and heap references.
///
/// This structure represents a Platform Invoke (P/Invoke) mapping entry as stored
/// directly in the metadata stream. All references are unresolved coded indexes
/// or heap offsets that require processing during metadata loading.
///
/// # Table Structure (ECMA-335 §22.22)
/// | Column | Size | Description |
/// |--------|------|-------------|
/// | `MappingFlags` | 2 bytes | P/Invoke attribute flags |
/// | `MemberForwarded` | Coded index | Method or field being forwarded (typically `MethodDef`) |
/// | `ImportName` | String index | Name of target function in native library |
/// | `ImportScope` | `ModuleRef` index | Target module containing the native function |
///
/// # Coded Index Resolution
/// The `member_forwarded` field uses the `MemberForwarded` coded index encoding:
/// - **Tag 0**: Field table (not supported for exports)
/// - **Tag 1**: `MethodDef` table (standard case for P/Invoke)
#[derive(Clone, Debug)]
pub struct ImplMapRaw {
    /// Row identifier within the `ImplMap` table.
    ///
    /// Unique identifier for this P/Invoke mapping entry, used for internal
    /// table management and token generation.
    pub rid: u32,

    /// Metadata token for this `ImplMap` entry (`TableId` 0x1C).
    ///
    /// Computed as `0x1C000000 | rid` to create the full token value
    /// for referencing this P/Invoke mapping from other metadata structures.
    pub token: Token,

    /// Byte offset of this entry within the raw table data.
    ///
    /// Used for efficient table navigation and binary metadata processing.
    pub offset: usize,

    /// Platform Invoke attribute flags as a 2-byte bitmask.
    ///
    /// Defines calling conventions, character sets, error handling, and other
    /// P/Invoke characteristics. See ECMA-335 §23.1.8 and [`PInvokeAttributes`]
    /// for detailed flag definitions.
    ///
    /// [`PInvokeAttributes`]: crate::metadata::tables::implmap::PInvokeAttributes
    pub mapping_flags: u32,

    /// `MemberForwarded` coded index to the method or field being mapped.
    ///
    /// Points to either a Field or `MethodDef` table entry (ECMA-335 §24.2.6).
    /// In practice, only `MethodDef` is used since field export is not supported.
    /// Requires resolution during processing to obtain the actual method reference.
    pub member_forwarded: CodedIndex,

    /// String heap index for the target function name.
    ///
    /// References the name of the native function to be called in the target
    /// library. Requires string heap lookup to obtain the actual function name.
    pub import_name: u32,

    /// `ModuleRef` table index for the target native library.
    ///
    /// References the module containing the native function to be invoked.
    /// Requires `ModuleRef` table lookup to obtain the library reference.
    pub import_scope: u32,
}

impl ImplMapRaw {
    /// Applies P/Invoke mapping directly to referenced method and import system.
    ///
    /// This method resolves references and immediately applies the P/Invoke configuration
    /// to the target method and import tracking system. It's an alternative to the
    /// two-step process of conversion to owned structure followed by application.
    ///
    /// # Arguments
    /// * `strings` - String heap for resolving import function names
    /// * `modules` - `ModuleRef` map for resolving target library references
    /// * `methods` - `MethodDef` map for resolving target method references
    /// * `imports` - Import tracking system for registering P/Invoke mappings
    ///
    /// * `Ok(())` - P/Invoke mapping applied successfully
    /// * `Err(_)` - Reference resolution failed or invalid coded index
    ///
    /// # Errors
    /// - Invalid `member_forwarded` token or unsupported table reference
    /// - Method reference cannot be resolved in the `MethodDef` map
    /// - `ModuleRef` reference cannot be resolved
    /// - String heap lookup fails for import name
    pub fn apply(
        &self,
        strings: &Strings,
        modules: &ModuleRefMap,
        methods: &MethodMap,
        imports: &Imports,
    ) -> Result<()> {
        match self.member_forwarded.tag {
            TableId::MethodDef => match methods.get(&self.member_forwarded.token) {
                Some(method) => {
                    method
                        .value()
                        .flags_pinvoke
                        .store(self.mapping_flags, Ordering::Relaxed);

                    match modules.get(&Token::new(self.import_scope | 0x1A00_0000)) {
                        Some(module_ref) => {
                            let import_name = strings.get(self.import_name as usize)?.to_string();
                            imports.add_method(
                                import_name,
                                &self.token,
                                method.value().clone(),
                                module_ref.value(),
                            )
                        }
                        None => Err(malformed_error!(
                            "Failed to resolve import_scope token - {}",
                            self.import_scope | 0x1A00_0000
                        )),
                    }
                }
                None => Err(malformed_error!(
                    "Failed to resolve member_forwarded token - {}",
                    self.member_forwarded.token.value()
                )),
            },
            /* According to ECMA-355 TableId::Field is not supported and should not appear */
            _ => Err(malformed_error!(
                "Invalid member_forwarded token - {}",
                self.member_forwarded.token.value()
            )),
        }
    }

    /// Converts raw `ImplMap` entry to owned structure with resolved references.
    ///
    /// This method processes the raw table entry by resolving all coded indexes
    /// and heap references, creating an [`ImplMap`] instance with owned data
    /// suitable for runtime use and further processing.
    ///
    /// # Arguments
    /// * `get_ref` - Closure to resolve coded indexes to type references
    /// * `strings` - String heap for resolving import function names
    /// * `modules` - `ModuleRef` map for resolving target library references
    ///
    /// # Returns
    /// * `Ok(ImplMapRc)` - Successfully converted owned `ImplMap` structure
    /// * `Err(_)` - Reference resolution failed or invalid data
    ///
    /// # Errors
    /// - Invalid `member_forwarded` coded index or weak reference upgrade failure
    /// - String heap lookup fails for import name
    /// - `ModuleRef` reference cannot be resolved
    /// - Non-MethodDef reference in `member_forwarded` (unsupported)
    pub fn to_owned<F>(
        &self,
        get_ref: F,
        strings: &Strings,
        modules: &ModuleRefMap,
    ) -> Result<ImplMapRc>
    where
        F: Fn(&CodedIndex) -> CilTypeReference,
    {
        let member_forwarded = match get_ref(&self.member_forwarded) {
            CilTypeReference::MethodDef(method_def) => match method_def.upgrade() {
                Some(method) => {
                    method
                        .flags_pinvoke
                        .store(self.mapping_flags, Ordering::Relaxed);
                    method
                }
                None => {
                    return Err(malformed_error!(
                        "Failed to upgrade MethodDef weak reference - {}",
                        self.member_forwarded.token.value()
                    ))
                }
            },
            _ => {
                return Err(malformed_error!(
                    "Invalid member_forwarded token - {}",
                    self.member_forwarded.token.value()
                ))
            }
        };

        Ok(Arc::new(ImplMap {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            mapping_flags: self.mapping_flags,
            member_forwarded,
            import_name: strings.get(self.import_name as usize)?.to_string(),
            import_scope: match modules.get(&Token::new(self.import_scope | 0x1A00_0000)) {
                Some(module_ref) => module_ref.value().clone(),
                None => {
                    return Err(malformed_error!(
                        "Failed to resolve import_scope token - {}",
                        self.import_scope | 0x1A00_0000
                    ))
                }
            },
        }))
    }
}

impl<'a> RowDefinition<'a> for ImplMapRaw {
    /// Calculates the byte size of an `ImplMap` table row based on table sizing information.
    ///
    /// The row size depends on the size of coded indexes and string/table references,
    /// which vary based on the total number of entries in referenced tables.
    ///
    /// # Row Layout
    /// - `mapping_flags`: 2 bytes (fixed size)
    /// - `member_forwarded`: Variable size `MemberForwarded` coded index
    /// - `import_name`: Variable size string heap index (2 or 4 bytes)
    /// - `import_scope`: Variable size `ModuleRef` table index (2 or 4 bytes)
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* mapping_flags */    2 +
            /* member_forwarded */ sizes.coded_index_bytes(CodedIndexType::MemberForwarded) +
            /* import_name */      sizes.str_bytes() +
            /* import_scope */     sizes.table_index_bytes(TableId::ModuleRef)
        )
    }

    /// Reads a single `ImplMap` table row from binary metadata stream.
    ///
    /// Parses the binary representation of an `ImplMap` entry, reading fields
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
    /// * `Ok(ImplMapRaw)` - Successfully parsed table row
    /// * `Err(_)` - Binary data reading or parsing error
    fn read_row(
        data: &'a [u8],
        offset: &mut usize,
        rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<Self> {
        Ok(ImplMapRaw {
            rid,
            token: Token::new(0x1C00_0000 + rid),
            offset: *offset,
            mapping_flags: u32::from(read_le_at::<u16>(data, offset)?),
            member_forwarded: CodedIndex::read(
                data,
                offset,
                sizes,
                CodedIndexType::MemberForwarded,
            )?,
            import_name: read_le_at_dyn(data, offset, sizes.is_large_str())?,
            import_scope: read_le_at_dyn(data, offset, sizes.is_large(TableId::ModuleRef))?,
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
            0x01, 0x01, // mapping_flags
            0x02, 0x00, // member_forwarded (tag 0 = Field, index = 1)
            0x03, 0x03, // import_name
            0x04, 0x04, // import_scope
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::ImplMap, 1),
                (TableId::Field, 10),
                (TableId::MethodDef, 10),
                (TableId::ModuleRef, 10),
            ],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<ImplMapRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: ImplMapRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x1C000001);
            assert_eq!(row.mapping_flags, 0x0101);
            assert_eq!(
                row.member_forwarded,
                CodedIndex {
                    tag: TableId::Field,
                    row: 1,
                    token: Token::new(1 | 0x04000000),
                }
            );
            assert_eq!(row.import_name, 0x0303);
            assert_eq!(row.import_scope, 0x0404);
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
            0x01, 0x01, // mapping_flags
            0x02, 0x00, 0x00, 0x00, // member_forwarded (tag 0 = Field, index = 1)
            0x03, 0x03, 0x03, 0x03, // import_name
            0x04, 0x04, 0x04, 0x04, // import_scope
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::ImplMap, u16::MAX as u32 + 3),
                (TableId::Field, u16::MAX as u32 + 3),
                (TableId::MethodDef, u16::MAX as u32 + 3),
                (TableId::ModuleRef, u16::MAX as u32 + 3),
            ],
            true,
            true,
            true,
        ));
        let table = MetadataTable::<ImplMapRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: ImplMapRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x1C000001);
            assert_eq!(row.mapping_flags, 0x0101);
            assert_eq!(
                row.member_forwarded,
                CodedIndex {
                    tag: TableId::Field,
                    row: 1,
                    token: Token::new(1 | 0x04000000),
                }
            );
            assert_eq!(row.import_name, 0x03030303);
            assert_eq!(row.import_scope, 0x04040404);
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
