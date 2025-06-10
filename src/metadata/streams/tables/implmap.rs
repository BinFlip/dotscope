use crossbeam_skiplist::SkipMap;
use std::sync::{atomic::Ordering, Arc};

use crate::{
    file::io::{read_le_at, read_le_at_dyn},
    metadata::{
        imports::Imports,
        method::{MethodMap, MethodRc},
        streams::{
            CodedIndex, CodedIndexType, ModuleRefMap, ModuleRefRc, RowDefinition, Strings, TableId,
            TableInfoRef,
        },
        token::Token,
        typesystem::CilTypeReference,
    },
    Result,
};

/// A map that holds the mapping of Token to parsed `ImplMap`
pub type ImplMapMap = SkipMap<Token, ImplMapRc>;
/// A vector that holds a list of `ImplMap`
pub type ImplMapList = Arc<boxcar::Vec<ImplMapRc>>;
/// A reference to a `ImplMap`
pub type ImplMapRc = Arc<ImplMap>;

#[allow(non_snake_case)]
/// All possible flags for `PInvokeAttributes`
pub mod PInvokeAttributes {
    /// `PInvoke` is to use the member name as specified
    pub const NO_MANGLE: u32 = 0x0001;
    /// `PInvoke` is to import a character set conversion library
    pub const CHAR_SET_NOT_SPEC: u32 = 0x0000;
    /// `PInvoke` is to import a character set conversion library
    pub const CHAR_SET_ANSI: u32 = 0x0002;
    /// `PInvoke` is to import a character set conversion library
    pub const CHAR_SET_UNICODE: u32 = 0x0004;
    /// `PInvoke` is to import a character set conversion library
    pub const CHAR_SET_AUTO: u32 = 0x0006;
    /// Character set mask
    pub const CHAR_SET_MASK: u32 = 0x0006;
    /// Information about target function. Not relevant for fields
    pub const SUPPORTS_LAST_ERROR: u32 = 0x0040;
    /// Calling convention mask
    pub const CALL_CONV_MASK: u32 = 0x0700;
    /// Calling convention = `WinAPI`
    pub const CALL_CONV_WINAPI: u32 = 0x0100;
    /// Calling convention = C
    pub const CALL_CONV_CDECL: u32 = 0x0200;
    /// Calling convention = `StdCall`
    pub const CALL_CONV_STDCALL: u32 = 0x0300;
    /// Calling convention = `ThisCall`
    pub const CALL_CONV_THISCALL: u32 = 0x0400;
    /// Calling convention = `FastCall`
    pub const CALL_CONV_FASTCALL: u32 = 0x0500;
    /// Calling convention specified explicitly
    pub const BEST_FIT_MASK: u32 = 0x0030;
    /// Best fit mapping
    pub const BEST_FIT_ENABLED: u32 = 0x0010;
    /// Best fit mapping is disabled
    pub const BEST_FIT_DISABLED: u32 = 0x0020;
    /// Throw on unmappable chars
    pub const THROW_ON_UNMAPPABLE_MASK: u32 = 0x3000;
    /// Throw on unmappable chars enabled
    pub const THROW_ON_UNMAPPABLE_ENABLED: u32 = 0x1000;
    /// Throw on unmappable chars disabled
    pub const THROW_ON_UNMAPPABLE_DISABLED: u32 = 0x2000;
}

/// The `ImplMap` table holds information about platform invoke (P/Invoke) methods. Similar to `ImplMapRaw` but
/// with resolved indexes and owned data
pub struct ImplMap {
    /// `RowID`
    pub rid: u32,
    /// Token
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// a 2-byte bitmask of type `PInvokeAttributes`, §II.23.1.8
    pub mapping_flags: u32,
    /// `MemberForwarded` (an index into the Field or `MethodDef` table; more precisely, a `MemberForwarded`
    /// (§II.24.2.6) coded index). However, it only ever indexes the `MethodDef` table, since Field export
    /// is not supported.
    pub member_forwarded: MethodRc,
    /// an index into the String heap
    pub import_name: String,
    /// an index into the `ModuleRef` table
    pub import_scope: ModuleRefRc,
}

impl ImplMap {
    /// Apply an `ImplMap` to update method flags and add import information.
    ///
    /// Since this is the owned structure, all references are already resolved, so we can
    /// efficiently update the method and imports without re-resolving anything.
    ///
    /// # Errors
    /// Returns an error if adding the import fails.
    pub fn apply(&self) -> Result<()> {
        self.member_forwarded
            .flags_pinvoke
            .store(self.mapping_flags, Ordering::Relaxed);

        Ok(())
    }
}

#[derive(Clone, Debug)]
/// The `ImplMap` table holds information about platform invoke (P/Invoke) methods. `TableId` = 0x1C
pub struct ImplMapRaw {
    /// `RowID`
    pub rid: u32,
    /// Token
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// a 2-byte bitmask of type `PInvokeAttributes`, §II.23.1.8
    pub mapping_flags: u32,
    /// `MemberForwarded` (an index into the Field or `MethodDef` table; more precisely, a `MemberForwarded`
    /// (§II.24.2.6) coded index). However, it only ever indexes the `MethodDef` table, since Field export
    /// is not supported.
    pub member_forwarded: CodedIndex,
    /// an index into the String heap
    pub import_name: u32,
    /// an index into the `ModuleRef` table
    pub import_scope: u32,
}

impl ImplMapRaw {
    /// Apply an `ImplMapRaw` to the relevant entries of types (e.g. fields, methods and parameters)
    ///
    /// ## Arguments
    /// * 'value'   - The value to be converted
    /// * 'string'  - The #String heap
    /// * 'modules' - All parsed `ModuleRef` entries
    /// * 'methods' - All parsed `MethodDef` entries
    /// * 'imports' - All `Import`s
    ///
    /// # Errors
    /// Returns an error if the member forwarded reference cannot be resolved,
    /// if the method token is invalid, or if the import name cannot be retrieved.
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

    /// Convert an `ImplMapRaw`, into a `ImplMap` which has indexes resolved and owns the referenced data
    ///
    /// ## Arguments
    /// * `get_ref` - Closure to resolve coded indexes
    /// * 'string'  - The #String heap
    /// * 'modules' - All parsed `ModuleRef` entries
    ///
    /// # Errors
    /// Returns an error if the member forwarded reference cannot be resolved,
    /// if the import name cannot be retrieved, or if the import scope module cannot be found.
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
            CilTypeReference::MethodDef(method_def) => {
                // Convert from MethodDefWeak to MethodRc
                match method_def.upgrade() {
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
                }
            }
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
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* mapping_flags */    2 +
            /* member_forwarded */ sizes.coded_index_bytes(CodedIndexType::MemberForwarded) +
            /* import_name */      sizes.str_bytes() +
            /* import_scope */     sizes.table_index_bytes(TableId::ModuleRef)
        )
    }

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
    use crate::metadata::streams::{MetadataTable, TableId, TableInfo};

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
