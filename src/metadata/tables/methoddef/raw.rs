use std::sync::{atomic::AtomicU32, Arc, OnceLock};

use crate::{
    file::io::{read_le_at, read_le_at_dyn},
    metadata::{
        method::{
            Method, MethodAccessFlags, MethodImplCodeType, MethodImplManagement, MethodImplOptions,
            MethodModifiers, MethodRc, MethodVtableFlags,
        },
        signatures::parse_method_signature,
        streams::{Blob, Strings},
        tables::{
            types::{RowDefinition, TableId, TableInfoRef},
            ParamMap, ParamPtrMap,
        },
        token::Token,
    },
    prelude::MetadataTable,
    Result,
};

#[derive(Clone, Debug)]
/// The `MethodDef` table defines methods for types in the `TypeDef` table. `TableId` = 0x06
pub struct MethodDefRaw {
    /// `RowID`
    pub rid: u32,
    /// Token
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// a 4-byte constant
    pub rva: u32,
    /// bitmask of `MethodImplAttributes`, §II.23.1.10
    pub impl_flags: u32,
    /// bitmask of `MethodAttributes`, §II.23.1.10
    pub flags: u32,
    /// an index into the String heap
    pub name: u32,
    /// an index into the Blob heap
    pub signature: u32,
    /// an index into the Param table
    pub param_list: u32,
}

impl MethodDefRaw {
    /// Convert an `MethodDefRaw`, into a `Method` which has indexes resolved and owns the referenced data
    ///
    /// ## Arguments
    /// * 'strings' - The processed Strings
    /// * 'blob'    - The processed Blobs
    /// * '`params_map`'  - All parsed `Param` entries for param resolution
    /// * '`param_ptr_map`' - All parsed `ParamPtr` entries for indirection resolution
    /// * 'table'   - The `MethodDef` table for getting next row's `param_list`
    ///
    /// # Errors
    /// Returns an error if the method name cannot be retrieved from the strings heap,
    /// or if the method signature cannot be parsed from the blob heap.
    pub fn to_owned(
        &self,
        strings: &Strings,
        blob: &Blob,
        params_map: &ParamMap,
        param_ptr_map: &ParamPtrMap,
        table: &MetadataTable<MethodDefRaw>,
    ) -> Result<MethodRc> {
        let signature = parse_method_signature(blob.get(self.signature as usize)?)?;

        let type_params = if self.param_list == 0 || params_map.is_empty() {
            Arc::new(boxcar::Vec::new())
        } else {
            let next_row_id = self.rid + 1;
            let start = self.param_list as usize;
            let end = if next_row_id > table.row_count() {
                params_map.len() + 1
            } else {
                match table.get(next_row_id) {
                    Some(next_row) => {
                        let calculated_end = next_row.param_list as usize;
                        let expected_param_count = signature.params.len();

                        // If the calculated range would be empty but we expect parameters,
                        // use the signature to determine the correct end
                        if calculated_end <= start && expected_param_count > 0 {
                            start + expected_param_count
                        } else {
                            calculated_end
                        }
                    }
                    None => {
                        return Err(malformed_error!(
                            "Failed to resolve param_end from next row - {}",
                            next_row_id
                        ))
                    }
                }
            };

            if start > params_map.len() || end > (params_map.len() + 1) || end < start {
                Arc::new(boxcar::Vec::new())
            } else {
                let type_params = Arc::new(boxcar::Vec::with_capacity(end - start));
                for counter in start..end {
                    let actual_param_token = if param_ptr_map.is_empty() {
                        let token_value = u32::try_from(counter | 0x0800_0000).map_err(|_| {
                            malformed_error!("Token value too large: {}", counter | 0x0800_0000)
                        })?;
                        Token::new(token_value)
                    } else {
                        let param_ptr_token_value =
                            u32::try_from(counter | 0x0A00_0000).map_err(|_| {
                                malformed_error!(
                                    "ParamPtr token value too large: {}",
                                    counter | 0x0A00_0000
                                )
                            })?;
                        let param_ptr_token = Token::new(param_ptr_token_value);

                        match param_ptr_map.get(&param_ptr_token) {
                            Some(param_ptr) => {
                                let actual_param_rid = param_ptr.value().param;
                                let actual_param_token_value =
                                    u32::try_from(actual_param_rid as usize | 0x0800_0000)
                                        .map_err(|_| {
                                            malformed_error!(
                                                "Param token value too large: {}",
                                                actual_param_rid as usize | 0x0800_0000
                                            )
                                        })?;
                                Token::new(actual_param_token_value)
                            }
                            None => {
                                return Err(malformed_error!(
                                    "Failed to resolve ParamPtr - {}",
                                    counter | 0x0A00_0000
                                ))
                            }
                        }
                    };

                    match params_map.get(&actual_param_token) {
                        Some(param) => _ = type_params.push(param.value().clone()),
                        None => {
                            return Err(malformed_error!(
                                "Failed to resolve param - {}",
                                actual_param_token.value()
                            ))
                        }
                    }
                }

                type_params
            }
        };
        Ok(Arc::new(Method {
            rid: self.rid,
            token: self.token,
            meta_offset: self.offset,
            name: strings.get(self.name as usize)?.to_string(),
            impl_code_type: MethodImplCodeType::from_impl_flags(self.impl_flags),
            impl_management: MethodImplManagement::from_impl_flags(self.impl_flags),
            impl_options: MethodImplOptions::from_impl_flags(self.impl_flags),
            flags_access: MethodAccessFlags::from_method_flags(self.flags),
            flags_vtable: MethodVtableFlags::from_method_flags(self.flags),
            flags_modifiers: MethodModifiers::from_method_flags(self.flags),
            flags_pinvoke: AtomicU32::new(0),
            params: type_params,
            varargs: Arc::new(boxcar::Vec::new()),
            generic_params: Arc::new(boxcar::Vec::new()),
            generic_args: Arc::new(boxcar::Vec::new()),
            signature,
            rva: if self.rva == 0 { None } else { Some(self.rva) },
            body: OnceLock::new(),
            local_vars: Arc::new(boxcar::Vec::new()),
            overrides: OnceLock::new(),
            interface_impls: Arc::new(boxcar::Vec::new()),
            security: OnceLock::new(),
            blocks: OnceLock::new(),
            custom_attributes: Arc::new(boxcar::Vec::new()),
            // cfg: RwLock::new(None),
            // ssa: RwLock::new(None),
        }))
    }

    /// Apply a `MethodDefRaw` entry to update related metadata structures.
    ///
    /// `MethodDef` entries define methods within types. They are associated with their parent
    /// types but don't themselves modify other metadata during the dual variant resolution phase.
    /// Method-specific metadata (P/Invoke info, generic parameters, etc.) is resolved separately.
    ///
    /// # Errors
    /// Always returns `Ok(())` as `MethodDef` entries don't modify other tables directly.
    pub fn apply(&self) -> Result<()> {
        Ok(())
    }
}

impl<'a> RowDefinition<'a> for MethodDefRaw {
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* rva */           4 +
            /* impl_flags */    2 +
            /* flags */         2 +
            /* name */          sizes.str_bytes() +
            /* signature */     sizes.blob_bytes() +
            /* param_list */    sizes.table_index_bytes(TableId::Param)
        )
    }

    fn read_row(
        data: &'a [u8],
        offset: &mut usize,
        rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<Self> {
        Ok(MethodDefRaw {
            rid,
            token: Token::new(0x0600_0000 + rid),
            offset: *offset,
            rva: read_le_at::<u32>(data, offset)?,
            impl_flags: u32::from(read_le_at::<u16>(data, offset)?),
            flags: u32::from(read_le_at::<u16>(data, offset)?),
            name: read_le_at_dyn(data, offset, sizes.is_large_str())?,
            signature: read_le_at_dyn(data, offset, sizes.is_large_blob())?,
            param_list: read_le_at_dyn(data, offset, sizes.is_large(TableId::Param))?,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::metadata::tables::{MetadataTable, TableInfo};

    use super::*;

    #[test]
    fn crafted_short() {
        let data = vec![
            0x01, 0x01, 0x01, 0x01, // rva
            0x02, 0x02, // impl_flags
            0x03, 0x03, // flags
            0x04, 0x04, // name
            0x05, 0x05, // signature
            0x06, 0x06, // param_list
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::MethodDef, 1)],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<MethodDefRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: MethodDefRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x06000001);
            assert_eq!(row.rva, 0x01010101);
            assert_eq!(row.impl_flags, 0x0202);
            assert_eq!(row.flags, 0x0303);
            assert_eq!(row.name, 0x0404);
            assert_eq!(row.signature, 0x0505);
            assert_eq!(row.param_list, 0x0606);
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
            0x01, 0x01, 0x01, 0x01, // rva
            0x02, 0x02, // impl_flags
            0x03, 0x03, // flags
            0x04, 0x04, 0x04, 0x04, // name
            0x05, 0x05, 0x05, 0x05, // signature
            0x06, 0x06, 0x06, 0x06, // param_list
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Param, u16::MAX as u32 + 2)],
            true,
            true,
            true,
        ));
        let table = MetadataTable::<MethodDefRaw>::new(&data, u16::MAX as u32 + 2, sizes).unwrap();

        let eval = |row: MethodDefRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x06000001);
            assert_eq!(row.rva, 0x01010101);
            assert_eq!(row.impl_flags, 0x0202);
            assert_eq!(row.flags, 0x0303);
            assert_eq!(row.name, 0x04040404);
            assert_eq!(row.signature, 0x05050505);
            assert_eq!(row.param_list, 0x06060606);
        };

        {
            let row = table.get(1).unwrap();
            eval(row);
        }
    }
}
