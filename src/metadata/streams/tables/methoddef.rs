use std::sync::{atomic::AtomicU32, Arc, OnceLock};

use crate::{
    file::io::{read_le_at, read_le_at_dyn},
    metadata::{
        method::{
            Method, MethodAccessFlags, MethodImplCodeType, MethodImplManagement, MethodImplOptions,
            MethodModifiers, MethodVtableFlags,
        },
        signatures::parse_method_signature,
        streams::{
            tables::types::{RowDefinition, TableId, TableInfoRef},
            Blob, ParamList, Strings,
        },
        token::Token,
    },
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
    /// * 'params'  - The `Param` for this method
    ///
    /// # Errors
    /// Returns an error if the method name cannot be retrieved from the strings heap,
    /// or if the method signature cannot be parsed from the blob heap.
    pub fn to_owned(&self, strings: &Strings, blob: &Blob, params: ParamList) -> Result<Method> {
        Ok(Method {
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
            params,
            varargs: Arc::new(boxcar::Vec::new()),
            generic_params: Arc::new(boxcar::Vec::new()),
            generic_args: Arc::new(boxcar::Vec::new()),
            signature: parse_method_signature(blob.get(self.signature as usize)?)?,
            rva: if self.rva == 0 { None } else { Some(self.rva) },
            body: OnceLock::new(),
            local_vars: Arc::new(boxcar::Vec::new()),
            overrides: OnceLock::new(),
            interface_impls: Arc::new(boxcar::Vec::new()),
            security: OnceLock::new(),
            blocks: OnceLock::new(),
            // cfg: RwLock::new(None),
            // ssa: RwLock::new(None),
        })
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

    use crate::metadata::streams::tables::types::{MetadataTable, TableInfo};

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
