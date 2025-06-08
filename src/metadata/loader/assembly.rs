//! Assembly table loader implementation.

use crate::{
    metadata::{
        loader::{data::CilObjectData, MetadataLoader},
        streams::{tables::assembly::AssemblyRaw, TableId},
    },
    Result,
};

/// Loader for the Assembly metadata table.
pub(crate) struct AssemblyLoader;

impl MetadataLoader for AssemblyLoader {
    fn load(&self, data: &CilObjectData) -> Result<()> {
        if let (Some(header), Some(strings), Some(blob)) = (
            data.meta.as_ref(),
            data.strings.as_ref(),
            data.blobs.as_ref(),
        ) {
            if let Some(table) = header.table::<AssemblyRaw>(TableId::Assembly) {
                match table.get(1) {
                    Some(first_assembly) => {
                        let res = first_assembly.to_owned(strings, blob)?;
                        let _ = data.assembly.set(res);
                    }
                    None => return Err(malformed_error!("First assembly doesn't exist")),
                }
            }
        }
        Ok(())
    }

    fn table_id(&self) -> TableId {
        TableId::Assembly
    }

    fn dependencies(&self) -> &'static [TableId] {
        &[]
    }
}
