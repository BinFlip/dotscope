//! `AssemblyOS` table loader implementation.

use std::sync::Arc;

use crate::{
    metadata::{
        loader::{data::CilObjectData, MetadataLoader},
        streams::{tables::assemblyos::AssemblyOsRaw, TableId},
    },
    Result,
};

/// Loader for the `AssemblyOS` metadata table.
pub(crate) struct AssemblyOsLoader;

impl MetadataLoader for AssemblyOsLoader {
    fn load(&self, data: &CilObjectData) -> Result<()> {
        if let Some(header) = &data.meta {
            if let Some(table) = header.table::<AssemblyOsRaw>(TableId::AssemblyOS) {
                match table.get(1) {
                    Some(entry) => {
                        let _ = data.assembly_os.set(Arc::new(entry));
                    }
                    None => return Err(malformed_error!("Failed to find main AssemblyOS entry")),
                }
            }
        }
        Ok(())
    }

    fn table_id(&self) -> TableId {
        TableId::AssemblyOS
    }

    fn dependencies(&self) -> &'static [TableId] {
        &[]
    }
}
