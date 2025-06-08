//! `AssemblyProcessor` table loader implementation.

use std::sync::Arc;

use crate::{
    metadata::{
        loader::{data::CilObjectData, MetadataLoader},
        streams::{tables::assemblyprocessor::AssemblyProcessorRaw, TableId},
    },
    Result,
};

/// Loader for the `AssemblyProcessor` metadata table.
pub(crate) struct AssemblyProcessorLoader;

impl MetadataLoader for AssemblyProcessorLoader {
    fn load(&self, data: &CilObjectData) -> Result<()> {
        if let Some(ref header) = data.meta {
            if let Some(table) = header.table::<AssemblyProcessorRaw>(TableId::AssemblyProcessor) {
                match table.get(1) {
                    Some(entry) => {
                        data.assembly_processor.set(Arc::new(entry)).map_err(|_| {
                            crate::Error::Error("Failed to set assembly processor".to_string())
                        })?;
                    }
                    None => {
                        return Err(malformed_error!(
                            "Failed to find first AssemblyProcessor entry"
                        ))
                    }
                }
            }
        }
        Ok(())
    }

    fn table_id(&self) -> TableId {
        TableId::AssemblyProcessor
    }

    fn dependencies(&self) -> &'static [TableId] {
        &[]
    }
}
