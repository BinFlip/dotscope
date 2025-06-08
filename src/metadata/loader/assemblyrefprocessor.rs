//! `AssemblyRefProcessor` loader implementation

use crate::{
    metadata::{
        loader::{data::CilObjectData, MetadataLoader},
        streams::AssemblyRefProcessorRaw,
    },
    prelude::TableId,
    Result,
};

/// Loader for `AssemblyRefProcessor` metadata
pub(crate) struct AssemblyRefProcessorLoader;

impl MetadataLoader for AssemblyRefProcessorLoader {
    fn load(&self, data: &CilObjectData) -> Result<()> {
        if let Some(ref header) = data.meta {
            if let Some(table) =
                header.table::<AssemblyRefProcessorRaw>(TableId::AssemblyRefProcessor)
            {
                table.par_iter().try_for_each(|row| {
                    row.apply(&data.refs_assembly)?;
                    Ok(())
                })?;
            }
        }
        Ok(())
    }

    fn table_id(&self) -> TableId {
        TableId::AssemblyRefProcessor
    }

    fn dependencies(&self) -> &'static [TableId] {
        &[TableId::AssemblyRef]
    }
}
