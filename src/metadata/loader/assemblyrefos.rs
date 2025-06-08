//! `AssemblyRefOs` loader implementation

use crate::{
    metadata::{
        loader::{data::CilObjectData, MetadataLoader},
        streams::AssemblyRefOsRaw,
    },
    prelude::TableId,
    Result,
};

/// Loader for `AssemblyRefOs` metadata
pub(crate) struct AssemblyRefOsLoader;

impl MetadataLoader for AssemblyRefOsLoader {
    fn load(&self, data: &CilObjectData) -> Result<()> {
        if let Some(ref header) = data.meta {
            if let Some(table) = header.table::<AssemblyRefOsRaw>(TableId::AssemblyRefOS) {
                table.par_iter().try_for_each(|row| {
                    row.apply(&data.refs_assembly)?;
                    Ok(())
                })?;
            }
        }
        Ok(())
    }

    fn table_id(&self) -> TableId {
        TableId::AssemblyRefOS
    }

    fn dependencies(&self) -> &'static [TableId] {
        &[TableId::AssemblyRef]
    }
}
