//! `AssemblyOS` table loader implementation.

use crate::{
    metadata::{
        loader::{LoaderContext, MetadataLoader},
        tables::{AssemblyOsRaw, TableId},
    },
    Result,
};

/// Loader for the `AssemblyOS` metadata table.
pub(crate) struct AssemblyOsLoader;

impl MetadataLoader for AssemblyOsLoader {
    fn load(&self, context: &LoaderContext) -> Result<()> {
        if let Some(header) = context.meta {
            if let Some(table) = header.table::<AssemblyOsRaw>(TableId::AssemblyOS) {
                if let Some(row) = table.get(1) {
                    let owned = row.to_owned()?;

                    context
                        .assembly_os
                        .set(owned)
                        .map_err(|_| malformed_error!("AssemblyOs has already been set"))?;
                    return Ok(());
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
