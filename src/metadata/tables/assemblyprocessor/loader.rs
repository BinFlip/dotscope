//! `AssemblyProcessor` table loader implementation.

use crate::{
    metadata::{
        loader::{LoaderContext, MetadataLoader},
        tables::{AssemblyProcessorRaw, TableId},
    },
    Result,
};

/// Loader for the `AssemblyProcessor` metadata table.
pub(crate) struct AssemblyProcessorLoader;

impl MetadataLoader for AssemblyProcessorLoader {
    fn load(&self, context: &LoaderContext) -> Result<()> {
        if let Some(ref header) = context.meta {
            if let Some(table) = header.table::<AssemblyProcessorRaw>(TableId::AssemblyProcessor) {
                if let Some(row) = table.get(1) {
                    let owned = row.to_owned()?;

                    context
                        .assembly_processor
                        .set(owned)
                        .map_err(|_| malformed_error!("AssemblyProcessor has already been set"))?;
                    return Ok(());
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
