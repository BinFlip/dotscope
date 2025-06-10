//! `AssemblyRefProcessor` loader implementation

use crate::{
    metadata::{
        loader::{LoaderContext, MetadataLoader},
        streams::AssemblyRefProcessorRaw,
    },
    prelude::TableId,
    Result,
};

/// Loader for `AssemblyRefProcessor` metadata
pub(crate) struct AssemblyRefProcessorLoader;

impl MetadataLoader for AssemblyRefProcessorLoader {
    fn load(&self, context: &LoaderContext) -> Result<()> {
        if let Some(header) = context.meta {
            if let Some(table) =
                header.table::<AssemblyRefProcessorRaw>(TableId::AssemblyRefProcessor)
            {
                table.par_iter().try_for_each(|row| {
                    let owned = row.to_owned(context.assembly_ref)?;
                    owned.apply()?;

                    context.assembly_ref_processor.insert(row.token, owned);
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
