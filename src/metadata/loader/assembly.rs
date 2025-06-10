//! Assembly table loader implementation.

use crate::{
    metadata::{
        loader::{LoaderContext, MetadataLoader},
        streams::{tables::assembly::AssemblyRaw, TableId},
    },
    Result,
};

/// Loader for the Assembly metadata table.
pub(crate) struct AssemblyLoader;

impl MetadataLoader for AssemblyLoader {
    fn load(&self, context: &LoaderContext) -> Result<()> {
        if let (Some(header), Some(strings), Some(blob)) =
            (context.meta, context.strings, context.blobs)
        {
            if let Some(table) = header.table::<AssemblyRaw>(TableId::Assembly) {
                if let Some(row) = table.get(1) {
                    let owned = row.to_owned(strings, blob)?;

                    context
                        .assembly
                        .set(owned)
                        .map_err(|_| malformed_error!("Assembly has already been set"))?;
                    return Ok(());
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
