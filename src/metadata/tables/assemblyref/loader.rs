//! `AssemblyRef` table loader implementation.

use crate::{
    metadata::{
        loader::{LoaderContext, MetadataLoader},
        tables::{AssemblyRefRaw, TableId},
    },
    Result,
};

/// Loader for the `AssemblyRef` metadata table.
pub(crate) struct AssemblyRefLoader;

impl MetadataLoader for AssemblyRefLoader {
    fn load(&self, context: &LoaderContext) -> Result<()> {
        if let (Some(header), Some(blob), Some(strings)) =
            (context.meta, context.blobs, context.strings)
        {
            if let Some(table) = header.table::<AssemblyRefRaw>(TableId::AssemblyRef) {
                table.par_iter().try_for_each(|row| {
                    let res = row.to_owned(strings, blob)?;
                    context.assembly_ref.insert(row.token, res.clone());
                    Ok(())
                })?;
            }
        }
        Ok(())
    }

    fn table_id(&self) -> TableId {
        TableId::AssemblyRef
    }

    fn dependencies(&self) -> &'static [TableId] {
        &[]
    }
}
