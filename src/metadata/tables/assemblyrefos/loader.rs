//! `AssemblyRefOs` loader implementation

use crate::{
    metadata::{
        loader::{LoaderContext, MetadataLoader},
        tables::AssemblyRefOsRaw,
    },
    prelude::TableId,
    Result,
};

/// Loader for `AssemblyRefOs` metadata
pub(crate) struct AssemblyRefOsLoader;

impl MetadataLoader for AssemblyRefOsLoader {
    fn load(&self, context: &LoaderContext) -> Result<()> {
        if let Some(ref header) = context.meta {
            if let Some(table) = header.table::<AssemblyRefOsRaw>(TableId::AssemblyRefOS) {
                table.par_iter().try_for_each(|row| {
                    let owned = row.to_owned(context.assembly_ref)?;
                    owned.apply()?;

                    context.assembly_ref_os.insert(row.token, owned);
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
