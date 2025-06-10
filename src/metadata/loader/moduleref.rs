//! `ModuleRef` loader implementation

use crate::{
    metadata::{
        loader::{LoaderContext, MetadataLoader},
        streams::ModuleRefRaw,
    },
    prelude::TableId,
    Result,
};

/// Loader for `ModuleRef` metadata
pub(crate) struct ModuleRefLoader;

impl MetadataLoader for ModuleRefLoader {
    fn load(&self, context: &LoaderContext) -> Result<()> {
        if let (Some(header), Some(strings)) = (context.meta, context.strings) {
            if let Some(table) = header.table::<ModuleRefRaw>(TableId::ModuleRef) {
                table.par_iter().try_for_each(|row| {
                    let res = row.to_owned(strings)?;

                    context.module_ref.insert(row.token, res.clone());
                    Ok(())
                })?;
            }
        }
        Ok(())
    }

    fn table_id(&self) -> TableId {
        TableId::ModuleRef
    }

    fn dependencies(&self) -> &'static [TableId] {
        &[]
    }
}
