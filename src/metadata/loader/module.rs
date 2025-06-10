//! Module table loader implementation.

use crate::{
    metadata::{
        loader::{LoaderContext, MetadataLoader},
        streams::{tables::module::ModuleRaw, TableId},
    },
    Result,
};

/// Loader for the Module metadata table.
pub(crate) struct ModuleLoader;

impl MetadataLoader for ModuleLoader {
    fn load(&self, context: &LoaderContext) -> Result<()> {
        if let (Some(tables_header), Some(strings), Some(guids)) =
            (context.meta, context.strings, context.guids)
        {
            if let Some(table) = tables_header.table::<ModuleRaw>(TableId::Module) {
                if let Some(row) = table.get(1) {
                    let owned = row.to_owned(strings, guids)?;

                    context
                        .module
                        .set(owned)
                        .map_err(|_| malformed_error!("Module has already been set"))?;
                    return Ok(());
                }
            }
        }

        Err(malformed_error!("No module has been found"))
    }

    fn table_id(&self) -> TableId {
        TableId::Module
    }

    fn dependencies(&self) -> &'static [TableId] {
        &[]
    }
}
