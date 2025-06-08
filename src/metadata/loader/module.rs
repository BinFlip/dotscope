//! Module table loader implementation.

use crate::{
    metadata::{
        loader::{data::CilObjectData, MetadataLoader},
        streams::{tables::module::ModuleRaw, TableId},
    },
    Result,
};

/// Loader for the Module metadata table.
pub(crate) struct ModuleLoader;

impl MetadataLoader for ModuleLoader {
    fn load(&self, data: &CilObjectData) -> Result<()> {
        // ToDo: According to ECMA-335, this should ever only hold one module. But the standard does have references to
        //       cases where one assembly may contain more than one?

        if let (Some(tables_header), Some(strings), Some(guids)) = (
            data.meta.as_ref(),
            data.strings.as_ref(),
            data.guids.as_ref(),
        ) {
            if let Some(module_table) = tables_header.table::<ModuleRaw>(TableId::Module) {
                if let Some(table) = module_table.get(1) {
                    data.module
                        .set(table.to_owned(strings, guids)?)
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
