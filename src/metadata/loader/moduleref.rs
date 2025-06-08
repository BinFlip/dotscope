//! `ModuleRef` loader implementation

use crate::{
    metadata::{
        loader::{data::CilObjectData, MetadataLoader},
        streams::ModuleRefRaw,
    },
    prelude::TableId,
    Result,
};

/// Loader for `ModuleRef` metadata
pub(crate) struct ModuleRefLoader;

impl MetadataLoader for ModuleRefLoader {
    fn load(&self, data: &CilObjectData) -> Result<()> {
        if let (Some(header), Some(strings)) = (data.meta.as_ref(), data.strings.as_ref()) {
            if let Some(table) = header.table::<ModuleRefRaw>(TableId::ModuleRef) {
                table.par_iter().try_for_each(|row| {
                    let res = row.to_owned(strings)?;
                    data.refs_module.insert(row.token, res);

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
