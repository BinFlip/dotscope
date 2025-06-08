//! `ImplMap` metadata table loader

use crate::{
    metadata::{
        loader::{data::CilObjectData, MetadataLoader},
        streams::{tables::implmap::ImplMapRaw, TableId},
    },
    Result,
};

pub(crate) struct ImplMapLoader;

impl MetadataLoader for ImplMapLoader {
    fn load(&self, data: &CilObjectData) -> Result<()> {
        if let (Some(header), Some(strings)) = (data.meta.as_ref(), data.strings.as_ref()) {
            if let Some(table) = header.table::<ImplMapRaw>(TableId::ImplMap) {
                table.par_iter().try_for_each(|row| {
                    row.apply(strings, &data.refs_module, &data.methods, &data.imports)?;
                    Ok(())
                })?;
            }
        }
        Ok(())
    }

    fn table_id(&self) -> TableId {
        TableId::ImplMap
    }

    fn dependencies(&self) -> &'static [TableId] {
        &[
            TableId::MethodDef,
            TableId::ModuleRef,
            TableId::Module,
            TableId::MemberRef,
        ]
    }
}
