//! `ImplMap` metadata table loader

use crate::{
    metadata::{
        loader::{LoaderContext, MetadataLoader},
        streams::{tables::implmap::ImplMapRaw, TableId},
    },
    Result,
};

pub(crate) struct ImplMapLoader;

impl MetadataLoader for ImplMapLoader {
    fn load(&self, context: &LoaderContext) -> Result<()> {
        if let (Some(header), Some(strings)) = (context.meta, context.strings) {
            if let Some(table) = header.table::<ImplMapRaw>(TableId::ImplMap) {
                table.par_iter().try_for_each(|row| {
                    let owned = row.to_owned(strings, context.module_ref, context.method_def)?;
                    owned.apply()?;

                    context.imports.add_method(
                        owned.import_name.clone(),
                        &owned.token,
                        owned.member_forwarded.clone(),
                        &owned.import_scope,
                    )?;
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
