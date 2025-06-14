//! `InterfaceImpl` loader implementation

use crate::{
    metadata::{
        loader::{LoaderContext, MetadataLoader},
        tables::InterfaceImplRaw,
    },
    prelude::TableId,
    Result,
};

/// Loader for `InterfaceImpl` metadata
pub(crate) struct InterfaceImplLoader;

impl MetadataLoader for InterfaceImplLoader {
    fn load(&self, context: &LoaderContext) -> Result<()> {
        if let Some(header) = context.meta {
            if let Some(table) = header.table::<InterfaceImplRaw>(TableId::InterfaceImpl) {
                table.par_iter().try_for_each(|row| {
                    let res = row.to_owned(context.types)?;
                    res.apply()?;

                    context.interface_impl.insert(row.token, res);
                    Ok(())
                })?;
            }
        }
        Ok(())
    }

    fn table_id(&self) -> TableId {
        TableId::InterfaceImpl
    }

    fn dependencies(&self) -> &'static [TableId] {
        &[TableId::TypeDef, TableId::TypeRef, TableId::TypeSpec]
    }
}
