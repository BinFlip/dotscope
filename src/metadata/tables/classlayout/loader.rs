//! `ClassLayout` loader implementation

use crate::{
    metadata::{
        loader::{LoaderContext, MetadataLoader},
        tables::ClassLayoutRaw,
    },
    prelude::TableId,
    Result,
};

/// Loader for `ClassLayout` metadata
pub(crate) struct ClassLayoutLoader;

impl MetadataLoader for ClassLayoutLoader {
    fn load(&self, context: &LoaderContext) -> Result<()> {
        if let Some(header) = context.meta {
            if let Some(table) = header.table::<ClassLayoutRaw>(TableId::ClassLayout) {
                table.par_iter().try_for_each(|row| {
                    let owned = row.to_owned(context.types)?;
                    owned.apply()?;

                    context.class_layout.insert(row.token, owned);
                    Ok(())
                })?;
            }
        }
        Ok(())
    }

    fn table_id(&self) -> TableId {
        TableId::ClassLayout
    }

    fn dependencies(&self) -> &'static [TableId] {
        &[TableId::TypeDef]
    }
}
