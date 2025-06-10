//! `FieldLayout` loader implementation

use crate::{
    metadata::{
        loader::{LoaderContext, MetadataLoader},
        streams::FieldLayoutRaw,
    },
    prelude::TableId,
    Result,
};

/// Loader for `FieldLayout` metadata
pub(crate) struct FieldLayoutLoader;

impl MetadataLoader for FieldLayoutLoader {
    fn load(&self, context: &LoaderContext) -> Result<()> {
        if let Some(header) = context.meta {
            if let Some(table) = header.table::<FieldLayoutRaw>(TableId::FieldLayout) {
                table.par_iter().try_for_each(|row| {
                    let owned = row.to_owned(&context.field)?;
                    owned.apply()?;

                    context.field_layout.insert(row.token, owned);
                    Ok(())
                })?;
            }
        }
        Ok(())
    }

    fn table_id(&self) -> TableId {
        TableId::FieldLayout
    }

    fn dependencies(&self) -> &'static [TableId] {
        &[TableId::Field]
    }
}
