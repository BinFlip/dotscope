//! `PropertyMap` loader implementation

use crate::{
    metadata::{
        loader::{LoaderContext, MetadataLoader},
        tables::PropertyMapRaw,
    },
    prelude::TableId,
    Result,
};

/// Loader for `PropertyMap` metadata
pub(crate) struct PropertyMapLoader;

impl MetadataLoader for PropertyMapLoader {
    fn load(&self, context: &LoaderContext) -> Result<()> {
        if let Some(header) = context.meta.as_ref() {
            if let Some(table) = header.table::<PropertyMapRaw>(TableId::PropertyMap) {
                table.par_iter().try_for_each(|row| {
                    let owned = row.to_owned(
                        context.types,
                        &context.property,
                        &context.property_ptr,
                        table,
                    )?;
                    owned.apply()?;

                    context.property_map.insert(row.token, owned);
                    Ok(())
                })?;
            }
        }

        Ok(())
    }

    fn table_id(&self) -> TableId {
        TableId::PropertyMap
    }

    fn dependencies(&self) -> &'static [TableId] {
        &[
            TableId::Property,
            TableId::PropertyPtr,
            TableId::TypeDef,
            TableId::TypeRef,
            TableId::TypeSpec,
        ]
    }
}
