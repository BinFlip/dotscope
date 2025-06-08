//! `PropertyMap` loader implementation

use crate::{
    metadata::{
        loader::{data::CilObjectData, MetadataLoader},
        streams::PropertyMapRaw,
    },
    prelude::TableId,
    Result,
};

/// Loader for `PropertyMap` metadata
pub(crate) struct PropertyMapLoader;

impl MetadataLoader for PropertyMapLoader {
    fn load(&self, data: &CilObjectData) -> Result<()> {
        if let Some(header) = data.meta.as_ref() {
            if let Some(table) = header.table::<PropertyMapRaw>(TableId::PropertyMap) {
                table.par_iter().try_for_each(|row| {
                    row.apply(&data.types, &data.properties, table)?;
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
            TableId::TypeDef,
            TableId::TypeRef,
            TableId::TypeSpec,
        ]
    }
}
