//! `FieldLayout` loader implementation

use crate::{
    metadata::{
        loader::{data::CilObjectData, MetadataLoader},
        streams::FieldLayoutRaw,
    },
    prelude::TableId,
    Result,
};

/// Loader for `FieldLayout` metadata
pub(crate) struct FieldLayoutLoader;

impl MetadataLoader for FieldLayoutLoader {
    fn load(&self, data: &CilObjectData) -> Result<()> {
        if let Some(header) = data.meta.as_ref() {
            if let Some(table) = header.table::<FieldLayoutRaw>(TableId::FieldLayout) {
                table.par_iter().try_for_each(|row| {
                    row.apply(&data.fields)?;

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
