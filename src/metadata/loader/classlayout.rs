//! `ClassLayout` loader implementation

use crate::{
    metadata::{
        loader::{data::CilObjectData, MetadataLoader},
        streams::ClassLayoutRaw,
    },
    prelude::TableId,
    Result,
};

/// Loader for `ClassLayout` metadata
pub(crate) struct ClassLayoutLoader;

impl MetadataLoader for ClassLayoutLoader {
    fn load(&self, data: &CilObjectData) -> Result<()> {
        if let Some(header) = &data.meta {
            if let Some(table) = header.table::<ClassLayoutRaw>(TableId::ClassLayout) {
                table.par_iter().try_for_each(|row| {
                    row.apply(&data.types)?;
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
