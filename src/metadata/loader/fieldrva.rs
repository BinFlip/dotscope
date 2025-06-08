//! `FieldRva` loader implementation

use crate::{
    metadata::{
        loader::{data::CilObjectData, MetadataLoader},
        streams::FieldRvaRaw,
    },
    prelude::TableId,
    Result,
};

/// Loader for `FieldRva` metadata
pub(crate) struct FieldRvaLoader;

impl MetadataLoader for FieldRvaLoader {
    fn load(&self, data: &CilObjectData) -> Result<()> {
        if let Some(header) = data.meta.as_ref() {
            if let Some(table) = header.table::<FieldRvaRaw>(TableId::FieldRVA) {
                table.par_iter().try_for_each(|row| {
                    row.apply(&data.fields)?;
                    Ok(())
                })?;
            }
        }
        Ok(())
    }

    fn table_id(&self) -> TableId {
        TableId::FieldRVA
    }

    fn dependencies(&self) -> &'static [TableId] {
        &[TableId::Field]
    }
}
