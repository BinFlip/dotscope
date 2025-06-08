//! Field loader implementation

use crate::{
    metadata::{
        loader::{data::CilObjectData, MetadataLoader},
        streams::FieldRaw,
    },
    prelude::TableId,
    Result,
};

/// Loader for Field metadata
pub(crate) struct FieldLoader;

impl MetadataLoader for FieldLoader {
    fn load(&self, data: &CilObjectData) -> Result<()> {
        if let (Some(header), Some(strings), Some(blob)) = (
            data.meta.as_ref(),
            data.strings.as_ref(),
            data.blobs.as_ref(),
        ) {
            if let Some(table) = header.table::<FieldRaw>(TableId::Field) {
                table.par_iter().try_for_each(|row| {
                    let res = row.to_owned(blob, strings)?;
                    data.fields.insert(row.token, res);
                    Ok(())
                })?;
            }
        }
        Ok(())
    }

    fn table_id(&self) -> TableId {
        TableId::Field
    }

    fn dependencies(&self) -> &'static [TableId] {
        &[]
    }
}
