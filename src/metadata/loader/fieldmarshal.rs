//! `FieldMarshal` loader implementation

use crate::{
    metadata::{
        loader::{data::CilObjectData, MetadataLoader},
        streams::FieldMarshalRaw,
    },
    prelude::TableId,
    Result,
};

/// Loader for `FieldMarshal` metadata
pub(crate) struct FieldMarshalLoader;

impl MetadataLoader for FieldMarshalLoader {
    fn load(&self, data: &CilObjectData) -> Result<()> {
        if let (Some(header), Some(blob)) = (&data.meta, &data.blobs) {
            if let Some(table) = header.table::<FieldMarshalRaw>(TableId::FieldMarshal) {
                table.par_iter().try_for_each(|row| {
                    row.apply(blob, &data.params, &data.fields)?;
                    Ok(())
                })?;
            }
        }
        Ok(())
    }

    fn table_id(&self) -> TableId {
        TableId::FieldMarshal
    }

    fn dependencies(&self) -> &'static [TableId] {
        &[TableId::Field, TableId::Param]
    }
}
