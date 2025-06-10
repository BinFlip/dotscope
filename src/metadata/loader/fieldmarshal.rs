//! `FieldMarshal` loader implementation

use crate::{
    metadata::{
        loader::{LoaderContext, MetadataLoader},
        streams::FieldMarshalRaw,
    },
    prelude::TableId,
    Result,
};

/// Loader for `FieldMarshal` metadata
pub(crate) struct FieldMarshalLoader;

impl MetadataLoader for FieldMarshalLoader {
    fn load(&self, context: &LoaderContext) -> Result<()> {
        if let (Some(header), Some(blob)) = (context.meta, context.blobs) {
            if let Some(table) = header.table::<FieldMarshalRaw>(TableId::FieldMarshal) {
                table.par_iter().try_for_each(|row| {
                    let res = row.to_owned(blob, &context.param, &context.field)?;
                    res.apply()?;

                    context.field_marshal.insert(row.token, res);
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
