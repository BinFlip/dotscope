//! Field loader implementation

use crate::{
    metadata::{
        loader::{LoaderContext, MetadataLoader},
        tables::FieldRaw,
    },
    prelude::TableId,
    Result,
};

/// Loader for Field metadata
pub(crate) struct FieldLoader;

impl MetadataLoader for FieldLoader {
    fn load(&self, context: &LoaderContext) -> Result<()> {
        if let (Some(header), Some(strings), Some(blob)) =
            (context.meta, context.strings, context.blobs)
        {
            if let Some(table) = header.table::<FieldRaw>(TableId::Field) {
                table.par_iter().try_for_each(|row| {
                    let res = row.to_owned(blob, strings)?;

                    context.field.insert(row.token, res.clone());
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
