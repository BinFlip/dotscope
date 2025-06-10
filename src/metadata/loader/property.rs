//! Property loader implementation

use crate::{
    metadata::{
        loader::{LoaderContext, MetadataLoader},
        streams::PropertyRaw,
    },
    prelude::TableId,
    Result,
};

/// Loader for Property metadata
pub(crate) struct PropertyLoader;

impl MetadataLoader for PropertyLoader {
    fn load(&self, context: &LoaderContext) -> Result<()> {
        if let (Some(header), Some(strings), Some(blob)) =
            (context.meta, context.strings, context.blobs)
        {
            if let Some(table) = header.table::<PropertyRaw>(TableId::Property) {
                table.par_iter().try_for_each(|row| {
                    let res = row.to_owned(strings, blob)?;

                    context.property.insert(row.token, res.clone());
                    Ok(())
                })?;
            }
        }

        Ok(())
    }

    fn table_id(&self) -> TableId {
        TableId::Property
    }

    fn dependencies(&self) -> &'static [TableId] {
        &[]
    }
}
