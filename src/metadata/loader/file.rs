//! `File` loader implementation

use crate::{
    metadata::{
        loader::{LoaderContext, MetadataLoader},
        streams::FileRaw,
    },
    prelude::TableId,
    Result,
};

/// Loader for `File` metadata
pub(crate) struct FileLoader;

impl MetadataLoader for FileLoader {
    fn load(&self, context: &LoaderContext) -> Result<()> {
        if let (Some(header), Some(blob), Some(strings)) =
            (context.meta, context.blobs, context.strings)
        {
            if let Some(table) = header.table::<FileRaw>(TableId::File) {
                table.par_iter().try_for_each(|row| {
                    let res = row.to_owned(blob, strings)?;

                    context.file.insert(row.token, res.clone());
                    Ok(())
                })?;
            }
        }
        Ok(())
    }

    fn table_id(&self) -> TableId {
        TableId::File
    }

    fn dependencies(&self) -> &'static [TableId] {
        &[]
    }
}
