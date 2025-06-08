//! `File` loader implementation

use crate::{
    metadata::{
        loader::{data::CilObjectData, MetadataLoader},
        streams::FileRaw,
    },
    prelude::TableId,
    Result,
};

/// Loader for `File` metadata
pub(crate) struct FileLoader;

impl MetadataLoader for FileLoader {
    fn load(&self, data: &CilObjectData) -> Result<()> {
        if let (Some(header), Some(blob), Some(strings)) = (&data.meta, &data.blobs, &data.strings)
        {
            if let Some(table) = header.table::<FileRaw>(TableId::File) {
                table.par_iter().try_for_each(|row| {
                    let res = row.to_owned(blob, strings)?;
                    data.refs_file.insert(row.token, res);

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
