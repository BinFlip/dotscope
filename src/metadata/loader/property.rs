//! Property loader implementation

use crate::{
    metadata::{
        loader::{data::CilObjectData, MetadataLoader},
        streams::PropertyRaw,
    },
    prelude::TableId,
    Result,
};

/// Loader for Property metadata
pub(crate) struct PropertyLoader;

impl MetadataLoader for PropertyLoader {
    fn load(&self, data: &CilObjectData) -> Result<()> {
        if let (Some(header), Some(strings), Some(blob)) = (
            data.meta.as_ref(),
            data.strings.as_ref(),
            data.blobs.as_ref(),
        ) {
            if let Some(table) = header.table::<PropertyRaw>(TableId::Property) {
                table.par_iter().try_for_each(|row| {
                    let res = row.to_owned(strings, blob)?;
                    data.properties.insert(row.token, res);
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
