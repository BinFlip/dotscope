//! Param loader implementation

use crate::{
    metadata::{
        loader::{data::CilObjectData, MetadataLoader},
        streams::ParamRaw,
    },
    prelude::TableId,
    Result,
};

/// Loader for Param metadata
pub(crate) struct ParamLoader;

impl MetadataLoader for ParamLoader {
    fn load(&self, data: &CilObjectData) -> Result<()> {
        if let (Some(header), Some(strings)) = (&data.meta, &data.strings) {
            if let Some(table) = header.table::<ParamRaw>(TableId::Param) {
                table.par_iter().try_for_each(|row| {
                    let res = row.to_owned(strings)?;
                    data.params.insert(row.token, res);
                    Ok(())
                })?;
            }
        }

        Ok(())
    }

    fn table_id(&self) -> TableId {
        TableId::Param
    }

    fn dependencies(&self) -> &'static [TableId] {
        &[]
    }
}
