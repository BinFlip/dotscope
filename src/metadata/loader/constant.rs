//! Constant loader implementation

use crate::{
    metadata::{
        loader::{data::CilObjectData, MetadataLoader},
        streams::ConstantRaw,
    },
    prelude::TableId,
    Result,
};

/// Loader for Constant metadata
pub(crate) struct ConstantLoader;

impl MetadataLoader for ConstantLoader {
    fn load(&self, data: &CilObjectData) -> Result<()> {
        if let (Some(header), Some(blob)) = (data.meta.as_ref(), data.blobs.as_ref()) {
            if let Some(table) = header.table::<ConstantRaw>(TableId::Constant) {
                table.par_iter().try_for_each(|row| {
                    row.apply(blob, &data.params, &data.fields, &data.properties)?;
                    Ok(())
                })?;
            }
        }
        Ok(())
    }

    fn table_id(&self) -> TableId {
        TableId::Constant
    }

    fn dependencies(&self) -> &'static [TableId] {
        &[TableId::Field, TableId::Param, TableId::Property]
    }
}
