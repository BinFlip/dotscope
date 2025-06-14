//! Param loader implementation

use crate::{
    metadata::{
        loader::{LoaderContext, MetadataLoader},
        tables::ParamRaw,
    },
    prelude::TableId,
    Result,
};

/// Loader for Param metadata
pub(crate) struct ParamLoader;

impl MetadataLoader for ParamLoader {
    fn load(&self, context: &LoaderContext) -> Result<()> {
        if let (Some(header), Some(strings)) = (context.meta, context.strings) {
            if let Some(table) = header.table::<ParamRaw>(TableId::Param) {
                table.par_iter().try_for_each(|row| {
                    let res = row.to_owned(strings)?;

                    context.param.insert(row.token, res.clone());
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
