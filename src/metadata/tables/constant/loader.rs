//! Constant loader implementation

use crate::{
    metadata::{
        loader::{LoaderContext, MetadataLoader},
        tables::ConstantRaw,
    },
    prelude::TableId,
    Result,
};

/// Loader for Constant metadata
pub(crate) struct ConstantLoader;

impl MetadataLoader for ConstantLoader {
    fn load(&self, context: &LoaderContext) -> Result<()> {
        if let (Some(header), Some(blob)) = (context.meta, context.blobs) {
            if let Some(table) = header.table::<ConstantRaw>(TableId::Constant) {
                table.par_iter().try_for_each(|row| {
                    let owned = row.to_owned(|coded_index| context.get_ref(coded_index), blob)?;
                    owned.apply()?;

                    context.constant.insert(row.token, owned);
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
