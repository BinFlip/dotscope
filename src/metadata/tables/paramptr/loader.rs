//! `ParamPtr` loader implementation
use crate::{
    metadata::{
        loader::{LoaderContext, MetadataLoader},
        tables::{ParamPtrRaw, TableId},
    },
    Result,
};

/// Loader for `ParamPtr` metadata table entries.
pub(crate) struct ParamPtrLoader;

impl MetadataLoader for ParamPtrLoader {
    fn load(&self, context: &LoaderContext) -> Result<()> {
        if let Some(header) = context.meta {
            if let Some(table) = header.table::<ParamPtrRaw>(TableId::ParamPtr) {
                for row in table {
                    let owned = row.to_owned()?;
                    context.param_ptr.insert(row.token, owned);
                }
            }
        }
        Ok(())
    }

    fn table_id(&self) -> TableId {
        TableId::ParamPtr
    }

    fn dependencies(&self) -> &'static [TableId] {
        &[]
    }
}
