//! `MethodPtr` loader implementation

use crate::{
    metadata::{
        loader::{LoaderContext, MetadataLoader},
        streams::{MethodPtrRaw, TableId},
    },
    Result,
};

/// Loader for the `MethodPtr` table.
pub(crate) struct MethodPtrLoader;

impl MetadataLoader for MethodPtrLoader {
    fn load(&self, context: &LoaderContext) -> Result<()> {
        if let Some(header) = context.meta {
            if let Some(table) = header.table::<MethodPtrRaw>(TableId::MethodPtr) {
                for row in table {
                    let owned = row.to_owned()?;
                    row.apply()?;

                    context.method_ptr.insert(row.token, owned);
                }
            }
        }
        Ok(())
    }

    fn table_id(&self) -> TableId {
        TableId::MethodPtr
    }

    fn dependencies(&self) -> &'static [TableId] {
        &[]
    }
}
