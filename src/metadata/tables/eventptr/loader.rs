//! `EventPtr` loader implementation
use crate::{
    metadata::{
        loader::{LoaderContext, MetadataLoader},
        tables::{EventPtrRaw, TableId},
    },
    Result,
};

/// Loader for the `EventPtr` table.
pub struct EventPtrLoader;

impl MetadataLoader for EventPtrLoader {
    fn load(&self, context: &LoaderContext) -> Result<()> {
        if let Some(header) = context.meta {
            if let Some(table) = header.table::<EventPtrRaw>(TableId::EventPtr) {
                for row in table {
                    let owned = row.to_owned()?;
                    context.event_ptr.insert(row.token, owned);
                }
            }
        }
        Ok(())
    }

    fn table_id(&self) -> TableId {
        TableId::EventPtr
    }

    fn dependencies(&self) -> &'static [TableId] {
        &[]
    }
}
