//! `EventMap` loader implementation

use crate::{
    metadata::{
        loader::{LoaderContext, MetadataLoader},
        tables::EventMapRaw,
    },
    prelude::TableId,
    Result,
};

/// Loader for `EventMap` metadata
pub(crate) struct EventMapLoader;

impl MetadataLoader for EventMapLoader {
    fn load(&self, context: &LoaderContext) -> Result<()> {
        if let Some(header) = context.meta.as_ref() {
            if let Some(table) = header.table::<EventMapRaw>(TableId::EventMap) {
                table.par_iter().try_for_each(|row| {
                    let owned =
                        row.to_owned(context.types, &context.event, &context.event_ptr, table)?;
                    owned.apply()?;

                    context.event_map.insert(row.token, owned);
                    Ok(())
                })?;
            }
        }
        Ok(())
    }

    fn table_id(&self) -> TableId {
        TableId::EventMap
    }

    fn dependencies(&self) -> &'static [TableId] {
        &[TableId::Event, TableId::EventPtr]
    }
}
