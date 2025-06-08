//! `EventMap` loader implementation

use crate::{
    metadata::{
        loader::{data::CilObjectData, MetadataLoader},
        streams::EventMapRaw,
    },
    prelude::TableId,
    Result,
};

/// Loader for `EventMap` metadata
pub(crate) struct EventMapLoader;

impl MetadataLoader for EventMapLoader {
    fn load(&self, data: &CilObjectData) -> Result<()> {
        if let Some(header) = data.meta.as_ref() {
            if let Some(table) = header.table::<EventMapRaw>(TableId::EventMap) {
                table.par_iter().try_for_each(|row| {
                    row.apply(&data.types, &data.events, table)?;
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
        &[TableId::Event]
    }
}
