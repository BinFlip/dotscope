//! Event loader implementation

use crate::{
    metadata::{
        loader::{data::CilObjectData, MetadataLoader},
        streams::EventRaw,
    },
    prelude::TableId,
    Result,
};

/// Loader for Event metadata
pub(crate) struct EventLoader;

impl MetadataLoader for EventLoader {
    fn load(&self, data: &CilObjectData) -> Result<()> {
        if let (Some(header), Some(strings)) = (data.meta.as_ref(), data.strings.as_ref()) {
            if let Some(table) = header.table::<EventRaw>(TableId::Event) {
                table.par_iter().try_for_each(|row| {
                    data.events
                        .insert(row.token, row.to_owned(strings, &data.types)?);
                    Ok(())
                })?;
            }
        }
        Ok(())
    }

    fn table_id(&self) -> TableId {
        TableId::Event
    }

    fn dependencies(&self) -> &'static [TableId] {
        &[TableId::TypeDef, TableId::TypeRef, TableId::TypeSpec]
    }
}
