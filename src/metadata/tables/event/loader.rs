//! Event loader implementation

use crate::{
    metadata::{
        loader::{LoaderContext, MetadataLoader},
        tables::EventRaw,
    },
    prelude::TableId,
    Result,
};

/// Loader for Event metadata
pub(crate) struct EventLoader;

impl MetadataLoader for EventLoader {
    fn load(&self, context: &LoaderContext) -> Result<()> {
        if let (Some(header), Some(strings)) = (context.meta, context.strings) {
            if let Some(table) = header.table::<EventRaw>(TableId::Event) {
                table.par_iter().try_for_each(|row| {
                    let owned = row.to_owned(strings, context.types)?;

                    context.event.insert(row.token, owned.clone());
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
