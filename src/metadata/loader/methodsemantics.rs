//! `MethodSemantics` loader implementation

use crate::{
    metadata::{
        loader::{data::CilObjectData, MetadataLoader},
        streams::MethodSemanticsRaw,
    },
    prelude::TableId,
    Result,
};

/// Loader for `MethodSemantics` metadata
pub(crate) struct MethodSemanticsLoader;

impl MetadataLoader for MethodSemanticsLoader {
    fn load(&self, data: &CilObjectData) -> Result<()> {
        if let Some(header) = data.meta.as_ref() {
            if let Some(table) = header.table::<MethodSemanticsRaw>(TableId::MethodSemantics) {
                table.par_iter().try_for_each(|row| {
                    row.apply(&data.methods, &data.events, &data.properties)?;
                    Ok(())
                })?;
            }
        }
        Ok(())
    }

    fn table_id(&self) -> TableId {
        TableId::MethodSemantics
    }

    fn dependencies(&self) -> &'static [TableId] {
        &[
            TableId::Event,
            TableId::EventMap,
            TableId::Property,
            TableId::PropertyMap,
        ]
    }
}
