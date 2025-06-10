//! `MethodSemantics` loader implementation

use crate::{
    metadata::{
        loader::{LoaderContext, MetadataLoader},
        streams::MethodSemanticsRaw,
    },
    prelude::TableId,
    Result,
};

/// Loader for `MethodSemantics` metadata
pub(crate) struct MethodSemanticsLoader;

impl MetadataLoader for MethodSemanticsLoader {
    fn load(&self, context: &LoaderContext) -> Result<()> {
        if let Some(header) = context.meta {
            if let Some(table) = header.table::<MethodSemanticsRaw>(TableId::MethodSemantics) {
                table.par_iter().try_for_each(|row| {
                    let owned = row.to_owned(
                        |coded_index| context.get_ref(coded_index),
                        context.method_def,
                    )?;
                    owned.apply()?;

                    context.method_semantics.insert(row.token, owned);
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
