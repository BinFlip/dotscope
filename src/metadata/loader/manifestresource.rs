//! `ManifestResource` loader implementation

use crate::{
    metadata::{
        loader::{LoaderContext, MetadataLoader},
        streams::ManifestResourceRaw,
    },
    prelude::TableId,
    Result,
};

/// Loader for `ManifestResource` metadata
pub(crate) struct ManifestResourceLoader;

impl MetadataLoader for ManifestResourceLoader {
    fn load(&self, context: &LoaderContext) -> Result<()> {
        if let (Some(header), Some(strings)) = (context.meta, context.strings) {
            if let Some(table) = header.table::<ManifestResourceRaw>(TableId::ManifestResource) {
                table.par_iter().try_for_each(|row| {
                    let owned = row.to_owned(
                        &context.input,
                        context.header,
                        strings,
                        context.file,
                        context.assembly_ref,
                        table,
                    )?;

                    context.resources.insert(owned.clone());
                    Ok(())
                })?;
            }
        }
        Ok(())
    }

    fn table_id(&self) -> TableId {
        TableId::ManifestResource
    }

    fn dependencies(&self) -> &'static [TableId] {
        &[TableId::File, TableId::AssemblyRef]
    }
}
