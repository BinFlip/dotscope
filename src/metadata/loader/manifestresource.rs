//! `ManifestResource` loader implementation

use crate::{
    metadata::loader::{data::CilObjectData, MetadataLoader},
    prelude::TableId,
    Result,
};

/// Loader for `ManifestResource` metadata
pub(crate) struct ManifestResourceLoader;

impl MetadataLoader for ManifestResourceLoader {
    fn load(&self, data: &CilObjectData) -> Result<()> {
        if let (Some(header), Some(strings)) = (data.meta.as_ref(), data.strings.as_ref()) {
            data.resources.load(
                &data.header,
                strings,
                header,
                &data.refs_assembly,
                &data.refs_file,
            )?;
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
