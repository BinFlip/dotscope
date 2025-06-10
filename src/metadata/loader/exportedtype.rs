//! `ExportedType` loader implementation

use crate::{
    metadata::{
        loader::{LoaderContext, MetadataLoader},
        streams::ExportedTypeRaw,
    },
    prelude::TableId,
    Result,
};

/// Loader for `ExportedType` metadata
pub(crate) struct ExportedTypeLoader;

impl MetadataLoader for ExportedTypeLoader {
    fn load(&self, context: &LoaderContext) -> Result<()> {
        if let (Some(header), Some(strings)) = (context.meta, context.strings) {
            if let Some(table) = header.table::<ExportedTypeRaw>(TableId::ExportedType) {
                for row in table {
                    let owned = row.to_owned(
                        strings,
                        context.file,
                        context.assembly_ref,
                        context.exported_type,
                    )?;

                    context.exported_type.insert(row.token, owned.clone())?;
                }
            }
        }
        Ok(())
    }

    fn table_id(&self) -> TableId {
        TableId::ExportedType
    }

    fn dependencies(&self) -> &'static [TableId] {
        &[TableId::File, TableId::AssemblyRef]
    }
}
