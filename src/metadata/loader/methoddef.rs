//! `MethodDef` loader implementation

use crate::{
    metadata::loader::{LoaderContext, MetadataLoader},
    prelude::{MethodDefRaw, TableId},
    Result,
};

/// Loader for `MethodDef` metadata
pub(crate) struct MethodDefLoader;

impl MetadataLoader for MethodDefLoader {
    fn load(&self, context: &LoaderContext) -> Result<()> {
        if let (Some(header), Some(strings), Some(blobs)) =
            (context.meta, context.strings, context.blobs)
        {
            if let Some(table) = header.table::<MethodDefRaw>(TableId::MethodDef) {
                table.par_iter().try_for_each(|row| {
                    let owned = row.to_owned(strings, blobs, &context.param, table)?;

                    context.method_def.insert(row.token, owned.clone());
                    Ok(())
                })?;
            }
        }

        Ok(())
    }

    fn table_id(&self) -> TableId {
        TableId::MethodDef
    }

    fn dependencies(&self) -> &'static [TableId] {
        &[TableId::Param]
    }
}
