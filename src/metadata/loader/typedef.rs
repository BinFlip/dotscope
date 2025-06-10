//! `TypeDef` table loader implementation.
use crate::{
    metadata::{
        loader::{LoaderContext, MetadataLoader},
        streams::{tables::typedef::TypeDefRaw, TableId},
    },
    Result,
};

/// Loader for the `TypeDef` metadata table.
pub(crate) struct TypeDefLoader;

impl MetadataLoader for TypeDefLoader {
    fn load(&self, context: &LoaderContext) -> Result<()> {
        if let (Some(header), Some(strings)) = (context.meta, context.strings) {
            if let Some(table) = header.table::<TypeDefRaw>(TableId::TypeDef) {
                table.par_iter().try_for_each(|row| {
                    let res = row.to_owned(strings, &context.field, context.method_def, table)?;

                    // ToDo: Verify this
                    //data.imports.add_type(&res)?;
                    context.types.insert(res);

                    Ok(())
                })?;
            }
        }
        Ok(())
    }

    fn table_id(&self) -> TableId {
        TableId::TypeDef
    }

    fn dependencies(&self) -> &'static [TableId] {
        &[TableId::Field, TableId::MethodDef]
    }
}
