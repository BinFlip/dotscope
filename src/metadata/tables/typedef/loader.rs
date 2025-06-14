//! `TypeDef` table loader implementation.
use crate::{
    metadata::{
        loader::{LoaderContext, MetadataLoader},
        tables::{TableId, TypeDefRaw},
    },
    Result,
};

/// Loader for the `TypeDef` metadata table.
pub(crate) struct TypeDefLoader;

impl MetadataLoader for TypeDefLoader {
    fn load(&self, context: &LoaderContext) -> Result<()> {
        if let (Some(header), Some(strings)) = (context.meta, context.strings) {
            if let Some(table) = header.table::<TypeDefRaw>(TableId::TypeDef) {
                for row in table {
                    let res = row.to_owned(
                        |coded_index| context.get_ref(coded_index),
                        strings,
                        &context.field,
                        &context.field_ptr,
                        context.method_def,
                        &context.method_ptr,
                        table,
                    )?;

                    context.types.insert(res);
                }
            }
        }
        Ok(())
    }

    fn table_id(&self) -> TableId {
        TableId::TypeDef
    }

    fn dependencies(&self) -> &'static [TableId] {
        &[
            TableId::Field,
            TableId::FieldPtr,
            TableId::MethodDef,
            TableId::MethodPtr,
            TableId::TypeRef,
        ]
    }
}
