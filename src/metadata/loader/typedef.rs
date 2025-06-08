//! `TypeDef` table loader implementation.
use crate::{
    metadata::{
        loader::{data::CilObjectData, MetadataLoader},
        streams::{tables::typedef::TypeDefRaw, TableId},
    },
    Result,
};

/// Loader for the `TypeDef` metadata table.
pub(crate) struct TypeDefLoader;

impl MetadataLoader for TypeDefLoader {
    fn load(&self, data: &CilObjectData) -> Result<()> {
        if let (Some(header), Some(strings)) = (data.meta.as_ref(), data.strings.as_ref()) {
            if let Some(table) = header.table::<TypeDefRaw>(TableId::TypeDef) {
                table.par_iter().try_for_each(|row| {
                    let res = row.to_owned(strings, &data.fields, &data.methods, table)?;
                    data.imports.add_type(&res)?;
                    data.types.insert(res);

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
