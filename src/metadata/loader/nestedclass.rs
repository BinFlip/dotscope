//! `NestedClass` loader implementation

use crate::{
    metadata::{
        loader::{LoaderContext, MetadataLoader},
        streams::NestedClassRaw,
    },
    prelude::TableId,
    Result,
};

/// Loader for `NestedClass` metadata
pub(crate) struct NestedClassLoader;

impl MetadataLoader for NestedClassLoader {
    fn load(&self, context: &LoaderContext) -> Result<()> {
        if let Some(header) = context.meta.as_ref() {
            if let Some(table) = header.table::<NestedClassRaw>(TableId::NestedClass) {
                table.par_iter().try_for_each(|row| {
                    let owned = row.to_owned(context.types)?;
                    owned.apply()?;

                    context.nested_class.insert(row.token, owned);
                    Ok(())
                })?;
            }
        }

        Ok(())
    }

    fn table_id(&self) -> TableId {
        TableId::NestedClass
    }

    fn dependencies(&self) -> &'static [TableId] {
        &[TableId::TypeRef, TableId::TypeDef, TableId::TypeSpec]
    }
}
