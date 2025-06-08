//! `NestedClass` loader implementation

use crate::{
    metadata::{
        loader::{data::CilObjectData, MetadataLoader},
        streams::NestedClassRaw,
    },
    prelude::TableId,
    Result,
};

/// Loader for `NestedClass` metadata
pub(crate) struct NestedClassLoader;

impl MetadataLoader for NestedClassLoader {
    fn load(&self, data: &CilObjectData) -> Result<()> {
        if let Some(header) = data.meta.as_ref() {
            if let Some(table) = header.table::<NestedClassRaw>(TableId::NestedClass) {
                NestedClassRaw::apply(table, &data.types)?;
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
