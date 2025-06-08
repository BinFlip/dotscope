//! `InterfaceImpl` loader implementation

use crate::{
    metadata::{
        loader::{data::CilObjectData, MetadataLoader},
        streams::InterfaceImplRaw,
    },
    prelude::TableId,
    Result,
};

/// Loader for `InterfaceImpl` metadata
pub(crate) struct InterfaceImplLoader;

impl MetadataLoader for InterfaceImplLoader {
    fn load(&self, data: &CilObjectData) -> Result<()> {
        if let Some(header) = data.meta.as_ref() {
            if let Some(table) = header.table::<InterfaceImplRaw>(TableId::InterfaceImpl) {
                table.par_iter().try_for_each(|row| {
                    row.apply(&data.types)?;
                    Ok(())
                })?;
            }
        }
        Ok(())
    }

    fn table_id(&self) -> TableId {
        TableId::InterfaceImpl
    }

    fn dependencies(&self) -> &'static [TableId] {
        &[TableId::TypeDef, TableId::TypeRef, TableId::TypeSpec]
    }
}
