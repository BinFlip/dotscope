//! `MethodImpl` loader implementation

use crate::{
    metadata::{
        loader::{data::CilObjectData, MetadataLoader},
        streams::MethodImplRaw,
    },
    prelude::TableId,
    Result,
};

/// Loader for `MethodImpl` metadata
pub(crate) struct MethodImplLoader;

impl MetadataLoader for MethodImplLoader {
    fn load(&self, data: &CilObjectData) -> Result<()> {
        if let Some(header) = data.meta.as_ref() {
            if let Some(table) = header.table::<MethodImplRaw>(TableId::MethodImpl) {
                table.par_iter().try_for_each(|row| {
                    row.apply(&data.types, &data.refs_member, &data.methods)?;
                    Ok(())
                })?;
            }
        }
        Ok(())
    }

    fn table_id(&self) -> TableId {
        TableId::MethodImpl
    }

    fn dependencies(&self) -> &'static [TableId] {
        &[
            TableId::TypeDef,
            TableId::TypeRef,
            TableId::MethodDef,
            TableId::MemberRef,
        ]
    }
}
