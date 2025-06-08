//! `MethodSpec` loader implementation
use crate::{
    metadata::{
        loader::{data::CilObjectData, MetadataLoader},
        streams::MethodSpecRaw,
    },
    prelude::TableId,
    Result,
};

/// Loader for `MethodSpec` metadata
pub(crate) struct MethodSpecLoader;

impl MetadataLoader for MethodSpecLoader {
    fn load(&self, data: &CilObjectData) -> Result<()> {
        if let (Some(header), Some(blob)) = (data.meta.as_ref(), data.blobs.as_ref()) {
            if let Some(table) = header.table::<MethodSpecRaw>(TableId::MethodSpec) {
                table.par_iter().try_for_each(|row| {
                    row.apply(blob, &data.types, &data.methods, &data.refs_member)?;
                    Ok(())
                })?;
            }
        }
        Ok(())
    }

    fn table_id(&self) -> TableId {
        TableId::MethodSpec
    }

    fn dependencies(&self) -> &'static [TableId] {
        &[
            TableId::TypeDef,
            TableId::TypeRef,
            TableId::TypeSpec,
            TableId::MethodDef,
            TableId::MemberRef,
        ]
    }
}
