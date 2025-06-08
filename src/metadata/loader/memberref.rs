//! `MemberRef` loader implementation

use crate::{
    metadata::{
        loader::{data::CilObjectData, MetadataLoader},
        streams::MemberRefRaw,
    },
    prelude::TableId,
    Result,
};

/// Loader for `MemberRef` metadata
pub(crate) struct MemberRefLoader;

impl MetadataLoader for MemberRefLoader {
    fn load(&self, data: &CilObjectData) -> Result<()> {
        if let (Some(header), Some(strings), Some(blob)) = (&data.meta, &data.strings, &data.blobs)
        {
            if let Some(table) = header.table::<MemberRefRaw>(TableId::MemberRef) {
                table.par_iter().try_for_each(|row| {
                    let res =
                        row.to_owned(strings, blob, &data.types, &data.refs_module, &data.methods)?;
                    data.refs_member.insert(row.token, res);
                    Ok(())
                })?;
            }
        }
        Ok(())
    }

    fn table_id(&self) -> TableId {
        TableId::MemberRef
    }

    fn dependencies(&self) -> &'static [TableId] {
        &[
            TableId::ModuleRef,
            TableId::TypeDef,
            TableId::TypeRef,
            TableId::TypeSpec,
            TableId::MethodDef,
        ]
    }
}
