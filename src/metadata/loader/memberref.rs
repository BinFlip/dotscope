//! `MemberRef` loader implementation

use crate::{
    metadata::{
        loader::{LoaderContext, MetadataLoader},
        streams::MemberRefRaw,
    },
    prelude::TableId,
    Result,
};

/// Loader for `MemberRef` metadata
pub(crate) struct MemberRefLoader;

impl MetadataLoader for MemberRefLoader {
    fn load(&self, context: &LoaderContext) -> Result<()> {
        if let (Some(header), Some(strings), Some(blob)) =
            (context.meta, context.strings, context.blobs)
        {
            if let Some(table) = header.table::<MemberRefRaw>(TableId::MemberRef) {
                table.par_iter().try_for_each(|row| {
                    let res = row.to_owned(strings, blob, context.types, |coded_index| {
                        context.get_ref(coded_index)
                    })?;

                    context.member_ref.insert(row.token, res.clone());
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
