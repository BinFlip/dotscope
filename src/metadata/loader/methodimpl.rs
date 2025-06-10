//! `MethodImpl` loader implementation

use crate::{
    metadata::{
        loader::{LoaderContext, MetadataLoader},
        streams::MethodImplRaw,
    },
    prelude::TableId,
    Result,
};

/// Loader for `MethodImpl` metadata
pub(crate) struct MethodImplLoader;

impl MetadataLoader for MethodImplLoader {
    fn load(&self, context: &LoaderContext) -> Result<()> {
        if let Some(header) = context.meta {
            if let Some(table) = header.table::<MethodImplRaw>(TableId::MethodImpl) {
                table.par_iter().try_for_each(|row| {
                    let owned =
                        row.to_owned(context.types, context.member_ref, context.method_def)?;
                    owned.apply()?;

                    context.method_impl.insert(row.token, owned);
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
