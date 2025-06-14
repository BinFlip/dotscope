//! `MethodImpl` loader implementation

use crate::{
    metadata::{
        loader::{LoaderContext, MetadataLoader},
        tables::MethodImplRaw,
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
                        row.to_owned(|coded_index| context.get_ref(coded_index), context.types)?;
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
