//! `MethodSpec` loader implementation
use crate::{
    metadata::{
        loader::{LoaderContext, MetadataLoader},
        streams::MethodSpecRaw,
    },
    prelude::TableId,
    Result,
};

/// Loader for `MethodSpec` metadata
pub(crate) struct MethodSpecLoader;

impl MetadataLoader for MethodSpecLoader {
    fn load(&self, context: &LoaderContext) -> Result<()> {
        if let (Some(header), Some(blob)) = (context.meta, context.blobs) {
            if let Some(table) = header.table::<MethodSpecRaw>(TableId::MethodSpec) {
                table.par_iter().try_for_each(|row| {
                    let owned = row.to_owned(|coded_index| context.get_ref(coded_index), blob)?;

                    // ToDo: Implement MethodSpec apply
                    //owned.apply()?;

                    context.method_spec.insert(row.token, owned);
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
