//! `GenericParam` loader implementation

use crate::{
    metadata::{
        loader::{LoaderContext, MetadataLoader},
        streams::GenericParamRaw,
    },
    prelude::TableId,
    Result,
};

/// Loader for `GenericParam` metadata
pub(crate) struct GenericParamLoader;

impl MetadataLoader for GenericParamLoader {
    fn load(&self, context: &LoaderContext) -> Result<()> {
        if let (Some(header), Some(strings)) = (context.meta, context.strings) {
            if let Some(generics) = header.table::<GenericParamRaw>(TableId::GenericParam) {
                generics.par_iter().try_for_each(|row| {
                    let owned =
                        row.to_owned(|coded_index| context.get_ref(coded_index), strings)?;
                    owned.apply()?;

                    context.generic_param.insert(row.token, owned.clone());
                    Ok(())
                })?;
            }
        }
        Ok(())
    }

    fn table_id(&self) -> TableId {
        TableId::GenericParam
    }

    fn dependencies(&self) -> &'static [TableId] {
        &[
            TableId::TypeDef,
            TableId::TypeRef,
            TableId::TypeSpec,
            TableId::MethodDef,
        ]
    }
}
