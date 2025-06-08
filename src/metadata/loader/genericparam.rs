//! `GenericParam` loader implementation

use crate::{
    metadata::{
        loader::{data::CilObjectData, MetadataLoader},
        streams::GenericParamRaw,
    },
    prelude::{GenericParam, TableId},
    Result,
};

/// Loader for `GenericParam` metadata
pub(crate) struct GenericParamLoader;

impl MetadataLoader for GenericParamLoader {
    fn load(&self, data: &CilObjectData) -> Result<()> {
        if let (Some(header), Some(strings)) = (data.meta.as_ref(), data.strings.as_ref()) {
            if let Some(generics) = header.table::<GenericParamRaw>(TableId::GenericParam) {
                generics.par_iter().try_for_each(|row| {
                    let res = row.to_owned(strings, &data.types, &data.methods)?;
                    GenericParam::apply(&res)?;
                    data.params_generic.insert(row.token, res);
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
