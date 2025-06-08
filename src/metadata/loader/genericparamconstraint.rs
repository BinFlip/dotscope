//! `GenericParamConstraint` loader implementation

use crate::{
    metadata::{
        loader::{data::CilObjectData, MetadataLoader},
        streams::GenericParamConstraintRaw,
    },
    prelude::TableId,
    Result,
};

/// Loader for `GenericParamConstraint` metadata
pub(crate) struct GenericParamConstraintLoader;

impl MetadataLoader for GenericParamConstraintLoader {
    fn load(&self, data: &CilObjectData) -> Result<()> {
        if let Some(header) = data.meta.as_ref() {
            if let Some(table) =
                header.table::<GenericParamConstraintRaw>(TableId::GenericParamConstraint)
            {
                table.par_iter().try_for_each(|row| {
                    row.apply(&data.params_generic, &data.types)?;
                    Ok(())
                })?;
            }
        }
        Ok(())
    }

    fn table_id(&self) -> TableId {
        TableId::GenericParamConstraint
    }

    fn dependencies(&self) -> &'static [TableId] {
        &[
            TableId::GenericParam,
            TableId::TypeDef,
            TableId::TypeSpec,
            TableId::TypeRef,
            TableId::MethodDef,
            TableId::MemberRef,
        ]
    }
}
