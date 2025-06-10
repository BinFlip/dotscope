//! `GenericParamConstraint` loader implementation

use crate::{
    metadata::{
        loader::{LoaderContext, MetadataLoader},
        streams::GenericParamConstraintRaw,
    },
    prelude::TableId,
    Result,
};

/// Loader for `GenericParamConstraint` metadata
pub(crate) struct GenericParamConstraintLoader;

impl MetadataLoader for GenericParamConstraintLoader {
    fn load(&self, context: &LoaderContext) -> Result<()> {
        if let Some(header) = context.meta {
            if let Some(table) =
                header.table::<GenericParamConstraintRaw>(TableId::GenericParamConstraint)
            {
                table.par_iter().try_for_each(|row| {
                    let res = row.to_owned(&context.generic_param, context.types)?;
                    res.apply()?;

                    context.generic_param_constraint.insert(row.token, res);
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
