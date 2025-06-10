//! `TypeSpec` loader implementation

use crate::{
    metadata::loader::{LoaderContext, MetadataLoader},
    prelude::{TableId, TypeResolver, TypeSpecRaw},
    Result,
};

/// Loader for `TypeSpec` metadata
pub(crate) struct TypeSpecLoader;

impl MetadataLoader for TypeSpecLoader {
    fn load(&self, context: &LoaderContext) -> Result<()> {
        if let (Some(header), Some(blobs)) = (context.meta, context.blobs) {
            if let Some(table) = header.table::<TypeSpecRaw>(TableId::TypeSpec) {
                table.par_iter().try_for_each(|row| {
                    let owned = row.to_owned(blobs)?;
                    owned.apply()?;

                    let mut resolver =
                        TypeResolver::new(context.types.clone()).with_token_init(row.token);
                    resolver.resolve(&owned.signature.base)?;

                    context.type_spec.insert(row.token, owned);
                    Ok(())
                })?;
            }
        }

        Ok(())
    }

    fn table_id(&self) -> TableId {
        TableId::TypeSpec
    }

    fn dependencies(&self) -> &'static [TableId] {
        &[TableId::TypeRef, TableId::TypeDef]
    }
}
