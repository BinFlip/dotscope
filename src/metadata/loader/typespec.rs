//! `TypeSpec` loader implementation

use crate::{
    metadata::{
        loader::{data::CilObjectData, MetadataLoader},
        signatures::parse_type_spec_signature,
    },
    prelude::{TableId, TypeResolver, TypeSpecRaw},
    Result,
};

/// Loader for `TypeSpec` metadata
pub(crate) struct TypeSpecLoader;

impl MetadataLoader for TypeSpecLoader {
    fn load(&self, data: &CilObjectData) -> Result<()> {
        if let (Some(header), Some(blobs)) = (data.meta.as_ref(), data.blobs.as_ref()) {
            if let Some(table) = header.table::<TypeSpecRaw>(TableId::TypeSpec) {
                table.par_iter().try_for_each(|row| {
                    let type_spec_sig =
                        parse_type_spec_signature(blobs.get(row.signature as usize)?)?;
                    let mut resolver =
                        TypeResolver::new(data.types.clone()).with_token_init(row.token);
                    resolver.resolve(&type_spec_sig.base)?;
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
