//! `DeclSecurity` loader implementation

use crate::{
    metadata::{
        loader::{LoaderContext, MetadataLoader},
        tables::DeclSecurityRaw,
    },
    prelude::TableId,
    Result,
};

/// Loader for `DeclSecurity` metadata
pub(crate) struct DeclSecurityLoader;

impl MetadataLoader for DeclSecurityLoader {
    fn load(&self, context: &LoaderContext) -> Result<()> {
        if let (Some(header), Some(blob)) = (context.meta, context.blobs) {
            if let Some(table) = header.table::<DeclSecurityRaw>(TableId::DeclSecurity) {
                table.par_iter().try_for_each(|row| {
                    let owned = row.to_owned(|coded_index| context.get_ref(coded_index), blob)?;
                    owned.apply()?;

                    context.decl_security.insert(row.token, owned);
                    Ok(())
                })?;
            }
        }
        Ok(())
    }

    fn table_id(&self) -> TableId {
        TableId::DeclSecurity
    }

    fn dependencies(&self) -> &'static [TableId] {
        &[TableId::TypeDef, TableId::MethodDef, TableId::Assembly]
    }
}
