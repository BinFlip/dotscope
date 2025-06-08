//! `DeclSecurity` loader implementation

use crate::{
    metadata::{
        loader::{data::CilObjectData, MetadataLoader},
        streams::DeclSecurityRaw,
    },
    prelude::TableId,
    Result,
};

/// Loader for `DeclSecurity` metadata
pub(crate) struct DeclSecurityLoader;

impl MetadataLoader for DeclSecurityLoader {
    fn load(&self, data: &CilObjectData) -> Result<()> {
        if let (Some(header), Some(blob)) = (data.meta.as_ref(), data.blobs.as_ref()) {
            if let Some(table) = header.table::<DeclSecurityRaw>(TableId::DeclSecurity) {
                table.par_iter().try_for_each(|row| {
                    row.apply(blob, &data.types, &data.methods, &data.assembly)?;

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
