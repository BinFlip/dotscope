//! `FieldRva` loader implementation

use crate::{
    metadata::{
        loader::{LoaderContext, MetadataLoader},
        tables::FieldRvaRaw,
    },
    prelude::TableId,
    Result,
};

/// Loader for `FieldRva` metadata
pub(crate) struct FieldRvaLoader;

impl MetadataLoader for FieldRvaLoader {
    fn load(&self, context: &LoaderContext) -> Result<()> {
        if let Some(header) = context.meta {
            if let Some(table) = header.table::<FieldRvaRaw>(TableId::FieldRVA) {
                table.par_iter().try_for_each(|row| {
                    let owned = row.to_owned(&context.field)?;
                    owned.apply()?;

                    context.field_rva.insert(row.token, owned);
                    Ok(())
                })?;
            }
        }
        Ok(())
    }

    fn table_id(&self) -> TableId {
        TableId::FieldRVA
    }

    fn dependencies(&self) -> &'static [TableId] {
        &[TableId::Field]
    }
}
