//! `PropertyPtr` loader implementation
use crate::{
    metadata::{
        loader::context::LoaderContext,
        streams::{PropertyPtrRaw, TableId},
    },
    Result,
};

use super::MetadataLoader;

/// Loader for the PropertyPtr table.
pub struct PropertyPtrLoader;

impl MetadataLoader for PropertyPtrLoader {
    fn load(&self, context: &LoaderContext) -> Result<()> {
        if let Some(header) = context.meta {
            if let Some(table) = header.table::<PropertyPtrRaw>(TableId::PropertyPtr) {
                for row in table {
                    let owned = row.to_owned()?;
                    context.property_ptr.insert(row.token, owned);
                }
            }
        }
        Ok(())
    }

    fn table_id(&self) -> TableId {
        TableId::PropertyPtr
    }

    fn dependencies(&self) -> &'static [TableId] {
        &[]
    }
}
