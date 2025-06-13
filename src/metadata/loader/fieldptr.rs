//! `FieldPtr` loader implementation
//!
use crate::{
    metadata::{
        loader::context::LoaderContext,
        streams::{FieldPtrRaw, TableId},
    },
    Result,
};

use super::MetadataLoader;

/// Loader for the FieldPtr table.
pub struct FieldPtrLoader;

impl MetadataLoader for FieldPtrLoader {
    fn load(&self, context: &LoaderContext) -> Result<()> {
        if let Some(header) = context.meta {
            if let Some(table) = header.table::<FieldPtrRaw>(TableId::FieldPtr) {
                for row in table {
                    let owned = row.to_owned()?;
                    context.field_ptr.insert(row.token, owned);
                }
            }
        }
        Ok(())
    }

    fn table_id(&self) -> TableId {
        TableId::FieldPtr
    }

    fn dependencies(&self) -> &'static [TableId] {
        &[]
    }
}
