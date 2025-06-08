//! `ExportedType` loader implementation

use crate::{
    metadata::{
        loader::{data::CilObjectData, MetadataLoader},
        streams::ExportedTypeRaw,
    },
    prelude::TableId,
    Result,
};

/// Loader for `ExportedType` metadata
pub(crate) struct ExportedTypeLoader;

impl MetadataLoader for ExportedTypeLoader {
    fn load(&self, data: &CilObjectData) -> Result<()> {
        if let (Some(header), Some(strings)) = (&data.meta, &data.strings) {
            if let Some(table) = header.table::<ExportedTypeRaw>(TableId::ExportedType) {
                for row in table {
                    let exported_type =
                        row.to_owned(strings, &data.refs_file, &data.refs_assembly, &data.exports)?;
                    data.exports.insert(row.token, exported_type)?;
                }
            }
        }
        Ok(())
    }

    fn table_id(&self) -> TableId {
        TableId::ExportedType
    }

    fn dependencies(&self) -> &'static [TableId] {
        &[TableId::File, TableId::AssemblyRef]
    }
}
