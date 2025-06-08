//! `AssemblyRef` table loader implementation.

use crate::{
    metadata::{
        loader::{data::CilObjectData, MetadataLoader},
        streams::{tables::assemblyref::AssemblyRefRaw, TableId},
    },
    Result,
};

/// Loader for the `AssemblyRef` metadata table.
pub(crate) struct AssemblyRefLoader;

impl MetadataLoader for AssemblyRefLoader {
    fn load(&self, data: &CilObjectData) -> Result<()> {
        if let (Some(header), Some(blob), Some(strings)) = (
            data.meta.as_ref(),
            data.blobs.as_ref(),
            data.strings.as_ref(),
        ) {
            if let Some(table) = header.table::<AssemblyRefRaw>(TableId::AssemblyRef) {
                table.par_iter().try_for_each(|row| {
                    let res = row.to_owned(strings, blob)?;
                    data.refs_assembly.insert(row.token, res);

                    Ok(())
                })?;
            }
        }
        Ok(())
    }

    fn table_id(&self) -> TableId {
        TableId::AssemblyRef
    }

    fn dependencies(&self) -> &'static [TableId] {
        &[]
    }
}
