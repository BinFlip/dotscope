//! `TypeRef` loader implementation

use crate::{
    metadata::loader::{data::CilObjectData, MetadataLoader},
    prelude::{TableId, TypeRefRaw},
    Result,
};

/// Loader for `TypeRef` metadata
pub(crate) struct TypeRefLoader;

impl MetadataLoader for TypeRefLoader {
    fn load(&self, data: &CilObjectData) -> Result<()> {
        if let (Some(header), Some(strings)) = (&data.meta, &data.strings) {
            let Some(module) = data.module.get() else {
                return Err(malformed_error!(
                    "Module is missing, and required to load TypeRefs"
                ));
            };

            if let Some(table) = header.table::<TypeRefRaw>(TableId::TypeRef) {
                for row in table {
                    let new_entry = row.to_owned(
                        strings,
                        module,
                        &data.refs_module,
                        &data.refs_assembly,
                        &data.types,
                    )?;
                    data.imports.add_type(&new_entry)?;
                    data.types.insert(new_entry);
                }
            }
        }

        Ok(())
    }

    fn table_id(&self) -> TableId {
        TableId::TypeRef
    }

    fn dependencies(&self) -> &'static [TableId] {
        &[TableId::ModuleRef, TableId::AssemblyRef]
    }
}
