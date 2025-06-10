//! `TypeRef` loader implementation

use crate::{
    metadata::loader::{LoaderContext, MetadataLoader},
    prelude::{TableId, TypeRefRaw},
    Result,
};

/// Loader for `TypeRef` metadata
pub(crate) struct TypeRefLoader;

impl MetadataLoader for TypeRefLoader {
    fn load(&self, context: &LoaderContext) -> Result<()> {
        if let (Some(header), Some(strings), Some(module)) =
            (context.meta, context.strings, context.module.get())
        {
            if let Some(table) = header.table::<TypeRefRaw>(TableId::TypeRef) {
                for row in table {
                    let new_entry = row.to_owned(
                        strings,
                        module,
                        context.module_ref,
                        context.assembly_ref,
                        context.types,
                    )?;

                    context.imports.add_type(&new_entry)?;
                    context.types.insert(new_entry);
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
