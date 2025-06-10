//! `CustomAttribute` loader implementation

use crate::{
    metadata::loader::{LoaderContext, MetadataLoader},
    prelude::TableId,
    Result,
};

/// Loader for `CustomAttribute` metadata
pub(crate) struct CustomAttributeLoader;

impl MetadataLoader for CustomAttributeLoader {
    fn load(&self, _context: &LoaderContext) -> Result<()> {
        // if let Some(header) = data.meta {
        //     if let Some(table) = header.table::<CustomAttributeRaw>(TableId::CustomAttribute) {
        //         table.par_iter().try_for_each(|row| {
        //             row.apply(&data.types, data.refs_member, data.methods)?;
        //             Ok(())
        //         })?;
        //     }
        // }
        Ok(())
    }

    fn table_id(&self) -> TableId {
        TableId::CustomAttribute
    }

    fn dependencies(&self) -> &'static [TableId] {
        &[
            TableId::MethodDef,
            TableId::Field,
            TableId::TypeRef,
            TableId::TypeDef,
            TableId::Param,
            TableId::InterfaceImpl,
            TableId::MemberRef,
            TableId::Module,
            TableId::DeclSecurity,
            TableId::Property,
            TableId::Event,
            TableId::StandAloneSig,
            TableId::ModuleRef,
            TableId::TypeSpec,
            TableId::Assembly,
            TableId::AssemblyRef,
            TableId::File,
            TableId::ExportedType,
            TableId::ManifestResource,
            TableId::GenericParam,
            TableId::GenericParamConstraint,
            TableId::MethodSpec,
        ]
    }
}
