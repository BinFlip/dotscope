//! `CustomAttribute` loader implementation

use crate::{
    metadata::{
        loader::{LoaderContext, MetadataLoader},
        streams::CustomAttributeRaw,
    },
    prelude::TableId,
    Result,
};

/// Loader for `CustomAttribute` metadata
pub(crate) struct CustomAttributeLoader;

impl MetadataLoader for CustomAttributeLoader {
    fn load(&self, context: &LoaderContext) -> Result<()> {
        if let (Some(header), Some(blob)) = (context.meta, context.blobs) {
            if let Some(table) = header.table::<CustomAttributeRaw>(TableId::CustomAttribute) {
                table.par_iter().try_for_each(|row| {
                    let owned = row.to_owned(|coded_index| context.get_ref(coded_index), blob)?;
                    owned.apply()?;

                    context.custom_attribute.insert(row.token, owned);
                    Ok(())
                })?;
            }
        }
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
