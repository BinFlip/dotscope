//! CustomAttribute table loader implementation.
//!
//! This module provides the [`crate::metadata::tables::customattribute::loader::CustomAttributeLoader`]
//! implementation for loading CustomAttribute metadata from the ECMA-335 CustomAttribute table (0x0C).
//! The loader processes custom attribute instances that decorate metadata elements with additional
//! compile-time information, integrating this data with existing metadata entries.
//!
//! # Table Structure
//!
//! The CustomAttribute table contains zero or more rows that associate attributes with metadata elements:
//! - **Parent**: Coded index referencing the metadata element decorated with the attribute
//! - **Type**: Coded index referencing the attribute constructor (MethodDef or MemberRef)
//! - **Value**: Blob heap reference containing the serialized attribute arguments
//!
//! # Reference
//! - [ECMA-335 II.22.10](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - CustomAttribute table specification

use crate::{
    metadata::{
        loader::{LoaderContext, MetadataLoader},
        tables::CustomAttributeRaw,
    },
    prelude::TableId,
    Result,
};

/// Loader for the CustomAttribute metadata table
///
/// Implements [`crate::metadata::loader::MetadataLoader`] to process the CustomAttribute table (0x0C)
/// which contains custom attribute instances applied to various metadata elements. Custom attributes
/// provide extensible metadata decoration throughout .NET assemblies.
///
pub(crate) struct CustomAttributeLoader;

impl MetadataLoader for CustomAttributeLoader {
    /// Load CustomAttribute metadata and associate with target elements
    ///
    /// Processes all rows in the CustomAttribute table, resolving references to target metadata
    /// elements and attribute constructors, as well as deserializing attribute argument data.
    ///
    /// # Arguments
    ///
    /// * `context` - Loader context containing metadata tables, heap references, and storage collections
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on successful completion, or [`crate::Error`] if any step fails.
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

    /// Returns the table identifier for CustomAttribute
    ///
    /// Provides the [`TableId::CustomAttribute`] constant used to identify this table
    /// type within the metadata loading framework.
    fn table_id(&self) -> TableId {
        TableId::CustomAttribute
    }

    /// Returns the table dependencies for CustomAttribute loading
    ///
    /// Specifies the extensive list of tables that CustomAttribute loading depends on.
    /// Custom attributes can be applied to almost any metadata element, requiring
    /// that all potential target tables are loaded before attribute associations
    /// are established.
    ///
    /// Dependencies include type system tables, member tables, module tables,
    /// assembly tables, security tables, generic tables, resource tables, and
    /// signature tables to cover all possible attribute targets.
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
