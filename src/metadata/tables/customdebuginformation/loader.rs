//! `CustomDebugInformation` table loader for efficient metadata processing
//!
//! This module provides the [`CustomDebugInformationLoader`] implementation that handles
//! loading and processing `CustomDebugInformation` table entries from Portable PDB metadata.
//! The loader follows the established `MetadataLoader` pattern for consistent parallel
//! processing and efficient memory utilization.

use crate::{
    metadata::{
        loader::{LoaderContext, MetadataLoader},
        tables::{CustomDebugInformationRaw, TableId},
    },
    Result,
};

/// Metadata loader for `CustomDebugInformation` table entries
///
/// This loader processes `CustomDebugInformation` table data to build efficient lookup
/// structures for custom debugging information access. The loader handles:
///
/// - Parallel processing of table rows for optimal performance
/// - Building token-based lookup maps for fast custom debug info resolution
/// - Creating ordered lists for sequential access patterns
/// - Memory-efficient storage using reference counting
///
/// # Custom Debug Information Context
///
/// The `CustomDebugInformation` table provides extensibility for debugging scenarios
/// beyond the standard Portable PDB tables. It allows compilers and tools to store
/// implementation-specific debugging metadata such as:
///
/// - State machine variable hoisting information for async/await debugging
/// - Dynamic type tracking for C# dynamic variables
/// - Edit-and-continue mapping information for debugging sessions
/// - Embedded source code and source link configuration
/// - Language-specific namespace and scope information
///
/// # Integration
///
/// This loader integrates with the broader metadata loading infrastructure:
/// - Uses the [`LoaderContext`] for coordinated loading across all tables
/// - Implements [`MetadataLoader`] trait for consistent processing patterns
/// - Provides thread-safe data structures for concurrent debugger access
/// - Resolves GUID and blob heap references during loading
///
/// # Performance Considerations
///
/// Custom debug information can be quite large (especially embedded source),
/// so the loader is designed for efficiency:
/// - Parallel processing of table entries
/// - Lazy resolution of heap data only when needed
/// - Memory-efficient storage of resolved data
///
/// # References
///
/// - [Portable PDB Format - CustomDebugInformation Table](https://github.com/dotnet/corefx/blob/master/src/System.Reflection.Metadata/specs/PortablePdb-Metadata.md#customdebuginformation-table-0x37)
/// - [Custom Debug Information Records](https://github.com/dotnet/corefx/blob/master/src/System.Reflection.Metadata/specs/PortablePdb-Metadata.md#language-specific-custom-debug-information-records)
pub struct CustomDebugInformationLoader;

impl MetadataLoader for CustomDebugInformationLoader {
    fn load(&self, context: &LoaderContext) -> Result<()> {
        if let (Some(header), Some(guids), Some(blobs)) =
            (context.meta, context.guids, context.blobs)
        {
            if let Some(table) =
                header.table::<CustomDebugInformationRaw>(TableId::CustomDebugInformation)
            {
                table.par_iter().try_for_each(|row| {
                    let custom_debug_info =
                        row.to_owned(|coded_index| context.get_ref(coded_index), guids, blobs)?;
                    context
                        .custom_debug_information
                        .insert(custom_debug_info.token, custom_debug_info);
                    Ok(())
                })?;
            }
        }
        Ok(())
    }

    fn table_id(&self) -> TableId {
        TableId::CustomDebugInformation
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
            TableId::Document,
            TableId::LocalScope,
            TableId::LocalVariable,
            TableId::LocalConstant,
            TableId::ImportScope,
        ]
    }
}
