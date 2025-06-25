//! Common utilities for the write module.
//!
//! This module provides frequently used helper functions that are shared across
//! multiple components of the binary generation pipeline. It consolidates common
//! operations like layout searches, table size calculations, and alignment utilities
//! to reduce code duplication and ensure consistency throughout the write process.
//!
//! # Key Components
//!
//! - [`crate::cilassembly::write::utils::find_metadata_section`] - Metadata section location utility
//! - [`crate::cilassembly::write::utils::find_stream_layout`] - Stream layout search utility
//! - [`crate::cilassembly::write::utils::calculate_table_row_size`] - Universal table row size calculation
//! - [`crate::cilassembly::write::utils::align_to`] - General alignment utility
//! - [`crate::cilassembly::write::utils::align_to_4_bytes`] - ECMA-335 metadata alignment utility
//!
//! # Architecture
//!
//! The utilities are organized into several categories:
//!
//! ## Layout Search Utilities
//! Functions for locating specific components within file layouts:
//! - Metadata section identification within PE file layouts
//! - Stream layout search within metadata sections
//! - Error handling for missing components
//!
//! ## Table Size Calculations
//! Comprehensive table row size calculation supporting all ECMA-335 metadata tables:
//! - Dynamic row size calculation based on table schema
//! - Index size considerations for cross-table references
//! - Heap index size handling for string/blob/GUID references
//!
//! ## Alignment Utilities
//! Functions for maintaining proper data alignment:
//! - General alignment to arbitrary boundaries
//! - ECMA-335 specific 4-byte alignment for metadata heaps
//! - Consistent alignment behavior across the pipeline
//!
//! # Usage Examples
//!
//! ```rust,ignore
//! use crate::cilassembly::write::utils::{find_metadata_section, calculate_table_row_size, align_to_4_bytes};
//! use crate::cilassembly::write::planner::FileLayout;
//! use crate::metadata::tables::TableId;
//!
//! # let file_layout = FileLayout {
//! #     dos_header: crate::cilassembly::write::planner::FileRegion { offset: 0, size: 64 },
//! #     pe_headers: crate::cilassembly::write::planner::FileRegion { offset: 64, size: 100 },
//! #     section_table: crate::cilassembly::write::planner::FileRegion { offset: 164, size: 80 },
//! #     sections: vec![]
//! # };
//! # let table_info = std::sync::Arc::new(
//! #     crate::metadata::tables::TableInfo::new_test(&[], false, false, false)
//! # );
//!
//! // Find the metadata section in a file layout
//! let metadata_section = find_metadata_section(&file_layout)?;
//! println!("Metadata section: {}", metadata_section.name);
//!
//! // Calculate table row size
//! let row_size = calculate_table_row_size(TableId::TypeDef, &table_info);
//! println!("TypeDef row size: {} bytes", row_size);
//!
//! // Align data to 4-byte boundary
//! let aligned_size = align_to_4_bytes(123); // Returns 124
//! # Ok::<(), crate::Error>(())
//! ```
//!
//! # Thread Safety
//!
//! All utilities in this module are stateless functions that perform calculations
//! or searches without modifying shared state, making them inherently thread-safe.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::cilassembly::write::planner`] - Layout planning structures and algorithms
//! - [`crate::cilassembly::write::writers`] - Binary generation writers
//! - [`crate::metadata::tables`] - Table schema and row definitions
//! - [`crate::cilassembly::write::output`] - Output file management

use crate::{
    cilassembly::write::planner::{FileLayout, SectionFileLayout, StreamFileLayout},
    metadata::tables::{
        AssemblyOsRaw, AssemblyProcessorRaw, AssemblyRaw, AssemblyRefOsRaw,
        AssemblyRefProcessorRaw, AssemblyRefRaw, ClassLayoutRaw, ConstantRaw, CustomAttributeRaw,
        CustomDebugInformationRaw, DeclSecurityRaw, DocumentRaw, EncLogRaw, EncMapRaw, EventMapRaw,
        EventPtrRaw, EventRaw, ExportedTypeRaw, FieldLayoutRaw, FieldMarshalRaw, FieldPtrRaw,
        FieldRaw, FieldRvaRaw, FileRaw, GenericParamConstraintRaw, GenericParamRaw, ImplMapRaw,
        ImportScopeRaw, InterfaceImplRaw, LocalConstantRaw, LocalScopeRaw, LocalVariableRaw,
        ManifestResourceRaw, MemberRefRaw, MethodDebugInformationRaw, MethodDefRaw, MethodImplRaw,
        MethodPtrRaw, MethodSemanticsRaw, MethodSpecRaw, ModuleRaw, ModuleRefRaw, NestedClassRaw,
        ParamPtrRaw, ParamRaw, PropertyMapRaw, PropertyPtrRaw, PropertyRaw, StandAloneSigRaw,
        StateMachineMethodRaw, TableId, TableInfoRef, TableRow, TypeDefRaw, TypeRefRaw,
        TypeSpecRaw,
    },
    Error, Result,
};

/// Finds the metadata section in a file layout.
///
/// This is a commonly used operation across multiple components that need to
/// locate the section containing .NET metadata. Typically this is the .text
/// section in most .NET assemblies.
///
/// # Arguments
/// * `file_layout` - The [`crate::cilassembly::write::planner::FileLayout`] to search
///
/// # Returns
/// Returns a reference to the [`crate::cilassembly::write::planner::SectionFileLayout`] containing metadata.
///
/// # Errors
/// Returns [`crate::Error::WriteLayoutFailed`] if no metadata section is found in the layout.
pub fn find_metadata_section(file_layout: &FileLayout) -> Result<&SectionFileLayout> {
    file_layout
        .sections
        .iter()
        .find(|section| section.contains_metadata)
        .ok_or_else(|| Error::WriteLayoutFailed {
            message: "No metadata section found in file layout".to_string(),
        })
}

/// Finds a specific stream layout within a metadata section.
///
/// This is used throughout the write pipeline to locate specific metadata streams
/// like "#Strings", "#Blob", "#GUID", "#US", "#~", etc. within a metadata-containing section.
///
/// # Arguments
/// * `metadata_section` - The [`crate::cilassembly::write::planner::SectionFileLayout`] containing metadata streams
/// * `stream_name` - The name of the stream to locate (e.g., "#Strings", "#Blob")
///
/// # Returns
/// Returns a reference to the [`crate::cilassembly::write::planner::StreamFileLayout`] for the specified stream.
///
/// # Errors
/// Returns [`crate::Error::WriteLayoutFailed`] if the specified stream is not found in the section.
pub fn find_stream_layout<'a>(
    metadata_section: &'a SectionFileLayout,
    stream_name: &str,
) -> Result<&'a StreamFileLayout> {
    metadata_section
        .metadata_streams
        .iter()
        .find(|stream| stream.name == stream_name)
        .ok_or_else(|| Error::WriteLayoutFailed {
            message: format!("Stream '{}' not found in metadata section", stream_name),
        })
}

/// Calculates the row size for any table type using the table info.
///
/// This consolidates the large match statement that appears in multiple places
/// throughout the codebase for calculating metadata table row sizes. The calculation
/// takes into account the specific schema of each table type and the current
/// index sizes for cross-table and heap references.
///
/// # Arguments
/// * `table_id` - The [`crate::metadata::tables::TableId`] to calculate size for
/// * `table_info` - The [`crate::metadata::tables::TableInfoRef`] containing schema information
///
/// # Returns
/// Returns the row size in bytes for the specified table type.
///
/// # Details
/// Row sizes are calculated based on:
/// - Fixed-size fields (RIDs, flags, etc.)
/// - Variable-size index fields (depending on table row counts)
/// - Heap index fields (depending on heap sizes)
/// - Cross-table reference fields (depending on target table sizes)
pub fn calculate_table_row_size(table_id: TableId, table_info: &TableInfoRef) -> u32 {
    match table_id {
        TableId::Module => ModuleRaw::row_size(table_info),
        TableId::TypeRef => TypeRefRaw::row_size(table_info),
        TableId::TypeDef => TypeDefRaw::row_size(table_info),
        TableId::FieldPtr => FieldPtrRaw::row_size(table_info),
        TableId::Field => FieldRaw::row_size(table_info),
        TableId::MethodPtr => MethodPtrRaw::row_size(table_info),
        TableId::MethodDef => MethodDefRaw::row_size(table_info),
        TableId::ParamPtr => ParamPtrRaw::row_size(table_info),
        TableId::Param => ParamRaw::row_size(table_info),
        TableId::InterfaceImpl => InterfaceImplRaw::row_size(table_info),
        TableId::MemberRef => MemberRefRaw::row_size(table_info),
        TableId::Constant => ConstantRaw::row_size(table_info),
        TableId::CustomAttribute => CustomAttributeRaw::row_size(table_info),
        TableId::FieldMarshal => FieldMarshalRaw::row_size(table_info),
        TableId::DeclSecurity => DeclSecurityRaw::row_size(table_info),
        TableId::ClassLayout => ClassLayoutRaw::row_size(table_info),
        TableId::FieldLayout => FieldLayoutRaw::row_size(table_info),
        TableId::StandAloneSig => StandAloneSigRaw::row_size(table_info),
        TableId::EventMap => EventMapRaw::row_size(table_info),
        TableId::EventPtr => EventPtrRaw::row_size(table_info),
        TableId::Event => EventRaw::row_size(table_info),
        TableId::PropertyMap => PropertyMapRaw::row_size(table_info),
        TableId::PropertyPtr => PropertyPtrRaw::row_size(table_info),
        TableId::Property => PropertyRaw::row_size(table_info),
        TableId::MethodSemantics => MethodSemanticsRaw::row_size(table_info),
        TableId::MethodImpl => MethodImplRaw::row_size(table_info),
        TableId::ModuleRef => ModuleRefRaw::row_size(table_info),
        TableId::TypeSpec => TypeSpecRaw::row_size(table_info),
        TableId::ImplMap => ImplMapRaw::row_size(table_info),
        TableId::FieldRVA => FieldRvaRaw::row_size(table_info),
        TableId::EncLog => EncLogRaw::row_size(table_info),
        TableId::EncMap => EncMapRaw::row_size(table_info),
        TableId::Assembly => AssemblyRaw::row_size(table_info),
        TableId::AssemblyProcessor => AssemblyProcessorRaw::row_size(table_info),
        TableId::AssemblyOS => AssemblyOsRaw::row_size(table_info),
        TableId::AssemblyRef => AssemblyRefRaw::row_size(table_info),
        TableId::AssemblyRefProcessor => AssemblyRefProcessorRaw::row_size(table_info),
        TableId::AssemblyRefOS => AssemblyRefOsRaw::row_size(table_info),
        TableId::File => FileRaw::row_size(table_info),
        TableId::ExportedType => ExportedTypeRaw::row_size(table_info),
        TableId::ManifestResource => ManifestResourceRaw::row_size(table_info),
        TableId::NestedClass => NestedClassRaw::row_size(table_info),
        TableId::GenericParam => GenericParamRaw::row_size(table_info),
        TableId::MethodSpec => MethodSpecRaw::row_size(table_info),
        TableId::GenericParamConstraint => GenericParamConstraintRaw::row_size(table_info),
        TableId::Document => DocumentRaw::row_size(table_info),
        TableId::MethodDebugInformation => MethodDebugInformationRaw::row_size(table_info),
        TableId::LocalScope => LocalScopeRaw::row_size(table_info),
        TableId::LocalVariable => LocalVariableRaw::row_size(table_info),
        TableId::LocalConstant => LocalConstantRaw::row_size(table_info),
        TableId::ImportScope => ImportScopeRaw::row_size(table_info),
        TableId::StateMachineMethod => StateMachineMethodRaw::row_size(table_info),
        TableId::CustomDebugInformation => CustomDebugInformationRaw::row_size(table_info),
    }
}

/// Aligns a value to the next multiple of the given alignment.
///
/// This is used throughout the write module for heap and stream alignment.
/// The alignment must be a power of 2 for correct behavior.
///
/// # Arguments
/// * `value` - The value to align
/// * `alignment` - The alignment boundary (must be a power of 2)
///
/// # Returns
/// Returns the smallest value >= input that is a multiple of the alignment.
///
/// # Examples
/// ```ignore
/// # use crate::cilassembly::write::utils::align_to;
/// assert_eq!(align_to(5, 4), 8);
/// assert_eq!(align_to(8, 4), 8);
/// assert_eq!(align_to(0, 4), 0);
/// ```
pub fn align_to(value: u64, alignment: u64) -> u64 {
    (value + alignment - 1) & !(alignment - 1)
}

/// Aligns a value to the next 4-byte boundary.
///
/// Common case of [`crate::cilassembly::write::utils::align_to`] for metadata heap alignment
/// as required by ECMA-335 II.24.2.2. All metadata heaps must be aligned to 4-byte boundaries.
///
/// # Arguments
/// * `value` - The value to align to 4 bytes
///
/// # Returns
/// Returns the value rounded up to the next 4-byte boundary.
///
/// # Examples
/// ```ignore
/// # use crate::cilassembly::write::utils::align_to_4_bytes;
/// assert_eq!(align_to_4_bytes(1), 4);
/// assert_eq!(align_to_4_bytes(4), 4);
/// assert_eq!(align_to_4_bytes(5), 8);
/// ```
pub fn align_to_4_bytes(value: u64) -> u64 {
    align_to(value, 4)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cilassembly::write::planner::{FileRegion, StreamFileLayout};

    #[test]
    fn test_find_metadata_section() {
        let sections = vec![
            // Add a non-metadata section
            SectionFileLayout {
                name: ".rdata".to_string(),
                file_region: FileRegion {
                    offset: 0,
                    size: 100,
                },
                virtual_address: 0x1000,
                virtual_size: 100,
                characteristics: 0,
                contains_metadata: false,
                metadata_streams: Vec::new(),
            },
            // Add a metadata section
            SectionFileLayout {
                name: ".text".to_string(),
                file_region: FileRegion {
                    offset: 100,
                    size: 200,
                },
                virtual_address: 0x2000,
                virtual_size: 200,
                characteristics: 0,
                contains_metadata: true,
                metadata_streams: Vec::new(),
            },
        ];

        let file_layout = FileLayout {
            dos_header: FileRegion {
                offset: 0,
                size: 64,
            },
            pe_headers: FileRegion {
                offset: 64,
                size: 100,
            },
            section_table: FileRegion {
                offset: 164,
                size: 80,
            },
            sections,
        };

        let metadata_section = find_metadata_section(&file_layout).unwrap();
        assert_eq!(metadata_section.name, ".text");
        assert!(metadata_section.contains_metadata);
    }

    #[test]
    fn test_find_stream_layout() {
        let streams = vec![
            StreamFileLayout {
                name: "#Strings".to_string(),
                file_region: FileRegion {
                    offset: 0,
                    size: 100,
                },
                size: 100,
                has_additions: false,
            },
            StreamFileLayout {
                name: "#Blob".to_string(),
                file_region: FileRegion {
                    offset: 100,
                    size: 50,
                },
                size: 50,
                has_additions: false,
            },
        ];

        let metadata_section = SectionFileLayout {
            name: ".text".to_string(),
            file_region: FileRegion {
                offset: 0,
                size: 300,
            },
            virtual_address: 0x2000,
            virtual_size: 300,
            characteristics: 0,
            contains_metadata: true,
            metadata_streams: streams,
        };

        let strings_stream = find_stream_layout(&metadata_section, "#Strings").unwrap();
        assert_eq!(strings_stream.name, "#Strings");
        assert_eq!(strings_stream.size, 100);

        let blob_stream = find_stream_layout(&metadata_section, "#Blob").unwrap();
        assert_eq!(blob_stream.name, "#Blob");
        assert_eq!(blob_stream.size, 50);

        // Test error case
        assert!(find_stream_layout(&metadata_section, "#NonExistent").is_err());
    }

    #[test]
    fn test_alignment_functions() {
        assert_eq!(align_to(0, 4), 0);
        assert_eq!(align_to(1, 4), 4);
        assert_eq!(align_to(4, 4), 4);
        assert_eq!(align_to(5, 4), 8);

        assert_eq!(align_to_4_bytes(0), 0);
        assert_eq!(align_to_4_bytes(1), 4);
        assert_eq!(align_to_4_bytes(3), 4);
        assert_eq!(align_to_4_bytes(4), 4);
        assert_eq!(align_to_4_bytes(5), 8);
    }

    #[test]
    fn test_calculate_table_row_size() {
        // Test with minimal table info
        let table_info = std::sync::Arc::new(crate::metadata::tables::TableInfo::new_test(
            &[],
            false,
            false,
            false,
        ));

        // Test a few different table types
        let module_size = calculate_table_row_size(TableId::Module, &table_info);
        assert!(
            module_size > 0,
            "Module table should have positive row size"
        );

        let typedef_size = calculate_table_row_size(TableId::TypeDef, &table_info);
        assert!(
            typedef_size > 0,
            "TypeDef table should have positive row size"
        );

        let field_size = calculate_table_row_size(TableId::Field, &table_info);
        assert!(field_size > 0, "Field table should have positive row size");
    }
}
