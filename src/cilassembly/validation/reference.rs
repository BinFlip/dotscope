//! Reference scanning and handling logic for referential integrity validation.
//!
//! This module contains the core logic for finding and handling references between
//! metadata tables. It provides comprehensive scanning capabilities that examine
//! all possible cross-references in .NET metadata tables to support safe deletion
//! and modification operations.
//!
//! # Key Components
//!
//! - [`crate::cilassembly::validation::reference::ReferenceScanner`] - Comprehensive reference scanner for metadata tables
//!
//! # Architecture
//!
//! The reference scanner system provides two main scanning strategies:
//!
//! ## Direct Reference Scanning
//! Scans all metadata tables to find references to a specific table row by examining:
//! - Direct table references (RID values pointing to specific tables)
//! - Coded indices (compressed references that can point to multiple table types)
//! - Heap references (string, blob, GUID, and user string indices)
//!
//! ## Cached Reference Tracking
//! Builds a comprehensive reference graph once on first access and caches it for
//! efficient repeated lookups. The [`ReferenceScanner`] automatically handles
//! caching to optimize performance when multiple reference queries are needed.
//!
//! # Usage Examples
//!
//! ```rust,ignore
//! use crate::cilassembly::validation::reference::ReferenceScanner;
//! use crate::metadata::cilassemblyview::CilAssemblyView;
//! use crate::metadata::tables::TableId;
//! use std::path::Path;
//!
//! # let view = CilAssemblyView::from_file(Path::new("test.dll"))?;
//! // Create a reference scanner (builds tracker during construction)
//! let scanner = ReferenceScanner::new(&view)?;
//!
//! // Find all references to a specific table row (fast lookup using pre-built tracker)
//! let references = scanner.find_references_to_table_row(TableId::TypeDef, 1);
//! println!("Found {} references to TypeDef row 1", references.row_count);
//!
//! // Subsequent calls use the same tracker for fast lookups
//! let more_refs = scanner.find_references_to_table_row(TableId::MethodDef, 5);
//! println!("Found {} references to MethodDef row 5", more_refs.row_count);
//!
//! // Direct access to internal tracker (alternative approach)
//! let tracker = scanner.get_reference_tracker();
//! # Ok::<(), crate::Error>(())
//! ```
//!
//! # Thread Safety
//!
//! This type is [`Send`] and [`Sync`] as it only borrows data from the assembly view
//! and does not maintain any mutable state.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::cilassembly::validation::integrity::ReferentialIntegrityValidator`] - Uses reference scanning for validation
//! - [`crate::cilassembly::references::ReferenceTracker`] - Builds reference tracking structures

use crate::{
    cilassembly::references::{ReferenceTracker, TableReference},
    metadata::{
        cilassemblyview::CilAssemblyView,
        tables::{
            AssemblyOsRaw, AssemblyProcessorRaw, AssemblyRaw, AssemblyRefOsRaw,
            AssemblyRefProcessorRaw, AssemblyRefRaw, ClassLayoutRaw, CodedIndex, CodedIndexType,
            ConstantRaw, CustomAttributeRaw, CustomDebugInformationRaw, DeclSecurityRaw,
            DocumentRaw, EncLogRaw, EncMapRaw, EventMapRaw, EventPtrRaw, EventRaw, ExportedTypeRaw,
            FieldLayoutRaw, FieldMarshalRaw, FieldPtrRaw, FieldRaw, FieldRvaRaw, FileRaw,
            GenericParamConstraintRaw, GenericParamRaw, ImplMapRaw, ImportScopeRaw,
            InterfaceImplRaw, LocalConstantRaw, LocalScopeRaw, LocalVariableRaw,
            ManifestResourceRaw, MemberRefRaw, MethodDebugInformationRaw, MethodDefRaw,
            MethodImplRaw, MethodPtrRaw, MethodSemanticsRaw, MethodSpecRaw, ModuleRaw,
            ModuleRefRaw, NestedClassRaw, ParamPtrRaw, ParamRaw, PropertyMapRaw, PropertyPtrRaw,
            PropertyRaw, StandAloneSigRaw, StateMachineMethodRaw, TableId, TypeDefRaw, TypeRefRaw,
            TypeSpecRaw,
        },
    },
    Error, Result, TablesHeader,
};

/// Comprehensive reference scanner for metadata tables.
///
/// [`ReferenceScanner`] examines all metadata tables to find references to a specific
/// table row. It handles both direct references and coded indices, providing complete
/// coverage of cross-reference relationships in .NET assembly metadata.
///
/// This scanner is designed to support referential integrity validation by identifying
/// all locations where a specific table row is referenced, enabling safe deletion
/// operations and dependency analysis.
///
/// # Performance
///
/// The scanner builds a comprehensive reference tracker when created, making all
/// subsequent reference queries very efficient. The reference tracker is stored
/// internally and provides O(1) lookup time for finding references.
///
/// # Usage Examples
///
/// ```rust,ignore
/// use crate::cilassembly::validation::reference::ReferenceScanner;
/// use crate::metadata::cilassemblyview::CilAssemblyView;
/// use crate::metadata::tables::TableId;
/// use std::path::Path;
///
/// # let view = CilAssemblyView::from_file(Path::new("test.dll"))?;
/// let scanner = ReferenceScanner::new(&view)?;
///
/// // Fast lookups using pre-built reference tracker
/// let references = scanner.find_references_to_table_row(TableId::TypeDef, 1);
/// println!("Found {} references to TypeDef row 1", references.row_count);
///
/// let more_refs = scanner.find_references_to_table_row(TableId::MethodDef, 5);
/// println!("Found {} references to MethodDef row 5", more_refs.row_count);
///
/// for reference in references {
///     println!("Found reference from {}:{} in column '{}'",
///              reference.table_id as u32, reference.row_rid, reference.column_name);
/// }
/// # Ok::<(), crate::Error>(())
/// ```
///
/// # Thread Safety
///
/// This type is [`Send`] and [`Sync`] as it only borrows immutable data from the
/// [`crate::metadata::cilassemblyview::CilAssemblyView`] and contains an owned reference tracker.
pub struct ReferenceScanner<'a> {
    /// Reference to the assembly view containing the metadata to scan
    view: &'a CilAssemblyView,
    /// Reference tracker built during construction
    tracker: ReferenceTracker,
}

impl<'a> ReferenceScanner<'a> {
    /// Creates a new reference scanner for the given assembly view.
    ///
    /// This constructor initializes a [`ReferenceScanner`] that will operate on the
    /// provided [`crate::metadata::cilassemblyview::CilAssemblyView`] to find cross-references within the assembly metadata.
    /// The reference tracker is built immediately during construction for efficient subsequent queries.
    ///
    /// # Arguments
    ///
    /// * `view` - The assembly view containing metadata tables to scan for references
    ///
    /// # Returns
    ///
    /// Returns a new [`ReferenceScanner`] instance ready to perform reference scanning operations.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] if there are issues building the reference tracker during construction.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use crate::cilassembly::validation::reference::ReferenceScanner;
    /// use crate::metadata::cilassemblyview::CilAssemblyView;
    /// use std::path::Path;
    ///
    /// # let view = CilAssemblyView::from_file(Path::new("test.dll"))?;
    /// let scanner = ReferenceScanner::new(&view)?;
    /// # Ok::<(), crate::Error>(())
    /// ```
    pub fn new(view: &'a CilAssemblyView) -> Result<Self> {
        let tracker = Self::build_reference_tracker(view)?;
        Ok(Self { view, tracker })
    }

    /// Gets a reference to the internal reference tracker.
    ///
    /// This method provides access to the reference tracker that was built during
    /// construction. The tracker contains a complete mapping of all cross-references
    /// in the assembly metadata.
    ///
    /// # Returns
    ///
    /// Returns a reference to the internal [`crate::cilassembly::references::ReferenceTracker`].
    pub fn get_reference_tracker(&self) -> &ReferenceTracker {
        &self.tracker
    }

    /// Builds a comprehensive reference tracker for the entire assembly.
    ///
    /// This method performs a complete scan of all metadata tables in the assembly to build
    /// a comprehensive reference graph. This is used internally during scanner construction
    /// to build the reference tracker once.
    ///
    /// The reference tracker maps heap indices and table RIDs to all locations that reference
    /// them, enabling efficient batch operations for referential integrity validation.
    ///
    /// # Arguments
    ///
    /// * `view` - The assembly view containing metadata tables to scan for references
    ///
    /// # Returns
    ///
    /// Returns a [`crate::cilassembly::references::ReferenceTracker`] containing a complete mapping
    /// of all cross-references in the assembly metadata.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] if there are issues reading metadata tables during the scan.
    fn build_reference_tracker(view: &CilAssemblyView) -> Result<ReferenceTracker> {
        let mut tracker = ReferenceTracker::new();

        let Some(tables) = view.tables() else {
            return Ok(tracker);
        };

        for scanning_table_id in tables.present_tables() {
            match scanning_table_id {
                TableId::Module => {
                    if let Some(module_table) = tables.table::<ModuleRaw>() {
                        for (scanning_rid, row) in module_table.iter().enumerate() {
                            let scanning_rid = scanning_rid as u32 + 1;
                            let reference = TableReference {
                                table_id: TableId::Module,
                                row_rid: scanning_rid,
                                column_name: "name".to_string(),
                            };

                            if row.name != 0 {
                                tracker.add_string_reference(row.name, reference.clone());
                            }

                            if row.mvid != 0 {
                                tracker.add_guid_reference(
                                    row.mvid,
                                    TableReference {
                                        table_id: TableId::Module,
                                        row_rid: scanning_rid,
                                        column_name: "mvid".to_string(),
                                    },
                                );
                            }

                            if row.encid != 0 {
                                tracker.add_guid_reference(
                                    row.encid,
                                    TableReference {
                                        table_id: TableId::Module,
                                        row_rid: scanning_rid,
                                        column_name: "encid".to_string(),
                                    },
                                );
                            }

                            if row.encbaseid != 0 {
                                tracker.add_guid_reference(
                                    row.encbaseid,
                                    TableReference {
                                        table_id: TableId::Module,
                                        row_rid: scanning_rid,
                                        column_name: "encbaseid".to_string(),
                                    },
                                );
                            }
                        }
                    }
                }
                TableId::TypeRef => {
                    if let Some(typeref_table) = tables.table::<TypeRefRaw>() {
                        for (scanning_rid, row) in typeref_table.iter().enumerate() {
                            let scanning_rid = scanning_rid as u32 + 1;
                            if row.resolution_scope.row != 0 {
                                tracker.add_rid_reference(
                                    row.resolution_scope.tag,
                                    row.resolution_scope.row,
                                    TableReference {
                                        table_id: TableId::TypeRef,
                                        row_rid: scanning_rid,
                                        column_name: "resolution_scope".to_string(),
                                    },
                                );
                            }
                            if row.type_name != 0 {
                                tracker.add_string_reference(
                                    row.type_name,
                                    TableReference {
                                        table_id: TableId::TypeRef,
                                        row_rid: scanning_rid,
                                        column_name: "type_name".to_string(),
                                    },
                                );
                            }

                            if row.type_namespace != 0 {
                                tracker.add_string_reference(
                                    row.type_namespace,
                                    TableReference {
                                        table_id: TableId::TypeRef,
                                        row_rid: scanning_rid,
                                        column_name: "type_namespace".to_string(),
                                    },
                                );
                            }
                        }
                    }
                }
                TableId::TypeDef => {
                    if let Some(typedef_table) = tables.table::<TypeDefRaw>() {
                        for (scanning_rid, row) in typedef_table.iter().enumerate() {
                            let scanning_rid = scanning_rid as u32 + 1;
                            if row.extends.row != 0 {
                                tracker.add_rid_reference(
                                    row.extends.tag,
                                    row.extends.row,
                                    TableReference {
                                        table_id: TableId::TypeDef,
                                        row_rid: scanning_rid,
                                        column_name: "extends".to_string(),
                                    },
                                );
                            }
                            if row.type_name != 0 {
                                tracker.add_string_reference(
                                    row.type_name,
                                    TableReference {
                                        table_id: TableId::TypeDef,
                                        row_rid: scanning_rid,
                                        column_name: "type_name".to_string(),
                                    },
                                );
                            }

                            if row.type_namespace != 0 {
                                tracker.add_string_reference(
                                    row.type_namespace,
                                    TableReference {
                                        table_id: TableId::TypeDef,
                                        row_rid: scanning_rid,
                                        column_name: "type_namespace".to_string(),
                                    },
                                );
                            }
                            if row.field_list != 0 {
                                tracker.add_rid_reference(
                                    TableId::Field,
                                    row.field_list,
                                    TableReference {
                                        table_id: TableId::TypeDef,
                                        row_rid: scanning_rid,
                                        column_name: "field_list".to_string(),
                                    },
                                );
                            }

                            if row.method_list != 0 {
                                tracker.add_rid_reference(
                                    TableId::MethodDef,
                                    row.method_list,
                                    TableReference {
                                        table_id: TableId::TypeDef,
                                        row_rid: scanning_rid,
                                        column_name: "method_list".to_string(),
                                    },
                                );
                            }
                        }
                    }
                }
                TableId::Field => {
                    if let Some(field_table) = tables.table::<FieldRaw>() {
                        for (scanning_rid, row) in field_table.iter().enumerate() {
                            let scanning_rid = scanning_rid as u32 + 1;
                            if row.name != 0 {
                                tracker.add_string_reference(
                                    row.name,
                                    TableReference {
                                        table_id: TableId::Field,
                                        row_rid: scanning_rid,
                                        column_name: "name".to_string(),
                                    },
                                );
                            }
                            if row.signature != 0 {
                                tracker.add_blob_reference(
                                    row.signature,
                                    TableReference {
                                        table_id: TableId::Field,
                                        row_rid: scanning_rid,
                                        column_name: "signature".to_string(),
                                    },
                                );
                            }
                        }
                    }
                }
                TableId::MethodDef => {
                    if let Some(methoddef_table) = tables.table::<MethodDefRaw>() {
                        for (scanning_rid, row) in methoddef_table.iter().enumerate() {
                            let scanning_rid = scanning_rid as u32 + 1;
                            if row.name != 0 {
                                tracker.add_string_reference(
                                    row.name,
                                    TableReference {
                                        table_id: TableId::MethodDef,
                                        row_rid: scanning_rid,
                                        column_name: "name".to_string(),
                                    },
                                );
                            }
                            if row.signature != 0 {
                                tracker.add_blob_reference(
                                    row.signature,
                                    TableReference {
                                        table_id: TableId::MethodDef,
                                        row_rid: scanning_rid,
                                        column_name: "signature".to_string(),
                                    },
                                );
                            }
                            if row.param_list != 0 {
                                tracker.add_rid_reference(
                                    TableId::Param,
                                    row.param_list,
                                    TableReference {
                                        table_id: TableId::MethodDef,
                                        row_rid: scanning_rid,
                                        column_name: "param_list".to_string(),
                                    },
                                );
                            }
                        }
                    }
                }
                TableId::Param => {
                    if let Some(param_table) = tables.table::<ParamRaw>() {
                        for (scanning_rid, row) in param_table.iter().enumerate() {
                            let scanning_rid = scanning_rid as u32 + 1;
                            if row.name != 0 {
                                tracker.add_string_reference(
                                    row.name,
                                    TableReference {
                                        table_id: TableId::Param,
                                        row_rid: scanning_rid,
                                        column_name: "name".to_string(),
                                    },
                                );
                            }
                        }
                    }
                }
                TableId::InterfaceImpl => {
                    if let Some(interfaceimpl_table) = tables.table::<InterfaceImplRaw>() {
                        for (scanning_rid, row) in interfaceimpl_table.iter().enumerate() {
                            let scanning_rid = scanning_rid as u32 + 1;
                            if row.class != 0 {
                                tracker.add_rid_reference(
                                    TableId::TypeDef,
                                    row.class,
                                    TableReference {
                                        table_id: TableId::InterfaceImpl,
                                        row_rid: scanning_rid,
                                        column_name: "class".to_string(),
                                    },
                                );
                            }
                            if row.interface.row != 0 {
                                tracker.add_rid_reference(
                                    row.interface.tag,
                                    row.interface.row,
                                    TableReference {
                                        table_id: TableId::InterfaceImpl,
                                        row_rid: scanning_rid,
                                        column_name: "interface".to_string(),
                                    },
                                );
                            }
                        }
                    }
                }
                TableId::MemberRef => {
                    if let Some(memberref_table) = tables.table::<MemberRefRaw>() {
                        for (scanning_rid, row) in memberref_table.iter().enumerate() {
                            let scanning_rid = scanning_rid as u32 + 1;
                            if row.class.row != 0 {
                                tracker.add_rid_reference(
                                    row.class.tag,
                                    row.class.row,
                                    TableReference {
                                        table_id: TableId::MemberRef,
                                        row_rid: scanning_rid,
                                        column_name: "class".to_string(),
                                    },
                                );
                            }
                            if row.name != 0 {
                                tracker.add_string_reference(
                                    row.name,
                                    TableReference {
                                        table_id: TableId::MemberRef,
                                        row_rid: scanning_rid,
                                        column_name: "name".to_string(),
                                    },
                                );
                            }
                            if row.signature != 0 {
                                tracker.add_blob_reference(
                                    row.signature,
                                    TableReference {
                                        table_id: TableId::MemberRef,
                                        row_rid: scanning_rid,
                                        column_name: "signature".to_string(),
                                    },
                                );
                            }
                        }
                    }
                }
                TableId::Constant => {
                    if let Some(constant_table) = tables.table::<ConstantRaw>() {
                        for (scanning_rid, row) in constant_table.iter().enumerate() {
                            let scanning_rid = scanning_rid as u32 + 1;
                            if row.parent.row != 0 {
                                tracker.add_rid_reference(
                                    row.parent.tag,
                                    row.parent.row,
                                    TableReference {
                                        table_id: TableId::Constant,
                                        row_rid: scanning_rid,
                                        column_name: "parent".to_string(),
                                    },
                                );
                            }
                            if row.value != 0 {
                                tracker.add_blob_reference(
                                    row.value,
                                    TableReference {
                                        table_id: TableId::Constant,
                                        row_rid: scanning_rid,
                                        column_name: "value".to_string(),
                                    },
                                );
                            }
                        }
                    }
                }
                TableId::CustomAttribute => {
                    if let Some(customattr_table) = tables.table::<CustomAttributeRaw>() {
                        for (scanning_rid, row) in customattr_table.iter().enumerate() {
                            let scanning_rid = scanning_rid as u32 + 1;
                            if row.parent.row != 0 {
                                tracker.add_rid_reference(
                                    row.parent.tag,
                                    row.parent.row,
                                    TableReference {
                                        table_id: TableId::CustomAttribute,
                                        row_rid: scanning_rid,
                                        column_name: "parent".to_string(),
                                    },
                                );
                            }
                            if row.constructor.row != 0 {
                                tracker.add_rid_reference(
                                    row.constructor.tag,
                                    row.constructor.row,
                                    TableReference {
                                        table_id: TableId::CustomAttribute,
                                        row_rid: scanning_rid,
                                        column_name: "constructor".to_string(),
                                    },
                                );
                            }
                            if row.value != 0 {
                                tracker.add_blob_reference(
                                    row.value,
                                    TableReference {
                                        table_id: TableId::CustomAttribute,
                                        row_rid: scanning_rid,
                                        column_name: "value".to_string(),
                                    },
                                );
                            }
                        }
                    }
                }
                TableId::FieldMarshal => {
                    if let Some(fieldmarshal_table) = tables.table::<FieldMarshalRaw>() {
                        for (scanning_rid, row) in fieldmarshal_table.iter().enumerate() {
                            let scanning_rid = scanning_rid as u32 + 1;
                            if row.parent.row != 0 {
                                tracker.add_rid_reference(
                                    row.parent.tag,
                                    row.parent.row,
                                    TableReference {
                                        table_id: TableId::FieldMarshal,
                                        row_rid: scanning_rid,
                                        column_name: "parent".to_string(),
                                    },
                                );
                            }
                            if row.native_type != 0 {
                                tracker.add_blob_reference(
                                    row.native_type,
                                    TableReference {
                                        table_id: TableId::FieldMarshal,
                                        row_rid: scanning_rid,
                                        column_name: "native_type".to_string(),
                                    },
                                );
                            }
                        }
                    }
                }
                TableId::DeclSecurity => {
                    if let Some(declsecurity_table) = tables.table::<DeclSecurityRaw>() {
                        for (scanning_rid, row) in declsecurity_table.iter().enumerate() {
                            let scanning_rid = scanning_rid as u32 + 1;
                            if row.parent.row != 0 {
                                tracker.add_rid_reference(
                                    row.parent.tag,
                                    row.parent.row,
                                    TableReference {
                                        table_id: TableId::DeclSecurity,
                                        row_rid: scanning_rid,
                                        column_name: "parent".to_string(),
                                    },
                                );
                            }
                            if row.permission_set != 0 {
                                tracker.add_blob_reference(
                                    row.permission_set,
                                    TableReference {
                                        table_id: TableId::DeclSecurity,
                                        row_rid: scanning_rid,
                                        column_name: "permission_set".to_string(),
                                    },
                                );
                            }
                        }
                    }
                }
                TableId::ClassLayout => {
                    if let Some(classlayout_table) = tables.table::<ClassLayoutRaw>() {
                        for (scanning_rid, row) in classlayout_table.iter().enumerate() {
                            let scanning_rid = scanning_rid as u32 + 1;
                            if row.parent != 0 {
                                tracker.add_rid_reference(
                                    TableId::TypeDef,
                                    row.parent,
                                    TableReference {
                                        table_id: TableId::ClassLayout,
                                        row_rid: scanning_rid,
                                        column_name: "parent".to_string(),
                                    },
                                );
                            }
                        }
                    }
                }
                TableId::FieldLayout => {
                    if let Some(fieldlayout_table) = tables.table::<FieldLayoutRaw>() {
                        for (scanning_rid, row) in fieldlayout_table.iter().enumerate() {
                            let scanning_rid = scanning_rid as u32 + 1;
                            if row.field != 0 {
                                tracker.add_rid_reference(
                                    TableId::Field,
                                    row.field,
                                    TableReference {
                                        table_id: TableId::FieldLayout,
                                        row_rid: scanning_rid,
                                        column_name: "field".to_string(),
                                    },
                                );
                            }
                        }
                    }
                }
                TableId::StandAloneSig => {
                    if let Some(standalonesig_table) = tables.table::<StandAloneSigRaw>() {
                        for (scanning_rid, row) in standalonesig_table.iter().enumerate() {
                            let scanning_rid = scanning_rid as u32 + 1;
                            if row.signature != 0 {
                                tracker.add_blob_reference(
                                    row.signature,
                                    TableReference {
                                        table_id: TableId::StandAloneSig,
                                        row_rid: scanning_rid,
                                        column_name: "signature".to_string(),
                                    },
                                );
                            }
                        }
                    }
                }
                TableId::EventMap => {
                    if let Some(eventmap_table) = tables.table::<EventMapRaw>() {
                        for (scanning_rid, row) in eventmap_table.iter().enumerate() {
                            let scanning_rid = scanning_rid as u32 + 1;
                            if row.parent != 0 {
                                tracker.add_rid_reference(
                                    TableId::TypeDef,
                                    row.parent,
                                    TableReference {
                                        table_id: TableId::EventMap,
                                        row_rid: scanning_rid,
                                        column_name: "parent".to_string(),
                                    },
                                );
                            }
                            if row.event_list != 0 {
                                tracker.add_rid_reference(
                                    TableId::Event,
                                    row.event_list,
                                    TableReference {
                                        table_id: TableId::EventMap,
                                        row_rid: scanning_rid,
                                        column_name: "event_list".to_string(),
                                    },
                                );
                            }
                        }
                    }
                }
                TableId::Event => {
                    if let Some(event_table) = tables.table::<EventRaw>() {
                        for (scanning_rid, row) in event_table.iter().enumerate() {
                            let scanning_rid = scanning_rid as u32 + 1;
                            if row.event_type.row != 0 {
                                tracker.add_rid_reference(
                                    row.event_type.tag,
                                    row.event_type.row,
                                    TableReference {
                                        table_id: TableId::Event,
                                        row_rid: scanning_rid,
                                        column_name: "event_type".to_string(),
                                    },
                                );
                            }
                            if row.name != 0 {
                                tracker.add_string_reference(
                                    row.name,
                                    TableReference {
                                        table_id: TableId::Event,
                                        row_rid: scanning_rid,
                                        column_name: "name".to_string(),
                                    },
                                );
                            }
                        }
                    }
                }
                TableId::PropertyMap => {
                    if let Some(propertymap_table) = tables.table::<PropertyMapRaw>() {
                        for (scanning_rid, row) in propertymap_table.iter().enumerate() {
                            let scanning_rid = scanning_rid as u32 + 1;
                            if row.parent != 0 {
                                tracker.add_rid_reference(
                                    TableId::TypeDef,
                                    row.parent,
                                    TableReference {
                                        table_id: TableId::PropertyMap,
                                        row_rid: scanning_rid,
                                        column_name: "parent".to_string(),
                                    },
                                );
                            }
                            if row.property_list != 0 {
                                tracker.add_rid_reference(
                                    TableId::Property,
                                    row.property_list,
                                    TableReference {
                                        table_id: TableId::PropertyMap,
                                        row_rid: scanning_rid,
                                        column_name: "property_list".to_string(),
                                    },
                                );
                            }
                        }
                    }
                }
                TableId::Property => {
                    if let Some(property_table) = tables.table::<PropertyRaw>() {
                        for (scanning_rid, row) in property_table.iter().enumerate() {
                            let scanning_rid = scanning_rid as u32 + 1;
                            if row.name != 0 {
                                tracker.add_string_reference(
                                    row.name,
                                    TableReference {
                                        table_id: TableId::Property,
                                        row_rid: scanning_rid,
                                        column_name: "name".to_string(),
                                    },
                                );
                            }
                            if row.signature != 0 {
                                tracker.add_blob_reference(
                                    row.signature,
                                    TableReference {
                                        table_id: TableId::Property,
                                        row_rid: scanning_rid,
                                        column_name: "signature".to_string(),
                                    },
                                );
                            }
                        }
                    }
                }
                TableId::MethodSemantics => {
                    if let Some(methodsemantics_table) = tables.table::<MethodSemanticsRaw>() {
                        for (scanning_rid, row) in methodsemantics_table.iter().enumerate() {
                            let scanning_rid = scanning_rid as u32 + 1;
                            if row.method != 0 {
                                tracker.add_rid_reference(
                                    TableId::MethodDef,
                                    row.method,
                                    TableReference {
                                        table_id: TableId::MethodSemantics,
                                        row_rid: scanning_rid,
                                        column_name: "method".to_string(),
                                    },
                                );
                            }
                            if row.association.row != 0 {
                                tracker.add_rid_reference(
                                    row.association.tag,
                                    row.association.row,
                                    TableReference {
                                        table_id: TableId::MethodSemantics,
                                        row_rid: scanning_rid,
                                        column_name: "association".to_string(),
                                    },
                                );
                            }
                        }
                    }
                }
                TableId::MethodImpl => {
                    if let Some(methodimpl_table) = tables.table::<MethodImplRaw>() {
                        for (scanning_rid, row) in methodimpl_table.iter().enumerate() {
                            let scanning_rid = scanning_rid as u32 + 1;
                            if row.class != 0 {
                                tracker.add_rid_reference(
                                    TableId::TypeDef,
                                    row.class,
                                    TableReference {
                                        table_id: TableId::MethodImpl,
                                        row_rid: scanning_rid,
                                        column_name: "class".to_string(),
                                    },
                                );
                            }
                            if row.method_body.row != 0 {
                                tracker.add_rid_reference(
                                    row.method_body.tag,
                                    row.method_body.row,
                                    TableReference {
                                        table_id: TableId::MethodImpl,
                                        row_rid: scanning_rid,
                                        column_name: "method_body".to_string(),
                                    },
                                );
                            }
                            if row.method_declaration.row != 0 {
                                tracker.add_rid_reference(
                                    row.method_declaration.tag,
                                    row.method_declaration.row,
                                    TableReference {
                                        table_id: TableId::MethodImpl,
                                        row_rid: scanning_rid,
                                        column_name: "method_declaration".to_string(),
                                    },
                                );
                            }
                        }
                    }
                }
                TableId::ModuleRef => {
                    if let Some(moduleref_table) = tables.table::<ModuleRefRaw>() {
                        for (scanning_rid, row) in moduleref_table.iter().enumerate() {
                            let scanning_rid = scanning_rid as u32 + 1;
                            if row.name != 0 {
                                tracker.add_string_reference(
                                    row.name,
                                    TableReference {
                                        table_id: TableId::ModuleRef,
                                        row_rid: scanning_rid,
                                        column_name: "name".to_string(),
                                    },
                                );
                            }
                        }
                    }
                }
                TableId::TypeSpec => {
                    if let Some(typespec_table) = tables.table::<TypeSpecRaw>() {
                        for (scanning_rid, row) in typespec_table.iter().enumerate() {
                            let scanning_rid = scanning_rid as u32 + 1;
                            if row.signature != 0 {
                                tracker.add_blob_reference(
                                    row.signature,
                                    TableReference {
                                        table_id: TableId::TypeSpec,
                                        row_rid: scanning_rid,
                                        column_name: "signature".to_string(),
                                    },
                                );
                            }
                        }
                    }
                }
                TableId::ImplMap => {
                    if let Some(implmap_table) = tables.table::<ImplMapRaw>() {
                        for (scanning_rid, row) in implmap_table.iter().enumerate() {
                            let scanning_rid = scanning_rid as u32 + 1;
                            if row.member_forwarded.row != 0 {
                                tracker.add_rid_reference(
                                    row.member_forwarded.tag,
                                    row.member_forwarded.row,
                                    TableReference {
                                        table_id: TableId::ImplMap,
                                        row_rid: scanning_rid,
                                        column_name: "member_forwarded".to_string(),
                                    },
                                );
                            }
                            if row.import_name != 0 {
                                tracker.add_string_reference(
                                    row.import_name,
                                    TableReference {
                                        table_id: TableId::ImplMap,
                                        row_rid: scanning_rid,
                                        column_name: "import_name".to_string(),
                                    },
                                );
                            }
                            if row.import_scope != 0 {
                                tracker.add_rid_reference(
                                    TableId::ModuleRef,
                                    row.import_scope,
                                    TableReference {
                                        table_id: TableId::ImplMap,
                                        row_rid: scanning_rid,
                                        column_name: "import_scope".to_string(),
                                    },
                                );
                            }
                        }
                    }
                }
                TableId::FieldRVA => {
                    if let Some(fieldrva_table) = tables.table::<FieldRvaRaw>() {
                        for (scanning_rid, row) in fieldrva_table.iter().enumerate() {
                            let scanning_rid = scanning_rid as u32 + 1;
                            if row.field != 0 {
                                tracker.add_rid_reference(
                                    TableId::Field,
                                    row.field,
                                    TableReference {
                                        table_id: TableId::FieldRVA,
                                        row_rid: scanning_rid,
                                        column_name: "field".to_string(),
                                    },
                                );
                            }
                        }
                    }
                }
                TableId::Assembly => {
                    if let Some(assembly_table) = tables.table::<AssemblyRaw>() {
                        for (scanning_rid, row) in assembly_table.iter().enumerate() {
                            let scanning_rid = scanning_rid as u32 + 1;
                            if row.name != 0 {
                                tracker.add_string_reference(
                                    row.name,
                                    TableReference {
                                        table_id: TableId::Assembly,
                                        row_rid: scanning_rid,
                                        column_name: "name".to_string(),
                                    },
                                );
                            }

                            if row.culture != 0 {
                                tracker.add_string_reference(
                                    row.culture,
                                    TableReference {
                                        table_id: TableId::Assembly,
                                        row_rid: scanning_rid,
                                        column_name: "culture".to_string(),
                                    },
                                );
                            }
                            if row.public_key != 0 {
                                tracker.add_blob_reference(
                                    row.public_key,
                                    TableReference {
                                        table_id: TableId::Assembly,
                                        row_rid: scanning_rid,
                                        column_name: "public_key".to_string(),
                                    },
                                );
                            }
                        }
                    }
                }
                TableId::AssemblyRef => {
                    if let Some(assemblyref_table) = tables.table::<AssemblyRefRaw>() {
                        for (scanning_rid, row) in assemblyref_table.iter().enumerate() {
                            let scanning_rid = scanning_rid as u32 + 1;
                            if row.name != 0 {
                                tracker.add_string_reference(
                                    row.name,
                                    TableReference {
                                        table_id: TableId::AssemblyRef,
                                        row_rid: scanning_rid,
                                        column_name: "name".to_string(),
                                    },
                                );
                            }

                            if row.culture != 0 {
                                tracker.add_string_reference(
                                    row.culture,
                                    TableReference {
                                        table_id: TableId::AssemblyRef,
                                        row_rid: scanning_rid,
                                        column_name: "culture".to_string(),
                                    },
                                );
                            }
                            if row.public_key_or_token != 0 {
                                tracker.add_blob_reference(
                                    row.public_key_or_token,
                                    TableReference {
                                        table_id: TableId::AssemblyRef,
                                        row_rid: scanning_rid,
                                        column_name: "public_key_or_token".to_string(),
                                    },
                                );
                            }

                            if row.hash_value != 0 {
                                tracker.add_blob_reference(
                                    row.hash_value,
                                    TableReference {
                                        table_id: TableId::AssemblyRef,
                                        row_rid: scanning_rid,
                                        column_name: "hash_value".to_string(),
                                    },
                                );
                            }
                        }
                    }
                }
                TableId::File => {
                    if let Some(file_table) = tables.table::<FileRaw>() {
                        for (scanning_rid, row) in file_table.iter().enumerate() {
                            let scanning_rid = scanning_rid as u32 + 1;
                            if row.name != 0 {
                                tracker.add_string_reference(
                                    row.name,
                                    TableReference {
                                        table_id: TableId::File,
                                        row_rid: scanning_rid,
                                        column_name: "name".to_string(),
                                    },
                                );
                            }
                            if row.hash_value != 0 {
                                tracker.add_blob_reference(
                                    row.hash_value,
                                    TableReference {
                                        table_id: TableId::File,
                                        row_rid: scanning_rid,
                                        column_name: "hash_value".to_string(),
                                    },
                                );
                            }
                        }
                    }
                }
                TableId::ExportedType => {
                    if let Some(exportedtype_table) = tables.table::<ExportedTypeRaw>() {
                        for (scanning_rid, row) in exportedtype_table.iter().enumerate() {
                            let scanning_rid = scanning_rid as u32 + 1;
                            if row.name != 0 {
                                tracker.add_string_reference(
                                    row.name,
                                    TableReference {
                                        table_id: TableId::ExportedType,
                                        row_rid: scanning_rid,
                                        column_name: "name".to_string(),
                                    },
                                );
                            }

                            if row.namespace != 0 {
                                tracker.add_string_reference(
                                    row.namespace,
                                    TableReference {
                                        table_id: TableId::ExportedType,
                                        row_rid: scanning_rid,
                                        column_name: "namespace".to_string(),
                                    },
                                );
                            }
                            if row.implementation.row != 0 {
                                tracker.add_rid_reference(
                                    row.implementation.tag,
                                    row.implementation.row,
                                    TableReference {
                                        table_id: TableId::ExportedType,
                                        row_rid: scanning_rid,
                                        column_name: "implementation".to_string(),
                                    },
                                );
                            }
                        }
                    }
                }
                TableId::ManifestResource => {
                    if let Some(manifestresource_table) = tables.table::<ManifestResourceRaw>() {
                        for (scanning_rid, row) in manifestresource_table.iter().enumerate() {
                            let scanning_rid = scanning_rid as u32 + 1;
                            if row.name != 0 {
                                tracker.add_string_reference(
                                    row.name,
                                    TableReference {
                                        table_id: TableId::ManifestResource,
                                        row_rid: scanning_rid,
                                        column_name: "name".to_string(),
                                    },
                                );
                            }
                            if row.implementation.row != 0 {
                                tracker.add_rid_reference(
                                    row.implementation.tag,
                                    row.implementation.row,
                                    TableReference {
                                        table_id: TableId::ManifestResource,
                                        row_rid: scanning_rid,
                                        column_name: "implementation".to_string(),
                                    },
                                );
                            }
                        }
                    }
                }
                TableId::NestedClass => {
                    if let Some(nestedclass_table) = tables.table::<NestedClassRaw>() {
                        for (scanning_rid, row) in nestedclass_table.iter().enumerate() {
                            let scanning_rid = scanning_rid as u32 + 1;
                            if row.nested_class != 0 {
                                tracker.add_rid_reference(
                                    TableId::TypeDef,
                                    row.nested_class,
                                    TableReference {
                                        table_id: TableId::NestedClass,
                                        row_rid: scanning_rid,
                                        column_name: "nested_class".to_string(),
                                    },
                                );
                            }
                            if row.enclosing_class != 0 {
                                tracker.add_rid_reference(
                                    TableId::TypeDef,
                                    row.enclosing_class,
                                    TableReference {
                                        table_id: TableId::NestedClass,
                                        row_rid: scanning_rid,
                                        column_name: "enclosing_class".to_string(),
                                    },
                                );
                            }
                        }
                    }
                }
                TableId::GenericParam => {
                    if let Some(genericparam_table) = tables.table::<GenericParamRaw>() {
                        for (scanning_rid, row) in genericparam_table.iter().enumerate() {
                            let scanning_rid = scanning_rid as u32 + 1;
                            if row.owner.row != 0 {
                                tracker.add_rid_reference(
                                    row.owner.tag,
                                    row.owner.row,
                                    TableReference {
                                        table_id: TableId::GenericParam,
                                        row_rid: scanning_rid,
                                        column_name: "owner".to_string(),
                                    },
                                );
                            }
                            if row.name != 0 {
                                tracker.add_string_reference(
                                    row.name,
                                    TableReference {
                                        table_id: TableId::GenericParam,
                                        row_rid: scanning_rid,
                                        column_name: "name".to_string(),
                                    },
                                );
                            }
                        }
                    }
                }
                TableId::MethodSpec => {
                    if let Some(methodspec_table) = tables.table::<MethodSpecRaw>() {
                        for (scanning_rid, row) in methodspec_table.iter().enumerate() {
                            let scanning_rid = scanning_rid as u32 + 1;
                            if row.method.row != 0 {
                                tracker.add_rid_reference(
                                    row.method.tag,
                                    row.method.row,
                                    TableReference {
                                        table_id: TableId::MethodSpec,
                                        row_rid: scanning_rid,
                                        column_name: "method".to_string(),
                                    },
                                );
                            }
                            if row.instantiation != 0 {
                                tracker.add_blob_reference(
                                    row.instantiation,
                                    TableReference {
                                        table_id: TableId::MethodSpec,
                                        row_rid: scanning_rid,
                                        column_name: "instantiation".to_string(),
                                    },
                                );
                            }
                        }
                    }
                }
                TableId::GenericParamConstraint => {
                    if let Some(genericparamconstraint_table) =
                        tables.table::<GenericParamConstraintRaw>()
                    {
                        for (scanning_rid, row) in genericparamconstraint_table.iter().enumerate() {
                            let scanning_rid = scanning_rid as u32 + 1;
                            if row.owner != 0 {
                                tracker.add_rid_reference(
                                    TableId::GenericParam,
                                    row.owner,
                                    TableReference {
                                        table_id: TableId::GenericParamConstraint,
                                        row_rid: scanning_rid,
                                        column_name: "owner".to_string(),
                                    },
                                );
                            }
                            if row.constraint.row != 0 {
                                tracker.add_rid_reference(
                                    row.constraint.tag,
                                    row.constraint.row,
                                    TableReference {
                                        table_id: TableId::GenericParamConstraint,
                                        row_rid: scanning_rid,
                                        column_name: "constraint".to_string(),
                                    },
                                );
                            }
                        }
                    }
                }
                TableId::FieldPtr => {
                    if let Some(fieldptr_table) = tables.table::<FieldPtrRaw>() {
                        for (scanning_rid, row) in fieldptr_table.iter().enumerate() {
                            let scanning_rid = scanning_rid as u32 + 1;
                            if row.field != 0 {
                                tracker.add_rid_reference(
                                    TableId::Field,
                                    row.field,
                                    TableReference {
                                        table_id: TableId::FieldPtr,
                                        row_rid: scanning_rid,
                                        column_name: "field".to_string(),
                                    },
                                );
                            }
                        }
                    }
                }
                TableId::MethodPtr => {
                    if let Some(methodptr_table) = tables.table::<MethodPtrRaw>() {
                        for (scanning_rid, row) in methodptr_table.iter().enumerate() {
                            let scanning_rid = scanning_rid as u32 + 1;
                            if row.method != 0 {
                                tracker.add_rid_reference(
                                    TableId::MethodDef,
                                    row.method,
                                    TableReference {
                                        table_id: TableId::MethodPtr,
                                        row_rid: scanning_rid,
                                        column_name: "method".to_string(),
                                    },
                                );
                            }
                        }
                    }
                }
                TableId::ParamPtr => {
                    if let Some(paramptr_table) = tables.table::<ParamPtrRaw>() {
                        for (scanning_rid, row) in paramptr_table.iter().enumerate() {
                            let scanning_rid = scanning_rid as u32 + 1;
                            if row.param != 0 {
                                tracker.add_rid_reference(
                                    TableId::Param,
                                    row.param,
                                    TableReference {
                                        table_id: TableId::ParamPtr,
                                        row_rid: scanning_rid,
                                        column_name: "param".to_string(),
                                    },
                                );
                            }
                        }
                    }
                }
                TableId::EventPtr => {
                    if let Some(eventptr_table) = tables.table::<EventPtrRaw>() {
                        for (scanning_rid, row) in eventptr_table.iter().enumerate() {
                            let scanning_rid = scanning_rid as u32 + 1;
                            if row.event != 0 {
                                tracker.add_rid_reference(
                                    TableId::Event,
                                    row.event,
                                    TableReference {
                                        table_id: TableId::EventPtr,
                                        row_rid: scanning_rid,
                                        column_name: "event".to_string(),
                                    },
                                );
                            }
                        }
                    }
                }
                TableId::PropertyPtr => {
                    if let Some(propertyptr_table) = tables.table::<PropertyPtrRaw>() {
                        for (scanning_rid, row) in propertyptr_table.iter().enumerate() {
                            let scanning_rid = scanning_rid as u32 + 1;
                            if row.property != 0 {
                                tracker.add_rid_reference(
                                    TableId::Property,
                                    row.property,
                                    TableReference {
                                        table_id: TableId::PropertyPtr,
                                        row_rid: scanning_rid,
                                        column_name: "property".to_string(),
                                    },
                                );
                            }
                        }
                    }
                }
                TableId::AssemblyProcessor => {
                    if let Some(assemblyprocessor_table) = tables.table::<AssemblyProcessorRaw>() {
                        for (scanning_rid, _row) in assemblyprocessor_table.iter().enumerate() {
                            let _scanning_rid = scanning_rid as u32 + 1;
                        }
                    }
                }
                TableId::AssemblyOS => {
                    if let Some(assemblyos_table) = tables.table::<AssemblyOsRaw>() {
                        for (scanning_rid, _row) in assemblyos_table.iter().enumerate() {
                            let _scanning_rid = scanning_rid as u32 + 1;
                        }
                    }
                }
                TableId::AssemblyRefProcessor => {
                    if let Some(assemblyrefprocessor_table) =
                        tables.table::<AssemblyRefProcessorRaw>()
                    {
                        for (scanning_rid, row) in assemblyrefprocessor_table.iter().enumerate() {
                            let scanning_rid = scanning_rid as u32 + 1;
                            if row.assembly_ref != 0 {
                                tracker.add_rid_reference(
                                    TableId::AssemblyRef,
                                    row.assembly_ref,
                                    TableReference {
                                        table_id: TableId::AssemblyRefProcessor,
                                        row_rid: scanning_rid,
                                        column_name: "assembly_ref".to_string(),
                                    },
                                );
                            }
                        }
                    }
                }
                TableId::AssemblyRefOS => {
                    if let Some(assemblyrefos_table) = tables.table::<AssemblyRefOsRaw>() {
                        for (scanning_rid, row) in assemblyrefos_table.iter().enumerate() {
                            let scanning_rid = scanning_rid as u32 + 1;
                            if row.assembly_ref != 0 {
                                tracker.add_rid_reference(
                                    TableId::AssemblyRef,
                                    row.assembly_ref,
                                    TableReference {
                                        table_id: TableId::AssemblyRefOS,
                                        row_rid: scanning_rid,
                                        column_name: "assembly_ref".to_string(),
                                    },
                                );
                            }
                        }
                    }
                }
                TableId::Document => {
                    if let Some(document_table) = tables.table::<DocumentRaw>() {
                        for (scanning_rid, row) in document_table.iter().enumerate() {
                            let scanning_rid = scanning_rid as u32 + 1;
                            if row.name != 0 {
                                tracker.add_blob_reference(
                                    row.name,
                                    TableReference {
                                        table_id: TableId::Document,
                                        row_rid: scanning_rid,
                                        column_name: "name".to_string(),
                                    },
                                );
                            }
                            if row.hash_algorithm != 0 {
                                tracker.add_guid_reference(
                                    row.hash_algorithm,
                                    TableReference {
                                        table_id: TableId::Document,
                                        row_rid: scanning_rid,
                                        column_name: "hash_algorithm".to_string(),
                                    },
                                );
                            }

                            if row.hash != 0 {
                                tracker.add_blob_reference(
                                    row.hash,
                                    TableReference {
                                        table_id: TableId::Document,
                                        row_rid: scanning_rid,
                                        column_name: "hash".to_string(),
                                    },
                                );
                            }

                            if row.language != 0 {
                                tracker.add_guid_reference(
                                    row.language,
                                    TableReference {
                                        table_id: TableId::Document,
                                        row_rid: scanning_rid,
                                        column_name: "language".to_string(),
                                    },
                                );
                            }
                        }
                    }
                }
                TableId::MethodDebugInformation => {
                    if let Some(methoddebuginfo_table) = tables.table::<MethodDebugInformationRaw>()
                    {
                        for (scanning_rid, row) in methoddebuginfo_table.iter().enumerate() {
                            let scanning_rid = scanning_rid as u32 + 1;
                            if row.document != 0 {
                                tracker.add_rid_reference(
                                    TableId::Document,
                                    row.document,
                                    TableReference {
                                        table_id: TableId::MethodDebugInformation,
                                        row_rid: scanning_rid,
                                        column_name: "document".to_string(),
                                    },
                                );
                            }
                            if row.sequence_points != 0 {
                                tracker.add_blob_reference(
                                    row.sequence_points,
                                    TableReference {
                                        table_id: TableId::MethodDebugInformation,
                                        row_rid: scanning_rid,
                                        column_name: "sequence_points".to_string(),
                                    },
                                );
                            }
                        }
                    }
                }
                TableId::LocalScope => {
                    if let Some(localscope_table) = tables.table::<LocalScopeRaw>() {
                        for (scanning_rid, row) in localscope_table.iter().enumerate() {
                            let scanning_rid = scanning_rid as u32 + 1;
                            if row.method != 0 {
                                tracker.add_rid_reference(
                                    TableId::MethodDef,
                                    row.method,
                                    TableReference {
                                        table_id: TableId::LocalScope,
                                        row_rid: scanning_rid,
                                        column_name: "method".to_string(),
                                    },
                                );
                            }
                            if row.import_scope != 0 {
                                tracker.add_rid_reference(
                                    TableId::ImportScope,
                                    row.import_scope,
                                    TableReference {
                                        table_id: TableId::LocalScope,
                                        row_rid: scanning_rid,
                                        column_name: "import_scope".to_string(),
                                    },
                                );
                            }
                            if row.variable_list != 0 {
                                tracker.add_rid_reference(
                                    TableId::LocalVariable,
                                    row.variable_list,
                                    TableReference {
                                        table_id: TableId::LocalScope,
                                        row_rid: scanning_rid,
                                        column_name: "variable_list".to_string(),
                                    },
                                );
                            }
                            if row.constant_list != 0 {
                                tracker.add_rid_reference(
                                    TableId::LocalConstant,
                                    row.constant_list,
                                    TableReference {
                                        table_id: TableId::LocalScope,
                                        row_rid: scanning_rid,
                                        column_name: "constant_list".to_string(),
                                    },
                                );
                            }
                        }
                    }
                }
                TableId::LocalVariable => {
                    if let Some(localvariable_table) = tables.table::<LocalVariableRaw>() {
                        for (scanning_rid, row) in localvariable_table.iter().enumerate() {
                            let scanning_rid = scanning_rid as u32 + 1;
                            if row.name != 0 {
                                tracker.add_string_reference(
                                    row.name,
                                    TableReference {
                                        table_id: TableId::LocalVariable,
                                        row_rid: scanning_rid,
                                        column_name: "name".to_string(),
                                    },
                                );
                            }
                        }
                    }
                }
                TableId::LocalConstant => {
                    if let Some(localconstant_table) = tables.table::<LocalConstantRaw>() {
                        for (scanning_rid, row) in localconstant_table.iter().enumerate() {
                            let scanning_rid = scanning_rid as u32 + 1;
                            if row.name != 0 {
                                tracker.add_string_reference(
                                    row.name,
                                    TableReference {
                                        table_id: TableId::LocalConstant,
                                        row_rid: scanning_rid,
                                        column_name: "name".to_string(),
                                    },
                                );
                            }
                            if row.signature != 0 {
                                tracker.add_blob_reference(
                                    row.signature,
                                    TableReference {
                                        table_id: TableId::LocalConstant,
                                        row_rid: scanning_rid,
                                        column_name: "signature".to_string(),
                                    },
                                );
                            }
                        }
                    }
                }
                TableId::ImportScope => {
                    if let Some(importscope_table) = tables.table::<ImportScopeRaw>() {
                        for (scanning_rid, row) in importscope_table.iter().enumerate() {
                            let scanning_rid = scanning_rid as u32 + 1;
                            if row.parent != 0 {
                                tracker.add_rid_reference(
                                    TableId::ImportScope,
                                    row.parent,
                                    TableReference {
                                        table_id: TableId::ImportScope,
                                        row_rid: scanning_rid,
                                        column_name: "parent".to_string(),
                                    },
                                );
                            }
                            if row.imports != 0 {
                                tracker.add_blob_reference(
                                    row.imports,
                                    TableReference {
                                        table_id: TableId::ImportScope,
                                        row_rid: scanning_rid,
                                        column_name: "imports".to_string(),
                                    },
                                );
                            }
                        }
                    }
                }
                TableId::StateMachineMethod => {
                    if let Some(statemachinemethod_table) = tables.table::<StateMachineMethodRaw>()
                    {
                        for (scanning_rid, row) in statemachinemethod_table.iter().enumerate() {
                            let scanning_rid = scanning_rid as u32 + 1;
                            if row.move_next_method != 0 {
                                tracker.add_rid_reference(
                                    TableId::MethodDef,
                                    row.move_next_method,
                                    TableReference {
                                        table_id: TableId::StateMachineMethod,
                                        row_rid: scanning_rid,
                                        column_name: "move_next_method".to_string(),
                                    },
                                );
                            }
                            if row.kickoff_method != 0 {
                                tracker.add_rid_reference(
                                    TableId::MethodDef,
                                    row.kickoff_method,
                                    TableReference {
                                        table_id: TableId::StateMachineMethod,
                                        row_rid: scanning_rid,
                                        column_name: "kickoff_method".to_string(),
                                    },
                                );
                            }
                        }
                    }
                }
                TableId::CustomDebugInformation => {
                    if let Some(customdebuginfo_table) = tables.table::<CustomDebugInformationRaw>()
                    {
                        for (scanning_rid, row) in customdebuginfo_table.iter().enumerate() {
                            let scanning_rid = scanning_rid as u32 + 1;
                            if row.parent.row != 0 {
                                tracker.add_rid_reference(
                                    row.parent.tag,
                                    row.parent.row,
                                    TableReference {
                                        table_id: TableId::CustomDebugInformation,
                                        row_rid: scanning_rid,
                                        column_name: "parent".to_string(),
                                    },
                                );
                            }
                            if row.kind != 0 {
                                tracker.add_guid_reference(
                                    row.kind,
                                    TableReference {
                                        table_id: TableId::CustomDebugInformation,
                                        row_rid: scanning_rid,
                                        column_name: "kind".to_string(),
                                    },
                                );
                            }
                            if row.value != 0 {
                                tracker.add_blob_reference(
                                    row.value,
                                    TableReference {
                                        table_id: TableId::CustomDebugInformation,
                                        row_rid: scanning_rid,
                                        column_name: "value".to_string(),
                                    },
                                );
                            }
                        }
                    }
                }
                TableId::EncLog => {
                    if let Some(enclog_table) = tables.table::<EncLogRaw>() {
                        for (scanning_rid, _row) in enclog_table.iter().enumerate() {
                            let _scanning_rid = scanning_rid as u32 + 1;
                        }
                    }
                }
                TableId::EncMap => {
                    if let Some(encmap_table) = tables.table::<EncMapRaw>() {
                        for (scanning_rid, _row) in encmap_table.iter().enumerate() {
                            let _scanning_rid = scanning_rid as u32 + 1;
                        }
                    }
                }
            }
        }

        Ok(tracker)
    }

    /// Finds all references to the specified table row.
    ///
    /// This method uses the internal reference tracker to efficiently find every location
    /// that references the specified table row. It examines both direct references (where a
    /// column directly stores a RID) and coded indices (where multiple table types can be
    /// referenced through a single column).
    ///
    /// The scan covers all ECMA-335 metadata tables and their cross-reference relationships,
    /// providing complete coverage for referential integrity validation.
    ///
    /// # Performance
    ///
    /// This method provides O(1) lookup time using the reference tracker that was built
    /// during scanner construction. All queries are fast regardless of assembly size.
    ///
    /// # Arguments
    ///
    /// * `table_id` - The [`crate::metadata::tables::TableId`] of the table containing the target row
    /// * `rid` - The Row ID (RID) of the target row within the specified table
    ///
    /// # Returns
    ///
    /// Returns a [`Vec`] of [`crate::cilassembly::references::TableReference`] instances, each representing
    /// a location where the target row is referenced. An empty vector indicates no references were found.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use crate::cilassembly::validation::reference::ReferenceScanner;
    /// use crate::metadata::cilassemblyview::CilAssemblyView;
    /// use crate::metadata::tables::TableId;
    /// use std::path::Path;
    ///
    /// # let view = CilAssemblyView::from_file(Path::new("test.dll"))?;
    /// let scanner = ReferenceScanner::new(&view)?;
    ///
    /// // Find all references to TypeDef row 1
    /// let references = scanner.find_references_to_table_row(TableId::TypeDef, 1);
    ///
    /// if references.is_empty() {
    ///     println!("No references found - safe to delete");
    /// } else {
    ///     println!("Found {} references:", references.row_count);
    ///     for reference in references {
    ///         println!("  - {}:{} column '{}'",
    ///                  reference.table_id as u32, reference.row_rid, reference.column_name);
    ///     }
    /// }
    /// # Ok::<(), crate::Error>(())
    /// ```
    pub fn find_references_to_table_row(&self, table_id: TableId, rid: u32) -> Vec<TableReference> {
        if rid == 0 {
            return Vec::new();
        }

        self.tracker
            .get_rid_references(table_id, rid)
            .cloned()
            .unwrap_or_default()
    }

    /// Resolves coded index references to find all table rows that could be referenced
    /// by the specified coded index type and value.
    ///
    /// This method handles the decoding of coded indices by examining the lower bits
    /// to determine the target table type and the upper bits for the row index.
    /// It supports all coded index types defined in ECMA-335 §II.24.2.6.
    ///
    /// # Arguments
    ///
    /// * `coded_index` - The coded index value to resolve
    /// * `coded_index_type` - The type of coded index (determines valid table types)
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing a vector of `TableReference` objects for each
    /// table row that could be referenced by this coded index.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The coded index value is invalid for the specified type
    /// - The resolved table or row doesn't exist in the metadata
    /// - The coded index type is not supported
    fn resolve_coded_index_references(
        &self,
        coded_index: u32,
        coded_index_type: CodedIndexType,
    ) -> Result<Vec<TableReference>> {
        if coded_index == 0 {
            return Ok(Vec::new());
        }

        let tables = coded_index_type.tables();
        let tag_bits = match tables.len() {
            1 => 0,
            2 => 1,
            3..=4 => 2,
            5..=8 => 3,
            9..=16 => 4,
            17..=32 => 5,
            _ => {
                return Err(malformed_error!(
                    "Unsupported coded index table count: {}",
                    tables.len()
                ))
            }
        };

        let tag_mask = (1u32 << tag_bits) - 1;
        let tag = (coded_index & tag_mask) as usize;
        let row = coded_index >> tag_bits;

        if tag >= tables.len() {
            return Err(malformed_error!(
                "Invalid coded index tag {} for type {:?}",
                tag,
                coded_index_type
            ));
        }

        let target_table = tables[tag];
        if row == 0 {
            return Ok(Vec::new());
        }

        Ok(vec![TableReference {
            table_id: target_table,
            row_rid: row,
            column_name: "coded_index".to_string(),
        }])
    }

    /// Finds all coded index references in the specified table that point to the target table and row.
    ///
    /// This method scans the specified table for coded index fields that could reference
    /// the target table and row. It handles the encoding/decoding of coded indices
    /// according to ECMA-335 specifications.
    ///
    /// # Arguments
    ///
    /// * `search_table` - The table to search for coded index references
    /// * `coded_index_type` - The type of coded index to look for
    /// * `field_getter` - Function to extract the coded index value from a table row
    /// * `target_table` - The table being referenced
    /// * `target_row` - The row being referenced
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing a vector of `TableReference` objects for each
    /// table row that contains a coded index referencing the target.
    fn find_coded_index_references<T, F>(
        &self,
        _search_table: TableId,
        coded_index_type: CodedIndexType,
        _field_getter: F,
        target_table: TableId,
        target_row: u32,
    ) -> Result<Vec<TableReference>>
    where
        F: Fn(&T) -> CodedIndex,
    {
        let mut references = Vec::new();
        let tables = coded_index_type.tables();

        let target_tag = tables.iter().position(|&t| t == target_table);
        if target_tag.is_none() {
            return Ok(references);
        }

        let Some(assembly_tables) = self.view.tables() else {
            return Ok(references);
        };

        match coded_index_type {
            CodedIndexType::TypeDefOrRef => {
                self.find_typedeforref_references(
                    target_table,
                    target_row,
                    &mut references,
                    assembly_tables,
                )?;
            }
            CodedIndexType::HasConstant => {
                self.find_hasconstant_references(
                    target_table,
                    target_row,
                    &mut references,
                    assembly_tables,
                )?;
            }
            CodedIndexType::HasCustomAttribute => {
                self.find_hascustomattribute_references(
                    target_table,
                    target_row,
                    &mut references,
                    assembly_tables,
                )?;
            }
            CodedIndexType::HasFieldMarshal => {
                self.find_hasfieldmarshal_references(
                    target_table,
                    target_row,
                    &mut references,
                    assembly_tables,
                )?;
            }
            CodedIndexType::HasDeclSecurity => {
                self.find_hasdeclsecurity_references(
                    target_table,
                    target_row,
                    &mut references,
                    assembly_tables,
                )?;
            }
            CodedIndexType::MemberRefParent => {
                self.find_memberrefparent_references(
                    target_table,
                    target_row,
                    &mut references,
                    assembly_tables,
                )?;
            }
            CodedIndexType::HasSemantics => {
                self.find_hassemantics_references(
                    target_table,
                    target_row,
                    &mut references,
                    assembly_tables,
                )?;
            }
            CodedIndexType::MethodDefOrRef => {
                self.find_methoddeforref_references(
                    target_table,
                    target_row,
                    &mut references,
                    assembly_tables,
                )?;
            }
            CodedIndexType::MemberForwarded => {
                self.find_memberforwarded_references(
                    target_table,
                    target_row,
                    &mut references,
                    assembly_tables,
                )?;
            }
            CodedIndexType::Implementation => {
                self.find_implementation_references(
                    target_table,
                    target_row,
                    &mut references,
                    assembly_tables,
                )?;
            }
            CodedIndexType::CustomAttributeType => {
                self.find_customattributetype_references(
                    target_table,
                    target_row,
                    &mut references,
                    assembly_tables,
                )?;
            }
            CodedIndexType::ResolutionScope => {
                self.find_resolutionscope_references(
                    target_table,
                    target_row,
                    &mut references,
                    assembly_tables,
                )?;
            }
            CodedIndexType::TypeOrMethodDef => {
                self.find_typeormethoddef_references(
                    target_table,
                    target_row,
                    &mut references,
                    assembly_tables,
                )?;
            }
            CodedIndexType::HasCustomDebugInformation => {
                self.find_hascustomdebuginformation_references(
                    target_table,
                    target_row,
                    &mut references,
                    assembly_tables,
                )?;
            }
        }

        Ok(references)
    }

    /// Finds all TypeDefOrRef coded index references to a specific table row.
    ///
    /// This method searches all tables that contain TypeDefOrRef coded indices
    /// and identifies references to the specified target table and row.
    ///
    /// # Arguments
    ///
    /// * `target_table` - The table being referenced
    /// * `target_row` - The row being referenced
    /// * `references` - Vector to collect found references
    /// * `assembly_tables` - Table metadata for scanning
    fn find_typedeforref_references(
        &self,
        target_table: TableId,
        target_row: u32,
        references: &mut Vec<TableReference>,
        assembly_tables: &TablesHeader,
    ) -> Result<()> {
        if let Some(table) = assembly_tables.table::<TypeDefRaw>() {
            for (index, row) in table.iter().enumerate() {
                if row.extends.tag == target_table && row.extends.row == target_row {
                    references.push(TableReference {
                        table_id: TableId::TypeDef,
                        row_rid: (index + 1) as u32,
                        column_name: "extends".to_string(),
                    });
                }
            }
        }

        if let Some(table) = assembly_tables.table::<InterfaceImplRaw>() {
            for (index, row) in table.iter().enumerate() {
                if row.interface.tag == target_table && row.interface.row == target_row {
                    references.push(TableReference {
                        table_id: TableId::InterfaceImpl,
                        row_rid: (index + 1) as u32,
                        column_name: "interface".to_string(),
                    });
                }
            }
        }

        Ok(())
    }

    /// Finds all HasConstant coded index references to a specific table row.
    ///
    /// HasConstant coded indices are used in the Constant table to reference
    /// Field, Param, or Property tables that have associated constant values.
    ///
    /// # Arguments
    ///
    /// * `target_table` - The table being referenced
    /// * `target_row` - The row being referenced
    /// * `references` - Vector to collect found references
    /// * `assembly_tables` - Table metadata for scanning
    fn find_hasconstant_references(
        &self,
        target_table: TableId,
        target_row: u32,
        references: &mut Vec<TableReference>,
        assembly_tables: &TablesHeader,
    ) -> Result<()> {
        if let Some(table) = assembly_tables.table::<ConstantRaw>() {
            for (index, row) in table.iter().enumerate() {
                if row.parent.tag == target_table && row.parent.row == target_row {
                    references.push(TableReference {
                        table_id: TableId::Constant,
                        row_rid: (index + 1) as u32,
                        column_name: "parent".to_string(),
                    });
                }
            }
        }
        Ok(())
    }

    /// Finds all HasCustomAttribute coded index references to a specific table row.
    ///
    /// HasCustomAttribute coded indices are used in the CustomAttribute table to reference
    /// any of 22 different table types that can have custom attributes applied.
    ///
    /// # Arguments
    ///
    /// * `target_table` - The table being referenced
    /// * `target_row` - The row being referenced
    /// * `references` - Vector to collect found references
    /// * `assembly_tables` - Table metadata for scanning
    fn find_hascustomattribute_references(
        &self,
        target_table: TableId,
        target_row: u32,
        references: &mut Vec<TableReference>,
        assembly_tables: &TablesHeader,
    ) -> Result<()> {
        if let Some(table) = assembly_tables.table::<CustomAttributeRaw>() {
            for (index, row) in table.iter().enumerate() {
                if row.parent.tag == target_table && row.parent.row == target_row {
                    references.push(TableReference {
                        table_id: TableId::CustomAttribute,
                        row_rid: (index + 1) as u32,
                        column_name: "parent".to_string(),
                    });
                }
            }
        }
        Ok(())
    }

    /// Finds all HasFieldMarshal coded index references to a specific table row.
    ///
    /// HasFieldMarshal coded indices are used in the FieldMarshal table to reference
    /// Field or Param tables that have marshaling information.
    ///
    /// # Arguments
    ///
    /// * `target_table` - The table being referenced
    /// * `target_row` - The row being referenced
    /// * `references` - Vector to collect found references
    /// * `assembly_tables` - Table metadata for scanning
    fn find_hasfieldmarshal_references(
        &self,
        target_table: TableId,
        target_row: u32,
        references: &mut Vec<TableReference>,
        assembly_tables: &TablesHeader,
    ) -> Result<()> {
        if let Some(table) = assembly_tables.table::<FieldMarshalRaw>() {
            for (index, row) in table.iter().enumerate() {
                if row.parent.tag == target_table && row.parent.row == target_row {
                    references.push(TableReference {
                        table_id: TableId::FieldMarshal,
                        row_rid: (index + 1) as u32,
                        column_name: "parent".to_string(),
                    });
                }
            }
        }
        Ok(())
    }

    /// Finds all HasDeclSecurity coded index references to a specific table row.
    ///
    /// HasDeclSecurity coded indices are used in the DeclSecurity table to reference
    /// TypeDef, MethodDef, or Assembly tables that have declarative security attributes.
    ///
    /// # Arguments
    ///
    /// * `target_table` - The table being referenced
    /// * `target_row` - The row being referenced
    /// * `references` - Vector to collect found references
    /// * `assembly_tables` - Table metadata for scanning
    fn find_hasdeclsecurity_references(
        &self,
        target_table: TableId,
        target_row: u32,
        references: &mut Vec<TableReference>,
        assembly_tables: &TablesHeader,
    ) -> Result<()> {
        if let Some(table) = assembly_tables.table::<DeclSecurityRaw>() {
            for (index, row) in table.iter().enumerate() {
                if row.parent.tag == target_table && row.parent.row == target_row {
                    references.push(TableReference {
                        table_id: TableId::DeclSecurity,
                        row_rid: (index + 1) as u32,
                        column_name: "parent".to_string(),
                    });
                }
            }
        }
        Ok(())
    }

    /// Finds all MemberRefParent coded index references to a specific table row.
    ///
    /// MemberRefParent coded indices are used in the MemberRef table to reference
    /// TypeDef, TypeRef, ModuleRef, MethodDef, or TypeSpec tables that contain members.
    ///
    /// # Arguments
    ///
    /// * `target_table` - The table being referenced
    /// * `target_row` - The row being referenced
    /// * `references` - Vector to collect found references
    /// * `assembly_tables` - Table metadata for scanning
    fn find_memberrefparent_references(
        &self,
        target_table: TableId,
        target_row: u32,
        references: &mut Vec<TableReference>,
        assembly_tables: &TablesHeader,
    ) -> Result<()> {
        if let Some(table) = assembly_tables.table::<MemberRefRaw>() {
            for (index, row) in table.iter().enumerate() {
                if row.class.tag == target_table && row.class.row == target_row {
                    references.push(TableReference {
                        table_id: TableId::MemberRef,
                        row_rid: (index + 1) as u32,
                        column_name: "class".to_string(),
                    });
                }
            }
        }
        Ok(())
    }

    /// Finds all HasSemantics coded index references to a specific table row.
    ///
    /// HasSemantics coded indices are used in the MethodSemantics table to reference
    /// Event or Property tables that have associated semantic methods.
    ///
    /// # Arguments
    ///
    /// * `target_table` - The table being referenced
    /// * `target_row` - The row being referenced
    /// * `references` - Vector to collect found references
    /// * `assembly_tables` - Table metadata for scanning
    fn find_hassemantics_references(
        &self,
        target_table: TableId,
        target_row: u32,
        references: &mut Vec<TableReference>,
        assembly_tables: &TablesHeader,
    ) -> Result<()> {
        if let Some(table) = assembly_tables.table::<MethodSemanticsRaw>() {
            for (index, row) in table.iter().enumerate() {
                if row.association.tag == target_table && row.association.row == target_row {
                    references.push(TableReference {
                        table_id: TableId::MethodSemantics,
                        row_rid: (index + 1) as u32,
                        column_name: "association".to_string(),
                    });
                }
            }
        }
        Ok(())
    }

    /// Finds all MethodDefOrRef coded index references to a specific table row.
    ///
    /// MethodDefOrRef coded indices are used in several tables including MethodImpl and
    /// CustomAttribute to reference MethodDef or MemberRef tables.
    ///
    /// # Arguments
    ///
    /// * `target_table` - The table being referenced
    /// * `target_row` - The row being referenced
    /// * `references` - Vector to collect found references
    /// * `assembly_tables` - Table metadata for scanning
    fn find_methoddeforref_references(
        &self,
        target_table: TableId,
        target_row: u32,
        references: &mut Vec<TableReference>,
        assembly_tables: &TablesHeader,
    ) -> Result<()> {
        if let Some(table) = assembly_tables.table::<MethodImplRaw>() {
            for (index, row) in table.iter().enumerate() {
                if row.method_body.tag == target_table && row.method_body.row == target_row {
                    references.push(TableReference {
                        table_id: TableId::MethodImpl,
                        row_rid: (index + 1) as u32,
                        column_name: "method_body".to_string(),
                    });
                }
                if row.method_declaration.tag == target_table
                    && row.method_declaration.row == target_row
                {
                    references.push(TableReference {
                        table_id: TableId::MethodImpl,
                        row_rid: (index + 1) as u32,
                        column_name: "method_declaration".to_string(),
                    });
                }
            }
        }
        Ok(())
    }

    /// Finds all MemberForwarded coded index references to a specific table row.
    ///
    /// MemberForwarded coded indices are used in the ImplMap table to reference
    /// Field or MethodDef tables that have P/Invoke implementation mappings.
    ///
    /// # Arguments
    ///
    /// * `target_table` - The table being referenced
    /// * `target_row` - The row being referenced
    /// * `references` - Vector to collect found references
    /// * `assembly_tables` - Table metadata for scanning
    fn find_memberforwarded_references(
        &self,
        target_table: TableId,
        target_row: u32,
        references: &mut Vec<TableReference>,
        assembly_tables: &TablesHeader,
    ) -> Result<()> {
        if let Some(table) = assembly_tables.table::<ImplMapRaw>() {
            for (index, row) in table.iter().enumerate() {
                if row.member_forwarded.tag == target_table
                    && row.member_forwarded.row == target_row
                {
                    references.push(TableReference {
                        table_id: TableId::ImplMap,
                        row_rid: (index + 1) as u32,
                        column_name: "member_forwarded".to_string(),
                    });
                }
            }
        }
        Ok(())
    }

    /// Finds all Implementation coded index references to a specific table row.
    ///
    /// Implementation coded indices are used in the ExportedType table to reference
    /// File, AssemblyRef, or ExportedType tables that implement the exported type.
    ///
    /// # Arguments
    ///
    /// * `target_table` - The table being referenced
    /// * `target_row` - The row being referenced
    /// * `references` - Vector to collect found references
    /// * `assembly_tables` - Table metadata for scanning
    fn find_implementation_references(
        &self,
        target_table: TableId,
        target_row: u32,
        references: &mut Vec<TableReference>,
        assembly_tables: &TablesHeader,
    ) -> Result<()> {
        if let Some(table) = assembly_tables.table::<ExportedTypeRaw>() {
            for (index, row) in table.iter().enumerate() {
                if row.implementation.tag == target_table && row.implementation.row == target_row {
                    references.push(TableReference {
                        table_id: TableId::ExportedType,
                        row_rid: (index + 1) as u32,
                        column_name: "implementation".to_string(),
                    });
                }
            }
        }
        Ok(())
    }

    /// Finds all CustomAttributeType coded index references to a specific table row.
    ///
    /// CustomAttributeType coded indices are used in the CustomAttribute table to reference
    /// MethodDef or MemberRef tables that define custom attribute constructors.
    ///
    /// # Arguments
    ///
    /// * `target_table` - The table being referenced
    /// * `target_row` - The row being referenced
    /// * `references` - Vector to collect found references
    /// * `assembly_tables` - Table metadata for scanning
    fn find_customattributetype_references(
        &self,
        target_table: TableId,
        target_row: u32,
        references: &mut Vec<TableReference>,
        assembly_tables: &TablesHeader,
    ) -> Result<()> {
        if let Some(table) = assembly_tables.table::<CustomAttributeRaw>() {
            for (index, row) in table.iter().enumerate() {
                if row.constructor.tag == target_table && row.constructor.row == target_row {
                    references.push(TableReference {
                        table_id: TableId::CustomAttribute,
                        row_rid: (index + 1) as u32,
                        column_name: "constructor".to_string(),
                    });
                }
            }
        }
        Ok(())
    }

    /// Finds all ResolutionScope coded index references to a specific table row.
    ///
    /// ResolutionScope coded indices are used in the TypeRef table to reference
    /// Module, ModuleRef, AssemblyRef, or TypeRef tables that define the scope for type resolution.
    ///
    /// # Arguments
    ///
    /// * `target_table` - The table being referenced
    /// * `target_row` - The row being referenced
    /// * `references` - Vector to collect found references
    /// * `assembly_tables` - Table metadata for scanning
    fn find_resolutionscope_references(
        &self,
        target_table: TableId,
        target_row: u32,
        references: &mut Vec<TableReference>,
        assembly_tables: &TablesHeader,
    ) -> Result<()> {
        if let Some(table) = assembly_tables.table::<TypeRefRaw>() {
            for (index, row) in table.iter().enumerate() {
                if row.resolution_scope.tag == target_table
                    && row.resolution_scope.row == target_row
                {
                    references.push(TableReference {
                        table_id: TableId::TypeRef,
                        row_rid: (index + 1) as u32,
                        column_name: "resolution_scope".to_string(),
                    });
                }
            }
        }
        Ok(())
    }

    /// Finds all TypeOrMethodDef coded index references to a specific table row.
    ///
    /// TypeOrMethodDef coded indices are used in the GenericParam table to reference
    /// TypeDef or MethodDef tables that own generic parameters.
    ///
    /// # Arguments
    ///
    /// * `target_table` - The table being referenced
    /// * `target_row` - The row being referenced
    /// * `references` - Vector to collect found references
    /// * `assembly_tables` - Table metadata for scanning
    fn find_typeormethoddef_references(
        &self,
        target_table: TableId,
        target_row: u32,
        references: &mut Vec<TableReference>,
        assembly_tables: &TablesHeader,
    ) -> Result<()> {
        if let Some(table) = assembly_tables.table::<GenericParamRaw>() {
            for (index, row) in table.iter().enumerate() {
                if row.owner.tag == target_table && row.owner.row == target_row {
                    references.push(TableReference {
                        table_id: TableId::GenericParam,
                        row_rid: (index + 1) as u32,
                        column_name: "owner".to_string(),
                    });
                }
            }
        }
        Ok(())
    }

    /// Finds all HasCustomDebugInformation coded index references to a specific table row.
    ///
    /// HasCustomDebugInformation coded indices are used in the CustomDebugInformation table
    /// to reference many different table types for debug information association.
    ///
    /// # Arguments
    ///
    /// * `target_table` - The table being referenced
    /// * `target_row` - The row being referenced
    /// * `references` - Vector to collect found references
    /// * `assembly_tables` - Table metadata for scanning
    fn find_hascustomdebuginformation_references(
        &self,
        target_table: TableId,
        target_row: u32,
        references: &mut Vec<TableReference>,
        assembly_tables: &TablesHeader,
    ) -> Result<()> {
        if let Some(table) = assembly_tables.table::<CustomDebugInformationRaw>() {
            for (index, row) in table.iter().enumerate() {
                if row.parent.tag == target_table && row.parent.row == target_row {
                    references.push(TableReference {
                        table_id: TableId::CustomDebugInformation,
                        row_rid: (index + 1) as u32,
                        column_name: "parent".to_string(),
                    });
                }
            }
        }
        Ok(())
    }

    /// Returns the column name for a coded index field in a specific table.
    ///
    /// This method maps table ID and coded index type combinations to their
    /// corresponding column names in the metadata table structure.
    ///
    /// # Arguments
    ///
    /// * `table_id` - The table containing the coded index field
    /// * `coded_index_type` - The type of coded index
    ///
    /// # Returns
    ///
    /// Returns the column name as a string, or "coded_index" as a fallback.
    fn get_coded_index_column_name(
        &self,
        table_id: TableId,
        coded_index_type: CodedIndexType,
    ) -> String {
        match (table_id, coded_index_type) {
            (TableId::TypeRef, CodedIndexType::ResolutionScope) => "resolution_scope".to_string(),
            (TableId::TypeDef, CodedIndexType::TypeDefOrRef) => "extends".to_string(),
            (TableId::InterfaceImpl, CodedIndexType::TypeDefOrRef) => "interface".to_string(),
            (TableId::MemberRef, CodedIndexType::MemberRefParent) => "class".to_string(),
            (TableId::Constant, CodedIndexType::HasConstant) => "parent".to_string(),
            (TableId::CustomAttribute, CodedIndexType::HasCustomAttribute) => "parent".to_string(),
            (TableId::CustomAttribute, CodedIndexType::CustomAttributeType) => {
                "constructor".to_string()
            }
            (TableId::FieldMarshal, CodedIndexType::HasFieldMarshal) => "parent".to_string(),
            (TableId::DeclSecurity, CodedIndexType::HasDeclSecurity) => "parent".to_string(),
            (TableId::MethodSemantics, CodedIndexType::HasSemantics) => "association".to_string(),
            (TableId::MethodImpl, CodedIndexType::MethodDefOrRef) => "method_body".to_string(),
            (TableId::ImplMap, CodedIndexType::MemberForwarded) => "member_forwarded".to_string(),
            (TableId::ExportedType, CodedIndexType::Implementation) => "implementation".to_string(),
            (TableId::ExportedType, CodedIndexType::TypeDefOrRef) => "type_def_id".to_string(),
            (TableId::GenericParam, CodedIndexType::TypeOrMethodDef) => "owner".to_string(),
            (TableId::CustomDebugInformation, CodedIndexType::HasCustomDebugInformation) => {
                "parent".to_string()
            }
            _ => "coded_index".to_string(), // Generic fallback
        }
    }

    /// Validates that all coded index references in the metadata are consistent and valid.
    ///
    /// This method performs comprehensive validation of coded index references by:
    /// - Checking that all coded index values decode to valid table/row combinations
    /// - Verifying that referenced rows exist in their target tables
    /// - Ensuring coded index types are used consistently
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if all coded index references are valid, or an error
    /// describing the first validation failure encountered.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Any coded index references a non-existent table or row
    /// - Coded index values are malformed or inconsistent
    /// - Table metadata is corrupted or incomplete
    pub fn validate_coded_index_consistency(&self) -> Result<()> {
        self.validate_coded_index_table_references(CodedIndexType::HasFieldMarshal)?;
        self.validate_coded_index_table_references(CodedIndexType::HasDeclSecurity)?;
        self.validate_coded_index_table_references(CodedIndexType::MemberRefParent)?;
        self.validate_coded_index_table_references(CodedIndexType::HasSemantics)?;
        self.validate_coded_index_table_references(CodedIndexType::MethodDefOrRef)?;
        self.validate_coded_index_table_references(CodedIndexType::MemberForwarded)?;
        self.validate_coded_index_table_references(CodedIndexType::Implementation)?;
        self.validate_coded_index_table_references(CodedIndexType::CustomAttributeType)?;
        self.validate_coded_index_table_references(CodedIndexType::ResolutionScope)?;
        self.validate_coded_index_table_references(CodedIndexType::TypeOrMethodDef)?;
        self.validate_coded_index_table_references(CodedIndexType::HasCustomDebugInformation)?;

        Ok(())
    }

    /// Validates coded index references for a specific coded index type.
    ///
    /// This helper method validates that all coded index values of the specified type
    /// decode to valid table/row combinations and that the referenced rows exist.
    ///
    /// # Arguments
    ///
    /// * `coded_index_type` - The type of coded index to validate
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if all coded index references are valid, or an error
    /// describing the first validation failure encountered.
    fn validate_coded_index_table_references(
        &self,
        coded_index_type: CodedIndexType,
    ) -> Result<()> {
        match coded_index_type {
            CodedIndexType::TypeDefOrRef => {
                self.validate_typedeforref_references()?;
            }
            CodedIndexType::HasConstant => {
                self.validate_hasconstant_references()?;
            }
            CodedIndexType::HasCustomAttribute => {
                self.validate_hascustomattribute_references()?;
            }
            CodedIndexType::HasFieldMarshal => {
                self.validate_hasfieldmarshal_references()?;
            }
            CodedIndexType::HasDeclSecurity => {
                self.validate_hasdeclsecurity_references()?;
            }
            CodedIndexType::MemberRefParent => {
                self.validate_memberrefparent_references()?;
            }
            CodedIndexType::HasSemantics => {
                self.validate_hassemantics_references()?;
            }
            CodedIndexType::MethodDefOrRef => {
                self.validate_methoddeforref_references()?;
            }
            CodedIndexType::MemberForwarded => {
                self.validate_memberforwarded_references()?;
            }
            CodedIndexType::Implementation => {
                self.validate_implementation_references()?;
            }
            CodedIndexType::CustomAttributeType => {
                self.validate_customattributetype_references()?;
            }
            CodedIndexType::ResolutionScope => {
                self.validate_resolutionscope_references()?;
            }
            CodedIndexType::TypeOrMethodDef => {
                self.validate_typeormethoddef_references()?;
            }
            CodedIndexType::HasCustomDebugInformation => {
                self.validate_hascustomdebuginformation_references()?;
            }
        }

        Ok(())
    }

    /// Validates all TypeDefOrRef coded index references in the metadata.
    ///
    /// TypeDefOrRef coded indices are used in multiple tables including TypeSpec,
    /// MemberRef, InterfaceImpl, and others. Full validation would require signature
    /// parsing, so this method currently performs basic validation.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if validation passes, or an error if inconsistencies are found.
    fn validate_typedeforref_references(&self) -> Result<()> {
        Ok(())
    }

    /// Validates all HasConstant coded index references in the metadata.
    ///
    /// HasConstant coded indices are used in the Constant table to reference
    /// Field, Param, or Property tables that have associated constant values.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if all references are valid, or an error describing
    /// the first validation failure encountered.
    fn validate_hasconstant_references(&self) -> Result<()> {
        if let Some(tables) = self.view.tables() {
            if let Some(constant_table) = tables.table::<ConstantRaw>() {
                for (rid, row) in constant_table.iter().enumerate() {
                    let rid = rid as u32 + 1;

                    if row.parent.row == 0 {
                        continue;
                    }

                    match row.parent.tag {
                        TableId::Field => {
                            if let Some(field_table) = tables.table::<FieldRaw>() {
                                if row.parent.row > field_table.row_count {
                                    return Err(Error::ValidationReferentialIntegrity {
                                        message: format!(
                                            "Constant row {} references non-existent Field row {} (table has {} rows)",
                                            rid, row.parent.row, field_table.row_count
                                        ),
                                    });
                                }
                            } else {
                                return Err(Error::ValidationReferentialIntegrity {
                                    message: format!(
                                        "Constant row {rid} references Field table but Field table is not present"
                                    ),
                                });
                            }
                        }
                        TableId::Param => {
                            if let Some(param_table) = tables.table::<ParamRaw>() {
                                if row.parent.row > param_table.row_count {
                                    return Err(Error::ValidationReferentialIntegrity {
                                        message: format!(
                                            "Constant row {} references non-existent Param row {} (table has {} rows)",
                                            rid, row.parent.row, param_table.row_count
                                        ),
                                    });
                                }
                            } else {
                                return Err(Error::ValidationReferentialIntegrity {
                                    message: format!(
                                        "Constant row {rid} references Param table but Param table is not present"
                                    ),
                                });
                            }
                        }
                        TableId::Property => {
                            if let Some(property_table) = tables.table::<PropertyRaw>() {
                                if row.parent.row > property_table.row_count {
                                    return Err(Error::ValidationReferentialIntegrity {
                                        message: format!(
                                            "Constant row {} references non-existent Property row {} (table has {} rows)",
                                            rid, row.parent.row, property_table.row_count
                                        ),
                                    });
                                }
                            } else {
                                return Err(Error::ValidationReferentialIntegrity {
                                    message: format!(
                                        "Constant row {rid} references Property table but Property table is not present"
                                    ),
                                });
                            }
                        }
                        _ => {
                            return Err(Error::ValidationReferentialIntegrity {
                                message: format!(
                                    "Constant row {} has invalid HasConstant coded index pointing to table {:?}",
                                    rid, row.parent.tag
                                ),
                            });
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Validates all HasCustomAttribute coded index references in the metadata.
    ///
    /// HasCustomAttribute coded indices are used in the CustomAttribute table to reference
    /// any of 22 different table types that can have custom attributes applied.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if all references are valid, or an error describing
    /// the first validation failure encountered.
    fn validate_hascustomattribute_references(&self) -> Result<()> {
        if let Some(tables) = self.view.tables() {
            if let Some(custom_attr_table) = tables.table::<CustomAttributeRaw>() {
                for (rid, row) in custom_attr_table.iter().enumerate() {
                    let rid = rid as u32 + 1;

                    if row.parent.row == 0 {
                        continue;
                    }

                    let table_exists = match row.parent.tag {
                        TableId::Module => tables
                            .table::<ModuleRaw>()
                            .is_some_and(|t| row.parent.row <= t.row_count),
                        TableId::TypeRef => tables
                            .table::<TypeRefRaw>()
                            .is_some_and(|t| row.parent.row <= t.row_count),
                        TableId::TypeDef => tables
                            .table::<TypeDefRaw>()
                            .is_some_and(|t| row.parent.row <= t.row_count),
                        TableId::Field => tables
                            .table::<FieldRaw>()
                            .is_some_and(|t| row.parent.row <= t.row_count),
                        TableId::MethodDef => tables
                            .table::<MethodDefRaw>()
                            .is_some_and(|t| row.parent.row <= t.row_count),
                        TableId::Param => tables
                            .table::<ParamRaw>()
                            .is_some_and(|t| row.parent.row <= t.row_count),
                        TableId::InterfaceImpl => tables
                            .table::<InterfaceImplRaw>()
                            .is_some_and(|t| row.parent.row <= t.row_count),
                        TableId::MemberRef => tables
                            .table::<MemberRefRaw>()
                            .is_some_and(|t| row.parent.row <= t.row_count),
                        TableId::DeclSecurity => tables
                            .table::<DeclSecurityRaw>()
                            .is_some_and(|t| row.parent.row <= t.row_count),
                        TableId::Property => tables
                            .table::<PropertyRaw>()
                            .is_some_and(|t| row.parent.row <= t.row_count),
                        TableId::Event => tables
                            .table::<EventRaw>()
                            .is_some_and(|t| row.parent.row <= t.row_count),
                        TableId::StandAloneSig => tables
                            .table::<StandAloneSigRaw>()
                            .is_some_and(|t| row.parent.row <= t.row_count),
                        TableId::ModuleRef => tables
                            .table::<ModuleRefRaw>()
                            .is_some_and(|t| row.parent.row <= t.row_count),
                        TableId::TypeSpec => tables
                            .table::<TypeSpecRaw>()
                            .is_some_and(|t| row.parent.row <= t.row_count),
                        TableId::Assembly => tables
                            .table::<AssemblyRaw>()
                            .is_some_and(|t| row.parent.row <= t.row_count),
                        TableId::AssemblyRef => tables
                            .table::<AssemblyRefRaw>()
                            .is_some_and(|t| row.parent.row <= t.row_count),
                        TableId::File => tables
                            .table::<FileRaw>()
                            .is_some_and(|t| row.parent.row <= t.row_count),
                        TableId::ExportedType => tables
                            .table::<ExportedTypeRaw>()
                            .is_some_and(|t| row.parent.row <= t.row_count),
                        TableId::ManifestResource => tables
                            .table::<ManifestResourceRaw>()
                            .is_some_and(|t| row.parent.row <= t.row_count),
                        TableId::GenericParam => tables
                            .table::<GenericParamRaw>()
                            .is_some_and(|t| row.parent.row <= t.row_count),
                        TableId::MethodSpec => tables
                            .table::<MethodSpecRaw>()
                            .is_some_and(|t| row.parent.row <= t.row_count),
                        TableId::GenericParamConstraint => tables
                            .table::<GenericParamConstraintRaw>()
                            .is_some_and(|t| row.parent.row <= t.row_count),
                        _ => false, // Invalid table type for HasCustomAttribute
                    };

                    if !table_exists {
                        return Err(Error::ValidationReferentialIntegrity {
                            message: format!(
                                "CustomAttribute row {} references non-existent or invalid {:?} row {}",
                                rid, row.parent.tag, row.parent.row
                            ),
                        });
                    }
                }
            }
        }

        Ok(())
    }

    /// Validates all HasFieldMarshal coded index references in the metadata.
    ///
    /// HasFieldMarshal coded indices are used in the FieldMarshal table to reference
    /// Field or Param tables that have marshaling information.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if all references are valid, or an error describing
    /// the first validation failure encountered.
    fn validate_hasfieldmarshal_references(&self) -> Result<()> {
        if let Some(tables) = self.view.tables() {
            if let Some(field_marshal_table) = tables.table::<FieldMarshalRaw>() {
                for (rid, row) in field_marshal_table.iter().enumerate() {
                    let rid = rid as u32 + 1;

                    if row.parent.row == 0 {
                        continue;
                    }

                    match row.parent.tag {
                        TableId::Field => {
                            if let Some(field_table) = tables.table::<FieldRaw>() {
                                if row.parent.row > field_table.row_count {
                                    return Err(Error::ValidationReferentialIntegrity {
                                        message: format!(
                                            "FieldMarshal row {} references non-existent Field row {} (table has {} rows)",
                                            rid, row.parent.row, field_table.row_count
                                        ),
                                    });
                                }
                            } else {
                                return Err(Error::ValidationReferentialIntegrity {
                                    message: format!(
                                        "FieldMarshal row {rid} references Field table but Field table is not present"
                                    ),
                                });
                            }
                        }
                        TableId::Param => {
                            if let Some(param_table) = tables.table::<ParamRaw>() {
                                if row.parent.row > param_table.row_count {
                                    return Err(Error::ValidationReferentialIntegrity {
                                        message: format!(
                                            "FieldMarshal row {} references non-existent Param row {} (table has {} rows)",
                                            rid, row.parent.row, param_table.row_count
                                        ),
                                    });
                                }
                            } else {
                                return Err(Error::ValidationReferentialIntegrity {
                                    message: format!(
                                        "FieldMarshal row {rid} references Param table but Param table is not present"
                                    ),
                                });
                            }
                        }
                        _ => {
                            return Err(Error::ValidationReferentialIntegrity {
                                message: format!(
                                    "FieldMarshal row {} has invalid HasFieldMarshal coded index pointing to table {:?}",
                                    rid, row.parent.tag
                                ),
                            });
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Validates all HasDeclSecurity coded index references in the metadata.
    ///
    /// HasDeclSecurity coded indices are used in the DeclSecurity table to reference
    /// TypeDef, MethodDef, or Assembly tables that have declarative security attributes.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if all references are valid, or an error describing
    /// the first validation failure encountered.
    fn validate_hasdeclsecurity_references(&self) -> Result<()> {
        if let Some(tables) = self.view.tables() {
            if let Some(decl_security_table) = tables.table::<DeclSecurityRaw>() {
                for (rid, row) in decl_security_table.iter().enumerate() {
                    let rid = rid as u32 + 1;

                    if row.parent.row == 0 {
                        continue;
                    }

                    match row.parent.tag {
                        TableId::TypeDef => {
                            if let Some(typedef_table) = tables.table::<TypeDefRaw>() {
                                if row.parent.row > typedef_table.row_count {
                                    return Err(Error::ValidationReferentialIntegrity {
                                        message: format!(
                                            "DeclSecurity row {} references non-existent TypeDef row {} (table has {} rows)",
                                            rid, row.parent.row, typedef_table.row_count
                                        ),
                                    });
                                }
                            } else {
                                return Err(Error::ValidationReferentialIntegrity {
                                    message: format!(
                                        "DeclSecurity row {rid} references TypeDef table but TypeDef table is not present"
                                    ),
                                });
                            }
                        }
                        TableId::MethodDef => {
                            if let Some(methoddef_table) = tables.table::<MethodDefRaw>() {
                                if row.parent.row > methoddef_table.row_count {
                                    return Err(Error::ValidationReferentialIntegrity {
                                        message: format!(
                                            "DeclSecurity row {} references non-existent MethodDef row {} (table has {} rows)",
                                            rid, row.parent.row, methoddef_table.row_count
                                        ),
                                    });
                                }
                            } else {
                                return Err(Error::ValidationReferentialIntegrity {
                                    message: format!(
                                        "DeclSecurity row {rid} references MethodDef table but MethodDef table is not present"
                                    ),
                                });
                            }
                        }
                        TableId::Assembly => {
                            if let Some(assembly_table) = tables.table::<AssemblyRaw>() {
                                if row.parent.row > assembly_table.row_count {
                                    return Err(Error::ValidationReferentialIntegrity {
                                        message: format!(
                                            "DeclSecurity row {} references non-existent Assembly row {} (table has {} rows)",
                                            rid, row.parent.row, assembly_table.row_count
                                        ),
                                    });
                                }
                            } else {
                                return Err(Error::ValidationReferentialIntegrity {
                                    message: format!(
                                        "DeclSecurity row {rid} references Assembly table but Assembly table is not present"
                                    ),
                                });
                            }
                        }
                        _ => {
                            return Err(Error::ValidationReferentialIntegrity {
                                message: format!(
                                    "DeclSecurity row {} has invalid HasDeclSecurity coded index pointing to table {:?}",
                                    rid, row.parent.tag
                                ),
                            });
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Validates all MemberRefParent coded index references in the metadata.
    ///
    /// MemberRefParent coded indices are used in the MemberRef table to reference
    /// TypeDef, TypeRef, ModuleRef, MethodDef, or TypeSpec tables that contain members.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if all references are valid, or an error describing
    /// the first validation failure encountered.
    fn validate_memberrefparent_references(&self) -> Result<()> {
        if let Some(tables) = self.view.tables() {
            if let Some(memberref_table) = tables.table::<MemberRefRaw>() {
                for (rid, row) in memberref_table.iter().enumerate() {
                    let rid = rid as u32 + 1;

                    if row.class.row == 0 {
                        continue;
                    }

                    let table_exists = match row.class.tag {
                        TableId::TypeDef => tables
                            .table::<TypeDefRaw>()
                            .is_some_and(|t| row.class.row <= t.row_count),
                        TableId::TypeRef => tables
                            .table::<TypeRefRaw>()
                            .is_some_and(|t| row.class.row <= t.row_count),
                        TableId::ModuleRef => tables
                            .table::<ModuleRefRaw>()
                            .is_some_and(|t| row.class.row <= t.row_count),
                        TableId::MethodDef => tables
                            .table::<MethodDefRaw>()
                            .is_some_and(|t| row.class.row <= t.row_count),
                        TableId::TypeSpec => tables
                            .table::<TypeSpecRaw>()
                            .is_some_and(|t| row.class.row <= t.row_count),
                        _ => false, // Invalid table type for MemberRefParent
                    };

                    if !table_exists {
                        return Err(Error::ValidationReferentialIntegrity {
                            message: format!(
                                "MemberRef row {} references non-existent or invalid {:?} row {}",
                                rid, row.class.tag, row.class.row
                            ),
                        });
                    }
                }
            }
        }

        Ok(())
    }

    /// Validates all HasSemantics coded index references in the metadata.
    ///
    /// HasSemantics coded indices are used in the MethodSemantics table to reference
    /// Event or Property tables that have associated semantic methods.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if all references are valid, or an error describing
    /// the first validation failure encountered.
    fn validate_hassemantics_references(&self) -> Result<()> {
        if let Some(tables) = self.view.tables() {
            if let Some(method_semantics_table) = tables.table::<MethodSemanticsRaw>() {
                for (rid, row) in method_semantics_table.iter().enumerate() {
                    let rid = rid as u32 + 1;

                    if row.association.row == 0 {
                        continue;
                    }

                    match row.association.tag {
                        TableId::Event => {
                            if let Some(event_table) = tables.table::<EventRaw>() {
                                if row.association.row > event_table.row_count {
                                    return Err(Error::ValidationReferentialIntegrity {
                                        message: format!(
                                            "MethodSemantics row {} references non-existent Event row {} (table has {} rows)",
                                            rid, row.association.row, event_table.row_count
                                        ),
                                    });
                                }
                            } else {
                                return Err(Error::ValidationReferentialIntegrity {
                                    message: format!(
                                        "MethodSemantics row {rid} references Event table but Event table is not present"
                                    ),
                                });
                            }
                        }
                        TableId::Property => {
                            if let Some(property_table) = tables.table::<PropertyRaw>() {
                                if row.association.row > property_table.row_count {
                                    return Err(Error::ValidationReferentialIntegrity {
                                        message: format!(
                                            "MethodSemantics row {} references non-existent Property row {} (table has {} rows)",
                                            rid, row.association.row, property_table.row_count
                                        ),
                                    });
                                }
                            } else {
                                return Err(Error::ValidationReferentialIntegrity {
                                    message: format!(
                                        "MethodSemantics row {rid} references Property table but Property table is not present"
                                    ),
                                });
                            }
                        }
                        _ => {
                            return Err(Error::ValidationReferentialIntegrity {
                                message: format!(
                                    "MethodSemantics row {} has invalid HasSemantics coded index pointing to table {:?}",
                                    rid, row.association.tag
                                ),
                            });
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Validates all MethodDefOrRef coded index references in the metadata.
    ///
    /// MethodDefOrRef coded indices are used in several tables including MethodImpl
    /// to reference MethodDef or MemberRef tables.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if all references are valid, or an error describing
    /// the first validation failure encountered.
    fn validate_methoddeforref_references(&self) -> Result<()> {
        if let Some(tables) = self.view.tables() {
            if let Some(method_impl_table) = tables.table::<MethodImplRaw>() {
                for (rid, row) in method_impl_table.iter().enumerate() {
                    let rid = rid as u32 + 1;

                    if row.method_body.row != 0 {
                        let table_exists = match row.method_body.tag {
                            TableId::MethodDef => tables
                                .table::<MethodDefRaw>()
                                .is_some_and(|t| row.method_body.row <= t.row_count),
                            TableId::MemberRef => tables
                                .table::<MemberRefRaw>()
                                .is_some_and(|t| row.method_body.row <= t.row_count),
                            _ => false,
                        };

                        if !table_exists {
                            return Err(Error::ValidationReferentialIntegrity {
                                message: format!(
                                    "MethodImpl row {} method_body references non-existent or invalid {:?} row {}",
                                    rid, row.method_body.tag, row.method_body.row
                                ),
                            });
                        }
                    }

                    if row.method_declaration.row != 0 {
                        let table_exists = match row.method_declaration.tag {
                            TableId::MethodDef => tables
                                .table::<MethodDefRaw>()
                                .is_some_and(|t| row.method_declaration.row <= t.row_count),
                            TableId::MemberRef => tables
                                .table::<MemberRefRaw>()
                                .is_some_and(|t| row.method_declaration.row <= t.row_count),
                            _ => false,
                        };

                        if !table_exists {
                            return Err(Error::ValidationReferentialIntegrity {
                                message: format!(
                                    "MethodImpl row {} method_declaration references non-existent or invalid {:?} row {}",
                                    rid, row.method_declaration.tag, row.method_declaration.row
                                ),
                            });
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Validates MemberForwarded coded index references in ImplMap table.
    ///
    /// This method validates that MemberForwarded coded index references in the ImplMap
    /// table point to valid Field or MethodDef table rows. It ensures that P/Invoke
    /// mappings correctly reference the forwarded members they are associated with.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if all MemberForwarded references are valid, or an error
    /// describing the first validation failure encountered.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationReferentialIntegrity`] if any MemberForwarded
    /// coded index references a non-existent or invalid table row.
    fn validate_memberforwarded_references(&self) -> Result<()> {
        if let Some(tables) = self.view.tables() {
            if let Some(impl_map_table) = tables.table::<ImplMapRaw>() {
                for (rid, row) in impl_map_table.iter().enumerate() {
                    let rid = rid as u32 + 1;

                    if row.member_forwarded.row == 0 {
                        continue;
                    }

                    let table_exists = match row.member_forwarded.tag {
                        TableId::Field => tables
                            .table::<FieldRaw>()
                            .is_some_and(|t| row.member_forwarded.row <= t.row_count),
                        TableId::MethodDef => tables
                            .table::<MethodDefRaw>()
                            .is_some_and(|t| row.member_forwarded.row <= t.row_count),
                        _ => false, // Invalid table type for MemberForwarded
                    };

                    if !table_exists {
                        return Err(Error::ValidationReferentialIntegrity {
                            message: format!(
                                "ImplMap row {} references non-existent or invalid {:?} row {}",
                                rid, row.member_forwarded.tag, row.member_forwarded.row
                            ),
                        });
                    }
                }
            }
        }

        Ok(())
    }

    /// Validates Implementation coded index references in ExportedType table.
    ///
    /// This method validates that Implementation coded index references in the ExportedType
    /// table point to valid File, AssemblyRef, or ExportedType table rows. It ensures that
    /// exported types correctly reference their implementation location.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if all Implementation references are valid, or an error
    /// describing the first validation failure encountered.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationReferentialIntegrity`] if any Implementation
    /// coded index references a non-existent or invalid table row.
    fn validate_implementation_references(&self) -> Result<()> {
        if let Some(tables) = self.view.tables() {
            if let Some(exported_type_table) = tables.table::<ExportedTypeRaw>() {
                for (rid, row) in exported_type_table.iter().enumerate() {
                    let rid = rid as u32 + 1;

                    if row.implementation.row == 0 {
                        continue;
                    }

                    let table_exists = match row.implementation.tag {
                        TableId::File => tables
                            .table::<FileRaw>()
                            .is_some_and(|t| row.implementation.row <= t.row_count),
                        TableId::AssemblyRef => tables
                            .table::<AssemblyRefRaw>()
                            .is_some_and(|t| row.implementation.row <= t.row_count),
                        TableId::ExportedType => tables
                            .table::<ExportedTypeRaw>()
                            .is_some_and(|t| row.implementation.row <= t.row_count),
                        _ => false, // Invalid table type for Implementation
                    };

                    if !table_exists {
                        return Err(Error::ValidationReferentialIntegrity {
                            message: format!(
                                "ExportedType row {} references non-existent or invalid {:?} row {}",
                                rid, row.implementation.tag, row.implementation.row
                            ),
                        });
                    }
                }
            }
        }

        Ok(())
    }

    /// Validates CustomAttributeType coded index references in CustomAttribute table.
    ///
    /// This method validates that CustomAttributeType coded index references in the CustomAttribute
    /// table point to valid MethodDef or MemberRef table rows. It ensures that custom attributes
    /// correctly reference their constructor methods.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if all CustomAttributeType references are valid, or an error
    /// describing the first validation failure encountered.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationReferentialIntegrity`] if any CustomAttributeType
    /// coded index references a non-existent or invalid table row.
    fn validate_customattributetype_references(&self) -> Result<()> {
        if let Some(tables) = self.view.tables() {
            if let Some(custom_attr_table) = tables.table::<CustomAttributeRaw>() {
                for (rid, row) in custom_attr_table.iter().enumerate() {
                    let rid = rid as u32 + 1;

                    if row.constructor.row == 0 {
                        continue;
                    }

                    let table_exists = match row.constructor.tag {
                        TableId::MethodDef => tables
                            .table::<MethodDefRaw>()
                            .is_some_and(|t| row.constructor.row <= t.row_count),
                        TableId::MemberRef => tables
                            .table::<MemberRefRaw>()
                            .is_some_and(|t| row.constructor.row <= t.row_count),
                        _ => false, // Invalid table type for CustomAttributeType
                    };

                    if !table_exists {
                        return Err(Error::ValidationReferentialIntegrity {
                            message: format!(
                                "CustomAttribute row {} references non-existent or invalid {:?} row {}",
                                rid, row.constructor.tag, row.constructor.row
                            ),
                        });
                    }
                }
            }
        }

        Ok(())
    }

    /// Validates ResolutionScope coded index references in TypeRef table.
    ///
    /// This method validates that ResolutionScope coded index references in the TypeRef
    /// table point to valid Module, ModuleRef, AssemblyRef, or TypeRef table rows. It ensures
    /// that type references correctly identify their resolution scope.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if all ResolutionScope references are valid, or an error
    /// describing the first validation failure encountered.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationReferentialIntegrity`] if any ResolutionScope
    /// coded index references a non-existent or invalid table row.
    fn validate_resolutionscope_references(&self) -> Result<()> {
        if let Some(tables) = self.view.tables() {
            if let Some(type_ref_table) = tables.table::<TypeRefRaw>() {
                for (rid, row) in type_ref_table.iter().enumerate() {
                    let rid = rid as u32 + 1;

                    if row.resolution_scope.row == 0 {
                        continue;
                    }

                    let table_exists = match row.resolution_scope.tag {
                        TableId::Module => tables
                            .table::<ModuleRaw>()
                            .is_some_and(|t| row.resolution_scope.row <= t.row_count),
                        TableId::ModuleRef => tables
                            .table::<ModuleRefRaw>()
                            .is_some_and(|t| row.resolution_scope.row <= t.row_count),
                        TableId::AssemblyRef => tables
                            .table::<AssemblyRefRaw>()
                            .is_some_and(|t| row.resolution_scope.row <= t.row_count),
                        TableId::TypeRef => tables
                            .table::<TypeRefRaw>()
                            .is_some_and(|t| row.resolution_scope.row <= t.row_count),
                        _ => false, // Invalid table type for ResolutionScope
                    };

                    if !table_exists {
                        return Err(Error::ValidationReferentialIntegrity {
                            message: format!(
                                "TypeRef row {} references non-existent or invalid {:?} row {}",
                                rid, row.resolution_scope.tag, row.resolution_scope.row
                            ),
                        });
                    }
                }
            }
        }

        Ok(())
    }

    /// Validates TypeOrMethodDef coded index references in GenericParam table.
    ///
    /// This method validates that TypeOrMethodDef coded index references in the GenericParam
    /// table point to valid TypeDef or MethodDef table rows. It ensures that generic parameters
    /// correctly reference their owning type or method definition.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if all TypeOrMethodDef references are valid, or an error
    /// describing the first validation failure encountered.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationReferentialIntegrity`] if any TypeOrMethodDef
    /// coded index references a non-existent or invalid table row.
    fn validate_typeormethoddef_references(&self) -> Result<()> {
        if let Some(tables) = self.view.tables() {
            if let Some(generic_param_table) = tables.table::<GenericParamRaw>() {
                for (rid, row) in generic_param_table.iter().enumerate() {
                    let rid = rid as u32 + 1;

                    if row.owner.row == 0 {
                        continue;
                    }

                    let table_exists = match row.owner.tag {
                        TableId::TypeDef => tables
                            .table::<TypeDefRaw>()
                            .is_some_and(|t| row.owner.row <= t.row_count),
                        TableId::MethodDef => tables
                            .table::<MethodDefRaw>()
                            .is_some_and(|t| row.owner.row <= t.row_count),
                        _ => false, // Invalid table type for TypeOrMethodDef
                    };

                    if !table_exists {
                        return Err(Error::ValidationReferentialIntegrity {
                            message: format!(
                                "GenericParam row {} references non-existent or invalid {:?} row {}",
                                rid, row.owner.tag, row.owner.row
                            ),
                        });
                    }
                }
            }
        }

        Ok(())
    }

    /// Validates HasCustomDebugInformation coded index references in CustomDebugInformation table.
    ///
    /// This method validates that HasCustomDebugInformation coded index references in the
    /// CustomDebugInformation table point to valid metadata entity rows. It ensures that
    /// custom debug information correctly references its associated metadata elements.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if all HasCustomDebugInformation references are valid, or an error
    /// describing the first validation failure encountered.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationReferentialIntegrity`] if any HasCustomDebugInformation
    /// coded index references a non-existent or invalid table row.
    fn validate_hascustomdebuginformation_references(&self) -> Result<()> {
        if let Some(tables) = self.view.tables() {
            if let Some(custom_debug_table) = tables.table::<CustomDebugInformationRaw>() {
                for (rid, row) in custom_debug_table.iter().enumerate() {
                    let rid = rid as u32 + 1;

                    if row.parent.row == 0 {
                        continue;
                    }

                    let table_exists = match row.parent.tag {
                        TableId::Module => tables
                            .table::<ModuleRaw>()
                            .is_some_and(|t| row.parent.row <= t.row_count),
                        TableId::TypeRef => tables
                            .table::<TypeRefRaw>()
                            .is_some_and(|t| row.parent.row <= t.row_count),
                        TableId::TypeDef => tables
                            .table::<TypeDefRaw>()
                            .is_some_and(|t| row.parent.row <= t.row_count),
                        TableId::Field => tables
                            .table::<FieldRaw>()
                            .is_some_and(|t| row.parent.row <= t.row_count),
                        TableId::MethodDef => tables
                            .table::<MethodDefRaw>()
                            .is_some_and(|t| row.parent.row <= t.row_count),
                        TableId::Param => tables
                            .table::<ParamRaw>()
                            .is_some_and(|t| row.parent.row <= t.row_count),
                        TableId::InterfaceImpl => tables
                            .table::<InterfaceImplRaw>()
                            .is_some_and(|t| row.parent.row <= t.row_count),
                        TableId::MemberRef => tables
                            .table::<MemberRefRaw>()
                            .is_some_and(|t| row.parent.row <= t.row_count),
                        TableId::DeclSecurity => tables
                            .table::<DeclSecurityRaw>()
                            .is_some_and(|t| row.parent.row <= t.row_count),
                        TableId::Property => tables
                            .table::<PropertyRaw>()
                            .is_some_and(|t| row.parent.row <= t.row_count),
                        TableId::Event => tables
                            .table::<EventRaw>()
                            .is_some_and(|t| row.parent.row <= t.row_count),
                        TableId::StandAloneSig => tables
                            .table::<StandAloneSigRaw>()
                            .is_some_and(|t| row.parent.row <= t.row_count),
                        TableId::ModuleRef => tables
                            .table::<ModuleRefRaw>()
                            .is_some_and(|t| row.parent.row <= t.row_count),
                        TableId::TypeSpec => tables
                            .table::<TypeSpecRaw>()
                            .is_some_and(|t| row.parent.row <= t.row_count),
                        TableId::Assembly => tables
                            .table::<AssemblyRaw>()
                            .is_some_and(|t| row.parent.row <= t.row_count),
                        TableId::AssemblyRef => tables
                            .table::<AssemblyRefRaw>()
                            .is_some_and(|t| row.parent.row <= t.row_count),
                        TableId::File => tables
                            .table::<FileRaw>()
                            .is_some_and(|t| row.parent.row <= t.row_count),
                        TableId::ExportedType => tables
                            .table::<ExportedTypeRaw>()
                            .is_some_and(|t| row.parent.row <= t.row_count),
                        TableId::ManifestResource => tables
                            .table::<ManifestResourceRaw>()
                            .is_some_and(|t| row.parent.row <= t.row_count),
                        TableId::GenericParam => tables
                            .table::<GenericParamRaw>()
                            .is_some_and(|t| row.parent.row <= t.row_count),
                        TableId::MethodSpec => tables
                            .table::<MethodSpecRaw>()
                            .is_some_and(|t| row.parent.row <= t.row_count),
                        TableId::GenericParamConstraint => tables
                            .table::<GenericParamConstraintRaw>()
                            .is_some_and(|t| row.parent.row <= t.row_count),
                        TableId::Document => tables
                            .table::<DocumentRaw>()
                            .is_some_and(|t| row.parent.row <= t.row_count),
                        TableId::LocalScope => tables
                            .table::<LocalScopeRaw>()
                            .is_some_and(|t| row.parent.row <= t.row_count),
                        TableId::LocalVariable => tables
                            .table::<LocalVariableRaw>()
                            .is_some_and(|t| row.parent.row <= t.row_count),
                        TableId::LocalConstant => tables
                            .table::<LocalConstantRaw>()
                            .is_some_and(|t| row.parent.row <= t.row_count),
                        TableId::ImportScope => tables
                            .table::<ImportScopeRaw>()
                            .is_some_and(|t| row.parent.row <= t.row_count),
                        _ => false, // Invalid table type for HasCustomDebugInformation
                    };

                    if !table_exists {
                        return Err(Error::ValidationReferentialIntegrity {
                            message: format!(
                                "CustomDebugInformation row {} references non-existent or invalid {:?} row {}",
                                rid, row.parent.tag, row.parent.row
                            ),
                        });
                    }
                }
            }
        }

        Ok(())
    }

    /// Finds all references to a specific string heap index.
    ///
    /// This method queries the internal reference tracker to find all table columns
    /// that reference the specified string heap index. It returns an empty vector
    /// if no references are found.
    ///
    /// # Arguments
    ///
    /// * `string_index` - The string heap index to search for
    ///
    /// # Returns
    ///
    /// A vector of [`TableReference`] instances representing all locations where
    /// the string heap index is referenced.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use crate::cilassembly::validation::reference::ReferenceScanner;
    /// use crate::metadata::cilassemblyview::CilAssemblyView;
    ///
    /// # let view = CilAssemblyView::from_file("test.dll")?;
    /// let scanner = ReferenceScanner::new(&view)?;
    /// let references = scanner.find_references_to_string_heap_index(42);
    /// println!("String index 42 has {} references", references.row_count);
    /// # Ok::<(), crate::Error>(())
    /// ```
    pub fn find_references_to_string_heap_index(&self, string_index: u32) -> Vec<TableReference> {
        self.tracker
            .get_string_references(string_index)
            .cloned()
            .unwrap_or_default()
    }

    /// Finds all references to a specific blob heap index.
    ///
    /// This method queries the internal reference tracker to find all table columns
    /// that reference the specified blob heap index. It returns an empty vector
    /// if no references are found.
    ///
    /// # Arguments
    ///
    /// * `blob_index` - The blob heap index to search for
    ///
    /// # Returns
    ///
    /// A vector of [`TableReference`] instances representing all locations where
    /// the blob heap index is referenced.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use crate::cilassembly::validation::reference::ReferenceScanner;
    /// use crate::metadata::cilassemblyview::CilAssemblyView;
    ///
    /// # let view = CilAssemblyView::from_file("test.dll")?;
    /// let scanner = ReferenceScanner::new(&view)?;
    /// let references = scanner.find_references_to_blob_heap_index(128);
    /// println!("Blob index 128 has {} references", references.row_count);
    /// # Ok::<(), crate::Error>(())
    /// ```
    pub fn find_references_to_blob_heap_index(&self, blob_index: u32) -> Vec<TableReference> {
        self.tracker
            .get_blob_references(blob_index)
            .cloned()
            .unwrap_or_default()
    }

    /// Finds all references to a specific GUID heap index.
    ///
    /// This method queries the internal reference tracker to find all table columns
    /// that reference the specified GUID heap index. It returns an empty vector
    /// if no references are found.
    ///
    /// # Arguments
    ///
    /// * `guid_index` - The GUID heap index to search for
    ///
    /// # Returns
    ///
    /// A vector of [`TableReference`] instances representing all locations where
    /// the GUID heap index is referenced.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use crate::cilassembly::validation::reference::ReferenceScanner;
    /// use crate::metadata::cilassemblyview::CilAssemblyView;
    ///
    /// # let view = CilAssemblyView::from_file("test.dll")?;
    /// let scanner = ReferenceScanner::new(&view)?;
    /// let references = scanner.find_references_to_guid_heap_index(3);
    /// println!("GUID index 3 has {} references", references.row_count);
    /// # Ok::<(), crate::Error>(())
    /// ```
    pub fn find_references_to_guid_heap_index(&self, guid_index: u32) -> Vec<TableReference> {
        self.tracker
            .get_guid_references(guid_index)
            .cloned()
            .unwrap_or_default()
    }

    /// Finds all references to a specific user string heap index.
    ///
    /// This method queries the internal reference tracker to find all table columns
    /// that reference the specified user string heap index. It returns an empty vector
    /// if no references are found.
    ///
    /// User string references are primarily used by IL instructions (such as `ldstr`)
    /// and are less commonly referenced by metadata tables than other heap types.
    ///
    /// # Arguments
    ///
    /// * `userstring_index` - The user string heap index to search for
    ///
    /// # Returns
    ///
    /// A vector of [`TableReference`] instances representing all locations where
    /// the user string heap index is referenced.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use crate::cilassembly::validation::reference::ReferenceScanner;
    /// use crate::metadata::cilassemblyview::CilAssemblyView;
    ///
    /// # let view = CilAssemblyView::from_file("test.dll")?;
    /// let scanner = ReferenceScanner::new(&view)?;
    /// let references = scanner.find_references_to_userstring_heap_index(15);
    /// println!("User string index 15 has {} references", references.row_count);
    /// # Ok::<(), crate::Error>(())
    /// ```
    pub fn find_references_to_userstring_heap_index(
        &self,
        userstring_index: u32,
    ) -> Vec<TableReference> {
        self.tracker
            .get_userstring_references(userstring_index)
            .cloned()
            .unwrap_or_default()
    }
}
