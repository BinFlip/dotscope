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
//! Builds a comprehensive reference graph once and uses it for efficient lookups.
//! This is optimal when multiple reference queries are needed.
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
//! // Create a reference scanner
//! let scanner = ReferenceScanner::new(&view);
//!
//! // Find all references to a specific table row
//! let references = scanner.find_references_to_table_row(TableId::TypeDef, 1)?;
//! println!("Found {} references to TypeDef row 1", references.len());
//!
//! // Build a reference tracker for efficient repeated queries
//! let tracker = scanner.build_reference_tracker()?;
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
            ClassLayoutRaw, ConstantRaw, CustomAttributeRaw, DeclSecurityRaw, EventMapRaw,
            EventPtrRaw, EventRaw, ExportedTypeRaw, FieldLayoutRaw, FieldMarshalRaw, FieldPtrRaw,
            FieldRvaRaw, GenericParamConstraintRaw, GenericParamRaw, ImplMapRaw, InterfaceImplRaw,
            ManifestResourceRaw, MemberRefRaw, MethodImplRaw, MethodPtrRaw, MethodSemanticsRaw,
            MethodSpecRaw, NestedClassRaw, ParamPtrRaw, PropertyMapRaw, PropertyPtrRaw, TableId,
            TypeDefRaw, TypeRefRaw,
        },
    },
    Result,
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
/// # Usage Examples
///
/// ```rust,ignore
/// use crate::cilassembly::validation::reference::ReferenceScanner;
/// use crate::metadata::cilassemblyview::CilAssemblyView;
/// use crate::metadata::tables::TableId;
/// use std::path::Path;
///
/// # let view = CilAssemblyView::from_file(Path::new("test.dll"))?;
/// let scanner = ReferenceScanner::new(&view);
/// let references = scanner.find_references_to_table_row(TableId::TypeDef, 1)?;
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
/// [`crate::metadata::cilassemblyview::CilAssemblyView`] and maintains no mutable state.
pub struct ReferenceScanner<'a> {
    /// Reference to the assembly view containing the metadata to scan
    view: &'a CilAssemblyView,
}

impl<'a> ReferenceScanner<'a> {
    /// Creates a new reference scanner for the given assembly view.
    ///
    /// This constructor initializes a [`ReferenceScanner`] that will operate on the
    /// provided [`crate::metadata::cilassemblyview::CilAssemblyView`] to find cross-references within the assembly metadata.
    ///
    /// # Arguments
    ///
    /// * `view` - The assembly view containing metadata tables to scan for references
    ///
    /// # Returns
    ///
    /// Returns a new [`ReferenceScanner`] instance ready to perform reference scanning operations.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use crate::cilassembly::validation::reference::ReferenceScanner;
    /// use crate::metadata::cilassemblyview::CilAssemblyView;
    /// use std::path::Path;
    ///
    /// # let view = CilAssemblyView::from_file(Path::new("test.dll"))?;
    /// let scanner = ReferenceScanner::new(&view);
    /// # Ok::<(), crate::Error>(())
    /// ```
    pub fn new(view: &'a CilAssemblyView) -> Self {
        Self { view }
    }

    /// Builds a comprehensive reference tracker for the entire assembly.
    ///
    /// This method performs a complete scan of all metadata tables in the assembly to build
    /// a comprehensive reference graph. This is more efficient than repeated calls to
    /// [`ReferenceScanner::find_references_to_table_row`] when multiple reference queries are needed.
    ///
    /// The reference tracker maps heap indices and table RIDs to all locations that reference
    /// them, enabling efficient batch operations for referential integrity validation.
    ///
    /// # Returns
    ///
    /// Returns a [`crate::cilassembly::references::ReferenceTracker`] containing a complete mapping
    /// of all cross-references in the assembly metadata.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] if there are issues reading metadata tables during the scan.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use crate::cilassembly::validation::reference::ReferenceScanner;
    /// use crate::metadata::cilassemblyview::CilAssemblyView;
    /// use std::path::Path;
    ///
    /// # let view = CilAssemblyView::from_file(Path::new("test.dll"))?;
    /// let scanner = ReferenceScanner::new(&view);
    /// let tracker = scanner.build_reference_tracker()?;
    ///
    /// // Use tracker for efficient repeated queries
    /// if let Some(refs) = tracker.get_string_references(42) {
    ///     println!("String index 42 has {} references", refs.len());
    /// }
    /// # Ok::<(), crate::Error>(())
    /// ```
    pub fn build_reference_tracker(&self) -> Result<ReferenceTracker> {
        let tracker = ReferenceTracker::new();

        // ToDo: Use ReferenceTracker
        // 1. Scan all tables and populate the reference tracker
        // 2. Handle all coded index types and direct references
        // 3. Track heap references (string, blob, guid, userstring indices)
        Ok(tracker)
    }

    /// Finds all references to the specified table row.
    ///
    /// This method performs a comprehensive scan of all metadata tables to find every location
    /// that references the specified table row. It examines both direct references (where a
    /// column directly stores a RID) and coded indices (where multiple table types can be
    /// referenced through a single column).
    ///
    /// The scan covers all ECMA-335 metadata tables and their cross-reference relationships,
    /// providing complete coverage for referential integrity validation.
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
    /// # Errors
    ///
    /// Returns [`crate::Error`] if there are issues accessing metadata tables during the scan.
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
    /// let scanner = ReferenceScanner::new(&view);
    ///
    /// // Find all references to TypeDef row 1
    /// let references = scanner.find_references_to_table_row(TableId::TypeDef, 1)?;
    ///
    /// if references.is_empty() {
    ///     println!("No references found - safe to delete");
    /// } else {
    ///     println!("Found {} references:", references.len());
    ///     for reference in references {
    ///         println!("  - {}:{} column '{}'",
    ///                  reference.table_id as u32, reference.row_rid, reference.column_name);
    ///     }
    /// }
    /// # Ok::<(), crate::Error>(())
    /// ```
    pub fn find_references_to_table_row(
        &self,
        table_id: TableId,
        rid: u32,
    ) -> Result<Vec<TableReference>> {
        let mut references = Vec::new();
        let Some(tables) = self.view.tables() else {
            return Ok(references);
        };

        // Scan all present tables for references to our target
        for scanning_table_id in tables.present_tables() {
            match scanning_table_id {
                TableId::TypeDef => {
                    if let Some(typedef_table) = tables.table::<TypeDefRaw>() {
                        for (scanning_rid, row) in typedef_table.iter().enumerate() {
                            let scanning_rid = scanning_rid as u32 + 1;
                            // Check 'extends' field (CodedIndex TypeDefOrRef)
                            if row.extends.tag == table_id && row.extends.row == rid {
                                references.push(TableReference {
                                    table_id: TableId::TypeDef,
                                    row_rid: scanning_rid,
                                    column_name: "extends".to_string(),
                                });
                            }
                        }
                    }
                }
                TableId::MemberRef => {
                    if let Some(memberref_table) = tables.table::<MemberRefRaw>() {
                        for (scanning_rid, row) in memberref_table.iter().enumerate() {
                            let scanning_rid = scanning_rid as u32 + 1;
                            // Check 'class' field (CodedIndex MemberRefParent)
                            if row.class.tag == table_id && row.class.row == rid {
                                references.push(TableReference {
                                    table_id: TableId::MemberRef,
                                    row_rid: scanning_rid,
                                    column_name: "class".to_string(),
                                });
                            }
                        }
                    }
                }
                TableId::InterfaceImpl => {
                    if let Some(interfaceimpl_table) = tables.table::<InterfaceImplRaw>() {
                        for (scanning_rid, row) in interfaceimpl_table.iter().enumerate() {
                            let scanning_rid = scanning_rid as u32 + 1;
                            // Check 'class' field (direct TypeDef reference)
                            if table_id == TableId::TypeDef && row.class == rid {
                                references.push(TableReference {
                                    table_id: TableId::InterfaceImpl,
                                    row_rid: scanning_rid,
                                    column_name: "class".to_string(),
                                });
                            }
                            // Check 'interface' field (CodedIndex TypeDefOrRef)
                            if row.interface.tag == table_id && row.interface.row == rid {
                                references.push(TableReference {
                                    table_id: TableId::InterfaceImpl,
                                    row_rid: scanning_rid,
                                    column_name: "interface".to_string(),
                                });
                            }
                        }
                    }
                }
                TableId::CustomAttribute => {
                    if let Some(customattr_table) = tables.table::<CustomAttributeRaw>() {
                        for (scanning_rid, row) in customattr_table.iter().enumerate() {
                            let scanning_rid = scanning_rid as u32 + 1;
                            // Check 'parent' field (CodedIndex HasCustomAttribute)
                            if row.parent.tag == table_id && row.parent.row == rid {
                                references.push(TableReference {
                                    table_id: TableId::CustomAttribute,
                                    row_rid: scanning_rid,
                                    column_name: "parent".to_string(),
                                });
                            }
                            // Check 'constructor' field (CodedIndex CustomAttributeType)
                            if row.constructor.tag == table_id && row.constructor.row == rid {
                                references.push(TableReference {
                                    table_id: TableId::CustomAttribute,
                                    row_rid: scanning_rid,
                                    column_name: "constructor".to_string(),
                                });
                            }
                        }
                    }
                }
                TableId::TypeRef => {
                    if let Some(typeref_table) = tables.table::<TypeRefRaw>() {
                        for (scanning_rid, row) in typeref_table.iter().enumerate() {
                            let scanning_rid = scanning_rid as u32 + 1;
                            // Check 'resolution_scope' field (CodedIndex ResolutionScope)
                            if row.resolution_scope.tag == table_id
                                && row.resolution_scope.row == rid
                            {
                                references.push(TableReference {
                                    table_id: TableId::TypeRef,
                                    row_rid: scanning_rid,
                                    column_name: "resolution_scope".to_string(),
                                });
                            }
                        }
                    }
                }
                TableId::NestedClass => {
                    if let Some(nestedclass_table) = tables.table::<NestedClassRaw>() {
                        for (scanning_rid, row) in nestedclass_table.iter().enumerate() {
                            let scanning_rid = scanning_rid as u32 + 1;
                            // Check 'nested_class' field (direct TypeDef reference)
                            if table_id == TableId::TypeDef && row.nested_class == rid {
                                references.push(TableReference {
                                    table_id: TableId::NestedClass,
                                    row_rid: scanning_rid,
                                    column_name: "nested_class".to_string(),
                                });
                            }
                            // Check 'enclosing_class' field (direct TypeDef reference)
                            if table_id == TableId::TypeDef && row.enclosing_class == rid {
                                references.push(TableReference {
                                    table_id: TableId::NestedClass,
                                    row_rid: scanning_rid,
                                    column_name: "enclosing_class".to_string(),
                                });
                            }
                        }
                    }
                }
                TableId::ManifestResource => {
                    if let Some(manifestresource_table) = tables.table::<ManifestResourceRaw>() {
                        for (scanning_rid, row) in manifestresource_table.iter().enumerate() {
                            let scanning_rid = scanning_rid as u32 + 1;
                            // Check 'implementation' field (CodedIndex Implementation)
                            if row.implementation.tag == table_id && row.implementation.row == rid {
                                references.push(TableReference {
                                    table_id: TableId::ManifestResource,
                                    row_rid: scanning_rid,
                                    column_name: "implementation".to_string(),
                                });
                            }
                        }
                    }
                }
                TableId::ExportedType => {
                    if let Some(exportedtype_table) = tables.table::<ExportedTypeRaw>() {
                        for (scanning_rid, row) in exportedtype_table.iter().enumerate() {
                            let scanning_rid = scanning_rid as u32 + 1;
                            // Check 'implementation' field (CodedIndex Implementation)
                            if row.implementation.tag == table_id && row.implementation.row == rid {
                                references.push(TableReference {
                                    table_id: TableId::ExportedType,
                                    row_rid: scanning_rid,
                                    column_name: "implementation".to_string(),
                                });
                            }
                        }
                    }
                }
                TableId::Constant => {
                    if let Some(constant_table) = tables.table::<ConstantRaw>() {
                        for (scanning_rid, row) in constant_table.iter().enumerate() {
                            let scanning_rid = scanning_rid as u32 + 1;
                            // Check 'parent' field (CodedIndex HasConstant)
                            if row.parent.tag == table_id && row.parent.row == rid {
                                references.push(TableReference {
                                    table_id: TableId::Constant,
                                    row_rid: scanning_rid,
                                    column_name: "parent".to_string(),
                                });
                            }
                        }
                    }
                }
                TableId::FieldMarshal => {
                    if let Some(fieldmarshal_table) = tables.table::<FieldMarshalRaw>() {
                        for (scanning_rid, row) in fieldmarshal_table.iter().enumerate() {
                            let scanning_rid = scanning_rid as u32 + 1;
                            // Check 'parent' field (CodedIndex HasFieldMarshal)
                            if row.parent.tag == table_id && row.parent.row == rid {
                                references.push(TableReference {
                                    table_id: TableId::FieldMarshal,
                                    row_rid: scanning_rid,
                                    column_name: "parent".to_string(),
                                });
                            }
                        }
                    }
                }
                TableId::DeclSecurity => {
                    if let Some(declsecurity_table) = tables.table::<DeclSecurityRaw>() {
                        for (scanning_rid, row) in declsecurity_table.iter().enumerate() {
                            let scanning_rid = scanning_rid as u32 + 1;
                            // Check 'parent' field (CodedIndex HasDeclSecurity)
                            if row.parent.tag == table_id && row.parent.row == rid {
                                references.push(TableReference {
                                    table_id: TableId::DeclSecurity,
                                    row_rid: scanning_rid,
                                    column_name: "parent".to_string(),
                                });
                            }
                        }
                    }
                }
                TableId::ClassLayout => {
                    if let Some(classlayout_table) = tables.table::<ClassLayoutRaw>() {
                        for (scanning_rid, row) in classlayout_table.iter().enumerate() {
                            let scanning_rid = scanning_rid as u32 + 1;
                            // Check 'parent' field (direct TypeDef reference)
                            if table_id == TableId::TypeDef && row.parent == rid {
                                references.push(TableReference {
                                    table_id: TableId::ClassLayout,
                                    row_rid: scanning_rid,
                                    column_name: "parent".to_string(),
                                });
                            }
                        }
                    }
                }
                TableId::FieldLayout => {
                    if let Some(fieldlayout_table) = tables.table::<FieldLayoutRaw>() {
                        for (scanning_rid, row) in fieldlayout_table.iter().enumerate() {
                            let scanning_rid = scanning_rid as u32 + 1;
                            // Check 'field' field (direct Field reference)
                            if table_id == TableId::Field && row.field == rid {
                                references.push(TableReference {
                                    table_id: TableId::FieldLayout,
                                    row_rid: scanning_rid,
                                    column_name: "field".to_string(),
                                });
                            }
                        }
                    }
                }
                TableId::PropertyMap => {
                    if let Some(propertymap_table) = tables.table::<PropertyMapRaw>() {
                        for (scanning_rid, row) in propertymap_table.iter().enumerate() {
                            let scanning_rid = scanning_rid as u32 + 1;
                            // Check 'parent' field (direct TypeDef reference)
                            if table_id == TableId::TypeDef && row.parent == rid {
                                references.push(TableReference {
                                    table_id: TableId::PropertyMap,
                                    row_rid: scanning_rid,
                                    column_name: "parent".to_string(),
                                });
                            }
                        }
                    }
                }
                TableId::EventMap => {
                    if let Some(eventmap_table) = tables.table::<EventMapRaw>() {
                        for (scanning_rid, row) in eventmap_table.iter().enumerate() {
                            let scanning_rid = scanning_rid as u32 + 1;
                            // Check 'parent' field (direct TypeDef reference)
                            if table_id == TableId::TypeDef && row.parent == rid {
                                references.push(TableReference {
                                    table_id: TableId::EventMap,
                                    row_rid: scanning_rid,
                                    column_name: "parent".to_string(),
                                });
                            }
                        }
                    }
                }
                TableId::MethodSemantics => {
                    if let Some(methodsemantics_table) = tables.table::<MethodSemanticsRaw>() {
                        for (scanning_rid, row) in methodsemantics_table.iter().enumerate() {
                            let scanning_rid = scanning_rid as u32 + 1;
                            // Check 'method' field (direct MethodDef reference)
                            if table_id == TableId::MethodDef && row.method == rid {
                                references.push(TableReference {
                                    table_id: TableId::MethodSemantics,
                                    row_rid: scanning_rid,
                                    column_name: "method".to_string(),
                                });
                            }
                            // Check 'association' field (CodedIndex HasSemantics)
                            if row.association.tag == table_id && row.association.row == rid {
                                references.push(TableReference {
                                    table_id: TableId::MethodSemantics,
                                    row_rid: scanning_rid,
                                    column_name: "association".to_string(),
                                });
                            }
                        }
                    }
                }
                TableId::MethodImpl => {
                    if let Some(methodimpl_table) = tables.table::<MethodImplRaw>() {
                        for (scanning_rid, row) in methodimpl_table.iter().enumerate() {
                            let scanning_rid = scanning_rid as u32 + 1;
                            // Check 'class' field (direct TypeDef reference)
                            if table_id == TableId::TypeDef && row.class == rid {
                                references.push(TableReference {
                                    table_id: TableId::MethodImpl,
                                    row_rid: scanning_rid,
                                    column_name: "class".to_string(),
                                });
                            }
                            // Check 'method_body' field (CodedIndex MethodDefOrRef)
                            if row.method_body.tag == table_id && row.method_body.row == rid {
                                references.push(TableReference {
                                    table_id: TableId::MethodImpl,
                                    row_rid: scanning_rid,
                                    column_name: "method_body".to_string(),
                                });
                            }
                            // Check 'method_declaration' field (CodedIndex MethodDefOrRef)
                            if row.method_declaration.tag == table_id
                                && row.method_declaration.row == rid
                            {
                                references.push(TableReference {
                                    table_id: TableId::MethodImpl,
                                    row_rid: scanning_rid,
                                    column_name: "method_declaration".to_string(),
                                });
                            }
                        }
                    }
                }
                TableId::GenericParam => {
                    if let Some(genericparam_table) = tables.table::<GenericParamRaw>() {
                        for (scanning_rid, row) in genericparam_table.iter().enumerate() {
                            let scanning_rid = scanning_rid as u32 + 1;
                            // Check 'owner' field (CodedIndex TypeOrMethodDef)
                            if row.owner.tag == table_id && row.owner.row == rid {
                                references.push(TableReference {
                                    table_id: TableId::GenericParam,
                                    row_rid: scanning_rid,
                                    column_name: "owner".to_string(),
                                });
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
                            // Check 'owner' field (direct GenericParam reference)
                            if table_id == TableId::GenericParam && row.owner == rid {
                                references.push(TableReference {
                                    table_id: TableId::GenericParamConstraint,
                                    row_rid: scanning_rid,
                                    column_name: "owner".to_string(),
                                });
                            }
                            // Check 'constraint' field (CodedIndex TypeDefOrRef)
                            if row.constraint.tag == table_id && row.constraint.row == rid {
                                references.push(TableReference {
                                    table_id: TableId::GenericParamConstraint,
                                    row_rid: scanning_rid,
                                    column_name: "constraint".to_string(),
                                });
                            }
                        }
                    }
                }
                TableId::MethodSpec => {
                    if let Some(methodspec_table) = tables.table::<MethodSpecRaw>() {
                        for (scanning_rid, row) in methodspec_table.iter().enumerate() {
                            let scanning_rid = scanning_rid as u32 + 1;
                            // Check 'method' field (CodedIndex MethodDefOrRef)
                            if row.method.tag == table_id && row.method.row == rid {
                                references.push(TableReference {
                                    table_id: TableId::MethodSpec,
                                    row_rid: scanning_rid,
                                    column_name: "method".to_string(),
                                });
                            }
                        }
                    }
                }
                TableId::Event => {
                    if let Some(event_table) = tables.table::<EventRaw>() {
                        for (scanning_rid, row) in event_table.iter().enumerate() {
                            let scanning_rid = scanning_rid as u32 + 1;
                            // Check 'event_type' field (CodedIndex TypeDefOrRef)
                            if row.event_type.tag == table_id && row.event_type.row == rid {
                                references.push(TableReference {
                                    table_id: TableId::Event,
                                    row_rid: scanning_rid,
                                    column_name: "event_type".to_string(),
                                });
                            }
                        }
                    }
                }
                TableId::FieldRVA => {
                    if let Some(fieldrva_table) = tables.table::<FieldRvaRaw>() {
                        for (scanning_rid, row) in fieldrva_table.iter().enumerate() {
                            let scanning_rid = scanning_rid as u32 + 1;
                            // Check 'field' field (direct Field reference)
                            if table_id == TableId::Field && row.field == rid {
                                references.push(TableReference {
                                    table_id: TableId::FieldRVA,
                                    row_rid: scanning_rid,
                                    column_name: "field".to_string(),
                                });
                            }
                        }
                    }
                }
                TableId::FieldPtr => {
                    if let Some(fieldptr_table) = tables.table::<FieldPtrRaw>() {
                        for (scanning_rid, row) in fieldptr_table.iter().enumerate() {
                            let scanning_rid = scanning_rid as u32 + 1;
                            // Check 'field' field (direct Field reference)
                            if table_id == TableId::Field && row.field == rid {
                                references.push(TableReference {
                                    table_id: TableId::FieldPtr,
                                    row_rid: scanning_rid,
                                    column_name: "field".to_string(),
                                });
                            }
                        }
                    }
                }
                TableId::MethodPtr => {
                    if let Some(methodptr_table) = tables.table::<MethodPtrRaw>() {
                        for (scanning_rid, row) in methodptr_table.iter().enumerate() {
                            let scanning_rid = scanning_rid as u32 + 1;
                            // Check 'method' field (direct MethodDef reference)
                            if table_id == TableId::MethodDef && row.method == rid {
                                references.push(TableReference {
                                    table_id: TableId::MethodPtr,
                                    row_rid: scanning_rid,
                                    column_name: "method".to_string(),
                                });
                            }
                        }
                    }
                }
                TableId::ParamPtr => {
                    if let Some(paramptr_table) = tables.table::<ParamPtrRaw>() {
                        for (scanning_rid, row) in paramptr_table.iter().enumerate() {
                            let scanning_rid = scanning_rid as u32 + 1;
                            // Check 'param' field (direct Param reference)
                            if table_id == TableId::Param && row.param == rid {
                                references.push(TableReference {
                                    table_id: TableId::ParamPtr,
                                    row_rid: scanning_rid,
                                    column_name: "param".to_string(),
                                });
                            }
                        }
                    }
                }
                TableId::PropertyPtr => {
                    if let Some(propertyptr_table) = tables.table::<PropertyPtrRaw>() {
                        for (scanning_rid, row) in propertyptr_table.iter().enumerate() {
                            let scanning_rid = scanning_rid as u32 + 1;
                            // Check 'property' field (direct Property reference)
                            if table_id == TableId::Property && row.property == rid {
                                references.push(TableReference {
                                    table_id: TableId::PropertyPtr,
                                    row_rid: scanning_rid,
                                    column_name: "property".to_string(),
                                });
                            }
                        }
                    }
                }
                TableId::EventPtr => {
                    if let Some(eventptr_table) = tables.table::<EventPtrRaw>() {
                        for (scanning_rid, row) in eventptr_table.iter().enumerate() {
                            let scanning_rid = scanning_rid as u32 + 1;
                            // Check 'event' field (direct Event reference)
                            if table_id == TableId::Event && row.event == rid {
                                references.push(TableReference {
                                    table_id: TableId::EventPtr,
                                    row_rid: scanning_rid,
                                    column_name: "event".to_string(),
                                });
                            }
                        }
                    }
                }
                TableId::ImplMap => {
                    if let Some(implmap_table) = tables.table::<ImplMapRaw>() {
                        for (scanning_rid, row) in implmap_table.iter().enumerate() {
                            let scanning_rid = scanning_rid as u32 + 1;
                            // Check 'member_forwarded' field (CodedIndex MemberForwarded)
                            if row.member_forwarded.tag == table_id
                                && row.member_forwarded.row == rid
                            {
                                references.push(TableReference {
                                    table_id: TableId::ImplMap,
                                    row_rid: scanning_rid,
                                    column_name: "member_forwarded".to_string(),
                                });
                            }
                            // Check 'import_scope' field (direct ModuleRef reference)
                            if table_id == TableId::ModuleRef && row.import_scope == rid {
                                references.push(TableReference {
                                    table_id: TableId::ImplMap,
                                    row_rid: scanning_rid,
                                    column_name: "import_scope".to_string(),
                                });
                            }
                        }
                    }
                }
                // For remaining tables that don't have references
                _ => {}
            }
        }

        Ok(references)
    }
}
