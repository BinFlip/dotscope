//! Raw `TypeDef` table implementation for .NET metadata.
//!
//! This module provides the [`TypeDefRaw`] structure for representing rows in the `TypeDef` table,
//! which defines types (classes, interfaces, value types, enums) within the current module.
//! Each row contains type attributes, names, base type references, and field/method ranges.
//!
//! ## Table Structure
//! The `TypeDef` table (`TableId` 0x02) contains the following columns:
//! - **`TypeName`** (string heap index): The name of the type
//! - **`TypeNamespace`** (string heap index): The namespace containing the type
//! - **`Extends`** (coded index): Base type reference (`TypeDef`, `TypeRef`, or `TypeSpec`)
//! - **`FieldList`** (Field table index): First field belonging to this type
//! - **`MethodList`** (`MethodDef` table index): First method belonging to this type
//!
//! ## ECMA-335 Reference
//! See ECMA-335, Partition II, Section 22.37 for the complete `TypeDef` table specification.

use std::sync::Arc;

use crate::{
    metadata::{
        method::MethodMap,
        streams::Strings,
        tables::{
            CodedIndex, CodedIndexType, FieldMap, FieldPtrMap, MetadataTable, MethodPtrMap,
            TableId, TableInfoRef, TableRow,
        },
        token::Token,
        typesystem::{CilType, CilTypeRc, CilTypeRef, CilTypeReference},
    },
    Result,
};

#[derive(Clone, Debug)]
/// Raw representation of a row in the `TypeDef` metadata table.
///
/// The `TypeDef` table defines types (classes, interfaces, value types, enums) within the current
/// module. Each row represents a complete type definition including its attributes, name, namespace,
/// base type, and ranges indicating which fields and methods belong to this type.
///
/// ## Fields Overview
/// - **rid**: Row identifier within the `TypeDef` table
/// - **token**: Metadata token with table ID 0x02 and row ID
/// - **flags**: Type attributes controlling visibility, layout, and semantics
/// - **`type_name`/`type_namespace`**: String heap indices for the type's name and namespace
/// - **`extends`**: Reference to base type (`TypeDef`, `TypeRef`, or `TypeSpec`)
/// - **`field_list`/`method_list`**: Starting indices for this type's fields and methods
///
/// ## ECMA-335 Compliance
/// This structure directly corresponds to the `TypeDef` table format specified in
/// ECMA-335, Partition II, Section 22.37.
///
/// **Table ID**: `0x02`
pub struct TypeDefRaw {
    /// Row identifier within the `TypeDef` table.
    ///
    /// This 1-based index uniquely identifies this type definition within the table.
    pub rid: u32,

    /// Metadata token for this type definition.
    ///
    /// Constructed as `0x02000000 | rid`, providing a unique identifier
    /// across all metadata tables in the assembly.
    pub token: Token,

    /// Byte offset of this row within the `TypeDef` table data.
    ///
    /// Used for debugging and low-level table operations.
    pub offset: usize,

    /// Type attributes as a 4-byte bitmask.
    ///
    /// Controls type visibility, layout, semantics, and other characteristics.
    /// See [`crate::metadata::tables::typedef::TypeAttributes`] for flag constants.
    pub flags: u32,

    /// Index into the String heap for the type name.
    ///
    /// Points to the simple name of the type (without namespace).
    pub type_name: u32,

    /// Index into the String heap for the type namespace.
    ///
    /// Points to the namespace containing this type, or 0 for the global namespace.
    pub type_namespace: u32,

    /// Coded index referencing the base type.
    ///
    /// Points to a `TypeDef`, `TypeRef`, or `TypeSpec` table entry representing
    /// the base type. Set to 0 for types with no base type (e.g., System.Object).
    pub extends: CodedIndex,

    /// Index into the Field table marking the first field.
    ///
    /// Indicates the starting position of a contiguous range of fields
    /// belonging to this type. Field ownership is determined by comparing
    /// with the next type's `field_list` value.
    pub field_list: u32,

    /// Index into the `MethodDef` table marking the first method.
    ///
    /// Indicates the starting position of a contiguous range of methods
    /// belonging to this type. Method ownership is determined by comparing
    /// with the next type's `method_list` value.
    pub method_list: u32,
}

impl TypeDefRaw {
    /// Converts this raw `TypeDef` entry into a fully resolved [`CilType`].
    ///
    /// This method resolves all references and builds a complete type representation
    /// including fields, methods, namespace information, and optionally base type.
    /// It handles field and method pointer indirection when present.
    ///
    /// ## Arguments
    /// * `get_ref` - Closure to resolve coded indexes to type references
    /// * `strings` - The #String heap for resolving names and namespaces  
    /// * `fields` - Map of all processed Field entries indexed by token
    /// * `field_ptr` - Map of `FieldPtr` entries for indirection resolution
    /// * `methods` - Map of all processed Method entries indexed by token
    /// * `method_ptr` - Map of `MethodPtr` entries for indirection resolution
    /// * `defs` - The complete `TypeDef` table for determining field/method ranges
    /// * `resolve_base_type` - Whether to resolve the base type during creation (for two-phase loading)
    ///
    /// ## Returns
    /// Returns a reference-counted [`CilType`] with all metadata resolved and owned.
    /// If `resolve_base_type` is false, the base type will be None and must be set later.
    ///
    /// ## Errors
    /// Returns an error if:
    /// - Type name or namespace cannot be resolved from the strings heap
    /// - Next row in the `TypeDef` table cannot be found for range calculation
    /// - Field or method tokens cannot be resolved through pointer indirection
    /// - Token value arithmetic overflows during resolution
    #[allow(clippy::too_many_arguments)]
    pub fn to_owned<F>(
        &self,
        get_ref: F,
        strings: &Strings,
        fields: &FieldMap,
        field_ptr: &FieldPtrMap,
        methods: &MethodMap,
        method_ptr: &MethodPtrMap,
        defs: &MetadataTable<TypeDefRaw>,
        resolve_base_type: bool,
    ) -> Result<CilTypeRc>
    where
        F: Fn(&CodedIndex) -> CilTypeReference,
    {
        let (end_fields, end_methods) = if self.rid + 1 > defs.row_count {
            (fields.len() + 1, methods.len() + 1)
        } else {
            match defs.get(self.rid + 1) {
                Some(next_row) => (next_row.field_list as usize, next_row.method_list as usize),
                None => {
                    return Err(malformed_error!(
                        "Failed to resolve fields_end from next row - {}",
                        self.rid + 1
                    ))
                }
            }
        };

        let start_fields = self.field_list as usize;
        let type_fields = if self.field_list == 0
            || fields.is_empty()
            || end_fields >= fields.len()
            || start_fields > fields.len()
            || end_fields <= start_fields
        {
            Arc::new(boxcar::Vec::new())
        } else {
            let type_fields = Arc::new(boxcar::Vec::with_capacity(end_fields - start_fields));
            for counter in start_fields..end_fields {
                let actual_field_token = if field_ptr.is_empty() {
                    Token::new(u32::try_from(counter | 0x0400_0000).map_err(|_| {
                        malformed_error!("Field token overflow: {}", counter | 0x0400_0000)
                    })?)
                } else {
                    let field_ptr_token_value =
                        u32::try_from(counter | 0x0300_0000).map_err(|_| {
                            malformed_error!(
                                "FieldPtr token value too large: {}",
                                counter | 0x0300_0000
                            )
                        })?;
                    let field_ptr_token = Token::new(field_ptr_token_value);

                    match field_ptr.get(&field_ptr_token) {
                        Some(field_ptr_entry) => {
                            let actual_field_rid = field_ptr_entry.value().field;
                            let actual_field_token_value = u32::try_from(
                                actual_field_rid as usize | 0x0400_0000,
                            )
                            .map_err(|_| {
                                malformed_error!(
                                    "Field token value too large: {}",
                                    actual_field_rid as usize | 0x0400_0000
                                )
                            })?;
                            Token::new(actual_field_token_value)
                        }
                        None => {
                            return Err(malformed_error!(
                                "Failed to resolve FieldPtr - {}",
                                counter | 0x0300_0000
                            ))
                        }
                    }
                };

                match fields.get(&actual_field_token) {
                    Some(field) => _ = type_fields.push(field.value().clone()),
                    None => {
                        return Err(malformed_error!(
                            "Failed to resolve field - {}",
                            actual_field_token.value()
                        ))
                    }
                }
            }

            type_fields
        };

        let start_methods = self.method_list as usize;
        let type_methods = if self.method_list == 0
            || methods.is_empty()
            || end_methods >= methods.len()
            || start_methods > methods.len()
            || end_methods < start_methods
        {
            Arc::new(boxcar::Vec::new())
        } else {
            let type_methods = Arc::new(boxcar::Vec::with_capacity(end_methods - start_methods));
            for counter in start_methods..end_methods {
                let actual_method_token = if method_ptr.is_empty() {
                    Token::new(u32::try_from(counter | 0x0600_0000).map_err(|_| {
                        malformed_error!("Method token overflow: {}", counter | 0x0600_0000)
                    })?)
                } else {
                    let method_ptr_token_value =
                        u32::try_from(counter | 0x0900_0000).map_err(|_| {
                            malformed_error!(
                                "MethodPtr token value too large: {}",
                                counter | 0x0900_0000
                            )
                        })?;
                    let method_ptr_token = Token::new(method_ptr_token_value);

                    match method_ptr.get(&method_ptr_token) {
                        Some(method_ptr_entry) => {
                            let actual_method_rid = method_ptr_entry.value().method;
                            let actual_method_token_value = u32::try_from(
                                actual_method_rid as usize | 0x0600_0000,
                            )
                            .map_err(|_| {
                                malformed_error!(
                                    "Method token value too large: {}",
                                    actual_method_rid as usize | 0x0600_0000
                                )
                            })?;
                            Token::new(actual_method_token_value)
                        }
                        None => {
                            return Err(malformed_error!(
                                "Failed to resolve MethodPtr - {}",
                                counter | 0x0900_0000
                            ))
                        }
                    }
                };

                match methods.get(&actual_method_token) {
                    Some(method) => _ = type_methods.push(method.value().clone().into()),
                    None => {
                        return Err(malformed_error!(
                            "Failed to resolve method - {}",
                            actual_method_token.value()
                        ))
                    }
                }
            }

            type_methods
        };

        let base_type = if resolve_base_type && self.extends.row != 0 {
            match get_ref(&self.extends) {
                CilTypeReference::TypeDef(type_ref)
                | CilTypeReference::TypeRef(type_ref)
                | CilTypeReference::TypeSpec(type_ref) => Some(type_ref),
                _ => None,
            }
        } else {
            None
        };

        Ok(Arc::new(CilType::new(
            self.token,
            strings.get(self.type_namespace as usize)?.to_string(),
            strings.get(self.type_name as usize)?.to_string(),
            None,
            base_type,
            self.flags,
            type_fields,
            type_methods,
            None,
        )))
    }

    /// Resolves and returns the base type reference for this TypeDef entry.
    ///
    /// This method is used during the second phase of two-phase loading to resolve
    /// base types after all TypeDef entries have been loaded. It handles the same
    /// logic as `to_owned` but only for base type resolution.
    ///
    /// # Arguments
    ///
    /// * `get_ref` - Closure to resolve coded index references to type references
    ///
    /// # Returns
    ///
    /// Returns `Some(CilTypeRef)` if this type has a base type that can be resolved,
    /// or `None` if this type has no base type or the base type cannot be resolved.
    pub fn resolve_base_type<F>(&self, get_ref: F) -> Option<CilTypeRef>
    where
        F: Fn(&CodedIndex) -> CilTypeReference,
    {
        if self.extends.row == 0 {
            None
        } else {
            match get_ref(&self.extends) {
                CilTypeReference::TypeDef(type_ref)
                | CilTypeReference::TypeRef(type_ref)
                | CilTypeReference::TypeSpec(type_ref) => Some(type_ref),
                _ => None,
            }
        }
    }

    /// Applies this `TypeDef` entry to update related metadata structures.
    ///
    /// `TypeDef` entries define types within the current assembly and serve as primary
    /// metadata containers. Unlike some other table types, `TypeDef` entries don't
    /// directly modify other metadata structures during the dual variant resolution
    /// phase. Type-specific metadata (fields, methods, properties, events, etc.)
    /// is resolved through separate table processing.
    ///
    /// ## Returns
    /// Always returns [`Ok(())`] as `TypeDef` entries don't modify other tables directly.
    ///
    /// ## ECMA-335 Reference
    /// See ECMA-335, Partition II, Section 22.37 for `TypeDef` table semantics.
    ///
    /// # Errors
    /// Returns an error if the operation fails for any reason.
    pub fn apply(&self) -> Result<()> {
        Ok(())
    }
}

impl TableRow for TypeDefRaw {
    /// Calculates the byte size of a `TypeDef` table row.
    ///
    /// The row size depends on the size configuration of various heaps and tables:
    /// - Flags: Always 4 bytes
    /// - TypeName/TypeNamespace: 2 or 4 bytes depending on string heap size
    /// - Extends: 2 or 4 bytes depending on coded index size for `TypeDefOrRef`
    /// - FieldList/MethodList: 2 or 4 bytes depending on target table sizes
    ///
    /// ## Arguments
    /// * `sizes` - Table size information for calculating index widths
    ///
    /// ## Returns
    /// The total byte size required for one `TypeDef` table row.
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* flags */             4 +
            /* type_name */         sizes.str_bytes() +
            /* type_namespace */    sizes.str_bytes() +
            /* extends */           sizes.coded_index_bytes(CodedIndexType::TypeDefOrRef) +
            /* field_list */        sizes.table_index_bytes(TableId::Field) +
            /* method_list */       sizes.table_index_bytes(TableId::MethodDef)
        )
    }
}
