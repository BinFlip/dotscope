use std::sync::Arc;

use crate::{
    file::io::{read_le_at, read_le_at_dyn},
    metadata::{
        method::MethodMap,
        streams::Strings,
        tables::{
            CodedIndex, CodedIndexType, FieldMap, FieldPtrMap, MetadataTable, MethodPtrMap,
            RowDefinition, TableId, TableInfoRef,
        },
        token::Token,
        typesystem::{CilType, CilTypeRc, CilTypeReference},
    },
    Result,
};

#[derive(Clone, Debug)]
/// The `TypeDef` table defines types (classes, interfaces, value types, enums) in the current module. `TableId` = 0x02
pub struct TypeDefRaw {
    /// `RowID`
    pub rid: u32,
    /// Token
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// a 4-byte bitmask of type `TypeAttributes`
    pub flags: u32,
    /// an index into the String heap
    pub type_name: u32,
    /// an index into the String heap
    pub type_namespace: u32,
    /// an index into the `TypeDef`, `TypeRef`, or `TypeSpec` table; more precisely, a `TypeDefOrRef`
    pub extends: CodedIndex,
    /// an index into the Field table; it marks the first of a contiguous run of Fields owned by this Type
    pub field_list: u32,
    /// an index into the `MethodDef` table; it marks the first of a continguous run of Methods owned by this Type
    pub method_list: u32,
}

impl TypeDefRaw {
    /// Convert an `TypeDefRaw`, into a `CilType` which has indexes resolved and owns the referenced data
    ///
    /// ## Arguments
    /// * `get_ref` - Closure to resolve coded indexes
    /// * 'strings'     - The #String heap
    /// * 'fields'  - All processed `Field` elements
    /// * '`field_ptr`' - All parsed `FieldPtr` entries for indirection resolution
    /// * 'methods' - All processed `Method` elements
    /// * '`method_ptr`' - All parsed `MethodPtr` entries for indirection resolution
    /// * '`defs`' - The `TypeDef` table for getting next row's field/method boundaries
    ///
    /// # Errors
    /// Returns an error if the type name or namespace cannot be resolved from the strings heap,
    /// if the next row in the `TypeDef` table cannot be found, or if field/method tokens cannot be resolved.
    pub fn to_owned<F>(
        &self,
        get_ref: F,
        strings: &Strings,
        fields: &FieldMap,
        field_ptr: &FieldPtrMap,
        methods: &MethodMap,
        method_ptr: &MethodPtrMap,
        defs: &MetadataTable<TypeDefRaw>,
    ) -> Result<CilTypeRc>
    where
        F: Fn(&CodedIndex) -> CilTypeReference,
    {
        let (end_fields, end_methods) = if self.rid + 1 > defs.row_count() {
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

        let base_type = if self.extends.row == 0 {
            None
        } else {
            match get_ref(&self.extends) {
                CilTypeReference::TypeDef(type_ref)
                | CilTypeReference::TypeRef(type_ref)
                | CilTypeReference::TypeSpec(type_ref) => Some(type_ref),
                _ => None,
            }
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

    /// Apply a `TypeDefRaw` entry to update related metadata structures.
    ///
    /// `TypeDef` entries define types within the current assembly. They are primary metadata
    /// containers but don't themselves modify other metadata during the dual variant
    /// resolution phase. Type-specific metadata (fields, methods, properties, events, etc.)
    /// is resolved separately.
    ///
    /// # Errors
    /// Always returns `Ok(())` as `TypeDef` entries don't modify other tables directly.
    pub fn apply(&self) -> Result<()> {
        Ok(())
    }
}

impl<'a> RowDefinition<'a> for TypeDefRaw {
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

    fn read_row(
        data: &'a [u8],
        offset: &mut usize,
        rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<Self> {
        Ok(TypeDefRaw {
            rid,
            token: Token::new(0x0200_0000 + rid),
            offset: *offset,
            flags: read_le_at::<u32>(data, offset)?,
            type_name: read_le_at_dyn(data, offset, sizes.is_large_str())?,
            type_namespace: read_le_at_dyn(data, offset, sizes.is_large_str())?,
            extends: CodedIndex::read(data, offset, sizes, CodedIndexType::TypeDefOrRef)?,
            field_list: read_le_at_dyn(data, offset, sizes.is_large(TableId::Field))?,
            method_list: read_le_at_dyn(data, offset, sizes.is_large(TableId::MethodDef))?,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::metadata::tables::{MetadataTable, TableId, TableInfo};

    use super::*;

    #[test]
    fn crafted_short() {
        let data = vec![
            0x00, 0x00, 0x00, 0x01, // flags
            0x42, 0x00, // type_name
            0x43, 0x00, // type_namespace
            0x00, 0x02, // extends
            0x00, 0x03, // field_list
            0x00, 0x04, // method_list
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Field, 1), (TableId::MethodDef, 1)],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<TypeDefRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: TypeDefRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x02000001);
            assert_eq!(row.flags, 0x01000000);
            assert_eq!(row.type_name, 0x42);
            assert_eq!(row.type_namespace, 0x43);
            assert_eq!(
                row.extends,
                CodedIndex {
                    tag: TableId::TypeDef,
                    row: 0x80,
                    token: Token::new(0x80 | 0x02000000),
                }
            );
            assert_eq!(row.field_list, 0x0300);
            assert_eq!(row.method_list, 0x0400);
        };

        {
            for row in table.iter() {
                eval(row);
            }
        }

        {
            let row = table.get(1).unwrap();
            eval(row);
        }
    }

    #[test]
    fn crafted_long() {
        let data = vec![
            0x00, 0x00, 0x00, 0x01, // flags
            0x00, 0x00, 0x00, 0x02, // type_name
            0x00, 0x00, 0x00, 0x03, // type_namespace
            0x00, 0x00, 0x00, 0x04, // extends
            0x00, 0x00, 0x00, 0x05, // field_list
            0x00, 0x00, 0x00, 0x06, // method_list
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::Field, u16::MAX as u32 + 2),
                (TableId::MethodDef, u16::MAX as u32 + 2),
                (TableId::TypeDef, u16::MAX as u32 + 2),
                (TableId::TypeRef, u16::MAX as u32 + 2),
                (TableId::TypeSpec, u16::MAX as u32 + 2),
            ],
            true,
            true,
            true,
        ));
        let table = MetadataTable::<TypeDefRaw>::new(&data, u16::MAX as u32 + 2, sizes).unwrap();

        let eval = |row: TypeDefRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x02000001);
            assert_eq!(row.flags, 0x01000000);
            assert_eq!(row.type_name, 0x02000000);
            assert_eq!(row.type_namespace, 0x03000000);
            assert_eq!(
                row.extends,
                CodedIndex {
                    tag: TableId::TypeDef,
                    row: 0x1000000,
                    token: Token::new(0x1000000 | 0x02000000),
                }
            );
            assert_eq!(row.field_list, 0x05000000);
            assert_eq!(row.method_list, 0x06000000);
        };

        {
            let row = table.get(1).unwrap();
            eval(row);
        }
    }
}
