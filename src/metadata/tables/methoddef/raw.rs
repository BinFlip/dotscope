//! Raw MethodDef table structure with unresolved indexes and heap references.
//!
//! This module provides the [`MethodDefRaw`] struct, which represents method definitions
//! as stored in the metadata stream. The structure contains unresolved indexes
//! and heap references that require processing to establish complete method information
//! with parameter metadata and signature details.
//!
//! # Purpose
//! [`MethodDefRaw`] serves as the direct representation of MethodDef table entries from the
//! binary metadata stream, before parameter resolution and signature parsing. This raw format
//! is processed during metadata loading to create [`Method`] instances with resolved
//! parameters and complete method implementation information.
//!
//! [`Method`]: crate::metadata::method::Method

use std::sync::{atomic::AtomicU32, Arc, OnceLock};

use crate::{
    file::io::{read_le_at, read_le_at_dyn},
    metadata::{
        method::{
            Method, MethodAccessFlags, MethodImplCodeType, MethodImplManagement, MethodImplOptions,
            MethodModifiers, MethodRc, MethodVtableFlags,
        },
        signatures::parse_method_signature,
        streams::{Blob, Strings},
        tables::{
            types::{RowDefinition, TableId, TableInfoRef},
            ParamMap, ParamPtrMap,
        },
        token::Token,
    },
    prelude::MetadataTable,
    Result,
};

/// Raw MethodDef table entry with unresolved indexes and heap references.
///
/// This structure represents a method definition as stored directly in the metadata stream.
/// All references are unresolved indexes or heap offsets that require processing during
/// metadata loading to establish complete method information with parameter metadata
/// and implementation details.
///
/// # Table Structure (ECMA-335 §22.26)
/// | Column | Size | Description |
/// |--------|------|-------------|
/// | RVA | 4 bytes | Relative virtual address of method implementation |
/// | ImplFlags | 2 bytes | Method implementation attributes |
/// | Flags | 2 bytes | Method attributes and access modifiers |
/// | Name | String index | Method name identifier |
/// | Signature | Blob index | Method signature (calling convention, parameters, return type) |
/// | ParamList | Param index | First parameter in the parameter list |
///
/// # Implementation Attributes (ImplFlags)
/// The `impl_flags` field contains method implementation characteristics:
/// - **Code type**: IL, native, OPTIL, or runtime implementation
/// - **Management**: Managed, unmanaged, or mixed execution model
/// - **Implementation**: Forward reference, synchronized, or no inlining flags
/// - **Security**: Security critical or transparent method marking
///
/// # Method Attributes (Flags)
/// The `flags` field contains method access and behavior modifiers:
/// - **Access**: Private, public, protected, internal visibility levels
/// - **Virtual dispatch**: Virtual, abstract, final, override, or new slot semantics
/// - **Special methods**: Constructor, property accessor, event handler, or operator
/// - **Calling convention**: Static, instance, or vararg method calling patterns
///
/// # Parameter Resolution
/// The `param_list` field provides access to method parameters:
/// - **Parameter range**: Contiguous range in the Param table for this method
/// - **Return parameter**: Special parameter at sequence 0 for return type information
/// - **Parameter metadata**: Names, types, default values, and custom attributes
/// - **Indirect access**: Optional ParamPtr table for parameter pointer indirection
///
/// # RVA and Implementation
/// The `rva` field specifies method implementation location:
/// - **Zero RVA**: Abstract methods, interface methods, or extern methods without implementation
/// - **Non-zero RVA**: Concrete methods with IL code or native implementation at specified address
/// - **Implementation type**: Determined by combination of RVA and implementation flags
#[derive(Clone, Debug)]
pub struct MethodDefRaw {
    /// Row identifier within the MethodDef table.
    ///
    /// Unique identifier for this method definition entry, used for internal
    /// table management and token generation.
    pub rid: u32,

    /// Metadata token for this MethodDef entry (TableId 0x06).
    ///
    /// Computed as `0x06000000 | rid` to create the full token value
    /// for referencing this method from other metadata structures.
    pub token: Token,

    /// Byte offset of this entry within the raw table data.
    ///
    /// Used for efficient table navigation and binary metadata processing.
    pub offset: usize,

    /// Relative virtual address of the method implementation.
    ///
    /// Points to the method's IL code or native implementation within the PE file.
    /// A value of 0 indicates an abstract method, interface method, or extern method
    /// without implementation in the current assembly.
    pub rva: u32,

    /// Method implementation attributes bitmask.
    ///
    /// Contains flags controlling method implementation characteristics including
    /// code type (IL/native), management model (managed/unmanaged), and special
    /// implementation features (synchronized, no inlining, etc.).
    pub impl_flags: u32,

    /// Method attributes and access modifiers bitmask.
    ///
    /// Contains flags controlling method visibility, virtual dispatch behavior,
    /// special method types, and calling conventions. Used for access control
    /// and method resolution during compilation and runtime.
    pub flags: u32,

    /// String heap index for the method name.
    ///
    /// References the method identifier name in the string heap. For constructors,
    /// this is typically ".ctor" (instance) or ".cctor" (static type initializer).
    pub name: u32,

    /// Blob heap index for the method signature.
    ///
    /// References signature data in the blob heap describing calling convention,
    /// parameter types, return type, and generic type parameters. Must be parsed
    /// according to method signature format specifications.
    pub signature: u32,

    /// Index into the Param table for the first parameter.
    ///
    /// Specifies the starting position of this method's parameters in the Param table.
    /// Parameter lists are contiguous ranges ending at the next method's param_list
    /// or the end of the table. A value of 0 indicates no parameters.
    pub param_list: u32,
}

impl MethodDefRaw {
    /// Converts a MethodDefRaw entry into a Method with resolved parameters and parsed signature.
    ///
    /// This method performs complete method definition resolution, including parameter
    /// range calculation, signature parsing, and method attribute processing. The resulting
    /// owned structure provides complete method information for invocation, reflection,
    /// and type system integration.
    ///
    /// # Arguments
    /// * `strings` - The string heap for resolving method names
    /// * `blob` - The blob heap for signature data retrieval
    /// * `params_map` - Collection of all Param entries for parameter resolution
    /// * `param_ptr_map` - Collection of ParamPtr entries for indirection (if present)
    /// * `table` - The MethodDef table for parameter range calculation
    ///
    /// # Returns
    /// * `Ok(MethodRc)` - Successfully resolved method with complete parameter metadata
    /// * `Err(_)` - If signature parsing, parameter resolution, or name retrieval fails
    ///
    pub fn to_owned(
        &self,
        strings: &Strings,
        blob: &Blob,
        params_map: &ParamMap,
        param_ptr_map: &ParamPtrMap,
        table: &MetadataTable<MethodDefRaw>,
    ) -> Result<MethodRc> {
        let signature = parse_method_signature(blob.get(self.signature as usize)?)?;

        let type_params = if self.param_list == 0 || params_map.is_empty() {
            Arc::new(boxcar::Vec::new())
        } else {
            let next_row_id = self.rid + 1;
            let start = self.param_list as usize;
            let end = if next_row_id > table.row_count() {
                params_map.len() + 1
            } else {
                match table.get(next_row_id) {
                    Some(next_row) => {
                        let calculated_end = next_row.param_list as usize;
                        let expected_param_count = signature.params.len();

                        // If the calculated range would be empty but we expect parameters,
                        // use the signature to determine the correct end
                        if calculated_end <= start && expected_param_count > 0 {
                            start + expected_param_count
                        } else {
                            calculated_end
                        }
                    }
                    None => {
                        return Err(malformed_error!(
                            "Failed to resolve param_end from next row - {}",
                            next_row_id
                        ))
                    }
                }
            };

            if start > params_map.len() || end > (params_map.len() + 1) || end < start {
                Arc::new(boxcar::Vec::new())
            } else {
                let type_params = Arc::new(boxcar::Vec::with_capacity(end - start));
                for counter in start..end {
                    let actual_param_token = if param_ptr_map.is_empty() {
                        let token_value = u32::try_from(counter | 0x0800_0000).map_err(|_| {
                            malformed_error!("Token value too large: {}", counter | 0x0800_0000)
                        })?;
                        Token::new(token_value)
                    } else {
                        let param_ptr_token_value =
                            u32::try_from(counter | 0x0A00_0000).map_err(|_| {
                                malformed_error!(
                                    "ParamPtr token value too large: {}",
                                    counter | 0x0A00_0000
                                )
                            })?;
                        let param_ptr_token = Token::new(param_ptr_token_value);

                        match param_ptr_map.get(&param_ptr_token) {
                            Some(param_ptr) => {
                                let actual_param_rid = param_ptr.value().param;
                                let actual_param_token_value =
                                    u32::try_from(actual_param_rid as usize | 0x0800_0000)
                                        .map_err(|_| {
                                            malformed_error!(
                                                "Param token value too large: {}",
                                                actual_param_rid as usize | 0x0800_0000
                                            )
                                        })?;
                                Token::new(actual_param_token_value)
                            }
                            None => {
                                return Err(malformed_error!(
                                    "Failed to resolve ParamPtr - {}",
                                    counter | 0x0A00_0000
                                ))
                            }
                        }
                    };

                    match params_map.get(&actual_param_token) {
                        Some(param) => _ = type_params.push(param.value().clone()),
                        None => {
                            return Err(malformed_error!(
                                "Failed to resolve param - {}",
                                actual_param_token.value()
                            ))
                        }
                    }
                }

                type_params
            }
        };
        Ok(Arc::new(Method {
            rid: self.rid,
            token: self.token,
            meta_offset: self.offset,
            name: strings.get(self.name as usize)?.to_string(),
            impl_code_type: MethodImplCodeType::from_impl_flags(self.impl_flags),
            impl_management: MethodImplManagement::from_impl_flags(self.impl_flags),
            impl_options: MethodImplOptions::from_impl_flags(self.impl_flags),
            flags_access: MethodAccessFlags::from_method_flags(self.flags),
            flags_vtable: MethodVtableFlags::from_method_flags(self.flags),
            flags_modifiers: MethodModifiers::from_method_flags(self.flags),
            flags_pinvoke: AtomicU32::new(0),
            params: type_params,
            varargs: Arc::new(boxcar::Vec::new()),
            generic_params: Arc::new(boxcar::Vec::new()),
            generic_args: Arc::new(boxcar::Vec::new()),
            signature,
            rva: if self.rva == 0 { None } else { Some(self.rva) },
            body: OnceLock::new(),
            local_vars: Arc::new(boxcar::Vec::new()),
            overrides: OnceLock::new(),
            interface_impls: Arc::new(boxcar::Vec::new()),
            security: OnceLock::new(),
            blocks: OnceLock::new(),
            custom_attributes: Arc::new(boxcar::Vec::new()),
            // cfg: RwLock::new(None),
            // ssa: RwLock::new(None),
        }))
    }

    /// Apply a `MethodDefRaw` entry to update related metadata structures.
    ///
    /// `MethodDef` entries define methods within types. They are associated with their parent
    /// types but don't themselves modify other metadata during the dual variant resolution phase.
    /// Method-specific metadata (P/Invoke info, generic parameters, etc.) is resolved separately.
    ///
    /// # Errors
    /// Always returns `Ok(())` as `MethodDef` entries don't modify other tables directly.
    pub fn apply(&self) -> Result<()> {
        Ok(())
    }
}

impl<'a> RowDefinition<'a> for MethodDefRaw {
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* rva */           4 +
            /* impl_flags */    2 +
            /* flags */         2 +
            /* name */          sizes.str_bytes() +
            /* signature */     sizes.blob_bytes() +
            /* param_list */    sizes.table_index_bytes(TableId::Param)
        )
    }

    fn read_row(
        data: &'a [u8],
        offset: &mut usize,
        rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<Self> {
        Ok(MethodDefRaw {
            rid,
            token: Token::new(0x0600_0000 + rid),
            offset: *offset,
            rva: read_le_at::<u32>(data, offset)?,
            impl_flags: u32::from(read_le_at::<u16>(data, offset)?),
            flags: u32::from(read_le_at::<u16>(data, offset)?),
            name: read_le_at_dyn(data, offset, sizes.is_large_str())?,
            signature: read_le_at_dyn(data, offset, sizes.is_large_blob())?,
            param_list: read_le_at_dyn(data, offset, sizes.is_large(TableId::Param))?,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::metadata::tables::{MetadataTable, TableInfo};

    use super::*;

    #[test]
    fn crafted_short() {
        let data = vec![
            0x01, 0x01, 0x01, 0x01, // rva
            0x02, 0x02, // impl_flags
            0x03, 0x03, // flags
            0x04, 0x04, // name
            0x05, 0x05, // signature
            0x06, 0x06, // param_list
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::MethodDef, 1)],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<MethodDefRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: MethodDefRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x06000001);
            assert_eq!(row.rva, 0x01010101);
            assert_eq!(row.impl_flags, 0x0202);
            assert_eq!(row.flags, 0x0303);
            assert_eq!(row.name, 0x0404);
            assert_eq!(row.signature, 0x0505);
            assert_eq!(row.param_list, 0x0606);
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
            0x01, 0x01, 0x01, 0x01, // rva
            0x02, 0x02, // impl_flags
            0x03, 0x03, // flags
            0x04, 0x04, 0x04, 0x04, // name
            0x05, 0x05, 0x05, 0x05, // signature
            0x06, 0x06, 0x06, 0x06, // param_list
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Param, u16::MAX as u32 + 2)],
            true,
            true,
            true,
        ));
        let table = MetadataTable::<MethodDefRaw>::new(&data, u16::MAX as u32 + 2, sizes).unwrap();

        let eval = |row: MethodDefRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x06000001);
            assert_eq!(row.rva, 0x01010101);
            assert_eq!(row.impl_flags, 0x0202);
            assert_eq!(row.flags, 0x0303);
            assert_eq!(row.name, 0x04040404);
            assert_eq!(row.signature, 0x05050505);
            assert_eq!(row.param_list, 0x06060606);
        };

        {
            let row = table.get(1).unwrap();
            eval(row);
        }
    }
}
