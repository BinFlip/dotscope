//! # MethodSpec Raw Implementation
//!
//! This module provides the raw variant of MethodSpec table entries with unresolved
//! indexes for initial parsing and memory-efficient storage.

use std::sync::Arc;

use crate::{
    file::io::read_le_at_dyn,
    metadata::{
        signatures::parse_method_spec_signature,
        streams::Blob,
        tables::{
            CodedIndex, CodedIndexType, MethodSpec, MethodSpecRc, RowDefinition, TableInfoRef,
        },
        token::Token,
        typesystem::{CilTypeReference, TypeRegistry, TypeResolver},
    },
    Result,
};

#[derive(Clone, Debug)]
/// Raw representation of a MethodSpec table entry with unresolved indexes.
///
/// This structure represents an unprocessed entry from the MethodSpec metadata table
/// (ID 0x2B), which defines instantiations of generic methods with concrete type arguments.
/// It contains raw index values that require resolution to actual metadata objects.
///
/// ## Purpose
///
/// The MethodSpec table enables generic method instantiation by:
/// - Referencing the generic method definition or member reference
/// - Specifying the blob heap location of the instantiation signature
/// - Providing the foundation for runtime generic method dispatch
///
/// ## Raw vs Owned
///
/// This raw variant is used during initial metadata parsing and contains:
/// - Unresolved table indexes requiring lookup
/// - Minimal memory footprint for storage
/// - Direct representation of file format
///
/// Use [`MethodSpec`] for resolved references and runtime access.
///
/// ## ECMA-335 Reference
///
/// Corresponds to ECMA-335 §II.22.29 MethodSpec table structure.
pub struct MethodSpecRaw {
    /// Row identifier within the MethodSpec table.
    ///
    /// This 1-based index uniquely identifies this entry within the table.
    /// Combined with table ID 0x2B, forms the metadata token 0x2BXXXXXX.
    pub rid: u32,

    /// Metadata token for this MethodSpec entry.
    ///
    /// Format: 0x2BXXXXXX where XXXXXX is the row ID.
    /// Used for cross-referencing this entry from other metadata structures.
    pub token: Token,

    /// Byte offset of this entry in the original metadata stream.
    ///
    /// Points to the start of this entry's data in the metadata file.
    /// Used for debugging and low-level metadata inspection.
    pub offset: usize,

    /// Raw MethodDefOrRef coded index to the generic method.
    ///
    /// This coded index identifies the generic method that will be instantiated:
    /// - Low 1 bit: Table tag (0=MethodDef, 1=MemberRef)
    /// - High bits: Row index in the target table
    ///
    /// Must be resolved using the appropriate table to get the actual method reference.
    /// Index size depends on table sizes (2 or 4 bytes).
    pub method: CodedIndex,

    /// Raw index into the blob heap containing the instantiation signature.
    ///
    /// Points to a [`MethodSpecSignature`](crate::metadata::signatures::SignatureMethodSpec) in the blob heap
    /// that specifies the concrete type arguments for the generic method parameters.
    ///
    /// The signature format follows ECMA-335 §II.23.2.15 and contains:
    /// - Generic argument count
    /// - Type signatures for each generic argument
    ///
    /// Index size depends on blob heap size (2 or 4 bytes).
    pub instantiation: u32,
}

impl MethodSpecRaw {
    /// Converts this raw entry to an owned [`MethodSpec`] and applies the generic instantiation.
    ///
    /// This method combines the functionality of resolving indexes, parsing the signature,
    /// resolving generic arguments, and applying them to the target method all in one step.
    /// It's the primary method for processing MethodSpec entries during metadata loading.
    ///
    /// ## Arguments
    ///
    /// * `get_ref` - Function to resolve coded index to [`CilTypeReference`]
    /// * `blob` - The blob heap containing the instantiation signature
    /// * `types` - The type registry for resolving generic argument types
    ///
    /// ## Returns
    ///
    /// A reference-counted [`MethodSpecRc`] containing the resolved and applied entry.
    ///
    /// ## Errors
    ///
    /// - Method token is invalid or cannot be resolved
    /// - Referenced method or member reference cannot be resolved
    /// - Blob heap entry is malformed or missing
    /// - Method specification signature cannot be parsed
    /// - Generic type arguments cannot be resolved
    /// - Target method cannot accept the generic instantiation
    pub fn to_owned_and_apply<F>(
        &self,
        get_ref: F,
        blob: &Blob,
        types: &Arc<TypeRegistry>,
    ) -> Result<MethodSpecRc>
    where
        F: Fn(&CodedIndex) -> CilTypeReference,
    {
        let method = get_ref(&self.method);
        if matches!(method, CilTypeReference::None) {
            return Err(malformed_error!(
                "Failed to resolve method token - {}",
                self.method.token.value()
            ));
        }

        let instantiation = parse_method_spec_signature(blob.get(self.instantiation as usize)?)?;
        let generic_args = Arc::new(boxcar::Vec::with_capacity(instantiation.generic_args.len()));

        let mut resolver = TypeResolver::new(types.clone());
        for type_sig in &instantiation.generic_args {
            let resolved_type = resolver.resolve(type_sig)?;
            generic_args.push(resolved_type.into());
        }

        let method_spec = Arc::new(MethodSpec {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            method: method.clone(),
            instantiation,
            custom_attributes: Arc::new(boxcar::Vec::new()),
            generic_args,
        });

        match &method {
            CilTypeReference::MethodDef(method_ref) => {
                if let Some(method_def) = method_ref.upgrade() {
                    method_def.generic_args.push(method_spec.clone());
                } else {
                    return Err(malformed_error!(
                        "Failed to resolve method - {}",
                        self.method.token.value()
                    ));
                }
            }
            CilTypeReference::MemberRef(member_ref) => {
                match &member_ref.declaredby {
                    CilTypeReference::TypeRef(ciltype)
                    | CilTypeReference::TypeDef(ciltype)
                    | CilTypeReference::TypeSpec(ciltype) => {
                        if let Some(args) = ciltype.generic_args() {
                            args.push(method_spec.clone());
                        }
                    }
                    CilTypeReference::MethodDef(target_method) => {
                        if let Some(target_method) = target_method.upgrade() {
                            target_method.generic_args.push(method_spec.clone());
                        }
                    }
                    CilTypeReference::ModuleRef(_module) => {
                        // ToDo: ModuleRef case is not yet implemented
                    }
                    _ => {
                        return Err(malformed_error!("Invalid memberref type reference"));
                    }
                }
            }
            _ => {
                return Err(malformed_error!("Invalid method type reference"));
            }
        }

        Ok(method_spec)
    }
}

impl<'a> RowDefinition<'a> for MethodSpecRaw {
    /// Calculates the byte size of a MethodSpec table row.
    ///
    /// The row size depends on the metadata table sizes and is calculated as:
    /// - `method`: 2 or 4 bytes (depends on MethodDefOrRef coded index size)
    /// - `instantiation`: 2 or 4 bytes (depends on blob heap size)
    ///
    /// ## Arguments
    /// * `sizes` - Table size information for calculating index widths
    ///
    /// ## Returns
    /// Total byte size of one table row
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* method */        sizes.coded_index_bytes(CodedIndexType::MethodDefOrRef) +
            /* instantiation */ sizes.blob_bytes()
        )
    }

    /// Reads a single MethodSpec table row from binary data.
    ///
    /// Parses the binary representation according to ECMA-335 §II.22.29:
    /// 1. **Method** (2-4 bytes): MethodDefOrRef coded index to the generic method
    /// 2. **Instantiation** (2-4 bytes): Index into blob heap containing signature
    ///
    /// ## Arguments
    /// * `data` - Binary data containing the table
    /// * `offset` - Current read position (updated by this method)
    /// * `rid` - Row identifier for this entry (1-based)
    /// * `sizes` - Table size information for proper index width calculation
    ///
    /// ## Returns
    /// Parsed [`MethodSpecRaw`] instance with populated fields
    ///
    /// ## Errors
    /// Returns an error if:
    /// - Insufficient data remaining at offset
    /// - Invalid coded index encoding
    /// - Data corruption or malformed structure
    fn read_row(
        data: &'a [u8],
        offset: &mut usize,
        rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<Self> {
        Ok(MethodSpecRaw {
            rid,
            token: Token::new(0x2B00_0000 + rid),
            offset: *offset,
            method: CodedIndex::read(data, offset, sizes, CodedIndexType::MethodDefOrRef)?,
            instantiation: read_le_at_dyn(data, offset, sizes.is_large_blob())?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::tables::{MetadataTable, TableId, TableInfo};

    #[test]
    fn crafted_short() {
        let data = vec![
            0x01, 0x00, // method
            0x02, 0x02, // instantiation
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::MethodSpec, 1),
                (TableId::MethodDef, 10),
                (TableId::MemberRef, 10),
            ],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<MethodSpecRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: MethodSpecRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x2B000001);
            assert_eq!(
                row.method,
                CodedIndex {
                    tag: TableId::MemberRef,
                    row: 0,
                    token: Token::new(0x0A000000),
                }
            );
            assert_eq!(row.instantiation, 0x0202);
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
            0x01, 0x00, 0x00, 0x00, // method
            0x02, 0x02, 0x02, 0x02, // instantiation
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::MethodSpec, u16::MAX as u32 + 3),
                (TableId::MethodDef, u16::MAX as u32 + 3),
                (TableId::MemberRef, u16::MAX as u32 + 3),
            ],
            true,
            true,
            true,
        ));
        let table = MetadataTable::<MethodSpecRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: MethodSpecRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x2B000001);
            assert_eq!(
                row.method,
                CodedIndex {
                    tag: TableId::MemberRef,
                    row: 0,
                    token: Token::new(0x0A000000),
                }
            );
            assert_eq!(row.instantiation, 0x02020202);
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
}
