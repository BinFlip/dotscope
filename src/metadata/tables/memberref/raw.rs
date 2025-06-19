//! Raw `MemberRef` table structure with unresolved coded indexes and blob references.
//!
//! This module provides the [`MemberRefRaw`] struct, which represents external member references
//! as stored in the metadata stream. The structure contains unresolved coded indexes
//! and blob heap references that require processing to establish member access information.
//!
//! # Purpose
//! [`MemberRefRaw`] serves as the direct representation of `MemberRef` table entries from the
//! binary metadata stream, before reference resolution and signature parsing. This raw format
//! is processed during metadata loading to create [`MemberRef`] instances with resolved
//! references and parsed signature information.
//!
//! [`MemberRef`]: crate::metadata::tables::MemberRef

use std::sync::{atomic::AtomicBool, Arc, OnceLock};

use crate::{
    file::io::read_le_at_dyn,
    metadata::{
        signatures::{
            parse_field_signature, parse_method_signature, SignatureMethod, TypeSignature,
        },
        streams::{Blob, Strings},
        tables::{
            CodedIndex, CodedIndexType, MemberRef, MemberRefRc, MemberRefSignature, Param, ParamRc,
            RowDefinition, TableInfoRef,
        },
        token::Token,
        typesystem::{CilTypeReference, TypeRegistry},
    },
    Result,
};

/// Raw `MemberRef` table entry with unresolved indexes and blob references.
///
/// This structure represents an external member reference as stored directly in the metadata
/// stream. All references are unresolved coded indexes or heap offsets that require processing
/// during metadata loading to establish member access and signature information.
///
/// # Table Structure (ECMA-335 §22.25)
/// | Column | Size | Description |
/// |--------|------|-------------|
/// | Class | `MemberRefParent` coded index | Declaring type or module reference |
/// | Name | String index | Member name identifier |
/// | Signature | Blob index | Member signature (method or field) |
///
/// # Coded Index Resolution
/// The `class` field uses the `MemberRefParent` coded index encoding:
/// - **Tag 0**: `TypeDef` table (current assembly types)
/// - **Tag 1**: `TypeRef` table (external assembly types)
/// - **Tag 2**: `ModuleRef` table (external modules)
/// - **Tag 3**: `MethodDef` table (vararg method signatures)
/// - **Tag 4**: `TypeSpec` table (generic type instantiations)
///
/// # Signature Parsing
/// Member signatures in the blob heap are parsed according to their type:
/// - **Field signatures**: Start with 0x06, contain type information
/// - **Method signatures**: Start with calling convention, contain parameter and return types
/// - **Generic signatures**: Include type parameter information
/// - **Property signatures**: Start with 0x08, handled as field signatures
#[derive(Clone, Debug)]
pub struct MemberRefRaw {
    /// Row identifier within the `MemberRef` table.
    ///
    /// Unique identifier for this member reference entry, used for internal
    /// table management and token generation.
    pub rid: u32,

    /// Metadata token for this `MemberRef` entry (`TableId` 0x0A).
    ///
    /// Computed as `0x0A000000 | rid` to create the full token value
    /// for referencing this member from other metadata structures.
    pub token: Token,

    /// Byte offset of this entry within the raw table data.
    ///
    /// Used for efficient table navigation and binary metadata processing.
    pub offset: usize,

    /// `MemberRefParent` coded index for the declaring type or module.
    ///
    /// Points to `TypeDef`, `TypeRef`, `ModuleRef`, `MethodDef`, or `TypeSpec` tables
    /// to specify the context where this member is declared. Requires
    /// coded index resolution during processing to determine the actual parent.
    pub class: CodedIndex,

    /// String heap index for the member name.
    ///
    /// References the member identifier name in the string heap. For constructors,
    /// this is typically ".ctor" (instance) or ".cctor" (static).
    pub name: u32,

    /// Blob heap index for the member signature.
    ///
    /// References signature data in the blob heap that describes the member type,
    /// calling convention (for methods), parameters, and return type. Must be
    /// parsed according to signature format specifications.
    pub signature: u32,
}

impl MemberRefRaw {
    /// Creates parameter metadata structures from a parsed method signature.
    ///
    /// This method generates parameter objects similar to those created for `MethodDef`
    /// entries, enabling unified parameter handling across both definition and reference
    /// contexts. The created parameters include return type information and all method
    /// parameters with proper sequence numbering.
    ///
    /// # Parameter Structure
    /// The created parameter collection includes:
    /// - **Return parameter**: Sequence 0, contains return type information
    /// - **Method parameters**: Sequence 1-N, contain parameter type information
    /// - **Placeholder metadata**: Names are None as `MemberRef` parameters lack names
    ///
    /// # Arguments
    /// * `method_sig` - The parsed method signature containing parameter and return type information
    /// * `_strings` - The strings heap (unused as `MemberRef` parameters don't have names)
    ///
    /// # Returns
    /// Thread-safe collection of parameter metadata structures with type information applied.
    fn create_params_from_signature(
        method_sig: &SignatureMethod,
        _strings: &Strings,
    ) -> Arc<boxcar::Vec<ParamRc>> {
        let params = Arc::new(boxcar::Vec::with_capacity(method_sig.params.len() + 1));

        // Create return parameter (sequence 0)
        let return_param = Arc::new(Param {
            rid: 0,               // No actual row ID for MemberRef params
            token: Token::new(0), // Placeholder token
            offset: 0,
            flags: 0,
            sequence: 0, // Return parameter
            name: None,  // MemberRef parameters don't have names from metadata
            default: OnceLock::new(),
            marshal: OnceLock::new(),
            modifiers: Arc::new(boxcar::Vec::new()),
            base: OnceLock::new(),
            is_by_ref: AtomicBool::new(method_sig.return_type.by_ref),
            custom_attributes: Arc::new(boxcar::Vec::new()),
        });
        params.push(return_param);

        // Create parameters for each method parameter
        for (index, param_sig) in method_sig.params.iter().enumerate() {
            let param = Arc::new(Param {
                rid: 0,               // No actual row ID for MemberRef params
                token: Token::new(0), // Placeholder token
                offset: 0,
                flags: 0,
                #[allow(clippy::cast_possible_truncation)]
                sequence: (index + 1) as u32, // Parameter sequence starts at 1
                name: None, // MemberRef parameters don't have names from metadata
                default: OnceLock::new(),
                marshal: OnceLock::new(),
                modifiers: Arc::new(boxcar::Vec::new()),
                base: OnceLock::new(),
                is_by_ref: AtomicBool::new(param_sig.by_ref),
                custom_attributes: Arc::new(boxcar::Vec::new()),
            });
            params.push(param);
        }

        params
    }

    /// Applies a `MemberRefRaw` entry to update related metadata structures.
    ///
    /// `MemberRef` entries represent references to external members and don't require
    /// cross-table modifications during the dual variant resolution phase. Unlike
    /// definition tables (`TypeDef`, `MethodDef`, etc.), reference tables are primarily
    /// descriptive and don't modify other metadata structures.
    ///
    /// # Design Rationale
    /// Member references are passive metadata that describe external dependencies
    /// rather than active definitions that need to update type systems or establish
    /// relationships with other metadata tables.
    ///
    /// # Returns
    /// * `Ok(())` - Always succeeds as `MemberRef` entries don't modify other tables
    /// * `Err(_)` - Reserved for future error conditions (currently infallible)
    ///
    /// # Errors
    ///
    /// This function is infallible and always returns `Ok(())`. Reserved for future error conditions.
    pub fn apply(&self) -> Result<()> {
        Ok(())
    }

    /// Converts a `MemberRefRaw` entry into a `MemberRef` with resolved references and parsed signatures.
    ///
    /// This method performs complete member reference resolution, including parent type resolution,
    /// signature parsing, and parameter metadata creation. The resulting owned structure provides
    /// type-safe access to all member information for invocation and access operations.
    ///
    /// # Arguments
    /// * `strings` - The string heap for resolving member names
    /// * `blob` - The blob heap for signature data retrieval
    /// * `types` - Type registry for signature parsing and type resolution
    /// * `get_ref` - Closure for resolving coded indexes to type references
    ///
    /// # Returns
    /// * `Ok(MemberRefRc)` - Successfully resolved member reference with complete metadata
    /// * `Err(_)` - If signature parsing, parent resolution, or name retrieval fails
    ///
    /// # Signature Format Detection
    /// Signature type is determined by the first byte of blob data:
    /// - `0x06`: Field signature with type information
    /// - Other values: Method signature with calling convention and parameters
    ///
    /// # Errors
    ///
    /// Returns an error if signature parsing, parent resolution, or name retrieval fails.
    pub fn to_owned<F>(
        &self,
        strings: &Strings,
        blob: &Blob,
        types: &Arc<TypeRegistry>,
        get_ref: F,
    ) -> Result<MemberRefRc>
    where
        F: Fn(&CodedIndex) -> CilTypeReference,
    {
        let signature_data = blob.get(self.signature as usize)?;
        if signature_data.is_empty() {
            return Err(malformed_error!("Invalid signature data"));
        }

        let (signature, params) = if signature_data[0] == 0x6 {
            (
                MemberRefSignature::Field(parse_field_signature(signature_data)?),
                Arc::new(boxcar::Vec::new()),
            )
        } else {
            let method_sig = parse_method_signature(signature_data)?;
            let params = Self::create_params_from_signature(&method_sig, strings);

            let method_param_count = Some(method_sig.params.len());
            for (_, param) in params.iter() {
                if param.sequence == 0 {
                    // Return parameter
                    param.apply_signature(
                        &method_sig.return_type,
                        types.clone(),
                        method_param_count,
                    )?;
                } else {
                    // Regular parameter
                    let index = (param.sequence - 1) as usize;
                    if let Some(param_signature) = method_sig.params.get(index) {
                        param.apply_signature(
                            param_signature,
                            types.clone(),
                            method_param_count,
                        )?;
                    }
                }
            }

            (MemberRefSignature::Method(method_sig), params)
        };

        let declaredby = get_ref(&self.class);
        if matches!(declaredby, CilTypeReference::None) {
            return Err(malformed_error!(
                "Failed to resolve class token - {}",
                self.class.token.value()
            ));
        }

        match (&signature, &declaredby) {
            (
                MemberRefSignature::Method(method_sig),
                CilTypeReference::TypeDef(_parent_type) | CilTypeReference::TypeRef(_parent_type),
            ) => {
                if strings.get(self.name as usize)?.is_empty() {
                    return Err(malformed_error!(
                        "Method name cannot be empty for MemberRef token {}",
                        self.token.value()
                    ));
                }

                if method_sig.params.len() > 255 {
                    return Err(malformed_error!(
                        "Method signature has too many parameters ({}) for MemberRef token {}",
                        method_sig.params.len(),
                        self.token.value()
                    ));
                }
            }
            (
                MemberRefSignature::Field(field_sig),
                CilTypeReference::TypeDef(_parent_type) | CilTypeReference::TypeRef(_parent_type),
            ) => {
                if strings.get(self.name as usize)?.is_empty() {
                    return Err(malformed_error!(
                        "Field name cannot be empty for MemberRef token {}",
                        self.token.value()
                    ));
                }

                if matches!(field_sig.base, TypeSignature::Unknown) {
                    return Err(malformed_error!(
                        "Field signature has unknown type for MemberRef token {}",
                        self.token.value()
                    ));
                }
            }
            // For module references and other parent types, we allow more flexibility
            // as these might reference external or special members
            _ => {}
        }

        let member_ref = Arc::new(MemberRef {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            declaredby,
            name: strings.get(self.name as usize)?.to_string(),
            signature,
            params,
            custom_attributes: Arc::new(boxcar::Vec::new()),
        });

        Ok(member_ref)
    }
}

impl<'a> RowDefinition<'a> for MemberRefRaw {
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* class */     sizes.coded_index_bytes(CodedIndexType::MemberRefParent) +
            /* name */      sizes.str_bytes() +
            /* signature */ sizes.blob_bytes()
        )
    }

    fn read_row(
        data: &'a [u8],
        offset: &mut usize,
        rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<Self> {
        Ok(MemberRefRaw {
            rid,
            token: Token::new(0x0A00_0000 + rid),
            offset: *offset,
            class: CodedIndex::read(data, offset, sizes, CodedIndexType::MemberRefParent)?,
            name: read_le_at_dyn(data, offset, sizes.is_large_str())?,
            signature: read_le_at_dyn(data, offset, sizes.is_large_blob())?,
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
            0x01, 0x01, // class
            0x02, 0x02, // name
            0x03, 0x03, // signature
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::MethodDef, 1)],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<MemberRefRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: MemberRefRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x0A000001);
            assert_eq!(
                row.class,
                CodedIndex {
                    tag: TableId::TypeRef,
                    row: 32,
                    token: Token::new(32 | 0x01000000),
                }
            );
            assert_eq!(row.name, 0x202);
            assert_eq!(row.signature, 0x303);
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
            0x01, 0x01, 0x01, 0x01, // class
            0x02, 0x02, 0x02, 0x02, // name
            0x03, 0x03, 0x03, 0x03, // signature
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::TypeDef, u16::MAX as u32 + 3)],
            true,
            true,
            true,
        ));
        let table = MetadataTable::<MemberRefRaw>::new(&data, u16::MAX as u32 + 3, sizes).unwrap();

        let eval = |row: MemberRefRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x0A000001);
            assert_eq!(
                row.class,
                CodedIndex {
                    tag: TableId::TypeRef,
                    row: 0x202020,
                    token: Token::new(0x202020 | 0x01000000),
                }
            );
            assert_eq!(row.name, 0x2020202);
            assert_eq!(row.signature, 0x3030303);
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
