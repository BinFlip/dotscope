//! # `MethodSpec` Owned Implementation
//!
//! This module provides the owned variant of `MethodSpec` table entries with resolved
//! references and owned data structures for efficient runtime access.

use crate::metadata::{
    customattributes::CustomAttributeValueList,
    signatures::SignatureMethodSpec,
    token::Token,
    typesystem::{CilTypeRefList, CilTypeReference},
};

/// Owned representation of a `MethodSpec` table entry with resolved references.
///
/// This structure represents a processed entry from the `MethodSpec` metadata table,
/// which defines instantiations of generic methods with concrete type arguments.
/// Unlike [`MethodSpecRaw`](crate::metadata::tables::MethodSpecRaw), this version contains resolved references
/// to actual method and type objects for efficient runtime access.
///
/// ## Purpose
///
/// `MethodSpec` entries enable generic method instantiation by:
/// - Linking to the generic method definition or member reference
/// - Specifying concrete type arguments for generic parameters
/// - Providing parsed instantiation signatures for runtime use
/// - Enabling proper generic method dispatch and type safety
///
/// ## Generic Method Resolution
///
/// The generic method resolution process involves:
/// 1. **Method Lookup**: Resolving the `method` field to the actual generic method
/// 2. **Signature Parsing**: Parsing the `instantiation` signature from the blob heap
/// 3. **Type Resolution**: Resolving each generic argument using the type registry
/// 4. **Application**: Applying the instantiation to the target method
pub struct MethodSpec {
    /// Row identifier within the `MethodSpec` table.
    ///
    /// This 1-based index uniquely identifies this entry within the table.
    /// Combined with the table ID, it forms the complete metadata token.
    pub rid: u32,

    /// Metadata token for this `MethodSpec` entry.
    ///
    /// Format: 0x2BXXXXXX where XXXXXX is the row ID.
    /// This token uniquely identifies this entry across the entire metadata.
    pub token: Token,

    /// Byte offset of this entry in the original metadata stream.
    ///
    /// Used for debugging and low-level metadata inspection.
    /// Points to the start of this entry's data in the file.
    pub offset: usize,

    /// Resolved reference to the generic method.
    ///
    /// Points to either a [`MethodDef`](crate::metadata::method::Method) for internal methods
    /// or a [`MemberRef`](crate::metadata::tables::MemberRef) for external methods.
    /// This is the generic method template that will be instantiated with concrete type arguments.
    pub method: CilTypeReference,

    /// Parsed method specification signature containing type arguments.
    ///
    /// Contains the parsed signature from the blob heap specifying the concrete type
    /// arguments for the generic method parameters. This signature defines how to
    /// instantiate the generic method with specific types.
    pub instantiation: SignatureMethodSpec,

    /// Custom attributes applied to this method specification.
    ///
    /// Thread-safe collection of custom attributes that provide additional metadata
    /// for this specific method instantiation.
    pub custom_attributes: CustomAttributeValueList,

    /// Resolved generic type arguments for this method specification.
    ///
    /// Contains the concrete types that replace the generic parameters in the method.
    /// These types are resolved from the instantiation signature using the type registry
    /// and represent the actual types used for this instantiation.
    pub generic_args: CilTypeRefList,
}
