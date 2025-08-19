//! Owned Field structures for the Field metadata table.
//!
//! This module provides the [`crate::metadata::tables::field::owned::Field`] struct which represents field definitions
//! with resolved references and owned data. Fields define the data members of types
//! in the `TypeDef` table, including instance fields, static fields, and literals.
//!
//! # ECMA-335 Reference
//! See ECMA-335, Partition II, §22.15 for the Field table specification.

use std::sync::OnceLock;

use crate::metadata::{
    customattributes::CustomAttributeValueList, marshalling::MarshallingInfo,
    signatures::SignatureField, token::Token, typesystem::CilPrimitive,
};

/// Represents a field definition with resolved indexes and owned data.
///
/// A field defines a data member of a type, including instance fields, static fields,
/// and compile-time constants (literals). This structure contains all resolved
/// information about the field, including its signature, optional default value,
/// marshalling information, and custom attributes.
///
/// # Field Types
/// - **Instance fields**: Non-static data members of a class or value type
/// - **Static fields**: Class-level data members shared across all instances
/// - **Literals**: Compile-time constants with default values
///
/// # ECMA-335 Reference
/// See ECMA-335, Partition II, §22.15 for the complete Field table specification.
pub struct Field {
    /// The row identifier in the Field table.
    ///
    /// This 1-based index uniquely identifies this field within the Field table.
    /// Combined with the table type, it forms the field's unique identity.
    pub rid: u32,

    /// The metadata token for this field.
    ///
    /// A [`crate::metadata::token::Token`] that uniquely identifies this field across the entire assembly.
    /// The token encodes both the table type (Field) and the row ID.
    pub token: Token,

    /// The byte offset of this field in the metadata tables stream.
    ///
    /// This offset points to the start of this field's row data within the
    /// metadata tables stream, used for binary parsing and navigation.
    pub offset: usize,

    /// Field attributes and flags.
    ///
    /// A 2-byte bitmask of type `FieldAttributes` as defined in ECMA-335, §II.23.1.5.
    /// This includes accessibility modifiers, static/instance designation, and
    /// special flags like `HasDefault`, `HasFieldRVA`, and `HasFieldMarshal`.
    ///
    /// Common flag values:
    /// - `0x0001`: `CompilerControlled`
    /// - `0x0002`: `Private`  
    /// - `0x0003`: `FamANDAssem`
    /// - `0x0004`: `Assembly`
    /// - `0x0005`: `Family`
    /// - `0x0006`: `FamORAssem`
    /// - `0x0007`: `Public`
    /// - `0x0010`: `Static`
    /// - `0x0020`: `Literal`
    /// - `0x0040`: `NotSerialized`
    /// - `0x0080`: `HasFieldRVA`
    /// - `0x1000`: `HasDefault`
    /// - `0x2000`: `HasFieldMarshal`
    // ToDo: Make this a proper bitfield for cleaner access
    pub flags: u32,

    /// The name of the field.
    ///
    /// A string from the String heap containing the field's identifier name.
    /// This name is used for field resolution and debugging information.
    pub name: String,

    /// The field's type signature.
    ///
    /// A [`crate::metadata::signatures::SignatureField`] that describes the field's type, including
    /// primitive types, object references, value types, and arrays.
    /// This signature is parsed from the Blob heap.
    pub signature: SignatureField,

    /// Default value for this field (lazy-loaded).
    ///
    /// Contains the default value if the field has the `HasDefault` flag set.
    /// This is typically used for literal fields and fields with explicit
    /// default values. The value is loaded on-demand from the Constant table.
    pub default: OnceLock<CilPrimitive>,

    /// Relative Virtual Address for field data (lazy-loaded).
    ///
    /// Contains the RVA if the field has the `HasFieldRVA` flag set.
    /// This points to the field's initial data in the PE file,
    /// typically used for static fields with explicit initial values.
    pub rva: OnceLock<u32>,

    /// Field layout offset within the containing type (lazy-loaded).
    ///
    /// A 4-byte value specifying the byte offset of the field within its
    /// containing class or value type. This is loaded from the `FieldLayout`
    /// table when explicit field positioning is used.
    pub layout: OnceLock<u32>,

    /// Field marshalling information (lazy-loaded).
    ///
    /// Contains marshalling information if the field has the `HasFieldMarshal`
    /// flag set. This describes how the field should be marshalled when
    /// crossing managed/unmanaged boundaries.
    pub marshal: OnceLock<MarshallingInfo>,

    /// Custom attributes applied to this field.
    ///
    /// A collection of custom attributes that provide additional metadata
    /// for this field, such as serialization hints, validation attributes,
    /// or framework-specific annotations.
    pub custom_attributes: CustomAttributeValueList,
}
