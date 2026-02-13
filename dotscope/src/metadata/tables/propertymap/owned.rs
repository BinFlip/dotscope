//! # `PropertyMap` Owned Implementation
//!
//! This module provides the owned variant of `PropertyMap` table entries with resolved
//! references and complete metadata context for application use.

use crate::{
    metadata::{tables::PropertyList, token::Token, typesystem::CilTypeRef},
    Result,
};

/// Owned representation of a `PropertyMap` table entry with complete metadata context.
///
/// This structure represents a fully processed entry from the `PropertyMap` metadata table
/// (ID 0x15), which establishes the relationship between types and their properties.
/// It contains resolved type and property references, enabling efficient property
/// enumeration and type-property binding operations.
///
/// ## Purpose
///
/// The `PropertyMap` table serves as the foundation for type-property relationships:
/// - **Type-Property Binding**: Links types to their associated properties
/// - **Property Enumeration**: Enables discovery of all properties for a given type
/// - **Inheritance Support**: Facilitates property inheritance and override resolution
/// - **Reflection Foundation**: Supports property-based reflection and metadata queries
///
/// ## Owned vs Raw
///
/// This owned variant provides:
/// - Resolved parent type references from the type system
/// - Complete property collections with resolved property entries
/// - Validated property-type relationships and constraints
/// - Integration with the broader metadata resolution system
/// - High-level access methods for property enumeration
///
/// ## References
///
/// - ECMA-335, Partition II, §22.35 - `PropertyMap` table specification
/// - [`crate::metadata::tables::PropertyMapRaw`] - Raw variant for comparison
/// - [`crate::metadata::tables::Property`] - Property definitions
/// - [`crate::metadata::typesystem::CilTypeRef`] - Type reference details
pub struct PropertyMapEntry {
    /// Row identifier within the `PropertyMap` table (1-based indexing).
    ///
    /// This field provides the logical position of this entry within the `PropertyMap` table,
    /// following the standard 1-based indexing convention used throughout .NET metadata.
    pub rid: u32,

    /// Metadata token uniquely identifying this `PropertyMap` entry.
    ///
    /// The token combines the table identifier (`PropertyMap` = 0x15) with the row ID,
    /// providing a unique reference for this property mapping across the entire
    /// metadata system.
    pub token: Token,

    /// Byte offset of this entry within the metadata stream.
    ///
    /// This offset indicates the exact position of this `PropertyMap` entry within the
    /// metadata stream, enabling direct access to the raw table data and supporting
    /// metadata analysis and debugging operations.
    pub offset: usize,

    /// The parent type that owns these properties.
    ///
    /// This field contains a resolved reference to the type (`TypeDef`, `TypeRef`, or `TypeSpec`)
    /// that declares and owns the properties in this mapping. The reference provides
    /// access to the complete type information and integration with the type system.
    pub parent: CilTypeRef,

    /// The collection of properties belonging to the parent type.
    ///
    /// This field contains the resolved list of properties associated with the parent
    /// type, enabling efficient property enumeration and access. Properties are
    /// resolved from the `Property` table with potential indirection through `PropertyPtr`.
    pub properties: PropertyList,
}

impl PropertyMapEntry {
    /// Apply a `PropertyMapEntry` to update the parent type with its properties.
    ///
    /// Since this is the owned structure, all references are already resolved, so we can
    /// efficiently update the parent type without re-resolving anything.
    ///
    /// # Errors
    /// Returns an error if the parent type reference is invalid or if property assignment fails.
    pub fn apply(&self) -> Result<()> {
        if let Some(parent_type) = self.parent.upgrade() {
            for (_, property) in self.properties.iter() {
                _ = parent_type.properties.push(property.clone());
            }
            Ok(())
        } else {
            Err(malformed_error!(
                "PropertyMapEntry parent type reference is no longer valid"
            ))
        }
    }
}
