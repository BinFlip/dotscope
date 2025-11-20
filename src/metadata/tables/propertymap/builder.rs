//! # PropertyMap Builder
//!
//! Provides a fluent API for building PropertyMap table entries that establish ownership relationships
//! between types and their properties. The PropertyMap table defines contiguous ranges of properties that
//! belong to specific types, enabling efficient enumeration and lookup of properties by owning type.
//!
//! ## Overview
//!
//! The `PropertyMapBuilder` enables creation of property map entries with:
//! - Parent type specification (required)
//! - Property list starting index specification (required)
//! - Validation of type tokens and property indices
//! - Automatic token generation and metadata management
//!
//! ## Usage
//!
//! ```rust,ignore
//! # use dotscope::prelude::*;
//! # use std::path::Path;
//! # fn main() -> dotscope::Result<()> {
//! # let view = CilAssemblyView::from_file(Path::new("test.dll"))?;
//! # let assembly = CilAssembly::new(view);
//! # let mut context = BuilderContext::new(assembly);
//!
//! // Create a type first
//! let type_token = TypeDefBuilder::new()
//!     .name("MyClass")
//!     .namespace("MyApp")
//!     .public_class()
//!     .build(&mut context)?;
//!
//! // Create property signatures
//! let string_property_sig = &[0x08, 0x1C]; // PROPERTY calling convention + ELEMENT_TYPE_OBJECT
//! let int_property_sig = &[0x08, 0x08]; // PROPERTY calling convention + ELEMENT_TYPE_I4
//!
//! // Create properties
//! let prop1_token = PropertyBuilder::new()
//!     .name("Name")
//!     .signature(string_property_sig)
//!     .build(&mut context)?;
//!
//! let prop2_token = PropertyBuilder::new()
//!     .name("Count")
//!     .signature(int_property_sig)
//!     .build(&mut context)?;
//!
//! // Create a property map entry for the type
//! let property_map_token = PropertyMapBuilder::new()
//!     .parent(type_token)
//!     .property_list(prop1_token.row()) // Starting property index
//!     .build(&mut context)?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Design
//!
//! The builder follows the established pattern with:
//! - **Validation**: Parent type and property list index are required and validated
//! - **Type Verification**: Ensures parent token is valid and points to TypeDef table
//! - **Token Generation**: Metadata tokens are created automatically
//! - **Range Support**: Supports defining contiguous property ranges for efficient lookup

use crate::{
    cilassembly::BuilderContext,
    metadata::{
        tables::{PropertyMapRaw, TableDataOwned, TableId},
        token::Token,
    },
    Error, Result,
};

/// Builder for creating PropertyMap table entries.
///
/// `PropertyMapBuilder` provides a fluent API for creating entries in the PropertyMap
/// metadata table, which establishes ownership relationships between types and their properties
/// through contiguous ranges of Property table entries.
///
/// # Purpose
///
/// The PropertyMap table serves several key functions:
/// - **Property Ownership**: Defines which types own which properties
/// - **Range Management**: Establishes contiguous ranges of properties owned by types
/// - **Efficient Lookup**: Enables O(log n) lookup of properties by owning type
/// - **Property Enumeration**: Supports efficient iteration through all properties of a type
/// - **Metadata Organization**: Maintains sorted order for optimal access patterns
///
/// # Builder Pattern
///
/// The builder provides a fluent interface for constructing PropertyMap entries:
///
/// ```rust,ignore
/// # use dotscope::prelude::*;
/// # use std::path::Path;
/// # let view = CilAssemblyView::from_file(Path::new("test.dll"))?;
/// # let assembly = CilAssembly::new(view);
/// # let mut context = BuilderContext::new(assembly);
/// # let type_token = Token::new(0x02000001);
///
/// let property_map_token = PropertyMapBuilder::new()
///     .parent(type_token)
///     .property_list(1) // Starting property index
///     .build(&mut context)?;
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Validation
///
/// The builder enforces the following constraints:
/// - **Parent Required**: A parent type token must be provided
/// - **Parent Validation**: Parent token must be a valid TypeDef table token
/// - **Property List Required**: A property list starting index must be provided
/// - **Index Validation**: Property list index must be greater than 0
/// - **Token Validation**: Parent token row cannot be 0
///
/// # Integration
///
/// PropertyMap entries integrate with other metadata structures:
/// - **TypeDef**: References specific types in the TypeDef table as parent
/// - **Property**: Points to starting positions in the Property table for range definition
/// - **PropertyPtr**: Supports indirection through PropertyPtr table when present
/// - **Metadata Loading**: Establishes property ownership during type loading
#[derive(Debug, Clone)]
pub struct PropertyMapBuilder {
    /// The token of the parent type that owns the properties
    parent: Option<Token>,
    /// The starting index in the Property table for this type's properties
    property_list: Option<u32>,
}

impl Default for PropertyMapBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl PropertyMapBuilder {
    /// Creates a new `PropertyMapBuilder` instance.
    ///
    /// Returns a builder with all fields unset, ready for configuration
    /// through the fluent API methods.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::prelude::*;
    /// let builder = PropertyMapBuilder::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            parent: None,
            property_list: None,
        }
    }

    /// Sets the parent type token that owns the properties.
    ///
    /// The parent must be a valid TypeDef token that represents the type
    /// that declares and owns the properties in the specified range.
    ///
    /// # Arguments
    ///
    /// * `parent_token` - Token of the TypeDef table entry
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// # use dotscope::prelude::*;
    /// # use std::path::Path;
    /// # let view = CilAssemblyView::from_file(Path::new("test.dll"))?;
    /// # let assembly = CilAssembly::new(view);
    /// # let mut context = BuilderContext::new(assembly);
    /// let type_token = TypeDefBuilder::new()
    ///     .name("PropertyfulClass")
    ///     .namespace("MyApp")
    ///     .public_class()
    ///     .build(&mut context)?;
    ///
    /// let builder = PropertyMapBuilder::new()
    ///     .parent(type_token);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn parent(mut self, parent_token: Token) -> Self {
        self.parent = Some(parent_token);
        self
    }

    /// Sets the starting index in the Property table for this type's properties.
    ///
    /// This index defines the beginning of the contiguous range of properties
    /// owned by the parent type. The range extends to the next PropertyMap entry's
    /// property_list index (or end of Property table for the final entry).
    ///
    /// # Arguments
    ///
    /// * `property_list_index` - 1-based index into the Property table
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::prelude::*;
    /// let builder = PropertyMapBuilder::new()
    ///     .property_list(1); // Start from first property
    /// ```
    #[must_use]
    pub fn property_list(mut self, property_list_index: u32) -> Self {
        self.property_list = Some(property_list_index);
        self
    }

    /// Builds the PropertyMap entry and adds it to the assembly.
    ///
    /// This method validates all required fields, verifies the parent token is valid,
    /// validates the property list index, creates the PropertyMap table entry, and returns the
    /// metadata token for the new entry.
    ///
    /// # Arguments
    ///
    /// * `context` - The builder context for the assembly being modified
    ///
    /// # Returns
    ///
    /// Returns the metadata token for the newly created PropertyMap entry.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The parent token is not set
    /// - The parent token is not a valid TypeDef token
    /// - The parent token row is 0
    /// - The property list index is not set
    /// - The property list index is 0
    /// - There are issues adding the table row
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// # use dotscope::prelude::*;
    /// # use std::path::Path;
    /// # let view = CilAssemblyView::from_file(Path::new("test.dll"))?;
    /// # let assembly = CilAssembly::new(view);
    /// # let mut context = BuilderContext::new(assembly);
    /// # let type_token = Token::new(0x02000001);
    ///
    /// let property_map_token = PropertyMapBuilder::new()
    ///     .parent(type_token)
    ///     .property_list(1)
    ///     .build(&mut context)?;
    ///
    /// println!("Created PropertyMap with token: {}", property_map_token);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn build(self, context: &mut BuilderContext) -> Result<Token> {
        let parent_token = self
            .parent
            .ok_or_else(|| Error::ModificationInvalidOperation {
                details: "Parent token is required for PropertyMap".to_string(),
            })?;

        let property_list_index =
            self.property_list
                .ok_or_else(|| Error::ModificationInvalidOperation {
                    details: "Property list index is required for PropertyMap".to_string(),
                })?;

        if parent_token.table() != TableId::TypeDef as u8 {
            return Err(Error::ModificationInvalidOperation {
                details: format!(
                    "Parent token must be a TypeDef token, got table ID: {}",
                    parent_token.table()
                ),
            });
        }

        if parent_token.row() == 0 {
            return Err(Error::ModificationInvalidOperation {
                details: "Parent token row cannot be 0".to_string(),
            });
        }

        if property_list_index == 0 {
            return Err(Error::ModificationInvalidOperation {
                details: "Property list index cannot be 0".to_string(),
            });
        }

        let rid = context.next_rid(TableId::PropertyMap);
        let token = Token::from_parts(TableId::PropertyMap, rid);

        let property_map = PropertyMapRaw {
            rid,
            token,
            offset: 0, // Will be set during binary generation
            parent: parent_token.row(),
            property_list: property_list_index,
        };

        let table_data = TableDataOwned::PropertyMap(property_map);
        context.table_row_add(TableId::PropertyMap, table_data)?;

        Ok(token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        metadata::tables::TableId, test::factories::table::assemblyref::get_test_assembly,
    };

    #[test]
    fn test_property_map_builder_basic() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Create a TypeDef for testing
        let type_token = crate::metadata::tables::TypeDefBuilder::new()
            .name("PropertyfulClass")
            .namespace("MyApp")
            .public_class()
            .build(&mut context)?;

        let token = PropertyMapBuilder::new()
            .parent(type_token)
            .property_list(1)
            .build(&mut context)?;

        // Verify the token has the correct table ID
        assert_eq!(token.table(), TableId::PropertyMap as u8);
        assert!(token.row() > 0);

        Ok(())
    }

    #[test]
    fn test_property_map_builder_default() -> Result<()> {
        let builder = PropertyMapBuilder::default();
        assert!(builder.parent.is_none());
        assert!(builder.property_list.is_none());
        Ok(())
    }

    #[test]
    fn test_property_map_builder_missing_parent() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        let result = PropertyMapBuilder::new()
            .property_list(1)
            .build(&mut context);

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Parent token is required"));

        Ok(())
    }

    #[test]
    fn test_property_map_builder_missing_property_list() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Create a TypeDef for testing
        let type_token = crate::metadata::tables::TypeDefBuilder::new()
            .name("PropertyfulClass")
            .namespace("MyApp")
            .public_class()
            .build(&mut context)?;

        let result = PropertyMapBuilder::new()
            .parent(type_token)
            .build(&mut context);

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Property list index is required"));

        Ok(())
    }

    #[test]
    fn test_property_map_builder_invalid_parent_token() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Use an invalid token (not TypeDef)
        let invalid_token = Token::new(0x04000001); // Field token instead of TypeDef

        let result = PropertyMapBuilder::new()
            .parent(invalid_token)
            .property_list(1)
            .build(&mut context);

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Parent token must be a TypeDef token"));

        Ok(())
    }

    #[test]
    fn test_property_map_builder_zero_row_parent() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Use a zero row token
        let zero_token = Token::new(0x02000000);

        let result = PropertyMapBuilder::new()
            .parent(zero_token)
            .property_list(1)
            .build(&mut context);

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Parent token row cannot be 0"));

        Ok(())
    }

    #[test]
    fn test_property_map_builder_zero_property_list() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Create a TypeDef for testing
        let type_token = crate::metadata::tables::TypeDefBuilder::new()
            .name("PropertyfulClass")
            .namespace("MyApp")
            .public_class()
            .build(&mut context)?;

        let result = PropertyMapBuilder::new()
            .parent(type_token)
            .property_list(0) // Zero property list index is invalid
            .build(&mut context);

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Property list index cannot be 0"));

        Ok(())
    }

    #[test]
    fn test_property_map_builder_multiple_entries() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Create TypeDefs for testing
        let type1_token = crate::metadata::tables::TypeDefBuilder::new()
            .name("PropertyfulClass1")
            .namespace("MyApp")
            .public_class()
            .build(&mut context)?;

        let type2_token = crate::metadata::tables::TypeDefBuilder::new()
            .name("PropertyfulClass2")
            .namespace("MyApp")
            .public_class()
            .build(&mut context)?;

        let map1_token = PropertyMapBuilder::new()
            .parent(type1_token)
            .property_list(1)
            .build(&mut context)?;

        let map2_token = PropertyMapBuilder::new()
            .parent(type2_token)
            .property_list(3)
            .build(&mut context)?;

        // Verify tokens are different and sequential
        assert_ne!(map1_token, map2_token);
        assert_eq!(map1_token.table(), TableId::PropertyMap as u8);
        assert_eq!(map2_token.table(), TableId::PropertyMap as u8);
        assert_eq!(map2_token.row(), map1_token.row() + 1);

        Ok(())
    }

    #[test]
    fn test_property_map_builder_various_property_indices() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Test with different property list indices
        let test_indices = [1, 5, 10, 20, 100];

        for (i, &index) in test_indices.iter().enumerate() {
            let type_token = crate::metadata::tables::TypeDefBuilder::new()
                .name(format!("PropertyfulClass{i}"))
                .namespace("MyApp")
                .public_class()
                .build(&mut context)?;

            let map_token = PropertyMapBuilder::new()
                .parent(type_token)
                .property_list(index)
                .build(&mut context)?;

            assert_eq!(map_token.table(), TableId::PropertyMap as u8);
            assert!(map_token.row() > 0);
        }

        Ok(())
    }

    #[test]
    fn test_property_map_builder_fluent_api() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Create a TypeDef for testing
        let type_token = crate::metadata::tables::TypeDefBuilder::new()
            .name("FluentTestClass")
            .namespace("MyApp")
            .public_class()
            .build(&mut context)?;

        // Test fluent API chaining
        let token = PropertyMapBuilder::new()
            .parent(type_token)
            .property_list(5)
            .build(&mut context)?;

        assert_eq!(token.table(), TableId::PropertyMap as u8);
        assert!(token.row() > 0);

        Ok(())
    }

    #[test]
    fn test_property_map_builder_clone() {
        let parent_token = Token::new(0x02000001);

        let builder1 = PropertyMapBuilder::new()
            .parent(parent_token)
            .property_list(1);
        let builder2 = builder1.clone();

        assert_eq!(builder1.parent, builder2.parent);
        assert_eq!(builder1.property_list, builder2.property_list);
    }

    #[test]
    fn test_property_map_builder_debug() {
        let parent_token = Token::new(0x02000001);

        let builder = PropertyMapBuilder::new()
            .parent(parent_token)
            .property_list(1);
        let debug_str = format!("{builder:?}");
        assert!(debug_str.contains("PropertyMapBuilder"));
    }
}
