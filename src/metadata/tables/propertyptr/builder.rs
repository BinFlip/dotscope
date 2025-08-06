//! Builder for constructing `PropertyPtr` table entries
//!
//! This module provides the [`crate::metadata::tables::propertyptr::PropertyPtrBuilder`] which enables fluent construction
//! of `PropertyPtr` metadata table entries. The builder follows the established
//! pattern used across all table builders in the library.
//!
//! # Usage Example
//!
//! ```rust,ignore
//! use dotscope::prelude::*;
//!
//! let builder_context = BuilderContext::new();
//!
//! let propertyptr_token = PropertyPtrBuilder::new()
//!     .property(6)                   // Points to Property table RID 6
//!     .build(&mut builder_context)?;
//! ```

use crate::{
    cilassembly::BuilderContext,
    metadata::{
        tables::{PropertyPtrRaw, TableDataOwned, TableId},
        token::Token,
    },
    Error, Result,
};

/// Builder for constructing `PropertyPtr` table entries
///
/// Provides a fluent interface for building `PropertyPtr` metadata table entries.
/// These entries provide indirection for property access when logical and physical
/// property ordering differs, enabling metadata optimizations and compressed layouts.
///
/// # Required Fields
/// - `property`: Property table RID that this pointer references
///
/// # Indirection Context
///
/// The PropertyPtr table provides a mapping layer between logical property references
/// and physical Property table entries. This enables:
/// - Property reordering for metadata optimization
/// - Compressed metadata streams with flexible property organization
/// - Runtime property access pattern optimizations
/// - Edit-and-continue property modifications without breaking references
///
/// # Examples
///
/// ```rust,ignore
/// use dotscope::prelude::*;
///
/// // Create property pointer for property reordering
/// let ptr1 = PropertyPtrBuilder::new()
///     .property(9)  // Points to Property table entry 9
///     .build(&mut context)?;
///
/// // Create pointer for optimized property layout
/// let ptr2 = PropertyPtrBuilder::new()
///     .property(4)  // Points to Property table entry 4
///     .build(&mut context)?;
///
/// // Multiple pointers for complex property arrangements
/// let ptr3 = PropertyPtrBuilder::new()
///     .property(18) // Points to Property table entry 18
///     .build(&mut context)?;
/// ```
#[derive(Debug, Clone)]
pub struct PropertyPtrBuilder {
    /// Property table RID that this pointer references
    property: Option<u32>,
}

impl PropertyPtrBuilder {
    /// Creates a new `PropertyPtrBuilder` with default values
    ///
    /// Initializes a new builder instance with all fields unset. The caller
    /// must provide the required property RID before calling build().
    ///
    /// # Returns
    /// A new `PropertyPtrBuilder` instance ready for configuration
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::prelude::*;
    ///
    /// let builder = PropertyPtrBuilder::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self { property: None }
    }

    /// Sets the Property table RID
    ///
    /// Specifies which Property table entry this pointer references. This creates
    /// the indirection mapping from the PropertyPtr RID (logical index) to the
    /// actual Property table entry (physical index).
    ///
    /// # Parameters
    /// - `property`: The Property table RID to reference
    ///
    /// # Returns
    /// Self for method chaining
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::prelude::*;
    ///
    /// // Point to first property
    /// let builder = PropertyPtrBuilder::new()
    ///     .property(1);
    ///
    /// // Point to a later property for reordering
    /// let builder = PropertyPtrBuilder::new()
    ///     .property(15);
    /// ```
    #[must_use]
    pub fn property(mut self, property: u32) -> Self {
        self.property = Some(property);
        self
    }

    /// Builds and adds the `PropertyPtr` entry to the metadata
    ///
    /// Validates all required fields, creates the `PropertyPtr` table entry,
    /// and adds it to the builder context. Returns a token that can be used
    /// to reference this property pointer entry.
    ///
    /// # Parameters
    /// - `context`: Mutable reference to the builder context
    ///
    /// # Returns
    /// - `Ok(Token)`: Token referencing the created property pointer entry
    /// - `Err(Error)`: If validation fails or table operations fail
    ///
    /// # Errors
    /// - Missing required field (property RID)
    /// - Table operations fail due to metadata constraints
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::prelude::*;
    ///
    /// let mut context = BuilderContext::new();
    /// let token = PropertyPtrBuilder::new()
    ///     .property(6)
    ///     .build(&mut context)?;
    /// ```
    pub fn build(self, context: &mut BuilderContext) -> Result<Token> {
        let property = self
            .property
            .ok_or_else(|| Error::ModificationInvalidOperation {
                details: "Property RID is required for PropertyPtr".to_string(),
            })?;

        let next_rid = context.next_rid(TableId::PropertyPtr);
        let token = Token::from_parts(TableId::PropertyPtr, next_rid);

        let property_ptr = PropertyPtrRaw {
            rid: next_rid,
            token,
            offset: 0,
            property,
        };

        context.table_row_add(
            TableId::PropertyPtr,
            TableDataOwned::PropertyPtr(property_ptr),
        )?;
        Ok(token)
    }
}

impl Default for PropertyPtrBuilder {
    /// Creates a default `PropertyPtrBuilder`
    ///
    /// Equivalent to calling [`PropertyPtrBuilder::new()`].
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cilassembly::BuilderContext, test::factories::table::assemblyref::get_test_assembly,
    };

    #[test]
    fn test_propertyptr_builder_new() {
        let builder = PropertyPtrBuilder::new();

        assert!(builder.property.is_none());
    }

    #[test]
    fn test_propertyptr_builder_default() {
        let builder = PropertyPtrBuilder::default();

        assert!(builder.property.is_none());
    }

    #[test]
    fn test_propertyptr_builder_basic() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);
        let token = PropertyPtrBuilder::new()
            .property(1)
            .build(&mut context)
            .expect("Should build successfully");

        assert_eq!(token.table(), TableId::PropertyPtr as u8);
        assert_eq!(token.row(), 1);
        Ok(())
    }

    #[test]
    fn test_propertyptr_builder_reordering() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);
        let token = PropertyPtrBuilder::new()
            .property(15) // Point to later property for reordering
            .build(&mut context)
            .expect("Should build successfully");

        assert_eq!(token.table(), TableId::PropertyPtr as u8);
        assert_eq!(token.row(), 1);
        Ok(())
    }

    #[test]
    fn test_propertyptr_builder_missing_property() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);
        let result = PropertyPtrBuilder::new().build(&mut context);

        assert!(result.is_err());
        match result.unwrap_err() {
            Error::ModificationInvalidOperation { details } => {
                assert!(details.contains("Property RID is required"));
            }
            _ => panic!("Expected ModificationInvalidOperation error"),
        }
        Ok(())
    }

    #[test]
    fn test_propertyptr_builder_clone() {
        let builder = PropertyPtrBuilder::new().property(6);

        let cloned = builder.clone();
        assert_eq!(builder.property, cloned.property);
    }

    #[test]
    fn test_propertyptr_builder_debug() {
        let builder = PropertyPtrBuilder::new().property(11);

        let debug_str = format!("{builder:?}");
        assert!(debug_str.contains("PropertyPtrBuilder"));
        assert!(debug_str.contains("property"));
    }

    #[test]
    fn test_propertyptr_builder_fluent_interface() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Test method chaining
        let token = PropertyPtrBuilder::new()
            .property(25)
            .build(&mut context)
            .expect("Should build successfully");

        assert_eq!(token.table(), TableId::PropertyPtr as u8);
        assert_eq!(token.row(), 1);
        Ok(())
    }

    #[test]
    fn test_propertyptr_builder_multiple_builds() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Build first pointer
        let token1 = PropertyPtrBuilder::new()
            .property(9)
            .build(&mut context)
            .expect("Should build first pointer");

        // Build second pointer
        let token2 = PropertyPtrBuilder::new()
            .property(4)
            .build(&mut context)
            .expect("Should build second pointer");

        // Build third pointer
        let token3 = PropertyPtrBuilder::new()
            .property(18)
            .build(&mut context)
            .expect("Should build third pointer");

        assert_eq!(token1.row(), 1);
        assert_eq!(token2.row(), 2);
        assert_eq!(token3.row(), 3);
        assert_ne!(token1, token2);
        assert_ne!(token2, token3);
        Ok(())
    }

    #[test]
    fn test_propertyptr_builder_large_property_rid() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);
        let token = PropertyPtrBuilder::new()
            .property(0xFFFF) // Large Property RID
            .build(&mut context)
            .expect("Should handle large property RID");

        assert_eq!(token.table(), TableId::PropertyPtr as u8);
        assert_eq!(token.row(), 1);
        Ok(())
    }

    #[test]
    fn test_propertyptr_builder_property_ordering_scenario() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Simulate property reordering: logical order 1,2,3 -> physical order 12,6,15
        let logical_to_physical = [(1, 12), (2, 6), (3, 15)];

        let mut tokens = Vec::new();
        for (logical_idx, physical_property) in logical_to_physical {
            let token = PropertyPtrBuilder::new()
                .property(physical_property)
                .build(&mut context)
                .expect("Should build property pointer");
            tokens.push((logical_idx, token));
        }

        // Verify logical ordering is preserved in tokens
        for (i, (logical_idx, token)) in tokens.iter().enumerate() {
            assert_eq!(*logical_idx, i + 1);
            assert_eq!(token.row(), (i + 1) as u32);
        }

        Ok(())
    }

    #[test]
    fn test_propertyptr_builder_zero_property() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Test with property 0 (typically invalid but should not cause builder to fail)
        let result = PropertyPtrBuilder::new().property(0).build(&mut context);

        // Should build successfully even with property 0
        assert!(result.is_ok());
        Ok(())
    }

    #[test]
    fn test_propertyptr_builder_type_property_scenario() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Simulate type with multiple properties that need indirection
        let type_properties = [7, 14, 3, 21, 9]; // Properties in custom order

        let mut property_pointers = Vec::new();
        for &property_rid in &type_properties {
            let pointer_token = PropertyPtrBuilder::new()
                .property(property_rid)
                .build(&mut context)
                .expect("Should build property pointer");
            property_pointers.push(pointer_token);
        }

        // Verify property pointers maintain logical sequence
        for (i, token) in property_pointers.iter().enumerate() {
            assert_eq!(token.table(), TableId::PropertyPtr as u8);
            assert_eq!(token.row(), (i + 1) as u32);
        }

        Ok(())
    }

    #[test]
    fn test_propertyptr_builder_compressed_metadata_scenario() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Simulate compressed metadata scenario with property indirection
        let compressed_order = [25, 10, 30, 5, 40, 15];

        let mut pointer_tokens = Vec::new();
        for &property_order in &compressed_order {
            let token = PropertyPtrBuilder::new()
                .property(property_order)
                .build(&mut context)
                .expect("Should build pointer for compressed metadata");
            pointer_tokens.push(token);
        }

        // Verify consistent indirection mapping
        assert_eq!(pointer_tokens.len(), 6);
        for (i, token) in pointer_tokens.iter().enumerate() {
            assert_eq!(token.table(), TableId::PropertyPtr as u8);
            assert_eq!(token.row(), (i + 1) as u32);
        }

        Ok(())
    }

    #[test]
    fn test_propertyptr_builder_optimization_scenario() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Simulate property optimization with access pattern-based ordering
        let optimized_access_order = [100, 50, 200, 25, 150, 75, 300];

        let mut optimization_pointers = Vec::new();
        for &optimized_property in &optimized_access_order {
            let pointer_token = PropertyPtrBuilder::new()
                .property(optimized_property)
                .build(&mut context)
                .expect("Should build optimization pointer");
            optimization_pointers.push(pointer_token);
        }

        // Verify optimization indirection maintains consistency
        assert_eq!(optimization_pointers.len(), 7);
        for (i, token) in optimization_pointers.iter().enumerate() {
            assert_eq!(token.table(), TableId::PropertyPtr as u8);
            assert_eq!(token.row(), (i + 1) as u32);
        }

        Ok(())
    }

    #[test]
    fn test_propertyptr_builder_interface_property_scenario() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Simulate interface with properties requiring specific ordering
        let interface_properties = [1, 5, 3, 8, 2]; // Interface property order

        let mut interface_pointers = Vec::new();
        for &prop_rid in &interface_properties {
            let token = PropertyPtrBuilder::new()
                .property(prop_rid)
                .build(&mut context)
                .expect("Should build interface property pointer");
            interface_pointers.push(token);
        }

        // Verify interface property pointer ordering
        for (i, token) in interface_pointers.iter().enumerate() {
            assert_eq!(token.table(), TableId::PropertyPtr as u8);
            assert_eq!(token.row(), (i + 1) as u32);
        }

        Ok(())
    }

    #[test]
    fn test_propertyptr_builder_edit_continue_property_scenario() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Simulate edit-and-continue where properties are added/modified
        let original_properties = [10, 20, 30];
        let mut pointers = Vec::new();

        for &property_rid in &original_properties {
            let pointer = PropertyPtrBuilder::new()
                .property(property_rid)
                .build(&mut context)
                .expect("Should build property pointer for edit-continue");
            pointers.push(pointer);
        }

        // Add new property during edit session
        let new_property_pointer = PropertyPtrBuilder::new()
            .property(500) // New property added during edit
            .build(&mut context)
            .expect("Should build new property pointer");

        // Verify stable property pointer tokens
        for (i, token) in pointers.iter().enumerate() {
            assert_eq!(token.row(), (i + 1) as u32);
        }
        assert_eq!(new_property_pointer.row(), 4);

        Ok(())
    }
}
