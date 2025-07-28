//! MethodSemanticsBuilder for creating method semantic relationship metadata entries.
//!
//! This module provides [`crate::metadata::tables::methodsemantics::MethodSemanticsBuilder`] for creating MethodSemantics table entries
//! with a fluent API. Method semantic relationships define which concrete methods provide
//! semantic behavior for properties (getters/setters) and events (add/remove/fire handlers),
//! enabling the .NET runtime to understand accessor patterns and event handling mechanisms.

use crate::{
    cilassembly::BuilderContext,
    metadata::{
        tables::{CodedIndex, CodedIndexType, MethodSemanticsRaw, TableDataOwned, TableId},
        token::Token,
    },
    Error, Result,
};

/// Builder for creating MethodSemantics metadata entries.
///
/// `MethodSemanticsBuilder` provides a fluent API for creating MethodSemantics table entries
/// with validation and automatic relationship management. Method semantic relationships are
/// essential for connecting properties and events to their associated accessor methods,
/// enabling proper encapsulation and event handling in .NET programming models.
///
/// # Method Semantics Model
///
/// .NET method semantics follow this pattern:
/// - **Semantic Type**: The role the method plays (getter, setter, adder, etc.)
/// - **Method**: The concrete method that implements the semantic behavior
/// - **Association**: The property or event that the method provides behavior for
/// - **Runtime Integration**: The .NET runtime uses these relationships for proper dispatch
///
/// # Semantic Relationship Categories
///
/// Different categories of semantic relationships serve various purposes:
/// - **Property Semantics**: Getters, setters, and other property-related methods
/// - **Event Semantics**: Add, remove, fire, and other event-related methods
/// - **Custom Semantics**: Other specialized semantic relationships
/// - **Multiple Semantics**: Methods can have multiple semantic roles
///
/// # Coded Index Management
///
/// Method semantic relationships use HasSemantics coded indices:
/// - **Event References**: Links to event definitions in the Event table
/// - **Property References**: Links to property definitions in the Property table
/// - **Cross-Assembly Scenarios**: Support for semantic relationships across assembly boundaries
/// - **Type Safety**: Compile-time and runtime validation of semantic contracts
///
/// # Examples
///
/// ## Property Getter/Setter Relationship
///
/// ```rust
/// use dotscope::prelude::*;
///
/// # fn example(context: &mut BuilderContext) -> Result<()> {
/// // Create getter semantic relationship
/// let getter_semantic = MethodSemanticsBuilder::new()
///     .semantics(MethodSemanticsAttributes::GETTER)
///     .method(Token::new(0x06000001)) // MethodDef token
///     .association_from_property(Token::new(0x17000001)) // Property token
///     .build(context)?;
///
/// // Create setter semantic relationship  
/// let setter_semantic = MethodSemanticsBuilder::new()
///     .semantics(MethodSemanticsAttributes::SETTER)
///     .method(Token::new(0x06000002)) // MethodDef token
///     .association_from_property(Token::new(0x17000001)) // Same property
///     .build(context)?;
/// # Ok(())
/// # }
/// ```
///
/// ## Event Add/Remove Relationship
///
/// ```rust
/// use dotscope::prelude::*;
///
/// # fn example(context: &mut BuilderContext) -> Result<()> {
/// // Create event add handler relationship
/// let add_semantic = MethodSemanticsBuilder::new()
///     .semantics(MethodSemanticsAttributes::ADD_ON)
///     .method(Token::new(0x06000003)) // Add method token
///     .association_from_event(Token::new(0x14000001)) // Event token
///     .build(context)?;
///
/// // Create event remove handler relationship
/// let remove_semantic = MethodSemanticsBuilder::new()
///     .semantics(MethodSemanticsAttributes::REMOVE_ON)
///     .method(Token::new(0x06000004)) // Remove method token
///     .association_from_event(Token::new(0x14000001)) // Same event
///     .build(context)?;
/// # Ok(())
/// # }
/// ```
///
/// # Thread Safety
///
/// `MethodSemanticsBuilder` follows the established builder pattern:
/// - No internal state requiring synchronization
/// - Context passed to build() method handles concurrency
/// - Can be created and used across thread boundaries
/// - Final build() operation is atomic within the context
pub struct MethodSemanticsBuilder {
    /// Semantic relationship type bitmask.
    ///
    /// Defines the method's semantic role using MethodSemanticsAttributes constants.
    /// Can combine multiple semantic types using bitwise OR operations.
    semantics: Option<u32>,

    /// Method that implements the semantic behavior.
    ///
    /// Token referencing a MethodDef entry that provides the concrete implementation
    /// for the semantic relationship.
    method: Option<Token>,

    /// HasSemantics coded index to the associated property or event.
    ///
    /// References either an Event or Property table entry that this method
    /// provides semantic behavior for.
    association: Option<CodedIndex>,
}

impl MethodSemanticsBuilder {
    /// Creates a new `MethodSemanticsBuilder` instance.
    ///
    /// Initializes all fields to `None`, requiring explicit configuration
    /// through the fluent API methods before building.
    ///
    /// # Returns
    ///
    /// New builder instance ready for configuration.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::prelude::*;
    ///
    /// let builder = MethodSemanticsBuilder::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            semantics: None,
            method: None,
            association: None,
        }
    }

    /// Sets the semantic relationship type.
    ///
    /// Specifies the role this method plays in relation to the associated
    /// property or event using MethodSemanticsAttributes constants.
    ///
    /// # Arguments
    ///
    /// * `semantics` - Bitmask of semantic attributes (can combine multiple values)
    ///
    /// # Returns
    ///
    /// Updated builder instance for method chaining.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::prelude::*;
    ///
    /// let builder = MethodSemanticsBuilder::new()
    ///     .semantics(MethodSemanticsAttributes::GETTER);
    ///
    /// // Multiple semantics can be combined
    /// let combined = MethodSemanticsBuilder::new()
    ///     .semantics(MethodSemanticsAttributes::GETTER | MethodSemanticsAttributes::OTHER);
    /// ```
    #[must_use]
    pub fn semantics(mut self, semantics: u32) -> Self {
        self.semantics = Some(semantics);
        self
    }

    /// Sets the method that implements the semantic behavior.
    ///
    /// Specifies the MethodDef token for the method that provides the concrete
    /// implementation of the semantic relationship.
    ///
    /// # Arguments
    ///
    /// * `method` - Token referencing a MethodDef table entry
    ///
    /// # Returns
    ///
    /// Updated builder instance for method chaining.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::prelude::*;
    ///
    /// let builder = MethodSemanticsBuilder::new()
    ///     .method(Token::new(0x06000001)); // MethodDef token
    /// ```
    #[must_use]
    pub fn method(mut self, method: Token) -> Self {
        self.method = Some(method);
        self
    }

    /// Sets the association to a property using its token.
    ///
    /// Creates a HasSemantics coded index referencing a Property table entry
    /// that this method provides semantic behavior for.
    ///
    /// # Arguments
    ///
    /// * `property` - Token referencing a Property table entry
    ///
    /// # Returns
    ///
    /// Updated builder instance for method chaining.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::prelude::*;
    ///
    /// let builder = MethodSemanticsBuilder::new()
    ///     .association_from_property(Token::new(0x17000001)); // Property token
    /// ```
    #[must_use]
    pub fn association_from_property(mut self, property: Token) -> Self {
        self.association = Some(CodedIndex::new(
            TableId::Property,
            property.row(),
            CodedIndexType::HasSemantics,
        ));
        self
    }

    /// Sets the association to an event using its token.
    ///
    /// Creates a HasSemantics coded index referencing an Event table entry
    /// that this method provides semantic behavior for.
    ///
    /// # Arguments
    ///
    /// * `event` - Token referencing an Event table entry
    ///
    /// # Returns
    ///
    /// Updated builder instance for method chaining.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::prelude::*;
    ///
    /// let builder = MethodSemanticsBuilder::new()
    ///     .association_from_event(Token::new(0x14000001)); // Event token
    /// ```
    #[must_use]
    pub fn association_from_event(mut self, event: Token) -> Self {
        self.association = Some(CodedIndex::new(
            TableId::Event,
            event.row(),
            CodedIndexType::HasSemantics,
        ));
        self
    }

    /// Sets the association using a pre-constructed coded index.
    ///
    /// Allows direct specification of a HasSemantics coded index for advanced
    /// scenarios where the coded index is constructed externally.
    ///
    /// # Arguments
    ///
    /// * `association` - HasSemantics coded index to property or event
    ///
    /// # Returns
    ///
    /// Updated builder instance for method chaining.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::prelude::*;
    ///
    /// let coded_index = CodedIndex::new(
    ///     TableId::Property,
    ///     1,
    ///     CodedIndexType::HasSemantics
    /// );
    ///
    /// let builder = MethodSemanticsBuilder::new()
    ///     .association(coded_index);
    /// ```
    #[must_use]
    pub fn association(mut self, association: CodedIndex) -> Self {
        self.association = Some(association);
        self
    }

    /// Builds the MethodSemantics entry and adds it to the assembly.
    ///
    /// Validates all required fields, creates the raw MethodSemantics entry,
    /// and adds it to the MethodSemantics table through the builder context.
    /// Returns the token for the newly created entry.
    ///
    /// # Arguments
    ///
    /// * `context` - Mutable reference to the builder context for assembly modification
    ///
    /// # Returns
    ///
    /// `Result<Token>` - Token for the created MethodSemantics entry or error if validation fails
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Required semantics field is not set
    /// - Required method field is not set  
    /// - Required association field is not set
    /// - Context operations fail (heap allocation, table modification)
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::prelude::*;
    ///
    /// # fn example(context: &mut BuilderContext) -> Result<()> {
    /// let semantic_token = MethodSemanticsBuilder::new()
    ///     .semantics(MethodSemanticsAttributes::GETTER)
    ///     .method(Token::new(0x06000001))
    ///     .association_from_property(Token::new(0x17000001))
    ///     .build(context)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn build(self, context: &mut BuilderContext) -> Result<Token> {
        // Validate required fields
        let semantics = self
            .semantics
            .ok_or_else(|| Error::ModificationInvalidOperation {
                details: "MethodSemantics semantics field is required".to_string(),
            })?;

        let method = self
            .method
            .ok_or_else(|| Error::ModificationInvalidOperation {
                details: "MethodSemantics method field is required".to_string(),
            })?;

        let association = self
            .association
            .ok_or_else(|| Error::ModificationInvalidOperation {
                details: "MethodSemantics association field is required".to_string(),
            })?;

        // Get the next RID for MethodSemantics table
        let rid = context.next_rid(TableId::MethodSemantics);
        let token = Token::new(((TableId::MethodSemantics as u32) << 24) | rid);

        // Create the raw MethodSemantics entry
        let method_semantics_raw = MethodSemanticsRaw {
            rid,
            token,
            offset: 0, // Will be set during binary generation
            semantics,
            method: method.row(),
            association,
        };

        // Add to the MethodSemantics table
        context.table_row_add(
            TableId::MethodSemantics,
            TableDataOwned::MethodSemantics(method_semantics_raw),
        )?;

        Ok(token)
    }
}

impl Default for MethodSemanticsBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cilassembly::{BuilderContext, CilAssembly},
        metadata::{cilassemblyview::CilAssemblyView, tables::MethodSemanticsAttributes},
    };
    use std::{env, path::PathBuf};

    #[test]
    fn test_methodsemantics_builder_creation() {
        let builder = MethodSemanticsBuilder::new();
        assert!(builder.semantics.is_none());
        assert!(builder.method.is_none());
        assert!(builder.association.is_none());
    }

    #[test]
    fn test_methodsemantics_builder_default() {
        let builder = MethodSemanticsBuilder::default();
        assert!(builder.semantics.is_none());
        assert!(builder.method.is_none());
        assert!(builder.association.is_none());
    }

    #[test]
    fn test_property_getter_semantic() -> Result<()> {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            let semantic_token = MethodSemanticsBuilder::new()
                .semantics(MethodSemanticsAttributes::GETTER)
                .method(Token::new(0x06000001))
                .association_from_property(Token::new(0x17000001))
                .build(&mut context)?;

            assert!(semantic_token.row() > 0);
            assert_eq!(semantic_token.table(), TableId::MethodSemantics as u8);
        }
        Ok(())
    }

    #[test]
    fn test_property_setter_semantic() -> Result<()> {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            let semantic_token = MethodSemanticsBuilder::new()
                .semantics(MethodSemanticsAttributes::SETTER)
                .method(Token::new(0x06000002))
                .association_from_property(Token::new(0x17000001))
                .build(&mut context)?;

            assert!(semantic_token.row() > 0);
            assert_eq!(semantic_token.table(), TableId::MethodSemantics as u8);
        }
        Ok(())
    }

    #[test]
    fn test_event_add_semantic() -> Result<()> {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            let semantic_token = MethodSemanticsBuilder::new()
                .semantics(MethodSemanticsAttributes::ADD_ON)
                .method(Token::new(0x06000003))
                .association_from_event(Token::new(0x14000001))
                .build(&mut context)?;

            assert!(semantic_token.row() > 0);
            assert_eq!(semantic_token.table(), TableId::MethodSemantics as u8);
        }
        Ok(())
    }

    #[test]
    fn test_event_remove_semantic() -> Result<()> {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            let semantic_token = MethodSemanticsBuilder::new()
                .semantics(MethodSemanticsAttributes::REMOVE_ON)
                .method(Token::new(0x06000004))
                .association_from_event(Token::new(0x14000001))
                .build(&mut context)?;

            assert!(semantic_token.row() > 0);
            assert_eq!(semantic_token.table(), TableId::MethodSemantics as u8);
        }
        Ok(())
    }

    #[test]
    fn test_event_fire_semantic() -> Result<()> {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            let semantic_token = MethodSemanticsBuilder::new()
                .semantics(MethodSemanticsAttributes::FIRE)
                .method(Token::new(0x06000005))
                .association_from_event(Token::new(0x14000001))
                .build(&mut context)?;

            assert!(semantic_token.row() > 0);
            assert_eq!(semantic_token.table(), TableId::MethodSemantics as u8);
        }
        Ok(())
    }

    #[test]
    fn test_combined_semantics() -> Result<()> {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            let semantic_token = MethodSemanticsBuilder::new()
                .semantics(MethodSemanticsAttributes::GETTER | MethodSemanticsAttributes::OTHER)
                .method(Token::new(0x06000006))
                .association_from_property(Token::new(0x17000002))
                .build(&mut context)?;

            assert!(semantic_token.row() > 0);
            assert_eq!(semantic_token.table(), TableId::MethodSemantics as u8);
        }
        Ok(())
    }

    #[test]
    fn test_direct_coded_index() -> Result<()> {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            let coded_index = CodedIndex::new(TableId::Property, 1, CodedIndexType::HasSemantics);

            let semantic_token = MethodSemanticsBuilder::new()
                .semantics(MethodSemanticsAttributes::GETTER)
                .method(Token::new(0x06000007))
                .association(coded_index)
                .build(&mut context)?;

            assert!(semantic_token.row() > 0);
            assert_eq!(semantic_token.table(), TableId::MethodSemantics as u8);
        }
        Ok(())
    }

    #[test]
    fn test_multiple_method_semantics() -> Result<()> {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            // Create multiple semantic relationships for the same property
            let getter_token = MethodSemanticsBuilder::new()
                .semantics(MethodSemanticsAttributes::GETTER)
                .method(Token::new(0x06000001))
                .association_from_property(Token::new(0x17000001))
                .build(&mut context)?;

            let setter_token = MethodSemanticsBuilder::new()
                .semantics(MethodSemanticsAttributes::SETTER)
                .method(Token::new(0x06000002))
                .association_from_property(Token::new(0x17000001))
                .build(&mut context)?;

            let other_token = MethodSemanticsBuilder::new()
                .semantics(MethodSemanticsAttributes::OTHER)
                .method(Token::new(0x06000003))
                .association_from_property(Token::new(0x17000001))
                .build(&mut context)?;

            assert!(getter_token.row() > 0);
            assert!(setter_token.row() > 0);
            assert!(other_token.row() > 0);
            assert!(getter_token.row() != setter_token.row());
            assert!(setter_token.row() != other_token.row());
        }
        Ok(())
    }

    #[test]
    fn test_build_without_semantics_fails() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            let result = MethodSemanticsBuilder::new()
                .method(Token::new(0x06000001))
                .association_from_property(Token::new(0x17000001))
                .build(&mut context);

            assert!(result.is_err());
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("semantics field is required"));
        }
    }

    #[test]
    fn test_build_without_method_fails() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            let result = MethodSemanticsBuilder::new()
                .semantics(MethodSemanticsAttributes::GETTER)
                .association_from_property(Token::new(0x17000001))
                .build(&mut context);

            assert!(result.is_err());
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("method field is required"));
        }
    }

    #[test]
    fn test_build_without_association_fails() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            let result = MethodSemanticsBuilder::new()
                .semantics(MethodSemanticsAttributes::GETTER)
                .method(Token::new(0x06000001))
                .build(&mut context);

            assert!(result.is_err());
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("association field is required"));
        }
    }
}
