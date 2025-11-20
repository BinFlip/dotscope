//! # FieldRVA Builder
//!
//! Provides a fluent API for building FieldRVA table entries that define Relative Virtual Addresses (RVAs)
//! for fields with initial data stored in the PE file. The FieldRVA table enables static field initialization,
//! constant data embedding, and global variable setup with pre-computed values.
//!
//! ## Overview
//!
//! The `FieldRVABuilder` enables creation of field RVA entries with:
//! - Field reference specification (required)
//! - RVA location for initial data (required)
//! - Validation of field tokens and RVA values
//! - Automatic token generation and metadata management
//!
//! ## Usage
//!
//! ```rust,ignore
//! # use dotscope::prelude::*;
//! # use std::path::Path;
//! # let view = CilAssemblyView::from_file(Path::new("test.dll"))?;
//! # let assembly = CilAssembly::new(view);
//! # let mut context = BuilderContext::new(assembly);
//!
//! // Create a field signature for static data
//! let field_sig = vec![0x06]; // Simple type signature
//!
//! // Create a field first
//! let field_token = FieldBuilder::new()
//!     .name("StaticData")
//!     .flags(FieldAttributes::STATIC | FieldAttributes::PRIVATE)
//!     .signature(&field_sig)
//!     .build(&mut context)?;
//!
//! // Create a field RVA entry for static field initialization
//! let field_rva_token = FieldRVABuilder::new()
//!     .field(field_token)
//!     .rva(0x2000) // RVA pointing to initial data
//!     .build(&mut context)?;
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Design
//!
//! The builder follows the established pattern with:
//! - **Validation**: Field token and RVA are required and validated
//! - **Field Verification**: Ensures field token is valid and points to Field table
//! - **Token Generation**: Metadata tokens are created automatically
//! - **RVA Validation**: Ensures RVA values are non-zero and valid

use crate::{
    cilassembly::BuilderContext,
    metadata::{
        tables::{FieldRvaRaw, TableDataOwned, TableId},
        token::Token,
    },
    Error, Result,
};

/// Builder for creating FieldRVA table entries.
///
/// `FieldRVABuilder` provides a fluent API for creating entries in the FieldRVA
/// metadata table, which specifies Relative Virtual Addresses for fields that have
/// initial data stored in the PE file.
///
/// # Purpose
///
/// The FieldRVA table serves several key functions:
/// - **Static Field Initialization**: Pre-computed values for static fields
/// - **Constant Data**: Read-only data embedded directly in the PE file
/// - **Global Variables**: Module-level data with specific initial states
/// - **Interop Data**: Native data structures for P/Invoke and COM scenarios
/// - **Resource Embedding**: Binary resources accessible through field references
///
/// # Builder Pattern
///
/// The builder provides a fluent interface for constructing FieldRVA entries:
///
/// ```rust,ignore
/// # use dotscope::prelude::*;
/// # use std::path::Path;
/// # let view = CilAssemblyView::from_file(Path::new("test.dll"))?;
/// # let assembly = CilAssembly::new(view);
/// # let mut context = BuilderContext::new(assembly);
/// # let field_token = Token::new(0x04000001);
///
/// let field_rva_token = FieldRVABuilder::new()
///     .field(field_token)
///     .rva(0x2000)
///     .build(&mut context)?;
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Validation
///
/// The builder enforces the following constraints:
/// - **Field Required**: A field token must be provided
/// - **Field Validation**: Field token must be a valid Field table token
/// - **RVA Required**: An RVA value must be provided
/// - **RVA Validation**: RVA values must be greater than 0
/// - **Token Validation**: Field token row cannot be 0
///
/// # Integration
///
/// FieldRVA entries integrate with other metadata structures:
/// - **Field**: References specific fields in the Field table
/// - **PE Sections**: RVAs point to data in specific PE file sections
/// - **Static Data**: Enables runtime access to pre-initialized field values
#[derive(Debug, Clone)]
pub struct FieldRVABuilder {
    /// The token of the field with initial data
    field: Option<Token>,
    /// The RVA pointing to the field's initial data
    rva: Option<u32>,
}

impl Default for FieldRVABuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl FieldRVABuilder {
    /// Creates a new `FieldRVABuilder` instance.
    ///
    /// Returns a builder with all fields unset, ready for configuration
    /// through the fluent API methods.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::prelude::*;
    /// let builder = FieldRVABuilder::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            field: None,
            rva: None,
        }
    }

    /// Sets the field token for the field with initial data.
    ///
    /// The field must be a valid Field token that represents the field
    /// that has initial data stored at the specified RVA location.
    ///
    /// # Arguments
    ///
    /// * `field_token` - Token of the Field table entry
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// # use dotscope::prelude::*;
    /// # use std::path::Path;
    /// # let view = CilAssemblyView::from_file(Path::new("test.dll"))?;
    /// # let assembly = CilAssembly::new(view);
    /// # let mut context = BuilderContext::new(assembly);
    /// let field_sig = vec![0x06]; // Simple type signature
    /// let field_token = FieldBuilder::new()
    ///     .name("StaticArray")
    ///     .flags(FieldAttributes::STATIC | FieldAttributes::PRIVATE)
    ///     .signature(&field_sig)
    ///     .build(&mut context)?;
    ///
    /// let builder = FieldRVABuilder::new()
    ///     .field(field_token);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn field(mut self, field_token: Token) -> Self {
        self.field = Some(field_token);
        self
    }

    /// Sets the RVA pointing to the field's initial data.
    ///
    /// The RVA (Relative Virtual Address) specifies the location within the PE file
    /// where the field's initial data is stored. This address is relative to the
    /// image base and must point to valid data.
    ///
    /// # Arguments
    ///
    /// * `rva` - The RVA value pointing to initial data
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::prelude::*;
    /// let builder = FieldRVABuilder::new()
    ///     .rva(0x2000); // RVA pointing to initial data
    /// ```
    #[must_use]
    pub fn rva(mut self, rva: u32) -> Self {
        self.rva = Some(rva);
        self
    }

    /// Builds the FieldRVA entry and adds it to the assembly.
    ///
    /// This method validates all required fields, verifies the field token is valid,
    /// validates the RVA value, creates the FieldRVA table entry, and returns the
    /// metadata token for the new entry.
    ///
    /// # Arguments
    ///
    /// * `context` - The builder context for the assembly being modified
    ///
    /// # Returns
    ///
    /// Returns the metadata token for the newly created FieldRVA entry.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The field token is not set
    /// - The field token is not a valid Field token
    /// - The field token row is 0
    /// - The RVA is not set
    /// - The RVA value is 0
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
    /// # let field_token = Token::new(0x04000001);
    ///
    /// let field_rva_token = FieldRVABuilder::new()
    ///     .field(field_token)
    ///     .rva(0x2000)
    ///     .build(&mut context)?;
    ///
    /// println!("Created FieldRVA with token: {}", field_rva_token);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn build(self, context: &mut BuilderContext) -> Result<Token> {
        let field_token = self
            .field
            .ok_or_else(|| Error::ModificationInvalidOperation {
                details: "Field token is required for FieldRVA".to_string(),
            })?;

        let rva = self
            .rva
            .ok_or_else(|| Error::ModificationInvalidOperation {
                details: "RVA is required for FieldRVA".to_string(),
            })?;

        if field_token.table() != TableId::Field as u8 {
            return Err(Error::ModificationInvalidOperation {
                details: format!(
                    "Field token must be a Field token, got table ID: {}",
                    field_token.table()
                ),
            });
        }

        if field_token.row() == 0 {
            return Err(Error::ModificationInvalidOperation {
                details: "Field token row cannot be 0".to_string(),
            });
        }

        if rva == 0 {
            return Err(Error::ModificationInvalidOperation {
                details: "RVA cannot be 0".to_string(),
            });
        }

        let rid = context.next_rid(TableId::FieldRVA);
        let token = Token::from_parts(TableId::FieldRVA, rid);

        let field_rva = FieldRvaRaw {
            rid,
            token,
            offset: 0, // Will be set during binary generation
            rva,
            field: field_token.row(),
        };

        let table_data = TableDataOwned::FieldRVA(field_rva);
        context.table_row_add(TableId::FieldRVA, table_data)?;

        Ok(token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        metadata::tables::{FieldAttributes, TableId},
        test::factories::table::assemblyref::get_test_assembly,
    };

    #[test]
    fn test_field_rva_builder_basic() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Create a Field for testing
        let field_token = crate::metadata::tables::FieldBuilder::new()
            .name("StaticData")
            .flags(FieldAttributes::STATIC | FieldAttributes::PRIVATE)
            .signature(&[0x06]) // Simple signature
            .build(&mut context)?;

        let token = FieldRVABuilder::new()
            .field(field_token)
            .rva(0x2000)
            .build(&mut context)?;

        // Verify the token has the correct table ID
        assert_eq!(token.table(), TableId::FieldRVA as u8);
        assert!(token.row() > 0);

        Ok(())
    }

    #[test]
    fn test_field_rva_builder_default() -> Result<()> {
        let builder = FieldRVABuilder::default();
        assert!(builder.field.is_none());
        assert!(builder.rva.is_none());
        Ok(())
    }

    #[test]
    fn test_field_rva_builder_missing_field() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        let result = FieldRVABuilder::new().rva(0x2000).build(&mut context);

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Field token is required"));

        Ok(())
    }

    #[test]
    fn test_field_rva_builder_missing_rva() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Create a Field for testing
        let field_token = crate::metadata::tables::FieldBuilder::new()
            .name("StaticData")
            .flags(FieldAttributes::STATIC | FieldAttributes::PRIVATE)
            .signature(&[0x06])
            .build(&mut context)?;

        let result = FieldRVABuilder::new()
            .field(field_token)
            .build(&mut context);

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("RVA is required"));

        Ok(())
    }

    #[test]
    fn test_field_rva_builder_invalid_field_token() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Use an invalid token (not Field)
        let invalid_token = Token::new(0x02000001); // TypeDef token instead of Field

        let result = FieldRVABuilder::new()
            .field(invalid_token)
            .rva(0x2000)
            .build(&mut context);

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Field token must be a Field token"));

        Ok(())
    }

    #[test]
    fn test_field_rva_builder_zero_row_field() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Use a zero row token
        let zero_token = Token::new(0x04000000);

        let result = FieldRVABuilder::new()
            .field(zero_token)
            .rva(0x2000)
            .build(&mut context);

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Field token row cannot be 0"));

        Ok(())
    }

    #[test]
    fn test_field_rva_builder_zero_rva() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Create a Field for testing
        let field_token = crate::metadata::tables::FieldBuilder::new()
            .name("StaticData")
            .flags(FieldAttributes::STATIC | FieldAttributes::PRIVATE)
            .signature(&[0x06])
            .build(&mut context)?;

        let result = FieldRVABuilder::new()
            .field(field_token)
            .rva(0) // Zero RVA is invalid
            .build(&mut context);

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("RVA cannot be 0"));

        Ok(())
    }

    #[test]
    fn test_field_rva_builder_multiple_entries() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Create Fields for testing
        let field1_token = crate::metadata::tables::FieldBuilder::new()
            .name("StaticData1")
            .flags(FieldAttributes::STATIC | FieldAttributes::PRIVATE)
            .signature(&[0x06])
            .build(&mut context)?;

        let field2_token = crate::metadata::tables::FieldBuilder::new()
            .name("StaticData2")
            .flags(FieldAttributes::STATIC | FieldAttributes::PRIVATE)
            .signature(&[0x06])
            .build(&mut context)?;

        let rva1_token = FieldRVABuilder::new()
            .field(field1_token)
            .rva(0x2000)
            .build(&mut context)?;

        let rva2_token = FieldRVABuilder::new()
            .field(field2_token)
            .rva(0x3000)
            .build(&mut context)?;

        // Verify tokens are different and sequential
        assert_ne!(rva1_token, rva2_token);
        assert_eq!(rva1_token.table(), TableId::FieldRVA as u8);
        assert_eq!(rva2_token.table(), TableId::FieldRVA as u8);
        assert_eq!(rva2_token.row(), rva1_token.row() + 1);

        Ok(())
    }

    #[test]
    fn test_field_rva_builder_various_rva_values() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Test with different RVA values
        let test_rvas = [0x1000, 0x2000, 0x4000, 0x8000, 0x10000];

        for (i, &rva) in test_rvas.iter().enumerate() {
            let field_token = crate::metadata::tables::FieldBuilder::new()
                .name(format!("StaticData{i}"))
                .flags(FieldAttributes::STATIC | FieldAttributes::PRIVATE)
                .signature(&[0x06])
                .build(&mut context)?;

            let rva_token = FieldRVABuilder::new()
                .field(field_token)
                .rva(rva)
                .build(&mut context)?;

            assert_eq!(rva_token.table(), TableId::FieldRVA as u8);
            assert!(rva_token.row() > 0);
        }

        Ok(())
    }

    #[test]
    fn test_field_rva_builder_fluent_api() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Create a Field for testing
        let field_token = crate::metadata::tables::FieldBuilder::new()
            .name("FluentTestField")
            .flags(FieldAttributes::STATIC | FieldAttributes::PRIVATE)
            .signature(&[0x06])
            .build(&mut context)?;

        // Test fluent API chaining
        let token = FieldRVABuilder::new()
            .field(field_token)
            .rva(0x5000)
            .build(&mut context)?;

        assert_eq!(token.table(), TableId::FieldRVA as u8);
        assert!(token.row() > 0);

        Ok(())
    }

    #[test]
    fn test_field_rva_builder_clone() {
        let field_token = Token::new(0x04000001);

        let builder1 = FieldRVABuilder::new().field(field_token).rva(0x2000);
        let builder2 = builder1.clone();

        assert_eq!(builder1.field, builder2.field);
        assert_eq!(builder1.rva, builder2.rva);
    }

    #[test]
    fn test_field_rva_builder_debug() {
        let field_token = Token::new(0x04000001);

        let builder = FieldRVABuilder::new().field(field_token).rva(0x2000);
        let debug_str = format!("{builder:?}");
        assert!(debug_str.contains("FieldRVABuilder"));
    }
}
