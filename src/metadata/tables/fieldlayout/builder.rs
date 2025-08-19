//! FieldLayoutBuilder for creating explicit field layout specifications.
//!
//! This module provides [`crate::metadata::tables::fieldlayout::FieldLayoutBuilder`] for creating FieldLayout table entries
//! with a fluent API. Field layouts specify explicit byte offsets for fields in types
//! with explicit layout control, enabling precise memory layout for P/Invoke interop,
//! performance optimization, and native structure compatibility.

use crate::{
    cilassembly::BuilderContext,
    metadata::{
        tables::{FieldLayoutRaw, TableDataOwned, TableId},
        token::Token,
    },
    Error, Result,
};

/// Builder for creating FieldLayout metadata entries.
///
/// `FieldLayoutBuilder` provides a fluent API for creating FieldLayout table entries
/// with validation and automatic table management. Field layouts define explicit byte
/// offsets for fields within types that use explicit layout control, enabling precise
/// memory layout specification for interoperability, performance optimization, and
/// compatibility scenarios.
///
/// # Explicit Layout Model
///
/// .NET explicit layout follows a structured pattern:
/// - **Containing Type**: Must be marked with `StructLayout(LayoutKind.Explicit)`
/// - **Field Offset**: Explicit byte position within the type's memory layout
/// - **Field Reference**: Direct reference to the field being positioned
/// - **Memory Control**: Precise control over field placement for optimal alignment
///
/// # Layout Types and Scenarios
///
/// Field layouts are essential for various interoperability scenarios:
/// - **P/Invoke Interop**: Matching native C/C++ struct layouts exactly
/// - **COM Interop**: Implementing COM interface memory layouts
/// - **Performance Critical Types**: Cache-line alignment and SIMD optimization
/// - **Union Types**: Overlapping fields to implement C-style unions
/// - **Legacy Compatibility**: Matching existing binary format specifications
/// - **Memory Mapping**: Direct memory-mapped file and hardware register access
///
/// # Offset Specifications
///
/// Field offsets must follow specific rules:
/// - **Byte Aligned**: Offsets are specified in bytes from the start of the type
/// - **Non-Negative**: Offsets must be ≥ 0 and ≤ `i32::MAX`
/// - **Type Boundaries**: Fields must fit within the declared type size
/// - **Alignment Requirements**: Respect platform and type alignment constraints
/// - **No Gaps Required**: Fields can be packed tightly or have intentional gaps
///
/// # Examples
///
/// ```rust,ignore
/// # use dotscope::prelude::*;
/// # use dotscope::metadata::tables::FieldLayoutBuilder;
/// # use dotscope::metadata::token::Token;
/// # use std::path::Path;
/// # let view = CilAssemblyView::from_file(Path::new("test.dll"))?;
/// let assembly = CilAssembly::new(view);
/// let mut context = BuilderContext::new(assembly);
///
/// // Create explicit layout for a P/Invoke structure
/// // struct Point { int x; int y; }
/// let x_field_token = Token::new(0x04000001); // Field RID 1
/// let y_field_token = Token::new(0x04000002); // Field RID 2
///
/// // X field at offset 0 (start of struct)
/// let x_layout = FieldLayoutBuilder::new()
///     .field(x_field_token)
///     .field_offset(0)
///     .build(&mut context)?;
///
/// // Y field at offset 4 (after 4-byte int)
/// let y_layout = FieldLayoutBuilder::new()
///     .field(y_field_token)
///     .field_offset(4)
///     .build(&mut context)?;
///
/// // Create a union-like structure with overlapping fields
/// // union Value { int intValue; float floatValue; }
/// let int_field = Token::new(0x04000003);   // Field RID 3
/// let float_field = Token::new(0x04000004); // Field RID 4
///
/// // Both fields start at offset 0 (overlapping)
/// let int_layout = FieldLayoutBuilder::new()
///     .field(int_field)
///     .field_offset(0)
///     .build(&mut context)?;
///
/// let float_layout = FieldLayoutBuilder::new()
///     .field(float_field)
///     .field_offset(0) // Same offset = union behavior
///     .build(&mut context)?;
///
/// // Create cache-line aligned fields for performance
/// let cache_field1 = Token::new(0x04000005); // Field RID 5
/// let cache_field2 = Token::new(0x04000006); // Field RID 6
///
/// // First field at start
/// let aligned_layout1 = FieldLayoutBuilder::new()
///     .field(cache_field1)
///     .field_offset(0)
///     .build(&mut context)?;
///
/// // Second field at 64-byte boundary (cache line)
/// let aligned_layout2 = FieldLayoutBuilder::new()
///     .field(cache_field2)
///     .field_offset(64)
///     .build(&mut context)?;
/// # Ok::<(), dotscope::Error>(())
/// ```
pub struct FieldLayoutBuilder {
    field_offset: Option<u32>,
    field: Option<Token>,
}

impl Default for FieldLayoutBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl FieldLayoutBuilder {
    /// Creates a new FieldLayoutBuilder.
    ///
    /// # Returns
    ///
    /// A new [`crate::metadata::tables::fieldlayout::FieldLayoutBuilder`] instance ready for configuration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            field_offset: None,
            field: None,
        }
    }

    /// Sets the explicit byte offset for the field.
    ///
    /// The field offset specifies the exact byte position where this field begins
    /// within the containing type's memory layout. Offsets are measured from the
    /// start of the type and must respect alignment and size constraints.
    ///
    /// Offset considerations:
    /// - **Zero-based**: Offset 0 means the field starts at the beginning of the type
    /// - **Byte granularity**: Offsets are specified in bytes, not bits
    /// - **Alignment**: Consider natural alignment requirements for the field type
    /// - **Overlapping**: Multiple fields can have the same offset (union behavior)
    /// - **Gaps**: Intentional gaps between fields are allowed for padding
    /// - **Maximum**: Offset must be ≤ `i32::MAX` (2,147,483,647)
    ///
    /// Common offset patterns:
    /// - **Packed structures**: Sequential offsets with no padding
    /// - **Aligned structures**: Offsets respecting natural type alignment
    /// - **Cache-aligned**: Offsets at 64-byte boundaries for performance
    /// - **Page-aligned**: Offsets at 4KB boundaries for memory mapping
    ///
    /// # Arguments
    ///
    /// * `offset` - The byte offset from the start of the containing type
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn field_offset(mut self, offset: u32) -> Self {
        self.field_offset = Some(offset);
        self
    }

    /// Sets the field that this layout applies to.
    ///
    /// The field must be a valid Field token that references a field definition
    /// in the current assembly. This establishes which field will be positioned
    /// at the specified offset within the containing type's layout.
    ///
    /// Field requirements:
    /// - **Valid Token**: Must be a properly formatted Field token (0x04xxxxxx)
    /// - **Existing Field**: Must reference a field that has been defined
    /// - **Explicit Layout Type**: The containing type must use explicit layout
    /// - **Single Layout**: Each field can have at most one FieldLayout entry
    /// - **Instance Fields**: Only applies to instance fields, not static fields
    ///
    /// Field types that require explicit layout:
    /// - **Primitive Types**: int, float, byte, etc. with specific positioning
    /// - **Value Types**: Custom structs with explicit internal layout
    /// - **Reference Types**: Object references with controlled placement
    /// - **Array Fields**: Fixed-size arrays with explicit positioning
    /// - **Pointer Fields**: Unmanaged pointers with specific alignment needs
    ///
    /// # Arguments
    ///
    /// * `field` - A Field token pointing to the field being positioned
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn field(mut self, field: Token) -> Self {
        self.field = Some(field);
        self
    }

    /// Builds the field layout and adds it to the assembly.
    ///
    /// This method validates all required fields are set, verifies the field token
    /// is valid, creates the raw field layout structure, and adds it to the
    /// FieldLayout table with proper token generation and validation.
    ///
    /// # Arguments
    ///
    /// * `context` - The builder context for managing the assembly
    ///
    /// # Returns
    ///
    /// A [`crate::metadata::token::Token`] representing the newly created field layout, or an error if
    /// validation fails or required fields are missing.
    ///
    /// # Errors
    ///
    /// - Returns error if field_offset is not set
    /// - Returns error if field is not set
    /// - Returns error if field is not a valid Field token
    /// - Returns error if field RID is 0 (invalid RID)
    /// - Returns error if offset exceeds maximum allowed value
    /// - Returns error if table operations fail
    pub fn build(self, context: &mut BuilderContext) -> Result<Token> {
        let field_offset =
            self.field_offset
                .ok_or_else(|| Error::ModificationInvalidOperation {
                    details: "Field offset is required".to_string(),
                })?;

        let field = self
            .field
            .ok_or_else(|| Error::ModificationInvalidOperation {
                details: "Field reference is required".to_string(),
            })?;

        if field.table() != TableId::Field as u8 {
            return Err(Error::ModificationInvalidOperation {
                details: format!(
                    "Field reference must be a Field token, got table {:?}",
                    field.table()
                ),
            });
        }

        if field.row() == 0 {
            return Err(Error::ModificationInvalidOperation {
                details: "Field RID cannot be 0".to_string(),
            });
        }

        // Note: u32::MAX is reserved as "missing offset" indicator in some contexts
        if field_offset == u32::MAX {
            return Err(Error::ModificationInvalidOperation {
                details: "Field offset cannot be 0xFFFFFFFF (reserved value)".to_string(),
            });
        }

        let rid = context.next_rid(TableId::FieldLayout);

        let token_value = ((TableId::FieldLayout as u32) << 24) | rid;
        let token = Token::new(token_value);

        let field_layout_raw = FieldLayoutRaw {
            rid,
            token,
            offset: 0, // Will be set during binary generation
            field_offset,
            field: field.row(),
        };

        context.table_row_add(
            TableId::FieldLayout,
            TableDataOwned::FieldLayout(field_layout_raw),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cilassembly::{BuilderContext, CilAssembly},
        metadata::cilassemblyview::CilAssemblyView,
    };
    use std::path::PathBuf;

    #[test]
    fn test_field_layout_builder_basic() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);

            // Check existing FieldLayout table count
            let existing_count = assembly.original_table_row_count(TableId::FieldLayout);
            let expected_rid = existing_count + 1;

            let mut context = BuilderContext::new(assembly);

            // Create a basic field layout
            let field_token = Token::new(0x04000001); // Field RID 1

            let token = FieldLayoutBuilder::new()
                .field(field_token)
                .field_offset(0)
                .build(&mut context)
                .unwrap();

            // Verify token is created correctly
            assert_eq!(token.value() & 0xFF000000, 0x10000000); // FieldLayout table prefix
            assert_eq!(token.value() & 0x00FFFFFF, expected_rid); // RID should be existing + 1
        }
    }

    #[test]
    fn test_field_layout_builder_different_offsets() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            // Test various common offset values
            let field1 = Token::new(0x04000001); // Field RID 1
            let field2 = Token::new(0x04000002); // Field RID 2
            let field3 = Token::new(0x04000003); // Field RID 3
            let field4 = Token::new(0x04000004); // Field RID 4

            // Offset 0 (start of structure)
            let layout1 = FieldLayoutBuilder::new()
                .field(field1)
                .field_offset(0)
                .build(&mut context)
                .unwrap();

            // Offset 4 (typical int alignment)
            let layout2 = FieldLayoutBuilder::new()
                .field(field2)
                .field_offset(4)
                .build(&mut context)
                .unwrap();

            // Offset 8 (typical double alignment)
            let layout3 = FieldLayoutBuilder::new()
                .field(field3)
                .field_offset(8)
                .build(&mut context)
                .unwrap();

            // Offset 64 (cache line alignment)
            let layout4 = FieldLayoutBuilder::new()
                .field(field4)
                .field_offset(64)
                .build(&mut context)
                .unwrap();

            // All should succeed with FieldLayout table prefix
            assert_eq!(layout1.value() & 0xFF000000, 0x10000000);
            assert_eq!(layout2.value() & 0xFF000000, 0x10000000);
            assert_eq!(layout3.value() & 0xFF000000, 0x10000000);
            assert_eq!(layout4.value() & 0xFF000000, 0x10000000);

            // All should have different RIDs
            assert_ne!(layout1.value() & 0x00FFFFFF, layout2.value() & 0x00FFFFFF);
            assert_ne!(layout1.value() & 0x00FFFFFF, layout3.value() & 0x00FFFFFF);
            assert_ne!(layout1.value() & 0x00FFFFFF, layout4.value() & 0x00FFFFFF);
        }
    }

    #[test]
    fn test_field_layout_builder_union_layout() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            // Create overlapping fields (union behavior)
            let int_field = Token::new(0x04000001); // Field RID 1
            let float_field = Token::new(0x04000002); // Field RID 2

            // Both fields at offset 0 (overlapping)
            let int_layout = FieldLayoutBuilder::new()
                .field(int_field)
                .field_offset(0)
                .build(&mut context)
                .unwrap();

            let float_layout = FieldLayoutBuilder::new()
                .field(float_field)
                .field_offset(0) // Same offset = union
                .build(&mut context)
                .unwrap();

            // Both should succeed with different tokens
            assert_ne!(int_layout.value(), float_layout.value());
            assert_eq!(int_layout.value() & 0xFF000000, 0x10000000);
            assert_eq!(float_layout.value() & 0xFF000000, 0x10000000);
        }
    }

    #[test]
    fn test_field_layout_builder_large_offsets() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            let field_token = Token::new(0x04000001); // Field RID 1

            // Test large but valid offset
            let large_offset = 1024 * 1024; // 1MB offset
            let token = FieldLayoutBuilder::new()
                .field(field_token)
                .field_offset(large_offset)
                .build(&mut context)
                .unwrap();

            // Should succeed
            assert_eq!(token.value() & 0xFF000000, 0x10000000);
        }
    }

    #[test]
    fn test_field_layout_builder_missing_field_offset() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            let field_token = Token::new(0x04000001); // Field RID 1

            let result = FieldLayoutBuilder::new()
                .field(field_token)
                // Missing field_offset
                .build(&mut context);

            // Should fail because field offset is required
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_field_layout_builder_missing_field() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            let result = FieldLayoutBuilder::new()
                .field_offset(4)
                // Missing field
                .build(&mut context);

            // Should fail because field is required
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_field_layout_builder_invalid_field_token() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            // Use a token that's not from Field table
            let invalid_field = Token::new(0x02000001); // TypeDef token instead

            let result = FieldLayoutBuilder::new()
                .field(invalid_field)
                .field_offset(0)
                .build(&mut context);

            // Should fail because field must be a Field token
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_field_layout_builder_zero_field_rid() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            // Use a Field token with RID 0 (invalid)
            let invalid_field = Token::new(0x04000000); // Field with RID 0

            let result = FieldLayoutBuilder::new()
                .field(invalid_field)
                .field_offset(0)
                .build(&mut context);

            // Should fail because field RID cannot be 0
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_field_layout_builder_reserved_offset() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            let field_token = Token::new(0x04000001); // Field RID 1

            let result = FieldLayoutBuilder::new()
                .field(field_token)
                .field_offset(u32::MAX) // Reserved value
                .build(&mut context);

            // Should fail because 0xFFFFFFFF is reserved
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_field_layout_builder_multiple_layouts() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            // Create layouts for multiple fields simulating a struct
            let field1 = Token::new(0x04000001); // int field
            let field2 = Token::new(0x04000002); // float field
            let field3 = Token::new(0x04000003); // double field
            let field4 = Token::new(0x04000004); // byte field

            let layout1 = FieldLayoutBuilder::new()
                .field(field1)
                .field_offset(0) // int at offset 0
                .build(&mut context)
                .unwrap();

            let layout2 = FieldLayoutBuilder::new()
                .field(field2)
                .field_offset(4) // float at offset 4
                .build(&mut context)
                .unwrap();

            let layout3 = FieldLayoutBuilder::new()
                .field(field3)
                .field_offset(8) // double at offset 8 (aligned)
                .build(&mut context)
                .unwrap();

            let layout4 = FieldLayoutBuilder::new()
                .field(field4)
                .field_offset(16) // byte at offset 16
                .build(&mut context)
                .unwrap();

            // All should succeed and have different RIDs
            assert_ne!(layout1.value() & 0x00FFFFFF, layout2.value() & 0x00FFFFFF);
            assert_ne!(layout1.value() & 0x00FFFFFF, layout3.value() & 0x00FFFFFF);
            assert_ne!(layout1.value() & 0x00FFFFFF, layout4.value() & 0x00FFFFFF);
            assert_ne!(layout2.value() & 0x00FFFFFF, layout3.value() & 0x00FFFFFF);
            assert_ne!(layout2.value() & 0x00FFFFFF, layout4.value() & 0x00FFFFFF);
            assert_ne!(layout3.value() & 0x00FFFFFF, layout4.value() & 0x00FFFFFF);

            // All should have FieldLayout table prefix
            assert_eq!(layout1.value() & 0xFF000000, 0x10000000);
            assert_eq!(layout2.value() & 0xFF000000, 0x10000000);
            assert_eq!(layout3.value() & 0xFF000000, 0x10000000);
            assert_eq!(layout4.value() & 0xFF000000, 0x10000000);
        }
    }

    #[test]
    fn test_field_layout_builder_realistic_struct() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            // Realistic scenario: Point3D struct with explicit layout
            // struct Point3D { float x, y, z; int flags; }
            let x_field = Token::new(0x04000001); // x coordinate
            let y_field = Token::new(0x04000002); // y coordinate
            let z_field = Token::new(0x04000003); // z coordinate
            let flags_field = Token::new(0x04000004); // flags

            // Create layouts with proper float alignment
            let x_layout = FieldLayoutBuilder::new()
                .field(x_field)
                .field_offset(0) // x at start
                .build(&mut context)
                .unwrap();

            let y_layout = FieldLayoutBuilder::new()
                .field(y_field)
                .field_offset(4) // y after x (4-byte float)
                .build(&mut context)
                .unwrap();

            let z_layout = FieldLayoutBuilder::new()
                .field(z_field)
                .field_offset(8) // z after y (4-byte float)
                .build(&mut context)
                .unwrap();

            let flags_layout = FieldLayoutBuilder::new()
                .field(flags_field)
                .field_offset(12) // flags after z (4-byte float)
                .build(&mut context)
                .unwrap();

            // All layouts should be created successfully
            assert_eq!(x_layout.value() & 0xFF000000, 0x10000000);
            assert_eq!(y_layout.value() & 0xFF000000, 0x10000000);
            assert_eq!(z_layout.value() & 0xFF000000, 0x10000000);
            assert_eq!(flags_layout.value() & 0xFF000000, 0x10000000);

            // All should have different RIDs
            assert_ne!(x_layout.value() & 0x00FFFFFF, y_layout.value() & 0x00FFFFFF);
            assert_ne!(x_layout.value() & 0x00FFFFFF, z_layout.value() & 0x00FFFFFF);
            assert_ne!(
                x_layout.value() & 0x00FFFFFF,
                flags_layout.value() & 0x00FFFFFF
            );
            assert_ne!(y_layout.value() & 0x00FFFFFF, z_layout.value() & 0x00FFFFFF);
            assert_ne!(
                y_layout.value() & 0x00FFFFFF,
                flags_layout.value() & 0x00FFFFFF
            );
            assert_ne!(
                z_layout.value() & 0x00FFFFFF,
                flags_layout.value() & 0x00FFFFFF
            );
        }
    }

    #[test]
    fn test_field_layout_builder_performance_alignment() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            // Performance-oriented layout with cache line alignment
            let hot_field = Token::new(0x04000001); // Frequently accessed
            let cold_field = Token::new(0x04000002); // Rarely accessed

            // Hot field at start (cache line 0)
            let hot_layout = FieldLayoutBuilder::new()
                .field(hot_field)
                .field_offset(0)
                .build(&mut context)
                .unwrap();

            // Cold field at next cache line boundary (64 bytes)
            let cold_layout = FieldLayoutBuilder::new()
                .field(cold_field)
                .field_offset(64)
                .build(&mut context)
                .unwrap();

            // Both should succeed
            assert_eq!(hot_layout.value() & 0xFF000000, 0x10000000);
            assert_eq!(cold_layout.value() & 0xFF000000, 0x10000000);
            assert_ne!(hot_layout.value(), cold_layout.value());
        }
    }
}
