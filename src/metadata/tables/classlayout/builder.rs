//! ClassLayoutBuilder for creating type layout specifications.
//!
//! This module provides [`ClassLayoutBuilder`] for creating ClassLayout table entries
//! with a fluent API. Class layouts define memory layout characteristics for types,
//! including field alignment boundaries, explicit type sizes, and packing behavior
//! for P/Invoke interop, performance optimization, and platform compatibility.

use crate::{
    metadata::{
        cilassembly::BuilderContext,
        tables::{ClassLayoutRaw, TableDataOwned, TableId},
        token::Token,
    },
    Error, Result,
};

/// Builder for creating ClassLayout metadata entries.
///
/// `ClassLayoutBuilder` provides a fluent API for creating ClassLayout table entries
/// with validation and automatic table management. Class layouts define type-level
/// memory layout characteristics including field alignment boundaries, explicit type
/// sizes, and packing behavior for performance optimization and interoperability scenarios.
///
/// # Class Layout Model
///
/// .NET class layout follows a structured pattern:
/// - **Parent Type**: The type definition that this layout applies to
/// - **Packing Size**: Field alignment boundary (must be 0 or power of 2)
/// - **Class Size**: Explicit type size override (0 for automatic sizing)
/// - **Layout Control**: Precise control over type memory characteristics
///
/// # Layout Types and Scenarios
///
/// Class layouts are essential for various memory management scenarios:
/// - **P/Invoke Interop**: Matching native C/C++ struct sizes and alignment
/// - **Performance Critical Types**: Cache-line alignment and SIMD optimization
/// - **Memory Mapping**: Direct memory-mapped structures with fixed sizes
/// - **Platform Compatibility**: Consistent layouts across different architectures
/// - **Legacy Compatibility**: Matching existing binary format specifications
/// - **COM Interop**: Implementing COM interface memory layout requirements
///
/// # Packing Size Specifications
///
/// Packing size controls field alignment boundaries:
/// - **0**: Default packing (typically 8 bytes, platform-dependent)
/// - **1**: Byte alignment (no padding between fields)
/// - **2**: 2-byte alignment (short/char alignment)
/// - **4**: 4-byte alignment (int/float alignment)
/// - **8**: 8-byte alignment (long/double alignment)
/// - **16**: 16-byte alignment (SIMD/SSE alignment)
/// - **32**: 32-byte alignment (AVX alignment)
/// - **64**: 64-byte alignment (cache line alignment)
/// - **128**: 128-byte alignment (maximum allowed)
///
/// # Class Size Specifications
///
/// Class size provides explicit type size control:
/// - **0**: Automatic size calculation based on fields
/// - **Non-zero**: Explicit type size override in bytes
/// - **Minimum**: Must accommodate all fields within the type
/// - **Maximum**: Cannot exceed 256MB (0x10000000 bytes)
/// - **Alignment**: Should respect packing size alignment
///
/// # Examples
///
/// ```rust,no_run
/// # use dotscope::{CilAssembly, CilAssemblyView};
/// # use dotscope::metadata::cilassembly::BuilderContext;
/// # use dotscope::metadata::tables::ClassLayoutBuilder;
/// # use dotscope::metadata::token::Token;
/// # use std::path::Path;
/// # let view = CilAssemblyView::from_file(Path::new("test.dll"))?;
/// let mut assembly = CilAssembly::new(view);
/// let mut context = BuilderContext::new(&mut assembly);
///
/// // Create layout for a P/Invoke structure with byte packing
/// let struct_type = Token::new(0x02000001); // TypeDef RID 1
///
/// let packed_layout = ClassLayoutBuilder::new()
///     .parent(struct_type)
///     .packing_size(1) // Byte packing (no padding)
///     .class_size(0)   // Automatic size
///     .build(&mut context)?;
///
/// // Create layout for a performance-critical type with cache-line alignment
/// let perf_type = Token::new(0x02000002); // TypeDef RID 2
///
/// let aligned_layout = ClassLayoutBuilder::new()
///     .parent(perf_type)
///     .packing_size(64) // Cache line alignment
///     .class_size(128)  // Fixed 128-byte size
///     .build(&mut context)?;
///
/// // Create layout for SIMD-optimized mathematics structure
/// let simd_type = Token::new(0x02000003); // TypeDef RID 3
///
/// let simd_layout = ClassLayoutBuilder::new()
///     .parent(simd_type)
///     .packing_size(16) // SSE/SIMD alignment
///     .class_size(64)   // Fixed 64-byte size for 4x float4
///     .build(&mut context)?;
///
/// // Create layout for exact native structure matching
/// let native_type = Token::new(0x02000004); // TypeDef RID 4
///
/// let native_layout = ClassLayoutBuilder::new()
///     .parent(native_type)
///     .packing_size(4)  // 32-bit alignment
///     .class_size(24)   // Exact size to match native struct
///     .build(&mut context)?;
/// # Ok::<(), dotscope::Error>(())
/// ```
pub struct ClassLayoutBuilder {
    packing_size: Option<u16>,
    class_size: Option<u32>,
    parent: Option<Token>,
}

impl Default for ClassLayoutBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ClassLayoutBuilder {
    /// Creates a new ClassLayoutBuilder.
    ///
    /// # Returns
    ///
    /// A new [`ClassLayoutBuilder`] instance ready for configuration.
    pub fn new() -> Self {
        Self {
            packing_size: None,
            class_size: None,
            parent: None,
        }
    }

    /// Sets the field alignment boundary (packing size).
    ///
    /// The packing size controls the alignment boundary for fields within the type,
    /// affecting both field placement and overall type size. This directly impacts
    /// memory layout, performance characteristics, and interoperability requirements.
    ///
    /// Packing size constraints:
    /// - **Must be 0 or a power of 2**: 0, 1, 2, 4, 8, 16, 32, 64, 128
    /// - **0 means default**: Platform-dependent default alignment (typically 8 bytes)
    /// - **Maximum value**: 128 bytes (larger values are not supported)
    /// - **Performance impact**: Smaller values reduce memory usage but may hurt performance
    /// - **Interop requirement**: Must match native structure alignment expectations
    ///
    /// Common packing scenarios:
    /// - **1**: Tight packing for network protocols and file formats
    /// - **4**: Standard 32-bit platform alignment
    /// - **8**: Standard 64-bit platform alignment and double precision
    /// - **16**: SIMD/SSE optimization alignment
    /// - **32**: AVX optimization alignment
    /// - **64**: Cache line alignment for performance-critical structures
    ///
    /// # Arguments
    ///
    /// * `packing` - The field alignment boundary in bytes (0 or power of 2, max 128)
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    pub fn packing_size(mut self, packing: u16) -> Self {
        self.packing_size = Some(packing);
        self
    }

    /// Sets the explicit type size override.
    ///
    /// The class size provides explicit control over the total size of the type,
    /// overriding automatic size calculation based on field layout. This is essential
    /// for exact native structure matching and performance optimization scenarios.
    ///
    /// Class size considerations:
    /// - **0 means automatic**: Let the runtime calculate size based on fields
    /// - **Non-zero override**: Explicit size specification in bytes
    /// - **Minimum requirement**: Must accommodate all fields and their alignment
    /// - **Maximum limit**: Cannot exceed 256MB (0x10000000 bytes)
    /// - **Alignment respect**: Should be aligned to packing size boundary
    /// - **Padding inclusion**: Size includes any trailing padding needed
    ///
    /// Size specification scenarios:
    /// - **Native matching**: Exact size to match C/C++ structures
    /// - **Performance tuning**: Specific sizes for cache optimization
    /// - **Memory mapping**: Fixed sizes for memory-mapped data structures
    /// - **Protocol compliance**: Exact sizes for network and file protocols
    /// - **Legacy compatibility**: Maintaining compatibility with existing layouts
    ///
    /// # Arguments
    ///
    /// * `size` - The explicit type size in bytes (0 for automatic, max 256MB)
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    pub fn class_size(mut self, size: u32) -> Self {
        self.class_size = Some(size);
        self
    }

    /// Sets the parent type that this layout applies to.
    ///
    /// The parent must be a valid TypeDef token that references a type definition
    /// in the current assembly. This establishes which type will have this layout
    /// specification applied to control its memory characteristics.
    ///
    /// Parent type requirements:
    /// - **Valid Token**: Must be a properly formatted TypeDef token (0x02xxxxxx)
    /// - **Existing Type**: Must reference a type that has been defined
    /// - **Layout Compatible**: Type must support explicit layout specification
    /// - **Single Layout**: Each type can have at most one ClassLayout entry
    /// - **Class or Struct**: Only applies to classes and value types, not interfaces
    ///
    /// Type categories that can have layout:
    /// - **Value Types**: Structs with explicit memory layout control
    /// - **Reference Types**: Classes with specific layout requirements
    /// - **P/Invoke Types**: Types used in native interop scenarios
    /// - **Performance Types**: Types optimized for specific performance characteristics
    /// - **Protocol Types**: Types matching external data format specifications
    ///
    /// # Arguments
    ///
    /// * `parent` - A TypeDef token pointing to the type receiving this layout
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    pub fn parent(mut self, parent: Token) -> Self {
        self.parent = Some(parent);
        self
    }

    /// Builds the class layout and adds it to the assembly.
    ///
    /// This method validates all required fields are set, verifies the constraints
    /// are met, creates the raw class layout structure, and adds it to the
    /// ClassLayout table with proper token generation and validation.
    ///
    /// # Arguments
    ///
    /// * `context` - The builder context for managing the assembly
    ///
    /// # Returns
    ///
    /// A [`Token`] representing the newly created class layout, or an error if
    /// validation fails or required fields are missing.
    ///
    /// # Errors
    ///
    /// - Returns error if packing_size is not set
    /// - Returns error if class_size is not set
    /// - Returns error if parent is not set
    /// - Returns error if parent is not a valid TypeDef token
    /// - Returns error if parent RID is 0 (invalid RID)
    /// - Returns error if packing_size is not 0 or a power of 2
    /// - Returns error if packing_size exceeds 128 bytes
    /// - Returns error if class_size exceeds 256MB limit
    /// - Returns error if table operations fail
    pub fn build(self, context: &mut BuilderContext) -> Result<Token> {
        let packing_size =
            self.packing_size
                .ok_or_else(|| Error::ModificationInvalidOperation {
                    details: "Packing size is required".to_string(),
                })?;

        let class_size = self
            .class_size
            .ok_or_else(|| Error::ModificationInvalidOperation {
                details: "Class size is required".to_string(),
            })?;

        let parent = self
            .parent
            .ok_or_else(|| Error::ModificationInvalidOperation {
                details: "Parent type is required".to_string(),
            })?;

        if parent.table() != TableId::TypeDef as u8 {
            return Err(Error::ModificationInvalidOperation {
                details: format!(
                    "Parent must be a TypeDef token, got table {:?}",
                    parent.table()
                ),
            });
        }

        if parent.row() == 0 {
            return Err(Error::ModificationInvalidOperation {
                details: "Parent TypeDef RID cannot be 0".to_string(),
            });
        }

        if packing_size != 0 && (packing_size & (packing_size - 1)) != 0 {
            return Err(Error::ModificationInvalidOperation {
                details: format!(
                    "Packing size must be 0 or a power of 2, got {}",
                    packing_size
                ),
            });
        }

        if packing_size > 128 {
            return Err(Error::ModificationInvalidOperation {
                details: format!("Packing size cannot exceed 128 bytes, got {}", packing_size),
            });
        }

        const MAX_CLASS_SIZE: u32 = 0x10000000; // 256MB
        if class_size > MAX_CLASS_SIZE {
            return Err(Error::ModificationInvalidOperation {
                details: format!(
                    "Class size cannot exceed 256MB (0x{:X}), got {}",
                    MAX_CLASS_SIZE, class_size
                ),
            });
        }

        let rid = context.next_rid(TableId::ClassLayout);

        let token_value = ((TableId::ClassLayout as u32) << 24) | rid;
        let token = Token::new(token_value);

        let class_layout_raw = ClassLayoutRaw {
            rid,
            token,
            offset: 0, // Will be set during binary generation
            packing_size,
            class_size,
            parent: parent.row(),
        };

        context.add_table_row(
            TableId::ClassLayout,
            TableDataOwned::ClassLayout(class_layout_raw),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::{
        cilassembly::{BuilderContext, CilAssembly},
        cilassemblyview::CilAssemblyView,
    };
    use std::path::PathBuf;

    #[test]
    fn test_class_layout_builder_basic() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let mut assembly = CilAssembly::new(view);

            // Check existing ClassLayout table count
            let existing_count = assembly.original_table_row_count(TableId::ClassLayout);
            let expected_rid = existing_count + 1;

            let mut context = BuilderContext::new(&mut assembly);

            // Create a basic class layout
            let type_token = Token::new(0x02000001); // TypeDef RID 1

            let token = ClassLayoutBuilder::new()
                .parent(type_token)
                .packing_size(4)
                .class_size(0)
                .build(&mut context)
                .unwrap();

            // Verify token is created correctly
            assert_eq!(token.value() & 0xFF000000, 0x0F000000); // ClassLayout table prefix
            assert_eq!(token.value() & 0x00FFFFFF, expected_rid); // RID should be existing + 1
        }
    }

    #[test]
    fn test_class_layout_builder_different_packings() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let mut assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(&mut assembly);

            // Test various valid packing sizes (powers of 2)
            let type1 = Token::new(0x02000001); // TypeDef RID 1
            let type2 = Token::new(0x02000002); // TypeDef RID 2
            let type3 = Token::new(0x02000003); // TypeDef RID 3
            let type4 = Token::new(0x02000004); // TypeDef RID 4

            // Packing 1 (byte packing)
            let layout1 = ClassLayoutBuilder::new()
                .parent(type1)
                .packing_size(1)
                .class_size(0)
                .build(&mut context)
                .unwrap();

            // Packing 8 (standard 64-bit alignment)
            let layout2 = ClassLayoutBuilder::new()
                .parent(type2)
                .packing_size(8)
                .class_size(0)
                .build(&mut context)
                .unwrap();

            // Packing 16 (SIMD alignment)
            let layout3 = ClassLayoutBuilder::new()
                .parent(type3)
                .packing_size(16)
                .class_size(0)
                .build(&mut context)
                .unwrap();

            // Packing 64 (cache line alignment)
            let layout4 = ClassLayoutBuilder::new()
                .parent(type4)
                .packing_size(64)
                .class_size(0)
                .build(&mut context)
                .unwrap();

            // All should succeed with ClassLayout table prefix
            assert_eq!(layout1.value() & 0xFF000000, 0x0F000000);
            assert_eq!(layout2.value() & 0xFF000000, 0x0F000000);
            assert_eq!(layout3.value() & 0xFF000000, 0x0F000000);
            assert_eq!(layout4.value() & 0xFF000000, 0x0F000000);

            // All should have different RIDs
            assert_ne!(layout1.value() & 0x00FFFFFF, layout2.value() & 0x00FFFFFF);
            assert_ne!(layout1.value() & 0x00FFFFFF, layout3.value() & 0x00FFFFFF);
            assert_ne!(layout1.value() & 0x00FFFFFF, layout4.value() & 0x00FFFFFF);
        }
    }

    #[test]
    fn test_class_layout_builder_default_packing() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let mut assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(&mut assembly);

            let type_token = Token::new(0x02000001); // TypeDef RID 1

            // Packing 0 (default alignment)
            let token = ClassLayoutBuilder::new()
                .parent(type_token)
                .packing_size(0) // Default packing
                .class_size(0) // Automatic size
                .build(&mut context)
                .unwrap();

            // Should succeed
            assert_eq!(token.value() & 0xFF000000, 0x0F000000);
        }
    }

    #[test]
    fn test_class_layout_builder_explicit_sizes() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let mut assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(&mut assembly);

            // Test various explicit sizes
            let type1 = Token::new(0x02000001); // TypeDef RID 1
            let type2 = Token::new(0x02000002); // TypeDef RID 2
            let type3 = Token::new(0x02000003); // TypeDef RID 3

            // Small structure (16 bytes)
            let layout1 = ClassLayoutBuilder::new()
                .parent(type1)
                .packing_size(4)
                .class_size(16)
                .build(&mut context)
                .unwrap();

            // Medium structure (256 bytes)
            let layout2 = ClassLayoutBuilder::new()
                .parent(type2)
                .packing_size(8)
                .class_size(256)
                .build(&mut context)
                .unwrap();

            // Large structure (64KB)
            let layout3 = ClassLayoutBuilder::new()
                .parent(type3)
                .packing_size(16)
                .class_size(65536)
                .build(&mut context)
                .unwrap();

            // All should succeed
            assert_eq!(layout1.value() & 0xFF000000, 0x0F000000);
            assert_eq!(layout2.value() & 0xFF000000, 0x0F000000);
            assert_eq!(layout3.value() & 0xFF000000, 0x0F000000);
        }
    }

    #[test]
    fn test_class_layout_builder_missing_packing_size() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let mut assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(&mut assembly);

            let type_token = Token::new(0x02000001); // TypeDef RID 1

            let result = ClassLayoutBuilder::new()
                .parent(type_token)
                .class_size(16)
                // Missing packing_size
                .build(&mut context);

            // Should fail because packing size is required
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_class_layout_builder_missing_class_size() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let mut assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(&mut assembly);

            let type_token = Token::new(0x02000001); // TypeDef RID 1

            let result = ClassLayoutBuilder::new()
                .parent(type_token)
                .packing_size(4)
                // Missing class_size
                .build(&mut context);

            // Should fail because class size is required
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_class_layout_builder_missing_parent() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let mut assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(&mut assembly);

            let result = ClassLayoutBuilder::new()
                .packing_size(4)
                .class_size(16)
                // Missing parent
                .build(&mut context);

            // Should fail because parent is required
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_class_layout_builder_invalid_parent_token() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let mut assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(&mut assembly);

            // Use a token that's not from TypeDef table
            let invalid_parent = Token::new(0x04000001); // Field token instead

            let result = ClassLayoutBuilder::new()
                .parent(invalid_parent)
                .packing_size(4)
                .class_size(16)
                .build(&mut context);

            // Should fail because parent must be a TypeDef token
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_class_layout_builder_zero_parent_rid() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let mut assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(&mut assembly);

            // Use a TypeDef token with RID 0 (invalid)
            let invalid_parent = Token::new(0x02000000); // TypeDef with RID 0

            let result = ClassLayoutBuilder::new()
                .parent(invalid_parent)
                .packing_size(4)
                .class_size(16)
                .build(&mut context);

            // Should fail because parent RID cannot be 0
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_class_layout_builder_invalid_packing_size() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let mut assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(&mut assembly);

            let type_token = Token::new(0x02000001); // TypeDef RID 1

            // Test non-power-of-2 packing size
            let result = ClassLayoutBuilder::new()
                .parent(type_token)
                .packing_size(3) // Not a power of 2
                .class_size(16)
                .build(&mut context);

            // Should fail because packing size is not a power of 2
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_class_layout_builder_excessive_packing_size() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let mut assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(&mut assembly);

            let type_token = Token::new(0x02000001); // TypeDef RID 1

            let result = ClassLayoutBuilder::new()
                .parent(type_token)
                .packing_size(256) // Exceeds maximum of 128
                .class_size(16)
                .build(&mut context);

            // Should fail because packing size exceeds maximum
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_class_layout_builder_excessive_class_size() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let mut assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(&mut assembly);

            let type_token = Token::new(0x02000001); // TypeDef RID 1

            let result = ClassLayoutBuilder::new()
                .parent(type_token)
                .packing_size(4)
                .class_size(0x20000000) // Exceeds 256MB limit
                .build(&mut context);

            // Should fail because class size exceeds maximum
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_class_layout_builder_maximum_valid_values() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let mut assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(&mut assembly);

            let type_token = Token::new(0x02000001); // TypeDef RID 1

            // Test maximum valid values
            let token = ClassLayoutBuilder::new()
                .parent(type_token)
                .packing_size(128) // Maximum packing size
                .class_size(0x10000000 - 1) // Just under 256MB limit
                .build(&mut context)
                .unwrap();

            // Should succeed
            assert_eq!(token.value() & 0xFF000000, 0x0F000000);
        }
    }

    #[test]
    fn test_class_layout_builder_all_valid_packing_sizes() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let mut assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(&mut assembly);

            // Test all valid packing sizes (powers of 2 from 0 to 128)
            let valid_packings = [0, 1, 2, 4, 8, 16, 32, 64, 128];

            for (i, &packing) in valid_packings.iter().enumerate() {
                let type_token = Token::new(0x02000001 + i as u32); // Different TypeDef for each

                let token = ClassLayoutBuilder::new()
                    .parent(type_token)
                    .packing_size(packing)
                    .class_size(16)
                    .build(&mut context)
                    .unwrap();

                // All should succeed
                assert_eq!(token.value() & 0xFF000000, 0x0F000000);
            }
        }
    }

    #[test]
    fn test_class_layout_builder_realistic_scenarios() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let mut assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(&mut assembly);

            // P/Invoke struct with byte packing
            let pinvoke_type = Token::new(0x02000001);
            let pinvoke_layout = ClassLayoutBuilder::new()
                .parent(pinvoke_type)
                .packing_size(1) // Byte packing for exact native matching
                .class_size(32) // Fixed size to match native struct
                .build(&mut context)
                .unwrap();

            // Performance-critical type with cache line alignment
            let perf_type = Token::new(0x02000002);
            let perf_layout = ClassLayoutBuilder::new()
                .parent(perf_type)
                .packing_size(64) // Cache line alignment
                .class_size(128) // Two cache lines
                .build(&mut context)
                .unwrap();

            // SIMD mathematics structure
            let simd_type = Token::new(0x02000003);
            let simd_layout = ClassLayoutBuilder::new()
                .parent(simd_type)
                .packing_size(16) // SSE/SIMD alignment
                .class_size(64) // 4x float4 vectors
                .build(&mut context)
                .unwrap();

            // Standard managed type with default layout
            let managed_type = Token::new(0x02000004);
            let managed_layout = ClassLayoutBuilder::new()
                .parent(managed_type)
                .packing_size(0) // Default runtime alignment
                .class_size(0) // Automatic size calculation
                .build(&mut context)
                .unwrap();

            // All should succeed
            assert_eq!(pinvoke_layout.value() & 0xFF000000, 0x0F000000);
            assert_eq!(perf_layout.value() & 0xFF000000, 0x0F000000);
            assert_eq!(simd_layout.value() & 0xFF000000, 0x0F000000);
            assert_eq!(managed_layout.value() & 0xFF000000, 0x0F000000);

            // All should have different RIDs
            assert_ne!(
                pinvoke_layout.value() & 0x00FFFFFF,
                perf_layout.value() & 0x00FFFFFF
            );
            assert_ne!(
                pinvoke_layout.value() & 0x00FFFFFF,
                simd_layout.value() & 0x00FFFFFF
            );
            assert_ne!(
                pinvoke_layout.value() & 0x00FFFFFF,
                managed_layout.value() & 0x00FFFFFF
            );
            assert_ne!(
                perf_layout.value() & 0x00FFFFFF,
                simd_layout.value() & 0x00FFFFFF
            );
            assert_ne!(
                perf_layout.value() & 0x00FFFFFF,
                managed_layout.value() & 0x00FFFFFF
            );
            assert_ne!(
                simd_layout.value() & 0x00FFFFFF,
                managed_layout.value() & 0x00FFFFFF
            );
        }
    }
}
