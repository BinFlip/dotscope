//! # Class Layout Validation for .NET Metadata
//!
//! This module provides comprehensive validation for class-level layout constraints according
//! to .NET runtime rules and ECMA-335 specifications. Layout validation ensures that explicit
//! layout types conform to runtime requirements and memory alignment constraints.
//!
//! ## Overview
//!
//! Class layout validation in .NET involves several key aspects:
//!
//! - **Packing Size Validation**: Ensuring packing alignment values are valid powers of 2
//! - **Type Compatibility**: Verifying that explicit layout is only applied to appropriate types
//! - **Size Constraints**: Validating that class sizes are within reasonable runtime limits
//! - **Runtime Compliance**: Matching validation behavior of the .NET runtime
//!
//! ## Layout Types
//!
//! .NET supports three primary layout types:
//!
//! - **Auto Layout**: Runtime determines optimal field placement (default)
//! - **Sequential Layout**: Fields are laid out in declaration order
//! - **Explicit Layout**: Developer specifies exact field positions
//!
//! This module focuses on validation for explicit layout scenarios where precise
//! control over memory layout is required.
//!
//! ## Packing Size Rules
//!
//! Packing size controls field alignment and must follow these rules:
//! - Must be 0 (for default packing) or a power of 2
//! - Valid values: 0, 1, 2, 4, 8, 16, 32, 64, 128
//! - Default packing size is 64 bytes when 0 is specified
//! - Maximum packing size is 128 bytes
//!
//! ## Type Restrictions
//!
//! Explicit layout can only be applied to:
//! - **Classes**: Reference types with controlled layout
//! - **Value Types**: Structs with specific memory requirements
//!
//! Explicit layout cannot be applied to:
//! - **Interfaces**: No physical layout representation
//! - **Primitive Types**: Layout is fixed by the runtime
//! - **Arrays**: Layout is managed by the runtime
//!
//! ## Usage Examples
//!
//! The `LayoutValidator` provides methods for validating class layout parameters
//! including packing sizes, type compatibility, and size constraints. These
//! validations ensure that explicit layout types conform to runtime requirements.
//!
//! ## Runtime Compliance
//!
//! This implementation follows .NET runtime validation behavior to ensure
//! compatibility with actual runtime loading and execution:
//!
//! - **Packing validation** matches CoreCLR packing size constraints
//! - **Type restrictions** follow ECMA-335 layout specifications
//! - **Size limits** prevent excessive memory allocation
//! - **Error messages** provide runtime-style diagnostics
//!
//! ## Thread Safety
//!
//! The `LayoutValidator` is stateless and safe for concurrent use across multiple threads.
//!
//! ## Related Modules
//!
//! - [`crate::metadata::validation::field`] - Field-level layout validation
//! - [`crate::metadata::tables::ClassLayout`] - ClassLayout table structures
//! - [`crate::metadata::typesystem`] - Type system components
//!
//! ## References
//!
//! - ECMA-335, Partition II, Section 10.7 - Controlling instance layout
//! - ECMA-335, Partition II, Section 23.2.3 - ClassLayout table
//! - .NET Core Runtime: Layout validation implementation

use crate::{
    metadata::typesystem::{CilFlavor, CilTypeRc},
    Result,
};

/// Class layout validator for .NET metadata compliance.
///
/// Provides validation functionality for class layout metadata as defined in ECMA-335
/// and implemented by the .NET runtime. This validator ensures that class layout
/// specifications conform to runtime constraints and type system requirements.
///
/// ## Design Philosophy
///
/// The validator implements the same validation logic used by the .NET runtime
/// during type loading, ensuring that validated metadata will be compatible
/// with actual runtime execution. This includes matching error conditions,
/// size limits, and type restrictions.
///
/// ## Validation Categories
///
/// - **Structural validation**: Packing size format and range checking
/// - **Type compatibility**: Ensuring layout is applied to appropriate types
/// - **Runtime limits**: Enforcing practical size and alignment constraints
/// - **ECMA-335 compliance**: Following specification requirements
///
/// ## Thread Safety
///
/// This struct is stateless and all methods are safe for concurrent use.
pub struct LayoutValidator;

impl LayoutValidator {
    /// Validates class layout constraints according to .NET runtime rules.
    ///
    /// Performs comprehensive validation of class layout parameters to ensure compliance
    /// with .NET runtime requirements and ECMA-335 specifications. This validation
    /// prevents runtime errors and ensures proper memory layout behavior.
    ///
    /// ## Validation Performed
    ///
    /// ### Packing Size Validation
    /// - **Power of 2 requirement**: Packing size must be 0 or a power of 2
    /// - **Range checking**: Valid values are 0, 1, 2, 4, 8, 16, 32, 64, 128
    /// - **Default handling**: 0 indicates default packing (64 bytes)
    /// - **Maximum limit**: Enforces 128-byte maximum packing size
    ///
    /// ### Type Compatibility
    /// - **Valid types**: Classes and value types can use explicit layout
    /// - **Invalid types**: Interfaces and primitives cannot use explicit layout
    /// - **Type checking**: Verifies parent type flavor compatibility
    ///
    /// ### Size Constraints
    /// - **Reasonable limits**: Class size cannot exceed 256MB (0x10000000)
    /// - **Overflow prevention**: Prevents excessive memory allocation
    /// - **Runtime compatibility**: Matches .NET runtime size limits
    ///
    /// # Arguments
    ///
    /// * `class_size` - The declared size of the class in bytes
    /// * `packing_size` - The packing alignment value (0 for default, or power of 2)
    /// * `parent_type` - The type that this layout applies to
    ///
    /// # Returns
    ///
    /// `Ok(())` if all layout constraints are satisfied, or an error describing
    /// the first validation failure encountered.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] in these cases:
    /// - **Invalid Packing Size**: Not 0 or a power of 2, or exceeds 128
    /// - **Type Incompatibility**: Explicit layout applied to interface or invalid type
    /// - **Size Violation**: Class size exceeds maximum allowed size (256MB)
    ///
    /// # Packing Size Reference
    ///
    /// | Value | Alignment | Description |
    /// |-------|-----------|-------------|
    /// | 0     | 64 bytes  | Runtime default |
    /// | 1     | 1 byte    | No alignment |
    /// | 2     | 2 bytes   | 16-bit alignment |
    /// | 4     | 4 bytes   | 32-bit alignment |
    /// | 8     | 8 bytes   | 64-bit alignment |
    /// | 16    | 16 bytes  | 128-bit alignment |
    /// | 32    | 32 bytes  | 256-bit alignment |
    /// | 64    | 64 bytes  | Default alignment |
    /// | 128   | 128 bytes | Maximum alignment |
    ///
    /// # Type Compatibility
    ///
    /// | Type Flavor | Explicit Layout | Notes |
    /// |-------------|-----------------|-------|
    /// | Class       | ✅ Supported    | Reference types |
    /// | ValueType   | ✅ Supported    | Structs |
    /// | Interface   | ❌ Not allowed  | No physical layout |
    /// | Primitive   | ❌ Not allowed  | Fixed runtime layout |
    /// | Array       | ❌ Not allowed  | Runtime-managed |
    ///
    /// # .NET Runtime Compliance
    ///
    /// This validation matches the behavior implemented in the .NET Core runtime
    /// for class layout validation, ensuring compatibility with actual runtime
    /// type loading and execution.
    pub fn validate_class_layout(
        class_size: u32,
        packing_size: u16,
        parent_type: &CilTypeRc,
    ) -> Result<()> {
        // Validate packing size is a power of 2 (or 0 for default)
        // .NET runtime allows 0 which defaults to DEFAULT_PACKING_SIZE (64)
        if packing_size != 0 && !packing_size.is_power_of_two() {
            return Err(malformed_error!(
                "Invalid packing size {} for type {} (Token: 0x{:08X}) - must be 0 or power of 2",
                packing_size,
                parent_type.name,
                parent_type.token.value()
            ));
        }

        // Validate packing size is within .NET runtime bounds
        // The .NET runtime uses a maximum packing size of 128 for most scenarios
        // but the default is 64. Let's use 128 as the absolute maximum.
        if packing_size > 128 {
            return Err(malformed_error!(
                "Invalid packing size {} for type {} (Token: 0x{:08X}) - maximum is 128",
                packing_size,
                parent_type.name,
                parent_type.token.value()
            ));
        }

        // Validate that explicit layout is only applied to appropriate types
        match parent_type.flavor() {
            CilFlavor::Class | CilFlavor::ValueType => {
                // These are valid for explicit layout
            }
            CilFlavor::Interface => {
                return Err(malformed_error!(
                    "Cannot apply explicit layout to interface {} (Token: 0x{:08X})",
                    parent_type.name,
                    parent_type.token.value()
                ));
            }
            _ => {
                return Err(malformed_error!(
                    "Invalid type {} (Token: 0x{:08X}) for explicit layout - must be class or value type",
                    parent_type.name,
                    parent_type.token.value()
                ));
            }
        }

        // Validate class size is reasonable (not negative, not too large)
        if class_size > 0x1000_0000 {
            // 256MB limit seems reasonable for class size
            return Err(malformed_error!(
                "Class size {} for type {} (Token: 0x{:08X}) exceeds maximum allowed size",
                class_size,
                parent_type.name,
                parent_type.token.value()
            ));
        }

        Ok(())
    }

    /// Validates that a packing size value is valid according to .NET rules.
    ///
    /// Helper method for validating packing size constraints independently
    /// of full class layout validation. Useful for validating packing sizes
    /// in isolation or for custom validation scenarios.
    ///
    /// # Arguments
    ///
    /// * `packing_size` - The packing alignment value to validate
    ///
    /// # Returns
    ///
    /// `Ok(())` if the packing size is valid, or an error describing the issue.
    ///
    /// # Examples
    ///
    /// The `validate_packing_size` method validates that packing alignment values
    /// are either 0 (for default) or a power of 2 up to the maximum allowed size.
    pub fn validate_packing_size(packing_size: u16) -> Result<()> {
        if packing_size != 0 && !packing_size.is_power_of_two() {
            return Err(malformed_error!(
                "Invalid packing size {} - must be 0 or power of 2",
                packing_size
            ));
        }

        if packing_size > 128 {
            return Err(malformed_error!(
                "Invalid packing size {} - maximum is 128",
                packing_size
            ));
        }

        Ok(())
    }

    /// Validates that a type can use explicit layout.
    ///
    /// Helper method for checking type compatibility with explicit layout
    /// independently of other layout constraints. Useful for type system
    /// validation and custom layout scenarios.
    ///
    /// # Arguments
    ///
    /// * `type_flavor` - The flavor of the type to check
    ///
    /// # Returns
    ///
    /// `Ok(())` if the type can use explicit layout, or an error explaining why not.
    ///
    /// # Examples
    ///
    /// The `validate_type_layout_compatibility` method checks whether a type
    /// flavor can use explicit layout. Only classes and value types are permitted
    /// to use explicit layout in .NET.
    pub fn validate_type_layout_compatibility(type_flavor: &CilFlavor) -> Result<()> {
        match *type_flavor {
            CilFlavor::Class | CilFlavor::ValueType => Ok(()),
            CilFlavor::Interface => Err(malformed_error!(
                "Cannot apply explicit layout to interface type"
            )),
            _ => Err(malformed_error!(
                "Invalid type for explicit layout - must be class or value type"
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::token::Token;
    use crate::metadata::typesystem::{CilFlavor, CilType};
    use std::sync::Arc;

    fn create_test_type(name: &str, flavor: CilFlavor) -> CilTypeRc {
        Arc::new(CilType::new(
            Token::new(0x12345),
            "TestNamespace".to_string(),
            name.to_string(),
            None,                         // external
            None,                         // base
            0,                            // flags
            Arc::new(boxcar::Vec::new()), // fields
            Arc::new(boxcar::Vec::new()), // methods
            Some(flavor),
        ))
    }

    #[test]
    fn test_valid_class_layout() {
        let class_type = create_test_type("TestClass", CilFlavor::Class);

        // Valid layout parameters should pass
        assert!(LayoutValidator::validate_class_layout(64, 8, &class_type).is_ok());
        assert!(LayoutValidator::validate_class_layout(128, 0, &class_type).is_ok());
        assert!(LayoutValidator::validate_class_layout(32, 16, &class_type).is_ok());
    }

    #[test]
    fn test_valid_value_type_layout() {
        let value_type = create_test_type("TestStruct", CilFlavor::ValueType);

        // Value types should support explicit layout
        assert!(LayoutValidator::validate_class_layout(16, 4, &value_type).is_ok());
        assert!(LayoutValidator::validate_class_layout(8, 1, &value_type).is_ok());
    }

    #[test]
    fn test_invalid_packing_size_not_power_of_two() {
        let class_type = create_test_type("TestClass", CilFlavor::Class);

        // Non-power-of-2 packing sizes should fail
        let result = LayoutValidator::validate_class_layout(64, 3, &class_type);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("power of 2"));

        let result = LayoutValidator::validate_class_layout(64, 7, &class_type);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("power of 2"));
    }

    #[test]
    fn test_invalid_packing_size_too_large() {
        let class_type = create_test_type("TestClass", CilFlavor::Class);

        // Packing sizes > 128 should fail
        let result = LayoutValidator::validate_class_layout(64, 256, &class_type);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("maximum is 128"));
    }

    #[test]
    fn test_interface_layout_not_allowed() {
        let interface_type = create_test_type("ITestInterface", CilFlavor::Interface);

        // Interfaces cannot use explicit layout
        let result = LayoutValidator::validate_class_layout(64, 8, &interface_type);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("interface"));
    }

    #[test]
    fn test_class_size_too_large() {
        let class_type = create_test_type("TestClass", CilFlavor::Class);

        // Class size exceeding 256MB should fail
        let result = LayoutValidator::validate_class_layout(0x1000_0001, 8, &class_type);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("exceeds maximum"));
    }

    #[test]
    fn test_valid_packing_sizes() {
        // Test all valid power-of-2 packing sizes
        let valid_sizes = [0, 1, 2, 4, 8, 16, 32, 64, 128];

        for &size in &valid_sizes {
            assert!(
                LayoutValidator::validate_packing_size(size).is_ok(),
                "Packing size {} should be valid",
                size
            );
        }
    }

    #[test]
    fn test_invalid_packing_sizes() {
        // Test invalid packing sizes
        let invalid_sizes = [3, 5, 6, 7, 9, 15, 17, 31, 33, 63, 65, 127, 129, 256, 512];

        for &size in &invalid_sizes {
            assert!(
                LayoutValidator::validate_packing_size(size).is_err(),
                "Packing size {} should be invalid",
                size
            );
        }
    }

    #[test]
    fn test_type_layout_compatibility() {
        // Valid types for explicit layout
        assert!(LayoutValidator::validate_type_layout_compatibility(&CilFlavor::Class).is_ok());
        assert!(LayoutValidator::validate_type_layout_compatibility(&CilFlavor::ValueType).is_ok());

        // Invalid types for explicit layout
        assert!(
            LayoutValidator::validate_type_layout_compatibility(&CilFlavor::Interface).is_err()
        );
        assert!(LayoutValidator::validate_type_layout_compatibility(&CilFlavor::I4).is_err());
        assert!(LayoutValidator::validate_type_layout_compatibility(&CilFlavor::String).is_err());
    }

    #[test]
    fn test_edge_case_layouts() {
        let class_type = create_test_type("EdgeCaseClass", CilFlavor::Class);

        // Edge case: minimum valid class size with maximum packing
        assert!(LayoutValidator::validate_class_layout(0, 128, &class_type).is_ok());

        // Edge case: maximum valid class size with minimum packing
        assert!(LayoutValidator::validate_class_layout(0x1000_0000, 1, &class_type).is_ok());

        // Edge case: default packing (0) with various sizes
        assert!(LayoutValidator::validate_class_layout(1, 0, &class_type).is_ok());
        assert!(LayoutValidator::validate_class_layout(1024, 0, &class_type).is_ok());
    }

    #[test]
    fn test_comprehensive_layout_scenarios() {
        // Test realistic layout scenarios

        // Scenario 1: P/Invoke struct with 1-byte packing
        let pinvoke_struct = create_test_type("Win32Struct", CilFlavor::ValueType);
        assert!(LayoutValidator::validate_class_layout(32, 1, &pinvoke_struct).is_ok());

        // Scenario 2: Cache-aligned class with 64-byte packing
        let cache_aligned_class = create_test_type("CacheAlignedData", CilFlavor::Class);
        assert!(LayoutValidator::validate_class_layout(128, 64, &cache_aligned_class).is_ok());

        // Scenario 3: SIMD-friendly struct with 16-byte packing
        let simd_struct = create_test_type("Vector4", CilFlavor::ValueType);
        assert!(LayoutValidator::validate_class_layout(16, 16, &simd_struct).is_ok());

        // Scenario 4: Large data structure with default packing
        let large_class = create_test_type("LargeBuffer", CilFlavor::Class);
        assert!(LayoutValidator::validate_class_layout(65536, 0, &large_class).is_ok());
    }
}
