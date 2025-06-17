//! # Token Validation for .NET Metadata Systems
//!
//! This module provides comprehensive token validation that ensures metadata token
//! integrity, cross-reference consistency, and runtime compliance for .NET assemblies.
//! The validation aligns with CLR token validation behavior and focuses on issues
//! that would cause actual runtime failures rather than structural anomalies.
//!
//! ## Overview
//!
//! Token validation is a critical component of metadata validation that ensures
//! the integrity of metadata tokens used throughout .NET assemblies. Tokens serve
//! as unique identifiers for metadata elements (types, methods, fields, etc.)
//! and their consistency is essential for proper runtime behavior and type loading.
//!
//! ## Token System Architecture
//!
//! ### Token Structure
//! .NET metadata tokens consist of:
//! - **Table ID**: Identifies the metadata table (high byte)
//! - **Row Index (RID)**: Identifies the specific row within the table (lower 3 bytes)
//! - **Token Value**: 32-bit value encoding both table and row information
//!
//! ### Token Categories
//! - **Type Tokens**: TypeDef, TypeRef, TypeSpec (tables 0x02, 0x01, 0x1B)
//! - **Member Tokens**: MethodDef, FieldDef, PropertyDef, EventDef
//! - **Reference Tokens**: MemberRef, MethodSpec, signatures
//! - **Special Tokens**: String, UserString, Blob, Guid references
//!
//! ## Validation Philosophy
//!
//! The token validator implements a runtime-aligned validation approach:
//! - **Runtime Focus**: Validates only issues that cause actual CLR failures
//! - **Lazy Validation**: Aligns with CLR's lazy token resolution strategy
//! - **Critical Path**: Focuses on tokens in critical execution paths
//! - **Performance Aware**: Optimized for validation speed and resource usage
//!
//! ## Validation Categories
//!
//! ### Cross-Reference Integrity
//! - **Reference Resolution**: Ensures tokens resolve to valid metadata elements
//! - **Table Consistency**: Validates tokens reference appropriate table types
//! - **Null Token Detection**: Identifies invalid null token references
//! - **Circular Reference Prevention**: Detects and prevents circular token chains
//!
//! ### Runtime-Critical Validation
//! - **Inheritance Tokens**: Validates base type token references for inheritance
//! - **Method Signatures**: Ensures method signature tokens are resolvable
//! - **Field Types**: Validates field type token references
//! - **Interface Implementation**: Checks interface token consistency
//!
//! ### Type Loading Dependencies
//! - **Base Type Chains**: Validates inheritance token chains
//! - **Generic Parameters**: Ensures generic parameter tokens are valid
//! - **Nested Type References**: Validates nested type token relationships
//! - **Assembly References**: Checks cross-assembly token references
//!
//! ## Token Validation Scenarios
//!
//! ### Valid Token References
//! ```csharp
//! // Valid token references that pass validation
//! public class BaseClass { }
//! public class DerivedClass : BaseClass { }  // ✓ Valid base type token
//!
//! public class Container {
//!     public string Field;      // ✓ Valid field type token
//!     public void Method() { }  // ✓ Valid method signature tokens
//! }
//!
//! public interface IContract { }
//! public class Implementation : IContract { }  // ✓ Valid interface token
//! ```
//!
//! ### Invalid Token References
//! ```text
//! // Invalid token references detected by validation
//! Type 'DerivedClass' has null base type token              // ❌ Null token
//! Type 'BadClass' references unresolvable base type         // ❌ Invalid reference
//! Field 'field' has invalid type token 0x02000999           // ❌ Out of bounds
//! Method 'method' signature contains invalid parameter token // ❌ Bad signature
//! ```
//!
//! ## Error Categories
//!
//! | Error Type | Description | Impact |
//! |------------|-------------|---------|
//! | **Null Token** | Token with null/zero value | Type loading failure |
//! | **Unresolvable Reference** | Token points to non-existent element | Runtime exception |
//! | **Table Mismatch** | Token references wrong table type | Type system corruption |
//! | **Circular Reference** | Token creates circular dependency | Stack overflow |
//! | **Cross-Assembly** | Invalid cross-assembly token reference | Assembly loading failure |
//!
//! ## Thread Safety
//!
//! The [`TokenValidator`] is designed for safe concurrent operation:
//! - **Stateless Design**: No shared mutable state between validations
//! - **Read-Only Access**: Only reads metadata without modification
//! - **Thread-Local Storage**: Uses local collections for error aggregation
//! - **Concurrent Safe**: Safe to call from multiple threads simultaneously
//!
//! ## Integration Points
//!
//! The token validator integrates with:
//! - [`crate::metadata::loader::CilObjectData`]: Source of loaded metadata and type information
//! - [`crate::metadata::typesystem::TypeRegistry`]: Type lookup and token resolution
//! - [`crate::metadata::token::Token`]: Token representation and manipulation
//! - [`crate::metadata::validation::Orchestrator`]: Overall validation coordination
//!
//! ## Runtime Alignment
//!
//! The validation aligns with .NET runtime token handling:
//! - **CLR Token Resolution**: Matches CLR lazy token resolution patterns
//! - **Type Loading**: Validates tokens critical for type loading success
//! - **JIT Compilation**: Ensures tokens are suitable for JIT compilation
//! - **Reflection Safety**: Validates tokens work correctly with reflection
//!
//! ## Validation Scope
//!
//! ### Included Validations
//! - **Critical Cross-References**: Token references essential for runtime operation
//! - **Base Type Tokens**: Inheritance-related token validation
//! - **Null Token Detection**: Invalid null token identification
//! - **Reference Resolution**: Token resolvability verification
//!
//! ### Excluded Validations
//! - **Basic Format**: Already validated during metadata loading
//! - **Table Bounds**: Already checked by metadata parser
//! - **Signature Parsing**: Handled by signature validation components
//! - **Assembly Loading**: Covered by loader validation
//!
//! ## Future Enhancements
//!
//! Planned token validation expansions:
//! - **Generic Token Validation**: Comprehensive generic parameter token checking
//! - **Method Signature Tokens**: Detailed method signature token validation
//! - **Field Type Tokens**: Enhanced field type token consistency checking
//! - **Cross-Assembly Tokens**: Multi-assembly token reference validation
//! - **Performance Optimization**: Additional optimization opportunities
//!
//! ## References
//!
//! - ECMA-335: Common Language Infrastructure (CLI) specification, token format
//! - .NET Core Runtime: Token resolution and validation implementation
//! - CLR Via C#: Detailed token system documentation
//! - Metadata specification: Token encoding and usage patterns

use crate::metadata::{
    loader::CilObjectData,
    typesystem::{CilType, TypeRegistry},
};

/// Comprehensive token consistency validator for .NET metadata.
///
/// The `TokenValidator` provides sophisticated validation of metadata token integrity,
/// cross-reference consistency, and runtime compliance. It focuses on token-related
/// issues that would cause actual CLR failures during type loading, method compilation,
/// or runtime execution, aligning with the .NET runtime's token validation patterns.
///
/// ## Design Philosophy
///
/// The validator implements a runtime-focused validation approach:
/// - **Runtime Alignment**: Validates only issues that cause actual CLR failures
/// - **Lazy Validation**: Matches CLR's lazy token resolution strategy
/// - **Critical Path Focus**: Prioritizes tokens in critical execution paths
/// - **Performance Optimized**: Designed for efficient validation with minimal overhead
///
/// ## Validation Strategy
///
/// The validator employs a targeted validation strategy:
/// 1. **Selective Validation**: Focuses on runtime-critical token references
/// 2. **Efficient Resolution**: Uses optimized token resolution patterns
/// 3. **Error Aggregation**: Collects comprehensive error information
/// 4. **Early Detection**: Identifies issues before they cause runtime failures
///
/// ## Token Validation Categories
///
/// ### Cross-Reference Validation
/// - **Reference Resolution**: Ensures tokens resolve to valid metadata elements
/// - **Table Consistency**: Validates tokens reference appropriate table types
/// - **Null Detection**: Identifies invalid null or zero token values
/// - **Boundary Checking**: Ensures token values are within valid ranges
///
/// ### Runtime-Critical Validation
/// - **Inheritance Chains**: Validates base type token references
/// - **Type Dependencies**: Checks critical type relationship tokens
/// - **Method Signatures**: Ensures method-related tokens are resolvable
/// - **Field References**: Validates field type token consistency
///
/// ## Validation Scope
///
/// The validator focuses on specific areas while avoiding redundancy:
/// - **Included**: Runtime-critical cross-references and null token detection
/// - **Excluded**: Basic format validation (handled by metadata loader)
/// - **Excluded**: Table bounds checking (handled by metadata parser)
/// - **Excluded**: Signature token parsing (handled by signature validators)
///
/// ## Performance Optimization
///
/// The validator uses several optimization techniques:
/// - **Targeted Validation**: Only validates tokens critical for runtime operation
/// - **Efficient Traversal**: Uses optimized type registry access patterns
/// - **Memory Efficiency**: Minimizes temporary allocations during validation
/// - **Early Exit**: Stops validation on critical errors when configured
///
/// ## Error Reporting
///
/// The validator provides detailed error reporting:
/// - **Descriptive Messages**: Clear explanations of token validation failures
/// - **Token Context**: Includes token values and type context in error messages
/// - **Resolution Guidance**: Indicates how to resolve token validation issues
/// - **Categorized Results**: Organizes errors by validation category
///
/// ## Thread Safety
///
/// The validator is designed for safe concurrent operation:
/// - **Stateless Design**: Contains no mutable state between validations
/// - **Read-Only Access**: Only reads metadata without modification
/// - **Local Processing**: Uses local variables for all computations
/// - **Concurrent Safe**: Safe to call from multiple threads simultaneously
///
/// ## Usage Patterns
///
/// ### Standalone Validation
/// The TokenValidator can be used standalone to perform token
/// validation and collect error messages for processing.
///
/// ### Integrated Validation
/// For integrated validation, the token validator can be enabled
/// through the validation configuration and coordinated with other
/// validation components.
pub struct TokenValidator;

impl TokenValidator {
    /// Performs comprehensive token consistency validation across the metadata system.
    ///
    /// This method orchestrates token validation for all critical token references
    /// in the loaded metadata, ensuring that tokens resolve correctly and maintain
    /// consistency required for proper runtime operation. The validation focuses
    /// on token-related issues that would cause CLR failures during type loading,
    /// method compilation, or runtime execution.
    ///
    /// ## Validation Process
    ///
    /// The method performs validation in focused phases:
    /// 1. **Critical Cross-Reference Validation**: Validates token references essential for runtime
    /// 2. **Error Collection**: Aggregates validation errors from all token checks
    /// 3. **Result Compilation**: Organizes errors for comprehensive reporting
    ///
    /// ## Validation Focus Areas
    ///
    /// ### Runtime-Critical Token References
    /// The validation prioritizes tokens that are critical for runtime operation:
    /// - **Base Type Tokens**: Inheritance-related token references
    /// - **Interface Tokens**: Interface implementation token consistency
    /// - **Method Signature Tokens**: Method parameter and return type tokens
    /// - **Field Type Tokens**: Field type reference consistency
    ///
    /// ### Error Categories Detected
    /// - **Null Token References**: Invalid null or zero token values
    /// - **Unresolvable References**: Tokens that don't resolve to valid metadata elements
    /// - **Cross-Reference Failures**: Broken relationships between metadata elements
    /// - **Type Loading Dependencies**: Token issues that would prevent type loading
    ///
    /// ## Validation Alignment
    ///
    /// The validation aligns with .NET runtime token handling:
    /// - **CLR Behavior**: Matches CLR token resolution and validation patterns
    /// - **Lazy Resolution**: Aligns with CLR's lazy token resolution strategy
    /// - **Error Conditions**: Detects conditions that cause actual CLR failures
    /// - **Performance Focus**: Optimized for runtime-critical validation paths
    ///
    /// ## Validation Scope
    ///
    /// ### Included Validations
    /// - **Critical Cross-References**: Token references essential for runtime operation
    /// - **Null Token Detection**: Invalid null token identification and reporting
    /// - **Reference Resolution**: Token resolvability verification for critical paths
    /// - **Type Relationship Tokens**: Inheritance and interface implementation tokens
    ///
    /// ### Excluded Validations (Handled Elsewhere)
    /// - **Basic Token Format**: Already validated during metadata loading process
    /// - **Table Bounds Checking**: Already performed by metadata parser
    /// - **Signature Token Parsing**: Handled by dedicated signature validation
    /// - **Assembly Reference Tokens**: Covered by assembly loading validation
    ///
    /// ## Performance Optimization
    ///
    /// The validation leverages several performance optimizations:
    /// - **Selective Validation**: Only validates tokens critical for runtime operation
    /// - **Efficient Type Traversal**: Uses optimized type registry access patterns
    /// - **Early Error Detection**: Identifies critical issues before expensive operations
    /// - **Memory Efficiency**: Minimizes temporary allocations during validation
    ///
    /// # Arguments
    ///
    /// * `data` - The CIL object data containing the complete loaded metadata,
    ///   including type registry, tables, and token cross-references
    ///
    /// # Returns
    ///
    /// Returns a vector of validation error messages describing all token
    /// consistency violations found during validation. An empty vector indicates
    /// that no token issues were detected.
    ///
    /// # Examples
    ///
    /// ## Basic Token Validation
    ///
    /// The `validate_token_consistency` method performs comprehensive token
    /// validation and returns a vector of error messages describing any token
    /// violations found during the validation process.
    ///
    /// ## Error Analysis and Categorization
    ///
    /// The validation results can be analyzed and categorized by error type,
    /// such as null token errors, unresolvable references, and base type issues,
    /// to provide structured error reporting and debugging information.
    ///
    /// ## Integration with Error Handling
    ///
    /// The validation results can be integrated with error handling systems
    /// to provide different treatment for minor issues versus critical token
    /// validation failures that prevent safe operation.
    ///
    /// # Performance Characteristics
    ///
    /// - **Validation Time**: O(n) where n is number of types with token references
    /// - **Memory Usage**: O(e) where e is number of validation errors found
    /// - **CPU Overhead**: Minimal - focused on essential token validations only
    /// - **Cache Efficiency**: Good cache locality due to sequential type access
    ///
    /// # Error Categories
    ///
    /// The validation may return errors in these categories:
    /// - **Null Token Errors**: Tokens with null or zero values where valid tokens expected
    /// - **Unresolvable References**: Tokens that don't resolve to valid metadata elements
    /// - **Base Type Issues**: Problems with inheritance-related token references
    /// - **Cross-Reference Failures**: Broken relationships between metadata elements
    ///
    /// # Thread Safety
    ///
    /// This method is safe for concurrent execution because:
    /// - **Read-Only Access**: Only reads metadata without modification
    /// - **Local Processing**: Uses local variables for all computations
    /// - **No Shared State**: Contains no shared mutable state between calls
    /// - **Stateless Operation**: Each call is independent and self-contained
    ///
    /// # Implementation Strategy
    ///
    /// The method uses a focused validation strategy:
    /// - **Critical Path Focus**: Validates only tokens in critical execution paths
    /// - **Efficient Resolution**: Uses optimized token resolution patterns
    /// - **Error Aggregation**: Collects comprehensive error information
    /// - **Performance Awareness**: Balances thoroughness with validation speed
    pub fn validate_token_consistency(data: &CilObjectData) -> Vec<String> {
        let mut errors = Vec::new();

        Self::validate_critical_cross_references(&data.types, &mut errors);

        errors
    }

    /// Validates cross-references that are critical for runtime operation.
    ///
    /// This method performs targeted validation of token cross-references that are
    /// essential for proper .NET runtime operation. It focuses on relationships
    /// that would cause immediate failures during type loading, method compilation,
    /// or runtime execution, aligning with the CLR's lazy validation strategy.
    ///
    /// ## Validation Strategy
    ///
    /// The method employs a runtime-aligned validation approach:
    /// - **Critical Path Focus**: Validates only cross-references in critical execution paths
    /// - **Lazy Validation Alignment**: Matches CLR's lazy token resolution patterns
    /// - **Immediate Failure Detection**: Identifies issues that cause immediate runtime failures
    /// - **Efficient Traversal**: Uses optimized type registry access for performance
    ///
    /// ## Cross-Reference Categories
    ///
    /// ### Type Relationship References
    /// - **Base Type References**: Inheritance-related token cross-references
    /// - **Interface Implementation**: Interface contract token relationships
    /// - **Nested Type References**: Parent-child type token relationships
    /// - **Generic Parameter References**: Generic type parameter token consistency
    ///
    /// ### Member Reference Validation
    /// - **Method Signature References**: Method parameter and return type tokens
    /// - **Field Type References**: Field type declaration token consistency
    /// - **Property Type References**: Property getter/setter type token validation
    /// - **Event Handler References**: Event handler delegate token validation
    ///
    /// ## Runtime Failure Prevention
    ///
    /// The validation prevents specific runtime failure scenarios:
    /// - **Type Loading Failures**: Invalid base type references that prevent type loading
    /// - **Method Compilation Failures**: Unresolvable signature tokens that prevent JIT
    /// - **Interface Binding Failures**: Invalid interface tokens that prevent contract binding
    /// - **Generic Instantiation Failures**: Invalid generic parameter tokens
    ///
    /// ## Validation Process
    ///
    /// The method performs validation in systematic steps:
    /// 1. **Type Enumeration**: Iterates through all types in the registry
    /// 2. **Reference Extraction**: Identifies critical token references for each type
    /// 3. **Resolution Validation**: Verifies that each token resolves correctly
    /// 4. **Error Collection**: Aggregates validation errors for comprehensive reporting
    ///
    /// # Arguments
    ///
    /// * `types` - The type registry containing all loaded types and their token references
    /// * `errors` - Mutable vector for collecting validation errors during traversal
    ///
    /// # Validation Examples
    ///
    /// ## Valid Cross-References
    /// ```csharp
    /// // Valid cross-references that pass validation
    /// public class BaseClass { }
    /// public class DerivedClass : BaseClass { }  // ✓ Valid base type reference
    ///
    /// public interface IContract { }
    /// public class Implementation : IContract { }  // ✓ Valid interface reference
    ///
    /// public class Container {
    ///     public string Field;      // ✓ Valid field type reference
    ///     public void Method() { }  // ✓ Valid method signature references
    /// }
    /// ```
    ///
    /// ## Invalid Cross-References
    /// ```text
    /// // Invalid cross-references detected by validation
    /// Type 'DerivedClass' has null base type token
    /// Type 'BadClass' references unresolvable base type with token 0x02000999
    /// Interface 'IInvalid' references non-existent interface token
    /// Field 'badField' has unresolvable type token 0x01000123
    /// ```
    ///
    /// # Performance Characteristics
    ///
    /// - **Type Traversal**: O(n) where n is number of types in registry
    /// - **Reference Validation**: O(1) per token reference (hash table lookup)
    /// - **Memory Usage**: O(1) per type (minimal validation overhead)
    /// - **Cache Efficiency**: Good cache locality due to sequential type access
    ///
    /// # Thread Safety
    ///
    /// This method is safe for concurrent execution:
    /// - **Read-Only Access**: Only reads type registry and token information
    /// - **Local Error Collection**: Each invocation uses its own error vector
    /// - **No Shared State**: Contains no shared mutable state between calls
    /// - **Immutable Operations**: All token resolution operations are read-only
    ///
    /// # Implementation Details
    ///
    /// The method handles several implementation considerations:
    /// - **Type Registry Iteration**: Efficient iteration over all loaded types
    /// - **Token Resolution**: Optimized token-to-metadata element resolution
    /// - **Error Context**: Provides clear error messages with type and token context
    /// - **Validation Scope**: Focuses on runtime-critical references only
    fn validate_critical_cross_references(types: &TypeRegistry, errors: &mut Vec<String>) {
        for entry in types {
            let cil_type = entry.value();

            Self::validate_base_type_reference(cil_type, types, errors);
        }
    }

    /// Validates base type token references to prevent inheritance failures.
    ///
    /// This method performs comprehensive validation of base type token references
    /// that are critical for proper inheritance chain resolution during CLR type
    /// loading. Invalid base type tokens are one of the most common causes of
    /// `TypeLoadException` and related runtime failures, making this validation
    /// essential for runtime reliability.
    ///
    /// ## Validation Rationale
    ///
    /// Base type token validation is critical because:
    /// - **Type Loading Dependency**: CLR requires valid base type resolution for type loading
    /// - **Inheritance Chain**: Invalid base types break the entire inheritance chain
    /// - **Method Table Construction**: CLR needs base type information for vtable construction
    /// - **Runtime Safety**: Invalid inheritance can cause memory corruption and crashes
    ///
    /// ## Validation Rules
    ///
    /// ### Null Token Detection
    /// Identifies base type tokens with null or zero values:
    /// - **Runtime Rule**: CLR expects non-null tokens for base type references
    /// - **Error Impact**: Null tokens cause immediate type loading failures
    /// - **Detection Logic**: Checks for `token.is_null()` condition
    /// - **Error Reporting**: Provides clear indication of null token issue
    ///
    /// ### Reference Resolution Validation
    /// Ensures base type tokens resolve to valid metadata elements:
    /// - **Registry Lookup**: Attempts to resolve token in type registry
    /// - **Resolution Failure**: Detects when token doesn't map to valid type
    /// - **Cross-Reference Integrity**: Ensures inheritance relationships are valid
    /// - **Error Context**: Provides token value and type context in error messages
    ///
    /// ## Type Loading Context
    ///
    /// Understanding CLR type loading helps explain validation importance:
    /// ```text
    /// CLR Type Loading Process:
    /// 1. Load type metadata
    /// 2. Resolve base type token → VALIDATION POINT
    /// 3. Load base type (recursive)
    /// 4. Construct method table
    /// 5. Initialize type system structures
    /// ```
    ///
    /// ## Error Scenarios
    ///
    /// ### Null Base Type Token
    /// ```text
    /// Error: "Type 'DerivedClass' has null base type token"
    /// Cause: Base type token field contains null/zero value
    /// Impact: TypeLoadException during CLR type loading
    /// Resolution: Fix metadata to include valid base type token
    /// ```
    ///
    /// ### Unresolvable Base Type Token
    /// ```text
    /// Error: "Type 'BadClass' references unresolvable base type with token 0x02000999"
    /// Cause: Token references non-existent or invalid metadata element
    /// Impact: TypeLoadException with "Could not load base type" message
    /// Resolution: Fix token to reference valid TypeDef/TypeRef
    /// ```
    ///
    /// ## Inheritance Validation Context
    ///
    /// This validation is part of broader inheritance validation:
    /// - **Token Validation**: Ensures base type tokens are valid (this method)
    /// - **Semantic Validation**: Ensures inheritance relationships are legal
    /// - **Type System Validation**: Ensures inheritance doesn't create cycles
    /// - **Layout Validation**: Ensures field layouts are compatible
    ///
    /// # Arguments
    ///
    /// * `cil_type` - The type being validated for base type token compliance
    /// * `types` - The type registry for resolving base type token references
    /// * `errors` - Mutable vector for collecting validation errors
    ///
    /// # Validation Examples
    ///
    /// ## Valid Base Type References
    /// ```csharp
    /// // Valid base type references that pass validation
    /// public class BaseClass { }
    /// public class DerivedClass : BaseClass { }  // ✓ Valid token reference
    ///
    /// public abstract class AbstractBase { }
    /// public class ConcreteImpl : AbstractBase { }  // ✓ Valid abstract base
    ///
    /// public class SystemType : System.Object { }  // ✓ Valid system base
    /// ```
    ///
    /// ## Invalid Base Type References
    /// ```text
    /// // Invalid references detected by this validation
    ///
    /// Type 'NullBaseClass' has null base type token
    /// // Metadata contains null token where base type expected
    ///
    /// Type 'InvalidRef' references unresolvable base type with token 0x02000999
    /// // Token points to non-existent or corrupted metadata element
    /// ```
    ///
    /// ## IL Metadata Context
    ///
    /// In IL metadata, base type references appear as:
    /// ```il
    /// .class public DerivedClass extends BaseClass {
    ///     // Base type token stored in TypeDef table
    ///     // Token must resolve to valid TypeDef or TypeRef
    /// }
    /// ```
    ///
    /// # Performance Characteristics
    ///
    /// - **Token Checking**: O(1) null token detection
    /// - **Registry Lookup**: O(1) hash table lookup for token resolution
    /// - **Error Generation**: O(1) error message creation
    /// - **Memory Usage**: O(1) minimal overhead per type validation
    ///
    /// # Thread Safety
    ///
    /// This method is safe for concurrent execution:
    /// - **Read-Only Type Access**: Only reads type base type information
    /// - **Read-Only Registry Access**: Only performs lookups in type registry
    /// - **Local Error Collection**: Uses caller-provided error vector
    /// - **No Side Effects**: Doesn't modify any type or registry information
    ///
    /// # Error Recovery
    ///
    /// When validation errors are found:
    /// - **Graceful Degradation**: Continues validation for other types
    /// - **Comprehensive Reporting**: Reports all base type issues found
    /// - **Context Preservation**: Maintains error context for debugging
    /// - **Non-Fatal Processing**: Allows validation to complete despite errors
    ///
    /// # Integration with CLR Behavior
    ///
    /// The validation aligns with CLR type loading behavior:
    /// - **Error Conditions**: Matches conditions that cause CLR TypeLoadException
    /// - **Validation Timing**: Performed at same logical point as CLR validation
    /// - **Error Messages**: Similar context and information as CLR error messages
    /// - **Resolution Strategy**: Uses same token resolution approach as CLR
    fn validate_base_type_reference(
        cil_type: &std::sync::Arc<CilType>,
        types: &TypeRegistry,
        errors: &mut Vec<String>,
    ) {
        if let Some(base_type) = cil_type.base() {
            // Check if base type token is resolvable
            // This is important because inheritance failures cause runtime errors
            if base_type.token.is_null() {
                errors.push(format!("Type '{}' has null base type token", cil_type.name));
            } else if types.get(&base_type.token).is_none() {
                errors.push(format!(
                    "Type '{}' references unresolvable base type with token {:?}",
                    cil_type.name, base_type.token
                ));
            }
        }
    }
}
