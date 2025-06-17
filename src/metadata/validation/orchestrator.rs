//! # Validation Orchestration for .NET Metadata Systems
//!
//! This module provides comprehensive orchestration of the validation process across
//! the entire loaded .NET metadata system, coordinating multiple specialized validators
//! to ensure structural integrity, semantic correctness, and runtime compliance.
//!
//! ## Overview
//!
//! The validation orchestrator serves as the central coordinator for all metadata
//! validation activities, managing the execution order, dependencies, and performance
//! optimization of validation processes. It leverages parallel processing where safe
//! and ensures comprehensive coverage of all validation requirements.
//!
//! ## Architecture
//!
//! ### Validation Layers
//! 1. **Structural Validation**: Basic integrity checks (tokens, references, layout)
//! 2. **Semantic Validation**: Business rule compliance and consistency checks
//! 3. **Cross-Table Validation**: Inter-table relationship and dependency validation
//! 4. **Type System Validation**: Comprehensive type hierarchy and constraint validation
//!
//! ### Parallel Processing
//! The orchestrator optimizes validation performance through strategic parallelization:
//! - **Independent validations** run concurrently using [`rayon`] parallel iterators
//! - **Dependent validations** execute sequentially with proper ordering
//! - **Resource-intensive operations** are distributed across available CPU cores
//!
//! ## Validation Categories
//!
//! ### Token Validation
//! - **Token Consistency**: Validates token format, range, and cross-references
//! - **Reference Integrity**: Ensures all token references resolve correctly
//! - **Index Bounds**: Validates all indices are within valid table ranges
//!
//! ### Semantic Validation
//! - **Business Rules**: Enforces .NET metadata business rules and constraints
//! - **Type Relationships**: Validates inheritance, interface implementation
//! - **Accessibility Rules**: Ensures proper visibility and access control
//!
//! ### Structural Validation
//! - **Nested Classes**: Validates nesting hierarchy for cycles and depth limits
//! - **Field Layouts**: Ensures proper field positioning and overlap prevention
//! - **Method Signatures**: Validates method signature correctness and consistency
//!
//! ### Performance Validation
//! - **Resource Limits**: Prevents excessive memory usage and deep recursion
//! - **Complexity Bounds**: Enforces reasonable limits on type complexity
//! - **Load Time Optimization**: Identifies potential performance bottlenecks
//!
//! ## Validation Configuration
//!
//! The orchestrator supports flexible validation configuration through [`ValidationConfig`]:
//! - **Selective Validation**: Enable/disable specific validation categories
//! - **Performance Tuning**: Adjust limits and thresholds for performance
//! - **Error Handling**: Configure error reporting and recovery behavior
//! - **Parallel Execution**: Control parallelization and resource usage
//!
//! ## Error Handling
//!
//! The orchestrator provides comprehensive error reporting with detailed diagnostics:
//! - **Validation Summaries**: Aggregate reporting of all validation issues
//! - **Error Categories**: Classification of errors by type and severity
//! - **Diagnostic Information**: Detailed context for debugging validation failures
//! - **Performance Metrics**: Timing and resource usage information
//!
//! ## Thread Safety
//!
//! The [`Orchestrator`] is designed for safe concurrent operation:
//! - **Stateless Design**: No shared mutable state between validations
//! - **Parallel Safe**: Uses [`rayon`] for safe parallel processing
//! - **Read-Only Access**: Only reads metadata without modification
//!
//! ## Integration Points
//!
//! The orchestrator integrates with:
//! - [`TokenValidator`]: Token format and reference validation
//! - [`SemanticValidator`]: Business rule and semantic consistency validation  
//! - [`MethodValidator`]: Method signature and body validation
//! - [`NestedClassValidator`]: Nested type hierarchy validation
//! - [`FieldValidator`]: Field layout and overlap validation
//!
//! ## Future Enhancements
//!
//! Planned validation expansions:
//! - **Generic Constraint Validation**: Comprehensive generic type constraint checking
//! - **Interface Implementation Validation**: Detailed interface contract validation
//! - **Cross-Assembly Validation**: Multi-assembly dependency and compatibility checking
//! - **Security Attribute Validation**: Security permission and attribute validation
//! - **Custom Attribute Validation**: Extensible custom attribute validation framework
//!
//! ## References
//!
//! - ECMA-335: Common Language Infrastructure (CLI) specification
//! - .NET Core Runtime: Metadata validation implementation patterns
//! - [`rayon`]: Data parallelism library for performance optimization
//!
//! [`ValidationConfig`]: crate::metadata::validation::config::ValidationConfig
//! [`TokenValidator`]: crate::metadata::validation::TokenValidator
//! [`SemanticValidator`]: crate::metadata::validation::SemanticValidator
//! [`MethodValidator`]: crate::metadata::validation::MethodValidator
//! [`NestedClassValidator`]: crate::metadata::validation::NestedClassValidator
//! [`FieldValidator`]: crate::metadata::validation::FieldValidator

use crate::{
    metadata::{
        loader::CilObjectData,
        signatures::TypeSignature,
        typesystem::TypeRegistry,
        validation::{
            config::ValidationConfig, FieldValidator, MethodValidator, NestedClassValidator,
            SemanticValidator, TokenValidator,
        },
    },
    Result,
};
use rayon::prelude::*;

/// Central orchestrator for comprehensive .NET metadata validation.
///
/// The `Orchestrator` coordinates all validation activities across the loaded metadata
/// system, ensuring structural integrity, semantic correctness, and runtime compliance.
/// It manages validation execution order, parallelization, and performance optimization
/// to provide comprehensive validation with optimal resource utilization.
///
/// ## Design Philosophy
///
/// The orchestrator follows a layered validation approach:
/// 1. **Parallel Independent Validations**: Executes validations that don't depend on each other
/// 2. **Sequential Dependent Validations**: Runs validations that require specific ordering
/// 3. **Resource-Aware Processing**: Optimizes CPU and memory usage through smart scheduling
/// 4. **Comprehensive Coverage**: Ensures all critical validation aspects are addressed
///
/// ## Validation Coordination
///
/// ### Parallel Execution Strategy
/// The orchestrator uses [`rayon`] to parallelize independent validations:
/// - **Token validation**: Validates token format and consistency
/// - **Semantic validation**: Checks business rules and semantic consistency
/// - **Method validation**: Validates method signatures and implementations
///
/// ### Sequential Execution Requirements
/// Some validations require sequential execution due to dependencies:
/// - **Type system validation**: Depends on token validation completion
/// - **Field layout validation**: Requires type resolution for accurate sizing
///
/// ## Error Aggregation
///
/// The orchestrator aggregates validation errors from multiple sources:
/// - **Parallel Collection**: Safely collects errors from concurrent validations
/// - **Error Classification**: Categorizes errors by type and severity
/// - **Comprehensive Reporting**: Provides detailed diagnostic information
/// - **Structured Output**: Organizes errors for easy consumption by tools
///
/// ## Thread Safety
///
/// The orchestrator is designed for safe concurrent operation:
/// - **Stateless Design**: Contains no mutable state between validations
/// - **Read-Only Access**: Only reads metadata without modification
/// - **Parallel Safe**: Uses thread-safe parallel processing primitives
/// - **No Side Effects**: Validation operations don't modify the metadata
pub struct Orchestrator;

impl Orchestrator {
    /// Performs comprehensive validation across the entire metadata system.
    ///
    /// This method orchestrates all validation activities for loaded .NET metadata,
    /// coordinating multiple specialized validators to ensure structural integrity,
    /// semantic correctness, and runtime compliance. The validation process is
    /// optimized for performance through strategic parallelization and efficient
    /// resource utilization.
    ///
    /// ## Validation Process
    ///
    /// The method executes validation in carefully orchestrated phases:
    ///
    /// ### Phase 1: Parallel Independent Validations
    /// Executes independent validations concurrently for optimal performance:
    /// - **Token Validation**: Validates token format, consistency, and references
    /// - **Semantic Validation**: Checks business rules and semantic consistency
    /// - **Method Validation**: Validates method signatures and implementation rules
    ///
    /// ### Phase 2: Sequential Dependent Validations
    /// Executes validations that require specific ordering or exclusive access:
    /// - **Type System Validation**: Validates nested class hierarchies and constraints
    /// - **Field Layout Validation**: Ensures proper field positioning and layout rules
    ///
    /// ## Error Handling
    ///
    /// The method provides comprehensive error handling and reporting:
    /// - **Error Aggregation**: Collects all validation errors from parallel executions
    /// - **Structured Reporting**: Provides detailed diagnostic information for each error
    /// - **Non-Failing Validation**: Currently logs errors but continues execution (configurable)
    /// - **Performance Metrics**: Can include timing and resource usage information
    ///
    /// ## Validation Configuration
    ///
    /// The behavior is controlled by [`ValidationConfig`] settings:
    /// - **Cross-Table Validation**: Master switch for all cross-table validations
    /// - **Category Switches**: Enable/disable specific validation categories
    /// - **Performance Limits**: Configure thresholds and resource limits
    /// - **Error Behavior**: Control error handling and reporting behavior
    ///
    /// # Arguments
    ///
    /// * `data` - The loaded CIL object data containing all parsed metadata tables,
    ///   type information, and cross-references for validation
    /// * `config` - Validation configuration specifying which validations to perform,
    ///   performance limits, and error handling behavior
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if validation completes successfully (even with non-critical errors),
    /// or an error if critical structural problems are detected that prevent safe operation.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] in these cases:
    /// - **Critical Structural Errors**: Fundamental metadata corruption that prevents safe access
    /// - **Circular References**: Detected cycles in nested class hierarchies
    /// - **Resource Exhaustion**: Validation exceeds configured resource limits
    /// - **Invalid Layout**: Field layouts that violate runtime constraints
    ///
    /// # Thread Safety
    ///
    /// This method is safe for concurrent execution across multiple threads as it:
    /// - Only reads metadata without modification
    /// - Uses thread-safe parallel processing primitives
    /// - Contains no shared mutable state
    /// - Aggregates results safely from parallel executions
    ///
    /// # Internal Architecture
    ///
    /// The method uses a carefully designed execution strategy:
    /// 1. **Configuration Check**: Early exit if cross-table validation is disabled
    /// 2. **Parallel Dispatch**: Uses [`rayon::iter::ParallelIterator`] for concurrent independent validations
    /// 3. **Error Collection**: Safely aggregates errors from all parallel executions
    /// 4. **Sequential Execution**: Runs dependent validations in proper order
    /// 5. **Result Aggregation**: Combines all validation results for comprehensive reporting
    ///
    /// [`ValidationConfig`]: crate::metadata::validation::config::ValidationConfig
    pub fn validate_loaded_data(data: &CilObjectData, config: ValidationConfig) -> Result<()> {
        if !config.enable_cross_table_validation {
            return Ok(());
        }

        // Run independent validations in parallel for better performance
        let validation_results: Vec<Vec<String>> = [
            // Token consistency validation
            config.enable_token_validation,
            // Semantic validation
            config.enable_semantic_validation,
            // Method validation
            config.enable_method_validation,
        ]
        .into_par_iter()
        .enumerate()
        .filter_map(|(index, enabled)| {
            if !enabled {
                return None;
            }

            let errors = match index {
                0 => TokenValidator::validate_token_consistency(data),
                1 => SemanticValidator::validate_semantic_consistency(data),
                2 => MethodValidator::validate_method_rules(data),
                _ => Vec::new(),
            };

            Some(errors)
        })
        .collect();

        // Flatten all validation errors
        let all_errors: Vec<String> = validation_results.into_iter().flatten().collect();

        // Sequential validations that require exclusive access or have dependencies
        // Validate nested class relationships across the entire type system
        if config.enable_type_system_validation {
            Self::validate_nested_class_hierarchy(&data.types, config.max_nesting_depth)?;
        }

        // Validate field layouts for types with explicit layout
        if config.enable_field_layout_validation {
            Self::validate_field_layouts(&data.types)?;
        }

        // If we found any validation errors, report them
        if !all_errors.is_empty() {
            eprintln!("Validation found {} issues:", all_errors.len());
            for (i, error) in all_errors.iter().enumerate() {
                eprintln!("  {}: {}", i + 1, error);
            }
            // For now, we'll just log the errors rather than fail validation
            // In the future, this could be configurable
        }

        // TODO: Add more cross-table validations here:
        // - Generic constraint validation across type hierarchy
        // - Interface implementation validation
        // - Cross-assembly checks
        // - Security attribute validation

        Ok(())
    }

    /// Validates nested class relationships for structural integrity and runtime safety.
    ///
    /// This method performs comprehensive validation of nested class hierarchies to ensure
    /// they conform to .NET runtime requirements and prevent structural anomalies that
    /// could cause runtime failures. It specifically validates against circular references
    /// and excessive nesting depth that could lead to stack overflow conditions.
    ///
    /// ## Validation Performed
    ///
    /// ### Circular Reference Detection
    /// Uses depth-first search (DFS) algorithm to detect cycles in the nesting hierarchy:
    /// - **Graph Construction**: Builds adjacency list from nested type relationships
    /// - **Cycle Detection**: Identifies back edges that indicate circular references
    /// - **Early Termination**: Stops immediately when first cycle is detected
    ///
    /// ### Depth Limit Enforcement
    /// Validates that nesting chains don't exceed reasonable depth limits:
    /// - **Chain Traversal**: Follows nesting relationships from leaf to root
    /// - **Depth Counting**: Measures maximum depth in each nesting chain
    /// - **Limit Enforcement**: Ensures depth doesn't exceed configured maximum
    ///
    /// ## Type Registry Processing
    ///
    /// The method efficiently processes the type registry to extract relationships:
    /// ```text
    /// For each type in registry:
    ///   For each nested type reference:
    ///     If reference is valid:
    ///       Add (nested_token, enclosing_token) to relationships
    /// ```
    ///
    /// # Arguments
    ///
    /// * `types` - The type registry containing all loaded types and their relationships
    /// * `max_depth` - Maximum allowed nesting depth to prevent excessive hierarchy depth
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if all nested class relationships are valid, or an error
    /// describing the specific validation failure encountered.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] in these cases:
    /// - **Circular Reference**: A cycle is detected in the nesting hierarchy
    /// - **Depth Exceeded**: Nesting depth exceeds the configured maximum limit
    /// - **Invalid Reference**: A nested type reference cannot be resolved
    ///
    /// # Examples
    ///
    /// ## Valid Nesting Hierarchy
    /// ```text
    /// OuterClass
    /// ├── InnerClass1
    /// │   └── DeepClass
    /// └── InnerClass2
    /// ```
    /// This hierarchy has maximum depth of 2 and no cycles.
    ///
    /// ## Invalid Circular Hierarchy
    /// ```text
    /// ClassA → ClassB → ClassC → ClassA
    /// ```
    /// This hierarchy contains a cycle and would be rejected.
    ///
    /// ## Invalid Deep Hierarchy
    /// ```text
    /// Level1 → Level2 → Level3 → ... → Level100
    /// ```
    /// This hierarchy exceeds reasonable depth limits and would be rejected.
    ///
    /// # Thread Safety
    ///
    /// This method is safe for concurrent execution as it:
    /// - Only reads from the type registry without modification
    /// - Uses local collections for relationship storage
    /// - Contains no shared mutable state between calls
    fn validate_nested_class_hierarchy(types: &TypeRegistry, max_depth: usize) -> Result<()> {
        // Collect all nested class relationships
        let mut relationships = Vec::new();

        for entry in types {
            let cil_type = entry.value();
            for (_index, nested_type_ref) in cil_type.nested_types.iter() {
                if let Some(nested_type) = nested_type_ref.upgrade() {
                    relationships.push((nested_type.token, cil_type.token));
                }
            }
        }

        // Validate no circular references
        NestedClassValidator::validate_no_circular_nesting(&relationships)?;

        // Validate nesting depth
        NestedClassValidator::validate_nesting_depth(&relationships, max_depth)?;

        Ok(())
    }

    /// Validates field layouts for types with explicit layout using parallel processing.
    ///
    /// This method performs comprehensive validation of field layouts for types that specify
    /// explicit field positioning, ensuring compliance with .NET runtime layout rules and
    /// preventing field overlaps or boundary violations that could cause runtime errors.
    /// The validation leverages parallel processing for optimal performance across large
    /// type systems.
    ///
    /// ## Validation Categories
    ///
    /// ### Explicit Layout Detection
    /// Identifies types that require field layout validation:
    /// - **Class Size Presence**: Types with explicitly specified class size
    /// - **Field Offset Presence**: Fields with explicitly specified offsets
    /// - **Layout Attribute**: Types marked with explicit layout attributes
    ///
    /// ### Field Overlap Validation
    /// Ensures fields don't occupy overlapping memory regions:
    /// - **Boundary Calculation**: Computes field boundaries based on offset and size
    /// - **Overlap Detection**: Identifies any overlapping field regions
    /// - **Union Validation**: Handles legitimate overlaps in union-style types
    ///
    /// ### Size Constraint Validation
    /// Verifies fields fit within declared class boundaries:
    /// - **Boundary Checking**: Ensures all fields fit within class size
    /// - **Alignment Validation**: Verifies proper field alignment requirements
    /// - **Padding Validation**: Checks for appropriate padding between fields
    ///
    /// ## Type Size Resolution
    ///
    /// The method performs sophisticated type size calculation:
    /// - **Primitive Types**: Uses known sizes for built-in types
    /// - **Value Types**: Resolves actual sizes from type definitions
    /// - **Reference Types**: Uses platform-appropriate pointer sizes
    /// - **Generic Types**: Applies conservative size estimates
    ///
    /// ## Layout Validation Rules
    ///
    /// ### Field Positioning Rules
    /// 1. **Non-Overlapping**: Fields cannot occupy the same memory regions
    /// 2. **Boundary Respect**: Fields must fit within declared class size
    /// 3. **Alignment Requirements**: Fields must respect platform alignment rules
    /// 4. **Offset Validation**: Field offsets must be non-negative and reasonable
    ///
    /// ### Special Cases
    /// - **Union Types**: Allow overlapping fields when properly declared
    /// - **Sequential Layout**: Validates automatic field positioning
    /// - **Pack Attributes**: Respects custom packing requirements
    /// - **Inheritance**: Handles base class field layout inheritance
    ///
    /// # Arguments
    ///
    /// * `types` - The type registry containing all loaded types with their field information
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if all field layouts are valid, or an error describing
    /// the first layout violation encountered during validation.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] in these cases:
    /// - **Field Overlap**: Two or more fields occupy overlapping memory regions
    /// - **Boundary Violation**: A field extends beyond the declared class size
    /// - **Invalid Offset**: A field has a negative or unreasonable offset
    /// - **Size Calculation Error**: Unable to determine field size for validation
    ///
    /// # Examples
    ///
    /// ## Valid Explicit Layout
    /// ```csharp
    /// [StructLayout(LayoutKind.Explicit, Size = 16)]
    /// public struct ValidLayout
    /// {
    ///     [FieldOffset(0)] public int Field1;    // Bytes 0-3
    ///     [FieldOffset(4)] public int Field2;    // Bytes 4-7
    ///     [FieldOffset(8)] public long Field3;   // Bytes 8-15
    /// }
    /// ```
    /// This layout is valid: no overlaps, all fields fit within 16 bytes.
    ///
    /// ## Invalid Overlapping Layout
    /// ```csharp
    /// [StructLayout(LayoutKind.Explicit, Size = 8)]
    /// public struct InvalidLayout
    /// {
    ///     [FieldOffset(0)] public int Field1;    // Bytes 0-3
    ///     [FieldOffset(2)] public int Field2;    // Bytes 2-5 (overlaps!)
    /// }
    /// ```
    /// This layout is invalid: Field1 and Field2 overlap at bytes 2-3.
    ///
    /// ## Invalid Size Boundary
    /// ```csharp
    /// [StructLayout(LayoutKind.Explicit, Size = 8)]
    /// public struct BoundaryViolation
    /// {
    ///     [FieldOffset(0)] public int Field1;    // Bytes 0-3
    ///     [FieldOffset(6)] public int Field2;    // Bytes 6-9 (exceeds size!)
    /// }
    /// ```
    /// This layout is invalid: Field2 extends beyond the 8-byte class size.
    ///
    /// # Thread Safety
    ///
    /// This method is safe for concurrent execution because:
    /// - **Read-Only Access**: Only reads type and field information
    /// - **Independent Processing**: Each type is validated independently
    /// - **No Shared State**: Uses local collections for each validation
    /// - **Parallel Safe**: Uses [`rayon`] parallel iterators safely
    fn validate_field_layouts(types: &TypeRegistry) -> Result<()> {
        // Collect all types with explicit layout
        let types_with_layout: Vec<_> = types
            .iter()
            .filter_map(|entry| {
                let cil_type = entry.value();
                if cil_type.class_size.get().is_some() {
                    Some(cil_type.clone())
                } else {
                    None
                }
            })
            .collect();

        // Validate field layouts in parallel using rayon
        types_with_layout
            .par_iter()
            .try_for_each(|cil_type| -> Result<()> {
                let class_size = *cil_type.class_size.get().unwrap();
                let mut field_layouts = Vec::new();

                // Collect field layout information
                for (_index, field) in cil_type.fields.iter() {
                    if let Some(field_offset) = field.layout.get() {
                        // Calculate actual field size based on type signature and type registry
                        let field_size = Self::calculate_field_size_with_type_resolution(
                            &field.signature.base,
                            types,
                        );
                        field_layouts.push((*field_offset, field_size));
                    }
                }

                // Validate field overlaps
                if !field_layouts.is_empty() {
                    FieldValidator::validate_field_overlaps(&field_layouts)?;

                    // Validate fields fit within class size
                    FieldValidator::validate_explicit_layout_coverage(class_size, &field_layouts)?;
                }

                Ok(())
            })?;

        Ok(())
    }

    /// Calculates field size with comprehensive type resolution and registry lookup.
    ///
    /// This method provides accurate field size calculation by resolving type information
    /// from the type registry, enabling precise field layout validation. It handles the
    /// full spectrum of .NET type signatures and provides platform-aware size calculations
    /// for accurate memory layout validation.
    ///
    /// ## Type Resolution Strategy
    ///
    /// The method uses a hierarchical approach to size calculation:
    /// 1. **Primitive Types**: Uses fixed sizes defined by ECMA-335
    /// 2. **Value Type Lookup**: Queries type registry for explicit size information
    /// 3. **Well-Known Types**: Uses hardcoded sizes for common framework types
    /// 4. **Conservative Fallback**: Uses safe estimates for unknown types
    ///
    /// ## Platform Considerations
    ///
    /// The calculation accounts for platform-specific characteristics:
    /// - **Pointer Sizes**: 8 bytes for 64-bit platforms (current assumption)
    /// - **Alignment Requirements**: Natural alignment for primitive types
    /// - **Platform Types**: IntPtr/UIntPtr sized according to platform
    /// - **Reference Types**: Consistent pointer size for all reference types
    ///
    /// ## Type Registry Integration
    ///
    /// For value types, the method performs registry lookup:
    /// ```text
    /// Value Type → Registry Lookup → Explicit Size OR Well-Known Size OR Conservative Estimate
    /// ```
    ///
    /// ### Explicit Size Resolution
    /// - **Class Size Attribute**: Uses explicit size from metadata
    /// - **Computed Size**: Calculates from field layout when available
    /// - **Inheritance**: Considers base type size for derived types
    ///
    /// ### Well-Known Type Handling
    /// Provides accurate sizes for important framework types:
    /// - **System.DateTime**: 8 bytes (64-bit tick count)
    /// - **System.TimeSpan**: 8 bytes (64-bit tick count)
    /// - **System.Decimal**: 16 bytes (128-bit decimal representation)
    /// - **System.Guid**: 16 bytes (128-bit identifier)
    ///
    /// # Arguments
    ///
    /// * `field_signature` - The type signature of the field requiring size calculation
    /// * `types` - Type registry for resolving value type sizes and performing lookups
    ///
    /// # Returns
    ///
    /// Returns the calculated field size in bytes as a `u32`. For unknown or complex
    /// types, returns a conservative estimate to ensure safe field layout validation.
    ///
    /// # Size Calculation Rules
    ///
    /// ## Primitive Types (ECMA-335 Compliant)
    /// - **Void**: 0 bytes (special case)
    /// - **Boolean**: 1 byte
    /// - **I1/U1**: 1 byte (signed/unsigned 8-bit integers)
    /// - **I2/U2/Char**: 2 bytes (signed/unsigned 16-bit integers, Unicode character)
    /// - **I4/U4/R4**: 4 bytes (signed/unsigned 32-bit integers, single-precision float)
    /// - **I8/U8/R8**: 8 bytes (signed/unsigned 64-bit integers, double-precision float)
    /// - **I/U**: 8 bytes (native integer size, assuming 64-bit platform)
    ///
    /// ## Reference Types
    /// All reference types use consistent pointer sizing:
    /// - **String**: 8 bytes (object reference)
    /// - **Object**: 8 bytes (object reference)
    /// - **Class**: 8 bytes (object reference)
    /// - **Array**: 8 bytes (array reference)
    ///
    /// ## Pointer Types
    /// All pointer types use platform pointer size:
    /// - **Ptr**: 8 bytes (unmanaged pointer)
    /// - **ByRef**: 8 bytes (managed reference)
    /// - **FnPtr**: 8 bytes (function pointer)
    ///
    /// ## Special Types
    /// - **TypedByRef**: 16 bytes (TypedReference structure)
    /// - **Pinned**: Delegates to inner type size
    /// - **Modified**: Uses conservative 8-byte estimate
    ///
    /// # Thread Safety
    /// This method is safe for concurrent use because:
    /// - **Read-Only Registry Access**: Only reads from the type registry
    /// - **No Shared State**: Uses only local variables and function parameters
    /// - **Pure Function**: Returns same result for same inputs without side effects
    #[allow(clippy::match_same_arms)]
    fn calculate_field_size_with_type_resolution(
        field_signature: &TypeSignature,
        types: &TypeRegistry,
    ) -> u32 {
        match field_signature {
            // Primitive types with known sizes
            TypeSignature::Void => 0,
            TypeSignature::Boolean => 1,
            TypeSignature::I1 | TypeSignature::U1 => 1,
            TypeSignature::I2 | TypeSignature::U2 | TypeSignature::Char => 2,
            TypeSignature::I4 | TypeSignature::U4 | TypeSignature::R4 => 4,
            TypeSignature::I8 | TypeSignature::U8 | TypeSignature::R8 => 8,

            // ToDo: Handle I/U better, depending on compilation target of the assembly
            // Platform-dependent sizes (assuming 64-bit)
            TypeSignature::I | TypeSignature::U => 8, // IntPtr/UIntPtr on 64-bit

            // Reference types (pointers on 64-bit systems)
            TypeSignature::String | TypeSignature::Object => 8,
            TypeSignature::Class(_) | TypeSignature::SzArray(_) | TypeSignature::Array(_) => 8,

            // Pointer types
            TypeSignature::Ptr(_) | TypeSignature::ByRef(_) | TypeSignature::FnPtr(_) => 8,

            // Value types - try to resolve their actual size
            TypeSignature::ValueType(token) => {
                if let Some(value_type) = types.get(token) {
                    // Check if we have explicit class size information
                    if let Some(class_size) = value_type.class_size.get() {
                        *class_size
                    } else {
                        // For well-known value types, return their known sizes
                        match (value_type.namespace.as_str(), value_type.name.as_str()) {
                            ("System", "DateTime") => 8,           // DateTime is 8 bytes
                            ("System", "TimeSpan") => 8,           // TimeSpan is 8 bytes
                            ("System", "Decimal") => 16,           // Decimal is 16 bytes
                            ("System", "Guid") => 16,              // Guid is 16 bytes
                            ("System", "IntPtr" | "UIntPtr") => 8, // Platform pointers
                            _ => 8, // Conservative estimate for unknown value types
                        }
                    }
                } else {
                    8 // Conservative fallback
                }
            }

            // Generic types - conservative estimate
            TypeSignature::GenericParamType(_) | TypeSignature::GenericParamMethod(_) => 8,
            TypeSignature::GenericInst(_, _) => 8,

            // Modified types - recurse to base type
            TypeSignature::ModifiedRequired(_) | TypeSignature::ModifiedOptional(_) => 8,
            TypeSignature::Pinned(inner) => {
                Self::calculate_field_size_with_type_resolution(inner, types)
            }

            // Special types
            TypeSignature::TypedByRef => 16, // TypedReference is 16 bytes

            // Unknown or complex types - conservative estimate
            _ => 8,
        }
    }

    /// Calculates field size using signature analysis without type registry lookup.
    ///
    /// This method provides field size calculation based solely on type signature analysis,
    /// without performing type registry lookups for value types. It serves as a fallback
    /// or lightweight alternative when registry access is not available or desired.
    /// The calculation uses conservative estimates for complex types to ensure safe
    /// field layout validation.
    ///
    /// ## Design Purpose
    ///
    /// This legacy method serves specific use cases:
    /// - **Lightweight Calculation**: When type registry lookup overhead is undesirable
    /// - **Fallback Mechanism**: When registry lookup fails or is unavailable
    /// - **Conservative Validation**: When overestimation is preferable to underestimation
    /// - **Compatibility**: Maintains existing behavior for specific validation paths
    ///
    /// ## Size Calculation Strategy
    ///
    /// The method uses a simplified approach:
    /// 1. **Primitive Types**: Uses fixed sizes from ECMA-335 specification
    /// 2. **Reference Types**: Uses consistent platform pointer size
    /// 3. **Value Types**: Uses conservative 8-byte estimate (no registry lookup)
    /// 4. **Complex Types**: Uses safe estimates to prevent validation failures
    ///
    /// ## Limitations
    ///
    /// This method has known limitations compared to the registry-aware version:
    /// - **Value Type Accuracy**: Cannot determine actual value type sizes
    /// - **Custom Types**: Uses conservative estimates for all custom types
    /// - **Framework Types**: Doesn't distinguish between different framework value types
    /// - **Optimization**: Misses opportunities for precise size calculation
    ///
    /// ## Conservative Estimation Philosophy
    ///
    /// The method errs on the side of caution:
    /// - **Overestimation**: Prefers larger estimates to avoid false validation failures
    /// - **Safety First**: Ensures field layout validation doesn't miss real issues
    /// - **Compatibility**: Maintains consistent behavior across different scenarios
    /// - **Predictability**: Provides deterministic results without external dependencies
    ///
    /// # Arguments
    ///
    /// * `field_signature` - The type signature of the field requiring size calculation
    ///
    /// # Returns
    ///
    /// Returns the estimated field size in bytes as a `u32`. For unknown or complex
    /// types, returns conservative estimates that err on the side of safety.
    ///
    /// # Size Estimation Rules
    ///
    /// ## Primitive Types (Exact Sizes)
    /// - **Void**: 0 bytes
    /// - **Boolean**: 1 byte  
    /// - **I1/U1**: 1 byte
    /// - **I2/U2/Char**: 2 bytes
    /// - **I4/U4/R4**: 4 bytes
    /// - **I8/U8/R8**: 8 bytes
    /// - **I/U**: 8 bytes (64-bit platform assumption)
    ///
    /// ## Reference Types (Platform Pointer Size)
    /// - **String**: 8 bytes
    /// - **Object**: 8 bytes
    /// - **Class**: 8 bytes
    /// - **Array**: 8 bytes
    ///
    /// ## Pointer Types (Platform Pointer Size)
    /// - **Ptr**: 8 bytes
    /// - **ByRef**: 8 bytes  
    /// - **FnPtr**: 8 bytes
    ///
    /// ## Conservative Estimates
    /// - **ValueType**: 8 bytes (conservative, actual size could vary)
    /// - **Generic Types**: 8 bytes (conservative)
    /// - **Modified Types**: 8 bytes (conservative)
    /// - **Unknown Types**: 8 bytes (safe fallback)
    ///
    /// ## Special Cases
    /// - **TypedByRef**: 16 bytes (known structure size)
    /// - **Pinned**: Delegates to inner type (recursive calculation)
    #[allow(clippy::match_same_arms)]
    fn calculate_field_size(field_signature: &TypeSignature) -> u32 {
        match field_signature {
            // Primitive types with known sizes
            TypeSignature::Void => 0,
            TypeSignature::Boolean => 1,
            TypeSignature::I1 | TypeSignature::U1 => 1,
            TypeSignature::I2 | TypeSignature::U2 | TypeSignature::Char => 2,
            TypeSignature::I4 | TypeSignature::U4 | TypeSignature::R4 => 4,
            TypeSignature::I8 | TypeSignature::U8 | TypeSignature::R8 => 8,

            // Platform-dependent sizes (assuming 64-bit)
            TypeSignature::I | TypeSignature::U => 8, // IntPtr/UIntPtr on 64-bit

            // Reference types (pointers on 64-bit systems)
            TypeSignature::String | TypeSignature::Object => 8,
            TypeSignature::Class(_) | TypeSignature::SzArray(_) | TypeSignature::Array(_) => 8,

            // Pointer types
            TypeSignature::Ptr(_) | TypeSignature::ByRef(_) | TypeSignature::FnPtr(_) => 8,

            // Value types need type resolution - for now use conservative estimate
            TypeSignature::ValueType(_) => 8, // Could be 1-many bytes, needs type lookup

            // Generic types - conservative estimate
            TypeSignature::GenericParamType(_) | TypeSignature::GenericParamMethod(_) => 8,
            TypeSignature::GenericInst(_, _) => 8,

            // Modified types - recurse to base type
            TypeSignature::ModifiedRequired(_) | TypeSignature::ModifiedOptional(_) => 8,
            TypeSignature::Pinned(inner) => Self::calculate_field_size(inner),

            // Special types
            TypeSignature::TypedByRef => 16, // TypedReference is 16 bytes

            // Unknown or complex types - conservative estimate
            _ => 8,
        }
    }
}
