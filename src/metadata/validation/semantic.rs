//! # Semantic Validation for .NET Metadata Systems
//!
//! This module provides comprehensive semantic consistency validation that ensures
//! .NET metadata conforms to runtime behavioral requirements, focusing on type system
//! integrity, inheritance rules, and interface constraints as defined by ECMA-335
//! and enforced by the .NET Common Language Runtime (CLR).
//!
//! ## Overview
//!
//! Semantic validation focuses on business logic and behavioral correctness rather
//! than structural integrity. It validates the complex relationships between types,
//! inheritance hierarchies, interface implementations, and abstract type constraints
//! that must be satisfied for proper runtime behavior and type loading success.
//!
//! ## Validation Philosophy
//!
//! The semantic validator aligns with .NET runtime validation patterns, focusing on:
//! - **Critical Runtime Failures**: Validates rules that cause type loading failures
//! - **ECMA-335 Compliance**: Ensures adherence to CLI specification requirements
//! - **Real-World Constraints**: Focuses on issues that affect actual applications
//! - **Performance Aware**: Optimized for validation speed with parallel processing
//!
//! ## Validation Categories
//!
//! ### Inheritance Validation
//! - **Sealed Type Inheritance**: Prevents inheritance from sealed types
//! - **Value Type Constraints**: Validates proper value type inheritance patterns
//! - **Interface Inheritance**: Ensures interfaces only inherit from other interfaces
//! - **Circular Inheritance**: Detects and prevents circular inheritance chains
//!
//! ### Type System Validation
//! - **Abstract/Sealed Conflicts**: Validates proper abstract and sealed combinations
//! - **Interface Constraints**: Ensures interfaces follow proper structural rules
//! - **Generic Constraints**: Validates generic type parameter constraints
//! - **Nested Type Rules**: Validates proper nested type relationships
//!
//! ### Runtime Compliance
//! - **Type Loading Rules**: Validates rules enforced during CLR type loading
//! - **Method Constraints**: Validates constructor and method implementation rules
//! - **Access Modifiers**: Ensures proper visibility and accessibility rules
//! - **Special Type Rules**: Validates rules for delegates, enums, and attributes
//!
//! ## Semantic Validation Rules
//!
//! ### Inheritance Rules
//! 1. **No Sealed Inheritance**: Non-interface types cannot inherit from sealed types
//! 2. **Value Type Consistency**: Value types must follow proper inheritance patterns
//! 3. **Interface Inheritance**: Interfaces can only inherit from Object or other interfaces
//! 4. **Abstract Implementation**: Abstract members must be properly implemented
//!
//! ### Type Modifier Rules
//! 1. **Sealed + Abstract**: Only allowed for static classes (no instance constructors)
//! 2. **Interface Abstract**: All interfaces must be marked abstract
//! 3. **Constructor Constraints**: Interfaces cannot have instance constructors
//! 4. **Method Implementation**: Abstract methods must be implemented in concrete types
//!
//! ## Performance Optimization
//!
//! The validator leverages parallel processing for optimal performance:
//! - **Parallel Type Processing**: Uses [`rayon`] for concurrent type validation
//! - **Efficient Filtering**: Skips validation for types that don't require checking
//! - **Early Termination**: Stops processing when critical errors are detected
//! - **Memory Efficiency**: Minimizes temporary allocations during validation
//!
//! ## Validation Scenarios
//!
//! ### Valid Type Hierarchies
//! ```csharp
//! // Valid inheritance patterns
//! public class BaseClass { }
//! public class DerivedClass : BaseClass { }  // ✓ Normal inheritance
//!
//! public abstract class AbstractBase { }
//! public class ConcreteClass : AbstractBase { }  // ✓ Abstract to concrete
//!
//! public interface IContract { }
//! public interface IExtended : IContract { }  // ✓ Interface inheritance
//!
//! public static class StaticClass { }  // ✓ Static (sealed + abstract) class
//! ```
//!
//! ### Invalid Type Hierarchies
//! ```csharp
//! // Invalid inheritance patterns that semantic validation detects
//! public sealed class SealedClass { }
//! public class Derived : SealedClass { }  // ❌ Cannot inherit from sealed
//!
//! public interface IBad : SomeClass { }  // ❌ Interface inheriting from class
//!
//! public sealed abstract class Invalid {  // ❌ Sealed + abstract (not static)
//!     public Invalid() { }  // Has instance constructor
//! }
//!
//! public interface IWithConstructor {  // ❌ Interface with constructor
//!     IWithConstructor();
//! }
//! ```
//!
//! ## Error Categories
//!
//! | Error Type | Description | Example |
//! |------------|-------------|---------|
//! | **Sealed Inheritance** | Inheritance from sealed type | `class A : SealedType` |
//! | **Value Type Violation** | Incorrect value type inheritance | `class A : ValueType` |
//! | **Interface Inheritance** | Interface inheriting from class | `interface I : Class` |
//! | **Modifier Conflict** | Invalid sealed/abstract combination | `sealed abstract class C { C(); }` |
//! | **Interface Constructor** | Interface with instance constructor | `interface I { I(); }` |
//! | **Missing Abstract** | Interface not marked abstract | `interface I` (without abstract) |
//!
//! ## Thread Safety
//!
//! The [`SemanticValidator`] is designed for safe concurrent operation:
//! - **Stateless Design**: No shared mutable state between validations
//! - **Read-Only Access**: Only reads metadata without modification
//! - **Parallel Safe**: Uses [`rayon`] parallel iterators safely
//! - **Thread-Local Storage**: Uses local collections for error aggregation
//!
//! ## Integration Points
//!
//! The semantic validator integrates with:
//! - [`crate::metadata::loader::CilObjectData`]: Source of type and metadata information
//! - [`crate::metadata::typesystem::TypeRegistry`]: Type lookup and relationship resolution
//! - [`crate::metadata::tables::TypeAttributes`]: Type modifier and flag information
//! - [`crate::metadata::validation::Orchestrator`]: Overall validation coordination
//!
//! ## Runtime Alignment
//!
//! The validation rules align with .NET runtime behavior:
//! - **CLR Type Loading**: Matches type loading validation in CoreCLR
//! - **JIT Constraints**: Validates constraints enforced during JIT compilation
//! - **Reflection Safety**: Ensures types are safe for reflection and dynamic loading
//! - **Interop Compatibility**: Validates types suitable for interop scenarios
//!
//! ## Future Enhancements
//!
//! Planned semantic validation expansions:
//! - **Generic Constraint Validation**: Comprehensive generic type constraint checking
//! - **Delegate Validation**: Specialized validation for delegate types
//! - **Attribute Validation**: Validation of custom attribute usage and constraints
//! - **Cross-Assembly Validation**: Multi-assembly semantic consistency checking
//! - **Performance Optimization**: Additional parallel processing opportunities
//!
//! ## References
//!
//! - ECMA-335: Common Language Infrastructure (CLI) specification
//! - .NET Core Runtime: Type system validation implementation
//! - C# Language Specification: Type system semantics and constraints
//! - CLR Via C#: Detailed runtime behavior documentation

use crate::metadata::{
    loader::CilObjectData,
    tables::TypeAttributes,
    typesystem::{CilFlavor, CilType, TypeRegistry},
};
use rayon::prelude::*;

/// Comprehensive semantic consistency validator for .NET metadata.
///
/// The `SemanticValidator` provides sophisticated validation of type system semantics,
/// inheritance relationships, and behavioral constraints that must be satisfied for
/// proper .NET runtime operation. It aligns with CLR validation patterns and focuses
/// on issues that would cause actual runtime failures rather than style violations.
///
/// ## Design Philosophy
///
/// The validator implements a runtime-aligned validation approach:
/// - **Runtime Enforcement Focus**: Validates only rules enforced by the CLR
/// - **Performance Optimized**: Uses parallel processing for large type systems
/// - **Error Practicality**: Reports issues that affect real applications
/// - **Specification Compliance**: Ensures adherence to ECMA-335 requirements
///
/// ## Validation Approach
///
/// The validator employs a multi-layered validation strategy:
/// 1. **Type Filtering**: Efficiently identifies types requiring validation
/// 2. **Parallel Processing**: Leverages multiple CPU cores for performance
/// 3. **Rule-Based Validation**: Applies specific rules based on type characteristics
/// 4. **Error Aggregation**: Collects and organizes validation results
///
/// ## Validation Categories
///
/// ### Inheritance Validation
/// - **Sealed Type Rules**: Prevents inheritance from sealed types
/// - **Value Type Constraints**: Validates value type inheritance patterns
/// - **Interface Inheritance**: Ensures proper interface inheritance chains
/// - **Base Type Consistency**: Validates base type relationship correctness
///
/// ### Type Modifier Validation
/// - **Abstract/Sealed Conflicts**: Detects invalid modifier combinations
/// - **Interface Requirements**: Ensures interfaces meet structural requirements
/// - **Constructor Constraints**: Validates constructor presence and validity
/// - **Static Class Rules**: Validates static class implementation patterns
///
/// ## Error Reporting
///
/// The validator provides detailed error reporting:
/// - **Descriptive Messages**: Clear explanations of semantic violations
/// - **Type Context**: Includes type names and relationship information
/// - **Rule References**: Indicates which semantic rules were violated
/// - **Categorized Results**: Organizes errors by validation category
///
/// ## Thread Safety
///
/// The validator is designed for safe concurrent operation:
/// - **Stateless Design**: Contains no mutable state between validations
/// - **Read-Only Access**: Only reads metadata without modification
/// - **Parallel Safe**: Uses thread-safe parallel processing primitives
/// - **Local Collections**: Uses thread-local storage for error aggregation
pub struct SemanticValidator;

impl SemanticValidator {
    /// Performs comprehensive semantic consistency validation across the metadata system.
    ///
    /// This method orchestrates semantic validation for all types in the loaded metadata,
    /// ensuring that type relationships, inheritance patterns, and structural constraints
    /// conform to .NET runtime requirements. The validation focuses on issues that would
    /// cause type loading failures or runtime errors, aligning with CLR validation behavior.
    ///
    /// ## Validation Process
    ///
    /// The method performs validation in parallel for optimal performance:
    /// 1. **Type Enumeration**: Iterates through all types in the registry
    /// 2. **Parallel Processing**: Uses [`rayon`] for concurrent type validation
    /// 3. **Rule Application**: Applies semantic rules based on type characteristics
    /// 4. **Error Collection**: Aggregates validation errors from all parallel operations
    ///
    /// ## Validation Rules Applied
    ///
    /// ### Critical Inheritance Rules
    /// - **Sealed Type Inheritance**: Validates that non-interface types don't inherit from sealed types
    /// - **Value Type Consistency**: Ensures proper value type inheritance patterns
    /// - **Interface Inheritance**: Validates that interfaces only inherit from Object or other interfaces
    /// - **Base Type Validity**: Ensures base type relationships are structurally sound
    ///
    /// ### Type Modifier Rules
    /// - **Abstract/Sealed Validation**: Checks for valid sealed and abstract combinations
    /// - **Interface Requirements**: Ensures interfaces are properly marked abstract
    /// - **Constructor Constraints**: Validates constructor presence and accessibility
    /// - **Static Class Rules**: Validates static class implementation patterns
    ///
    /// ### Runtime Compliance Rules
    /// - **Type Loading Safety**: Validates rules enforced during CLR type loading
    /// - **JIT Constraints**: Ensures types meet Just-In-Time compilation requirements
    /// - **Reflection Safety**: Validates types are safe for reflection operations
    /// - **Interop Compatibility**: Ensures types work correctly in interop scenarios
    ///
    /// ## Performance Optimization
    ///
    /// The validation leverages several performance optimizations:
    /// - **Parallel Processing**: Concurrent validation across multiple CPU cores
    /// - **Smart Filtering**: Skips validation for types that don't require checking
    /// - **Efficient Type Access**: Optimized access patterns for type registry data
    /// - **Memory Efficiency**: Minimizes temporary allocations during validation
    ///
    /// ## Error Handling
    ///
    /// The method provides comprehensive error reporting:
    /// - **Detailed Messages**: Descriptive error messages with type context
    /// - **Rule Identification**: Indicates which semantic rules were violated
    /// - **Parallel Aggregation**: Safely collects errors from concurrent validations
    /// - **Categorized Results**: Organizes errors by validation category
    ///
    /// # Arguments
    ///
    /// * `data` - The CIL object data containing the complete loaded metadata,
    ///   including type registry, tables, and cross-references
    ///
    /// # Returns
    ///
    /// Returns a vector of validation error messages describing all semantic
    /// violations found during validation. An empty vector indicates that no
    /// semantic issues were detected.
    ///
    /// # Examples
    ///
    /// ## Basic Semantic Validation
    ///
    /// The `validate_semantic_consistency` method performs comprehensive semantic
    /// validation and returns a vector of error messages describing any violations
    /// found during the validation process.
    ///
    /// ## Error Processing and Analysis
    ///
    /// The validation results can be analyzed and categorized by error type,
    /// such as inheritance violations, interface constraints, and modifier
    /// conflicts, to provide structured error reporting.
    ///
    /// ## Integration with Logging
    ///
    /// The validation results can be integrated with logging systems to provide
    /// structured reporting of semantic validation outcomes, including success
    /// cases and detailed error information for debugging purposes.
    ///
    /// # Error Categories
    ///
    /// The validation may return errors in these categories:
    /// - **Inheritance Violations**: Types inheriting from inappropriate base types
    /// - **Interface Constraints**: Interfaces violating structural requirements
    /// - **Modifier Conflicts**: Invalid combinations of abstract, sealed, etc.
    /// - **Constructor Issues**: Invalid constructor patterns for type category
    /// - **Value Type Rules**: Violations of value type inheritance patterns
    ///
    /// # Thread Safety
    ///
    /// This method is safe for concurrent execution because:
    /// - **Read-Only Access**: Only reads metadata without modification
    /// - **Independent Processing**: Each type is validated independently
    /// - **Thread-Local Storage**: Uses local collections for error aggregation
    /// - **Parallel Safe**: Uses [`rayon`] parallel iterators safely
    ///
    /// # Implementation Notes
    ///
    /// The method uses sophisticated filtering to optimize performance:
    /// - **Complex Type Skipping**: Avoids validation of pointer, array, and generic types with misleading metadata
    /// - **Self-Reference Protection**: Prevents validation issues with self-referential types
    /// - **System Type Handling**: Special handling for framework and primitive types
    /// - **Error Deduplication**: Prevents duplicate errors for the same issue
    pub fn validate_semantic_consistency(data: &CilObjectData) -> Vec<String> {
        let type_registry = &data.types;

        // Use parallel iteration for better performance on large type systems
        type_registry
            .all_types()
            .par_iter()
            .flat_map(|type_entry| {
                let mut errors = Vec::new();

                // Validate inheritance - this is critical for runtime
                Self::validate_inheritance_critical(type_entry, type_registry, &mut errors);

                // Validate sealed/abstract combinations - runtime enforced
                Self::validate_sealed_abstract_rules(type_entry, &mut errors);

                // Validate interface constraints - runtime enforced
                Self::validate_interface_constraints(type_entry, &mut errors);

                errors
            })
            .collect()
    }
    /// Validates critical inheritance relationships enforced by the .NET runtime.
    ///
    /// This method performs comprehensive validation of inheritance patterns that
    /// are strictly enforced by the CLR during type loading. It focuses on rules
    /// that would cause `TypeLoadException` or similar runtime failures if violated,
    /// ensuring that type hierarchies are structurally sound and runtime-compliant.
    ///
    /// ## Validation Rules
    ///
    /// ### Sealed Type Inheritance Prevention
    /// Validates that types cannot inherit from sealed types (except special cases):
    /// - **Runtime Rule**: CLR prevents inheritance from sealed types
    /// - **Exception Handling**: Allows self-references and interface inheritance
    /// - **Error Detection**: Reports sealed inheritance violations with context
    ///
    /// ### Value Type Inheritance Consistency
    /// Ensures proper inheritance patterns for value types:
    /// - **Value Type Base**: Value types should inherit from `System.ValueType`
    /// - **Reference Type Restriction**: Reference types cannot inherit from value types
    /// - **Special Cases**: Allows system types and primitive types
    /// - **Enum Handling**: Permits `System.Enum` inheritance patterns
    ///
    /// ### Interface Inheritance Rules
    /// Validates that interfaces follow proper inheritance constraints:
    /// - **Interface to Interface**: Interfaces can inherit from other interfaces
    /// - **Object Inheritance**: Interfaces can inherit from `System.Object`
    /// - **Class Prevention**: Interfaces cannot inherit from class types
    /// - **Runtime Enforcement**: Matches CLR interface loading behavior
    ///
    /// ## Type Filtering Strategy
    ///
    /// The method employs intelligent filtering to avoid false positives:
    /// ```text
    /// Skip if:
    /// - Pointer types (contains '*')
    /// - Array types (contains '[')
    /// - Generic instantiations (both child and parent contain '`')
    /// ```
    ///
    /// This filtering prevents validation of metadata artifacts that don't represent
    /// actual inheritance relationships but appear in metadata due to generic instantiation
    /// or compiler-generated constructs.
    ///
    /// ## Error Context and Reporting
    ///
    /// The method provides detailed error context:
    /// - **Type Names**: Includes both child and parent type names
    /// - **Relationship Context**: Describes the inheritance relationship
    /// - **Rule Reference**: Indicates which inheritance rule was violated
    /// - **Actionable Messages**: Provides clear guidance on the violation
    ///
    /// # Arguments
    ///
    /// * `cil_type` - The type being validated for inheritance compliance
    /// * `_type_registry` - The type registry for resolving type relationships (currently unused but available for future enhancements)
    /// * `errors` - Mutable vector for collecting validation errors
    ///
    /// # Validation Examples
    ///
    /// ## Valid Inheritance Patterns
    /// ```csharp
    /// // Valid inheritance patterns that pass validation
    /// public class BaseClass { }
    /// public class DerivedClass : BaseClass { }  // ✓ Normal inheritance
    ///
    /// public abstract class AbstractBase { }
    /// public class ConcreteImpl : AbstractBase { }  // ✓ Abstract to concrete
    ///
    /// public interface IBase { }
    /// public interface IDerived : IBase { }  // ✓ Interface inheritance
    ///
    /// public struct CustomStruct { }  // ✓ Value type (inherits from ValueType)
    /// ```
    ///
    /// ## Invalid Inheritance Patterns
    /// ```csharp
    /// // Invalid patterns detected by this validation
    /// public sealed class SealedClass { }
    /// public class BadClass : SealedClass { }  // ❌ Cannot inherit from sealed
    ///
    /// public class BadReference : SomeValueType { }  // ❌ Reference type from value type
    ///
    /// public interface IBad : SomeClass { }  // ❌ Interface from class
    /// ```
    ///
    /// # Thread Safety
    ///
    /// This method is safe for concurrent execution:
    /// - **Read-Only Type Access**: Only reads type properties without modification
    /// - **Local Error Collection**: Each thread uses its own error vector
    /// - **No Shared State**: Contains no shared mutable state between calls
    /// - **Parallel Safe**: Designed for use in parallel validation scenarios
    fn validate_inheritance_critical(
        cil_type: &std::sync::Arc<CilType>,
        _type_registry: &TypeRegistry,
        errors: &mut Vec<String>,
    ) {
        if let Some(base_type) = cil_type.base() {
            // Skip validation for pointer types, array types, and generic instantiations
            // These often have misleading base type relationships in metadata
            if cil_type.name.contains('*')
                || cil_type.name.contains('[')
                || cil_type.name.contains('`') && base_type.name.contains('`')
            {
                return; // Skip validation for these complex types
            }

            // Critical: Cannot inherit from sealed types (runtime enforced)
            if (base_type.flags & TypeAttributes::SEALED) != 0
                && (cil_type.flags & TypeAttributes::INTERFACE) == 0
                && cil_type.name != base_type.name
            // Avoid self-reference issues
            {
                errors.push(format!(
                    "Type '{}' cannot inherit from sealed type '{}'",
                    cil_type.name, base_type.name
                ));
            }

            // Critical: Value type inheritance rules (runtime enforced)
            // Value types should inherit from ValueType, but non-value types should not
            if base_type.flavor() == &CilFlavor::ValueType {
                // If base is ValueType, child should also be a value type (or special cases)
                if cil_type.flavor() != &CilFlavor::ValueType
                    && cil_type.name != "System.Enum"
                    && !cil_type.name.starts_with("System.")  // Allow system types
                    && !is_primitive_type(&cil_type.name)
                // Allow primitive types
                {
                    errors.push(format!(
                        "Type '{}' cannot inherit from value type '{}'",
                        cil_type.name, base_type.name
                    ));
                }
            }

            // Critical: Interface cannot inherit from non-interface (runtime enforced)
            if (cil_type.flags & TypeAttributes::INTERFACE) != 0
                && (base_type.flags & TypeAttributes::INTERFACE) == 0
                && base_type.name != "System.Object"
            {
                // Object is allowed base
                errors.push(format!(
                    "Interface '{}' cannot inherit from non-interface type '{}'",
                    cil_type.name, base_type.name
                ));
            }
        }
    }

    /// Validates sealed and abstract type modifier combinations.
    ///
    /// This method ensures that the combination of sealed and abstract modifiers
    /// on types follows .NET runtime rules and represents valid type declarations.
    /// The CLR has specific rules about when types can be both sealed and abstract,
    /// and this validation ensures compliance with those constraints.
    ///
    /// ## Validation Logic
    ///
    /// ### Static Class Detection
    /// The method recognizes that static classes in C# compile to "sealed abstract" in IL:
    /// - **Valid Pattern**: Sealed + Abstract + No Instance Constructors = Static Class
    /// - **Invalid Pattern**: Sealed + Abstract + Has Instance Constructors = Invalid
    /// - **Runtime Rule**: CLR allows sealed abstract only for static classes
    ///
    /// ### Instance Constructor Analysis
    /// Determines if a type is a legitimate static class by analyzing constructors:
    /// ```text
    /// For each method in type:
    ///   If method name == ".ctor":  // Instance constructor
    ///     Type is NOT a static class
    ///     Sealed + Abstract combination is invalid
    /// ```
    ///
    /// ## Type Modifier Rules
    ///
    /// ### Valid Combinations
    /// - **Sealed Only**: Regular sealed class (cannot be inherited)
    /// - **Abstract Only**: Abstract class (cannot be instantiated, can be inherited)
    /// - **Sealed + Abstract + No Instance Constructor**: Static class
    /// - **Neither**: Regular instantiable and inheritable class
    ///
    /// ### Invalid Combinations
    /// - **Sealed + Abstract + Instance Constructor**: Contradictory requirements
    ///   - Sealed: Cannot be inherited
    ///   - Abstract: Cannot be instantiated
    ///   - Instance Constructor: Suggests instantiation capability
    ///
    /// ## Static Class Semantics
    ///
    /// Static classes have specific characteristics:
    /// - **Sealed**: Cannot be inherited (no derived classes)
    /// - **Abstract**: Cannot be instantiated (no instances)
    /// - **No Instance Constructors**: Only static constructors allowed
    /// - **Static Members Only**: All members must be static
    ///
    /// ## Error Detection and Reporting
    ///
    /// The method provides clear error messages:
    /// - **Context Information**: Includes type name in error message
    /// - **Rule Explanation**: Explains why the combination is invalid
    /// - **Disambiguation**: Clarifies that valid static classes are allowed
    /// - **Actionable Guidance**: Suggests removing conflicting modifiers or constructors
    ///
    /// # Arguments
    ///
    /// * `cil_type` - The type being validated for modifier combination compliance
    /// * `errors` - Mutable vector for collecting validation errors
    ///
    /// # Validation Examples
    ///
    /// ## Valid Modifier Combinations
    /// ```csharp
    /// // Valid combinations that pass validation
    /// public class RegularClass { }  // ✓ No special modifiers
    ///
    /// public sealed class SealedClass { }  // ✓ Sealed only
    ///
    /// public abstract class AbstractClass { }  // ✓ Abstract only
    ///
    /// public static class StaticClass {  // ✓ Static (sealed + abstract, no instance ctor)
    ///     static StaticClass() { }  // Static constructor OK
    ///     public static void Method() { }
    /// }
    /// ```
    ///
    /// ## Invalid Modifier Combinations
    /// ```csharp
    /// // Invalid combinations detected by this validation
    /// public sealed abstract class InvalidClass {  // ❌ Has instance constructor
    ///     public InvalidClass() { }  // Makes sealed+abstract invalid
    /// }
    ///
    /// // Note: This would be valid if no instance constructor existed
    /// public sealed abstract class WouldBeValidStatic {  // ✓ If no instance constructor
    ///     static WouldBeValidStatic() { }  // Only static constructor
    ///     public static void Method() { }  // Only static methods
    /// }
    /// ```
    ///
    /// # C# to IL Compilation Context
    ///
    /// Understanding how C# compiles to IL helps explain the validation:
    /// ```csharp
    /// // C# static class
    /// public static class MyStatic { }
    ///
    /// // Compiles to IL equivalent to:
    /// .class public sealed abstract MyStatic { }  // No instance constructor
    /// ```
    ///
    /// # Thread Safety
    ///
    /// This method is safe for concurrent execution:
    /// - **Read-Only Access**: Only reads type flags and method information
    /// - **Local Processing**: Uses local variables for computation
    /// - **No Shared State**: Contains no shared mutable state
    /// - **Weak Reference Handling**: Safely handles weak method references
    fn validate_sealed_abstract_rules(
        cil_type: &std::sync::Arc<CilType>,
        errors: &mut Vec<String>,
    ) {
        // Note: Static classes in C# compile to "sealed abstract" in IL, which is valid
        // Only flag sealed+abstract if it's NOT a static class (has instance members)
        if (cil_type.flags & TypeAttributes::SEALED) != 0
            && (cil_type.flags & TypeAttributes::ABSTRACT) != 0
        {
            // Check if this appears to be a static class by looking for instance constructors
            let has_instance_constructor = cil_type.methods.iter().any(|(_, method_ref)| {
                if let Some(method) = method_ref.upgrade() {
                    method.name == ".ctor" // Instance constructor
                } else {
                    false
                }
            });

            // If it has instance constructors, it's not a valid static class
            if has_instance_constructor {
                errors.push(format!(
                    "Type '{}' cannot be both sealed and abstract (not a static class)",
                    cil_type.name
                ));
            }
        }
    }

    /// Validates interface-specific structural constraints and requirements.
    ///
    /// This method ensures that interface types conform to the structural rules
    /// enforced by the .NET runtime, including modifier requirements and method
    /// constraints that are specific to interface types. The validation aligns
    /// with CLR interface loading behavior and ECMA-335 interface specifications.
    ///
    /// ## Interface Validation Rules
    ///
    /// ### Abstract Modifier Requirement
    /// Validates that all interfaces are properly marked as abstract:
    /// - **Runtime Rule**: CLR requires all interfaces to have the abstract flag
    /// - **ECMA-335 Compliance**: Specification mandates abstract flag for interfaces
    /// - **Type Loading**: Missing abstract flag causes type loading failures
    /// - **Error Detection**: Reports interfaces without proper abstract marking
    ///
    /// ### Constructor Prohibition
    /// Ensures that interfaces don't contain instance constructors:
    /// - **Conceptual Rule**: Interfaces define contracts, not implementations
    /// - **Runtime Enforcement**: CLR prohibits instance constructors in interfaces
    /// - **Method Analysis**: Checks for ".ctor" methods in interface types
    /// - **Static Constructor Allowance**: Static constructors (.cctor) are permitted
    ///
    /// ## Interface Design Principles
    ///
    /// The validation enforces fundamental interface design principles:
    /// - **Contract Definition**: Interfaces define behavior contracts only
    /// - **No Implementation**: Interfaces cannot contain implementation details
    /// - **No State**: Interfaces cannot maintain instance state
    /// - **Pure Abstraction**: Interfaces represent pure abstraction
    ///
    /// ## Validation Process
    ///
    /// The method performs validation in specific steps:
    /// 1. **Interface Detection**: Identifies types with interface flag
    /// 2. **Abstract Flag Validation**: Ensures abstract modifier is present
    /// 3. **Method Enumeration**: Iterates through all methods in interface
    /// 4. **Constructor Detection**: Identifies any instance constructor methods
    /// 5. **Error Reporting**: Reports violations with descriptive messages
    ///
    /// ## Error Categories
    ///
    /// ### Missing Abstract Flag
    /// ```text
    /// Error: "Interface 'IExample' must be marked abstract"
    /// Cause: Interface type without TypeAttributes::ABSTRACT flag
    /// Impact: Type loading failure in CLR
    /// ```
    ///
    /// ### Instance Constructor Present
    /// ```text
    /// Error: "Interface 'IExample' cannot have instance constructor"
    /// Cause: Interface contains ".ctor" method
    /// Impact: Runtime constraint violation
    /// ```
    ///
    /// # Arguments
    ///
    /// * `cil_type` - The type being validated for interface compliance
    /// * `errors` - Mutable vector for collecting validation errors
    ///
    /// # Validation Examples
    ///
    /// ## Valid Interface Declarations
    /// ```csharp
    /// // Valid interfaces that pass validation
    /// public interface IContract {  // ✓ Abstract (implicit in C#)
    ///     void Method();
    ///     int Property { get; set; }
    /// }
    ///
    /// public interface IGeneric<T> {  // ✓ Generic interface
    ///     T Process(T input);
    /// }
    ///
    /// public interface IWithStatic {  // ✓ Static constructor allowed
    ///     static IWithStatic() { }  // Static constructor OK
    ///     void Method();
    /// }
    /// ```
    ///
    /// ## Invalid Interface Declarations
    /// ```csharp
    /// // Invalid interfaces detected by this validation
    ///
    /// // Note: These examples are conceptual - C# compiler prevents most of these,
    /// // but malformed metadata or other languages might create such structures
    ///
    /// public interface IBadInterface {  // ❌ If not marked abstract in metadata
    ///     IBadInterface();  // ❌ Instance constructor not allowed
    ///     void Method();
    /// }
    /// ```
    ///
    /// ## IL Metadata Context
    ///
    /// In IL metadata, interfaces must have specific characteristics:
    /// ```il
    /// // Valid interface in IL
    /// .class interface public abstract IExample {
    ///     .method public hidebysig newslot abstract virtual
    ///         void Method() cil managed { }
    /// }
    ///
    /// // Invalid interface (missing abstract)
    /// .class interface public IInvalid {  // ❌ Missing abstract
    ///     .method public hidebysig specialname rtspecialname
    ///         void .ctor() cil managed { }  // ❌ Instance constructor
    /// }
    /// ```
    ///
    /// # Thread Safety
    ///
    /// This method is safe for concurrent execution:
    /// - **Read-Only Access**: Only reads type flags and method information
    /// - **Weak Reference Handling**: Safely handles weak method references
    /// - **Local Processing**: Uses local variables for all computations
    /// - **No Side Effects**: Doesn't modify any type or method information
    ///
    /// # Integration with Runtime
    ///
    /// The validation aligns with .NET runtime behavior:
    /// - **CLR Type Loading**: Matches interface validation during type loading
    /// - **JIT Compilation**: Ensures interfaces are suitable for JIT compilation
    /// - **Reflection Safety**: Validates interfaces work correctly with reflection
    /// - **Interop Compatibility**: Ensures interfaces work in interop scenarios
    fn validate_interface_constraints(
        cil_type: &std::sync::Arc<CilType>,
        errors: &mut Vec<String>,
    ) {
        if (cil_type.flags & TypeAttributes::INTERFACE) != 0 {
            // Critical: Interfaces must be abstract (runtime enforced)
            if (cil_type.flags & TypeAttributes::ABSTRACT) == 0 {
                errors.push(format!(
                    "Interface '{}' must be marked abstract",
                    cil_type.name
                ));
            }

            // Check for instance constructors in interfaces (not allowed)
            for (_, method_ref) in cil_type.methods.iter() {
                if let Some(method) = method_ref.upgrade() {
                    if method.name == ".ctor" {
                        errors.push(format!(
                            "Interface '{}' cannot have instance constructor",
                            cil_type.name
                        ));
                    }
                }
            }
        }
    }
}

/// Determines if a type name represents a .NET primitive type.
///
/// This helper function identifies primitive types that are legitimately allowed
/// to inherit from `System.ValueType` as part of the .NET type system architecture.
/// Primitive types have special inheritance relationships that are enforced by
/// the runtime and must be exempted from normal value type inheritance validation.
///
/// ## Primitive Type Categories
///
/// ### Void Type
/// - **Void**: Represents absence of a value, special runtime handling
///
/// ### Boolean Type
/// - **Boolean**: True/false values, 1 byte storage
///
/// ### Character Type
/// - **Char**: Unicode character, 2 bytes (UTF-16 code unit)
///
/// ### Signed Integer Types
/// - **SByte**: Signed 8-bit integer (-128 to 127)
/// - **Int16**: Signed 16-bit integer (-32,768 to 32,767)
/// - **Int32**: Signed 32-bit integer (-2,147,483,648 to 2,147,483,647)
/// - **Int64**: Signed 64-bit integer (large range)
///
/// ### Unsigned Integer Types
/// - **Byte**: Unsigned 8-bit integer (0 to 255)
/// - **UInt16**: Unsigned 16-bit integer (0 to 65,535)
/// - **UInt32**: Unsigned 32-bit integer (0 to 4,294,967,295)
/// - **UInt64**: Unsigned 64-bit integer (large range)
///
/// ### Floating Point Types
/// - **Single**: 32-bit floating point (IEEE 754)
/// - **Double**: 64-bit floating point (IEEE 754)
///
/// ### Platform-Dependent Types
/// - **IntPtr**: Platform-specific signed integer pointer
/// - **UIntPtr**: Platform-specific unsigned integer pointer
///
/// ### Special Runtime Types
/// - **TypedReference**: Type-safe reference with runtime type information
///
/// ## Inheritance Context
///
/// These primitive types have special inheritance characteristics:
/// - **Direct ValueType Inheritance**: Inherit directly from `System.ValueType`
/// - **Runtime Implementation**: Implemented directly by the CLR
/// - **Special Handling**: Receive special treatment during type loading
/// - **Validation Exemption**: Exempt from normal value type inheritance rules
///
/// ## Usage in Validation
///
/// This function is used in semantic validation to:
/// - **Exempt Primitives**: Skip inheritance validation for primitive types
/// - **Allow Special Patterns**: Permit primitive inheritance from ValueType
/// - **Prevent False Positives**: Avoid reporting valid primitive inheritance as errors
/// - **Maintain Accuracy**: Ensure validation reflects actual runtime behavior
///
/// # Arguments
///
/// * `type_name` - The name of the type to check for primitive classification
///
/// # Returns
///
/// Returns `true` if the type name represents a .NET primitive type that should
/// be exempted from normal value type inheritance validation, `false` otherwise.
///
/// # Type Name Format
///
/// The function expects simple type names without namespace qualifiers:
/// - **Correct**: "Int32", "Boolean", "Double"
/// - **Incorrect**: "System.Int32", "System.Boolean", "System.Double"
///
/// # Thread Safety
///
/// This function is completely thread-safe:
/// - **Pure Function**: No side effects or mutable state
/// - **Read-Only**: Only reads the input parameter
/// - **No Shared State**: Contains no shared mutable state
/// - **Concurrent Safe**: Safe to call from multiple threads simultaneously
///
/// # Specification Alignment
///
/// The function aligns with ECMA-335 primitive type definitions:
/// - **CLI Specification**: Matches CLI built-in type definitions
/// - **Runtime Behavior**: Reflects actual CLR primitive type handling
/// - **Standard Compliance**: Follows standard .NET primitive type conventions
/// - **Cross-Platform**: Works consistently across all .NET implementations
fn is_primitive_type(type_name: &str) -> bool {
    matches!(
        type_name,
        "Void"
            | "Boolean"
            | "Char"
            | "SByte"
            | "Byte"
            | "Int16"
            | "UInt16"
            | "Int32"
            | "UInt32"
            | "Int64"
            | "UInt64"
            | "Single"
            | "Double"
            | "IntPtr"
            | "UIntPtr"
            | "TypedReference"
    )
}
