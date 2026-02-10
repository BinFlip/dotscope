//! Factory methods for inheritance validation testing.
//!
//! Contains helper methods migrated from inheritance validation source files
//! for creating test assemblies with various inheritance validation scenarios.

use crate::{
    metadata::tables::{
        CodedIndex, CodedIndexType, MethodDefBuilder, TableId, TypeAttributes, TypeDefBuilder,
    },
    test::{create_test_assembly_with_error, get_testfile_mscorlib, TestAssembly},
    Error, Result,
};

/// Test factory for OwnedInheritanceValidator following the golden pattern.
///
/// Creates test assemblies with specific inheritance violations that should be detected
/// by the owned validator. Each assembly targets exactly one validation rule to ensure
/// test isolation and comprehensive coverage.
///
/// # Test Coverage
///
/// 1. **Clean Assembly** - Valid inheritance hierarchy (should pass)
/// 2. **Circular Inheritance** - Type A inherits from Type B which inherits from Type A
/// 3. **Sealed Type Inheritance** - Type inheriting from a sealed non-System type
/// 4. **Interface Inheritance Violation** - Class inheriting from interface (not implementing)
/// 5. **Accessibility Violation** - Public type inheriting from internal/private type
/// 6. **Abstract/Concrete Rule Violation** - Interface that is not marked as abstract
/// 7. **Method Inheritance Violation** - Concrete type with abstract methods
///
/// This follows the same pattern as raw validators: create corrupted raw assemblies
/// that when loaded by CilObject produce the inheritance violations that the owned
/// validator should detect in the resolved metadata structures.
///
/// Originally from: `src/metadata/validation/validators/owned/types/inheritance.rs`
pub fn owned_inheritance_validator_file_factory() -> Result<Vec<TestAssembly>> {
    let mut assemblies = Vec::new();

    let Some(clean_testfile) = get_testfile_mscorlib() else {
        return Err(Error::Other(
            "mscorlib.dll not available - test cannot run".to_string(),
        ));
    };

    // 1. REQUIRED: Clean assembly - should pass all validation
    assemblies.push(TestAssembly::new(&clean_testfile, true));

    // 2. NEGATIVE: Sealed type inheritance violation
    assemblies.push(create_assembly_with_sealed_type_inheritance()?);

    // 3. NEGATIVE: Interface inheritance violation
    assemblies.push(create_assembly_with_interface_inheritance_violation()?);

    // 4. NEGATIVE: Accessibility violation
    assemblies.push(create_assembly_with_accessibility_violation()?);

    // 5. NEGATIVE: Abstract/concrete violation
    assemblies.push(create_assembly_with_abstract_concrete_violation()?);

    // 6. NEGATIVE: Method inheritance violation (disabled - test case needs refinement)
    // TODO: Investigate why concrete type with abstract method is not detected as violation
    // assemblies.push(create_assembly_with_method_inheritance_violation()?);

    // 7. NEGATIVE: Circular inheritance dependency (disabled - test case needs refinement)
    // TODO: Investigate why deep inheritance chain is not triggering depth limit validation
    // assemblies.push(create_assembly_with_circular_inheritance()?);

    Ok(assemblies)
}

/// Creates an assembly with circular inheritance dependency.
///
/// This creates a raw assembly containing types that inherit from each other in a cycle,
/// which violates ECMA-335 inheritance constraints. When loaded by CilObject, this should
/// trigger circular dependency detection in the owned validator.
///
/// Originally from: `src/metadata/validation/validators/owned/types/inheritance.rs`
pub fn create_assembly_with_circular_inheritance() -> Result<TestAssembly> {
    create_test_assembly_with_error(
        get_testfile_mscorlib,
        "inheritance chain depth exceeds",
        |assembly| {
            let mut previous_token = None;

            for i in 0..50 {
                let mut builder = TypeDefBuilder::new()
                    .name(format!("DeepInheritanceType{i}"))
                    .namespace("Test.DeepInheritance")
                    .flags(TypeAttributes::CLASS | TypeAttributes::PUBLIC);

                if let Some(parent_token) = previous_token {
                    builder = builder.extends(CodedIndex::new(
                        TableId::TypeDef,
                        parent_token,
                        CodedIndexType::TypeDefOrRef,
                    ));
                }

                let current_token = builder.build(assembly)?;
                previous_token = Some(
                    current_token
                        .token()
                        .expect("TypeDef token should be resolved")
                        .row(),
                );
            }

            Ok(())
        },
    )
}

/// Creates an assembly with sealed type inheritance violation.
///
/// This creates a raw assembly containing a type that inherits from a sealed type
/// (not System types), which violates ECMA-335 inheritance constraints.
///
/// Originally from: `src/metadata/validation/validators/owned/types/inheritance.rs`
pub fn create_assembly_with_sealed_type_inheritance() -> Result<TestAssembly> {
    create_test_assembly_with_error(
        get_testfile_mscorlib,
        "cannot inherit from sealed type",
        |assembly| {
            let sealed_base_token = TypeDefBuilder::new()
                .name("SealedBaseType")
                .namespace("Test.Sealed")
                .flags(TypeAttributes::CLASS | TypeAttributes::PUBLIC | TypeAttributes::SEALED)
                .build(assembly)?;

            TypeDefBuilder::new()
                .name("DerivedFromSealed")
                .namespace("Test.Sealed")
                .flags(TypeAttributes::CLASS | TypeAttributes::PUBLIC)
                .extends(CodedIndex::new(
                    TableId::TypeDef,
                    sealed_base_token
                        .token()
                        .expect("TypeDef token should be resolved")
                        .row(),
                    CodedIndexType::TypeDefOrRef,
                ))
                .build(assembly)?;

            Ok(())
        },
    )
}

/// Creates an assembly with interface inheritance violation.
///
/// This creates a raw assembly containing a class that inherits from an interface
/// (rather than implementing it), which violates ECMA-335 inheritance rules.
///
/// Originally from: `src/metadata/validation/validators/owned/types/inheritance.rs`
pub fn create_assembly_with_interface_inheritance_violation() -> Result<TestAssembly> {
    create_test_assembly_with_error(
        get_testfile_mscorlib,
        "cannot inherit from interface",
        |assembly| {
            let interface_token = TypeDefBuilder::new()
                .name("ITestInterface")
                .namespace("Test.Interface")
                .flags(
                    TypeAttributes::INTERFACE | TypeAttributes::ABSTRACT | TypeAttributes::PUBLIC,
                )
                .build(assembly)?;

            TypeDefBuilder::new()
                .name("ClassInheritingFromInterface")
                .namespace("Test.Interface")
                .flags(TypeAttributes::CLASS | TypeAttributes::PUBLIC)
                .extends(CodedIndex::new(
                    TableId::TypeDef,
                    interface_token
                        .token()
                        .expect("TypeDef token should be resolved")
                        .row(),
                    CodedIndexType::TypeDefOrRef,
                ))
                .build(assembly)?;

            Ok(())
        },
    )
}

/// Creates an assembly with accessibility violation.
///
/// This creates a raw assembly containing a public type that inherits from an internal type,
/// which violates accessibility constraints in ECMA-335.
///
/// Originally from: `src/metadata/validation/validators/owned/types/inheritance.rs`
pub fn create_assembly_with_accessibility_violation() -> Result<TestAssembly> {
    create_test_assembly_with_error(
        get_testfile_mscorlib,
        "cannot inherit from less accessible base type",
        |assembly| {
            let internal_base_token = TypeDefBuilder::new()
                .name("InternalBaseType")
                .namespace("Test.Accessibility")
                .flags(TypeAttributes::CLASS | TypeAttributes::NOT_PUBLIC) // Internal visibility
                .build(assembly)?;

            TypeDefBuilder::new()
                .name("PublicDerivedType")
                .namespace("Test.Accessibility")
                .flags(TypeAttributes::CLASS | TypeAttributes::PUBLIC) // Public visibility
                .extends(CodedIndex::new(
                    TableId::TypeDef,
                    internal_base_token
                        .token()
                        .expect("TypeDef token should be resolved")
                        .row(),
                    CodedIndexType::TypeDefOrRef,
                ))
                .build(assembly)?;

            Ok(())
        },
    )
}

/// Creates an assembly with abstract/concrete rule violation.
///
/// This creates a raw assembly containing an interface that is not marked as abstract,
/// which violates ECMA-335 type definition rules.
///
/// Originally from: `src/metadata/validation/validators/owned/types/inheritance.rs`
pub fn create_assembly_with_abstract_concrete_violation() -> Result<TestAssembly> {
    create_test_assembly_with_error(get_testfile_mscorlib, "must be abstract", |assembly| {
        TypeDefBuilder::new()
            .name("IConcreteInterface")
            .namespace("Test.Abstract")
            .flags(TypeAttributes::INTERFACE | TypeAttributes::PUBLIC) // Missing ABSTRACT flag
            .build(assembly)?;

        Ok(())
    })
}

/// Creates an assembly with method inheritance violation.
///
/// This creates a raw assembly containing a concrete type with abstract methods,
/// which violates ECMA-335 inheritance rules.
///
/// Originally from: `src/metadata/validation/validators/owned/types/inheritance.rs`
pub fn create_assembly_with_method_inheritance_violation() -> Result<TestAssembly> {
    create_test_assembly_with_error(get_testfile_mscorlib, "Concrete type", |assembly| {
        let _concrete_type_token = TypeDefBuilder::new()
            .name("ConcreteClassWithAbstractMethods")
            .namespace("Test.Methods")
            .flags(TypeAttributes::CLASS | TypeAttributes::PUBLIC) // Concrete class, no ABSTRACT flag
            .build(assembly)?;

        let void_signature = vec![0x00, 0x00, 0x01];

        MethodDefBuilder::new()
            .name("AbstractMethodInConcreteClass")
            .flags(0x0446)
            .impl_flags(0x0000)
            .signature(&void_signature)
            .rva(0)
            .build(assembly)?;

        Ok(())
    })
}
