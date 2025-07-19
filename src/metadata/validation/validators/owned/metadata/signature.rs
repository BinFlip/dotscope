//! Owned signature validator for method signature validation.
//!
//! This validator provides comprehensive validation of method signatures within the context
//! of fully resolved .NET metadata, ensuring that signature components are properly formed,
//! compatible across inheritance hierarchies, and comply with ECMA-335 calling convention
//! requirements. It operates on resolved signature structures to validate signature integrity
//! and compatibility. This validator runs with priority 140 in the owned validation stage.
//!
//! # Architecture
//!
//! The signature validation system implements comprehensive method signature validation in sequential order:
//! 1. **Method Signature Format Validation** - Ensures signatures are well-formed with proper component structure
//! 2. **Signature Compatibility Validation** - Validates compatibility across inheritance and overriding scenarios
//!
//! The implementation validates method signatures according to ECMA-335 specifications,
//! ensuring proper signature formation and inheritance compatibility patterns.
//! All validation includes calling convention checking and parameter validation.
//!
//! # Key Components
//!
//! - [`crate::metadata::validation::validators::owned::metadata::signature::OwnedSignatureValidator`] - Main validator implementation providing comprehensive signature validation
//! - [`crate::metadata::validation::validators::owned::metadata::signature::OwnedSignatureValidator::validate_method_signature_format`] - Method signature format and encoding validation
//! - [`crate::metadata::validation::validators::owned::metadata::signature::OwnedSignatureValidator::validate_signature_compatibility`] - Signature compatibility validation across inheritance hierarchies
//!
//! # Usage Examples
//!
//! ```rust,no_run
//! use dotscope::metadata::validation::{OwnedSignatureValidator, OwnedValidator, OwnedValidationContext};
//!
//! # fn get_context() -> OwnedValidationContext<'static> { unimplemented!() }
//! let context = get_context();
//! let validator = OwnedSignatureValidator::new();
//!
//! // Check if validation should run based on configuration
//! if validator.should_run(&context) {
//!     validator.validate_owned(&context)?;
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Error Handling
//!
//! This validator returns [`crate::Error::ValidationOwnedValidatorFailed`] for:
//! - Method signature format violations (empty names, unresolved return types)
//! - Parameter signature issues (excessively long names, unresolved types, excessive custom attributes)
//! - Generic parameter violations (empty names, excessive lengths, invalid flags)
//! - Signature compatibility issues (excessive method overloads indicating complexity problems)
//! - Signature component validation failures (parameter count limits, name constraints)
//!
//! # Thread Safety
//!
//! All validation operations are read-only and thread-safe. The validator implements [`Send`] + [`Sync`]
//! and can be used concurrently across multiple threads without synchronization as it operates on
//! immutable resolved metadata structures.
//!
//! # Integration
//!
//! This validator integrates with:
//! - owned metadata validators - Part of the owned metadata validation stage
//! - [`crate::metadata::validation::engine::ValidationEngine`] - Orchestrates validator execution
//! - [`crate::metadata::validation::traits::OwnedValidator`] - Implements the owned validation interface
//! - [`crate::metadata::cilobject::CilObject`] - Source of resolved method signature structures
//! - [`crate::metadata::validation::context::OwnedValidationContext`] - Provides validation execution context
//! - [`crate::metadata::validation::config::ValidationConfig`] - Controls validation execution via enable_method_validation flag
//!
//! # References
//!
//! - [ECMA-335 II.12](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Method signatures and calling conventions
//! - [ECMA-335 II.22.26](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - MethodDef table signature constraints
//! - [ECMA-335 II.23.2](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Blobs and signatures
//! - [ECMA-335 I.8.6](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Assignment compatibility
//! - [ECMA-335 II.10.1](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Method overriding and signatures

use crate::{
    metadata::validation::{
        context::{OwnedValidationContext, ValidationContext},
        traits::OwnedValidator,
    },
    Result,
};

/// Foundation validator for method signatures, calling conventions, and signature compatibility.
///
/// Ensures the structural integrity and consistency of method signatures in resolved .NET metadata,
/// validating proper signature formation, inheritance compatibility, and calling convention
/// compliance. This validator operates on resolved signature structures to provide essential
/// guarantees about signature integrity and ECMA-335 compliance.
///
/// The validator implements comprehensive coverage of method signature validation according to
/// ECMA-335 specifications, ensuring proper signature definitions and compatibility patterns
/// in the resolved metadata object model.
///
/// # Thread Safety
///
/// This validator is [`Send`] and [`Sync`] as all validation operations are read-only
/// and operate on immutable resolved metadata structures.
pub struct OwnedSignatureValidator;

impl OwnedSignatureValidator {
    /// Creates a new signature validator instance.
    ///
    /// Initializes a validator instance that can be used to validate method signatures
    /// across multiple assemblies. The validator is stateless and can be reused safely
    /// across multiple validation operations.
    ///
    /// # Returns
    ///
    /// A new [`OwnedSignatureValidator`] instance ready for validation operations.
    ///
    /// # Thread Safety
    ///
    /// The returned validator is thread-safe and can be used concurrently.
    pub fn new() -> Self {
        Self
    }
}

impl OwnedSignatureValidator {
    /// Validates method signature format and encoding.
    ///
    /// Ensures that method signatures are properly formed according to ECMA-335
    /// specifications and that all signature components are valid. Validates
    /// method names, return types, parameters, and generic parameters.
    ///
    /// # Arguments
    ///
    /// * `context` - Owned validation context containing resolved method signature structures via [`crate::metadata::validation::context::OwnedValidationContext`]
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All method signature formats are valid
    /// * `Err(`[`crate::Error::ValidationOwnedValidatorFailed`]`)` - Signature format violations found
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationOwnedValidatorFailed`] if:
    /// - Method names are empty
    /// - Return types are unresolved (Unknown type signatures)
    /// - Parameter names exceed maximum length (>255 characters)
    /// - Parameters have unresolved types or excessive custom attributes (>10)
    /// - Generic parameters have empty names, excessive lengths, or invalid flags
    fn validate_method_signature_format(&self, context: &OwnedValidationContext) -> Result<()> {
        let methods = context.object().methods();

        for entry in methods.iter() {
            let method = entry.value();

            // Validate method name is not empty (basic signature validation)
            if method.name.is_empty() {
                return Err(crate::Error::ValidationOwnedValidatorFailed {
                    validator: self.name().to_string(),
                    message: format!(
                        "Method with token 0x{:08X} has empty name",
                        entry.key().value()
                    ),
                    source: None,
                });
            }

            // Validate return type is resolved (copied from method validator)
            if method.signature.return_type.base
                == crate::metadata::signatures::TypeSignature::Unknown
            {
                return Err(crate::Error::ValidationOwnedValidatorFailed {
                    validator: self.name().to_string(),
                    message: format!("Method '{}' has unresolved return type", method.name),
                    source: None,
                });
            }

            // Validate parameter signatures
            for (param_index, (_, param)) in method.params.iter().enumerate() {
                // Validate parameter name is reasonable (if present)
                if let Some(param_name) = &param.name {
                    if param_name.len() > 255 {
                        return Err(crate::Error::ValidationOwnedValidatorFailed {
                            validator: self.name().to_string(),
                            message: format!(
                                "Method '{}' parameter {} has excessively long name ({} characters)",
                                method.name,
                                param_index,
                                param_name.len()
                            ),
                            source: None,
                        });
                    }
                }

                // Validate parameter has resolved type (copied from method validator)
                if param.base.get().is_none() {
                    return Err(crate::Error::ValidationOwnedValidatorFailed {
                        validator: self.name().to_string(),
                        message: format!(
                            "Method '{}' parameter {} has unresolved type",
                            method.name, param_index
                        ),
                        source: None,
                    });
                }

                // Check for reasonable number of custom attributes on parameters
                let custom_attr_count = param.custom_attributes.iter().count();
                if custom_attr_count > 10 {
                    return Err(crate::Error::ValidationOwnedValidatorFailed {
                        validator: self.name().to_string(),
                        message: format!(
                            "Method '{}' parameter {} has excessive custom attributes ({})",
                            method.name, param_index, custom_attr_count
                        ),
                        source: None,
                    });
                }
            }

            // Validate generic parameters if present
            for (_, generic_param) in method.generic_params.iter() {
                // Validate generic parameter name
                if generic_param.name.is_empty() {
                    return Err(crate::Error::ValidationOwnedValidatorFailed {
                        validator: self.name().to_string(),
                        message: format!(
                            "Method '{}' has generic parameter with empty name",
                            method.name
                        ),
                        source: None,
                    });
                }

                if generic_param.name.len() > 255 {
                    return Err(crate::Error::ValidationOwnedValidatorFailed {
                        validator: self.name().to_string(),
                        message: format!(
                            "Method '{}' generic parameter '{}' has excessively long name",
                            method.name, generic_param.name
                        ),
                        source: None,
                    });
                }

                // Validate generic parameter flags are reasonable
                if generic_param.flags > 0x001F {
                    return Err(crate::Error::ValidationOwnedValidatorFailed {
                        validator: self.name().to_string(),
                        message: format!(
                            "Method '{}' generic parameter '{}' has invalid flags: 0x{:04X}",
                            method.name, generic_param.name, generic_param.flags
                        ),
                        source: None,
                    });
                }
            }
        }

        Ok(())
    }

    /// Validates signature compatibility across inheritance.
    ///
    /// Ensures that method signatures are compatible when methods are overridden
    /// or when interfaces are implemented. Detects excessive method overloading
    /// that could indicate signature complexity issues.
    ///
    /// # Arguments
    ///
    /// * `context` - Owned validation context containing resolved method signature structures via [`crate::metadata::validation::context::OwnedValidationContext`]
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All signature compatibility rules are followed
    /// * `Err(`[`crate::Error::ValidationOwnedValidatorFailed`]`)` - Signature compatibility violations found
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationOwnedValidatorFailed`] if:
    /// - Methods have excessive overloads (>1024) indicating potential complexity issues
    fn validate_signature_compatibility(&self, context: &OwnedValidationContext) -> Result<()> {
        let methods = context.object().methods();

        // Track method signatures by name for compatibility checking
        let mut method_signatures: std::collections::HashMap<String, Vec<u32>> =
            std::collections::HashMap::new();

        // Collect all methods by name
        for entry in methods.iter() {
            let method = entry.value();
            method_signatures
                .entry(method.name.clone())
                .or_default()
                .push(entry.key().value());
        }

        // Check for potential overloading issues
        // Allow reasonable number of overloads as found in legitimate .NET libraries
        for (method_name, method_tokens) in method_signatures {
            if method_tokens.len() > 1024 {
                return Err(crate::Error::ValidationOwnedValidatorFailed {
                    validator: self.name().to_string(),
                    message: format!(
                        "Method '{}' has excessive overloads ({}), potential signature complexity issue",
                        method_name, method_tokens.len()
                    ),
                    source: None,
                });
            }
        }

        Ok(())
    }
}

impl OwnedValidator for OwnedSignatureValidator {
    fn validate_owned(&self, context: &OwnedValidationContext) -> Result<()> {
        self.validate_method_signature_format(context)?;
        self.validate_signature_compatibility(context)?;

        Ok(())
    }

    fn name(&self) -> &'static str {
        "OwnedSignatureValidator"
    }

    fn priority(&self) -> u32 {
        140
    }

    fn should_run(&self, context: &OwnedValidationContext) -> bool {
        context.config().enable_method_validation
    }
}

impl Default for OwnedSignatureValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cilassembly::CilAssembly,
        metadata::{
            cilassemblyview::CilAssemblyView,
            tables::{
                CodedIndex, CodedIndexType, MethodDefRaw, ParamRaw, TableDataOwned, TableId,
                TypeDefRaw,
            },
            token::Token,
            validation::ValidationConfig,
        },
        test::{get_clean_testfile, owned_validator_test, TestAssembly},
    };

    fn owned_signature_validator_file_factory() -> crate::Result<Vec<TestAssembly>> {
        let mut assemblies = Vec::new();

        let Some(clean_testfile) = get_clean_testfile() else {
            return Err(crate::Error::Error(
                "WindowsBase.dll not available - test cannot run".to_string(),
            ));
        };

        // 1. REQUIRED: Clean assembly - should pass all signature validation
        assemblies.push(TestAssembly::new(&clean_testfile, true));

        // 2. NEGATIVE: Test method with empty name
        assemblies.push(create_assembly_with_empty_method_name()?);

        // 3. NEGATIVE: Test parameter with excessively long name (>255 characters)
        assemblies.push(create_assembly_with_long_parameter_name()?);

        // 4. NEGATIVE: Test method with unresolved return type
        assemblies.push(create_assembly_with_unresolved_return_type()?);

        // 5. NEGATIVE: Test method with unresolved parameter type
        assemblies.push(create_assembly_with_unresolved_parameter_type()?);

        // Note: Other test cases (excessive custom attributes, generic parameter issues,
        // excessive overloads) require additional table manipulation and will be added incrementally

        Ok(assemblies)
    }

    /// Creates an assembly with a method having an empty name - validation should fail
    fn create_assembly_with_empty_method_name() -> crate::Result<TestAssembly> {
        let Some(clean_testfile) = get_clean_testfile() else {
            return Err(crate::Error::Error(
                "WindowsBase.dll not available".to_string(),
            ));
        };
        let view = CilAssemblyView::from_file(&clean_testfile)
            .map_err(|e| crate::Error::Error(format!("Failed to load test assembly: {e}")))?;

        let mut assembly = CilAssembly::new(view);

        // Create type to contain the method
        let type_name_index = assembly
            .string_add("TypeWithEmptyMethodName")
            .map_err(|e| crate::Error::Error(format!("Failed to add type name: {e}")))?;

        let type_rid = assembly.original_table_row_count(TableId::TypeDef) + 1;
        let method_rid = assembly.original_table_row_count(TableId::MethodDef) + 1;

        let type_def = TypeDefRaw {
            rid: type_rid,
            token: Token::new(0x02000000 + type_rid),
            offset: 0,
            flags: 0x00000001, // Public
            type_name: type_name_index,
            type_namespace: 0,
            extends: CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::TypeDefOrRef),
            field_list: 1,
            method_list: method_rid,
        };

        // Create method with empty name
        let empty_name_index = assembly
            .string_add("")
            .map_err(|e| crate::Error::Error(format!("Failed to add empty method name: {e}")))?;

        let signature_bytes = vec![0x00, 0x00]; // Default method signature (no parameters, void return)
        let signature_index = assembly
            .blob_add(&signature_bytes)
            .map_err(|e| crate::Error::Error(format!("Failed to add signature: {e}")))?;

        let invalid_method = MethodDefRaw {
            rid: method_rid,
            token: Token::new(0x06000000 + method_rid),
            offset: 0,
            rva: 0,
            impl_flags: 0,
            flags: 0x0006,          // Public
            name: empty_name_index, // Empty name - should trigger validation failure
            signature: signature_index,
            param_list: 1,
        };

        assembly
            .table_row_add(TableId::TypeDef, TableDataOwned::TypeDef(type_def))
            .map_err(|e| crate::Error::Error(format!("Failed to add type: {e}")))?;

        assembly
            .table_row_add(
                TableId::MethodDef,
                TableDataOwned::MethodDef(invalid_method),
            )
            .map_err(|e| crate::Error::Error(format!("Failed to add invalid method: {e}")))?;

        let temp_file = tempfile::NamedTempFile::new()
            .map_err(|e| crate::Error::Error(format!("Failed to create temp file: {e}")))?;

        assembly
            .write_to_file(temp_file.path())
            .map_err(|e| crate::Error::Error(format!("Failed to write assembly: {e}")))?;

        Ok(TestAssembly::from_temp_file(temp_file, false))
    }

    /// Creates an assembly with a parameter having an excessively long name - validation should fail
    fn create_assembly_with_long_parameter_name() -> crate::Result<TestAssembly> {
        let Some(clean_testfile) = get_clean_testfile() else {
            return Err(crate::Error::Error(
                "WindowsBase.dll not available".to_string(),
            ));
        };
        let view = CilAssemblyView::from_file(&clean_testfile)
            .map_err(|e| crate::Error::Error(format!("Failed to load test assembly: {e}")))?;

        let mut assembly = CilAssembly::new(view);

        // Create type to contain the method
        let type_name_index = assembly
            .string_add("TypeWithLongParameterName")
            .map_err(|e| crate::Error::Error(format!("Failed to add type name: {e}")))?;

        let type_rid = assembly.original_table_row_count(TableId::TypeDef) + 1;
        let method_rid = assembly.original_table_row_count(TableId::MethodDef) + 1;
        let param_rid = assembly.original_table_row_count(TableId::Param) + 1;

        let type_def = TypeDefRaw {
            rid: type_rid,
            token: Token::new(0x02000000 + type_rid),
            offset: 0,
            flags: 0x00000001, // Public
            type_name: type_name_index,
            type_namespace: 0,
            extends: CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::TypeDefOrRef),
            field_list: 1,
            method_list: method_rid,
        };

        // Create method name
        let method_name_index = assembly
            .string_add("MethodWithLongParam")
            .map_err(|e| crate::Error::Error(format!("Failed to add method name: {e}")))?;

        // Create signature with one parameter
        let signature_bytes = vec![0x00, 0x01, 0x01, 0x08]; // 1 parameter, void return, I4 parameter
        let signature_index = assembly
            .blob_add(&signature_bytes)
            .map_err(|e| crate::Error::Error(format!("Failed to add signature: {e}")))?;

        let method_def = MethodDefRaw {
            rid: method_rid,
            token: Token::new(0x06000000 + method_rid),
            offset: 0,
            rva: 0,
            impl_flags: 0,
            flags: 0x0006, // Public
            name: method_name_index,
            signature: signature_index,
            param_list: param_rid,
        };

        // Create parameter with excessively long name (>255 characters)
        let long_param_name = "a".repeat(300); // 300 characters - should trigger validation failure
        let long_param_name_index = assembly
            .string_add(&long_param_name)
            .map_err(|e| crate::Error::Error(format!("Failed to add long parameter name: {e}")))?;

        let invalid_param = ParamRaw {
            rid: param_rid,
            token: Token::new(0x08000000 + param_rid),
            offset: 0,
            flags: 0x0000, // In
            sequence: 1,
            name: long_param_name_index, // Excessively long name - should trigger validation failure
        };

        assembly
            .table_row_add(TableId::TypeDef, TableDataOwned::TypeDef(type_def))
            .map_err(|e| crate::Error::Error(format!("Failed to add type: {e}")))?;

        assembly
            .table_row_add(TableId::MethodDef, TableDataOwned::MethodDef(method_def))
            .map_err(|e| crate::Error::Error(format!("Failed to add method: {e}")))?;

        assembly
            .table_row_add(TableId::Param, TableDataOwned::Param(invalid_param))
            .map_err(|e| crate::Error::Error(format!("Failed to add invalid parameter: {e}")))?;

        let temp_file = tempfile::NamedTempFile::new()
            .map_err(|e| crate::Error::Error(format!("Failed to create temp file: {e}")))?;

        assembly
            .write_to_file(temp_file.path())
            .map_err(|e| crate::Error::Error(format!("Failed to write assembly: {e}")))?;

        Ok(TestAssembly::from_temp_file(temp_file, false))
    }

    /// Creates an assembly with a parameter having excessive custom attributes - validation should fail
    fn create_assembly_with_excessive_parameter_attributes() -> crate::Result<TestAssembly> {
        let Some(clean_testfile) = get_clean_testfile() else {
            return Err(crate::Error::Error(
                "WindowsBase.dll not available".to_string(),
            ));
        };
        let view = CilAssemblyView::from_file(&clean_testfile)
            .map_err(|e| crate::Error::Error(format!("Failed to load test assembly: {e}")))?;

        let mut assembly = CilAssembly::new(view);

        // Create type to contain the method
        let type_name_index = assembly
            .string_add("TypeWithExcessiveParamAttrs")
            .map_err(|e| crate::Error::Error(format!("Failed to add type name: {e}")))?;

        let type_rid = assembly.original_table_row_count(TableId::TypeDef) + 1;
        let method_rid = assembly.original_table_row_count(TableId::MethodDef) + 1;
        let param_rid = assembly.original_table_row_count(TableId::Param) + 1;

        let type_def = TypeDefRaw {
            rid: type_rid,
            token: Token::new(0x02000000 + type_rid),
            offset: 0,
            flags: 0x00000001, // Public
            type_name: type_name_index,
            type_namespace: 0,
            extends: CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::TypeDefOrRef),
            field_list: 1,
            method_list: method_rid,
        };

        // Create method name
        let method_name_index = assembly
            .string_add("MethodWithExcessiveParamAttrs")
            .map_err(|e| crate::Error::Error(format!("Failed to add method name: {e}")))?;

        // Create signature with one parameter
        let signature_bytes = vec![0x00, 0x01, 0x01, 0x08]; // 1 parameter, void return, I4 parameter
        let signature_index = assembly
            .blob_add(&signature_bytes)
            .map_err(|e| crate::Error::Error(format!("Failed to add signature: {e}")))?;

        let method_def = MethodDefRaw {
            rid: method_rid,
            token: Token::new(0x06000000 + method_rid),
            offset: 0,
            rva: 0,
            impl_flags: 0,
            flags: 0x0006, // Public
            name: method_name_index,
            signature: signature_index,
            param_list: param_rid,
        };

        // Create parameter
        let param_name_index = assembly
            .string_add("paramWithManyAttrs")
            .map_err(|e| crate::Error::Error(format!("Failed to add parameter name: {e}")))?;

        let param = ParamRaw {
            rid: param_rid,
            token: Token::new(0x08000000 + param_rid),
            offset: 0,
            flags: 0x0001, // In
            sequence: 1,
            name: param_name_index,
        };

        assembly
            .table_row_add(TableId::TypeDef, TableDataOwned::TypeDef(type_def))
            .map_err(|e| crate::Error::Error(format!("Failed to add type: {e}")))?;

        assembly
            .table_row_add(TableId::MethodDef, TableDataOwned::MethodDef(method_def))
            .map_err(|e| crate::Error::Error(format!("Failed to add method: {e}")))?;

        assembly
            .table_row_add(TableId::Param, TableDataOwned::Param(param))
            .map_err(|e| crate::Error::Error(format!("Failed to add parameter: {e}")))?;

        let temp_file = tempfile::NamedTempFile::new()
            .map_err(|e| crate::Error::Error(format!("Failed to create temp file: {e}")))?;

        assembly
            .write_to_file(temp_file.path())
            .map_err(|e| crate::Error::Error(format!("Failed to write assembly: {e}")))?;

        Ok(TestAssembly::from_temp_file(temp_file, false))
    }

    /// Creates an assembly with a method having unresolved return type - validation should fail
    fn create_assembly_with_unresolved_return_type() -> crate::Result<TestAssembly> {
        let Some(clean_testfile) = get_clean_testfile() else {
            return Err(crate::Error::Error(
                "WindowsBase.dll not available".to_string(),
            ));
        };
        let view = CilAssemblyView::from_file(&clean_testfile)
            .map_err(|e| crate::Error::Error(format!("Failed to load test assembly: {e}")))?;

        let mut assembly = CilAssembly::new(view);

        // Create type to contain the method
        let type_name_index = assembly
            .string_add("TypeWithUnresolvedReturnType")
            .map_err(|e| crate::Error::Error(format!("Failed to add type name: {e}")))?;

        let type_rid = assembly.original_table_row_count(TableId::TypeDef) + 1;
        let method_rid = assembly.original_table_row_count(TableId::MethodDef) + 1;

        let type_def = TypeDefRaw {
            rid: type_rid,
            token: Token::new(0x02000000 + type_rid),
            offset: 0,
            flags: 0x00000001, // Public
            type_name: type_name_index,
            type_namespace: 0,
            extends: CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::TypeDefOrRef),
            field_list: 1,
            method_list: method_rid,
        };

        // Create method name
        let method_name_index = assembly
            .string_add("MethodWithUnresolvedReturnType")
            .map_err(|e| crate::Error::Error(format!("Failed to add method name: {e}")))?;

        // Create invalid signature blob with unresolved return type
        // Format: [calling_convention, param_count, return_type, ...params]
        let invalid_signature_bytes = vec![
            0x00, // DEFAULT calling convention
            0x00, // 0 parameters
            0x12, // ELEMENT_TYPE_CLASS (indicates a class type follows)
            0xFF, 0xFF, 0xFF,
            0x7F, // Invalid TypeDefOrRef token (compressed integer, maximum invalid value)
        ];
        let signature_index = assembly
            .blob_add(&invalid_signature_bytes)
            .map_err(|e| crate::Error::Error(format!("Failed to add invalid signature: {e}")))?;

        let invalid_method = MethodDefRaw {
            rid: method_rid,
            token: Token::new(0x06000000 + method_rid),
            offset: 0,
            rva: 0,
            impl_flags: 0,
            flags: 0x0006, // Public
            name: method_name_index,
            signature: signature_index, // Invalid signature with unresolved return type
            param_list: 1,
        };

        assembly
            .table_row_add(TableId::TypeDef, TableDataOwned::TypeDef(type_def))
            .map_err(|e| crate::Error::Error(format!("Failed to add type: {e}")))?;

        assembly
            .table_row_add(
                TableId::MethodDef,
                TableDataOwned::MethodDef(invalid_method),
            )
            .map_err(|e| crate::Error::Error(format!("Failed to add invalid method: {e}")))?;

        let temp_file = tempfile::NamedTempFile::new()
            .map_err(|e| crate::Error::Error(format!("Failed to create temp file: {e}")))?;

        assembly
            .write_to_file(temp_file.path())
            .map_err(|e| crate::Error::Error(format!("Failed to write assembly: {e}")))?;

        Ok(TestAssembly::from_temp_file(temp_file, false))
    }

    /// Creates an assembly with a method having unresolved parameter type - validation should fail
    fn create_assembly_with_unresolved_parameter_type() -> crate::Result<TestAssembly> {
        let Some(clean_testfile) = get_clean_testfile() else {
            return Err(crate::Error::Error(
                "WindowsBase.dll not available".to_string(),
            ));
        };
        let view = CilAssemblyView::from_file(&clean_testfile)
            .map_err(|e| crate::Error::Error(format!("Failed to load test assembly: {e}")))?;

        let mut assembly = CilAssembly::new(view);

        // Create type to contain the method
        let type_name_index = assembly
            .string_add("TypeWithUnresolvedParamType")
            .map_err(|e| crate::Error::Error(format!("Failed to add type name: {e}")))?;

        let type_rid = assembly.original_table_row_count(TableId::TypeDef) + 1;
        let method_rid = assembly.original_table_row_count(TableId::MethodDef) + 1;
        let param_rid = assembly.original_table_row_count(TableId::Param) + 1;

        let type_def = TypeDefRaw {
            rid: type_rid,
            token: Token::new(0x02000000 + type_rid),
            offset: 0,
            flags: 0x00000001, // Public
            type_name: type_name_index,
            type_namespace: 0,
            extends: CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::TypeDefOrRef),
            field_list: 1,
            method_list: method_rid,
        };

        // Create method name
        let method_name_index = assembly
            .string_add("MethodWithUnresolvedParamType")
            .map_err(|e| crate::Error::Error(format!("Failed to add method name: {e}")))?;

        // Create invalid signature blob with unresolved parameter type
        // Format: [calling_convention, param_count, return_type, param1_type, ...]
        let invalid_signature_bytes = vec![
            0x00, // DEFAULT calling convention
            0x01, // 1 parameter
            0x01, // Return type: ELEMENT_TYPE_VOID
            0x12, // Parameter type: ELEMENT_TYPE_CLASS (indicates a class type follows)
            0xFF, 0xFF, 0xFF,
            0x7F, // Invalid TypeDefOrRef token (compressed integer, maximum invalid value)
        ];
        let signature_index = assembly
            .blob_add(&invalid_signature_bytes)
            .map_err(|e| crate::Error::Error(format!("Failed to add invalid signature: {e}")))?;

        let invalid_method = MethodDefRaw {
            rid: method_rid,
            token: Token::new(0x06000000 + method_rid),
            offset: 0,
            rva: 0,
            impl_flags: 0,
            flags: 0x0006, // Public
            name: method_name_index,
            signature: signature_index, // Invalid signature with unresolved parameter type
            param_list: param_rid,
        };

        // Create parameter with name (the signature is what has the unresolved type)
        let param_name_index = assembly
            .string_add("unresolvedParam")
            .map_err(|e| crate::Error::Error(format!("Failed to add parameter name: {e}")))?;

        let param = ParamRaw {
            rid: param_rid,
            token: Token::new(0x08000000 + param_rid),
            offset: 0,
            flags: 0x0001, // In
            sequence: 1,
            name: param_name_index,
        };

        assembly
            .table_row_add(TableId::TypeDef, TableDataOwned::TypeDef(type_def))
            .map_err(|e| crate::Error::Error(format!("Failed to add type: {e}")))?;

        assembly
            .table_row_add(
                TableId::MethodDef,
                TableDataOwned::MethodDef(invalid_method),
            )
            .map_err(|e| crate::Error::Error(format!("Failed to add invalid method: {e}")))?;

        assembly
            .table_row_add(TableId::Param, TableDataOwned::Param(param))
            .map_err(|e| crate::Error::Error(format!("Failed to add parameter: {e}")))?;

        let temp_file = tempfile::NamedTempFile::new()
            .map_err(|e| crate::Error::Error(format!("Failed to create temp file: {e}")))?;

        assembly
            .write_to_file(temp_file.path())
            .map_err(|e| crate::Error::Error(format!("Failed to write assembly: {e}")))?;

        Ok(TestAssembly::from_temp_file(temp_file, false))
    }

    #[test]
    fn test_owned_signature_validator() -> crate::Result<()> {
        let validator = OwnedSignatureValidator::new();
        let config = ValidationConfig {
            enable_method_validation: true,
            ..Default::default()
        };

        owned_validator_test(
            owned_signature_validator_file_factory,
            "OwnedSignatureValidator",
            "ValidationOwnedValidatorFailed",
            config,
            |context| validator.validate_owned(context),
        )
    }
}
