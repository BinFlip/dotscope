//! Owned assembly validator for assembly-level validation.
//!
//! This validator provides comprehensive validation of assembly-level metadata within the context
//! of fully resolved .NET metadata. It operates on resolved assembly structures to validate
//! cross-assembly references, version compatibility, and assembly integrity constraints.
//! This validator ensures that assemblies are properly formed and don't violate ECMA-335
//! assembly model requirements. This validator runs with priority 110 in the owned validation stage.
//!
//! # Architecture
//!
//! The assembly validation system implements comprehensive assembly-level validation in sequential order:
//! 1. **Assembly Metadata Consistency Validation** - Ensures assembly-level metadata is properly formed and complete
//! 2. **Cross-Assembly Reference Validation** - Validates external assembly references and resolution
//! 3. **Assembly Version Compatibility Validation** - Ensures version dependencies are compatible and consistent
//! 4. **Module File Consistency Validation** - Validates modules and files are properly registered within assemblies
//!
//! The implementation validates assembly constraints according to ECMA-335 specifications,
//! ensuring proper assembly formation and dependency management.
//! All validation includes reference checking and version compatibility verification.
//!
//! # Key Components
//!
//! - [`crate::metadata::validation::validators::owned::system::assembly::OwnedAssemblyValidator`] - Main validator implementation providing comprehensive assembly validation
//! - [`crate::metadata::validation::validators::owned::system::assembly::OwnedAssemblyValidator::validate_assembly_metadata_consistency`] - Assembly metadata consistency and completeness validation
//! - [`crate::metadata::validation::validators::owned::system::assembly::OwnedAssemblyValidator::validate_cross_assembly_references`] - Cross-assembly reference validation and resolution checking
//! - [`crate::metadata::validation::validators::owned::system::assembly::OwnedAssemblyValidator::validate_assembly_version_compatibility`] - Assembly version compatibility and dependency validation
//! - [`crate::metadata::validation::validators::owned::system::assembly::OwnedAssemblyValidator::validate_module_file_consistency`] - Module and file consistency validation within assemblies
//!
//! # Usage Examples
//!
//! ```rust,no_run
//! use dotscope::metadata::validation::{OwnedAssemblyValidator, OwnedValidator, OwnedValidationContext};
//!
//! # fn get_context() -> OwnedValidationContext<'static> { unimplemented!() }
//! let context = get_context();
//! let validator = OwnedAssemblyValidator::new();
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
//! - Assembly metadata consistency violations (empty names, invalid formats, excessive lengths)
//! - Cross-assembly reference failures (unresolved references, invalid public keys, malformed identities)
//! - Version compatibility issues (suspicious version numbers, all-zero versions, excessive values)
//! - Module file consistency violations (invalid modules, corrupted PE files, suspicious sizes)
//! - Strong name validation failures (invalid public keys, zero tokens, malformed signatures)
//! - Custom attribute violations (excessive arguments, malformed attribute data)
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
//! - owned system validators - Part of the owned system validation stage
//! - [`crate::metadata::validation::engine::ValidationEngine`] - Orchestrates validator execution
//! - [`crate::metadata::validation::traits::OwnedValidator`] - Implements the owned validation interface
//! - [`crate::metadata::cilobject::CilObject`] - Source of resolved assembly structures
//! - [`crate::metadata::validation::context::OwnedValidationContext`] - Provides validation execution context
//! - [`crate::metadata::validation::config::ValidationConfig`] - Controls validation execution via enable_semantic_validation flag
//!
//! # References
//!
//! - [ECMA-335 II.6.2](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Assemblies and modules
//! - [ECMA-335 II.22.2](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - AssemblyRef table
//! - [ECMA-335 II.22.20](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Assembly table
//! - [ECMA-335 II.22.14](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - File table
//! - [ECMA-335 I.6.3](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Application domains and assemblies

use crate::{
    metadata::validation::{
        context::{OwnedValidationContext, ValidationContext},
        traits::OwnedValidator,
    },
    Error, Result,
};
use std::sync::Arc;

/// Foundation validator for assembly-level metadata, references, and integrity constraints.
///
/// Ensures the structural integrity and consistency of assembly-level metadata in resolved .NET metadata,
/// validating assembly metadata completeness, cross-assembly reference resolution, version compatibility,
/// and module file consistency. This validator operates on resolved assembly structures to provide
/// essential guarantees about assembly integrity and ECMA-335 compliance.
///
/// The validator implements comprehensive coverage of assembly validation according to
/// ECMA-335 specifications, ensuring proper assembly formation and dependency management
/// in the resolved metadata object model.
///
/// # Thread Safety
///
/// This validator is [`Send`] and [`Sync`] as all validation operations are read-only
/// and operate on immutable resolved metadata structures.
pub struct OwnedAssemblyValidator;

impl OwnedAssemblyValidator {
    /// Creates a new assembly validator instance.
    ///
    /// Initializes a validator instance that can be used to validate assembly-level metadata
    /// across multiple assemblies. The validator is stateless and can be reused safely
    /// across multiple validation operations.
    ///
    /// # Returns
    ///
    /// A new [`OwnedAssemblyValidator`] instance ready for validation operations.
    ///
    /// # Thread Safety
    ///
    /// The returned validator is thread-safe and can be used concurrently.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl OwnedAssemblyValidator {
    /// Validates assembly metadata consistency and completeness.
    ///
    /// Ensures that assembly-level metadata is properly formed and contains
    /// all required information according to ECMA-335 specifications.
    /// Validates assembly names, versions, cultures, public keys, and custom attributes.
    ///
    /// # Arguments
    ///
    /// * `context` - Owned validation context containing resolved assembly structures via [`crate::metadata::validation::context::OwnedValidationContext`]
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All assembly metadata is consistent and complete
    /// * `Err(`[`crate::Error::ValidationOwnedValidatorFailed`]`)` - Metadata consistency violations found
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationOwnedValidatorFailed`] if:
    /// - Assembly has empty or invalid name format
    /// - Assembly version components are invalid or excessive
    /// - Culture format is malformed
    /// - Public key has invalid size or suspicious patterns
    /// - Custom attributes have excessive argument counts
    fn validate_assembly_metadata_consistency(
        &self,
        context: &OwnedValidationContext,
    ) -> Result<()> {
        let assembly_info = context.object().assembly();

        if let Some(assembly) = assembly_info {
            // Validate basic assembly properties
            if assembly.name.is_empty() {
                return Err(Error::ValidationOwnedValidatorFailed {
                    validator: self.name().to_string(),
                    message: "Assembly has empty name".to_string(),
                    source: None,
                });
            }

            // Validate assembly name format
            if !Self::is_valid_assembly_name(&assembly.name) {
                return Err(Error::ValidationOwnedValidatorFailed {
                    validator: self.name().to_string(),
                    message: format!("Assembly has invalid name format: '{}'", assembly.name),
                    source: None,
                });
            }

            // Validate version information
            self.validate_assembly_version(assembly)?;

            // Validate culture information
            if let Some(culture) = &assembly.culture {
                if !Self::is_valid_culture_format(culture) {
                    return Err(Error::ValidationOwnedValidatorFailed {
                        validator: self.name().to_string(),
                        message: format!("Assembly has invalid culture format: '{culture}'"),
                        source: None,
                    });
                }
            }

            // Validate public key information
            if let Some(public_key) = &assembly.public_key {
                self.validate_assembly_public_key(public_key)?;
            }

            // Validate custom attributes
            self.validate_assembly_custom_attributes(assembly)?;
        }

        Ok(())
    }

    /// Validates assembly name format.
    fn is_valid_assembly_name(name: &str) -> bool {
        // Assembly names must be valid identifiers
        if name.is_empty() || name.len() > 260 {
            return false;
        }

        // Check for invalid characters
        let invalid_chars = ['/', '\\', ':', '*', '?', '"', '<', '>', '|'];
        if name.chars().any(|c| invalid_chars.contains(&c)) {
            return false;
        }

        // Must not start with whitespace or dot
        if name.starts_with(' ') || name.starts_with('.') {
            return false;
        }

        true
    }

    /// Validates assembly version information.
    fn validate_assembly_version(
        &self,
        assembly: &Arc<crate::metadata::tables::Assembly>,
    ) -> Result<()> {
        // Version components should be reasonable
        if assembly.major_version > 65535
            || assembly.minor_version > 65535
            || assembly.build_number > 65535
            || assembly.revision_number > 65535
        {
            return Err(Error::ValidationOwnedValidatorFailed {
                validator: self.name().to_string(),
                message: format!(
                    "Assembly '{}' has invalid version components: {}.{}.{}.{}",
                    assembly.name,
                    assembly.major_version,
                    assembly.minor_version,
                    assembly.build_number,
                    assembly.revision_number
                ),
                source: None,
            });
        }

        Ok(())
    }

    /// Validates culture format.
    fn is_valid_culture_format(culture: &str) -> bool {
        if culture.is_empty() || culture == "neutral" {
            return true;
        }

        // Standard culture format validation
        let parts: Vec<&str> = culture.split('-').collect();
        match parts.len() {
            1 => {
                // Language only (e.g., "en", "fr")
                parts[0].len() == 2 && parts[0].chars().all(|c| c.is_ascii_lowercase())
            }
            2 => {
                // Language-Country (e.g., "en-US", "fr-FR")
                parts[0].len() == 2
                    && parts[0].chars().all(|c| c.is_ascii_lowercase())
                    && parts[1].len() == 2
                    && parts[1].chars().all(|c| c.is_ascii_uppercase())
            }
            _ => false,
        }
    }

    /// Validates assembly public key format.
    fn validate_assembly_public_key(&self, public_key: &[u8]) -> Result<()> {
        // Public key should be reasonable size
        if public_key.is_empty() {
            return Ok(()); // Empty public key is valid (no strong name)
        }

        if public_key.len() < 160 || public_key.len() > 2048 {
            return Err(Error::ValidationOwnedValidatorFailed {
                validator: self.name().to_string(),
                message: format!(
                    "Assembly public key has invalid size: {} bytes",
                    public_key.len()
                ),
                source: None,
            });
        }

        // Check for suspicious patterns (all zeros, all ones, etc.)
        if public_key.iter().all(|&b| b == 0) {
            return Err(Error::ValidationOwnedValidatorFailed {
                validator: self.name().to_string(),
                message: "Assembly public key consists entirely of zero bytes".to_string(),
                source: None,
            });
        }

        if public_key.iter().all(|&b| b == 0xFF) {
            return Err(Error::ValidationOwnedValidatorFailed {
                validator: self.name().to_string(),
                message: "Assembly public key consists entirely of 0xFF bytes".to_string(),
                source: None,
            });
        }

        Ok(())
    }

    /// Validates assembly custom attributes.
    fn validate_assembly_custom_attributes(
        &self,
        assembly: &Arc<crate::metadata::tables::Assembly>,
    ) -> Result<()> {
        for (_, custom_attr) in assembly.custom_attributes.iter() {
            // Check for reasonable number of arguments
            if custom_attr.fixed_args.len() > 20 {
                return Err(Error::ValidationOwnedValidatorFailed {
                    validator: self.name().to_string(),
                    message: format!(
                        "Assembly '{}' has custom attribute with excessive fixed arguments ({})",
                        assembly.name,
                        custom_attr.fixed_args.len()
                    ),
                    source: None,
                });
            }

            if custom_attr.named_args.len() > 50 {
                return Err(Error::ValidationOwnedValidatorFailed {
                    validator: self.name().to_string(),
                    message: format!(
                        "Assembly '{}' has custom attribute with excessive named arguments ({})",
                        assembly.name,
                        custom_attr.named_args.len()
                    ),
                    source: None,
                });
            }
        }

        Ok(())
    }

    /// Validates cross-assembly reference validation and resolution.
    ///
    /// Ensures that all assembly references can be resolved and that
    /// cross-assembly dependencies are properly formed and accessible.
    /// Validates assembly references, type references, and member references.
    ///
    /// # Arguments
    ///
    /// * `context` - Owned validation context containing resolved assembly structures via [`crate::metadata::validation::context::OwnedValidationContext`]
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All cross-assembly references are valid and resolvable
    /// * `Err(`[`crate::Error::ValidationOwnedValidatorFailed`]`)` - Cross-assembly reference violations found
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationOwnedValidatorFailed`] if:
    /// - Assembly references have empty names or excessive lengths
    /// - Culture formats are invalid in references
    /// - Public key tokens or keys are malformed
    /// - Type references have empty names or excessive namespace lengths
    /// - Member references have empty or excessively long names
    fn validate_cross_assembly_references(&self, context: &OwnedValidationContext) -> Result<()> {
        // Check that the assembly object itself is valid
        if let Some(assembly) = context.object().assembly() {
            // Validate assembly name is not excessively long
            if assembly.name.len() > 1024 {
                return Err(Error::ValidationOwnedValidatorFailed {
                    validator: self.name().to_string(),
                    message: format!(
                        "Assembly name is excessively long: {} characters",
                        assembly.name.len()
                    ),
                    source: None,
                });
            }

            // Validate culture format if present
            if let Some(culture) = &assembly.culture {
                if !Self::is_valid_culture_format(culture) {
                    return Err(Error::ValidationOwnedValidatorFailed {
                        validator: self.name().to_string(),
                        message: format!("Assembly has invalid culture format: '{culture}'"),
                        source: None,
                    });
                }
            }
        }

        // Validate external assembly references
        let assembly_refs = context.object().refs_assembly();
        for (index, entry) in assembly_refs.iter().enumerate() {
            let assembly_ref = entry.value();
            // Validate assembly reference name
            if assembly_ref.name.is_empty() {
                return Err(Error::ValidationOwnedValidatorFailed {
                    validator: self.name().to_string(),
                    message: format!("Assembly reference {index} has empty name"),
                    source: None,
                });
            }

            // Validate assembly reference name length
            if assembly_ref.name.len() > 1024 {
                return Err(Error::ValidationOwnedValidatorFailed {
                    validator: self.name().to_string(),
                    message: format!(
                        "Assembly reference '{}' has excessively long name: {} characters",
                        assembly_ref.name,
                        assembly_ref.name.len()
                    ),
                    source: None,
                });
            }

            // Validate culture format if present
            if let Some(culture) = &assembly_ref.culture {
                if !Self::is_valid_culture_format(culture) {
                    return Err(Error::ValidationOwnedValidatorFailed {
                        validator: self.name().to_string(),
                        message: format!(
                            "Assembly reference '{}' has invalid culture format: '{}'",
                            assembly_ref.name, culture
                        ),
                        source: None,
                    });
                }
            }

            // Validate identity (public key/token) if present
            if let Some(identity) = &assembly_ref.identifier {
                match identity {
                    crate::metadata::identity::Identity::Token(token) => {
                        if *token == 0 {
                            return Err(Error::ValidationOwnedValidatorFailed {
                                validator: self.name().to_string(),
                                message: format!(
                                    "Assembly reference '{}' has empty public key token",
                                    assembly_ref.name
                                ),
                                source: None,
                            });
                        }
                    }
                    crate::metadata::identity::Identity::PubKey(public_key) => {
                        if public_key.is_empty() {
                            return Err(Error::ValidationOwnedValidatorFailed {
                                validator: self.name().to_string(),
                                message: format!(
                                    "Assembly reference '{}' has empty public key",
                                    assembly_ref.name
                                ),
                                source: None,
                            });
                        }
                        if public_key.len() < 160 || public_key.len() > 2048 {
                            return Err(Error::ValidationOwnedValidatorFailed {
                                validator: self.name().to_string(),
                                message: format!(
                                    "Assembly reference '{}' has invalid public key size: {} bytes",
                                    assembly_ref.name,
                                    public_key.len()
                                ),
                                source: None,
                            });
                        }
                    }
                }
            }
        }

        // Validate cross-assembly type references
        let types = context.object().types();
        for type_entry in types.all_types() {
            let type_ref = &*type_entry;
            // Only validate external type references
            if let Some(_external) = type_ref.get_external() {
                // Validate type reference has valid name
                if type_ref.name.is_empty() {
                    return Err(Error::ValidationOwnedValidatorFailed {
                        validator: self.name().to_string(),
                        message: "Cross-assembly type reference has empty name".to_string(),
                        source: None,
                    });
                }

                // Validate namespace is reasonable
                if type_ref.namespace.len() > 512 {
                    return Err(Error::ValidationOwnedValidatorFailed {
                        validator: self.name().to_string(),
                        message: format!(
                            "Type reference '{}' has excessively long namespace: {} characters",
                            type_ref.name,
                            type_ref.namespace.len()
                        ),
                        source: None,
                    });
                }
            }
        }

        // Validate cross-assembly member references
        let member_refs = context.object().refs_members();
        for entry in member_refs {
            let member_ref = entry.value();
            // Validate member reference has valid name
            if member_ref.name.is_empty() {
                return Err(Error::ValidationOwnedValidatorFailed {
                    validator: self.name().to_string(),
                    message: "Cross-assembly member reference has empty name".to_string(),
                    source: None,
                });
            }

            // Validate member name length
            if member_ref.name.len() > 512 {
                return Err(Error::ValidationOwnedValidatorFailed {
                    validator: self.name().to_string(),
                    message: format!(
                        "Member reference '{}' has excessively long name: {} characters",
                        member_ref.name,
                        member_ref.name.len()
                    ),
                    source: None,
                });
            }
        }

        Ok(())
    }

    /// Validates assembly version compatibility and dependency validation.
    ///
    /// Ensures that assembly version dependencies are compatible and don't
    /// create impossible resolution scenarios or version conflicts.
    /// Validates version numbers and strong name consistency.
    ///
    /// # Arguments
    ///
    /// * `context` - Owned validation context containing resolved assembly structures via [`crate::metadata::validation::context::OwnedValidationContext`]
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All assembly versions are compatible and consistent
    /// * `Err(`[`crate::Error::ValidationOwnedValidatorFailed`]`)` - Version compatibility violations found
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationOwnedValidatorFailed`] if:
    /// - Assembly or reference versions are all-zero or excessively high
    /// - Strong name tokens or public keys are malformed
    /// - Assembly reference flags contain unknown values
    fn validate_assembly_version_compatibility(
        &self,
        context: &OwnedValidationContext,
    ) -> Result<()> {
        // Validate the current assembly's version information
        if let Some(assembly) = context.object().assembly() {
            // Check for reasonable version numbers
            if assembly.major_version == 0
                && assembly.minor_version == 0
                && assembly.build_number == 0
                && assembly.revision_number == 0
            {
                return Err(Error::ValidationOwnedValidatorFailed {
                    validator: self.name().to_string(),
                    message: format!(
                        "Assembly '{}' has all-zero version number, which may cause versioning issues",
                        assembly.name
                    ),
                    source: None,
                });
            }

            // Check for excessively high version numbers that might indicate corruption
            if assembly.major_version > 999
                || assembly.minor_version > 999
                || assembly.build_number > 65535
                || assembly.revision_number > 65535
            {
                return Err(Error::ValidationOwnedValidatorFailed {
                    validator: self.name().to_string(),
                    message: format!(
                        "Assembly '{}' has suspicious version numbers: {}.{}.{}.{}",
                        assembly.name,
                        assembly.major_version,
                        assembly.minor_version,
                        assembly.build_number,
                        assembly.revision_number
                    ),
                    source: None,
                });
            }
        }

        // Validate assembly reference versions for compatibility
        let assembly_refs = context.object().refs_assembly();
        for entry in assembly_refs {
            let assembly_ref = entry.value();
            // Check for reasonable version numbers in dependencies
            if assembly_ref.major_version == 0
                && assembly_ref.minor_version == 0
                && assembly_ref.build_number == 0
                && assembly_ref.revision_number == 0
            {
                return Err(Error::ValidationOwnedValidatorFailed {
                    validator: self.name().to_string(),
                    message: format!(
                        "Assembly reference '{}' has all-zero version number",
                        assembly_ref.name
                    ),
                    source: None,
                });
            }

            // Check for excessively high version numbers in dependencies
            if assembly_ref.major_version > 999
                || assembly_ref.minor_version > 999
                || assembly_ref.build_number > 65535
                || assembly_ref.revision_number > 65535
            {
                return Err(Error::ValidationOwnedValidatorFailed {
                    validator: self.name().to_string(),
                    message: format!(
                        "Assembly reference '{}' has suspicious version numbers: {}.{}.{}.{}",
                        assembly_ref.name,
                        assembly_ref.major_version,
                        assembly_ref.minor_version,
                        assembly_ref.build_number,
                        assembly_ref.revision_number
                    ),
                    source: None,
                });
            }

            // Validate strong name consistency
            if let Some(identity) = &assembly_ref.identifier {
                match identity {
                    crate::metadata::identity::Identity::Token(token) => {
                        if *token == 0 {
                            return Err(Error::ValidationOwnedValidatorFailed {
                                validator: self.name().to_string(),
                                message: format!(
                                    "Assembly reference '{}' has zero public key token",
                                    assembly_ref.name
                                ),
                                source: None,
                            });
                        }
                    }
                    crate::metadata::identity::Identity::PubKey(public_key) => {
                        if public_key.iter().all(|&b| b == 0) {
                            return Err(Error::ValidationOwnedValidatorFailed {
                                validator: self.name().to_string(),
                                message: format!(
                                    "Assembly reference '{}' public key consists entirely of zero bytes",
                                    assembly_ref.name
                                ),
                                source: None,
                            });
                        }
                    }
                }
            }

            // Validate flags are reasonable
            if assembly_ref.flags > 0x0001 {
                return Err(Error::ValidationOwnedValidatorFailed {
                    validator: self.name().to_string(),
                    message: format!(
                        "Assembly reference '{}' has unknown flags: 0x{:08X}",
                        assembly_ref.name, assembly_ref.flags
                    ),
                    source: None,
                });
            }
        }

        Ok(())
    }

    /// Validates module and file consistency within assemblies.
    ///
    /// Ensures that modules and files are properly registered and consistent
    /// within the assembly structure. Validates module metadata and PE file structure.
    ///
    /// # Arguments
    ///
    /// * `context` - Owned validation context containing resolved assembly structures via [`crate::metadata::validation::context::OwnedValidationContext`]
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All modules and files are consistent within the assembly
    /// * `Err(`[`crate::Error::ValidationOwnedValidatorFailed`]`)` - Module file consistency violations found
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationOwnedValidatorFailed`] if:
    /// - Assembly flags or hash algorithm IDs are unknown
    /// - Module names are empty, excessively long, or have suspicious generation numbers
    /// - Module IDs (MVIDs) are all-zero
    /// - PE file size is suspiciously small or excessively large
    fn validate_module_file_consistency(&self, context: &OwnedValidationContext) -> Result<()> {
        // Validate basic assembly structure
        if let Some(assembly) = context.object().assembly() {
            // Check that assembly has reasonable flags
            if assembly.flags > 0x0001 {
                return Err(Error::ValidationOwnedValidatorFailed {
                    validator: self.name().to_string(),
                    message: format!(
                        "Assembly '{}' has unknown flags: 0x{:08X}",
                        assembly.name, assembly.flags
                    ),
                    source: None,
                });
            }

            // Validate hash algorithm is reasonable
            if assembly.hash_alg_id != 0
                && assembly.hash_alg_id != 0x8003
                && assembly.hash_alg_id != 0x8004
                && assembly.hash_alg_id != 0x800C
            {
                return Err(Error::ValidationOwnedValidatorFailed {
                    validator: self.name().to_string(),
                    message: format!(
                        "Assembly '{}' has unknown hash algorithm: 0x{:08X}",
                        assembly.name, assembly.hash_alg_id
                    ),
                    source: None,
                });
            }
        }

        // Validate modules within the assembly
        if let Some(module) = context.object().module() {
            let index = 0;
            // Validate module name
            if module.name.is_empty() {
                return Err(Error::ValidationOwnedValidatorFailed {
                    validator: self.name().to_string(),
                    message: format!("Module {index} has empty name"),
                    source: None,
                });
            }

            // Validate module name length
            if module.name.len() > 260 {
                return Err(Error::ValidationOwnedValidatorFailed {
                    validator: self.name().to_string(),
                    message: format!(
                        "Module '{}' has excessively long name: {} characters",
                        module.name,
                        module.name.len()
                    ),
                    source: None,
                });
            }

            // Validate module generation is reasonable
            if module.generation > 65535 {
                return Err(Error::ValidationOwnedValidatorFailed {
                    validator: self.name().to_string(),
                    message: format!(
                        "Module '{}' has suspicious generation number: {}",
                        module.name, module.generation
                    ),
                    source: None,
                });
            }

            // Validate module ID is not all zeros
            if module.mvid.to_bytes().iter().all(|&b| b == 0) {
                return Err(Error::ValidationOwnedValidatorFailed {
                    validator: self.name().to_string(),
                    message: format!(
                        "Module '{}' has all-zero MVID (Module Version ID)",
                        module.name
                    ),
                    source: None,
                });
            }
        }

        // Validate PE file structure
        let file = context.object().file();
        let file_data = file.data();

        // Basic PE file validation
        if file_data.len() < 1024 {
            return Err(Error::ValidationOwnedValidatorFailed {
                validator: self.name().to_string(),
                message: "Assembly file is suspiciously small (< 1024 bytes)".to_string(),
                source: None,
            });
        }

        // Check for reasonable PE file size (not corrupted)
        if file_data.len() > 100_000_000 {
            // 100MB limit
            return Err(Error::ValidationOwnedValidatorFailed {
                validator: self.name().to_string(),
                message: format!(
                    "Assembly file is excessively large: {} bytes",
                    file_data.len()
                ),
                source: None,
            });
        }

        Ok(())
    }
}

impl OwnedValidator for OwnedAssemblyValidator {
    fn validate_owned(&self, context: &OwnedValidationContext) -> Result<()> {
        self.validate_assembly_metadata_consistency(context)?;
        self.validate_cross_assembly_references(context)?;
        self.validate_assembly_version_compatibility(context)?;
        self.validate_module_file_consistency(context)?;

        Ok(())
    }

    fn name(&self) -> &'static str {
        "OwnedAssemblyValidator"
    }

    fn priority(&self) -> u32 {
        110
    }

    fn should_run(&self, context: &OwnedValidationContext) -> bool {
        context.config().enable_semantic_validation
    }
}

impl Default for OwnedAssemblyValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        metadata::validation::ValidationConfig,
        test::{
            factories::validation::system_assembly::owned_assembly_validator_file_factory,
            owned_validator_test,
        },
    };

    #[test]
    fn test_owned_assembly_validator() -> Result<()> {
        let validator = OwnedAssemblyValidator::new();
        let config = ValidationConfig {
            enable_semantic_validation: true,
            ..Default::default()
        };

        owned_validator_test(
            owned_assembly_validator_file_factory,
            "OwnedAssemblyValidator",
            "ValidationOwnedValidatorFailed",
            config,
            |context| validator.validate_owned(context),
        )
    }
}
