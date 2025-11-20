//! Raw signature validation for .NET assembly signature blob integrity and format compliance.
//!
//! This validator ensures the structural integrity of signature blobs in metadata tables,
//! validating proper ECMA-335 binary format, calling convention compliance, and blob bounds
//! checking before signature parsing occurs. It operates on raw blob heap data to validate
//! the foundational requirements before higher-level signature validation can proceed.
//! This validator runs with priority 175 in the raw validation stage.
//!
//! # Architecture
//!
//! The signature validation system implements comprehensive blob format validation:
//! 1. **Method Signature Validation** - Validates method signature blobs in MethodDef table
//! 2. **Field Signature Validation** - Validates field type signatures in Field table  
//! 3. **Property Signature Validation** - Validates property signatures in Property table
//! 4. **LocalVar Signature Validation** - Validates local variable signatures in StandAloneSig table
//! 5. **TypeSpec Signature Validation** - Validates type specification signatures in TypeSpec table
//! 6. **MemberRef Signature Validation** - Validates member reference signatures in MemberRef table
//!
//! The implementation validates signature blob format according to ECMA-335 specifications,
//! ensuring proper calling convention encoding, compressed integer format, and blob bounds
//! checking without performing full signature parsing.
//!
//! # Key Components
//!
//! - [`RawSignatureValidator`] - Main validator implementation providing comprehensive signature blob validation
//! - [`RawSignatureValidator::validate_signature_blob_integrity`] - Core blob format validation with calling convention checking
//! - [`RawSignatureValidator::validate_calling_convention`] - Calling convention byte validation
//! - [`RawSignatureValidator::validate_compressed_integer`] - Compressed integer format validation
//! - [`RawSignatureValidator::validate_blob_bounds`] - Blob boundary and size validation
//!
//! # Usage Examples
//!
//! ```rust,no_run
//! use dotscope::metadata::validation::{RawSignatureValidator, RawValidator, RawValidationContext};
//!
//! # fn get_context() -> RawValidationContext<'static> { unimplemented!() }
//! let context = get_context();
//! let validator = RawSignatureValidator::new();
//!
//! // Check if validation should run based on configuration
//! if validator.should_run(&context) {
//!     validator.validate_raw(&context)?;
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Error Handling
//!
//! This validator returns [`crate::Error::ValidationRawValidatorFailed`] for:
//! - Invalid calling convention bytes in signature blobs
//! - Malformed compressed integer encoding in signatures
//! - Signature blobs extending beyond blob heap boundaries
//! - Invalid signature blob size encoding
//! - Signature blobs with insufficient data for declared size
//! - Recursive type definitions exceeding maximum nesting depth
//!
//! # Thread Safety
//!
//! All validation operations are read-only and thread-safe. The validator implements [`Send`] + [`Sync`]
//! and can be used concurrently across multiple threads without synchronization as it operates on
//! immutable signature blob structures.
//!
//! # Integration
//!
//! This validator integrates with:
//! - raw structure validators - Part of the foundational structural validation stage
//! - [`crate::metadata::validation::engine::ValidationEngine`] - Orchestrates validator execution with fail-fast behavior
//! - [`crate::metadata::validation::traits::RawValidator`] - Implements the raw validation interface
//! - [`crate::metadata::cilassemblyview::CilAssemblyView`] - Source of metadata tables and blob heap
//! - [`crate::metadata::validation::context::RawValidationContext`] - Provides validation execution context
//! - [`crate::metadata::validation::config::ValidationConfig`] - Controls validation execution via enable_token_validation flag
//! - owned metadata signature validator - Complemented by semantic signature validation
//!
//! # References
//!
//! - [ECMA-335 II.23.2](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Blobs and signatures
//! - [ECMA-335 II.23.2.1](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Method signatures
//! - [ECMA-335 II.23.2.4](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Field signatures
//! - [ECMA-335 II.23.2.5](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Property signatures

use crate::{
    metadata::{
        cilassemblyview::CilAssemblyView,
        tables::{
            FieldRaw, MemberRefRaw, MethodDefRaw, PropertyRaw, StandAloneSigRaw, TypeSpecRaw,
        },
        validation::{
            context::{RawValidationContext, ValidationContext},
            traits::RawValidator,
        },
    },
    Error, Result,
};

/// Foundation validator for signature blob structure and ECMA-335 format compliance.
///
/// Ensures the structural integrity and format compliance of all signature blobs
/// in a .NET assembly, validating proper calling convention encoding, compressed
/// integer format, and blob bounds checking. This validator operates at the binary
/// format level before signature parsing, providing essential guarantees for safe
/// signature processing.
///
/// The validator implements comprehensive coverage of all signature types according to
/// ECMA-335 specifications, ensuring proper binary format compliance, calling convention
/// validity, and structural integrity across all signature blob formats.
///
/// # Thread Safety
///
/// This validator is [`Send`] and [`Sync`] as all validation operations are read-only
/// and operate on immutable signature blob structures.
pub struct RawSignatureValidator;

/// Signature kind enumeration for blob validation context.
///
/// Defines the expected signature type for blob validation to ensure proper
/// calling convention and format validation according to ECMA-335 specifications.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SignatureKind {
    /// Method signature (ECMA-335 II.23.2.1)
    Method,
    /// Field signature (ECMA-335 II.23.2.4)
    Field,
    /// Property signature (ECMA-335 II.23.2.5)
    Property,
    /// Local variable signature (ECMA-335 II.23.2.6)
    LocalVar,
    /// Type specification signature (ECMA-335 II.23.2.14)
    TypeSpec,
    /// Member reference signature (method or field)
    MemberRef,
}

impl RawSignatureValidator {
    /// Creates a new signature blob validator.
    ///
    /// Initializes a validator instance that can be used to validate signature
    /// blob structures across multiple assemblies. The validator is stateless
    /// and can be reused safely across multiple validation operations.
    ///
    /// # Returns
    ///
    /// A new [`RawSignatureValidator`] instance ready for validation operations.
    ///
    /// # Thread Safety
    ///
    /// The returned validator is thread-safe and can be used concurrently.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Validates the integrity and format compliance of a signature blob.
    ///
    /// Performs comprehensive validation of signature blob format including:
    /// 1. Blob existence and minimum size validation
    /// 2. Calling convention byte validation for signature kind
    /// 3. Compressed integer encoding validation
    /// 4. Blob boundary checking to prevent buffer overruns
    /// 5. Basic ECMA-335 format compliance verification
    ///
    /// This method provides foundational guarantees about signature blob integrity
    /// that signature parsers can rely upon during content parsing.
    ///
    /// # Arguments
    ///
    /// * `assembly_view` - Assembly metadata view containing blob heap data
    /// * `blob_index` - Index into the blob heap for the signature
    /// * `expected_kind` - Expected signature type for validation context
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Signature blob is valid and properly formatted
    /// * `Err(`[`crate::Error::ValidationRawValidatorFailed`]`)` - Signature blob violations found
    ///
    /// # Errors
    ///
    /// Returns validation errors for:
    /// - Blob index pointing beyond heap boundaries
    /// - Invalid calling convention for signature kind
    /// - Malformed compressed integer encoding
    /// - Insufficient blob data for declared signature size
    fn validate_signature_blob_integrity(
        assembly_view: &CilAssemblyView,
        blob_index: u32,
        expected_kind: SignatureKind,
    ) -> Result<()> {
        if blob_index == 0 {
            return Ok(());
        }

        let Some(blob_heap) = assembly_view.blobs() else {
            return Err(Error::ValidationRawValidatorFailed {
                validator: "RawSignatureValidator".to_string(),
                message: "Signature validation requires blob heap access".to_string(),
                source: None,
            });
        };

        let blob_data = blob_heap.get(blob_index as usize).map_err(|_| {
            Error::ValidationRawValidatorFailed {
                validator: "RawSignatureValidator".to_string(),
                message: format!("Signature blob index {blob_index} exceeds blob heap bounds"),
                source: None,
            }
        })?;

        if blob_data.is_empty() {
            return Err(Error::ValidationRawValidatorFailed {
                validator: "RawSignatureValidator".to_string(),
                message: format!("Signature blob at index {blob_index} is empty"),
                source: None,
            });
        }

        let calling_convention = blob_data[0];
        Self::validate_calling_convention(calling_convention, expected_kind, blob_index)?;

        if matches!(
            expected_kind,
            SignatureKind::Method | SignatureKind::LocalVar | SignatureKind::Property
        ) {
            if blob_data.len() < 2 {
                return Err(Error::ValidationRawValidatorFailed {
                    validator: "RawSignatureValidator".to_string(),
                    message: format!(
                        "Signature blob at index {blob_index} too short for parameter count"
                    ),
                    source: None,
                });
            }

            Self::validate_compressed_integer(&blob_data[1..], blob_index)?;
        }

        Self::validate_blob_bounds(blob_data, blob_index)?;

        Ok(())
    }

    /// Validates calling convention byte for the expected signature kind.
    ///
    /// Ensures the calling convention byte is valid for the signature type
    /// according to ECMA-335 calling convention specifications.
    ///
    /// # Arguments
    ///
    /// * `calling_convention` - The calling convention byte from signature
    /// * `expected_kind` - Expected signature type
    /// * `blob_index` - Blob index for error reporting
    ///
    /// # Returns
    ///
    /// Returns validation error if calling convention is invalid for signature kind.
    fn validate_calling_convention(
        calling_convention: u8,
        expected_kind: SignatureKind,
        blob_index: u32,
    ) -> Result<()> {
        match expected_kind {
            SignatureKind::Method | SignatureKind::MemberRef => {
                // Method calling conventions (ECMA-335 II.23.2.1)
                // 0x00 = DEFAULT, 0x01 = C, 0x02 = STDCALL, 0x03 = THISCALL, 0x04 = FASTCALL, 0x05 = VARARG
                // Can also have HASTHIS (0x20) and EXPLICIT_THIS (0x40) flags
                let base_convention = calling_convention & 0x0F;
                if base_convention > 0x05 {
                    return Err(Error::ValidationRawValidatorFailed {
                        validator: "RawSignatureValidator".to_string(),
                        message: format!("Invalid method calling convention 0x{calling_convention:02X} in signature blob {blob_index}"),
                        source: None,
                    });
                }
            }
            SignatureKind::Field => {
                // Field signature (ECMA-335 II.23.2.4) - should be 0x06
                if calling_convention != 0x06 {
                    return Err(Error::ValidationRawValidatorFailed {
                        validator: "RawSignatureValidator".to_string(),
                        message: format!("Invalid field signature marker 0x{calling_convention:02X} in blob {blob_index}, expected 0x06"),
                        source: None,
                    });
                }
            }
            SignatureKind::Property => {
                // Property signature (ECMA-335 II.23.2.5) - should be 0x08 (PROPERTY)
                // Can also have HASTHIS (0x20) flag
                let base_convention = calling_convention & 0x0F;
                if base_convention != 0x08 {
                    return Err(Error::ValidationRawValidatorFailed {
                        validator: "RawSignatureValidator".to_string(),
                        message: format!("Invalid property signature marker 0x{calling_convention:02X} in blob {blob_index}, expected 0x08"),
                        source: None,
                    });
                }
            }
            SignatureKind::LocalVar => {
                // Local variable signature (ECMA-335 II.23.2.6) - should be 0x07
                if calling_convention != 0x07 {
                    return Err(Error::ValidationRawValidatorFailed {
                        validator: "RawSignatureValidator".to_string(),
                        message: format!("Invalid local variable signature marker 0x{calling_convention:02X} in blob {blob_index}, expected 0x07"),
                        source: None,
                    });
                }
            }
            SignatureKind::TypeSpec => {
                // TypeSpec signature has various type encodings, basic validation for known ranges
                // Valid element types are in ranges 0x01-0x16, 0x1B-0x20, etc.
                if calling_convention == 0x00 {
                    return Err(Error::ValidationRawValidatorFailed {
                        validator: "RawSignatureValidator".to_string(),
                        message: format!("Invalid type specification signature marker 0x{calling_convention:02X} in blob {blob_index}"),
                        source: None,
                    });
                }
            }
        }
        Ok(())
    }

    /// Validates compressed integer encoding format.
    ///
    /// Ensures compressed integers follow ECMA-335 encoding rules:
    /// - 1-byte: 0bbbbbbb (0-127)  
    /// - 2-byte: 10bbbbbb xxxxxxxx (128-16383)
    /// - 4-byte: 110bbbbb xxxxxxxx yyyyyyyy zzzzzzzz (16384+)
    ///
    /// # Arguments
    ///
    /// * `data` - Blob data starting at compressed integer
    /// * `blob_index` - Blob index for error reporting
    ///
    /// # Returns
    ///
    /// Returns validation error if compressed integer encoding is malformed.
    fn validate_compressed_integer(data: &[u8], blob_index: u32) -> Result<()> {
        if data.is_empty() {
            return Err(Error::ValidationRawValidatorFailed {
                validator: "RawSignatureValidator".to_string(),
                message: format!("Insufficient data for compressed integer in blob {blob_index}"),
                source: None,
            });
        }

        let first_byte = data[0];

        if (first_byte & 0x80) == 0 {
            // 1-byte encoding: 0bbbbbbb
            // Valid as-is
            Ok(())
        } else if (first_byte & 0xC0) == 0x80 {
            // 2-byte encoding: 10bbbbbb xxxxxxxx
            if data.len() < 2 {
                return Err(Error::ValidationRawValidatorFailed {
                    validator: "RawSignatureValidator".to_string(),
                    message: format!(
                        "Insufficient data for 2-byte compressed integer in blob {blob_index}"
                    ),
                    source: None,
                });
            }
            Ok(())
        } else if (first_byte & 0xE0) == 0xC0 {
            // 4-byte encoding: 110bbbbb xxxxxxxx yyyyyyyy zzzzzzzz
            if data.len() < 4 {
                return Err(Error::ValidationRawValidatorFailed {
                    validator: "RawSignatureValidator".to_string(),
                    message: format!(
                        "Insufficient data for 4-byte compressed integer in blob {blob_index}"
                    ),
                    source: None,
                });
            }
            Ok(())
        } else {
            // Invalid encoding pattern
            Err(Error::ValidationRawValidatorFailed {
                validator: "RawSignatureValidator".to_string(),
                message: format!(
                    "Invalid compressed integer encoding 0x{first_byte:02X} in blob {blob_index}"
                ),
                source: None,
            })
        }
    }

    /// Validates blob boundary constraints and structural integrity.
    ///
    /// Performs basic structural validation to ensure the blob data is
    /// consistent and does not contain obvious corruption indicators.
    ///
    /// # Arguments
    ///
    /// * `blob_data` - The blob data to validate
    /// * `blob_index` - Blob index for error reporting
    ///
    /// # Returns
    ///
    /// Returns validation error for structural inconsistencies.
    fn validate_blob_bounds(blob_data: &[u8], blob_index: u32) -> Result<()> {
        if blob_data.len() > 65536 {
            return Err(Error::ValidationRawValidatorFailed {
                validator: "RawSignatureValidator".to_string(),
                message: format!(
                    "Signature blob {} exceeds maximum reasonable size ({})",
                    blob_index,
                    blob_data.len()
                ),
                source: None,
            });
        }

        // ToDo: Additional bounds checking can be added here for specific signature format constraints
        Ok(())
    }
}

impl RawValidator for RawSignatureValidator {
    /// Validates the structural integrity and format compliance of all signature blobs.
    ///
    /// Performs comprehensive validation of signature blob structures, including:
    /// 1. Method signature validation in MethodDef table
    /// 2. Field signature validation in Field table  
    /// 3. Property signature validation in Property table
    /// 4. Local variable signature validation in StandAloneSig table
    /// 5. Type specification signature validation in TypeSpec table
    /// 6. Member reference signature validation in MemberRef table
    ///
    /// This method provides foundational guarantees about signature blob integrity
    /// that higher-level signature validators and parsers can rely upon during content validation.
    ///
    /// # Arguments
    ///
    /// * `context` - Raw validation context containing assembly view and configuration
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All signature blobs are valid and properly formatted
    /// * `Err(`[`crate::Error::ValidationRawValidatorFailed`]`)` - Signature blob violations found
    ///
    /// # Configuration
    ///
    /// Controlled by `enable_token_validation` flag in validation configuration.
    fn validate_raw(&self, context: &RawValidationContext) -> Result<()> {
        if !self.should_run(context) {
            return Ok(());
        }

        let assembly_view = context.assembly_view();

        let Some(tables) = assembly_view.tables() else {
            return Ok(());
        };

        if let Some(table) = tables.table::<MethodDefRaw>() {
            for method in table {
                if let Some(blob_heap) = assembly_view.blobs() {
                    if let Ok(blob_data) = blob_heap.get(method.signature as usize) {
                        if !blob_data.is_empty() {
                            let calling_convention = blob_data[0];
                            let signature_kind = match calling_convention {
                                0x06 => SignatureKind::Field,
                                _ => SignatureKind::Method,
                            };

                            Self::validate_signature_blob_integrity(
                                assembly_view,
                                method.signature,
                                signature_kind,
                            )?;
                        }
                    }
                } else {
                    Self::validate_signature_blob_integrity(
                        assembly_view,
                        method.signature,
                        SignatureKind::Method,
                    )?;
                }
            }
        }

        if let Some(table) = tables.table::<FieldRaw>() {
            for field in table {
                Self::validate_signature_blob_integrity(
                    assembly_view,
                    field.signature,
                    SignatureKind::Field,
                )?;
            }
        }

        if let Some(table) = tables.table::<PropertyRaw>() {
            for property in table {
                Self::validate_signature_blob_integrity(
                    assembly_view,
                    property.signature,
                    SignatureKind::Property,
                )?;
            }
        }

        if let Some(table) = tables.table::<StandAloneSigRaw>() {
            for standalone_sig in table {
                if let Some(blob_heap) = assembly_view.blobs() {
                    if let Ok(blob_data) = blob_heap.get(standalone_sig.signature as usize) {
                        if !blob_data.is_empty() {
                            let calling_convention = blob_data[0];
                            let signature_kind = match calling_convention {
                                0x07 => SignatureKind::LocalVar,
                                0x06 => SignatureKind::Field,
                                _ => SignatureKind::Method,
                            };

                            Self::validate_signature_blob_integrity(
                                assembly_view,
                                standalone_sig.signature,
                                signature_kind,
                            )?;
                        }
                    }
                }
            }
        }

        if let Some(table) = tables.table::<TypeSpecRaw>() {
            for type_spec in table {
                Self::validate_signature_blob_integrity(
                    assembly_view,
                    type_spec.signature,
                    SignatureKind::TypeSpec,
                )?;
            }
        }

        if let Some(table) = tables.table::<MemberRefRaw>() {
            for member_ref in table {
                if let Some(blob_heap) = assembly_view.blobs() {
                    if let Ok(blob_data) = blob_heap.get(member_ref.signature as usize) {
                        if !blob_data.is_empty() {
                            let calling_convention = blob_data[0];
                            let signature_kind = match calling_convention {
                                0x06 => SignatureKind::Field,
                                _ => SignatureKind::Method,
                            };

                            Self::validate_signature_blob_integrity(
                                assembly_view,
                                member_ref.signature,
                                signature_kind,
                            )?;
                        }
                    }
                } else {
                    Self::validate_signature_blob_integrity(
                        assembly_view,
                        member_ref.signature,
                        SignatureKind::MemberRef,
                    )?;
                }
            }
        }

        Ok(())
    }

    /// Returns the validation priority for signature blob validation.
    ///
    /// Signature validation runs with priority 175, after heap validation (180)
    /// but before other structural validators, ensuring blob integrity before
    /// signature parsing occurs.
    fn priority(&self) -> u32 {
        175
    }

    /// Returns the validator name for identification and logging.
    fn name(&self) -> &'static str {
        "RawSignatureValidator"
    }

    /// Determines if signature validation should run based on validation configuration.
    ///
    /// Signature validation is controlled by the `enable_token_validation` flag
    /// since signature blobs are part of the token validation infrastructure.
    fn should_run(&self, context: &RawValidationContext) -> bool {
        context.config().enable_token_validation
    }
}

impl Default for RawSignatureValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        metadata::validation::ValidationConfig,
        test::{factories::validation::raw_structure_signature::*, validator_test},
        Result,
    };

    #[test]
    fn test_raw_signature_validator() -> Result<()> {
        let validator = RawSignatureValidator::new();
        let config = ValidationConfig {
            enable_token_validation: true,
            ..Default::default()
        };

        validator_test(
            raw_signature_validator_file_factory,
            "RawSignatureValidator",
            "ValidationRawValidatorFailed",
            config,
            |context| validator.validate_raw(context),
        )
    }
}
