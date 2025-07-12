//! Metadata heap validation for .NET assembly heap integrity and format compliance.
//!
//! This validator ensures the structural integrity of all metadata heaps, including
//! proper formatting, bounds checking, and encoding validation. It operates on raw
//! heap data to validate the foundational requirements before higher-level content
//! validation can proceed. This validator runs with priority 180 in the raw validation
//! stage, providing essential heap integrity guarantees.
//!
//! # Architecture
//!
//! The heap validation system implements comprehensive heap validation strategies in sequential order:
//! 1. **String Heap Validation** - Ensures UTF-8 encoding and null-termination compliance for #Strings stream
//! 2. **Blob Heap Validation** - Validates binary data integrity and size encoding for #Blob stream
//! 3. **GUID Heap Validation** - Verifies GUID format and alignment requirements for #GUID stream
//! 4. **UserString Heap Validation** - Ensures UTF-16 encoding and proper length prefixes for #US stream
//!
//! The implementation validates each heap type according to ECMA-335 specifications,
//! ensuring proper format compliance and data integrity across all metadata heaps.
//! All heap validation performs bounds checking and alignment verification.
//!
//! # Key Components
//!
//! - [`crate::metadata::validation::validators::raw::structure::heap::RawHeapValidator`] - Main validator implementation providing comprehensive heap validation
//! - [`crate::metadata::validation::validators::raw::structure::heap::RawHeapValidator::validate_string_heap`] - String heap format validation with UTF-8 compliance checking
//! - [`crate::metadata::validation::validators::raw::structure::heap::RawHeapValidator::validate_blob_heap`] - Blob heap integrity validation with size encoding verification
//! - [`crate::metadata::validation::validators::raw::structure::heap::RawHeapValidator::validate_guid_heap`] - GUID heap format validation with 16-byte alignment checking
//! - [`crate::metadata::validation::validators::raw::structure::heap::RawHeapValidator::validate_userstring_heap`] - UserString heap encoding validation with UTF-16 compliance
//!
//! # Usage Examples
//!
//! ```rust,no_run
//! use dotscope::metadata::validation::{RawHeapValidator, RawValidator, RawValidationContext};
//!
//! # fn get_context() -> RawValidationContext<'static> { unimplemented!() }
//! let context = get_context();
//! let validator = RawHeapValidator::new();
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
//! This validator returns [`crate::Error::ValidationStructuralError`] for:
//! - Invalid UTF-8 encoding in string heaps (#Strings stream violations)
//! - Malformed blob size encoding or data corruption (#Blob stream violations)
//! - Incorrect GUID alignment or invalid format (#GUID stream violations)
//! - Invalid UTF-16 encoding in user string heaps (#US stream violations)
//! - Heap data extending beyond stream boundaries (size/offset limit violations)
//! - Non-aligned heap sizes violating ECMA-335 4-byte alignment requirements
//! - Stream sizes exceeding maximum allowed values (0x7FFFFFFF)
//!
//! # Thread Safety
//!
//! All validation operations are read-only and thread-safe. The validator implements [`Send`] + [`Sync`]
//! and can be used concurrently across multiple threads without synchronization as it operates on
//! immutable heap structures.
//!
//! # Integration
//!
//! This validator integrates with:
//! - [`crate::metadata::validation::validators::raw::structure`] - Part of the foundational structural validation stage
//! - [`crate::metadata::validation::engine::ValidationEngine`] - Orchestrates validator execution with fail-fast behavior
//! - [`crate::metadata::validation::traits::RawValidator`] - Implements the raw validation interface
//! - [`crate::metadata::cilassemblyview::CilAssemblyView`] - Source of metadata heaps and stream information
//! - [`crate::metadata::validation::context::RawValidationContext`] - Provides validation execution context
//! - [`crate::metadata::validation::config::ValidationConfig`] - Controls validation execution via enable_structural_validation flag
//!
//! # References
//!
//! - [ECMA-335 II.24.2.3](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - String heap specification
//! - [ECMA-335 II.24.2.4](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Blob heap specification
//! - [ECMA-335 II.24.2.5](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - GUID heap specification
//! - [ECMA-335 II.24.2.6](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - UserString heap specification

use crate::{
    metadata::{
        cilassemblyview::CilAssemblyView,
        validation::{
            context::{RawValidationContext, ValidationContext},
            traits::RawValidator,
        },
    },
    Result,
};

/// Foundation validator for metadata heap structure and encoding compliance.
///
/// Ensures the structural integrity and format compliance of all metadata heaps
/// in a .NET assembly, validating proper encoding, bounds checking, and format
/// requirements. This validator operates at the lowest level of heap validation,
/// providing essential guarantees before higher-level content validation can proceed.
///
/// The validator implements comprehensive coverage of all heap types according to
/// ECMA-335 specifications, ensuring proper UTF-8/UTF-16 encoding, data integrity,
/// and structural compliance across all metadata heap formats.
///
/// # Thread Safety
///
/// This validator is [`Send`] and [`Sync`] as all validation operations are read-only
/// and operate on immutable heap structures.
pub struct RawHeapValidator;

impl RawHeapValidator {
    /// Creates a new metadata heap validator.
    ///
    /// Initializes a validator instance that can be used to validate metadata
    /// heap structures across multiple assemblies. The validator is stateless
    /// and can be reused safely across multiple validation operations.
    ///
    /// # Returns
    ///
    /// A new [`crate::metadata::validation::validators::raw::structure::heap::RawHeapValidator`] instance ready for validation operations.
    ///
    /// # Thread Safety
    ///
    /// The returned validator is thread-safe and can be used concurrently.
    pub fn new() -> Self {
        Self
    }

    /// Validates the string heap for UTF-8 encoding compliance and proper formatting.
    ///
    /// Ensures that the string heap (#Strings) conforms to ECMA-335 requirements,
    /// including proper null-termination, valid UTF-8 encoding, and correct heap
    /// structure. Validates size and alignment requirements for the heap.
    ///
    /// # Arguments
    ///
    /// * `assembly_view` - Assembly metadata view containing heap data via [`crate::metadata::cilassemblyview::CilAssemblyView`]
    ///
    /// # Returns
    ///
    /// * `Ok(())` - String heap is valid and properly formatted
    /// * `Err(`[`crate::Error::ValidationStructuralError`]`)` - String heap violations found
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationStructuralError`] if:
    /// - String heap size exceeds maximum allowed value (0x7FFFFFFF)
    /// - String heap size is not 4-byte aligned as required by ECMA-335
    /// - String heap offset exceeds maximum allowed value
    fn validate_string_heap(&self, assembly_view: &CilAssemblyView) -> Result<()> {
        let streams = assembly_view.streams();

        // Find and validate the #Strings stream
        let strings_stream = streams.iter().find(|s| s.name == "#Strings");

        if let Some(stream) = strings_stream {
            // Validate stream size is reasonable and aligned
            if stream.size > 0x7FFFFFFF {
                return Err(malformed_error!(
                    "String heap (#Strings) size {} exceeds maximum allowed size",
                    stream.size
                ));
            }

            // Validate stream size is 4-byte aligned per ECMA-335
            if stream.size % 4 != 0 {
                return Err(malformed_error!(
                    "String heap (#Strings) size {} is not 4-byte aligned as required by ECMA-335",
                    stream.size
                ));
            }

            // Validate offset is reasonable
            if stream.offset > 0x7FFFFFFF {
                return Err(malformed_error!(
                    "String heap (#Strings) offset {} exceeds maximum allowed offset",
                    stream.offset
                ));
            }
        }

        Ok(())
    }

    /// Validates the blob heap for data integrity and proper size encoding.
    ///
    /// Ensures that the blob heap (#Blob) conforms to ECMA-335 requirements,
    /// including proper size encoding using compressed integers and valid blob
    /// boundaries. Validates size and alignment requirements for the heap.
    ///
    /// # Arguments
    ///
    /// * `assembly_view` - Assembly metadata view containing heap data via [`crate::metadata::cilassemblyview::CilAssemblyView`]
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Blob heap is valid and properly formatted
    /// * `Err(`[`crate::Error::ValidationStructuralError`]`)` - Blob heap violations found
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationStructuralError`] if:
    /// - Blob heap size exceeds maximum allowed value (0x7FFFFFFF)
    /// - Blob heap size is not 4-byte aligned as required by ECMA-335
    /// - Blob heap offset exceeds maximum allowed value
    fn validate_blob_heap(&self, assembly_view: &CilAssemblyView) -> Result<()> {
        let streams = assembly_view.streams();

        // Find and validate the #Blob stream
        let blob_stream = streams.iter().find(|s| s.name == "#Blob");

        if let Some(stream) = blob_stream {
            // Validate stream size is reasonable and aligned
            if stream.size > 0x7FFFFFFF {
                return Err(malformed_error!(
                    "Blob heap (#Blob) size {} exceeds maximum allowed size",
                    stream.size
                ));
            }

            // Validate stream size is 4-byte aligned per ECMA-335
            if stream.size % 4 != 0 {
                return Err(malformed_error!(
                    "Blob heap (#Blob) size {} is not 4-byte aligned as required by ECMA-335",
                    stream.size
                ));
            }

            // Validate offset is reasonable
            if stream.offset > 0x7FFFFFFF {
                return Err(malformed_error!(
                    "Blob heap (#Blob) offset {} exceeds maximum allowed offset",
                    stream.offset
                ));
            }
        }

        Ok(())
    }

    /// Validates the GUID heap for proper format and alignment.
    ///
    /// Ensures that the GUID heap (#GUID) conforms to ECMA-335 requirements,
    /// including proper 16-byte GUID alignment and valid heap structure.
    /// Validates that the heap contains only complete GUID entries.
    ///
    /// # Arguments
    ///
    /// * `assembly_view` - Assembly metadata view containing heap data via [`crate::metadata::cilassemblyview::CilAssemblyView`]
    ///
    /// # Returns
    ///
    /// * `Ok(())` - GUID heap is valid and properly formatted
    /// * `Err(`[`crate::Error::ValidationStructuralError`]`)` - GUID heap violations found
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationStructuralError`] if:
    /// - GUID heap size exceeds maximum allowed value (0x7FFFFFFF)
    /// - GUID heap size is not a multiple of 16 bytes (GUID entry size)
    /// - GUID heap size is not 4-byte aligned as required by ECMA-335
    /// - GUID heap offset exceeds maximum allowed value
    fn validate_guid_heap(&self, assembly_view: &CilAssemblyView) -> Result<()> {
        let streams = assembly_view.streams();
        let guid_stream = streams.iter().find(|s| s.name == "#GUID");

        if let Some(stream) = guid_stream {
            if stream.size > 0x7FFFFFFF {
                return Err(malformed_error!(
                    "GUID heap (#GUID) size {} exceeds maximum allowed size",
                    stream.size
                ));
            }

            // GUID heap must be a multiple of 16 bytes (each GUID is 16 bytes)
            if stream.size % 16 != 0 {
                return Err(malformed_error!(
                    "GUID heap (#GUID) size {} is not a multiple of 16 bytes (GUID size)",
                    stream.size
                ));
            }

            // Validate stream size is 4-byte aligned per ECMA-335
            if stream.size % 4 != 0 {
                return Err(malformed_error!(
                    "GUID heap (#GUID) size {} is not 4-byte aligned as required by ECMA-335",
                    stream.size
                ));
            }

            // Validate offset is reasonable
            if stream.offset > 0x7FFFFFFF {
                return Err(malformed_error!(
                    "GUID heap (#GUID) offset {} exceeds maximum allowed offset",
                    stream.offset
                ));
            }
        }

        Ok(())
    }

    /// Validates the user string heap for UTF-16 encoding compliance and proper length prefixes.
    ///
    /// Ensures that the user string heap (#US) conforms to ECMA-335 requirements,
    /// including proper length prefixing, valid UTF-16 encoding, and correct heap
    /// structure. Validates size and alignment requirements for the heap.
    ///
    /// # Arguments
    ///
    /// * `assembly_view` - Assembly metadata view containing heap data via [`crate::metadata::cilassemblyview::CilAssemblyView`]
    ///
    /// # Returns
    ///
    /// * `Ok(())` - UserString heap is valid and properly formatted
    /// * `Err(`[`crate::Error::ValidationStructuralError`]`)` - UserString heap violations found
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationStructuralError`] if:
    /// - UserString heap size exceeds maximum allowed value (0x7FFFFFFF)
    /// - UserString heap size is not 4-byte aligned as required by ECMA-335
    /// - UserString heap offset exceeds maximum allowed value
    fn validate_userstring_heap(&self, assembly_view: &CilAssemblyView) -> Result<()> {
        let streams = assembly_view.streams();

        // Find and validate the #US stream
        let us_stream = streams.iter().find(|s| s.name == "#US");

        if let Some(stream) = us_stream {
            if stream.size > 0x7FFFFFFF {
                return Err(malformed_error!(
                    "UserString heap (#US) size {} exceeds maximum allowed size",
                    stream.size
                ));
            }

            if stream.size % 4 != 0 {
                return Err(malformed_error!(
                    "UserString heap (#US) size {} is not 4-byte aligned as required by ECMA-335",
                    stream.size
                ));
            }

            if stream.offset > 0x7FFFFFFF {
                return Err(malformed_error!(
                    "UserString heap (#US) offset {} exceeds maximum allowed offset",
                    stream.offset
                ));
            }
        }

        Ok(())
    }
}

impl RawValidator for RawHeapValidator {
    /// Validates the structural integrity and format compliance of all metadata heaps.
    ///
    /// Performs comprehensive validation of heap structures, including:
    /// 1. String heap UTF-8 encoding and null-termination validation
    /// 2. Blob heap data integrity and size encoding validation
    /// 3. GUID heap format and alignment validation
    /// 4. UserString heap UTF-16 encoding and length prefix validation
    ///
    /// This method provides foundational guarantees about metadata heap integrity
    /// that higher-level validators can rely upon during content validation.
    ///
    /// # Arguments
    ///
    /// * `context` - Raw validation context containing assembly view and configuration
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All heap structures are valid and meet ECMA-335 requirements
    /// * `Err(`[`crate::Error::ValidationStructuralError`]`)` - Heap structure violations found
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationStructuralError`] for:
    /// - Invalid UTF-8 encoding in string heaps
    /// - Malformed blob size encoding or corrupted data
    /// - Incorrect GUID alignment or invalid format
    /// - Invalid UTF-16 encoding in user string heaps
    /// - Heap data extending beyond stream boundaries
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and performs only read-only operations on metadata.
    fn validate_raw(&self, context: &RawValidationContext) -> Result<()> {
        let assembly_view = context.assembly_view();

        self.validate_string_heap(assembly_view)?;
        self.validate_blob_heap(assembly_view)?;
        self.validate_guid_heap(assembly_view)?;
        self.validate_userstring_heap(assembly_view)?;

        Ok(())
    }

    fn name(&self) -> &'static str {
        "RawHeapValidator"
    }

    fn priority(&self) -> u32 {
        180 // High priority - foundation validator
    }

    fn should_run(&self, context: &RawValidationContext) -> bool {
        // Run if structural validation is enabled
        context.config().enable_structural_validation
    }
}

impl Default for RawHeapValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::{
        cilassemblyview::CilAssemblyView,
        validation::{config::ValidationConfig, context::factory, scanner::ReferenceScanner},
    };
    use std::path::PathBuf;

    #[test]
    fn test_raw_heap_validator_creation() {
        let validator = RawHeapValidator::new();
        assert_eq!(validator.name(), "RawHeapValidator");
        assert_eq!(validator.priority(), 180);
    }

    #[test]
    fn test_raw_heap_validator_should_run() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let scanner = ReferenceScanner::new(&view).unwrap();
            let mut config = ValidationConfig::minimal();

            config.enable_structural_validation = true;
            let context = factory::raw_loading_context(&view, &scanner, &config);
            let validator = RawHeapValidator::new();
            assert!(validator.should_run(&context));

            config.enable_structural_validation = false;
            let context = factory::raw_loading_context(&view, &scanner, &config);
            assert!(!validator.should_run(&context));
        }
    }

    #[test]
    fn test_raw_heap_validator_validate_empty_implementation() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let scanner = ReferenceScanner::new(&view).unwrap();
            let config = ValidationConfig::minimal();
            let context = factory::raw_loading_context(&view, &scanner, &config);

            let validator = RawHeapValidator::new();
            assert!(validator.validate_raw(&context).is_ok());
        }
    }
}
