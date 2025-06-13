//! Layout validation logic for class layouts
//!
//! This module provides validation for class-level layout constraints according to .NET runtime rules.
//! For field-level validation, see the `field` module.

use crate::{
    metadata::typesystem::{CilFlavor, CilTypeRc},
    Result,
};

/// Validates class layout constraints
pub struct LayoutValidator;

impl LayoutValidator {
    /// Validates class layout constraints according to .NET runtime rules
    ///
    /// # Arguments
    /// * `class_size` - The specified class size
    /// * `packing_size` - The specified packing alignment
    /// * `parent_type` - The type this layout applies to
    ///
    /// # Errors
    /// Returns an error if layout constraints are violated
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
}
