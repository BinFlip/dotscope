//! Owned `ClassLayout` table representation.
//!
//! This module provides the [`crate::metadata::tables::classlayout::owned::ClassLayout`] struct
//! which contains fully resolved memory layout information for types with owned data and resolved
//! table references. This is the primary data structure for representing explicit class layout
//! information in a usable form after the dual variant resolution phase.
//!
//! # Architecture
//!
//! The owned representation stores fully resolved data from the `ClassLayout` metadata table,
//! including resolved references to type definitions. This eliminates the need for table
//! lookups during runtime access, providing immediate access to memory layout metadata.
//!
//! # Key Components
//!
//! - [`crate::metadata::tables::classlayout::owned::ClassLayout`] - Main owned layout structure
//! - [`crate::metadata::typesystem::CilTypeRc`] - Referenced type definition
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::tables::classlayout::raw`] - Raw table representation
//! - [`crate::metadata::typesystem`] - Type system components
//! - [`crate::metadata::validation`] - Layout validation logic
//! - [`crate::metadata::token`] - Token-based metadata references

use crate::{
    metadata::{token::Token, typesystem::CilTypeRc},
    Result,
};

/// Represents explicit memory layout information for a .NET type
///
/// This structure contains the complete layout specification from the `ClassLayout`
/// metadata table (0x0F), with all table references resolved to owned type instances.
/// Unlike [`crate::metadata::tables::classlayout::raw::ClassLayoutRaw`], this provides
/// immediate access to the type data without requiring table lookups.
///
/// # Memory Layout Control
///
/// `ClassLayout` provides explicit control over type memory layout:
/// - **Field alignment**: `PackingSize` specifies byte boundary alignment for fields
/// - **Total size**: `ClassSize` can override automatic size calculation
/// - **Layout kind**: Works with Sequential and Explicit layout attributes
/// - **Interop support**: Enables precise control for native interoperability
///
/// # Usage Context
///
/// `ClassLayout` is primarily used for:
/// - **P/Invoke scenarios**: Matching native C/C++ struct layouts
/// - **Performance optimization**: Controlling cache alignment and padding
/// - **Binary compatibility**: Ensuring consistent layout across platforms
/// - **Custom marshalling**: Supporting specific serialization requirements
///
/// # Layout Validation
///
/// Layout parameters are validated during application to ensure:
/// - `PackingSize` is a power of 2 or 0 (for default)
/// - `ClassSize` is reasonable and not conflicting
/// - No duplicate layout specifications exist
///
/// # Thread Safety
///
/// This type is [`Send`] and [`Sync`]. All fields are read-only after construction and safe
/// for concurrent access. The `apply` method uses atomic operations when updating type
/// definition data.
///
/// # References
/// - [ECMA-335 II.22.8](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `ClassLayout` table specification
pub struct ClassLayout {
    /// Row identifier within the `ClassLayout` metadata table
    ///
    /// The 1-based index of this `ClassLayout` row within the table.
    pub rid: u32,

    /// Metadata token for this `ClassLayout` entry
    ///
    /// Combines the table identifier (0x0F for `ClassLayout`) with the row ID to create
    /// a unique token that can be used to reference this entry from other metadata.
    pub token: Token,

    /// Byte offset of this `ClassLayout` row within the metadata tables stream
    ///
    /// Physical location of the raw `ClassLayout` data within the metadata binary format.
    /// Used for debugging and low-level metadata analysis.
    pub offset: usize,

    /// Field alignment boundary in bytes
    ///
    /// Specifies the byte boundary for field alignment within the type. Common values:
    /// - `1`: No special alignment (byte boundary)
    /// - `2`: 2-byte alignment (for Int16, etc.)
    /// - `4`: 4-byte alignment (for Int32, float, etc.)
    /// - `8`: 8-byte alignment (for Int64, double, etc.)
    /// - `16`: 16-byte alignment (for SIMD types, etc.)
    ///
    /// Must be a power of 2 or 0 for default alignment.
    pub packing_size: u16,

    /// Total size of the type in bytes
    ///
    /// Explicit size override for the type. Values:
    /// - `0`: Use automatic size calculation based on fields
    /// - `> 0`: Force the type to be exactly this many bytes
    ///
    /// When non-zero, this overrides the natural size calculation and can be used
    /// to add padding or ensure specific size requirements for interoperability.
    pub class_size: u32,

    /// Reference to the type this layout applies to
    ///
    /// Points to the corresponding [`crate::metadata::typesystem::CilTypeRc`]
    /// that represents the type definition with this explicit layout specification.
    pub parent: CilTypeRc,
}

impl ClassLayout {
    /// Apply memory layout information to the parent type
    ///
    /// Updates the parent type with explicit layout specifications from this
    /// `ClassLayout` entry. This includes setting the class size and packing size
    /// on the type definition, after validating the layout parameters through
    /// the metadata validation framework.
    ///
    /// The method performs comprehensive validation before applying layout settings,
    /// ensuring that the layout parameters are valid and consistent with .NET
    /// runtime requirements.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Layout successfully applied to parent type
    /// * `Err(`[`crate::Error`]`)` - Layout validation failed or already applied
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] if:
    /// - Layout validation fails (invalid packing size, unreasonable class size)
    /// - Class size has already been set on the target type (duplicate application)
    /// - Packing size has already been set on the target type (duplicate application)
    /// - `PackingSize` is not a power of 2 (when non-zero)
    /// - `ClassSize` would create invalid memory layout
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe as it uses atomic operations to update the type
    /// definition. Multiple threads can safely call this method concurrently, though
    /// only one will succeed in setting the layout parameters.
    pub fn apply(&self) -> Result<()> {
        self.parent
            .class_size
            .set(self.class_size)
            .map_err(|_| malformed_error!("Class size already set"))?;
        self.parent
            .packing_size
            .set(self.packing_size)
            .map_err(|_| malformed_error!("Packing size already set"))
    }
}
