//! Owned `FieldRva` structures for the `FieldRva` metadata table.
//!
//! This module provides the [`FieldRva`] struct which represents field RVA
//! definitions with resolved references and owned data. Field RVAs specify
//! Relative Virtual Addresses for fields that have initial data stored in
//! the PE file.
//!
//! # Purpose
//! The `FieldRva` table enables static field initialization and data embedding:
//! - **Static field initialization**: Pre-computed initial values for static fields
//! - **Constant data**: Read-only data embedded directly in the PE file
//! - **Global variables**: Module-level data with specific initial states
//! - **Interop data**: Native data structures for P/Invoke operations
//! - **Resource embedding**: Binary resources accessible through field references
//!
//! # RVA Context
//! RVAs provide data location information:
//! - **PE file integration**: Data stored within PE file sections
//! - **Memory mapping**: Direct access to data when PE is memory-mapped
//! - **File offset calculation**: RVA + section base → file offset
//! - **Type-safe access**: Field type determines data interpretation
//!
//! # ECMA-335 Reference
//! See ECMA-335, Partition II, §22.19 for the `FieldRva` table specification.

use crate::{
    metadata::{tables::FieldRc, token::Token},
    Result,
};

/// Represents a field RVA definition with resolved references and owned data.
///
/// A field RVA specifies the Relative Virtual Address of initial data for a field
/// within the PE file. This enables static field initialization with pre-computed
/// values and embedding of constant data directly in the assembly.
///
/// # RVA Usage
/// Field RVAs are used in various scenarios:
/// - **Static arrays**: Pre-initialized array data for static fields
/// - **Constant strings**: String literals embedded in the PE file
/// - **Numeric constants**: Pre-computed values for mathematical constants
/// - **Lookup tables**: Read-only data tables for algorithms
/// - **Configuration data**: Default settings and application parameters
///
/// # Data Access
/// The RVA enables direct access to field data:
/// ```text
/// 1. RVA points to data location in PE file
/// 2. Field type determines data size and interpretation
/// 3. Runtime loads data from RVA location
/// 4. Data becomes field's initial value
/// ```
///
/// # PE File Integration
/// Field RVAs integrate with PE file structure:
/// - **Section placement**: Data positioned in appropriate PE sections
/// - **Memory alignment**: Data aligned for efficient access
/// - **Protection flags**: Sections marked with correct read/write permissions
/// - **Relocation handling**: RVAs adjusted during PE loading
///
/// # ECMA-335 Reference
/// See ECMA-335, Partition II, §22.19 for the complete `FieldRva` table specification.
pub struct FieldRva {
    /// The row identifier in the `FieldRva` table.
    ///
    /// This 1-based index uniquely identifies this field RVA within the `FieldRva` table.
    /// Combined with the table type, it forms the RVA entry's unique identity.
    pub rid: u32,

    /// The metadata token for this field RVA.
    ///
    /// A [`crate::metadata::token::Token`] that uniquely identifies this field RVA across the entire assembly.
    /// The token encodes both the table type (`FieldRva`) and the row ID.
    ///
    /// [`crate::metadata::token::Token`]: crate::metadata::token::Token
    pub token: Token,

    /// The byte offset of this field RVA in the metadata tables stream.
    ///
    /// This offset points to the start of this RVA's row data within the
    /// metadata tables stream, used for binary parsing and navigation.
    pub offset: usize,

    /// The Relative Virtual Address of the field's initial data.
    ///
    /// A 4-byte RVA pointing to the location of the field's initial data within
    /// the PE file. This address is relative to the image base and must be
    /// resolved to an actual file offset for data access.
    ///
    /// # RVA Resolution
    /// - **Image base**: PE file's preferred load address
    /// - **Section mapping**: RVA maps to specific PE sections
    /// - **File offset**: RVA + section base → actual file position
    /// - **Data access**: Binary data reading from calculated offset
    pub rva: u32,

    /// Reference to the field that this RVA applies to.
    ///
    /// A reference-counted [`Field`] instance representing the field whose
    /// initial data is located at the specified RVA. The field must have
    /// the appropriate attributes for RVA-based initialization.
    ///
    /// [`Field`]: crate::metadata::tables::field::Field
    pub field: FieldRc,
}

impl FieldRva {
    /// Apply this field RVA to the referenced field.
    ///
    /// This method applies the RVA information to the target field, updating
    /// the field's RVA property with the data location. Since this is the owned
    /// structure, the field reference is already resolved, enabling efficient updates.
    ///
    /// # Returns
    /// Returns `Ok(())` on successful application, or an error if:
    /// - RVA is already set on the target field
    /// - Field does not support RVA-based initialization
    /// - Memory constraints are violated
    ///
    /// # Errors
    /// - **Duplicate RVA**: If the field already has an RVA assigned
    /// - **Invalid Field**: If the field type doesn't support RVA initialization
    /// - **Memory Error**: If allocation fails during assignment
    pub fn apply(&self) -> Result<()> {
        self.field
            .rva
            .set(self.rva)
            .map_err(|_| malformed_error!("Field RVA already set"))
    }
}
