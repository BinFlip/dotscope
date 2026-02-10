//! Owned `AssemblyRefOS` table representation.
//!
//! This module provides the [`crate::metadata::tables::assemblyrefos::owned::AssemblyRefOs`] struct
//! which contains fully resolved operating system compatibility information for external assembly
//! references. This is the primary data structure for representing OS requirements for referenced
//! assemblies in a usable form after the dual variant resolution phase.
//!
//! # Architecture
//!
//! The owned representation stores fully resolved data from the `AssemblyRefOS` metadata table,
//! including resolved references to assembly dependencies. This eliminates the need for table
//! lookups during runtime access, providing immediate access to OS compatibility metadata.
//!
//! # Key Components
//!
//! - [`crate::metadata::tables::assemblyrefos::owned::AssemblyRefOs`] - Main owned OS compatibility structure
//! - [`crate::metadata::tables::assemblyref::AssemblyRefRc`] - Referenced assembly dependency
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::tables::assemblyrefos::raw`] - Raw table representation
//! - [`crate::metadata::tables::assemblyref`] - Assembly reference table entries
//! - [`crate::metadata::token`] - Token-based metadata references

use std::sync::atomic::Ordering;

use crate::{
    metadata::{tables::AssemblyRefRc, token::Token},
    Result,
};

/// Represents operating system compatibility information for an external assembly reference
///
/// This structure contains OS targeting information from the `AssemblyRefOS` metadata table (0x25),
/// with all references resolved to owned data. Unlike [`crate::metadata::tables::assemblyrefos::raw::AssemblyRefOsRaw`],
/// this provides immediate access to the referenced assembly without requiring table lookups.
///
/// # Operating System Targeting
///
/// The `AssemblyRefOS` table allows specifying explicit OS requirements for external assemblies:
/// - **Platform ID**: Operating system family identifier
/// - **Major Version**: Target OS major version number  
/// - **Minor Version**: Target OS minor version number
/// - **Assembly Reference**: The external assembly these requirements apply to
///
/// # Historical Context
///
/// This table is rarely used in modern .NET assemblies and is considered legacy. It was designed
/// for early .NET Framework scenarios where assemblies might need explicit OS compatibility
/// declarations. Modern .NET relies on runtime platform abstraction instead.
///
/// # Thread Safety
///
/// This type is [`Send`] and [`Sync`]. All fields are read-only after construction and safe
/// for concurrent access. The `apply` method uses atomic operations when updating assembly
/// reference data.
///
/// # References
/// - [ECMA-335 II.22.7](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `AssemblyRefOS` table specification
pub struct AssemblyRefOs {
    /// Row identifier within the `AssemblyRefOS` metadata table
    ///
    /// The 1-based index of this `AssemblyRefOS` row within the table.
    pub rid: u32,

    /// Metadata token for this `AssemblyRefOS` entry
    ///
    /// Combines the table identifier (0x25 for `AssemblyRefOS`) with the row ID to create
    /// a unique token that can be used to reference this entry from other metadata.
    pub token: Token,

    /// Byte offset of this `AssemblyRefOS` row within the metadata tables stream
    ///
    /// Physical location of the raw `AssemblyRefOS` data within the metadata binary format.
    /// Used for debugging and low-level metadata analysis.
    pub offset: usize,

    /// Operating system platform identifier
    ///
    /// Specifies the target operating system family. Common values include:
    /// - 1: Windows 32-bit
    /// - 2: Windows 64-bit
    /// - Other values for various platform types
    pub os_platform_id: u32,

    /// Major version number of the target operating system
    ///
    /// The major version component of the required OS version (e.g., 6 for Windows Vista/7/8).
    pub os_major_version: u32,

    /// Minor version number of the target operating system  
    ///
    /// The minor version component of the required OS version (e.g., 1 for Windows 7).
    pub os_minor_version: u32,

    /// Reference to the external assembly that these OS requirements apply to
    ///
    /// Points to the corresponding [`crate::metadata::tables::assemblyref::AssemblyRef`]
    /// entry that represents the external assembly dependency.
    pub assembly_ref: AssemblyRefRc,
}

impl AssemblyRefOs {
    /// Apply operating system compatibility information to the referenced assembly
    ///
    /// Updates the referenced assembly with OS platform and version information from this
    /// `AssemblyRefOS` entry. The assembly reference already contains atomic fields for storing
    /// OS data, allowing thread-safe updates without additional synchronization.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - OS information successfully applied to assembly reference
    ///
    /// # Errors
    ///
    /// This function never returns an error as atomic operations cannot fail.
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe as it uses atomic operations to update the assembly
    /// reference. Multiple threads can safely call this method concurrently.
    pub fn apply(&self) -> Result<()> {
        self.assembly_ref
            .os_major_version
            .store(self.os_major_version, Ordering::Relaxed);
        self.assembly_ref
            .os_minor_version
            .store(self.os_minor_version, Ordering::Relaxed);
        self.assembly_ref
            .os_platform_id
            .store(self.os_platform_id, Ordering::Relaxed);
        Ok(())
    }
}
