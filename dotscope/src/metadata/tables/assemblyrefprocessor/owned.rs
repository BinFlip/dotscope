//! Owned `AssemblyRefProcessor` table representation.
//!
//! This module provides the [`crate::metadata::tables::assemblyrefprocessor::owned::AssemblyRefProcessor`] struct
//! which contains fully resolved processor architecture compatibility information for external assembly
//! references. This is the primary data structure for representing processor requirements for referenced
//! assemblies in a usable form after the dual variant resolution phase.
//!
//! # Architecture
//!
//! The owned representation stores fully resolved data from the `AssemblyRefProcessor` metadata table,
//! including resolved references to assembly dependencies. This eliminates the need for table
//! lookups during runtime access, providing immediate access to processor compatibility metadata.
//!
//! # Key Components
//!
//! - [`crate::metadata::tables::assemblyrefprocessor::owned::AssemblyRefProcessor`] - Main owned processor compatibility structure
//! - [`crate::metadata::tables::assemblyref::AssemblyRefRc`] - Referenced assembly dependency
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::tables::assemblyrefprocessor::raw`] - Raw table representation
//! - [`crate::metadata::tables::assemblyref`] - Assembly reference table entries
//! - [`crate::metadata::token`] - Token-based metadata references

use std::sync::atomic::Ordering;

use crate::{
    metadata::{tables::AssemblyRefRc, token::Token},
    Result,
};

/// Represents processor architecture compatibility information for an external assembly reference
///
/// This structure contains the complete processor requirement information from the `AssemblyRefProcessor`
/// metadata table (0x24), with all table references resolved to owned assembly reference instances.
/// Unlike [`crate::metadata::tables::assemblyrefprocessor::raw::AssemblyRefProcessorRaw`], this provides
/// immediate access to the referenced assembly without requiring table lookups.
///
/// # Processor Compatibility
///
/// The `AssemblyRefProcessor` table allows specifying explicit processor requirements for external assemblies:
/// - **Processor Architecture**: Target processor family identifier (x86, x64, ARM, etc.)
/// - **Assembly Reference**: The external assembly these requirements apply to
///
/// # Historical Context
///
/// This table is rarely used in modern .NET assemblies and is considered legacy. It was designed
/// for early .NET Framework scenarios where assemblies might need explicit processor architecture
/// declarations. Modern .NET relies on runtime platform abstraction and JIT compilation instead.
///
/// # Thread Safety
///
/// This type is [`Send`] and [`Sync`]. All fields are read-only after construction and safe
/// for concurrent access. The `apply` method uses atomic operations when updating assembly
/// reference data.
///
/// # References
/// - [ECMA-335 II.22.8](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `AssemblyRefProcessor` table specification
pub struct AssemblyRefProcessor {
    /// Row identifier within the `AssemblyRefProcessor` metadata table
    ///
    /// The 1-based index of this `AssemblyRefProcessor` row within the table.
    pub rid: u32,

    /// Metadata token for this `AssemblyRefProcessor` entry
    ///
    /// Combines the table identifier (0x24 for `AssemblyRefProcessor`) with the row ID to create
    /// a unique token that can be used to reference this entry from other metadata.
    pub token: Token,

    /// Byte offset of this `AssemblyRefProcessor` row within the metadata tables stream
    ///
    /// Physical location of the raw `AssemblyRefProcessor` data within the metadata binary format.
    /// Used for debugging and low-level metadata analysis.
    pub offset: usize,

    /// Processor architecture identifier
    ///
    /// Specifies the target processor architecture. Common values include:
    /// - `0x0000`: No specific processor requirement
    /// - `0x014C`: Intel 386 (x86)
    /// - `0x8664`: AMD64 (x64)
    /// - `0x01C0`: ARM (32-bit)
    /// - `0xAA64`: ARM64
    ///
    /// See processor architecture constants in PE specification for standard values.
    pub processor: u32,

    /// Reference to the external assembly this processor requirement applies to
    ///
    /// Points to the corresponding [`crate::metadata::tables::assemblyref::AssemblyRef`]
    /// entry that represents the external assembly dependency with this processor requirement.
    pub assembly_ref: AssemblyRefRc,
}

impl AssemblyRefProcessor {
    /// Apply processor architecture information to the referenced assembly
    ///
    /// Updates the referenced assembly with processor architecture information from this
    /// `AssemblyRefProcessor` entry. The assembly reference already contains atomic fields for storing
    /// processor data, allowing thread-safe updates without additional synchronization.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Processor information successfully applied to assembly reference
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
            .processor
            .store(self.processor, Ordering::Relaxed);
        Ok(())
    }
}
