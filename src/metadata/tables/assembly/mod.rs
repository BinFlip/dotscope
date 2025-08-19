//! Assembly table module
//!
//! Provides complete support for the ECMA-335 Assembly metadata table (0x20), which contains
//! the identity and versioning information for the current assembly. This module includes
//! raw table access, resolved data structures, and collection types.
//!
//! # Components
//!
//! - [`crate::metadata::tables::assembly::AssemblyRaw`]: Raw table structure with unresolved heap indexes
//! - [`crate::metadata::tables::assembly::Assembly`]: Owned variant with resolved strings/blobs and full metadata
//! - [`crate::metadata::tables::assembly::loader::AssemblyLoader`]: Internal loader for processing Assembly table data
//! - Type aliases for efficient collections and reference management
//!
//! # Assembly Table Structure
//!
//! The Assembly table contains exactly one row (if present) with these fields:
//! - **`HashAlgId`**: Hash algorithm identifier (see [`crate::metadata::tables::assembly::AssemblyHashAlgorithm`])
//! - **Version**: Four-part version number (Major.Minor.Build.Revision)
//! - **Flags**: Assembly attributes (see [`crate::metadata::tables::assembly::AssemblyFlags`])
//! - **`PublicKey`**: Strong name public key for assembly verification
//! - **Name**: Simple assembly name (e.g., "System.Core")
//! - **Culture**: Localization culture (empty for culture-neutral assemblies)
//!
//! # Reference
//! - [ECMA-335 II.22.2](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Assembly table specification
use crossbeam_skiplist::SkipMap;
use std::sync::Arc;

use crate::metadata::token::Token;

mod builder;
mod loader;
mod owned;
mod raw;
mod reader;
mod writer;

pub use builder::*;
pub(crate) use loader::*;
pub use owned::*;
pub use raw::*;

/// A map that holds the mapping of [`crate::metadata::token::Token`] to parsed [`crate::metadata::tables::assembly::Assembly`]
///
/// Thread-safe concurrent map using skip list data structure for efficient lookups
/// and insertions. Used to cache resolved assembly references by their metadata tokens.
pub type AssemblyMap = SkipMap<Token, AssemblyRc>;

/// A vector that holds a list of [`crate::metadata::tables::assembly::Assembly`] references
///
/// Thread-safe append-only vector for storing assembly collections. Uses atomic operations
/// for lock-free concurrent access and is optimized for scenarios with frequent reads.
pub type AssemblyList = Arc<boxcar::Vec<AssemblyRc>>;

/// A reference-counted pointer to an [`crate::metadata::tables::assembly::Assembly`]
///
/// Provides shared ownership and automatic memory management for assembly instances.
/// Multiple references can safely point to the same assembly data across threads.
pub type AssemblyRc = Arc<Assembly>;

#[allow(non_snake_case)]
/// Assembly flags bit field constants
///
/// Defines assembly-level attributes that control loading behavior, security requirements,
/// and compatibility settings. These flags are stored in the Assembly table's Flags field
/// and can be combined using bitwise OR operations.
///
/// # Reference
/// - [ECMA-335 II.23.1.2](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `AssemblyFlags` enumeration
pub mod AssemblyFlags {
    /// The assembly reference holds the full (unhashed) public key
    ///
    /// When set, the `PublicKey` field contains the complete public key.
    /// When clear, the `PublicKey` field contains only the public key token (last 8 bytes of hash).
    pub const PUBLIC_KEY: u32 = 0x0001;

    /// The implementation of this assembly used at runtime is not expected to match the version seen at compile time
    ///
    /// Allows the runtime to substitute a different version of this assembly if available.
    /// Commonly used for platform assemblies that may have runtime-specific implementations.
    pub const RETARGETABLE: u32 = 0x0100;

    /// Reserved (a conforming implementation of the CLI may ignore this setting on read)
    ///
    /// Legacy flag for JIT compiler optimization control. Modern runtimes typically ignore this setting.
    pub const DISABLE_JIT_COMPILE_OPTIMIZER: u32 = 0x4000;

    /// Reserved (a conforming implementation of the CLI may ignore this setting on read)
    ///
    /// Legacy flag for JIT compiler tracking control. Modern runtimes typically ignore this setting.
    pub const ENABLE_JIT_COMPILE_TRACKING: u32 = 0x8000;
}

#[allow(non_snake_case)]
/// Assembly hash algorithm constants
///
/// Defines cryptographic hash algorithms used for assembly integrity verification.
/// The hash algorithm is specified in the Assembly table's `HashAlgId` field and
/// determines how file hashes in the manifest are computed.
///
/// # Security Note
///
/// MD5 is considered cryptographically weak and should not be used for new assemblies.
/// SHA1 is also deprecated for security purposes. Modern assemblies should use stronger
/// hash algorithms, though ECMA-335 hasn't been updated to reflect this.
///
/// # Reference
/// - [ECMA-335 II.23.1.1](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `AssemblyHashAlgorithm` enumeration
// TODO: Microsoft has extended this enumeration in newer versions without updating ECMA-335
pub mod AssemblyHashAlgorithm {
    /// No hash algorithm specified
    ///
    /// Indicates that no file integrity checking should be performed.
    /// This is appropriate for assemblies that don't require verification.
    pub const NONE: u32 = 0x0000;

    /// MD5 hash algorithm (RFC 1321)
    ///
    /// **Security Warning**: MD5 is cryptographically broken and should not be used
    /// for security-sensitive applications. Included for compatibility with legacy assemblies.
    pub const MD5: u32 = 0x8003;

    /// SHA1 hash algorithm (FIPS 180-1)
    ///
    /// **Security Warning**: SHA1 is deprecated due to known collision vulnerabilities.
    /// While stronger than MD5, it should be avoided for new assemblies.
    pub const SHA1: u32 = 0x8004;
}
