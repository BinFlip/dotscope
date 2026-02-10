//! Owned `ImportScope` table representation for Portable PDB format
//!
//! This module provides the [`ImportScope`] struct that represents
//! a fully resolved `ImportScope` table entry with processed data.
//! All heap indices have been resolved to their actual values and
//! the imports blob has been parsed into structured declarations.

use crate::{metadata::importscope::ImportsInfo, metadata::token::Token};

/// Owned representation of an `ImportScope` table entry
///
/// This structure contains the processed `ImportScope` data with all heap indices
/// resolved to their actual values. The imports field contains the resolved
/// binary data from the #Blob heap that describes the imported namespaces
/// and types available within this lexical scope.
///
/// # Fields
///
/// - `rid`: Row identifier (1-based index in the `ImportScope` table)
/// - `token`: Metadata token for this `ImportScope` entry
/// - `offset`: Byte offset in the original metadata stream
/// - `parent`: Index of parent `ImportScope` (0 for root scopes)
/// - `imports`: Resolved import data blob
#[derive(Debug, Clone)]
pub struct ImportScope {
    /// Row identifier (1-based index in the table)
    pub rid: u32,

    /// Metadata token for this `ImportScope` entry
    pub token: Token,

    /// Byte offset of this row in the original metadata stream
    pub offset: usize,

    /// Index into `ImportScope` table for parent scope
    ///
    /// Points to the parent import scope that encloses this scope, or 0 if
    /// this is a root-level import scope. Import scopes form a tree structure
    /// where child scopes inherit imports from their parent scopes.
    // ToDo: Resolve this to a ImportScopeRef
    pub parent: u32,

    /// Resolved import information
    ///
    /// Contains the parsed import declarations that describe the imported namespaces,
    /// types, and assemblies that are available within this lexical scope. All blob
    /// heap references have been resolved to their actual string values.
    pub imports: ImportsInfo,
}
