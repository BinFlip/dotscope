//! Assembly table module
//!
//! This module contains all components related to the Assembly metadata table:
//! - `AssemblyRaw`: Raw table structure with unresolved indexes
//! - `Assembly`: Owned variant with resolved indexes and owned data  
//! - Type aliases for collections and references
//! - Internal loader (pub(crate) only)
use crossbeam_skiplist::SkipMap;
use std::sync::Arc;

use crate::metadata::token::Token;

mod loader;
mod owned;
mod raw;

pub(crate) use loader::*;
pub use owned::*;
pub use raw::*;

/// A map that holds the mapping of Token to parsed `Assembly`
pub type AssemblyMap = SkipMap<Token, AssemblyRc>;
/// A vector that holds a list of `Assembly`
pub type AssemblyList = Arc<boxcar::Vec<AssemblyRc>>;
/// A reference to a `Assembly`
pub type AssemblyRc = Arc<Assembly>;

#[allow(non_snake_case)]
/// All possible flags for `AssemblyFlags`
pub mod AssemblyFlags {
    /// The assembly reference holds the full (unhashed) public key
    pub const PUBLIC_KEY: u32 = 0x0001;
    /// The implementation of this assembly used at runtime is not expected to match the version seen at compile time
    pub const RETARGETABLE: u32 = 0x0100;
    /// Reserved (a conforming implementation of the CLI may ignore this setting on read)
    pub const DISABLE_JIT_COMPILE_OPTIMIZER: u32 = 0x4000;
    /// Reserved (a conforming implementation of the CLI may ignore this setting on read)
    pub const ENABLE_JIT_COMPILE_TRACKING: u32 = 0x8000;
}

#[allow(non_snake_case)]
/// All possible values for `AssemblyHashAlgorithm`
// ToDo: It seems that MS has extended this in future versions, without updating ECMA-335
pub mod AssemblyHashAlgorithm {
    /// No hash algorithm specified
    pub const NONE: u32 = 0x0000;
    /// MD5 hash algorithm
    pub const MD5: u32 = 0x8003;
    /// SHA1 hash algorithm
    pub const SHA1: u32 = 0x8004;
}
