//! # Param Table Module
//!
//! This module provides access to the Param metadata table, which contains information
//! about method parameters, including their names, attributes, and default values.
//!
//! The module follows a dual-variant pattern:
//! - `ParamRaw`: Raw table data with unresolved indexes
//! - `Param`: Processed data with resolved references and owned strings
//!
//! ## Usage
//!
//! ```rust
//! use dotscope::metadata::tables::{Param, ParamRaw, ParamAttributes};
//! ```
use crate::metadata::token::Token;
use crossbeam_skiplist::SkipMap;
use std::sync::Arc;

mod loader;
mod owned;
mod raw;

pub(crate) use loader::*;
pub use owned::*;
pub use raw::*;

/// A map that holds the mapping of Token to parsed `Param`
pub type ParamMap = SkipMap<Token, ParamRc>;
/// A vector that holds a list of `Param`
pub type ParamList = Arc<boxcar::Vec<ParamRc>>;
/// A reference to a `Param`
pub type ParamRc = Arc<Param>;

#[allow(non_snake_case)]
/// All possible flags for `ParamAttributes`
pub mod ParamAttributes {
    /// Param is `In`
    pub const IN: u32 = 0x0001;
    /// Param is `out`
    pub const OUT: u32 = 0x0002;
    /// Param is optional
    pub const OPTIONAL: u32 = 0x0010;
    /// Param has default value
    pub const HAS_DEFAULT: u32 = 0x1000;
    /// Param has `FieldMarshal`
    pub const HAS_FIELD_MARSHAL: u32 = 0x2000;
    /// Reserved: shall be zero in a conforming implementation
    pub const UNUSED: u32 = 0xcfe0;
}
