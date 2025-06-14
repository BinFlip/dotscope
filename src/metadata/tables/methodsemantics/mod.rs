//! # `MethodSemantics` Table Module
//!
//! This module provides access to the `MethodSemantics` metadata table, which specifies the
//! relationship between methods and events or properties. It defines which methods are
//! getters, setters, adders, removers, etc.
//!
//! The module follows a dual-variant pattern:
//! - `MethodSemanticsRaw`: Raw table data with unresolved indexes
//! - `MethodSemantics`: Processed data with resolved references and owned data
//!
//! ## Usage
//!
//! ```rust
//! use dotscope::metadata::tables::{MethodSemantics, MethodSemanticsRaw, MethodSemanticsAttributes};
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

/// A map that holds the mapping of Token to parsed `MethodSemantics`
pub type MethodSemanticsMap = SkipMap<Token, MethodSemanticsRc>;
/// A vector that holds a list of `MethodSemantics`
pub type MethodSemanticsList = Arc<boxcar::Vec<MethodSemanticsRc>>;
/// A reference to a `MethodSemantics`
pub type MethodSemanticsRc = Arc<MethodSemantics>;

#[allow(non_snake_case)]
/// All possible flags for `MethodSemanticsAttributes`
pub mod MethodSemanticsAttributes {
    /// Setter for property
    pub const SETTER: u32 = 0x0001;
    /// Getter for property
    pub const GETTER: u32 = 0x0002;
    /// Other method for property or event
    pub const OTHER: u32 = 0x0004;
    /// `AddOn` method for event
    pub const ADD_ON: u32 = 0x0008;
    /// `RemoveOn` method for event
    pub const REMOVE_ON: u32 = 0x0010;
    /// Fire method for event
    pub const FIRE: u32 = 0x0020;
}
