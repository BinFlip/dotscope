//! `MethodDef` table module
//!
//! This module contains all components related to the `MethodDef` metadata table:
//! - `MethodDefRaw`: Raw table structure with unresolved indexes
//! - Internal loader (pub(crate) only)
mod loader;
mod raw;

pub(crate) use loader::*;
pub use raw::*;
