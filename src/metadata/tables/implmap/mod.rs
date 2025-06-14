//! `ImplMap` table module
//!
//! This module contains all components related to the `ImplMap` metadata table:
//! - `ImplMapRaw`: Raw table structure with unresolved indexes
//! - `ImplMap`: Owned variant with resolved indexes and owned data  
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

/// A map that holds the mapping of Token to parsed `ImplMap`
pub type ImplMapMap = SkipMap<Token, ImplMapRc>;
/// A vector that holds a list of `ImplMap`
pub type ImplMapList = Arc<boxcar::Vec<ImplMapRc>>;
/// A reference to a `ImplMap`
pub type ImplMapRc = Arc<ImplMap>;

#[allow(non_snake_case)]
/// All possible flags for `PInvokeAttributes`
pub mod PInvokeAttributes {
    /// `PInvoke` is to use the member name as specified
    pub const NO_MANGLE: u32 = 0x0001;
    /// `PInvoke` is to import a character set conversion library
    pub const CHAR_SET_NOT_SPEC: u32 = 0x0000;
    /// `PInvoke` is to import a character set conversion library
    pub const CHAR_SET_ANSI: u32 = 0x0002;
    /// `PInvoke` is to import a character set conversion library
    pub const CHAR_SET_UNICODE: u32 = 0x0004;
    /// `PInvoke` is to import a character set conversion library
    pub const CHAR_SET_AUTO: u32 = 0x0006;
    /// Character set mask
    pub const CHAR_SET_MASK: u32 = 0x0006;
    /// Information about target function. Not relevant for fields
    pub const SUPPORTS_LAST_ERROR: u32 = 0x0040;
    /// Calling convention mask
    pub const CALL_CONV_MASK: u32 = 0x0700;
    /// Calling convention = `WinAPI`
    pub const CALL_CONV_WINAPI: u32 = 0x0100;
    /// Calling convention = C
    pub const CALL_CONV_CDECL: u32 = 0x0200;
    /// Calling convention = `StdCall`
    pub const CALL_CONV_STDCALL: u32 = 0x0300;
    /// Calling convention = `ThisCall`
    pub const CALL_CONV_THISCALL: u32 = 0x0400;
    /// Calling convention = `FastCall`
    pub const CALL_CONV_FASTCALL: u32 = 0x0500;
    /// Calling convention specified explicitly
    pub const BEST_FIT_MASK: u32 = 0x0030;
    /// Best fit mapping
    pub const BEST_FIT_ENABLED: u32 = 0x0010;
    /// Best fit mapping is disabled
    pub const BEST_FIT_DISABLED: u32 = 0x0020;
    /// Throw on unmappable chars
    pub const THROW_ON_UNMAPPABLE_MASK: u32 = 0x3000;
    /// Throw on unmappable chars enabled
    pub const THROW_ON_UNMAPPABLE_ENABLED: u32 = 0x1000;
    /// Throw on unmappable chars disabled
    pub const THROW_ON_UNMAPPABLE_DISABLED: u32 = 0x2000;
}
