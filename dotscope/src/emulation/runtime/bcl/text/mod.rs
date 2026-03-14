//! `System.Text` namespace BCL method hooks.
//!
//! This module provides hook implementations for .NET text encoding and string
//! building operations that are essential for decrypting obfuscated strings.
//!
//! # Organization
//!
//! | Module | .NET Type(s) | Description |
//! |--------|-------------|-------------|
//! | [`encoding`] | `System.Text.Encoding`, `System.Text.UTF8Encoding`, `System.Text.ASCIIEncoding`, `System.Text.UnicodeEncoding` | Text encoding and decoding between byte arrays and strings |
//! | [`stringbuilder`] | `System.Text.StringBuilder` | Mutable string construction |
//!
//! # Deobfuscation Relevance
//!
//! Text encoding is one of the most critical BCL areas for deobfuscation:
//! - **Encoding.GetString**: Final step in nearly all string decryption schemes — converts
//!   decrypted byte arrays back to readable strings
//! - **Encoding.GetBytes**: Used to prepare plaintext for re-encryption or hash verification
//! - **StringBuilder**: Used by some obfuscators to incrementally build decrypted strings
//!   character-by-character to evade static analysis

mod encoding;
mod stringbuilder;

use crate::{emulation::runtime::hook::HookManager, Result};

/// Registers all `System.Text` namespace hooks with the given hook manager.
///
/// Delegates to each submodule's `register()` function to install hooks for
/// `Encoding`, `UTF8Encoding`, `ASCIIEncoding`, `UnicodeEncoding`, and `StringBuilder`.
///
/// # Arguments
///
/// * `manager` - The [`HookManager`] to register hooks with
pub fn register(manager: &HookManager) -> Result<()> {
    encoding::register(manager)?;
    stringbuilder::register(manager)?;
    Ok(())
}
