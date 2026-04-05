//! BitMono-specific SSA transformation passes.
//!
//! These passes reverse BitMono's obfuscation protections by operating on SSA
//! form. Each pass is created by its corresponding detection technique in
//! [`crate::deobfuscation::techniques::bitmono`] via
//! [`Technique::create_pass`](crate::deobfuscation::techniques::Technique::create_pass).
//!
//! # Passes
//!
//! | Pass | Phase | Description |
//! |------|-------|-------------|
//! | [`StringDecryptionPass`] | Simplify | Decrypts AES-256-CBC encrypted strings (requires `legacy-crypto` feature) |
//! | [`UnmanagedStringReversalPass`] | Simplify | Replaces fake native string method calls with `ldstr` constants |

#[cfg(feature = "legacy-crypto")]
mod strings;
mod unmanaged;

pub use self::unmanaged::UnmanagedStringReversalPass;

#[cfg(feature = "legacy-crypto")]
pub use self::strings::StringDecryptionPass;
