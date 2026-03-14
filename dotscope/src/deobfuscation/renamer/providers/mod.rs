//! Rename provider implementations.
//!
//! Contains the available [`RenameProvider`](super::RenameProvider) implementations:
//! - [`SimpleProvider`] — sequential alphabetic names (always available)
//! - [`LocalProvider`](local::LocalProvider) — LLM-powered semantic names (requires `smart-rename` feature)

mod simple;

#[cfg(feature = "smart-rename")]
mod local;

pub use simple::{SimpleNameGenerator, SimpleProvider};

use crate::deobfuscation::renamer::{RenameProvider, SmartRenameConfig};

/// Creates the appropriate rename provider based on configuration.
///
/// Returns a [`LocalProvider`](local::LocalProvider) if the `smart-rename`
/// feature is enabled and a [`SmartRenameConfig`] is provided. Otherwise
/// falls back to [`SimpleProvider`].
///
/// # Arguments
///
/// * `config` - Optional smart rename configuration. When `None` or when the
///   `smart-rename` feature is not enabled, a [`SimpleProvider`] is returned.
///
/// # Returns
///
/// A boxed provider ready for [`initialize()`](RenameProvider::initialize).
pub fn create_provider(_config: Option<&SmartRenameConfig>) -> Box<dyn RenameProvider> {
    #[cfg(feature = "smart-rename")]
    if let Some(cfg) = _config {
        return Box::new(local::LocalProvider::new(cfg.clone()));
    }

    Box::new(SimpleProvider::new())
}
