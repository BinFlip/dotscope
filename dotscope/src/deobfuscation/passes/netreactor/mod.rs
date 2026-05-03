//! .NET Reactor-specific SSA transformation passes.
//!
//! These passes complement the shared deobfuscation passes with NR-specific
//! rewrites that are only safe when the corresponding NR protection has been
//! detected. Each pass is created by its detection technique in
//! [`crate::deobfuscation::techniques::netreactor`] via
//! [`Technique::create_pass`](crate::deobfuscation::techniques::Technique::create_pass).
//!
//! # Passes
//!
//! | Pass | Phase | Description |
//! |------|-------|-------------|
//! | [`TokenResolverPass`] | Value | Folds `accessor(<const_int>)` calls back to `ldtoken X` for the NR anti-tamper metadata-token resolver |
//! | [`ResourceShimRewritePass`] | Value | Rewrites NR resource-resolver shim calls (`eBxqprrF8` → `Assembly::GetManifestResourceNames`; lazy-init → `Nop`) so the resolver type can be deleted |

mod resolver;
mod rewrite;

pub use self::resolver::TokenResolverPass;
pub use self::rewrite::ResourceShimRewritePass;
