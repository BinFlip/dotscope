//! Deobfuscation-specific SSA transformation passes.
//!
//! These passes complement the generic compiler passes in [`crate::compiler`]
//! with transformations that require obfuscator-specific knowledge: decryptor
//! registrations, dispatcher tracking, emulation hooks, and state machines.
//!
//! # Passes
//!
//! | Pass | Phase | Description |
//! |------|-------|-------------|
//! | [`OpaqueFieldPredicatePass`] | Structure | Removes opaque predicates based on static field chains resolved via emulation, before CFF unflattening |
//! | [`CffReconstructionPass`] | Structure | Recovers original control flow from flattened state-machine dispatchers using Z3-backed symbolic analysis and tree-based tracing |
//! | [`DecryptionPass`] | Value | Decrypts obfuscated strings and constants by emulating registered decryptor methods, with caching and state machine support |
//! | [`NeutralizationPass`] | Cleanup | Removes protection code (anti-tamper, anti-debug calls) from method bodies via taint analysis, preserving legitimate initialization |
//! | [`NativeMethodConversionPass`] | Pre-SSA | Converts native x86 methods back to CIL bytecode (runs before the SSA pipeline) |
//!
//! # Relationship to Compiler Passes
//!
//! Generic SSA passes ([`crate::compiler::SsaPass`]) operate only on
//! [`crate::compiler::CompilerContext`] and have no knowledge
//! of obfuscators. The passes here take shared references (via `Arc`) to
//! deobfuscation state from [`AnalysisContext`](crate::deobfuscation::AnalysisContext)
//! at construction time, allowing them to participate in the same
//! [`PassScheduler`](crate::compiler::PassScheduler) pipeline as compiler passes.

mod decryption;
mod delegates;
mod native;
mod neutralize;
mod opaquefields;
mod unflattening;

pub use self::decryption::DecryptionPass;
pub use self::delegates::{DelegateProxyResolutionPass, DelegateTypeInfo};
pub use self::native::{ConversionStats, NativeMethodConversionPass};
pub use self::neutralize::NeutralizationPass;
pub use self::opaquefields::OpaqueFieldPredicatePass;
pub use self::unflattening::CffReconstructionPass;
pub use self::unflattening::{TraceTree, UnflattenConfig};
