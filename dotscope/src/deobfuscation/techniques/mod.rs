//! Technique-centric deobfuscation framework.
//!
//! This module defines the core abstractions for technique-based deobfuscation,
//! where each deobfuscation capability is a standalone [`Technique`] that can
//! detect and transform specific obfuscation patterns independently of which
//! obfuscator produced them.
//!
//! # Trait Design
//!
//! A single [`Technique`] trait covers all capabilities. Optional capabilities
//! are expressed via default method implementations that return `None` / no-ops:
//!
//! - **IL detection**: [`Technique::detect`] — required, runs on raw IL
//! - **SSA detection**: [`Technique::detect_ssa`] — optional, runs after SSA is built
//! - **Byte transform**: [`Technique::byte_transform`] — optional, returns `None` if not applicable
//! - **SSA pass**: [`Technique::ssa_phase`] + [`Technique::create_pass`] — optional
//! - **Initialization**: [`Technique::initialize`] — optional, registers decryptors/hooks
//! - **Cleanup**: [`Technique::cleanup`] — optional, contributes tokens to remove

mod assembly;
mod bitmono;
mod confuserex;
mod detection;
mod generic;
mod obfuscar;
mod registry;
mod result;

pub use assembly::WorkingAssembly;
pub use detection::{AttributionResult, Detection, Detections, Evidence};
pub use registry::{ObfuscatorSignature, TechniqueRegistry};
pub use result::TechniqueResult;

use std::sync::Arc;

use crate::{
    cilassembly::CleanupRequest,
    compiler::{EventLog, SsaPass},
    deobfuscation::{config::EngineConfig, context::AnalysisContext},
    CilObject, Result,
};

/// Execution phase for an SSA pass.
///
/// Determines when in the deobfuscation pipeline a pass runs.
/// The engine groups passes by phase and executes them in order:
/// `Structure` → `Value` → `Simplify` → `Inline` → `Normalize`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PassPhase {
    /// Structural transformations (e.g., control flow unflattening).
    Structure,
    /// Value-level transformations (e.g., constant decryption, string decryption).
    Value,
    /// Simplification passes (e.g., proxy resolution, anti-debug neutralization).
    Simplify,
    /// Inlining passes (e.g., delegate inlining).
    Inline,
    /// Normalization passes (e.g., nop removal, dead code elimination).
    Normalize,
}

/// Broad category for a technique, used for ordering and grouping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TechniqueCategory {
    /// Metadata-level transformations (renaming, attribute removal).
    Metadata,
    /// Protection removal (anti-tamper, anti-debug, anti-dump).
    Protection,
    /// Structural recovery (control-flow unflattening, proxy removal).
    Structure,
    /// Value recovery (string/constant decryption, array decryption).
    Value,
    /// Call-site transforms (delegate resolution, devirtualization).
    Call,
    /// Neutralization of obfuscation infrastructure.
    Neutralization,
}

/// Unified trait for all deobfuscation techniques.
///
/// Object-safe, `Send + Sync`. Every technique must provide identity, category,
/// and IL-level detection. All other capabilities (byte transform, SSA pass,
/// SSA-level detection) are expressed as optional default implementations.
///
/// # Capability Model
///
/// - **Byte transform** (`byte_transform` returns `Some`): technique can patch raw bytes
///   before SSA is built. Only runs when the technique is detected.
/// - **SSA pass** (`ssa_phase` returns `Some`): technique participates in the pass scheduler.
/// - **SSA detection** (`detect_ssa` returns non-empty): supplements IL detection with
///   def-use chain analysis after SSA is built, enabling cross-block pattern matching.
///
/// # Implementation Patterns
///
/// ## Pattern A — Technique-owned SSA pass
///
/// `ssa_phase()` returns `Some(phase)` and `create_pass()` returns `Some(pass)`.
/// Used when the SSA transform is specific to this technique, e.g.:
/// - `bitmono.calli` (`BitMonoCalli`): creates `CalltocalliReversalPass`
/// - `generic.opaquefields` (`GenericOpaquePredicates`): creates `OpaqueFieldPredicatePass`
///
/// ## Pattern B — Contributes to shared infrastructure
///
/// `ssa_phase()` returns `Some(phase)` and `create_pass()` returns `None`.
/// The technique registers decryptors or hooks in `initialize()`.
/// Used when multiple techniques feed a shared pass:
/// - `generic.strings`, `generic.constants`, `confuserex.constants`: all feed `DecryptionPass`
///
/// ## Pattern C — Byte-only transform
///
/// `byte_transform()` returns `Some(...)`, `ssa_phase()` returns `None`.
/// Used for PE/metadata patching without SSA involvement.
pub trait Technique: Send + Sync {
    // === Required ===

    /// Unique identifier (e.g. `"confuserex.constants"`).
    fn id(&self) -> &'static str;

    /// Human-readable name (e.g. `"ConfuserEx Constant Decryption"`).
    fn name(&self) -> &'static str;

    /// Broad category for ordering.
    fn category(&self) -> TechniqueCategory;

    /// Detect whether this technique's target pattern is present in raw IL.
    fn detect(&self, assembly: &CilObject) -> Detection;

    // === Ordering (all default) ===

    /// IDs of techniques that must run before this one.
    fn requires(&self) -> &[&'static str] {
        &[]
    }

    /// IDs of techniques this one replaces (older/weaker versions).
    fn supersedes(&self) -> &[&'static str] {
        &[]
    }

    /// Whether this technique is enabled under the given config.
    fn enabled(&self, _config: &EngineConfig) -> bool {
        true
    }

    // === SSA-level detection — default: no-op ===

    /// Optional detection that runs after all methods' SSA is built.
    ///
    /// Returns a non-empty [`Detection`] if the technique found additional
    /// evidence using SSA def-use chains. The engine merges this into the
    /// existing IL-level detections via [`Detections::merge`].
    ///
    /// Use this for patterns that span basic block boundaries and cannot be
    /// reliably detected from raw IL instruction windows.
    fn detect_ssa(&self, _ctx: &AnalysisContext, _assembly: &CilObject) -> Detection {
        Detection::new_empty()
    }

    // === Byte-level transform — default: None (no byte transform) ===

    /// Apply a byte-level transform on the raw assembly bytes.
    ///
    /// Returns `Some(Ok(events))` on success, `Some(Err(e))` on failure,
    /// or `None` if this technique has no byte transform.
    ///
    /// Byte transforms run before SSA is built and can patch raw bytes,
    /// decrypt method bodies, or unpack resources.
    fn byte_transform(
        &self,
        _assembly: &mut WorkingAssembly,
        _detection: &Detection,
        _detections: &Detections,
    ) -> Option<Result<EventLog>> {
        None
    }

    /// If `true`, the assembly must be fully regenerated after this technique's byte transform.
    fn requires_regeneration(&self) -> bool {
        false
    }

    // === SSA-level — all default: None / no-op ===

    /// Which scheduler phase this technique's pass runs in. `None` = no SSA pass.
    fn ssa_phase(&self) -> Option<PassPhase> {
        None
    }

    /// One-time initialization after detection (e.g. register decryptors).
    ///
    /// Called in Phase 4 after all SSA is available in `ctx`. Techniques
    /// use this to register decryptors, hook factories, or other shared state.
    fn initialize(
        &self,
        _ctx: &AnalysisContext,
        _assembly: &CilObject,
        _detection: &Detection,
        _detections: &Detections,
    ) {
    }

    /// Create an SSA pass instance for the pipeline.
    ///
    /// Called after [`initialize`](Self::initialize), so the context has been
    /// fully populated by all techniques. Returns `None` for Pattern B techniques
    /// that contribute to shared infrastructure instead of owning their own pass.
    ///
    /// # Arguments
    ///
    /// * `_ctx` - The shared analysis context.
    /// * `_detection` - Detection findings for this technique.
    /// * `_assembly` - The assembly being processed (needed for passes that require it at construction).
    ///
    /// # Returns
    ///
    /// `Some(pass)` if this technique owns a pass, `None` for Pattern B techniques.
    fn create_pass(
        &self,
        _ctx: &AnalysisContext,
        _detection: &Detection,
        _assembly: &Arc<CilObject>,
    ) -> Option<Box<dyn SsaPass>> {
        None
    }

    /// Tokens / sections to clean up after all passes complete.
    fn cleanup(&self, _detection: &Detection) -> Option<CleanupRequest> {
        None
    }
}
