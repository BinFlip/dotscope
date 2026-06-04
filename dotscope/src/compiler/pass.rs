//! CIL-side pass infrastructure — re-exports analyssa's target-agnostic
//! [`SsaPass`] trait and supporting types, plus the CIL-specific
//! [`CilCapability`] enum and the [`PassPhase`] convention dotscope uses
//! to organize its deobfuscation pipeline.
//!
//! The actual trait and scheduling engine live in
//! [`analyssa::scheduling`]; this module specializes them for CIL.

pub use analyssa::scheduling::{DeobfuscationCapability, ModificationScope, SsaPass, SsaPassHost};

/// CIL-side capability tag.
///
/// Today this is a flat mirror of analyssa's [`DeobfuscationCapability`]
/// vocabulary so existing CIL passes can keep declaring
/// `PassCapability::DecryptedStrings` etc. without ceremony. Future
/// CIL-only milestones (e.g. .NET-specific tags not shared with x86/MIPS
/// hosts) land here as new variants. The
/// [`From<DeobfuscationCapability>`] impl bridges analyssa-side passes that
/// declare provides/requires using the shared vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CilCapability {
    /// Static field values have been resolved to concrete constants.
    ResolvedStaticFields,
    /// Encrypted strings have been decrypted.
    DecryptedStrings,
    /// Control flow flattening has been reversed.
    RestoredControlFlow,
    /// Opaque predicates have been simplified or removed.
    SimplifiedPredicates,
    /// Proxy or virtual calls have been devirtualized.
    DevirtualizedCalls,
    /// Small or pure methods have been inlined at their call sites.
    InlinedMethods,
}

impl From<DeobfuscationCapability> for CilCapability {
    fn from(cap: DeobfuscationCapability) -> Self {
        match cap {
            DeobfuscationCapability::ResolvedStaticFields => Self::ResolvedStaticFields,
            DeobfuscationCapability::DecryptedStrings => Self::DecryptedStrings,
            DeobfuscationCapability::RestoredControlFlow => Self::RestoredControlFlow,
            DeobfuscationCapability::SimplifiedPredicates => Self::SimplifiedPredicates,
            DeobfuscationCapability::DevirtualizedCalls => Self::DevirtualizedCalls,
            DeobfuscationCapability::InlinedMethods => Self::InlinedMethods,
        }
    }
}

/// Execution phase for a CIL pass — fallback layer assignment when the
/// scheduler can't derive ordering from capability dependencies.
///
/// Convention: `Structure=0`, `Value=1`, `Simplify=2`, `Inline=3`.
/// `Normalize` passes don't participate in layered scheduling and run
/// between every layer's fixpoint iterations (registered via
/// [`analyssa::scheduling::PassScheduler::add_normalize`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PassPhase {
    /// Structural transformations (e.g. control-flow unflattening).
    Structure,
    /// Value-level transformations (e.g. constant decryption).
    Value,
    /// Simplification passes (e.g. proxy resolution).
    Simplify,
    /// Inlining passes (e.g. delegate inlining).
    Inline,
    /// Normalization passes (e.g. nop removal, dead-code elimination).
    Normalize,
}

impl PassPhase {
    /// Returns the fallback scheduler layer for this phase.
    #[must_use]
    pub fn as_layer(self) -> usize {
        match self {
            Self::Structure => 0,
            Self::Value => 1,
            Self::Simplify => 2,
            Self::Inline => 3,
            Self::Normalize => 0,
        }
    }
}

/// Backwards-compatible alias of [`CilCapability`].
pub type PassCapability = CilCapability;
