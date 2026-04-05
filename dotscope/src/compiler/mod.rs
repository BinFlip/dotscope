//! Compiler infrastructure for SSA-based code transformations.
//!
//! This module provides the middle layer between analysis and code generation:
//!
//! - [`crate::analysis`] — CIL → SSA construction, CFG, dataflow
//! - [`compiler`](self) — SSA optimization passes, codegen (SSA → CIL)
//! - [`crate::deobfuscation`] — Obfuscator detection, orchestration
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────────┐
//! │                      Compiler Pipeline                           │
//! ├──────────────────────────────────────────────────────────────────┤
//! │                                                                  │
//! │  CompilerContext              Shared interprocedural state        │
//! │    ├─ SSA functions           (per-method SSA, call graph,       │
//! │    ├─ Method summaries         known values, dead methods)       │
//! │    └─ EventLog                                                   │
//! │                                                                  │
//! │  PassScheduler               Capability-based layered execution  │
//! │    ├─ Structure layer         (CFF unflattening)                 │
//! │    ├─ Value layer             (decryption)                       │
//! │    ├─ Simplify layer          (predicates, CFG, threading)       │
//! │    ├─ Inline layer            (small method inlining)            │
//! │    └─ Normalize passes        (DCE, const prop, GVN, etc.)      │
//! │    Each layer: run → normalize → repeat until stable             │
//! │                                                                  │
//! │  SsaPass trait               Interface for all passes            │
//! │    ├─ run_on_method()         Per-method transformation          │
//! │    ├─ initialize()            One-time setup before pipeline     │
//! │    └─ finalize()              Cleanup after pipeline completes   │
//! │                                                                  │
//! │  Passes (16 built-in)        Optimization transformations        │
//! │    ├─ Value: const prop, copy prop, GVN, strength reduction      │
//! │    ├─ CFG: branch simplify, jump threading, loop canon           │
//! │    ├─ Cleanup: DCE, block merging, dead method elimination       │
//! │    └─ Other: opaque predicates, algebraic, reassociation, LICM   │
//! │                                                                  │
//! │  SsaCodeGenerator            SSA → CIL roundtrip                 │
//! │    ├─ Register allocation     (SSA vars → CIL locals)            │
//! │    ├─ Phi elimination         (φ nodes → moves)                  │
//! │    └─ Instruction selection   (SSA ops → CIL bytecode)           │
//! │                                                                  │
//! │  EventLog                    Change tracking and diagnostics     │
//! │  MethodSummary               Interprocedural analysis results    │
//! │                                                                  │
//! └──────────────────────────────────────────────────────────────────┘
//! ```

mod codegen;
mod context;
mod events;
mod pass;
mod passes;
mod scheduler;
mod state;
mod summary;

pub use codegen::{CompilationResult, SsaCodeGenerator};
pub use context::CompilerContext;
pub use events::{DerivedStats, Event, EventKind, EventLog};
pub use pass::{ModificationScope, PassCapability, PassPhase, SsaPass};
pub use passes::{
    AlgebraicSimplificationPass, BlockMergingPass, ConstantPropagationPass,
    ControlFlowSimplificationPass, CopyPropagationPass, DeadCodeEliminationPass,
    DeadMethodEliminationPass, GlobalValueNumberingPass, InliningPass, JumpThreadingPass, LicmPass,
    LoopCanonicalizationPass, OpaquePredicatePass, PredicateResult, ProxyDevirtualizationPass,
    ReassociationPass, StrengthReductionPass, ValueRangePropagationPass,
};
pub use scheduler::PassScheduler;
pub use state::ProcessingState;
pub use summary::{CallSiteInfo, MethodSummary, ParameterSummary};
