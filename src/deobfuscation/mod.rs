//! Deobfuscation framework for .NET assemblies.
//!
//! This module provides a comprehensive deobfuscation system built on SSA
//! (Static Single Assignment) form. The key insight is that SSA provides
//! explicit def-use chains that make value tracking and propagation natural.
//!
//! # Architecture
//!
//! The deobfuscation system is SSA-centric:
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                        Deobfuscation Pipeline                           │
//! ├─────────────────────────────────────────────────────────────────────────┤
//! │  Input: Assembly (CilObject)                                            │
//! │           │                                                             │
//! │           ▼                                                             │
//! │  ┌─────────────────────────────────────────────────────────────────┐   │
//! │  │                    Obfuscator Detection                          │   │
//! │  │  Obfuscator-based detection with confidence scoring              │   │
//! │  └────────────────────────────┬────────────────────────────────────┘   │
//! │                               │                                         │
//! │                               ▼                                         │
//! │  ┌─────────────────────────────────────────────────────────────────┐   │
//! │  │                    Build SSA & Analysis Context                  │   │
//! │  │  CFG → Dominance → Phi Placement → Interprocedural Analysis     │   │
//! │  └────────────────────────────┬────────────────────────────────────┘   │
//! │                               │                                         │
//! │                               ▼                                         │
//! │  ┌─────────────────────────────────────────────────────────────────┐   │
//! │  │                    Pass Scheduler (Fixpoint)                     │   │
//! │  │  ┌───────────────────────────────────────────────────────────┐  │   │
//! │  │  │ Run passes in priority order until no more changes:       │  │   │
//! │  │  │                                                           │  │   │
//! │  │  │  Value Propagation & Folding:                             │  │   │
//! │  │  │  • Constant Propagation (SCCP-based)                      │  │   │
//! │  │  │  • Copy Propagation / Phi Simplification                  │  │   │
//! │  │  │  • Global Value Numbering (CSE)                           │  │   │
//! │  │  │  • Strength Reduction                                     │  │   │
//! │  │  │                                                           │  │   │
//! │  │  │  Control Flow Recovery:                                   │  │   │
//! │  │  │  • Control Flow Simplification (jump threading)           │  │   │
//! │  │  │  • Control Flow Unflattening (dispatcher removal)         │  │   │
//! │  │  │  • Enhanced Unflattening (SCCP + emulation)               │  │   │
//! │  │  │  • Loop Canonicalization (preheader/latch insertion)      │  │   │
//! │  │  │                                                           │  │   │
//! │  │  │  Dead Code Elimination:                                   │  │   │
//! │  │  │  • Dead Code Elimination (unreachable blocks)             │  │   │
//! │  │  │  • Dead Method Elimination (unused methods)               │  │   │
//! │  │  │                                                           │  │   │
//! │  │  │  Predicate & Condition Handling:                          │  │   │
//! │  │  │  • Opaque Predicate Removal                               │  │   │
//! │  │  │                                                           │  │   │
//! │  │  │  String & Data Recovery:                                  │  │   │
//! │  │  │  • String Decryption (emulation-based)                    │  │   │
//! │  │  │  • String Pattern Matching (lightweight)                  │  │   │
//! │  │  │                                                           │  │   │
//! │  │  │  Method Optimization:                                     │  │   │
//! │  │  │  • Small Method Inlining                                  │  │   │
//! │  │  └───────────────────────────────────────────────────────────┘  │   │
//! │  │  Repeat until fixpoint (no more changes)                        │   │
//! │  └────────────────────────────┬────────────────────────────────────┘   │
//! │                               │                                         │
//! │                               ▼                                         │
//! │  Output: DeobfuscationResult (stats, changes, detection info)          │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Key Components
//!
//! ## Engine
//!
//! The main entry point for deobfuscation ([`DeobfuscationEngine`](crate::deobfuscation::DeobfuscationEngine)):
//!
//! - Orchestrates detection, analysis, pass execution, and postprocessing
//! - Manages obfuscator support for detection and specialized handling
//! - Coordinates the pass scheduler for fixpoint iteration
//!
//! ## Obfuscator System
//!
//! Extensible obfuscator detection and handling ([`Obfuscator`](crate::deobfuscation::Obfuscator)):
//!
//! - [`ObfuscatorDetector`](crate::deobfuscation::ObfuscatorDetector) - Runs obfuscators to identify which one was used
//! - [`ObfuscatorRegistry`](crate::deobfuscation::ObfuscatorRegistry) - Manages registered obfuscators
//! - [`DetectionScore`](crate::deobfuscation::DetectionScore) / [`DetectionResult`](crate::deobfuscation::DetectionResult) - Confidence-based detection
//!
//! ## Pass System
//!
//! SSA-based transformation passes ([`SsaPass`](crate::deobfuscation::SsaPass)):
//!
//! - [`PassScheduler`](crate::deobfuscation::PassScheduler) - Manages pass execution order and fixpoint iteration
//! - [`EventLog`](crate::deobfuscation::EventLog) - Tracks changes made by passes
//! - [`AnalysisContext`](crate::deobfuscation::AnalysisContext) - Shared interprocedural analysis data
//!
//! # Built-in Passes
//!
//! The framework includes a comprehensive set of SSA transformation passes.
//! See the [`passes`](crate::deobfuscation::passes) module for detailed documentation of each pass.
//!
//! ## Value Propagation & Folding
//!
//! | Pass | Description |
//! |------|-------------|
//! | [`ConstantPropagationPass`](crate::deobfuscation::passes::ConstantPropagationPass) | Propagates and folds constant values using SCCP |
//! | [`CopyPropagationPass`](crate::deobfuscation::passes::CopyPropagationPass) | Eliminates redundant copy operations and phi nodes |
//! | [`GlobalValueNumberingPass`](crate::deobfuscation::passes::GlobalValueNumberingPass) | Eliminates redundant computations via value numbering |
//! | [`StrengthReductionPass`](crate::deobfuscation::passes::StrengthReductionPass) | Replaces expensive operations with cheaper equivalents |
//!
//! ## Control Flow Recovery
//!
//! | Pass | Description |
//! |------|-------------|
//! | [`ControlFlowSimplificationPass`](crate::deobfuscation::passes::ControlFlowSimplificationPass) | Jump threading, branch simplification, dead tail removal |
//! | [`ControlFlowUnflatteningPass`](crate::deobfuscation::passes::ControlFlowUnflatteningPass) | Z3-backed dispatcher analysis and CFG reconstruction |
//! | [`LoopCanonicalizationPass`](crate::deobfuscation::passes::LoopCanonicalizationPass) | Ensures loops have single preheaders and latches |
//!
//! ## Dead Code Elimination
//!
//! | Pass | Description |
//! |------|-------------|
//! | [`DeadCodeEliminationPass`](crate::deobfuscation::passes::DeadCodeEliminationPass) | Removes unreachable blocks and unused definitions |
//! | [`DeadMethodEliminationPass`](crate::deobfuscation::passes::DeadMethodEliminationPass) | Identifies and marks methods with no live callers |
//!
//! ## Predicate & Condition Handling
//!
//! | Pass | Description |
//! |------|-------------|
//! | [`OpaquePredicatePass`](crate::deobfuscation::passes::OpaquePredicatePass) | Removes always-true/false conditions, simplifies comparisons |
//!
//! ## Decryption
//!
//! | Pass | Description |
//! |------|-------------|
//! | [`DecryptionPass`](crate::deobfuscation::passes::DecryptionPass) | Decrypts values via emulation of registered decryptor methods |
//!
//! Decryptors are registered via:
//! - Obfuscator-specific detection (e.g., ConfuserEx pattern matching)
//! - [`HeuristicDecryptorDetector`] for generic signature-based detection
//!
//! ## Method Optimization
//!
//! | Pass | Description |
//! |------|-------------|
//! | [`InliningPass`](crate::deobfuscation::passes::InliningPass) | Inlines small methods and constant-returning functions |
//!
//! # Usage
//!
//! ## Basic Usage
//!
//! ```rust,ignore
//! use dotscope::deobfuscation::{DeobfuscationEngine, EngineConfig};
//!
//! let config = EngineConfig::default();
//! let mut engine = DeobfuscationEngine::new(config);
//!
//! let mut assembly = CilObject::from_path("obfuscated.dll")?;
//! let result = engine.process_file(&mut assembly)?;
//!
//! println!("{}", result.summary());
//! ```
//!
//! ## Custom Configuration
//!
//! ```rust,no_run
//! use dotscope::deobfuscation::{DeobfuscationEngine, EngineConfig};
//!
//! let config = EngineConfig {
//!     max_iterations: 50,
//!     inline_threshold: 30,
//!     emulation_max_instructions: 50000,
//!     ..Default::default()
//! };
//!
//! let mut engine = DeobfuscationEngine::new(config);
//! ```
//!
//! ## Adding Custom Obfuscators
//!
//! ```rust,ignore
//! use dotscope::deobfuscation::{DeobfuscationEngine, Obfuscator};
//!
//! let mut engine = DeobfuscationEngine::with_defaults();
//! engine.register_obfuscator(Arc::new(MyCustomObfuscator::new()));
//! ```

// Infrastructure
mod changes;
mod cleanup;
mod config;
mod context;
mod decryptors;
mod detection;
mod pass;
mod result;
mod scheduler;
mod statemachine;
mod summary;

// Engine and detector
mod detector;
mod engine;

// Code generation
mod codegen;

// Built-in passes
pub mod passes;

// Obfuscator support
mod obfuscators;

// Core types
pub use changes::{DerivedStats, Event, EventKind, EventLog};
pub use cleanup::execute_cleanup;
pub use config::{CleanupConfig, EngineConfig, ResolutionStrategy};
pub use context::{AnalysisContext, HookFactory};
pub use decryptors::{CacheKey, DecryptedCall, DecryptorContext, FailedCall, FailureReason};
pub use detection::{DetectionEvidence, DetectionResult, DetectionScore};
pub use detector::{DetectorBuilder, ObfuscatorDetector};
pub use engine::DeobfuscationEngine;
pub use obfuscators::{
    create_anti_tamper_stub_hook, create_lzma_hook, detect_confuserex, find_encrypted_methods,
    ConfuserExFindings, ConfuserExObfuscator, Obfuscator, ObfuscatorInfo, ObfuscatorRegistry,
};
pub use pass::SsaPass;
pub use result::DeobfuscationResult;
pub use scheduler::PassScheduler;
pub use statemachine::{
    CfgInfo, SsaOpKind, StateMachineCallSite, StateMachineProvider, StateMachineSemantics,
    StateMachineState, StateSlotOperation, StateUpdateCall,
};
pub use summary::{CallSiteInfo, MethodSummary, ParameterSummary};

// Code generation
pub use codegen::SsaCodeGenerator;

// Native method conversion
pub use passes::{ConversionStats, NativeMethodConversionPass};

#[cfg(test)]
mod tests {
    use crate::{
        deobfuscation::{DeobfuscationEngine, EngineConfig},
        metadata::validation::ValidationConfig,
        CilObject,
    };

    #[test]
    fn test_process_file_api() -> crate::Result<()> {
        let path = "tests/samples/packers/confuserex/original.exe";

        let mut engine = DeobfuscationEngine::new(EngineConfig::default());
        let (deobfuscated, result) = engine.process_file(path)?;

        assert!(deobfuscated.module().is_some());
        assert!(deobfuscated.module().is_some());
        assert!(result.total_time.as_millis() > 0);

        Ok(())
    }

    #[test]
    fn test_process_assembly_api() -> crate::Result<()> {
        let path = "tests/samples/packers/confuserex/original.exe";

        let assembly = CilObject::from_path_with_validation(path, ValidationConfig::analysis())?;

        let mut engine = DeobfuscationEngine::new(EngineConfig::default());
        let (deobfuscated, result) = engine.process_assembly(assembly)?;

        assert!(deobfuscated.module().is_some());
        assert!(result.total_time.as_millis() > 0);

        Ok(())
    }

    #[test]
    fn test_process_bytes_api() -> crate::Result<()> {
        let path = "tests/samples/packers/confuserex/original.exe";
        let bytes = std::fs::read(path)?;

        let mut engine = DeobfuscationEngine::new(EngineConfig::default());
        let (deobfuscated, result) = engine.process_bytes(bytes)?;

        assert!(deobfuscated.module().is_some());
        assert!(result.total_time.as_millis() > 0);

        Ok(())
    }
}
