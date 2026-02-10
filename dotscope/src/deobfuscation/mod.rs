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
//! The main entry point for deobfuscation ([`crate::deobfuscation::DeobfuscationEngine`]):
//!
//! - Orchestrates detection, analysis, pass execution, and postprocessing
//! - Manages obfuscator support for detection and specialized handling
//! - Coordinates the pass scheduler for fixpoint iteration
//!
//! ## Obfuscator System
//!
//! Extensible obfuscator detection and handling ([`crate::deobfuscation::Obfuscator`]):
//!
//! - [`crate::deobfuscation::ObfuscatorDetector`] - Runs obfuscators to identify which one was used
//! - [`crate::deobfuscation::ObfuscatorRegistry`] - Manages registered obfuscators
//! - [`crate::deobfuscation::DetectionScore`] / [`crate::deobfuscation::DetectionResult`] - Confidence-based detection
//!
//! ## Pass System
//!
//! SSA-based transformation passes ([`crate::compiler::SsaPass`]):
//!
//! - [`crate::compiler::PassScheduler`] - Manages pass execution order and fixpoint iteration
//! - [`crate::compiler::EventLog`] - Tracks changes made by passes
//! - [`crate::deobfuscation::AnalysisContext`] - Shared interprocedural analysis data
//!
//! # Built-in Passes
//!
//! The framework includes a comprehensive set of SSA transformation passes.
//! See the [`compiler`](crate::compiler) module for detailed documentation of each pass.
//!
//! ## Value Propagation & Folding
//!
//! | Pass | Description |
//! |------|-------------|
//! | [`ConstantPropagationPass`](crate::compiler::ConstantPropagationPass) | Propagates and folds constant values using SCCP |
//! | [`CopyPropagationPass`](crate::compiler::CopyPropagationPass) | Eliminates redundant copy operations and phi nodes |
//! | [`GlobalValueNumberingPass`](crate::compiler::GlobalValueNumberingPass) | Eliminates redundant computations via value numbering |
//! | [`StrengthReductionPass`](crate::compiler::StrengthReductionPass) | Replaces expensive operations with cheaper equivalents |
//!
//! ## Control Flow Recovery
//!
//! | Pass | Description |
//! |------|-------------|
//! | [`ControlFlowSimplificationPass`](crate::compiler::ControlFlowSimplificationPass) | Jump threading, branch simplification, dead tail removal |
//! | [`CffReconstructionPass`](crate::deobfuscation::CffReconstructionPass) | Z3-backed dispatcher analysis and CFG reconstruction |
//! | [`LoopCanonicalizationPass`](crate::compiler::LoopCanonicalizationPass) | Ensures loops have single preheaders and latches |
//!
//! ## Dead Code Elimination
//!
//! | Pass | Description |
//! |------|-------------|
//! | [`DeadCodeEliminationPass`](crate::compiler::DeadCodeEliminationPass) | Removes unreachable blocks and unused definitions |
//! | [`DeadMethodEliminationPass`](crate::compiler::DeadMethodEliminationPass) | Identifies and marks methods with no live callers |
//!
//! ## Predicate & Condition Handling
//!
//! | Pass | Description |
//! |------|-------------|
//! | [`OpaquePredicatePass`](crate::compiler::OpaquePredicatePass) | Removes always-true/false conditions, simplifies comparisons |
//!
//! ## Decryption
//!
//! | Pass | Description |
//! |------|-------------|
//! | [`DecryptionPass`](crate::deobfuscation::DecryptionPass) | Decrypts values via emulation of registered decryptor methods |
//!
//! Decryptors are registered via:
//! - Obfuscator-specific detection (e.g., ConfuserEx pattern matching)
//! - Heuristic detection for generic signature-based detection
//!
//! ## Method Optimization
//!
//! | Pass | Description |
//! |------|-------------|
//! | [`InliningPass`](crate::compiler::InliningPass) | Inlines small methods and constant-returning functions |
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
mod cleanup;
mod config;
mod context;
mod decryptors;
mod detection;
mod result;
mod statemachine;

// Deobfuscation-specific SSA passes (moved from compiler/passes/)
mod passes;

// Engine and detector
mod detector;
mod engine;

// Obfuscator support
mod obfuscators;

// Core types
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
pub use passes::{
    CffReconstructionPass, ConversionStats, DecryptionPass, NativeMethodConversionPass,
    NeutralizationPass, TraceTree, UnflattenConfig,
};
pub use result::DeobfuscationResult;
pub use statemachine::{
    CfgInfo, SsaOpKind, StateMachineCallSite, StateMachineProvider, StateMachineSemantics,
    StateMachineState, StateSlotOperation, StateUpdateCall,
};

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
