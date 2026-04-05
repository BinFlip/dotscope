//! Configuration for the deobfuscation engine.
//!
//! This module provides configuration types for controlling the deobfuscation
//! pipeline, including pass selection, iteration limits, and emulation settings.

use std::time::Duration;

use crate::{deobfuscation::SmartRenameConfig, emulation::TracingConfig};

/// Fixpoint iteration limits.
#[derive(Debug, Clone)]
pub struct IterationConfig {
    /// Maximum iterations for the pass scheduler (default: 20).
    pub max_ssa_iterations: usize,
    /// Number of stable iterations before stopping (default: 2).
    pub stable_iterations: usize,
    /// Maximum iterations per phase before moving on (default: 10).
    pub max_phase_iterations: usize,
    /// Maximum number of detection re-scan rounds (default: 2).
    pub max_detection_rounds: usize,
    /// Maximum outer fixpoint iterations for the work queue loop (default: 10).
    pub max_outer_iterations: usize,
    /// Maximum pipeline-level iterations for byte-transform re-runs (default: 3).
    ///
    /// Each pipeline iteration rebuilds SSA from scratch, so this is intentionally
    /// small. Increase only for assemblies that require multiple SSA↔byte-transform
    /// cycles (e.g., layered protections that reveal new byte-transforms after SSA).
    pub max_pipeline_iterations: usize,
}

impl Default for IterationConfig {
    fn default() -> Self {
        Self {
            max_ssa_iterations: 20,
            stable_iterations: 2,
            max_phase_iterations: 10,
            max_detection_rounds: 2,
            max_outer_iterations: 10,
            max_pipeline_iterations: 3,
        }
    }
}

/// SSA optimization pass toggles.
#[derive(Debug, Clone)]
pub struct PassConfig {
    /// Enable string decryption pass.
    pub string_decryption: bool,
    /// Enable constant propagation pass.
    pub constant_propagation: bool,
    /// Enable dead code elimination pass.
    pub dead_code_elimination: bool,
    /// Enable opaque predicate removal pass.
    pub opaque_predicate_removal: bool,
    /// Enable copy propagation pass.
    pub copy_propagation: bool,
    /// Enable strength reduction pass (mul->shl, div->shr, rem->and for powers of 2).
    pub strength_reduction: bool,
    /// Enable control flow simplification pass.
    pub control_flow_simplification: bool,
    /// Enable interprocedural analysis.
    pub interprocedural: bool,
    /// Enable method inlining.
    pub inlining: bool,
    /// Maximum instruction count for inlining candidates.
    pub inline_threshold: usize,
    /// Maximum iterations for dead code elimination fixpoint (default: 20).
    pub dce_max_iterations: usize,
    /// Maximum iterations for copy propagation fixpoint (default: 15).
    pub copy_prop_max_iterations: usize,
    /// Maximum iterations for constant propagation fixpoint (default: 10).
    pub const_prop_max_iterations: usize,
    /// Maximum iterations for block merging fixpoint (default: 50).
    pub block_merge_max_iterations: usize,
    /// Maximum iterations for control flow simplification fixpoint (default: 20).
    pub control_flow_max_iterations: usize,
    /// Maximum worklist iterations for value range dataflow solver (default: 10000).
    pub value_range_max_iterations: usize,
}

impl Default for PassConfig {
    fn default() -> Self {
        Self {
            string_decryption: true,
            constant_propagation: true,
            dead_code_elimination: true,
            opaque_predicate_removal: true,
            copy_propagation: true,
            strength_reduction: true,
            control_flow_simplification: true,
            interprocedural: true,
            inlining: false,
            inline_threshold: 20,
            dce_max_iterations: 20,
            copy_prop_max_iterations: 15,
            const_prop_max_iterations: 10,
            block_merge_max_iterations: 50,
            control_flow_max_iterations: 20,
            value_range_max_iterations: 10_000,
        }
    }
}

/// Emulation engine limits.
#[derive(Debug, Clone)]
pub struct EmulationConfig {
    /// Maximum instructions for emulation per method.
    pub max_instructions: u64,
    /// Emulation timeout per method.
    pub timeout: Duration,
    /// Tracing configuration for emulation debugging.
    pub tracing: Option<TracingConfig>,
    /// Timeout for template pool warmup (Module.cctor + technique warmup).
    pub warmup_timeout: Duration,
    /// Number of retry passes for warmup methods with dependency chains.
    pub warmup_retry_passes: usize,
}

impl Default for EmulationConfig {
    fn default() -> Self {
        Self {
            max_instructions: 1_000_000,
            timeout: Duration::from_secs(5),
            tracing: None,
            warmup_timeout: Duration::from_secs(60),
            warmup_retry_passes: 5,
        }
    }
}

/// String decryptor heuristic thresholds.
#[derive(Debug, Clone)]
pub struct DecryptorHeuristics {
    /// Maximum instruction count for string decryptor heuristic detection.
    pub max_instructions: usize,
    /// Maximum parameter count for string decryptor heuristic detection.
    pub max_params: usize,
    /// Minimum score (0-100) for a method to be considered a string decryptor.
    pub min_score: u32,
    /// Maximum basic blocks to traverse when resolving decryptor call targets.
    pub max_resolution_blocks: usize,
}

impl Default for DecryptorHeuristics {
    fn default() -> Self {
        Self {
            max_instructions: 200,
            max_params: 3,
            min_score: 45,
            max_resolution_blocks: 50,
        }
    }
}

/// CFF unflattening thresholds.
#[derive(Debug, Clone)]
pub struct UnflatteningThresholds {
    /// Minimum switch cases to consider as potential flattening dispatcher.
    pub min_switch_cases: usize,
    /// Maximum states to enumerate per case when solving dispatcher.
    pub max_states_per_case: usize,
    /// Maximum iterations when tracing execution through flattened CFG.
    pub max_trace_iterations: usize,
    /// Threshold for large constant detection in state encoding.
    pub large_constant_threshold: i64,
    /// Maximum BFS depth for back-edge transitive reachability check.
    pub max_backedge_depth: usize,
    /// Confidence scoring weights for CFF dispatcher detection.
    pub confidence_weights: DetectionWeights,
}

impl Default for UnflatteningThresholds {
    fn default() -> Self {
        Self {
            min_switch_cases: 4,
            max_states_per_case: 15,
            max_trace_iterations: 500,
            large_constant_threshold: 100_000,
            max_backedge_depth: 10,
            confidence_weights: DetectionWeights::default(),
        }
    }
}

/// Confidence scoring weights for CFF dispatcher detection.
///
/// Each weight corresponds to a signal used in `compute_confidence()` to assess
/// how likely a candidate basic block is a CFF dispatcher. The final score is
/// the sum of all weighted signals, capped at 1.0.
#[derive(Debug, Clone)]
pub struct DetectionWeights {
    /// Base score for having ≥3 case blocks, plus bonuses at ≥5 and ≥10.
    pub case_count_base: f64,
    /// Bonus per threshold tier for case count (≥5 and ≥10).
    pub case_count_bonus: f64,
    /// Weight for state variable with phi node present.
    pub state_variable: f64,
    /// Weight for state variable being updated in most case blocks.
    pub state_update_coverage: f64,
    /// Weight for dispatcher having many predecessors (back-edges).
    pub predecessor_ratio: f64,
    /// Weight for back-edge reachability ratio (cases that reach dispatcher).
    pub back_edge_ratio: f64,
    /// Weight for having exit blocks.
    pub exit_blocks: f64,
    /// Bonus for switch-based dispatcher (vs branch-based).
    pub switch_bonus: f64,
    /// Bonus for modulo transform presence (strong CFF indicator).
    pub modulo_bonus: f64,
    /// Weight for dominance ratio (dispatcher dominates case blocks).
    pub dominance_ratio: f64,
    /// Weight for method coverage ratio (fraction of all blocks dominated).
    pub method_coverage: f64,
}

impl Default for DetectionWeights {
    fn default() -> Self {
        Self {
            case_count_base: 0.10,
            case_count_bonus: 0.05,
            state_variable: 0.15,
            state_update_coverage: 0.10,
            predecessor_ratio: 0.10,
            back_edge_ratio: 0.10,
            exit_blocks: 0.05,
            switch_bonus: 0.10,
            modulo_bonus: 0.10,
            dominance_ratio: 0.20,
            method_coverage: 0.10,
        }
    }
}

/// Configuration for the deobfuscation engine.
///
/// Controls all aspects of the deobfuscation pipeline including iteration limits,
/// pass selection, emulation parameters, and resolution strategies.
#[derive(Debug, Clone)]
pub struct EngineConfig {
    /// Fixpoint iteration limits.
    pub iterations: IterationConfig,

    /// SSA optimization pass toggles.
    pub passes: PassConfig,

    /// Emulation engine limits.
    pub emulation: EmulationConfig,

    /// String decryptor heuristic thresholds.
    pub decryptor_heuristics: DecryptorHeuristics,

    /// CFF unflattening thresholds.
    pub unflattening: UnflatteningThresholds,

    /// Detection threshold for obfuscator identification (0-100, default: 20).
    pub detection_threshold: u32,

    /// Target specific obfuscator (bypasses detection).
    pub target_obfuscator: Option<String>,

    /// Verify semantic preservation after passes (slow).
    pub verify_semantics: bool,

    /// Resolution strategies to use, in order of preference.
    pub resolution_strategies: Vec<ResolutionStrategy>,

    /// NOP threshold for dead method detection in BitMono-style junk analysis.
    pub detection_nop_threshold: usize,

    /// Post-deobfuscation cleanup configuration.
    pub cleanup: CleanupConfig,
}

/// Configuration for post-deobfuscation cleanup.
///
/// Controls what artifacts are removed after the deobfuscation passes complete.
/// Most options default to `true` for maximum cleanup, except `remove_unused_methods`
/// which defaults to `false` to preserve exported/reflection-used methods.
#[derive(Debug, Clone)]
pub struct CleanupConfig {
    /// Remove fully-decrypted AND dead decryptor methods.
    pub remove_decryptors: bool,

    /// Remove dead protection methods (anti-tamper, anti-debug, resource handlers).
    pub remove_protection_methods: bool,

    /// Remove types that become empty after method removal.
    pub remove_empty_types: bool,

    /// Remove orphaned Param/CustomAttribute entries for removed methods.
    pub remove_orphan_metadata: bool,

    /// Remove PE sections containing encrypted/artifact data.
    ///
    /// This removes sections that contain encrypted method bodies or other
    /// obfuscator-specific data that is no longer needed after deobfuscation.
    pub remove_artifact_sections: bool,

    /// Rename obfuscated type and method names to simple identifiers.
    ///
    /// This replaces unicode/non-printable names with sequential simple names
    /// like A, B, C, ..., AA, AB, etc. to reduce binary size and improve readability.
    pub rename_obfuscated_names: bool,

    /// Remove methods that become unused after inlining.
    ///
    /// This is disabled by default because:
    /// - DLLs may export methods that appear unused but are called via reflection
    /// - Framework methods may be invoked dynamically
    /// - Malware analysts often want to see the original structure
    ///
    /// Enable this in aggressive mode for maximum size reduction.
    pub remove_unused_methods: bool,

    /// Optional configuration for LLM-powered smart renaming.
    ///
    /// When `Some`, the cascade renamer uses LLM inference for semantic
    /// identifier names. When `None`, falls back to simple sequential naming.
    /// Requires the `smart-rename` Cargo feature for the LLM backend.
    pub smart_rename: Option<SmartRenameConfig>,
}

impl Default for CleanupConfig {
    fn default() -> Self {
        Self {
            remove_decryptors: true,
            remove_protection_methods: true,
            remove_empty_types: true,
            remove_orphan_metadata: true,
            remove_artifact_sections: true,
            rename_obfuscated_names: true,
            remove_unused_methods: false, // Off by default - may break reflection/exports
            smart_rename: None,
        }
    }
}

impl CleanupConfig {
    /// Creates a new cleanup configuration with all options enabled.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a configuration with all cleanup disabled.
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            remove_decryptors: false,
            remove_protection_methods: false,
            remove_empty_types: false,
            remove_orphan_metadata: false,
            remove_artifact_sections: false,
            rename_obfuscated_names: false,
            remove_unused_methods: false,
            smart_rename: None,
        }
    }

    /// Returns true if any cleanup is enabled.
    #[must_use]
    pub fn any_enabled(&self) -> bool {
        self.remove_decryptors
            || self.remove_protection_methods
            || self.remove_empty_types
            || self.remove_orphan_metadata
            || self.remove_artifact_sections
            || self.rename_obfuscated_names
            || self.remove_unused_methods
    }

    /// Creates a configuration for aggressive cleanup (all options enabled).
    #[must_use]
    pub fn aggressive() -> Self {
        Self {
            remove_unused_methods: true,
            smart_rename: None,
            ..Self::default()
        }
    }
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            iterations: IterationConfig::default(),
            passes: PassConfig::default(),
            emulation: EmulationConfig::default(),
            decryptor_heuristics: DecryptorHeuristics::default(),
            unflattening: UnflatteningThresholds::default(),
            detection_threshold: 20,
            target_obfuscator: None,
            verify_semantics: false,
            resolution_strategies: vec![
                ResolutionStrategy::Static,
                ResolutionStrategy::Pattern,
                ResolutionStrategy::Emulation,
            ],
            detection_nop_threshold: 50_000,
            cleanup: CleanupConfig::default(),
        }
    }
}

impl EngineConfig {
    /// Creates a new configuration with default settings.
    ///
    /// # Returns
    ///
    /// A new `EngineConfig` with default values.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a "fast" configuration for quick processing.
    ///
    /// This configuration uses:
    /// - Fewer iterations (5 max)
    /// - Limited emulation (100k instructions)
    /// - No inlining
    /// - No interprocedural analysis
    ///
    /// # Returns
    ///
    /// A new `EngineConfig` optimized for speed over thoroughness.
    #[must_use]
    pub fn fast() -> Self {
        Self {
            iterations: IterationConfig {
                max_ssa_iterations: 5,
                stable_iterations: 1,
                max_detection_rounds: 1,
                ..Default::default()
            },
            passes: PassConfig {
                interprocedural: false,
                inlining: false,
                ..Default::default()
            },
            emulation: EmulationConfig {
                max_instructions: 100_000,
                timeout: Duration::from_millis(500),
                warmup_timeout: Duration::from_secs(30),
                warmup_retry_passes: 2,
                ..Default::default()
            },
            resolution_strategies: vec![ResolutionStrategy::Static, ResolutionStrategy::Pattern],
            ..Self::default()
        }
    }

    /// Creates an "aggressive" configuration for maximum deobfuscation.
    ///
    /// This configuration uses:
    /// - More iterations (50 max)
    /// - Extended emulation limits (10M instructions)
    /// - All features enabled including inlining
    /// - All resolution strategies including symbolic execution
    /// - Aggressive cleanup (removes unused methods after inlining)
    ///
    /// # Returns
    ///
    /// A new `EngineConfig` optimized for thoroughness over speed.
    #[must_use]
    pub fn aggressive() -> Self {
        Self {
            iterations: IterationConfig {
                max_ssa_iterations: 50,
                stable_iterations: 3,
                max_detection_rounds: 3,
                ..Default::default()
            },
            passes: PassConfig {
                inlining: true,
                inline_threshold: 50,
                interprocedural: true,
                ..Default::default()
            },
            emulation: EmulationConfig {
                max_instructions: 10_000_000,
                timeout: Duration::from_secs(30),
                warmup_timeout: Duration::from_secs(120),
                warmup_retry_passes: 8,
                ..Default::default()
            },
            unflattening: UnflatteningThresholds {
                max_backedge_depth: 15,
                ..Default::default()
            },
            resolution_strategies: vec![
                ResolutionStrategy::Static,
                ResolutionStrategy::Pattern,
                ResolutionStrategy::Emulation,
                ResolutionStrategy::Symbolic,
            ],
            cleanup: CleanupConfig::aggressive(),
            ..Self::default()
        }
    }

    /// Sets the maximum number of iterations.
    ///
    /// # Arguments
    ///
    /// * `max` - The maximum number of pass iterations.
    ///
    /// # Returns
    ///
    /// The modified configuration (builder pattern).
    #[must_use]
    pub fn with_max_iterations(mut self, max: usize) -> Self {
        self.iterations.max_ssa_iterations = max;
        self
    }

    /// Sets the detection threshold for obfuscator identification.
    ///
    /// # Arguments
    ///
    /// * `threshold` - A value from 0-100 representing the confidence threshold.
    ///
    /// # Returns
    ///
    /// The modified configuration (builder pattern).
    #[must_use]
    pub fn with_detection_threshold(mut self, threshold: u32) -> Self {
        self.detection_threshold = threshold;
        self
    }

    /// Targets a specific obfuscator, bypassing automatic detection.
    ///
    /// # Arguments
    ///
    /// * `obfuscator` - The obfuscator plugin ID to target.
    ///
    /// # Returns
    ///
    /// The modified configuration (builder pattern).
    #[must_use]
    pub fn with_target_obfuscator(mut self, obfuscator: impl Into<String>) -> Self {
        self.target_obfuscator = Some(obfuscator.into());
        self
    }

    /// Sets emulation limits for string decryption and value resolution.
    ///
    /// # Arguments
    ///
    /// * `max_instructions` - Maximum instructions to execute per emulation.
    /// * `timeout` - Maximum time to spend on emulation per method.
    ///
    /// # Returns
    ///
    /// The modified configuration (builder pattern).
    #[must_use]
    pub fn with_emulation_limits(mut self, max_instructions: u64, timeout: Duration) -> Self {
        self.emulation.max_instructions = max_instructions;
        self.emulation.timeout = timeout;
        self
    }

    /// Enables or disables method inlining.
    ///
    /// # Arguments
    ///
    /// * `enable` - Whether to enable method inlining.
    /// * `threshold` - Maximum instruction count for inlining candidates.
    ///
    /// # Returns
    ///
    /// The modified configuration (builder pattern).
    #[must_use]
    pub fn with_inlining(mut self, enable: bool, threshold: usize) -> Self {
        self.passes.inlining = enable;
        self.passes.inline_threshold = threshold;
        self
    }

    /// Enables or disables interprocedural analysis.
    ///
    /// # Arguments
    ///
    /// * `enable` - Whether to enable interprocedural analysis.
    ///
    /// # Returns
    ///
    /// The modified configuration (builder pattern).
    #[must_use]
    pub fn with_interprocedural(mut self, enable: bool) -> Self {
        self.passes.interprocedural = enable;
        self
    }

    /// Sets the resolution strategies to use.
    ///
    /// # Arguments
    ///
    /// * `strategies` - The resolution strategies in order of preference.
    ///
    /// # Returns
    ///
    /// The modified configuration (builder pattern).
    #[must_use]
    pub fn with_strategies(mut self, strategies: Vec<ResolutionStrategy>) -> Self {
        self.resolution_strategies = strategies;
        self
    }

    /// Sets the pass configuration.
    ///
    /// # Arguments
    ///
    /// * `passes` - The pass configuration to use.
    ///
    /// # Returns
    ///
    /// The modified configuration (builder pattern).
    #[must_use]
    pub fn with_passes(mut self, passes: PassConfig) -> Self {
        self.passes = passes;
        self
    }

    /// Checks if all core passes are enabled.
    ///
    /// # Returns
    ///
    /// `true` if all core deobfuscation passes are enabled.
    #[must_use]
    pub fn all_passes_enabled(&self) -> bool {
        self.passes.string_decryption
            && self.passes.constant_propagation
            && self.passes.dead_code_elimination
            && self.passes.opaque_predicate_removal
            && self.passes.copy_propagation
            && self.passes.strength_reduction
            && self.passes.control_flow_simplification
    }

    /// Sets the tracing configuration for emulation debugging.
    ///
    /// When set, emulation processes created during deobfuscation will write
    /// trace events to the configured output.
    ///
    /// # Arguments
    ///
    /// * `tracing` - The tracing configuration to use.
    ///
    /// # Returns
    ///
    /// The modified configuration (builder pattern).
    #[must_use]
    pub fn with_tracing(mut self, tracing: TracingConfig) -> Self {
        self.emulation.tracing = Some(tracing);
        self
    }

    /// Sets the warmup timeout for template pool initialization.
    ///
    /// The template pool executes Module.cctor and technique warmup methods
    /// during initialization. Complex assemblies (e.g., PureLogs with ~1.88M
    /// instructions) may require longer timeouts.
    ///
    /// # Arguments
    ///
    /// * `timeout` - Maximum time for warmup execution.
    ///
    /// # Returns
    ///
    /// The modified configuration (builder pattern).
    #[must_use]
    pub fn with_warmup_timeout(mut self, timeout: Duration) -> Self {
        self.emulation.warmup_timeout = timeout;
        self
    }

    /// Sets the number of retry passes for warmup methods.
    ///
    /// Warmup methods may have dependency chains (e.g., type A's .cctor
    /// depends on type B's .cctor). Multiple passes retry failed methods
    /// after their dependencies have been initialized.
    ///
    /// # Arguments
    ///
    /// * `passes` - Number of retry passes (each pass retries previously failed methods).
    ///
    /// # Returns
    ///
    /// The modified configuration (builder pattern).
    #[must_use]
    pub fn with_warmup_retry_passes(mut self, passes: usize) -> Self {
        self.emulation.warmup_retry_passes = passes;
        self
    }

    /// Sets the NOP threshold for dead method detection.
    ///
    /// Methods in `<Module>` containing more than this many `nop` instructions
    /// are flagged as BitMono BillionNops dead methods for removal.
    ///
    /// # Arguments
    ///
    /// * `threshold` - Minimum NOP count to classify a method as dead.
    ///
    /// # Returns
    ///
    /// The modified configuration (builder pattern).
    #[must_use]
    pub fn with_nop_threshold(mut self, threshold: usize) -> Self {
        self.detection_nop_threshold = threshold;
        self
    }
}

/// Strategy for resolving unknown values in SSA.
///
/// These strategies are tried in order of preference to resolve
/// unknown values during deobfuscation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResolutionStrategy {
    /// Static analysis: constant propagation, dataflow analysis.
    /// Fast and always safe.
    Static,

    /// Pattern matching: recognize known obfuscation patterns.
    /// Fast, targeted at specific obfuscators.
    Pattern,

    /// Emulation: execute code to get concrete values.
    /// Powerful but potentially slow or unsafe.
    Emulation,

    /// Symbolic execution: track constraints without concrete execution.
    /// Can handle more complex cases but may be expensive.
    Symbolic,
}

impl ResolutionStrategy {
    /// Returns a human-readable name for this strategy.
    ///
    /// # Returns
    ///
    /// A static string with the strategy's display name.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::Static => "Static Analysis",
            Self::Pattern => "Pattern Matching",
            Self::Emulation => "Emulation",
            Self::Symbolic => "Symbolic Execution",
        }
    }

    /// Returns whether this strategy is safe (no side effects).
    ///
    /// # Returns
    ///
    /// `true` if the strategy cannot cause side effects during execution.
    #[must_use]
    pub fn is_safe(&self) -> bool {
        matches!(self, Self::Static | Self::Pattern | Self::Symbolic)
    }

    /// Returns whether this strategy requires emulation.
    ///
    /// # Returns
    ///
    /// `true` if the strategy needs the emulation engine.
    #[must_use]
    pub fn requires_emulation(&self) -> bool {
        matches!(self, Self::Emulation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = EngineConfig::default();
        assert_eq!(config.iterations.max_ssa_iterations, 20);
        assert!(config.passes.string_decryption);
        assert!(config.passes.interprocedural);
        assert!(!config.passes.inlining); // Disabled by default
        assert!(!config.cleanup.remove_unused_methods); // Disabled by default
        assert_eq!(config.emulation.warmup_timeout, Duration::from_secs(60));
        assert_eq!(config.emulation.warmup_retry_passes, 5);
        assert_eq!(config.unflattening.max_backedge_depth, 10);
        assert_eq!(config.decryptor_heuristics.max_resolution_blocks, 50);
        assert_eq!(config.detection_nop_threshold, 50_000);
    }

    #[test]
    fn test_fast_config() {
        let config = EngineConfig::fast();
        assert_eq!(config.iterations.max_ssa_iterations, 5);
        assert!(!config.passes.interprocedural);
        assert_eq!(config.resolution_strategies.len(), 2);
        assert_eq!(config.emulation.warmup_timeout, Duration::from_secs(30));
        assert_eq!(config.emulation.warmup_retry_passes, 2);
    }

    #[test]
    fn test_aggressive_config() {
        let config = EngineConfig::aggressive();
        assert_eq!(config.iterations.max_ssa_iterations, 50);
        assert!(config.passes.inlining);
        assert!(config.passes.interprocedural);
        assert_eq!(config.resolution_strategies.len(), 4);
        assert!(config.cleanup.remove_unused_methods); // Enabled in aggressive mode
        assert_eq!(config.emulation.warmup_timeout, Duration::from_secs(120));
        assert_eq!(config.emulation.warmup_retry_passes, 8);
        assert_eq!(config.unflattening.max_backedge_depth, 15);
    }

    #[test]
    fn test_builder_pattern() {
        let config = EngineConfig::new()
            .with_max_iterations(100)
            .with_target_obfuscator("confuserex");

        assert_eq!(config.iterations.max_ssa_iterations, 100);
        assert_eq!(config.target_obfuscator, Some("confuserex".to_string()));
    }

    #[test]
    fn test_detection_weights_default() {
        let w = DetectionWeights::default();
        assert!((w.case_count_base - 0.10).abs() < f64::EPSILON);
        assert!((w.state_variable - 0.15).abs() < f64::EPSILON);
        assert!((w.dominance_ratio - 0.20).abs() < f64::EPSILON);
        assert!((w.method_coverage - 0.10).abs() < f64::EPSILON);
    }

    #[test]
    fn test_builder_warmup_and_nop() {
        let config = EngineConfig::new()
            .with_warmup_timeout(Duration::from_secs(120))
            .with_warmup_retry_passes(10)
            .with_nop_threshold(100_000);

        assert_eq!(config.emulation.warmup_timeout, Duration::from_secs(120));
        assert_eq!(config.emulation.warmup_retry_passes, 10);
        assert_eq!(config.detection_nop_threshold, 100_000);
    }

    #[test]
    fn test_resolution_strategy() {
        assert!(ResolutionStrategy::Static.is_safe());
        assert!(ResolutionStrategy::Pattern.is_safe());
        assert!(!ResolutionStrategy::Emulation.is_safe());

        assert!(ResolutionStrategy::Emulation.requires_emulation());
        assert!(!ResolutionStrategy::Static.requires_emulation());
    }
}
