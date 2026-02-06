//! Configuration for the deobfuscation engine.
//!
//! This module provides configuration types for controlling the deobfuscation
//! pipeline, including pass selection, iteration limits, and emulation settings.

use std::time::Duration;

use crate::emulation::TracingConfig;

/// Configuration for the deobfuscation engine.
///
/// Controls all aspects of the deobfuscation pipeline including iteration limits,
/// pass selection, emulation parameters, and resolution strategies.
#[derive(Debug, Clone)]
pub struct EngineConfig {
    /// Maximum iterations for the pass scheduler (default: 20).
    pub max_iterations: usize,

    /// Number of stable iterations before stopping (default: 2).
    pub stable_iterations: usize,

    /// Maximum iterations per phase before moving on (default: 10).
    pub max_phase_iterations: usize,

    /// Detection threshold for obfuscator identification (0-100, default: 50).
    pub detection_threshold: u32,

    /// Target specific obfuscator (bypasses detection).
    pub target_obfuscator: Option<String>,

    /// Maximum instructions for emulation per method.
    pub emulation_max_instructions: u64,

    /// Emulation timeout per method.
    pub emulation_timeout: Duration,

    /// Enable method inlining.
    pub enable_inlining: bool,

    /// Maximum instruction count for inlining candidates.
    pub inline_threshold: usize,

    /// Enable string decryption pass.
    pub enable_string_decryption: bool,

    /// Enable constant propagation pass.
    pub enable_constant_propagation: bool,

    /// Enable dead code elimination pass.
    pub enable_dead_code_elimination: bool,

    /// Enable opaque predicate removal pass.
    pub enable_opaque_predicate_removal: bool,

    /// Enable copy propagation pass.
    pub enable_copy_propagation: bool,

    /// Enable strength reduction pass (mul→shl, div→shr, rem→and for powers of 2).
    pub enable_strength_reduction: bool,

    /// Enable control flow simplification pass.
    pub enable_control_flow_simplification: bool,

    /// Enable interprocedural analysis.
    pub enable_interprocedural: bool,

    /// Maximum instruction count for string decryptor heuristic detection.
    pub string_decryptor_max_instructions: usize,

    /// Maximum parameter count for string decryptor heuristic detection.
    pub string_decryptor_max_params: usize,

    /// Minimum score (0-100) for a method to be considered a string decryptor.
    /// Based on heuristic analysis of return type, parameters, operations, etc.
    pub string_decryptor_min_score: u32,

    /// Minimum switch cases to consider as potential flattening dispatcher.
    pub unflattening_min_switch_cases: usize,

    /// Maximum states to enumerate per case when solving dispatcher.
    pub unflattening_max_states_per_case: usize,

    /// Maximum iterations when tracing execution through flattened CFG.
    pub unflattening_max_trace_iterations: usize,

    /// Threshold for large constant detection in state encoding (absolute value).
    /// Constants larger than this are considered potential state values.
    pub unflattening_large_constant_threshold: i64,

    /// Verify semantic preservation after passes (slow).
    pub verify_semantics: bool,

    /// Resolution strategies to use, in order of preference.
    pub resolution_strategies: Vec<ResolutionStrategy>,

    /// Post-deobfuscation cleanup configuration.
    pub cleanup: CleanupConfig,

    /// Tracing configuration for emulation debugging.
    ///
    /// When set, emulation processes created during deobfuscation will write
    /// trace events to help debug decryption and other emulation-based passes.
    pub tracing: Option<TracingConfig>,
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
            ..Self::default()
        }
    }
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            max_iterations: 20,
            stable_iterations: 2,
            max_phase_iterations: 10,
            detection_threshold: 50,
            target_obfuscator: None,
            emulation_max_instructions: 1_000_000,
            emulation_timeout: Duration::from_secs(5),
            enable_inlining: false,
            inline_threshold: 20,
            enable_string_decryption: true,
            enable_constant_propagation: true,
            enable_dead_code_elimination: true,
            enable_opaque_predicate_removal: true,
            enable_copy_propagation: true,
            enable_strength_reduction: true,
            enable_control_flow_simplification: true,
            enable_interprocedural: true,
            // String decryption heuristics (tuned for common obfuscators)
            string_decryptor_max_instructions: 200,
            string_decryptor_max_params: 3,
            string_decryptor_min_score: 45, // Requires return type + at least one other indicator
            // Unflattening configuration (tuned for ConfuserEx-style dispatchers)
            unflattening_min_switch_cases: 4,
            unflattening_max_states_per_case: 15,
            unflattening_max_trace_iterations: 500,
            unflattening_large_constant_threshold: 100_000,
            verify_semantics: false,
            resolution_strategies: vec![
                ResolutionStrategy::Static,
                ResolutionStrategy::Pattern,
                ResolutionStrategy::Emulation,
            ],
            cleanup: CleanupConfig::default(),
            tracing: None,
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
            max_iterations: 5,
            stable_iterations: 1,
            emulation_max_instructions: 100_000,
            emulation_timeout: Duration::from_millis(500),
            enable_inlining: false,
            enable_interprocedural: false,
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
            max_iterations: 50,
            stable_iterations: 3,
            emulation_max_instructions: 10_000_000,
            emulation_timeout: Duration::from_secs(30),
            enable_inlining: true,
            inline_threshold: 50,
            enable_interprocedural: true,
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
        self.max_iterations = max;
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
        self.emulation_max_instructions = max_instructions;
        self.emulation_timeout = timeout;
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
        self.enable_inlining = enable;
        self.inline_threshold = threshold;
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
        self.enable_interprocedural = enable;
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

    /// Enables or disables specific passes.
    ///
    /// # Arguments
    ///
    /// * `string_decryption` - Enable string decryption pass.
    /// * `constant_propagation` - Enable constant propagation pass.
    /// * `dead_code` - Enable dead code elimination pass.
    /// * `opaque_predicates` - Enable opaque predicate removal pass.
    ///
    /// # Returns
    ///
    /// The modified configuration (builder pattern).
    #[must_use]
    #[allow(clippy::fn_params_excessive_bools)]
    pub fn with_passes(
        mut self,
        string_decryption: bool,
        constant_propagation: bool,
        dead_code: bool,
        opaque_predicates: bool,
    ) -> Self {
        self.enable_string_decryption = string_decryption;
        self.enable_constant_propagation = constant_propagation;
        self.enable_dead_code_elimination = dead_code;
        self.enable_opaque_predicate_removal = opaque_predicates;
        self
    }

    /// Checks if all core passes are enabled.
    ///
    /// # Returns
    ///
    /// `true` if all core deobfuscation passes are enabled.
    #[must_use]
    pub fn all_passes_enabled(&self) -> bool {
        self.enable_string_decryption
            && self.enable_constant_propagation
            && self.enable_dead_code_elimination
            && self.enable_opaque_predicate_removal
            && self.enable_copy_propagation
            && self.enable_strength_reduction
            && self.enable_control_flow_simplification
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
        self.tracing = Some(tracing);
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
        assert_eq!(config.max_iterations, 20);
        assert!(config.enable_string_decryption);
        assert!(config.enable_interprocedural);
        assert!(!config.enable_inlining); // Disabled by default
        assert!(!config.cleanup.remove_unused_methods); // Disabled by default
    }

    #[test]
    fn test_fast_config() {
        let config = EngineConfig::fast();
        assert_eq!(config.max_iterations, 5);
        assert!(!config.enable_interprocedural);
        assert_eq!(config.resolution_strategies.len(), 2);
    }

    #[test]
    fn test_aggressive_config() {
        let config = EngineConfig::aggressive();
        assert_eq!(config.max_iterations, 50);
        assert!(config.enable_inlining);
        assert!(config.enable_interprocedural);
        assert_eq!(config.resolution_strategies.len(), 4);
        assert!(config.cleanup.remove_unused_methods); // Enabled in aggressive mode
    }

    #[test]
    fn test_builder_pattern() {
        let config = EngineConfig::new()
            .with_max_iterations(100)
            .with_target_obfuscator("confuserex");

        assert_eq!(config.max_iterations, 100);
        assert_eq!(config.target_obfuscator, Some("confuserex".to_string()));
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
