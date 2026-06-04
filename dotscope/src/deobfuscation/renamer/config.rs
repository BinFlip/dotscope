//! Configuration for the smart renaming subsystem.
//!
//! Contains tunable parameters for both the LLM inference backend and the
//! cascade renaming pipeline. All parameters have sensible defaults.

use std::path::PathBuf;

/// Configuration for the smart renaming pipeline.
///
/// Controls the local inference backend (mistral.rs) and the cascade
/// renaming pipeline parameters. When `None` in
/// [`CleanupConfig`](crate::deobfuscation::CleanupConfig), the simple
/// sequential renamer is used instead.
///
/// # Feature Gate
///
/// The inference backend requires the `smart-rename` Cargo feature.
/// Without it, this config is accepted but the engine falls back to
/// `SimpleProvider`.
///
/// # Examples
///
/// ```rust
/// use std::path::PathBuf;
/// use dotscope::deobfuscation::SmartRenameConfig;
///
/// let config = SmartRenameConfig {
///     model_path: PathBuf::from("model.gguf"),
///     ..SmartRenameConfig::default()
/// };
/// ```
#[derive(Debug, Clone)]
pub struct SmartRenameConfig {
    /// Path to GGUF model file.
    ///
    /// Must be a model with chat support (e.g., Qwen, Codestral,
    /// CodeLlama). Both base and instruct-tuned variants are compatible.
    pub model_path: PathBuf,

    /// Maximum tokens to generate per identifier name.
    ///
    /// Identifier names are short — 20 tokens is generous for most names.
    /// Increase for languages with longer naming conventions.
    ///
    /// Default: `20`
    pub max_tokens: u16,

    /// Number of CPU threads for inference.
    ///
    /// Set to `0` for automatic detection based on available cores.
    ///
    /// Default: `0`
    pub threads: usize,

    /// Force CPU-only inference, disabling GPU/Metal acceleration.
    ///
    /// When `false` (default), mistral.rs auto-detects the best backend
    /// (Metal on macOS, CUDA on Linux/Windows). Set to `true` only if
    /// GPU inference causes issues.
    ///
    /// Default: `false`
    pub force_cpu: bool,

    /// Sampling temperature for name generation.
    ///
    /// `0.0` gives deterministic (greedy) decoding. Higher values
    /// increase randomness. For identifier naming, greedy is preferred.
    ///
    /// Default: `0.0`
    pub temperature: f64,

    /// Stop sequences that terminate generation.
    ///
    /// When the model generates any of these strings, output is truncated
    /// before the stop sequence. These prevent the model from generating
    /// beyond the identifier name boundary.
    ///
    /// Default: `["(", "{", ";", " ", "\n", ")", ":"]`
    pub stop_sequences: Vec<String>,

    /// SSA instruction count threshold for "small" methods.
    ///
    /// Methods with instruction counts at or below this threshold get a
    /// call-site skeleton (pseudocode) instead of phase decomposition.
    /// Smaller values produce fewer skeletons; larger values increase
    /// context quality for compact methods.
    ///
    /// Default: `20`
    pub small_method_threshold: usize,

    /// Maximum number of phases to include in a prompt.
    ///
    /// If a method has more phases than this limit, the prompt retains
    /// the first half and last half with an elision in between.
    ///
    /// Default: `6`
    pub max_phases_in_prompt: usize,

    /// Maximum allowed length for generated identifier names.
    ///
    /// Names exceeding this length are truncated. Prevents excessively
    /// long model outputs from producing unwieldy identifiers.
    ///
    /// Default: `64`
    pub max_name_length: usize,
}

impl Default for SmartRenameConfig {
    fn default() -> Self {
        Self {
            model_path: PathBuf::new(),
            max_tokens: 20,
            threads: 0,
            force_cpu: false,
            temperature: 0.0,
            stop_sequences: vec![
                "(".to_string(),
                "{".to_string(),
                ";".to_string(),
                " ".to_string(),
                "\n".to_string(),
                ")".to_string(),
                ":".to_string(),
            ],
            small_method_threshold: 20,
            max_phases_in_prompt: 6,
            max_name_length: 64,
        }
    }
}
