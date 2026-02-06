//! Obfuscator support system for obfuscator-specific handling.
//!
//! This module provides the [`Obfuscator`] trait that allows obfuscator-specific
//! detection and deobfuscation logic to be modularly added to the system.
//!
//! # Architecture
//!
//! The obfuscator support system consists of:
//!
//! - [`Obfuscator`] - Trait for implementing obfuscator-specific detection and handling
//! - [`ObfuscatorRegistry`] - Manages registered obfuscators and runs detection
//! - [`ObfuscatorInfo`] - Metadata about a registered obfuscator
//!
//! # Built-in Obfuscators
//!
//! - [`ConfuserExObfuscator`] - ConfuserEx open-source obfuscator
//!
//! # Example
//!
//! ```rust,no_run
//! use std::sync::Arc;
//! use dotscope::deobfuscation::{Obfuscator, ObfuscatorRegistry, ConfuserExObfuscator};
//!
//! // Create a registry and register ConfuserEx
//! let mut registry = ObfuscatorRegistry::new();
//! registry.register(Arc::new(ConfuserExObfuscator::new()));
//! ```

mod confuserex;
mod registry;

pub use confuserex::{
    create_anti_tamper_stub_hook, create_lzma_hook, detect_confuserex, find_encrypted_methods,
    ConfuserExFindings, ConfuserExObfuscator,
};
pub use registry::{ObfuscatorInfo, ObfuscatorRegistry};

use crate::{
    cilassembly::CleanupRequest,
    deobfuscation::{
        changes::EventLog, config::EngineConfig, context::AnalysisContext,
        detection::DetectionScore, pass::SsaPass,
    },
    CilObject, Result,
};

/// Trait for handling a specific obfuscator.
///
/// Each obfuscator implementation provides:
/// - Detection logic (scoring-based identification)
/// - Obfuscator-specific passes
/// - Optional pre/post processing
///
/// Obfuscators are registered with the [`ObfuscatorRegistry`] and automatically
/// selected based on detection scores.
///
/// # Implementing an Obfuscator
///
/// To add support for a new obfuscator:
///
/// 1. Create a new module under `obfuscators/` (e.g., `obfuscators/confuserex/`)
/// 2. Implement the `Obfuscator` trait
/// 3. Register with the engine via `DeobfuscationEngine::register_obfuscator()`
///
/// # Example
///
/// ```rust,ignore
/// use dotscope::deobfuscation::{Obfuscator, DetectionScore, SsaPass};
///
/// pub struct MyObfuscator;
///
/// impl Obfuscator for MyObfuscator {
///     fn id(&self) -> &str { "my_obfuscator" }
///     fn name(&self) -> &'static str { "My Obfuscator" }
///
///     fn detect(&self, assembly: &CilObject) -> DetectionScore {
///         // Analyze assembly for obfuscator markers
///         DetectionScore::new()
///     }
/// }
/// ```
pub trait Obfuscator: Send + Sync {
    /// Unique identifier for this obfuscator (e.g., "confuserex", "dotfuscator").
    ///
    /// This ID is used for registration and lookup. It should be lowercase,
    /// alphanumeric, and use underscores for separation.
    fn id(&self) -> String;

    /// Human-readable name (e.g., "ConfuserEx", "Dotfuscator Pro").
    ///
    /// This name is used for display purposes in logs and reports.
    fn name(&self) -> String;

    /// Scan assembly and return detection score.
    ///
    /// Higher scores indicate higher confidence that this obfuscator was used.
    /// The obfuscator with the highest score above the threshold will be selected.
    ///
    /// # Arguments
    ///
    /// * `assembly` - The assembly to analyze for obfuscation markers.
    ///
    /// # Returns
    ///
    /// A [`DetectionScore`] indicating confidence level and evidence.
    fn detect(&self, assembly: &CilObject) -> DetectionScore;

    /// Return passes specific to this obfuscator.
    ///
    /// These passes run in the devirtualization phase of the pipeline.
    /// Use this for:
    /// - VM deobfuscation
    /// - Method body decryption
    /// - Obfuscator-specific string decryption
    /// - Proxy call resolution
    ///
    /// # Returns
    ///
    /// A vector of SSA passes to run for this obfuscator. Default is empty.
    fn passes(&self) -> Vec<Box<dyn SsaPass>> {
        Vec::new()
    }

    /// Byte-level deobfuscation.
    ///
    /// This method performs all byte-level deobfuscation for this obfuscator.
    /// It can perform multiple internal passes as needed:
    /// 1. Receives a `CilObject` with parsed metadata
    /// 2. Accesses raw bytes via `assembly.file().data()`
    /// 3. Performs transformations (decrypt, fix metadata, etc.) in multiple passes
    /// 4. Reloads `CilObject` from modified bytes after each pass
    /// 5. Returns the final deobfuscated `CilObject`
    ///
    /// The obfuscator manages its own iteration internally. For example, ConfuserEx
    /// might do:
    /// - Pass 1: Decrypt method headers
    /// - Pass 2: Fix invalid metadata
    /// - Pass 3: Decrypt method bodies (now headers work!)
    /// - Pass 4: Decrypt strings
    ///
    /// # Arguments
    ///
    /// * `assembly` - Input assembly (consumed).
    /// * `events` - Event log for recording deobfuscation activity.
    ///
    /// # Returns
    ///
    /// The deobfuscated `CilObject`. If no deobfuscation is needed, returns the
    /// input assembly unchanged.
    ///
    /// # Errors
    ///
    /// Returns an error if deobfuscation fails.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// fn deobfuscate(&self, assembly: CilObject, events: &mut EventLog) -> Result<CilObject> {
    ///     let mut current = assembly;
    ///
    ///     // Pass 1: Decrypt headers
    ///     let bytes = current.file().data();
    ///     let mut modified = bytes.to_vec();
    ///     if self.decrypt_headers(&mut modified, &current)? {
    ///         events.info("Decrypted method headers");
    ///         current = CilObject::from_mem_with_validation(
    ///             modified,
    ///             ValidationConfig::analysis()
    ///         )?;
    ///     }
    ///
    ///     // Pass 2: Decrypt bodies (now that headers work)
    ///     let bytes = current.file().data();
    ///     let mut modified = bytes.to_vec();
    ///     if self.decrypt_bodies(&mut modified, &current)? {
    ///         events.info("Decrypted method bodies");
    ///         current = CilObject::from_mem_with_validation(
    ///             modified,
    ///             ValidationConfig::analysis()
    ///         )?;
    ///     }
    ///
    ///     Ok(current)
    /// }
    /// ```
    fn deobfuscate(&self, assembly: CilObject, _events: &mut EventLog) -> Result<CilObject> {
        // Default: pass through unchanged (no deobfuscation support)
        Ok(assembly)
    }

    /// Initializes the analysis context with obfuscator-specific data.
    ///
    /// This method is called after byte-level deobfuscation but before SSA passes run.
    /// Use this to:
    /// - Register detected decryptor methods with `ctx.decryptors`
    /// - Map MethodSpec tokens to decryptor MethodDefs
    /// - Set up any other obfuscator-specific state in the context
    ///
    /// # Arguments
    ///
    /// * `ctx` - The analysis context to initialize.
    /// * `assembly` - The deobfuscated assembly (after `deobfuscate()` has run).
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// fn initialize_context(&self, ctx: &AnalysisContext, assembly: &CilObject) {
    ///     if let Some(findings) = self.cached_findings() {
    ///         // Register decryptors found during detection
    ///         ctx.decryptors.register_confuserex_decryptors(
    ///             findings.decryptor_methods.iter().copied()
    ///         );
    ///     }
    /// }
    /// ```
    fn initialize_context(&self, _ctx: &AnalysisContext, _assembly: &CilObject) {
        // Default: no initialization needed
    }

    /// Sets the engine configuration for this obfuscator.
    ///
    /// This method is called before `deobfuscate()` to allow the obfuscator to
    /// access configuration values like tracing settings. Since obfuscators use
    /// interior mutability, this can store relevant config values internally.
    ///
    /// # Arguments
    ///
    /// * `config` - The engine configuration.
    fn set_config(&self, _config: &EngineConfig) {
        // Default: no configuration needed
    }

    /// Returns the cleanup request for this obfuscator.
    ///
    /// Called after SSA passes complete. The returned request specifies:
    /// - Methods, types, fields to remove (decryptors, protection code, etc.)
    /// - PE sections to exclude from output (artifact sections)
    /// - Whether to rename obfuscated names
    ///
    /// The engine will merge this request with dead methods from analysis
    /// and execute a single unified cleanup pass.
    ///
    /// # Arguments
    ///
    /// * `assembly` - The assembly to analyze for cleanup targets.
    /// * `ctx` - The analysis context with dead method tracking and decryptor state.
    ///
    /// # Returns
    ///
    /// `Some(CleanupRequest)` with cleanup specifications, or `None` if no cleanup needed.
    ///
    /// # Errors
    ///
    /// Returns an error if building the cleanup request fails.
    fn cleanup_request(
        &self,
        _assembly: &CilObject,
        _ctx: &AnalysisContext,
    ) -> Result<Option<CleanupRequest>> {
        Ok(None)
    }

    /// Supported versions of this obfuscator.
    ///
    /// Returns a list of version strings this obfuscator handles.
    /// Empty list means all versions are supported.
    ///
    /// # Returns
    ///
    /// A slice of version strings (e.g., `["1.0", "2.0"]`).
    fn supported_versions(&self) -> &[&str] {
        &[]
    }

    /// Description of what this obfuscator handles.
    ///
    /// # Returns
    ///
    /// A human-readable description string.
    fn description(&self) -> &'static str {
        "No description available"
    }
}
