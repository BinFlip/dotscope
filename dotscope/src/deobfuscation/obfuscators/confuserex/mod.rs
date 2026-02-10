//! ConfuserEx obfuscator support.
//!
//! ConfuserEx is a popular open-source obfuscator for .NET assemblies.
//! This module provides detection and deobfuscation for assemblies protected
//! by ConfuserEx and its forks (e.g., mkaring/ConfuserEx).
//!
//! # Protection Presets
//!
//! ConfuserEx organizes protections into cumulative presets. Higher presets
//! include all protections from lower presets.
//!
//! ## Preset Minimum (1)
//!
//! Basic protections that provide minimal security:
//!
//! | Protection    | Description                              |
//! |---------------|------------------------------------------|
//! | AntiDebug     | Detects debuggers and terminates         |
//! | AntiILDasm    | SuppressIldasmAttribute on assembly      |
//! | Hardening     | Minor hardening tweaks                   |
//! | Rename        | Name obfuscation (types, methods, etc.)  |
//!
//! ## Preset Normal (2)
//!
//! Standard protection level including Minimum plus:
//!
//! | Protection      | Description                                    |
//! |-----------------|------------------------------------------------|
//! | Constants       | String/constant encryption via decryptor calls |
//! | Resources       | Embedded resource encryption                   |
//! | ReferenceProxy  | Indirect method calls via delegates            |
//! | ControlFlow     | Switch-based control flow obfuscation          |
//!
//! ## Preset Aggressive (3)
//!
//! Same as Normal in base ConfuserEx (no additional protections).
//!
//! ## Preset Maximum (4)
//!
//! Strongest protection level including Aggressive plus:
//!
//! | Protection  | Description                                      |
//! |-------------|--------------------------------------------------|
//! | AntiTamper  | Method body encryption (decrypted at runtime)    |
//! | AntiDump    | Prevents memory dumps of the process             |
//!
//! ## Protections NOT in Presets (Preset = None)
//!
//! These must be explicitly enabled:
//!
//! | Protection       | Description                              |
//! |------------------|------------------------------------------|
//! | InvalidMetadata  | Corrupts metadata indices (0x7fff7fff)   |
//! | TypeScrambler    | Scrambles generic type parameters        |
//! | Compressor       | Packs the assembly                       |
//!
//! # Mode Parameters
//!
//! Some protections support mode parameters that enable native x86 code generation.
//! **These are NOT enabled by any preset** - they must be explicitly configured.
//!
//! ## Constants Protection Modes
//!
//! ```text
//! mode=Normal    (default) CIL-based decryption
//! mode=Dynamic   Dynamic cipher generation
//! mode=x86       Native x86 decryption code (Windows-only)
//! ```
//!
//! ## ControlFlow Predicate Types
//!
//! ```text
//! predicate=Normal      (default) Simple numeric predicates
//! predicate=Expression  Complex expression-based predicates
//! predicate=x86         Native x86 predicate evaluation (Windows-only)
//! ```
//!
//! When `mode=x86` or `predicate=x86` is used, ConfuserEx generates methods with
//! `MethodImplCodeType::NATIVE` that contain raw x86 machine code. These require
//! special handling via the [`NativeMethodConversionPass`] before emulation.
//!
//! # Test Samples
//!
//! Our test samples in `tests/samples/packers/confuserex/` were created with
//! mkaring/ConfuserEx using different preset configurations:
//!
//! | Sample                     | Preset   | Protections Enabled                    |
//! |----------------------------|----------|----------------------------------------|
//! | `original.exe`             | None     | Unprotected baseline                   |
//! | `mkaring_minimal.exe`      | Minimum  | AntiDebug, AntiILDasm, Rename          |
//! | `mkaring_normal.exe`       | Normal   | Minimum + Constants, ControlFlow, etc. |
//! | `mkaring_maximum.exe`      | Maximum  | Normal + AntiTamper, AntiDump          |
//! | `mkaring_constants.exe`    | None     | Constants only (mode=Normal)           |
//! | `mkaring_controlflow.exe`  | None     | ControlFlow only (predicate=Normal)    |
//! | `mkaring_resources.exe`    | None     | Resources only                         |
//!
//! **Note:** None of our test samples use `mode=x86` or `predicate=x86`. To test
//! native x86 method conversion, samples must be explicitly generated with those
//! parameters set.
//!
//! # Detection
//!
//! ConfuserEx can be detected by looking for:
//! - Custom attributes (ConfuserVersion, ConfusedByAttribute)
//! - Invalid metadata patterns (0x7fff7fff indices)
//! - Encrypted method bodies (anti-tamper)
//! - Characteristic naming patterns (RTL/LTR Unicode names)
//! - Decryptor method signatures (`string(int32)`, `T(int32)`)
//! - SuppressIldasmAttribute on assembly
//!
//! # Deobfuscation Pipeline
//!
//! The [`ConfuserExObfuscator::deobfuscate`] method implements a multi-pass pipeline:
//!
//! ```text
//! Pass 1: Fix invalid metadata (0x7fff7fff indices)
//!         └─> Reload CilObject with fixed metadata
//!
//! Pass 2: Decrypt anti-tamper protected method bodies
//!         └─> Reload CilObject with decrypted methods
//!         └─> Re-run detection to find native helpers
//!
//! Pass 3: Convert native x86 helpers to CIL (if detected)
//!         └─> Required before emulation can proceed
//!
//! Pass 4: Patch anti-tamper/anti-debug initialization
//!         └─> Remove runtime protection checks
//!
//! Pass 5: Decrypt resources
//!         └─> Extract embedded assemblies
//!
//! Pass 6: Cleanup obfuscator artifacts
//!         └─> Remove marker attributes, infrastructure types
//!
//! Pass 7: Build final CilObject
//!         └─> Return deobfuscated assembly
//! ```
//!
//! # SSA Pass Hooks
//!
//! During SSA-level deobfuscation passes, the obfuscator can provide hooks for:
//! - String decryption (emulate decryptor methods)
//! - Constant decryption (emulate constant resolvers)
//! - Proxy method resolution (inline delegate calls)
//!
//! # State Management
//!
//! The obfuscator uses interior mutability to cache findings from detection.
//! When `detect()` is called, it populates internal state that `deobfuscate()`
//! and `passes()` can later access without re-scanning the assembly.

mod antidebug;
mod antitamper;
mod candidates;
mod constants;
mod detection;
mod findings;
mod hooks;
mod metadata;
mod resources;

mod cleanup;

pub use antitamper::find_encrypted_methods;
pub use detection::detect_confuserex;
pub use findings::ConfuserExFindings;
pub use hooks::{create_anti_tamper_stub_hook, create_lzma_hook};

use std::{
    collections::HashSet,
    sync::{Arc, RwLock},
};

use crate::{
    cilassembly::{CilAssembly, CleanupRequest, GeneratorConfig},
    compiler::{EventLog, SsaPass},
    deobfuscation::{
        config::EngineConfig, context::AnalysisContext, detection::DetectionScore,
        obfuscators::Obfuscator, passes::NativeMethodConversionPass,
    },
    emulation::TracingConfig,
    metadata::{
        tables::{MethodSpecRaw, TableId},
        token::Token,
        validation::ValidationConfig,
    },
    CilObject, Result,
};

/// ConfuserEx obfuscator implementation.
///
/// Handles detection and deobfuscation of assemblies protected by ConfuserEx.
///
/// # State Management
///
/// This struct uses interior mutability to cache detection findings and
/// engine configuration. When `detect()` is called via the `Obfuscator` trait,
/// findings are stored internally and reused by `deobfuscate()` and `passes()`
/// to avoid redundant scanning of the assembly.
pub struct ConfuserExObfuscator {
    /// Cached findings from detection (populated by `detect()`).
    findings: RwLock<Option<ConfuserExFindings>>,
    /// Tracing configuration from engine (populated by `set_config()`).
    tracing: RwLock<Option<TracingConfig>>,
}

impl Default for ConfuserExObfuscator {
    fn default() -> Self {
        Self::new()
    }
}

impl ConfuserExObfuscator {
    /// Creates a new ConfuserEx obfuscator instance.
    #[must_use]
    pub fn new() -> Self {
        Self {
            findings: RwLock::new(None),
            tracing: RwLock::new(None),
        }
    }

    /// Returns the cached findings from the last detection, if any.
    fn findings(&self) -> Option<ConfuserExFindings> {
        self.findings.read().ok().and_then(|f| f.clone())
    }

    /// Returns the cached tracing configuration, if set.
    fn tracing(&self) -> Option<TracingConfig> {
        self.tracing.read().ok().and_then(|t| t.clone())
    }

    /// Registers MethodSpec → MethodDef mappings for generic decryptors.
    ///
    /// ConfuserEx generic decryptors like `T Get<T>(int32)` are called via MethodSpec
    /// tokens that instantiate the generic with specific type arguments (int, string, etc.).
    /// This method scans the MethodSpec table to find these instantiations and maps them
    /// to the base MethodDef so the decryption pass can identify them.
    fn register_methodspec_mappings(
        &self,
        ctx: &AnalysisContext,
        assembly: &CilObject,
        findings: &ConfuserExFindings,
    ) {
        // Collect decryptor tokens into a HashSet for fast lookup
        // boxcar::Vec::iter() yields (index, &Token) tuples
        let decryptor_set: HashSet<_> = findings
            .decryptor_methods
            .iter()
            .map(|(_, token)| *token)
            .collect();

        // Get MethodSpec table
        let Some(tables) = assembly.tables() else {
            return;
        };
        let Some(methodspec_table) = tables.table::<MethodSpecRaw>() else {
            return;
        };

        // For each MethodSpec, check if its method is a registered decryptor
        for methodspec in methodspec_table.iter() {
            let method_token = methodspec.method.token;

            // Check if this MethodSpec references a known decryptor
            // The method field can be a MethodDef or MemberRef token
            let base_decryptor = if decryptor_set.contains(&method_token) {
                // Direct reference to MethodDef decryptor
                Some(method_token)
            } else if method_token.is_table(TableId::MemberRef) {
                // MemberRef might reference a decryptor - resolve it
                // For now, we check MemberRef's class to see if it matches a decryptor's declaring type
                self.resolve_memberref_to_decryptor(assembly, method_token, &decryptor_set)
            } else {
                None
            };

            if let Some(decryptor) = base_decryptor {
                let methodspec_token = methodspec.token;
                ctx.decryptors.map_methodspec(methodspec_token, decryptor);
            }
        }
    }

    /// Attempts to resolve a MemberRef to a decryptor MethodDef.
    ///
    /// MemberRef tokens can reference methods in other assemblies or generic method
    /// instantiations. This method checks if a MemberRef points to a known decryptor.
    fn resolve_memberref_to_decryptor(
        &self,
        assembly: &CilObject,
        memberref_token: Token,
        decryptor_set: &HashSet<Token>,
    ) -> Option<Token> {
        // Get the MemberRef entry
        let memberrefs = assembly.refs_members();
        let memberref_entry = memberrefs.get(&memberref_token)?;
        let memberref = memberref_entry.value();

        // For ConfuserEx, decryptors are typically in <Module> or an obfuscated type
        // Find a decryptor with matching name
        for decryptor_token in decryptor_set.iter() {
            if let Some(method_entry) = assembly.methods().get(decryptor_token) {
                let method = method_entry.value();
                // Check if names match (MemberRef name should match decryptor name)
                if method.name == memberref.name {
                    return Some(*decryptor_token);
                }
            }
        }

        None
    }

    /// Finds the static constructor (.cctor) of the type that contains a method.
    ///
    /// ConfuserEx decryptor types have a .cctor that performs expensive one-time
    /// initialization (LZMA decompression of the constants buffer). This method
    /// finds that .cctor so it can be registered as a warmup method.
    ///
    /// # Arguments
    ///
    /// * `assembly` - The assembly to search in.
    /// * `method_token` - A method token whose declaring type's .cctor we want.
    ///
    /// # Returns
    ///
    /// The .cctor method token if found, `None` otherwise.
    fn find_type_cctor(&self, assembly: &CilObject, method_token: Token) -> Option<Token> {
        // Get the method entry
        let method_entry = assembly.methods().get(&method_token)?;
        let method = method_entry.value();

        // Get the declaring type
        let type_ref = method.declaring_type.get()?;
        let cil_type = type_ref.upgrade()?;

        // Find the .cctor in the type's methods
        for (_, method_ref) in cil_type.methods.iter() {
            if let Some(method_arc) = method_ref.upgrade() {
                if method_arc.is_cctor() {
                    return Some(method_arc.token);
                }
            }
        }

        None
    }

    /// Internal helper to run the deobfuscation pipeline.
    ///
    /// Uses and updates the cached findings in `self.findings` as the pipeline
    /// progresses and more of the binary becomes accessible.
    fn run_deobfuscation(&self, assembly: CilObject, events: &mut EventLog) -> Result<CilObject> {
        let mut current = assembly;

        // Get initial findings (from detection or re-detect if needed)
        let mut findings = self.findings().unwrap_or_else(|| {
            let (_, f) = detection::detect_confuserex(&current);
            f
        });

        // Pass 0: Extract embedded resources/assemblies (before any modifications)
        // ConfuserEx can encrypt embedded resources and assemblies.
        // This pass runs first because it uses emulation which needs the original assembly.
        // The extracted assemblies are logged in events for external processing.
        if findings.needs_resource_decryption() {
            let (returned, result) = resources::decrypt_resources(current, events)?;
            current = returned;
            if result.has_assemblies() {
                events.info(format!(
                    "Extracted {} embedded assemblies from resource protection",
                    result.assembly_count()
                ));
            }
        }

        // Pass 1: Decrypt anti-tamper protected method bodies
        // This MUST run before other modifications because:
        // - It needs to find and emulate the anti-tamper initialization method
        // - Other passes do roundtrips (write+reload) that can corrupt method bodies
        // - Once decrypted, method bodies are properly stored in .text section
        let had_anti_tamper = findings.needs_anti_tamper_decryption();
        if had_anti_tamper {
            current = antitamper::decrypt_bodies(current, events, self.tracing())?;
        }

        // Pass 2: Re-run detection after anti-tamper decryption
        // Some detection (like native helpers) requires parsing method bodies that
        // were encrypted before anti-tamper decryption. Update cached findings.
        if had_anti_tamper {
            // IMPORTANT: Preserve anti-tamper method tokens from original findings.
            // After decryption, re-detection won't find these because method bodies
            // are no longer encrypted. We need to keep them so that initialize_context()
            // can stub them during warmup emulation to prevent re-execution.
            let preserved_anti_tamper: Vec<Token> = findings
                .anti_tamper_methods
                .iter()
                .map(|(_, &t)| t)
                .collect();

            let (_, updated) = detection::detect_confuserex(&current);
            let native_count = updated.native_helpers.count();
            let decryptor_count = updated.decryptor_methods.count();

            // Restore the anti-tamper method tokens
            for token in preserved_anti_tamper {
                updated.anti_tamper_methods.push(token);
            }

            findings = updated;
            if let Ok(mut cached) = self.findings.write() {
                *cached = Some(findings.clone());
            }
            events.info(format!(
                "Re-ran detection after anti-tamper decryption: {} decryptors, {} native helpers, {} anti-tamper methods preserved",
                decryptor_count, native_count, findings.anti_tamper_methods.count()
            ));
        }

        // Pass 3: Fix invalid metadata (0x7fff7fff indices)
        if findings.needs_metadata_fix() {
            current = metadata::fix_invalid_metadata(current)?;
            events.info("Fixed invalid ConfuserEx metadata markers (0x7fff7fff)");
        }

        // Pass 4: Remove SuppressIldasmAttribute
        // This attribute prevents IL disassemblers from working and often has malformed blob data
        if let Some(token) = findings.suppress_ildasm_token {
            current = metadata::remove_suppress_ildasm(current, token)?;
            events.info(format!(
                "Removed SuppressIldasmAttribute (0x{:08x})",
                token.value()
            ));
        }

        // Pass 5: Remove ConfuserEx marker attributes (ConfuserVersion, ConfusedByAttribute)
        // These mark the assembly as obfuscated and can be removed for clean output.
        if findings.has_confuser_attributes {
            let tokens: Vec<_> = findings
                .confuser_attribute_tokens
                .iter()
                .map(|(_, t)| *t)
                .collect();
            if !tokens.is_empty() {
                let count = tokens.len();
                current = metadata::remove_confuser_attributes(current, tokens)?;
                events.info(format!("Removed {} ConfuserEx marker attributes", count));
            }
        }

        // Pass 6: Convert native x86 helper methods to CIL
        // ConfuserEx's x86Predicate protection creates native methods for key computation.
        // These must be converted to CIL before emulation can run string decryption.
        if findings.needs_native_conversion() {
            current = self.convert_native_helpers(current, &findings, events)?;
        }

        // The SSA-level passes (string decryption, control flow, etc.)
        // are handled by the main deobfuscation engine's pass scheduler

        Ok(current)
    }

    /// Converts native x86 helper methods to CIL.
    ///
    /// ConfuserEx's x86Predicate protection creates native x86 methods that perform
    /// key transformation for string/constant decryption. These methods must be
    /// converted to CIL before emulation can proceed.
    fn convert_native_helpers(
        &self,
        assembly: CilObject,
        findings: &ConfuserExFindings,
        events: &mut EventLog,
    ) -> Result<CilObject> {
        // Get the underlying file for reading native code bytes
        let file = assembly.file();

        // Create CilAssembly for modifications
        let mut cil_assembly = CilAssembly::from_bytes_with_validation(
            file.data().to_vec(),
            ValidationConfig::analysis(),
        )?;

        // Set up the conversion pass with all detected native helpers
        let mut converter = NativeMethodConversionPass::new();
        for (_, helper) in findings.native_helpers.iter() {
            converter.register_target(helper.token);
        }

        // Run the conversion
        let stats = converter.run(&mut cil_assembly, file)?;

        // Log single event summarizing the conversion
        if stats.failed > 0 {
            events.warn(format!(
                "Converted {}/{} native x86 methods to CIL (failures: {})",
                stats.converted,
                stats.converted + stats.failed,
                stats.errors.join(", ")
            ));
        } else {
            events.info(format!(
                "Converted {} native x86 method(s) to CIL",
                stats.converted
            ));
        }

        // Write and reload if any conversions succeeded
        if stats.converted > 0 {
            cil_assembly
                .into_cilobject_with(ValidationConfig::analysis(), GeneratorConfig::default())
        } else {
            // No conversions, return original assembly
            // We need to reload since we already consumed the original
            CilAssembly::from_bytes_with_validation(
                file.data().to_vec(),
                ValidationConfig::analysis(),
            )?
            .into_cilobject_with(ValidationConfig::analysis(), GeneratorConfig::default())
        }
    }
}

impl Obfuscator for ConfuserExObfuscator {
    fn id(&self) -> String {
        "confuserex".to_string()
    }

    fn name(&self) -> String {
        "ConfuserEx".to_string()
    }

    fn detect(&self, assembly: &CilObject) -> DetectionScore {
        // Run detection and cache the findings for later use
        let (score, findings) = detection::detect_confuserex(assembly);

        // Store findings for use by deobfuscate() and passes()
        if let Ok(mut cached) = self.findings.write() {
            *cached = Some(findings);
        }

        score
    }

    fn passes(&self) -> Vec<Box<dyn SsaPass>> {
        // SSA-level passes for ConfuserEx deobfuscation
        // These run during the main deobfuscation engine's pass scheduler

        let mut passes: Vec<Box<dyn SsaPass>> = Vec::new();

        // Get cached findings to determine which passes to enable
        if let Some(findings) = self.findings() {
            // Anti-debug pass if anti-debug methods were detected
            if findings.needs_anti_debug_patch() {
                let anti_debug_tokens: Vec<_> = findings
                    .anti_debug_methods
                    .iter()
                    .map(|(_, t)| *t)
                    .collect();
                passes.push(Box::new(antidebug::ConfuserExAntiDebugPass::with_methods(
                    anti_debug_tokens,
                )));
            }
        }

        passes
    }

    fn deobfuscate(&self, assembly: CilObject, events: &mut EventLog) -> Result<CilObject> {
        self.run_deobfuscation(assembly, events)
    }

    fn set_config(&self, config: &EngineConfig) {
        // Store tracing configuration for use during anti-tamper emulation
        if let Ok(mut tracing) = self.tracing.write() {
            *tracing = config.tracing.clone();
        }
    }

    fn initialize_context(&self, ctx: &AnalysisContext, assembly: &CilObject) {
        let findings = self.findings().unwrap_or_else(|| {
            let (_, f) = detection::detect_confuserex(assembly);
            f
        });

        // Register detected decryptor methods
        // ConfuserEx uses generic decryptors that can return any type (string, int, float, etc.)
        let decryptor_count = findings.decryptor_methods.count();
        if decryptor_count > 0 {
            // Try to find the constants Initialize() method directly.
            // This is better than running .cctor because Initialize() only does
            // decryptor setup (LZMA decompress, etc.) without protection code.
            if let Some(init_method) = constants::find_constants_initializer(assembly) {
                ctx.events.info(format!(
                    "Found constants Initialize() method 0x{:08X} - using for targeted warmup",
                    init_method.value()
                ));

                // Only run Initialize(), NOT the .cctor.
                //
                // The .cctor often contains anti-tamper/anti-debug code that throws exceptions
                // in emulation. We don't need to run .cctor because:
                // 1. RuntimeHelpers.InitializeArray is hooked to read FieldRVA directly from PE
                // 2. Initialize() will call InitializeArray with the right field tokens
                // 3. Our hook handles the array population without needing .cctor to run first
                ctx.register_warmup_method(init_method);
            }

            // Register decryptor methods
            for (_, token) in findings.decryptor_methods.iter() {
                ctx.decryptors.register(*token);
            }

            // Also register MethodSpec mappings for generic decryptors
            // ConfuserEx generic decryptors (T Get<T>(int32)) are called via MethodSpec
            // tokens that instantiate the generic with specific types
            self.register_methodspec_mappings(ctx, assembly, &findings);

            ctx.events.info(format!(
                "Registered {} ConfuserEx decryptor method(s)",
                decryptor_count
            ));

            // Register the LZMA hook for decryption emulation
            // ConfuserEx uses an inline LZMA decompressor to decompress the encrypted
            // constants array during initialization. This hook provides native
            // LZMA decompression instead of emulating the complex algorithm.
            ctx.register_emulation_hook(hooks::create_lzma_hook);

            // CRITICAL: Register anti-tamper stub hook if anti-tamper methods were detected.
            //
            // When warmup runs, it may trigger <Module>..cctor which contains:
            // 1. Anti-tamper initialization (DynCipher decryption)
            // 2. Constants initialization (LZMA decompress)
            // 3. Other protection code
            //
            // If anti-tamper decryption has already run (in run_deobfuscation), we must
            // stub out the anti-tamper methods during warmup emulation. Otherwise, the
            // .cctor would re-execute the DynCipher on already-decrypted method bodies,
            // corrupting them and causing ArrayIndexOutOfBounds errors.
            //
            // We stub ONLY the anti-tamper methods (not the entire .cctor) so that
            // legitimate initialization (like Constants.Initialize) still runs.
            if findings.anti_tamper_methods.count() > 0 {
                let anti_tamper_tokens: std::collections::HashSet<Token> = findings
                    .anti_tamper_methods
                    .iter()
                    .map(|(_, &t)| t)
                    .collect();
                let count = anti_tamper_tokens.len();
                ctx.register_emulation_hook({
                    let tokens = anti_tamper_tokens.clone();
                    move || hooks::create_anti_tamper_stub_hook(tokens.clone())
                });
                ctx.events.info(format!(
                    "Registered stub hooks for {} anti-tamper method(s) to prevent re-execution during warmup",
                    count
                ));
            }
        }

        // Register state machine provider if CFG mode detected
        if let Some(ref provider) = findings.statemachine_provider {
            let method_count = provider.methods().len();
            ctx.register_statemachine_provider(Arc::clone(provider));

            ctx.events.info(format!(
                "CFG mode detected: {} methods require order-dependent decryption",
                method_count
            ));
        }
    }

    fn cleanup_request(
        &self,
        assembly: &CilObject,
        ctx: &AnalysisContext,
    ) -> Result<Option<CleanupRequest>> {
        Ok(cleanup::build_request(self, assembly, ctx))
    }

    fn supported_versions(&self) -> &[&str] {
        &["1.0", "1.1", "1.2", "1.3", "1.4", "1.5", "1.6"]
    }

    fn description(&self) -> &'static str {
        "ConfuserEx open-source obfuscator - supports name obfuscation, control flow, string encryption, anti-tamper, and more"
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        compiler::EventLog,
        deobfuscation::obfuscators::{confuserex::ConfuserExObfuscator, Obfuscator},
        CilObject, Result, ValidationConfig,
    };

    #[test]
    fn test_detect_confuserex_samples() -> Result<()> {
        let obfuscator = ConfuserExObfuscator::new();

        // Test obfuscated samples - should all detect ConfuserEx
        let obfuscated_samples = [
            "tests/samples/packers/confuserex/mkaring_minimal.exe",
            "tests/samples/packers/confuserex/mkaring_normal.exe",
            "tests/samples/packers/confuserex/mkaring_maximum.exe",
            "tests/samples/packers/confuserex/mkaring_constants.exe",
            "tests/samples/packers/confuserex/mkaring_controlflow.exe",
            "tests/samples/packers/confuserex/mkaring_resources.exe",
        ];

        for path in obfuscated_samples {
            let assembly =
                CilObject::from_path_with_validation(path, ValidationConfig::analysis())?;
            let score = obfuscator.detect(&assembly);

            assert!(
                score.score() > 0,
                "{}: Should detect ConfuserEx (score: {}, evidence: {})",
                path,
                score.score(),
                score.evidence_summary()
            );

            println!("{}: score={}, evidence:", path, score.score());
            for evidence in score.evidence() {
                println!("  - {:?}", evidence);
            }
        }

        // Test original unobfuscated sample - should NOT detect ConfuserEx
        let assembly = CilObject::from_path("tests/samples/packers/confuserex/original.exe")?;
        let score = obfuscator.detect(&assembly);
        println!(
            "original.exe: score={}, evidence={}",
            score.score(),
            score.evidence_summary()
        );
        assert_eq!(
            score.score(),
            0,
            "Original should not be detected as ConfuserEx"
        );

        Ok(())
    }

    #[test]
    fn test_findings_cached_after_detection() -> Result<()> {
        let obfuscator = ConfuserExObfuscator::new();

        // Initially no findings
        assert!(obfuscator.findings().is_none());

        // After detection, findings should be cached
        let assembly = CilObject::from_path_with_validation(
            "tests/samples/packers/confuserex/mkaring_normal.exe",
            ValidationConfig::analysis(),
        )?;
        let _score = obfuscator.detect(&assembly);

        let findings = obfuscator.findings();
        assert!(
            findings.is_some(),
            "Findings should be cached after detect()"
        );

        let findings = findings.unwrap();
        assert!(findings.has_confuser_attributes);
        assert!(findings.decryptor_methods.count() > 0);

        Ok(())
    }

    #[test]
    fn test_deobfuscate_uses_cached_findings() -> Result<()> {
        let obfuscator = ConfuserExObfuscator::new();

        let assembly = CilObject::from_path_with_validation(
            "tests/samples/packers/confuserex/mkaring_normal.exe",
            ValidationConfig::analysis(),
        )?;

        // Call detect first (caches findings)
        let _score = obfuscator.detect(&assembly);

        // Deobfuscate should use cached findings (not re-scan)
        let mut events = EventLog::new();
        let result = obfuscator.deobfuscate(assembly, &mut events);
        assert!(result.is_ok());

        Ok(())
    }
}
