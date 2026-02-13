//! Obfuscar obfuscator support.
//!
//! Obfuscar is the most actively maintained open-source .NET obfuscator. Unlike
//! ConfuserEx which is a multi-layer protection framework, Obfuscar is a
//! **renaming-focused** obfuscator with string hiding as its only code-transforming
//! protection.
//!
//! # Protection Summary
//!
//! | Protection | Description |
//! |------------|-------------|
//! | Rename | Symbol renaming (types, methods, fields, properties, events) |
//! | String Hiding | XOR-encrypted strings via injected helper type |
//! | SuppressIldasm | Adds SuppressIldasmAttribute to block ILDasm |
//! | Property/Event Removal | Drops property/event metadata (keeps accessor methods) |
//!
//! # Detection
//!
//! Obfuscar is detected primarily by the `<PrivateImplementationDetails>{GUID}` helper
//! type injected for string hiding. This type has a characteristic structure with a
//! method named "6" (shared getter) and multiple per-string accessor methods.
//!
//! # String Decryption
//!
//! String decryption uses the emulation pipeline (same as ConfuserEx). The `.cctor` of the
//! helper type runs as a warmup method to initialize the encrypted byte array, then each
//! per-string accessor method is emulated to retrieve the decrypted string. Call sites
//! targeting accessor methods are replaced with the decrypted string constants.
//!
//! # Test Samples
//!
//! Test samples in `tests/samples/packers/obfuscar/` are generated with different
//! Obfuscar configurations:
//!
//! | Sample | Configuration |
//! |--------|--------------|
//! | `original.exe` | Unprotected baseline |
//! | `obfuscar_default.exe` | Defaults (rename private API + strings + SuppressIldasm) |
//! | `obfuscar_strings_only.exe` | String hiding only (no renaming) |
//! | `obfuscar_rename_only.exe` | Renaming only (no strings, no SuppressIldasm) |
//! | `obfuscar_unicode.exe` | Unicode name mode (defaults + UseUnicodeNames) |
//! | `obfuscar_maximum.exe` | Maximum: all protections, public API also renamed |

mod cleanup;
mod detection;

pub use detection::detect_obfuscar;

use crate::{
    cilassembly::CleanupRequest,
    compiler::EventLog,
    deobfuscation::{
        context::AnalysisContext, detection::DetectionScore, findings::DeobfuscationFindings,
        obfuscators::Obfuscator,
    },
    metadata::{signatures::TypeSignature, token::Token},
    CilObject, Result,
};

/// Obfuscar obfuscator implementation.
///
/// Handles detection and deobfuscation of assemblies protected by Obfuscar.
///
/// Detection populates a [`DeobfuscationFindings`] struct that is passed through
/// the pipeline by the engine. The obfuscator itself is stateless.
pub struct ObfuscarObfuscator;

impl Default for ObfuscarObfuscator {
    fn default() -> Self {
        Self::new()
    }
}

impl ObfuscarObfuscator {
    /// Creates a new Obfuscar obfuscator instance.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Finds the `.cctor` token for the Obfuscar helper type.
    ///
    /// The `.cctor` initializes the encrypted byte array (XOR decryption loop)
    /// and must run as a warmup method before accessor methods can be emulated.
    ///
    /// Searches `findings.protection_infrastructure_types` for types whose namespace
    /// starts with `<PrivateImplementationDetails>{`, then locates the `.cctor` method
    /// within that type.
    ///
    /// # Returns
    ///
    /// The `.cctor` method token if found, or `None` if no helper type has a `.cctor`.
    fn find_helper_cctor(assembly: &CilObject, findings: &DeobfuscationFindings) -> Option<Token> {
        for (_, &type_token) in &findings.protection_infrastructure_types {
            let cil_type = assembly.types().get(&type_token)?;

            if !cil_type
                .namespace
                .starts_with("<PrivateImplementationDetails>{")
            {
                continue;
            }

            for (_, method_ref) in cil_type.methods.iter() {
                let Some(method) = method_ref.upgrade() else {
                    continue;
                };
                if method.name == ".cctor" {
                    return Some(method.token);
                }
            }
        }
        None
    }

    /// Finds the method "6" token (shared string getter) for the helper type.
    ///
    /// Method "6" is Obfuscar's shared string getter with signature
    /// `static string "6"(int32, int32, int32)`. It decodes a substring from the
    /// decrypted byte array using `Encoding.UTF8.GetString()`. This method is not
    /// a decryptor itself (user code doesn't call it directly), but it must be
    /// accessible during emulation since all per-string accessor methods call it.
    ///
    /// # Returns
    ///
    /// The method "6" token if found with the correct signature, or `None`.
    fn find_method_6(assembly: &CilObject, findings: &DeobfuscationFindings) -> Option<Token> {
        for (_, &type_token) in &findings.protection_infrastructure_types {
            let Some(cil_type) = assembly.types().get(&type_token) else {
                continue;
            };

            for (_, method_ref) in cil_type.methods.iter() {
                let Some(method) = method_ref.upgrade() else {
                    continue;
                };
                if method.name == "6" {
                    let sig = &method.signature;
                    let returns_string = matches!(sig.return_type.base, TypeSignature::String);
                    let has_3_params = sig.params.len() == 3;
                    if returns_string && has_3_params {
                        return Some(method.token);
                    }
                }
            }
        }
        None
    }
}

impl Obfuscator for ObfuscarObfuscator {
    fn id(&self) -> String {
        "obfuscar".to_string()
    }

    fn name(&self) -> String {
        "Obfuscar".to_string()
    }

    fn detect(&self, assembly: &CilObject, findings: &mut DeobfuscationFindings) -> DetectionScore {
        let (score, detected) = detection::detect_obfuscar(assembly);

        // Copy detected findings into the framework-level findings
        *findings = detected;

        score
    }

    fn deobfuscate(
        &self,
        assembly: CilObject,
        events: &mut EventLog,
        findings: &mut DeobfuscationFindings,
    ) -> Result<CilObject> {
        // Pre-SSA deobfuscation phase.
        // Obfuscar doesn't need byte-level patching — string decryption is handled
        // by the SSA pipeline via emulation (DecryptionPass) after initialize_context
        // registers the accessor methods and warmup.

        if let Some(token) = findings.suppress_ildasm_token {
            events.info(format!(
                "Found SuppressIldasmAttribute (0x{:08x}) — will be removed during cleanup",
                token.value()
            ));
        }

        if findings.decryptor_methods.count() > 0 {
            events.info(format!(
                "Found {} Obfuscar string accessor methods — will decrypt via emulation",
                findings.decryptor_methods.count()
            ));
        }

        Ok(assembly)
    }

    fn initialize_context(
        &self,
        ctx: &AnalysisContext,
        assembly: &CilObject,
        findings: &DeobfuscationFindings,
    ) {
        let decryptor_count = findings.decryptor_methods.count();
        if decryptor_count == 0 {
            return;
        }

        // Register the .cctor as a warmup method.
        // The .cctor runs the XOR decryption loop to populate the decrypted byte array
        // in memory. This must execute before accessor methods can return strings.
        if let Some(cctor_token) = Self::find_helper_cctor(assembly, findings) {
            ctx.events.info(format!(
                "Found Obfuscar helper .cctor (0x{:08X}) — registering as warmup",
                cctor_token.value()
            ));
            ctx.register_warmup_method(cctor_token);
        }

        // Register accessor methods as decryptors.
        // Each accessor is a static parameterless method returning string — user code
        // calls these instead of ldstr. The DecryptionPass will emulate each one
        // to retrieve the decrypted string.
        for (_, token) in &findings.decryptor_methods {
            ctx.decryptors.register(*token);
        }

        if let Some(m6_token) = Self::find_method_6(assembly, findings) {
            ctx.events.info(format!(
                "Found shared string getter method \"6\" (0x{:08X})",
                m6_token.value()
            ));
        }

        ctx.events.info(format!(
            "Registered {decryptor_count} Obfuscar string accessor method(s) for emulation"
        ));
    }

    fn cleanup_request(
        &self,
        assembly: &CilObject,
        ctx: &AnalysisContext,
        findings: &DeobfuscationFindings,
    ) -> Result<Option<CleanupRequest>> {
        Ok(cleanup::build_request(assembly, ctx, findings))
    }

    fn supported_versions(&self) -> &[&str] {
        &["2.0", "2.1", "2.2"]
    }

    fn description(&self) -> &'static str {
        "Obfuscar open-source obfuscator - supports name obfuscation, string hiding, and SuppressIldasm"
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        compiler::EventLog,
        deobfuscation::{
            findings::DeobfuscationFindings,
            obfuscators::{obfuscar::ObfuscarObfuscator, Obfuscator},
        },
        CilObject, Result, ValidationConfig,
    };

    #[test]
    fn test_obfuscar_trait_methods() {
        let obfuscator = ObfuscarObfuscator::new();
        assert_eq!(obfuscator.id(), "obfuscar");
        assert_eq!(obfuscator.name(), "Obfuscar");
        assert!(!obfuscator.supported_versions().is_empty());
        assert!(!obfuscator.description().is_empty());
    }

    #[test]
    fn test_detect_original_not_obfuscar() -> Result<()> {
        let path = "tests/samples/packers/confuserex/original.exe";

        // Skip if sample doesn't exist
        if !std::path::Path::new(path).exists() {
            eprintln!("Skipping test: sample not found at {path}");
            return Ok(());
        }

        let obfuscator = ObfuscarObfuscator::new();
        let assembly = CilObject::from_path_with_validation(path, ValidationConfig::analysis())?;
        let mut findings = DeobfuscationFindings::new();
        let score = obfuscator.detect(&assembly, &mut findings);

        // An unobfuscated sample should score below the detection threshold (50)
        assert!(
            score.score() < 50,
            "Unobfuscated sample should not be detected as Obfuscar (score: {})",
            score.score()
        );

        Ok(())
    }

    #[test]
    fn test_detect_obfuscar_samples() -> Result<()> {
        let obfuscator = ObfuscarObfuscator::new();

        let samples = [
            "tests/samples/packers/obfuscar/obfuscar_default.exe",
            "tests/samples/packers/obfuscar/obfuscar_strings_only.exe",
        ];

        for path in samples {
            if !std::path::Path::new(path).exists() {
                eprintln!("Skipping test: sample not found at {path}");
                continue;
            }

            let assembly =
                CilObject::from_path_with_validation(path, ValidationConfig::analysis())?;
            let mut findings = DeobfuscationFindings::new();
            let score = obfuscator.detect(&assembly, &mut findings);

            assert!(
                score.score() > 0,
                "{path}: Should detect Obfuscar (score: {}, evidence: {})",
                score.score(),
                score.evidence_summary()
            );

            println!("{path}: score={}, evidence:", score.score());
            for evidence in score.evidence() {
                println!("  - {evidence:?}");
            }
        }

        Ok(())
    }

    #[test]
    fn test_deobfuscate_with_findings() -> Result<()> {
        let path = "tests/samples/packers/obfuscar/obfuscar_default.exe";

        if !std::path::Path::new(path).exists() {
            eprintln!("Skipping test: sample not found at {path}");
            return Ok(());
        }

        let obfuscator = ObfuscarObfuscator::new();
        let assembly = CilObject::from_path_with_validation(path, ValidationConfig::analysis())?;

        let mut findings = DeobfuscationFindings::new();
        let _score = obfuscator.detect(&assembly, &mut findings);

        let mut events = EventLog::new();
        let result = obfuscator.deobfuscate(assembly, &mut events, &mut findings);
        assert!(result.is_ok());

        Ok(())
    }
}
