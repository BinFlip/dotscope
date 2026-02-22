//! Framework-level deobfuscation findings.
//!
//! Central collection of everything detected during analysis. Populated by
//! obfuscator modules during detection, read by engine phases (deobfuscation,
//! pass selection, context setup, cleanup), and returned in
//! [`DeobfuscationResult`](crate::deobfuscation::DeobfuscationResult) for consumer access.
//!
//! # Architecture
//!
//! Fields are split into two categories:
//! - **Shared fields**: generic protection concepts applicable across obfuscators
//!   (decryptors, anti-debug, proxy methods, marker attributes, etc.)
//! - **Obfuscator-specific data**: held in an [`ObfuscatorData`] enum whose
//!   variants wrap per-obfuscator sub-structs ([`BitMonoFindings`],
//!   [`ConfuserExFindings`], [`ObfuscarFindings`]).
//!
//! Aggregation methods on `DeobfuscationFindings` delegate to the active
//! variant through the [`ObfuscatorFindingsProvider`] trait.

use std::{collections::HashSet, fmt};

// Re-export sub-struct types so existing `use crate::deobfuscation::findings::*` paths work.
pub use crate::deobfuscation::obfuscators::{
    BitMonoFindings, ConfuserExFindings, NativeHelperInfo, ObfuscarFindings,
};
use crate::{
    deobfuscation::detection::DetectionScore, file::repair::RepairAction, metadata::token::Token,
};

/// Cross-cutting queries that aggregation methods on `DeobfuscationFindings`
/// delegate to each obfuscator's sub-struct.
pub trait ObfuscatorFindingsProvider {
    /// Additional type tokens that should be removed during cleanup.
    fn removable_type_tokens(&self) -> Vec<Token> {
        vec![]
    }

    /// Whether this obfuscator contributes invalid metadata markers.
    fn has_invalid_metadata(&self) -> bool {
        false
    }

    /// Whether this obfuscator has ENC table artifacts.
    fn has_enc_tables(&self) -> bool {
        false
    }

    /// Whether this obfuscator has additional protection-specific artifacts.
    fn has_protections(&self) -> bool {
        false
    }
}

/// Holds the active obfuscator's specific findings.
#[derive(Debug, Clone)]
pub enum ObfuscatorData {
    /// No obfuscator-specific data.
    None,
    /// ConfuserEx-specific findings.
    ConfuserEx(ConfuserExFindings),
    /// BitMono-specific findings.
    BitMono(BitMonoFindings),
    /// Obfuscar-specific findings.
    Obfuscar(ObfuscarFindings),
}

impl Default for ObfuscatorData {
    fn default() -> Self {
        Self::None
    }
}

impl ObfuscatorData {
    /// Returns a reference to the provider trait object for the active variant.
    fn provider(&self) -> Option<&dyn ObfuscatorFindingsProvider> {
        match self {
            Self::None => None,
            Self::ConfuserEx(f) => Some(f),
            Self::BitMono(f) => Some(f),
            Self::Obfuscar(f) => Some(f),
        }
    }
}

/// Framework-level deobfuscation findings.
///
/// Central collection of everything detected during analysis. Populated by
/// obfuscator modules during detection, read by engine phases (deobfuscation,
/// pass selection, context setup, cleanup), and returned in
/// `DeobfuscationResult` for consumer access.
///
/// Each token collection uses `boxcar::Vec` for lock-free parallel writes
/// during detection. Obfuscator-specific fields are held in the
/// [`obfuscator`](Self::obfuscator) enum variant.
#[derive(Debug, Clone)]
pub struct DeobfuscationFindings {
    // === Detection Summary ===
    /// Detection score carrying confidence level and all evidence.
    pub detection: DetectionScore,

    // === Obfuscator Identification ===
    /// Detected obfuscator name (e.g., "ConfuserEx").
    pub obfuscator_name: Option<String>,
    /// Detected obfuscator version.
    pub obfuscator_version: Option<String>,

    // === String/Constant Encryption ===
    /// Decryptor method tokens.
    pub decryptor_methods: boxcar::Vec<Token>,
    /// Data fields with FieldRVA entries (encrypted constant storage).
    pub constant_data_fields: boxcar::Vec<Token>,
    /// Backing value types for constant data fields.
    pub constant_data_types: boxcar::Vec<Token>,

    // === Anti-Tamper ===
    /// Anti-tamper initialization method tokens.
    pub anti_tamper_methods: boxcar::Vec<Token>,

    // === Anti-Debug ===
    /// Anti-debug method tokens.
    pub anti_debug_methods: boxcar::Vec<Token>,

    // === Anti-Dump ===
    /// Anti-dump method tokens.
    pub anti_dump_methods: boxcar::Vec<Token>,

    // === Reference Proxy ===
    /// Proxy forwarding method tokens.
    pub proxy_methods: boxcar::Vec<Token>,

    // === Resource Encryption ===
    /// Resource handler method tokens.
    pub resource_handler_methods: boxcar::Vec<Token>,

    // === Metadata Artifacts ===
    /// Marker attribute tokens (ConfusedByAttribute, ConfuserVersionAttribute, AntiDe4dot).
    pub marker_attribute_tokens: boxcar::Vec<Token>,
    /// SuppressIldasm attribute token (if present).
    pub suppress_ildasm_token: Option<Token>,
    /// TypeRef tokens with out-of-bounds ResolutionScope (invalid metadata).
    pub invalid_metadata_entries: boxcar::Vec<Token>,

    // === PE Repair ===
    /// PE repairs applied before loading (empty if file loaded normally).
    pub pe_repairs: Vec<RepairAction>,

    // === Cleanup Infrastructure ===
    /// Protection infrastructure types (all methods are protection code).
    pub protection_infrastructure_types: boxcar::Vec<Token>,
    /// Infrastructure fields (only used by protection code).
    pub infrastructure_fields: boxcar::Vec<Token>,

    // === Obfuscator-Specific ===
    /// Holds the active obfuscator's specific findings.
    pub obfuscator: ObfuscatorData,
}

impl Default for DeobfuscationFindings {
    fn default() -> Self {
        Self {
            detection: DetectionScore::new(),
            obfuscator_name: None,
            obfuscator_version: None,
            decryptor_methods: boxcar::Vec::new(),
            constant_data_fields: boxcar::Vec::new(),
            constant_data_types: boxcar::Vec::new(),
            anti_tamper_methods: boxcar::Vec::new(),
            anti_debug_methods: boxcar::Vec::new(),
            anti_dump_methods: boxcar::Vec::new(),
            proxy_methods: boxcar::Vec::new(),
            resource_handler_methods: boxcar::Vec::new(),
            marker_attribute_tokens: boxcar::Vec::new(),
            suppress_ildasm_token: None,
            invalid_metadata_entries: boxcar::Vec::new(),
            pe_repairs: Vec::new(),
            protection_infrastructure_types: boxcar::Vec::new(),
            infrastructure_fields: boxcar::Vec::new(),
            obfuscator: ObfuscatorData::None,
        }
    }
}

impl DeobfuscationFindings {
    /// Creates empty findings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns a reference to the BitMono-specific findings, if active.
    #[must_use]
    pub fn bitmono(&self) -> Option<&BitMonoFindings> {
        match &self.obfuscator {
            ObfuscatorData::BitMono(f) => Some(f),
            _ => None,
        }
    }

    /// Returns a mutable reference to the BitMono-specific findings, if active.
    pub fn bitmono_mut(&mut self) -> Option<&mut BitMonoFindings> {
        match &mut self.obfuscator {
            ObfuscatorData::BitMono(f) => Some(f),
            _ => None,
        }
    }

    /// Initializes the BitMono variant (if not already active) and returns a
    /// mutable reference to it.
    pub fn init_bitmono(&mut self) -> &mut BitMonoFindings {
        if !matches!(self.obfuscator, ObfuscatorData::BitMono(_)) {
            self.obfuscator = ObfuscatorData::BitMono(BitMonoFindings::default());
        }
        match &mut self.obfuscator {
            ObfuscatorData::BitMono(f) => f,
            _ => unreachable!(),
        }
    }

    /// Returns a reference to the ConfuserEx-specific findings, if active.
    #[must_use]
    pub fn confuserex(&self) -> Option<&ConfuserExFindings> {
        match &self.obfuscator {
            ObfuscatorData::ConfuserEx(f) => Some(f),
            _ => None,
        }
    }

    /// Returns a mutable reference to the ConfuserEx-specific findings, if active.
    pub fn confuserex_mut(&mut self) -> Option<&mut ConfuserExFindings> {
        match &mut self.obfuscator {
            ObfuscatorData::ConfuserEx(f) => Some(f),
            _ => None,
        }
    }

    /// Initializes the ConfuserEx variant (if not already active) and returns a
    /// mutable reference to it.
    pub fn init_confuserex(&mut self) -> &mut ConfuserExFindings {
        if !matches!(self.obfuscator, ObfuscatorData::ConfuserEx(_)) {
            self.obfuscator = ObfuscatorData::ConfuserEx(ConfuserExFindings::default());
        }
        match &mut self.obfuscator {
            ObfuscatorData::ConfuserEx(f) => f,
            _ => unreachable!(),
        }
    }

    /// Returns a reference to the Obfuscar-specific findings, if active.
    #[must_use]
    pub fn obfuscar(&self) -> Option<&ObfuscarFindings> {
        match &self.obfuscator {
            ObfuscatorData::Obfuscar(f) => Some(f),
            _ => None,
        }
    }

    /// Initializes the Obfuscar variant (if not already active) and returns a
    /// mutable reference to it.
    pub fn init_obfuscar(&mut self) -> &mut ObfuscarFindings {
        if !matches!(self.obfuscator, ObfuscatorData::Obfuscar(_)) {
            self.obfuscator = ObfuscatorData::Obfuscar(ObfuscarFindings::default());
        }
        match &mut self.obfuscator {
            ObfuscatorData::Obfuscar(f) => f,
            _ => unreachable!(),
        }
    }

    /// Returns the detection confidence score.
    #[must_use]
    pub fn detection_score(&self) -> usize {
        self.detection.score()
    }

    /// Returns true if an obfuscator was detected with confidence above the given threshold.
    #[must_use]
    pub fn detected(&self, threshold: usize) -> bool {
        self.detection.score() >= threshold
    }

    /// Generates a human-readable detection summary.
    #[must_use]
    pub fn detection_summary(&self) -> String {
        if let Some(name) = &self.obfuscator_name {
            format!("Detected: {} (score={})", name, self.detection.score())
        } else {
            "No obfuscator detected".to_string()
        }
    }

    /// Returns true if any protection was detected.
    #[must_use]
    pub fn has_any_protection(&self) -> bool {
        self.has_invalid_metadata()
            || self.decryptor_methods.count() > 0
            || self.anti_tamper_methods.count() > 0
            || self.anti_debug_methods.count() > 0
            || self.anti_dump_methods.count() > 0
            || self.resource_handler_methods.count() > 0
            || self.proxy_methods.count() > 0
            || self.has_enc_tables()
            || self.has_marker_attributes()
            || self.has_suppress_ildasm()
            || self.protection_infrastructure_types.count() > 0
            || self.infrastructure_fields.count() > 0
            || self
                .obfuscator
                .provider()
                .is_some_and(|p| p.has_protections())
    }

    /// Returns true if marker attributes were detected.
    #[must_use]
    pub fn has_marker_attributes(&self) -> bool {
        self.marker_attribute_tokens.count() > 0
    }

    /// Returns true if SuppressIldasmAttribute was detected.
    #[must_use]
    pub fn has_suppress_ildasm(&self) -> bool {
        self.suppress_ildasm_token.is_some()
    }

    /// Returns true if any invalid metadata was detected.
    #[must_use]
    pub fn has_invalid_metadata(&self) -> bool {
        self.invalid_metadata_entries.count() > 0
            || self
                .obfuscator
                .provider()
                .is_some_and(|p| p.has_invalid_metadata())
    }

    /// Returns the total count of invalid metadata entries.
    #[must_use]
    pub fn invalid_metadata_count(&self) -> usize {
        self.invalid_metadata_entries.count()
    }

    /// Returns true if the obfuscator-specific marker was found.
    #[must_use]
    pub fn has_obfuscator_marker(&self) -> bool {
        self.confuserex()
            .is_some_and(|cx| cx.obfuscator_marker_value.is_some())
    }

    /// Returns true if ENC tables are present.
    #[must_use]
    pub fn has_enc_tables(&self) -> bool {
        self.obfuscator
            .provider()
            .is_some_and(|p| p.has_enc_tables())
    }

    /// Returns true if string/constant decryption is needed.
    #[must_use]
    pub fn needs_string_decryption(&self) -> bool {
        self.decryptor_methods.count() > 0
    }

    /// Returns true if anti-tamper patching is needed.
    #[must_use]
    pub fn needs_anti_tamper_patch(&self) -> bool {
        self.anti_tamper_methods.count() > 0
    }

    /// Returns true if anti-tamper decryption is needed.
    ///
    /// Requires both anti-tamper initialization methods AND encrypted method
    /// bodies present (ConfuserEx-specific).
    #[must_use]
    pub fn needs_anti_tamper_decryption(&self) -> bool {
        self.anti_tamper_methods.count() > 0
            && self
                .confuserex()
                .is_some_and(|cx| cx.encrypted_method_count > 0)
    }

    /// Returns true if anti-debug patching is needed.
    #[must_use]
    pub fn needs_anti_debug_patch(&self) -> bool {
        self.anti_debug_methods.count() > 0
    }

    /// Returns true if anti-dump patching is needed.
    #[must_use]
    pub fn needs_anti_dump_patch(&self) -> bool {
        self.anti_dump_methods.count() > 0
    }

    /// Returns true if resource decryption is needed.
    #[must_use]
    pub fn needs_resource_decryption(&self) -> bool {
        self.resource_handler_methods.count() > 0
    }

    /// Returns true if metadata fixing is needed.
    #[must_use]
    pub fn needs_metadata_fix(&self) -> bool {
        self.has_invalid_metadata()
    }

    /// Returns true if marker attributes should be removed.
    #[must_use]
    pub fn needs_marker_attribute_removal(&self) -> bool {
        self.marker_attribute_tokens.count() > 0
    }

    /// Returns true if constant data infrastructure was detected.
    #[must_use]
    pub fn has_constant_data_infrastructure(&self) -> bool {
        self.constant_data_fields.count() > 0 || self.constant_data_types.count() > 0
    }

    /// Returns true if protection infrastructure types were identified.
    #[must_use]
    pub fn has_protection_infrastructure_types(&self) -> bool {
        self.protection_infrastructure_types.count() > 0
    }

    /// Returns true if infrastructure fields were identified.
    #[must_use]
    pub fn has_infrastructure_fields(&self) -> bool {
        self.infrastructure_fields.count() > 0
    }

    /// Returns true if proxy method inlining should be enabled.
    #[must_use]
    pub fn needs_proxy_inlining(&self) -> bool {
        self.proxy_methods.count() > 0
    }

    /// Returns true if CFG mode was detected.
    #[must_use]
    pub fn uses_cfg_mode(&self) -> bool {
        self.confuserex().is_some_and(|cx| cx.uses_cfg_mode())
    }

    /// Returns true if a specific method uses CFG mode.
    #[must_use]
    pub fn is_cfg_mode_method(&self, token: Token) -> bool {
        self.confuserex()
            .is_some_and(|cx| cx.is_cfg_mode_method(token))
    }

    /// Returns true if native x86 method conversion is needed.
    #[must_use]
    pub fn needs_native_conversion(&self) -> bool {
        self.confuserex()
            .is_some_and(|cx| cx.needs_native_conversion())
    }

    /// Returns all protection method tokens as a collected set.
    #[must_use]
    pub fn all_protection_method_tokens(&self) -> HashSet<Token> {
        let mut tokens = HashSet::new();
        for (_, token) in &self.decryptor_methods {
            tokens.insert(*token);
        }
        for (_, token) in &self.anti_tamper_methods {
            tokens.insert(*token);
        }
        for (_, token) in &self.anti_debug_methods {
            tokens.insert(*token);
        }
        for (_, token) in &self.anti_dump_methods {
            tokens.insert(*token);
        }
        for (_, token) in &self.resource_handler_methods {
            tokens.insert(*token);
        }
        for (_, token) in &self.proxy_methods {
            tokens.insert(*token);
        }
        tokens
    }

    /// Returns all field tokens that should be removed during cleanup.
    #[must_use]
    pub fn all_removable_field_tokens(&self) -> HashSet<Token> {
        let mut tokens = HashSet::new();
        for (_, token) in &self.constant_data_fields {
            tokens.insert(*token);
        }
        for (_, token) in &self.infrastructure_fields {
            tokens.insert(*token);
        }
        tokens
    }

    /// Returns all type tokens that should be removed during cleanup.
    #[must_use]
    pub fn all_removable_type_tokens(&self) -> HashSet<Token> {
        let mut tokens = HashSet::new();
        for (_, token) in &self.constant_data_types {
            tokens.insert(*token);
        }
        for (_, token) in &self.protection_infrastructure_types {
            tokens.insert(*token);
        }
        if let Some(provider) = self.obfuscator.provider() {
            tokens.extend(provider.removable_type_tokens());
        }
        tokens
    }
}

impl fmt::Display for DeobfuscationFindings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Detection summary
        if let Some(name) = &self.obfuscator_name {
            writeln!(
                f,
                "  Obfuscator:  {} (score: {})",
                name,
                self.detection.score()
            )?;
        } else {
            writeln!(f, "  Obfuscator:  none detected")?;
            return Ok(());
        }

        if !self.has_any_protection() {
            return Ok(());
        }

        // Shared protections
        writeln!(f)?;
        writeln!(f, "  Detected protections:")?;

        let decryptor_count = self.decryptor_methods.count();
        if decryptor_count > 0 {
            writeln!(f, "    Decryptors:        {} methods", decryptor_count)?;
        }

        let anti_tamper_count = self.anti_tamper_methods.count();
        if anti_tamper_count > 0 {
            let encrypted = self.confuserex().map_or(0, |cx| cx.encrypted_method_count);
            if encrypted > 0 {
                writeln!(
                    f,
                    "    Anti-tamper:       {} methods ({} encrypted bodies)",
                    anti_tamper_count, encrypted
                )?;
            } else {
                writeln!(f, "    Anti-tamper:       {} methods", anti_tamper_count)?;
            }
        }

        let anti_debug_count = self.anti_debug_methods.count();
        if anti_debug_count > 0 {
            writeln!(f, "    Anti-debug:        {} methods", anti_debug_count)?;
        }

        let anti_dump_count = self.anti_dump_methods.count();
        if anti_dump_count > 0 {
            writeln!(f, "    Anti-dump:         {} methods", anti_dump_count)?;
        }

        let proxy_count = self.proxy_methods.count();
        if proxy_count > 0 {
            writeln!(f, "    Proxy methods:     {} methods", proxy_count)?;
        }

        let resource_count = self.resource_handler_methods.count();
        if resource_count > 0 {
            writeln!(f, "    Resources:         {} handlers", resource_count)?;
        }

        // Metadata artifacts
        if self.has_marker_attributes() {
            writeln!(f, "    Marker attributes: yes")?;
        }

        if self.has_suppress_ildasm() {
            writeln!(f, "    SuppressIldasm:    yes")?;
        }

        let invalid_count = self.invalid_metadata_entries.count();
        if invalid_count > 0 {
            writeln!(f, "    Invalid metadata:  {} entries", invalid_count)?;
        }

        // Obfuscator-specific section
        match &self.obfuscator {
            ObfuscatorData::BitMono(bm) if bm.has_protections() => {
                writeln!(f)?;
                writeln!(f, "  BitMono-specific:")?;
                write!(f, "{bm}")?;
            }
            ObfuscatorData::ConfuserEx(cx) => {
                let has_any = cx.native_helpers.count() > 0
                    || cx.encrypted_method_count > 0
                    || cx.uses_cfg_mode()
                    || cx.obfuscator_marker_value.is_some()
                    || cx.enc_tables.count() > 0
                    || cx.artifact_sections.count() > 0;
                if has_any {
                    writeln!(f)?;
                    writeln!(f, "  ConfuserEx-specific:")?;
                    write!(f, "{cx}")?;
                }
            }
            _ => {}
        }

        Ok(())
    }
}
