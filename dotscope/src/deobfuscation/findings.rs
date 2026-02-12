//! Framework-level deobfuscation findings.
//!
//! Central collection of everything detected during analysis. Populated by
//! obfuscator modules during detection, read by engine phases (deobfuscation,
//! pass selection, context setup, cleanup), and returned in
//! [`DeobfuscationResult`](crate::deobfuscation::DeobfuscationResult) for consumer access.

use std::{collections::HashSet, sync::Arc};

use crate::{
    deobfuscation::{detection::DetectionScore, StateMachineProvider},
    metadata::token::Token,
};

/// Information about a detected native x86 helper method.
///
/// These are native methods (with `MethodImplCodeType::NATIVE`) called by
/// decryptor methods for key transformation. They need to be converted to
/// CIL before emulation can proceed.
#[derive(Debug, Clone)]
pub struct NativeHelperInfo {
    /// Metadata token of the native method.
    pub token: Token,
    /// RVA of the native code.
    pub rva: u32,
    /// Tokens of methods that call this native method.
    pub callers: Vec<Token>,
}

impl NativeHelperInfo {
    /// Creates a new native helper info.
    #[must_use]
    pub fn new(token: Token, rva: u32) -> Self {
        Self {
            token,
            rva,
            callers: Vec::new(),
        }
    }

    /// Adds a caller to this native helper.
    pub fn add_caller(&mut self, caller: Token) {
        if !self.callers.contains(&caller) {
            self.callers.push(caller);
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
/// during detection.
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
    /// State machine provider for order-dependent decryption (CFG mode).
    pub statemachine_provider: Option<Arc<dyn StateMachineProvider>>,

    // === Native Code ===
    /// Native x86 helper methods used by decryptors.
    pub native_helpers: boxcar::Vec<NativeHelperInfo>,

    // === Anti-Tamper ===
    /// Anti-tamper initialization method tokens.
    pub anti_tamper_methods: boxcar::Vec<Token>,
    /// Number of encrypted method bodies detected.
    pub encrypted_method_count: usize,
    /// Method tokens decrypted during anti-tamper processing.
    pub decrypted_method_tokens: boxcar::Vec<Token>,

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
    /// Marker attribute tokens (ConfusedByAttribute, ConfuserVersionAttribute).
    pub marker_attribute_tokens: boxcar::Vec<Token>,
    /// Obfuscator-added type tokens (marker types like ConfusedByAttribute).
    pub obfuscator_type_tokens: boxcar::Vec<Token>,
    /// SuppressIldasm attribute token (if present).
    pub suppress_ildasm_token: Option<Token>,
    /// TypeRef tokens with out-of-bounds ResolutionScope (invalid metadata).
    pub invalid_metadata_entries: boxcar::Vec<Token>,
    /// Obfuscator-specific marker value found in metadata (e.g., 0x7fff7fff).
    pub obfuscator_marker_value: Option<u32>,
    /// Non-empty ENC table indices (ENCLog=0x1E, ENCMap=0x1F).
    pub enc_tables: boxcar::Vec<u8>,

    // === Cleanup Infrastructure ===
    /// PE sections containing encrypted/artifact data.
    pub artifact_sections: boxcar::Vec<String>,
    /// Protection infrastructure types (all methods are protection code).
    pub protection_infrastructure_types: boxcar::Vec<Token>,
    /// Infrastructure fields (only used by protection code).
    pub infrastructure_fields: boxcar::Vec<Token>,
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
            statemachine_provider: None,
            native_helpers: boxcar::Vec::new(),
            anti_tamper_methods: boxcar::Vec::new(),
            encrypted_method_count: 0,
            decrypted_method_tokens: boxcar::Vec::new(),
            anti_debug_methods: boxcar::Vec::new(),
            anti_dump_methods: boxcar::Vec::new(),
            proxy_methods: boxcar::Vec::new(),
            resource_handler_methods: boxcar::Vec::new(),
            marker_attribute_tokens: boxcar::Vec::new(),
            obfuscator_type_tokens: boxcar::Vec::new(),
            suppress_ildasm_token: None,
            invalid_metadata_entries: boxcar::Vec::new(),
            obfuscator_marker_value: None,
            enc_tables: boxcar::Vec::new(),
            artifact_sections: boxcar::Vec::new(),
            protection_infrastructure_types: boxcar::Vec::new(),
            infrastructure_fields: boxcar::Vec::new(),
        }
    }
}

impl DeobfuscationFindings {
    /// Creates empty findings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
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
        self.invalid_metadata_entries.count() > 0 || self.obfuscator_marker_value.is_some()
    }

    /// Returns the total count of invalid metadata entries.
    #[must_use]
    pub fn invalid_metadata_count(&self) -> usize {
        self.invalid_metadata_entries.count()
    }

    /// Returns true if the obfuscator-specific marker was found.
    #[must_use]
    pub fn has_obfuscator_marker(&self) -> bool {
        self.obfuscator_marker_value.is_some()
    }

    /// Returns true if ENC tables are present.
    #[must_use]
    pub fn has_enc_tables(&self) -> bool {
        self.enc_tables.count() > 0
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
    /// This requires both:
    /// - Anti-tamper initialization methods detected (VirtualProtect + GetHINSTANCE)
    /// - Encrypted method bodies present (methods with RVA but no parseable body)
    #[must_use]
    pub fn needs_anti_tamper_decryption(&self) -> bool {
        self.anti_tamper_methods.count() > 0 && self.encrypted_method_count > 0
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

    /// Returns true if native x86 method conversion is needed.
    #[must_use]
    pub fn needs_native_conversion(&self) -> bool {
        !self.native_helpers.is_empty()
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
        for (_, token) in &self.obfuscator_type_tokens {
            tokens.insert(*token);
        }
        for (_, token) in &self.constant_data_types {
            tokens.insert(*token);
        }
        for (_, token) in &self.protection_infrastructure_types {
            tokens.insert(*token);
        }
        tokens
    }

    /// Returns true if CFG mode was detected.
    #[must_use]
    pub fn uses_cfg_mode(&self) -> bool {
        self.statemachine_provider
            .as_ref()
            .is_some_and(|p| !p.methods().is_empty())
    }

    /// Returns true if a specific method uses CFG mode.
    #[must_use]
    pub fn is_cfg_mode_method(&self, token: Token) -> bool {
        self.statemachine_provider
            .as_ref()
            .is_some_and(|p| p.applies_to_method(token))
    }
}
