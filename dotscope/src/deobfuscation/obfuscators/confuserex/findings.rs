//! ConfuserEx detection findings.
//!
//! This module stores the results of detection scanning, which can be reused
//! during deobfuscation to avoid redundant processing.

use std::{collections::HashSet, sync::Arc};

use crate::{deobfuscation::StateMachineProvider, metadata::token::Token};

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

/// Findings from ConfuserEx detection.
///
/// This structure caches information discovered during detection so it doesn't
/// need to be recomputed during deobfuscation.
///
/// Uses `boxcar::Vec` for token collections to enable lock-free parallel writes
/// during detection and avoid unnecessary copies.
#[derive(Debug, Clone)]
pub struct ConfuserExFindings {
    /// Detected ConfuserEx version (if found in attributes).
    pub version: Option<String>,

    /// Whether the specific ConfuserEx marker (0x7fff7fff) was found.
    /// This is a high-confidence indicator of original ConfuserEx.
    pub has_confuserex_marker: bool,

    /// Whether any invalid metadata protection is present (marker or out-of-bounds).
    pub has_invalid_metadata: bool,

    /// Count of out-of-bounds metadata indices found.
    pub invalid_metadata_count: usize,

    /// Tokens of identified string/constants decryptor methods.
    pub decryptor_methods: boxcar::Vec<Token>,

    /// Tokens of methods with anti-tamper patterns (VirtualProtect + GetHINSTANCE).
    pub anti_tamper_methods: boxcar::Vec<Token>,

    /// Tokens of methods with anti-debug patterns.
    ///
    /// Anti-debug methods check for debugger presence using:
    /// - `Debugger.IsAttached` / `Debugger.IsLogging()`
    /// - `IsDebuggerPresent` P/Invoke
    /// - `Environment.FailFast` for termination
    /// - `COR_ENABLE_PROFILING` environment variable checks
    pub anti_debug_methods: boxcar::Vec<Token>,

    /// Tokens of methods with resource handler registration.
    pub resource_handler_methods: boxcar::Vec<Token>,

    /// Whether ENC tables are present (unusual for release builds).
    pub has_enc_tables: bool,

    /// Whether ConfuserEx marker attributes were found.
    pub has_confuser_attributes: bool,

    /// Tokens of ConfuserEx marker attributes (ConfuserVersion, ConfusedByAttribute).
    ///
    /// These can be removed during cleanup to hide evidence of deobfuscation.
    pub confuser_attribute_tokens: boxcar::Vec<Token>,

    /// TypeDef tokens for obfuscator-added types (ConfusedByAttribute, ConfuserVersionAttribute).
    ///
    /// These type definitions should be removed during cleanup along with their methods.
    pub obfuscator_type_tokens: boxcar::Vec<Token>,

    /// Whether SuppressIldasmAttribute is present on the assembly.
    ///
    /// ConfuserEx's "Anti ILDASM" protection adds this attribute, often with
    /// malformed blob data to crash parsers.
    pub has_suppress_ildasm: bool,

    /// Token of the SuppressIldasmAttribute custom attribute (for removal).
    pub suppress_ildasm_token: Option<Token>,

    /// Number of methods with encrypted bodies (RVA set but body couldn't be parsed).
    pub encrypted_method_count: usize,

    /// Tokens of methods that were decrypted during anti-tamper processing.
    ///
    /// These methods may contain references to obfuscator infrastructure types
    /// and need to be cleaned during the cleanup phase.
    pub decrypted_method_tokens: boxcar::Vec<Token>,

    /// PE section names containing encrypted/artifact data (for removal during cleanup).
    ///
    /// These are sections identified by:
    /// - Containing encrypted method body RVAs (methods with RVA but no parseable body)
    /// - Having non-standard names (not .text, .rsrc, .reloc, .rdata, .data, .tls)
    pub artifact_sections: boxcar::Vec<String>,

    /// Field tokens used for encrypted constant/resource data (via ldtoken + InitializeArray).
    ///
    /// These are the DataField tokens that have FieldRVA entries pointing to encrypted data.
    /// They should be removed during cleanup along with their FieldRVA entries.
    pub constant_data_fields: boxcar::Vec<Token>,

    /// TypeDef tokens for backing value types used by constant data fields.
    ///
    /// ConfuserEx creates nested value types with ClassLayout entries to hold encrypted data.
    /// These types should be removed during cleanup.
    pub constant_data_types: boxcar::Vec<Token>,

    /// TypeDef tokens for protection infrastructure types.
    ///
    /// These are types (typically nested in `<Module>`) where ALL methods are protection
    /// methods (anti-tamper, anti-debug, decryptors, resource handlers). Since they contain
    /// only obfuscator infrastructure, the entire type can be safely removed.
    ///
    /// This is computed after all protection method detection completes by checking which
    /// types have no legitimate (non-protection) methods.
    pub protection_infrastructure_types: boxcar::Vec<Token>,

    /// Field tokens for protection infrastructure fields in `<Module>`.
    ///
    /// These are static fields in `<Module>` that are only used by protection infrastructure:
    /// - `byte[]` fields storing decrypted/decompressed data
    /// - `Assembly` fields for resource loading
    /// - Fields only accessed by methods being removed
    ///
    /// These fields serve no purpose after deobfuscation and should be removed.
    pub infrastructure_fields: boxcar::Vec<Token>,

    /// Native x86 helper methods used by decryptors for key transformation.
    ///
    /// These are methods with `MethodImplCodeType::NATIVE` that are called by
    /// decryptor methods. They need to be converted to CIL using the
    /// `NativeMethodConversionPass` before emulation can proceed.
    ///
    /// Typical signature: `static int32(int32)` (DynCipher pattern).
    pub native_helpers: boxcar::Vec<NativeHelperInfo>,

    /// State machine provider for CFG mode constant decryption.
    ///
    /// This encapsulates both the dynamically detected CFGCtx semantics and
    /// the set of methods that use CFG mode. The provider implements the
    /// generic [`StateMachineProvider`] trait, allowing the decryption pass
    /// to work with any obfuscator's state machine pattern.
    ///
    /// Created during detection when CFG mode patterns are found.
    pub statemachine_provider: Option<Arc<dyn StateMachineProvider>>,
}

impl Default for ConfuserExFindings {
    fn default() -> Self {
        Self {
            version: None,
            has_confuserex_marker: false,
            has_invalid_metadata: false,
            invalid_metadata_count: 0,
            decryptor_methods: boxcar::Vec::new(),
            anti_tamper_methods: boxcar::Vec::new(),
            anti_debug_methods: boxcar::Vec::new(),
            resource_handler_methods: boxcar::Vec::new(),
            has_enc_tables: false,
            has_confuser_attributes: false,
            confuser_attribute_tokens: boxcar::Vec::new(),
            obfuscator_type_tokens: boxcar::Vec::new(),
            has_suppress_ildasm: false,
            suppress_ildasm_token: None,
            encrypted_method_count: 0,
            decrypted_method_tokens: boxcar::Vec::new(),
            artifact_sections: boxcar::Vec::new(),
            constant_data_fields: boxcar::Vec::new(),
            constant_data_types: boxcar::Vec::new(),
            protection_infrastructure_types: boxcar::Vec::new(),
            infrastructure_fields: boxcar::Vec::new(),
            native_helpers: boxcar::Vec::new(),
            statemachine_provider: None,
        }
    }
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

impl ConfuserExFindings {
    /// Creates empty findings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns true if any ConfuserEx protection was detected.
    #[must_use]
    pub fn has_any_protection(&self) -> bool {
        self.has_invalid_metadata
            || self.decryptor_methods.count() > 0
            || self.anti_tamper_methods.count() > 0
            || self.anti_debug_methods.count() > 0
            || self.resource_handler_methods.count() > 0
            || self.has_enc_tables
            || self.has_confuser_attributes
            || self.has_suppress_ildasm
            || self.protection_infrastructure_types.count() > 0
            || self.infrastructure_fields.count() > 0
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

    /// Returns true if resource decryption is needed.
    #[must_use]
    pub fn needs_resource_decryption(&self) -> bool {
        self.resource_handler_methods.count() > 0
    }

    /// Returns true if metadata fixing is needed.
    #[must_use]
    pub fn needs_metadata_fix(&self) -> bool {
        self.has_invalid_metadata
    }

    /// Returns true if ConfuserEx marker attributes should be removed.
    #[must_use]
    pub fn needs_marker_attribute_removal(&self) -> bool {
        self.confuser_attribute_tokens.count() > 0
    }

    /// Returns true if constant data infrastructure was detected.
    ///
    /// This indicates there are FieldRVA entries and backing types that should
    /// be removed during cleanup.
    #[must_use]
    pub fn has_constant_data_infrastructure(&self) -> bool {
        self.constant_data_fields.count() > 0 || self.constant_data_types.count() > 0
    }

    /// Returns true if protection infrastructure types were identified.
    ///
    /// These are types (typically in `<Module>`) containing only protection methods.
    #[must_use]
    pub fn has_protection_infrastructure_types(&self) -> bool {
        self.protection_infrastructure_types.count() > 0
    }

    /// Returns true if infrastructure fields were identified.
    ///
    /// These are static fields in `<Module>` only used by protection infrastructure
    /// (e.g., `byte[]` for decrypted data, `Assembly` for resource loading).
    #[must_use]
    pub fn has_infrastructure_fields(&self) -> bool {
        self.infrastructure_fields.count() > 0
    }

    /// Returns true if native x86 method conversion is needed.
    ///
    /// This indicates that decryptor methods call native x86 helpers that must
    /// be converted to CIL before emulation can proceed.
    #[must_use]
    pub fn needs_native_conversion(&self) -> bool {
        !self.native_helpers.is_empty()
    }

    /// Returns all protection method tokens as a collected set.
    ///
    /// This includes decryptors, anti-tamper, anti-debug, and resource handler methods.
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
        for (_, token) in &self.resource_handler_methods {
            tokens.insert(*token);
        }
        tokens
    }

    /// Returns all field tokens that should be removed during cleanup.
    ///
    /// This includes constant data fields (FieldRVA entries) and infrastructure fields.
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
    ///
    /// This includes obfuscator types, constant data backing types, and protection infrastructure types.
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
