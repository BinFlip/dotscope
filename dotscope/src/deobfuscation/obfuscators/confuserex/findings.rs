//! ConfuserEx-specific detection findings.

use std::{fmt, sync::Arc};

use crate::{
    deobfuscation::{findings::ObfuscatorFindingsProvider, StateMachineProvider},
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

/// ConfuserEx-specific detection findings.
#[derive(Debug, Clone, Default)]
pub struct ConfuserExFindings {
    /// State machine provider for order-dependent decryption (CFG mode).
    pub statemachine_provider: Option<Arc<dyn StateMachineProvider>>,
    /// Native x86 helper methods used by decryptors.
    pub native_helpers: boxcar::Vec<NativeHelperInfo>,
    /// Number of encrypted method bodies detected.
    pub encrypted_method_count: usize,
    /// Obfuscator-specific marker value found in metadata (e.g., 0x7fff7fff).
    pub obfuscator_marker_value: Option<u32>,
    /// Non-empty ENC table indices (ENCLog=0x1E, ENCMap=0x1F).
    pub enc_tables: boxcar::Vec<u8>,
    /// Obfuscator-added type tokens (marker types like ConfusedByAttribute).
    pub obfuscator_type_tokens: boxcar::Vec<Token>,
    /// PE sections containing encrypted/artifact data.
    pub artifact_sections: boxcar::Vec<String>,
}

impl ConfuserExFindings {
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

    /// Returns true if native x86 method conversion is needed.
    #[must_use]
    pub fn needs_native_conversion(&self) -> bool {
        !self.native_helpers.is_empty()
    }
}

impl ObfuscatorFindingsProvider for ConfuserExFindings {
    fn removable_type_tokens(&self) -> Vec<Token> {
        self.obfuscator_type_tokens
            .iter()
            .map(|(_, t)| *t)
            .collect()
    }

    fn has_invalid_metadata(&self) -> bool {
        self.obfuscator_marker_value.is_some()
    }

    fn has_enc_tables(&self) -> bool {
        self.enc_tables.count() > 0
    }
}

impl fmt::Display for ConfuserExFindings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut printed = false;

        let native_count = self.native_helpers.count();
        if native_count > 0 {
            writeln!(f, "    Native helpers:    {} methods", native_count)?;
            printed = true;
        }
        if self.encrypted_method_count > 0 {
            writeln!(
                f,
                "    Encrypted bodies:  {} methods",
                self.encrypted_method_count
            )?;
            printed = true;
        }
        if self.uses_cfg_mode() {
            let method_count = self
                .statemachine_provider
                .as_ref()
                .map_or(0, |p| p.methods().len());
            writeln!(f, "    CFG mode:          {} methods", method_count)?;
            printed = true;
        }
        if let Some(marker) = self.obfuscator_marker_value {
            writeln!(f, "    Marker value:      0x{:08X}", marker)?;
            printed = true;
        }
        let enc_count = self.enc_tables.count();
        if enc_count > 0 {
            writeln!(f, "    ENC tables:        {} tables", enc_count)?;
            printed = true;
        }
        let section_count = self.artifact_sections.count();
        if section_count > 0 {
            writeln!(f, "    Artifact sections: {}", section_count)?;
            printed = true;
        }

        if !printed {
            writeln!(f, "    (no ConfuserEx-specific protections detected)")?;
        }

        Ok(())
    }
}
