//! BitMono-specific detection findings.

use std::fmt;

use crate::{deobfuscation::findings::ObfuscatorFindingsProvider, metadata::token::Token};

/// BitMono-specific detection findings.
#[derive(Debug, Clone, Default)]
pub struct BitMonoFindings {
    /// Number of CallToCalli conversion sites detected.
    pub calltocalli_count: usize,
    /// Number of DotNetHook redirect stub pairs detected.
    pub dotnethook_count: usize,
    /// Token of the RedirectStub method identified during detection.
    pub dotnethook_redirect_stub: Option<Token>,
    /// Number of methods with BitMethodDotnet junk prefix detected.
    pub junk_prefix_count: usize,
    /// Number of fake native string methods detected.
    pub unmanaged_string_count: usize,
    /// Mapping from fake native method tokens to their decrypted string values.
    pub unmanaged_string_map: boxcar::Vec<(Token, String)>,
    /// Method tokens for BillionNops dead methods in `<Module>`.
    pub billion_nops_methods: boxcar::Vec<Token>,
    /// Type tokens with AntiDecompiler invalid attributes.
    pub anti_decompiler_types: boxcar::Vec<Token>,
    /// Method tokens with malformed exception handlers (AntiDecompiler).
    pub malformed_eh_methods: boxcar::Vec<Token>,
}

impl BitMonoFindings {
    /// Returns true if CallToCalli reversal is needed.
    #[must_use]
    pub fn needs_calltocalli_reversal(&self) -> bool {
        self.calltocalli_count > 0
    }

    /// Returns true if DotNetHook reversal is needed.
    #[must_use]
    pub fn needs_dotnethook_reversal(&self) -> bool {
        self.dotnethook_count > 0
    }

    /// Returns true if BitMethodDotnet junk prefix removal is needed.
    #[must_use]
    pub fn needs_junk_prefix_removal(&self) -> bool {
        self.junk_prefix_count > 0
    }

    /// Returns true if UnmanagedString reversal is needed.
    #[must_use]
    pub fn needs_unmanaged_string_reversal(&self) -> bool {
        self.unmanaged_string_count > 0
    }

    /// Returns true if BillionNops dead method removal is needed.
    #[must_use]
    pub fn needs_billion_nops_removal(&self) -> bool {
        self.billion_nops_methods.count() > 0
    }

    /// Returns true if AntiDecompiler attribute fix is needed.
    #[must_use]
    pub fn needs_anti_decompiler_fix(&self) -> bool {
        self.anti_decompiler_types.count() > 0
    }

    /// Returns true if malformed exception handler cleanup is needed.
    #[must_use]
    pub fn needs_malformed_eh_cleanup(&self) -> bool {
        self.malformed_eh_methods.count() > 0
    }
}

impl ObfuscatorFindingsProvider for BitMonoFindings {
    fn has_protections(&self) -> bool {
        self.calltocalli_count > 0
            || self.dotnethook_count > 0
            || self.junk_prefix_count > 0
            || self.unmanaged_string_count > 0
            || self.billion_nops_methods.count() > 0
            || self.anti_decompiler_types.count() > 0
            || self.malformed_eh_methods.count() > 0
    }
}

impl fmt::Display for BitMonoFindings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut printed = false;

        if self.calltocalli_count > 0 {
            writeln!(f, "    CallToCalli:       {} sites", self.calltocalli_count)?;
            printed = true;
        }
        if self.dotnethook_count > 0 {
            writeln!(
                f,
                "    DotNetHook:        {} redirect stubs",
                self.dotnethook_count
            )?;
            printed = true;
        }
        if self.junk_prefix_count > 0 {
            writeln!(
                f,
                "    Junk prefix:       {} methods",
                self.junk_prefix_count
            )?;
            printed = true;
        }
        if self.unmanaged_string_count > 0 {
            writeln!(
                f,
                "    UnmanagedString:   {} methods",
                self.unmanaged_string_count
            )?;
            printed = true;
        }
        let billion_nops = self.billion_nops_methods.count();
        if billion_nops > 0 {
            writeln!(f, "    BillionNops:       {} methods", billion_nops)?;
            printed = true;
        }
        let anti_decompiler = self.anti_decompiler_types.count();
        if anti_decompiler > 0 {
            writeln!(f, "    AntiDecompiler:    {} types", anti_decompiler)?;
            printed = true;
        }
        let malformed_eh = self.malformed_eh_methods.count();
        if malformed_eh > 0 {
            writeln!(f, "    Malformed EH:      {} methods", malformed_eh)?;
            printed = true;
        }

        if !printed {
            writeln!(f, "    (no BitMono-specific protections detected)")?;
        }

        Ok(())
    }
}
