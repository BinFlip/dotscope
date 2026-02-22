//! Obfuscar-specific detection findings.

use crate::deobfuscation::findings::ObfuscatorFindingsProvider;

/// Obfuscar-specific detection findings (empty — Obfuscar only uses shared fields).
#[derive(Debug, Clone, Default)]
pub struct ObfuscarFindings;

impl ObfuscatorFindingsProvider for ObfuscarFindings {}
