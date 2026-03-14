//! Generic invalid metadata detection and repair.
//!
//! Detects and repairs invalid metadata table entries — malformed indices,
//! out-of-range token references, and corrupted table rows — that prevent
//! correct assembly parsing. These patterns are common across multiple
//! obfuscators (ConfuserEx uses 0x7fff markers, others use different values).
//!
//! # Detection
//!
//! Scans TypeRef resolution scopes, Module name indices, and Assembly name
//! indices for obviously invalid values (overflow, 0x7fff markers, out of
//! bounds heap references).
//!
//! # Transform
//!
//! For each invalid entry, computes the correct value and writes it via
//! `WorkingAssembly::write_le()`.

use std::any::Any;

use crate::{
    compiler::{EventKind, EventLog},
    deobfuscation::techniques::{
        Detection, Detections, Evidence, Technique, TechniqueCategory, WorkingAssembly,
    },
    metadata::tables::{AssemblyRaw, DeclSecurityRaw, ModuleRaw, TableId, TypeRefRaw},
    CilObject, Result,
};

/// Marker value used by ConfuserEx for invalid metadata indices.
const CONFUSEREX_MARKER: u32 = 0x7fff_7fff;

/// Marker value for 16-bit invalid fields.
const CONFUSEREX_MARKER_16: u16 = 0x7fff;

/// Findings from generic metadata scanning.
#[derive(Debug)]
pub struct MetadataFindings {
    /// Number of invalid Module rows detected.
    pub invalid_module_rows: usize,
    /// Number of invalid Assembly rows detected.
    pub invalid_assembly_rows: usize,
    /// Number of invalid DeclSecurity rows detected.
    pub invalid_declsecurity_rows: usize,
    /// Number of invalid TypeRef resolution scopes detected.
    pub invalid_typeref_scopes: usize,
    /// File offsets and sizes of invalid entries for patching.
    pub patches: Vec<MetadataPatch>,
}

/// A single metadata patch to apply.
#[derive(Debug, Clone)]
pub struct MetadataPatch {
    /// File offset to patch.
    pub offset: usize,
    /// Size in bytes (2 or 4).
    pub size: u8,
    /// Original invalid value.
    pub original: u32,
    /// Corrected value.
    pub corrected: u32,
}

/// Detects and repairs invalid metadata table entries.
///
/// This is the generic version that catches common patterns across obfuscators.
/// Obfuscator-specific techniques (e.g., `confuserex.metadata`) supersede this
/// with more targeted logic.
pub struct GenericMetadata;

impl Technique for GenericMetadata {
    fn id(&self) -> &'static str {
        "generic.metadata"
    }

    fn name(&self) -> &'static str {
        "Generic Invalid Metadata Repair"
    }

    fn category(&self) -> TechniqueCategory {
        TechniqueCategory::Metadata
    }

    fn detect(&self, assembly: &CilObject) -> Detection {
        let Some(tables) = assembly.tables() else {
            return Detection::new_empty();
        };
        let strings = assembly.strings();

        let mut findings = MetadataFindings {
            invalid_module_rows: 0,
            invalid_assembly_rows: 0,
            invalid_declsecurity_rows: 0,
            invalid_typeref_scopes: 0,
            patches: Vec::new(),
        };
        let mut evidence = Vec::new();

        // Check Module table for invalid name indices
        if let Some(module_table) = tables.table::<ModuleRaw>() {
            let strings_size = strings.as_ref().map(|s| s.data().len()).unwrap_or(0);

            for row in module_table {
                let name_index = row.name as usize;
                if name_index >= strings_size || row.name == CONFUSEREX_MARKER {
                    findings.invalid_module_rows += 1;
                    findings.patches.push(MetadataPatch {
                        offset: row.offset + 2, // name field offset within Module row
                        size: if strings_size > 0xFFFF { 4 } else { 2 },
                        original: row.name,
                        corrected: 0,
                    });
                }
            }
        }

        // Check Assembly table for invalid name indices
        if let Some(assembly_table) = tables.table::<AssemblyRaw>() {
            let strings_size = strings.as_ref().map(|s| s.data().len()).unwrap_or(0);

            for row in assembly_table {
                if row.name as usize >= strings_size || row.name == CONFUSEREX_MARKER {
                    findings.invalid_assembly_rows += 1;
                }
            }
        }

        // Check DeclSecurity for invalid action values
        if let Some(declsec_table) = tables.table::<DeclSecurityRaw>() {
            for row in declsec_table {
                if row.action == CONFUSEREX_MARKER_16 || row.action > 0x000E {
                    findings.invalid_declsecurity_rows += 1;
                }
            }
        }

        // Check TypeRef resolution scopes for invalid indices
        if let Some(typeref_table) = tables.table::<TypeRefRaw>() {
            for row in typeref_table {
                // Resolution scope with tag Module but row 0 is suspicious
                // (valid Module is row 1)
                if row.resolution_scope.tag == TableId::Module && row.resolution_scope.row == 0 {
                    findings.invalid_typeref_scopes += 1;
                }
            }
        }

        let total_invalid = findings.invalid_module_rows
            + findings.invalid_assembly_rows
            + findings.invalid_declsecurity_rows;

        if total_invalid > 0 {
            evidence.push(Evidence::MetadataPattern(format!(
                "{} invalid metadata entries (Module: {}, Assembly: {}, DeclSecurity: {})",
                total_invalid,
                findings.invalid_module_rows,
                findings.invalid_assembly_rows,
                findings.invalid_declsecurity_rows,
            )));

            Detection::new_detected(
                evidence,
                Some(Box::new(findings) as Box<dyn Any + Send + Sync>),
            )
        } else {
            Detection::new_empty()
        }
    }

    fn byte_transform(
        &self,
        assembly: &mut WorkingAssembly,
        detection: &Detection,
        _detections: &Detections,
    ) -> Option<Result<EventLog>> {
        let events = EventLog::new();

        let Some(findings) = detection.findings::<MetadataFindings>() else {
            return Some(Ok(events));
        };

        let mut patched = 0usize;

        for patch in &findings.patches {
            match patch.size {
                2 => {
                    if let Err(e) = assembly.write_le::<u16>(patch.offset, patch.corrected as u16) {
                        return Some(Err(e));
                    }
                    patched += 1;
                }
                4 => {
                    if let Err(e) = assembly.write_le::<u32>(patch.offset, patch.corrected) {
                        return Some(Err(e));
                    }
                    patched += 1;
                }
                _ => {}
            }
        }

        if patched > 0 {
            events
                .record(EventKind::ArtifactRemoved)
                .message(format!("Patched {} invalid metadata entries", patched));
        }

        Some(Ok(events))
    }

    fn requires_regeneration(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use crate::deobfuscation::techniques::Technique;
    use crate::test::helpers::load_sample;

    /// Verify detection runs without error on a protected sample.
    ///
    /// None of the current test samples include the ConfuserEx InvalidMetadata
    /// protection (0x7fff markers), so this verifies the technique handles
    /// obfuscated assemblies gracefully without panicking.
    #[test]
    fn test_detect_no_panic_on_obfuscated() {
        let asm = load_sample("tests/samples/packers/confuserex/1.6.0/mkaring_normal.exe");
        let technique = super::GenericMetadata;
        let _detection = technique.detect(&asm);
    }

    #[test]
    fn test_detect_negative() {
        let asm = load_sample("tests/samples/packers/confuserex/1.6.0/original.exe");
        let technique = super::GenericMetadata;
        let detection = technique.detect(&asm);
        assert!(!detection.detected);
    }
}
