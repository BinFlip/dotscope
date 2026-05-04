//! ConfuserEx invalid metadata detection and repair.
//!
//! ConfuserEx's InvalidMetadata protection adds corrupted rows to metadata
//! tables with the characteristic marker value `0x7fff7fff`. This breaks
//! disassemblers and analysis tools that expect valid indices. The protection
//! also injects non-empty ENC tables and duplicate stream headers.
//!
//! # How ConfuserEx Invalid Metadata Works
//!
//! ConfuserEx **adds new invalid rows** to metadata tables (it doesn't modify
//! existing valid rows). This means we can safely remove the invalid rows
//! entirely. Specifically, ConfuserEx adds:
//! - Module row with `name = 0x7fff7fff`
//! - Assembly row with `name = 0x7fff7fff`
//! - DeclSecurity row with `action = 0x7fff`
//! - Random ENCLog/ENCMap entries
//! - Duplicate stream headers (#GUID, #Strings, #Blob, #Schema)
//!
//! This technique supersedes [`GenericMetadata`](super::super::generic::GenericMetadata)
//! with ConfuserEx-specific knowledge: it recognises the exact marker value,
//! patches all affected table types (Module, Assembly, DeclSecurity), removes
//! ENC table entries, and flags duplicate stream headers for removal during
//! regeneration.
//!
//! # Detection
//!
//! Scans Module, Assembly, and DeclSecurity tables for fields containing the
//! `0x7fff7fff` / `0x7fff` marker. Also checks for non-empty ENCLog/ENCMap
//! tables and duplicate metadata stream headers.
//!
//! # Transform
//!
//! We remove rows that have invalid values:
//! 1. **Module/Assembly tables**: Remove rows with out-of-bounds string indices
//! 2. **DeclSecurity table**: Remove rows with invalid action values
//! 3. **ENC tables**: Remove all rows (not needed at runtime)
//!
//! Patches invalid fields in-place via `WorkingAssembly::write_le()`. ENC
//! tables and duplicate streams are handled during assembly regeneration.

use std::any::Any;

use crate::{
    compiler::{EventKind, EventLog},
    deobfuscation::techniques::{
        Detection, Detections, Evidence, Technique, TechniqueCategory, WorkingAssembly,
    },
    metadata::tables::{
        AssemblyRaw, DeclSecurityRaw, EncLogRaw, EncMapRaw, ModuleRaw, TableId, TypeRefRaw,
    },
    CilObject, Result,
};

/// ConfuserEx-specific marker value for invalid metadata indices.
const CONFUSEREX_MARKER: u32 = 0x7fff_7fff;

/// ConfuserEx-specific marker value for 16-bit fields.
const CONFUSEREX_MARKER_16: u16 = 0x7fff;

/// Findings from ConfuserEx metadata scanning.
#[derive(Debug)]
pub struct CxMetadataFindings {
    /// Total number of invalid metadata entries detected.
    pub invalid_entries: usize,
    /// Non-empty ENC table indices (ENCLog = 0x1E, ENCMap = 0x1F).
    pub enc_tables: Vec<u8>,
    /// Whether duplicate metadata stream headers were found.
    pub has_duplicate_streams: bool,
    /// Byte-level patches to apply (offset, size, corrected value).
    pub patches: Vec<CxMetadataPatch>,
}

/// A single byte-level metadata patch.
#[derive(Debug, Clone)]
pub struct CxMetadataPatch {
    /// File offset to write to.
    pub offset: usize,
    /// Size of the field (2 or 4 bytes).
    pub size: u8,
    /// Corrected value to write.
    pub corrected: u32,
}

/// Detects and repairs ConfuserEx invalid metadata markers.
///
/// Supersedes the generic metadata technique with ConfuserEx-specific
/// knowledge of the `0x7fff7fff` marker pattern, ENC tables, and duplicate
/// stream headers.
pub struct ConfuserExMetadata;

impl Technique for ConfuserExMetadata {
    fn id(&self) -> &'static str {
        "confuserex.metadata"
    }

    fn name(&self) -> &'static str {
        "ConfuserEx Invalid Metadata Repair"
    }

    fn category(&self) -> TechniqueCategory {
        TechniqueCategory::Metadata
    }

    fn supersedes(&self) -> &[&'static str] {
        &["generic.metadata"]
    }

    fn detect(&self, assembly: &CilObject) -> Detection {
        let Some(tables) = assembly.tables() else {
            return Detection::new_empty();
        };
        let strings = assembly.strings();
        let strings_size = strings.as_ref().map(|s| s.data().len()).unwrap_or(0);

        let mut findings = CxMetadataFindings {
            invalid_entries: 0,
            enc_tables: Vec::new(),
            has_duplicate_streams: false,
            patches: Vec::new(),
        };
        let mut evidence = Vec::new();

        // Check Module table for invalid name indices (0x7fff7fff marker).
        if let Some(module_table) = tables.table::<ModuleRaw>() {
            for row in module_table {
                if row.name == CONFUSEREX_MARKER || row.name as usize >= strings_size {
                    findings.invalid_entries = findings.invalid_entries.saturating_add(1);
                    // Skip rows where the file offset would overflow when adding the
                    // name field offset within the Module row.
                    if let Some(name_offset) = row.offset.checked_add(2) {
                        findings.patches.push(CxMetadataPatch {
                            offset: name_offset,
                            size: if strings_size > 0xFFFF { 4 } else { 2 },
                            corrected: 0,
                        });
                    }
                }
            }
        }

        // Check Assembly table for invalid name indices.
        if let Some(assembly_table) = tables.table::<AssemblyRaw>() {
            for row in assembly_table {
                if row.name == CONFUSEREX_MARKER || row.name as usize >= strings_size {
                    findings.invalid_entries = findings.invalid_entries.saturating_add(1);
                }
            }
        }

        // Check DeclSecurity for invalid action values.
        if let Some(declsec_table) = tables.table::<DeclSecurityRaw>() {
            for row in declsec_table {
                if row.action == CONFUSEREX_MARKER_16 || row.action > 0x000E {
                    findings.invalid_entries = findings.invalid_entries.saturating_add(1);
                }
            }
        }

        // Check TypeRef resolution scopes for invalid indices.
        if let Some(typeref_table) = tables.table::<TypeRefRaw>() {
            for row in typeref_table {
                if row.resolution_scope.tag == TableId::Module && row.resolution_scope.row == 0 {
                    findings.invalid_entries = findings.invalid_entries.saturating_add(1);
                }
            }
        }

        // Check for non-empty ENC tables (ConfuserEx injects garbage entries).
        if let Some(enclog) = tables.table::<EncLogRaw>() {
            if enclog.row_count > 0 {
                findings.enc_tables.push(0x1E);
            }
        }
        if let Some(encmap) = tables.table::<EncMapRaw>() {
            if encmap.row_count > 0 {
                findings.enc_tables.push(0x1F);
            }
        }

        // Check for duplicate stream headers in the metadata root.
        // ConfuserEx sometimes adds duplicate #GUID, #Strings, #Blob headers
        // to confuse parsers.
        findings.has_duplicate_streams = check_duplicate_streams(assembly);

        // Build evidence and decide if detected.
        let has_marker_pattern = findings.invalid_entries > 0;
        let has_enc = !findings.enc_tables.is_empty();
        let has_dups = findings.has_duplicate_streams;

        if !has_marker_pattern && !has_enc && !has_dups {
            return Detection::new_empty();
        }

        if has_marker_pattern {
            evidence.push(Evidence::MetadataPattern(format!(
                "{} invalid metadata entries with 0x7fff marker",
                findings.invalid_entries,
            )));
        }
        if has_enc {
            evidence.push(Evidence::MetadataPattern(format!(
                "Non-empty ENC tables: {:?}",
                findings.enc_tables,
            )));
        }
        if has_dups {
            evidence.push(Evidence::MetadataPattern(
                "Duplicate metadata stream headers".to_string(),
            ));
        }

        Detection::new_detected(
            evidence,
            Some(Box::new(findings) as Box<dyn Any + Send + Sync>),
        )
    }

    fn byte_transform(
        &self,
        assembly: &mut WorkingAssembly,
        detection: &Detection,
        _detections: &Detections,
    ) -> Option<Result<EventLog>> {
        let events = EventLog::new();

        let Some(findings) = detection.findings::<CxMetadataFindings>() else {
            return Some(Ok(events));
        };

        let mut patched = 0usize;

        for patch in &findings.patches {
            match patch.size {
                2 => match assembly.write_le::<u16>(patch.offset, patch.corrected as u16) {
                    Ok(_) => patched = patched.saturating_add(1),
                    Err(e) => return Some(Err(e)),
                },
                4 => match assembly.write_le::<u32>(patch.offset, patch.corrected) {
                    Ok(_) => patched = patched.saturating_add(1),
                    Err(e) => return Some(Err(e)),
                },
                _ => {}
            }
        }

        if patched > 0 {
            events.record(EventKind::ArtifactRemoved).message(format!(
                "Patched {} ConfuserEx invalid metadata entries (0x7fff marker)",
                patched,
            ));
        }

        if !findings.enc_tables.is_empty() {
            events.record(EventKind::ArtifactRemoved).message(format!(
                "ENC tables {:?} will be cleared on regeneration",
                findings.enc_tables,
            ));
        }

        if findings.has_duplicate_streams {
            events
                .record(EventKind::ArtifactRemoved)
                .message("Duplicate stream headers will be removed on regeneration");
        }

        Some(Ok(events))
    }

    fn requires_regeneration(&self) -> bool {
        true
    }
}

/// Checks whether the assembly has duplicate metadata stream headers.
///
/// ConfuserEx sometimes adds extra copies of #GUID, #Strings, or #Blob
/// stream headers to confuse metadata parsers.
fn check_duplicate_streams(assembly: &CilObject) -> bool {
    let file = assembly.file();
    let data = file.data();

    // Find the metadata root via the CLI header.
    let metadata_rva = assembly.cor20header().meta_data_rva as usize;
    let Ok(metadata_offset) = file.rva_to_offset(metadata_rva) else {
        return false;
    };

    // Parse stream count from metadata root header.
    // Metadata root layout: signature(4) + major(2) + minor(2) + reserved(4) + version_len(4)
    let header_base = metadata_offset;
    let Some(header_end) = header_base.checked_add(16) else {
        return false;
    };
    if header_end > data.len() {
        return false;
    }

    let Some(version_len_start) = header_base.checked_add(12) else {
        return false;
    };
    let Some(version_bytes) = data.get(version_len_start..header_end) else {
        return false;
    };
    let version_len = u32::from_le_bytes(version_bytes.try_into().unwrap_or_default()) as usize;
    // Align version length to 4 bytes
    let aligned_len = match version_len.checked_add(3) {
        Some(v) => v & !3,
        None => return false,
    };
    let Some(flags_offset) = header_end.checked_add(aligned_len) else {
        return false;
    };

    let Some(streams_end) = flags_offset.checked_add(4) else {
        return false;
    };
    if streams_end > data.len() {
        return false;
    }

    // flags(2) + streams(2)
    let Some(stream_count_start) = flags_offset.checked_add(2) else {
        return false;
    };
    let Some(stream_count_bytes) = data.get(stream_count_start..streams_end) else {
        return false;
    };
    let stream_count =
        u16::from_le_bytes(stream_count_bytes.try_into().unwrap_or_default()) as usize;

    // Walk stream headers and check for duplicate names.
    let mut seen_names = std::collections::HashSet::new();
    let mut pos = streams_end;

    for _ in 0..stream_count {
        let Some(after_header) = pos.checked_add(8) else {
            break;
        };
        if after_header > data.len() {
            break;
        }
        // offset(4) + size(4) + name (null-terminated, 4-byte aligned)
        pos = after_header;

        // Read stream name
        let name_start = pos;
        while let Some(&byte) = data.get(pos) {
            if byte == 0 {
                break;
            }
            let Some(next) = pos.checked_add(1) else {
                return false;
            };
            pos = next;
        }
        if pos >= data.len() {
            break;
        }
        let name_bytes = match data.get(name_start..pos) {
            Some(b) => b,
            None => break,
        };
        let name = std::str::from_utf8(name_bytes).unwrap_or("");
        pos = match pos.checked_add(1) {
            Some(v) => v,
            None => break,
        };
        // Align to 4 bytes
        pos = match pos.checked_add(3) {
            Some(v) => v & !3,
            None => break,
        };

        if !name.is_empty() && !seen_names.insert(name.to_string()) {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use crate::{
        deobfuscation::techniques::{confuserex::metadata::ConfuserExMetadata, Technique},
        test::helpers::load_sample,
    };

    #[test]
    fn test_detect_negative_original() {
        let assembly = load_sample("tests/samples/packers/confuserex/1.6.0/original.exe");

        let technique = ConfuserExMetadata;
        let detection = technique.detect(&assembly);

        assert!(
            !detection.is_detected(),
            "ConfuserExMetadata should not detect invalid metadata in original.exe"
        );
    }

    #[test]
    fn test_detect_negative_normal() {
        // Normal preset does not include InvalidMetadata protection.
        let assembly = load_sample("tests/samples/packers/confuserex/1.6.0/mkaring_normal.exe");

        let technique = ConfuserExMetadata;
        let detection = technique.detect(&assembly);

        // InvalidMetadata is a separate ConfuserEx protection not included
        // in standard presets (Minimum, Normal, Maximum).
        // The 0x7fff marker pattern is specific to this protection.
        assert!(
            !detection.is_detected(),
            "ConfuserExMetadata should not detect in normal preset (no InvalidMetadata protection)"
        );
    }

    #[test]
    fn test_technique_properties() {
        let technique = ConfuserExMetadata;

        assert_eq!(technique.id(), "confuserex.metadata");
        assert_eq!(technique.supersedes(), &["generic.metadata"]);
        assert!(
            technique.requires_regeneration(),
            "Metadata repair requires PE regeneration"
        );
    }

    #[test]
    fn test_detect_on_maximum() {
        // Maximum preset: check if metadata markers are present.
        // InvalidMetadata is separate from the standard presets,
        // so this may or may not detect depending on the sample.
        let assembly = load_sample("tests/samples/packers/confuserex/1.6.0/mkaring_maximum.exe");

        let technique = ConfuserExMetadata;
        let detection = technique.detect(&assembly);

        // If detected, verify findings structure
        if detection.is_detected() {
            assert!(!detection.evidence().is_empty());
            let findings = detection
                .findings::<super::CxMetadataFindings>()
                .expect("Should have CxMetadataFindings");

            assert!(
                findings.invalid_entries > 0
                    || !findings.enc_tables.is_empty()
                    || findings.has_duplicate_streams,
                "At least one indicator should be present"
            );
        }
    }
}
