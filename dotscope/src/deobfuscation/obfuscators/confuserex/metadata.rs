//! ConfuserEx invalid metadata removal.
//!
//! ConfuserEx adds invalid metadata rows to break disassemblers and analysis tools.
//! This module removes those invalid rows.
//!
//! # How ConfuserEx Invalid Metadata Works
//!
//! ConfuserEx **adds new invalid rows** to metadata tables (it doesn't modify existing
//! valid rows). This means we can safely remove the invalid rows entirely.
//!
//! Specifically, ConfuserEx adds:
//! - Module row with `name = 0x7fff7fff`
//! - Assembly row with `name = 0x7fff7fff`
//! - DeclSecurity row with `action = 0x7fff`
//! - Random ENCLog/ENCMap entries
//! - Duplicate stream headers (#GUID, #Strings, #Blob, #Schema)
//!
//! # Fix Strategy
//!
//! We remove rows that have invalid values:
//!
//! 1. **Module/Assembly tables**: Remove rows with out-of-bounds string indices
//! 2. **DeclSecurity table**: Remove rows with invalid action values
//! 3. **ENC tables**: Remove all rows (not needed at runtime)

use crate::{
    cilassembly::{CilAssembly, GeneratorConfig},
    deobfuscation::{
        detection::{DetectionEvidence, DetectionScore},
        findings::DeobfuscationFindings,
    },
    metadata::{
        cilassemblyview::CilAssemblyView,
        tables::{
            AssemblyRaw, CustomAttributeRaw, DeclSecurityRaw, EncLogRaw, EncMapRaw, MemberRefRaw,
            MethodDefRaw, ModuleRaw, TableId, TypeDefRaw, TypeRefRaw,
        },
        token::Token,
    },
    CilObject, Error, Result, ValidationConfig,
};

/// ConfuserEx-specific marker value for invalid metadata.
const CONFUSEREX_MARKER: u32 = 0x7fff_7fff;

/// ConfuserEx-specific marker value for 16-bit fields.
const CONFUSEREX_MARKER_SHORT: u16 = 0x7fff;

/// Detects invalid metadata patterns and populates findings.
///
/// This is called by the orchestrator in detection.rs to detect
/// ConfuserEx metadata protection including:
/// - Invalid metadata markers (0x7fff7fff)
/// - Out-of-bounds metadata indices
/// - ENC tables (unusual for release builds)
/// - SuppressIldasmAttribute
/// - ConfuserEx marker attributes (ConfuserVersion, ConfusedByAttribute)
pub fn detect(assembly: &CilObject, score: &DetectionScore, findings: &mut DeobfuscationFindings) {
    // Check for invalid metadata patterns
    check_invalid_metadata(assembly, score, findings);

    // Check for SuppressIldasmAttribute
    check_suppress_ildasm(assembly, score, findings);

    // Check for ConfuserEx marker attributes
    check_confuser_attributes(assembly, score, findings);
}

/// Checks for invalid metadata patterns used by ConfuserEx.
fn check_invalid_metadata(
    assembly: &CilObject,
    score: &DetectionScore,
    findings: &mut DeobfuscationFindings,
) {
    let Some(tables) = assembly.tables() else {
        return;
    };

    let mut marker_count = 0usize;
    let mut oob_count = 0usize;

    // Get heap size for bounds checking
    let string_heap_size = assembly.strings().map_or(0, |s| s.data().len());

    // Check Module table - string heap index
    if let Some(module_table) = tables.table::<ModuleRaw>() {
        for module in module_table {
            if module.name == CONFUSEREX_MARKER {
                marker_count += 1;
            } else if module.name as usize >= string_heap_size {
                oob_count += 1;
            }
        }
    }

    // Check Assembly table - string heap index
    if let Some(assembly_table) = tables.table::<AssemblyRaw>() {
        for asm in assembly_table {
            if asm.name == CONFUSEREX_MARKER {
                marker_count += 1;
            } else if asm.name as usize >= string_heap_size {
                oob_count += 1;
            }
        }
    }

    // Check TypeRef table - coded index row bounds
    if let Some(typeref_table) = tables.table::<TypeRefRaw>() {
        let max_valid_row = typeref_table
            .row_count
            .max(tables.table::<ModuleRaw>().map_or(0, |t| t.row_count))
            .max(tables.table::<AssemblyRaw>().map_or(0, |t| t.row_count));

        for typeref in typeref_table {
            if typeref.resolution_scope.row == CONFUSEREX_MARKER {
                marker_count += 1;
            } else if typeref.resolution_scope.row > 0
                && typeref.resolution_scope.row > max_valid_row * 2
            {
                oob_count += 1;
            }
        }
    }

    // Check MemberRef table - coded index row bounds
    if let Some(memberref_table) = tables.table::<MemberRefRaw>() {
        let max_valid_row = tables
            .table::<TypeRefRaw>()
            .map_or(0, |t| t.row_count)
            .max(tables.table::<TypeDefRaw>().map_or(0, |t| t.row_count));

        for memberref in memberref_table {
            if memberref.class.row == CONFUSEREX_MARKER {
                marker_count += 1;
            } else if memberref.class.row > 0 && memberref.class.row > max_valid_row * 2 {
                oob_count += 1;
            }
        }
    }

    // Check CustomAttribute table - coded index row bounds
    if let Some(custom_attr_table) = tables.table::<CustomAttributeRaw>() {
        // Sum row counts from all present tables for a generous upper bound
        let total_rows: u32 = tables
            .present_tables()
            .map(|t| tables.table_row_count(t))
            .sum();

        for attr in custom_attr_table {
            if attr.parent.row == CONFUSEREX_MARKER {
                marker_count += 1;
            } else if attr.parent.row > total_rows {
                oob_count += 1;
            }

            if attr.constructor.row == CONFUSEREX_MARKER {
                marker_count += 1;
            } else if attr.constructor.row > total_rows {
                oob_count += 1;
            }
        }
    }

    // Check DeclSecurity table - action field
    if let Some(declsecurity_table) = tables.table::<DeclSecurityRaw>() {
        for decl in declsecurity_table {
            if decl.action == CONFUSEREX_MARKER_SHORT {
                marker_count += 1;
            } else if decl.action >= 0x1000 {
                // Valid SecurityAction values are 0-15
                oob_count += 1;
            }
        }
    }

    // Check ENC tables
    let has_enc_tables = tables.table::<EncLogRaw>().is_some_and(|t| t.row_count > 0)
        || tables.table::<EncMapRaw>().is_some_and(|t| t.row_count > 0);

    // Store in findings
    if marker_count > 0 {
        findings.obfuscator_marker_value = Some(CONFUSEREX_MARKER);
    }
    if has_enc_tables {
        if tables.table::<EncLogRaw>().is_some_and(|t| t.row_count > 0) {
            findings.enc_tables.push(0x1E);
        }
        if tables.table::<EncMapRaw>().is_some_and(|t| t.row_count > 0) {
            findings.enc_tables.push(0x1F);
        }
    }

    // Add evidence for specific ConfuserEx marker (high confidence)
    if marker_count > 0 {
        score.add(DetectionEvidence::StructuralPattern {
            description: format!(
                "ConfuserEx marker (0x7fff7fff) found {marker_count} times in metadata"
            ),
            confidence: (marker_count * 15).min(40),
        });
    }

    // Add evidence for generic out-of-bounds (lower confidence, could be other obfuscators)
    if oob_count > 0 {
        score.add(DetectionEvidence::StructuralPattern {
            description: format!("Out-of-bounds metadata indices ({oob_count} entries)"),
            confidence: (oob_count * 5).min(20),
        });
    }

    if has_enc_tables {
        score.add(DetectionEvidence::StructuralPattern {
            description: "ENC tables present (unusual for release builds)".to_string(),
            confidence: 25,
        });
    }
}

/// Checks for SuppressIldasmAttribute on the module.
fn check_suppress_ildasm(
    assembly: &CilObject,
    score: &DetectionScore,
    findings: &mut DeobfuscationFindings,
) {
    let Some(tables) = assembly.tables() else {
        return;
    };
    let Some(strings) = assembly.strings() else {
        return;
    };
    let Some(custom_attr_table) = tables.table::<CustomAttributeRaw>() else {
        return;
    };
    let Some(memberref_table) = tables.table::<MemberRefRaw>() else {
        return;
    };
    let Some(typeref_table) = tables.table::<TypeRefRaw>() else {
        return;
    };

    for attr in custom_attr_table {
        // Check if this attribute is applied to the Module or Assembly
        let is_module_or_assembly_attr =
            attr.parent.tag == TableId::Module || attr.parent.tag == TableId::Assembly;

        if !is_module_or_assembly_attr {
            continue;
        }

        // Get the type name and namespace from the constructor's declaring type
        let (type_name, type_namespace) = match attr.constructor.tag {
            TableId::MemberRef => {
                if let Some(memberref) = memberref_table.get(attr.constructor.row) {
                    if memberref.class.tag == TableId::TypeRef {
                        if let Some(typeref) = typeref_table.get(memberref.class.row) {
                            let name = strings.get(typeref.type_name as usize).ok();
                            let namespace = strings.get(typeref.type_namespace as usize).ok();
                            (name, namespace)
                        } else {
                            (None, None)
                        }
                    } else {
                        (None, None)
                    }
                } else {
                    (None, None)
                }
            }
            _ => (None, None),
        };

        // Check for SuppressIldasmAttribute in System.Runtime.CompilerServices
        if let (Some(name), Some(namespace)) = (type_name, type_namespace) {
            if name == "SuppressIldasmAttribute" && namespace == "System.Runtime.CompilerServices" {
                findings.suppress_ildasm_token = Some(attr.token);

                score.add(DetectionEvidence::Attribute {
                    name: format!("{namespace}.{name}"),
                    confidence: 25, // Common protection, not ConfuserEx-specific
                });
                return;
            }
        }
    }
}

/// Checks for ConfuserEx-specific marker attributes.
fn check_confuser_attributes(
    assembly: &CilObject,
    score: &DetectionScore,
    findings: &mut DeobfuscationFindings,
) {
    let Some(tables) = assembly.tables() else {
        return;
    };
    let Some(strings) = assembly.strings() else {
        return;
    };
    let Some(custom_attr_table) = tables.table::<CustomAttributeRaw>() else {
        return;
    };
    let Some(methoddef_table) = tables.table::<MethodDefRaw>() else {
        return;
    };
    let Some(memberref_table) = tables.table::<MemberRefRaw>() else {
        return;
    };
    let Some(typedef_table) = tables.table::<TypeDefRaw>() else {
        return;
    };
    let Some(typeref_table) = tables.table::<TypeRefRaw>() else {
        return;
    };

    for attr in custom_attr_table {
        let constructor_idx = attr.constructor;
        // Track both the type name and the TypeDef token (if local)
        let (type_name, typedef_token): (Option<&str>, Option<Token>) = match constructor_idx.tag {
            TableId::MethodDef => {
                if let Some(method) = methoddef_table.get(constructor_idx.row) {
                    if let Some(typedef) = typedef_table.iter().find(|t| {
                        t.method_list <= method.rid
                            && typedef_table
                                .iter()
                                .find(|next| next.rid > t.rid)
                                .is_none_or(|next| method.rid < next.method_list)
                    }) {
                        (
                            strings.get(typedef.type_name as usize).ok(),
                            Some(typedef.token),
                        )
                    } else {
                        (None, None)
                    }
                } else {
                    (None, None)
                }
            }
            TableId::MemberRef => {
                if let Some(memberref) = memberref_table.get(constructor_idx.row) {
                    match memberref.class.tag {
                        TableId::TypeDef => {
                            if let Some(typedef) = typedef_table.get(memberref.class.row) {
                                (
                                    strings.get(typedef.type_name as usize).ok(),
                                    Some(typedef.token),
                                )
                            } else {
                                (None, None)
                            }
                        }
                        TableId::TypeRef => {
                            // TypeRef points to external assembly - no local TypeDef to remove
                            if let Some(typeref) = typeref_table.get(memberref.class.row) {
                                (strings.get(typeref.type_name as usize).ok(), None)
                            } else {
                                (None, None)
                            }
                        }
                        _ => (None, None),
                    }
                } else {
                    (None, None)
                }
            }
            _ => (None, None),
        };

        if let Some(name) = type_name {
            if name.contains("ConfuserVersion") || name.contains("ConfusedByAttribute") {
                // Store the token for later removal
                let attr_token = Token::new((TableId::CustomAttribute as u32) << 24 | attr.rid);
                findings.marker_attribute_tokens.push(attr_token);

                // Track the TypeDef if it's a local type (for removal)
                if let Some(token) = typedef_token {
                    // Avoid duplicates - only add if not already tracked
                    if !findings
                        .obfuscator_type_tokens
                        .iter()
                        .any(|(_, t)| *t == token)
                    {
                        findings.obfuscator_type_tokens.push(token);
                    }
                }

                if name.contains("ConfuserVersion") {
                    if let Some(blob) = assembly.blob() {
                        if let Ok(attr_data) = blob.get(attr.value as usize) {
                            findings.obfuscator_version = extract_version_from_blob(attr_data);
                        }
                    }
                }

                score.add(DetectionEvidence::Attribute {
                    name: name.to_string(),
                    confidence: 50,
                });
                // Continue to find all marker attributes, don't return early
            }
        }
    }
}

/// Tries to extract a version string from an attribute blob.
fn extract_version_from_blob(data: &[u8]) -> Option<String> {
    if data.len() < 4 || data[0] != 0x01 || data[1] != 0x00 {
        return None;
    }

    let text = String::from_utf8_lossy(&data[2..]);
    for word in text.split(|c: char| !c.is_ascii_alphanumeric() && c != '.') {
        if word.contains('.') && word.chars().next().is_some_and(|c| c.is_ascii_digit()) {
            let version: String = word
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '.')
                .collect();
            if version.len() >= 3 {
                return Some(version);
            }
        }
    }

    None
}

/// Fixes invalid metadata in the assembly.
///
/// Iterates each table once, removing invalid rows as they're found.
/// The assembly is only rebuilt if changes were made.
///
/// # Arguments
///
/// * `assembly` - The assembly with invalid metadata.
///
/// # Returns
///
/// A new `CilObject` with fixed metadata, or the original if no fixes were needed.
pub fn fix_invalid_metadata(assembly: CilObject) -> Result<CilObject> {
    let bytes = assembly.file().data().to_vec();
    let view = CilAssemblyView::from_mem(bytes)?;
    let mut asm = view.to_owned();

    let mut total_removed = 0;
    total_removed += clean_module_table(&mut asm)?;
    total_removed += clean_assembly_table(&mut asm)?;
    total_removed += clean_declsecurity_table(&mut asm)?;
    total_removed += clean_enc_tables(&mut asm)?;

    if total_removed == 0 {
        return Ok(assembly);
    }

    asm.into_cilobject_with(ValidationConfig::analysis(), GeneratorConfig::default())
}

/// Removes invalid Module rows (invalid name index).
fn clean_module_table(asm: &mut CilAssembly) -> Result<usize> {
    let Some(tables) = asm.view().tables() else {
        return Ok(0);
    };
    let row_count = tables.table::<ModuleRaw>().map_or(0, |t| t.row_count);
    let string_heap_size = asm.view().strings().map_or(0, |s| s.data().len());

    let mut removed = 0;
    for rid in 1..=row_count {
        // Note: closure needed here — method reference with turbofish breaks downstream type inference
        #[allow(clippy::redundant_closure_for_method_calls)]
        let is_invalid = asm
            .view()
            .tables()
            .and_then(|t| t.table::<ModuleRaw>())
            .and_then(|t| t.get(rid))
            .is_some_and(|r| r.name == CONFUSEREX_MARKER || r.name as usize >= string_heap_size);

        if is_invalid {
            asm.table_row_remove(TableId::Module, rid)?;
            removed += 1;
        }
    }
    Ok(removed)
}

/// Removes invalid Assembly rows (invalid name index).
fn clean_assembly_table(asm: &mut CilAssembly) -> Result<usize> {
    let Some(tables) = asm.view().tables() else {
        return Ok(0);
    };
    let row_count = tables.table::<AssemblyRaw>().map_or(0, |t| t.row_count);
    let string_heap_size = asm.view().strings().map_or(0, |s| s.data().len());

    let mut removed = 0;
    for rid in 1..=row_count {
        // Note: closure needed here — method reference with turbofish breaks downstream type inference
        #[allow(clippy::redundant_closure_for_method_calls)]
        let is_invalid = asm
            .view()
            .tables()
            .and_then(|t| t.table::<AssemblyRaw>())
            .and_then(|t| t.get(rid))
            .is_some_and(|r| r.name == CONFUSEREX_MARKER || r.name as usize >= string_heap_size);

        if is_invalid {
            asm.table_row_remove(TableId::Assembly, rid)?;
            removed += 1;
        }
    }
    Ok(removed)
}

/// Removes invalid DeclSecurity rows (invalid action value).
fn clean_declsecurity_table(asm: &mut CilAssembly) -> Result<usize> {
    let Some(tables) = asm.view().tables() else {
        return Ok(0);
    };
    let row_count = tables.table::<DeclSecurityRaw>().map_or(0, |t| t.row_count);

    let mut removed = 0;
    for rid in 1..=row_count {
        // Note: closure needed here — method reference with turbofish breaks downstream type inference
        #[allow(clippy::redundant_closure_for_method_calls)]
        let is_invalid = asm
            .view()
            .tables()
            .and_then(|t| t.table::<DeclSecurityRaw>())
            .and_then(|t| t.get(rid))
            .is_some_and(|r| r.action == CONFUSEREX_MARKER_SHORT || r.action >= 0x1000);

        if is_invalid {
            asm.table_row_remove(TableId::DeclSecurity, rid)?;
            removed += 1;
        }
    }
    Ok(removed)
}

/// Removes all ENCLog and ENCMap rows (not needed at runtime).
fn clean_enc_tables(asm: &mut CilAssembly) -> Result<usize> {
    let Some(tables) = asm.view().tables() else {
        return Ok(0);
    };
    let enc_log_count = tables.table::<EncLogRaw>().map_or(0, |t| t.row_count);
    let enc_map_count = tables.table::<EncMapRaw>().map_or(0, |t| t.row_count);

    for rid in 1..=enc_log_count {
        asm.table_row_remove(TableId::EncLog, rid)?;
    }
    for rid in 1..=enc_map_count {
        asm.table_row_remove(TableId::EncMap, rid)?;
    }

    Ok((enc_log_count + enc_map_count) as usize)
}

/// Removes ConfuserEx marker attributes (ConfuserVersion, ConfusedByAttribute).
///
/// These attributes mark the assembly as having been obfuscated by ConfuserEx.
/// Removing them cleans up the assembly after deobfuscation.
///
/// # Arguments
///
/// * `assembly` - The assembly with ConfuserEx marker attributes.
/// * `tokens` - Iterator of CustomAttribute tokens to remove.
///
/// # Returns
///
/// A new `CilObject` with the marker attributes removed, or the original if none were provided.
///
/// # Errors
///
/// Returns an error if the assembly cannot be modified or reloaded.
pub fn remove_confuser_attributes(
    assembly: CilObject,
    tokens: impl IntoIterator<Item = Token>,
) -> Result<CilObject> {
    let tokens: Vec<Token> = tokens.into_iter().collect();
    if tokens.is_empty() {
        return Ok(assembly);
    }

    // Verify all tokens are CustomAttribute tokens
    for token in &tokens {
        if !token.is_table(TableId::CustomAttribute) {
            return Err(Error::InvalidToken {
                token: *token,
                message: "Token must be a CustomAttribute".to_string(),
            });
        }
    }

    // Get the raw bytes and create a view for modification
    let bytes = assembly.file().data().to_vec();
    let view = CilAssemblyView::from_mem(bytes)?;
    let mut asm = view.to_owned();

    // Remove all specified rows
    for token in &tokens {
        asm.table_row_remove(TableId::CustomAttribute, token.row())?;
    }

    asm.into_cilobject_with(ValidationConfig::analysis(), GeneratorConfig::default())
}

/// Removes the SuppressIldasmAttribute from an assembly.
///
/// ConfuserEx adds this attribute to prevent IL disassemblers from working.
/// The attribute value blob is often malformed to crash parsers.
///
/// # Arguments
///
/// * `assembly` - The assembly with SuppressIldasm attribute.
/// * `token` - The CustomAttribute token to remove.
///
/// # Returns
///
/// A new `CilObject` with the attribute removed.
///
/// # Errors
///
/// Returns an error if the assembly cannot be modified or reloaded.
pub fn remove_suppress_ildasm(assembly: &CilObject, token: Token) -> Result<CilObject> {
    // Verify the token is a CustomAttribute (table ID 0x0C)
    if !token.is_table(TableId::CustomAttribute) {
        return Err(Error::InvalidToken {
            token,
            message: "Token must be a CustomAttribute".to_string(),
        });
    }

    // Get the raw bytes and create a view for modification
    let bytes = assembly.file().data().to_vec();
    let view = CilAssemblyView::from_mem(bytes)?;
    let mut asm = view.to_owned();

    // Verify the row exists
    let row_exists = {
        let Some(tables) = asm.view().tables() else {
            return Err(Error::Malformed {
                message: "No metadata tables".to_string(),
                file: file!(),
                line: line!(),
            });
        };
        let Some(custom_attr_table) = tables.table::<CustomAttributeRaw>() else {
            return Err(Error::Malformed {
                message: "No CustomAttribute table".to_string(),
                file: file!(),
                line: line!(),
            });
        };
        custom_attr_table.get(token.row()).is_some()
    };

    if !row_exists {
        return Err(Error::InvalidRid {
            rid: token.row(),
            table: TableId::CustomAttribute,
        });
    }

    // Remove the row
    asm.table_row_remove(TableId::CustomAttribute, token.row())?;

    asm.into_cilobject_with(ValidationConfig::analysis(), GeneratorConfig::default())
}

#[cfg(test)]
mod tests {
    use crate::{
        deobfuscation::obfuscators::confuserex::{
            detection::detect_confuserex,
            metadata::{
                fix_invalid_metadata, remove_confuser_attributes, remove_suppress_ildasm,
                CONFUSEREX_MARKER, CONFUSEREX_MARKER_SHORT,
            },
        },
        metadata::{
            tables::{
                AssemblyRaw, CustomAttributeRaw, DeclSecurityRaw, EncLogRaw, EncMapRaw, ModuleRaw,
            },
            token::Token,
        },
        CilObject, Error, ValidationConfig,
    };

    /// Helper to count invalid Module rows (marker value or out-of-bounds name).
    fn count_invalid_module_rows(assembly: &CilObject) -> usize {
        let Some(tables) = assembly.tables() else {
            return 0;
        };
        let Some(module_table) = tables.table::<ModuleRaw>() else {
            return 0;
        };
        let string_heap_size = assembly.strings().map_or(0, |s| s.data().len());

        module_table
            .iter()
            .filter(|m| m.name == CONFUSEREX_MARKER || m.name as usize >= string_heap_size)
            .count()
    }

    /// Helper to count invalid Assembly rows (marker value or out-of-bounds name).
    fn count_invalid_assembly_rows(assembly: &CilObject) -> usize {
        let Some(tables) = assembly.tables() else {
            return 0;
        };
        let Some(assembly_table) = tables.table::<AssemblyRaw>() else {
            return 0;
        };
        let string_heap_size = assembly.strings().map_or(0, |s| s.data().len());

        assembly_table
            .iter()
            .filter(|a| a.name == CONFUSEREX_MARKER || a.name as usize >= string_heap_size)
            .count()
    }

    /// Helper to count invalid DeclSecurity rows (marker value or out-of-range action).
    fn count_invalid_declsecurity_rows(assembly: &CilObject) -> usize {
        let Some(tables) = assembly.tables() else {
            return 0;
        };
        let Some(declsecurity_table) = tables.table::<DeclSecurityRaw>() else {
            return 0;
        };

        declsecurity_table
            .iter()
            .filter(|d| d.action == CONFUSEREX_MARKER_SHORT || d.action >= 0x1000)
            .count()
    }

    /// Helper to count ENC table rows.
    fn count_enc_rows(assembly: &CilObject) -> (u32, u32) {
        let Some(tables) = assembly.tables() else {
            return (0, 0);
        };
        let enc_log = tables.table::<EncLogRaw>().map_or(0, |t| t.row_count);
        let enc_map = tables.table::<EncMapRaw>().map_or(0, |t| t.row_count);
        (enc_log, enc_map)
    }

    #[test]
    fn test_fix_invalid_metadata_passthrough() -> crate::Result<()> {
        // Original assembly should pass through unchanged (no fixes needed)
        let assembly = CilObject::from_path_with_validation(
            "tests/samples/packers/confuserex/original.exe",
            ValidationConfig::analysis(),
        )?;

        // Capture BEFORE state
        let before_module_count = assembly
            .tables()
            .and_then(|t| t.table::<ModuleRaw>())
            .map_or(0, |t| t.row_count);
        let before_assembly_count = assembly
            .tables()
            .and_then(|t| t.table::<AssemblyRaw>())
            .map_or(0, |t| t.row_count);
        let before_invalid_module = count_invalid_module_rows(&assembly);
        let before_invalid_assembly = count_invalid_assembly_rows(&assembly);
        let before_invalid_declsec = count_invalid_declsecurity_rows(&assembly);
        let (before_enc_log, before_enc_map) = count_enc_rows(&assembly);

        // Verify the original has NO invalid metadata (it's unobfuscated)
        assert_eq!(
            before_invalid_module, 0,
            "Original should have no invalid Module rows"
        );
        assert_eq!(
            before_invalid_assembly, 0,
            "Original should have no invalid Assembly rows"
        );
        assert_eq!(
            before_invalid_declsec, 0,
            "Original should have no invalid DeclSecurity rows"
        );
        assert_eq!(before_enc_log, 0, "Original should have no ENCLog rows");
        assert_eq!(before_enc_map, 0, "Original should have no ENCMap rows");

        // Apply fix
        let fixed = fix_invalid_metadata(assembly)?;

        // Capture AFTER state
        let after_module_count = fixed
            .tables()
            .and_then(|t| t.table::<ModuleRaw>())
            .map_or(0, |t| t.row_count);
        let after_assembly_count = fixed
            .tables()
            .and_then(|t| t.table::<AssemblyRaw>())
            .map_or(0, |t| t.row_count);

        // Verify row counts are unchanged (no rows removed because none were invalid)
        assert_eq!(
            after_module_count, before_module_count,
            "Module row count should be unchanged for clean assembly"
        );
        assert_eq!(
            after_assembly_count, before_assembly_count,
            "Assembly row count should be unchanged for clean assembly"
        );

        // Verify AFTER has no invalid rows
        assert_eq!(
            count_invalid_module_rows(&fixed),
            0,
            "Fixed assembly should have no invalid Module rows"
        );
        assert_eq!(
            count_invalid_assembly_rows(&fixed),
            0,
            "Fixed assembly should have no invalid Assembly rows"
        );

        Ok(())
    }

    #[test]
    fn test_fix_invalid_metadata_confuserex_normal() -> crate::Result<()> {
        // Normal protection sample - has SuppressIldasm which indicates invalid metadata protection
        let assembly = CilObject::from_path_with_validation(
            "tests/samples/packers/confuserex/mkaring_normal.exe",
            ValidationConfig::analysis(),
        )?;

        // Capture BEFORE state
        let before_module_count = assembly
            .tables()
            .and_then(|t| t.table::<ModuleRaw>())
            .map_or(0, |t| t.row_count);
        let before_assembly_count = assembly
            .tables()
            .and_then(|t| t.table::<AssemblyRaw>())
            .map_or(0, |t| t.row_count);
        let before_invalid_module = count_invalid_module_rows(&assembly);
        let before_invalid_assembly = count_invalid_assembly_rows(&assembly);
        let before_invalid_declsec = count_invalid_declsecurity_rows(&assembly);
        let (before_enc_log, before_enc_map) = count_enc_rows(&assembly);

        println!("BEFORE fix (normal protection):");
        println!(
            "  Module rows: {} (invalid: {})",
            before_module_count, before_invalid_module
        );
        println!(
            "  Assembly rows: {} (invalid: {})",
            before_assembly_count, before_invalid_assembly
        );
        println!("  Invalid DeclSecurity rows: {}", before_invalid_declsec);
        println!(
            "  ENCLog rows: {}, ENCMap rows: {}",
            before_enc_log, before_enc_map
        );

        // Apply fix
        let fixed = fix_invalid_metadata(assembly)?;

        // Capture AFTER state
        let after_module_count = fixed
            .tables()
            .and_then(|t| t.table::<ModuleRaw>())
            .map_or(0, |t| t.row_count);
        let after_assembly_count = fixed
            .tables()
            .and_then(|t| t.table::<AssemblyRaw>())
            .map_or(0, |t| t.row_count);
        let after_invalid_module = count_invalid_module_rows(&fixed);
        let after_invalid_assembly = count_invalid_assembly_rows(&fixed);
        let after_invalid_declsec = count_invalid_declsecurity_rows(&fixed);
        let (after_enc_log, after_enc_map) = count_enc_rows(&fixed);

        println!("AFTER fix:");
        println!(
            "  Module rows: {} (invalid: {})",
            after_module_count, after_invalid_module
        );
        println!(
            "  Assembly rows: {} (invalid: {})",
            after_assembly_count, after_invalid_assembly
        );
        println!("  Invalid DeclSecurity rows: {}", after_invalid_declsec);
        println!(
            "  ENCLog rows: {}, ENCMap rows: {}",
            after_enc_log, after_enc_map
        );

        // Verify all invalid rows were removed
        assert_eq!(
            after_invalid_module, 0,
            "All invalid Module rows should be removed"
        );
        assert_eq!(
            after_invalid_assembly, 0,
            "All invalid Assembly rows should be removed"
        );
        assert_eq!(
            after_invalid_declsec, 0,
            "All invalid DeclSecurity rows should be removed"
        );
        assert_eq!(after_enc_log, 0, "All ENCLog rows should be removed");
        assert_eq!(after_enc_map, 0, "All ENCMap rows should be removed");

        // Verify the delta: removed rows = before_invalid count
        let module_removed = before_module_count - after_module_count;
        let assembly_removed = before_assembly_count - after_assembly_count;
        assert_eq!(
            module_removed, before_invalid_module as u32,
            "Number of Module rows removed should match invalid count"
        );
        assert_eq!(
            assembly_removed, before_invalid_assembly as u32,
            "Number of Assembly rows removed should match invalid count"
        );

        // Verify at least 1 valid Module and Assembly row remains
        assert!(
            after_module_count >= 1,
            "At least one valid Module row should remain"
        );
        assert!(
            after_assembly_count >= 1,
            "At least one valid Assembly row should remain"
        );

        // Verify the remaining Module row has a valid, readable name
        let string_heap_size = fixed.strings().map_or(0, |s| s.data().len());
        if let Some(module_table) = fixed.tables().and_then(|t| t.table::<ModuleRaw>()) {
            for module in module_table {
                assert!(
                    (module.name as usize) < string_heap_size,
                    "Remaining Module.name index {} should be within string heap size {}",
                    module.name,
                    string_heap_size
                );
                // Try to read the actual string
                if let Some(strings) = fixed.strings() {
                    let name = strings.get(module.name as usize);
                    assert!(
                        name.is_ok(),
                        "Should be able to read Module name at index {}",
                        module.name
                    );
                    println!("  Valid Module name: {:?}", name.unwrap());
                }
            }
        }

        Ok(())
    }

    #[test]
    fn test_fix_invalid_metadata_confuserex_maximum() -> crate::Result<()> {
        // Maximum protection sample
        let assembly = CilObject::from_path_with_validation(
            "tests/samples/packers/confuserex/mkaring_maximum.exe",
            ValidationConfig::analysis(),
        )?;

        // Capture BEFORE state
        let before_module_count = assembly
            .tables()
            .and_then(|t| t.table::<ModuleRaw>())
            .map_or(0, |t| t.row_count);
        let before_assembly_count = assembly
            .tables()
            .and_then(|t| t.table::<AssemblyRaw>())
            .map_or(0, |t| t.row_count);
        let before_invalid_module = count_invalid_module_rows(&assembly);
        let before_invalid_assembly = count_invalid_assembly_rows(&assembly);
        let before_invalid_declsec = count_invalid_declsecurity_rows(&assembly);
        let (before_enc_log, before_enc_map) = count_enc_rows(&assembly);

        println!("BEFORE fix (maximum protection):");
        println!(
            "  Module rows: {} (invalid: {})",
            before_module_count, before_invalid_module
        );
        println!(
            "  Assembly rows: {} (invalid: {})",
            before_assembly_count, before_invalid_assembly
        );
        println!("  Invalid DeclSecurity rows: {}", before_invalid_declsec);
        println!(
            "  ENCLog rows: {}, ENCMap rows: {}",
            before_enc_log, before_enc_map
        );

        // Apply fix
        let fixed = fix_invalid_metadata(assembly)?;

        // Capture AFTER state
        let after_module_count = fixed
            .tables()
            .and_then(|t| t.table::<ModuleRaw>())
            .map_or(0, |t| t.row_count);
        let after_assembly_count = fixed
            .tables()
            .and_then(|t| t.table::<AssemblyRaw>())
            .map_or(0, |t| t.row_count);
        let after_invalid_module = count_invalid_module_rows(&fixed);
        let after_invalid_assembly = count_invalid_assembly_rows(&fixed);
        let after_invalid_declsec = count_invalid_declsecurity_rows(&fixed);
        let (after_enc_log, after_enc_map) = count_enc_rows(&fixed);

        println!("AFTER fix:");
        println!(
            "  Module rows: {} (invalid: {})",
            after_module_count, after_invalid_module
        );
        println!(
            "  Assembly rows: {} (invalid: {})",
            after_assembly_count, after_invalid_assembly
        );
        println!("  Invalid DeclSecurity rows: {}", after_invalid_declsec);
        println!(
            "  ENCLog rows: {}, ENCMap rows: {}",
            after_enc_log, after_enc_map
        );

        // Verify all invalid rows were removed
        assert_eq!(
            after_invalid_module, 0,
            "All invalid Module rows should be removed"
        );
        assert_eq!(
            after_invalid_assembly, 0,
            "All invalid Assembly rows should be removed"
        );
        assert_eq!(
            after_invalid_declsec, 0,
            "All invalid DeclSecurity rows should be removed"
        );
        assert_eq!(after_enc_log, 0, "All ENCLog rows should be removed");
        assert_eq!(after_enc_map, 0, "All ENCMap rows should be removed");

        // Verify the delta matches what we expected to remove
        let module_removed = before_module_count - after_module_count;
        let assembly_removed = before_assembly_count - after_assembly_count;
        assert_eq!(
            module_removed, before_invalid_module as u32,
            "Number of Module rows removed ({}) should match invalid count ({})",
            module_removed, before_invalid_module
        );
        assert_eq!(
            assembly_removed, before_invalid_assembly as u32,
            "Number of Assembly rows removed ({}) should match invalid count ({})",
            assembly_removed, before_invalid_assembly
        );

        // Verify at least 1 valid Module and Assembly row remains
        assert!(
            after_module_count >= 1,
            "At least one valid Module row should remain"
        );
        assert!(
            after_assembly_count >= 1,
            "At least one valid Assembly row should remain"
        );

        // Verify the remaining rows have valid, readable names
        let string_heap_size = fixed.strings().map_or(0, |s| s.data().len());
        if let Some(module_table) = fixed.tables().and_then(|t| t.table::<ModuleRaw>()) {
            for module in module_table {
                assert!(
                    (module.name as usize) < string_heap_size,
                    "Remaining Module.name index {} should be within string heap size {}",
                    module.name,
                    string_heap_size
                );
            }
        }

        if let Some(assembly_table) = fixed.tables().and_then(|t| t.table::<AssemblyRaw>()) {
            for asm_row in assembly_table {
                assert!(
                    (asm_row.name as usize) < string_heap_size,
                    "Remaining Assembly.name index {} should be within string heap size {}",
                    asm_row.name,
                    string_heap_size
                );
            }
        }

        // Verify re-detection shows no invalid metadata
        let (_, new_findings) = detect_confuserex(&fixed);
        assert!(
            !new_findings.has_invalid_metadata(),
            "Re-detection should show no invalid metadata after fix"
        );
        assert!(
            !new_findings.has_enc_tables(),
            "Re-detection should show no ENC tables after fix"
        );

        Ok(())
    }

    #[test]
    fn test_remove_suppress_ildasm() -> crate::Result<()> {
        // Normal protection has SuppressIldasm attribute but NO anti-tamper.
        // Maximum protection also has SuppressIldasm but its method bodies are
        // encrypted by anti-tamper, which would need decryption first.
        let assembly = CilObject::from_path_with_validation(
            "tests/samples/packers/confuserex/mkaring_normal.exe",
            ValidationConfig::analysis(),
        )?;

        // Detect to find the token
        let (_, findings) = detect_confuserex(&assembly);
        assert!(
            findings.has_suppress_ildasm(),
            "Normal protection should have SuppressIldasm"
        );
        let token = findings.suppress_ildasm_token.expect("Should have token");

        // Count CustomAttribute rows before removal
        let initial_count = assembly
            .tables()
            .and_then(|t| t.table::<CustomAttributeRaw>())
            .map_or(0, |t| t.row_count);

        println!("BEFORE removal:");
        println!("  CustomAttribute rows: {}", initial_count);
        println!("  SuppressIldasm token: {}", token);

        // Verify the token refers to a valid row
        assert!(
            token.row() <= initial_count,
            "Token row {} should be within CustomAttribute table size {}",
            token.row(),
            initial_count
        );

        // Remove the attribute
        let fixed = remove_suppress_ildasm(&assembly, token)?;

        // Capture AFTER state
        let final_count = fixed
            .tables()
            .and_then(|t| t.table::<CustomAttributeRaw>())
            .map_or(0, |t| t.row_count);

        println!("AFTER removal:");
        println!("  CustomAttribute rows: {}", final_count);

        // Verify exactly one row was removed
        assert_eq!(
            final_count,
            initial_count - 1,
            "Should have exactly one fewer CustomAttribute row (before: {}, after: {})",
            initial_count,
            final_count
        );

        // Verify re-detection shows no SuppressIldasm
        let (_, new_findings) = detect_confuserex(&fixed);
        assert!(
            !new_findings.has_suppress_ildasm(),
            "SuppressIldasm should be removed after fix"
        );
        assert!(
            new_findings.suppress_ildasm_token.is_none(),
            "SuppressIldasm token should be None after removal"
        );

        Ok(())
    }

    #[test]
    fn test_remove_suppress_ildasm_invalid_token() {
        // Test with invalid token table type
        let assembly = CilObject::from_path_with_validation(
            "tests/samples/packers/confuserex/mkaring_maximum.exe",
            ValidationConfig::analysis(),
        )
        .unwrap();

        // Create a token that's not a CustomAttribute (e.g., MethodDef table 0x06)
        let invalid_token = Token::new(0x06000001);
        let result = remove_suppress_ildasm(&assembly, invalid_token);

        assert!(
            result.is_err(),
            "Should fail with non-CustomAttribute token"
        );

        // Verify error type is InvalidToken
        match result {
            Err(Error::InvalidToken { token, message }) => {
                assert_eq!(
                    token, invalid_token,
                    "Error should reference the invalid token"
                );
                assert!(
                    message.contains("CustomAttribute"),
                    "Error message should mention CustomAttribute: {}",
                    message
                );
            }
            Err(other) => panic!("Expected InvalidToken error, got: {:?}", other),
            Ok(_) => panic!("Expected error, got Ok"),
        }
    }

    #[test]
    fn test_remove_suppress_ildasm_nonexistent_row() {
        // Test with a CustomAttribute token that doesn't exist
        let assembly = CilObject::from_path_with_validation(
            "tests/samples/packers/confuserex/mkaring_maximum.exe",
            ValidationConfig::analysis(),
        )
        .unwrap();

        // Create a CustomAttribute token with an absurdly high row number
        let nonexistent_token = Token::new(0x0c00ffff); // CustomAttribute table, row 65535
        let result = remove_suppress_ildasm(&assembly, nonexistent_token);

        assert!(result.is_err(), "Should fail with nonexistent row");
    }

    #[test]
    fn test_remove_confuser_attributes() -> crate::Result<()> {
        // Minimal protection has ConfusedByAttribute
        let assembly = CilObject::from_path_with_validation(
            "tests/samples/packers/confuserex/mkaring_minimal.exe",
            ValidationConfig::analysis(),
        )?;

        // Detect to find marker attribute tokens
        let (_, findings) = detect_confuserex(&assembly);
        assert!(
            findings.has_marker_attributes(),
            "Minimal protection should have ConfuserEx marker attributes"
        );

        let marker_count = findings.marker_attribute_tokens.count();
        assert!(
            marker_count > 0,
            "Should have at least one marker attribute token"
        );

        // Count CustomAttribute rows before removal
        let initial_count = assembly
            .tables()
            .and_then(|t| t.table::<CustomAttributeRaw>())
            .map_or(0, |t| t.row_count);

        println!("BEFORE marker removal:");
        println!("  CustomAttribute rows: {}", initial_count);
        println!("  ConfuserEx marker attributes: {}", marker_count);

        // Collect tokens for removal
        let tokens: Vec<_> = findings
            .marker_attribute_tokens
            .iter()
            .map(|(_, t)| *t)
            .collect();

        // Remove the marker attributes
        let fixed = remove_confuser_attributes(assembly, tokens)?;

        // Capture AFTER state
        let final_count = fixed
            .tables()
            .and_then(|t| t.table::<CustomAttributeRaw>())
            .map_or(0, |t| t.row_count);

        println!("AFTER marker removal:");
        println!("  CustomAttribute rows: {}", final_count);

        // Verify the correct number of rows were removed
        assert_eq!(
            final_count,
            initial_count - marker_count as u32,
            "Should have {} fewer CustomAttribute rows (before: {}, after: {})",
            marker_count,
            initial_count,
            final_count
        );

        // Verify re-detection shows no marker attributes
        let (_, new_findings) = detect_confuserex(&fixed);
        assert!(
            !new_findings.has_marker_attributes(),
            "ConfuserEx marker attributes should be removed after fix"
        );
        assert_eq!(
            new_findings.marker_attribute_tokens.count(),
            0,
            "Should have no marker attribute tokens after removal"
        );

        Ok(())
    }

    #[test]
    fn test_remove_confuser_attributes_empty_list() -> crate::Result<()> {
        // Test that an empty token list passes through unchanged
        let assembly = CilObject::from_path_with_validation(
            "tests/samples/packers/confuserex/original.exe",
            ValidationConfig::analysis(),
        )?;

        let initial_count = assembly
            .tables()
            .and_then(|t| t.table::<CustomAttributeRaw>())
            .map_or(0, |t| t.row_count);

        // Pass empty token list
        let fixed = remove_confuser_attributes(assembly, Vec::<Token>::new())?;

        let final_count = fixed
            .tables()
            .and_then(|t| t.table::<CustomAttributeRaw>())
            .map_or(0, |t| t.row_count);

        assert_eq!(
            final_count, initial_count,
            "Empty token list should not change CustomAttribute count"
        );

        Ok(())
    }
}
