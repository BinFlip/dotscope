//! Obfuscar detection logic.
//!
//! Identifies assemblies protected by Obfuscar through characteristic patterns:
//! - `<PrivateImplementationDetails>{GUID}` helper type with string hiding structure
//! - Method named "6" that takes (int, int, int) and returns string (shared getter)
//! - Multiple static parameterless methods returning string (per-string accessors)
//! - `.cctor` with XOR decryption loop
//! - `SuppressIldasmAttribute` on the module (optional, version-dependent)
//! - Null/empty parameter names

use crate::{
    deobfuscation::{
        detection::{DetectionEvidence, DetectionScore},
        findings::DeobfuscationFindings,
        obfuscators::utils,
    },
    metadata::{signatures::TypeSignature, token::Token},
    CilObject,
};

/// Detects Obfuscar obfuscation in an assembly.
///
/// Runs all detection checks in sequence:
/// 1. `SuppressIldasmAttribute` on the module (+10 confidence)
/// 2. `<PrivateImplementationDetails>{GUID}` helper type (+60 confidence)
/// 3. Per-string accessor method count (+10 if >= 5 accessors)
/// 4. XOR decryption loop in `.cctor` (+10 confidence)
/// 5. Null/empty parameter names (+5 if >= 5 found)
///
/// # Returns
///
/// A tuple of (`DetectionScore`, `DeobfuscationFindings`). The score indicates
/// detection confidence (>= 50 means Obfuscar detected). The findings contain
/// tokens for infrastructure types, decryptor methods, fields, and the
/// `SuppressIldasmAttribute` — used downstream by the deobfuscation pipeline.
pub fn detect_obfuscar(assembly: &CilObject) -> (DetectionScore, DeobfuscationFindings) {
    let score = DetectionScore::new();
    let mut findings = DeobfuscationFindings::new();

    // Check for SuppressIldasmAttribute on the module (shared utility, confidence: 10)
    utils::check_suppress_ildasm(assembly, &score, &mut findings, 10);

    // Check for <PrivateImplementationDetails>{GUID} helper type with string hiding structure
    detect_string_hiding_infrastructure(assembly, &score, &mut findings);

    // Check for null/empty parameter names (weak signal)
    check_null_parameter_names(assembly, &score);

    (score, findings)
}

/// Detects Obfuscar's `<PrivateImplementationDetails>{GUID}` helper type.
///
/// The helper type has a characteristic structure:
/// - Name starts with `<PrivateImplementationDetails>{` (may have `.GUID` suffix in v2.2+)
/// - Has a method named "6" that takes (int32, int32, int32) and returns string
/// - Has multiple static parameterless methods returning string (per-string accessors)
/// - Has a `.cctor` with XOR decryption loop containing the encryption key
///
/// When the helper type is found, this populates `findings` with:
/// - `protection_infrastructure_types` — the helper type and nested types
/// - `infrastructure_fields` — all fields in the helper and nested types
/// - `decryptor_methods` — per-string accessor methods (called from user code)
///
/// Also adds detection evidence to `score` for the helper type structure (+60),
/// accessor count (+10 if >= 5), XOR key (+10), and nested ExplicitLayout struct (+5).
fn detect_string_hiding_infrastructure(
    assembly: &CilObject,
    score: &DetectionScore,
    findings: &mut DeobfuscationFindings,
) {
    for type_entry in assembly.types().iter() {
        let cil_type = type_entry.value();

        // Check for the characteristic namespace pattern
        if !is_obfuscar_helper_type(&cil_type.namespace, &cil_type.name) {
            continue;
        }

        // Check for method "6" (the shared string getter)
        // Signature: static string "6"(int32, int32, int32)
        let mut has_method_6 = false;
        let mut accessor_method_tokens: Vec<Token> = Vec::new();
        let mut cctor_token: Option<Token> = None;

        for (_, method_ref) in cil_type.methods.iter() {
            let Some(method) = method_ref.upgrade() else {
                continue;
            };

            if method.name == "6" {
                // Verify signature: returns string, takes 3 int params
                let sig = &method.signature;
                let returns_string = matches!(sig.return_type.base, TypeSignature::String);
                let has_3_params = sig.params.len() == 3;

                if returns_string && has_3_params {
                    has_method_6 = true;
                }
            } else if method.name == ".cctor" {
                cctor_token = Some(method.token);
            } else if method.name == ".ctor" {
                // Skip instance constructor
            } else {
                // Potential per-string accessor method
                // Must be static, return string, take no parameters
                let sig = &method.signature;
                let returns_string = matches!(sig.return_type.base, TypeSignature::String);
                let no_params = sig.params.is_empty();

                if returns_string && no_params {
                    accessor_method_tokens.push(method.token);
                }
            }
        }

        let has_accessors = !accessor_method_tokens.is_empty();

        // The primary detection signal: method "6" with correct signature + accessors
        if has_method_6 && has_accessors {
            score.add(DetectionEvidence::StructuralPattern {
                description: format!(
                    "Obfuscar string hiding helper type '{}.{}' with method 6 and {} accessor methods",
                    cil_type.namespace,
                    cil_type.name,
                    accessor_method_tokens.len()
                ),
                confidence: 60,
            });

            // Store the helper type token for cleanup
            findings
                .protection_infrastructure_types
                .push(cil_type.token);

            // Store all fields as infrastructure (they're all part of the hiding mechanism)
            for (_, field) in cil_type.fields.iter() {
                findings.infrastructure_fields.push(field.token);
            }

            // Store only accessor methods as decryptor methods (called from user code).
            // Method "6" and .cctor are internal helpers — they run during emulation
            // but are not directly called from user code.
            for token in &accessor_method_tokens {
                findings.decryptor_methods.push(*token);
            }

            // Additional confidence from accessor count
            if accessor_method_tokens.len() >= 5 {
                score.add(DetectionEvidence::MetadataPattern {
                    name: "Obfuscar per-string accessor methods".to_string(),
                    locations: {
                        let locs = boxcar::Vec::new();
                        for token in &accessor_method_tokens {
                            locs.push(*token);
                        }
                        locs
                    },
                    confidence: 10,
                });
            }

            // Extract XOR key from .cctor for scoring (adds detection confidence)
            if let Some(cctor) = cctor_token {
                if let Some(xor_key) = extract_xor_key_from_cctor(assembly, cctor) {
                    score.add(DetectionEvidence::StructuralPattern {
                        description: format!(
                            "XOR decryption loop in .cctor (key=0x{:02X})",
                            xor_key
                        ),
                        confidence: 10,
                    });
                }
            }

            // Check for nested struct with ExplicitLayout (FieldRVA data source)
            // Also mark nested types as infrastructure for cleanup
            for (_, nested_ref) in cil_type.nested_types.iter() {
                if let Some(nested_type) = nested_ref.upgrade() {
                    // All nested types of the helper are infrastructure
                    findings
                        .protection_infrastructure_types
                        .push(nested_type.token);

                    for (_, field) in nested_type.fields.iter() {
                        findings.infrastructure_fields.push(field.token);
                    }

                    // ExplicitLayout flag is 0x10 in TypeAttributes
                    if nested_type.flags & 0x10 != 0 {
                        score.add(DetectionEvidence::StructuralPattern {
                            description: "Nested ExplicitLayout struct (FieldRVA data source)"
                                .to_string(),
                            confidence: 5,
                        });
                    }
                }
            }
        }
    }
}

/// Extracts the XOR key from the `.cctor` method of the helper type.
///
/// Scans the `.cctor` instruction stream for the characteristic double-XOR pattern
/// used by Obfuscar's string decryption: `xor`, `ldc.i4 <KEY>`, `xor`. The constant
/// between the two `xor` instructions is the encryption key byte (typically `0xAA`).
///
/// # Returns
///
/// The XOR key byte if found, or `None` if the pattern is not present or the
/// method cannot be loaded.
fn extract_xor_key_from_cctor(assembly: &CilObject, cctor_token: Token) -> Option<u8> {
    let method = assembly.method(&cctor_token)?;
    let instructions: Vec<_> = method.instructions().collect();

    // Look for: xor, ldc.i4 <constant>, xor pattern
    for window in instructions.windows(3) {
        if window[0].mnemonic == "xor" && window[2].mnemonic == "xor" {
            // The ldc.i4 between the two xors is the key
            if let Some(val) = window[1].get_i32_operand() {
                if (0..=255).contains(&val) {
                    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
                    return Some(val as u8);
                }
            }
        }
    }

    None
}

/// Checks if a type matches the Obfuscar helper type pattern.
///
/// Obfuscar injects types with namespace `<PrivateImplementationDetails>{GUID}` and
/// a GUID-like type name. The check verifies the namespace starts with
/// `<PrivateImplementationDetails>{` and contains content after the opening brace
/// (the GUID portion).
///
/// # Returns
///
/// `true` if the namespace matches the Obfuscar helper type pattern.
fn is_obfuscar_helper_type(namespace: &str, _name: &str) -> bool {
    let prefix = "<PrivateImplementationDetails>{";
    if !namespace.starts_with(prefix) {
        return false;
    }
    // Must have content after the prefix (the GUID)
    namespace.len() > prefix.len()
}

/// Checks for null/empty parameter names (weak Obfuscar signal).
///
/// Obfuscar sets method parameter names to null during `RenameParams()`. This is
/// a weak signal (confidence: 5) since other tools can also produce null parameter
/// names. Only triggers if 5 or more null/empty parameter names are found, to avoid
/// false positives on assemblies with a few intentionally unnamed parameters.
fn check_null_parameter_names(assembly: &CilObject, score: &DetectionScore) {
    let mut null_param_count = 0usize;

    for method_entry in assembly.methods() {
        let method = method_entry.value();

        // Skip special methods
        if method.name == ".ctor" || method.name == ".cctor" {
            continue;
        }

        // Check each parameter
        for (_, param) in method.params.iter() {
            if param.sequence == 0 {
                continue; // Skip return value parameter
            }
            match &param.name {
                None => null_param_count += 1,
                Some(name) if name.is_empty() => null_param_count += 1,
                _ => {}
            }
        }
    }

    if null_param_count >= 5 {
        score.add(DetectionEvidence::StructuralPattern {
            description: format!("{null_param_count} null/empty parameter names"),
            confidence: 5,
        });
    }
}

#[cfg(test)]
mod tests {
    use crate::deobfuscation::obfuscators::obfuscar::detection::is_obfuscar_helper_type;

    #[test]
    fn test_obfuscar_helper_type_matching() {
        // Standard namespace format with separate name
        assert!(is_obfuscar_helper_type(
            "<PrivateImplementationDetails>{549CA519-2B22-4A20-871F-C40FA9335A42}",
            "38CC15C4-E7D1-45A1-8841-82A260C99761"
        ));
        // Short GUID namespace
        assert!(is_obfuscar_helper_type(
            "<PrivateImplementationDetails>{ABCDEF}",
            "SomeName"
        ));
        // Invalid cases
        assert!(!is_obfuscar_helper_type(
            "<PrivateImplementationDetails>",
            "SomeName"
        ));
        assert!(!is_obfuscar_helper_type(
            "<PrivateImplementationDetails>{",
            "SomeName"
        ));
        assert!(!is_obfuscar_helper_type("SomeNamespace", "SomeType"));
        assert!(!is_obfuscar_helper_type("", ""));
    }
}
