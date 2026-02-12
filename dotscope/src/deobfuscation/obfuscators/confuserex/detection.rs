//! ConfuserEx detection orchestrator.
//!
//! This module coordinates detection across all ConfuserEx protection modules.
//! Each module implements its own `detect()` function that populates findings
//! and adds evidence to the detection score.
//!
//! # Detection Pipeline
//!
//! ```text
//! detect_confuserex()
//!   ├─> metadata::detect()        - Invalid metadata, ENC tables, SuppressIldasm, markers
//!   ├─> constants::detect()       - Constants decryptor methods
//!   ├─> antitamper::detect()      - Anti-tamper initialization methods + encrypted bodies
//!   ├─> antidebug::detect()       - Anti-debug check patterns
//!   ├─> antidump::detect()        - Anti-dump header corruption patterns
//!   ├─> resources::detect()       - Resource protection handler patterns
//!   └─> referenceproxy::detect()  - ReferenceProxy call forwarding methods
//! ```
//!
//! Note: Control flow flattening (CFF) detection is handled separately by the
//! `UnflatteningPass` using SSA-based structural analysis. See
//! `deobfuscation/passes/unflattening/detection.rs` for the `CffDetector` which
//! uses dominator analysis, back-edge ratios, and state variable identification.
//!
//! The orchestrator creates a `DetectionScore` and `DeobfuscationFindings` struct,
//! then calls each module's detect function to populate them.

use std::collections::HashSet;

use rustc_hash::FxHashMap;

use crate::{
    assembly::{Instruction, Operand},
    deobfuscation::{
        detection::{DetectionEvidence, DetectionScore},
        findings::{DeobfuscationFindings, NativeHelperInfo},
        obfuscators::confuserex::{
            antidebug, antidump, antitamper, constants, metadata, referenceproxy, resources,
        },
    },
    file::pe::SectionTable,
    metadata::{
        method::MethodImplCodeType,
        signatures::{parse_field_signature, TypeSignature},
        streams::TablesHeader,
        tables::{FieldRaw, FieldRvaRaw, TypeDefRaw, TypeRefRaw},
        token::Token,
        typesystem::CilTypeRef,
    },
    prelude::{FlowType, TableId},
    CilObject,
};

/// Detects ConfuserEx obfuscation in an assembly.
///
/// This is the main entry point for ConfuserEx detection. It orchestrates
/// detection across all protection modules and returns:
/// - A `DetectionScore` with confidence and evidence
/// - `DeobfuscationFindings` with cached data for deobfuscation
///
/// # Detection Strategy
///
/// Each protection module has its own `detect()` function that:
/// 1. Scans for protection-specific patterns
/// 2. Populates the relevant fields in `DeobfuscationFindings`
/// 3. Adds evidence to the `DetectionScore`
///
/// # Arguments
///
/// * `assembly` - The assembly to analyze.
///
/// # Returns
///
/// A tuple of `(DetectionScore, DeobfuscationFindings)`.
pub fn detect_confuserex(assembly: &CilObject) -> (DetectionScore, DeobfuscationFindings) {
    let score = DetectionScore::new();
    let mut findings = DeobfuscationFindings::new();

    // Metadata protection: invalid indices, ENC tables, SuppressIldasm, markers
    metadata::detect(assembly, &score, &mut findings);

    // Constants encryption: decryptor methods, CFG mode, state machine semantics
    constants::detect(assembly, &score, &mut findings);

    // Native x86 helpers: methods called by decryptors with Native impl flag
    // Must run AFTER string detection since we need decryptor_methods
    detect_native_helpers(assembly, &score, &mut findings);

    // Anti-tamper: VirtualProtect + GetHINSTANCE patterns, encrypted method bodies
    antitamper::detect(assembly, &score, &mut findings);

    // Anti-debug: debugger checks + FailFast patterns
    antidebug::detect(assembly, &score, &mut findings);

    // Anti-dump: VirtualProtect + GetHINSTANCE + get_Module + Marshal.Copy patterns
    antidump::detect(assembly, &score, &mut findings);

    // Resources: AssemblyResolve/ResourceResolve handler patterns
    resources::detect(assembly, &score, &mut findings);

    // ReferenceProxy: indirect call forwarding methods
    referenceproxy::detect(assembly, &score, &mut findings);

    // Note: Control flow flattening (CFF) detection is handled by the
    // UnflatteningPass using SSA-based structural analysis (see
    // deobfuscation/passes/unflattening/detection.rs). This provides
    // robust detection via dominator analysis, back-edge ratios, and
    // state variable identification rather than hardcoded constants.

    // Artifact sections: encrypted data sections for removal during cleanup
    detect_artifact_sections(assembly, &score, &mut findings);

    // Constant data infrastructure: fields with FieldRVA used by decryptors
    detect_constant_data_infrastructure(assembly, &score, &mut findings);

    // Protection infrastructure types: types containing only protection methods
    // This must run AFTER all protection method detection is complete
    detect_protection_infrastructure_types(assembly, &score, &mut findings);

    // Infrastructure fields: static fields in <Module> only used by infrastructure code
    // This must run AFTER all protection method/type detection is complete
    detect_infrastructure_fields(assembly, &score, &mut findings);

    (score, findings)
}

/// Detects native x86 helper methods used by ConfuserEx.
///
/// ConfuserEx uses native x86 methods in two ways:
/// 1. **Constants encryption (x86 cipher)**: Native methods called by decryptor methods
///    for key transformation during constant decryption.
/// 2. **Control flow (x86 predicate)**: Native methods called by user code to evaluate
///    opaque predicates for control flow obfuscation.
///
/// Detection uses two phases:
/// - Phase 1: Scan decryptor methods for calls to native helpers (tracks callers)
/// - Phase 2: Scan ALL methods in `<Module>` for native `int32(int32)` signature
///   (catches x86 predicate helpers not called by decryptors)
fn detect_native_helpers(
    assembly: &CilObject,
    score: &DetectionScore,
    findings: &mut DeobfuscationFindings,
) {
    // Build set of decryptor tokens for quick lookup
    let decryptor_tokens: std::collections::HashSet<Token> =
        findings.decryptor_methods.iter().map(|(_, t)| *t).collect();

    // Map from native method token to NativeHelperInfo
    let mut native_helpers: FxHashMap<Token, NativeHelperInfo> = FxHashMap::default();

    // Phase 1: Scan decryptor methods for calls to native methods (tracks callers)
    if !decryptor_tokens.is_empty() {
        for method_entry in assembly.methods() {
            let method = method_entry.value();

            // Only scan decryptor methods
            if !decryptor_tokens.contains(&method.token) {
                continue;
            }

            // Scan instructions for call instructions
            for instr in method.instructions() {
                // Look for call instructions
                if instr.flow_type != FlowType::Call {
                    continue;
                }

                let Operand::Token(call_target) = &instr.operand else {
                    continue;
                };

                // Check if the call target is a native method with int32(int32) signature
                let Some(target_method) = assembly.method(call_target) else {
                    continue;
                };

                // Check if it's a native method
                if !target_method
                    .impl_code_type
                    .contains(MethodImplCodeType::NATIVE)
                {
                    continue;
                }

                // Check signature: static int32(int32)
                let sig = &target_method.signature;
                let is_int32_to_int32 = sig.return_type.base == TypeSignature::I4
                    && sig.params.len() == 1
                    && sig.params[0].base == TypeSignature::I4;

                if !is_int32_to_int32 {
                    continue;
                }

                // Get RVA
                let Some(rva) = target_method.rva else {
                    continue;
                };

                // Add or update the native helper entry
                native_helpers
                    .entry(*call_target)
                    .or_insert_with(|| NativeHelperInfo::new(*call_target, rva))
                    .add_caller(method.token);
            }
        }
    }

    // Phase 2: Detect ALL native methods in <Module> with int32(int32) signature.
    // This catches x86 predicate helpers that are called by user code (not decryptors).
    // ConfuserEx always places native helpers in <Module> (TypeDef RID 1).
    let module_token = Token::from_parts(TableId::TypeDef, 1);
    for method_entry in assembly.methods() {
        let method = method_entry.value();

        // Skip if already detected in Phase 1
        if native_helpers.contains_key(&method.token) {
            continue;
        }

        // Must be a native method
        if !method.impl_code_type.contains(MethodImplCodeType::NATIVE) {
            continue;
        }

        // Must belong to <Module>
        let is_module_method = method
            .declaring_type_rc()
            .is_some_and(|t| t.token == module_token);
        if !is_module_method {
            continue;
        }

        // Check signature: static int32(int32)
        let sig = &method.signature;
        let is_int32_to_int32 = sig.return_type.base == TypeSignature::I4
            && sig.params.len() == 1
            && sig.params[0].base == TypeSignature::I4;

        if !is_int32_to_int32 {
            continue;
        }

        // Get RVA
        let Some(rva) = method.rva else {
            continue;
        };

        native_helpers
            .entry(method.token)
            .or_insert_with(|| NativeHelperInfo::new(method.token, rva));
    }

    // Store findings
    if !native_helpers.is_empty() {
        let count = native_helpers.len();
        let locations: boxcar::Vec<Token> = boxcar::Vec::new();
        for key in native_helpers.keys() {
            locations.push(*key);
        }

        for (_, info) in native_helpers {
            findings.native_helpers.push(info);
        }

        // Add detection evidence
        score.add(DetectionEvidence::MetadataPattern {
            name: format!("Native x86 helper methods ({count} with signature int32(int32))"),
            locations,
            confidence: (count * 25).min(40),
        });
    }
}

/// Detects PE sections containing artifact/encrypted data for cleanup.
///
/// This identifies sections that should be removed after deobfuscation:
/// 1. Sections containing encrypted method body RVAs (methods with RVA but no parseable body)
/// 2. Sections with non-standard names (not .text, .rsrc, .reloc, .rdata, .data, .tls)
fn detect_artifact_sections(
    assembly: &CilObject,
    score: &DetectionScore,
    findings: &mut DeobfuscationFindings,
) {
    let file = assembly.file();
    let sections = file.sections();

    let mut artifact_section_names: HashSet<String> = HashSet::new();

    // Find sections containing encrypted method bodies
    // These are methods where RVA is set but body couldn't be parsed
    for method in &assembly.query_methods().without_body() {
        if let Some(rva) = method.rva {
            if rva > 0 {
                if let Some(section) = find_section_for_rva(sections, rva) {
                    // If it's not in .text, it's an artifact section
                    // (ConfuserEx sometimes puts encrypted bodies in custom sections)
                    if !section.name.starts_with(".text") {
                        artifact_section_names.insert(section.name.clone());
                    }
                }
            }
        }
    }

    // Mark non-standard sections as artifacts
    // Standard .NET PE sections that should be preserved
    let standard_prefixes = [".text", ".rsrc", ".reloc", ".rdata", ".data", ".tls"];
    for section in sections {
        // Check if section name starts with any standard prefix
        let is_standard = standard_prefixes
            .iter()
            .any(|prefix| section.name.starts_with(prefix));

        if !is_standard {
            // Non-standard section name - likely ConfuserEx artifact
            // Examples: "~`v&R28", custom obfuscated names, etc.
            artifact_section_names.insert(section.name.clone());
        }
    }

    // Store findings
    let section_list: Vec<String> = artifact_section_names.iter().cloned().collect();
    for name in &section_list {
        findings.artifact_sections.push(name.clone());
    }

    // Add evidence if artifact sections were found
    if !section_list.is_empty() {
        score.add_evidence(DetectionEvidence::ArtifactSections {
            sections: section_list,
            confidence: 5, // Low confidence - artifact sections alone aren't definitive
        });
    }
}

/// Finds the section containing a given RVA.
fn find_section_for_rva(sections: &[SectionTable], rva: u32) -> Option<&SectionTable> {
    sections.iter().find(|s| {
        let section_end = s.virtual_address.saturating_add(s.virtual_size);
        rva >= s.virtual_address && rva < section_end
    })
}

/// Detects constant data infrastructure (FieldRVA entries used by decryptors).
///
/// ConfuserEx stores encrypted constants in fields with FieldRVA entries:
/// 1. Creates a nested value type with ClassLayout specifying size
/// 2. Creates a field of that type with HasFieldRVA flag
/// 3. Stores encrypted data at the field's RVA
/// 4. Uses `ldtoken field` + `RuntimeHelpers.InitializeArray` to load at runtime
///
/// This function identifies:
/// - Fields referenced by `ldtoken` followed by `InitializeArray` calls
/// - Fields with FieldRVA entries that belong to obfuscator infrastructure types
/// - The backing value types (for ClassLayout cleanup)
fn detect_constant_data_infrastructure(
    assembly: &CilObject,
    score: &DetectionScore,
    findings: &mut DeobfuscationFindings,
) {
    let mut data_field_tokens: HashSet<Token> = HashSet::new();
    let mut data_type_tokens: HashSet<Token> = HashSet::new();

    // Strategy 1: Find ldtoken + InitializeArray patterns in method bodies
    // This is the primary detection method based on ConfuserEx's code pattern
    for method_entry in assembly.methods() {
        let method = method_entry.value();

        // Collect instructions to allow looking ahead
        let instructions: Vec<&Instruction> = method.instructions().collect();
        let len = instructions.len();

        // Look for: ldtoken <field>, call RuntimeHelpers.InitializeArray
        for i in 0..len.saturating_sub(1) {
            let instr = instructions[i];
            let next_instr = instructions[i + 1];

            // Check for ldtoken with field operand
            if instr.mnemonic != "ldtoken" {
                continue;
            }

            // Check if the token is a field token (table 0x04 = Field)
            let Operand::Token(operand_token) = &instr.operand else {
                continue;
            };
            let token = Token::new(operand_token.value());
            if !token.is_table(TableId::Field) {
                continue;
            }

            // Check if next instruction is a call to InitializeArray
            if next_instr.flow_type != FlowType::Call {
                continue;
            }

            // Check if the call target is RuntimeHelpers.InitializeArray
            let Operand::Token(call_operand) = &next_instr.operand else {
                continue;
            };
            let call_token = Token::new(call_operand.value());

            // Check if it's a MemberRef to InitializeArray
            let is_init_array = call_token.is_table(TableId::MemberRef)
                && assembly
                    .refs_members()
                    .get(&call_token)
                    .is_some_and(|r| r.value().name == "InitializeArray");

            if is_init_array {
                // Found a constant data field!
                data_field_tokens.insert(token);

                // Try to find the backing type from the field's signature
                if let Some(backing_type_token) = find_field_backing_type(assembly, token) {
                    data_type_tokens.insert(backing_type_token);
                }
            }
        }
    }

    // Strategy 2: Find fields with FieldRVA that belong to known obfuscator types
    // This catches any data fields we might have missed in the pattern scan
    let obfuscator_type_rids: HashSet<u32> = findings
        .obfuscator_type_tokens
        .iter()
        .map(|(_, t)| t.row())
        .collect();

    if let Some(tables) = assembly.tables() {
        // Get FieldRVA table to find fields with initialization data
        if let Some(fieldrva_table) = tables.table::<FieldRvaRaw>() {
            for fieldrva in fieldrva_table {
                if fieldrva.rva == 0 {
                    continue;
                }

                let field_rid = fieldrva.field;
                let field_token = Token::from_parts(TableId::Field, field_rid);

                // Check if this field belongs to an obfuscator type
                if let Some(declaring_type_rid) = find_field_declaring_type(tables, field_rid) {
                    if obfuscator_type_rids.contains(&declaring_type_rid) {
                        data_field_tokens.insert(field_token);

                        // Also track the declaring type for removal
                        let type_token = Token::from_parts(TableId::TypeDef, declaring_type_rid);
                        data_type_tokens.insert(type_token);
                    }
                }

                // Also check if the field's type is a value type with ClassLayout
                // These are the backing types created by ConfuserEx
                if let Some(backing_type) = find_field_backing_type(assembly, field_token) {
                    // Check if this backing type has a ClassLayout entry
                    // (indicating it's a fixed-size buffer type)
                    let has_class_layout = assembly.types().get(&backing_type).is_some_and(|t| {
                        t.class_size.get().is_some() || t.packing_size.get().is_some()
                    });

                    if has_class_layout {
                        data_field_tokens.insert(field_token);
                        data_type_tokens.insert(backing_type);
                    }
                }
            }
        }
    }

    // Store findings
    let field_count = data_field_tokens.len();
    let type_count = data_type_tokens.len();

    for token in data_field_tokens {
        findings.constant_data_fields.push(token);
    }
    for token in data_type_tokens {
        findings.constant_data_types.push(token);
    }

    // Add evidence if constant data infrastructure was found
    if field_count > 0 || type_count > 0 {
        score.add_evidence(DetectionEvidence::ConstantDataFields {
            field_count,
            type_count,
            confidence: 15, // Moderate confidence - this is a ConfuserEx-specific pattern
        });
    }
}

/// Finds the backing value type for a field (from its signature).
fn find_field_backing_type(assembly: &CilObject, field_token: Token) -> Option<Token> {
    let field_rid = field_token.row();

    let tables = assembly.tables()?;
    let field_table = tables.table::<FieldRaw>()?;
    let field = field_table.get(field_rid)?;

    // Get field signature from blob heap
    let blobs = assembly.blob()?;
    let sig_data = blobs.get(field.signature as usize).ok()?;

    // Parse field signature to get the type
    let field_sig = parse_field_signature(sig_data).ok()?;

    // Check if it's a ValueType
    match &field_sig.base {
        TypeSignature::ValueType(type_token) => {
            // Only return TypeDef tokens (table 0x02)
            if type_token.is_table(TableId::TypeDef) {
                Some(*type_token)
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Finds which TypeDef owns a given field.
/// Note: Uses raw table access since CilObject doesn't expose a global field map.
fn find_field_declaring_type(tables: &TablesHeader, field_rid: u32) -> Option<u32> {
    let typedef_table = tables.table::<TypeDefRaw>()?;
    let field_table = tables.table::<FieldRaw>()?;
    let type_count = typedef_table.row_count;
    let field_count = field_table.row_count;

    for type_rid in 1..=type_count {
        let typedef = typedef_table.get(type_rid)?;
        let field_start = typedef.field_list;
        let field_end = if type_rid < type_count {
            typedef_table
                .get(type_rid + 1)
                .map_or(field_count + 1, |next| next.field_list)
        } else {
            field_count + 1
        };

        if field_rid >= field_start && field_rid < field_end {
            return Some(type_rid);
        }
    }

    None
}

/// Detects types that are pure protection infrastructure.
///
/// After protection detection is complete, this function identifies types that
/// are part of the obfuscator's runtime infrastructure. Since protection methods
/// are typically placed directly in `<Module>`, we focus on removing the nested
/// support types (delegates, data storage, helpers) that are:
///
/// 1. Nested directly in `<Module>` (ConfuserEx pattern)
/// 2. Have NestedPrivate or NestedAssembly visibility (not public)
/// 3. Have no public methods (no external API)
///
/// Additionally, we recursively include nested types within infrastructure types.
///
/// This enables cleanup of ConfuserEx infrastructure while preserving legitimate
/// types that might be in `<Module>` but have public visibility.
fn detect_protection_infrastructure_types(
    assembly: &CilObject,
    score: &DetectionScore,
    findings: &mut DeobfuscationFindings,
) {
    // Only run if we have strong ConfuserEx detection
    // This prevents false positives on normal assemblies
    if !findings.has_any_protection() && !findings.has_marker_attributes() {
        return;
    }

    let types = assembly.types();

    // Types already marked for removal (don't double-process)
    let already_marked: HashSet<u32> = findings
        .obfuscator_type_tokens
        .iter()
        .map(|(_, t)| t.row())
        .chain(findings.constant_data_types.iter().map(|(_, t)| t.row()))
        .collect();

    let mut infrastructure_types: Vec<Token> = Vec::new();

    // Get <Module> type (RID 1) and its nested types
    let module_token = Token::from_parts(TableId::TypeDef, 1);
    let types_nested_in_module: Vec<Token> = types
        .get(&module_token)
        .map(|module_type| {
            module_type
                .nested_types
                .iter()
                .filter_map(|(_, type_ref)| type_ref.upgrade())
                .map(|t| t.token)
                .collect()
        })
        .unwrap_or_default();

    // Check each type nested in <Module>
    for type_token in &types_nested_in_module {
        let type_rid = type_token.row();

        // Skip <Module> itself (RID 1)
        if type_rid == 1 {
            continue;
        }

        // Skip types already marked for removal
        if already_marked.contains(&type_rid) {
            continue;
        }

        // Get the type for checking visibility and methods
        let Some(cil_type) = types.get(type_token) else {
            continue;
        };

        // Check type visibility - must be NestedPrivate, NestedAssembly, or NestedFamANDAssem
        // These are internal types not meant to be accessed externally
        if !cil_type.is_nested_internal() {
            continue;
        }

        // Check if type has any public methods - if so, skip (it might have an API)
        if cil_type.has_public_methods() {
            continue;
        }

        // This type is infrastructure: nested in <Module>, internal visibility, no public API
        infrastructure_types.push(*type_token);
    }

    // Recursively include nested types within infrastructure types
    // (ConfuserEx nests helper types within its infrastructure types)
    let mut more_to_check = true;
    while more_to_check {
        more_to_check = false;
        let infra_tokens: HashSet<Token> = infrastructure_types.iter().copied().collect();

        for infra_token in &infra_tokens.clone() {
            let Some(infra_type) = types.get(infra_token) else {
                continue;
            };

            // Check nested types within this infrastructure type
            for (_, nested_ref) in infra_type.nested_types.iter() {
                let Some(nested_type) = nested_ref.upgrade() else {
                    continue;
                };

                let nested_token = nested_type.token;
                let nested_rid = nested_token.row();

                // Skip if already in infrastructure list
                if infra_tokens.contains(&nested_token) {
                    continue;
                }

                // Skip if already marked elsewhere
                if already_marked.contains(&nested_rid) {
                    continue;
                }

                // Only if it's also internal with no public methods
                if !nested_type.is_public() && !nested_type.has_public_methods() {
                    infrastructure_types.push(nested_token);
                    more_to_check = true;
                }
            }
        }
    }

    // Store findings
    let infra_count = infrastructure_types.len();
    for token in infrastructure_types {
        findings.protection_infrastructure_types.push(token);
    }

    // Add evidence if infrastructure types were found
    if infra_count > 0 {
        score.add_evidence(DetectionEvidence::ProtectionInfrastructure {
            count: infra_count,
            description: format!("Found {infra_count} types as protection infrastructure"),
            confidence: 20,
        });
    }
}

/// Detects infrastructure fields in `<Module>` that should be removed.
///
/// ConfuserEx adds static fields to `<Module>` for storing decrypted data:
/// - `byte[]` fields storing decrypted/decompressed data buffers
/// - `Assembly` fields for resource loading
///
/// These fields are detected by:
/// 1. Being static fields in `<Module>` (TypeDef RID 1)
/// 2. Having infrastructure-related types (byte[], Assembly, etc.)
/// 3. Being only accessed by infrastructure methods (protection methods)
///
/// This must run AFTER protection method detection so we know which methods are infrastructure.
fn detect_infrastructure_fields(
    assembly: &CilObject,
    score: &DetectionScore,
    findings: &mut DeobfuscationFindings,
) {
    // Only run if we have strong ConfuserEx detection
    if !findings.has_any_protection() && !findings.has_marker_attributes() {
        return;
    }

    // Collect all infrastructure method tokens for checking field access
    let infrastructure_methods: HashSet<Token> = findings.all_protection_method_tokens();

    // Also include methods in infrastructure types
    let infrastructure_type_tokens: HashSet<Token> = findings
        .protection_infrastructure_types
        .iter()
        .map(|(_, t)| *t)
        .chain(findings.obfuscator_type_tokens.iter().map(|(_, t)| *t))
        .collect();

    // Get fields from <Module> (TypeDef RID 1)
    let Some(tables) = assembly.tables() else {
        return;
    };

    let Some(field_table) = tables.table::<FieldRaw>() else {
        return;
    };

    let Some(typedef_table) = tables.table::<TypeDefRaw>() else {
        return;
    };

    // Get <Module> type's field range
    let Some(module_typedef) = typedef_table.get(1) else {
        return;
    };

    let module_field_start = module_typedef.field_list;
    let module_field_end = if typedef_table.row_count > 1 {
        typedef_table
            .get(2)
            .map_or(field_table.row_count + 1, |next| next.field_list)
    } else {
        field_table.row_count + 1
    };

    let mut infrastructure_fields: Vec<Token> = Vec::new();

    // Check each field in <Module>
    for field_rid in module_field_start..module_field_end {
        let Some(field) = field_table.get(field_rid) else {
            continue;
        };

        let field_token = Token::from_parts(TableId::Field, field_rid);

        // Skip fields already marked as constant data
        if findings
            .constant_data_fields
            .iter()
            .any(|(_, t)| *t == field_token)
        {
            continue;
        }

        // Check if field type is infrastructure-related
        let is_infrastructure_type = is_infrastructure_field_type(assembly, &field);

        if !is_infrastructure_type {
            continue;
        }

        // Check if field is only accessed by infrastructure methods
        let only_infra_access = is_field_only_accessed_by_infrastructure(
            assembly,
            field_token,
            &infrastructure_methods,
            &infrastructure_type_tokens,
        );

        if only_infra_access {
            infrastructure_fields.push(field_token);
        }
    }

    // Store findings
    let field_count = infrastructure_fields.len();
    for token in infrastructure_fields {
        findings.infrastructure_fields.push(token);
    }

    // Add evidence if infrastructure fields were found
    if field_count > 0 {
        score.add_evidence(DetectionEvidence::ProtectionInfrastructure {
            count: field_count,
            description: format!(
                "Found {field_count} fields in <Module> as protection infrastructure"
            ),
            confidence: 15,
        });
    }
}

/// Checks if a field has an infrastructure-related type.
///
/// Infrastructure fields typically are:
/// - `byte[]` (System.Byte[]) - for decrypted data buffers
/// - `System.Reflection.Assembly` - for resource loading
/// - Custom delegate types in infrastructure types
fn is_infrastructure_field_type(assembly: &CilObject, field: &FieldRaw) -> bool {
    let Some(blobs) = assembly.blob() else {
        return false;
    };

    let Ok(sig_data) = blobs.get(field.signature as usize) else {
        return false;
    };

    let Ok(field_sig) = parse_field_signature(sig_data) else {
        return false;
    };

    // Check for byte[] (SzArray of U1)
    if let TypeSignature::SzArray(inner) = &field_sig.base {
        if matches!(*inner.base, TypeSignature::U1) {
            return true;
        }
    }

    // Check for Assembly type reference
    if let TypeSignature::Class(type_token) = &field_sig.base {
        // Check if it's a TypeRef to System.Reflection.Assembly
        if type_token.is_table(TableId::TypeRef) {
            let Some(tables) = assembly.tables() else {
                return false;
            };
            let Some(typeref_table) = tables.table::<TypeRefRaw>() else {
                return false;
            };
            let Some(strings) = assembly.strings() else {
                return false;
            };

            if let Some(type_ref) = typeref_table.get(type_token.row()) {
                let name = strings.get(type_ref.type_name as usize).unwrap_or_default();
                let namespace = strings
                    .get(type_ref.type_namespace as usize)
                    .unwrap_or_default();
                if name == "Assembly" && namespace == "System.Reflection" {
                    return true;
                }
            }
        }
    }

    false
}

/// Checks if a field is only accessed by infrastructure methods.
///
/// A field is considered infrastructure-only if all methods that access it
/// (via ldsfld, stsfld, ldsflda) are either:
/// - In the set of protection methods
/// - In an infrastructure type
/// - The module .cctor (which contains initialization code being cleaned)
fn is_field_only_accessed_by_infrastructure(
    assembly: &CilObject,
    field_token: Token,
    infrastructure_methods: &HashSet<Token>,
    infrastructure_type_tokens: &HashSet<Token>,
) -> bool {
    // Find the module .cctor token
    let cctor_token = assembly.methods().iter().find_map(|entry| {
        let method = entry.value();
        if method.is_cctor() {
            if let Some(owner) = method.declaring_type_rc() {
                if owner.name == "<Module>" {
                    return Some(method.token);
                }
            }
        }
        None
    });

    let mut accessed_by_any = false;
    let mut accessed_by_non_infra = false;

    for method_entry in assembly.methods() {
        let method = method_entry.value();
        let method_token_val = method.token;

        // Check if this method accesses the field
        let accesses_field = method.instructions().any(|instr| {
            // Check for field access instructions
            if instr.mnemonic == "ldsfld"
                || instr.mnemonic == "stsfld"
                || instr.mnemonic == "ldsflda"
            {
                if let Operand::Token(t) = &instr.operand {
                    return *t == field_token;
                }
            }
            false
        });

        if accesses_field {
            accessed_by_any = true;

            // Check if method is infrastructure
            let is_infra_method = infrastructure_methods.contains(&method_token_val)
                || Some(method_token_val) == cctor_token;

            // Check if method is in an infrastructure type
            let is_in_infra_type = method
                .declaring_type
                .get()
                .and_then(CilTypeRef::upgrade)
                .is_some_and(|owner| infrastructure_type_tokens.contains(&owner.token));

            if !is_infra_method && !is_in_infra_type {
                accessed_by_non_infra = true;
                break;
            }
        }
    }

    // Field is infrastructure-only if it's accessed AND only by infrastructure
    accessed_by_any && !accessed_by_non_infra
}

#[cfg(test)]
mod tests {
    use crate::{
        deobfuscation::obfuscators::confuserex::detection::detect_confuserex, CilObject,
        ValidationConfig,
    };

    #[test]
    fn test_detect_suppress_ildasm_original() -> crate::Result<()> {
        // Original assembly should NOT have SuppressIldasm
        let assembly = CilObject::from_path_with_validation(
            "tests/samples/packers/confuserex/original.exe",
            ValidationConfig::analysis(),
        )?;
        let (_, findings) = detect_confuserex(&assembly);
        assert!(
            !findings.has_suppress_ildasm(),
            "Original should not have SuppressIldasm"
        );
        assert!(findings.suppress_ildasm_token.is_none());
        Ok(())
    }

    #[test]
    fn test_detect_suppress_ildasm_minimal() -> crate::Result<()> {
        // Minimal protection may or may not have SuppressIldasm depending on config
        let assembly = CilObject::from_path_with_validation(
            "tests/samples/packers/confuserex/mkaring_minimal.exe",
            ValidationConfig::analysis(),
        )?;
        let (_, findings) = detect_confuserex(&assembly);
        // Just verify we don't crash - minimal may or may not have this
        println!(
            "Minimal: suppress_ildasm={}, token={:?}",
            findings.has_suppress_ildasm(),
            findings.suppress_ildasm_token
        );
        Ok(())
    }

    #[test]
    fn test_detect_suppress_ildasm_maximum() -> crate::Result<()> {
        // Maximum protection should have SuppressIldasm
        let assembly = CilObject::from_path_with_validation(
            "tests/samples/packers/confuserex/mkaring_maximum.exe",
            ValidationConfig::analysis(),
        )?;
        let (score, findings) = detect_confuserex(&assembly);
        println!(
            "Maximum: suppress_ildasm={}, token={:?}, score={}",
            findings.has_suppress_ildasm(),
            findings.suppress_ildasm_token,
            score.score()
        );
        // Maximum protection should have SuppressIldasm enabled
        assert!(
            findings.has_suppress_ildasm(),
            "Maximum protection should have SuppressIldasm"
        );
        assert!(findings.suppress_ildasm_token.is_some());
        Ok(())
    }

    #[test]
    fn test_detect_decryptor_methods() -> crate::Result<()> {
        // Maximum protection should have decryptor methods (constants protection)
        let assembly = CilObject::from_path_with_validation(
            "tests/samples/packers/confuserex/mkaring_maximum.exe",
            ValidationConfig::analysis(),
        )?;
        let (_, findings) = detect_confuserex(&assembly);
        println!(
            "Decryptor methods count: {}",
            findings.decryptor_methods.count()
        );
        // Maximum protection with constants enabled should have decryptors
        Ok(())
    }

    #[test]
    fn test_detect_anti_debug() -> crate::Result<()> {
        // Normal protection includes anti-debug
        let assembly = CilObject::from_path_with_validation(
            "tests/samples/packers/confuserex/mkaring_normal.exe",
            ValidationConfig::analysis(),
        )?;
        let (_, findings) = detect_confuserex(&assembly);
        println!(
            "Anti-debug methods count: {}",
            findings.anti_debug_methods.count()
        );
        assert!(
            findings.anti_debug_methods.count() > 0,
            "Normal protection should have anti-debug methods"
        );
        assert!(
            findings.needs_anti_debug_patch(),
            "Should indicate anti-debug patching is needed"
        );
        Ok(())
    }

    #[test]
    fn test_detect_antitamper() -> crate::Result<()> {
        // Maximum protection should have anti-tamper
        let assembly = CilObject::from_path_with_validation(
            "tests/samples/packers/confuserex/mkaring_maximum.exe",
            ValidationConfig::analysis(),
        )?;
        let (score, findings) = detect_confuserex(&assembly);
        println!(
            "Anti-tamper methods: {}, encrypted methods: {}, score: {}",
            findings.anti_tamper_methods.count(),
            findings.encrypted_method_count,
            score.score()
        );
        assert!(
            findings.anti_tamper_methods.count() > 0,
            "Maximum protection should have anti-tamper methods"
        );
        assert!(
            findings.encrypted_method_count > 0,
            "Maximum protection should have encrypted method bodies"
        );
        assert!(
            findings.needs_anti_tamper_decryption(),
            "Should indicate anti-tamper decryption is needed"
        );
        Ok(())
    }

    #[test]
    fn test_detect_original_no_protections() -> crate::Result<()> {
        // Original unobfuscated assembly should have no protections detected
        let assembly = CilObject::from_path_with_validation(
            "tests/samples/packers/confuserex/original.exe",
            ValidationConfig::analysis(),
        )?;
        let (score, findings) = detect_confuserex(&assembly);

        assert_eq!(
            score.score(),
            0,
            "Original should have zero detection score"
        );
        assert!(
            !findings.has_any_protection(),
            "Original should have no protections"
        );
        assert!(!findings.has_invalid_metadata());
        assert!(!findings.has_marker_attributes());
        assert!(!findings.has_suppress_ildasm());
        assert_eq!(findings.anti_tamper_methods.count(), 0);
        assert_eq!(findings.anti_debug_methods.count(), 0);
        assert_eq!(findings.decryptor_methods.count(), 0);

        Ok(())
    }

    #[test]
    fn test_detect_protection_infrastructure_types() -> crate::Result<()> {
        // Maximum protection has nested internal types in <Module> for protection infrastructure
        // Verified via: monodis --typedef and monodis --nested
        // Types 2,3,4,5,9,10,11,12 are nested directly in <Module>
        // Types 6,7,8 are nested within type 5
        let assembly = CilObject::from_path_with_validation(
            "tests/samples/packers/confuserex/mkaring_maximum.exe",
            ValidationConfig::analysis(),
        )?;
        let (score, findings) = detect_confuserex(&assembly);

        // Should detect nested internal infrastructure types
        assert!(
            findings.protection_infrastructure_types.count() >= 8,
            "Should detect at least 8 infrastructure types nested in <Module>, found {}",
            findings.protection_infrastructure_types.count()
        );

        // Should detect protection methods
        assert!(
            findings.decryptor_methods.count() >= 5,
            "Should detect decryptor methods, found {}",
            findings.decryptor_methods.count()
        );

        assert!(
            findings.anti_tamper_methods.count() >= 2,
            "Should detect anti-tamper methods, found {}",
            findings.anti_tamper_methods.count()
        );

        // Should detect constant data infrastructure
        assert!(
            findings.constant_data_types.count() >= 2,
            "Should detect constant data types, found {}",
            findings.constant_data_types.count()
        );

        // Overall score should reflect maximum protection level
        assert!(
            score.score() >= 150,
            "Maximum protection should have high score, found {}",
            score.score()
        );

        Ok(())
    }
}
