//! Shared utilities for obfuscator detection and deobfuscation.
//!
//! This module contains helper functions used across multiple obfuscator
//! implementations. Functions here handle common patterns like attribute
//! detection, token collection, P/Invoke resolution, and name analysis
//! that are shared by ConfuserEx, Obfuscar, BitMono, and future obfuscators.

use std::collections::{HashMap, HashSet};

use crate::{
    cilassembly::CleanupRequest,
    deobfuscation::{
        cleanup::is_entry_point,
        detection::{DetectionEvidence, DetectionScore},
        findings::DeobfuscationFindings,
    },
    metadata::{
        imports::ImportType,
        signatures::{parse_field_signature, TypeSignature},
        tables::{ClassLayoutRaw, CustomAttributeRaw, FieldRaw, MemberRefRaw, TableId, TypeRefRaw},
        token::Token,
    },
    CilObject,
};

/// Checks for `SuppressIldasmAttribute` on the module or assembly.
///
/// This is a common protection used by multiple obfuscators (ConfuserEx, Obfuscar, etc.).
/// If found, the attribute token is stored in `findings.suppress_ildasm_token` and a
/// detection evidence entry is added with the specified `confidence`.
///
/// # Arguments
///
/// * `assembly` - The assembly to check.
/// * `score` - The detection score to add evidence to.
/// * `findings` - The findings to store the attribute token in.
/// * `confidence` - The confidence score to assign (varies by obfuscator context).
pub fn check_suppress_ildasm(
    assembly: &CilObject,
    score: &DetectionScore,
    findings: &mut DeobfuscationFindings,
    confidence: usize,
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
        let is_module_or_assembly =
            attr.parent.tag == TableId::Module || attr.parent.tag == TableId::Assembly;

        if !is_module_or_assembly {
            continue;
        }

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

        if let (Some(name), Some(namespace)) = (type_name, type_namespace) {
            if name == "SuppressIldasmAttribute" && namespace == "System.Runtime.CompilerServices" {
                findings.suppress_ildasm_token = Some(attr.token);

                score.add(DetectionEvidence::Attribute {
                    name: format!("{namespace}.{name}"),
                    confidence,
                });
                return;
            }
        }
    }
}

/// Gets the size of a field's data based on its backing type's ClassLayout entry.
///
/// For FieldRVA entries, the field's type is a compiler-generated value type with
/// explicit layout (e.g., `__StaticArrayInitTypeSize=16`). The size is defined in
/// the ClassLayout table.
///
/// # Arguments
///
/// * `assembly` - The assembly containing the field.
/// * `field_rid` - The raw 1-based row index into the Field table.
///
/// # Returns
///
/// The field data size in bytes, or `None` if the size cannot be determined.
pub fn get_field_data_size(assembly: &CilObject, field_rid: u32) -> Option<usize> {
    let tables = assembly.tables()?;
    let blobs = assembly.blob()?;

    let field_table = tables.table::<FieldRaw>()?;
    let field_row = field_table.get(field_rid)?;

    let sig_data = blobs.get(field_row.signature as usize).ok()?;
    let field_sig = parse_field_signature(sig_data).ok()?;

    match &field_sig.base {
        TypeSignature::ValueType(token) => {
            // Only TypeDef tokens have ClassLayout entries
            if token.table() != 0x02 {
                return None;
            }
            let type_rid = token.row();

            let class_layout_table = tables.table::<ClassLayoutRaw>()?;
            for layout in class_layout_table {
                if layout.parent == type_rid {
                    return Some(layout.class_size as usize);
                }
            }
            None
        }
        _ => None,
    }
}

/// Collects tokens from a `boxcar::Vec<Token>` into a `HashSet`.
pub(crate) fn collect_tokens(tokens: &boxcar::Vec<Token>) -> HashSet<Token> {
    tokens.iter().map(|(_, t)| *t).collect()
}

/// Collects tokens from multiple `boxcar::Vec<Token>` sources into a single `HashSet`.
pub(crate) fn collect_all_tokens(sources: &[&boxcar::Vec<Token>]) -> HashSet<Token> {
    let mut set = HashSet::new();
    for source in sources {
        for (_, t) in *source {
            set.insert(*t);
        }
    }
    set
}

/// Builds a map from MethodDef token to P/Invoke import name.
///
/// This is necessary because some obfuscators rename P/Invoke methods while keeping
/// the actual import name (in the ImplMap table) intact. For example, a method
/// named "VirtualProtect" might be renamed to invisible Unicode characters,
/// but the ImplMap entry still records "VirtualProtect" as the import name.
///
/// Returns a map from MethodDef token to the actual import name.
pub(crate) fn build_pinvoke_import_map(assembly: &CilObject) -> HashMap<Token, String> {
    let mut map = HashMap::new();

    for import_entry in assembly.imports().cil() {
        let import = import_entry.value();

        if let ImportType::Method(method) = &import.import {
            map.insert(method.token, import.name.clone());
        }
    }

    map
}

/// Resolves a call target token to a method name.
///
/// For MethodDef tokens that are P/Invoke methods, returns the actual import name
/// from the ImplMap table (not the potentially obfuscated method name).
/// For other tokens, delegates to `CilObject::resolve_method_name()`.
pub(crate) fn resolve_call_target(
    assembly: &CilObject,
    token: Token,
    import_map: &HashMap<Token, String>,
) -> Option<String> {
    if token.table() == 0x06 {
        if let Some(import_name) = import_map.get(&token) {
            return Some(import_name.clone());
        }
    }
    assembly.resolve_method_name(token)
}

/// Checks if a name appears to be obfuscated.
///
/// Detects names containing invisible Unicode characters, private use area code points,
/// bidirectional overrides, and ASCII spaces in identifiers (all strong obfuscation signals).
pub(crate) fn is_obfuscated_name(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }

    // ASCII spaces in identifiers are a strong obfuscation signal (BitMono FullRenamer).
    // Valid .NET identifiers never contain spaces.
    if name.contains(' ') {
        return true;
    }

    for c in name.chars() {
        match c {
            '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{206F}'
            | '\u{FEFF}'
            | '\u{E000}'..='\u{F8FF}' => return true,
            c if !c.is_ascii() => {
                if !c.is_alphabetic() {
                    return true;
                }
            }
            _ => {}
        }
    }

    false
}

/// Checks if a name is a special .NET name that should not be renamed.
///
/// Protects constructors, module types, CLR-internal angle-bracket names,
/// and property/event accessor prefixes (get_, set_, add_, remove_).
pub(crate) fn is_special_name(name: &str) -> bool {
    if name == ".ctor" || name == ".cctor" {
        return true;
    }

    if name == "<Module>" || name == "<PrivateImplementationDetails>" {
        return true;
    }

    // Angle-bracket-wrapped names are CLR-internal (e.g. "<Generic Parameter>").
    // Check this before the space filter since some legitimate CLR names contain spaces.
    if name.starts_with('<') && name.ends_with('>') {
        return true;
    }

    // Names containing spaces cannot be legitimate property/event accessors.
    // This prevents BitMono FullRenamer names like "get_Syntax get_AllowedCaller..."
    // from being incorrectly protected by the prefix checks below.
    if name.contains(' ') {
        return false;
    }

    if name.starts_with("get_")
        || name.starts_with("set_")
        || name.starts_with("add_")
        || name.starts_with("remove_")
    {
        return true;
    }

    false
}

/// Finds the `.cctor` (static constructor) for the declaring type of a given method.
///
/// Looks up the method by token, finds its declaring type, then searches
/// for a `.cctor` method within that type.
///
/// # Returns
///
/// The `.cctor` method token if found, `None` otherwise.
/// Validates a cleanup request by checking for entry point methods.
///
/// Logs warnings for any methods in the cleanup request that are protected
/// entry points (assembly entry point, public methods in non-aggressive mode,
/// static constructors).
pub(crate) fn validate_cleanup_request(
    request: &CleanupRequest,
    assembly: &CilObject,
    aggressive: bool,
) {
    for method_token in request.methods() {
        if is_entry_point(assembly, *method_token, aggressive) {
            log::warn!(
                "Cleanup request contains entry point method 0x{:08X} — skipping would be safer",
                method_token.value()
            );
        }
    }
}

/// Finds the `.cctor` (static constructor) for the declaring type of a given method.
///
/// Looks up the method by token, finds its declaring type, then searches
/// for a `.cctor` method within that type.
///
/// # Returns
///
/// The `.cctor` method token if found, `None` otherwise.
pub(crate) fn find_type_cctor(assembly: &CilObject, method_token: Token) -> Option<Token> {
    let method = assembly.method(&method_token)?;
    let cil_type = method.declaring_type_rc()?;
    let result = cil_type
        .query_methods()
        .static_constructors()
        .find_first()
        .map(|m| m.token);
    result
}
