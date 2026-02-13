//! Shared utilities for obfuscator detection and deobfuscation.
//!
//! This module contains helper functions used across multiple obfuscator
//! implementations. Functions here handle common patterns like attribute
//! detection that are shared by ConfuserEx, Obfuscar, and future obfuscators.

use crate::{
    deobfuscation::{
        detection::{DetectionEvidence, DetectionScore},
        findings::DeobfuscationFindings,
    },
    metadata::tables::{CustomAttributeRaw, MemberRefRaw, TableId, TypeRefRaw},
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
