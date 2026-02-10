//! Reference scanning for orphan detection.
//!
//! This module provides functions to scan method bodies and metadata tables
//! to determine which entries (TypeRef, MemberRef, TypeSpec) are still
//! referenced and which can be safely removed.
//!
//! # Design
//!
//! Reference scanning is performed in two phases:
//!
//! 1. **Method body scanning**: Parses IL instructions in all method bodies
//!    (both original and regenerated) to collect token operands.
//!
//! 2. **Metadata table scanning**: Scans metadata tables that can reference
//!    TypeRefs, MemberRefs, and TypeSpecs (extends clauses, interfaces, etc.)
//!
//! # Regenerated Methods
//!
//! After SSA-based code optimization, method bodies may be regenerated with
//! different IL instructions. This module handles both:
//!
//! - **Original methods**: Read from the source file using their RVA
//! - **Regenerated methods**: Read from `CilAssembly.changes.method_bodies`
//!   (identified by placeholder RVAs >= 0xF000_0000)
//!
//! # Usage
//!
//! These functions are called from [`super::orphans`] to determine which
//! metadata entries can be removed without breaking the assembly.

use std::collections::HashSet;

use crate::{
    assembly::{decode_blocks, Operand},
    cilassembly::{modifications::TableModifications, operation::Operation, CilAssembly},
    metadata::{
        method::MethodBody,
        signatures::{
            parse_field_signature, parse_local_var_signature, parse_method_signature,
            parse_property_signature, parse_type_spec_signature, CustomModifier,
            SignatureLocalVariable, SignatureParameter, TypeSignature,
        },
        streams::Blob,
        tables::{
            CustomAttributeRaw, FieldRaw, GenericParamConstraintRaw, InterfaceImplRaw,
            MemberRefRaw, MethodDefRaw, MethodSpecRaw, PropertyRaw, StandAloneSigRaw,
            TableDataOwned, TableId, TypeDefRaw, TypeRefRaw, TypeSpecRaw,
        },
        token::Token,
    },
    Result,
};

/// Placeholder RVA threshold - RVAs at or above this value are placeholder RVAs
/// that point to regenerated method bodies stored in AssemblyChanges.
const PLACEHOLDER_RVA_THRESHOLD: u32 = 0xF000_0000;

/// Checks if a table row has been marked for deletion in AssemblyChanges.
///
/// This is used to skip rows that have been deleted during earlier cleanup
/// phases when scanning for references.
fn is_row_deleted(assembly: &CilAssembly, table_id: TableId, rid: u32) -> bool {
    if let Some(table_mods) = assembly.changes().table_changes.get(&table_id) {
        match table_mods {
            TableModifications::Sparse { operations, .. } => {
                // Check if there's a Delete operation for this RID
                for op in operations.iter().rev() {
                    if op.get_rid() == rid {
                        return matches!(op.operation, Operation::Delete(_));
                    }
                }
            }
            TableModifications::Replaced(rows) => {
                // For replaced tables, check if the row index exists
                // (though this is less common for deletions)
                return rid as usize > rows.len();
            }
        }
    }
    false
}

/// Gets the effective RVA for a MethodDef row, checking for updates.
///
/// If the MethodDef row has been updated (e.g., after code regeneration),
/// this returns the updated RVA from the operation. Otherwise returns the
/// original RVA from the table.
///
/// # Arguments
///
/// * `assembly` - The CilAssembly containing changes.
/// * `rid` - The MethodDef RID to look up.
/// * `original_rva` - The original RVA from the table.
///
/// # Returns
///
/// The effective RVA (updated if available, otherwise original).
fn get_effective_method_rva(assembly: &CilAssembly, rid: u32, original_rva: u32) -> u32 {
    // Check if there's an Update operation for this MethodDef
    if let Some(table_mods) = assembly.changes().table_changes.get(&TableId::MethodDef) {
        match table_mods {
            TableModifications::Sparse { operations, .. } => {
                // Search operations in reverse (most recent first) for this RID
                for op in operations.iter().rev() {
                    if op.get_rid() == rid {
                        match &op.operation {
                            Operation::Update(_, TableDataOwned::MethodDef(updated)) => {
                                return updated.rva;
                            }
                            Operation::Delete(_) => {
                                // Method was deleted, skip it
                                return 0;
                            }
                            _ => {}
                        }
                    }
                }
            }
            TableModifications::Replaced(rows) => {
                // Full replacement - find the row by index (RID - 1)
                if let Some(TableDataOwned::MethodDef(row)) = rows.get((rid - 1) as usize) {
                    return row.rva;
                }
            }
        }
    }

    original_rva
}

/// Scans a method body's bytes and collects all referenced tokens.
///
/// This helper parses the method body header, decodes the IL instructions,
/// and extracts any token operands from the instructions.
///
/// # Arguments
///
/// * `data` - The method body bytes (starting with the header).
/// * `base_rva` - The RVA of the method body (used for relative addressing in IL).
/// * `referenced` - Output set to add discovered tokens to.
fn scan_method_body_bytes(data: &[u8], base_rva: usize, referenced: &mut HashSet<Token>) {
    let Ok(body) = MethodBody::from(data) else {
        return;
    };

    // Get the code bytes (after the header)
    let code_start = body.size_header;
    let code_end = code_start + body.size_code;
    if code_end > data.len() {
        return;
    }

    // Decode basic blocks and collect tokens from instructions
    let code_rva = base_rva + body.size_header;
    if let Ok(blocks) = decode_blocks(&data[code_start..code_end], 0, code_rva, None) {
        for block in &blocks {
            for instr in &block.instructions {
                if let Operand::Token(token) = instr.operand {
                    referenced.insert(token);
                }
            }
        }
    }
}

/// Collects StandAloneSig RIDs referenced by method body headers.
///
/// Scans all method bodies (original and regenerated) and extracts the
/// LocalVarSigTok from fat headers. Returns the set of StandAloneSig RIDs
/// that are actually used by method bodies.
fn collect_referenced_standalonesig_rids(assembly: &CilAssembly) -> HashSet<u32> {
    let mut referenced = HashSet::new();

    let view = assembly.view();
    let Some(tables) = view.tables() else {
        return referenced;
    };

    let Some(methoddef_table) = tables.table::<MethodDefRaw>() else {
        return referenced;
    };

    let file = view.file();
    let original_data = file.data();

    for methoddef in methoddef_table.iter() {
        let effective_rva = get_effective_method_rva(assembly, methoddef.rid, methoddef.rva);

        if effective_rva == 0 {
            continue;
        }

        // Parse method body to get LocalVarSigTok
        if effective_rva >= PLACEHOLDER_RVA_THRESHOLD {
            // Regenerated method body
            if let Some(body_bytes) = assembly.changes().get_method_body(effective_rva) {
                if let Ok(body) = MethodBody::from(body_bytes.as_slice()) {
                    if body.local_var_sig_token != 0 {
                        let sig_token = Token::new(body.local_var_sig_token);
                        if sig_token.is_table(TableId::StandAloneSig) {
                            referenced.insert(sig_token.row());
                        }
                    }
                }
            }
        } else {
            // Original method body
            let Ok(offset) = file.rva_to_offset(effective_rva as usize) else {
                continue;
            };
            if offset < original_data.len() {
                if let Ok(body) = MethodBody::from(&original_data[offset..]) {
                    if body.local_var_sig_token != 0 {
                        let sig_token = Token::new(body.local_var_sig_token);
                        if sig_token.is_table(TableId::StandAloneSig) {
                            referenced.insert(sig_token.row());
                        }
                    }
                }
            }
        }
    }

    referenced
}

/// Scans all method bodies and collects tokens referenced from IL instructions.
///
/// This function handles both original method bodies (from the source file) and
/// regenerated method bodies (stored in AssemblyChanges after SSA optimization).
/// It checks for MethodDef row updates to get the correct RVA (placeholder for
/// regenerated methods, or original for unchanged methods).
///
/// Returns a set of all referenced tokens (TypeRef, TypeDef, MemberRef, MethodDef,
/// MethodSpec, TypeSpec, Field, etc.)
pub fn scan_method_body_tokens(assembly: &CilAssembly) -> Result<HashSet<Token>> {
    let mut referenced = HashSet::new();

    let view = assembly.view();
    let Some(tables) = view.tables() else {
        return Ok(referenced);
    };

    let Some(methoddef_table) = tables.table::<MethodDefRaw>() else {
        return Ok(referenced);
    };

    let file = view.file();
    let original_data = file.data();

    for methoddef in methoddef_table.iter() {
        // Get the effective RVA (may be updated with placeholder if regenerated)
        let effective_rva = get_effective_method_rva(assembly, methoddef.rid, methoddef.rva);

        // Skip methods without RVA (abstract, extern, or deleted)
        if effective_rva == 0 {
            continue;
        }

        // Check if this method has a regenerated body (placeholder RVA)
        if effective_rva >= PLACEHOLDER_RVA_THRESHOLD {
            // Get regenerated method body from AssemblyChanges
            if let Some(body_bytes) = assembly.changes().get_method_body(effective_rva) {
                scan_method_body_bytes(body_bytes, 0, &mut referenced);
            }
        } else {
            // Original method body - read from file
            let Ok(offset) = file.rva_to_offset(effective_rva as usize) else {
                continue;
            };

            if offset >= original_data.len() {
                continue;
            }

            scan_method_body_bytes(
                &original_data[offset..],
                effective_rva as usize,
                &mut referenced,
            );
        }
    }

    Ok(referenced)
}

/// Scans metadata tables to collect TypeRef RIDs that are referenced.
///
/// Collects references from:
/// - TypeDef.extends (base class)
/// - InterfaceImpl.interface
/// - MemberRef.class (when pointing to TypeRef)
/// - GenericParamConstraint.constraint
/// - CustomAttribute.constructor (indirectly via MemberRef)
pub fn scan_typeref_metadata_refs(assembly: &CilAssembly) -> Result<HashSet<u32>> {
    let mut referenced_rids = HashSet::new();

    let view = assembly.view();
    let Some(tables) = view.tables() else {
        return Ok(referenced_rids);
    };

    // TypeDef.extends - base class references
    if let Some(typedef_table) = tables.table::<TypeDefRaw>() {
        for typedef in typedef_table.iter() {
            if typedef.extends.token.is_table(TableId::TypeRef) {
                referenced_rids.insert(typedef.extends.token.row());
            }
        }
    }

    // InterfaceImpl.interface
    if let Some(interfaceimpl_table) = tables.table::<InterfaceImplRaw>() {
        for impl_ in interfaceimpl_table.iter() {
            if impl_.interface.token.is_table(TableId::TypeRef) {
                referenced_rids.insert(impl_.interface.token.row());
            }
        }
    }

    // MemberRef.class - declaring type of member references (skip deleted rows)
    if let Some(memberref_table) = tables.table::<MemberRefRaw>() {
        for memberref in memberref_table.iter() {
            // Skip MemberRefs that have been deleted in earlier cleanup phases
            if is_row_deleted(assembly, TableId::MemberRef, memberref.rid) {
                continue;
            }
            if memberref.class.token.is_table(TableId::TypeRef) {
                referenced_rids.insert(memberref.class.token.row());
            }
        }
    }

    // GenericParamConstraint - type constraints
    if let Some(constraint_table) = tables.table::<GenericParamConstraintRaw>() {
        for constraint in constraint_table.iter() {
            if constraint.constraint.token.is_table(TableId::TypeRef) {
                referenced_rids.insert(constraint.constraint.token.row());
            }
        }
    }

    // CustomAttribute.constructor - when it's a MemberRef on a TypeRef
    if let Some(attr_table) = tables.table::<CustomAttributeRaw>() {
        if let Some(memberref_table) = tables.table::<MemberRefRaw>() {
            for attr in attr_table.iter() {
                if attr.constructor.token.is_table(TableId::MemberRef) {
                    let memberref_rid = attr.constructor.token.row();
                    // Skip if the MemberRef has been deleted
                    if is_row_deleted(assembly, TableId::MemberRef, memberref_rid) {
                        continue;
                    }
                    if let Some(memberref) = memberref_table.get(memberref_rid) {
                        if memberref.class.token.is_table(TableId::TypeRef) {
                            referenced_rids.insert(memberref.class.token.row());
                        }
                    }
                }
            }
        }
    }

    Ok(referenced_rids)
}

/// Scans metadata tables to collect MemberRef RIDs that are referenced.
///
/// Collects references from:
/// - CustomAttribute.constructor
/// - MethodSpec.method
pub fn scan_memberref_metadata_refs(assembly: &CilAssembly) -> Result<HashSet<u32>> {
    let mut referenced_rids = HashSet::new();

    let view = assembly.view();
    let Some(tables) = view.tables() else {
        return Ok(referenced_rids);
    };

    // CustomAttribute.constructor
    if let Some(attr_table) = tables.table::<CustomAttributeRaw>() {
        for attr in attr_table.iter() {
            if attr.constructor.token.is_table(TableId::MemberRef) {
                referenced_rids.insert(attr.constructor.token.row());
            }
        }
    }

    // MethodSpec.method
    if let Some(methodspec_table) = tables.table::<MethodSpecRaw>() {
        for spec in methodspec_table.iter() {
            if spec.method.token.is_table(TableId::MemberRef) {
                referenced_rids.insert(spec.method.token.row());
            }
        }
    }

    Ok(referenced_rids)
}

/// Scans metadata tables to collect TypeSpec RIDs that are referenced.
///
/// Collects references from:
/// - MemberRef.class
/// - InterfaceImpl.interface
/// - GenericParamConstraint.constraint
/// - TypeDef.extends
pub fn scan_typespec_metadata_refs(assembly: &CilAssembly) -> Result<HashSet<u32>> {
    let mut referenced_rids = HashSet::new();

    let view = assembly.view();
    let Some(tables) = view.tables() else {
        return Ok(referenced_rids);
    };

    // MemberRef.class
    if let Some(memberref_table) = tables.table::<MemberRefRaw>() {
        for memberref in memberref_table.iter() {
            if memberref.class.token.is_table(TableId::TypeSpec) {
                referenced_rids.insert(memberref.class.token.row());
            }
        }
    }

    // InterfaceImpl.interface
    if let Some(interfaceimpl_table) = tables.table::<InterfaceImplRaw>() {
        for impl_ in interfaceimpl_table.iter() {
            if impl_.interface.token.is_table(TableId::TypeSpec) {
                referenced_rids.insert(impl_.interface.token.row());
            }
        }
    }

    // GenericParamConstraint.constraint
    if let Some(constraint_table) = tables.table::<GenericParamConstraintRaw>() {
        for constraint in constraint_table.iter() {
            if constraint.constraint.token.is_table(TableId::TypeSpec) {
                referenced_rids.insert(constraint.constraint.token.row());
            }
        }
    }

    // TypeDef.extends
    if let Some(typedef_table) = tables.table::<TypeDefRaw>() {
        for typedef in typedef_table.iter() {
            if typedef.extends.token.is_table(TableId::TypeSpec) {
                referenced_rids.insert(typedef.extends.token.row());
            }
        }
    }

    Ok(referenced_rids)
}

/// Extracts TypeRef RIDs from a TypeSignature recursively.
///
/// TypeRef tokens can appear in Class/ValueType type signatures and in
/// custom modifiers. This function walks the type signature tree and
/// collects all embedded TypeRef RIDs.
fn collect_typerefs_from_type(sig: &TypeSignature, referenced: &mut HashSet<u32>) {
    match sig {
        // Direct type references
        TypeSignature::Class(token) | TypeSignature::ValueType(token) => {
            if token.is_table(TableId::TypeRef) {
                referenced.insert(token.row());
            }
        }

        // Recursive types
        TypeSignature::SzArray(arr) => {
            for modifier in &arr.modifiers {
                collect_typerefs_from_modifier(modifier, referenced);
            }
            collect_typerefs_from_type(&arr.base, referenced);
        }
        TypeSignature::Array(arr) => {
            collect_typerefs_from_type(&arr.base, referenced);
        }
        TypeSignature::Ptr(ptr) => {
            for modifier in &ptr.modifiers {
                collect_typerefs_from_modifier(modifier, referenced);
            }
            collect_typerefs_from_type(&ptr.base, referenced);
        }
        TypeSignature::ByRef(inner) | TypeSignature::Pinned(inner) => {
            collect_typerefs_from_type(inner, referenced);
        }

        // Generic instantiation - base type + type arguments
        TypeSignature::GenericInst(base, args) => {
            collect_typerefs_from_type(base, referenced);
            for arg in args {
                collect_typerefs_from_type(arg, referenced);
            }
        }

        // Custom modifiers
        TypeSignature::ModifiedRequired(modifiers) | TypeSignature::ModifiedOptional(modifiers) => {
            for modifier in modifiers {
                collect_typerefs_from_modifier(modifier, referenced);
            }
        }

        // Function pointer - method signature embedded
        TypeSignature::FnPtr(method_sig) => {
            collect_typerefs_from_parameter(&method_sig.return_type, referenced);
            for param in &method_sig.params {
                collect_typerefs_from_parameter(param, referenced);
            }
        }

        // Primitive and simple types - no tokens
        TypeSignature::Void
        | TypeSignature::Boolean
        | TypeSignature::Char
        | TypeSignature::I1
        | TypeSignature::U1
        | TypeSignature::I2
        | TypeSignature::U2
        | TypeSignature::I4
        | TypeSignature::U4
        | TypeSignature::I8
        | TypeSignature::U8
        | TypeSignature::R4
        | TypeSignature::R8
        | TypeSignature::I
        | TypeSignature::U
        | TypeSignature::String
        | TypeSignature::Object
        | TypeSignature::TypedByRef
        | TypeSignature::GenericParamType(_)
        | TypeSignature::GenericParamMethod(_)
        | TypeSignature::Sentinel
        | TypeSignature::Internal
        | TypeSignature::Unknown
        | TypeSignature::Type
        | TypeSignature::Boxed
        | TypeSignature::Field
        | TypeSignature::Modifier
        | TypeSignature::Reserved => {}
    }
}

/// Extracts TypeRef RIDs from a custom modifier.
fn collect_typerefs_from_modifier(modifier: &CustomModifier, referenced: &mut HashSet<u32>) {
    if modifier.modifier_type.is_table(TableId::TypeRef) {
        referenced.insert(modifier.modifier_type.row());
    }
}

/// Extracts TypeRef RIDs from a parameter (method return type or parameter).
fn collect_typerefs_from_parameter(param: &SignatureParameter, referenced: &mut HashSet<u32>) {
    for modifier in &param.modifiers {
        collect_typerefs_from_modifier(modifier, referenced);
    }
    collect_typerefs_from_type(&param.base, referenced);
}

/// Extracts TypeRef RIDs from a local variable.
fn collect_typerefs_from_local(local: &SignatureLocalVariable, referenced: &mut HashSet<u32>) {
    for modifier in &local.modifiers {
        collect_typerefs_from_modifier(modifier, referenced);
    }
    collect_typerefs_from_type(&local.base, referenced);
}

/// Scans all signature blobs in metadata tables to collect TypeRef RIDs.
///
/// This function scans signatures from:
/// - MethodDef.signature (method signatures)
/// - Field.signature (field signatures)
/// - MemberRef.signature (member reference signatures)
/// - StandAloneSig.signature (local variable signatures)
/// - TypeSpec.signature (type specification signatures)
/// - Property.type (property signatures)
///
/// Note: MethodSpec.instantiation contains only type arguments, which are
/// handled separately through the TypeSpec signature parser.
pub fn scan_signature_typeref_refs(assembly: &CilAssembly) -> Result<HashSet<u32>> {
    let mut referenced_rids = HashSet::new();

    let view = assembly.view();
    let Some(tables) = view.tables() else {
        return Ok(referenced_rids);
    };

    let Some(blob_heap) = view.blobs() else {
        return Ok(referenced_rids);
    };

    // MethodDef signatures
    if let Some(methoddef_table) = tables.table::<MethodDefRaw>() {
        for methoddef in methoddef_table.iter() {
            scan_method_signature_blob(blob_heap, methoddef.signature, &mut referenced_rids);
        }
    }

    // Field signatures
    if let Some(field_table) = tables.table::<FieldRaw>() {
        for field in field_table.iter() {
            scan_field_signature_blob(blob_heap, field.signature, &mut referenced_rids);
        }
    }

    // MemberRef signatures - skip deleted rows
    if let Some(memberref_table) = tables.table::<MemberRefRaw>() {
        for memberref in memberref_table.iter() {
            // Skip MemberRefs that have been deleted in earlier cleanup phases
            if is_row_deleted(assembly, TableId::MemberRef, memberref.rid) {
                continue;
            }
            // MemberRef can have either method or field signature
            // Try method first (more common), then field
            if !scan_method_signature_blob(blob_heap, memberref.signature, &mut referenced_rids) {
                scan_field_signature_blob(blob_heap, memberref.signature, &mut referenced_rids);
            }
        }
    }

    // StandAloneSig signatures (local variables) - only scan those actually referenced
    // by method bodies. Regenerated methods may not use their original signatures.
    let referenced_sigs = collect_referenced_standalonesig_rids(assembly);
    if let Some(standalonesig_table) = tables.table::<StandAloneSigRaw>() {
        for sig in standalonesig_table.iter() {
            // Only scan StandAloneSigs that are referenced by current method bodies
            if referenced_sigs.contains(&sig.rid) {
                scan_local_var_signature_blob(blob_heap, sig.signature, &mut referenced_rids);
            }
        }
    }

    // TypeSpec signatures
    if let Some(typespec_table) = tables.table::<TypeSpecRaw>() {
        for typespec in typespec_table.iter() {
            scan_typespec_signature_blob(blob_heap, typespec.signature, &mut referenced_rids);
        }
    }

    // Property signatures
    if let Some(property_table) = tables.table::<PropertyRaw>() {
        for property in property_table.iter() {
            scan_property_signature_blob(blob_heap, property.signature, &mut referenced_rids);
        }
    }

    Ok(referenced_rids)
}

/// Scans a method signature blob for TypeRef references.
/// Returns true if the blob was successfully parsed as a method signature.
fn scan_method_signature_blob(
    blob_heap: &Blob<'_>,
    blob_index: u32,
    referenced: &mut HashSet<u32>,
) -> bool {
    let Ok(blob_data) = blob_heap.get(blob_index as usize) else {
        return false;
    };

    let Ok(sig) = parse_method_signature(blob_data) else {
        return false;
    };

    collect_typerefs_from_parameter(&sig.return_type, referenced);
    for param in &sig.params {
        collect_typerefs_from_parameter(param, referenced);
    }

    true
}

/// Scans a field signature blob for TypeRef references.
/// Returns true if the blob was successfully parsed as a field signature.
fn scan_field_signature_blob(
    blob_heap: &Blob<'_>,
    blob_index: u32,
    referenced: &mut HashSet<u32>,
) -> bool {
    let Ok(blob_data) = blob_heap.get(blob_index as usize) else {
        return false;
    };

    let Ok(sig) = parse_field_signature(blob_data) else {
        return false;
    };

    for modifier in &sig.modifiers {
        collect_typerefs_from_modifier(modifier, referenced);
    }
    collect_typerefs_from_type(&sig.base, referenced);

    true
}

/// Scans a local variable signature blob for TypeRef references.
fn scan_local_var_signature_blob(
    blob_heap: &Blob<'_>,
    blob_index: u32,
    referenced: &mut HashSet<u32>,
) {
    let Ok(blob_data) = blob_heap.get(blob_index as usize) else {
        return;
    };

    let Ok(sig) = parse_local_var_signature(blob_data) else {
        return;
    };

    for local in &sig.locals {
        collect_typerefs_from_local(local, referenced);
    }
}

/// Scans a TypeSpec signature blob for TypeRef references.
fn scan_typespec_signature_blob(
    blob_heap: &Blob<'_>,
    blob_index: u32,
    referenced: &mut HashSet<u32>,
) {
    let Ok(blob_data) = blob_heap.get(blob_index as usize) else {
        return;
    };

    let Ok(sig) = parse_type_spec_signature(blob_data) else {
        return;
    };

    collect_typerefs_from_type(&sig.base, referenced);
}

/// Scans a property signature blob for TypeRef references.
fn scan_property_signature_blob(
    blob_heap: &Blob<'_>,
    blob_index: u32,
    referenced: &mut HashSet<u32>,
) {
    let Ok(blob_data) = blob_heap.get(blob_index as usize) else {
        return;
    };

    let Ok(sig) = parse_property_signature(blob_data) else {
        return;
    };

    for modifier in &sig.modifiers {
        collect_typerefs_from_modifier(modifier, referenced);
    }
    collect_typerefs_from_type(&sig.base, referenced);
    for param in &sig.params {
        collect_typerefs_from_parameter(param, referenced);
    }
}

/// Removes TypeRef entries that are not referenced by any code or metadata.
///
/// Scans method bodies, metadata tables, and signature blobs to find referenced
/// TypeRefs, then removes any TypeRef that is not in the referenced set.
pub fn remove_unreferenced_typerefs(assembly: &mut CilAssembly) -> Result<usize> {
    // Collect all referenced TypeRef RIDs
    let mut referenced_rids = HashSet::new();

    // From method bodies (IL token operands)
    let body_tokens = scan_method_body_tokens(assembly)?;
    for token in &body_tokens {
        if token.is_table(TableId::TypeRef) {
            referenced_rids.insert(token.row());
        }
    }

    // From metadata tables (extends, interfaces, constraints, etc.)
    let metadata_refs = scan_typeref_metadata_refs(assembly)?;
    referenced_rids.extend(metadata_refs);

    // From signature blobs (method sigs, field sigs, local var sigs, etc.)
    let signature_refs = scan_signature_typeref_refs(assembly)?;
    referenced_rids.extend(signature_refs);

    // Also include TypeRefs referenced indirectly through MemberRefs used in code
    let memberref_body_rids: HashSet<u32> = body_tokens
        .iter()
        .filter(|t| t.is_table(TableId::MemberRef))
        .map(|t| t.row())
        .collect();

    {
        let view = assembly.view();
        if let Some(tables) = view.tables() {
            if let Some(memberref_table) = tables.table::<MemberRefRaw>() {
                for memberref in memberref_table.iter() {
                    if memberref_body_rids.contains(&memberref.rid)
                        && memberref.class.token.is_table(TableId::TypeRef)
                    {
                        referenced_rids.insert(memberref.class.token.row());
                    }
                }
            }
        }
    }

    // Get total TypeRef count
    let typeref_count = {
        let view = assembly.view();
        view.tables()
            .and_then(|t| t.table::<TypeRefRaw>())
            .map_or(0, |t| t.row_count)
    };

    // Remove unreferenced TypeRefs (in reverse order)
    let mut removed = 0;
    for rid in (1..=typeref_count).rev() {
        if !referenced_rids.contains(&rid)
            && assembly.table_row_remove(TableId::TypeRef, rid).is_ok()
        {
            removed += 1;
        }
    }

    Ok(removed)
}

/// Removes MemberRef entries that are not referenced by any code or metadata.
///
/// Scans method bodies and metadata tables to find referenced MemberRefs,
/// then removes any MemberRef that is not in the referenced set.
pub fn remove_unreferenced_memberrefs(assembly: &mut CilAssembly) -> Result<usize> {
    // Collect all referenced MemberRef RIDs
    let mut referenced_rids = HashSet::new();

    // From method bodies
    let body_tokens = scan_method_body_tokens(assembly)?;
    for token in &body_tokens {
        if token.is_table(TableId::MemberRef) {
            referenced_rids.insert(token.row());
        }
    }

    // From metadata tables
    let metadata_refs = scan_memberref_metadata_refs(assembly)?;
    referenced_rids.extend(metadata_refs);

    // Also include MemberRefs referenced through MethodSpecs in method bodies
    let methodspec_body_rids: HashSet<u32> = body_tokens
        .iter()
        .filter(|t| t.is_table(TableId::MethodSpec))
        .map(|t| t.row())
        .collect();

    {
        let view = assembly.view();
        if let Some(tables) = view.tables() {
            if let Some(methodspec_table) = tables.table::<MethodSpecRaw>() {
                for spec in methodspec_table.iter() {
                    if methodspec_body_rids.contains(&spec.rid)
                        && spec.method.token.is_table(TableId::MemberRef)
                    {
                        referenced_rids.insert(spec.method.token.row());
                    }
                }
            }
        }
    }

    // Get total MemberRef count
    let memberref_count = {
        let view = assembly.view();
        view.tables()
            .and_then(|t| t.table::<MemberRefRaw>())
            .map_or(0, |t| t.row_count)
    };

    // Remove unreferenced MemberRefs (in reverse order)
    let mut removed = 0;
    for rid in (1..=memberref_count).rev() {
        if !referenced_rids.contains(&rid)
            && assembly.table_row_remove(TableId::MemberRef, rid).is_ok()
        {
            removed += 1;
        }
    }

    Ok(removed)
}

/// Removes TypeSpec entries that are not referenced by any code or metadata.
///
/// Scans method bodies and metadata tables to find referenced TypeSpecs,
/// then removes any TypeSpec that is not in the referenced set.
pub fn remove_unreferenced_typespecs(assembly: &mut CilAssembly) -> Result<usize> {
    // Collect all referenced TypeSpec RIDs
    let mut referenced_rids = HashSet::new();

    // From method bodies
    let body_tokens = scan_method_body_tokens(assembly)?;
    for token in &body_tokens {
        if token.is_table(TableId::TypeSpec) {
            referenced_rids.insert(token.row());
        }
    }

    // From metadata tables
    let metadata_refs = scan_typespec_metadata_refs(assembly)?;
    referenced_rids.extend(metadata_refs);

    // Get total TypeSpec count
    let typespec_count = {
        let view = assembly.view();
        view.tables()
            .and_then(|t| t.table::<TypeSpecRaw>())
            .map_or(0, |t| t.row_count)
    };

    // Remove unreferenced TypeSpecs (in reverse order)
    let mut removed = 0;
    for rid in (1..=typespec_count).rev() {
        if !referenced_rids.contains(&rid)
            && assembly.table_row_remove(TableId::TypeSpec, rid).is_ok()
        {
            removed += 1;
        }
    }

    Ok(removed)
}

#[cfg(test)]
mod tests {
    use crate::metadata::{tables::TableId, token::Token};

    #[test]
    fn test_placeholder_rva_detection() {
        // Placeholder RVAs start at 0xF000_0000
        const { assert!(0xF000_0000 >= super::PLACEHOLDER_RVA_THRESHOLD) };
        const { assert!(0xF000_0001 >= super::PLACEHOLDER_RVA_THRESHOLD) };

        // Normal RVAs are below the threshold
        const { assert!(0x2000 < super::PLACEHOLDER_RVA_THRESHOLD) };
        const { assert!(0x0000_FFFF < super::PLACEHOLDER_RVA_THRESHOLD) };
    }

    #[test]
    fn test_token_table_detection() {
        let typeref_token = Token::new(0x01000005);
        let memberref_token = Token::new(0x0A000010);
        let typespec_token = Token::new(0x1B000003);

        assert!(typeref_token.is_table(TableId::TypeRef));
        assert!(memberref_token.is_table(TableId::MemberRef));
        assert!(typespec_token.is_table(TableId::TypeSpec));
    }
}
