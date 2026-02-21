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

use std::collections::{BTreeSet, HashSet};

use crate::{
    assembly::{decode_blocks, BasicBlock, Operand},
    cilassembly::{
        cleanup::utils::{
            extract_local_var_sig_rid, remove_candidates_not_alive, with_method_body,
        },
        modifications::TableModifications,
        operation::Operation,
        CilAssembly,
    },
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
            TableDataOwned, TableId, TypeDefRaw, TypeSpecRaw,
        },
        token::Token,
    },
};

/// Pre-deletion reference data for cascade-based cleanup.
///
/// Collected **before** entities are deleted, this tracks what tokens the
/// entities being deleted currently reference. After deletion, only entries
/// that appear in this set AND are no longer referenced by surviving entities
/// are cascade-removed.
///
/// This approach is fundamentally safer than garbage-collection-style orphan
/// removal because it never removes pre-existing orphans (which may be used
/// via reflection or dynamic code generation).
pub struct PreDeletionRefs {
    /// Token operands found in method bodies of entities being deleted.
    pub(super) il_tokens: HashSet<Token>,
    /// TypeRef RIDs referenced by signatures and extends clauses of entities being deleted.
    pub(super) typeref_rids: HashSet<u32>,
    /// StandAloneSig RIDs referenced by method bodies of methods being deleted.
    pub(super) standalonesig_rids: BTreeSet<u32>,
}

impl PreDeletionRefs {
    /// Returns the set of IL token operands found in method bodies of entities being deleted.
    #[must_use]
    pub fn il_tokens(&self) -> &HashSet<Token> {
        &self.il_tokens
    }

    /// Returns the set of TypeRef RIDs referenced by signatures and extends clauses.
    #[must_use]
    pub fn typeref_rids(&self) -> &HashSet<u32> {
        &self.typeref_rids
    }

    /// Returns the set of StandAloneSig RIDs referenced by method bodies.
    #[must_use]
    pub fn standalonesig_rids(&self) -> &BTreeSet<u32> {
        &self.standalonesig_rids
    }
}

/// Collects all token references from entities that are about to be deleted.
///
/// Must be called **before** the entities are actually deleted, while their
/// method bodies, signatures, and metadata are still accessible.
///
/// # Arguments
///
/// * `assembly` - The assembly to scan
/// * `methods` - Method tokens that will be deleted
/// * `fields` - Field tokens that will be deleted
/// * `types` - Type tokens that will be deleted
///
/// # Returns
///
/// A [`PreDeletionRefs`] containing all tokens referenced by the entities.
pub fn collect_pre_deletion_references(
    assembly: &CilAssembly,
    methods: &BTreeSet<Token>,
    fields: &BTreeSet<Token>,
    types: &BTreeSet<Token>,
) -> PreDeletionRefs {
    let mut il_tokens = HashSet::new();
    let mut typeref_rids = HashSet::new();
    let mut standalonesig_rids = BTreeSet::new();

    {
        let view = assembly.view();
        let Some(tables) = view.tables() else {
            return PreDeletionRefs {
                il_tokens,
                typeref_rids,
                standalonesig_rids,
            };
        };

        let blob_heap = view.blobs();

        // Scan method bodies and signatures of methods being deleted
        if let Some(methoddef_table) = tables.table::<MethodDefRaw>() {
            for methoddef in methoddef_table {
                let method_token = Token::from_parts(TableId::MethodDef, methoddef.rid);
                if !methods.contains(&method_token) {
                    continue;
                }

                // Get effective RVA (may be updated with placeholder if regenerated)
                let effective_rva =
                    get_effective_method_rva(assembly, methoddef.rid, methoddef.rva);
                if effective_rva == 0 {
                    continue;
                }

                // Scan method body IL for token operands and collect LocalVarSigTok
                with_method_body(assembly, effective_rva, &mut |data, base_rva| {
                    scan_method_body_bytes(data, base_rva, &mut il_tokens);
                    if let Some(sig_rid) = extract_local_var_sig_rid(data) {
                        standalonesig_rids.insert(sig_rid);
                    }
                });

                // Scan method signature for TypeRef references
                if let Some(blob) = &blob_heap {
                    scan_method_signature_blob(blob, methoddef.signature, &mut typeref_rids);
                }
            }
        }

        // Scan field signatures of fields being deleted
        if let Some(field_table) = tables.table::<FieldRaw>() {
            if let Some(blob) = &blob_heap {
                for field in field_table {
                    let field_token = Token::from_parts(TableId::Field, field.rid);
                    if !fields.contains(&field_token) {
                        continue;
                    }
                    scan_field_signature_blob(blob, field.signature, &mut typeref_rids);
                }
            }
        }

        // Scan extends clause of types being deleted
        if let Some(typedef_table) = tables.table::<TypeDefRaw>() {
            for type_token in types {
                if let Some(typedef) = typedef_table.get(type_token.row()) {
                    if typedef.extends.token.is_table(TableId::TypeRef) {
                        typeref_rids.insert(typedef.extends.token.row());
                    }
                }
            }
        }

        // Scan CustomAttribute constructors whose parent is being deleted
        if let Some(attr_table) = tables.table::<CustomAttributeRaw>() {
            for attr in attr_table {
                let parent_token = attr.parent.token;
                let parent_deleted = types.contains(&parent_token)
                    || methods.contains(&parent_token)
                    || fields.contains(&parent_token);
                if !parent_deleted {
                    continue;
                }
                // The constructor may be a MemberRef or MethodDef
                il_tokens.insert(attr.constructor.token);
            }
        }
    }

    PreDeletionRefs {
        il_tokens,
        typeref_rids,
        standalonesig_rids,
    }
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

    let code_data = &data[code_start..code_end];
    let code_rva = base_rva + body.size_header;

    // Helper: extract token operands from decoded blocks
    let collect = |blocks: &[BasicBlock], out: &mut HashSet<Token>| {
        for block in blocks {
            for instr in &block.instructions {
                if let Operand::Token(token) = instr.operand {
                    out.insert(token);
                }
            }
        }
    };

    // Decode main code flow
    if let Ok(blocks) = decode_blocks(code_data, 0, code_rva, None) {
        collect(&blocks, referenced);
    }

    // Decode exception handler regions — these are not reachable via normal
    // control flow so decode_blocks(offset=0) never visits them.
    for handler in &body.exception_handlers {
        let h_offset = handler.handler_offset as usize;
        let h_length = handler.handler_length as usize;
        if h_offset < code_data.len() {
            let h_rva = code_rva + h_offset;
            if let Ok(blocks) = decode_blocks(code_data, h_offset, h_rva, Some(h_length)) {
                collect(&blocks, referenced);
            }
        }

        // Catch clause class token (TypeDef/TypeRef/TypeSpec of the caught exception)
        if let Some(class_token) = handler.get_class_token() {
            referenced.insert(Token::new(class_token));
        }
    }
}

/// Collects StandAloneSig RIDs referenced by method body headers.
///
/// Scans all method bodies (original and regenerated) and extracts the
/// LocalVarSigTok from fat headers. Returns the set of StandAloneSig RIDs
/// that are actually used by method bodies.
pub(super) fn collect_referenced_standalonesig_rids(assembly: &CilAssembly) -> HashSet<u32> {
    let mut referenced = HashSet::new();

    // Collect (rid, rva) pairs while holding view borrow
    let method_rvas: Vec<u32> = {
        let view = assembly.view();
        let Some(tables) = view.tables() else {
            return referenced;
        };

        let Some(methoddef_table) = tables.table::<MethodDefRaw>() else {
            return referenced;
        };

        methoddef_table
            .into_iter()
            .filter(|m| !assembly.changes().is_row_deleted(TableId::MethodDef, m.rid))
            .map(|m| get_effective_method_rva(assembly, m.rid, m.rva))
            .filter(|&rva| rva != 0)
            .collect()
    };

    for effective_rva in method_rvas {
        with_method_body(assembly, effective_rva, &mut |data, _| {
            if let Some(sig_rid) = extract_local_var_sig_rid(data) {
                referenced.insert(sig_rid);
            }
        });
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
pub fn scan_method_body_tokens(assembly: &CilAssembly) -> HashSet<Token> {
    let mut referenced = HashSet::new();

    // Collect (rid, effective_rva) pairs while holding view borrow
    let method_rvas: Vec<u32> = {
        let view = assembly.view();
        let Some(tables) = view.tables() else {
            return referenced;
        };

        let Some(methoddef_table) = tables.table::<MethodDefRaw>() else {
            return referenced;
        };

        methoddef_table
            .into_iter()
            .filter(|m| !assembly.changes().is_row_deleted(TableId::MethodDef, m.rid))
            .map(|m| get_effective_method_rva(assembly, m.rid, m.rva))
            .filter(|&rva| rva != 0)
            .collect()
    };

    for effective_rva in method_rvas {
        with_method_body(assembly, effective_rva, &mut |data, base_rva| {
            scan_method_body_bytes(data, base_rva, &mut referenced);
        });
    }

    referenced
}

/// Collects TypeRef RIDs referenced by the signatures of the given MemberRefs.
///
/// When MemberRefs are cascade-deleted, their `.class` TypeRefs become cascade
/// candidates. But TypeRefs referenced only through their **signatures** (parameter
/// types, return types) are not captured by the `.class` cascade. This function
/// fills that gap by scanning the signatures of deleted MemberRefs and returning
/// any TypeRef RIDs found within.
pub fn collect_typerefs_from_deleted_memberref_sigs(
    assembly: &CilAssembly,
    memberref_rids: &HashSet<u32>,
) -> HashSet<u32> {
    let mut result = HashSet::new();

    if memberref_rids.is_empty() {
        return result;
    }

    let view = assembly.view();
    let Some(tables) = view.tables() else {
        return result;
    };
    let Some(blob_heap) = view.blobs() else {
        return result;
    };
    let Some(memberref_table) = tables.table::<MemberRefRaw>() else {
        return result;
    };

    for &rid in memberref_rids {
        if let Some(memberref) = memberref_table.get(rid) {
            if !scan_method_signature_blob(blob_heap, memberref.signature, &mut result) {
                scan_field_signature_blob(blob_heap, memberref.signature, &mut result);
            }
        }
    }

    result
}

/// Scans metadata tables to collect TypeRef RIDs that are referenced.
///
/// Collects references from:
/// - TypeDef.extends (base class)
/// - InterfaceImpl.interface
/// - MemberRef.class (when pointing to TypeRef)
/// - GenericParamConstraint.constraint
/// - CustomAttribute.constructor (indirectly via MemberRef)
pub fn scan_typeref_metadata_refs(assembly: &CilAssembly) -> HashSet<u32> {
    let mut referenced_rids = HashSet::new();

    let view = assembly.view();
    let Some(tables) = view.tables() else {
        return referenced_rids;
    };

    // TypeDef.extends - base class references (skip deleted types)
    if let Some(typedef_table) = tables.table::<TypeDefRaw>() {
        for typedef in typedef_table {
            if assembly
                .changes()
                .is_row_deleted(TableId::TypeDef, typedef.rid)
            {
                continue;
            }
            if typedef.extends.token.is_table(TableId::TypeRef) {
                referenced_rids.insert(typedef.extends.token.row());
            }
        }
    }

    // InterfaceImpl.interface (skip deleted rows)
    if let Some(interfaceimpl_table) = tables.table::<InterfaceImplRaw>() {
        for impl_ in interfaceimpl_table {
            if assembly
                .changes()
                .is_row_deleted(TableId::InterfaceImpl, impl_.rid)
            {
                continue;
            }
            if impl_.interface.token.is_table(TableId::TypeRef) {
                referenced_rids.insert(impl_.interface.token.row());
            }
        }
    }

    // MemberRef.class - declaring type of member references (skip deleted rows)
    if let Some(memberref_table) = tables.table::<MemberRefRaw>() {
        for memberref in memberref_table {
            if assembly
                .changes()
                .is_row_deleted(TableId::MemberRef, memberref.rid)
            {
                continue;
            }
            if memberref.class.token.is_table(TableId::TypeRef) {
                referenced_rids.insert(memberref.class.token.row());
            }
        }
    }

    // GenericParamConstraint - type constraints (skip deleted rows)
    if let Some(constraint_table) = tables.table::<GenericParamConstraintRaw>() {
        for constraint in constraint_table {
            if assembly
                .changes()
                .is_row_deleted(TableId::GenericParamConstraint, constraint.rid)
            {
                continue;
            }
            if constraint.constraint.token.is_table(TableId::TypeRef) {
                referenced_rids.insert(constraint.constraint.token.row());
            }
        }
    }

    // CustomAttribute.constructor - when it's a MemberRef on a TypeRef (skip deleted rows)
    if let Some(attr_table) = tables.table::<CustomAttributeRaw>() {
        if let Some(memberref_table) = tables.table::<MemberRefRaw>() {
            for attr in attr_table {
                if assembly
                    .changes()
                    .is_row_deleted(TableId::CustomAttribute, attr.rid)
                {
                    continue;
                }
                if attr.constructor.token.is_table(TableId::MemberRef) {
                    let memberref_rid = attr.constructor.token.row();
                    if assembly
                        .changes()
                        .is_row_deleted(TableId::MemberRef, memberref_rid)
                    {
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

    referenced_rids
}

/// Scans metadata tables to collect MemberRef RIDs that are referenced.
///
/// Collects references from:
/// - CustomAttribute.constructor
/// - MethodSpec.method
pub fn scan_memberref_metadata_refs(assembly: &CilAssembly) -> HashSet<u32> {
    let mut referenced_rids = HashSet::new();

    let view = assembly.view();
    let Some(tables) = view.tables() else {
        return referenced_rids;
    };

    // CustomAttribute.constructor (skip deleted rows)
    if let Some(attr_table) = tables.table::<CustomAttributeRaw>() {
        for attr in attr_table {
            if assembly
                .changes()
                .is_row_deleted(TableId::CustomAttribute, attr.rid)
            {
                continue;
            }
            if attr.constructor.token.is_table(TableId::MemberRef) {
                referenced_rids.insert(attr.constructor.token.row());
            }
        }
    }

    // MethodSpec.method (skip deleted rows)
    if let Some(methodspec_table) = tables.table::<MethodSpecRaw>() {
        for spec in methodspec_table {
            if assembly
                .changes()
                .is_row_deleted(TableId::MethodSpec, spec.rid)
            {
                continue;
            }
            if spec.method.token.is_table(TableId::MemberRef) {
                referenced_rids.insert(spec.method.token.row());
            }
        }
    }

    referenced_rids
}

/// Scans metadata tables to collect TypeSpec RIDs that are referenced.
///
/// Collects references from:
/// - MemberRef.class
/// - InterfaceImpl.interface
/// - GenericParamConstraint.constraint
/// - TypeDef.extends
pub fn scan_typespec_metadata_refs(assembly: &CilAssembly) -> HashSet<u32> {
    let mut referenced_rids = HashSet::new();

    let view = assembly.view();
    let Some(tables) = view.tables() else {
        return referenced_rids;
    };

    // MemberRef.class (skip deleted rows)
    if let Some(memberref_table) = tables.table::<MemberRefRaw>() {
        for memberref in memberref_table {
            if assembly
                .changes()
                .is_row_deleted(TableId::MemberRef, memberref.rid)
            {
                continue;
            }
            if memberref.class.token.is_table(TableId::TypeSpec) {
                referenced_rids.insert(memberref.class.token.row());
            }
        }
    }

    // InterfaceImpl.interface (skip deleted rows)
    if let Some(interfaceimpl_table) = tables.table::<InterfaceImplRaw>() {
        for impl_ in interfaceimpl_table {
            if assembly
                .changes()
                .is_row_deleted(TableId::InterfaceImpl, impl_.rid)
            {
                continue;
            }
            if impl_.interface.token.is_table(TableId::TypeSpec) {
                referenced_rids.insert(impl_.interface.token.row());
            }
        }
    }

    // GenericParamConstraint.constraint (skip deleted rows)
    if let Some(constraint_table) = tables.table::<GenericParamConstraintRaw>() {
        for constraint in constraint_table {
            if assembly
                .changes()
                .is_row_deleted(TableId::GenericParamConstraint, constraint.rid)
            {
                continue;
            }
            if constraint.constraint.token.is_table(TableId::TypeSpec) {
                referenced_rids.insert(constraint.constraint.token.row());
            }
        }
    }

    // TypeDef.extends (skip deleted rows)
    if let Some(typedef_table) = tables.table::<TypeDefRaw>() {
        for typedef in typedef_table {
            if assembly
                .changes()
                .is_row_deleted(TableId::TypeDef, typedef.rid)
            {
                continue;
            }
            if typedef.extends.token.is_table(TableId::TypeSpec) {
                referenced_rids.insert(typedef.extends.token.row());
            }
        }
    }

    referenced_rids
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
pub fn scan_signature_typeref_refs(assembly: &CilAssembly) -> HashSet<u32> {
    let mut referenced_rids = HashSet::new();

    let view = assembly.view();
    let Some(tables) = view.tables() else {
        return referenced_rids;
    };

    let Some(blob_heap) = view.blobs() else {
        return referenced_rids;
    };

    // MethodDef signatures (skip deleted rows)
    if let Some(methoddef_table) = tables.table::<MethodDefRaw>() {
        for methoddef in methoddef_table {
            if assembly
                .changes()
                .is_row_deleted(TableId::MethodDef, methoddef.rid)
            {
                continue;
            }
            scan_method_signature_blob(blob_heap, methoddef.signature, &mut referenced_rids);
        }
    }

    // Field signatures (skip deleted rows)
    if let Some(field_table) = tables.table::<FieldRaw>() {
        for field in field_table {
            if assembly.changes().is_row_deleted(TableId::Field, field.rid) {
                continue;
            }
            scan_field_signature_blob(blob_heap, field.signature, &mut referenced_rids);
        }
    }

    // MemberRef signatures (skip deleted rows)
    if let Some(memberref_table) = tables.table::<MemberRefRaw>() {
        for memberref in memberref_table {
            if assembly
                .changes()
                .is_row_deleted(TableId::MemberRef, memberref.rid)
            {
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
        for sig in standalonesig_table {
            // Only scan StandAloneSigs that are referenced by current method bodies
            if referenced_sigs.contains(&sig.rid) {
                scan_local_var_signature_blob(blob_heap, sig.signature, &mut referenced_rids);
            }
        }
    }

    // TypeSpec signatures (skip deleted rows)
    if let Some(typespec_table) = tables.table::<TypeSpecRaw>() {
        for typespec in typespec_table {
            if assembly
                .changes()
                .is_row_deleted(TableId::TypeSpec, typespec.rid)
            {
                continue;
            }
            scan_typespec_signature_blob(blob_heap, typespec.signature, &mut referenced_rids);
        }
    }

    // Property signatures (skip deleted rows)
    if let Some(property_table) = tables.table::<PropertyRaw>() {
        for property in property_table {
            if assembly
                .changes()
                .is_row_deleted(TableId::Property, property.rid)
            {
                continue;
            }
            scan_property_signature_blob(blob_heap, property.signature, &mut referenced_rids);
        }
    }

    referenced_rids
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

/// Removes TypeRef entries that are cascade candidates and no longer referenced.
///
/// Only removes TypeRefs that are in the `candidates` set AND are not referenced
/// by any surviving code or metadata. This is the cascade-safe version that
/// preserves pre-existing orphans.
///
/// # Returns
///
/// A tuple of (count_removed, set_of_deleted_rids).
pub fn remove_unreferenced_typerefs(
    assembly: &mut CilAssembly,
    candidates: &BTreeSet<u32>,
    body_tokens: &HashSet<Token>,
) -> (usize, HashSet<u32>) {
    if candidates.is_empty() {
        return (0, HashSet::new());
    }

    // Collect all referenced TypeRef RIDs (live set from surviving entities)
    let mut referenced_rids = HashSet::new();

    // From method bodies (IL token operands)
    for token in body_tokens {
        if token.is_table(TableId::TypeRef) {
            referenced_rids.insert(token.row());
        }
    }

    // From metadata tables (computed at this point, after prior cascade removals)
    referenced_rids.extend(scan_typeref_metadata_refs(assembly));

    // From signature blobs (method sigs, field sigs, local var sigs, etc.)
    let signature_refs = scan_signature_typeref_refs(assembly);
    referenced_rids.extend(signature_refs);

    // Also include TypeRefs referenced indirectly through MemberRefs used in code
    let memberref_body_rids: HashSet<u32> = body_tokens
        .iter()
        .filter(|t| t.is_table(TableId::MemberRef))
        .map(Token::row)
        .collect();

    {
        let view = assembly.view();
        if let Some(tables) = view.tables() {
            if let Some(memberref_table) = tables.table::<MemberRefRaw>() {
                for memberref in memberref_table {
                    if assembly
                        .changes()
                        .is_row_deleted(TableId::MemberRef, memberref.rid)
                    {
                        continue;
                    }
                    if memberref_body_rids.contains(&memberref.rid)
                        && memberref.class.token.is_table(TableId::TypeRef)
                    {
                        referenced_rids.insert(memberref.class.token.row());
                    }
                }
            }
        }
    }

    remove_candidates_not_alive(assembly, TableId::TypeRef, candidates, &referenced_rids)
}

/// Removes MemberRef entries that are cascade candidates and no longer referenced.
///
/// Only removes MemberRefs that are in the `candidates` set AND are not referenced
/// by any surviving code or metadata.
///
/// # Returns
///
/// A tuple of (count_removed, set_of_deleted_rids).
pub fn remove_unreferenced_memberrefs(
    assembly: &mut CilAssembly,
    candidates: &BTreeSet<u32>,
    body_tokens: &HashSet<Token>,
) -> (usize, HashSet<u32>) {
    if candidates.is_empty() {
        return (0, HashSet::new());
    }

    // Collect all referenced MemberRef RIDs (live set)
    let mut referenced_rids = HashSet::new();

    // From method bodies
    for token in body_tokens {
        if token.is_table(TableId::MemberRef) {
            referenced_rids.insert(token.row());
        }
    }

    // From metadata tables (computed at this point, reflecting current deletion state)
    referenced_rids.extend(scan_memberref_metadata_refs(assembly));

    // Also include MemberRefs referenced through MethodSpecs in method bodies
    let methodspec_body_rids: HashSet<u32> = body_tokens
        .iter()
        .filter(|t| t.is_table(TableId::MethodSpec))
        .map(Token::row)
        .collect();

    {
        let view = assembly.view();
        if let Some(tables) = view.tables() {
            if let Some(methodspec_table) = tables.table::<MethodSpecRaw>() {
                for spec in methodspec_table {
                    if assembly
                        .changes()
                        .is_row_deleted(TableId::MethodSpec, spec.rid)
                    {
                        continue;
                    }
                    if methodspec_body_rids.contains(&spec.rid)
                        && spec.method.token.is_table(TableId::MemberRef)
                    {
                        referenced_rids.insert(spec.method.token.row());
                    }
                }
            }
        }
    }

    remove_candidates_not_alive(assembly, TableId::MemberRef, candidates, &referenced_rids)
}

/// Removes TypeSpec entries that are cascade candidates and no longer referenced.
///
/// Only removes TypeSpecs that are in the `candidates` set AND are not referenced
/// by any surviving code or metadata.
///
/// # Returns
///
/// A tuple of (count_removed, set_of_deleted_rids).
pub fn remove_unreferenced_typespecs(
    assembly: &mut CilAssembly,
    candidates: &BTreeSet<u32>,
    body_tokens: &HashSet<Token>,
) -> (usize, HashSet<u32>) {
    if candidates.is_empty() {
        return (0, HashSet::new());
    }

    // Collect all referenced TypeSpec RIDs (live set)
    let mut referenced_rids = HashSet::new();

    // From method bodies
    for token in body_tokens {
        if token.is_table(TableId::TypeSpec) {
            referenced_rids.insert(token.row());
        }
    }

    // From metadata tables (computed at this point, after prior cascade removals)
    referenced_rids.extend(scan_typespec_metadata_refs(assembly));

    remove_candidates_not_alive(assembly, TableId::TypeSpec, candidates, &referenced_rids)
}

#[cfg(test)]
mod tests {
    use crate::{
        cilassembly::cleanup::utils::PLACEHOLDER_RVA_THRESHOLD,
        metadata::{tables::TableId, token::Token},
    };

    #[test]
    fn test_placeholder_rva_detection() {
        // Placeholder RVAs start at 0xF000_0000
        const { assert!(0xF000_0000 >= PLACEHOLDER_RVA_THRESHOLD) };
        const { assert!(0xF000_0001 >= PLACEHOLDER_RVA_THRESHOLD) };

        // Normal RVAs are below the threshold
        const { assert!(0x2000 < PLACEHOLDER_RVA_THRESHOLD) };
        const { assert!(0x0000_FFFF < PLACEHOLDER_RVA_THRESHOLD) };
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
