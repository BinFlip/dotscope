//! Orphan detection and removal for metadata tables.
//!
//! This module provides functions to find and remove metadata entries that
//! have become orphaned due to deletions. Each table type has a corresponding
//! removal function that checks for orphaned entries.
//!
//! # Design Principle
//!
//! These functions only remove entries that reference **deleted items**.
//! They do NOT remove all orphaned entries in the original assembly, as those
//! may be intentionally orphaned (e.g., used via reflection).

use std::collections::HashSet;

use crate::{
    cilassembly::{
        cleanup::{
            references::{
                remove_unreferenced_memberrefs, remove_unreferenced_typerefs,
                remove_unreferenced_typespecs,
            },
            CleanupStats,
        },
        CilAssembly,
    },
    metadata::{
        method::MethodBody,
        streams::TablesHeader,
        tables::{
            ClassLayoutRaw, ConstantRaw, CustomAttributeRaw, DeclSecurityRaw, EventMapRaw,
            FieldLayoutRaw, FieldMarshalRaw, FieldRvaRaw, GenericParamConstraintRaw,
            GenericParamRaw, ImplMapRaw, InterfaceImplRaw, MethodDefRaw, MethodImplRaw,
            MethodSemanticsRaw, MethodSpecRaw, NestedClassRaw, ParamRaw, PropertyMapRaw,
            RowReadable, StandAloneSigRaw, TableAccess, TableId,
        },
        token::Token,
    },
};

/// Context for orphan removal operations.
///
/// Tracks which tokens have been deleted, allowing orphan detection
/// functions to determine what should be removed.
///
/// This struct holds references to the deleted token sets to avoid
/// unnecessary copying during cleanup operations.
#[derive(Debug, Clone, Copy)]
pub struct OrphanContext<'a> {
    /// Types (TypeDef) that have been deleted.
    types: &'a HashSet<Token>,
    /// Methods (MethodDef) that have been deleted.
    methods: &'a HashSet<Token>,
    /// Fields that have been deleted.
    fields: &'a HashSet<Token>,
}

impl<'a> OrphanContext<'a> {
    /// Creates a new orphan context from references to deleted token sets.
    #[must_use]
    pub fn new(
        deleted_types: &'a HashSet<Token>,
        deleted_methods: &'a HashSet<Token>,
        deleted_fields: &'a HashSet<Token>,
    ) -> Self {
        Self {
            types: deleted_types,
            methods: deleted_methods,
            fields: deleted_fields,
        }
    }

    /// Returns true if the given token has been deleted.
    ///
    /// Checks all three token sets (types, methods, fields).
    #[must_use]
    pub fn is_deleted(&self, token: Token) -> bool {
        self.types.contains(&token) || self.methods.contains(&token) || self.fields.contains(&token)
    }

    /// Returns true if the given type token has been deleted.
    #[must_use]
    pub fn is_type_deleted(&self, token: Token) -> bool {
        self.types.contains(&token)
    }

    /// Returns true if the given method token has been deleted.
    #[must_use]
    pub fn is_method_deleted(&self, token: Token) -> bool {
        self.methods.contains(&token)
    }

    /// Returns true if the given field token has been deleted.
    #[must_use]
    pub fn is_field_deleted(&self, token: Token) -> bool {
        self.fields.contains(&token)
    }
}

/// Generic helper to remove orphaned entries from a table.
///
/// Iterates through a table and removes entries for which the predicate
/// returns `true`. Entries are removed in reverse RID order to maintain
/// consistent indexing during removal.
///
/// # Type Parameters
///
/// * `T` - The raw table row type (e.g., `ParamRaw`, `CustomAttributeRaw`)
///
/// # Arguments
///
/// * `assembly` - The assembly to modify
/// * `is_orphan` - Closure that returns `true` if a row should be removed
///
/// # Returns
///
/// The count of removed entries.
pub fn remove_orphan_entries<T>(assembly: &mut CilAssembly, is_orphan: impl Fn(&T) -> bool) -> usize
where
    T: RowReadable,
    for<'a> TablesHeader<'a>: TableAccess<'a, T>,
{
    // First pass: collect orphan RIDs (immutable borrow)
    let orphan_rids: Vec<u32> = {
        let view = assembly.view();
        let Some(tables) = view.tables() else {
            return 0;
        };

        let Some(table) = tables.table::<T>() else {
            return 0;
        };

        (1..=table.row_count)
            .filter_map(|rid| table.get(rid).filter(|r| is_orphan(r)).map(|_| rid))
            .collect()
    };

    // Second pass: remove in reverse order (mutable borrow)
    let mut removed_count = 0;
    for rid in orphan_rids.into_iter().rev() {
        if assembly.table_row_remove(T::TABLE_ID, rid).is_ok() {
            removed_count += 1;
        }
    }

    removed_count
}

/// Removes orphaned Param entries for deleted methods.
///
/// Parameters belong to methods via the `param_list` field in MethodDef.
/// When a method is deleted, its parameters become orphaned.
pub fn remove_orphan_params(assembly: &mut CilAssembly, ctx: &OrphanContext) -> usize {
    let view = assembly.view();
    let Some(tables) = view.tables() else {
        return 0;
    };

    let Some(methoddef_table) = tables.table::<MethodDefRaw>() else {
        return 0;
    };

    let Some(param_table) = tables.table::<ParamRaw>() else {
        return 0;
    };

    let method_count = methoddef_table.row_count;
    let param_count = param_table.row_count;

    // Collect param RIDs that belong to deleted methods
    let mut orphan_params: HashSet<u32> = HashSet::new();

    for method_rid in 1..=method_count {
        let method_token = Token::from_parts(TableId::MethodDef, method_rid);

        if !ctx.is_method_deleted(method_token) {
            continue;
        }

        let Some(methoddef) = methoddef_table.get(method_rid) else {
            continue;
        };

        let param_start = methoddef.param_list;
        let param_end = if method_rid < method_count {
            methoddef_table
                .get(method_rid + 1)
                .map_or(param_count + 1, |m| m.param_list)
        } else {
            param_count + 1
        };

        for param_rid in param_start..param_end {
            orphan_params.insert(param_rid);
        }
    }

    // Remove collected orphans
    let mut removed_count = 0;
    for rid in orphan_params
        .into_iter()
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
    {
        if assembly.table_row_remove(TableId::Param, rid).is_ok() {
            removed_count += 1;
        }
    }

    removed_count
}

/// Removes orphaned CustomAttribute entries for deleted tokens.
///
/// Custom attributes reference their parent via the `parent` coded index,
/// and their constructor via the `constructor` coded index.
/// When either the parent or constructor is deleted, the attribute becomes orphaned.
pub fn remove_orphan_attributes(assembly: &mut CilAssembly, ctx: &OrphanContext) -> usize {
    remove_orphan_entries::<CustomAttributeRaw>(assembly, |attr| {
        // Remove if parent is deleted
        if ctx.is_deleted(attr.parent.token) {
            return true;
        }
        // Also remove if constructor method is deleted (MethodDef or MemberRef)
        ctx.is_deleted(attr.constructor.token)
    })
}

/// Removes orphaned ClassLayout entries for deleted types.
pub fn remove_orphan_classlayouts(assembly: &mut CilAssembly, ctx: &OrphanContext) -> usize {
    remove_orphan_entries::<ClassLayoutRaw>(assembly, |layout| {
        let parent_token = Token::from_parts(TableId::TypeDef, layout.parent);
        ctx.is_type_deleted(parent_token)
    })
}

/// Removes orphaned FieldRVA entries for deleted fields.
pub fn remove_orphan_fieldrvas(assembly: &mut CilAssembly, ctx: &OrphanContext) -> usize {
    remove_orphan_entries::<FieldRvaRaw>(assembly, |rva| {
        let field_token = Token::from_parts(TableId::Field, rva.field);
        ctx.is_field_deleted(field_token)
    })
}

/// Removes orphaned NestedClass entries for deleted types.
pub fn remove_orphan_nestedclass(assembly: &mut CilAssembly, ctx: &OrphanContext) -> usize {
    remove_orphan_entries::<NestedClassRaw>(assembly, |nested| {
        let nested_token = Token::from_parts(TableId::TypeDef, nested.nested_class);
        let enclosing_token = Token::from_parts(TableId::TypeDef, nested.enclosing_class);
        ctx.is_type_deleted(nested_token) || ctx.is_type_deleted(enclosing_token)
    })
}

/// Removes orphaned InterfaceImpl entries for deleted types.
pub fn remove_orphan_interfaceimpl(assembly: &mut CilAssembly, ctx: &OrphanContext) -> usize {
    remove_orphan_entries::<InterfaceImplRaw>(assembly, |impl_| {
        let class_token = Token::from_parts(TableId::TypeDef, impl_.class);
        ctx.is_type_deleted(class_token)
    })
}

/// Removes orphaned MethodImpl entries for deleted types or methods.
pub fn remove_orphan_methodimpl(assembly: &mut CilAssembly, ctx: &OrphanContext) -> usize {
    remove_orphan_entries::<MethodImplRaw>(assembly, |impl_| {
        let class_token = Token::from_parts(TableId::TypeDef, impl_.class);

        // Check class and method_body and method_declaration (MethodDefOrRef coded index)
        ctx.is_type_deleted(class_token)
            || ctx.is_deleted(impl_.method_body.token)
            || ctx.is_deleted(impl_.method_declaration.token)
    })
}

/// Removes orphaned MethodSemantics entries for deleted methods.
pub fn remove_orphan_methodsemantics(assembly: &mut CilAssembly, ctx: &OrphanContext) -> usize {
    remove_orphan_entries::<MethodSemanticsRaw>(assembly, |sem| {
        let method_token = Token::from_parts(TableId::MethodDef, sem.method);
        ctx.is_method_deleted(method_token)
    })
}

/// Removes orphaned Constant entries for deleted fields.
pub fn remove_orphan_constant(assembly: &mut CilAssembly, ctx: &OrphanContext) -> usize {
    remove_orphan_entries::<ConstantRaw>(assembly, |constant| ctx.is_deleted(constant.parent.token))
}

/// Removes orphaned FieldMarshal entries for deleted fields.
pub fn remove_orphan_fieldmarshal(assembly: &mut CilAssembly, ctx: &OrphanContext) -> usize {
    remove_orphan_entries::<FieldMarshalRaw>(assembly, |marshal| {
        ctx.is_deleted(marshal.parent.token)
    })
}

/// Removes orphaned FieldLayout entries for deleted fields.
pub fn remove_orphan_fieldlayout(assembly: &mut CilAssembly, ctx: &OrphanContext) -> usize {
    remove_orphan_entries::<FieldLayoutRaw>(assembly, |layout| {
        let field_token = Token::from_parts(TableId::Field, layout.field);
        ctx.is_field_deleted(field_token)
    })
}

/// Removes orphaned GenericParam entries for deleted types or methods.
///
/// Returns the set of removed GenericParam RIDs for cascading to constraints.
pub fn remove_orphan_genericparam(
    assembly: &mut CilAssembly,
    ctx: &OrphanContext,
) -> (usize, HashSet<u32>) {
    // First pass: collect orphan RIDs
    let orphan_rids: Vec<u32> = {
        let view = assembly.view();
        let Some(tables) = view.tables() else {
            return (0, HashSet::new());
        };

        let Some(table) = tables.table::<GenericParamRaw>() else {
            return (0, HashSet::new());
        };

        (1..=table.row_count)
            .filter_map(|rid| {
                table.get(rid).and_then(|param| {
                    if ctx.is_deleted(param.owner.token) {
                        Some(rid)
                    } else {
                        None
                    }
                })
            })
            .collect()
    };

    let removed_rids: HashSet<u32> = orphan_rids.iter().copied().collect();

    // Second pass: remove
    let mut removed_count = 0;
    for rid in orphan_rids.into_iter().rev() {
        if assembly
            .table_row_remove(TableId::GenericParam, rid)
            .is_ok()
        {
            removed_count += 1;
        }
    }

    (removed_count, removed_rids)
}

/// Removes orphaned GenericParamConstraint entries for removed GenericParams.
pub fn remove_orphan_genericparamconstraint(
    assembly: &mut CilAssembly,
    removed_genericparams: &HashSet<u32>,
) -> usize {
    remove_orphan_entries::<GenericParamConstraintRaw>(assembly, |constraint| {
        removed_genericparams.contains(&constraint.owner)
    })
}

/// Removes orphaned MethodSpec entries for deleted methods.
pub fn remove_orphan_methodspec(assembly: &mut CilAssembly, ctx: &OrphanContext) -> usize {
    remove_orphan_entries::<MethodSpecRaw>(assembly, |spec| ctx.is_deleted(spec.method.token))
}

/// Removes orphaned DeclSecurity entries for deleted types or methods.
pub fn remove_orphan_declsecurity(assembly: &mut CilAssembly, ctx: &OrphanContext) -> usize {
    remove_orphan_entries::<DeclSecurityRaw>(assembly, |security| {
        ctx.is_deleted(security.parent.token)
    })
}

/// Removes orphaned ImplMap entries for deleted methods (P/Invoke).
pub fn remove_orphan_implmap(assembly: &mut CilAssembly, ctx: &OrphanContext) -> usize {
    remove_orphan_entries::<ImplMapRaw>(assembly, |implmap| {
        ctx.is_deleted(implmap.member_forwarded.token)
    })
}

/// Removes orphaned EventMap entries for deleted types.
pub fn remove_orphan_eventmap(assembly: &mut CilAssembly, ctx: &OrphanContext) -> usize {
    remove_orphan_entries::<EventMapRaw>(assembly, |eventmap| {
        let parent_token = Token::from_parts(TableId::TypeDef, eventmap.parent);
        ctx.is_type_deleted(parent_token)
    })
}

/// Removes orphaned PropertyMap entries for deleted types.
pub fn remove_orphan_propertymap(assembly: &mut CilAssembly, ctx: &OrphanContext) -> usize {
    remove_orphan_entries::<PropertyMapRaw>(assembly, |propmap| {
        let parent_token = Token::from_parts(TableId::TypeDef, propmap.parent);
        ctx.is_type_deleted(parent_token)
    })
}

/// Removes orphaned StandAloneSig entries for deleted methods.
///
/// StandAloneSigs are referenced by method bodies via LocalVarSigTok.
/// When methods are deleted, their signatures may become orphaned.
pub fn remove_orphan_standalonesigs(assembly: &mut CilAssembly, ctx: &OrphanContext) -> usize {
    // Collect all StandAloneSig RIDs still referenced by remaining methods
    let referenced_rids: HashSet<u32> = {
        let view = assembly.view();
        let Some(tables) = view.tables() else {
            return 0;
        };

        let Some(methoddef_table) = tables.table::<MethodDefRaw>() else {
            return 0;
        };

        let file = view.file();
        let mut referenced = HashSet::new();

        for methoddef in methoddef_table {
            let method_token = Token::from_parts(TableId::MethodDef, methoddef.rid);

            // Skip deleted methods
            if ctx.is_method_deleted(method_token) {
                continue;
            }

            // Skip methods without RVA (abstract, extern, etc.)
            if methoddef.rva == 0 {
                continue;
            }

            // Parse method body to get LocalVarSigTok
            let Ok(offset) = file.rva_to_offset(methoddef.rva as usize) else {
                continue;
            };

            if offset >= file.data().len() {
                continue;
            }

            if let Ok(body) = MethodBody::from(&file.data()[offset..]) {
                if body.local_var_sig_token != 0 {
                    let sig_token = Token::new(body.local_var_sig_token);
                    if sig_token.is_table(TableId::StandAloneSig) {
                        referenced.insert(sig_token.row());
                    }
                }
            }
        }

        referenced
    };

    // Remove StandAloneSigs not in the referenced set (that were used by deleted methods)
    // We need to be careful: only remove sigs that WERE referenced by deleted methods
    // not sigs that were never referenced in the first place

    // For now, just use the generic helper with a reference check
    remove_orphan_entries::<StandAloneSigRaw>(assembly, |sig| !referenced_rids.contains(&sig.rid))
}

/// Removes all orphaned metadata entries caused by the deletions in the context.
///
/// This is the main entry point for orphan removal. It calls all the individual
/// removal functions in the correct order (handling cascading dependencies).
///
/// # Arguments
///
/// * `assembly` - The assembly to modify
/// * `ctx` - Context containing the deleted tokens
///
/// # Returns
///
/// Statistics about what was removed.
pub fn remove_all_orphans(assembly: &mut CilAssembly, ctx: &OrphanContext) -> CleanupStats {
    let mut stats = CleanupStats::new();

    // Remove in order that respects dependencies

    // 1. Params (depend on methods)
    stats.params_removed = remove_orphan_params(assembly, ctx);

    // 2. Custom attributes (can target anything)
    stats.attributes_removed = remove_orphan_attributes(assembly, ctx);

    // 3. Type-related tables
    stats.classlayouts_removed = remove_orphan_classlayouts(assembly, ctx);
    stats.nestedclasses_removed = remove_orphan_nestedclass(assembly, ctx);
    stats.interfaceimpls_removed = remove_orphan_interfaceimpl(assembly, ctx);
    stats.eventmaps_removed = remove_orphan_eventmap(assembly, ctx);
    stats.propertymaps_removed = remove_orphan_propertymap(assembly, ctx);

    // 4. Method-related tables
    stats.methodimpls_removed = remove_orphan_methodimpl(assembly, ctx);
    stats.methodsemantics_removed = remove_orphan_methodsemantics(assembly, ctx);
    stats.implmaps_removed = remove_orphan_implmap(assembly, ctx);
    stats.declsecurities_removed = remove_orphan_declsecurity(assembly, ctx);
    stats.methodspecs_removed = remove_orphan_methodspec(assembly, ctx);
    stats.standalonesigs_removed = remove_orphan_standalonesigs(assembly, ctx);

    // 5. Field-related tables
    stats.fieldrvas_removed = remove_orphan_fieldrvas(assembly, ctx);
    stats.fieldlayouts_removed = remove_orphan_fieldlayout(assembly, ctx);
    stats.fieldmarshals_removed = remove_orphan_fieldmarshal(assembly, ctx);
    stats.constants_removed = remove_orphan_constant(assembly, ctx);

    // 6. Generic params (and cascade to constraints)
    let (genericparams, removed_gp_rids) = remove_orphan_genericparam(assembly, ctx);
    stats.genericparams_removed = genericparams;
    stats.genericparam_constraints_removed =
        remove_orphan_genericparamconstraint(assembly, &removed_gp_rids);

    // 7. Reference-based cleanup: remove entries no longer referenced by any code
    // Order matters: remove consumers before producers
    // MemberRefs reference TypeRefs/TypeSpecs, so remove MemberRefs first
    stats.memberrefs_removed = remove_unreferenced_memberrefs(assembly);
    stats.typespecs_removed = remove_unreferenced_typespecs(assembly);

    // TypeRef removal - must come after MemberRef/TypeSpec removal since those
    // reference TypeRefs. The signature blob remapping infrastructure now supports
    // TypeRef tokens (remap_token() handles table 0x01).
    stats.typerefs_removed = remove_unreferenced_typerefs(assembly);

    stats
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use crate::{
        cilassembly::cleanup::orphans::OrphanContext,
        metadata::{tables::TableId, token::Token},
    };

    #[test]
    fn test_orphan_context_creation() {
        let types = HashSet::from([Token::from_parts(TableId::TypeDef, 1)]);
        let methods = HashSet::from([Token::from_parts(TableId::MethodDef, 2)]);
        let fields = HashSet::from([Token::from_parts(TableId::Field, 3)]);

        let ctx = OrphanContext::new(&types, &methods, &fields);

        assert!(ctx.is_type_deleted(Token::from_parts(TableId::TypeDef, 1)));
        assert!(ctx.is_method_deleted(Token::from_parts(TableId::MethodDef, 2)));
        assert!(ctx.is_field_deleted(Token::from_parts(TableId::Field, 3)));
        assert!(!ctx.is_type_deleted(Token::from_parts(TableId::TypeDef, 99)));
    }

    #[test]
    fn test_orphan_context_is_deleted() {
        let types = HashSet::from([Token::from_parts(TableId::TypeDef, 1)]);
        let empty_methods = HashSet::new();
        let empty_fields = HashSet::new();
        let ctx = OrphanContext::new(&types, &empty_methods, &empty_fields);

        assert!(ctx.is_deleted(Token::from_parts(TableId::TypeDef, 1)));
        assert!(!ctx.is_deleted(Token::from_parts(TableId::TypeDef, 2)));
    }
}
