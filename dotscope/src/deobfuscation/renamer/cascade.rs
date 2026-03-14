//! Cascade renaming engine for smart identifier renaming.
//!
//! Implements a 4-phase cascade that progressively builds naming context:
//!
//! 1. **Anchors** — Extract known names from external API call parameters
//! 2. **Phase labels** — Decompose methods into semantic phases, label via provider
//! 3. **Members** — Rename parameters, methods (callees-first), and fields
//! 4. **Types** — Rename type definitions using member names as context
//!
//! Each phase feeds context into subsequent phases, producing increasingly
//! informed names. The cascade works with any [`RenameProvider`] — simple
//! sequential names or LLM-powered semantic names.

use std::collections::{HashMap, HashSet};

use crate::{
    analysis::{CallGraph, SsaFunction},
    deobfuscation::{
        renamer::{
            context::{
                ApiCallInfo, CallerInfo, IdentifierKind, ParamInfo, PhaseInfo, RenameContext,
            },
            features, phases, prompt, validate, RenameEntry, RenameProvider, SmartRenameConfig,
        },
        utils::{is_obfuscated_name, is_special_name},
    },
    metadata::{
        tables::{FieldRaw, MethodDefRaw, ParamRaw, TableId, TypeDefRaw},
        token::Token,
    },
    CilObject, Result,
};

/// Orchestrates the multi-phase cascade renaming process.
///
/// The cascade builds naming context incrementally: each phase produces
/// names that inform subsequent phases. This is the core algorithm that
/// distinguishes smart renaming from simple sequential naming.
///
/// # Lifecycle
///
/// 1. Construct via [`new()`](Self::new) with assembly, providers, and config
/// 2. Call [`execute()`](Self::execute) to run the full cascade
/// 3. The returned [`Vec<RenameEntry>`] can be applied via
///    [`renames_apply()`](super::renames_apply)
pub struct CascadeRenamer<'a> {
    /// The assembly being renamed.
    assembly: &'a CilObject,
    /// Primary provider for name suggestions (may be LLM-backed).
    provider: &'a dyn RenameProvider,
    /// Fallback provider when primary returns `None`.
    fallback: &'a dyn RenameProvider,
    /// Pipeline configuration (thresholds, max lengths, patterns).
    config: SmartRenameConfig,
    /// Names committed so far: token → new name.
    committed: HashMap<Token, String>,
    /// Collected rename entries for later application.
    entries: Vec<RenameEntry>,
    /// String indices already processed (dedup for shared offsets).
    seen_indices: HashSet<u32>,
    /// SSA functions built on demand, keyed by method token.
    ssa_cache: HashMap<Token, SsaFunction>,
    /// Call graph for topological ordering.
    call_graph: Option<CallGraph>,
    /// Phase narratives keyed by method token.
    phase_narratives: HashMap<Token, Vec<PhaseInfo>>,
    /// API call anchors keyed by method token.
    anchors: HashMap<Token, Vec<ApiCallInfo>>,
    /// Caller-side context for each method, keyed by callee token.
    caller_contexts: HashMap<Token, Vec<CallerInfo>>,
    /// Names already used within each scope, for duplicate prevention.
    /// Key is a scope discriminator (e.g. declaring type token for methods/fields,
    /// method token for params, namespace string for types).
    used_names: HashMap<u64, HashSet<String>>,
}

impl<'a> CascadeRenamer<'a> {
    /// Creates a new cascade renamer.
    ///
    /// # Arguments
    ///
    /// * `assembly` - The assembly whose identifiers will be renamed.
    /// * `provider` - Primary rename provider (LLM or simple).
    /// * `fallback` - Fallback provider used when primary returns `None`.
    /// * `config` - Pipeline configuration for thresholds and constraints.
    pub fn new(
        assembly: &'a CilObject,
        provider: &'a dyn RenameProvider,
        fallback: &'a dyn RenameProvider,
        config: SmartRenameConfig,
    ) -> Self {
        Self {
            assembly,
            provider,
            fallback,
            config,
            committed: HashMap::new(),
            entries: Vec::new(),
            seen_indices: HashSet::new(),
            ssa_cache: HashMap::new(),
            call_graph: None,
            phase_narratives: HashMap::new(),
            anchors: HashMap::new(),
            caller_contexts: HashMap::new(),
            used_names: HashMap::new(),
        }
    }

    /// Executes the full cascade and returns rename entries.
    ///
    /// Runs all 4 phases in order:
    /// 1. Build SSA + call graph for methods with CFGs
    /// 2. Extract anchors from known API calls
    /// 3. Decompose methods into phases and label them
    /// 4. Rename members (params → methods → fields) and types
    ///
    /// # Returns
    ///
    /// A vector of rename entries ready for application via
    /// [`renames_apply()`](super::renames_apply).
    ///
    /// # Errors
    ///
    /// Returns an error if SSA construction or name suggestion fails
    /// in an unrecoverable way.
    pub fn execute(mut self) -> Result<Vec<RenameEntry>> {
        // Phase 0: Build infrastructure (SSA cache + call graph)
        self.build_infrastructure();

        // Phase 1: Extract anchors from external API calls
        self.extract_anchors();

        // Phase 1.5: Collect caller-side context for callee methods
        self.collect_caller_contexts();

        // Phase 2: Decompose methods and label phases
        self.decompose_and_label_phases();

        // Phase 3: Rename members (parameters, methods callees-first, fields)
        self.rename_parameters();
        self.rename_methods();
        self.rename_fields();

        // Phase 4: Rename types
        self.rename_types();

        Ok(self.entries)
    }

    /// Builds SSA functions and call graph for methods with CFGs.
    ///
    /// Populates [`ssa_cache`](Self) with SSA representations for all methods
    /// that have control flow graphs, and builds a [`CallGraph`] for
    /// topological ordering in method renaming.
    fn build_infrastructure(&mut self) {
        // Build SSA for each method that has a parseable control flow graph
        for entry in self.assembly.methods().iter() {
            let method = entry.value();
            if method.cfg().is_none() {
                continue;
            }
            if let Ok(ssa) = method.ssa(self.assembly) {
                self.ssa_cache.insert(*entry.key(), ssa);
            }
        }

        // Build call graph
        self.call_graph = CallGraph::build(self.assembly).ok();

        log::debug!(
            "Cascade infrastructure: {}/{} methods have SSA",
            self.ssa_cache.len(),
            self.assembly.methods().len(),
        );
    }

    /// Phase 1: Extracts anchor information from known API calls.
    ///
    /// For each method with SSA, identifies calls to external APIs and maps
    /// argument positions. These anchors provide deterministic naming signals
    /// that don't require LLM inference.
    fn extract_anchors(&mut self) {
        for (token, ssa) in &self.ssa_cache {
            let anchors = features::extract_anchors(ssa, self.assembly);
            if !anchors.is_empty() {
                self.anchors.insert(*token, anchors);
            }
        }
        log::debug!(
            "Extracted anchors for {}/{} methods",
            self.anchors.len(),
            self.ssa_cache.len(),
        );
    }

    /// Phase 1.5: Collects caller-side context for methods via reverse call graph.
    ///
    /// For each method in the SSA cache, queries the call graph for its callers,
    /// then extracts string literals near the call site and what the return value
    /// feeds into. This propagates naming signals from callers to callees —
    /// critical for context-starved methods (pure arithmetic, getters) that have
    /// no external calls or strings of their own.
    fn collect_caller_contexts(&mut self) {
        let Some(ref call_graph) = self.call_graph else {
            return;
        };

        let callee_tokens: Vec<Token> = self.ssa_cache.keys().copied().collect();

        for callee_token in &callee_tokens {
            let callers = call_graph.callers(*callee_token);
            if callers.is_empty() {
                continue;
            }

            let mut caller_infos = Vec::new();

            for caller_token in &callers {
                let Some(caller_ssa) = self.ssa_cache.get(caller_token) else {
                    continue;
                };

                // Get caller name (committed or original, skip obfuscated)
                let caller_name = self
                    .committed
                    .get(caller_token)
                    .cloned()
                    .or_else(|| {
                        self.assembly
                            .method(caller_token)
                            .filter(|m| !is_obfuscated_name(&m.name))
                            .map(|m| m.name.clone())
                    })
                    .unwrap_or_default();

                if caller_name.is_empty() {
                    continue;
                }

                let (nearby_strings, return_usage) =
                    features::collect_call_site_context(caller_ssa, *callee_token, self.assembly);

                if !nearby_strings.is_empty() || return_usage.is_some() {
                    caller_infos.push(CallerInfo {
                        caller_name,
                        nearby_strings,
                        return_usage,
                    });
                }
            }

            if !caller_infos.is_empty() {
                // Cap at 3 callers to avoid prompt bloat
                caller_infos.truncate(3);
                self.caller_contexts.insert(*callee_token, caller_infos);
            }
        }

        log::debug!(
            "Collected caller context for {}/{} methods",
            self.caller_contexts.len(),
            self.ssa_cache.len(),
        );
    }

    /// Phase 2: Decomposes methods into semantic phases and labels them.
    ///
    /// For large methods (above [`SmartRenameConfig::small_method_threshold`]),
    /// segments into phases (namespace boundaries, loops, exception handlers,
    /// transform regions) and uses the provider to generate descriptive labels.
    fn decompose_and_label_phases(&mut self) {
        let tokens: Vec<Token> = self.ssa_cache.keys().copied().collect();
        let small_threshold = self.config.small_method_threshold;

        for token in &tokens {
            let ssa = match self.ssa_cache.get(token) {
                Some(s) => s,
                None => continue,
            };

            let phases = phases::decompose_method(ssa, self.assembly, small_threshold);
            if phases.is_empty() {
                continue;
            }

            // Label each phase using the provider
            let labeled_phases: Vec<PhaseInfo> = phases
                .into_iter()
                .map(|mut phase| {
                    if phase.label.is_empty() {
                        // Build a phase label prompt and ask the provider
                        let (prefix, suffix) = prompt::build_phase_label_prompt(&phase);
                        let label_ctx = RenameContext {
                            kind: Some(IdentifierKind::Method),
                            call_targets: phase.call_targets.clone(),
                            ..Default::default()
                        };

                        // Try primary provider, fall back to generating from call targets
                        let label = self
                            .provider
                            .suggest_name(&label_ctx)
                            .ok()
                            .flatten()
                            .or_else(|| generate_phase_label_from_context(&phase, &prefix, &suffix))
                            .unwrap_or_default();

                        phase.label = label;
                    }
                    phase
                })
                .collect();

            self.phase_narratives.insert(*token, labeled_phases);
        }
    }

    /// Phase 3a: Renames obfuscated parameters.
    ///
    /// Builds a Param RID → owning MethodDef mapping from the `param_list`
    /// column, then iterates the Param table. For each obfuscated parameter,
    /// populates the rename context with the owning method's name, the
    /// parameter's .NET type from the method signature, and any API call
    /// anchors from SSA analysis.
    fn rename_parameters(&mut self) {
        let Some(tables) = self.assembly.tables() else {
            return;
        };
        let Some(strings) = self.assembly.strings() else {
            return;
        };
        let Some(param_table) = tables.table::<ParamRaw>() else {
            return;
        };
        let Some(methoddef_table) = tables.table::<MethodDefRaw>() else {
            return;
        };

        // Build Param RID → owning MethodDef RID mapping from param_list ranges
        let param_owners = build_param_owner_map(methoddef_table, param_table.row_count);

        for rid in 1..=param_table.row_count {
            let Some(param) = param_table.get(rid) else {
                continue;
            };
            let name_index = param.name;
            if name_index == 0 {
                continue;
            }
            let Ok(name) = strings.get(name_index as usize) else {
                continue;
            };
            if !is_obfuscated_name(name) || is_special_name(name) {
                continue;
            }
            if !self.seen_indices.insert(name_index) {
                continue;
            }

            let context = self.build_param_context(rid, param.sequence, &param_owners);

            // Scope: owning method (params within the same method must be unique)
            let scope_key = param_owners
                .get(&rid)
                .map(|&method_rid| 0x0600_0000u64 | method_rid as u64)
                .unwrap_or(0);
            let new_name = self.suggest_unique_name(scope_key, &context);
            self.entries.push(RenameEntry {
                table_id: TableId::Param,
                rid,
                string_index: name_index,
                new_name,
            });
        }
    }

    /// Phase 3b: Renames obfuscated methods in callees-first order.
    ///
    /// Uses topological ordering from the call graph so that callee names
    /// are available as context when renaming callers. This propagation
    /// is the key advantage of the cascade architecture.
    fn rename_methods(&mut self) {
        let Some(tables) = self.assembly.tables() else {
            return;
        };
        let Some(strings) = self.assembly.strings() else {
            return;
        };
        let Some(methoddef_table) = tables.table::<MethodDefRaw>() else {
            return;
        };
        let typedef_table = tables.table::<TypeDefRaw>();

        // Build MethodDef RID → declaring TypeDef RID map for scope-based dedup
        let method_owners = typedef_table
            .map(|tdt| build_member_owner_map(tdt, methoddef_table.row_count, |td| td.method_list))
            .unwrap_or_default();

        // Determine method processing order: topological (callees first) if available
        let method_order = self.build_method_order(methoddef_table.row_count);

        for rid in method_order {
            let Some(methoddef) = methoddef_table.get(rid) else {
                continue;
            };
            let name_index = methoddef.name;
            if name_index == 0 {
                continue;
            }
            let Ok(name) = strings.get(name_index as usize) else {
                continue;
            };
            if !is_obfuscated_name(name) || is_special_name(name) {
                continue;
            }
            if !self.seen_indices.insert(name_index) {
                continue;
            }

            // Build method token from RID
            let method_token = Token::new(0x0600_0000 | rid);

            // Build context with available features
            let context = self.build_method_context(method_token);

            // Scope: declaring type (methods within the same type must be unique)
            let scope_key = method_owners
                .get(&rid)
                .map(|&type_rid| 0x0200_0000u64 | type_rid as u64)
                .unwrap_or(0);
            let new_name = self.suggest_unique_name(scope_key, &context);

            // Record the committed name for context propagation
            self.committed.insert(method_token, new_name.clone());

            self.entries.push(RenameEntry {
                table_id: TableId::MethodDef,
                rid,
                string_index: name_index,
                new_name,
            });
        }
    }

    /// Phase 3c: Renames obfuscated fields.
    ///
    /// Uses already-committed method names as sibling context and API call
    /// anchors from SSA analysis.
    fn rename_fields(&mut self) {
        let Some(tables) = self.assembly.tables() else {
            return;
        };
        let Some(strings) = self.assembly.strings() else {
            return;
        };
        let Some(field_table) = tables.table::<FieldRaw>() else {
            return;
        };
        let typedef_table = tables.table::<TypeDefRaw>();

        // Build Field RID → declaring TypeDef RID map for scope-based dedup
        let field_owners = typedef_table
            .map(|tdt| build_member_owner_map(tdt, field_table.row_count, |td| td.field_list))
            .unwrap_or_default();

        for rid in 1..=field_table.row_count {
            let Some(field) = field_table.get(rid) else {
                continue;
            };
            let name_index = field.name;
            if name_index == 0 {
                continue;
            }
            let Ok(name) = strings.get(name_index as usize) else {
                continue;
            };
            if !is_obfuscated_name(name) || is_special_name(name) {
                continue;
            }
            if !self.seen_indices.insert(name_index) {
                continue;
            }

            let field_token = Token::new(0x0400_0000 | rid);
            let context = self.build_field_context(field_token);

            // Scope: declaring type (fields within the same type must be unique)
            let scope_key = field_owners
                .get(&rid)
                .map(|&type_rid| 0x0400_0000u64 | type_rid as u64)
                .unwrap_or(0);
            let new_name = self.suggest_unique_name(scope_key, &context);
            self.committed.insert(field_token, new_name.clone());

            self.entries.push(RenameEntry {
                table_id: TableId::Field,
                rid,
                string_index: name_index,
                new_name,
            });
        }
    }

    /// Phase 4: Renames obfuscated type definitions.
    ///
    /// Uses already-renamed member names as context signals. Types are
    /// renamed last because their names benefit most from knowing the
    /// names of their members.
    fn rename_types(&mut self) {
        let Some(tables) = self.assembly.tables() else {
            return;
        };
        let Some(strings) = self.assembly.strings() else {
            return;
        };
        let Some(typedef_table) = tables.table::<TypeDefRaw>() else {
            return;
        };

        for rid in 1..=typedef_table.row_count {
            // Skip <Module> (RID 1)
            if rid == 1 {
                continue;
            }

            let Some(typedef) = typedef_table.get(rid) else {
                continue;
            };
            let name_index = typedef.type_name;
            if name_index == 0 {
                continue;
            }
            let Ok(name) = strings.get(name_index as usize) else {
                continue;
            };
            if !is_obfuscated_name(name) || is_special_name(name) {
                continue;
            }
            if !self.seen_indices.insert(name_index) {
                continue;
            }

            let type_token = Token::new(0x0200_0000 | rid);
            let context = self.build_type_context(type_token);

            // Scope: namespace (types within the same namespace must be unique).
            // Use the namespace string heap index shifted to avoid collision with token-based keys.
            let scope_key = 0xFF00_0000u64 | typedef.type_namespace as u64;
            let new_name = self.suggest_unique_name(scope_key, &context);
            self.committed.insert(type_token, new_name.clone());

            self.entries.push(RenameEntry {
                table_id: TableId::TypeDef,
                rid,
                string_index: name_index,
                new_name,
            });
        }
    }

    /// Determines method processing order.
    ///
    /// If a call graph is available, returns RIDs in topological order
    /// (callees first). Otherwise falls back to sequential RID order.
    ///
    /// # Arguments
    ///
    /// * `row_count` - Total number of rows in the MethodDef table.
    ///
    /// # Returns
    ///
    /// An ordered list of method RIDs to process.
    fn build_method_order(&self, row_count: u32) -> Vec<u32> {
        if let Some(ref cg) = self.call_graph {
            let topo = cg.topological_order();

            // Map tokens to RIDs, keeping only MethodDef tokens
            let mut ordered_rids: Vec<u32> = topo
                .iter()
                .filter(|t| t.table() == 0x06)
                .map(|t| t.row())
                .filter(|&rid| rid >= 1 && rid <= row_count)
                .collect();

            // Add any RIDs not in the call graph (methods without calls)
            let ordered_set: HashSet<u32> = ordered_rids.iter().copied().collect();
            for rid in 1..=row_count {
                if !ordered_set.contains(&rid) {
                    ordered_rids.push(rid);
                }
            }

            ordered_rids
        } else {
            (1..=row_count).collect()
        }
    }

    /// Builds a [`RenameContext`] for a method.
    ///
    /// Populates the context with:
    /// - Return type and parameter types from the method signature
    /// - Interfaces and base class from the declaring type
    /// - Already-renamed sibling methods for context propagation
    /// - SSA-based features (call targets, strings, field accesses, anchors)
    /// - Call-site skeleton (small methods) or phase narrative (large methods)
    ///
    /// # Arguments
    ///
    /// * `method_token` - The token of the method to build context for.
    ///
    /// # Returns
    ///
    /// A fully-populated rename context for method naming.
    fn build_method_context(&self, method_token: Token) -> RenameContext {
        let mut context = RenameContext {
            kind: Some(IdentifierKind::Method),
            ..Default::default()
        };

        // Get method metadata
        if let Some(method) = self.assembly.method(&method_token) {
            // Return type
            context.dotnet_type = Some(method.signature.return_type.to_string());

            // Parameters
            context.parameters = method
                .signature
                .params
                .iter()
                .map(|p| ParamInfo {
                    dotnet_type: p.to_string(),
                    known_name: None,
                })
                .collect();

            // Interfaces from declaring type
            if let Some(declaring_type) = method.declaring_type_rc() {
                // Collect interface names
                for (_, iface_entry) in declaring_type.interfaces.iter() {
                    if let Some(name) = iface_entry.interface.fullname() {
                        context.interfaces.push(name);
                    }
                }
                // Base class
                if let Some(base) = declaring_type.base() {
                    context.base_class = Some(base.fullname());
                }
                // Siblings: already-renamed methods in the same type
                for sibling_method in declaring_type.methods() {
                    if let Some(name) = self.committed.get(&sibling_method.token) {
                        context.siblings.push(name.clone());
                    }
                }
            }
        }

        // SSA-based features
        let has_ssa = self.ssa_cache.contains_key(&method_token);
        if let Some(ssa) = self.ssa_cache.get(&method_token) {
            context.call_targets = features::collect_call_targets(ssa, self.assembly);
            context.string_literals = features::collect_string_literals(ssa, self.assembly);
            context.field_accesses = features::collect_field_accesses(ssa, self.assembly);
            if let Some(method_anchors) = self.anchors.get(&method_token) {
                context.api_calls = method_anchors.clone();
            }

            // Small method: call-site skeleton
            if ssa.instruction_count() <= self.config.small_method_threshold {
                context.call_site_skeleton = phases::build_call_site_skeleton(ssa, self.assembly);
            }

            // Large method: phase narrative
            if let Some(narrative) = self.phase_narratives.get(&method_token) {
                context.phase_narrative = narrative.clone();
            }
        }

        // Caller-side context (propagated from methods that call this one)
        if let Some(caller_ctx) = self.caller_contexts.get(&method_token) {
            context.caller_context = caller_ctx.clone();
        }

        log::debug!(
            "Method context 0x{:08X}: ssa={}, calls={}, strings={}, fields={}, skeleton={}, phases={}, callers={}",
            method_token.value(),
            has_ssa,
            context.call_targets.len(),
            context.string_literals.len(),
            context.field_accesses.len(),
            context.call_site_skeleton.is_some(),
            context.phase_narrative.len(),
            context.caller_context.len(),
        );

        context
    }

    /// Builds a [`RenameContext`] for a field.
    ///
    /// Populates the context with:
    /// - Field type from the field signature
    /// - Already-renamed sibling members (methods and fields)
    /// - API call anchors from methods that reference this field
    ///
    /// # Arguments
    ///
    /// * `field_token` - The token of the field to build context for.
    ///
    /// # Returns
    ///
    /// A fully-populated rename context for field naming.
    fn build_field_context(&self, field_token: Token) -> RenameContext {
        let mut context = RenameContext {
            kind: Some(IdentifierKind::Field),
            ..Default::default()
        };

        let resolver = self.assembly.resolver();

        // Get declaring type for sibling context
        if let Some(declaring_type) = resolver.declaring_type_of_field(field_token) {
            // Already-renamed siblings (methods and other fields)
            for method in declaring_type.methods() {
                if let Some(name) = self.committed.get(&method.token) {
                    context.siblings.push(name.clone());
                }
            }
            for (_, field_rc) in declaring_type.fields.iter() {
                if let Some(name) = self.committed.get(&field_rc.token) {
                    context.siblings.push(name.clone());
                }
            }

            // Find field type from metadata
            for (_, field_rc) in declaring_type.fields.iter() {
                if field_rc.token == field_token {
                    context.dotnet_type = Some(field_rc.signature.base.to_string());
                    break;
                }
            }
        }

        // Collect API call anchors: find methods that use this field
        self.collect_field_api_anchors(field_token, &mut context.api_calls);

        context
    }

    /// Builds a [`RenameContext`] for a type.
    ///
    /// Populates the context with:
    /// - Already-renamed member names as siblings
    /// - Base class and interface information
    ///
    /// # Arguments
    ///
    /// * `type_token` - The token of the type to build context for.
    ///
    /// # Returns
    ///
    /// A fully-populated rename context for type naming.
    fn build_type_context(&self, type_token: Token) -> RenameContext {
        let mut context = RenameContext {
            kind: Some(IdentifierKind::Type),
            ..Default::default()
        };

        if let Some(cil_type) = self.assembly.types().resolve(&type_token) {
            // Already-renamed members as siblings
            for method in cil_type.methods() {
                if let Some(name) = self.committed.get(&method.token) {
                    context.siblings.push(name.clone());
                }
            }
            for (_, field_rc) in cil_type.fields.iter() {
                if let Some(name) = self.committed.get(&field_rc.token) {
                    context.siblings.push(name.clone());
                }
            }

            // Base class
            if let Some(base) = cil_type.base() {
                context.base_class = Some(base.fullname());
            }

            // Interfaces
            for (_, iface_entry) in cil_type.interfaces.iter() {
                if let Some(name) = iface_entry.interface.fullname() {
                    context.interfaces.push(name);
                }
            }
        }

        context
    }

    /// Builds a [`RenameContext`] for a parameter.
    ///
    /// Resolves the owning method from the param→method mapping, and populates:
    /// - `parent_type`: the owning method's name (committed name or original)
    /// - `dotnet_type`: the parameter's .NET type from the method signature
    /// - `api_calls`: anchors from SSA analysis of the owning method
    /// - `call_targets`: external call targets from the owning method's SSA
    /// - `siblings`: already-committed param names in the same method
    fn build_param_context(
        &self,
        param_rid: u32,
        param_sequence: u32,
        param_owners: &HashMap<u32, u32>,
    ) -> RenameContext {
        let mut context = RenameContext {
            kind: Some(IdentifierKind::Parameter),
            ..Default::default()
        };

        let Some(&method_rid) = param_owners.get(&param_rid) else {
            return context;
        };

        let method_token = Token::new(0x0600_0000 | method_rid);

        // Parent method name (committed or original)
        if let Some(name) = self.committed.get(&method_token) {
            context.parent_type = Some(name.clone());
        } else if let Some(method) = self.assembly.method(&method_token) {
            if !is_obfuscated_name(&method.name) {
                context.parent_type = Some(method.name.clone());
            }
        }

        // Parameter type from method signature
        if let Some(method) = self.assembly.method(&method_token) {
            // param.sequence is 1-based (0 = return type), so index = sequence - 1
            let sig_index = (param_sequence as usize).saturating_sub(1);
            if sig_index < method.signature.params.len() {
                context.dotnet_type = Some(method.signature.params[sig_index].to_string());
            }
        }

        // API call anchors from the owning method
        if let Some(method_anchors) = self.anchors.get(&method_token) {
            context.api_calls = method_anchors.clone();
        }

        // Call targets from the owning method's SSA
        if let Some(ssa) = self.ssa_cache.get(&method_token) {
            context.call_targets = features::collect_call_targets(ssa, self.assembly);
        }

        context
    }

    /// Collects API call anchors for a field by scanning methods that reference it.
    ///
    /// Searches the SSA cache for methods that load/store the target field
    /// and also make external API calls. When both conditions are met, the
    /// API call info is added as an anchor for the field.
    ///
    /// # Arguments
    ///
    /// * `field_token` - The token of the field to find anchors for.
    /// * `anchors` - Output vector to append found anchors to.
    fn collect_field_api_anchors(&self, field_token: Token, anchors: &mut Vec<ApiCallInfo>) {
        // Resolve the field's qualified name once
        let field_name = self
            .assembly
            .resolver()
            .declaring_type_of_field(field_token)
            .and_then(|t| {
                for (_, f) in t.fields.iter() {
                    if f.token == field_token {
                        return Some(format!("{}.{}", t.fullname(), f.name));
                    }
                }
                None
            });
        let Some(field_name) = field_name else {
            return;
        };

        // Scan methods that have cached anchors and also access this field
        for (method_token, method_anchors) in &self.anchors {
            let Some(ssa) = self.ssa_cache.get(method_token) else {
                continue;
            };
            let field_accesses = features::collect_field_accesses(ssa, self.assembly);
            if field_accesses.contains(&field_name) {
                if let Some(anchor) = method_anchors.first() {
                    anchors.push(anchor.clone());
                }
            }
        }
    }

    /// Suggests a name using the primary provider, falling back if needed.
    ///
    /// Tries the primary provider first, validates the result, then falls
    /// back to the fallback provider if the primary fails. As a last resort,
    /// returns a generic name based on the identifier kind.
    ///
    /// # Arguments
    ///
    /// * `context` - The rename context with extracted features.
    ///
    /// # Returns
    ///
    /// A validated identifier name (never empty).
    fn suggest_name_with_fallback(&self, context: &RenameContext) -> String {
        let kind = context.kind.unwrap_or(IdentifierKind::Method);
        let max_length = self.config.max_name_length;

        // Try primary provider
        if let Ok(Some(name)) = self.provider.suggest_name(context) {
            if let Some(validated) = validate::validate_name(&name, kind, max_length) {
                return validated;
            }
        }

        // Fall back (still validate for consistent casing)
        if let Ok(Some(name)) = self.fallback.suggest_name(context) {
            if let Some(validated) = validate::validate_name(&name, kind, max_length) {
                return validated;
            }
            return name;
        }

        // Last resort: use kind prefix (shouldn't reach here)
        match kind {
            IdentifierKind::Type => "UnknownType".to_string(),
            IdentifierKind::Method => "unknownMethod".to_string(),
            IdentifierKind::Field => "unknownField".to_string(),
            IdentifierKind::Parameter => "unknownParam".to_string(),
        }
    }

    /// Maximum number of LLM retries before falling back to numeric suffixes.
    const MAX_DEDUP_RETRIES: usize = 3;

    /// Suggests a name that is unique within its scope.
    ///
    /// 1. Asks the provider for a name via [`suggest_name_with_fallback`].
    /// 2. If the name is already used in this scope, re-queries the provider
    ///    with the duplicate added to [`RenameContext::rejected_names`], giving
    ///    the LLM a chance to suggest something genuinely different.
    /// 3. After [`MAX_DEDUP_RETRIES`] failed retries, falls back to appending
    ///    `_2`, `_3`, etc.
    ///
    /// # Arguments
    ///
    /// * `scope_key` - Scope discriminator (declaring type token for methods/fields,
    ///   owning method for params, namespace hash for types).
    /// * `context` - The rename context (will be cloned for retries if needed).
    fn suggest_unique_name(&mut self, scope_key: u64, context: &RenameContext) -> String {
        let name = self.suggest_name_with_fallback(context);

        // Fast path: name is unique in scope
        if self.is_name_available(scope_key, &name) {
            self.reserve_name(scope_key, &name);
            return name;
        }

        // Retry with rejected_names to nudge the LLM toward a different suggestion
        let mut rejected = context.rejected_names.clone();
        rejected.push(name.clone());

        for _ in 0..Self::MAX_DEDUP_RETRIES {
            let mut retry_ctx = context.clone();
            retry_ctx.rejected_names = rejected.clone();

            let candidate = self.suggest_name_with_fallback(&retry_ctx);
            if self.is_name_available(scope_key, &candidate) {
                self.reserve_name(scope_key, &candidate);
                return candidate;
            }
            rejected.push(candidate);
        }

        // All retries produced duplicates — fall back to numeric suffix
        let mut suffix = 2u32;
        loop {
            let candidate = format!("{name}_{suffix}");
            if self.is_name_available(scope_key, &candidate) {
                self.reserve_name(scope_key, &candidate);
                return candidate;
            }
            suffix += 1;
        }
    }

    /// Checks whether a name is available (not yet used) within a scope.
    fn is_name_available(&self, scope_key: u64, name: &str) -> bool {
        self.used_names
            .get(&scope_key)
            .is_none_or(|used| !used.contains(name))
    }

    /// Marks a name as used within a scope.
    fn reserve_name(&mut self, scope_key: u64, name: &str) {
        self.used_names
            .entry(scope_key)
            .or_default()
            .insert(name.to_string());
    }
}

/// Builds a mapping from Param RID → owning MethodDef RID.
///
/// Each MethodDef row has a `param_list` column pointing to the first Param RID
/// belonging to that method. The range extends to the next method's `param_list`
/// or the end of the Param table.
fn build_param_owner_map(
    methoddef_table: &crate::metadata::tables::MetadataTable<'_, MethodDefRaw>,
    param_row_count: u32,
) -> HashMap<u32, u32> {
    let mut map = HashMap::new();

    for method_rid in 1..=methoddef_table.row_count {
        let Some(method) = methoddef_table.get(method_rid) else {
            continue;
        };
        let param_start = method.param_list;
        if param_start == 0 {
            continue;
        }

        // End is next method's param_list or end of table
        let param_end = if method_rid < methoddef_table.row_count {
            methoddef_table
                .get(method_rid + 1)
                .map(|next| next.param_list)
                .unwrap_or(param_row_count + 1)
        } else {
            param_row_count + 1
        };

        for param_rid in param_start..param_end {
            map.insert(param_rid, method_rid);
        }
    }

    map
}

/// Builds a mapping from member RID → declaring TypeDef RID.
///
/// Works for both MethodDef and Field tables by using a closure to extract
/// the list-start column (`method_list` or `field_list`) from each TypeDef row.
fn build_member_owner_map(
    typedef_table: &crate::metadata::tables::MetadataTable<'_, TypeDefRaw>,
    member_row_count: u32,
    get_list_start: fn(&TypeDefRaw) -> u32,
) -> HashMap<u32, u32> {
    let mut map = HashMap::new();

    for type_rid in 1..=typedef_table.row_count {
        let Some(typedef) = typedef_table.get(type_rid) else {
            continue;
        };
        let start = get_list_start(&typedef);
        if start == 0 {
            continue;
        }

        let end = if type_rid < typedef_table.row_count {
            typedef_table
                .get(type_rid + 1)
                .map(|next| get_list_start(&next))
                .unwrap_or(member_row_count + 1)
        } else {
            member_row_count + 1
        };

        for member_rid in start..end {
            map.insert(member_rid, type_rid);
        }
    }

    map
}

/// Generates a phase label from call targets or opcode profile.
///
/// Used as a fallback when no LLM provider is available. Produces simple
/// descriptive labels like "Call ReadAllText" or "Transform data" based
/// on the available information in the phase.
///
/// # Arguments
///
/// * `phase` - The phase info to generate a label for.
/// * `_prefix` - Unused FIM prefix (reserved for future use).
/// * `_suffix` - Unused FIM suffix (reserved for future use).
///
/// # Returns
///
/// A descriptive label string, or `None` if no label can be generated.
fn generate_phase_label_from_context(
    phase: &PhaseInfo,
    _prefix: &str,
    _suffix: &str,
) -> Option<String> {
    if !phase.call_targets.is_empty() {
        // Use the first call target as a label
        let first = &phase.call_targets[0];
        // Extract just the method name part
        let label = if let Some(idx) = first.rfind("::") {
            &first[idx + 2..]
        } else {
            first.as_str()
        };
        Some(format!("Call {label}"))
    } else if let Some(ref profile) = phase.opcode_profile {
        if profile.bitwise > 0 || profile.arithmetic > 0 {
            Some("Transform data".to_string())
        } else if profile.array > 0 {
            Some("Array operations".to_string())
        } else if profile.comparison > 0 {
            Some("Conditional logic".to_string())
        } else {
            Some("Process data".to_string())
        }
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        deobfuscation::{
            renamer::{
                cascade::{
                    build_param_owner_map, generate_phase_label_from_context, CascadeRenamer,
                },
                context::{IdentifierKind, OpcodeProfile, PhaseInfo, RenameContext},
                features, phases,
                providers::SimpleProvider,
                RenameProvider, SmartRenameConfig,
            },
            utils::{is_obfuscated_name, is_special_name},
        },
        metadata::{
            tables::{FieldRaw, MethodDefRaw, ParamRaw, TableId, TypeDefRaw},
            token::Token,
            validation::ValidationConfig,
        },
        test::helpers::load_sample,
        CilObject,
    };

    const RENAMER_SAMPLE: &str = "tests/samples/packers/bitmono/0.39.0/bitmono_renamer.exe";

    #[test]
    fn test_generate_phase_label_from_calls() {
        let phase = PhaseInfo {
            label: String::new(),
            call_targets: vec!["System.IO.File::ReadAllText".to_string()],
            opcode_profile: None,
            structure: None,
        };
        let label = generate_phase_label_from_context(&phase, "", "");
        assert_eq!(label, Some("Call ReadAllText".to_string()));
    }

    #[test]
    fn test_generate_phase_label_from_profile() {
        let phase = PhaseInfo {
            label: String::new(),
            call_targets: vec![],
            opcode_profile: Some(OpcodeProfile {
                bitwise: 5,
                arithmetic: 3,
                ..Default::default()
            }),
            structure: None,
        };
        let label = generate_phase_label_from_context(&phase, "", "");
        assert_eq!(label, Some("Transform data".to_string()));
    }

    #[test]
    fn test_generate_phase_label_array() {
        let phase = PhaseInfo {
            label: String::new(),
            call_targets: vec![],
            opcode_profile: Some(OpcodeProfile {
                array: 4,
                ..Default::default()
            }),
            structure: None,
        };
        let label = generate_phase_label_from_context(&phase, "", "");
        assert_eq!(label, Some("Array operations".to_string()));
    }

    #[test]
    fn test_cascade_simple_fallback() {
        // Test that the cascade with SimpleProvider produces valid names
        let provider = SimpleProvider::new();
        let ctx = RenameContext {
            kind: Some(IdentifierKind::Type),
            ..Default::default()
        };
        let name = provider.suggest_name(&ctx).unwrap().unwrap();
        assert_eq!(name, "A");

        let ctx2 = RenameContext {
            kind: Some(IdentifierKind::Method),
            ..Default::default()
        };
        let name2 = provider.suggest_name(&ctx2).unwrap().unwrap();
        assert_eq!(name2, "a");
    }

    #[test]
    fn test_cascade_context_propagation() {
        // Verify that RenameContext can hold sibling names
        let context = RenameContext {
            kind: Some(IdentifierKind::Type),
            siblings: vec![
                "ProcessData".to_string(),
                "Initialize".to_string(),
                "Shutdown".to_string(),
            ],
            interfaces: vec!["IDisposable".to_string()],
            base_class: Some("System.Object".to_string()),
            ..Default::default()
        };

        assert_eq!(context.siblings.len(), 3);
        assert_eq!(context.interfaces.len(), 1);
        assert!(context.base_class.is_some());
    }

    /// Integration test: cascade on a real sample with SimpleProvider.
    #[test]
    fn test_cascade_on_bitmono_sample() {
        let path = "tests/samples/packers/bitmono/0.39.0/bitmono_renamer.exe";
        if !std::path::Path::new(path).exists() {
            eprintln!("Skipping: sample not found");
            return;
        }

        let assembly =
            CilObject::from_path_with_validation(path, ValidationConfig::analysis()).unwrap();

        let provider = SimpleProvider::new();
        let fallback = SimpleProvider::new();
        let config = SmartRenameConfig::default();
        let cascade = CascadeRenamer::new(&assembly, &provider, &fallback, config);
        let entries = cascade.execute().unwrap();

        // Should produce rename entries
        assert!(!entries.is_empty(), "Cascade should produce rename entries");

        // All entries should have non-empty names
        for entry in &entries {
            assert!(!entry.new_name.is_empty(), "Name should not be empty");
        }
    }

    /// Verifies that cascade rename entries follow the correct naming patterns
    /// for each identifier kind (sequential alphabetic for SimpleProvider).
    #[test]
    fn test_cascade_rename_patterns() {
        let path = "tests/samples/packers/bitmono/0.39.0/bitmono_renamer.exe";
        if !std::path::Path::new(path).exists() {
            eprintln!("Skipping: sample not found");
            return;
        }

        let assembly =
            CilObject::from_path_with_validation(path, ValidationConfig::analysis()).unwrap();

        let provider = SimpleProvider::new();
        let fallback = SimpleProvider::new();
        let config = SmartRenameConfig::default();
        let cascade = CascadeRenamer::new(&assembly, &provider, &fallback, config);
        let entries = cascade.execute().unwrap();

        // Verify naming patterns per table type.
        // Note: the cascade validates primary provider output, which applies
        // PascalCase to methods (turning "a" → "A"). Type names are already
        // uppercase. Field/param names have distinctive prefixes.
        for entry in &entries {
            match entry.table_id {
                TableId::TypeDef => {
                    // Type names: PascalCase alphabetic (A, B, ..., AA, AB, ...)
                    assert!(
                        entry.new_name.chars().next().unwrap().is_ascii_uppercase(),
                        "Type name '{}' should start with uppercase",
                        entry.new_name
                    );
                    assert!(
                        entry.new_name.chars().all(|c| c.is_ascii_alphabetic()),
                        "Type name '{}' should be alphabetic",
                        entry.new_name
                    );
                }
                TableId::MethodDef => {
                    // Method names: PascalCased after validation (A, B, ..., Aa, Ab, ...)
                    assert!(
                        entry.new_name.chars().next().unwrap().is_ascii_uppercase(),
                        "Method name '{}' should start with uppercase (PascalCase)",
                        entry.new_name
                    );
                    assert!(
                        entry.new_name.chars().all(|c| c.is_ascii_alphabetic()),
                        "Method name '{}' should be alphabetic",
                        entry.new_name
                    );
                }
                TableId::Field => {
                    // Field names have f_ prefix: f_a, f_b, ...
                    assert!(
                        entry.new_name.starts_with("f_"),
                        "Field name '{}' should start with 'f_'",
                        entry.new_name
                    );
                }
                TableId::Param => {
                    // Param names have p_ prefix: p_a, p_b, ...
                    assert!(
                        entry.new_name.starts_with("p_"),
                        "Param name '{}' should start with 'p_'",
                        entry.new_name
                    );
                }
                _ => {}
            }
        }
    }

    /// Verifies that well-known .NET names are NOT renamed by the cascade.
    #[test]
    fn test_cascade_preserves_known_names() {
        let path = "tests/samples/packers/bitmono/0.39.0/original.exe";
        if !std::path::Path::new(path).exists() {
            eprintln!("Skipping: original sample not found");
            return;
        }

        // Original.exe has NO obfuscated names — cascade should produce zero renames
        let assembly =
            CilObject::from_path_with_validation(path, ValidationConfig::analysis()).unwrap();

        let provider = SimpleProvider::new();
        let fallback = SimpleProvider::new();
        let config = SmartRenameConfig::default();
        let cascade = CascadeRenamer::new(&assembly, &provider, &fallback, config);
        let entries = cascade.execute().unwrap();

        assert!(
            entries.is_empty(),
            "Original (non-obfuscated) assembly should produce zero renames, got {}",
            entries.len()
        );
    }

    /// Verifies that the cascade produces the correct entry counts per table
    /// on a known obfuscated sample.
    #[test]
    fn test_cascade_entry_counts() {
        let path = "tests/samples/packers/bitmono/0.39.0/bitmono_renamer.exe";
        if !std::path::Path::new(path).exists() {
            eprintln!("Skipping: sample not found");
            return;
        }

        let assembly =
            CilObject::from_path_with_validation(path, ValidationConfig::analysis()).unwrap();

        let provider = SimpleProvider::new();
        let fallback = SimpleProvider::new();
        let config = SmartRenameConfig::default();
        let cascade = CascadeRenamer::new(&assembly, &provider, &fallback, config);
        let entries = cascade.execute().unwrap();

        // Count entries by table
        let type_count = entries
            .iter()
            .filter(|e| e.table_id == TableId::TypeDef)
            .count();
        let method_count = entries
            .iter()
            .filter(|e| e.table_id == TableId::MethodDef)
            .count();
        let field_count = entries
            .iter()
            .filter(|e| e.table_id == TableId::Field)
            .count();
        let param_count = entries
            .iter()
            .filter(|e| e.table_id == TableId::Param)
            .count();

        // BitMono renamer obfuscation renames types, methods, fields — verify we found them
        assert!(
            type_count > 0,
            "Should find obfuscated type names to rename"
        );
        assert!(
            method_count > 0,
            "Should find obfuscated method names to rename"
        );
        // Fields and params may or may not be present depending on the sample
        eprintln!(
            "Cascade entries: types={type_count}, methods={method_count}, \
             fields={field_count}, params={param_count}"
        );
    }

    /// Verifies that the cascade with custom config uses the configured thresholds.
    #[test]
    fn test_cascade_respects_config() {
        let path = "tests/samples/packers/bitmono/0.39.0/bitmono_renamer.exe";
        if !std::path::Path::new(path).exists() {
            eprintln!("Skipping: sample not found");
            return;
        }

        let assembly =
            CilObject::from_path_with_validation(path, ValidationConfig::analysis()).unwrap();

        // Use a very small method threshold to force phase decomposition
        let config = SmartRenameConfig {
            small_method_threshold: 5,
            max_name_length: 10,
            ..SmartRenameConfig::default()
        };

        let provider = SimpleProvider::new();
        let fallback = SimpleProvider::new();
        let cascade = CascadeRenamer::new(&assembly, &provider, &fallback, config);
        let entries = cascade.execute().unwrap();

        // Should still produce valid entries
        assert!(!entries.is_empty(), "Should produce rename entries");

        // Names should respect the max length
        for entry in &entries {
            assert!(
                entry.new_name.len() <= 10,
                "Name '{}' exceeds max_name_length=10",
                entry.new_name
            );
        }
    }

    /// Verifies that method context is populated with SSA features.
    ///
    /// Uses original.exe (non-obfuscated) where method names like SayHello,
    /// DemoLoop etc. have known call targets. The cascade shouldn't rename
    /// these (they're not obfuscated), but we can verify the infrastructure
    /// populates SSA by building contexts directly.
    #[test]
    fn test_cascade_ssa_context_populated() {
        let path = "tests/samples/packers/confuserex/1.6.0/original.exe";
        if !std::path::Path::new(path).exists() {
            eprintln!("Skipping: sample not found");
            return;
        }

        let assembly =
            CilObject::from_path_with_validation(path, ValidationConfig::analysis()).unwrap();

        let provider = SimpleProvider::new();
        let fallback = SimpleProvider::new();
        let config = SmartRenameConfig::default();
        let mut cascade = CascadeRenamer::new(&assembly, &provider, &fallback, config);
        cascade.build_infrastructure();

        // Verify SSA was built for at least some methods
        assert!(
            !cascade.ssa_cache.is_empty(),
            "SSA cache should be populated for original.exe (got 0/{} methods)",
            assembly.methods().len()
        );

        // Find the SayHello method token and verify its context has call targets
        let sayhello_token = assembly
            .methods()
            .iter()
            .find(|e| e.value().name == "SayHello")
            .map(|e| *e.key());

        if let Some(token) = sayhello_token {
            let context = cascade.build_method_context(token);
            assert!(
                !context.call_targets.is_empty(),
                "SayHello context should have call targets (e.g., Console.WriteLine)"
            );
            assert!(
                context.call_targets.iter().any(|t| t.contains("WriteLine")),
                "SayHello should call WriteLine, got: {:?}",
                context.call_targets
            );
        }
    }

    /// Verifies that SSA context is populated for obfuscated methods too.
    ///
    /// The ConfuserEx maximum sample has obfuscated method names. After the
    /// deobfuscation engine runs, methods should have parsed bodies. But even
    /// loading the raw sample, some methods should have parseable IL.
    #[test]
    fn test_cascade_context_quality_on_obfuscated() {
        let path = "tests/samples/packers/confuserex/1.6.0/mkaring_maximum.exe";
        if !std::path::Path::new(path).exists() {
            eprintln!("Skipping: sample not found");
            return;
        }

        let assembly =
            CilObject::from_path_with_validation(path, ValidationConfig::analysis()).unwrap();

        let provider = SimpleProvider::new();
        let fallback = SimpleProvider::new();
        let config = SmartRenameConfig::default();
        let mut cascade = CascadeRenamer::new(&assembly, &provider, &fallback, config);
        cascade.build_infrastructure();

        let total_methods = assembly.methods().len();
        let ssa_count = cascade.ssa_cache.len();

        eprintln!("Obfuscated sample: {ssa_count}/{total_methods} methods have SSA");

        // Check how many obfuscated methods have non-empty contexts
        let mut with_calls = 0;
        let mut with_skeleton = 0;
        let mut with_phases = 0;
        let mut empty_context = 0;

        // Run phase decomposition
        cascade.decompose_and_label_phases();

        let tables = assembly.tables().unwrap();
        let strings = assembly.strings().unwrap();
        let methoddef_table = tables.table::<MethodDefRaw>().unwrap();

        for rid in 1..=methoddef_table.row_count {
            let Some(methoddef) = methoddef_table.get(rid) else {
                continue;
            };
            let name_index = methoddef.name;
            if name_index == 0 {
                continue;
            }
            let Ok(name) = strings.get(name_index as usize) else {
                continue;
            };
            if !is_obfuscated_name(name) || is_special_name(name) {
                continue;
            }

            let method_token = Token::new(0x0600_0000 | rid);
            let context = cascade.build_method_context(method_token);

            if !context.call_targets.is_empty() {
                with_calls += 1;
            }
            if context.call_site_skeleton.is_some() {
                with_skeleton += 1;
            }
            if !context.phase_narrative.is_empty() {
                with_phases += 1;
            }
            if context.call_targets.is_empty()
                && context.call_site_skeleton.is_none()
                && context.phase_narrative.is_empty()
                && context.string_literals.is_empty()
            {
                empty_context += 1;
            }
        }

        eprintln!(
            "Context quality: with_calls={with_calls}, with_skeleton={with_skeleton}, \
             with_phases={with_phases}, empty={empty_context}"
        );

        // At least some obfuscated methods should have non-empty context
        let total_with_context = with_calls + with_skeleton + with_phases;
        assert!(
            total_with_context > 0 || ssa_count == 0,
            "If SSA is available, at least some methods should have context"
        );
    }

    /// All 17 obfuscated methods in bitmono_renamer.exe must have SSA
    /// (code is intact, only names were obfuscated by BitMono FullRenamer).
    /// At least half should have non-empty call targets or skeletons.
    #[test]
    fn test_bitmono_renamer_all_methods_have_ssa() {
        let assembly = load_sample(RENAMER_SAMPLE);

        let provider = SimpleProvider::new();
        let fallback = SimpleProvider::new();
        let config = SmartRenameConfig::default();
        let mut cascade = CascadeRenamer::new(&assembly, &provider, &fallback, config);
        cascade.build_infrastructure();
        cascade.extract_anchors();
        cascade.decompose_and_label_phases();

        let tables = assembly.tables().unwrap();
        let strings = assembly.strings().unwrap();
        let methoddef_table = tables.table::<MethodDefRaw>().unwrap();

        let mut obfuscated_count = 0u32;
        let mut obfuscated_with_ssa = 0u32;
        let mut obfuscated_with_context = 0u32;

        for rid in 1..=methoddef_table.row_count {
            let Some(methoddef) = methoddef_table.get(rid) else {
                continue;
            };
            let Ok(name) = strings.get(methoddef.name as usize) else {
                continue;
            };
            if !is_obfuscated_name(name) || is_special_name(name) {
                continue;
            }

            obfuscated_count += 1;
            let method_token = Token::new(0x0600_0000 | rid);

            if cascade.ssa_cache.contains_key(&method_token) {
                obfuscated_with_ssa += 1;
            }

            let ctx = cascade.build_method_context(method_token);
            if !ctx.call_targets.is_empty()
                || ctx.call_site_skeleton.is_some()
                || !ctx.string_literals.is_empty()
            {
                obfuscated_with_context += 1;
            }
        }

        assert_eq!(obfuscated_count, 17, "Expected 17 obfuscated methods");
        assert_eq!(
            obfuscated_with_ssa, 17,
            "All 17 methods should have SSA (code intact, only names obfuscated)"
        );
        assert!(
            obfuscated_with_context >= 10,
            "At least 10/17 methods should have call targets, skeleton, or strings — got {obfuscated_with_context}"
        );
    }

    /// Verify the FIM prompt text for a method with SSA actually contains
    /// the context (not just that the RenameContext fields are populated).
    /// This guards against the bug where context was collected but not rendered.
    #[test]
    fn test_bitmono_renamer_prompt_text_contains_context() {
        use crate::deobfuscation::renamer::prompt;

        let assembly = load_sample(RENAMER_SAMPLE);

        let provider = SimpleProvider::new();
        let fallback = SimpleProvider::new();
        let config = SmartRenameConfig::default();
        let mut cascade = CascadeRenamer::new(&assembly, &provider, &fallback, config.clone());
        cascade.build_infrastructure();
        cascade.extract_anchors();
        cascade.decompose_and_label_phases();

        let tables = assembly.tables().unwrap();
        let strings = assembly.strings().unwrap();
        let methoddef_table = tables.table::<MethodDefRaw>().unwrap();

        // Find the first obfuscated method with call targets
        let mut found_method_with_calls = false;
        for rid in 1..=methoddef_table.row_count {
            let Some(methoddef) = methoddef_table.get(rid) else {
                continue;
            };
            let Ok(name) = strings.get(methoddef.name as usize) else {
                continue;
            };
            if !is_obfuscated_name(name) || is_special_name(name) {
                continue;
            }

            let method_token = Token::new(0x0600_0000 | rid);
            let ctx = cascade.build_method_context(method_token);

            if ctx.call_targets.is_empty() {
                continue;
            }

            found_method_with_calls = true;

            // Build the FIM prompt and verify context is rendered
            let (prefix, _suffix) = prompt::build_fim_prompt(&ctx, config.max_phases_in_prompt);

            assert!(
                prefix.contains("API calls:"),
                "RID {rid}: prompt should contain 'API calls:' when call_targets={:?}, got:\n{prefix}",
                ctx.call_targets
            );

            // If there are string literals, they should also appear
            if !ctx.string_literals.is_empty() {
                assert!(
                    prefix.contains("Strings:"),
                    "RID {rid}: prompt should contain 'Strings:' when string_literals={:?}",
                    ctx.string_literals
                );
            }

            break; // one verified method is enough
        }

        assert!(
            found_method_with_calls,
            "Should find at least one obfuscated method with call targets"
        );
    }

    /// Verify parameter context has parent method info and type info populated.
    #[test]
    fn test_bitmono_renamer_param_context_populated() {
        use crate::metadata::tables::ParamRaw;

        let assembly = load_sample(RENAMER_SAMPLE);

        let provider = SimpleProvider::new();
        let fallback = SimpleProvider::new();
        let config = SmartRenameConfig::default();
        let mut cascade = CascadeRenamer::new(&assembly, &provider, &fallback, config);
        cascade.build_infrastructure();
        cascade.extract_anchors();

        let tables = assembly.tables().unwrap();
        let strings = assembly.strings().unwrap();
        let param_table = tables.table::<ParamRaw>().unwrap();
        let methoddef_table = tables.table::<MethodDefRaw>().unwrap();

        let param_owners = super::build_param_owner_map(methoddef_table, param_table.row_count);

        let mut obfuscated_params = 0u32;
        let mut params_with_type = 0u32;
        let mut params_with_parent_or_calls = 0u32;

        for rid in 1..=param_table.row_count {
            let Some(param) = param_table.get(rid) else {
                continue;
            };
            if param.name == 0 {
                continue;
            }
            let Ok(name) = strings.get(param.name as usize) else {
                continue;
            };
            if !is_obfuscated_name(name) || is_special_name(name) {
                continue;
            }

            obfuscated_params += 1;
            let ctx = cascade.build_param_context(rid, param.sequence, &param_owners);

            if ctx.dotnet_type.is_some() {
                params_with_type += 1;
            }
            if ctx.parent_type.is_some() || !ctx.call_targets.is_empty() {
                params_with_parent_or_calls += 1;
            }
        }

        assert_eq!(obfuscated_params, 19, "Expected 19 obfuscated params");
        assert!(
            params_with_type >= 15,
            "Most params should have dotnet_type resolved — got {params_with_type}/19"
        );
        assert!(
            params_with_parent_or_calls >= 5,
            "At least some params should have parent method or call targets — got {params_with_parent_or_calls}/19"
        );
    }

    /// SimpleProvider produces sequential names (a, b, c...), so within the same
    /// scope the cascade should dedup: if two methods in the same type would both
    /// get "A", the second should get "A_2" (or "B" if the fallback retries).
    #[test]
    fn test_cascade_dedup_prevents_duplicates() {
        let assembly = load_sample(RENAMER_SAMPLE);

        let simple = SimpleProvider::new();
        let fallback = SimpleProvider::new();
        let config = SmartRenameConfig::default();

        let renamer = CascadeRenamer::new(&assembly, &simple, &fallback, config);
        let entries = renamer.execute().unwrap();

        // Collect method entries grouped by their declaring type scope
        // For SimpleProvider, all names within a type-scope should be unique
        let method_entries: Vec<_> = entries
            .iter()
            .filter(|e| e.table_id == TableId::MethodDef)
            .collect();

        // All method names across the assembly should have no duplicates
        // within the same type (SimpleProvider generates sequential globally,
        // but the dedup mechanism should still ensure uniqueness per scope)
        let mut all_names: Vec<&str> = method_entries.iter().map(|e| e.new_name.as_str()).collect();
        let total = all_names.len();
        all_names.sort();
        all_names.dedup();
        assert_eq!(
            all_names.len(),
            total,
            "Method names should be unique — found duplicates"
        );

        // Same check for type entries
        let type_names: Vec<&str> = entries
            .iter()
            .filter(|e| e.table_id == TableId::TypeDef)
            .map(|e| e.new_name.as_str())
            .collect();
        let type_total = type_names.len();
        let mut type_unique = type_names.clone();
        type_unique.sort();
        type_unique.dedup();
        assert_eq!(
            type_unique.len(),
            type_total,
            "Type names should be unique — found duplicates"
        );
    }

    /// Verifies that caller→callee context propagation works.
    ///
    /// In original.exe, `Main` calls `Calculator::Add` with a nearby format
    /// string "Add(10, 5) = {0}". After `collect_caller_contexts()`, the Add
    /// method should have a CallerInfo entry from Main with that string.
    #[test]
    fn test_caller_context_propagation() {
        const ORIGINAL_SAMPLE: &str = "tests/samples/packers/bitmono/0.39.0/original.exe";
        let assembly = load_sample(ORIGINAL_SAMPLE);

        let provider = SimpleProvider::new();
        let fallback = SimpleProvider::new();
        let config = SmartRenameConfig::default();
        let mut cascade = CascadeRenamer::new(&assembly, &provider, &fallback, config);
        cascade.build_infrastructure();
        cascade.extract_anchors();
        cascade.collect_caller_contexts();

        // Find the Add method token (0x06000008 based on diagnostic output)
        let add_token = assembly
            .methods()
            .iter()
            .find(|e| e.value().name == "Add")
            .map(|e| *e.key())
            .expect("original.exe should have an Add method");

        let ctx = cascade.build_method_context(add_token);

        assert!(
            !ctx.caller_context.is_empty(),
            "Add's caller_context should be non-empty — Main calls Add with format strings"
        );

        let main_caller = ctx
            .caller_context
            .iter()
            .find(|ci| ci.caller_name == "Main");
        assert!(
            main_caller.is_some(),
            "Add should have caller context from Main, got callers: {:?}",
            ctx.caller_context
                .iter()
                .map(|c| &c.caller_name)
                .collect::<Vec<_>>()
        );

        let main_caller = main_caller.unwrap();
        assert!(
            main_caller.nearby_strings.iter().any(|s| s.contains("Add")),
            "Main's caller context for Add should include nearby string containing 'Add', got: {:?}",
            main_caller.nearby_strings
        );
    }

    /// Verifies that `NewObj` constructor calls appear in call_targets.
    ///
    /// In original.exe, the `Divide` method creates a `DivideByZeroException`
    /// via `newobj`. This should now appear in `collect_call_targets()`.
    #[test]
    fn test_newobj_in_call_targets() {
        const ORIGINAL_SAMPLE: &str = "tests/samples/packers/bitmono/0.39.0/original.exe";
        let assembly = load_sample(ORIGINAL_SAMPLE);

        let provider = SimpleProvider::new();
        let fallback = SimpleProvider::new();
        let config = SmartRenameConfig::default();
        let mut cascade = CascadeRenamer::new(&assembly, &provider, &fallback, config);
        cascade.build_infrastructure();

        let divide_token = assembly
            .methods()
            .iter()
            .find(|e| e.value().name == "Divide")
            .map(|e| *e.key())
            .expect("original.exe should have a Divide method");

        let ssa = cascade
            .ssa_cache
            .get(&divide_token)
            .expect("Divide should have SSA");
        let call_targets = features::collect_call_targets(ssa, &assembly);

        assert!(
            call_targets
                .iter()
                .any(|t| t.contains("DivideByZeroException")),
            "Divide's call_targets should include DivideByZeroException via NewObj, got: {:?}",
            call_targets
        );
    }

    /// Verifies that the skeleton for arithmetic methods includes operators.
    ///
    /// `Add` in original.exe is `return a + b;`. The skeleton should render
    /// the addition operator and a return with a value.
    #[test]
    fn test_skeleton_arithmetic_method() {
        const ORIGINAL_SAMPLE: &str = "tests/samples/packers/bitmono/0.39.0/original.exe";
        let assembly = load_sample(ORIGINAL_SAMPLE);

        let provider = SimpleProvider::new();
        let fallback = SimpleProvider::new();
        let config = SmartRenameConfig::default();
        let mut cascade = CascadeRenamer::new(&assembly, &provider, &fallback, config);
        cascade.build_infrastructure();

        let add_token = assembly
            .methods()
            .iter()
            .find(|e| e.value().name == "Add")
            .map(|e| *e.key())
            .expect("original.exe should have an Add method");

        let ssa = cascade
            .ssa_cache
            .get(&add_token)
            .expect("Add should have SSA");
        let skeleton = phases::build_call_site_skeleton(ssa, &assembly);

        let skeleton = skeleton.expect("Add should produce a call-site skeleton");
        assert!(
            skeleton.contains('+'),
            "Add skeleton should contain '+' operator, got:\n{skeleton}"
        );
        assert!(
            skeleton.contains("return var_"),
            "Add skeleton should contain 'return var_' (return with value), got:\n{skeleton}"
        );
    }

    /// Verifies that the skeleton for GetApiKey includes the string constant.
    ///
    /// `GetApiKey` in original.exe returns a hardcoded string literal. The
    /// skeleton should render the string and a return.
    #[test]
    fn test_skeleton_string_constant() {
        const ORIGINAL_SAMPLE: &str = "tests/samples/packers/bitmono/0.39.0/original.exe";
        let assembly = load_sample(ORIGINAL_SAMPLE);

        let provider = SimpleProvider::new();
        let fallback = SimpleProvider::new();
        let config = SmartRenameConfig::default();
        let mut cascade = CascadeRenamer::new(&assembly, &provider, &fallback, config);
        cascade.build_infrastructure();

        let getapikey_token = assembly
            .methods()
            .iter()
            .find(|e| e.value().name == "GetApiKey")
            .map(|e| *e.key())
            .expect("original.exe should have a GetApiKey method");

        let ssa = cascade
            .ssa_cache
            .get(&getapikey_token)
            .expect("GetApiKey should have SSA");
        let skeleton = phases::build_call_site_skeleton(ssa, &assembly);

        let skeleton = skeleton.expect("GetApiKey should produce a call-site skeleton");
        assert!(
            skeleton.contains("// string:"),
            "GetApiKey skeleton should contain a string constant comment, got:\n{skeleton}"
        );
        assert!(
            skeleton.contains("return var_"),
            "GetApiKey skeleton should contain 'return var_', got:\n{skeleton}"
        );
    }

    /// Comprehensive diagnostic dump of the entire renamer cascade on a clean,
    /// unobfuscated assembly. Prints every method's SSA features, phase
    /// decomposition, anchors, call-site skeletons, and the full RenameContext
    /// that `build_method_context()` produces.
    ///
    /// Run with: `cargo test --release -p dotscope --lib cascade::tests::test_diagnostic_context_dump -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn test_diagnostic_context_dump() {
        const ORIGINAL_SAMPLE: &str = "tests/samples/packers/bitmono/0.39.0/original.exe";

        let assembly = load_sample(ORIGINAL_SAMPLE);

        eprintln!("========================================================================");
        eprintln!("  DIAGNOSTIC CONTEXT DUMP — original.exe (clean, unobfuscated)");
        eprintln!("========================================================================");

        // ---------------------------------------------------------------
        // 1. Enumerate ALL types, methods, fields, params in metadata
        // ---------------------------------------------------------------
        let tables = assembly.tables().expect("assembly should have tables");
        let strings = assembly.strings().expect("assembly should have strings");

        eprintln!("\n--- METADATA INVENTORY ---");

        if let Some(typedef_table) = tables.table::<TypeDefRaw>() {
            eprintln!("\nTypeDef table: {} rows", typedef_table.row_count);
            for rid in 1..=typedef_table.row_count {
                if let Some(td) = typedef_table.get(rid) {
                    let name = strings.get(td.type_name as usize).unwrap_or("?");
                    let ns = strings.get(td.type_namespace as usize).unwrap_or("");
                    let obf = is_obfuscated_name(name);
                    let special = is_special_name(name);
                    eprintln!(
                        "  TypeDef RID={rid:3} token=0x{:08X} name={ns}.{name} obfuscated={obf} special={special}",
                        0x0200_0000 | rid
                    );
                }
            }
        }

        if let Some(methoddef_table) = tables.table::<MethodDefRaw>() {
            eprintln!("\nMethodDef table: {} rows", methoddef_table.row_count);
            for rid in 1..=methoddef_table.row_count {
                if let Some(md) = methoddef_table.get(rid) {
                    let name = strings.get(md.name as usize).unwrap_or("?");
                    let obf = is_obfuscated_name(name);
                    let special = is_special_name(name);
                    let method_token = Token::new(0x0600_0000 | rid);
                    let has_cfg = assembly
                        .method(&method_token)
                        .map(|m| m.cfg().is_some())
                        .unwrap_or(false);
                    eprintln!(
                        "  MethodDef RID={rid:3} token=0x{:08X} name={name} obfuscated={obf} special={special} has_cfg={has_cfg}",
                        method_token.value()
                    );
                }
            }
        }

        if let Some(field_table) = tables.table::<FieldRaw>() {
            eprintln!("\nField table: {} rows", field_table.row_count);
            for rid in 1..=field_table.row_count {
                if let Some(f) = field_table.get(rid) {
                    let name = strings.get(f.name as usize).unwrap_or("?");
                    let obf = is_obfuscated_name(name);
                    eprintln!(
                        "  Field RID={rid:3} token=0x{:08X} name={name} obfuscated={obf}",
                        0x0400_0000 | rid
                    );
                }
            }
        }

        if let Some(param_table) = tables.table::<ParamRaw>() {
            eprintln!("\nParam table: {} rows", param_table.row_count);
            for rid in 1..=param_table.row_count {
                if let Some(p) = param_table.get(rid) {
                    let name = strings.get(p.name as usize).unwrap_or("?");
                    let obf = is_obfuscated_name(name);
                    eprintln!(
                        "  Param RID={rid:3} sequence={} name={name} obfuscated={obf}",
                        p.sequence
                    );
                }
            }
        }

        // ---------------------------------------------------------------
        // 2. Build infrastructure (SSA + call graph) via CascadeRenamer
        // ---------------------------------------------------------------
        let provider = SimpleProvider::new();
        let fallback = SimpleProvider::new();
        let config = SmartRenameConfig::default();
        let mut cascade = CascadeRenamer::new(&assembly, &provider, &fallback, config.clone());
        cascade.build_infrastructure();
        cascade.extract_anchors();
        cascade.collect_caller_contexts();
        cascade.decompose_and_label_phases();

        eprintln!("\n--- SSA INFRASTRUCTURE ---");
        eprintln!(
            "Total methods: {}, Methods with SSA: {}",
            assembly.methods().len(),
            cascade.ssa_cache.len()
        );

        // List methods WITHOUT SSA (and why)
        eprintln!("\nMethods WITHOUT SSA:");
        if let Some(methoddef_table) = tables.table::<MethodDefRaw>() {
            for rid in 1..=methoddef_table.row_count {
                let method_token = Token::new(0x0600_0000 | rid);
                if cascade.ssa_cache.contains_key(&method_token) {
                    continue;
                }
                let name = methoddef_table
                    .get(rid)
                    .and_then(|md| strings.get(md.name as usize).ok())
                    .unwrap_or("?");
                let method = assembly.method(&method_token);
                let has_cfg = method.as_ref().map(|m| m.cfg().is_some()).unwrap_or(false);
                let has_body = method
                    .as_ref()
                    .map(|m| m.body.get().is_some())
                    .unwrap_or(false);
                let reason = if !has_body {
                    "no body (abstract/native/extern)"
                } else if !has_cfg {
                    "no CFG (IL parse failed?)"
                } else {
                    "SSA construction failed"
                };
                eprintln!(
                    "  0x{:08X} {name} -- reason: {reason}",
                    method_token.value()
                );
            }
        }

        // ---------------------------------------------------------------
        // 3. For EACH method with SSA: dump all extracted features
        // ---------------------------------------------------------------
        eprintln!("\n========================================================================");
        eprintln!("  PER-METHOD SSA FEATURE EXTRACTION");
        eprintln!("========================================================================");

        let methoddef_table = tables.table::<MethodDefRaw>().unwrap();
        let mut method_tokens_with_ssa: Vec<(Token, String)> = Vec::new();

        for rid in 1..=methoddef_table.row_count {
            let method_token = Token::new(0x0600_0000 | rid);
            let Some(ssa) = cascade.ssa_cache.get(&method_token) else {
                continue;
            };
            let name = methoddef_table
                .get(rid)
                .and_then(|md| strings.get(md.name as usize).ok())
                .unwrap_or("?")
                .to_string();

            method_tokens_with_ssa.push((method_token, name.clone()));

            eprintln!(
                "\n---------- Method: {name} (0x{:08X}) ----------",
                method_token.value()
            );
            eprintln!(
                "  Blocks: {}, Instructions: {}",
                ssa.blocks().len(),
                ssa.instruction_count()
            );

            // Call targets
            let call_targets = features::collect_call_targets(ssa, &assembly);
            eprintln!("  Call targets ({}):", call_targets.len());
            for t in &call_targets {
                eprintln!("    - {t}");
            }

            // String literals
            let string_lits = features::collect_string_literals(ssa, &assembly);
            eprintln!("  String literals ({}):", string_lits.len());
            for s in &string_lits {
                let display = if s.len() > 60 {
                    format!("{}...", &s[..57])
                } else {
                    s.clone()
                };
                eprintln!("    - \"{display}\"");
            }

            // Field accesses
            let field_accesses = features::collect_field_accesses(ssa, &assembly);
            eprintln!("  Field accesses ({}):", field_accesses.len());
            for f in &field_accesses {
                eprintln!("    - {f}");
            }

            // Opcode profile
            let profile = features::build_opcode_profile(ssa);
            eprintln!(
                "  Opcode profile: calls={} strings={} field_io={} bitwise={} arithmetic={} array={} comparison={} conversion={}",
                profile.calls, profile.strings, profile.field_io,
                profile.bitwise, profile.arithmetic, profile.array,
                profile.comparison, profile.conversion
            );

            // Anchors
            let anchors = features::extract_anchors(ssa, &assembly);
            eprintln!("  Anchors ({}):", anchors.len());
            for a in &anchors {
                eprintln!("    - {} arg_pos={:?}", a.method_name, a.argument_position);
            }

            // Phase decomposition (with threshold=0 to force full decomposition)
            let phases_full = phases::decompose_method(ssa, &assembly, 0);
            eprintln!(
                "  Phase decomposition (threshold=0, {} phases):",
                phases_full.len()
            );
            for (i, phase) in phases_full.iter().enumerate() {
                eprintln!(
                    "    Phase {}: structure={:?} label={:?}",
                    i, phase.structure, phase.label
                );
                if !phase.call_targets.is_empty() {
                    eprintln!("      calls: {:?}", phase.call_targets);
                }
                if let Some(ref prof) = phase.opcode_profile {
                    eprintln!(
                        "      ops: calls={} strings={} field_io={} bitwise={} arith={} array={} cmp={} conv={}",
                        prof.calls, prof.strings, prof.field_io,
                        prof.bitwise, prof.arithmetic, prof.array,
                        prof.comparison, prof.conversion
                    );
                }
            }

            // Phase decomposition (with default threshold for comparison)
            let phases_default =
                phases::decompose_method(ssa, &assembly, config.small_method_threshold);
            eprintln!(
                "  Phase decomposition (threshold={}, {} phases):",
                config.small_method_threshold,
                phases_default.len()
            );
            for (i, phase) in phases_default.iter().enumerate() {
                eprintln!(
                    "    Phase {}: structure={:?} calls={:?}",
                    i, phase.structure, phase.call_targets
                );
            }

            // Call-site skeleton (for small methods)
            if ssa.instruction_count() <= config.small_method_threshold {
                let skeleton = phases::build_call_site_skeleton(ssa, &assembly);
                eprintln!("  Call-site skeleton (small method):");
                if let Some(ref sk) = skeleton {
                    for line in sk.lines() {
                        eprintln!("    {line}");
                    }
                } else {
                    eprintln!("    (none)");
                }
            } else {
                eprintln!(
                    "  Call-site skeleton: N/A (large method, {} instructions)",
                    ssa.instruction_count()
                );
            }
        }

        // ---------------------------------------------------------------
        // 4. build_method_context() for each method
        // ---------------------------------------------------------------
        eprintln!("\n========================================================================");
        eprintln!("  FULL RENAME CONTEXT (build_method_context)");
        eprintln!("========================================================================");

        for (token, name) in &method_tokens_with_ssa {
            let ctx = cascade.build_method_context(*token);
            eprintln!("\n--- {name} (0x{:08X}) ---", token.value());
            eprintln!("  kind: {:?}", ctx.kind);
            eprintln!("  dotnet_type (return): {:?}", ctx.dotnet_type);
            eprintln!("  parameters:");
            for (i, p) in ctx.parameters.iter().enumerate() {
                eprintln!(
                    "    [{i}] type={} known_name={:?}",
                    p.dotnet_type, p.known_name
                );
            }
            eprintln!("  base_class: {:?}", ctx.base_class);
            eprintln!("  interfaces: {:?}", ctx.interfaces);
            eprintln!("  parent_type: {:?}", ctx.parent_type);
            eprintln!("  siblings: {:?}", ctx.siblings);
            eprintln!("  call_targets: {:?}", ctx.call_targets);
            eprintln!("  string_literals: {:?}", ctx.string_literals);
            eprintln!("  field_accesses: {:?}", ctx.field_accesses);
            eprintln!("  api_calls ({}):", ctx.api_calls.len());
            for a in &ctx.api_calls {
                eprintln!("    {} arg={:?}", a.method_name, a.argument_position);
            }
            eprintln!(
                "  call_site_skeleton: {}",
                if ctx.call_site_skeleton.is_some() {
                    "present"
                } else {
                    "none"
                }
            );
            if let Some(ref sk) = ctx.call_site_skeleton {
                for line in sk.lines() {
                    eprintln!("    | {line}");
                }
            }
            eprintln!("  phase_narrative ({} phases):", ctx.phase_narrative.len());
            for (i, ph) in ctx.phase_narrative.iter().enumerate() {
                eprintln!(
                    "    Phase {i}: label={:?} structure={:?} calls={:?}",
                    ph.label, ph.structure, ph.call_targets
                );
            }
            eprintln!("  caller_context ({}):", ctx.caller_context.len());
            for ci in &ctx.caller_context {
                eprintln!(
                    "    caller={:?} strings={:?} return_usage={:?}",
                    ci.caller_name, ci.nearby_strings, ci.return_usage
                );
            }
        }

        // ---------------------------------------------------------------
        // 5. Build param contexts
        // ---------------------------------------------------------------
        eprintln!("\n========================================================================");
        eprintln!("  PARAMETER CONTEXTS");
        eprintln!("========================================================================");

        if let Some(param_table) = tables.table::<ParamRaw>() {
            let param_owners = build_param_owner_map(methoddef_table, param_table.row_count);

            for rid in 1..=param_table.row_count {
                let Some(param) = param_table.get(rid) else {
                    continue;
                };
                let name = strings.get(param.name as usize).unwrap_or("?");
                let owner_rid = param_owners.get(&rid).copied();
                let owner_name = owner_rid
                    .and_then(|r| methoddef_table.get(r))
                    .and_then(|md| strings.get(md.name as usize).ok())
                    .unwrap_or("?");

                let ctx = cascade.build_param_context(rid, param.sequence, &param_owners);
                eprintln!(
                    "\n  Param RID={rid} name={name} seq={} owner={owner_name} (0x{:08X})",
                    param.sequence,
                    owner_rid.map(|r| 0x0600_0000 | r).unwrap_or(0)
                );
                eprintln!("    dotnet_type: {:?}", ctx.dotnet_type);
                eprintln!("    parent_type: {:?}", ctx.parent_type);
                eprintln!("    call_targets: {:?}", ctx.call_targets);
                eprintln!("    api_calls ({}):", ctx.api_calls.len());
                for a in &ctx.api_calls {
                    eprintln!("      {} arg={:?}", a.method_name, a.argument_position);
                }
                eprintln!("    siblings: {:?}", ctx.siblings);
            }
        }

        // ---------------------------------------------------------------
        // 6. Build field contexts
        // ---------------------------------------------------------------
        eprintln!("\n========================================================================");
        eprintln!("  FIELD CONTEXTS");
        eprintln!("========================================================================");

        if let Some(field_table) = tables.table::<FieldRaw>() {
            for rid in 1..=field_table.row_count {
                let Some(f) = field_table.get(rid) else {
                    continue;
                };
                let name = strings.get(f.name as usize).unwrap_or("?");
                let field_token = Token::new(0x0400_0000 | rid);
                let ctx = cascade.build_field_context(field_token);
                eprintln!(
                    "\n  Field RID={rid} token=0x{:08X} name={name}",
                    field_token.value()
                );
                eprintln!("    dotnet_type: {:?}", ctx.dotnet_type);
                eprintln!("    siblings: {:?}", ctx.siblings);
                eprintln!("    api_calls ({}):", ctx.api_calls.len());
                for a in &ctx.api_calls {
                    eprintln!("      {} arg={:?}", a.method_name, a.argument_position);
                }
            }
        }

        // ---------------------------------------------------------------
        // 7. Build type contexts
        // ---------------------------------------------------------------
        eprintln!("\n========================================================================");
        eprintln!("  TYPE CONTEXTS");
        eprintln!("========================================================================");

        if let Some(typedef_table) = tables.table::<TypeDefRaw>() {
            for rid in 1..=typedef_table.row_count {
                if rid == 1 {
                    continue; // skip <Module>
                }
                let Some(td) = typedef_table.get(rid) else {
                    continue;
                };
                let name = strings.get(td.type_name as usize).unwrap_or("?");
                let ns = strings.get(td.type_namespace as usize).unwrap_or("");
                let type_token = Token::new(0x0200_0000 | rid);
                let ctx = cascade.build_type_context(type_token);
                eprintln!(
                    "\n  Type RID={rid} token=0x{:08X} name={ns}.{name}",
                    type_token.value()
                );
                eprintln!("    base_class: {:?}", ctx.base_class);
                eprintln!("    interfaces: {:?}", ctx.interfaces);
                eprintln!("    siblings (members): {:?}", ctx.siblings);
            }
        }

        // ---------------------------------------------------------------
        // 8. Run full cascade and dump entries
        // ---------------------------------------------------------------
        eprintln!("\n========================================================================");
        eprintln!("  FULL CASCADE EXECUTION");
        eprintln!("========================================================================");

        let provider2 = SimpleProvider::new();
        let fallback2 = SimpleProvider::new();
        let config2 = SmartRenameConfig::default();
        let cascade2 = CascadeRenamer::new(&assembly, &provider2, &fallback2, config2);
        let entries = cascade2.execute().unwrap();

        eprintln!("Total rename entries: {}", entries.len());
        for entry in &entries {
            eprintln!(
                "  {:?} RID={} string_idx={} -> {:?}",
                entry.table_id, entry.rid, entry.string_index, entry.new_name
            );
        }

        if entries.is_empty() {
            eprintln!("  (No entries -- clean assembly has no obfuscated names, as expected)");
        }

        // ---------------------------------------------------------------
        // 9. Call graph analysis
        // ---------------------------------------------------------------
        eprintln!("\n========================================================================");
        eprintln!("  CALL GRAPH ANALYSIS");
        eprintln!("========================================================================");

        if let Some(ref cg) = cascade.call_graph {
            let topo = cg.topological_order();
            eprintln!("Topological order ({} nodes):", topo.len());
            for (i, token) in topo.iter().enumerate() {
                let name = assembly
                    .method(token)
                    .map(|m| m.name.clone())
                    .or_else(|| assembly.resolve_method_name(*token))
                    .unwrap_or_else(|| format!("0x{:08X}", token.value()));
                eprintln!("  [{i:3}] 0x{:08X} {name}", token.value());
            }
        } else {
            eprintln!("  (No call graph available)");
        }

        // ---------------------------------------------------------------
        // 10. Summary statistics
        // ---------------------------------------------------------------
        eprintln!("\n========================================================================");
        eprintln!("  SUMMARY");
        eprintln!("========================================================================");

        let total_methods = if let Some(t) = tables.table::<MethodDefRaw>() {
            t.row_count
        } else {
            0
        };
        let methods_with_ssa = cascade.ssa_cache.len();
        let methods_with_anchors = cascade.anchors.len();
        let methods_with_phases = cascade.phase_narratives.len();

        let methods_with_callers = cascade.caller_contexts.len();

        eprintln!("Methods total:         {total_methods}");
        eprintln!("Methods with SSA:      {methods_with_ssa}");
        eprintln!("Methods with anchors:  {methods_with_anchors}");
        eprintln!("Methods with phases:   {methods_with_phases}");
        eprintln!("Methods with callers:  {methods_with_callers}");

        let mut methods_with_calls = 0u32;
        let mut methods_with_strings = 0u32;
        let mut methods_with_fields = 0u32;
        let mut methods_with_skeleton = 0u32;

        for (token, _) in &method_tokens_with_ssa {
            let ctx = cascade.build_method_context(*token);
            if !ctx.call_targets.is_empty() {
                methods_with_calls += 1;
            }
            if !ctx.string_literals.is_empty() {
                methods_with_strings += 1;
            }
            if !ctx.field_accesses.is_empty() {
                methods_with_fields += 1;
            }
            if ctx.call_site_skeleton.is_some() {
                methods_with_skeleton += 1;
            }
        }

        eprintln!("Methods with call targets:      {methods_with_calls}");
        eprintln!("Methods with string literals:    {methods_with_strings}");
        eprintln!("Methods with field accesses:     {methods_with_fields}");
        eprintln!("Methods with call-site skeleton: {methods_with_skeleton}");
        eprintln!("Rename entries produced:         {}", entries.len());

        eprintln!("\n========================================================================");
        eprintln!("  DIAGNOSTIC DUMP COMPLETE");
        eprintln!("========================================================================");
    }
}
