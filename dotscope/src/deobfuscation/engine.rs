//! Main deobfuscation engine.
//!
//! The [`DeobfuscationEngine`] is the main entry point for deobfuscating
//! .NET assemblies. It orchestrates detection, analysis, pass execution,
//! and code generation.

use std::{collections::HashSet, sync::Arc, time::Instant};

use log::info;
use rayon::prelude::*;

use crate::{
    analysis::{CallGraph, SsaFunction, SsaOp},
    cilassembly::{GeneratorConfig, MethodBodyBuilder},
    compiler::{
        AlgebraicSimplificationPass, BlockMergingPass, CallSiteInfo, ConstantPropagationPass,
        ControlFlowSimplificationPass, CopyPropagationPass, DeadCodeEliminationPass,
        DeadMethodEliminationPass, EventKind, GlobalValueNumberingPass, InliningPass,
        JumpThreadingPass, LicmPass, MethodSummary, OpaquePredicatePass, ParameterSummary,
        PassScheduler, ReassociationPass, SsaCodeGenerator, SsaPass, StrengthReductionPass,
        ValueRangePropagationPass,
    },
    deobfuscation::{
        cleanup::execute_cleanup,
        config::EngineConfig,
        context::AnalysisContext,
        passes::{CffReconstructionPass, DecryptionPass, NeutralizationPass, UnflattenConfig},
        result::DeobfuscationResult,
        techniques::{
            Detections, PassPhase, Technique, TechniqueRegistry, TechniqueResult, WorkingAssembly,
        },
        EmulationTemplatePool,
    },
    metadata::{
        tables::{MethodDefRaw, TableDataOwned, TableId},
        token::Token,
        validation::ValidationConfig,
    },
    CilObject, CleanupRequest, Error, File, Result,
};

/// Main deobfuscation engine.
///
/// The engine orchestrates the complete deobfuscation pipeline:
///
/// 1. **Detection**: Identify which obfuscator was used
/// 2. **Preprocessing**: Obfuscator-specific preprocessing (decrypt methods, etc.)
/// 3. **Analysis**: Build SSA, compute interprocedural summaries
/// 4. **Pass Execution**: Run passes until fixpoint
/// 5. **Postprocessing**: Obfuscator-specific cleanup
///
/// # APIs
///
/// The engine provides three levels of granularity:
///
/// - [`process_file`](Self::process_file) - Full assembly processing with detection
/// - [`process_method`](Self::process_method) - Single method from an assembly
/// - [`process_ssa`](Self::process_ssa) - Standalone SSA function
///
/// # Example
///
/// ```rust,ignore
/// use dotscope::deobfuscation::{DeobfuscationEngine, EngineConfig};
///
/// let config = EngineConfig::default();
/// let mut engine = DeobfuscationEngine::new(config);
///
/// // Process entire assembly
/// let mut assembly = CilObject::from_path("obfuscated.dll")?;
/// let result = engine.process_file(&mut assembly)?;
/// println!("{}", result.summary());
///
/// // Or process a single method
/// let (ssa, result) = engine.process_method(&assembly, method_token)?;
///
/// // Or process a standalone SSA function
/// let result = engine.process_ssa(&mut ssa_function, synthetic_token)?;
/// ```
pub struct DeobfuscationEngine {
    /// Configuration.
    config: EngineConfig,
    /// Technique-based deobfuscation registry.
    registry: TechniqueRegistry,
}

impl Default for DeobfuscationEngine {
    fn default() -> Self {
        Self::new(EngineConfig::default())
    }
}

impl DeobfuscationEngine {
    /// Creates a new engine with the given configuration.
    ///
    /// # Arguments
    ///
    /// * `config` - Engine configuration controlling iteration limits, thresholds, etc.
    ///
    /// # Returns
    ///
    /// A new `DeobfuscationEngine` instance ready to process assemblies.
    #[must_use]
    pub fn new(config: EngineConfig) -> Self {
        Self {
            config,
            registry: TechniqueRegistry::with_defaults(),
        }
    }

    /// Creates a fresh pass scheduler configured from the engine settings.
    ///
    /// Called once per run so that each pipeline execution starts with a clean
    /// scheduler and no stale pass state.
    fn create_scheduler(&self) -> PassScheduler {
        let mut scheduler = PassScheduler::new(
            self.config.max_iterations,
            self.config.stable_iterations,
            self.config.max_phase_iterations,
        );

        // Phase 1: Structure recovery (control-flow unflattening)
        // Populated by create_deob_passes() after AnalysisContext is built.

        // Phase 2: Value recovery (decryption)
        // Populated by create_deob_passes() after AnalysisContext is built.

        // Phase 3: Simplification (opaque predicates + CFG recovery + jump threading + range propagation)
        if self.config.enable_opaque_predicate_removal {
            scheduler
                .simplify
                .push(Box::new(OpaquePredicatePass::new()));
            scheduler
                .simplify
                .push(Box::new(ValueRangePropagationPass::new()));
        }
        if self.config.enable_control_flow_simplification {
            scheduler
                .simplify
                .push(Box::new(ControlFlowSimplificationPass::new()));
            scheduler.simplify.push(Box::new(JumpThreadingPass::new()));
        }

        // Phase 4: Proxy/delegate inlining
        if self.config.enable_inlining {
            scheduler.inline.push(Box::new(InliningPass::new(
                self.config.inline_threshold,
                false,
            )));
        }

        // Normalization passes (run after each structural change in every phase)
        if self.config.enable_dead_code_elimination {
            scheduler
                .normalize
                .push(Box::new(DeadCodeEliminationPass::new()));
            scheduler.normalize.push(Box::new(BlockMergingPass::new()));
            scheduler.normalize.push(Box::new(LicmPass::new()));
        }
        if self.config.enable_constant_propagation {
            scheduler.normalize.push(Box::new(ReassociationPass::new()));
            scheduler
                .normalize
                .push(Box::new(ConstantPropagationPass::new()));
            scheduler
                .normalize
                .push(Box::new(GlobalValueNumberingPass::new()));
        }
        if self.config.enable_copy_propagation {
            scheduler
                .normalize
                .push(Box::new(CopyPropagationPass::new()));
        }
        if self.config.enable_strength_reduction {
            scheduler
                .normalize
                .push(Box::new(StrengthReductionPass::new()));
            scheduler
                .normalize
                .push(Box::new(AlgebraicSimplificationPass::new()));
        }

        scheduler
    }

    /// Registers a technique with the engine.
    ///
    /// Techniques are evaluated during the detection phase and, if detected,
    /// participate in byte-level transforms and SSA pass creation.
    ///
    /// # Arguments
    ///
    /// * `technique` - The technique to register. Ownership is transferred to the
    ///   engine's internal [`TechniqueRegistry`].
    pub fn register_technique(&mut self, technique: Box<dyn Technique>) {
        self.registry.register(technique);
    }

    /// Processes an assembly through the complete deobfuscation pipeline.
    ///
    /// This is the main entry point for deobfuscation. The pipeline follows a clean
    /// consume → produce pattern at each phase:
    ///
    /// 1. **Detection** - Identify obfuscator (borrows assembly, read-only)
    /// 2. **Byte-level deobfuscation** - Decrypt methods, unpack resources (consume → produce)
    /// 3. **SSA pipeline + code generation + postprocessing** - Optimize and regenerate (consume → produce)
    ///
    /// # Arguments
    ///
    /// * `assembly` - The assembly to deobfuscate (consumed).
    ///
    /// # Returns
    ///
    /// A tuple containing:
    /// - The deobfuscated `CilObject` (clean, reloaded with strict validation)
    /// - A [`DeobfuscationResult`] with statistics, detection info, and changes
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Call graph construction fails
    /// - SSA construction fails for any method
    /// - Any pass returns an error
    /// - Obfuscator deobfuscation or postprocessing fails
    /// - Final strict reload fails
    pub fn process_assembly(
        &self,
        assembly: CilObject,
    ) -> Result<(CilObject, DeobfuscationResult)> {
        self.run_technique_pipeline(assembly)
    }

    /// Runs technique detection on an assembly and returns a [`DeobfuscationResult`].
    ///
    /// This is a detection-only API — no transforms are applied. Useful for
    /// identifying which obfuscator was used without modifying the assembly.
    /// The returned result contains per-technique detections and attribution
    /// but no events (since no transforms were run).
    ///
    /// # Arguments
    ///
    /// * `assembly` - The assembly to detect obfuscation techniques in (read-only).
    ///
    /// # Returns
    ///
    /// A [`DeobfuscationResult`] containing per-technique detections, attribution,
    /// and timing information. The `events` field will be empty since no transforms
    /// are applied.
    #[must_use]
    pub fn detect(&self, assembly: &CilObject) -> DeobfuscationResult {
        let start = Instant::now();
        let mut detections = Detections::new();
        let mut technique_results = Vec::new();

        for tech in self.registry.techniques() {
            if !tech.enabled(&self.config) {
                continue;
            }
            let detection = tech.detect(assembly);
            if detection.detected {
                technique_results.push(TechniqueResult {
                    id: tech.id().to_string(),
                    detected: true,
                    transformed: false,
                    evidence: detection.evidence.clone(),
                    events: crate::compiler::EventLog::new(),
                    duration: std::time::Duration::ZERO,
                });
            }
            detections.insert(tech.id(), detection);
        }

        let attribution = self.registry.compute_attribution(&detections);
        let attributions = self.registry.compute_attributions_all(&detections);
        DeobfuscationResult::new_with_techniques(
            crate::compiler::EventLog::new(),
            technique_results,
            attribution,
        )
        .with_attributions(attributions)
        .with_timing(start.elapsed(), 0)
    }

    /// Runs the technique-based deobfuscation pipeline.
    ///
    /// This is the new pipeline that replaces the obfuscator-based one.
    /// Flow: detect → byte transforms → SSA transforms → neutralize → codegen → cleanup
    fn run_technique_pipeline(
        &self,
        assembly: CilObject,
    ) -> Result<(CilObject, DeobfuscationResult)> {
        let start = Instant::now();
        let mut technique_results: Vec<TechniqueResult> = Vec::new();

        // === Phase 1: IL detection ===
        let mut detections = self.run_il_detection(&assembly);

        // === Phase 2: Byte transforms ===
        let assembly =
            self.run_byte_transforms(assembly, &mut detections, &mut technique_results)?;

        // === Phase 2.5: Post-transform re-detection ===
        self.run_post_transform_detection(&assembly, &mut detections);
        self.record_detected_techniques(&detections, &mut technique_results);

        // === Phase 3: SSA pipeline ===
        let assembly_arc = Arc::new(assembly);
        let ctx = self.build_context(&assembly_arc)?;

        // === Phase 3.5: SSA detection + initialize + create passes ===
        self.run_ssa_detection(&ctx, &assembly_arc, &mut detections);
        self.record_detected_techniques(&detections, &mut technique_results);
        self.initialize_techniques(&ctx, &assembly_arc, &detections);

        // Create shared emulation template pool (only if any technique needs emulation)
        if Self::needs_emulation(&ctx) {
            let original_pe_cow = assembly_arc.file().fork_cowfile()?;
            let pool = Arc::new(EmulationTemplatePool::new(
                Arc::clone(&assembly_arc),
                original_pe_cow,
                Arc::clone(&ctx.emulation_hooks),
                Arc::clone(&ctx.warmup_methods),
                Arc::clone(&ctx.statemachine_providers),
                self.config.clone(),
            ));
            pool.warmup()?;
            let _ = ctx.template_pool.set(pool);
        }

        let mut scheduler = self.create_scheduler();
        self.create_deob_passes(&ctx, &mut scheduler);
        self.create_technique_passes(&ctx, &assembly_arc, &detections, &mut scheduler);
        self.configure_no_inline(&ctx);

        // Interprocedural analysis
        info!(
            "Interprocedural analysis on {} methods",
            ctx.ssa_functions.len()
        );
        self.run_interprocedural_analysis(&ctx)?;

        // Run SSA passes to fixpoint
        info!(
            "Running SSA optimization pipeline (max {} iterations)",
            self.config.max_iterations
        );
        let mut iterations = scheduler.run_pipeline(&ctx, &assembly_arc)?;

        // === Detection iteration loop ===
        // After the pipeline stabilizes, re-run SSA detection to discover
        // techniques that were hidden by earlier passes (e.g., delegate
        // proxy resolution reveals string decryptor call sites).
        iterations += self.run_detection_loop(
            &ctx,
            &assembly_arc,
            &mut scheduler,
            &mut detections,
            &mut technique_results,
        )?;

        // Dead method elimination
        if ctx.config.cleanup.remove_unused_methods {
            let dead_method_pass = DeadMethodEliminationPass::new();
            let _ = dead_method_pass.run_global(&ctx, &assembly_arc)?;
        }

        // === Phase 4: Neutralization ===
        // Neutralize references to deleted tokens across ALL SSA-processed methods.
        // The token set is expanded so that type deletions also cover their member
        // tokens (fields, methods), which is what SSA instructions actually reference.
        let merged_cleanup = self.build_cleanup(&ctx, &detections);

        let all_tokens = Self::expand_cleanup_tokens(&merged_cleanup, &assembly_arc);
        if !all_tokens.is_empty() {
            let pass = NeutralizationPass::new(&all_tokens);
            let mut neutralized = false;

            let method_tokens: Vec<Token> = ctx.ssa_functions.iter().map(|e| *e.key()).collect();
            for method_token in &method_tokens {
                if let Some(mut ssa) = ctx.ssa_functions.get_mut(method_token) {
                    if pass.run_on_method(&mut ssa, *method_token, &ctx, &assembly_arc)? {
                        neutralized = true;
                    }
                }
            }

            if neutralized {
                iterations += scheduler.run_pipeline(&ctx, &assembly_arc)?;
            }
        }

        // Canonicalize and release
        ctx.canonicalize_all_ssa();
        drop(scheduler);

        // Release the emulation template pool's Arc<CilObject> reference
        // before attempting to unwrap the assembly Arc.
        if let Some(pool) = ctx.template_pool.get() {
            pool.release();
        }

        let assembly = Arc::try_unwrap(assembly_arc).map_err(|_| {
            Error::Deobfuscation("Cannot unwrap assembly - still has other references".into())
        })?;

        // === Phase 5: Code generation ===
        let (assembly, methods_regenerated) = Self::generate_code(assembly, &ctx)?;
        info!(
            "Code generation: {} method bodies regenerated",
            methods_regenerated
        );

        // === Phase 6: Cleanup ===
        info!(
            "Cleanup request: {} types, {} methods, {} fields, {} attributes",
            merged_cleanup.types_len(),
            merged_cleanup.methods_len(),
            merged_cleanup.fields_len(),
            merged_cleanup.attributes_len(),
        );
        let cleanup_request =
            if merged_cleanup.has_deletions() || !merged_cleanup.excluded_sections().is_empty() {
                Some(merged_cleanup)
            } else {
                None
            };
        let assembly = execute_cleanup(assembly, cleanup_request, &ctx)?;

        // === Phase 7: Attribution ===
        let attribution = self.registry.compute_attribution(&detections);
        let attributions = self.registry.compute_attributions_all(&detections);

        // === Build result ===
        let events = ctx.compiler.events.take();
        let result =
            DeobfuscationResult::new_with_techniques(events, technique_results, attribution)
                .with_attributions(attributions)
                .with_timing(start.elapsed(), iterations);

        info!(
            "Technique pipeline complete in {:.1}s",
            start.elapsed().as_secs_f64()
        );
        Ok((assembly, result))
    }

    // === Extracted helpers for run_technique_pipeline ===

    /// Phase 1: Run IL-level detection on all enabled techniques.
    ///
    /// Iterates all registered techniques, skipping disabled ones, and calls
    /// [`Technique::detect`] on each. Results are collected into a [`Detections`]
    /// map keyed by technique ID.
    ///
    /// # Arguments
    ///
    /// * `assembly` - The assembly to run IL-level detection on.
    ///
    /// # Returns
    ///
    /// A [`Detections`] map containing detection results for all enabled techniques.
    fn run_il_detection(&self, assembly: &CilObject) -> Detections {
        let mut detections = Detections::new();
        for tech in self.registry.techniques() {
            if !tech.enabled(&self.config) {
                continue;
            }
            let detection = tech.detect(assembly);
            if detection.detected {
                info!("[technique] Detected: {}", tech.name());
            }
            detections.insert(tech.id(), detection);
        }
        detections
    }

    /// Phase 2: Run byte-level transforms for detected techniques.
    ///
    /// Iterates detected techniques in dependency order and applies their byte-level
    /// transforms (e.g., anti-tamper decryption, PE section restoration). Transforms
    /// that modify raw bytes trigger a regeneration of the assembly.
    ///
    /// # Arguments
    ///
    /// * `assembly` - The assembly to transform (consumed and returned).
    /// * `detections` - Detection results; updated with transform status.
    /// * `technique_results` - Accumulated per-technique results for reporting.
    ///
    /// # Returns
    ///
    /// The transformed [`CilObject`], or an error if regeneration fails.
    fn run_byte_transforms(
        &self,
        assembly: CilObject,
        detections: &mut Detections,
        technique_results: &mut Vec<TechniqueResult>,
    ) -> Result<CilObject> {
        let mut working = WorkingAssembly::new(assembly);
        for tech in self.registry.sorted_techniques(detections) {
            if !detections.is_detected(tech.id()) {
                continue;
            }
            let detection = detections.get(tech.id()).unwrap();
            let Some(transform_result) = tech.byte_transform(&mut working, detection, detections)
            else {
                continue;
            };
            let tech_start = Instant::now();
            match transform_result {
                Ok(events) => {
                    technique_results.push(TechniqueResult {
                        id: tech.id().to_string(),
                        detected: true,
                        transformed: true,
                        evidence: detection.evidence.clone(),
                        events,
                        duration: tech_start.elapsed(),
                    });
                    detections.mark_transformed(tech.id());
                    if tech.requires_regeneration() {
                        working.commit()?;
                    }
                }
                Err(e) => {
                    log::warn!("[technique] {} transform failed: {}", tech.name(), e);
                }
            }
        }
        working.into_cilobject()
    }

    /// Phase 2.5: Re-detect on post-transform assembly.
    ///
    /// Byte transforms (e.g. anti-tamper decryption) reveal infrastructure
    /// patterns that were invisible when method bodies were encrypted.
    fn run_post_transform_detection(&self, assembly: &CilObject, detections: &mut Detections) {
        for tech in self.registry.techniques() {
            if !tech.enabled(&self.config) {
                continue;
            }
            let detection = tech.detect(assembly);
            if detection.detected {
                info!("[technique] Post-transform re-detected: {}", tech.name());
            }
            // Use merge() not insert(): preserves positive detections from Phase 1
            // that become invisible after the byte transform consumed the evidence.
            detections.merge(tech.id(), detection);
        }
    }

    /// Records detected techniques into the results list, deduplicating by ID.
    ///
    /// Scans all registered techniques and appends a [`TechniqueResult`] for each
    /// that was detected but not yet recorded. Called after each detection phase
    /// to capture newly-discovered techniques.
    ///
    /// # Arguments
    ///
    /// * `detections` - The current detection state.
    /// * `technique_results` - The results list to append to; existing entries are
    ///   not duplicated.
    fn record_detected_techniques(
        &self,
        detections: &Detections,
        technique_results: &mut Vec<TechniqueResult>,
    ) {
        for tech in self.registry.techniques() {
            if let Some(d) = detections.get(tech.id()) {
                if d.detected {
                    let already_recorded = technique_results.iter().any(|r| r.id == tech.id());
                    if !already_recorded {
                        technique_results.push(TechniqueResult {
                            id: tech.id().to_string(),
                            detected: true,
                            transformed: false,
                            evidence: d.evidence.clone(),
                            events: crate::compiler::EventLog::new(),
                            duration: std::time::Duration::ZERO,
                        });
                    }
                }
            }
        }
    }

    /// Phase 3.5: Run SSA-level detection on all enabled techniques.
    ///
    /// Called after SSA functions are built, this runs [`Technique::detect_ssa`]
    /// on each enabled technique. SSA-level detection can follow def-use chains
    /// for more precise pattern matching than IL-level detection.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The analysis context containing SSA functions.
    /// * `assembly` - The assembly for metadata lookups.
    /// * `detections` - Detection results; merged with SSA-level findings.
    fn run_ssa_detection(
        &self,
        ctx: &AnalysisContext,
        assembly: &CilObject,
        detections: &mut Detections,
    ) {
        for tech in self.registry.techniques() {
            if !tech.enabled(&self.config) {
                continue;
            }
            let ssa_det = tech.detect_ssa(ctx, assembly);
            if ssa_det.detected {
                info!("[technique] SSA-detected: {}", tech.name());
            }
            detections.merge(tech.id(), ssa_det);
        }
    }

    /// Initializes detected techniques by registering decryptors, emulation hooks,
    /// warmup methods, and other state needed by their SSA passes.
    ///
    /// Tracks initialization via `ctx.initialized_techniques` to prevent
    /// double-initialization across detection re-scan rounds.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The analysis context for registering hooks, warmup methods, etc.
    /// * `assembly` - The assembly for metadata lookups.
    /// * `detections` - Detection results with findings for each technique.
    fn initialize_techniques(
        &self,
        ctx: &AnalysisContext,
        assembly: &CilObject,
        detections: &Detections,
    ) {
        for tech in self.registry.sorted_techniques(detections) {
            if !detections.is_detected(tech.id()) {
                continue;
            }
            if tech.ssa_phase().is_none() {
                continue;
            }
            if ctx.initialized_techniques.contains(tech.id()) {
                continue;
            }
            let detection = detections.get(tech.id()).unwrap();
            tech.initialize(ctx, assembly, detection, detections);
            ctx.initialized_techniques.insert(tech.id().to_string());
        }
    }

    /// Creates technique-owned SSA passes and adds them to the scheduler.
    ///
    /// For each detected technique with an SSA phase, calls
    /// [`Technique::create_pass`] and inserts the resulting pass into the
    /// appropriate phase bucket on the scheduler. Tracks created passes in
    /// `ctx.passes_created` to prevent duplicate instances when called again
    /// during detection re-scan rounds.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The analysis context (used for pass creation and dedup tracking).
    /// * `assembly` - The assembly (shared reference for pass construction).
    /// * `detections` - Detection results with findings for each technique.
    /// * `scheduler` - The pass scheduler to add technique passes to.
    fn create_technique_passes(
        &self,
        ctx: &AnalysisContext,
        assembly: &Arc<CilObject>,
        detections: &Detections,
        scheduler: &mut PassScheduler,
    ) {
        for tech in self.registry.sorted_techniques(detections) {
            if !detections.is_detected(tech.id()) {
                continue;
            }
            if ctx.passes_created.contains(tech.id()) {
                continue;
            }
            let Some(phase) = tech.ssa_phase() else {
                continue;
            };
            let detection = detections.get(tech.id()).unwrap();
            if let Some(pass) = tech.create_pass(ctx, detection, assembly) {
                match phase {
                    PassPhase::Structure => scheduler.structure.push(pass),
                    PassPhase::Value => scheduler.value.push(pass),
                    PassPhase::Simplify => scheduler.simplify.push(pass),
                    PassPhase::Inline => scheduler.inline.push(pass),
                    PassPhase::Normalize => scheduler.normalize.push(pass),
                }
                ctx.passes_created.insert(tech.id().to_string());
            }
        }
    }

    /// Marks dispatcher and decryptor methods as non-inlinable.
    ///
    /// CFF dispatchers should not be inlined because they are unflattened in
    /// place. Decryptor methods should not be inlined because the
    /// [`DecryptionPass`] needs to see them as intact call targets.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The analysis context containing dispatcher and decryptor token sets.
    fn configure_no_inline(&self, ctx: &AnalysisContext) {
        for token in ctx.dispatchers.iter() {
            ctx.compiler.no_inline.insert(*token);
        }
        for token in ctx.decryptors.registered_tokens() {
            ctx.compiler.no_inline.insert(token);
        }
    }

    /// Returns `true` if any technique has registered emulation requirements.
    ///
    /// Checks for decryptors, warmup methods, emulation hooks, or state machine
    /// providers — any of which indicate that passes will need emulation.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The analysis context to inspect for emulation requirements.
    fn needs_emulation(ctx: &AnalysisContext) -> bool {
        ctx.decryptors.has_decryptors()
            || ctx.has_warmup_methods()
            || ctx.has_emulation_hooks()
            || ctx.has_statemachine_providers()
    }

    /// Detection iteration loop: re-run SSA detection after the pipeline stabilizes.
    ///
    /// After the initial pipeline run reaches fixpoint, some techniques may become
    /// detectable for the first time (e.g., delegate proxy resolution exposes
    /// string decryptor call sites). This loop:
    ///
    /// 1. Re-runs `detect_ssa()` on all techniques
    /// 2. Initializes newly-detected techniques
    /// 3. Creates their passes and adds them to the scheduler
    /// 4. Re-runs the pipeline
    ///
    /// Bounded by `config.max_detection_rounds`.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The analysis context for detection and pass creation.
    /// * `assembly` - The assembly (shared reference for detection and passes).
    /// * `scheduler` - The pass scheduler to add newly-created passes to.
    /// * `detections` - Detection results; updated with new SSA-level findings.
    /// * `technique_results` - Accumulated per-technique results for reporting.
    ///
    /// # Returns
    ///
    /// The total number of additional pipeline iterations executed across all
    /// detection rounds.
    fn run_detection_loop(
        &self,
        ctx: &AnalysisContext,
        assembly: &Arc<CilObject>,
        scheduler: &mut PassScheduler,
        detections: &mut Detections,
        technique_results: &mut Vec<TechniqueResult>,
    ) -> Result<usize> {
        let mut total_iterations = 0;

        for detection_round in 0..self.config.max_detection_rounds {
            let mut new_detections = false;

            for tech in self.registry.techniques() {
                if !tech.enabled(&self.config) {
                    continue;
                }
                let ssa_det = tech.detect_ssa(ctx, assembly);
                if !ssa_det.detected {
                    continue;
                }
                if detections.is_detected(tech.id()) {
                    // Already known — merge updated findings but don't count as new
                    detections.merge(tech.id(), ssa_det);
                    continue;
                }
                info!(
                    "[technique] Re-detected (round {}): {}",
                    detection_round + 1,
                    tech.name()
                );
                detections.merge(tech.id(), ssa_det);
                new_detections = true;
            }

            if !new_detections {
                break;
            }

            // Record newly detected techniques
            self.record_detected_techniques(detections, technique_results);

            // Initialize newly-detected techniques
            self.initialize_techniques(ctx, assembly, detections);

            // Create passes for newly-detected techniques (skips already-created)
            self.create_technique_passes(ctx, assembly, detections, scheduler);

            // Update no-inline sets for new decryptors
            self.configure_no_inline(ctx);

            // Re-run pipeline
            total_iterations += scheduler.run_pipeline(ctx, assembly)?;
        }

        Ok(total_iterations)
    }

    /// Builds the merged cleanup request from all detected techniques and decryptors.
    ///
    /// Iterates all detected techniques in dependency order, collects their
    /// individual cleanup requests (types, methods, fields to remove), and merges
    /// them into a single [`CleanupRequest`]. Also adds methods from fully-emulated
    /// decryptors that are now safe to remove.
    ///
    /// This request is used by both the neutralization pass (to know which tokens
    /// to neutralize) and the final cleanup phase (to perform the actual deletions).
    fn build_cleanup(&self, ctx: &AnalysisContext, detections: &Detections) -> CleanupRequest {
        let mut merged_cleanup = detections.merged_cleanup();
        for tech in self.registry.sorted_techniques(detections) {
            if !detections.is_detected(tech.id()) {
                continue;
            }
            let detection = detections.get(tech.id()).unwrap();
            if let Some(tech_cleanup) = tech.cleanup(detection) {
                merged_cleanup.merge(&tech_cleanup);
            }
        }

        // Add decryptors that were fully emulated and are now safe to remove.
        for token in ctx.decryptors.removable_decryptors() {
            merged_cleanup.add_method(token);
        }

        merged_cleanup
    }

    /// Expands a cleanup request's token set to include member tokens of deleted types.
    ///
    /// The cleanup request stores [`TypeDef`](TableId::TypeDef) tokens for types
    /// scheduled for deletion, but SSA instructions reference their members via
    /// [`Field`](TableId::Field) and [`MethodDef`](TableId::MethodDef) tokens.
    /// Without expansion, the neutralization pass cannot match instructions that
    /// load fields or call methods belonging to deleted types.
    ///
    /// For each type in the request, this collects all its field and method tokens
    /// from the type registry and adds them to the token set.
    ///
    /// # Arguments
    ///
    /// * `request` - The merged cleanup request containing types, methods, and
    ///   fields scheduled for deletion.
    /// * `assembly` - The assembly whose type registry is used to resolve type
    ///   members.
    ///
    /// # Returns
    ///
    /// A [`HashSet`] containing all tokens from the request plus the expanded
    /// member tokens. Returns the original token set unchanged if no types are
    /// scheduled for deletion.
    fn expand_cleanup_tokens(request: &CleanupRequest, assembly: &CilObject) -> HashSet<Token> {
        let mut tokens = request.all_tokens();
        let registry = assembly.types();

        for type_token in request.types() {
            if let Some(cil_type) = registry.get(type_token) {
                for (_, field) in cil_type.fields.iter() {
                    tokens.insert(field.token);
                }
                for (_, method_ref) in cil_type.methods.iter() {
                    if let Some(method) = method_ref.upgrade() {
                        tokens.insert(method.token);
                    }
                }
            }
        }

        tokens
    }

    /// Entry point: Process assembly from file path.
    ///
    /// Loads the PE file with transparent repair and then
    /// delegates to [`process_assembly`](Self::process_assembly).
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the assembly file.
    ///
    /// # Returns
    ///
    /// A tuple containing the deobfuscated assembly and results.
    ///
    /// # Errors
    ///
    /// Returns an error if loading fails or deobfuscation fails.
    pub fn process_file<P: AsRef<std::path::Path>>(
        &mut self,
        path: P,
    ) -> Result<(CilObject, DeobfuscationResult)> {
        let file = File::from_path(path)?;
        self.process_dotscope_file(file)
    }

    /// Entry point: Process assembly from memory buffer.
    ///
    /// Loads the PE with transparent repair, then delegates to
    /// [`process_assembly`](Self::process_assembly).
    ///
    /// # Arguments
    ///
    /// * `bytes` - Raw assembly bytes.
    ///
    /// # Returns
    ///
    /// A tuple containing the deobfuscated assembly and results.
    ///
    /// # Errors
    ///
    /// Returns an error if loading fails or deobfuscation fails.
    pub fn process_bytes(&mut self, bytes: Vec<u8>) -> Result<(CilObject, DeobfuscationResult)> {
        let file = File::from_mem(bytes)?;
        self.process_dotscope_file(file)
    }

    /// Internal: loads a dotscope `File` into a `CilObject` and processes it.
    fn process_dotscope_file(&mut self, file: File) -> Result<(CilObject, DeobfuscationResult)> {
        if !file.repairs().is_empty() {
            info!(
                "PE repair applied {} fix(es) during loading",
                file.repairs().len()
            );
        }

        let assembly =
            CilObject::from_dotscope_file_with_validation(file, ValidationConfig::analysis())?;
        self.process_assembly(assembly)
    }

    /// Processes a single method through the deobfuscation pipeline.
    ///
    /// This runs the complete deobfuscation pipeline on a single method:
    /// - Obfuscator detection
    /// - Byte-level deobfuscation (anti-tamper decryption, etc.)
    /// - Full obfuscator initialization (decryptor registration, MethodSpec mapping)
    /// - Heuristic decryptor detection
    /// - SSA optimization passes
    ///
    /// Useful for debugging or testing specific methods without processing
    /// the entire assembly.
    ///
    /// # Arguments
    ///
    /// * `assembly` - The assembly containing the method (consumed).
    /// * `method_token` - The token of the method to process.
    ///
    /// # Returns
    ///
    /// A tuple containing:
    /// - The deobfuscated SSA function
    /// - The deobfuscation result with statistics and changes
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The method is not found in the assembly
    /// - SSA construction fails for the method
    /// - Any pass returns an error
    pub fn process_method(
        &self,
        assembly: CilObject,
        method_token: Token,
    ) -> Result<(SsaFunction, DeobfuscationResult)> {
        let start = Instant::now();
        let mut technique_results: Vec<TechniqueResult> = Vec::new();

        // Phase 1: Detection
        let mut detections = Detections::new();
        for tech in self.registry.techniques() {
            if !tech.enabled(&self.config) {
                continue;
            }
            let detection = tech.detect(&assembly);
            if detection.detected {
                info!("[technique] Detected: {}", tech.name());
            }
            detections.insert(tech.id(), detection);
        }

        // Phase 2: Byte transforms
        let mut working = WorkingAssembly::new(assembly);
        for tech in self.registry.sorted_techniques(&detections) {
            if !detections.is_detected(tech.id()) {
                continue;
            }
            let detection = detections.get(tech.id()).unwrap();
            let Some(transform_result) = tech.byte_transform(&mut working, detection, &detections)
            else {
                continue;
            };
            let tech_start = Instant::now();
            match transform_result {
                Ok(events) => {
                    technique_results.push(TechniqueResult {
                        id: tech.id().to_string(),
                        detected: true,
                        transformed: true,
                        evidence: detection.evidence.clone(),
                        events,
                        duration: tech_start.elapsed(),
                    });
                    detections.mark_transformed(tech.id());
                    if tech.requires_regeneration() {
                        working.commit()?;
                    }
                }
                Err(e) => {
                    log::warn!("[technique] {} transform failed: {}", tech.name(), e);
                }
            }
        }
        let assembly = working.into_cilobject()?;

        // Phase 2.5: Re-detect on post-transform assembly
        for tech in self.registry.techniques() {
            if !tech.enabled(&self.config) {
                continue;
            }
            let detection = tech.detect(&assembly);
            if detection.detected {
                info!("[technique] Post-transform detected: {}", tech.name());
            }
            detections.merge(tech.id(), detection);
        }

        // Phase 3: Build context and initialize techniques
        let assembly = Arc::new(assembly);
        let ctx = self.build_context(&assembly)?;

        // Phase 3.5: SSA-level detection
        for tech in self.registry.techniques() {
            if !tech.enabled(&self.config) {
                continue;
            }
            let ssa_det = tech.detect_ssa(&ctx, &assembly);
            if ssa_det.detected {
                info!("[technique] SSA-detected: {}", tech.name());
            }
            detections.merge(tech.id(), ssa_det);
        }

        for tech in self.registry.sorted_techniques(&detections) {
            if !detections.is_detected(tech.id()) {
                continue;
            }
            if tech.ssa_phase().is_none() {
                continue;
            }
            let detection = detections.get(tech.id()).unwrap();
            tech.initialize(&ctx, &assembly, detection, &detections);
        }

        // Create scheduler with compiler + technique passes
        let mut scheduler = self.create_scheduler();
        self.create_deob_passes(&ctx, &mut scheduler);

        for tech in self.registry.sorted_techniques(&detections) {
            if !detections.is_detected(tech.id()) {
                continue;
            }
            let Some(phase) = tech.ssa_phase() else {
                continue;
            };
            let detection = detections.get(tech.id()).unwrap();
            if let Some(pass) = tech.create_pass(&ctx, detection, &assembly) {
                match phase {
                    PassPhase::Structure => scheduler.structure.push(pass),
                    PassPhase::Value => scheduler.value.push(pass),
                    PassPhase::Simplify => scheduler.simplify.push(pass),
                    PassPhase::Inline => scheduler.inline.push(pass),
                    PassPhase::Normalize => scheduler.normalize.push(pass),
                }
            }
        }

        // Extract just the target method's SSA, process only this method
        let target_ssa = ctx
            .ssa_functions
            .remove(&method_token)
            .map(|(_, ssa)| ssa)
            .ok_or_else(|| Error::SsaError(format!("Method not found: {method_token}")))?;

        ctx.ssa_functions.clear();
        ctx.ssa_functions.insert(method_token, target_ssa);
        ctx.entry_points.clear();
        ctx.add_entry_point(method_token);

        // Run SSA optimization passes
        let iterations = scheduler.run_pipeline(&ctx, &assembly)?;

        // Extract and canonicalize
        let (_, mut final_ssa) = ctx
            .ssa_functions
            .remove(&method_token)
            .ok_or_else(|| Error::SsaError("SSA was unexpectedly removed".to_string()))?;

        final_ssa.canonicalize();

        let events = ctx.compiler.events.take();
        let attribution = self.registry.compute_attribution(&detections);
        let attributions = self.registry.compute_attributions_all(&detections);
        let result =
            DeobfuscationResult::new_with_techniques(events, technique_results, attribution)
                .with_attributions(attributions)
                .with_timing(start.elapsed(), iterations);

        Ok((final_ssa, result))
    }

    /// Processes a standalone SSA function through the deobfuscation pipeline.
    ///
    /// This is the lowest-level API for deobfuscation. It takes an SSA function
    /// directly and runs all passes on it. Useful for testing passes or when
    /// you've already constructed the SSA externally.
    ///
    /// Note: No obfuscator detection is performed since there's no assembly context.
    /// This means obfuscator-specific passes won't be activated.
    ///
    /// # Arguments
    ///
    /// * `assembly` - The assembly to use for context (needed for emulation).
    /// * `ssa` - The SSA function to process (will be modified in place).
    /// * `method_token` - A token to identify this method (can be synthetic).
    ///
    /// # Returns
    ///
    /// A [`DeobfuscationResult`] containing statistics and changes.
    /// The SSA is modified in place.
    ///
    /// # Errors
    ///
    /// Returns an error if any pass returns an error.
    pub fn process_ssa(
        &self,
        assembly: &Arc<CilObject>,
        ssa: &mut SsaFunction,
        method_token: Token,
    ) -> Result<DeobfuscationResult> {
        let start = Instant::now();

        // Build context (without assembly - it's passed separately to passes)
        let call_graph = Arc::new(CallGraph::new());
        let ctx = AnalysisContext::new(call_graph);

        // Create a fresh scheduler and populate deob passes
        let mut scheduler = self.create_scheduler();
        self.create_deob_passes(&ctx, &mut scheduler);

        // Take ownership of SSA temporarily
        let ssa_owned = std::mem::replace(ssa, SsaFunction::new(0, 0));
        ctx.ssa_functions.insert(method_token, ssa_owned);
        ctx.add_entry_point(method_token);

        // Run the pipeline
        let iterations = scheduler.run_pipeline(&ctx, assembly)?;

        // Extract and canonicalize the SSA, then return it via the mutable reference
        let (_, mut final_ssa) = ctx
            .ssa_functions
            .remove(&method_token)
            .ok_or_else(|| Error::SsaError("SSA was unexpectedly removed".to_string()))?;

        final_ssa.canonicalize();
        *ssa = final_ssa;

        let events = ctx.events.take();
        Ok(
            DeobfuscationResult::new_with_techniques(events, Vec::new(), None)
                .with_timing(start.elapsed(), iterations),
        )
    }

    /// Creates infrastructure deobfuscation passes.
    ///
    /// Adds only the passes that are not owned by any specific technique:
    /// - [`DecryptionPass`]: shared by all string/constant decryption techniques
    ///   (ConfuserEx, BitMono, Obfuscar, Generic strings/constants)
    ///
    /// Technique-owned passes (`OpaqueFieldPredicatePass`, `CffReconstructionPass`)
    /// are created by their respective techniques via [`SsaTechnique::create_pass`]
    /// and added separately by the technique pipeline.
    fn create_deob_passes(&self, ctx: &AnalysisContext, scheduler: &mut PassScheduler) {
        // CFF reconstruction runs unconditionally — it benefits all assemblies
        // regardless of whether CFF was explicitly detected, and is harmless
        // on non-CFF methods.
        scheduler
            .structure
            .push(Box::new(CffReconstructionPass::new(
                ctx,
                UnflattenConfig::default(),
            )));

        if self.config.enable_string_decryption {
            scheduler.value.push(Box::new(DecryptionPass::new(ctx)));
        }
    }

    /// Generates bytecode from optimized SSA and writes it back to the assembly.
    ///
    /// This phase takes the optimized SSA functions from the context and generates
    /// new CIL bytecode for each processed method, replacing the original method bodies.
    ///
    /// # Arguments
    ///
    /// * `assembly` - The assembly to update with new method bodies.
    /// * `ctx` - The analysis context containing canonicalized SSA functions.
    ///
    /// # Returns
    ///
    /// A tuple of (updated assembly, methods regenerated count).
    ///
    /// # Errors
    ///
    /// Returns an error if code generation or assembly writing fails.
    fn generate_code(assembly: CilObject, ctx: &AnalysisContext) -> Result<(CilObject, usize)> {
        // Skip if no methods were processed
        if ctx.processed_methods.is_empty() {
            return Ok((assembly, 0));
        }

        let mut cil_assembly = assembly.into_assembly();

        // Generate code for each processed method
        let mut codegen = SsaCodeGenerator::new();
        let mut methods_updated = 0;

        for entry in ctx.processed_methods.iter() {
            let method_token = *entry;
            // Note: Dead methods are not removed here during code generation.
            // Dead method removal is handled separately in postprocess cleanup
            // (see cleanup.rs), which uses table_row_remove() with proper RID
            // remapping to maintain metadata integrity.

            // Get the SSA function
            let Some(ssa) = ctx.ssa_functions.get(&method_token) else {
                continue;
            };

            // Generate CIL bytecode from SSA and build method body.
            // If codegen fails for a single method (e.g., EH offset issues
            // after optimization), skip rewriting it and keep the original IL.
            let result = match codegen.compile(&ssa, &mut cil_assembly) {
                Ok(result) => result,
                Err(e) => {
                    log::warn!(
                        "Code generation failed for method {method_token}, \
                         keeping original IL: {e}"
                    );
                    continue;
                }
            };

            // Warn if exception handlers were lost during code generation.
            // This can happen legitimately when optimization eliminates the
            // guarded try region, making handlers unreachable (e.g., dead code
            // removal, or fake handlers inserted by obfuscators).
            if ssa.has_exception_handlers() && result.exception_handlers.is_empty() {
                log::debug!(
                    "Method {method_token}: all exception handlers lost during code generation"
                );
            }

            let (method_body, _local_sig_token) = MethodBodyBuilder::from_compilation(
                result.bytecode,
                result.max_stack,
                result.locals,
                result.exception_handlers,
            )
            .build(&mut cil_assembly)?;

            // Store the method body and get placeholder RVA
            let placeholder_rva = cil_assembly.store_method_body(method_body);

            // Update the MethodDef row's RVA
            let rid = method_token.row();
            // closure needed — method reference with turbofish breaks type inference
            #[allow(clippy::redundant_closure_for_method_calls)]
            let existing_row = cil_assembly
                .view()
                .tables()
                .and_then(|t| t.table::<MethodDefRaw>())
                .and_then(|table| table.get(rid))
                .ok_or_else(|| {
                    Error::ModificationInvalid(format!("MethodDef row {rid} not found"))
                })?;

            let updated_row = MethodDefRaw {
                rid: existing_row.rid,
                token: existing_row.token,
                offset: existing_row.offset,
                rva: placeholder_rva,
                impl_flags: existing_row.impl_flags,
                flags: existing_row.flags,
                name: existing_row.name,
                signature: existing_row.signature,
                param_list: existing_row.param_list,
            };

            cil_assembly.table_row_update(
                TableId::MethodDef,
                rid,
                TableDataOwned::MethodDef(updated_row),
            )?;

            ctx.events
                .record(EventKind::CodeRegenerated)
                .method(method_token);
            methods_updated += 1;
        }

        if methods_updated == 0 {
            let result = cil_assembly
                .into_cilobject_with(ValidationConfig::analysis(), GeneratorConfig::default())?;
            return Ok((result, 0));
        }

        // Use deobfuscation config to skip original method bodies since we regenerated them
        let result = cil_assembly
            .into_cilobject_with(ValidationConfig::analysis(), GeneratorConfig::default())?;
        Ok((result, methods_updated))
    }

    /// Builds the analysis context for deobfuscation.
    ///
    /// Creates the call graph, SSA representations, and initializes the context
    /// with detection results and entry points.
    fn build_context(&self, assembly: &CilObject) -> Result<AnalysisContext> {
        // Build call graph
        let call_graph = Arc::new(CallGraph::build(assembly)?);
        let stats = call_graph.stats();
        info!(
            "Building analysis context: {} methods, {} call edges",
            stats.method_count, stats.edge_count
        );

        // Create context with engine config (important: cleanup settings!)
        let ctx = AnalysisContext::with_config(call_graph.clone(), self.config.clone());

        // Identify entry points
        Self::identify_entry_points(assembly, &ctx);

        // Build SSA for all methods
        Self::build_ssa_functions(assembly, &ctx)?;
        info!("Built SSA for {} methods", ctx.ssa_functions.len());

        Ok(ctx)
    }

    /// Identifies entry point methods in the assembly.
    ///
    /// Entry points are methods that can be called from outside the assembly or
    /// are special runtime entry points. This includes:
    ///
    /// - Main entry point from COR20 header
    /// - Static constructors (.cctor) - called automatically by the runtime
    /// - Instance constructors (.ctor) - can be called via `new`
    /// - Public virtual/abstract methods - can be called via polymorphism
    /// - Public static methods - can be called from external code
    /// - Event handler methods - commonly used as callbacks
    ///
    /// # Arguments
    ///
    /// * `assembly` - The CIL object containing the assembly metadata.
    /// * `ctx` - The analysis context to add entry points to.
    fn identify_entry_points(assembly: &CilObject, ctx: &AnalysisContext) {
        // 1. Main entry point from COR20 header
        let entry_token = assembly.cor20header().entry_point_token;
        if entry_token != 0 {
            ctx.add_entry_point(Token::new(entry_token));
        }

        // 2. Iterate through types and directly mark entry points for their methods
        let types = assembly.types();

        for type_entry in types.iter() {
            let cil_type = type_entry.value();
            let type_is_public = cil_type.is_public();

            // Check each method in this type using the query API
            for method in &cil_type.query_methods() {
                let method_token = method.token;

                // Static constructors are always entry points (runtime calls them)
                if method.is_cctor() {
                    ctx.add_entry_point(method_token);
                    continue;
                }

                // Check method characteristics
                let is_virtual = method.is_virtual();
                let is_abstract = method.is_abstract();
                let is_public = method.is_public();
                let is_static = method.is_static();

                // Virtual/abstract methods in public types are potential entry points
                if type_is_public && is_public && (is_virtual || is_abstract) {
                    ctx.add_entry_point(method_token);
                    continue;
                }

                // Instance constructors in public types
                if method.is_ctor() && type_is_public && is_public {
                    ctx.add_entry_point(method_token);
                    continue;
                }

                // Public static methods in public types
                if type_is_public && is_public && is_static {
                    ctx.add_entry_point(method_token);
                    continue;
                }

                // Methods with event handler signatures
                if method.is_event_handler() {
                    ctx.add_entry_point(method_token);
                }
            }
        }
    }

    /// Builds SSA functions for all methods in the assembly.
    ///
    /// Uses [`Method::ssa()`] to correctly resolve method signatures for call instructions,
    /// ensuring proper argument tracking in SSA form. Exception handlers are also
    /// preserved from the original method body.
    ///
    /// Methods are processed in parallel using rayon for faster SSA construction.
    fn build_ssa_functions(assembly: &CilObject, ctx: &AnalysisContext) -> Result<()> {
        // Collect method tokens that have CFGs
        let method_tokens: Vec<Token> = assembly
            .methods()
            .iter()
            .filter(|entry| entry.value().cfg().is_some())
            .map(|entry| *entry.key())
            .collect();

        // Build SSA in parallel, collecting errors
        let errors: Vec<(Token, Error)> = method_tokens
            .par_iter()
            .filter_map(|&method_token| {
                let method = assembly.method(&method_token)?;
                match method.ssa(assembly) {
                    Ok(ssa) => {
                        ctx.set_ssa(method_token, ssa);
                        None
                    }
                    Err(e) => Some((method_token, e)),
                }
            })
            .collect();

        if !errors.is_empty() {
            let messages: Vec<String> = errors
                .iter()
                .map(|(token, e)| format!("  0x{:08X}: {e}", token.value()))
                .collect();
            return Err(Error::SsaError(format!(
                "SSA construction failed for {} method(s):\n{}",
                errors.len(),
                messages.join("\n")
            )));
        }

        Ok(())
    }

    /// Runs interprocedural analysis on all methods.
    ///
    /// Performs interprocedural analysis: bottom-up summary computation followed
    /// by top-down constant propagation.
    ///
    /// In the bottom-up phase, iterates methods in reverse topological order
    /// (leaves first) to compute [`MethodSummary`] for each — return info,
    /// purity, parameter analysis, inlining candidacy, and pattern detection
    /// (string decryptors, dispatchers).
    ///
    /// In the top-down phase, collects call-site information from callers and
    /// propagates constant arguments to callee parameter summaries, enabling
    /// interprocedural constant propagation during SSA optimization.
    #[allow(clippy::unnecessary_wraps)] // Returns Result for API consistency with other analysis phases
    fn run_interprocedural_analysis(&self, ctx: &AnalysisContext) -> Result<()> {
        // Bottom-up: compute summaries from leaves to roots
        let topo_order = ctx.methods_topological();

        for method_token in topo_order.iter().rev() {
            if let Some(summary) = ctx.with_ssa(*method_token, |ssa| {
                self.compute_method_summary(ssa, *method_token)
            }) {
                // Mark dispatchers early so unflattening pass can skip redundant detection
                if summary.is_dispatcher {
                    ctx.mark_dispatcher(*method_token);
                }
                ctx.set_summary(summary);
            }
        }

        // Top-down: propagate constants from callers to callees
        let topo_order = ctx.methods_topological();
        for method_token in &topo_order {
            Self::collect_call_site_info(*method_token, ctx);
        }

        // Update parameter constants based on call sites
        Self::propagate_call_site_constants(ctx);
        Ok(())
    }

    /// Computes the [`MethodSummary`] for a single method from its SSA representation.
    ///
    /// Analyzes return behavior, side-effect purity, parameter usage, instruction
    /// count, inlining candidacy (pure + below threshold), and pattern detection
    /// for string decryptors and CFF dispatchers.
    fn compute_method_summary(&self, ssa: &SsaFunction, token: Token) -> MethodSummary {
        let mut summary = MethodSummary::new(token);

        summary.return_info = ssa.return_info();
        summary.purity = ssa.purity();
        summary.parameters = Self::analyze_parameters(ssa);
        summary.instruction_count = ssa.instruction_count();
        summary.inline_candidate = summary.purity.can_inline()
            && summary.instruction_count <= self.config.inline_threshold;
        summary.is_string_decryptor = Self::detect_string_decryptor_pattern(ssa);
        summary.is_dispatcher = Self::detect_dispatcher_pattern(ssa);

        summary
    }

    /// Analyzes method parameters for usage patterns.
    ///
    /// Examines how each parameter is used within the method:
    /// - Whether it's used at all (dead parameter detection)
    /// - How many times it's referenced
    /// - Whether it's only used in pure operations (foldable)
    /// - Whether it's passed through to return value unchanged
    fn analyze_parameters(ssa: &SsaFunction) -> Vec<ParameterSummary> {
        let param_count = ssa.num_args();
        let mut summaries = Vec::with_capacity(param_count);

        for i in 0..param_count {
            let mut param = ParameterSummary::new(i);
            param.is_used = ssa.is_parameter_used(i);
            param.use_count = ssa.parameter_use_count(i);

            // Determine if parameter is only used in pure operations
            // A parameter has pure-only usage if it's never passed to:
            // - Impure method calls
            // - Store operations
            // - Address-of operations
            let mut pure_only = true;

            // Find all uses of this parameter
            for block in ssa.blocks() {
                for instr in block.instructions() {
                    let op = instr.op();
                    // Check if this instruction uses the parameter
                    let uses = op.uses();
                    let uses_param = uses
                        .iter()
                        .any(|&var| ssa.is_parameter_variable(var) == Some(i));

                    if uses_param {
                        // Check if this is a pure operation
                        match op {
                            // These are impure or could escape the parameter
                            SsaOp::Call { .. }
                            | SsaOp::CallVirt { .. }
                            | SsaOp::CallIndirect { .. }
                            | SsaOp::NewObj { .. }
                            | SsaOp::StoreField { .. }
                            | SsaOp::StoreStaticField { .. }
                            | SsaOp::StoreElement { .. }
                            | SsaOp::StoreIndirect { .. }
                            | SsaOp::LoadFieldAddr { .. }
                            | SsaOp::LoadElementAddr { .. } => {
                                pure_only = false;
                            }
                            // Arithmetic, logical, and comparison ops are pure
                            _ => {}
                        }
                    }
                }
            }

            param.pure_usage_only = pure_only && param.is_used;
            summaries.push(param);
        }

        summaries
    }

    /// Collects call site information for a method.
    fn collect_call_site_info(caller_token: Token, ctx: &AnalysisContext) {
        let call_sites: Vec<(Token, CallSiteInfo)> = ctx
            .with_ssa(caller_token, |ssa| {
                let mut sites = Vec::new();

                for block in ssa.blocks() {
                    for (instr_idx, instr) in block.instructions().iter().enumerate() {
                        let op = instr.op();
                        let callee_token = match op {
                            SsaOp::Call { method, .. } | SsaOp::CallVirt { method, .. } => {
                                method.token()
                            }
                            _ => continue,
                        };

                        let info = CallSiteInfo {
                            caller: caller_token,
                            offset: instr_idx,
                            arguments: vec![],
                            is_live: true,
                        };

                        sites.push((callee_token, info));
                    }
                }

                sites
            })
            .unwrap_or_default();

        for (callee_token, info) in call_sites {
            ctx.add_call_site(callee_token, info);
        }
    }

    /// Propagates constants from call sites to callee parameters.
    fn propagate_call_site_constants(ctx: &AnalysisContext) {
        // Iterate directly over the DashMap entries
        for entry in &ctx.call_sites {
            let callee_token = *entry.key();
            let call_site_count = entry.value().count();

            ctx.modify_summary(callee_token, |summary| {
                summary.call_site_count = call_site_count;
            });
        }
    }

    /// Detects if a method looks like a string decryptor.
    ///
    /// Heuristics: small method with XOR operations or array accesses.
    fn detect_string_decryptor_pattern(ssa: &SsaFunction) -> bool {
        if ssa.instruction_count() > 200 {
            return false;
        }
        ssa.has_xor_operations() || ssa.has_array_element_access()
    }

    /// Detects if a method looks like a dispatcher (control flow obfuscation).
    ///
    /// Heuristics: contains a switch with many cases.
    fn detect_dispatcher_pattern(ssa: &SsaFunction) -> bool {
        ssa.largest_switch_target_count()
            .is_some_and(|switch_targets| switch_targets >= 5)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        analysis::{
            ConstValue, FieldRef, MethodPurity, MethodRef, ReturnInfo, SsaBlock, SsaFunction,
            SsaInstruction, SsaOp, SsaType, SsaVarId,
        },
        compiler::EventLog,
        deobfuscation::{
            config::EngineConfig, engine::DeobfuscationEngine, result::DeobfuscationResult,
        },
        metadata::token::Token,
    };

    #[test]
    fn test_engine_default() {
        let engine = DeobfuscationEngine::default();
        // Default config has all passes enabled
        assert!(engine.config.enable_constant_propagation);
        assert!(engine.config.enable_dead_code_elimination);
    }

    #[test]
    fn test_engine_config() {
        let config = EngineConfig {
            max_iterations: 10,
            inline_threshold: 30,
            ..Default::default()
        };

        let engine = DeobfuscationEngine::new(config);
        assert_eq!(engine.config.max_iterations, 10);
        assert_eq!(engine.config.inline_threshold, 30);
    }

    #[test]
    fn test_pipeline_passes_default() {
        let engine = DeobfuscationEngine::default();
        let scheduler = engine.create_scheduler();

        // Deob passes (structure, value) start empty — populated by create_deob_passes()
        // after detection builds an AnalysisContext.
        assert!(scheduler.structure.is_empty()); // Populated later with CffReconstructionPass
        assert!(scheduler.value.is_empty()); // Populated later with DecryptionPass

        // Generic compiler passes are always present from the constructor.
        assert!(!scheduler.simplify.is_empty()); // Opaque predicates + CFG (Phase 3)
        assert!(!scheduler.normalize.is_empty()); // DCE, constant prop, GVN, copy prop, strength reduction
    }

    #[test]
    fn test_pipeline_passes_selective() {
        let config = EngineConfig {
            enable_constant_propagation: true,
            enable_copy_propagation: false,
            enable_opaque_predicate_removal: false,
            enable_control_flow_simplification: false,
            enable_dead_code_elimination: false,
            enable_string_decryption: false,
            enable_strength_reduction: false,
            ..Default::default()
        };

        let engine = DeobfuscationEngine::new(config);
        let scheduler = engine.create_scheduler();

        // Reassociation + constant propagation + GVN should be in normalize
        assert_eq!(scheduler.normalize.len(), 3); // ReassociationPass + ConstantPropagationPass + GVN
        assert!(scheduler.simplify.is_empty()); // No opaque pred or CFG
        assert!(scheduler.structure.is_empty()); // No unflattening
        assert!(scheduler.value.is_empty()); // No decryption
    }

    #[test]
    fn test_analyze_return_void() {
        // Create SSA with void return
        let mut ssa = SsaFunction::new(0, 0);
        let mut block = SsaBlock::new(0);
        block.add_instruction(SsaInstruction::synthetic(SsaOp::Return { value: None }));
        ssa.add_block(block);

        let result = ssa.return_info();
        assert!(matches!(result, ReturnInfo::Void));
    }

    #[test]
    fn test_analyze_return_constant() {
        // Create SSA that returns a constant
        let mut ssa = SsaFunction::new(0, 0);
        let mut block = SsaBlock::new(0);

        // Define a constant
        let var = SsaVarId::from_index(0);
        block.add_instruction(SsaInstruction::synthetic(SsaOp::Const {
            dest: var,
            value: ConstValue::I32(42),
        }));

        // Return the constant
        block.add_instruction(SsaInstruction::synthetic(SsaOp::Return {
            value: Some(var),
        }));
        ssa.add_block(block);

        let result = ssa.return_info();
        assert!(matches!(result, ReturnInfo::Constant(ConstValue::I32(42))));
    }

    #[test]
    fn test_analyze_return_no_returns_is_void() {
        // Create SSA with no return statements (unusual but possible)
        let mut ssa = SsaFunction::new(0, 0);
        let block = SsaBlock::new(0);
        ssa.add_block(block);

        let result = ssa.return_info();
        assert!(matches!(result, ReturnInfo::Void));
    }

    #[test]
    fn test_analyze_purity_pure() {
        // Create SSA with only pure operations
        let mut ssa = SsaFunction::new(0, 0);
        let mut block = SsaBlock::new(0);

        // Pure arithmetic operation
        let dest = SsaVarId::from_index(0);
        let src1 = SsaVarId::from_index(1);
        let src2 = SsaVarId::from_index(2);
        block.add_instruction(SsaInstruction::synthetic(SsaOp::Add {
            dest,
            left: src1,
            right: src2,
        }));
        block.add_instruction(SsaInstruction::synthetic(SsaOp::Return {
            value: Some(dest),
        }));
        ssa.add_block(block);

        let result = ssa.purity();
        assert!(matches!(result, MethodPurity::Pure));
    }

    #[test]
    fn test_analyze_purity_impure_store_field() {
        // Create SSA with a field store
        let mut ssa = SsaFunction::new(0, 0);
        let mut block = SsaBlock::new(0);

        let obj = SsaVarId::from_index(0);
        let val = SsaVarId::from_index(1);
        block.add_instruction(SsaInstruction::synthetic(SsaOp::StoreField {
            object: obj,
            field: FieldRef::new(Token::new(0x04000001)),
            value: val,
        }));
        block.add_instruction(SsaInstruction::synthetic(SsaOp::Return { value: None }));
        ssa.add_block(block);

        let result = ssa.purity();
        assert!(matches!(result, MethodPurity::Impure));
    }

    #[test]
    fn test_analyze_purity_impure_throw() {
        // Create SSA with a throw
        let mut ssa = SsaFunction::new(0, 0);
        let mut block = SsaBlock::new(0);

        let exc = SsaVarId::from_index(0);
        block.add_instruction(SsaInstruction::synthetic(SsaOp::Throw { exception: exc }));
        ssa.add_block(block);

        let result = ssa.purity();
        assert!(matches!(result, MethodPurity::Impure));
    }

    #[test]
    fn test_analyze_purity_readonly() {
        // Create SSA with only field reads
        let mut ssa = SsaFunction::new(0, 0);
        let mut block = SsaBlock::new(0);

        let dest = SsaVarId::from_index(0);
        let obj = SsaVarId::from_index(1);
        block.add_instruction(
            SsaInstruction::synthetic(SsaOp::LoadField {
                dest,
                object: obj,
                field: FieldRef::new(Token::new(0x04000001)),
            })
            .with_result_type(SsaType::I32),
        );
        block.add_instruction(SsaInstruction::synthetic(SsaOp::Return {
            value: Some(dest),
        }));
        ssa.add_block(block);

        let result = ssa.purity();
        assert!(matches!(result, MethodPurity::ReadOnly));
    }

    #[test]
    fn test_analyze_purity_unknown_calls() {
        // Create SSA with a call
        let mut ssa = SsaFunction::new(0, 0);
        let mut block = SsaBlock::new(0);

        let dest = SsaVarId::from_index(0);
        block.add_instruction(
            SsaInstruction::synthetic(SsaOp::Call {
                dest: Some(dest),
                method: MethodRef::new(Token::new(0x06000001)),
                args: vec![],
            })
            .with_result_type(SsaType::I32),
        );
        block.add_instruction(SsaInstruction::synthetic(SsaOp::Return {
            value: Some(dest),
        }));
        ssa.add_block(block);

        let result = ssa.purity();
        assert!(matches!(result, MethodPurity::Unknown));
    }

    #[test]
    fn test_detect_string_decryptor_xor() {
        // Create small SSA with XOR operations (typical of string decryption)
        let mut ssa = SsaFunction::new(0, 0);
        let mut block = SsaBlock::new(0);

        let dest = SsaVarId::from_index(0);
        let left = SsaVarId::from_index(1);
        let right = SsaVarId::from_index(2);
        block.add_instruction(SsaInstruction::synthetic(SsaOp::Xor { dest, left, right }));
        block.add_instruction(SsaInstruction::synthetic(SsaOp::Return {
            value: Some(dest),
        }));
        ssa.add_block(block);

        let result = DeobfuscationEngine::detect_string_decryptor_pattern(&ssa);
        assert!(result);
    }

    #[test]
    fn test_detect_string_decryptor_large_method() {
        // Create large SSA (over 200 instructions)
        let mut ssa = SsaFunction::new(0, 0);
        let mut block = SsaBlock::new(0);

        // Add 250 instructions
        for _ in 0..250_usize {
            let dest = SsaVarId::from_index(0);
            block.add_instruction(SsaInstruction::synthetic(SsaOp::Const {
                dest,
                value: ConstValue::I32(42),
            }));
        }
        block.add_instruction(SsaInstruction::synthetic(SsaOp::Return { value: None }));
        ssa.add_block(block);

        // Large methods should not be detected as string decryptors
        let result = DeobfuscationEngine::detect_string_decryptor_pattern(&ssa);
        assert!(!result);
    }

    #[test]
    fn test_detect_dispatcher_with_switch() {
        // Create SSA with a switch having 5+ targets
        let mut ssa = SsaFunction::new(0, 0);
        let mut block = SsaBlock::new(0);

        let value = SsaVarId::from_index(0);
        block.add_instruction(SsaInstruction::synthetic(SsaOp::Switch {
            value,
            targets: vec![1, 2, 3, 4, 5], // 5 targets
            default: 6,
        }));
        ssa.add_block(block);

        let result = DeobfuscationEngine::detect_dispatcher_pattern(&ssa);
        assert!(result);
    }

    #[test]
    fn test_detect_dispatcher_small_switch() {
        // Create SSA with a small switch (< 5 targets)
        let mut ssa = SsaFunction::new(0, 0);
        let mut block = SsaBlock::new(0);

        let value = SsaVarId::from_index(0);
        block.add_instruction(SsaInstruction::synthetic(SsaOp::Switch {
            value,
            targets: vec![1, 2],
            default: 3,
        }));
        ssa.add_block(block);

        let result = DeobfuscationEngine::detect_dispatcher_pattern(&ssa);
        assert!(!result);
    }

    #[test]
    fn test_detect_dispatcher_no_switch() {
        // Create SSA without switch
        let mut ssa = SsaFunction::new(0, 0);
        let mut block = SsaBlock::new(0);
        block.add_instruction(SsaInstruction::synthetic(SsaOp::Return { value: None }));
        ssa.add_block(block);

        let result = DeobfuscationEngine::detect_dispatcher_pattern(&ssa);
        assert!(!result);
    }

    #[test]
    fn test_compute_method_summary() {
        let engine = DeobfuscationEngine::default();

        // Create a simple pure method with constant return
        let mut ssa = SsaFunction::new(0, 0);
        let mut block = SsaBlock::new(0);

        let var = SsaVarId::from_index(0);
        block.add_instruction(SsaInstruction::synthetic(SsaOp::Const {
            dest: var,
            value: ConstValue::I32(42),
        }));
        block.add_instruction(SsaInstruction::synthetic(SsaOp::Return {
            value: Some(var),
        }));
        ssa.add_block(block);

        let token = Token::new(0x06000001);
        let summary = engine.compute_method_summary(&ssa, token);

        assert_eq!(summary.token, token);
        assert!(matches!(summary.return_info, ReturnInfo::Constant(_)));
        assert!(matches!(summary.purity, MethodPurity::Pure));
        assert!(!summary.is_string_decryptor);
        assert!(!summary.is_dispatcher);
    }

    #[test]
    fn test_deobfuscation_result_summary() {
        let result = DeobfuscationResult::new_with_techniques(EventLog::new(), Vec::new(), None);

        // summary() returns just the stats (no prefix)
        let summary = result.summary();
        assert!(!summary.is_empty() || summary == "No changes"); // Stats or "No changes"

        // detailed_summary() includes detection info
        let detailed = result.detailed_summary();
        assert!(detailed.contains("Deobfuscation complete"));
    }
}
