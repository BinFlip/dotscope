//! Main deobfuscation engine.
//!
//! The [`DeobfuscationEngine`] is the main entry point for deobfuscating
//! .NET assemblies. It orchestrates detection, analysis, pass execution,
//! and code generation.

use std::{sync::Arc, time::Instant};

use rayon::prelude::*;

use crate::{
    analysis::{CallGraph, SsaFunction, SsaOp, SsaType},
    cilassembly::GeneratorConfig,
    deobfuscation::{
        changes::{EventKind, EventLog},
        cleanup::execute_cleanup,
        codegen::SsaCodeGenerator,
        config::EngineConfig,
        context::AnalysisContext,
        detection::DetectionResult,
        detector::ObfuscatorDetector,
        obfuscators::Obfuscator,
        pass::SsaPass,
        passes::{
            AlgebraicSimplificationPass, BlockMergingPass, CffReconstructionPass,
            ConstantPropagationPass, ControlFlowSimplificationPass, CopyPropagationPass,
            DeadCodeEliminationPass, DeadMethodEliminationPass, DecryptionPass,
            GlobalValueNumberingPass, InliningPass, JumpThreadingPass, LicmPass,
            NeutralizationPass, OpaquePredicatePass, ReassociationPass, StrengthReductionPass,
            ValueRangePropagationPass,
        },
        result::DeobfuscationResult,
        scheduler::PassScheduler,
        summary::{CallSiteInfo, MethodSummary, ParameterSummary},
    },
    metadata::{
        method::{
            encode_exception_handlers, encode_method_body_header, ExceptionHandler,
            ExceptionHandlerFlags, MethodAccessFlags, MethodModifiers,
        },
        signatures::{
            encode_local_var_signature, CustomModifiers, SignatureLocalVariable,
            SignatureLocalVariables,
        },
        tables::{MethodDefRaw, StandAloneSigBuilder, TableDataOwned, TableId, TypeAttributes},
        token::Token,
        validation::ValidationConfig,
    },
    CilObject, Error, Result,
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
    /// Obfuscator detector.
    detector: ObfuscatorDetector,
    /// Pass scheduler.
    scheduler: PassScheduler,

    // Pipeline passes (built once in constructor)
    // 4-phase architecture: each phase runs to fixpoint with normalize after changes
    /// Phase 1: Structure recovery (control-flow unflattening).
    structure_passes: Vec<Box<dyn SsaPass>>,
    /// Phase 2: Value recovery (string/constant decryption).
    value_passes: Vec<Box<dyn SsaPass>>,
    /// Phase 3: Simplification (opaque predicates + CFG recovery).
    simplify_passes: Vec<Box<dyn SsaPass>>,
    /// Phase 4: Proxy/delegate inlining.
    inline_passes: Vec<Box<dyn SsaPass>>,
    /// Normalization passes (DCE, GVN, constant/copy propagation).
    /// Run after each structural change in every phase.
    normalize_passes: Vec<Box<dyn SsaPass>>,
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
        let scheduler = PassScheduler::new(
            config.max_iterations,
            config.stable_iterations,
            config.max_phase_iterations,
        );

        // Phase 1: Structure recovery (control-flow unflattening)
        let mut structure_passes: Vec<Box<dyn SsaPass>> = Vec::new();
        if config.enable_control_flow_simplification {
            structure_passes.push(Box::new(CffReconstructionPass::with_defaults()));
        }

        // Phase 2: Value recovery (decryption)
        // DecryptionPass uses the DecryptorContext which is populated during detection by:
        // - Obfuscator-specific detectors (ConfuserEx, etc.) with high confidence
        // - Heuristic detectors that identify potential decryptors by signature
        let mut value_passes: Vec<Box<dyn SsaPass>> = Vec::new();
        if config.enable_string_decryption {
            value_passes.push(Box::new(DecryptionPass::new()));
        }

        // Phase 3: Simplification (opaque predicates + CFG recovery + jump threading + range propagation)
        // Combined from old phases 3 and 4, plus new jump threading and value range propagation
        let mut simplify_passes: Vec<Box<dyn SsaPass>> = Vec::new();
        if config.enable_opaque_predicate_removal {
            simplify_passes.push(Box::new(OpaquePredicatePass::new()));
            simplify_passes.push(Box::new(ValueRangePropagationPass::new()));
        }
        if config.enable_control_flow_simplification {
            simplify_passes.push(Box::new(ControlFlowSimplificationPass::new()));
            simplify_passes.push(Box::new(JumpThreadingPass::new()));
        }

        // Phase 4: Proxy/delegate inlining
        let mut inline_passes: Vec<Box<dyn SsaPass>> = Vec::new();
        if config.enable_inlining {
            inline_passes.push(Box::new(InliningPass::with_threshold(
                config.inline_threshold,
            )));
        }

        // Normalization passes (run after each structural change in every phase)
        let mut normalize_passes: Vec<Box<dyn SsaPass>> = Vec::new();
        if config.enable_dead_code_elimination {
            normalize_passes.push(Box::new(DeadCodeEliminationPass::new()));
            normalize_passes.push(Box::new(BlockMergingPass::new()));
            normalize_passes.push(Box::new(LicmPass::new()));
        }
        if config.enable_constant_propagation {
            normalize_passes.push(Box::new(ReassociationPass::new()));
            normalize_passes.push(Box::new(ConstantPropagationPass::new()));
            normalize_passes.push(Box::new(GlobalValueNumberingPass::new()));
        }
        if config.enable_copy_propagation {
            normalize_passes.push(Box::new(CopyPropagationPass::new()));
        }
        if config.enable_strength_reduction {
            normalize_passes.push(Box::new(StrengthReductionPass::new()));
            normalize_passes.push(Box::new(AlgebraicSimplificationPass::new()));
        }

        Self {
            config,
            detector: ObfuscatorDetector::new(),
            scheduler,
            structure_passes,
            value_passes,
            simplify_passes,
            inline_passes,
            normalize_passes,
        }
    }

    /// Registers an obfuscator with the engine.
    ///
    /// Obfuscators provide obfuscator-specific detection and transformation logic.
    ///
    /// # Arguments
    ///
    /// * `obfuscator` - The obfuscator to register, wrapped in an `Arc` for shared ownership.
    pub fn register_obfuscator(&mut self, obfuscator: Arc<dyn Obfuscator>) {
        self.detector.register(obfuscator);
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
        &mut self,
        assembly: CilObject,
    ) -> Result<(CilObject, DeobfuscationResult)> {
        let start = Instant::now();

        // Phase 1: Detection (borrow, read-only)
        let detection = self.detector.detect(&assembly);

        // Phase 2: Byte-level deobfuscation (consume → produce)
        let (assembly, byte_level_events) = self.run_byte_level(assembly, &detection)?;

        // Phase 3: SSA pipeline + code generation + postprocessing (consume → produce)
        let (assembly, ssa_events, iterations) = self.run_ssa_pipeline(assembly, &detection)?;

        // Build result by merging all events
        let events = byte_level_events;
        events.merge(ssa_events);
        let result =
            DeobfuscationResult::new(detection, events).with_timing(start.elapsed(), iterations);

        Ok((assembly, result))
    }

    /// Phase 2: Byte-level deobfuscation.
    ///
    /// Runs obfuscator-specific byte-level transformations such as:
    /// - Anti-tamper decryption
    /// - Method body decryption
    /// - Resource unpacking
    ///
    /// # Arguments
    ///
    /// * `assembly` - The assembly to process (consumed).
    /// * `detection` - Detection results identifying the obfuscator.
    ///
    /// # Returns
    ///
    /// A tuple of (processed assembly, event log).
    fn run_byte_level(
        &self,
        assembly: CilObject,
        detection: &DetectionResult,
    ) -> Result<(CilObject, EventLog)> {
        let mut events = EventLog::new();

        let assembly = if let Some(obfuscator) = detection.primary() {
            obfuscator.set_config(&self.config);
            obfuscator.deobfuscate(assembly, &mut events)?
        } else {
            assembly
        };

        Ok((assembly, events))
    }

    /// Phase 3: SSA pipeline, code generation, and postprocessing.
    ///
    /// This phase:
    /// 1. Reloads the assembly with analysis validation
    /// 2. Builds the analysis context with call graph and SSA
    /// 3. Runs interprocedural analysis
    /// 4. Executes SSA optimization passes
    /// 5. Generates optimized bytecode
    /// 6. Runs obfuscator-specific postprocessing (cleanup)
    ///
    /// The `AnalysisContext` is created internally and lives for the duration
    /// of this phase. The assembly is wrapped in `Arc` internally for sharing
    /// with the context and emulation.
    ///
    /// # Arguments
    ///
    /// * `assembly` - The assembly to process (consumed).
    /// * `detection` - Detection results identifying the obfuscator.
    ///
    /// # Returns
    ///
    /// A tuple of (processed assembly, event log, iteration count).
    fn run_ssa_pipeline(
        &mut self,
        assembly: CilObject,
        detection: &DetectionResult,
    ) -> Result<(CilObject, EventLog, usize)> {
        // Wrap in Arc for shared access during analysis
        let assembly_arc = Arc::new(assembly);

        // Build analysis context (doesn't store assembly)
        let mut ctx = self.build_context(&assembly_arc, detection.clone())?;

        // Initialize context with obfuscator-specific data
        // This registers decryptors and other state needed by SSA passes
        if let Some(obfuscator) = detection.primary() {
            obfuscator.initialize_context(&ctx, &assembly_arc);

            // Add obfuscator-specific SSA passes to the simplification phase
            // These run after value recovery (decryption) to clean up obfuscator artifacts
            let obfuscator_passes = obfuscator.passes();
            if !obfuscator_passes.is_empty() {
                self.simplify_passes.extend(obfuscator_passes);
            }
        }

        // Interprocedural analysis
        self.run_interprocedural_analysis(&ctx)?;

        // Run SSA optimization passes
        let mut iterations = self.run_pipeline_on_context(&ctx, &assembly_arc)?;

        // Run dead method elimination after all passes to identify methods that
        // became unreachable due to inlining or other transformations.
        // This uses SSA call information to account for transformations.
        if ctx.config.cleanup.remove_unused_methods {
            let dead_method_pass = DeadMethodEliminationPass::new();
            let _ = dead_method_pass.run_global(&ctx, &assembly_arc)?;
        }

        // Get obfuscator's cleanup request and run neutralization pass
        // This removes instructions that reference protection infrastructure
        let cleanup_request = if let Some(obfuscator) = detection.primary() {
            if let Some(request) = obfuscator.cleanup_request(&assembly_arc, &ctx)? {
                let removed_tokens = request.all_tokens();
                let mut neutralized = false;

                if !removed_tokens.is_empty() {
                    let pass = NeutralizationPass::new(&removed_tokens);

                    // Neutralize module .cctor if it exists
                    // The .cctor may contain both protection initialization AND legitimate code,
                    // so we neutralize (partial removal) rather than delete
                    if let Some(cctor_token) = assembly_arc.types().module_cctor() {
                        if let Some(mut ssa) = ctx.ssa_functions.get_mut(&cctor_token) {
                            if pass.run_on_method(&mut ssa, cctor_token, &ctx, &assembly_arc)? {
                                neutralized = true;
                            }
                        }
                    }
                }

                // After neutralization, re-run the full SSA pass pipeline to fixpoint
                // This cleans up dead code that fed into neutralized instructions
                if neutralized {
                    iterations += self.run_pipeline_on_context(&ctx, &assembly_arc)?;
                }

                Some(request)
            } else {
                None
            }
        } else {
            None
        };

        // Canonicalize all SSA functions before code generation
        ctx.canonicalize_all_ssa();

        // Unwrap the Arc - we should be the only owner now
        let assembly = Arc::try_unwrap(assembly_arc).map_err(|_| {
            Error::Deobfuscation("Cannot unwrap assembly - still has other references".into())
        })?;

        // Generate code from SSA back to CIL
        let (assembly, _methods_regenerated) = self.generate_code(assembly, &ctx)?;

        // Unified cleanup: combine obfuscator cleanup request with dead methods
        // All cleanup happens in one pass to avoid RID staleness issues.
        let assembly = execute_cleanup(assembly, cleanup_request, &ctx)?;

        let events = std::mem::take(&mut ctx.events);
        Ok((assembly, events, iterations))
    }

    /// Entry point: Process assembly from file path.
    ///
    /// Convenience wrapper that loads with lenient validation then
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
        let assembly = CilObject::from_path_with_validation(
            path,
            ValidationConfig::analysis(), // lenient
        )?;
        self.process_assembly(assembly)
    }

    /// Entry point: Process assembly from memory buffer.
    ///
    /// Convenience wrapper that loads with lenient validation then
    /// delegates to [`process_assembly`](Self::process_assembly).
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
        let assembly = CilObject::from_mem_with_validation(
            bytes,
            ValidationConfig::analysis(), // lenient
        )?;
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
        &mut self,
        assembly: CilObject,
        method_token: Token,
    ) -> Result<(SsaFunction, DeobfuscationResult)> {
        let start = Instant::now();

        // Phase 1: Detection
        let detection = self.detector.detect(&assembly);

        // Phase 2: Byte-level deobfuscation (anti-tamper, etc.)
        let (assembly, byte_events) = self.run_byte_level(assembly, &detection)?;
        let assembly = Arc::new(assembly);

        // Phase 3: Build context with full obfuscator initialization
        let ctx = self.build_context(&assembly, detection.clone())?;

        // Initialize context with obfuscator-specific data (decryptors, MethodSpec mappings)
        if let Some(obfuscator) = detection.primary() {
            obfuscator.initialize_context(&ctx, &assembly);
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
        let iterations = self.run_pipeline_on_context(&ctx, &assembly)?;

        // Extract and canonicalize
        let (_, mut final_ssa) = ctx
            .ssa_functions
            .remove(&method_token)
            .ok_or_else(|| Error::SsaError("SSA was unexpectedly removed".to_string()))?;

        final_ssa.canonicalize();

        // Merge events
        let events = byte_events;
        events.merge(ctx.events.take());
        let result =
            DeobfuscationResult::new(detection, events).with_timing(start.elapsed(), iterations);

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
        &mut self,
        assembly: &Arc<CilObject>,
        ssa: &mut SsaFunction,
        method_token: Token,
    ) -> Result<DeobfuscationResult> {
        let start = Instant::now();

        // Build context (without assembly - it's passed separately to passes)
        let call_graph = Arc::new(CallGraph::new());
        let ctx = AnalysisContext::new(call_graph);

        // Take ownership of SSA temporarily
        let ssa_owned = std::mem::replace(ssa, SsaFunction::new(0, 0));
        ctx.ssa_functions.insert(method_token, ssa_owned);
        ctx.add_entry_point(method_token);

        // Run the pipeline
        let iterations = self.run_pipeline_on_context(&ctx, assembly)?;

        // Extract and canonicalize the SSA, then return it via the mutable reference
        let (_, mut final_ssa) = ctx
            .ssa_functions
            .remove(&method_token)
            .ok_or_else(|| Error::SsaError("SSA was unexpectedly removed".to_string()))?;

        final_ssa.canonicalize();
        *ssa = final_ssa;

        let events = ctx.events.take();
        Ok(DeobfuscationResult::new(DetectionResult::default(), events)
            .with_timing(start.elapsed(), iterations))
    }

    /// Runs the deobfuscation pipeline on an already-prepared context.
    ///
    /// This is the shared internal implementation used by all public APIs.
    /// The context must already have SSA functions loaded.
    ///
    /// Returns the number of iterations. Events are accumulated in `ctx.events`.
    fn run_pipeline_on_context(
        &mut self,
        ctx: &AnalysisContext,
        assembly: &Arc<CilObject>,
    ) -> Result<usize> {
        self.scheduler.run_pipeline(
            ctx,
            &mut self.structure_passes,
            &mut self.value_passes,
            &mut self.simplify_passes,
            &mut self.inline_passes,
            &mut self.normalize_passes,
            assembly,
        )
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
    fn generate_code(
        &self,
        assembly: CilObject,
        ctx: &AnalysisContext,
    ) -> Result<(CilObject, usize)> {
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

            // Generate CIL bytecode from SSA
            let (bytecode, max_stack, num_locals) = codegen
                .generate_with_assembly(&ssa, &mut cil_assembly)
                .map_err(|e| {
                    Error::Deobfuscation(format!(
                        "Code generation failed for method {}: {}",
                        method_token, e
                    ))
                })?;

            // Generate local variable signature from compacted locals
            // The codegen automatically compacts locals - only allocating indices
            // for locals that are actually used. We build the signature from
            // the codegen's local_types map to match.
            let local_var_sig_token = if num_locals > 0 {
                let local_types = codegen.local_types();
                let original_mapping = codegen.original_local_mapping();

                // Build signature using codegen's compacted types
                // For each local index 0..num_locals, get its type from local_types
                // or fall back to the original SSA type if available
                let mut locals = Vec::with_capacity(num_locals as usize);
                for idx in 0..num_locals {
                    let local_type = if let Some(ssa_type) = local_types.get(&idx) {
                        // Use codegen's recorded type
                        ssa_type.to_type_signature()
                    } else {
                        // Fall back to original type via the mapping
                        let orig_type = original_mapping
                            .iter()
                            .find(|(_, &new)| new == idx)
                            .and_then(|(&orig, _)| {
                                ssa.original_local_types()
                                    .and_then(|types| types.get(orig as usize))
                                    .map(|v| v.base.clone())
                            });
                        orig_type.unwrap_or_else(|| SsaType::I32.to_type_signature())
                    };
                    locals.push(SignatureLocalVariable {
                        modifiers: CustomModifiers::default(),
                        is_pinned: false,
                        is_byref: false,
                        base: local_type,
                    });
                }

                let local_sig = SignatureLocalVariables { locals };

                if local_sig.locals.is_empty() {
                    0
                } else {
                    // Encode and add to assembly
                    match encode_local_var_signature(&local_sig) {
                        Ok(encoded) => {
                            match StandAloneSigBuilder::new()
                                .signature(&encoded)
                                .build(&mut cil_assembly)
                            {
                                Ok(change_ref) => Token::from_parts(
                                    TableId::StandAloneSig,
                                    change_ref.placeholder(),
                                )
                                .value(),
                                Err(_) => 0,
                            }
                        }
                        Err(_) => 0,
                    }
                }
            } else {
                0
            };

            // Remap and encode exception handlers if present
            let (exception_data, has_exceptions) = if ssa.has_exception_handlers() {
                let block_offsets = codegen.block_offsets();
                let bytecode_len = bytecode.len() as u32;

                // Remap exception handlers using block offset mapping
                let remapped_handlers: Vec<ExceptionHandler> = ssa
                    .exception_handlers()
                    .iter()
                    .filter_map(|eh| {
                        // Get new offsets from block mapping
                        let try_offset = eh
                            .try_start_block
                            .and_then(|b| block_offsets.get(&b).copied())
                            .unwrap_or(eh.try_offset);

                        let handler_offset = eh
                            .handler_start_block
                            .and_then(|b| block_offsets.get(&b).copied())
                            .unwrap_or(eh.handler_offset);

                        // For try_end: use handler_offset as fallback since try ends where handler starts
                        let try_end = eh
                            .try_end_block
                            .and_then(|b| block_offsets.get(&b).copied())
                            .unwrap_or(handler_offset);

                        // For handler_end: if no end block, handler extends to end of method
                        let handler_end = eh
                            .handler_end_block
                            .and_then(|b| block_offsets.get(&b).copied())
                            .unwrap_or(bytecode_len);

                        let filter_offset = if eh.flags == ExceptionHandlerFlags::FILTER {
                            eh.filter_start_block
                                .and_then(|b| block_offsets.get(&b).copied())
                                .unwrap_or(eh.class_token_or_filter)
                        } else {
                            eh.class_token_or_filter
                        };

                        // Validate offsets are within bytecode bounds
                        if try_offset >= bytecode_len
                            || handler_offset >= bytecode_len
                            || try_end > bytecode_len
                            || handler_end > bytecode_len
                        {
                            // Skip invalid handlers (may have been optimized away)
                            return None;
                        }

                        Some(ExceptionHandler {
                            flags: eh.flags,
                            try_offset,
                            try_length: try_end.saturating_sub(try_offset),
                            handler_offset,
                            handler_length: handler_end.saturating_sub(handler_offset),
                            handler: None, // Type info is in class_token_or_filter
                            filter_offset,
                        })
                    })
                    .collect();

                if remapped_handlers.is_empty() {
                    (Vec::new(), false)
                } else {
                    match encode_exception_handlers(&remapped_handlers) {
                        Ok(data) => (data, true),
                        Err(_) => (Vec::new(), false),
                    }
                }
            } else {
                (Vec::new(), false)
            };

            // Create the method body header
            let header = encode_method_body_header(
                bytecode.len() as u32,
                max_stack,
                local_var_sig_token,
                has_exceptions,
                local_var_sig_token != 0, // init_locals if we have locals
            )?;

            // Combine header and bytecode into complete method body
            let mut method_body = header;
            method_body.extend_from_slice(&bytecode);

            // Add exception handler data if present (must be 4-byte aligned)
            if has_exceptions && !exception_data.is_empty() {
                // Pad bytecode to 4-byte alignment
                while method_body.len() % 4 != 0 {
                    method_body.push(0);
                }
                method_body.extend_from_slice(&exception_data);
            }

            // Store the method body and get placeholder RVA
            let placeholder_rva = cil_assembly.store_method_body(method_body);

            // Update the MethodDef row's RVA
            let rid = method_token.row();
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
    fn build_context(
        &self,
        assembly: &CilObject,
        detection: DetectionResult,
    ) -> Result<AnalysisContext> {
        // Build call graph
        let call_graph = Arc::new(CallGraph::build(assembly)?);

        // Create context with engine config (important: cleanup settings!)
        let mut ctx = AnalysisContext::with_config(call_graph.clone(), self.config.clone());
        ctx.detection_result = detection;

        // Identify entry points
        Self::identify_entry_points(assembly, &ctx);

        // Build SSA for all methods
        Self::build_ssa_functions(assembly, &ctx);

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
            let visibility = cil_type.flags & TypeAttributes::VISIBILITY_MASK;
            let type_is_public =
                visibility == TypeAttributes::PUBLIC || visibility == TypeAttributes::NESTED_PUBLIC;

            // Check each method in this type
            for (_, method_ref) in cil_type.methods.iter() {
                let Some(method_token) = method_ref.token() else {
                    continue;
                };

                // Get method details from assembly
                let Some(method_entry) = assembly.methods().get(&method_token) else {
                    continue;
                };
                let method = method_entry.value();

                // Static constructors are always entry points (runtime calls them)
                if method.name == ".cctor" {
                    ctx.add_entry_point(method_token);
                    continue;
                }

                // Check method characteristics
                let is_virtual = method.flags_modifiers.contains(MethodModifiers::VIRTUAL);
                let is_abstract = method.flags_modifiers.contains(MethodModifiers::ABSTRACT);
                let is_public = method.flags_access == MethodAccessFlags::PUBLIC;
                let is_static = method.flags_modifiers.contains(MethodModifiers::STATIC);

                // Virtual/abstract methods in public types are potential entry points
                if type_is_public && is_public && (is_virtual || is_abstract) {
                    ctx.add_entry_point(method_token);
                    continue;
                }

                // Instance constructors in public types
                if method.name == ".ctor" && type_is_public && is_public {
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
    fn build_ssa_functions(assembly: &CilObject, ctx: &AnalysisContext) {
        // Collect method tokens that have CFGs
        let method_tokens: Vec<Token> = assembly
            .methods()
            .iter()
            .filter(|entry| entry.value().cfg().is_some())
            .map(|entry| *entry.key())
            .collect();

        // Build SSA in parallel
        method_tokens.par_iter().for_each(|&method_token| {
            // Get method from assembly (safe since methods is thread-safe)
            let Some(entry) = assembly.methods().get(&method_token) else {
                return;
            };
            let method = entry.value();

            if let Some(ssa) = method.ssa(assembly) {
                ctx.set_ssa(method_token, ssa);
            }
        });
    }

    /// Runs interprocedural analysis on all methods.
    ///
    /// Performs bottom-up summary computation and top-down constant propagation.
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

    /// Computes the summary for a single method.
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
        let param_count = ssa.parameter_count();
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
        for entry in ctx.call_sites.iter() {
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
            SsaInstruction, SsaOp, SsaVarId,
        },
        deobfuscation::{
            changes::EventLog, config::EngineConfig, detection::DetectionResult,
            engine::DeobfuscationEngine, result::DeobfuscationResult,
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

        // Engine should have passes in each enabled phase (built in constructor)
        assert!(!engine.structure_passes.is_empty()); // Control-flow unflattening (Phase 1)
        assert!(!engine.value_passes.is_empty()); // Decryption (Phase 2)
        assert!(!engine.simplify_passes.is_empty()); // Opaque predicates + CFG (Phase 3)
        assert!(!engine.normalize_passes.is_empty()); // DCE, constant prop, GVN, copy prop, strength reduction
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

        // Reassociation + constant propagation + GVN should be in normalize
        assert_eq!(engine.normalize_passes.len(), 3); // ReassociationPass + ConstantPropagationPass + GVN
        assert!(engine.simplify_passes.is_empty()); // No opaque pred or CFG
        assert!(engine.structure_passes.is_empty()); // No unflattening
        assert!(engine.value_passes.is_empty()); // No decryption
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
        let var = SsaVarId::new();
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
        let dest = SsaVarId::new();
        let src1 = SsaVarId::new();
        let src2 = SsaVarId::new();
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

        let obj = SsaVarId::new();
        let val = SsaVarId::new();
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

        let exc = SsaVarId::new();
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

        let dest = SsaVarId::new();
        let obj = SsaVarId::new();
        block.add_instruction(SsaInstruction::synthetic(SsaOp::LoadField {
            dest,
            object: obj,
            field: FieldRef::new(Token::new(0x04000001)),
        }));
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

        let dest = SsaVarId::new();
        block.add_instruction(SsaInstruction::synthetic(SsaOp::Call {
            dest: Some(dest),
            method: MethodRef::new(Token::new(0x06000001)),
            args: vec![],
        }));
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

        let dest = SsaVarId::new();
        let left = SsaVarId::new();
        let right = SsaVarId::new();
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
            let dest = SsaVarId::new();
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

        let value = SsaVarId::new();
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

        let value = SsaVarId::new();
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

        let var = SsaVarId::new();
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
        let result = DeobfuscationResult::new(DetectionResult::default(), EventLog::new());

        // summary() returns just the stats (no prefix)
        let summary = result.summary();
        assert!(!summary.is_empty() || summary == "No changes"); // Stats or "No changes"

        // detailed_summary() includes detection info
        let detailed = result.detailed_summary();
        assert!(detailed.contains("Deobfuscation complete"));
        assert!(detailed.contains("Detection"));
    }
}
