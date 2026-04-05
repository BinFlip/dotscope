//! Call resolution and method dispatch for the emulation engine.
//!
//! This module provides the [`CallResolver`], which encapsulates the multi-tier
//! method resolution pipeline used by the
//! [`EmulationController`](super::controller::EmulationController). It handles:
//!
//! - **Hook dispatch**: Token-cached, lock-free hook matching against the
//!   [`HookManager`] registry with O(1) fast-path for non-matching tokens
//! - **P/Invoke resolution**: Native method stub lookup for platform invoke methods
//! - **Virtual dispatch**: Runtime type-based method resolution with DashMap caching
//!   for both class inheritance and interface dispatch
//! - **Delegate dispatch**: Redirecting `Invoke` calls to the delegate's target method
//! - **MemberRef/MethodSpec resolution**: Resolving external references and generic
//!   instantiations to concrete method tokens
//! - **Frame management**: Creating and pushing call frames for entering methods
//! - **Type initialization**: Triggering `.cctor` execution before static field access
//!
//! # Token Cache
//!
//! The resolver maintains a per-token cache ([`DashMap`]) that eliminates metadata
//! lookups on repeated calls to the same method. On first encounter:
//!
//! 1. Full metadata resolution: Arc lookups, `CilTypeReference` upgrades, signature parsing
//! 2. Name-based hook matching against the `HookManager` index
//! 3. Result cached as [`TokenCacheEntry::NoMatch`] (fast reject) or
//!    [`TokenCacheEntry::Cached`] (pre-resolved identity)
//!
//! Subsequent calls skip directly to hook execution (~95% of tokens are `NoMatch`).
//!
//! # Usage
//!
//! The `CallResolver` is constructed once by the `EmulationController` and shared
//! for the lifetime of the emulation. The main execution loop calls
//! [`resolve_call`](CallResolver::resolve_call) in a redirect loop, acting on the
//! returned [`CallResolution`] variant.
//!
//! Free functions [`push_method_frame`] and [`maybe_run_type_cctor`] handle
//! frame creation and type initialization, called directly from the execution loop.

use std::sync::{Arc, RwLock};

use dashmap::DashMap;
use log::debug;

use crate::{
    emulation::{
        engine::{
            cctors::CctorTracker, context::EmulationContext, dispatch::DispatchResolver,
            error::synthetic_exception, generics::GenericRegistry, interpreter::Interpreter,
            resolution::CallResolution, typeops, EmulationError,
        },
        memory::{AddressSpace, HeapObject, TypeInitState},
        process::{EmulationConfig, UnknownMethodBehavior},
        runtime::{HookContext, HookManager, HookOutcome, RuntimeState},
        thread::{EmulationThread, MulticastState, ThreadCallFrame},
        tracer::{TraceEvent, TraceWriter},
        EmValue, SymbolicValue, TaintSource,
    },
    metadata::{
        signatures::TypeSignature,
        tables::{MemberRef, MemberRefSignature, TableId},
        token::Token,
        typesystem::{CilFlavor, CilTypeReference},
    },
    Result,
};

/// Cached result of token-to-hook resolution.
///
/// Populated lazily on the first call with each method token. Subsequent calls
/// with the same token skip all metadata resolution and name-based matching.
///
/// # Variants
///
/// - [`NoMatch`](Self::NoMatch) — No hook can match this token. The resolver
///   returns immediately without any metadata lookups or stack inspection. This
///   is the fast path for the ~95% of method calls that don't hit any hook.
///
/// - [`Cached`](Self::Cached) — A hook might (or does) match. Stores pre-resolved
///   name components and method metadata so that subsequent calls skip Phase 1
///   (metadata resolution) entirely and jump straight to context building and
///   hook execution.
enum TokenCacheEntry {
    /// No hook can match this token. Skip all name resolution and hook dispatch.
    NoMatch,

    /// Pre-resolved method identity and metadata for fast hook dispatch.
    ///
    /// On cache hit, the resolver skips the full metadata resolution (Arc lookups,
    /// `CilTypeReference` upgrades, signature parsing) and builds the `HookContext`
    /// directly from these cached values.
    Cached(ResolvedMethodInfo),
}

/// Pre-resolved method identity and metadata used for hook dispatch.
///
/// Groups the namespace, type name, method name, and calling convention
/// metadata needed to build a [`HookContext`] without re-resolving
/// metadata on every call.
#[derive(Clone)]
struct ResolvedMethodInfo {
    /// Namespace of the declaring type (e.g., `"System"`).
    namespace: Arc<str>,
    /// Name of the declaring type (e.g., `"String"`).
    type_name: Arc<str>,
    /// Name of the method (e.g., `"Concat"`).
    method_name: Arc<str>,
    /// Whether this is an internal (MethodDef) method.
    is_internal: bool,
    /// Number of declared parameters (excluding `this`).
    param_count: usize,
    /// Whether the method has a `this` parameter.
    has_this: bool,
}

/// Encapsulates method call resolution for the emulation engine.
///
/// The `CallResolver` owns the hook dispatch pipeline, virtual dispatch cache,
/// and token resolution cache. It is constructed once by the
/// [`EmulationController`](super::controller::EmulationController) and provides
/// the [`resolve_call`](Self::resolve_call) entry point for the main execution loop.
///
/// # Thread Safety
///
/// All methods take `&self` — concurrent access is safe because:
/// - [`DashMap`] provides lock-free concurrent reads/writes for the token cache
/// - [`DispatchResolver`] uses `DashMap` internally for virtual dispatch caching
/// - [`HookManager`] is immutable after construction (hooks registered during setup)
/// - [`RwLock<RuntimeState>`] provides synchronized access to runtime configuration
pub struct CallResolver {
    /// Direct reference to the hook manager for lock-free hook dispatch.
    /// Extracted from `RuntimeState` during construction. Since hooks are only
    /// registered during setup, this reference is effectively immutable.
    hooks: Arc<HookManager>,

    /// Token-to-hook resolution cache.
    ///
    /// Maps method tokens to pre-resolved metadata + match status, eliminating
    /// repeated metadata lookups and name matching for hot call sites.
    token_cache: DashMap<Token, TokenCacheEntry>,

    /// Cached virtual and interface method dispatch resolution.
    dispatch: DispatchResolver,

    /// Emulation configuration (provides pointer size, tracing settings).
    config: Arc<EmulationConfig>,

    /// Shared runtime state (for unknown method behavior configuration).
    runtime: Arc<RwLock<RuntimeState>>,

    /// Optional trace writer for hook invocation tracing.
    trace_writer: Option<Arc<TraceWriter>>,

    /// Generic type/method instantiation registry for MethodSpec resolution.
    generics: Arc<GenericRegistry>,
}

impl CallResolver {
    /// Creates a new call resolver with the given shared infrastructure.
    ///
    /// Extracts a direct `Arc<HookManager>` reference from the runtime state
    /// for lock-free hook dispatch during emulation.
    ///
    /// # Arguments
    ///
    /// * `runtime` — Shared runtime state containing the hook manager and
    ///   unknown-method behavior configuration.
    /// * `config` — Emulation configuration (pointer size, tracing settings).
    /// * `trace_writer` — Optional trace writer for hook invocation tracing.
    /// * `generics` — Generic instantiation registry for MethodSpec resolution.
    pub fn new(
        runtime: Arc<RwLock<RuntimeState>>,
        config: Arc<EmulationConfig>,
        trace_writer: Option<Arc<TraceWriter>>,
        generics: Arc<GenericRegistry>,
    ) -> Result<Self> {
        let hooks = runtime
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "runtime state",
            })?
            .hooks();
        Ok(Self {
            hooks,
            token_cache: DashMap::new(),
            dispatch: DispatchResolver::new(),
            config,
            runtime,
            trace_writer,
            generics,
        })
    }

    /// Returns a reference to the hook manager.
    ///
    /// Used by the execution loop for operations that need direct hook access
    /// (e.g., `newobj` resolution via [`typeops`](super::typeops)).
    #[must_use]
    pub fn hooks(&self) -> &HookManager {
        &self.hooks
    }

    /// Writes a trace event if tracing is enabled.
    #[inline]
    fn trace(&self, event: TraceEvent) {
        if let Some(ref writer) = self.trace_writer {
            writer.write(event);
        }
    }

    /// Checks if stub/hook tracing is enabled.
    #[inline]
    fn trace_stubs_enabled(&self) -> bool {
        self.trace_writer.is_some() && self.config.tracing.trace_stubs
    }

    /// Formats a method name from the token cache for trace output.
    ///
    /// # Arguments
    ///
    /// * `method_token` — Token of the method to format.
    ///
    /// # Returns
    ///
    /// `"Namespace.Type::Method"` if the token was previously resolved by the
    /// hook dispatch pipeline, or `"0xXXXXXXXX"` as fallback.
    #[must_use]
    pub fn format_method_name(&self, method_token: Token) -> String {
        if let Some(cached) = self.token_cache.get(&method_token) {
            if let TokenCacheEntry::Cached(info) = cached.value() {
                return if info.namespace.is_empty() {
                    format!("{}::{}", info.type_name, info.method_name)
                } else {
                    format!(
                        "{}.{}::{}",
                        info.namespace, info.type_name, info.method_name
                    )
                };
            }
        }
        format!("0x{:08X}", method_token.value())
    }

    /// Attempts to resolve a MemberRef by searching dynamically loaded assemblies.
    ///
    /// When the primary assembly references a method from an assembly loaded at
    /// runtime via `Assembly.Load(byte[])`, the MemberRef can't be resolved locally.
    /// This method searches all loaded assemblies for a type+method match and
    /// returns a [`CallResolution::EnterMethod`]-compatible redirect if found.
    ///
    /// # Returns
    ///
    /// `Some(CallResolution::Redirect)` if a matching MethodDef was found in a
    /// loaded assembly (with the appropriate `assembly_index` for frame tracking),
    /// `None` if the method couldn't be found in any loaded assembly.
    fn try_cross_assembly_resolve(
        &self,
        member_ref: &MemberRef,
        is_virtual: bool,
    ) -> Result<Option<CallResolution>> {
        let Some((namespace, type_name)) = EmulationContext::get_member_ref_type_info(member_ref)
        else {
            return Ok(None);
        };
        let method_name = &member_ref.name;
        let fullname = if namespace.is_empty() {
            type_name.clone()
        } else {
            format!("{namespace}.{type_name}")
        };

        let state = self
            .runtime
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "runtime state",
            })?;
        for i in 0..state.app_domain().parsed_assembly_count() {
            let Some(asm) = state.app_domain().get_parsed_assembly(i) else {
                continue;
            };
            let Some(cil_type) = asm.types().get_by_fullname(&fullname, true) else {
                continue;
            };
            if let Some(method) = cil_type.find_method(method_name) {
                debug!(
                    "Cross-assembly resolve: {}.{} → asm[{}] 0x{:08X}",
                    fullname,
                    method_name,
                    i,
                    method.token.value()
                );
                return Ok(Some(CallResolution::Redirect {
                    target_token: method.token,
                    arguments: vec![],
                    is_virtual,
                    pre_push_value: None,
                    is_reflection_invoke: false,
                    #[allow(clippy::cast_possible_truncation)]
                    assembly_index: Some(i as u8),
                    method_type_args: None,
                }));
            }
        }
        Ok(None)
    }

    /// Resolves a method call to a [`CallResolution`] without touching the
    /// instruction pointer or call stack.
    ///
    /// This is the main entry point for call resolution. The execution loop
    /// calls this in a redirect loop and acts on the returned variant:
    ///
    /// - [`HookedBypass`](CallResolution::HookedBypass) — Hook handled the call
    /// - [`ReturnSynthetic`](CallResolution::ReturnSynthetic) — Synthetic return value
    /// - [`EnterMethod`](CallResolution::EnterMethod) — Enter the method body
    /// - [`ThrowException`](CallResolution::ThrowException) — Throw a CLR exception
    /// - [`Redirect`](CallResolution::Redirect) — Redirect to another method token
    ///
    /// # Resolution Order
    ///
    /// 1. **Hook dispatch** — Check registered hooks via the token cache
    /// 2. **P/Invoke** — Check native stubs for unmanaged methods
    /// 3. **MethodSpec** — Resolve generic method instantiations
    /// 4. **MemberRef** — Resolve external method references
    /// 5. **Virtual dispatch** — Resolve callvirt to the runtime override
    /// 6. **Delegate dispatch** — Redirect `Invoke` to the delegate target
    /// 7. **Method body** — Enter the IL method body for emulation
    ///
    /// # Arguments
    ///
    /// * `context` — Assembly metadata context for method lookup.
    /// * `method_token` — Token of the method to resolve (MethodDef, MemberRef,
    ///   or MethodSpec).
    /// * `thread` — The emulation thread (for stack inspection, args, and heap).
    /// * `is_virtual` — `true` for `callvirt` instructions (enables virtual dispatch).
    /// * `constrained_type` — When set, the `constrained.` prefix type token.
    ///
    /// # Returns
    ///
    /// A [`CallResolution`] variant instructing the execution loop what to do next.
    ///
    /// # Errors
    ///
    /// Returns an error if method metadata lookup fails or the hook throws
    /// an unrecoverable error.
    pub fn resolve_call(
        &self,
        context: &EmulationContext,
        method_token: Token,
        thread: &mut EmulationThread,
        is_virtual: bool,
        constrained_type: Option<Token>,
        address_space: &AddressSpace,
    ) -> Result<CallResolution> {
        // First, try to resolve via hooks (highest priority)
        match self.try_hook_call(context, method_token, thread)? {
            HookOutcome::ReflectionInvoke {
                request,
                bypass_value,
            } => {
                if self.trace_stubs_enabled() {
                    let name = self.format_method_name(method_token);
                    self.trace(TraceEvent::HookInvoke {
                        method: method_token,
                        hook_name: format!("{name} [reflection-invoke]"),
                        bypassed: false,
                        return_value: None,
                    });
                }

                let request = *request;
                let target_token = request.method_token;

                if target_token.is_table(TableId::MethodDef) {
                    // For ConstructorInfo.Invoke: the hook's return value IS the result
                    // (the newly allocated object). Push it before entering the constructor
                    // so it's preserved in the caller's saved stack.
                    //
                    // For MethodBase.Invoke (non-constructor): the method's return value
                    // is pushed by the callee naturally — no pre-push needed, UNLESS the
                    // target is void. MethodBase.Invoke always returns Object, so void
                    // targets need a Null pre-push to satisfy the caller's stack.
                    let is_ctor_invoke = context
                        .get_method(target_token)
                        .map(|m| m.name == ".ctor")
                        .unwrap_or(false);
                    let target_returns_value =
                        context.method_returns_value(target_token).unwrap_or(false);
                    let pre_push = if is_ctor_invoke {
                        bypass_value.clone()
                    } else if !target_returns_value {
                        // Void method: Invoke returns null
                        Some(EmValue::Null)
                    } else {
                        None
                    };

                    // Build arguments for the reflected method.
                    // For instance methods, always include this_ref (even null) as arg[0]
                    // — real .NET passes null `this` and the NullRef happens when the
                    // method body dereferences it, not at call setup. For static methods,
                    // skip the this_ref entirely (it's always null for statics).
                    let is_static = context.is_static_method(target_token).unwrap_or(true);
                    let mut args = Vec::new();
                    if let Some(this_val) = request.this_ref {
                        if !is_static {
                            args.push(this_val);
                        }
                    }
                    args.extend(request.args);

                    return Ok(CallResolution::Redirect {
                        target_token,
                        arguments: args,
                        is_virtual: false,
                        pre_push_value: pre_push,
                        is_reflection_invoke: true,
                        assembly_index: None,
                        method_type_args: request.method_type_args,
                    });
                }

                // Target is not a MethodDef — can't invoke via reflection.
                // Push the placeholder return value so the caller's stack is correct.
                return Ok(CallResolution::HookedBypass {
                    return_value: bypass_value,
                });
            }
            HookOutcome::Handled(value) => {
                if self.trace_stubs_enabled() {
                    let name = self.format_method_name(method_token);
                    self.trace(TraceEvent::HookInvoke {
                        method: method_token,
                        hook_name: name,
                        bypassed: true,
                        return_value: value.as_ref().map(|v| format!("{v}")),
                    });
                }
                if let Some(EmValue::Symbolic(ref sym)) = value {
                    debug!(
                        "Hook for 0x{:08X} returned Symbolic({:?}, source={:?})",
                        method_token.value(),
                        sym.cil_flavor,
                        sym.source,
                    );
                }
                return Ok(CallResolution::HookedBypass {
                    return_value: value,
                });
            }
            HookOutcome::ThrewException {
                exception_type,
                message,
            } => {
                return Ok(CallResolution::ThrowException {
                    exception_type,
                    message,
                });
            }
            HookOutcome::NoMatch => { /* continue to next resolution step */ }
        }

        // Then try native stubs for P/Invoke methods
        if let Some(result) = self.try_native_call(context, method_token, thread)? {
            if self.trace_stubs_enabled() {
                self.trace(TraceEvent::HookInvoke {
                    method: method_token,
                    hook_name: format!("{} [native]", self.format_method_name(method_token)),
                    bypassed: true,
                    return_value: result.as_ref().map(|v| format!("{v}")),
                });
            }
            return Ok(CallResolution::HookedBypass {
                return_value: result,
            });
        }

        // Handle synthetic methods (from DynamicMethod/ILGenerator)
        if context.is_synthetic_method(method_token) {
            let is_static = context.is_static_method(method_token)?;
            let param_types = context.get_parameter_types(method_token)?;
            let total_args = if is_static {
                param_types.len()
            } else {
                param_types.len() + 1
            };
            let arg_values = thread.pop_args(total_args)?;
            let expects_return = context.method_returns_value(method_token)?;
            return Ok(CallResolution::EnterMethod {
                token: method_token,
                arguments: arg_values,
                expects_return,
                assembly_index: None,
                method_type_args: None,
            });
        }

        // Handle MethodSpec tokens (generic method instantiations)
        if method_token.is_table(TableId::MethodSpec) {
            if let Some(method_spec) = context.get_method_spec(method_token) {
                if let Some(underlying_token) =
                    EmulationContext::resolve_method_spec_to_token(&method_spec)
                {
                    // Extract generic type arguments from the MethodSpec signature.
                    // These are the concrete types for !!0, !!1, etc.
                    let type_args: Vec<Token> = method_spec
                        .instantiation
                        .generic_args
                        .iter()
                        .filter_map(|sig| {
                            // Resolve from current frame's generic context
                            let frame_type_args = thread
                                .current_frame()
                                .and_then(|f| f.type_type_args().map(|a| a.to_vec()));
                            let frame_method_args = thread
                                .current_frame()
                                .and_then(|f| f.method_type_args().map(|a| a.to_vec()));
                            context.type_signature_to_token(
                                sig,
                                frame_type_args.as_deref(),
                                frame_method_args.as_deref(),
                                &self.generics,
                            )
                        })
                        .collect();

                    let method_type_args = if type_args.is_empty() {
                        None
                    } else {
                        Some(type_args)
                    };

                    return Ok(CallResolution::Redirect {
                        target_token: underlying_token,
                        arguments: vec![],
                        is_virtual,
                        is_reflection_invoke: false,
                        pre_push_value: None,
                        assembly_index: None,
                        method_type_args,
                    });
                }
            }

            return Err(EmulationError::MethodNotFound {
                token: method_token,
            }
            .into());
        }

        // Handle MemberRef tokens (external methods) without stubs
        if method_token.is_table(TableId::MemberRef) {
            // Try resolving MemberRef → local MethodDef before returning Symbolic
            if let Some(resolved) = context.assembly().resolver().resolve_method(method_token) {
                if resolved.is_table(TableId::MethodDef) {
                    return Ok(CallResolution::Redirect {
                        target_token: resolved,
                        arguments: vec![],
                        is_virtual,
                        pre_push_value: None,
                        is_reflection_invoke: false,
                        assembly_index: None,
                        method_type_args: None,
                    });
                }
            }

            // Try cross-assembly resolution: the MemberRef may reference a method
            // in a dynamically loaded assembly (via Assembly.Load). Search loaded
            // assemblies by declaring type + method name.
            if let Some(member_ref) = context.get_member_ref(method_token) {
                if let Some(resolution) =
                    self.try_cross_assembly_resolve(&member_ref, is_virtual)?
                {
                    return Ok(resolution);
                }
            }

            if let Some(member_ref) = context.get_member_ref(method_token) {
                if let MemberRefSignature::Method(method_sig) = &member_ref.signature {
                    let total_args = if method_sig.has_this {
                        method_sig.param_count as usize + 1
                    } else {
                        method_sig.param_count as usize
                    };

                    // Virtual dispatch hook retry: when a `callvirt` targets a base class
                    // MemberRef (e.g., TextReader.ReadToEnd) but the runtime object is a
                    // derived type (e.g., StreamReader), the initial hook lookup fails
                    // because hooks are registered under the derived type name. Retry the
                    // hook lookup using the runtime type of `this`.
                    if is_virtual && method_sig.has_this && total_args > 0 {
                        let args = thread.peek_args(total_args)?;
                        let this_arg = &args[0];

                        if let EmValue::ObjectRef(heap_ref) = this_arg {
                            if let Ok(runtime_type_token) = thread.heap().get_type_token(*heap_ref)
                            {
                                if let Some(runtime_type) = context.get_type(runtime_type_token) {
                                    let rt_namespace = if runtime_type.namespace.is_empty() {
                                        runtime_type
                                            .enclosing_type()
                                            .map(|enc| enc.namespace.clone())
                                            .filter(|ns| !ns.is_empty())
                                            .unwrap_or_default()
                                    } else {
                                        runtime_type.namespace.clone()
                                    };
                                    let rt_type_name = &runtime_type.name;

                                    // Only retry if the runtime type differs from the declared type
                                    let declared_type_info =
                                        EmulationContext::get_member_ref_type_info(&member_ref);
                                    let types_differ =
                                        !declared_type_info.as_ref().is_some_and(|(dns, dtn)| {
                                            dns == &rt_namespace && dtn == rt_type_name.as_str()
                                        });

                                    if types_differ {
                                        let param_types =
                                            context.get_parameter_types(method_token).ok();
                                        let param_types_ref: Option<&[CilFlavor]> =
                                            param_types.as_deref();
                                        let return_type =
                                            context.get_return_type(method_token).ok().flatten();

                                        let (this_ref, method_args): (
                                            Option<&EmValue>,
                                            &[EmValue],
                                        ) = (Some(&args[0]), &args[1..]);

                                        let hook_context = HookContext::new(
                                            method_token,
                                            &rt_namespace,
                                            rt_type_name,
                                            &member_ref.name,
                                            self.config.pointer_size,
                                        )
                                        .with_this(this_ref)
                                        .with_args(method_args)
                                        .with_param_types(param_types_ref)
                                        .with_return_type(return_type);

                                        let outcome =
                                            self.hooks.execute(&hook_context, thread, |_| None)?;

                                        match outcome {
                                            HookOutcome::Handled(value) => {
                                                // Hook matched — pop the arguments
                                                thread.pop_args(total_args)?;
                                                if self.trace_stubs_enabled() {
                                                    self.trace(TraceEvent::HookInvoke {
                                                        method: method_token,
                                                        hook_name: format!(
                                                            "{}.{}.{} [virtual dispatch]",
                                                            rt_namespace,
                                                            rt_type_name,
                                                            member_ref.name
                                                        ),
                                                        bypassed: true,
                                                        return_value: value
                                                            .as_ref()
                                                            .map(|v| format!("{v}")),
                                                    });
                                                }
                                                return Ok(CallResolution::HookedBypass {
                                                    return_value: value,
                                                });
                                            }
                                            HookOutcome::ThrewException {
                                                exception_type,
                                                message,
                                            } => {
                                                thread.pop_args(total_args)?;
                                                return Ok(CallResolution::ThrowException {
                                                    exception_type,
                                                    message,
                                                });
                                            }
                                            HookOutcome::ReflectionInvoke { .. } => {
                                                // Unlikely for virtual dispatch, but handle
                                                thread.pop_args(total_args)?;
                                                return Ok(CallResolution::HookedBypass {
                                                    return_value: None,
                                                });
                                            }
                                            HookOutcome::NoMatch => {
                                                // Still no match — fall through to Symbolic
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // Pop arguments from stack
                    for _ in 0..total_args {
                        thread.pop()?;
                    }

                    // Get declaring type info for better diagnostics
                    let type_info = EmulationContext::get_member_ref_type_info(&member_ref);
                    let type_desc = type_info
                        .as_ref()
                        .map(|(ns, tn)| format!("{ns}.{tn}"))
                        .unwrap_or_else(|| "Unknown".to_string());

                    // Return symbolic value if the method has a return type
                    let value = if !matches!(method_sig.return_type.base, TypeSignature::Void) {
                        let return_type = CilFlavor::from(&method_sig.return_type.base);
                        debug!(
                            "Unhooked MemberRef 0x{:08X} '{}.{}' → returning Symbolic({:?})",
                            method_token.value(),
                            type_desc,
                            member_ref.name,
                            return_type
                        );
                        Some(EmValue::Symbolic(SymbolicValue::new(
                            return_type,
                            TaintSource::MethodReturn(method_token.value()),
                        )))
                    } else {
                        debug!(
                            "Unhooked MemberRef 0x{:08X} '{}.{}' → void (no return)",
                            method_token.value(),
                            type_desc,
                            member_ref.name,
                        );
                        None
                    };

                    if self.trace_stubs_enabled() {
                        self.trace(TraceEvent::HookInvoke {
                            method: method_token,
                            hook_name: format!("{}.{} [synthetic]", type_desc, member_ref.name),
                            bypassed: true,
                            return_value: value.as_ref().map(|v| format!("{v}")),
                        });
                    }
                    return Ok(CallResolution::ReturnSynthetic { value });
                }
            }

            return Err(EmulationError::MethodNotFound {
                token: method_token,
            }
            .into());
        }

        // Get method signature for internal method
        let method = context.get_method(method_token)?;

        let param_count = method.signature.params.len();
        let is_instance = !context.is_static_method(method_token)?;
        let total_args = if is_instance {
            param_count + 1
        } else {
            param_count
        };

        // Pop arguments from stack (in correct order)
        let mut arg_values = thread.pop_args(total_args)?;

        // Resolve virtual dispatch if this is a callvirt instruction
        let resolved_method_token = if is_virtual && is_instance && !arg_values.is_empty() {
            if let Some(constraint_token) = constrained_type {
                // constrained. callvirt: resolve against the constraint type, not runtime type.
                // For value types that override (e.g., Int32.ToString()), this finds the override.
                // For reference types or value types without an override, falls back to the
                // declared method (normal virtual dispatch will apply).
                let resolved = context.resolve_virtual_call(method_token, constraint_token);

                // ECMA-335 III.2.1: If the constraint type is a value type and it does NOT
                // override the method, box the value type and use the boxed ref as 'this'.
                if resolved == method_token && context.is_value_type(constraint_token) {
                    if let EmValue::ManagedPtr(ptr) = &arg_values[0] {
                        if let Ok(value) = typeops::deref_managed_ptr(address_space, thread, ptr) {
                            let boxed = thread.heap_mut().alloc_boxed(constraint_token, value)?;
                            arg_values[0] = EmValue::ObjectRef(boxed);
                        }
                    }
                }
                resolved
            } else {
                self.resolve_virtual_dispatch(context, thread, method_token, &arg_values[0])
            }
        } else {
            method_token
        };

        // Re-fetch method if we resolved to a different one
        let method = if resolved_method_token == method_token {
            method
        } else {
            context.get_method(resolved_method_token)?
        };

        // Check if this is a native method (x86 code, not IL)
        if method.is_code_native() && method.is_code_unmanaged() {
            return Err(EmulationError::InternalError {
                description: format!(
                    "Cannot emulate native x86 method 0x{:08x} '{}'. \
                     Native methods must be converted to CIL during deobfuscation.",
                    resolved_method_token.value(),
                    method.name
                ),
            }
            .into());
        }

        // Delegate dispatch: if this is a `runtime managed` method named "Invoke"
        // on a delegate object, redirect to the delegate's target method.
        if method.is_code_runtime()
            && method.name == "Invoke"
            && is_instance
            && !arg_values.is_empty()
        {
            if let EmValue::ObjectRef(href) = &arg_values[0] {
                match thread.heap().get(*href) {
                    Ok(HeapObject::Delegate {
                        invocation_list, ..
                    }) => {
                        // For multicast delegates, invoke entries in order (first to last).
                        // Only the last entry's return value is propagated to the caller.
                        if let Some(entry) = invocation_list.first() {
                            let target_token = entry.method_token;
                            let delegate_target = entry.target;

                            // Resolve MemberRef → MethodDef if the target is local
                            let mut dispatch_token = if target_token.is_table(TableId::MemberRef) {
                                context
                                    .assembly()
                                    .resolver()
                                    .resolve_method(target_token)
                                    .filter(|t| t.is_table(TableId::MethodDef))
                                    .unwrap_or(target_token)
                            } else {
                                target_token
                            };

                            let should_dispatch = if context.is_synthetic_method(dispatch_token) {
                                // Synthetic methods from DynamicMethod/ILGenerator
                                // are always dispatchable.
                                true
                            } else if dispatch_token.is_table(TableId::MethodDef) {
                                let has_il = context
                                    .get_method(dispatch_token)
                                    .map(|m| m.has_body() && m.instructions().next().is_some())
                                    .unwrap_or(false);
                                if has_il {
                                    true
                                } else {
                                    let is_virtual = context
                                        .get_method(dispatch_token)
                                        .map(|m| m.is_virtual())
                                        .unwrap_or(false);

                                    if is_virtual {
                                        let instance_ref = delegate_target.or_else(|| {
                                            arg_values.get(1).and_then(|v| match v {
                                                EmValue::ObjectRef(r) => Some(*r),
                                                _ => None,
                                            })
                                        });

                                        if let Some(inst_ref) = instance_ref {
                                            let resolved = self.resolve_virtual_dispatch(
                                                context,
                                                thread,
                                                dispatch_token,
                                                &EmValue::ObjectRef(inst_ref),
                                            );
                                            if resolved != dispatch_token {
                                                let resolved_has_il = context
                                                    .get_method(resolved)
                                                    .map(|m| {
                                                        m.has_body()
                                                            && m.instructions().next().is_some()
                                                    })
                                                    .unwrap_or(false);
                                                if resolved_has_il {
                                                    dispatch_token = resolved;
                                                    true
                                                } else {
                                                    false
                                                }
                                            } else {
                                                false
                                            }
                                        } else {
                                            false
                                        }
                                    } else {
                                        false
                                    }
                                }
                            } else {
                                false
                            };

                            if should_dispatch {
                                let delegate_args: Vec<EmValue> = arg_values[1..].to_vec();

                                // Set up multicast state if there are more entries
                                if invocation_list.len() > 1 {
                                    thread.set_multicast_state(MulticastState {
                                        remaining_entries: invocation_list[1..].to_vec(),
                                        delegate_args: delegate_args.clone(),
                                        dispatch_depth: thread.call_depth(),
                                    });
                                }

                                return Ok(CallResolution::Redirect {
                                    target_token: dispatch_token,
                                    arguments: delegate_args,
                                    is_virtual: false,
                                    pre_push_value: None,
                                    is_reflection_invoke: false,
                                    assembly_index: None,
                                    method_type_args: None,
                                });
                            }

                            if target_token.is_table(TableId::MemberRef) {
                                let delegate_args: Vec<EmValue> = arg_values[1..].to_vec();

                                // Set up multicast state if there are more entries
                                if invocation_list.len() > 1 {
                                    thread.set_multicast_state(MulticastState {
                                        remaining_entries: invocation_list[1..].to_vec(),
                                        delegate_args: delegate_args.clone(),
                                        dispatch_depth: thread.call_depth(),
                                    });
                                }

                                return Ok(CallResolution::Redirect {
                                    target_token,
                                    arguments: delegate_args,
                                    is_virtual: false,
                                    pre_push_value: None,
                                    is_reflection_invoke: false,
                                    assembly_index: None,
                                    method_type_args: None,
                                });
                            }

                            debug!(
                                "delegate dispatch failed: target 0x{:08X} has no concrete implementation",
                                target_token.value()
                            );
                            return Ok(CallResolution::ThrowException {
                                exception_type: synthetic_exception::INVALID_OPERATION,
                                message: format!(
                                    "delegate target 0x{:08X} has no concrete implementation",
                                    target_token.value()
                                ),
                            });
                        }
                    }
                    Ok(other) => {
                        debug!(
                            "Delegate Invoke on {:?}: this is {:?}, not a Delegate — dispatch skipped",
                            resolved_method_token,
                            std::mem::discriminant(&other),
                        );
                    }
                    Err(_) => {
                        debug!(
                            "Delegate Invoke on {:?}: heap lookup failed for {:?}",
                            resolved_method_token, href,
                        );
                    }
                }
            } else {
                debug!(
                    "Delegate Invoke on {:?}: this is {:?}, not an ObjectRef",
                    resolved_method_token, arg_values[0],
                );
            }
        }

        // Check if we should emulate or return symbolic
        let has_instructions = method.instructions().next().is_some();
        let default_behavior = self
            .runtime
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "runtime lock poisoned",
            })?
            .unknown_method_behavior();
        match default_behavior {
            UnknownMethodBehavior::Emulate => {
                if method.has_body() && has_instructions {
                    let expects_return = context.method_returns_value(resolved_method_token)?;
                    return Ok(CallResolution::EnterMethod {
                        token: resolved_method_token,
                        arguments: arg_values,
                        expects_return,
                        assembly_index: None,
                        method_type_args: None,
                    });
                }
                // No body - likely a P/Invoke, return symbolic
                let return_flavor = context
                    .get_return_type(resolved_method_token)?
                    .unwrap_or(CilFlavor::Object);
                Ok(CallResolution::ReturnSynthetic {
                    value: Some(EmValue::Symbolic(SymbolicValue::new(
                        return_flavor,
                        TaintSource::MethodReturn(resolved_method_token.value()),
                    ))),
                })
            }

            UnknownMethodBehavior::Symbolic => {
                let return_flavor = context
                    .get_return_type(resolved_method_token)?
                    .unwrap_or(CilFlavor::Object);
                Ok(CallResolution::ReturnSynthetic {
                    value: Some(EmValue::Symbolic(SymbolicValue::new(
                        return_flavor,
                        TaintSource::MethodReturn(resolved_method_token.value()),
                    ))),
                })
            }

            UnknownMethodBehavior::Fail => Err(EmulationError::UnsupportedMethod {
                token: resolved_method_token,
                reason: "No hook registered and Fail behavior configured",
            }
            .into()),

            UnknownMethodBehavior::Default => {
                let return_flavor = context.get_return_type(resolved_method_token)?;
                let value = return_flavor.and_then(|flavor| match flavor {
                    CilFlavor::Void => None,
                    CilFlavor::Boolean
                    | CilFlavor::I1
                    | CilFlavor::U1
                    | CilFlavor::I2
                    | CilFlavor::U2
                    | CilFlavor::I4
                    | CilFlavor::U4
                    | CilFlavor::Char => Some(EmValue::I32(0)),
                    CilFlavor::I8 | CilFlavor::U8 => Some(EmValue::I64(0)),
                    CilFlavor::R4 => Some(EmValue::F32(0.0)),
                    CilFlavor::R8 => Some(EmValue::F64(0.0)),
                    CilFlavor::I | CilFlavor::U => Some(EmValue::NativeInt(0)),
                    _ => Some(EmValue::Null),
                });
                Ok(CallResolution::ReturnSynthetic { value })
            }

            UnknownMethodBehavior::Skip => Ok(CallResolution::ReturnSynthetic { value: None }),
        }
    }

    /// Resolves virtual dispatch to find the actual method to call.
    ///
    /// For virtual method calls (`callvirt`), this resolves the declared method
    /// to the actual implementation based on the runtime type of the `this`
    /// object. Uses the [`DispatchResolver`] cache for O(1) repeated lookups.
    ///
    /// # Arguments
    ///
    /// * `context` — Assembly metadata context for type/method lookup.
    /// * `thread` — The emulation thread (for heap access to get runtime type).
    /// * `declared_method` — Token of the method as declared in the instruction.
    /// * `this_arg` — The `this` object value (must be `ObjectRef` for virtual
    ///   dispatch to take effect).
    ///
    /// # Returns
    ///
    /// The resolved method token. If virtual dispatch cannot be performed
    /// (e.g., `this` is null, type unknown, method not overridden), returns
    /// `declared_method` unchanged.
    pub fn resolve_virtual_dispatch(
        &self,
        context: &EmulationContext,
        thread: &EmulationThread,
        declared_method: Token,
        this_arg: &EmValue,
    ) -> Token {
        // Get the runtime type of the 'this' object
        let runtime_type = match this_arg {
            EmValue::ObjectRef(heap_ref) => {
                match thread.heap().get_type_token(*heap_ref) {
                    Ok(token) => token,
                    Err(_) => return declared_method, // Can't get type, use declared
                }
            }
            _ => return declared_method, // Null or other non-object type
        };

        // Use the cached dispatch resolver (handles both class virtual and interface dispatch)
        self.dispatch
            .resolve(declared_method, runtime_type, context)
    }

    /// Tries to execute a method call via a hook.
    ///
    /// Hooks provide flexible method interception with matching criteria and
    /// bypass capabilities. This method creates a [`HookContext`] and checks
    /// registered hooks in priority order.
    ///
    /// Uses a multi-phase resolution strategy:
    /// 1. **Cache hit** — Token already resolved, skip metadata lookups
    /// 2. **Metadata resolution** — Extract method identity from `MethodDef`/`MemberRef`
    /// 3. **Fast reject** — O(1) hash lookup against the hook registry index
    /// 4. **Context build + execute** — Build `HookContext` and run matching hooks
    ///
    /// # Returns
    ///
    /// - [`HookOutcome::Handled`] — Hook matched and returned a value
    /// - [`HookOutcome::ReflectionInvoke`] — Hook resolved a reflection redirect
    /// - [`HookOutcome::ThrewException`] — Hook threw a CLR exception
    /// - [`HookOutcome::NoMatch`] — No matching hook found
    fn try_hook_call(
        &self,
        context: &EmulationContext,
        method_token: Token,
        thread: &mut EmulationThread,
    ) -> Result<HookOutcome> {
        // Fast path: check token cache for previously resolved tokens.
        // This eliminates all metadata lookups and name matching for tokens
        // we've already seen.
        if let Some(cached) = self.token_cache.get(&method_token) {
            return match cached.value() {
                TokenCacheEntry::NoMatch => Ok(HookOutcome::NoMatch),
                TokenCacheEntry::Cached(info) => {
                    // Drop the DashMap guard before doing any mutable thread work
                    let info = info.clone();
                    drop(cached);

                    self.execute_hook_with_resolved(context, method_token, thread, &info)
                }
            };
        }

        // Cache miss: full metadata resolution path.
        // Phase 1: Extract lightweight method identity.
        // Keep Arc handles alive at function scope so we can borrow &str from them
        // without any String cloning.
        let member_ref_arc;
        let method_arc;
        let declaring_type_arc;
        let is_internal: bool;
        let param_count: usize;
        let has_this: bool;

        if method_token.is_table(TableId::MemberRef) {
            // MemberRef (external method)
            let Some(mr) = context.get_member_ref(method_token) else {
                self.token_cache
                    .insert(method_token, TokenCacheEntry::NoMatch);
                return Ok(HookOutcome::NoMatch);
            };

            // Upgrade the declaring type weak reference to get namespace/type (O(1))
            declaring_type_arc = match &mr.declaredby {
                CilTypeReference::TypeRef(r)
                | CilTypeReference::TypeDef(r)
                | CilTypeReference::TypeSpec(r) => r.upgrade(),
                _ => None,
            };

            let (count, ht) = match &mr.signature {
                MemberRefSignature::Method(sig) => (sig.param_count as usize, sig.has_this),
                MemberRefSignature::Field(_) => {
                    self.token_cache
                        .insert(method_token, TokenCacheEntry::NoMatch);
                    return Ok(HookOutcome::NoMatch);
                }
            };

            member_ref_arc = Some(mr);
            method_arc = None;
            is_internal = false;
            param_count = count;
            has_this = ht;
        } else {
            // MethodDef (internal method)
            let Ok(method) = context.get_method(method_token) else {
                self.token_cache
                    .insert(method_token, TokenCacheEntry::NoMatch);
                return Ok(HookOutcome::NoMatch);
            };

            declaring_type_arc = method.declaring_type_rc();
            let ht = !method.is_static();
            let pc = method.signature.params.len();

            method_arc = Some(method);
            member_ref_arc = None;
            is_internal = true;
            param_count = pc;
            has_this = ht;
        }

        // Borrow &str from the Arc handles — zero allocation
        let raw_namespace = declaring_type_arc
            .as_ref()
            .map_or("", |dt| dt.namespace.as_str());
        let type_name = declaring_type_arc
            .as_ref()
            .map_or("", |dt| dt.name.as_str());

        // Resolve namespace from enclosing type for nested types.
        // In .NET, nested types have empty namespace in metadata but inherit their
        // enclosing type's namespace (e.g., List`1/Enumerator → "System.Collections.Generic").
        let enclosing_ns: Option<String>;
        let namespace = if raw_namespace.is_empty() {
            enclosing_ns = declaring_type_arc
                .as_ref()
                .and_then(|dt| {
                    // First try: direct enclosing_type on the CilType.
                    let enc = dt.enclosing_type()?;
                    if enc.namespace.is_empty() {
                        None
                    } else {
                        Some(enc.namespace.clone())
                    }
                })
                .or_else(|| {
                    // Fallback for TypeSpec generic instantiations of nested types:
                    // Parse the TypeSpec blob to find the underlying TypeRef/TypeDef
                    // and check its enclosing type.
                    let dt = declaring_type_arc.as_ref()?;
                    if !dt.token.is_table(TableId::TypeSpec) {
                        return None;
                    }
                    let sig = context.get_typespec_signature(dt.token)?;
                    let base_token = match &sig.base {
                        TypeSignature::GenericInst(base_sig, _) => match base_sig.as_ref() {
                            TypeSignature::Class(t) | TypeSignature::ValueType(t) => Some(*t),
                            _ => None,
                        },
                        _ => None,
                    }?;
                    let base_type = context.get_type(base_token)?;
                    let enc = base_type.enclosing_type()?;
                    if enc.namespace.is_empty() {
                        None
                    } else {
                        Some(enc.namespace.clone())
                    }
                });
            enclosing_ns.as_deref().unwrap_or("")
        } else {
            raw_namespace
        };

        let method_name = if let Some(mr) = &member_ref_arc {
            mr.name.as_str()
        } else if let Some(m) = &method_arc {
            m.name.as_str()
        } else {
            self.token_cache
                .insert(method_token, TokenCacheEntry::NoMatch);
            return Ok(HookOutcome::NoMatch);
        };

        // Phase 2: Fast reject — O(1) hash lookup, zero allocation.
        // Also populates the token cache so future calls with the same token
        // skip all metadata resolution entirely.
        if !self
            .hooks
            .has_potential_match(namespace, type_name, method_name)?
        {
            self.token_cache
                .insert(method_token, TokenCacheEntry::NoMatch);
            return Ok(HookOutcome::NoMatch);
        }

        // Cache this token as a potential match for future calls.
        let info = ResolvedMethodInfo {
            namespace: Arc::from(namespace),
            type_name: Arc::from(type_name),
            method_name: Arc::from(method_name),
            is_internal,
            param_count,
            has_this,
        };
        self.token_cache
            .insert(method_token, TokenCacheEntry::Cached(info.clone()));

        // Phase 3+4: Build context and execute hook.
        self.execute_hook_with_resolved(context, method_token, thread, &info)
    }

    /// Tries to execute a method call via a native (P/Invoke) stub.
    ///
    /// For `MethodDef` tokens that have no IL body (P/Invoke methods), looks up
    /// the real import name from the assembly's import table and tries matching
    /// native hooks.
    ///
    /// # Returns
    ///
    /// - `Ok(Some(Some(value)))` — Stub matched and returned a value
    /// - `Ok(Some(None))` — Stub matched and returned void
    /// - `Ok(None)` — No matching stub found
    #[allow(clippy::option_option)] // None = no hook, Some(None) = void return, Some(Some) = value
    fn try_native_call(
        &self,
        context: &EmulationContext,
        method_token: Token,
        thread: &mut EmulationThread,
    ) -> Result<Option<Option<EmValue>>> {
        // Only MethodDef tokens can be P/Invoke - MemberRefs are handled via hooks
        if method_token.table() != 0x06 {
            return Ok(None);
        }

        // Get method info
        let Ok(method) = context.get_method(method_token) else {
            return Ok(None);
        };

        // Check if this is a P/Invoke (no method body)
        if method.has_body() {
            return Ok(None);
        }

        // For P/Invoke methods, look up the real import name from CilImports
        // This handles obfuscated method names where the actual import name differs
        let (function_name, dll_name): (String, Option<String>) =
            if let Some(import) = context.find_import_by_method(method_token) {
                let dll = context.get_import_dll_name(&import);
                (import.name.clone(), dll)
            } else {
                (method.name.clone(), None)
            };

        // Try native hooks for P/Invoke
        if let Some(dll) = &dll_name {
            // Get argument count - P/Invoke methods are always static
            let param_count = method.signature.params.len();

            // Pop arguments from stack
            let args = thread.pop_args(param_count)?;

            // Create native hook context
            let hook_context =
                HookContext::native(method_token, dll, &function_name, self.config.pointer_size)
                    .with_args(&args);

            // P/Invoke calls are always bypassed - no "original" to execute (lock-free)
            match self.hooks.execute(&hook_context, thread, |_| None)? {
                HookOutcome::NoMatch => {
                    // No hook found - push args back and return None
                    // (caller will decide how to handle unhandled P/Invoke)
                    for arg in args.into_iter().rev() {
                        thread.push(arg)?;
                    }
                    return Ok(None);
                }
                HookOutcome::Handled(result)
                | HookOutcome::ReflectionInvoke {
                    bypass_value: result,
                    ..
                } => {
                    return Ok(Some(result));
                }
                HookOutcome::ThrewException { message, .. } => {
                    return Err(EmulationError::HookError(format!(
                        "P/Invoke hook threw CLR exception: {message}"
                    ))
                    .into());
                }
            }
        }

        Ok(None)
    }

    /// Builds a [`HookContext`] from pre-resolved method identity and executes
    /// the hook pipeline.
    ///
    /// This is the shared execution path used by both the cache-hit and cache-miss
    /// branches of [`try_hook_call`](Self::try_hook_call). All metadata resolution
    /// has already been done; this method only handles argument peeking, context
    /// building, and hook dispatch.
    fn execute_hook_with_resolved(
        &self,
        context: &EmulationContext,
        method_token: Token,
        thread: &mut EmulationThread,
        info: &ResolvedMethodInfo,
    ) -> Result<HookOutcome> {
        let total_args = if info.has_this {
            info.param_count + 1
        } else {
            info.param_count
        };

        // Peek at arguments without popping (we may not match a hook)
        let args = thread.peek_args(total_args)?;

        // Get parameter types if available
        let param_types = context.get_parameter_types(method_token).ok();
        let param_types_ref: Option<&[CilFlavor]> = param_types.as_deref();

        // Get return type
        let return_type = context.get_return_type(method_token).ok().flatten();

        // Split into this and method args
        let (this_ref, method_args): (Option<&EmValue>, &[EmValue]) =
            if info.has_this && !args.is_empty() {
                (Some(&args[0]), &args[1..])
            } else {
                (None, &args[..])
            };

        let hook_context = HookContext::new(
            method_token,
            &info.namespace,
            &info.type_name,
            &info.method_name,
            self.config.pointer_size,
        )
        .with_this(this_ref)
        .with_args(method_args)
        .with_internal(info.is_internal)
        .with_param_types(param_types_ref)
        .with_return_type(return_type);

        // Execute matching hook (lock-free via direct Arc<HookManager>)
        let outcome = self.hooks.execute(&hook_context, thread, |_| {
            // Original method execution callback - for now, we don't execute
            // the original here since the controller handles stubs/internal
            // methods separately. Post-hooks that depend on the original
            // result won't work in this mode.
            None
        })?;

        match &outcome {
            HookOutcome::NoMatch => {}
            _ => {
                // Hook matched — pop the arguments from the stack
                thread.pop_args(total_args)?;
            }
        }

        Ok(outcome)
    }
}

/// Pushes a new call frame for a resolved method.
///
/// Saves the caller's evaluation stack, creates the callee's frame with local
/// variable slots and typed arguments, and updates the interpreter to point at
/// the callee's entry point (offset 0).
///
/// This is a shared helper used by the `Call`, `CallIndirect`, and `NewObj`
/// paths in the main execution loop.
///
/// # Arguments
///
/// * `interpreter` - The CIL interpreter (updated to the callee's method/offset)
/// * `thread` - The emulation thread (stack saved, new frame pushed)
/// * `context` - The emulation context for method metadata
/// * `token` - Method token of the callee
/// * `arguments` - Arguments to pass to the callee
/// * `expects_return` - Whether the caller expects a return value
///
/// # Errors
///
/// Returns an error if the method's local variable types or parameter types
/// cannot be resolved from metadata.
pub fn push_method_frame(
    interpreter: &mut Interpreter,
    thread: &mut EmulationThread,
    context: &EmulationContext,
    token: Token,
    arguments: Vec<EmValue>,
    expects_return: bool,
) -> Result<()> {
    // Get return info from current frame
    let return_method = thread.current_frame().map(ThreadCallFrame::method);
    let return_offset = interpreter.ip().next_offset();

    // Save caller's evaluation stack before entering new method
    let caller_stack = thread.take_stack();

    // Get local types for the callee
    let local_cil_flavors = context.get_local_types(token)?;

    // Get argument types
    let callee_is_instance = !context.is_static_method(token)?;
    let param_types = context.get_parameter_types(token)?;
    let arg_types: Vec<CilFlavor> = if callee_is_instance {
        let mut types = vec![CilFlavor::Object];
        types.extend(param_types);
        types
    } else {
        param_types
    };

    // Combine args with types
    let args_with_types: Vec<(EmValue, CilFlavor)> = arguments.into_iter().zip(arg_types).collect();

    // Create new call frame
    let mut frame = ThreadCallFrame::new(
        token,
        return_method,
        return_offset,
        local_cil_flavors,
        args_with_types,
        expects_return,
    );
    frame.save_caller_stack(caller_stack);

    // Save and clear the leave target from exception state.
    // This prevents the callee's `leave` instructions from clobbering
    // the caller's leave target (which is needed when the caller is
    // executing a finally handler entered via `leave`).
    let saved_leave_target = thread.exception_state_mut().take_leave_target();
    frame.save_leave_target(saved_leave_target);

    // Push the frame to the thread's call stack
    thread.push_frame(frame);

    // Update interpreter to new method
    interpreter.set_method(token);
    interpreter.set_offset(0);

    Ok(())
}

/// Checks if a type needs initialization and runs its `.cctor` if needed.
///
/// Implements lazy type initialization as per ECMA-335 §II.10.5.3: before
/// accessing a type's static members, its static constructor (`.cctor`) must
/// be run exactly once. If the `.cctor` previously failed, the type is
/// permanently unusable (though this implementation uses lenient mode).
///
/// # Arguments
///
/// * `address_space` - Shared address space for static field state
/// * `cctor_tracker` - Tracks `.cctor` failures for permanent type poisoning
/// * `interpreter` - Updated to point at the `.cctor` entry point if one is pushed
/// * `thread` - The emulation thread (new `.cctor` frame pushed if needed)
/// * `context` - The emulation context for type/method metadata
/// * `field` - The static field token being accessed
///
/// # Returns
///
/// * `true` — A `.cctor` was pushed and needs to run first (don't advance IP)
/// * `false` — Type is already initialized or has no `.cctor`
///
/// # Errors
///
/// Returns an error if the `.cctor` method cannot be resolved from metadata,
/// or if frame creation fails (e.g., local types cannot be determined).
pub fn maybe_run_type_cctor(
    address_space: &AddressSpace,
    cctor_tracker: &CctorTracker,
    interpreter: &mut Interpreter,
    thread: &mut EmulationThread,
    context: &EmulationContext,
    field: Token,
) -> Result<bool> {
    // Only process Field table tokens (0x04)
    if field.table() != 0x04 {
        return Ok(false);
    }

    // Find the type that owns this field
    let Some(type_token) = context
        .assembly()
        .resolver()
        .declaring_type_of_field(field)
        .map(|t| t.token)
    else {
        return Ok(false);
    };

    // If this type's .cctor previously failed, re-throw the stored exception.
    // Per ECMA-335, a type whose .cctor threw is permanently unusable.
    if cctor_tracker.get_type_failure(type_token)?.is_some() {
        // Signal failure — the caller's error handling will treat this as a
        // CLR exception (TypeInitializationException). For now we log and
        // skip, matching the existing lenient behavior.
        debug!(
            "type 0x{:08X} .cctor previously failed — skipping re-throw (lenient mode)",
            type_token.value()
        );
        return Ok(false);
    }

    // Check if already initialized
    if address_space.statics().is_type_initialized(type_token)? {
        return Ok(false);
    }

    // Find the .cctor for this type
    let Some(cctor_token) = context.find_type_cctor(type_token) else {
        // No .cctor - mark as initialized and proceed
        address_space.statics().mark_type_initialized(type_token)?;
        return Ok(false);
    };

    // Get method info for .cctor and check if it has a body
    let Ok(method) = context.get_method(cctor_token) else {
        // Can't get method - mark as initialized and skip
        address_space.statics().mark_type_initialized(type_token)?;
        return Ok(false);
    };

    // Check if .cctor has a body (it might be extern/P/Invoke)
    if !method.has_body() {
        // No body - mark as initialized and skip
        address_space.statics().mark_type_initialized(type_token)?;
        return Ok(false);
    }

    // Mark type as InProgress BEFORE running .cctor to prevent infinite recursion.
    // Per ECMA-335 §II.10.5.3.3: re-entrant access during .cctor is allowed (skip .cctor).
    address_space
        .statics()
        .set_type_init_state(type_token, TypeInitState::InProgress)?;

    // Zero-initialize all static fields for this type before running .cctor
    zero_initialize_static_fields(address_space, context, type_token)?;

    // Base-type-first initialization: ensure parent types are initialized first
    if let Some(parent_token) = context.get_base_type_token(type_token) {
        if !address_space.statics().is_type_initialized(parent_token)? {
            if let Some(parent_cctor) = context.find_type_cctor(parent_token) {
                if let Ok(parent_method) = context.get_method(parent_cctor) {
                    if parent_method.has_body() {
                        address_space
                            .statics()
                            .set_type_init_state(parent_token, TypeInitState::InProgress)?;
                        zero_initialize_static_fields(address_space, context, parent_token)?;
                    }
                }
            }
        }
    }

    // .cctor takes no arguments and returns void
    let local_types = context.get_local_types(cctor_token).unwrap_or_default();

    // Save current stack state
    let caller_stack = thread.take_stack();

    // Current method and offset for return
    let return_method = interpreter.ip().method();
    let return_offset = interpreter.ip().offset();

    // .cctor has no arguments (it's always static and parameterless)
    let args_with_types: Vec<(EmValue, CilFlavor)> = vec![];

    // Create new call frame - .cctor never returns a value
    let mut frame = ThreadCallFrame::new(
        cctor_token,
        Some(return_method),
        return_offset,
        local_types,
        args_with_types,
        false, // .cctor returns void
    );
    frame.save_caller_stack(caller_stack);
    frame.set_is_cctor();

    // Push the frame and set up interpreter
    thread.push_frame(frame);
    interpreter.set_method(cctor_token);
    interpreter.set_offset(0);

    Ok(true)
}

/// Checks if a method's declaring type needs `.cctor` initialization and runs it if needed.
///
/// Implements ECMA-335 §II.10.5.3: before invoking a type's static method,
/// its static constructor (`.cctor`) must be run exactly once. This complements
/// [`maybe_run_type_cctor`] which handles static field access.
///
/// # Returns
///
/// * `true` — A `.cctor` was pushed and needs to run first (don't advance IP)
/// * `false` — Type is already initialized, has no `.cctor`, or the method's
///   declaring type couldn't be resolved
pub fn maybe_run_type_cctor_for_method(
    address_space: &AddressSpace,
    cctor_tracker: &CctorTracker,
    interpreter: &mut Interpreter,
    thread: &mut EmulationThread,
    context: &EmulationContext,
    method: Token,
) -> Result<bool> {
    // Only process MethodDef (0x06), MemberRef (0x0A), MethodSpec (0x2B)
    let table = method.table();
    if table != 0x06 && table != 0x0A && table != 0x2B {
        return Ok(false);
    }

    // Find the type that declares this method
    let Some(type_info) = context.assembly().resolver().declaring_type(method) else {
        return Ok(false);
    };
    let type_token = type_info.token;

    // Skip <Module> (global type) — its .cctor is run explicitly during warmup
    if type_token.table() == 0x02 && type_token.row() == 1 {
        return Ok(false);
    }

    // If this type's .cctor previously failed, skip (lenient mode)
    if cctor_tracker.get_type_failure(type_token)?.is_some() {
        debug!(
            "type 0x{:08X} .cctor previously failed — skipping re-throw (lenient mode)",
            type_token.value()
        );
        return Ok(false);
    }

    // Check if already initialized
    if address_space.statics().is_type_initialized(type_token)? {
        return Ok(false);
    }

    // Find the .cctor for this type
    let Some(cctor_token) = context.find_type_cctor(type_token) else {
        address_space.statics().mark_type_initialized(type_token)?;
        return Ok(false);
    };

    // Get method info for .cctor and check if it has a body
    let Ok(cctor_method) = context.get_method(cctor_token) else {
        address_space.statics().mark_type_initialized(type_token)?;
        return Ok(false);
    };

    if !cctor_method.has_body() {
        address_space.statics().mark_type_initialized(type_token)?;
        return Ok(false);
    }

    // Mark type as InProgress BEFORE running .cctor to prevent infinite recursion
    address_space
        .statics()
        .set_type_init_state(type_token, TypeInitState::InProgress)?;

    // Zero-initialize all static fields for this type before running .cctor
    zero_initialize_static_fields(address_space, context, type_token)?;

    // Base-type-first initialization: ensure parent types are initialized first
    if let Some(parent_token) = context.get_base_type_token(type_token) {
        if !address_space.statics().is_type_initialized(parent_token)? {
            if let Some(parent_cctor) = context.find_type_cctor(parent_token) {
                if let Ok(parent_method) = context.get_method(parent_cctor) {
                    if parent_method.has_body() {
                        address_space
                            .statics()
                            .set_type_init_state(parent_token, TypeInitState::InProgress)?;
                        zero_initialize_static_fields(address_space, context, parent_token)?;
                    }
                }
            }
        }
    }

    debug!(
        "triggering .cctor 0x{:08X} for type 0x{:08X} (method call 0x{:08X})",
        cctor_token.value(),
        type_token.value(),
        method.value()
    );

    let local_types = context.get_local_types(cctor_token).unwrap_or_default();

    // Save current stack state
    let caller_stack = thread.take_stack();

    let return_method = interpreter.ip().method();
    let return_offset = interpreter.ip().offset();

    let args_with_types: Vec<(EmValue, CilFlavor)> = vec![];

    let mut frame = ThreadCallFrame::new(
        cctor_token,
        Some(return_method),
        return_offset,
        local_types,
        args_with_types,
        false,
    );
    frame.save_caller_stack(caller_stack);
    frame.set_is_cctor();

    thread.push_frame(frame);
    interpreter.set_method(cctor_token);
    interpreter.set_offset(0);

    Ok(true)
}

/// Zero-initializes all static fields for a type before running its .cctor.
///
/// Per ECMA-335 §II.10.5.3.2, all static fields are zero-initialized before
/// the type initializer runs. This ensures fields have predictable default
/// values even if the .cctor doesn't explicitly set them.
fn zero_initialize_static_fields(
    address_space: &AddressSpace,
    context: &EmulationContext,
    type_token: Token,
) -> Result<()> {
    let Some(type_info) = context.get_type(type_token) else {
        return Ok(());
    };

    for (_, field) in type_info.fields.iter() {
        if !field.flags.is_static() {
            continue;
        }

        // Only set if not already present (don't overwrite values set by parent .cctors)
        if address_space.statics().contains(field.token)? {
            continue;
        }

        let default_value = match CilFlavor::from(&field.signature.base) {
            CilFlavor::Boolean
            | CilFlavor::I1
            | CilFlavor::U1
            | CilFlavor::I2
            | CilFlavor::U2
            | CilFlavor::I4
            | CilFlavor::U4
            | CilFlavor::Char => EmValue::I32(0),
            CilFlavor::I8 | CilFlavor::U8 => EmValue::I64(0),
            CilFlavor::R4 => EmValue::F32(0.0),
            CilFlavor::R8 => EmValue::F64(0.0),
            CilFlavor::I | CilFlavor::U => EmValue::NativeInt(0),
            _ => EmValue::Null,
        };

        address_space.statics().set(field.token, default_value)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::emulation::{
        engine::generics::GenericRegistry, process::EmulationConfig, runtime::RuntimeState,
        tracer::TraceWriter,
    };

    fn create_test_resolver() -> CallResolver {
        let runtime = Arc::new(RwLock::new(RuntimeState::new()));
        let config = Arc::new(EmulationConfig::default());
        let generics = Arc::new(GenericRegistry::new());
        CallResolver::new(runtime, config, None, generics).unwrap()
    }

    #[test]
    fn test_resolver_creation() {
        let resolver = create_test_resolver();
        // RuntimeState::new() initializes with default hooks
        assert!(!resolver.hooks().is_empty());
    }

    #[test]
    fn test_format_method_name_no_cache() {
        let resolver = create_test_resolver();
        // Unknown token should return hex format
        let name = resolver.format_method_name(Token::new(0x0600_1234));
        assert_eq!(name, "0x06001234");
    }

    #[test]
    fn test_format_method_name_with_cache() {
        let resolver = create_test_resolver();

        // Manually insert a cached entry
        let info = ResolvedMethodInfo {
            namespace: Arc::from("System"),
            type_name: Arc::from("String"),
            method_name: Arc::from("Concat"),
            is_internal: false,
            param_count: 2,
            has_this: false,
        };
        resolver
            .token_cache
            .insert(Token::new(0x0A00_0042), TokenCacheEntry::Cached(info));

        let name = resolver.format_method_name(Token::new(0x0A00_0042));
        assert_eq!(name, "System.String::Concat");
    }

    #[test]
    fn test_format_method_name_empty_namespace() {
        let resolver = create_test_resolver();

        let info = ResolvedMethodInfo {
            namespace: Arc::from(""),
            type_name: Arc::from("Program"),
            method_name: Arc::from("Main"),
            is_internal: true,
            param_count: 0,
            has_this: false,
        };
        resolver
            .token_cache
            .insert(Token::new(0x0600_0001), TokenCacheEntry::Cached(info));

        let name = resolver.format_method_name(Token::new(0x0600_0001));
        assert_eq!(name, "Program::Main");
    }

    #[test]
    fn test_format_method_name_no_match_cached() {
        let resolver = create_test_resolver();

        // Insert a NoMatch entry
        resolver
            .token_cache
            .insert(Token::new(0x0600_0099), TokenCacheEntry::NoMatch);

        // Should fall through to hex format
        let name = resolver.format_method_name(Token::new(0x0600_0099));
        assert_eq!(name, "0x06000099");
    }

    #[test]
    fn test_resolver_with_trace_writer() {
        let runtime = Arc::new(RwLock::new(RuntimeState::new()));
        let config = Arc::new(EmulationConfig::default());
        let writer = Arc::new(TraceWriter::new_memory(1000, None));
        let generics = Arc::new(GenericRegistry::new());
        let resolver = CallResolver::new(runtime, config, Some(writer), generics).unwrap();

        // trace_stubs_enabled depends on config.tracing.trace_stubs
        // Default config has trace_stubs = false
        assert!(!resolver.trace_stubs_enabled());
    }
}
