//! Shared environment for all threads within an emulation process.
//!
//! [`ThreadContext`] groups the `Arc`-wrapped resources that every
//! [`EmulationThread`](super::EmulationThread) and
//! [`EmulationController`](crate::emulation::engine::EmulationController) needs.
//! Created once per `EmulationProcess` and shared via `Arc<ThreadContext>` —
//! spawning a new thread or controller is a single `Arc::clone`.

use std::sync::{
    atomic::{AtomicU32, Ordering},
    Arc, RwLock,
};

use dashmap::DashMap;

use crate::{
    emulation::{
        capture::CaptureContext,
        engine::{EmulationError, SyntheticMethodBody},
        fakeobjects::SharedFakeObjects,
        filesystem::VirtualFs,
        memory::{AddressSpace, ManagedHeap, StaticFieldStorage},
        process::EmulationConfig,
        runtime::RuntimeState,
        tokens,
    },
    metadata::token::Token,
    CilObject,
};

/// Shared environment for all threads within an emulation process.
///
/// Groups the `Arc`-wrapped resources that every `EmulationThread` and
/// `EmulationController` needs. Created once per `EmulationProcess` and
/// shared via `Arc<ThreadContext>` — spawning a new thread or controller
/// is a single `Arc::clone`.
pub struct ThreadContext {
    /// Shared address space for heap, statics, and mapped memory regions.
    pub address_space: Arc<AddressSpace>,
    /// Runtime state: AppDomain, hooks, dynamically loaded assemblies.
    pub runtime: Arc<RwLock<RuntimeState>>,
    /// Capture context for recording emulation artifacts (strings, values).
    pub capture: Arc<CaptureContext>,
    /// Immutable emulation configuration (limits, tracing, pointer size).
    pub config: Arc<EmulationConfig>,
    /// Primary assembly being emulated (metadata, type system).
    pub assembly: Option<Arc<CilObject>>,
    /// Pre-allocated fake BCL objects for consistent references.
    pub fake_objects: SharedFakeObjects,
    /// Virtual filesystem for sandboxed file access.
    pub virtual_fs: Arc<VirtualFs>,
    /// Synthetic method bodies created by `DynamicMethod`/`ILGenerator`.
    pub synthetic_methods: Arc<DashMap<Token, SyntheticMethodBody>>,
    /// Counter for assigning unique synthetic method tokens.
    synthetic_method_counter: Arc<AtomicU32>,
}

impl ThreadContext {
    /// Creates a new thread context with the given shared resources.
    pub fn new(
        address_space: Arc<AddressSpace>,
        runtime: Arc<RwLock<RuntimeState>>,
        capture: Arc<CaptureContext>,
        config: Arc<EmulationConfig>,
        assembly: Option<Arc<CilObject>>,
        fake_objects: SharedFakeObjects,
        virtual_fs: Arc<VirtualFs>,
    ) -> Self {
        Self {
            address_space,
            runtime,
            capture,
            config,
            assembly,
            fake_objects,
            virtual_fs,
            synthetic_methods: Arc::new(DashMap::new()),
            synthetic_method_counter: Arc::new(AtomicU32::new(1)),
        }
    }

    /// Returns a reference to the managed heap.
    #[must_use]
    pub fn heap(&self) -> &ManagedHeap {
        self.address_space.managed_heap()
    }

    /// Returns a reference to the static field storage.
    #[must_use]
    pub fn statics(&self) -> &StaticFieldStorage {
        self.address_space.statics()
    }

    /// Registers a synthetic method body and returns a unique synthetic token.
    ///
    /// The token is allocated from the `0x7F02_xxxx` range using a shared
    /// atomic counter, ensuring uniqueness across all threads.
    pub fn register_synthetic_method(&self, body: SyntheticMethodBody) -> Token {
        let id = self
            .synthetic_method_counter
            .fetch_add(1, Ordering::Relaxed);
        let token = Token::new(tokens::ranges::SYNTHETIC_METHOD_BASE | id);
        self.synthetic_methods.insert(token, body);
        token
    }

    /// Forks this context into an independent execution environment.
    ///
    /// Everything emulated code can mutate is separated, so two forks running concurrently
    /// cannot observe each other:
    ///
    /// - `address_space` — forked with CoW semantics
    /// - `runtime` — forked: the fork gets its own `AppDomainState`, so assemblies it loads
    ///   and strings it interns stay local (see [`RuntimeState::fork`])
    /// - `capture` — fresh context, same config, empty captures
    /// - `virtual_fs` — forked (falls back to shared on error)
    /// - `synthetic_methods` — seeded from the parent, then independent, so a `DynamicMethod`
    ///   emitted in one fork is not callable from another
    ///
    /// Genuinely immutable state is shared: `config`, `assembly`, `fake_objects` and the
    /// hook manager inside the runtime.
    ///
    /// `synthetic_method_counter` stays shared on purpose. It is the one mutable thing that
    /// must *not* be forked: two forks allocating from private counters would mint the same
    /// synthetic token for different bodies, and those tokens outlive the fork in captured
    /// output.
    ///
    /// # Errors
    ///
    /// Returns an error if the address space cannot be forked, or if the parent's runtime
    /// lock is poisoned.
    pub fn fork(&self) -> crate::Result<Self> {
        self.fork_with_config(Arc::clone(&self.config))
    }

    /// Forks this context, giving the fork its own configuration.
    ///
    /// The configuration is the one thing a fork legitimately needs to *differ* on. A
    /// template process is warmed up under a long budget because warmup genuinely takes it;
    /// the per-method executions forked from it are supposed to run under the much smaller
    /// per-method budget. Sharing the `Arc` makes that impossible to express, and mutating it
    /// in place would retroactively change the template's own budget.
    ///
    /// See [`Self::fork`] for what else separates and what stays shared.
    ///
    /// # Errors
    ///
    /// Returns an error if the address space cannot be forked, or if the parent's runtime
    /// lock is poisoned.
    pub fn fork_with_config(&self, config: Arc<EmulationConfig>) -> crate::Result<Self> {
        let virtual_fs = match self.virtual_fs.fork() {
            Ok(forked) => Arc::new(forked),
            Err(_) => Arc::clone(&self.virtual_fs),
        };

        let runtime = self
            .runtime
            .read()
            .map_err(|_| {
                crate::Error::Emulation(Box::new(EmulationError::LockPoisoned {
                    description: "runtime state",
                }))
            })?
            .fork();

        let synthetic_methods: DashMap<Token, SyntheticMethodBody> = self
            .synthetic_methods
            .iter()
            .map(|entry| (*entry.key(), entry.value().clone()))
            .collect();

        Ok(Self {
            address_space: Arc::new(self.address_space.fork()?),
            runtime: Arc::new(RwLock::new(runtime)),
            capture: Arc::new(CaptureContext::with_config(self.capture.config().clone())),
            config,
            assembly: self.assembly.clone(),
            fake_objects: self.fake_objects.clone(),
            virtual_fs,
            synthetic_methods: Arc::new(synthetic_methods),
            synthetic_method_counter: Arc::clone(&self.synthetic_method_counter),
        })
    }
}
