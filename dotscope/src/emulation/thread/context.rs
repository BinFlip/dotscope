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
        engine::SyntheticMethodBody,
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

    /// Forks this context with a forked address space.
    ///
    /// The forked context shares all `Arc`-wrapped resources except:
    /// - `address_space` — forked with CoW semantics
    /// - `capture` — fresh context (same config, empty captures)
    /// - `virtual_fs` — forked (falls back to shared on error)
    pub fn fork(&self) -> crate::Result<Self> {
        let virtual_fs = match self.virtual_fs.fork() {
            Ok(forked) => Arc::new(forked),
            Err(_) => Arc::clone(&self.virtual_fs),
        };

        Ok(Self {
            address_space: Arc::new(self.address_space.fork()?),
            runtime: Arc::clone(&self.runtime),
            capture: Arc::new(CaptureContext::with_config(self.capture.config().clone())),
            config: Arc::clone(&self.config),
            assembly: self.assembly.clone(),
            fake_objects: self.fake_objects.clone(),
            virtual_fs,
            synthetic_methods: Arc::clone(&self.synthetic_methods),
            synthetic_method_counter: Arc::clone(&self.synthetic_method_counter),
        })
    }
}
