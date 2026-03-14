//! Test utilities for the emulation module.
//!
//! This module provides shared test helpers for creating test fixtures
//! needed by emulation-related tests.

use std::sync::{Arc, RwLock};

use crate::emulation::{
    AddressSpace, CaptureContext, EmulationConfig, EmulationThread, RuntimeState,
    SharedFakeObjects, ThreadContext, ThreadId, VirtualFs,
};

/// Creates a minimal [`ThreadContext`] for testing.
///
/// This function provides a standard test context with:
/// - A fresh `AddressSpace` with default managed heap and memory regions
/// - An empty `CaptureContext` for tracking emulation artifacts
/// - Pre-allocated fake BCL objects for consistent hook behavior
/// - No parent assembly context
pub fn create_test_context() -> Arc<ThreadContext> {
    let address_space = Arc::new(AddressSpace::new());
    let fake_objects = SharedFakeObjects::new(address_space.managed_heap());
    Arc::new(ThreadContext::new(
        address_space,
        Arc::new(RwLock::new(RuntimeState::new())),
        Arc::new(CaptureContext::new()),
        Arc::new(EmulationConfig::default()),
        None,
        fake_objects,
        Arc::new(VirtualFs::new()),
    ))
}

/// Creates a minimal `EmulationThread` for testing.
///
/// This function provides a standard test thread with:
/// - A fresh `AddressSpace` with default managed heap and memory regions
/// - An empty `CaptureContext` for tracking emulation artifacts
/// - Pre-allocated fake BCL objects for consistent hook behavior
/// - The main thread ID
/// - No parent assembly context
///
/// # Example
///
/// ```rust,no_run
/// use dotscope::test::emulation::create_test_thread;
///
/// let mut thread = create_test_thread();
/// let handle = thread.heap().alloc_string("test").unwrap();
/// ```
pub fn create_test_thread() -> EmulationThread {
    EmulationThread::new(ThreadId::MAIN, create_test_context())
}
