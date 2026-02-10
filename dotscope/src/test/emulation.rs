//! Test utilities for the emulation module.
//!
//! This module provides shared test helpers for creating test fixtures
//! needed by emulation-related tests.

use std::sync::Arc;

use crate::emulation::{
    AddressSpace, CaptureContext, EmulationThread, SharedFakeObjects, ThreadId,
};

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
    let address_space = Arc::new(AddressSpace::new());
    let capture = Arc::new(CaptureContext::new());
    let fake_objects = SharedFakeObjects::new(address_space.managed_heap());
    EmulationThread::new(ThreadId::MAIN, address_space, capture, None, fake_objects)
}
