//! Synchronization utilities for multi-threaded operations.
//!
//! This module provides advanced synchronization primitives that extend beyond
//! the standard library capabilities, specifically designed for dotscope's
//! parallel processing needs.
//!
//! # Key Components
//!
//! - [`FailFastBarrier`] - A barrier that can be broken to prevent deadlocks when threads fail
//!
//! # Design Principles
//!
//! - **Fail-Fast Behavior**: When any thread fails, all waiting threads are unblocked
//! - **Deadlock Prevention**: Ensures threads don't hang indefinitely on failed operations
//! - **Thread Safety**: All operations are thread-safe and can be called concurrently
//! - **Performance**: Optimized for high-throughput parallel processing scenarios

use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Condvar, Mutex,
};

use crate::{Error, Result};

/// A fail-fast barrier that can be broken when any thread encounters an error.
///
/// Unlike `std::sync::Barrier`, this barrier allows threads to signal failure
/// and unblock all other waiting threads, preventing deadlocks when some
/// threads fail and never reach the barrier.
///
/// # Use Cases
///
/// This barrier is particularly useful in scenarios where:
/// - Multiple threads are performing parallel work that may fail
/// - All threads need to synchronize at specific points
/// - Failure of any thread should abort the entire operation
/// - Deadlock prevention is critical for system reliability
///
/// # Examples
///
/// ```rust,ignore
/// use dotscope::utils::synchronization::FailFastBarrier;
/// use std::sync::Arc;
/// use std::thread;
///
/// let barrier = Arc::new(FailFastBarrier::new(3));
/// let mut handles = vec![];
///
/// for i in 0..3 {
///     let barrier_clone = Arc::clone(&barrier);
///     let handle = thread::spawn(move || {
///         // Simulate some work
///         if i == 1 {
///             // Thread 1 fails and breaks the barrier
///             barrier_clone.break_barrier();
///             return Err("Simulated failure");
///         }
///         
///         // Try to wait for all threads
///         match barrier_clone.wait() {
///             Ok(()) => Ok("Success"),
///             Err(()) => Err("Barrier was broken by another thread"),
///         }
///     });
///     handles.push(handle);
/// }
///
/// // Collect results - some will succeed, others will get barrier broken error
/// for handle in handles {
///     let result = handle.join().unwrap();
///     match result {
///         Ok(msg) => println!("Thread succeeded: {}", msg),
///         Err(err) => println!("Thread failed: {}", err),
///     }
/// }
/// ```
pub struct FailFastBarrier {
    /// Number of threads that need to reach the barrier
    count: usize,
    /// Current number of threads that have reached the barrier
    arrived: AtomicUsize,
    /// Whether the barrier has been broken due to failure
    broken: AtomicBool,
    /// Condition variable for blocking/waking threads
    condvar: Condvar,
    /// Mutex for coordination and error message storage
    mutex: Mutex<Option<String>>,
}

impl FailFastBarrier {
    /// Creates a new `FailFastBarrier` that will wait for `count` threads.
    ///
    /// # Arguments
    ///
    /// * `count` - The number of threads that must reach the barrier before any are released
    ///
    /// # Panics
    ///
    /// Panics if `count` is 0, as this would result in a barrier that can never be satisfied.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::utils::synchronization::FailFastBarrier;
    ///
    /// let barrier = FailFastBarrier::new(4); // Wait for 4 threads
    /// ```
    pub fn new(count: usize) -> Self {
        assert!(count > 0, "FailFastBarrier count must be greater than 0");

        Self {
            count,
            arrived: AtomicUsize::new(0),
            broken: AtomicBool::new(false),
            condvar: Condvar::new(),
            mutex: Mutex::new(None),
        }
    }

    /// Wait for all threads to reach the barrier, or until the barrier is broken.
    ///
    /// This method blocks the calling thread until either:
    /// 1. All `count` threads have called `wait()` - returns `Ok(())`
    /// 2. Another thread calls `break_barrier()` - returns `Err(())`
    ///
    /// # Returns
    ///
    /// * `Ok(())` if all threads reached the barrier successfully
    /// * `Err(Error)` if the barrier was broken due to failure in another thread, with details about the failure
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently from multiple threads.
    /// The barrier ensures proper synchronization between all participating threads.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::utils::synchronization::FailFastBarrier;
    /// use std::sync::Arc;
    /// use std::thread;
    ///
    /// let barrier = Arc::new(FailFastBarrier::new(2));
    /// let barrier_clone = Arc::clone(&barrier);
    ///
    /// let handle = thread::spawn(move || {
    ///     match barrier_clone.wait() {
    ///         Ok(()) => println!("All threads reached barrier"),
    ///         Err(err) => println!("Barrier was broken: {}", err),
    ///     }
    /// });
    ///
    /// // Main thread also waits
    /// let _ = barrier.wait();
    /// handle.join().unwrap();
    /// ```
    pub fn wait(&self) -> Result<()> {
        // Check if already broken
        if self.broken.load(Ordering::Acquire) {
            let guard = self.mutex.lock().unwrap();
            if let Some(error_msg) = &*guard {
                return Err(Error::Error(format!("Barrier was broken: {}", error_msg)));
            }
            return Err(Error::Error(
                "Barrier was broken by another thread".to_string(),
            ));
        }

        let arrived_count = self.arrived.fetch_add(1, Ordering::AcqRel) + 1;

        if arrived_count == self.count {
            // Last thread to arrive - wake everyone up
            let _guard = self.mutex.lock().unwrap();
            self.condvar.notify_all();
            Ok(())
        } else {
            // Wait for others or until broken
            let guard = self.mutex.lock().unwrap();
            let guard = self
                .condvar
                .wait_while(guard, |_| {
                    !self.broken.load(Ordering::Acquire)
                        && self.arrived.load(Ordering::Acquire) < self.count
                })
                .unwrap();

            if self.broken.load(Ordering::Acquire) {
                if let Some(error_msg) = &*guard {
                    Err(Error::Error(format!("Barrier was broken: {}", error_msg)))
                } else {
                    Err(Error::Error(
                        "Barrier was broken by another thread".to_string(),
                    ))
                }
            } else {
                Ok(())
            }
        }
    }

    /// Break the barrier due to failure, immediately unblocking all waiting threads.
    ///
    /// This method should be called when a thread encounters an unrecoverable error
    /// and needs to signal all other threads to abort their waiting. Once called,
    /// all current and future calls to `wait()` will return `Err(Error)` with the provided message.
    ///
    /// # Arguments
    ///
    /// * `error_message` - A descriptive message about what caused the barrier to break
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently from multiple threads.
    /// Multiple calls to `break_barrier()` are safe - the first error message will be preserved.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::utils::synchronization::FailFastBarrier;
    /// use std::sync::Arc;
    /// use std::thread;
    ///
    /// let barrier = Arc::new(FailFastBarrier::new(3));
    ///
    /// // Thread that will fail and break the barrier
    /// let barrier_clone = Arc::clone(&barrier);
    /// thread::spawn(move || {
    ///     // Simulate work that fails
    ///     thread::sleep(std::time::Duration::from_millis(100));
    ///     
    ///     // Break the barrier on failure
    ///     barrier_clone.break_barrier("Assembly failed to parse due to invalid metadata");
    /// });
    ///
    /// // This will return Err(Error) when the barrier is broken
    /// match barrier.wait() {
    ///     Ok(()) => println!("Unexpectedly succeeded"),
    ///     Err(err) => println!("Barrier was broken: {}", err),
    /// }
    /// ```
    pub fn break_barrier(&self, error_message: &str) {
        self.broken.store(true, Ordering::Release);
        if let Ok(mut guard_rw) = self.mutex.lock() {
            *guard_rw = Some(error_message.to_string());
        }

        self.condvar.notify_all();
    }

    /// Check if the barrier has been broken without blocking.
    ///
    /// # Returns
    ///
    /// `true` if the barrier has been broken, `false` otherwise.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::utils::synchronization::FailFastBarrier;
    ///
    /// let barrier = FailFastBarrier::new(2);
    /// assert!(!barrier.is_broken());
    ///
    /// barrier.break_barrier();
    /// assert!(barrier.is_broken());
    /// ```
    pub fn is_broken(&self) -> bool {
        self.broken.load(Ordering::Acquire)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_normal_barrier_operation() {
        let barrier = Arc::new(FailFastBarrier::new(3));
        let mut handles = vec![];

        for _ in 0..3 {
            let barrier_clone = Arc::clone(&barrier);
            let handle = thread::spawn(move || barrier_clone.wait());
            handles.push(handle);
        }

        // All threads should succeed
        for handle in handles {
            assert!(handle.join().unwrap().is_ok());
        }
    }

    #[test]
    fn test_barrier_break() {
        let barrier = Arc::new(FailFastBarrier::new(3));
        let mut handles = vec![];

        // Start 2 threads that will wait
        for _ in 0..2 {
            let barrier_clone = Arc::clone(&barrier);
            let handle = thread::spawn(move || barrier_clone.wait());
            handles.push(handle);
        }

        // Give threads time to start waiting
        thread::sleep(Duration::from_millis(10));

        // Break the barrier
        barrier.break_barrier("Test failure");

        // All waiting threads should get Err with error message
        for handle in handles {
            let result = handle.join().unwrap();
            assert!(result.is_err());
            let error_msg = format!("{}", result.unwrap_err());
            assert!(error_msg.contains("Test failure"));
        }
    }

    #[test]
    fn test_is_broken() {
        let barrier = FailFastBarrier::new(2);
        assert!(!barrier.is_broken());

        barrier.break_barrier("Test break");
        assert!(barrier.is_broken());
    }

    #[test]
    #[should_panic(expected = "FailFastBarrier count must be greater than 0")]
    fn test_zero_count_panics() {
        FailFastBarrier::new(0);
    }
}
