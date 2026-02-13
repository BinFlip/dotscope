//! Execution statistics and limit checking for safe emulation.
//!
//! This module provides tracking for execution statistics and limit checking
//! during CIL emulation, including instruction counts and timeout handling.
//!
//! Call depth is tracked by the thread's call stack, not by `ExecutionStats`.
//! When checking limits, pass the current call depth from the thread.
//!
//! For configurable limits, see [`crate::emulation::process::EmulationLimits`].

use std::time::{Duration, Instant};

use crate::emulation::process::EmulationLimits;

/// Tracks execution statistics and limit checks.
///
/// This struct is used during emulation to track instruction count and timing.
/// Call depth is tracked separately by the thread's call stack.
#[derive(Clone, Debug)]
pub struct ExecutionStats {
    /// Number of instructions executed.
    pub instructions_executed: u64,

    /// Time when execution started.
    start_time: Option<Instant>,
}

impl ExecutionStats {
    /// Creates new execution statistics.
    #[must_use]
    pub fn new() -> Self {
        ExecutionStats {
            instructions_executed: 0,
            start_time: None,
        }
    }

    /// Marks the start of execution.
    pub fn start(&mut self) {
        self.start_time = Some(Instant::now());
    }

    /// Increments the instruction counter.
    pub fn increment_instructions(&mut self) {
        self.instructions_executed += 1;
    }

    /// Returns the elapsed time since execution started.
    #[must_use]
    pub fn elapsed(&self) -> Option<Duration> {
        self.start_time.map(|t| t.elapsed())
    }

    /// Checks if the instruction limit has been exceeded.
    #[must_use]
    pub fn instruction_limit_exceeded(&self, limits: &EmulationLimits) -> bool {
        self.instructions_executed >= limits.max_instructions
    }

    /// Checks if the timeout has been exceeded.
    #[must_use]
    pub fn timeout_exceeded(&self, limits: &EmulationLimits) -> bool {
        if limits.timeout_ms == 0 {
            return false;
        }
        let timeout = Duration::from_millis(limits.timeout_ms);
        self.elapsed().is_some_and(|e| e >= timeout)
    }

    /// Checks all limits and returns the first exceeded limit type, if any.
    ///
    /// # Arguments
    ///
    /// * `limits` - The configured execution limits.
    /// * `call_depth` - Current call depth from the thread's call stack.
    ///
    /// # Returns
    ///
    /// The first limit that was exceeded, or `None` if all limits are within bounds.
    #[must_use]
    pub fn check_limits(
        &self,
        limits: &EmulationLimits,
        call_depth: usize,
    ) -> Option<LimitExceeded> {
        if self.instruction_limit_exceeded(limits) {
            Some(LimitExceeded::Instructions {
                executed: self.instructions_executed,
                limit: limits.max_instructions,
            })
        } else if call_depth >= limits.max_call_depth {
            Some(LimitExceeded::CallDepth {
                depth: call_depth,
                limit: limits.max_call_depth,
            })
        } else if self.timeout_exceeded(limits) {
            let elapsed = self.elapsed().unwrap_or_default();
            let timeout = Duration::from_millis(limits.timeout_ms);
            Some(LimitExceeded::Timeout {
                elapsed,
                limit: timeout,
            })
        } else {
            None
        }
    }

    /// Resets the statistics for a new execution.
    pub fn reset(&mut self) {
        self.instructions_executed = 0;
        self.start_time = None;
    }
}

impl Default for ExecutionStats {
    fn default() -> Self {
        Self::new()
    }
}

/// Indicates which limit was exceeded.
#[derive(Clone, Debug)]
pub enum LimitExceeded {
    /// Instruction count limit was exceeded.
    Instructions {
        /// Number of instructions executed.
        executed: u64,
        /// Maximum allowed.
        limit: u64,
    },

    /// Call depth limit was exceeded.
    CallDepth {
        /// Current call depth.
        depth: usize,
        /// Maximum allowed.
        limit: usize,
    },

    /// Memory limit was exceeded.
    Memory {
        /// Current memory usage.
        used: usize,
        /// Maximum allowed.
        limit: usize,
    },

    /// Execution timeout was exceeded.
    Timeout {
        /// Time elapsed.
        elapsed: Duration,
        /// Timeout limit.
        limit: Duration,
    },
}

impl std::fmt::Display for LimitExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LimitExceeded::Instructions { executed, limit } => {
                write!(f, "instruction limit exceeded: {executed} (limit: {limit})")
            }
            LimitExceeded::CallDepth { depth, limit } => {
                write!(f, "call depth limit exceeded: {depth} (limit: {limit})")
            }
            LimitExceeded::Memory { used, limit } => {
                write!(f, "memory limit exceeded: {used} bytes (limit: {limit})")
            }
            LimitExceeded::Timeout { elapsed, limit } => {
                write!(f, "timeout exceeded: {elapsed:?} (limit: {limit:?})")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_execution_stats_new() {
        let stats = ExecutionStats::new();

        assert_eq!(stats.instructions_executed, 0);
        assert!(stats.elapsed().is_none());
    }

    #[test]
    fn test_execution_stats_instructions() {
        let mut stats = ExecutionStats::new();

        stats.increment_instructions();
        stats.increment_instructions();
        stats.increment_instructions();

        assert_eq!(stats.instructions_executed, 3);
    }

    #[test]
    fn test_execution_stats_elapsed() {
        let mut stats = ExecutionStats::new();

        assert!(stats.elapsed().is_none());

        stats.start();
        std::thread::sleep(Duration::from_millis(10));

        let elapsed = stats.elapsed();
        assert!(elapsed.is_some());
        assert!(elapsed.unwrap() >= Duration::from_millis(10));
    }

    #[test]
    fn test_instruction_limit_check() {
        let limits = EmulationLimits::new().with_max_instructions(100);
        let mut stats = ExecutionStats::new();

        assert!(!stats.instruction_limit_exceeded(&limits));

        for _ in 0..100 {
            stats.increment_instructions();
        }

        assert!(stats.instruction_limit_exceeded(&limits));
    }

    #[test]
    fn test_call_depth_limit_check() {
        let limits = EmulationLimits::new().with_max_call_depth(5);
        let stats = ExecutionStats::new();

        // Call depth is passed as a parameter, not tracked internally
        assert!(stats.check_limits(&limits, 0).is_none());
        assert!(stats.check_limits(&limits, 4).is_none());
        assert!(matches!(
            stats.check_limits(&limits, 5),
            Some(LimitExceeded::CallDepth { depth: 5, limit: 5 })
        ));
        assert!(matches!(
            stats.check_limits(&limits, 10),
            Some(LimitExceeded::CallDepth {
                depth: 10,
                limit: 5
            })
        ));
    }

    #[test]
    fn test_check_limits() {
        let limits = EmulationLimits::new()
            .with_max_instructions(10)
            .with_max_call_depth(5);
        let mut stats = ExecutionStats::new();
        stats.start();

        assert!(stats.check_limits(&limits, 0).is_none());

        // Exceed instruction limit
        for _ in 0..10 {
            stats.increment_instructions();
        }

        let exceeded = stats.check_limits(&limits, 0);
        assert!(exceeded.is_some());
        assert!(matches!(
            exceeded.unwrap(),
            LimitExceeded::Instructions { .. }
        ));
    }

    #[test]
    fn test_stats_reset() {
        let mut stats = ExecutionStats::new();
        stats.start();
        stats.increment_instructions();

        stats.reset();

        assert_eq!(stats.instructions_executed, 0);
        assert!(stats.elapsed().is_none());
    }

    #[test]
    fn test_limit_exceeded_display() {
        let exceeded = LimitExceeded::Instructions {
            executed: 1000,
            limit: 500,
        };
        let display = format!("{exceeded}");
        assert!(display.contains("1000"));
        assert!(display.contains("500"));

        let exceeded = LimitExceeded::CallDepth {
            depth: 100,
            limit: 50,
        };
        let display = format!("{exceeded}");
        assert!(display.contains("100"));
        assert!(display.contains("50"));
    }
}
