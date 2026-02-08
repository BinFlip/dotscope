//! Deobfuscation result types.
//!
//! This module contains the [`DeobfuscationResult`] struct which encapsulates
//! the outcome of running the deobfuscation engine on an assembly.

use std::time::Duration;

use crate::{
    compiler::{DerivedStats, EventLog},
    deobfuscation::detection::DetectionResult,
};

/// Result of running deobfuscation.
///
/// Contains the event log capturing all activity during deobfuscation,
/// and the detection result identifying the obfuscator. Statistics are
/// derived from the event log on demand.
///
/// # Example
///
/// ```rust,ignore
/// use dotscope::deobfuscation::{DeobfuscationEngine, EngineConfig};
///
/// let engine = DeobfuscationEngine::new(EngineConfig::default());
/// let result = engine.process_file(&mut assembly)?;
///
/// println!("Detection: {:?}", result.detection);
/// println!("Events: {}", result.events.len());
/// println!("Stats: {}", result.stats().summary());
/// ```
#[derive(Debug, Clone)]
pub struct DeobfuscationResult {
    /// Detection result identifying the obfuscator.
    pub detection: DetectionResult,
    /// All events from the deobfuscation run.
    pub events: EventLog,
    /// Number of pass iterations.
    pub iterations: usize,
    /// Total processing time.
    pub total_time: Duration,
}

impl DeobfuscationResult {
    /// Creates a new deobfuscation result.
    #[must_use]
    pub fn new(detection: DetectionResult, events: EventLog) -> Self {
        Self {
            detection,
            events,
            iterations: 0,
            total_time: Duration::ZERO,
        }
    }

    /// Sets timing and iteration info.
    #[must_use]
    pub fn with_timing(mut self, time: Duration, iterations: usize) -> Self {
        self.total_time = time;
        self.iterations = iterations;
        self
    }

    /// Computes statistics derived from the event log.
    #[must_use]
    pub fn stats(&self) -> DerivedStats {
        DerivedStats::from_log(&self.events)
            .with_time(self.total_time)
            .with_iterations(self.iterations)
    }

    /// Generates a human-readable summary of the deobfuscation results.
    #[must_use]
    pub fn summary(&self) -> String {
        self.stats().summary()
    }

    /// Generates a detailed multi-line summary including detection info.
    #[must_use]
    pub fn detailed_summary(&self) -> String {
        format!(
            "Deobfuscation complete: {}\nDetection: {}",
            self.stats().summary(),
            self.detection.summary()
        )
    }
}
