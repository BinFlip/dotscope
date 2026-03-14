//! Result type for individual technique execution.

use std::time::Duration;

use crate::{compiler::EventLog, deobfuscation::techniques::Evidence};

/// Outcome of running a single technique (detection + optional transform).
///
/// Each technique produces a `TechniqueResult` after its detection and
/// optional transformation phases complete. These are aggregated into
/// [`crate::deobfuscation::DeobfuscationResult`] for the final summary.
#[derive(Debug, Clone)]
pub struct TechniqueResult {
    /// Technique ID (e.g. `"confuserex.constants"`).
    pub id: String,
    /// Whether the target pattern was detected in the assembly.
    pub detected: bool,
    /// Whether a transformation was successfully applied.
    pub transformed: bool,
    /// Evidence collected during detection.
    pub evidence: Vec<Evidence>,
    /// Events produced during the technique's execution.
    pub events: EventLog,
    /// Wall-clock time for the technique's detection and transform phases.
    pub duration: Duration,
}
