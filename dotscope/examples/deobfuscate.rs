//! Deobfuscation CLI for .NET Assemblies
//!
//! This example demonstrates how to use dotscope's deobfuscation capabilities
//! to clean up obfuscated .NET assemblies.
//!
//! # Usage
//!
//! ```bash
//! # Basic deobfuscation (preserves original structure)
//! cargo run --example deobfuscate -- input.exe -o output.exe
//!
//! # Aggressive mode (inlining, unused method removal, maximum optimization)
//! cargo run --example deobfuscate -- input.exe -o output.exe --aggressive
//!
//! # Verbose output with all evidence details
//! cargo run --example deobfuscate -- input.exe -o output.exe --verbose
//! ```

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

use clap::Parser;
use dotscope::{
    deobfuscation::{DeobfuscationEngine, DeobfuscationResult, EngineConfig},
    emulation::TracingConfig,
    CilObject,
};

#[derive(Parser)]
#[command(name = "deobfuscate")]
#[command(about = "Deobfuscate .NET assemblies protected by known obfuscators", long_about = None)]
struct Cli {
    /// Path to the obfuscated .NET assembly
    input: PathBuf,

    /// Output path for the deobfuscated assembly
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Show verbose output
    #[arg(short, long)]
    verbose: bool,

    /// Enable aggressive optimization (inlining, unused method removal)
    ///
    /// Default mode preserves original code structure for analysis.
    /// Aggressive mode enables method inlining and removes unused methods
    /// for maximum optimization and size reduction.
    #[arg(short, long)]
    aggressive: bool,

    /// Maximum iterations for SSA pass fixpoint
    #[arg(long, default_value = "100")]
    max_iterations: usize,

    /// Write emulation trace to file for debugging
    ///
    /// When set, emulation events during decryption are written to this file
    /// in JSONL (newline-delimited JSON) format for debugging.
    #[arg(long)]
    trace: Option<PathBuf>,
}

/// Global abort flag for Ctrl+C handling
static ABORT: AtomicBool = AtomicBool::new(false);

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // Setup Ctrl+C handler
    ctrlc::set_handler(|| {
        eprintln!("\nAborting...");
        ABORT.store(true, Ordering::SeqCst);
        // Give a moment for cleanup, then force exit
        std::thread::sleep(std::time::Duration::from_millis(500));
        std::process::exit(130);
    })?;

    eprintln!("Loading: {}", cli.input.display());

    // Determine output path
    let output_path = cli.output.unwrap_or_else(|| {
        let stem = cli.input.file_stem().unwrap_or_default().to_string_lossy();
        let ext = cli.input.extension().unwrap_or_default().to_string_lossy();
        cli.input
            .with_file_name(format!("{}_deobfuscated.{}", stem, ext))
    });

    let input_path = cli.input.clone();
    let max_iterations = cli.max_iterations;
    let verbose = cli.verbose;
    let aggressive = cli.aggressive;
    let trace_path = cli.trace.clone();

    // Run deobfuscation in a separate thread so we can abort it
    let handle = thread::spawn(
        move || -> Result<(CilObject, DeobfuscationResult), dotscope::Error> {
            let mut config = if aggressive {
                // Aggressive mode: inlining enabled, unused method removal enabled
                EngineConfig {
                    max_iterations,
                    ..EngineConfig::aggressive()
                }
            } else {
                // Default mode: preserve original structure for analysis
                EngineConfig {
                    max_iterations,
                    ..Default::default()
                }
            };

            // Configure tracing if --trace was specified
            if let Some(path) = trace_path {
                config.tracing = Some(TracingConfig::full_trace(path));
            }

            let mut engine = DeobfuscationEngine::new(config);
            engine.process_file(&input_path)
        },
    );

    // Wait for completion or abort
    let result = loop {
        if ABORT.load(Ordering::SeqCst) {
            eprintln!("Deobfuscation aborted by user.");
            std::process::exit(130);
        }

        if handle.is_finished() {
            break handle.join().expect("Deobfuscation thread panicked");
        }

        thread::sleep(std::time::Duration::from_millis(100));
    };

    let (deobfuscated, result) = result?;

    // Display detection results
    eprintln!();
    eprintln!("=== Detection ===");
    if let Some(name) = &result.findings.obfuscator_name {
        eprintln!("{}: score {}", name, result.findings.detection.score());
        if verbose {
            for evidence in result.findings.detection.evidence() {
                eprintln!("  - {:?}", evidence);
            }
        } else {
            eprintln!(
                "  Evidence: {}",
                result.findings.detection.evidence_summary()
            );
        }
    }

    // Display deobfuscation results
    eprintln!();
    eprintln!("=== Results ===");
    eprintln!("{}", result.detailed_summary());

    if verbose {
        let warning_count = result.events.warnings().count();
        if warning_count > 0 {
            eprintln!();
            eprintln!("=== Warnings ({}) ===", warning_count);
            for warning in result.events.warnings() {
                eprintln!("  - {}", warning.message);
            }
        }
    }

    // Save the result
    eprintln!();
    eprintln!("=== Output ===");
    let output_bytes = deobfuscated.file().data();
    std::fs::write(&output_path, output_bytes)?;
    eprintln!(
        "Saved: {} ({} bytes)",
        output_path.display(),
        output_bytes.len()
    );

    Ok(())
}
