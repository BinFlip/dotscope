use std::path::{Path, PathBuf};

use anyhow::Context;
use dotscope::deobfuscation::{
    CleanupConfig, DeobfuscationEngine, DeobfuscationResult, EngineConfig,
};
use serde::Serialize;

use crate::{
    app::GlobalOptions,
    commands::common::{extract_detection_summary, file_display_name, process_directory},
};

#[derive(Debug, Serialize)]
struct DeobfuscationReport {
    file: String,
    output: String,
    detected: bool,
    obfuscator: Option<String>,
    score: usize,
    iterations: usize,
    time_ms: u128,
    stats: StatsReport,
    warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
struct StatsReport {
    methods_transformed: usize,
    strings_decrypted: usize,
    arrays_decrypted: usize,
    constants_folded: usize,
    constants_decrypted: usize,
    instructions_removed: usize,
    blocks_removed: usize,
    branches_simplified: usize,
    opaque_predicates_removed: usize,
    methods_inlined: usize,
    methods_regenerated: usize,
    artifacts_removed: usize,
}

pub struct DeobfuscateOptions<'a> {
    pub output: Option<&'a Path>,
    pub suffix: &'a str,
    pub recursive: bool,
    pub max_iterations: Option<usize>,
    pub max_instructions: Option<u64>,
    pub no_cleanup: bool,
    pub aggressive: bool,
    pub show_stats: bool,
    pub report: Option<&'a Path>,
    pub global: &'a GlobalOptions,
}

pub fn run(path: &Path, opts: &DeobfuscateOptions) -> anyhow::Result<()> {
    if opts.recursive {
        run_recursive(path, opts)
    } else {
        run_single(path, opts)
    }
}

fn run_single(path: &Path, opts: &DeobfuscateOptions) -> anyhow::Result<()> {
    let config = build_config(opts);

    let mut engine = DeobfuscationEngine::new(config);
    let (deobfuscated, result) = engine
        .process_file(path)
        .with_context(|| format!("deobfuscation failed: {}", path.display()))?;

    let output_path = resolve_output_path(path, opts.output, opts.suffix);

    std::fs::write(&output_path, deobfuscated.file().data())
        .with_context(|| format!("failed to write output: {}", output_path.display()))?;

    let report = build_report(path, &output_path, &result);

    if let Some(report_file) = opts.report {
        let json = serde_json::to_string_pretty(&report)?;
        std::fs::write(report_file, json)
            .with_context(|| format!("failed to write report: {}", report_file.display()))?;
        eprintln!("Report written to {}", report_file.display());
    }

    if opts.global.json {
        let json = serde_json::to_string_pretty(&report)?;
        println!("{json}");
    } else {
        let input_name = file_display_name(path);
        let output_name = file_display_name(&output_path);

        eprintln!("Deobfuscation complete: {input_name} -> {output_name}");

        if let Some(obf) = &report.obfuscator {
            eprintln!("  Obfuscator:  {} (score: {})", obf, report.score);
        } else {
            eprintln!("  Obfuscator:  none detected");
        }

        if opts.show_stats {
            display_stats(&report);
        }

        eprintln!("  Iterations:  {}", report.iterations);
        #[allow(clippy::cast_precision_loss)]
        let time_secs = report.time_ms as f64 / 1000.0;
        eprintln!("  Time:        {time_secs:.1}s");

        if !report.warnings.is_empty() {
            eprintln!("  Warnings:    {}", report.warnings.len());
            for w in &report.warnings {
                eprintln!("    - {w}");
            }
        }
    }

    Ok(())
}

fn run_recursive(dir: &Path, opts: &DeobfuscateOptions) -> anyhow::Result<()> {
    let config = build_config(opts);

    let (reports, fail_count) = process_directory(dir, |file| {
        let mut engine = DeobfuscationEngine::new(config.clone());
        let (deobfuscated, result) = engine
            .process_file(file)
            .with_context(|| format!("deobfuscation failed: {}", file.display()))?;

        let out_path = if let Some(out_dir) = opts.output {
            std::fs::create_dir_all(out_dir).with_context(|| {
                format!("failed to create output directory: {}", out_dir.display())
            })?;
            let name = suffixed_filename(file, opts.suffix);
            out_dir.join(name)
        } else {
            let name = suffixed_filename(file, opts.suffix);
            file.parent().unwrap_or(Path::new(".")).join(name)
        };

        std::fs::write(&out_path, deobfuscated.file().data())
            .with_context(|| format!("failed to write output: {}", out_path.display()))?;

        let report = build_report(file, &out_path, &result);

        if !opts.global.json {
            let fname = file_display_name(file);
            let obf = report.obfuscator.as_deref().unwrap_or("none");
            #[allow(clippy::cast_precision_loss)]
            let time_secs = report.time_ms as f64 / 1000.0;
            eprintln!("{fname}: {obf}, {time_secs:.1}s");
        }

        Ok(report)
    })?;

    let success_count = reports.len();

    if let Some(report_file) = opts.report {
        let json = serde_json::to_string_pretty(&reports)?;
        std::fs::write(report_file, json)
            .with_context(|| format!("failed to write report: {}", report_file.display()))?;
        eprintln!("Report written to {}", report_file.display());
    }

    if opts.global.json {
        let json = serde_json::to_string_pretty(&reports)?;
        println!("{json}");
    } else {
        eprintln!();
        eprintln!(
            "Processed {} files: {} succeeded, {} failed",
            success_count + fail_count,
            success_count,
            fail_count
        );
        if opts.show_stats {
            let total_strings: usize = reports.iter().map(|r| r.stats.strings_decrypted).sum();
            let total_methods: usize = reports.iter().map(|r| r.stats.methods_transformed).sum();
            eprintln!("  Total strings decrypted:  {total_strings}");
            eprintln!("  Total methods transformed: {total_methods}");
        }
    }

    Ok(())
}

fn build_config(opts: &DeobfuscateOptions) -> EngineConfig {
    let mut config = if opts.aggressive {
        EngineConfig::aggressive()
    } else {
        EngineConfig::default()
    };

    if let Some(iters) = opts.max_iterations {
        config.max_iterations = iters;
    }
    if let Some(instrs) = opts.max_instructions {
        config.emulation_max_instructions = instrs;
    }
    if opts.no_cleanup {
        config.cleanup = CleanupConfig::disabled();
    }

    config
}

fn resolve_output_path(input: &Path, output: Option<&Path>, suffix: &str) -> PathBuf {
    if let Some(out) = output {
        // If output is a directory, place the suffixed file inside it
        if out.is_dir() {
            let name = suffixed_filename(input, suffix);
            return out.join(name);
        }
        return out.to_path_buf();
    }

    let name = suffixed_filename(input, suffix);
    let parent = input.parent().unwrap_or(Path::new("."));
    parent.join(name)
}

fn suffixed_filename(input: &Path, suffix: &str) -> String {
    let stem = input
        .file_stem()
        .map_or("output", |s| s.to_str().unwrap_or("output"));
    let ext = input.extension().map_or("", |e| e.to_str().unwrap_or(""));

    if ext.is_empty() {
        format!("{stem}{suffix}")
    } else {
        format!("{stem}{suffix}.{ext}")
    }
}

fn build_report(input: &Path, output: &Path, result: &DeobfuscationResult) -> DeobfuscationReport {
    let (obfuscator_name, score) = extract_detection_summary(&result.detection);

    let derived = result.stats();
    let warnings: Vec<String> = result
        .events
        .warnings()
        .map(|ev| ev.message.clone())
        .collect();

    DeobfuscationReport {
        file: file_display_name(input),
        output: file_display_name(output),
        detected: result.detection.detected(),
        obfuscator: obfuscator_name,
        score,
        iterations: result.iterations,
        time_ms: result.total_time.as_millis(),
        stats: StatsReport {
            methods_transformed: derived.methods_transformed,
            strings_decrypted: derived.strings_decrypted,
            arrays_decrypted: derived.arrays_decrypted,
            constants_folded: derived.constants_folded,
            constants_decrypted: derived.constants_decrypted,
            instructions_removed: derived.instructions_removed,
            blocks_removed: derived.blocks_removed,
            branches_simplified: derived.branches_simplified,
            opaque_predicates_removed: derived.opaque_predicates_removed,
            methods_inlined: derived.methods_inlined,
            methods_regenerated: derived.methods_regenerated,
            artifacts_removed: derived.artifacts_removed,
        },
        warnings,
    }
}

fn display_stats(report: &DeobfuscationReport) {
    let s = &report.stats;
    if s.strings_decrypted > 0 {
        eprintln!("  Strings:     {} decrypted", s.strings_decrypted);
    }
    if s.arrays_decrypted > 0 {
        eprintln!("  Arrays:      {} decrypted", s.arrays_decrypted);
    }
    if s.constants_folded > 0 || s.constants_decrypted > 0 {
        eprintln!(
            "  Constants:   {} folded, {} decrypted",
            s.constants_folded, s.constants_decrypted
        );
    }
    if s.methods_transformed > 0 || s.methods_regenerated > 0 {
        eprintln!(
            "  Methods:     {} transformed, {} regenerated",
            s.methods_transformed, s.methods_regenerated
        );
    }
    if s.instructions_removed > 0 || s.blocks_removed > 0 {
        eprintln!(
            "  Dead code:   {} instructions, {} blocks removed",
            s.instructions_removed, s.blocks_removed
        );
    }
    if s.opaque_predicates_removed > 0 {
        eprintln!("  Predicates:  {} removed", s.opaque_predicates_removed);
    }
    if s.methods_inlined > 0 {
        eprintln!("  Inlined:     {} methods", s.methods_inlined);
    }
    if s.artifacts_removed > 0 {
        eprintln!("  Artifacts:   {} removed", s.artifacts_removed);
    }
}
