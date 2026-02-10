use std::path::Path;

use anyhow::bail;
use dotscope::deobfuscation::{DetectionEvidence, ObfuscatorDetector};
use serde::Serialize;

use crate::{
    app::GlobalOptions,
    commands::common::{
        collect_assemblies, extract_detection_summary, file_display_name, load_assembly,
    },
    output::print_output,
};

#[derive(Debug, Serialize)]
struct EvidenceInfo {
    evidence_type: String,
    description: String,
    confidence: usize,
}

#[derive(Debug, Serialize)]
struct DetectionInfo {
    file: String,
    detected: bool,
    obfuscator: Option<String>,
    score: usize,
    threshold: usize,
    evidence: Vec<EvidenceInfo>,
}

#[derive(Debug, Serialize)]
struct BatchDetectionInfo {
    results: Vec<DetectionInfo>,
    total_files: usize,
    detected_count: usize,
}

pub fn run(path: &Path, recursive: bool, opts: &GlobalOptions) -> anyhow::Result<()> {
    if recursive {
        run_recursive(path, opts)
    } else {
        run_single(path, opts)
    }
}

fn run_single(path: &Path, opts: &GlobalOptions) -> anyhow::Result<()> {
    let info = detect_file(path)?;

    print_output(&info, opts, |info| {
        display_detection(info);
    })
}

fn run_recursive(dir: &Path, opts: &GlobalOptions) -> anyhow::Result<()> {
    if !dir.is_dir() {
        bail!(
            "'{}' is not a directory (use without --recursive for single files)",
            dir.display()
        );
    }

    let files = collect_assemblies(dir)?;
    if files.is_empty() {
        bail!("no .exe or .dll files found in '{}'", dir.display());
    }

    let mut results = Vec::new();
    for file in &files {
        match detect_file(file) {
            Ok(info) => results.push(info),
            Err(e) => {
                eprintln!("warning: {}: {e:#}", file.display());
            }
        }
    }

    let detected_count = results.iter().filter(|r| r.detected).count();
    let batch = BatchDetectionInfo {
        total_files: results.len(),
        detected_count,
        results,
    };

    print_output(&batch, opts, |batch| {
        for info in &batch.results {
            let fname = &info.file;
            if info.detected {
                let obf = info.obfuscator.as_deref().unwrap_or("unknown");
                let confidence = confidence_label(info.score);
                println!(
                    "{fname}: {obf} (confidence: {confidence}, score: {})",
                    info.score
                );
            } else {
                println!("{fname}: no known obfuscator detected");
            }
        }
        println!();
        println!(
            "Scanned {} files, {} with obfuscation detected",
            batch.total_files, batch.detected_count
        );
    })
}

fn detect_file(path: &Path) -> anyhow::Result<DetectionInfo> {
    let assembly = load_assembly(path)?;

    let detector = ObfuscatorDetector::default();
    let result = detector.detect(&assembly);

    let (obfuscator_name, score) = extract_detection_summary(&result);

    // Collect evidence from all scores (use all_scores to include below-threshold)
    let all_scores = detector.all_scores(&assembly);
    let evidence: Vec<EvidenceInfo> = all_scores
        .iter()
        .flat_map(|(_, det_score)| {
            det_score.evidence().map(|ev| EvidenceInfo {
                evidence_type: evidence_type_name(ev),
                description: ev.short_description(),
                confidence: ev.confidence(),
            })
        })
        .collect();

    Ok(DetectionInfo {
        file: file_display_name(path),
        detected: result.detected(),
        obfuscator: obfuscator_name,
        score,
        threshold: result.threshold(),
        evidence,
    })
}

fn display_detection(info: &DetectionInfo) {
    if info.detected {
        let obf = info.obfuscator.as_deref().unwrap_or("unknown");
        let confidence = confidence_label(info.score);
        println!(
            "{}: {} (confidence: {}, score: {})",
            info.file, obf, confidence, info.score
        );
        if !info.evidence.is_empty() {
            println!("  Evidence:");
            for ev in &info.evidence {
                println!("    - {} (confidence: {})", ev.description, ev.confidence);
            }
        }
    } else {
        println!("{}: no known obfuscator detected", info.file);
        if !info.evidence.is_empty() {
            println!("  Below-threshold evidence:");
            for ev in &info.evidence {
                println!("    - {} (confidence: {})", ev.description, ev.confidence);
            }
        }
    }
}

fn confidence_label(score: usize) -> &'static str {
    match score {
        0..=20 => "very low",
        21..=50 => "low",
        51..=75 => "medium",
        76..=90 => "high",
        _ => "very high",
    }
}

fn evidence_type_name(ev: &DetectionEvidence) -> String {
    match ev {
        DetectionEvidence::Attribute { .. } => "Attribute".to_string(),
        DetectionEvidence::TypePattern { .. } => "TypePattern".to_string(),
        DetectionEvidence::BytecodePattern { .. } => "BytecodePattern".to_string(),
        DetectionEvidence::MetadataPattern { .. } => "MetadataPattern".to_string(),
        DetectionEvidence::Resource { .. } => "Resource".to_string(),
        DetectionEvidence::Version { .. } => "Version".to_string(),
        DetectionEvidence::MetadataString { .. } => "MetadataString".to_string(),
        DetectionEvidence::StructuralPattern { .. } => "StructuralPattern".to_string(),
        DetectionEvidence::Contradiction { .. } => "Contradiction".to_string(),
        DetectionEvidence::EncryptedMethodBodies { .. } => "EncryptedMethodBodies".to_string(),
        DetectionEvidence::ArtifactSections { .. } => "ArtifactSections".to_string(),
        DetectionEvidence::ConstantDataFields { .. } => "ConstantDataFields".to_string(),
        DetectionEvidence::ProtectionInfrastructure { .. } => {
            "ProtectionInfrastructure".to_string()
        }
    }
}
