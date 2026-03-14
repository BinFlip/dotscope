use std::path::Path;

use dotscope::deobfuscation::{DeobfuscationEngine, Evidence};
use serde::Serialize;

use crate::{
    app::GlobalOptions,
    commands::common::{file_display_name, load_assembly, process_directory},
    output::print_output,
};

#[derive(Debug, Serialize)]
struct EvidenceInfo {
    evidence_type: String,
    description: String,
}

#[derive(Debug, Serialize)]
struct TechniqueInfo {
    id: String,
    evidence: Vec<EvidenceInfo>,
}

#[derive(Debug, Serialize)]
struct ObfuscatorInfo {
    name: String,
    technique_ids: Vec<String>,
}

#[derive(Debug, Serialize)]
struct DetectionInfo {
    file: String,
    detected: bool,
    obfuscators: Vec<ObfuscatorInfo>,
    techniques: Vec<TechniqueInfo>,
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
    let (results, _fail_count) = process_directory(dir, detect_file)?;

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
                let names: Vec<&str> = info.obfuscators.iter().map(|o| o.name.as_str()).collect();
                println!("{fname}: {}", names.join(", "));
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

    let engine = DeobfuscationEngine::default();
    let result = engine.detect(&assembly);

    let obfuscators: Vec<ObfuscatorInfo> = result
        .attributions
        .into_iter()
        .map(|a| ObfuscatorInfo {
            name: a.obfuscator_name,
            technique_ids: a.technique_ids,
        })
        .collect();

    let detected = !obfuscators.is_empty();

    let techniques: Vec<TechniqueInfo> = result
        .techniques
        .into_iter()
        .filter(|t| t.detected)
        .map(|t| TechniqueInfo {
            id: t.id,
            evidence: t.evidence.into_iter().map(convert_evidence).collect(),
        })
        .collect();

    Ok(DetectionInfo {
        file: file_display_name(path),
        detected,
        obfuscators,
        techniques,
    })
}

fn convert_evidence(ev: Evidence) -> EvidenceInfo {
    let (evidence_type, description) = match ev {
        Evidence::Attribute(s) => ("Attribute", s),
        Evidence::BytecodePattern(s) => ("BytecodePattern", s),
        Evidence::MetadataPattern(s) => ("MetadataPattern", s),
        Evidence::TypePattern(s) => ("TypePattern", s),
        Evidence::Resource(s) => ("Resource", s),
        Evidence::Structural(s) => ("Structural", s),
    };

    EvidenceInfo {
        evidence_type: evidence_type.to_string(),
        description,
    }
}

fn display_detection(info: &DetectionInfo) {
    if info.detected {
        let names: Vec<&str> = info.obfuscators.iter().map(|o| o.name.as_str()).collect();
        println!("{}: {}", info.file, names.join(", "));
        for obf in &info.obfuscators {
            if info.obfuscators.len() == 1 {
                println!("  Techniques: {}", obf.technique_ids.join(", "));
            } else {
                println!("  {}: {}", obf.name, obf.technique_ids.join(", "));
            }
        }
    } else {
        println!("{}: no known obfuscator detected", info.file);
        if !info.techniques.is_empty() {
            println!("  Techniques with partial matches:");
            for tech in &info.techniques {
                println!("    - {}", tech.id);
                for ev in &tech.evidence {
                    println!("      {} [{}]", ev.description, ev.evidence_type);
                }
            }
        }
    }
}
