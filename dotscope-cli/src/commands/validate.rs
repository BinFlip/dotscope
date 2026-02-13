use std::path::Path;

use anyhow::{bail, Context};
use dotscope::{metadata::diagnostics::DiagnosticSeverity, CilObject, ValidationConfig};
use serde::Serialize;

use crate::{app::GlobalOptions, output::print_output};

#[derive(Debug, Serialize)]
pub struct DiagnosticEntry {
    severity: String,
    category: String,
    message: String,
}

#[derive(Debug, Serialize)]
pub struct ValidationResult {
    pub path: String,
    pub level: String,
    pub valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub diagnostics: Vec<DiagnosticEntry>,
}

pub fn run(path: &Path, level: &str, opts: &GlobalOptions) -> anyhow::Result<()> {
    let config = match level {
        "minimal" => ValidationConfig::minimal(),
        "analysis" => ValidationConfig::analysis(),
        "production" => ValidationConfig::production(),
        "comprehensive" => ValidationConfig::comprehensive(),
        "strict" => ValidationConfig::strict(),
        other => bail!("unknown validation level: {other} (expected minimal, analysis, production, comprehensive, or strict)"),
    };

    let load_result = CilObject::from_path_with_validation(path, config)
        .with_context(|| format!("validation failed for: {}", path.display()));

    let (valid, error_message, diagnostics) = match load_result {
        Ok(assembly) => {
            let diags: Vec<DiagnosticEntry> = assembly
                .diagnostics()
                .iter()
                .filter(|d| {
                    matches!(
                        d.severity,
                        DiagnosticSeverity::Warning | DiagnosticSeverity::Error
                    )
                })
                .map(|d| DiagnosticEntry {
                    severity: d.severity.to_string(),
                    category: d.category.to_string(),
                    message: d.message.clone(),
                })
                .collect();
            (true, None, diags)
        }
        Err(e) => (false, Some(format!("{e:#}")), Vec::new()),
    };

    let result = ValidationResult {
        path: path.display().to_string(),
        level: level.to_string(),
        valid,
        error_message,
        diagnostics,
    };

    print_output(&result, opts, |r| {
        let status = if r.valid { "PASS" } else { "FAIL" };
        println!(
            "{status}  {path}  (level: {level})",
            path = r.path,
            level = r.level
        );
        if let Some(err) = &r.error_message {
            println!("  Error: {err}");
        }
        if !r.diagnostics.is_empty() {
            println!("  Diagnostics:");
            for d in &r.diagnostics {
                println!("    [{}] [{}] {}", d.severity, d.category, d.message);
            }
        }
    })
}
