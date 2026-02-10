use std::path::{Path, PathBuf};

use anyhow::Context;
use dotscope::{deobfuscation::DetectionResult, CilObject, ValidationConfig};

/// Load a .NET assembly with the standard analysis validation config.
pub fn load_assembly(path: &Path) -> anyhow::Result<CilObject> {
    CilObject::from_path_with_validation(path, ValidationConfig::analysis())
        .with_context(|| format!("failed to load assembly: {}", path.display()))
}

/// Extract the primary obfuscator name and score from a detection result.
pub fn extract_detection_summary(result: &DetectionResult) -> (Option<String>, usize) {
    if result.detected() {
        let primary = result.primary().unwrap();
        let score = result
            .all()
            .iter()
            .find(|(name, _)| *name == primary.name())
            .map_or(0, |(_, s)| s.score());
        (Some(primary.name()), score)
    } else {
        (None, 0)
    }
}

/// Collect all `.exe` and `.dll` files recursively from a directory.
pub fn collect_assemblies(dir: &Path) -> anyhow::Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    collect_assemblies_recursive(dir, &mut files)?;
    files.sort();
    Ok(files)
}

fn collect_assemblies_recursive(dir: &Path, files: &mut Vec<PathBuf>) -> anyhow::Result<()> {
    let entries = std::fs::read_dir(dir)
        .with_context(|| format!("failed to read directory: {}", dir.display()))?;

    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_assemblies_recursive(&path, files)?;
        } else if is_assembly_file(&path) {
            files.push(path);
        }
    }
    Ok(())
}

/// Returns true if the path has an `.exe` or `.dll` extension.
pub fn is_assembly_file(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|e| e.to_str()),
        Some("exe" | "dll")
    )
}

/// Extract a display-friendly filename from a path.
pub fn file_display_name(path: &Path) -> String {
    path.file_name().map_or_else(
        || path.display().to_string(),
        |f| f.to_string_lossy().to_string(),
    )
}
