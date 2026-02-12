use std::path::{Path, PathBuf};

use anyhow::{bail, Context};
use dotscope::{CilObject, ValidationConfig};

/// Load a .NET assembly with the standard analysis validation config.
pub fn load_assembly(path: &Path) -> anyhow::Result<CilObject> {
    CilObject::from_path_with_validation(path, ValidationConfig::analysis())
        .with_context(|| format!("failed to load assembly: {}", path.display()))
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

/// Process all assemblies in a directory, collecting results and tolerating individual failures.
pub fn process_directory<T>(
    dir: &Path,
    mut process: impl FnMut(&Path) -> anyhow::Result<T>,
) -> anyhow::Result<(Vec<T>, usize)> {
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
    let mut fail_count = 0;
    for file in &files {
        match process(file) {
            Ok(r) => results.push(r),
            Err(e) => {
                eprintln!("warning: {}: {e:#}", file.display());
                fail_count += 1;
            }
        }
    }
    Ok((results, fail_count))
}

/// Case-insensitive substring match.
pub fn name_contains_ignore_case(haystack: &str, needle: &str) -> bool {
    haystack.to_lowercase().contains(&needle.to_lowercase())
}

/// Extract a display-friendly filename from a path.
pub fn file_display_name(path: &Path) -> String {
    path.file_name().map_or_else(
        || path.display().to_string(),
        |f| f.to_string_lossy().to_string(),
    )
}
