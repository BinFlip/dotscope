#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    missing_docs
)]

//! Shared assembly compatibility testing infrastructure.
//!
//! Provides common loading, comparison, and analysis logic for testing
//! assembly compatibility across different runtime sample sets (e.g., Mono 4.8,
//! .NET 10). Each test file only needs to specify the sample directory and labels.

#![allow(dead_code)]

use dotscope::{project::ProjectLoader, CilAssemblyView};
use rayon::prelude::*;
use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
};

/// Result of loading an assembly with a specific loader.
#[derive(Debug, Clone)]
pub struct LoadResult {
    pub success: bool,
    pub error_type: Option<String>,
}

/// Comprehensive comparison of loading results between ProjectLoader and CilAssemblyView.
#[derive(Debug)]
pub struct LoadComparison {
    pub file_name: String,
    pub file_size: u64,
    pub cilproject_result: LoadResult,
    pub cilassemblyview_result: LoadResult,
}

impl LoadComparison {
    pub fn both_successful(&self) -> bool {
        self.cilproject_result.success && self.cilassemblyview_result.success
    }

    pub fn both_failed(&self) -> bool {
        !self.cilproject_result.success && !self.cilassemblyview_result.success
    }

    pub fn only_cilproject_succeeded(&self) -> bool {
        self.cilproject_result.success && !self.cilassemblyview_result.success
    }

    pub fn only_cilassemblyview_succeeded(&self) -> bool {
        !self.cilproject_result.success && self.cilassemblyview_result.success
    }
}

/// Load an assembly using ProjectLoader (with dependencies) and return the result.
pub fn try_load_with_cilproject(path: &Path) -> LoadResult {
    let search_path = path.parent().unwrap_or_else(|| Path::new("."));

    match ProjectLoader::new()
        .primary_file(path)
        .and_then(|loader| loader.with_search_path(search_path))
        .map(|loader| loader.auto_discover(true))
        .and_then(|loader| loader.build())
    {
        Ok(result) => {
            if result.success_count() > 0 {
                LoadResult {
                    success: true,
                    error_type: None,
                }
            } else {
                LoadResult {
                    success: false,
                    error_type: Some("No assemblies loaded".to_string()),
                }
            }
        }
        Err(e) => LoadResult {
            success: false,
            error_type: Some(format!("{:?}", e)),
        },
    }
}

/// Load an assembly using CilAssemblyView and return the result.
pub fn try_load_with_cilassemblyview(path: &Path) -> LoadResult {
    match CilAssemblyView::from_path(path) {
        Ok(_) => LoadResult {
            success: true,
            error_type: None,
        },
        Err(e) => LoadResult {
            success: false,
            error_type: Some(format!("{:?}", e)),
        },
    }
}

/// Find all .dll and .exe files in a samples directory.
pub fn find_assemblies(samples_dir: &Path) -> Vec<PathBuf> {
    if !samples_dir.exists() {
        return Vec::new();
    }

    let mut assemblies = Vec::new();

    if let Ok(entries) = fs::read_dir(samples_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                if let Some(extension) = path.extension() {
                    if extension == "dll" || extension == "exe" {
                        assemblies.push(path);
                    }
                }
            }
        }
    }

    assemblies.sort();
    assemblies
}

/// Categorize error types for analysis.
pub fn categorize_error(error: &str) -> &'static str {
    if error.contains("RecursionLimit") {
        "RecursionLimit"
    } else if error.contains("OutOfBounds") {
        "OutOfBounds"
    } else if error.contains("Unicode") || error.contains("Utf8") {
        "UnicodeError"
    } else if error.contains("NotSupported") {
        "NotSupported"
    } else if error.contains("Io(") {
        "Io"
    } else {
        "Other"
    }
}

/// Print detailed analysis of loading results.
pub fn print_analysis(comparisons: &[LoadComparison], label: &str) {
    println!("\n=== {} ASSEMBLY COMPATIBILITY ANALYSIS ===", label);
    println!("Total assemblies tested: {}", comparisons.len());

    let both_success = comparisons.iter().filter(|c| c.both_successful()).count();
    let both_failed = comparisons.iter().filter(|c| c.both_failed()).count();
    let only_cilproject = comparisons
        .iter()
        .filter(|c| c.only_cilproject_succeeded())
        .count();
    let only_cilassemblyview = comparisons
        .iter()
        .filter(|c| c.only_cilassemblyview_succeeded())
        .count();

    println!("\n--- OVERALL RESULTS ---");
    println!(
        "Both succeeded:              {} ({:.1}%)",
        both_success,
        both_success as f64 / comparisons.len() as f64 * 100.0
    );
    println!(
        "Both failed:                 {} ({:.1}%)",
        both_failed,
        both_failed as f64 / comparisons.len() as f64 * 100.0
    );
    println!(
        "Only CilProject succeeded:   {} ({:.1}%)",
        only_cilproject,
        only_cilproject as f64 / comparisons.len() as f64 * 100.0
    );
    println!(
        "Only CilAssemblyView succeeded: {} ({:.1}%)",
        only_cilassemblyview,
        only_cilassemblyview as f64 / comparisons.len() as f64 * 100.0
    );

    let cilproject_success_rate = comparisons
        .iter()
        .filter(|c| c.cilproject_result.success)
        .count();
    let cilassemblyview_success_rate = comparisons
        .iter()
        .filter(|c| c.cilassemblyview_result.success)
        .count();

    println!("\n--- SUCCESS RATES ---");
    println!(
        "CilProject (with deps): {}/{} ({:.1}%)",
        cilproject_success_rate,
        comparisons.len(),
        cilproject_success_rate as f64 / comparisons.len() as f64 * 100.0
    );
    println!(
        "CilAssemblyView:        {}/{} ({:.1}%)",
        cilassemblyview_success_rate,
        comparisons.len(),
        cilassemblyview_success_rate as f64 / comparisons.len() as f64 * 100.0
    );

    // Error categorization for ProjectLoader and CilAssemblyView
    let mut cilproject_errors: HashMap<&str, usize> = HashMap::new();
    let mut cilassemblyview_errors: HashMap<&str, usize> = HashMap::new();

    for comparison in comparisons {
        if !comparison.cilproject_result.success {
            if let Some(error) = &comparison.cilproject_result.error_type {
                let category = categorize_error(error);
                *cilproject_errors.entry(category).or_insert(0) += 1;
            }
        }

        if !comparison.cilassemblyview_result.success {
            if let Some(error) = &comparison.cilassemblyview_result.error_type {
                let category = categorize_error(error);
                *cilassemblyview_errors.entry(category).or_insert(0) += 1;
            }
        }
    }

    println!("\n--- CILPROJECT ERROR CATEGORIES ---");
    for (category, count) in &cilproject_errors {
        println!("{}: {}", category, count);
    }

    println!("\n--- CILASSEMBLYVIEW ERROR CATEGORIES ---");
    for (category, count) in &cilassemblyview_errors {
        println!("{}: {}", category, count);
    }

    // Show successful assemblies
    println!("\n--- SUCCESSFUL ASSEMBLIES (Both) ---");
    for comparison in comparisons.iter().filter(|c| c.both_successful()) {
        println!(
            "  {} ({} bytes)",
            comparison.file_name, comparison.file_size
        );
    }

    // Show assemblies that only work with one approach
    if only_cilproject > 0 {
        println!("\n--- ONLY CILPROJECT SUCCEEDED ---");
        for comparison in comparisons.iter().filter(|c| c.only_cilproject_succeeded()) {
            println!(
                "  {} (CilAssemblyView error: {:?})",
                comparison.file_name, comparison.cilassemblyview_result.error_type
            );
        }
    }

    if only_cilassemblyview > 0 {
        println!("\n--- ONLY CILASSEMBLYVIEW SUCCEEDED ---");
        for comparison in comparisons
            .iter()
            .filter(|c| c.only_cilassemblyview_succeeded())
        {
            println!(
                "  {} (CilProject error: {:?})",
                comparison.file_name, comparison.cilproject_result.error_type
            );
        }
    }

    // Show failures for both
    if both_failed > 0 {
        println!("\n--- FAILED WITH BOTH APPROACHES ---");
        for comparison in comparisons.iter().filter(|c| c.both_failed()) {
            println!(
                "  {} ({} bytes)",
                comparison.file_name, comparison.file_size
            );
            println!(
                "   CilProject: {:?}",
                comparison.cilproject_result.error_type
            );
            println!(
                "   CilAssemblyView: {:?}",
                comparison.cilassemblyview_result.error_type
            );
        }
    }
}

/// Run a full assembly compatibility test for all assemblies in the given sample directory.
///
/// This is the main entry point shared by all runtime compatibility tests (mono, dotnet, etc.).
/// It loads all `.dll` and `.exe` files in `samples_dir`, tests them with both `ProjectLoader`
/// and `CilAssemblyView` in parallel, prints analysis, and asserts basic compatibility.
pub fn run_assembly_compatibility_test(samples_dir: &Path, label: &str) {
    let assemblies = find_assemblies(samples_dir);
    if assemblies.is_empty() {
        println!("No assemblies found in {}", samples_dir.display());
        return;
    }

    println!("Found {} {} assemblies to test", assemblies.len(), label);

    // Create a dedicated thread pool for the test to avoid nested rayon deadlock
    // (ProjectLoader internally uses rayon for parallel assembly loading)
    let num_test_threads = (rayon::current_num_threads() / 2).max(1);
    println!(
        "Loading assemblies in parallel across {} test threads...",
        num_test_threads
    );

    let test_pool = rayon::ThreadPoolBuilder::new()
        .num_threads(num_test_threads)
        .build()
        .expect("Failed to create test thread pool");

    // Use dedicated rayon pool for parallel processing
    let comparisons: Vec<LoadComparison> = test_pool.install(|| {
        assemblies
            .par_iter()
            .map(|assembly_path| {
                let file_name = assembly_path
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .to_string();

                println!("Testing: {}", file_name);

                let cilproject_result = try_load_with_cilproject(assembly_path);
                let cilassemblyview_result = try_load_with_cilassemblyview(assembly_path);

                let file_size = assembly_path.metadata().map(|m| m.len()).unwrap_or(0);

                LoadComparison {
                    file_name,
                    file_size,
                    cilproject_result,
                    cilassemblyview_result,
                }
            })
            .collect()
    });

    print_analysis(&comparisons, label);

    // Assertions for the test
    let total_count = comparisons.len();
    let success_count = comparisons
        .iter()
        .filter(|c| c.cilproject_result.success || c.cilassemblyview_result.success)
        .count();

    // At least one approach should work for most assemblies
    assert!(
        success_count > total_count / 2,
        "Less than 50% of assemblies could be loaded with either approach"
    );

    // At least some assemblies should be parseable
    assert!(success_count > 0, "No assemblies could be loaded at all");

    println!(
        "\n{} compatibility test completed: {}/{} assemblies can be loaded",
        label, success_count, total_count
    );
}
