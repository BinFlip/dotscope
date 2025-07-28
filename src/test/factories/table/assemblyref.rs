//! Factory methods for AssemblyRef table operations.
//!
//! Contains helper methods migrated from AssemblyRef table source files
//! for creating test data related to assembly reference operations.

use crate::{cilassembly::CilAssembly, metadata::cilassemblyview::CilAssemblyView, Result};
use std::path::PathBuf;

/// Helper function to get a test assembly for AssemblyRef operations
///
/// Originally from: `src/metadata/tables/assemblyref/builder.rs`
pub fn get_test_assembly() -> Result<CilAssembly> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
    let view = CilAssemblyView::from_file(&path)?;
    Ok(CilAssembly::new(view))
}
